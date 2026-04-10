// Command github polls the GitHub org audit log via GitHub App installation auth
// and emits normalized mallcop events as JSONL to stdout.
//
// Usage:
//
//	github --app-id <id> --installation-id <id> --private-key-path <path> --org <org> [--since <iso-timestamp>] [--cursor <cursor>]
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/thirdiv/mallcop-connectors/pkg/event"
)

const (
	apiBase      = "https://api.github.com"
	cursorMaxLen = 1000
	perPage      = "100"
)

// cursorRE accepts base64 standard + URL-safe alphabet plus padding.
var cursorRE = regexp.MustCompile(`^[A-Za-z0-9+/=_\-]+$`)

// validateCursor guards against tampered checkpoint cursors.
func validateCursor(cursor string) error {
	if len(cursor) > cursorMaxLen {
		return fmt.Errorf("invalid cursor: length %d exceeds maximum %d", len(cursor), cursorMaxLen)
	}
	if strings.ContainsAny(cursor, "\n\r\x00") {
		return fmt.Errorf("invalid cursor: contains control characters")
	}
	if !cursorRE.MatchString(cursor) {
		return fmt.Errorf("invalid cursor: contains unexpected characters (expected base64 alphabet)")
	}
	return nil
}

// encodeCursor wraps a raw GitHub cursor value with an HMAC to detect tampering.
// Format: base64(cursor) + "." + base64(hmac-sha256)
// The key is derived from the app-id + installation-id — config known at runtime.
func encodeCursor(raw string, sigKey []byte) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(raw))
	mac := hmac.New(sha256.New, sigKey)
	mac.Write([]byte(b64))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return b64 + "." + sig
}

// decodeCursor validates the HMAC and returns the raw cursor.
func decodeCursor(encoded string, sigKey []byte) (string, error) {
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid cursor format: missing signature")
	}
	b64, sig := parts[0], parts[1]

	// Validate base64 characters in the payload part.
	if err := validateCursor(b64); err != nil {
		return "", fmt.Errorf("invalid cursor payload: %w", err)
	}

	// Verify HMAC.
	mac := hmac.New(sha256.New, sigKey)
	mac.Write([]byte(b64))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid cursor: signature mismatch (tampered cursor rejected)")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("invalid cursor: base64 decode failed: %w", err)
	}
	return string(raw), nil
}

// sigKey builds a signing key from the app + installation IDs.
func sigKey(appID, installationID int64) []byte {
	return []byte(fmt.Sprintf("mallcop-github-cursor:%d:%d", appID, installationID))
}

// auditLogEntry is a single GitHub audit log entry (partial).
type auditLogEntry map[string]interface{}

// normalizeEntry maps a raw audit log entry to a mallcop Event.
func normalizeEntry(entry auditLogEntry, org string) (*event.Event, error) {
	payload, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}

	// Extract fields.
	action, _ := entry["action"].(string)
	actor, _ := entry["actor"].(string)
	if actor == "" {
		actor, _ = entry["actor_login"].(string)
	}

	var ts time.Time
	if createdAt, ok := entry["created_at"]; ok {
		switch v := createdAt.(type) {
		case float64:
			ts = time.UnixMilli(int64(v)).UTC()
		case string:
			ts, _ = time.Parse(time.RFC3339, v)
		}
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	// Build a stable ID from action + actor + timestamp.
	idSrc := fmt.Sprintf("github:%s:%s:%d", org, action, ts.UnixNano())
	if docID, ok := entry["_document_id"].(string); ok && docID != "" {
		idSrc = "github:" + docID
	}

	return &event.Event{
		ID:        fmt.Sprintf("%x", sha256Digest(idSrc)),
		Source:    "github",
		Type:      action,
		Actor:     actor,
		Timestamp: ts,
		Org:       org,
		Payload:   json.RawMessage(payload),
	}, nil
}

func sha256Digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// parseNextLink extracts the rel="next" URL from a GitHub Link header.
func parseNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	for _, part := range strings.Split(linkHeader, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, `rel="next"`) {
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start >= 0 && end > start {
				return part[start+1 : end]
			}
		}
	}
	return ""
}

// parseAfterCursor extracts the "after" query param from a Link header next URL.
func parseAfterCursor(linkHeader string) string {
	nextURL := parseNextLink(linkHeader)
	if nextURL == "" {
		return ""
	}
	u, err := url.Parse(nextURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("after")
}

// connector polls the GitHub audit log and emits events to w.
type connector struct {
	client         *http.Client
	org            string
	since          time.Time
	cursor         string // raw GitHub cursor
	appID          int64
	installationID int64
	out            io.Writer
	maxPages       int // 0 = unlimited
}

func (c *connector) authHeaders() map[string]string {
	return map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
}

func (c *connector) get(ctx context.Context, rawURL string, params url.Values) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if params != nil {
		q := u.Query()
		for k, vs := range params {
			for _, v := range vs {
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.authHeaders() {
		req.Header.Set(k, v)
	}
	return c.client.Do(req)
}

func (c *connector) fetchAuditLog(ctx context.Context) ([]*event.Event, string, error) {
	params := url.Values{"per_page": []string{perPage}}
	if !c.since.IsZero() && c.cursor == "" {
		// GitHub audit log doesn't directly support since; use cursor-based pagination.
		// We'll filter by timestamp client-side when no cursor is provided.
	}
	if c.cursor != "" {
		params.Set("after", c.cursor)
	}

	endpoint := fmt.Sprintf("%s/orgs/%s/audit-log", apiBase, c.org)

	var allEvents []*event.Event
	lastCursor := ""
	currentURL := endpoint
	isFirst := true
	pageCount := 0

	for {
		if c.maxPages > 0 && pageCount >= c.maxPages {
			break
		}
		pageCount++
		var resp *http.Response
		var err error

		if isFirst {
			resp, err = c.get(ctx, currentURL, params)
			isFirst = false
		} else {
			resp, err = c.get(ctx, currentURL, nil)
		}
		if err != nil {
			return nil, "", fmt.Errorf("GET %s: %w", currentURL, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, "", fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(body))
		}

		var entries []auditLogEntry
		decErr := json.NewDecoder(resp.Body).Decode(&entries)
		// Extract Link header before closing.
		linkHeader := resp.Header.Get("Link")
		resp.Body.Close()
		if decErr != nil {
			return nil, "", fmt.Errorf("decode response: %w", decErr)
		}

		// Track whether any entry on this page is newer than --since.
		// GitHub returns entries newest-first, so once we see an entry older
		// than --since, all subsequent pages will also be older — stop paginating.
		pageExhausted := false
		for _, entry := range entries {
			if !c.since.IsZero() {
				if createdAt, ok := entry["created_at"]; ok {
					var entryTS time.Time
					switch v := createdAt.(type) {
					case float64:
						entryTS = time.UnixMilli(int64(v)).UTC()
					case string:
						entryTS, _ = time.Parse(time.RFC3339, v)
					}
					if !entryTS.IsZero() && entryTS.Before(c.since) {
						// All subsequent entries (and pages) will be older — stop.
						pageExhausted = true
						break
					}
				}
			}

			ev, err := normalizeEntry(entry, c.org)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping entry: %v\n", err)
				continue
			}
			allEvents = append(allEvents, ev)
		}
		if pageExhausted {
			break
		}

		// Extract cursor from Link header.
		if after := parseAfterCursor(linkHeader); after != "" {
			lastCursor = after
		}

		// Follow pagination.
		next := parseNextLink(linkHeader)
		if next == "" {
			break
		}
		currentURL = next
	}

	return allEvents, lastCursor, nil
}

func run() error {
	var (
		appID          = flag.Int64("app-id", 0, "GitHub App ID")
		installationID = flag.Int64("installation-id", 0, "GitHub App Installation ID")
		privateKeyPath = flag.String("private-key-path", "", "Path to GitHub App private key PEM file")
		org            = flag.String("org", "", "GitHub organization name")
		since          = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursor         = flag.String("cursor", "", "Checkpoint cursor from previous run (base64-encoded, HMAC-signed)")
	)
	flag.Parse()

	// Validate required flags — no PAT support.
	if *appID == 0 {
		return fmt.Errorf("--app-id is required (GitHub App auth only, no PAT support)")
	}
	if *installationID == 0 {
		return fmt.Errorf("--installation-id is required")
	}
	if *privateKeyPath == "" {
		return fmt.Errorf("--private-key-path is required")
	}
	if *org == "" {
		return fmt.Errorf("--org is required")
	}

	// Parse --since.
	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339 format (e.g. 2024-01-01T00:00:00Z)", *since)
		}
	}

	// Decode and validate cursor if provided.
	key := sigKey(*appID, *installationID)
	rawCursor := ""
	if *cursor != "" {
		var err error
		rawCursor, err = decodeCursor(*cursor, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
	}

	// Set up GitHub App installation auth transport.
	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, *appID, *installationID, *privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create GitHub App installation auth: %w", err)
	}

	conn := &connector{
		client:         &http.Client{Transport: itr},
		org:            *org,
		since:          sinceTime,
		cursor:         rawCursor,
		appID:          *appID,
		installationID: *installationID,
		out:            os.Stdout,
	}

	ctx := context.Background()
	events, nextRawCursor, err := conn.fetchAuditLog(ctx)
	if err != nil {
		return fmt.Errorf("fetch audit log: %w", err)
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	// Emit checkpoint cursor to stderr so it can be captured separately.
	if nextRawCursor != "" {
		encodedCursor := encodeCursor(nextRawCursor, key)
		fmt.Fprintf(os.Stderr, "cursor: %s\n", encodedCursor)
	}

	return bw.Flush()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
