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
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen = 1000
	perPage      = "100"
	maxRetries   = 3

	// legacyCursorFallback is the re-scan window used when an HMAC-valid
	// cursor is found to carry a pre-highwater "after" pagination token
	// instead of a timestamp. See run()'s cursor decode for the migration.
	legacyCursorFallback = 24 * time.Hour
)

// apiBase is a var (not const) so tests can point it at an httptest.Server
// instead of the real GitHub API.
var apiBase = "https://api.github.com"

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
//
// The second return value, tsReliable, is true only when the Timestamp on
// the returned event came from the entry's own created_at field. When
// created_at is missing or unparseable, ts falls back to time.Now().UTC() so
// the event still has SOME timestamp for display/dedupe purposes — but that
// fabricated value must never be allowed to advance the resume high-water
// mark (it would silently poison the cursor to "now" and cause the next run
// to skip every real event between the true high-water mark and now).
// Callers must gate maxSeen updates on tsReliable, not merely on
// ev.Timestamp being non-zero.
func normalizeEntry(entry auditLogEntry, org string) (*event.Event, bool, error) {
	payload, err := json.Marshal(entry)
	if err != nil {
		return nil, false, fmt.Errorf("marshal entry: %w", err)
	}

	// Extract fields.
	action, _ := entry["action"].(string)
	actor, _ := entry["actor"].(string)
	if actor == "" {
		actor, _ = entry["actor_login"].(string)
	}

	var ts time.Time
	tsReliable := false
	if createdAt, ok := entry["created_at"]; ok {
		switch v := createdAt.(type) {
		case float64:
			ts = time.UnixMilli(int64(v)).UTC()
			tsReliable = true
		case string:
			var err error
			ts, err = time.Parse(time.RFC3339, v)
			if err != nil {
				log.Printf("warn: failed to parse created_at timestamp %q: %v, falling back to time.Now()", v, err)
			} else {
				tsReliable = true
			}
		}
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
		tsReliable = false
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
	}, tsReliable, nil
}

func sha256Digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// resolveFloor decodes an optional checkpoint cursor and combines it with
// --since to produce the effective query floor (the later of the two
// timestamps wins). An HMAC-valid cursor whose payload does not parse as a
// timestamp is a legacy pre-highwater pagination token: resolveFloor never
// resumes it and never hard-fails on it — it self-heals by falling back to
// legacyCursorFallback and reports legacy=true so the caller can log the
// one-line warning. An HMAC-invalid (tampered) cursor still hard-fails.
func resolveFloor(cursorArg string, sinceTime time.Time, key []byte) (floor time.Time, legacy bool, err error) {
	var cursorMark time.Time
	if cursorArg != "" {
		raw, err := decodeCursor(cursorArg, key)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			legacy = true
			cursorMark = time.Now().UTC().Add(-legacyCursorFallback)
		} else {
			cursorMark = ts.UTC()
		}
	}

	// When both --cursor and --since are supplied, the later (more recent)
	// timestamp wins.
	floor = sinceTime
	if cursorMark.After(floor) {
		floor = cursorMark
	}
	return floor, legacy, nil
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

// bearerTokenTransport is an http.RoundTripper that stamps every outbound
// request with a fixed Authorization: Bearer <token> header. Used when the
// connector is handed a pre-minted GitHub installation access token (via
// --installation-token) instead of minting one from an App key.
type bearerTokenTransport struct {
	token string
	next  http.RoundTripper
}

func (b *bearerTokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Clone the request so we don't mutate the caller's headers.
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(clone)
}

// connector polls the GitHub audit log and emits events to w.
type connector struct {
	client         *http.Client
	org            string
	since          time.Time // effective floor: max(--since, cursor high-water mark)
	appID          int64
	installationID int64
	out            io.Writer
	maxPages       int           // 0 = unlimited
	retryBaseDelay time.Duration // initial backoff delay; 0 = default 1s
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

// getWithRetry wraps get with exponential backoff on HTTP 429.
// It reads the X-RateLimit-Reset header for the wait time when present,
// falling back to exponential backoff (1s, 2s, 4s). Max retries: maxRetries.
func (c *connector) getWithRetry(ctx context.Context, rawURL string, params url.Values) (*http.Response, error) {
	backoff := c.retryBaseDelay
	if backoff <= 0 {
		backoff = time.Second
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.get(ctx, rawURL, params)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}
		// 429 — consume body to allow connection reuse.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if attempt >= maxRetries {
			return nil, fmt.Errorf("rate limited after %d retries", maxRetries)
		}

		// Determine wait duration.
		wait := backoff
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			if unix, err := strconv.ParseInt(reset, 10, 64); err == nil {
				if d := time.Until(time.Unix(unix, 0)); d > 0 {
					wait = d
				}
			}
		}
		fmt.Fprintf(os.Stderr, "rate limited: retry %d/%d after %s\n", attempt+1, maxRetries, wait.Round(time.Millisecond))
		backoff *= 2

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// fetchAuditLog pages the org audit log to completion and returns every
// event plus the maximum created_at timestamp among them. The audit log API
// has no server-side time-range query param, so resume is entirely
// client-side: entries come back newest-first, and once an entry's
// timestamp is strictly before c.since (the effective floor — max of
// --since and any decoded cursor high-water mark), every remaining entry on
// this page and every subsequent page is also older, so we stop. Entries
// exactly AT c.since are still included (inclusive boundary): a resumed run
// must never lose an event sharing the exact high-water timestamp with the
// last emitted event of the prior run, and re-emitted boundary duplicates
// are dropped downstream by mallcop core's per-ID dedupe (v0.11.3+).
//
// The connector never sends GitHub's own "after" cursor across runs: it is
// a one-shot continuation of a specific page of a specific request, and
// because the audit log is newest-first, persisting it across runs walks
// BACKWARD in time, missing every event newer than the token (mallcoppro-bb2).
func (c *connector) fetchAuditLog(ctx context.Context) ([]*event.Event, time.Time, error) {
	params := url.Values{"per_page": []string{perPage}}

	endpoint := fmt.Sprintf("%s/orgs/%s/audit-log", apiBase, c.org)

	var allEvents []*event.Event
	var maxSeen time.Time
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
			resp, err = c.getWithRetry(ctx, currentURL, params)
			isFirst = false
		} else {
			resp, err = c.getWithRetry(ctx, currentURL, nil)
		}
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("GET %s: %w", currentURL, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, time.Time{}, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(body))
		}

		var entries []auditLogEntry
		decErr := json.NewDecoder(resp.Body).Decode(&entries)
		// Extract Link header before closing.
		linkHeader := resp.Header.Get("Link")
		resp.Body.Close()
		if decErr != nil {
			return nil, time.Time{}, fmt.Errorf("decode response: %w", decErr)
		}

		// Track whether any entry on this page is older than the floor.
		// GitHub returns entries newest-first, so once we see an entry older
		// than the floor, all subsequent entries (and pages) will also be
		// older — stop paginating.
		pageExhausted := false
		for _, entry := range entries {
			if !c.since.IsZero() {
				if createdAt, ok := entry["created_at"]; ok {
					var entryTS time.Time
					switch v := createdAt.(type) {
					case float64:
						entryTS = time.UnixMilli(int64(v)).UTC()
					case string:
						var err error
						entryTS, err = time.Parse(time.RFC3339, v)
						if err != nil {
							log.Printf("warn: failed to parse entry timestamp %q for --since comparison: %v", v, err)
						}
					}
					if !entryTS.IsZero() && entryTS.Before(c.since) {
						// All subsequent entries (and pages) will be older — stop.
						pageExhausted = true
						break
					}
				}
			}

			ev, tsReliable, err := normalizeEntry(entry, c.org)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping entry: %v\n", err)
				continue
			}
			allEvents = append(allEvents, ev)
			// Only a real source timestamp may advance the resume high-water
			// mark. A fabricated time.Now() fallback (missing/unparseable
			// created_at) must never poison maxSeen to "now" — that would
			// silently skip every real event between the true high-water
			// mark and now on the next run.
			if tsReliable && ev.Timestamp.After(maxSeen) {
				maxSeen = ev.Timestamp
			}
		}
		if pageExhausted {
			break
		}

		// Follow pagination.
		next := parseNextLink(linkHeader)
		if next == "" {
			break
		}
		currentURL = next
	}

	return allEvents, maxSeen, nil
}

func run() error {
	var (
		appID             = flag.Int64("app-id", 0, "GitHub App ID (required when --installation-token is not set)")
		installationID    = flag.Int64("installation-id", 0, "GitHub App Installation ID")
		privateKeyPath    = flag.String("private-key-path", "", "Path to GitHub App private key PEM file (required when --installation-token is not set)")
		installationToken = flag.String("installation-token", "", "Pre-minted GitHub installation access token. When set, --app-id and --private-key-path are ignored. Use this path when mallcop-pro mints the token for you via POST /v1/github/token.")
		org               = flag.String("org", "", "GitHub organization name")
		since             = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursor            = flag.String("cursor", "", "Checkpoint cursor from previous run (base64-encoded, HMAC-signed)")
	)
	flag.Parse()

	// Validate required flags.
	if *installationID == 0 {
		return fmt.Errorf("--installation-id is required")
	}
	if *installationToken == "" {
		// Self-mint path: need app id + private key.
		if *appID == 0 {
			return fmt.Errorf("--app-id is required when --installation-token is not set")
		}
		if *privateKeyPath == "" {
			return fmt.Errorf("--private-key-path is required when --installation-token is not set")
		}
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
	floor, legacy, err := resolveFloor(*cursor, sinceTime, key)
	if err != nil {
		return err
	}
	if legacy {
		// Legacy pre-highwater cursor: an HMAC-valid "after" pagination
		// token, not a timestamp. Never resumed (an "after" token is a
		// one-shot continuation of a now-stale query, and the audit log is
		// newest-first — persisting it would walk backward in time) and
		// never hard-failed on either — self-healed by re-scanning a fixed
		// lookback window. Tampered (HMAC-invalid) cursors still hard-fail.
		fmt.Fprintf(os.Stderr, "warn: legacy pagination-token cursor detected; discarding and re-scanning the last 24h\n")
	}

	// Set up the authenticated HTTP client. Two paths:
	//
	//  1. --installation-token: caller (e.g. mallcop-pro /v1/github/token)
	//     already minted an installation access token. We use it as a
	//     static Bearer via bearerTokenTransport. This is the preferred
	//     path for customer deploys that don't hold the GitHub App key.
	//
	//  2. --app-id + --private-key-path: legacy / operator path. The
	//     connector mints its own token via ghinstallation.
	var httpClient *http.Client
	if *installationToken != "" {
		httpClient = &http.Client{
			Transport: &bearerTokenTransport{
				token: *installationToken,
				next:  http.DefaultTransport,
			},
		}
	} else {
		itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, *appID, *installationID, *privateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to create GitHub App installation auth: %w", err)
		}
		httpClient = &http.Client{Transport: itr}
	}

	conn := &connector{
		client:         httpClient,
		org:            *org,
		since:          floor,
		appID:          *appID,
		installationID: *installationID,
		out:            os.Stdout,
	}

	ctx := context.Background()
	events, maxSeen, err := conn.fetchAuditLog(ctx)
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
	// Only when at least one event was emitted this run; zero events means
	// the caller should keep using its previous cursor.
	if !maxSeen.IsZero() {
		encodedCursor := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
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
