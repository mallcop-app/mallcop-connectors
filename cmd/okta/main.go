// Command okta polls the Okta System Log API (/api/v1/logs)
// and emits normalized mallcop events as JSONL to stdout.
//
// Usage:
//
//	okta [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: OKTA_DOMAIN, OKTA_API_TOKEN (SSWS token).
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
	"strings"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen = 2000
	maxRetries   = 3
)

var cursorRE = regexp.MustCompile(`^[A-Za-z0-9+/=_\-]+$`)

func validateCursor(cursor string) error {
	if len(cursor) > cursorMaxLen {
		return fmt.Errorf("invalid cursor: length %d exceeds maximum %d", len(cursor), cursorMaxLen)
	}
	if strings.ContainsAny(cursor, "\n\r\x00") {
		return fmt.Errorf("invalid cursor: contains control characters")
	}
	if !cursorRE.MatchString(cursor) {
		return fmt.Errorf("invalid cursor: contains unexpected characters")
	}
	return nil
}

func sigKey(domain string) []byte {
	return []byte(fmt.Sprintf("mallcop-okta-cursor:%s", domain))
}

func encodeCursor(raw string, key []byte) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(raw))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b64))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return b64 + "." + sig
}

func decodeCursor(encoded string, key []byte) (string, error) {
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid cursor format: missing signature")
	}
	b64, sig := parts[0], parts[1]
	if err := validateCursor(b64); err != nil {
		return "", fmt.Errorf("invalid cursor payload: %w", err)
	}
	mac := hmac.New(sha256.New, key)
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

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

// oktaLogEvent is a single Okta System Log entry (partial).
type oktaLogEvent struct {
	UUID           string `json:"uuid"`
	Published      string `json:"published"`
	EventType      string `json:"eventType"`
	DisplayMessage string `json:"displayMessage"`
	Actor          struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		AlternateID string `json:"alternateId"`
		DisplayName string `json:"displayName"`
	} `json:"actor"`
	Target []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		AlternateID string `json:"alternateId"`
		DisplayName string `json:"displayName"`
	} `json:"target"`
}

// normalizeOktaEvent maps a raw Okta System Log event to one or more mallcop
// events. The canonical Type and detector-readable Payload come from the shared
// normalize library (NOT the raw Okta eventType, which gates no detector, and
// whose security fields are buried under client.* / target[] / outcome.*).
func normalizeOktaEvent(raw map[string]interface{}, domain string) ([]*event.Event, error) {
	oktaEventType, _ := raw["eventType"].(string)

	actor := ""
	if actorMap, ok := raw["actor"].(map[string]interface{}); ok {
		if alt, ok := actorMap["alternateId"].(string); ok && alt != "" {
			actor = alt
		} else if display, ok := actorMap["displayName"].(string); ok {
			actor = display
		}
	}

	ts := time.Now().UTC()
	if published, ok := raw["published"].(string); ok && published != "" {
		var err error
		ts, err = time.Parse(time.RFC3339, published)
		if err != nil {
			log.Printf("warn: failed to parse published timestamp %q: %v", published, err)
			ts = time.Now().UTC()
		}
	}

	idSrc := fmt.Sprintf("okta:%s:%s:%d", domain, oktaEventType, ts.UnixNano())
	if uuid, ok := raw["uuid"].(string); ok && uuid != "" {
		idSrc = "okta:uuid:" + uuid
	}
	baseID := sha256Hex(idSrc)

	results := normalize.Okta(oktaEventType, raw)
	out := make([]*event.Event, 0, len(results))
	for i, r := range results {
		payload, err := r.PayloadJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		id := baseID
		if i > 0 {
			id = sha256Hex(fmt.Sprintf("%s:%d", idSrc, i))
		}
		out = append(out, &event.Event{
			ID:        id,
			Source:    "okta",
			Type:      r.Type,
			Actor:     actor,
			Timestamp: ts,
			Org:       domain,
			Payload:   payload,
		})
	}
	return out, nil
}

// parseNextLink extracts the rel="next" URL from an Okta Link header.
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

type connector struct {
	client   *http.Client
	domain   string
	apiToken string
	since    time.Time
	nextURL  string // raw next URL from Link header
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
	req.Header.Set("Authorization", "SSWS "+c.apiToken)
	req.Header.Set("Accept", "application/json")
	return c.client.Do(req)
}

func (c *connector) fetchSystemLog(ctx context.Context) ([]*event.Event, string, error) {
	baseURL := fmt.Sprintf("https://%s/api/v1/logs", c.domain)
	params := url.Values{"limit": {"1000"}}
	if !c.since.IsZero() && c.nextURL == "" {
		params.Set("since", c.since.UTC().Format(time.RFC3339))
	}

	var allEvents []*event.Event
	lastNextURL := ""
	currentURL := baseURL
	isFirst := true

	for {
		var resp *http.Response
		var err error

		if isFirst {
			if c.nextURL != "" {
				// Resume from cursor (next URL already has params baked in).
				resp, err = c.get(ctx, c.nextURL, nil)
			} else {
				resp, err = c.get(ctx, currentURL, params)
			}
			isFirst = false
		} else {
			resp, err = c.get(ctx, currentURL, nil)
		}

		if err != nil {
			return nil, "", fmt.Errorf("GET %s: %w", currentURL, err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil, "", fmt.Errorf("rate limited by Okta API (429)")
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, "", fmt.Errorf("Okta API error %d: %s", resp.StatusCode, string(body))
		}

		linkHeader := resp.Header.Get("Link")

		var entries []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			resp.Body.Close()
			return nil, "", fmt.Errorf("decode response: %w", err)
		}
		resp.Body.Close()

		for _, entry := range entries {
			evs, err := normalizeOktaEvent(entry, c.domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping entry: %v\n", err)
				continue
			}
			allEvents = append(allEvents, evs...)
		}

		next := parseNextLink(linkHeader)
		if next == "" {
			break
		}
		lastNextURL = next
		currentURL = next
	}

	return allEvents, lastNextURL, nil
}

func run() error {
	var (
		since     = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursorArg = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	)
	flag.Parse()

	domain := os.Getenv("OKTA_DOMAIN")
	apiToken := os.Getenv("OKTA_API_TOKEN")

	if domain == "" {
		return fmt.Errorf("OKTA_DOMAIN must be set (e.g. myorg.okta.com)")
	}
	if apiToken == "" {
		return fmt.Errorf("OKTA_API_TOKEN must be set")
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(domain)
	rawCursor := ""
	if *cursorArg != "" {
		var err error
		rawCursor, err = decodeCursor(*cursorArg, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
	}

	conn := &connector{
		client:   http.DefaultClient,
		domain:   domain,
		apiToken: apiToken,
		since:    sinceTime,
		nextURL:  rawCursor,
	}

	ctx := context.Background()
	events, nextURL, err := conn.fetchSystemLog(ctx)
	if err != nil {
		return fmt.Errorf("fetch system log: %w", err)
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	if nextURL != "" {
		encoded := encodeCursor(nextURL, key)
		fmt.Fprintf(os.Stderr, "cursor: %s\n", encoded)
	}

	return bw.Flush()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
