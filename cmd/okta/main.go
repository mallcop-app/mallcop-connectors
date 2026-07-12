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

	// legacyCursorFallback is the re-scan window used when an HMAC-valid
	// cursor is found to carry a pre-highwater Link-header "next" URL
	// instead of a timestamp. See run()'s cursor decode for the migration.
	legacyCursorFallback = 24 * time.Hour
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
//
// The second return value, tsReliable, is true only when the Timestamp on the
// returned events came from the entry's own published field. When published
// is missing or unparseable, ts falls back to time.Now().UTC() so the event
// still has SOME timestamp for display/dedupe purposes — but that fabricated
// value must never be allowed to advance the resume high-water mark (it
// would silently poison the cursor to "now" and cause the next run to skip
// every real event between the true high-water mark and now). Callers must
// gate maxSeen updates on tsReliable, not merely on ev.Timestamp being
// non-zero.
func normalizeOktaEvent(raw map[string]interface{}, domain string) ([]*event.Event, bool, error) {
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
	tsReliable := false
	if published, ok := raw["published"].(string); ok && published != "" {
		var err error
		ts, err = time.Parse(time.RFC3339, published)
		if err != nil {
			log.Printf("warn: failed to parse published timestamp %q: %v", published, err)
			ts = time.Now().UTC()
		} else {
			tsReliable = true
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
			return nil, false, fmt.Errorf("marshal payload: %w", err)
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
	return out, tsReliable, nil
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
	since    time.Time // effective query floor: max(--since, cursor high-water mark)
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

// fetchSystemLog pages the System Log to completion, following the Link
// header's rel="next" URL within THIS run only, and returns every event plus
// the maximum published timestamp among them. c.since seeds the request's
// since= query param — the System Log API's own inclusive lower time bound
// ("published >= since", per Okta's docs) — so a resumed run must never lose
// an event sharing the exact high-water timestamp with the last emitted
// event of the prior run; re-emitted boundary duplicates are dropped
// downstream by mallcop core's per-ID dedupe (v0.11.3+). The connector never
// persists or resumes the Link "next" URL across runs — it is a polling
// cursor for THIS query only, not a checkpoint (mallcoppro-bb2).
func (c *connector) fetchSystemLog(ctx context.Context) ([]*event.Event, time.Time, error) {
	baseURL := fmt.Sprintf("https://%s/api/v1/logs", c.domain)
	params := url.Values{"limit": {"1000"}}
	if !c.since.IsZero() {
		params.Set("since", c.since.UTC().Format(time.RFC3339))
	}

	var allEvents []*event.Event
	var maxSeen time.Time
	currentURL := baseURL
	isFirst := true

	for {
		var resp *http.Response
		var err error

		if isFirst {
			resp, err = c.get(ctx, currentURL, params)
			isFirst = false
		} else {
			resp, err = c.get(ctx, currentURL, nil)
		}

		if err != nil {
			return nil, time.Time{}, fmt.Errorf("GET %s: %w", currentURL, err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil, time.Time{}, fmt.Errorf("rate limited by Okta API (429)")
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, time.Time{}, fmt.Errorf("Okta API error %d: %s", resp.StatusCode, string(body))
		}

		linkHeader := resp.Header.Get("Link")

		var entries []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			resp.Body.Close()
			return nil, time.Time{}, fmt.Errorf("decode response: %w", err)
		}
		resp.Body.Close()

		for _, entry := range entries {
			evs, tsReliable, err := normalizeOktaEvent(entry, c.domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping entry: %v\n", err)
				continue
			}
			allEvents = append(allEvents, evs...)
			// Only a real source timestamp may advance the resume high-water
			// mark. A fabricated time.Now() fallback (missing/unparseable
			// published) must never poison maxSeen to "now" — that would
			// silently skip every real event between the true high-water
			// mark and now on the next run.
			if tsReliable {
				for _, ev := range evs {
					if ev.Timestamp.After(maxSeen) {
						maxSeen = ev.Timestamp
					}
				}
			}
		}

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
	floor, legacy, err := resolveFloor(*cursorArg, sinceTime, key)
	if err != nil {
		return err
	}
	if legacy {
		fmt.Fprintf(os.Stderr, "warn: legacy pagination-token cursor detected; discarding and re-scanning the last 24h\n")
	}

	conn := &connector{
		client:   http.DefaultClient,
		domain:   domain,
		apiToken: apiToken,
		since:    floor,
	}

	ctx := context.Background()
	events, maxSeen, err := conn.fetchSystemLog(ctx)
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

	// Only emit a cursor when at least one event was emitted this run; zero
	// events means the caller should keep using its previous cursor.
	if !maxSeen.IsZero() {
		encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
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
