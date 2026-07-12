// Command gcp polls GCP Cloud Logging audit log entries via the Cloud Logging API v2
// and emits normalized mallcop events as JSONL to stdout.
//
// Usage:
//
//	gcp --project <project-id> [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: service account key via GOOGLE_APPLICATION_CREDENTIALS.
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
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/logging/v2"
	"google.golang.org/api/option"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen = 2000
	pageSize     = int64(1000)

	// legacyCursorFallback is the re-scan window used when an HMAC-valid
	// cursor is found to carry a pre-highwater Cloud Logging page token
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

func sigKey(projectID string) []byte {
	return []byte(fmt.Sprintf("mallcop-gcp-cursor:%s", projectID))
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

// normalizeLogEntry maps a raw GCP Cloud Audit Log entry to one or more mallcop
// events. The canonical Type and detector-readable Payload come from the shared
// normalize library (NOT the raw protoPayload.methodName, which gates no
// detector). A SetIamPolicy granting a privileged role fans out to two events.
//
// The second return value, tsReliable, is true only when the Timestamp on the
// returned events came from the entry's own Timestamp field. When Timestamp
// is missing or unparseable, ts falls back to time.Now().UTC() so the event
// still has SOME timestamp for display/dedupe purposes — but that fabricated
// value must never be allowed to advance the resume high-water mark (it
// would silently poison the cursor to "now" and cause the next run to skip
// every real event between the true high-water mark and now). Callers must
// gate maxSeen updates on tsReliable, not merely on ev.Timestamp being
// non-zero.
func normalizeLogEntry(entry *logging.LogEntry, projectID string) ([]*event.Event, bool, error) {
	var proto map[string]interface{}
	if entry.ProtoPayload != nil {
		_ = json.Unmarshal(entry.ProtoPayload, &proto)
	}

	// Extract actor from protoPayload.authenticationInfo.principalEmail.
	actor := ""
	if authInfo, ok := proto["authenticationInfo"].(map[string]interface{}); ok {
		actor, _ = authInfo["principalEmail"].(string)
	}

	// Extract method name for mapping; fall back to LogName when absent.
	methodName := entry.LogName
	if mn, ok := proto["methodName"].(string); ok && mn != "" {
		methodName = mn
	}

	// Parse timestamp.
	ts := time.Now().UTC()
	tsReliable := false
	if entry.Timestamp != "" {
		var err error
		ts, err = time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			ts, err = time.Parse(time.RFC3339, entry.Timestamp)
			if err != nil {
				log.Printf("warn: failed to parse timestamp %q: %v", entry.Timestamp, err)
				ts = time.Now().UTC()
			} else {
				tsReliable = true
			}
		} else {
			tsReliable = true
		}
	}

	idSrc := fmt.Sprintf("gcp:%s:%s:%d", projectID, entry.LogName, ts.UnixNano())
	if entry.InsertId != "" {
		idSrc = "gcp:insertid:" + entry.InsertId
	}
	baseID := sha256Hex(idSrc)

	results := normalize.GCP(methodName, proto)
	out := make([]*event.Event, 0, len(results))
	for i, r := range results {
		payload, err := r.PayloadJSON(proto)
		if err != nil {
			return nil, false, fmt.Errorf("marshal payload: %w", err)
		}
		id := baseID
		if i > 0 {
			id = sha256Hex(fmt.Sprintf("%s:%d", idSrc, i))
		}
		out = append(out, &event.Event{
			ID:        id,
			Source:    "gcp",
			Type:      r.Type,
			Actor:     actor,
			Timestamp: ts,
			Org:       projectID,
			Payload:   payload,
		})
	}
	return out, tsReliable, nil
}

func newLoggingClient(ctx context.Context) (*logging.Service, error) {
	credFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	var httpClient *http.Client
	var err error

	if credFile != "" {
		creds, err := google.FindDefaultCredentials(ctx, logging.LoggingReadScope)
		if err != nil {
			return nil, fmt.Errorf("find default credentials: %w", err)
		}
		httpClient, err = google.DefaultClient(ctx, logging.LoggingReadScope)
		if err != nil {
			return nil, fmt.Errorf("create default client: %w", err)
		}
		_ = creds
	} else {
		httpClient, err = google.DefaultClient(ctx, logging.LoggingReadScope)
		if err != nil {
			return nil, fmt.Errorf("create default client: %w", err)
		}
	}

	svc, err := logging.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("create logging service: %w", err)
	}
	return svc, nil
}

// fetchAuditLogs pages Entries.List to completion and returns every event
// plus the maximum entry timestamp among them. floor is the effective query
// start (max of --since and any decoded cursor high-water mark, computed by
// the caller) and is built into the filter as an inclusive "timestamp >="
// bound: a resumed run must never lose an event sharing the exact
// high-water timestamp with the last emitted event of the prior run.
// Re-emitted boundary duplicates are dropped downstream by mallcop core's
// per-ID dedupe (v0.11.3+). The connector never persists or resumes
// NextPageToken across runs — it is a one-shot continuation of THIS query
// only (mallcoppro-bb2).
func fetchAuditLogs(ctx context.Context, svc *logging.Service, projectID string, floor time.Time) ([]*event.Event, time.Time, error) {
	filter := `logName=("projects/` + projectID + `/logs/cloudaudit.googleapis.com%2Factivity" OR "projects/` + projectID + `/logs/cloudaudit.googleapis.com%2Fdata_access")`
	if !floor.IsZero() {
		filter += fmt.Sprintf(` AND timestamp >= "%s"`, floor.UTC().Format(time.RFC3339))
	}

	req := &logging.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + projectID},
		Filter:        filter,
		OrderBy:       "timestamp desc",
		PageSize:      pageSize,
	}

	var allEvents []*event.Event
	var maxSeen time.Time

	for {
		resp, err := svc.Entries.List(req).Context(ctx).Do()
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("entries.list: %w", err)
		}

		for _, entry := range resp.Entries {
			evs, tsReliable, err := normalizeLogEntry(entry, projectID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping entry: %v\n", err)
				continue
			}
			allEvents = append(allEvents, evs...)
			// Only a real source timestamp may advance the resume high-water
			// mark. A fabricated time.Now() fallback (missing/unparseable
			// Timestamp) must never poison maxSeen to "now" — that would
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

		if resp.NextPageToken == "" {
			break
		}
		req.PageToken = resp.NextPageToken
	}

	return allEvents, maxSeen, nil
}

func run() error {
	var (
		projectID = flag.String("project", "", "GCP project ID")
		since     = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursorArg = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	)
	flag.Parse()

	if *projectID == "" {
		*projectID = os.Getenv("GCP_PROJECT_ID")
	}
	if *projectID == "" {
		*projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if *projectID == "" {
		return fmt.Errorf("--project or GCP_PROJECT_ID is required")
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(*projectID)
	floor, legacy, err := resolveFloor(*cursorArg, sinceTime, key)
	if err != nil {
		return err
	}
	if legacy {
		fmt.Fprintf(os.Stderr, "warn: legacy pagination-token cursor detected; discarding and re-scanning the last 24h\n")
	}

	ctx := context.Background()
	svc, err := newLoggingClient(ctx)
	if err != nil {
		return fmt.Errorf("create logging client: %w", err)
	}

	events, maxSeen, err := fetchAuditLogs(ctx, svc, *projectID, floor)
	if err != nil {
		return fmt.Errorf("fetch audit logs: %w", err)
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
