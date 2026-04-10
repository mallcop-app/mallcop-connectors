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

	"github.com/thirdiv/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen = 2000
	pageSize     = int64(1000)
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

func normalizeLogEntry(entry *logging.LogEntry, projectID string) (*event.Event, error) {
	payload, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}

	// Extract actor from protoPayload.authenticationInfo.principalEmail.
	actor := ""
	if entry.ProtoPayload != nil {
		var proto map[string]interface{}
		if err := json.Unmarshal(entry.ProtoPayload, &proto); err == nil {
			if authInfo, ok := proto["authenticationInfo"].(map[string]interface{}); ok {
				actor, _ = authInfo["principalEmail"].(string)
			}
		}
	}

	// Extract method name (event type) from protoPayload.methodName.
	eventType := entry.LogName
	if entry.ProtoPayload != nil {
		var proto map[string]interface{}
		if err := json.Unmarshal(entry.ProtoPayload, &proto); err == nil {
			if methodName, ok := proto["methodName"].(string); ok && methodName != "" {
				eventType = methodName
			}
		}
	}

	// Parse timestamp.
	ts := time.Now().UTC()
	if entry.Timestamp != "" {
		var err error
		ts, err = time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			ts, err = time.Parse(time.RFC3339, entry.Timestamp)
			if err != nil {
				log.Printf("warn: failed to parse timestamp %q: %v", entry.Timestamp, err)
				ts = time.Now().UTC()
			}
		}
	}

	idSrc := fmt.Sprintf("gcp:%s:%s:%d", projectID, entry.LogName, ts.UnixNano())
	if entry.InsertId != "" {
		idSrc = "gcp:insertid:" + entry.InsertId
	}

	return &event.Event{
		ID:        sha256Hex(idSrc),
		Source:    "gcp",
		Type:      eventType,
		Actor:     actor,
		Timestamp: ts,
		Org:       projectID,
		Payload:   json.RawMessage(payload),
	}, nil
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

func fetchAuditLogs(ctx context.Context, svc *logging.Service, projectID string, since time.Time, pageToken string) ([]*event.Event, string, error) {
	filter := `logName=("projects/` + projectID + `/logs/cloudaudit.googleapis.com%2Factivity" OR "projects/` + projectID + `/logs/cloudaudit.googleapis.com%2Fdata_access")`
	if !since.IsZero() {
		filter += fmt.Sprintf(` AND timestamp >= "%s"`, since.UTC().Format(time.RFC3339))
	}

	req := &logging.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + projectID},
		Filter:        filter,
		OrderBy:       "timestamp desc",
		PageSize:      pageSize,
	}
	if pageToken != "" {
		req.PageToken = pageToken
	}

	var allEvents []*event.Event
	lastPageToken := ""

	for {
		resp, err := svc.Entries.List(req).Context(ctx).Do()
		if err != nil {
			return nil, "", fmt.Errorf("entries.list: %w", err)
		}

		for _, entry := range resp.Entries {
			ev, err := normalizeLogEntry(entry, projectID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping entry: %v\n", err)
				continue
			}
			allEvents = append(allEvents, ev)
		}

		if resp.NextPageToken == "" {
			break
		}
		lastPageToken = resp.NextPageToken
		req.PageToken = resp.NextPageToken
	}

	return allEvents, lastPageToken, nil
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
	rawCursor := ""
	if *cursorArg != "" {
		var err error
		rawCursor, err = decodeCursor(*cursorArg, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
	}

	ctx := context.Background()
	svc, err := newLoggingClient(ctx)
	if err != nil {
		return fmt.Errorf("create logging client: %w", err)
	}

	events, nextPageToken, err := fetchAuditLogs(ctx, svc, *projectID, sinceTime, rawCursor)
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

	if nextPageToken != "" {
		encoded := encodeCursor(nextPageToken, key)
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
