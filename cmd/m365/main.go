// Command m365 polls the Office 365 Management Activity API (Unified Audit Log)
// and emits normalized mallcop events as JSONL to stdout.
//
// Usage:
//
//	m365 [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET (OAuth2 client credentials).
// Content types fetched: Audit.AzureActiveDirectory, Audit.Exchange,
//                        Audit.SharePoint, Audit.General.
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

	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen    = 2000
	tokenEndpoint   = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	managementBase  = "https://manage.office.com/api/v1.0/%s/activity/feed"
)

var (
	contentTypes = []string{
		"Audit.AzureActiveDirectory",
		"Audit.Exchange",
		"Audit.SharePoint",
		"Audit.General",
	}
	cursorRE = regexp.MustCompile(`^[A-Za-z0-9+/=_\-]+$`)
)

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

func sigKey(tenantID string) []byte {
	return []byte(fmt.Sprintf("mallcop-m365-cursor:%s", tenantID))
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

// m365TokenResponse is the OAuth2 token response.
type m365TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func getAccessToken(tenantID, clientID, clientSecret string) (string, error) {
	endpoint := fmt.Sprintf(tokenEndpoint, tenantID)
	vals := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://manage.office.com/.default"},
	}
	resp, err := http.PostForm(endpoint, vals)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token error %d: %s", resp.StatusCode, string(body))
	}
	var tr m365TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	return tr.AccessToken, nil
}

// auditBlob represents a content blob reference returned by /subscriptions/content.
type auditBlob struct {
	ContentID   string `json:"contentId"`
	ContentURI  string `json:"contentUri"`
	ContentType string `json:"contentType"`
	Expiration  string `json:"expiration"`
}

// auditRecord is a single unified audit log record (subset of fields).
type auditRecord struct {
	ID           string `json:"Id"`
	CreationTime string `json:"CreationTime"`
	Operation    string `json:"Operation"`
	Workload     string `json:"Workload"`
	UserID       string `json:"UserId"`
	RecordType   int    `json:"RecordType"`
}

func normalizeRecord(raw map[string]interface{}, tenantID, contentType string) (*event.Event, error) {
	payload, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal record: %w", err)
	}

	operation, _ := raw["Operation"].(string)
	userID, _ := raw["UserId"].(string)
	workload, _ := raw["Workload"].(string)

	eventType := operation
	if workload != "" && operation != "" {
		eventType = workload + "." + operation
	}

	ts := time.Now().UTC()
	if creationTime, ok := raw["CreationTime"].(string); ok && creationTime != "" {
		var err error
		ts, err = time.Parse("2006-01-02T15:04:05", creationTime)
		if err != nil {
			ts, err = time.Parse(time.RFC3339, creationTime)
			if err != nil {
				log.Printf("warn: failed to parse CreationTime %q: %v", creationTime, err)
				ts = time.Now().UTC()
			}
		}
		ts = ts.UTC()
	}

	idSrc := fmt.Sprintf("m365:%s:%s:%d", tenantID, eventType, ts.UnixNano())
	if id, ok := raw["Id"].(string); ok && id != "" {
		idSrc = "m365:id:" + id
	}

	return &event.Event{
		ID:        sha256Hex(idSrc),
		Source:    "m365",
		Type:      eventType,
		Actor:     userID,
		Timestamp: ts,
		Org:       tenantID,
		Payload:   json.RawMessage(payload),
	}, nil
}

type connector struct {
	client      *http.Client
	accessToken string
	tenantID    string
	since       time.Time
}

func (c *connector) authGet(ctx context.Context, rawURL string, params url.Values) (*http.Response, error) {
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
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	return c.client.Do(req)
}

// ensureSubscription starts a subscription for a content type if not already active.
func (c *connector) ensureSubscription(ctx context.Context, contentType string) error {
	endpoint := fmt.Sprintf("%s/subscriptions/start", fmt.Sprintf(managementBase, c.tenantID))
	params := url.Values{
		"contentType":  {contentType},
		"PublisherIdentifier": {c.tenantID},
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	q := u.Query()
	for k, vs := range params {
		q.Set(k, vs[0])
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "0")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("subscription start: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// 200 = started, 400 with "AF20024" error = already subscribed — both are OK.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("subscription start %s: HTTP %d", contentType, resp.StatusCode)
	}
	return nil
}

// listBlobs returns content blob references for the given time range and content type.
func (c *connector) listBlobs(ctx context.Context, contentType string, startTime, endTime time.Time) ([]auditBlob, error) {
	endpoint := fmt.Sprintf("%s/subscriptions/content", fmt.Sprintf(managementBase, c.tenantID))
	params := url.Values{
		"contentType":         {contentType},
		"startTime":           {startTime.UTC().Format("2006-01-02T15:04:05")},
		"endTime":             {endTime.UTC().Format("2006-01-02T15:04:05")},
		"PublisherIdentifier": {c.tenantID},
	}

	var blobs []auditBlob
	currentURL := endpoint
	isFirst := true

	for {
		var resp *http.Response
		var err error
		if isFirst {
			resp, err = c.authGet(ctx, currentURL, params)
			isFirst = false
		} else {
			resp, err = c.authGet(ctx, currentURL, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("list blobs: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("list blobs %s HTTP %d: %s", contentType, resp.StatusCode, string(body))
		}

		var page []auditBlob
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode blobs: %w", err)
		}
		resp.Body.Close()
		blobs = append(blobs, page...)

		// The Management API returns nextPageUri in a response header.
		nextPage := resp.Header.Get("NextPageUri")
		if nextPage == "" {
			break
		}
		currentURL = nextPage
	}

	return blobs, nil
}

// fetchBlob downloads a content blob and returns its audit records.
func (c *connector) fetchBlob(ctx context.Context, contentURI, contentType string) ([]*event.Event, error) {
	resp, err := c.authGet(ctx, contentURI, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch blob: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetch blob HTTP %d: %s", resp.StatusCode, string(body))
	}

	var records []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, fmt.Errorf("decode blob: %w", err)
	}

	var events []*event.Event
	for _, record := range records {
		ev, err := normalizeRecord(record, c.tenantID, contentType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping record: %v\n", err)
			continue
		}
		events = append(events, ev)
	}
	return events, nil
}

// cursorState stores the last processed blob ID per content type.
type cursorState struct {
	LastBlobID map[string]string `json:"last_blob_id"`
}

func (c *connector) fetchAuditLog(ctx context.Context, since time.Time, lastBlobIDs map[string]string) ([]*event.Event, map[string]string, error) {
	// Window: since..now. Management API max window = 24h.
	endTime := time.Now().UTC()
	startTime := since
	if startTime.IsZero() {
		startTime = endTime.Add(-24 * time.Hour)
	}

	// If window > 24h, clamp to last 24h.
	if endTime.Sub(startTime) > 24*time.Hour {
		startTime = endTime.Add(-24 * time.Hour)
	}

	newLastBlobIDs := make(map[string]string)
	for k, v := range lastBlobIDs {
		newLastBlobIDs[k] = v
	}

	var allEvents []*event.Event

	for _, ct := range contentTypes {
		// Ensure subscription is active.
		if err := c.ensureSubscription(ctx, ct); err != nil {
			fmt.Fprintf(os.Stderr, "warn: subscription for %s: %v\n", ct, err)
		}

		blobs, err := c.listBlobs(ctx, ct, startTime, endTime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: list blobs for %s: %v\n", ct, err)
			continue
		}

		lastProcessed := lastBlobIDs[ct]
		foundLast := lastProcessed == ""
		var newLastID string

		for _, blob := range blobs {
			if blob.ContentID == lastProcessed {
				foundLast = true
				continue
			}
			if !foundLast {
				continue
			}
			if newLastID == "" {
				newLastID = blob.ContentID
			}

			events, err := c.fetchBlob(ctx, blob.ContentURI, ct)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: fetch blob %s: %v\n", blob.ContentID, err)
				continue
			}
			allEvents = append(allEvents, events...)
			newLastID = blob.ContentID
		}

		if newLastID != "" {
			newLastBlobIDs[ct] = newLastID
		}
	}

	return allEvents, newLastBlobIDs, nil
}

func run() error {
	var (
		since     = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursorArg = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	)
	flag.Parse()

	tenantID := os.Getenv("M365_TENANT_ID")
	clientID := os.Getenv("M365_CLIENT_ID")
	clientSecret := os.Getenv("M365_CLIENT_SECRET")

	if tenantID == "" || clientID == "" || clientSecret == "" {
		return fmt.Errorf("M365_TENANT_ID, M365_CLIENT_ID, and M365_CLIENT_SECRET must be set")
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(tenantID)
	lastBlobIDs := make(map[string]string)
	if *cursorArg != "" {
		raw, err := decodeCursor(*cursorArg, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		var state cursorState
		if err := json.Unmarshal([]byte(raw), &state); err != nil {
			return fmt.Errorf("decode cursor state: %w", err)
		}
		if state.LastBlobID != nil {
			lastBlobIDs = state.LastBlobID
		}
	}

	token, err := getAccessToken(tenantID, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	conn := &connector{
		client:      http.DefaultClient,
		accessToken: token,
		tenantID:    tenantID,
		since:       sinceTime,
	}

	ctx := context.Background()
	events, newLastBlobIDs, err := conn.fetchAuditLog(ctx, sinceTime, lastBlobIDs)
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

	// Encode cursor state to stderr.
	stateJSON, err := json.Marshal(cursorState{LastBlobID: newLastBlobIDs})
	if err != nil {
		return fmt.Errorf("encode cursor state: %w", err)
	}
	if len(newLastBlobIDs) > 0 {
		encoded := encodeCursor(string(stateJSON), key)
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
