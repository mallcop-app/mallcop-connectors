// Command azure polls Azure Monitor Activity Logs via the REST API
// and emits normalized mallcop events as JSONL to stdout.
//
// Usage:
//
//	azure --subscription-id <id> [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: service principal via AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.
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
	tokenEndpointFn = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	activityLogBase = "https://management.azure.com/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values"
	apiVersion      = "2015-04-01"
)

var cursorRE = regexp.MustCompile(`^[A-Za-z0-9+/=_\-&?%:.]+$`)

func validateCursor(cursor string) error {
	if len(cursor) > cursorMaxLen {
		return fmt.Errorf("invalid cursor: length %d exceeds maximum %d", len(cursor), cursorMaxLen)
	}
	if strings.ContainsAny(cursor, "\n\r\x00") {
		return fmt.Errorf("invalid cursor: contains control characters")
	}
	return nil
}

func sigKey(subscriptionID string) []byte {
	return []byte(fmt.Sprintf("mallcop-azure-cursor:%s", subscriptionID))
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

type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func getAccessToken(tenantID, clientID, clientSecret string) (string, error) {
	tokenURL := fmt.Sprintf(tokenEndpointFn, tenantID)
	vals := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://management.azure.com/.default"},
	}
	resp, err := http.PostForm(tokenURL, vals)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token error %d: %s", resp.StatusCode, string(body))
	}
	var tr azureTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	return tr.AccessToken, nil
}

// activityLogEntry represents a single Azure Activity Log entry (subset of fields).
type activityLogEntry struct {
	ID            string `json:"id"`
	OperationName struct {
		Value string `json:"value"`
	} `json:"operationName"`
	Caller    string `json:"caller"`
	EventName struct {
		Value string `json:"value"`
	} `json:"eventName"`
	EventTimestamp string `json:"eventTimestamp"`
	Status         struct {
		Value string `json:"value"`
	} `json:"status"`
}

func normalizeEntry(entry map[string]interface{}, subscriptionID string) (*event.Event, error) {
	payload, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}

	// Extract caller (actor).
	actor, _ := entry["caller"].(string)

	// Extract operation name as event type.
	eventType := ""
	if opName, ok := entry["operationName"].(map[string]interface{}); ok {
		eventType, _ = opName["value"].(string)
	}

	// Parse timestamp.
	ts := time.Now().UTC()
	if tsStr, ok := entry["eventTimestamp"].(string); ok && tsStr != "" {
		var err error
		ts, err = time.Parse(time.RFC3339, tsStr)
		if err != nil {
			// Try with nanoseconds.
			ts, err = time.Parse("2006-01-02T15:04:05.9999999Z", tsStr)
			if err != nil {
				log.Printf("warn: failed to parse eventTimestamp %q: %v", tsStr, err)
				ts = time.Now().UTC()
			}
		}
	}

	// Build ID from the Azure event ID or derive from content.
	idStr := ""
	if id, ok := entry["id"].(string); ok && id != "" {
		idStr = "azure:" + id
	} else {
		idStr = fmt.Sprintf("azure:%s:%s:%d", subscriptionID, eventType, ts.UnixNano())
	}

	return &event.Event{
		ID:        sha256Hex(idStr),
		Source:    "azure",
		Type:      eventType,
		Actor:     actor,
		Timestamp: ts,
		Org:       subscriptionID,
		Payload:   json.RawMessage(payload),
	}, nil
}

type activityLogResponse struct {
	Value    []map[string]interface{} `json:"value"`
	NextLink string                   `json:"nextLink"`
}

type connector struct {
	client         *http.Client
	accessToken    string
	subscriptionID string
	since          time.Time
	nextLink       string // raw nextLink cursor
}

func (c *connector) get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	return c.client.Do(req)
}

func (c *connector) fetchActivityLog(ctx context.Context) ([]*event.Event, string, error) {
	var firstURL string
	if c.nextLink != "" {
		// Resume from cursor.
		firstURL = c.nextLink
	} else {
		u := fmt.Sprintf(activityLogBase, c.subscriptionID)
		params := url.Values{"api-version": {apiVersion}}
		if !c.since.IsZero() {
			filter := fmt.Sprintf("eventTimestamp ge '%s'", c.since.UTC().Format(time.RFC3339))
			params.Set("$filter", filter)
		}
		firstURL = u + "?" + params.Encode()
	}

	var allEvents []*event.Event
	lastNextLink := ""
	currentURL := firstURL

	for {
		resp, err := c.get(ctx, currentURL)
		if err != nil {
			return nil, "", fmt.Errorf("GET %s: %w", currentURL, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, "", fmt.Errorf("Azure API error %d: %s", resp.StatusCode, string(body))
		}

		var result activityLogResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, "", fmt.Errorf("decode response: %w", err)
		}
		resp.Body.Close()

		for _, entry := range result.Value {
			ev, err := normalizeEntry(entry, c.subscriptionID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping entry: %v\n", err)
				continue
			}
			allEvents = append(allEvents, ev)
		}

		if result.NextLink == "" {
			break
		}
		lastNextLink = result.NextLink
		currentURL = result.NextLink
	}

	return allEvents, lastNextLink, nil
}

func run() error {
	var (
		subscriptionID = flag.String("subscription-id", "", "Azure subscription ID")
		since          = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursorArg      = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	)
	flag.Parse()

	if *subscriptionID == "" {
		*subscriptionID = os.Getenv("AZURE_SUBSCRIPTION_ID")
	}
	if *subscriptionID == "" {
		return fmt.Errorf("--subscription-id or AZURE_SUBSCRIPTION_ID is required")
	}

	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return fmt.Errorf("AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET must be set")
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(*subscriptionID)
	rawCursor := ""
	if *cursorArg != "" {
		var err error
		rawCursor, err = decodeCursor(*cursorArg, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
	}

	token, err := getAccessToken(tenantID, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	conn := &connector{
		client:         http.DefaultClient,
		accessToken:    token,
		subscriptionID: *subscriptionID,
		since:          sinceTime,
		nextLink:       rawCursor,
	}

	ctx := context.Background()
	events, nextLink, err := conn.fetchActivityLog(ctx)
	if err != nil {
		return fmt.Errorf("fetch activity log: %w", err)
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	if nextLink != "" {
		encoded := encodeCursor(nextLink, key)
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
