// Command mercury polls the Mercury Bank API for account transaction activity
// and emits normalized mallcop events as JSONL to stdout.
//
// Usage:
//
//	mercury [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: MERCURY_API_TOKEN (Bearer token, format "secret-token:...").
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
	"strconv"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const cursorMaxLen = 200

// apiBase, pageLimit and maxPages are vars (not consts) so tests can point
// the connector at an httptest.Server and shrink pagination limits to
// exercise pagination edges without waiting on hundreds of fake pages.
// pageLimit is the page size requested per /transactions call. maxPages is a
// safety cap on pagination for a single account: if the upstream API ever
// returns a full page forever (offset ignored, a stuck cursor, etc.) this
// stops the connector from looping instead of hanging indefinitely.
var (
	apiBase   = "https://api.mercury.com/api/v1"
	pageLimit = 500
	maxPages  = 1000
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

// sigKey derives the cursor HMAC key from the Mercury API token itself: there
// is no non-secret tenant identifier available (unlike Azure's subscription ID
// or Okta's domain), and the token is never echoed back, so it doubles safely
// as key material scoped to this one Mercury workspace.
func sigKey(token string) []byte {
	return []byte(fmt.Sprintf("mallcop-mercury-cursor:%s", token))
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

// mercuryAccount is a subset of the GET /accounts response.
type mercuryAccount struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

type accountsResponse struct {
	Accounts []mercuryAccount `json:"accounts"`
}

// transactionsResponse is the GET /account/{id}/transactions response.
// Transactions are decoded as raw maps (not a typed struct) so the full record
// flows unmodified into normalize.Mercury and into the "raw" payload field.
type transactionsResponse struct {
	Total        int              `json:"total"`
	Transactions []map[string]any `json:"transactions"`
}

// afterFloor reports whether ts should be emitted given the effective floor
// timestamp. When strict, the floor is a resume cursor high-water mark and ts
// must be strictly newer (excludes the boundary, since the boundary was
// already emitted on a prior run). When not strict, the floor came from
// --since and is inclusive (ts >= floor), matching every other connector's
// --since semantics.
func afterFloor(ts, floor time.Time, strict bool) bool {
	if floor.IsZero() {
		return true
	}
	if strict {
		return ts.After(floor)
	}
	return !ts.Before(floor)
}

// parseTxnTimestamp returns the transaction's postedAt, falling back to
// createdAt when postedAt is absent, per the connector contract.
func parseTxnTimestamp(txn map[string]any) (time.Time, error) {
	for _, key := range []string{"postedAt", "createdAt"} {
		s, ok := txn[key].(string)
		if !ok || s == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			continue
		}
		return ts.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("transaction missing a parsable postedAt/createdAt timestamp")
}

// normalizeTxn maps a raw Mercury transaction to one or more mallcop events.
// ts is the already-parsed transaction timestamp (see parseTxnTimestamp) so
// callers that also need ts for --since/cursor filtering only parse it once.
func normalizeTxn(txn map[string]any, accountID string, ts time.Time) ([]*event.Event, error) {
	actor, _ := txn["counterpartyName"].(string)
	kind, _ := txn["kind"].(string)

	txnID, _ := txn["id"].(string)
	idSrc := "mercury:" + txnID
	if txnID == "" {
		idSrc = fmt.Sprintf("mercury:%s:%d", accountID, ts.UnixNano())
	}
	baseID := sha256Hex(idSrc)

	results := normalize.Mercury(kind, txn)
	out := make([]*event.Event, 0, len(results))
	for i, r := range results {
		payload, err := r.PayloadJSON(txn)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		id := baseID
		if i > 0 {
			id = sha256Hex(fmt.Sprintf("%s:%d", idSrc, i))
		}
		out = append(out, &event.Event{
			ID:        id,
			Source:    "mercury",
			Type:      r.Type,
			Actor:     actor,
			Timestamp: ts,
			Org:       accountID,
			Payload:   payload,
		})
	}
	return out, nil
}

type connector struct {
	client *http.Client
	token  string
}

func (c *connector) get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	return c.client.Do(req)
}

func (c *connector) fetchAccounts(ctx context.Context) ([]mercuryAccount, error) {
	u := apiBase + "/accounts"
	resp, err := c.get(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Mercury API error %d: %s", resp.StatusCode, string(body))
	}

	var out accountsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode accounts response: %w", err)
	}
	return out.Accounts, nil
}

// fetchAccountTransactions pages through GET /account/{id}/transactions. The
// endpoint has no hasMore/next-cursor field: a page shorter than the
// requested limit signals the last page, matching the shape verified live
// against the Mercury API. maxPages is a hard stop against a runaway loop if
// that assumption is ever wrong upstream.
func (c *connector) fetchAccountTransactions(ctx context.Context, accountID string, floor time.Time) ([]map[string]any, error) {
	u := fmt.Sprintf("%s/account/%s/transactions", apiBase, accountID)

	var all []map[string]any
	offset := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("exceeded max pages (%d) polling account %s transactions — possible pagination loop", maxPages, accountID)
		}

		params := url.Values{
			"limit":  {strconv.Itoa(pageLimit)},
			"offset": {strconv.Itoa(offset)},
		}
		if !floor.IsZero() {
			params.Set("start", floor.UTC().Format(time.RFC3339))
		}

		resp, err := c.get(ctx, u+"?"+params.Encode())
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", u, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("Mercury API error %d: %s", resp.StatusCode, string(body))
		}

		var tr transactionsResponse
		if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode transactions response: %w", err)
		}
		resp.Body.Close()

		all = append(all, tr.Transactions...)

		if len(tr.Transactions) < pageLimit {
			break
		}
		offset += pageLimit
	}

	return all, nil
}

func run() error {
	var (
		since     = flag.String("since", "", "RFC3339 timestamp to filter transactions (e.g. 2024-01-01T00:00:00Z)")
		cursorArg = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	)
	flag.Parse()

	token := os.Getenv("MERCURY_API_TOKEN")
	if token == "" {
		return fmt.Errorf("MERCURY_API_TOKEN must be set")
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(token)
	var cursorMark time.Time
	if *cursorArg != "" {
		rawCursor, err := decodeCursor(*cursorArg, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		cursorMark, err = time.Parse(time.RFC3339Nano, rawCursor)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: bad timestamp %q: %w", rawCursor, err)
		}
	}

	// The cursor high-water mark wins (strict, excludes the boundary already
	// emitted) unless --since names a point strictly after it, in which case
	// --since wins (inclusive), matching the contract's independent
	// "--since is >=" / "cursor is strictly newer" semantics.
	floor := sinceTime
	strict := false
	if !cursorMark.IsZero() && (sinceTime.IsZero() || !sinceTime.After(cursorMark)) {
		floor = cursorMark
		strict = true
	}

	conn := &connector{client: http.DefaultClient, token: token}
	ctx := context.Background()

	accounts, err := conn.fetchAccounts(ctx)
	if err != nil {
		return fmt.Errorf("fetch accounts: %w", err)
	}

	var allEvents []*event.Event
	var maxSeen time.Time

	for _, acct := range accounts {
		txns, err := conn.fetchAccountTransactions(ctx, acct.ID, floor)
		if err != nil {
			return fmt.Errorf("fetch transactions for account %s: %w", acct.ID, err)
		}

		for _, txn := range txns {
			ts, err := parseTxnTimestamp(txn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping transaction: %v\n", err)
				continue
			}
			if !afterFloor(ts, floor, strict) {
				continue
			}

			evs, err := normalizeTxn(txn, acct.ID, ts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping transaction: %v\n", err)
				continue
			}
			allEvents = append(allEvents, evs...)
			if ts.After(maxSeen) {
				maxSeen = ts
			}
		}
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range allEvents {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	if !maxSeen.IsZero() && maxSeen.After(cursorMark) {
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
