// Command coinbase polls the Coinbase App API v2 (retail/consumer accounts)
// for wallet transaction history and emits normalized mallcop events as JSONL
// to stdout.
//
// Usage:
//
//	coinbase [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: CDP API key via COINBASE_API_KEY (key name, format
// "organizations/{org}/apiKeys/{key}") and COINBASE_API_SECRET (base64 of a
// 64-byte Ed25519 private key, seed||pubkey — decodes directly to
// crypto/ed25519.PrivateKey). A fresh CDP JWT (EdDSA, "cdp" issuer) is minted
// for every request per Coinbase's short-lived-bearer-token model.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

const (
	cursorMaxLen = 2000
	defaultBase  = "https://api.coinbase.com"
)

// --- cursor: HMAC-signed, copied verbatim from cmd/azure/main.go -----------

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

// sigKey scopes the cursor HMAC key to the CDP key name in use, mirroring
// azure's subscription-id / aws's region scoping — the key name encodes the
// org UUID, so a cursor minted for one Coinbase org can't be replayed against
// another.
func sigKey(keyName string) []byte {
	return []byte(fmt.Sprintf("mallcop-coinbase-cursor:%s", keyName))
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

// --- CDP JWT auth ------------------------------------------------------------

type cdpHeader struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Typ   string `json:"typ"`
	Nonce string `json:"nonce"`
}

type cdpClaims struct {
	Sub string `json:"sub"`
	Iss string `json:"iss"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	URI string `json:"uri"`
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// randomNonce returns 32 hex characters (16 random bytes) as required by the
// CDP JWT header's "nonce" claim.
func randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// mintJWT builds a fresh CDP JWT for a single request. host/path form the
// "uri" claim as "<METHOD> <host><path>" — path only, no query string.
func mintJWT(priv ed25519.PrivateKey, keyName, method, host, path string) (string, error) {
	nonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	header := cdpHeader{Alg: "EdDSA", Kid: keyName, Typ: "JWT", Nonce: nonce}
	claims := cdpClaims{
		Sub: keyName,
		Iss: "cdp",
		Nbf: now,
		Exp: now + 120,
		URI: fmt.Sprintf("%s %s%s", method, host, path),
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}
	signingInput := b64url(hb) + "." + b64url(cb)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + b64url(sig), nil
}

// --- Coinbase App API v2 client ---------------------------------------------

type client struct {
	http    *http.Client
	priv    ed25519.PrivateKey
	keyName string
	baseURL string // e.g. "https://api.coinbase.com"; overridable in tests
}

// get mints a fresh JWT scoped to this request's host+path (query excluded)
// and issues the GET.
func (c *client) get(ctx context.Context, rawPath string) (*http.Response, error) {
	full := c.baseURL + rawPath
	u, err := url.Parse(full)
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", full, err)
	}
	jwt, err := mintJWT(c.priv, c.keyName, http.MethodGet, u.Host, u.Path)
	if err != nil {
		return nil, fmt.Errorf("mint jwt: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	return c.http.Do(req)
}

type paginationInfo struct {
	NextURI string `json:"next_uri"`
}

type accountsPage struct {
	Pagination paginationInfo   `json:"pagination"`
	Data       []map[string]any `json:"data"`
}

type transactionsPage struct {
	Pagination paginationInfo   `json:"pagination"`
	Data       []map[string]any `json:"data"`
}

// fetchAllAccounts pages through GET /v2/accounts until pagination.next_uri
// is exhausted, returning every wallet account on the retail account (~250
// entries, one per currency).
func (c *client) fetchAllAccounts(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	path := "/v2/accounts?limit=100"
	for path != "" {
		resp, err := c.get(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("coinbase API error %d on %s: %s", resp.StatusCode, path, string(body))
		}
		var page accountsPage
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode accounts page: %w", err)
		}
		out = append(out, page.Data...)
		path = page.Pagination.NextURI
	}
	return out, nil
}

// fetchTransactions pages through GET /v2/accounts/{id}/transactions
// (newest-first) and stops — without fetching further pages — the moment it
// sees a transaction at or before `since`. When since is zero, all
// transactions for the account are returned.
func (c *client) fetchTransactions(ctx context.Context, accountID string, since time.Time) ([]map[string]any, error) {
	var out []map[string]any
	path := fmt.Sprintf("/v2/accounts/%s/transactions?limit=100", accountID)
	for path != "" {
		resp, err := c.get(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("coinbase API error %d on %s: %s", resp.StatusCode, path, string(body))
		}
		var page transactionsPage
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode transactions page for account %s: %w", accountID, err)
		}

		stop := false
		for _, txn := range page.Data {
			ts, ok := parseTime(mstr(txn, "created_at"))
			if !ok {
				fmt.Fprintf(os.Stderr, "warn: skipping transaction %v on account %s: bad or missing created_at\n", txn["id"], accountID)
				continue
			}
			if !since.IsZero() && !ts.After(since) {
				// Newest-first order: everything remaining on this and later
				// pages is at least as old, so stop paginating this account.
				stop = true
				break
			}
			out = append(out, txn)
		}
		if stop {
			break
		}
		path = page.Pagination.NextURI
	}
	return out, nil
}

// --- account selection / field helpers --------------------------------------

func mstr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func msub(m map[string]any, k string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return nil
}

func currencyCode(acct map[string]any) string {
	switch v := acct["currency"].(type) {
	case string:
		return v
	case map[string]any:
		if code, ok := v["code"].(string); ok {
			return code
		}
	}
	return ""
}

func hasNonzeroBalance(acct map[string]any) bool {
	amt := mstr(msub(acct, "balance"), "amount")
	if amt == "" {
		return false
	}
	f, err := strconv.ParseFloat(amt, 64)
	if err != nil {
		return false
	}
	return f != 0
}

// selectAccounts decides which of the ~250 per-currency wallet accounts on a
// retail Coinbase account are worth polling for transactions.
//
// DEVIATION FROM THE ORIGINAL DESIGN, LIVE-VERIFIED: the obvious cost-saving
// filter — skip accounts whose account-level `updated_at` is older than our
// resume mark — does NOT work against the real API. Probed live against the
// 3dl Coinbase retail account on 2026-07-11: the USDC wallet has received
// recurring "interest" transactions through 2026-07-09 (a balance-changing
// transaction), yet GET /v2/accounts/{id} still reports
// updated_at=2026-04-16T16:12:10Z — the account's creation time, frozen ever
// since. The field tracks account metadata, not transaction/balance activity.
//
// Filtering resumed-run polling by updated_at would therefore silently stop
// checking every account after its first cycle — including, worst case, an
// account mid-drain from a compromised key, which is the #1 scenario this
// connector exists to catch (see actorFor: a send's destination address is
// the new-actor signal). A filter that can hide that is worse than no filter.
//
// So: on a resumed run (since non-zero) we do NOT prune by updated_at — every
// account is polled, but fetchTransactions still stops after the first page
// once it hits a transaction at or before `since`, so a dormant account costs
// exactly one GET request per run, not one HTTP round-trip per historical
// page. Only on a first-ever run (since zero: no cursor, no --since) do we
// apply the nonzero-balance shortcut — safe there because it only bounds
// how much history we backfill for wallets that have never held currency,
// not whether we keep watching an account going forward.
func selectAccounts(accounts []map[string]any, since time.Time) []map[string]any {
	if !since.IsZero() {
		return accounts
	}
	var out []map[string]any
	for _, a := range accounts {
		if hasNonzeroBalance(a) {
			out = append(out, a)
		}
	}
	return out
}

// actorFor picks the mallcop Actor for a transaction. Outgoing sends use the
// destination — a withdrawal to a never-seen address is the #1 signal of a
// compromised-key theft pattern and must feed the new-actor detector.
// Everything else uses the counterparty from details/from, falling back to
// the account's own currency identity.
func actorFor(txType, currency string, txn map[string]any) string {
	details := msub(txn, "details")
	to := msub(txn, "to")
	from := msub(txn, "from")

	if txType == "send" {
		if addr := mstr(to, "address"); addr != "" {
			return addr
		}
		if res := mstr(to, "resource"); res != "" {
			return res
		}
		if sub := mstr(details, "subtitle"); sub != "" {
			return sub
		}
	}

	if sub := mstr(details, "subtitle"); sub != "" {
		return sub
	}
	if id := mstr(from, "id"); id != "" {
		return id
	}
	if res := mstr(from, "resource"); res != "" {
		return res
	}
	return "coinbase:" + currency
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// normalizeTxn maps a raw transaction to one or more mallcop events. The
// canonical Type and detector-readable Payload come from the shared
// normalize library.
func normalizeTxn(txn map[string]any, accountID, currency string) ([]*event.Event, error) {
	txnID := mstr(txn, "id")
	txType := mstr(txn, "type")
	ts, ok := parseTime(mstr(txn, "created_at"))
	if !ok {
		ts = time.Now().UTC()
	}
	actor := actorFor(txType, currency, txn)

	idSrc := "coinbase:" + txnID
	if txnID == "" {
		idSrc = fmt.Sprintf("coinbase:%s:%s:%d", accountID, txType, ts.UnixNano())
	}
	baseID := sha256Hex(idSrc)

	results := normalize.Coinbase(txType, txn)
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
			Source:    "coinbase",
			Type:      r.Type,
			Actor:     actor,
			Timestamp: ts,
			Org:       accountID,
			Payload:   payload,
		})
	}
	return out, nil
}

func run() error {
	var (
		since     = flag.String("since", "", "RFC3339 timestamp to filter transactions (e.g. 2024-01-01T00:00:00Z)")
		cursorArg = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	)
	flag.Parse()

	keyName := os.Getenv("COINBASE_API_KEY")
	secretB64 := os.Getenv("COINBASE_API_SECRET")
	if keyName == "" || secretB64 == "" {
		return fmt.Errorf("COINBASE_API_KEY and COINBASE_API_SECRET must be set")
	}

	secretRaw, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return fmt.Errorf("decode COINBASE_API_SECRET: %w", err)
	}
	if len(secretRaw) != ed25519.PrivateKeySize {
		return fmt.Errorf("COINBASE_API_SECRET must base64-decode to a %d-byte Ed25519 private key, got %d bytes", ed25519.PrivateKeySize, len(secretRaw))
	}
	priv := ed25519.PrivateKey(secretRaw)

	var sinceTime time.Time
	if *since != "" {
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(keyName)
	var cursorMark time.Time
	if *cursorArg != "" {
		raw, err := decodeCursor(*cursorArg, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		cursorMark, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: bad payload: %w", err)
		}
	}

	// The cursor, when present, is the exact high-water mark of the newest
	// transaction previously emitted — more precise than --since on resume,
	// so it takes precedence.
	effectiveSince := sinceTime
	if !cursorMark.IsZero() {
		effectiveSince = cursorMark
	}

	cl := &client{http: http.DefaultClient, priv: priv, keyName: keyName, baseURL: defaultBase}

	ctx := context.Background()
	accounts, err := cl.fetchAllAccounts(ctx)
	if err != nil {
		return fmt.Errorf("fetch accounts: %w", err)
	}

	var events []*event.Event
	newest := cursorMark // carry the prior high-water mark forward by default
	for _, acct := range selectAccounts(accounts, effectiveSince) {
		acctID := mstr(acct, "id")
		if acctID == "" {
			continue
		}
		currency := currencyCode(acct)
		txns, err := cl.fetchTransactions(ctx, acctID, effectiveSince)
		if err != nil {
			return fmt.Errorf("fetch transactions for account %s: %w", acctID, err)
		}
		for _, txn := range txns {
			evs, err := normalizeTxn(txn, acctID, currency)
			if err != nil {
				return fmt.Errorf("normalize transaction: %w", err)
			}
			events = append(events, evs...)
			if len(evs) > 0 && evs[0].Timestamp.After(newest) {
				newest = evs[0].Timestamp
			}
		}
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	if !newest.IsZero() {
		encoded := encodeCursor(newest.UTC().Format(time.RFC3339), key)
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
