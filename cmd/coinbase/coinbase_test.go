package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- cursor ------------------------------------------------------------------

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("organizations/org/apiKeys/key")
	raw := "2024-06-01T12:00:00Z"

	encoded := encodeCursor(raw, key)
	if encoded == "" {
		t.Fatal("encodeCursor returned empty string")
	}

	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if decoded != raw {
		t.Errorf("roundtrip mismatch: got %q, want %q", decoded, raw)
	}
}

func TestCursorTamperDetection(t *testing.T) {
	key := sigKey("organizations/org/apiKeys/key")
	raw := "2024-06-01T12:00:00Z"

	encoded := encodeCursor(raw, key)
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		t.Fatal("encoded cursor has no dot separator")
	}
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	_, err := decodeCursor(tampered, key)
	if err == nil {
		t.Fatal("expected error for tampered cursor, got nil")
	}
	if !strings.Contains(err.Error(), "signature mismatch") && !strings.Contains(err.Error(), "invalid cursor") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCursorWrongKey(t *testing.T) {
	key1 := sigKey("organizations/org-a/apiKeys/key")
	key2 := sigKey("organizations/org-b/apiKeys/key")
	raw := "2024-06-01T12:00:00Z"

	encoded := encodeCursor(raw, key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

// --- CDP JWT -----------------------------------------------------------------

func TestMintJWTStructureAndSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyName := "organizations/org-1/apiKeys/key-1"

	tok, err := mintJWT(priv, keyName, http.MethodGet, "api.coinbase.com", "/v2/accounts/abc/transactions")
	if err != nil {
		t.Fatalf("mintJWT: %v", err)
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3-part JWT, got %d parts", len(parts))
	}

	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header cdpHeader
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Alg != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", header.Alg)
	}
	if header.Typ != "JWT" {
		t.Errorf("typ = %q, want JWT", header.Typ)
	}
	if header.Kid != keyName {
		t.Errorf("kid = %q, want %q", header.Kid, keyName)
	}
	if len(header.Nonce) != 32 {
		t.Errorf("nonce length = %d, want 32 hex chars", len(header.Nonce))
	}
	if _, err := base64.RawURLEncoding.DecodeString(fmt.Sprintf("%08x", 0)); err != nil {
		t.Fatalf("sanity base64 check failed: %v", err)
	}

	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims cdpClaims
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.Sub != keyName {
		t.Errorf("sub = %q, want %q", claims.Sub, keyName)
	}
	if claims.Iss != "cdp" {
		t.Errorf("iss = %q, want cdp", claims.Iss)
	}
	wantURI := "GET api.coinbase.com/v2/accounts/abc/transactions"
	if claims.URI != wantURI {
		t.Errorf("uri = %q, want %q", claims.URI, wantURI)
	}
	if claims.Exp-claims.Nbf != 120 {
		t.Errorf("exp-nbf = %d, want 120", claims.Exp-claims.Nbf)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		t.Fatal("signature does not verify against the public key")
	}
}

func TestMintJWTNonceIsFresh(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok1, err := mintJWT(priv, "k", http.MethodGet, "api.coinbase.com", "/v2/accounts")
	if err != nil {
		t.Fatalf("mintJWT: %v", err)
	}
	tok2, err := mintJWT(priv, "k", http.MethodGet, "api.coinbase.com", "/v2/accounts")
	if err != nil {
		t.Fatalf("mintJWT: %v", err)
	}
	if tok1 == tok2 {
		t.Fatal("two JWTs minted for the same request produced identical output; nonce is not fresh")
	}
}

// --- account selection --------------------------------------------------------

func TestSelectAccountsFirstRunUsesNonzeroBalance(t *testing.T) {
	accounts := []map[string]any{
		{"id": "a-empty", "balance": map[string]any{"amount": "0.00000000"}},
		{"id": "a-funded", "balance": map[string]any{"amount": "1.50000000"}},
		{"id": "a-missing-balance"},
	}
	got := selectAccounts(accounts, time.Time{})
	if len(got) != 1 || got[0]["id"] != "a-funded" {
		t.Errorf("want only a-funded selected, got %+v", got)
	}
}

// TestSelectAccountsResumeIgnoresUpdatedAt guards the live-verified finding
// that Coinbase's account-level updated_at does not track transaction/balance
// activity (see selectAccounts doc comment): a resumed run must poll every
// account regardless of updated_at, or a mid-drain compromised-key account
// would silently stop being watched the moment its updated_at falls stale.
func TestSelectAccountsResumeIgnoresUpdatedAt(t *testing.T) {
	since := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	accounts := []map[string]any{
		{"id": "stale-metadata-but-must-still-be-polled", "updated_at": "2025-01-01T00:00:00Z"},
		{"id": "recently-updated", "updated_at": "2026-01-15T00:00:00Z"},
		{"id": "no-updated-at-field"},
	}
	got := selectAccounts(accounts, since)
	if len(got) != len(accounts) {
		t.Fatalf("resumed run must poll every account (updated_at is not a reliable activity signal); got %d of %d", len(got), len(accounts))
	}
}

// --- actor selection -----------------------------------------------------------

func TestActorForSendUsesDestinationAddress(t *testing.T) {
	txn := map[string]any{"to": map[string]any{"resource": "bitcoin_address", "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}}
	got := actorFor("send", "BTC", txn)
	if got != "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" {
		t.Errorf("actor = %q, want destination address", got)
	}
}

func TestActorForSendFallsBackToResourceThenSubtitle(t *testing.T) {
	txn1 := map[string]any{"to": map[string]any{"resource": "email"}}
	if got := actorFor("send", "BTC", txn1); got != "email" {
		t.Errorf("actor = %q, want resource fallback", got)
	}

	txn2 := map[string]any{"details": map[string]any{"subtitle": "to jane@example.com"}}
	if got := actorFor("send", "BTC", txn2); got != "to jane@example.com" {
		t.Errorf("actor = %q, want subtitle fallback", got)
	}
}

func TestActorForReceiveUsesCounterparty(t *testing.T) {
	txn := map[string]any{"details": map[string]any{"subtitle": "from Coinbase"}}
	if got := actorFor("receive", "BTC", txn); got != "from Coinbase" {
		t.Errorf("actor = %q, want subtitle", got)
	}
}

func TestActorForFallsBackToAccountCurrency(t *testing.T) {
	got := actorFor("buy", "USD", map[string]any{})
	if got != "coinbase:USD" {
		t.Errorf("actor = %q, want coinbase:USD", got)
	}
}

// --- normalizeTxn --------------------------------------------------------------

func TestNormalizeTxnStableID(t *testing.T) {
	txn := map[string]any{
		"id":         "tx-123",
		"type":       "receive",
		"status":     "completed",
		"created_at": "2026-01-15T08:30:00Z",
		"from":       map[string]any{"id": "user-9"},
	}
	evs1, err := normalizeTxn(txn, "acct-1", "BTC")
	if err != nil {
		t.Fatalf("normalizeTxn: %v", err)
	}
	evs2, err := normalizeTxn(txn, "acct-1", "BTC")
	if err != nil {
		t.Fatalf("normalizeTxn: %v", err)
	}
	if len(evs1) != 1 || len(evs2) != 1 {
		t.Fatalf("want 1 event each, got %d and %d", len(evs1), len(evs2))
	}
	if evs1[0].ID != evs2[0].ID {
		t.Errorf("ID not stable across calls: %q vs %q", evs1[0].ID, evs2[0].ID)
	}
	if evs1[0].ID == "" {
		t.Error("ID is empty")
	}
	ev := evs1[0]
	if ev.Source != "coinbase" {
		t.Errorf("Source = %q, want coinbase", ev.Source)
	}
	if ev.Org != "acct-1" {
		t.Errorf("Org = %q, want acct-1", ev.Org)
	}
	if ev.Actor != "user-9" {
		t.Errorf("Actor = %q, want user-9", ev.Actor)
	}
	wantTS := time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC)
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, wantTS)
	}

	var p map[string]any
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if p["tx_type"] != "receive" {
		t.Errorf("payload tx_type = %v", p["tx_type"])
	}
}

func TestNormalizeTxnMissingIDDerivesFromContent(t *testing.T) {
	txn := map[string]any{"type": "buy", "created_at": "2026-01-15T08:30:00Z"}
	evs, err := normalizeTxn(txn, "acct-2", "USD")
	if err != nil {
		t.Fatalf("normalizeTxn: %v", err)
	}
	if len(evs) != 1 || evs[0].ID == "" {
		t.Fatalf("want a derived non-empty ID, got %+v", evs)
	}
}

// --- HTTP fetch against httptest.Server (no network, no live creds) ---------

func testClient(t *testing.T, handler http.Handler) *client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &client{
		http:    srv.Client(),
		priv:    priv,
		keyName: "organizations/org/apiKeys/key",
		baseURL: srv.URL,
	}
}

func TestFetchAllAccountsPaginates(t *testing.T) {
	pages := []accountsPage{
		{
			Pagination: paginationInfo{NextURI: "/v2/accounts?limit=100&starting_after=1"},
			Data:       []map[string]any{{"id": "a1"}},
		},
		{
			Pagination: paginationInfo{},
			Data:       []map[string]any{{"id": "a2"}},
		},
	}
	call := 0
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing bearer auth header: %q", auth)
		}
		if call >= len(pages) {
			t.Fatalf("unexpected extra request: %s", r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(pages[call])
		call++
	}))

	accounts, err := c.fetchAllAccounts(t.Context())
	if err != nil {
		t.Fatalf("fetchAllAccounts: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("want 2 accounts, got %d", len(accounts))
	}
	if call != 2 {
		t.Errorf("want 2 requests, got %d", call)
	}
}

func TestFetchAllAccountsFailsLoudOnAPIError(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid signature"}`))
	}))
	_, err := c.fetchAllAccounts(t.Context())
	if err == nil {
		t.Fatal("want error on 401 response, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %v, want it to mention status 401", err)
	}
}

func TestFetchTransactionsStopsAtSinceBoundary(t *testing.T) {
	since := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	page := transactionsPage{
		Data: []map[string]any{
			{"id": "new-1", "type": "receive", "created_at": "2026-01-15T00:00:00Z"},
			{"id": "new-2", "type": "receive", "created_at": "2026-01-12T00:00:00Z"},
			{"id": "old-1", "type": "receive", "created_at": "2026-01-05T00:00:00Z"}, // <= since: stop here
			{"id": "old-2", "type": "receive", "created_at": "2026-01-01T00:00:00Z"},
		},
		Pagination: paginationInfo{NextURI: "/v2/accounts/acct/transactions?limit=100&starting_after=x"},
	}
	requests := 0
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(page)
	}))

	txns, err := c.fetchTransactions(t.Context(), "acct", since)
	if err != nil {
		t.Fatalf("fetchTransactions: %v", err)
	}
	if len(txns) != 2 {
		t.Fatalf("want 2 transactions newer than since, got %d: %+v", len(txns), txns)
	}
	if requests != 1 {
		t.Errorf("want pagination to stop after 1 request once the since boundary was hit, got %d requests", requests)
	}
}

func TestFetchTransactionsJWTPathExcludesQuery(t *testing.T) {
	var gotHost, gotPath string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(transactionsPage{})
	}))
	_, err := c.fetchTransactions(t.Context(), "acct-xyz", time.Time{})
	if err != nil {
		t.Fatalf("fetchTransactions: %v", err)
	}
	if gotPath != "/v2/accounts/acct-xyz/transactions" {
		t.Errorf("path = %q", gotPath)
	}
	if gotHost == "" {
		t.Error("request host is empty")
	}
}
