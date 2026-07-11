package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

// --- cursor -----------------------------------------------------------------

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("secret-token:abc123")
	raw := "2026-07-09T12:38:07.606142Z"

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
	key := sigKey("secret-token:abc123")
	raw := "2026-07-09T12:38:07.606142Z"

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
	key1 := sigKey("secret-token:aaa")
	key2 := sigKey("secret-token:bbb")
	raw := "2026-07-09T12:38:07.606142Z"

	encoded := encodeCursor(raw, key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

// --- afterFloor ---------------------------------------------------------------

func TestAfterFloorNoFloor(t *testing.T) {
	if !afterFloor(time.Now(), time.Time{}, false) {
		t.Error("zero floor should always pass")
	}
	if !afterFloor(time.Now(), time.Time{}, true) {
		t.Error("zero floor should always pass, even strict")
	}
}

func TestAfterFloorSinceIsInclusive(t *testing.T) {
	floor := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if !afterFloor(floor, floor, false) {
		t.Error("--since floor should be inclusive (>=)")
	}
	if afterFloor(floor.Add(-time.Second), floor, false) {
		t.Error("timestamp before the since floor must be excluded")
	}
}

func TestAfterFloorCursorIsStrict(t *testing.T) {
	floor := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if afterFloor(floor, floor, true) {
		t.Error("cursor high-water mark must be exclusive (>) — it was already emitted")
	}
	if !afterFloor(floor.Add(time.Second), floor, true) {
		t.Error("timestamp strictly after the cursor mark must be included")
	}
}

// --- parseTxnTimestamp -------------------------------------------------------

func TestParseTxnTimestampPrefersPostedAt(t *testing.T) {
	txn := map[string]any{
		"createdAt": "2026-07-09T05:01:47.468704Z",
		"postedAt":  "2026-07-09T12:38:07.606142Z",
	}
	ts, err := parseTxnTimestamp(txn)
	if err != nil {
		t.Fatalf("parseTxnTimestamp: %v", err)
	}
	want := time.Date(2026, 7, 9, 12, 38, 7, 606142000, time.UTC)
	if !ts.Equal(want) {
		t.Errorf("ts = %v, want %v", ts, want)
	}
}

func TestParseTxnTimestampFallsBackToCreatedAt(t *testing.T) {
	txn := map[string]any{"createdAt": "2026-07-09T05:01:47Z"}
	ts, err := parseTxnTimestamp(txn)
	if err != nil {
		t.Fatalf("parseTxnTimestamp: %v", err)
	}
	want := time.Date(2026, 7, 9, 5, 1, 47, 0, time.UTC)
	if !ts.Equal(want) {
		t.Errorf("ts = %v, want %v", ts, want)
	}
}

func TestParseTxnTimestampMissingBothErrors(t *testing.T) {
	_, err := parseTxnTimestamp(map[string]any{})
	if err == nil {
		t.Fatal("expected error when postedAt/createdAt are both absent")
	}
}

// --- normalizeTxn -------------------------------------------------------------

func TestNormalizeTxn(t *testing.T) {
	txn := map[string]any{
		"id":               "49be14f4-7b53-11f1-a102-35930b8d3d6b",
		"amount":           -70.01,
		"kind":             "debitCardTransaction",
		"counterpartyName": "Microsoft",
		"postedAt":         "2026-07-09T12:38:07.606142Z",
	}
	ts, err := parseTxnTimestamp(txn)
	if err != nil {
		t.Fatalf("parseTxnTimestamp: %v", err)
	}

	evs, err := normalizeTxn(txn, "acct-123", ts)
	if err != nil {
		t.Fatalf("normalizeTxn: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

	if ev.Source != "mercury" {
		t.Errorf("Source = %q, want mercury", ev.Source)
	}
	if ev.Type != normalize.CatchAll {
		t.Errorf("Type = %q, want %q", ev.Type, normalize.CatchAll)
	}
	if ev.Actor != "Microsoft" {
		t.Errorf("Actor = %q, want Microsoft (the counterparty)", ev.Actor)
	}
	if ev.Org != "acct-123" {
		t.Errorf("Org = %q, want acct-123", ev.Org)
	}
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, ts)
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}

	var p map[string]any
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if p["direction"] != "outgoing" {
		t.Errorf("payload direction = %v, want outgoing", p["direction"])
	}

	// Schema roundtrip, mirroring azure_test.go's coverage.
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded event.Event
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ID != ev.ID {
		t.Errorf("ID mismatch: got %q, want %q", decoded.ID, ev.ID)
	}
}

func TestNormalizeTxnMissingIDDerivesStableFallback(t *testing.T) {
	txn := map[string]any{"amount": 1.0, "kind": "fee"}
	ts := time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC)

	evs1, err := normalizeTxn(txn, "acct-123", ts)
	if err != nil {
		t.Fatalf("normalizeTxn: %v", err)
	}
	evs2, err := normalizeTxn(txn, "acct-123", ts)
	if err != nil {
		t.Fatalf("normalizeTxn: %v", err)
	}
	if evs1[0].ID != evs2[0].ID {
		t.Error("ID must be stable/deterministic for the same input")
	}
}

// --- HTTP: accounts + paginated transactions ---------------------------------

func TestFetchAccounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"accounts":[{"id":"acct-1","name":"Checking","kind":"checking","status":"active"}]}`)
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), token: "test-token"}
	origBase := apiBaseOverride(srv.URL)
	defer origBase()

	accounts, err := conn.fetchAccounts(context.Background())
	if err != nil {
		t.Fatalf("fetchAccounts: %v", err)
	}
	if len(accounts) != 1 || accounts[0].ID != "acct-1" {
		t.Fatalf("accounts = %+v", accounts)
	}
}

func TestFetchAccountsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":{"message":"no matching token found"}}`)
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), token: "bad-token"}
	defer apiBaseOverride(srv.URL)()

	_, err := conn.fetchAccounts(context.Background())
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status code: %v", err)
	}
}

// TestFetchAccountTransactionsPaginates verifies offset-based pagination
// assembles all pages and stops on the first short page (no hasMore field
// exists on this endpoint — a page shorter than the requested limit is the
// only termination signal).
func TestFetchAccountTransactionsPaginates(t *testing.T) {
	origLimit, origMax := pageLimit, maxPages
	pageLimit = 2
	maxPages = 10
	defer func() { pageLimit, maxPages = origLimit, origMax }()

	allIDs := []string{"t1", "t2", "t3", "t4", "t5"}
	var gotOffsets []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotOffsets = append(gotOffsets, q.Get("offset"))
		if q.Get("limit") != "2" {
			t.Errorf("limit = %q, want 2", q.Get("limit"))
		}
		offset, _ := strconv.Atoi(q.Get("offset"))

		var page []map[string]any
		end := offset + 2
		if end > len(allIDs) {
			end = len(allIDs)
		}
		for _, id := range allIDs[offset:end] {
			page = append(page, map[string]any{"id": id})
		}
		b, _ := json.Marshal(map[string]any{"total": len(page), "transactions": page})
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), token: "test-token"}
	defer apiBaseOverride(srv.URL)()

	txns, err := conn.fetchAccountTransactions(context.Background(), "acct-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchAccountTransactions: %v", err)
	}
	if len(txns) != len(allIDs) {
		t.Fatalf("got %d transactions, want %d", len(txns), len(allIDs))
	}
	if len(gotOffsets) != 3 {
		t.Fatalf("expected 3 page requests (2+2+1), got %d: %v", len(gotOffsets), gotOffsets)
	}
	if gotOffsets[0] != "0" || gotOffsets[1] != "2" || gotOffsets[2] != "4" {
		t.Errorf("unexpected offset sequence: %v", gotOffsets)
	}
}

// TestFetchAccountTransactionsStopsOnRunawayPagination guards against an
// upstream bug where every page comes back full (e.g. offset silently
// ignored): the connector must fail loud with a bounded number of requests
// instead of looping forever.
func TestFetchAccountTransactionsStopsOnRunawayPagination(t *testing.T) {
	origLimit, origMax := pageLimit, maxPages
	pageLimit = 2
	maxPages = 3
	defer func() { pageLimit, maxPages = origLimit, origMax }()

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		// Always return a full page, regardless of offset — simulates a
		// broken/looping upstream.
		page := []map[string]any{{"id": "dup-1"}, {"id": "dup-2"}}
		b, _ := json.Marshal(map[string]any{"total": 2, "transactions": page})
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), token: "test-token"}
	defer apiBaseOverride(srv.URL)()

	_, err := conn.fetchAccountTransactions(context.Background(), "acct-1", time.Time{})
	if err == nil {
		t.Fatal("expected an error when pagination never terminates, got nil")
	}
	if !strings.Contains(err.Error(), "max pages") {
		t.Errorf("error should mention the max-pages safety cap: %v", err)
	}
	if requests != maxPages {
		t.Errorf("expected exactly %d requests before bailing, got %d", maxPages, requests)
	}
}

func TestFetchAccountTransactionsSendsStartParam(t *testing.T) {
	floor := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	var gotStart string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotStart = r.URL.Query().Get("start")
		fmt.Fprint(w, `{"total":0,"transactions":[]}`)
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), token: "test-token"}
	defer apiBaseOverride(srv.URL)()

	if _, err := conn.fetchAccountTransactions(context.Background(), "acct-1", floor); err != nil {
		t.Fatalf("fetchAccountTransactions: %v", err)
	}
	if gotStart != floor.Format(time.RFC3339) {
		t.Errorf("start param = %q, want %q", gotStart, floor.Format(time.RFC3339))
	}
}

// --- test plumbing ------------------------------------------------------------

// apiBaseOverride points the package-level apiBase var at a test server for
// the duration of the caller's test, restoring the original value on return.
func apiBaseOverride(base string) func() {
	orig := apiBase
	apiBase = base
	return func() { apiBase = orig }
}
