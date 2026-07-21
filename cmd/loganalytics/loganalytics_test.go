package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// queryBaseOverride points the package-level queryBase var at a test server
// for the duration of the returned restore func (mirrors cmd/azure's
// activityLogBaseOverride idiom).
func queryBaseOverride(serverURL string) func() {
	orig := queryBase
	queryBase = serverURL + "/v1/workspaces/%s/query"
	return func() { queryBase = orig }
}

// --- cursor roundtrip / tamper detection (byte-identical pattern to cmd/azure) ---

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("ws-12345")
	raw := "2026-07-20T15:10:18.7459745Z"

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
	key := sigKey("ws-abc")
	raw := "2026-07-20T15:10:18Z"

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
}

func TestCursorWrongKey(t *testing.T) {
	key1 := sigKey("ws-aaa")
	key2 := sigKey("ws-bbb")
	raw := "2026-07-20T15:10:18Z"

	encoded := encodeCursor(raw, key1)
	if _, err := decodeCursor(encoded, key2); err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

// --- resolveFloor ---

func TestResolveFloorSinceOnly(t *testing.T) {
	key := sigKey("ws-x")
	since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	floor, err := resolveFloor("", since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(since) {
		t.Errorf("floor = %v, want %v", floor, since)
	}
}

func TestResolveFloorCursorLaterThanSinceWins(t *testing.T) {
	key := sigKey("ws-y")
	since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cursorTime := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	cursor := encodeCursor(cursorTime.Format(time.RFC3339Nano), key)

	floor, err := resolveFloor(cursor, since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(cursorTime) {
		t.Errorf("floor = %v, want cursor time %v (later of the two)", floor, cursorTime)
	}
}

func TestResolveFloorTamperedCursorHardFails(t *testing.T) {
	key := sigKey("ws-tamper")
	encoded := encodeCursor("2026-07-20T15:10:18Z", key)
	parts := strings.SplitN(encoded, ".", 2)
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	_, err := resolveFloor(tampered, time.Time{}, key)
	if err == nil {
		t.Fatal("expected hard failure for tampered cursor, got nil")
	}
}

func TestResolveFloorNonTimestampCursorHardFails(t *testing.T) {
	// Unlike cmd/azure, this connector's cursor has always only ever been a
	// timestamp (no legacy pagination-token format to migrate from), so a
	// non-timestamp HMAC-valid payload is just a bad cursor, not a
	// self-healing legacy case.
	key := sigKey("ws-nonts")
	encoded := encodeCursor("not-a-timestamp", key)
	_, err := resolveFloor(encoded, time.Time{}, key)
	if err == nil {
		t.Fatal("expected error for a non-timestamp cursor payload, got nil")
	}
}

// --- query: timespan is the ONLY thing that varies; KQL text is constant ---

func TestQueryOmitsTimespanWhenFloorZero(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lawQueryResponse{Tables: []lawTable{{Name: "PrimaryResult"}}})
	}))
	defer srv.Close()
	defer queryBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), accessToken: "tok", workspaceID: "ws-1"}
	if _, err := conn.query(context.Background(), time.Time{}); err != nil {
		t.Fatalf("query: %v", err)
	}
	if gotBody["query"] != kqlQuery {
		t.Errorf("query body's KQL text was not the constant kqlQuery verbatim: %v", gotBody["query"])
	}
	if _, ok := gotBody["timespan"]; ok {
		t.Errorf("timespan should be omitted when floor is zero, got %v", gotBody["timespan"])
	}
}

func TestQuerySetsTimespanFromFloorNeverInterpolatesKQL(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lawQueryResponse{Tables: []lawTable{{Name: "PrimaryResult"}}})
	}))
	defer srv.Close()
	defer queryBaseOverride(srv.URL)()

	floor := time.Date(2026, 7, 20, 15, 0, 0, 0, time.UTC)
	conn := &connector{client: srv.Client(), accessToken: "tok", workspaceID: "ws-2"}
	if _, err := conn.query(context.Background(), floor); err != nil {
		t.Fatalf("query: %v", err)
	}
	// The KQL text itself must be byte-identical to the constant regardless
	// of the floor value — the floor only ever reaches the request as the
	// separate "timespan" field, never concatenated/formatted into "query".
	if gotBody["query"] != kqlQuery {
		t.Errorf("query body's KQL text changed based on floor — got %v, want the constant kqlQuery unchanged", gotBody["query"])
	}
	ts, ok := gotBody["timespan"].(string)
	if !ok || !strings.HasPrefix(ts, "2026-07-20T15:00:00Z/") {
		t.Errorf("timespan = %v, want to start with 2026-07-20T15:00:00Z/", gotBody["timespan"])
	}
	if strings.Contains(kqlQuery, "2026-07-20") {
		t.Fatal("kqlQuery constant must never itself contain a floor timestamp")
	}
}

// --- processTable: parses the REAL captured fixture (mallcoppro-9701 live proof capture) ---

func loadFixture(t *testing.T, path string) lawQueryResponse {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var resp lawQueryResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
	return resp
}

// TestProcessTableRealCapturedUnauthorizedWriterFixture is the TDD anchor for
// mallcoppro-9701's live proof: this fixture is a byte-for-byte capture of a
// REAL query response from law-nostr-relay-prod (obtained via an operator
// `az account get-access-token --resource https://api.loganalytics.io` token
// against workspace 792ec658-bdd2-4c8d-858b-d5ca1d1a28db, 2026-07-21) — the
// mallcoppro-813 unauthorized-write probe row
// (pubkey 6a808ff3d28f55bf4554c9af244bd8b45a0c4dc7031dc4a2c59b49b8c59468f3,
// decision=unauthorized_writer, ~2026-07-20T15:10Z). It is NOT hand-written.
func TestProcessTableRealCapturedUnauthorizedWriterFixture(t *testing.T) {
	resp := loadFixture(t, "../../internal/normalize/testdata/law_unauthorized_writer_response.json")
	if len(resp.Tables) != 1 {
		t.Fatalf("want 1 table in fixture, got %d", len(resp.Tables))
	}

	events, maxSeen, err := processTable(resp.Tables[0], "org-test")
	if err != nil {
		t.Fatalf("processTable: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 normalized event from the real fixture, got %d", len(events))
	}
	ev := events[0]

	if ev.Type != "login_failure" {
		t.Errorf("Type = %q, want login_failure (the auth-failure-burst gate literal)", ev.Type)
	}
	if ev.Actor != "6a808ff3d28f55bf4554c9af244bd8b45a0c4dc7031dc4a2c59b49b8c59468f3" {
		t.Errorf("Actor = %q, want the probe pubkey", ev.Actor)
	}
	if ev.Source != "loganalytics" {
		t.Errorf("Source = %q, want loganalytics", ev.Source)
	}
	wantTS := time.Date(2026, 7, 20, 15, 10, 18, 745974500, time.UTC)
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, wantTS)
	}
	if maxSeen.IsZero() {
		t.Error("maxSeen is zero, want the row's TimeGenerated")
	}

	var p map[string]any
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if p["ip"] != "100.0.2.229" {
		t.Errorf("payload ip = %v, want 100.0.2.229", p["ip"])
	}
	if p["reason"] != "restricted: pubkey is not admitted to this relay's tenant write-allowlist" {
		t.Errorf("payload reason = %v", p["reason"])
	}
	raw, ok := p["raw"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing raw sub-object: %+v", p)
	}
	if raw["decision"] != "unauthorized_writer" {
		t.Errorf("raw.decision = %v, want unauthorized_writer (verbatim source row preserved)", raw["decision"])
	}
}

func TestProcessTableEmptyFixtureZeroEventsZeroCursor(t *testing.T) {
	resp := loadFixture(t, "../../internal/normalize/testdata/law_empty_response.json")
	events, maxSeen, err := processTable(resp.Tables[0], "org-test")
	if err != nil {
		t.Fatalf("processTable: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("want 0 events for an empty window, got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero (no cursor should advance across an empty poll)", maxSeen)
	}
}

func TestProcessTableSkipsRowsWithWrongMsg(t *testing.T) {
	tbl := lawTable{
		Columns: []lawColumn{{Name: "TimeGenerated"}, {Name: "Log_s"}},
		Rows: [][]any{
			{"2026-07-20T15:10:18Z", `{"msg":"something_else","decision":"unauthorized_writer"}`},
		},
	}
	events, _, err := processTable(tbl, "org-test")
	if err != nil {
		t.Fatalf("processTable: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("want 0 events for a non-relay_security msg, got %d", len(events))
	}
}

func TestProcessTableSkipsUnparseableRows(t *testing.T) {
	tbl := lawTable{
		Columns: []lawColumn{{Name: "TimeGenerated"}, {Name: "Log_s"}},
		Rows: [][]any{
			{"not-a-timestamp", `{"msg":"relay_security","decision":"unauthorized_writer"}`},
			{"2026-07-20T15:10:18Z", `not json`},
		},
	}
	events, maxSeen, err := processTable(tbl, "org-test")
	if err != nil {
		t.Fatalf("processTable should not hard-fail on malformed rows: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("want 0 events (both rows malformed), got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero", maxSeen)
	}
}

func TestProcessTableNIP86AdminCallEmitsTwoEvents(t *testing.T) {
	tbl := lawTable{
		Columns: []lawColumn{{Name: "TimeGenerated"}, {Name: "Log_s"}},
		Rows: [][]any{
			{"2026-07-20T15:10:18Z", `{"msg":"relay_security","decision":"nip86_admin_call","pubkey":"adminpk","remote":"","domain":"","detail":"method=allowpubkey outcome=allow"}`},
		},
	}
	events, _, err := processTable(tbl, "org-test")
	if err != nil {
		t.Fatalf("processTable: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 fan-out events for one nip86_admin_call row, got %d", len(events))
	}
	if events[0].ID == events[1].ID {
		t.Error("fan-out events must have distinct IDs")
	}
	types := map[string]bool{events[0].Type: true, events[1].Type: true}
	if !types["iam_policy_attach"] || !types["role_assignment"] {
		t.Errorf("want iam_policy_attach + role_assignment, got %v", types)
	}
}

// --- resolveFloor / validateCursor edge cases ---

func TestValidateCursorRejectsControlCharacters(t *testing.T) {
	if err := validateCursor("abc\x00def"); err == nil {
		t.Fatal("expected error for control character in cursor, got nil")
	}
}

func TestValidateCursorRejectsOverlong(t *testing.T) {
	long := strings.Repeat("a", cursorMaxLen+1)
	if err := validateCursor(long); err == nil {
		t.Fatal("expected error for overlong cursor, got nil")
	}
}
