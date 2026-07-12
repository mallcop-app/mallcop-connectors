package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
	"google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
)

// newTestLoggingService points a *logging.Service at an httptest.Server
// instead of the real Cloud Logging API, with no auth required.
func newTestLoggingService(t *testing.T, serverURL string) *logging.Service {
	t.Helper()
	svc, err := logging.NewService(context.Background(),
		option.WithEndpoint(serverURL+"/"),
		option.WithHTTPClient(http.DefaultClient),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("logging.NewService: %v", err)
	}
	return svc
}

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("my-project")
	raw := "CgwImbGr0AYQoNqXpAMSBQjg9b8H"

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
	key := sigKey("proj-abc")
	raw := "page-token-value"

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
	key1 := sigKey("project-a")
	key2 := sigKey("project-b")

	encoded := encodeCursor("some-token", key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestNormalizeLogEntry(t *testing.T) {
	protoPayload, _ := json.Marshal(map[string]interface{}{
		"methodName": "google.admin.AdminService.createUser",
		"authenticationInfo": map[string]interface{}{
			"principalEmail": "admin@example.com",
		},
	})

	entry := &logging.LogEntry{
		InsertId:     "insert-id-001",
		LogName:      "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
		Timestamp:    "2024-06-01T12:00:00Z",
		ProtoPayload: protoPayload,
	}

	evs, tsReliable, err := normalizeLogEntry(entry, "my-project")
	if err != nil {
		t.Fatalf("normalizeLogEntry: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

	if ev.Source != "gcp" {
		t.Errorf("Source = %q, want gcp", ev.Source)
	}
	if !tsReliable {
		t.Error("tsReliable = false, want true when Timestamp is present and parseable")
	}
	// The raw methodName gates no detector; createUser maps to canonical
	// "member_added" so priv-escalation / new-actor can fire.
	if ev.Type != "member_added" {
		t.Errorf("Type = %q, want member_added", ev.Type)
	}
	if ev.Actor != "admin@example.com" {
		t.Errorf("Actor = %q, want admin@example.com", ev.Actor)
	}
	expectedTS := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if ev.Timestamp != expectedTS {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, expectedTS)
	}
	if ev.Org != "my-project" {
		t.Errorf("Org = %q, want my-project", ev.Org)
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}
	if ev.Payload == nil {
		t.Error("Payload is nil")
	}
}

func TestNormalizeLogEntryMissingFields(t *testing.T) {
	entry := &logging.LogEntry{}
	evs, tsReliable, err := normalizeLogEntry(entry, "proj-x")
	if err != nil {
		t.Fatalf("normalizeLogEntry with empty entry: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Source != "gcp" {
		t.Errorf("Source = %q, want gcp", ev.Source)
	}
	if ev.Type != normalize.CatchAll {
		t.Errorf("Type = %q, want %q", ev.Type, normalize.CatchAll)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
	// The fabricated fallback timestamp must never be reported as reliable —
	// the caller (fetchAuditLogs) must not let it advance the resume
	// high-water mark.
	if tsReliable {
		t.Error("tsReliable = true, want false when Timestamp is missing (would poison the resume cursor to wall-clock now)")
	}
}

func TestNormalizeLogEntrySchemaRoundtrip(t *testing.T) {
	entry := &logging.LogEntry{
		InsertId:  "abc",
		LogName:   "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
		Timestamp: "2024-01-15T08:30:00.123Z",
	}

	evs, _, err := normalizeLogEntry(entry, "proj-roundtrip")
	if err != nil {
		t.Fatalf("normalizeLogEntry: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

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
	if decoded.Source != "gcp" {
		t.Errorf("Source mismatch: %q", decoded.Source)
	}
}

// --- mallcoppro-bb2: high-water cursor semantics ---

// (a) complete pagination emits a cursor whose decoded payload is the max
// emitted entry timestamp (RFC3339Nano), NOT a pagination token (page token).
func TestFetchAuditLogsCompletePaginationHighWaterCursor(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req logging.ListLogEntriesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		call++
		var resp logging.ListLogEntriesResponse
		switch call {
		case 1:
			resp.Entries = []*logging.LogEntry{
				{InsertId: "e1", LogName: "projects/p/logs/cloudaudit.googleapis.com%2Factivity", Timestamp: "2024-06-01T12:00:00Z"},
			}
			resp.NextPageToken = "page-2-token"
		case 2:
			resp.Entries = []*logging.LogEntry{
				{InsertId: "e2", LogName: "projects/p/logs/cloudaudit.googleapis.com%2Factivity", Timestamp: "2024-06-01T13:30:00.5Z"},
			}
		default:
			t.Fatalf("unexpected extra request %d", call)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	svc := newTestLoggingService(t, srv.URL)
	events, maxSeen, err := fetchAuditLogs(context.Background(), svc, "p", time.Time{})
	if err != nil {
		t.Fatalf("fetchAuditLogs: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events (full pagination), got %d", len(events))
	}
	if call != 2 {
		t.Fatalf("want 2 entries.list calls, got %d", call)
	}
	want := time.Date(2024, 6, 1, 13, 30, 0, 500000000, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v", maxSeen, want)
	}

	key := sigKey("p")
	encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, decoded); err != nil {
		t.Fatalf("cursor payload is not a timestamp (looks like a page token): %v", err)
	}
}

// (a2) a page mixing a good-timestamp entry with a missing-Timestamp entry
// must advance maxSeen to the good entry's time, NOT to the fabricated
// time.Now() fallback used for the missing-timestamp entry's own Timestamp
// field. Regression test for the high-water cursor poisoning bug.
func TestFetchAuditLogsMissingTimestampDoesNotPoisonMaxSeen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := logging.ListLogEntriesResponse{
			Entries: []*logging.LogEntry{
				{InsertId: "e1", LogName: "projects/p/logs/cloudaudit.googleapis.com%2Factivity", Timestamp: "2024-06-01T12:00:00Z"},
				// No Timestamp: normalizeLogEntry falls back to
				// time.Now().UTC(), which is always AFTER the good entry.
				{InsertId: "e2", LogName: "projects/p/logs/cloudaudit.googleapis.com%2Factivity"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	svc := newTestLoggingService(t, srv.URL)
	events, maxSeen, err := fetchAuditLogs(context.Background(), svc, "p", time.Time{})
	if err != nil {
		t.Fatalf("fetchAuditLogs: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events emitted (both, even the unreliable one), got %d", len(events))
	}
	want := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v (the fabricated now() timestamp on the missing-Timestamp entry must not advance the cursor)", maxSeen, want)
	}
}

// (b) resume with a timestamp cursor queries from that timestamp
// inclusively — assert the filter's "timestamp >=" clause reflects T.
func TestFetchAuditLogsResumeUsesInclusiveFilter(t *testing.T) {
	var gotFilter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req logging.ListLogEntriesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		gotFilter = req.Filter
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logging.ListLogEntriesResponse{})
	}))
	defer srv.Close()

	svc := newTestLoggingService(t, srv.URL)
	floor := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if _, _, err := fetchAuditLogs(context.Background(), svc, "p", floor); err != nil {
		t.Fatalf("fetchAuditLogs: %v", err)
	}

	wantClause := `AND timestamp >= "2024-06-01T12:00:00Z"`
	if !strings.Contains(gotFilter, wantClause) {
		t.Errorf("filter = %q, want it to contain %q (must be inclusive >=, not exclusive >)", gotFilter, wantClause)
	}
}

// (c) a legacy pagination-token cursor (HMAC-valid, non-timestamp payload)
// warns and falls back to the 24h window — the run SUCCEEDS.
func TestResolveFloorLegacyPaginationTokenFallsBack(t *testing.T) {
	key := sigKey("p")
	legacyCursor := encodeCursor("CgwImbGr0AYQoNqXpAMSBQjg9b8H", key)

	before := time.Now().UTC()
	floor, legacy, err := resolveFloor(legacyCursor, time.Time{}, key)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("resolveFloor: legacy cursor must not hard-fail, got: %v", err)
	}
	if !legacy {
		t.Error("legacy = false, want true for a non-timestamp HMAC-valid payload")
	}
	wantMin := before.Add(-legacyCursorFallback)
	wantMax := after.Add(-legacyCursorFallback)
	if floor.Before(wantMin) || floor.After(wantMax) {
		t.Errorf("floor = %v, want within [%v, %v] (now - 24h)", floor, wantMin, wantMax)
	}

	// Prove the run actually succeeds end-to-end with the fallback floor.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logging.ListLogEntriesResponse{})
	}))
	defer srv.Close()
	svc := newTestLoggingService(t, srv.URL)
	if _, _, err := fetchAuditLogs(context.Background(), svc, "p", floor); err != nil {
		t.Fatalf("fetchAuditLogs after legacy-cursor fallback: %v", err)
	}
}

// (d) zero events emitted -> caller (run()) must not print a "cursor:" line.
// fetchAuditLogs itself signals this via a zero maxSeen.
func TestFetchAuditLogsZeroEventsNoCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logging.ListLogEntriesResponse{})
	}))
	defer srv.Close()

	svc := newTestLoggingService(t, srv.URL)
	events, maxSeen, err := fetchAuditLogs(context.Background(), svc, "p", time.Time{})
	if err != nil {
		t.Fatalf("fetchAuditLogs: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("want 0 events, got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero (no cursor should be emitted)", maxSeen)
	}
}

// (e) a tampered (HMAC-invalid) cursor still hard-fails.
func TestResolveFloorTamperedCursorHardFails(t *testing.T) {
	key := sigKey("p")
	encoded := encodeCursor("2024-06-01T12:00:00Z", key)
	parts := strings.SplitN(encoded, ".", 2)
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	_, _, err := resolveFloor(tampered, time.Time{}, key)
	if err == nil {
		t.Fatal("expected hard failure for tampered cursor, got nil")
	}
}
