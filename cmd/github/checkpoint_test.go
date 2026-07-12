package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey(12345, 67890)
	raw := "Y3Vyc29yMTIzNDU2"

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
	key := sigKey(12345, 67890)
	raw := "original-cursor-value"

	encoded := encodeCursor(raw, key)

	// Tamper with the payload (flip a char in the base64 part before the dot).
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		t.Fatal("encoded cursor has no dot separator")
	}
	// Flip the last char of the payload.
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	_, err := decodeCursor(tampered, key)
	if err == nil {
		t.Fatal("expected error for tampered cursor, got nil")
	}
	if !strings.Contains(err.Error(), "signature mismatch") && !strings.Contains(err.Error(), "tampered") && !strings.Contains(err.Error(), "invalid cursor") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCursorTamperSignature(t *testing.T) {
	key := sigKey(12345, 67890)
	raw := "another-cursor"

	encoded := encodeCursor(raw, key)
	// Tamper with the signature part.
	parts := strings.SplitN(encoded, ".", 2)
	sig := []byte(parts[1])
	sig[0] ^= 0xFF
	tampered := parts[0] + "." + string(sig)

	_, err := decodeCursor(tampered, key)
	if err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
}

func TestCursorWrongKey(t *testing.T) {
	key1 := sigKey(1111, 2222)
	key2 := sigKey(3333, 4444)
	raw := "cursor-value"

	encoded := encodeCursor(raw, key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestCursorMissingDot(t *testing.T) {
	_, err := decodeCursor("nodothere", sigKey(1, 2))
	if err == nil {
		t.Fatal("expected error for cursor without dot separator")
	}
}

func TestValidateCursorInvalidChars(t *testing.T) {
	cases := []struct {
		name   string
		cursor string
	}{
		{"newline", "abc\ndef"},
		{"null byte", "abc\x00def"},
		{"space", "abc def"},
		{"too long", strings.Repeat("a", cursorMaxLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCursor(tc.cursor)
			if err == nil {
				t.Errorf("validateCursor(%q): expected error, got nil", tc.cursor)
			}
		})
	}
}

func TestValidateCursorValid(t *testing.T) {
	valid := []string{
		"abc123",
		"abc+def/ghi=",
		"abc_def-ghi",
		"Y3Vyc29yMTIzNDU2",
	}
	for _, c := range valid {
		if err := validateCursor(c); err != nil {
			t.Errorf("validateCursor(%q): unexpected error: %v", c, err)
		}
	}
}

// --- mallcoppro-bb2: high-water cursor semantics ---

// apiBaseOverride points the package-level apiBase var at a test server for
// the duration of the returned restore func (mirrors mercury's
// apiBaseOverride idiom in cmd/mercury/mercury_test.go).
func apiBaseOverride(serverURL string) func() {
	orig := apiBase
	apiBase = serverURL
	return func() { apiBase = orig }
}

// (a) complete pagination emits a cursor whose decoded payload is the max
// emitted created_at timestamp (RFC3339Nano), NOT a pagination token (the
// Link header's "after" cursor).
func TestFetchAuditLogCompletePaginationHighWaterCursor(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call++
		w.Header().Set("Content-Type", "application/json")
		switch call {
		case 1:
			w.Header().Set("Link", `<http://`+r.Host+`/orgs/testorg/audit-log?after=abc>; rel="next"`)
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"action": "repo.create", "actor": "alice", "created_at": "2024-06-01T13:30:00Z", "_document_id": "d1"},
			})
		case 2:
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"action": "repo.destroy", "actor": "bob", "created_at": "2024-06-01T12:00:00Z", "_document_id": "d2"},
			})
		default:
			t.Fatalf("unexpected extra request %d", call)
		}
	}))
	defer srv.Close()
	defer apiBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), org: "testorg"}
	events, maxSeen, err := conn.fetchAuditLog(context.Background())
	if err != nil {
		t.Fatalf("fetchAuditLog: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events (full pagination), got %d", len(events))
	}
	if call != 2 {
		t.Fatalf("want 2 requests (followed Link to completion), got %d", call)
	}
	want := time.Date(2024, 6, 1, 13, 30, 0, 0, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v", maxSeen, want)
	}

	key := sigKey(conn.appID, conn.installationID)
	encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, decoded); err != nil {
		t.Fatalf("cursor payload is not a timestamp (looks like an \"after\" token): %v", err)
	}
}

// (a2) a page mixing a good-timestamp entry with a missing-created_at entry
// must advance maxSeen to the good entry's time, NOT to the fabricated
// time.Now() fallback used for the missing-timestamp entry's own Timestamp
// field. Regression test for the high-water cursor poisoning bug.
func TestFetchAuditLogMissingTimestampDoesNotPoisonMaxSeen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"action": "repo.create", "actor": "alice", "created_at": "2024-06-01T12:00:00Z", "_document_id": "d1"},
			// No created_at: normalizeEntry falls back to time.Now().UTC(),
			// which is always AFTER the good entry.
			{"action": "repo.destroy", "actor": "bob", "_document_id": "d2"},
		})
	}))
	defer srv.Close()
	defer apiBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), org: "testorg"}
	events, maxSeen, err := conn.fetchAuditLog(context.Background())
	if err != nil {
		t.Fatalf("fetchAuditLog: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events emitted (both, even the unreliable one), got %d", len(events))
	}
	want := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v (the fabricated now() timestamp on the missing-created_at entry must not advance the cursor)", maxSeen, want)
	}
}

// (b) resume with a timestamp cursor queries from that timestamp inclusively
// via the CLIENT-SIDE newest-first early-stop: assert the actual early-stop
// boundary reflects T, INCLUSIVE (an entry exactly at the floor is kept, and
// the connector never even requests the next page once it sees an entry
// strictly older than the floor).
func TestFetchAuditLogResumeEarlyStopIsInclusive(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", `<http://`+r.Host+`/orgs/testorg/audit-log?after=zzz>; rel="next"`)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"action": "repo.create", "actor": "alice", "created_at": "2024-06-01T13:00:00Z"}, // newer than floor
			{"action": "repo.create", "actor": "carol", "created_at": "2024-06-01T12:00:00Z"}, // AT floor: inclusive boundary
			{"action": "repo.destroy", "actor": "bob", "created_at": "2024-06-01T11:00:00Z"},  // older than floor: triggers stop
		})
	}))
	defer srv.Close()
	defer apiBaseOverride(srv.URL)()

	floor := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	conn := &connector{client: srv.Client(), org: "testorg", since: floor}
	events, maxSeen, err := conn.fetchAuditLog(context.Background())
	if err != nil {
		t.Fatalf("fetchAuditLog: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events (newer + AT-floor, inclusive boundary), got %d", len(events))
	}
	if call != 1 {
		t.Fatalf("want early-stop after page 1 (never follows Link once older-than-floor is seen), got %d requests", call)
	}
	want := time.Date(2024, 6, 1, 13, 0, 0, 0, time.UTC)
	if !maxSeen.Equal(want) {
		t.Errorf("maxSeen = %v, want %v", maxSeen, want)
	}
}

// (c) a legacy pagination-token cursor (HMAC-valid, non-timestamp payload)
// warns and falls back to the 24h window — the run SUCCEEDS.
func TestResolveFloorLegacyPaginationTokenFallsBack(t *testing.T) {
	key := sigKey(12345, 67890)
	legacyCursor := encodeCursor("Y3Vyc29yMTIzNDU2", key)

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
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()
	defer apiBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), org: "testorg", since: floor}
	if _, _, err := conn.fetchAuditLog(context.Background()); err != nil {
		t.Fatalf("fetchAuditLog after legacy-cursor fallback: %v", err)
	}
}

// (d) zero events emitted -> caller (run()) must not print a "cursor:" line.
// fetchAuditLog itself signals this via a zero maxSeen.
func TestFetchAuditLogZeroEventsNoCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()
	defer apiBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), org: "testorg"}
	events, maxSeen, err := conn.fetchAuditLog(context.Background())
	if err != nil {
		t.Fatalf("fetchAuditLog: %v", err)
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
	key := sigKey(1, 2)
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
