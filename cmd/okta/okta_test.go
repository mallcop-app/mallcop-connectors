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
)

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("myorg.okta.com")
	raw := "https://myorg.okta.com/api/v1/logs?after=1234567890abcdef&limit=1000"

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
	key := sigKey("corp.okta.com")
	raw := "next-page-url"

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
	key1 := sigKey("org-a.okta.com")
	key2 := sigKey("org-b.okta.com")

	encoded := encodeCursor("cursor", key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestParseNextLink(t *testing.T) {
	cases := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "single next link",
			header:   `<https://myorg.okta.com/api/v1/logs?after=abc&limit=1000>; rel="next"`,
			expected: "https://myorg.okta.com/api/v1/logs?after=abc&limit=1000",
		},
		{
			name:     "self and next",
			header:   `<https://myorg.okta.com/api/v1/logs?limit=1000>; rel="self", <https://myorg.okta.com/api/v1/logs?after=xyz&limit=1000>; rel="next"`,
			expected: "https://myorg.okta.com/api/v1/logs?after=xyz&limit=1000",
		},
		{
			name:     "no next",
			header:   `<https://myorg.okta.com/api/v1/logs?limit=1000>; rel="self"`,
			expected: "",
		},
		{
			name:     "empty header",
			header:   "",
			expected: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseNextLink(tc.header)
			if got != tc.expected {
				t.Errorf("parseNextLink(%q) = %q, want %q", tc.header, got, tc.expected)
			}
		})
	}
}

func TestNormalizeOktaEvent(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":           "abc123-def456",
		"published":      "2024-06-01T12:00:00.000Z",
		"eventType":      "user.session.start",
		"displayMessage": "User login",
		"actor": map[string]interface{}{
			"id":          "00u1abc",
			"type":        "User",
			"alternateId": "alice@example.com",
			"displayName": "Alice",
		},
		"client": map[string]interface{}{
			"ipAddress": "198.51.100.9",
			"geographicalContext": map[string]interface{}{
				"country": "US",
				"state":   "WA",
			},
		},
	}

	evs, err := normalizeOktaEvent(raw, "myorg.okta.com")
	if err != nil {
		t.Fatalf("normalizeOktaEvent: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

	if ev.Source != "okta" {
		t.Errorf("Source = %q, want okta", ev.Source)
	}
	// The raw Okta eventType gates no detector; user.session.start maps to the
	// canonical "login" type, with ip/geo promoted to the flat payload.
	if ev.Type != "login" {
		t.Errorf("Type = %q, want login", ev.Type)
	}
	var p map[string]any
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if p["ip"] != "198.51.100.9" {
		t.Errorf("payload ip = %v, want 198.51.100.9", p["ip"])
	}
	if p["geo"] != "US/WA" {
		t.Errorf("payload geo = %v, want US/WA", p["geo"])
	}
	if ev.Actor != "alice@example.com" {
		t.Errorf("Actor = %q, want alice@example.com", ev.Actor)
	}
	expectedTS := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if ev.Timestamp != expectedTS {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, expectedTS)
	}
	if ev.Org != "myorg.okta.com" {
		t.Errorf("Org = %q, want myorg.okta.com", ev.Org)
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}
}

func TestNormalizeOktaEventActorFallback(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":      "xyz-789",
		"published": "2024-06-01T12:00:00Z",
		"eventType": "user.account.lock",
		"actor": map[string]interface{}{
			"id":          "00u2xyz",
			"type":        "User",
			"alternateId": "",
			"displayName": "Bob Smith",
		},
	}

	evs, err := normalizeOktaEvent(raw, "corp.okta.com")
	if err != nil {
		t.Fatalf("normalizeOktaEvent: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

	// alternateId is empty, should fall back to displayName.
	if ev.Actor != "Bob Smith" {
		t.Errorf("Actor = %q, want Bob Smith", ev.Actor)
	}
}

func TestNormalizeOktaEventMissingFields(t *testing.T) {
	evs, err := normalizeOktaEvent(map[string]interface{}{}, "empty.okta.com")
	if err != nil {
		t.Fatalf("normalizeOktaEvent with empty map: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Source != "okta" {
		t.Errorf("Source = %q, want okta", ev.Source)
	}
	if ev.Type != normalize.CatchAll {
		t.Errorf("Type = %q, want %q", ev.Type, normalize.CatchAll)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
}

func TestNormalizeOktaEventSchemaRoundtrip(t *testing.T) {
	raw := map[string]interface{}{
		"uuid":      "roundtrip-001",
		"published": "2024-03-15T10:00:00Z",
		"eventType": "policy.lifecycle.update",
	}

	evs, err := normalizeOktaEvent(raw, "org.okta.com")
	if err != nil {
		t.Fatalf("normalizeOktaEvent: %v", err)
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
	if decoded.Source != "okta" {
		t.Errorf("Source mismatch: %q", decoded.Source)
	}
}

// --- mallcoppro-bb2: high-water cursor semantics ---

// testDomain returns the connector's domain field for a TLS test server
// (fetchSystemLog hardcodes "https://" against c.domain, so the test server
// must be TLS and the client must trust its cert — see server.Client()).
func testDomain(serverURL string) string {
	return strings.TrimPrefix(serverURL, "https://")
}

// (a) complete pagination emits a cursor whose decoded payload is the max
// emitted published timestamp (RFC3339Nano), NOT a pagination token (the
// Link header's "next" URL).
func TestFetchSystemLogCompletePaginationHighWaterCursor(t *testing.T) {
	call := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call++
		w.Header().Set("Content-Type", "application/json")
		switch call {
		case 1:
			w.Header().Set("Link", `<https://`+r.Host+`/api/v1/logs?after=abc>; rel="next"`)
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"uuid": "e1", "eventType": "user.session.start", "published": "2024-06-01T12:00:00.000Z"},
			})
		case 2:
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"uuid": "e2", "eventType": "user.session.start", "published": "2024-06-01T13:30:00.500Z"},
			})
		default:
			t.Fatalf("unexpected extra request %d", call)
		}
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), domain: testDomain(srv.URL), apiToken: "tok"}
	events, maxSeen, err := conn.fetchSystemLog(context.Background())
	if err != nil {
		t.Fatalf("fetchSystemLog: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events (full pagination), got %d", len(events))
	}
	if call != 2 {
		t.Fatalf("want 2 requests, got %d", call)
	}
	want := time.Date(2024, 6, 1, 13, 30, 0, 500000000, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v", maxSeen, want)
	}

	key := sigKey(conn.domain)
	encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, decoded); err != nil {
		t.Fatalf("cursor payload is not a timestamp (looks like a polling link): %v", err)
	}
}

// (b) resume with a timestamp cursor queries from that timestamp
// inclusively — assert the request's since= param reflects T.
func TestFetchSystemLogResumeUsesInclusiveSinceParam(t *testing.T) {
	var gotSince string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSince = r.URL.Query().Get("since")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()

	floor := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	conn := &connector{client: srv.Client(), domain: testDomain(srv.URL), apiToken: "tok", since: floor}
	if _, _, err := conn.fetchSystemLog(context.Background()); err != nil {
		t.Fatalf("fetchSystemLog: %v", err)
	}

	want := "2024-06-01T12:00:00Z"
	if gotSince != want {
		t.Errorf("since= %q, want %q (System Log's own inclusive lower bound)", gotSince, want)
	}
}

// (c) a legacy pagination-token cursor (HMAC-valid, non-timestamp payload)
// warns and falls back to the 24h window — the run SUCCEEDS.
func TestResolveFloorLegacyPaginationTokenFallsBack(t *testing.T) {
	key := sigKey("myorg.okta.com")
	legacyCursor := encodeCursor("https://myorg.okta.com/api/v1/logs?after=1234567890abcdef&limit=1000", key)

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
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()
	conn := &connector{client: srv.Client(), domain: testDomain(srv.URL), apiToken: "tok", since: floor}
	if _, _, err := conn.fetchSystemLog(context.Background()); err != nil {
		t.Fatalf("fetchSystemLog after legacy-cursor fallback: %v", err)
	}
}

// (d) zero events emitted -> caller (run()) must not print a "cursor:" line.
// fetchSystemLog itself signals this via a zero maxSeen.
func TestFetchSystemLogZeroEventsNoCursor(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), domain: testDomain(srv.URL), apiToken: "tok"}
	events, maxSeen, err := conn.fetchSystemLog(context.Background())
	if err != nil {
		t.Fatalf("fetchSystemLog: %v", err)
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
	key := sigKey("myorg.okta.com")
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
