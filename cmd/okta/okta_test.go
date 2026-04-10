package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-connectors/pkg/event"
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
		"uuid":        "abc123-def456",
		"published":   "2024-06-01T12:00:00.000Z",
		"eventType":   "user.session.start",
		"displayMessage": "User login",
		"actor": map[string]interface{}{
			"id":          "00u1abc",
			"type":        "User",
			"alternateId": "alice@example.com",
			"displayName": "Alice",
		},
	}

	ev, err := normalizeOktaEvent(raw, "myorg.okta.com")
	if err != nil {
		t.Fatalf("normalizeOktaEvent: %v", err)
	}

	if ev.Source != "okta" {
		t.Errorf("Source = %q, want okta", ev.Source)
	}
	if ev.Type != "user.session.start" {
		t.Errorf("Type = %q, want user.session.start", ev.Type)
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

	ev, err := normalizeOktaEvent(raw, "corp.okta.com")
	if err != nil {
		t.Fatalf("normalizeOktaEvent: %v", err)
	}

	// alternateId is empty, should fall back to displayName.
	if ev.Actor != "Bob Smith" {
		t.Errorf("Actor = %q, want Bob Smith", ev.Actor)
	}
}

func TestNormalizeOktaEventMissingFields(t *testing.T) {
	ev, err := normalizeOktaEvent(map[string]interface{}{}, "empty.okta.com")
	if err != nil {
		t.Fatalf("normalizeOktaEvent with empty map: %v", err)
	}
	if ev.Source != "okta" {
		t.Errorf("Source = %q, want okta", ev.Source)
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

	ev, err := normalizeOktaEvent(raw, "org.okta.com")
	if err != nil {
		t.Fatalf("normalizeOktaEvent: %v", err)
	}

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
