package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/logging/v2"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

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
		InsertId:    "insert-id-001",
		LogName:     "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
		Timestamp:   "2024-06-01T12:00:00Z",
		ProtoPayload: protoPayload,
	}

	ev, err := normalizeLogEntry(entry, "my-project")
	if err != nil {
		t.Fatalf("normalizeLogEntry: %v", err)
	}

	if ev.Source != "gcp" {
		t.Errorf("Source = %q, want gcp", ev.Source)
	}
	if ev.Type != "google.admin.AdminService.createUser" {
		t.Errorf("Type = %q, want createUser", ev.Type)
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
	ev, err := normalizeLogEntry(entry, "proj-x")
	if err != nil {
		t.Fatalf("normalizeLogEntry with empty entry: %v", err)
	}
	if ev.Source != "gcp" {
		t.Errorf("Source = %q, want gcp", ev.Source)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
}

func TestNormalizeLogEntrySchemaRoundtrip(t *testing.T) {
	entry := &logging.LogEntry{
		InsertId:  "abc",
		LogName:   "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
		Timestamp: "2024-01-15T08:30:00.123Z",
	}

	ev, err := normalizeLogEntry(entry, "proj-roundtrip")
	if err != nil {
		t.Fatalf("normalizeLogEntry: %v", err)
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
	if decoded.Source != "gcp" {
		t.Errorf("Source mismatch: %q", decoded.Source)
	}
}
