package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-connectors/pkg/event"
)

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("sub-12345")
	raw := "https://management.azure.com/subscriptions/sub-12345?nextPage=token123"

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
	key := sigKey("sub-abc")
	raw := "next-link-value"

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
	key1 := sigKey("sub-aaa")
	key2 := sigKey("sub-bbb")
	raw := "cursor-value"

	encoded := encodeCursor(raw, key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestNormalizeEntry(t *testing.T) {
	entry := map[string]interface{}{
		"id":     "/subscriptions/sub-123/resourceGroups/rg/providers/foo/operations/bar",
		"caller": "admin@example.com",
		"operationName": map[string]interface{}{
			"value": "Microsoft.Authorization/roleAssignments/write",
		},
		"eventTimestamp": "2024-06-01T12:00:00Z",
		"status": map[string]interface{}{
			"value": "Succeeded",
		},
	}

	ev, err := normalizeEntry(entry, "sub-123")
	if err != nil {
		t.Fatalf("normalizeEntry: %v", err)
	}

	if ev.Source != "azure" {
		t.Errorf("Source = %q, want azure", ev.Source)
	}
	if ev.Type != "Microsoft.Authorization/roleAssignments/write" {
		t.Errorf("Type = %q, want roleAssignments/write", ev.Type)
	}
	if ev.Actor != "admin@example.com" {
		t.Errorf("Actor = %q, want admin@example.com", ev.Actor)
	}
	expectedTS := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if ev.Timestamp != expectedTS {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, expectedTS)
	}
	if ev.Org != "sub-123" {
		t.Errorf("Org = %q, want sub-123", ev.Org)
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}
}

func TestNormalizeEntryMissingFields(t *testing.T) {
	entry := map[string]interface{}{}
	ev, err := normalizeEntry(entry, "sub-xyz")
	if err != nil {
		t.Fatalf("normalizeEntry with empty entry: %v", err)
	}
	if ev.Source != "azure" {
		t.Errorf("Source = %q, want azure", ev.Source)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
}

func TestNormalizeEntrySchemaRoundtrip(t *testing.T) {
	entry := map[string]interface{}{
		"id":     "entry-001",
		"caller": "user@corp.com",
		"operationName": map[string]interface{}{
			"value": "Microsoft.Compute/virtualMachines/delete",
		},
		"eventTimestamp": "2024-01-15T08:30:00Z",
	}

	ev, err := normalizeEntry(entry, "sub-roundtrip")
	if err != nil {
		t.Fatalf("normalizeEntry: %v", err)
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
	if decoded.Source != "azure" {
		t.Errorf("Source mismatch: %q", decoded.Source)
	}
}
