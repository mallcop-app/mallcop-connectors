package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-connectors/pkg/event"
)

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("tenant-abc-123")
	raw := `{"last_blob_id":{"Audit.AzureActiveDirectory":"blob-001","Audit.Exchange":"blob-002"}}`

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
	key := sigKey("tenant-xyz")
	raw := `{"last_blob_id":{}}`

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
	key1 := sigKey("tenant-a")
	key2 := sigKey("tenant-b")

	encoded := encodeCursor(`{"last_blob_id":{}}`, key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestCursorStateRoundtrip(t *testing.T) {
	key := sigKey("tenant-state-test")
	state := cursorState{
		LastBlobID: map[string]string{
			"Audit.AzureActiveDirectory": "blob-aad-001",
			"Audit.Exchange":             "blob-ex-042",
			"Audit.SharePoint":           "blob-sp-007",
			"Audit.General":              "blob-gen-099",
		},
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	encoded := encodeCursor(string(stateJSON), key)
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}

	var decoded2 cursorState
	if err := json.Unmarshal([]byte(decoded), &decoded2); err != nil {
		t.Fatalf("unmarshal decoded state: %v", err)
	}

	for k, v := range state.LastBlobID {
		if decoded2.LastBlobID[k] != v {
			t.Errorf("LastBlobID[%q] = %q, want %q", k, decoded2.LastBlobID[k], v)
		}
	}
}

func TestNormalizeRecord(t *testing.T) {
	raw := map[string]interface{}{
		"Id":           "record-id-001",
		"CreationTime": "2024-06-01T12:00:00",
		"Operation":    "UserLoggedIn",
		"Workload":     "AzureActiveDirectory",
		"UserId":       "alice@example.com",
		"RecordType":   float64(15),
	}

	ev, err := normalizeRecord(raw, "tenant-001", "Audit.AzureActiveDirectory")
	if err != nil {
		t.Fatalf("normalizeRecord: %v", err)
	}

	if ev.Source != "m365" {
		t.Errorf("Source = %q, want m365", ev.Source)
	}
	if ev.Type != "AzureActiveDirectory.UserLoggedIn" {
		t.Errorf("Type = %q, want AzureActiveDirectory.UserLoggedIn", ev.Type)
	}
	if ev.Actor != "alice@example.com" {
		t.Errorf("Actor = %q, want alice@example.com", ev.Actor)
	}
	expectedTS := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if ev.Timestamp != expectedTS {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, expectedTS)
	}
	if ev.Org != "tenant-001" {
		t.Errorf("Org = %q, want tenant-001", ev.Org)
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}
}

func TestNormalizeRecordMissingFields(t *testing.T) {
	ev, err := normalizeRecord(map[string]interface{}{}, "tenant-x", "Audit.General")
	if err != nil {
		t.Fatalf("normalizeRecord with empty: %v", err)
	}
	if ev.Source != "m365" {
		t.Errorf("Source = %q, want m365", ev.Source)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
}

func TestNormalizeRecordOperationOnly(t *testing.T) {
	// No workload — Type should just be operation.
	raw := map[string]interface{}{
		"Id":           "op-only-001",
		"CreationTime": "2024-01-01T00:00:00",
		"Operation":    "FileUploaded",
		"UserId":       "bob@corp.com",
	}

	ev, err := normalizeRecord(raw, "tenant-op", "Audit.SharePoint")
	if err != nil {
		t.Fatalf("normalizeRecord: %v", err)
	}
	// No workload => type is just the operation.
	if ev.Type != "FileUploaded" {
		t.Errorf("Type = %q, want FileUploaded", ev.Type)
	}
}

func TestNormalizeRecordSchemaRoundtrip(t *testing.T) {
	raw := map[string]interface{}{
		"Id":           "rtrip-001",
		"CreationTime": "2024-03-15T10:00:00",
		"Operation":    "MailboxLogin",
		"Workload":     "Exchange",
		"UserId":       "charlie@company.com",
	}

	ev, err := normalizeRecord(raw, "tenant-roundtrip", "Audit.Exchange")
	if err != nil {
		t.Fatalf("normalizeRecord: %v", err)
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
	if decoded.Source != "m365" {
		t.Errorf("Source mismatch: %q", decoded.Source)
	}
}
