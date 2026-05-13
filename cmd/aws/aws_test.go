package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("us-east-1")
	raw := "AQIDAHiXkl4xxxxxxNextToken"

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
	key := sigKey("eu-west-1")
	raw := "some-next-token"

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
	key1 := sigKey("us-east-1")
	key2 := sigKey("ap-southeast-1")
	raw := "cursor-value"

	encoded := encodeCursor(raw, key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestNormalizeEvent(t *testing.T) {
	id := "event-id-123"
	name := "ConsoleLogin"
	username := "alice"
	ts := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

	e := types.Event{
		EventId:   &id,
		EventName: &name,
		Username:  &username,
		EventTime: &ts,
	}

	ev, err := normalizeEvent(e, "us-east-1")
	if err != nil {
		t.Fatalf("normalizeEvent: %v", err)
	}

	if ev.Source != "aws" {
		t.Errorf("Source = %q, want %q", ev.Source, "aws")
	}
	if ev.Type != "ConsoleLogin" {
		t.Errorf("Type = %q, want %q", ev.Type, "ConsoleLogin")
	}
	if ev.Actor != "alice" {
		t.Errorf("Actor = %q, want %q", ev.Actor, "alice")
	}
	if ev.Timestamp != ts {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, ts)
	}
	if ev.Org != "us-east-1" {
		t.Errorf("Org = %q, want %q", ev.Org, "us-east-1")
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}
	if ev.Payload == nil {
		t.Error("Payload is nil")
	}

	// Payload should be valid JSON.
	var raw map[string]interface{}
	if err := json.Unmarshal(ev.Payload, &raw); err != nil {
		t.Errorf("Payload is not valid JSON: %v", err)
	}
}

func TestNormalizeEventMissingFields(t *testing.T) {
	// Event with no username, no event name, no time.
	e := types.Event{}
	ev, err := normalizeEvent(e, "us-west-2")
	if err != nil {
		t.Fatalf("normalizeEvent with empty fields: %v", err)
	}

	if ev.Source != "aws" {
		t.Errorf("Source = %q, want %q", ev.Source, "aws")
	}
	// Actor should be empty string.
	if ev.Actor != "" {
		t.Errorf("Actor = %q, want empty", ev.Actor)
	}
	// Timestamp should default to now (not zero).
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
}

func TestNormalizeEventSchema(t *testing.T) {
	id := "abc123"
	name := "CreateUser"
	ts := time.Now().UTC()
	e := types.Event{EventId: &id, EventName: &name, EventTime: &ts}

	ev, err := normalizeEvent(e, "us-east-1")
	if err != nil {
		t.Fatalf("normalizeEvent: %v", err)
	}

	// Re-encode and decode to verify JSON round-trip.
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
	if decoded.Source != "aws" {
		t.Errorf("Source mismatch: %q", decoded.Source)
	}
}
