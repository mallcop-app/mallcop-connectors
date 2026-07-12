package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

// fakeCloudTrailPage is one page of a scripted LookupEvents response.
type fakeCloudTrailPage struct {
	events    []types.Event
	nextToken *string
}

// fakeCloudTrail implements cloudtrailAPI entirely in memory (no network, no
// live creds), mirroring the fakeS3Client idiom in aws_s3_test.go. It records
// the StartTime seen on every call so tests can assert the resume floor was
// actually sent to CloudTrail.
type fakeCloudTrail struct {
	pages         []fakeCloudTrailPage
	call          int
	gotStartTimes []*time.Time
}

func (f *fakeCloudTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.gotStartTimes = append(f.gotStartTimes, in.StartTime)
	if f.call >= len(f.pages) {
		return &cloudtrail.LookupEventsOutput{}, nil
	}
	p := f.pages[f.call]
	f.call++
	return &cloudtrail.LookupEventsOutput{Events: p.events, NextToken: p.nextToken}, nil
}

func strPtr(s string) *string { return &s }

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

	evs, err := normalizeEvent(e, "us-east-1")
	if err != nil {
		t.Fatalf("normalizeEvent: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

	if ev.Source != "aws" {
		t.Errorf("Source = %q, want %q", ev.Source, "aws")
	}
	// ConsoleLogin maps to the canonical "login" type (the raw eventName gates no
	// detector). With no responseElements outcome, it is a plain login.
	if ev.Type != "login" {
		t.Errorf("Type = %q, want %q", ev.Type, "login")
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
	evs, err := normalizeEvent(e, "us-west-2")
	if err != nil {
		t.Fatalf("normalizeEvent with empty fields: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

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

	evs, err := normalizeEvent(e, "us-east-1")
	if err != nil {
		t.Fatalf("normalizeEvent: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Type != "user_created" {
		t.Errorf("Type = %q, want %q", ev.Type, "user_created")
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

// --- mallcoppro-bb2: high-water cursor semantics (LookupEvents mode only) ---

// (a) complete pagination emits a cursor whose decoded payload is the max
// emitted event timestamp (RFC3339Nano), NOT a pagination token (NextToken).
func TestFetchEventsCompletePaginationHighWaterCursor(t *testing.T) {
	t1 := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 6, 1, 13, 30, 0, 0, time.UTC)
	name := "ConsoleLogin"
	client := &fakeCloudTrail{
		pages: []fakeCloudTrailPage{
			{events: []types.Event{{EventId: strPtr("e1"), EventName: &name, EventTime: &t1}}, nextToken: strPtr("page-2-token")},
			{events: []types.Event{{EventId: strPtr("e2"), EventName: &name, EventTime: &t2}}},
		},
	}

	events, maxSeen, err := fetchEvents(context.Background(), client, "us-east-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events (full pagination), got %d", len(events))
	}
	if client.call != 2 {
		t.Fatalf("want 2 LookupEvents calls, got %d", client.call)
	}
	if !maxSeen.Equal(t2) {
		t.Fatalf("maxSeen = %v, want %v", maxSeen, t2)
	}

	key := sigKey("us-east-1")
	encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, decoded); err != nil {
		t.Fatalf("cursor payload is not a timestamp (looks like a NextToken): %v", err)
	}
}

// (b) resume with a timestamp cursor queries from that timestamp
// inclusively — assert LookupEventsInput.StartTime reflects T.
func TestFetchEventsResumePassesFloorAsStartTime(t *testing.T) {
	floor := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	client := &fakeCloudTrail{}

	if _, _, err := fetchEvents(context.Background(), client, "us-east-1", floor); err != nil {
		t.Fatalf("fetchEvents: %v", err)
	}
	if len(client.gotStartTimes) != 1 || client.gotStartTimes[0] == nil {
		t.Fatalf("LookupEvents StartTime not set: %v", client.gotStartTimes)
	}
	if !client.gotStartTimes[0].Equal(floor) {
		t.Errorf("StartTime = %v, want %v (inclusive resume, CloudTrail's own >= semantics)", *client.gotStartTimes[0], floor)
	}
}

// (c) a legacy pagination-token cursor (HMAC-valid, non-timestamp payload)
// warns and falls back to the 24h window — the run SUCCEEDS.
func TestResolveFloorLegacyPaginationTokenFallsBack(t *testing.T) {
	key := sigKey("us-east-1")
	legacyCursor := encodeCursor("AQIDAHiXkl4xxxxxxNextToken", key)

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
	client := &fakeCloudTrail{}
	if _, _, err := fetchEvents(context.Background(), client, "us-east-1", floor); err != nil {
		t.Fatalf("fetchEvents after legacy-cursor fallback: %v", err)
	}
}

// (d) zero events emitted -> caller (run()) must not print a "cursor:" line.
// fetchEvents itself signals this via a zero maxSeen.
func TestFetchEventsZeroEventsNoCursor(t *testing.T) {
	client := &fakeCloudTrail{pages: []fakeCloudTrailPage{{events: nil}}}
	events, maxSeen, err := fetchEvents(context.Background(), client, "us-east-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchEvents: %v", err)
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
	key := sigKey("us-east-1")
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
