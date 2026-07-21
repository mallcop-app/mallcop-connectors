package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
)

// --- cursor / floor -----------------------------------------------------

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey([]string{"wss://relay.moot.pub"})
	raw := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)

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
	key := sigKey([]string{"wss://relay.moot.pub"})
	encoded := encodeCursor("2026-07-20T12:00:00Z", key)
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		t.Fatal("encoded cursor has no dot separator")
	}
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	if _, err := decodeCursor(tampered, key); err == nil {
		t.Fatal("expected error for tampered cursor, got nil")
	}
}

func TestCursorWrongRelaySet(t *testing.T) {
	key1 := sigKey([]string{"wss://relay-a.example"})
	key2 := sigKey([]string{"wss://relay-b.example"})
	encoded := encodeCursor("2026-07-20T12:00:00Z", key1)
	if _, err := decodeCursor(encoded, key2); err == nil {
		t.Fatal("expected error decoding cursor minted for a different relay set")
	}
}

// sigKey must be order-independent over the relay set so flag order doesn't
// silently break cursor resumption.
func TestSigKeyOrderIndependent(t *testing.T) {
	a := sigKey([]string{"wss://a", "wss://b"})
	b := sigKey([]string{"wss://b", "wss://a"})
	if string(a) != string(b) {
		t.Errorf("sigKey depends on argument order: %q vs %q", a, b)
	}
}

func TestResolveFloorSinceOnly(t *testing.T) {
	key := sigKey([]string{"wss://relay.moot.pub"})
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	floor, err := resolveFloor("", since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(since) {
		t.Errorf("floor = %v, want %v", floor, since)
	}
}

func TestResolveFloorCursorNewerThanSince(t *testing.T) {
	key := sigKey([]string{"wss://relay.moot.pub"})
	cursorTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cursor := encodeCursor(cursorTime.Format(time.RFC3339Nano), key)
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	floor, err := resolveFloor(cursor, since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(cursorTime) {
		t.Errorf("floor = %v, want cursor time %v (later of the two)", floor, cursorTime)
	}
}

func TestResolveFloorTamperedCursorHardFails(t *testing.T) {
	key := sigKey([]string{"wss://relay.moot.pub"})
	encoded := encodeCursor("2026-06-01T00:00:00Z", key)
	parts := strings.SplitN(encoded, ".", 2)
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	if _, err := resolveFloor(tampered, time.Time{}, key); err == nil {
		t.Fatal("expected hard failure for tampered cursor, got nil")
	}
}

// Unlike cmd/azure, a non-timestamp HMAC-valid payload is a hard failure
// here (no legacy pagination-token format exists for a brand-new connector).
func TestResolveFloorNonTimestampPayloadHardFails(t *testing.T) {
	key := sigKey([]string{"wss://relay.moot.pub"})
	cursor := encodeCursor("not-a-timestamp", key)
	if _, err := resolveFloor(cursor, time.Time{}, key); err == nil {
		t.Fatal("expected hard failure for a non-timestamp cursor payload")
	}
}

// --- frame parsing (fuzz-safety boundary) --------------------------------

// TestDecodeRelayFrameMalformedInputsNeverPanic is the core fuzz-safety
// assertion: every one of these hostile/malformed inputs must return an
// error, never panic. If this test crashes, the parser is unsafe.
func TestDecodeRelayFrameMalformedInputsNeverPanic(t *testing.T) {
	cases := []string{
		"",
		"not json at all",
		"{}",                     // object, not array
		"[]",                     // empty array
		"[123]",                  // label not a string
		`[null]`,                 // label is null
		`[[1,2,3]]`,              // label is an array
		`["EVENT", {"a":1}, }`,   // truncated/invalid trailing JSON
		strings.Repeat("[", 200), // deeply nested unclosed brackets
		`"just a string"`,        // valid JSON but not an array
		`42`,                     // valid JSON scalar
	}
	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decodeRelayFrame panicked on %q: %v", raw, r)
				}
			}()
			if _, _, err := decodeRelayFrame(raw); err == nil {
				t.Errorf("decodeRelayFrame(%q): expected error, got nil", raw)
			}
		})
	}
}

// TestDecodeRelayFrameShortEventParsesFrameLevelButNotEventLevel: a
// syntactically valid but incomplete ["EVENT"] frame is a legitimate parse
// at the frame layer (decodeRelayFrame doesn't know per-label arity rules);
// the arity check belongs to decodeEventFrame, which must then reject it.
func TestDecodeRelayFrameShortEventParsesFrameLevelButNotEventLevel(t *testing.T) {
	label, rest, err := decodeRelayFrame(`["EVENT"]`)
	if err != nil {
		t.Fatalf("decodeRelayFrame: %v", err)
	}
	if label != "EVENT" {
		t.Errorf("label = %q, want EVENT", label)
	}
	if _, _, err := decodeEventFrame(rest); err == nil {
		t.Fatal("decodeEventFrame: expected error for a frame missing the event element")
	}
}

func TestDecodeRelayFrameValidEvent(t *testing.T) {
	raw := `["EVENT","mallcop-poll",{"id":"abc","pubkey":"def","kind":1,"created_at":1700000000,"content":"hi","tags":[],"sig":"x"}]`
	label, rest, err := decodeRelayFrame(raw)
	if err != nil {
		t.Fatalf("decodeRelayFrame: %v", err)
	}
	if label != "EVENT" {
		t.Errorf("label = %q, want EVENT", label)
	}
	if len(rest) != 2 {
		t.Fatalf("rest len = %d, want 2", len(rest))
	}
}

func TestDecodeRelayFrameValidEOSE(t *testing.T) {
	label, rest, err := decodeRelayFrame(`["EOSE","mallcop-poll"]`)
	if err != nil {
		t.Fatalf("decodeRelayFrame: %v", err)
	}
	if label != "EOSE" {
		t.Errorf("label = %q, want EOSE", label)
	}
	if len(rest) != 1 {
		t.Errorf("rest len = %d, want 1", len(rest))
	}
}

// TestDecodeEventFrameMalformedNeverPanics: malformed EVENT payloads (not an
// object, missing fields, wrong types) must error, never panic.
func TestDecodeEventFrameMalformedNeverPanics(t *testing.T) {
	cases := [][]string{
		{`"mallcop-poll"`},                          // missing event element entirely
		{`"mallcop-poll"`, `"not-an-object"`},       // event is a bare string
		{`"mallcop-poll"`, `123`},                   // event is a number
		{`"mallcop-poll"`, `null`},                  // event is null
		{`"mallcop-poll"`, `{"kind":"not-an-int"}`}, // kind wrong type
		{`"mallcop-poll"`, `{"created_at":"nope"}`}, // created_at wrong type
	}
	for i, c := range cases {
		var rest []json.RawMessage
		for _, s := range c {
			rest = append(rest, json.RawMessage(s))
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d: decodeEventFrame panicked: %v", i, r)
				}
			}()
			// Some malformed shapes (e.g. wrong-typed field) may still decode
			// into a zero-valued struct without erroring at the raw-map
			// level; that's fine as long as it never panics downstream.
			_, _, _ = decodeEventFrame(rest)
		}()
	}
}

func TestDecodeEventFrameValid(t *testing.T) {
	rest := []json.RawMessage{
		json.RawMessage(`"mallcop-poll"`),
		json.RawMessage(`{"id":"abc123","pubkey":"pk1","kind":1,"created_at":1700000000,"content":"hello","tags":[["e","x"]],"sig":"sig1"}`),
	}
	raw, typed, err := decodeEventFrame(rest)
	if err != nil {
		t.Fatalf("decodeEventFrame: %v", err)
	}
	if typed.ID != "abc123" || typed.PubKey != "pk1" || typed.Kind != 1 || typed.CreatedAt != 1700000000 {
		t.Errorf("typed = %+v", typed)
	}
	if raw["content"] != "hello" {
		t.Errorf("raw[content] = %v", raw["content"])
	}
}

// --- normalizeNostrEvent --------------------------------------------------

func TestNormalizeNostrEventActorIsAuthorPubkey(t *testing.T) {
	typed := nostrEvent{ID: "e1", PubKey: "author-pubkey-1", Kind: 1, CreatedAt: 1700000000}
	raw := map[string]any{"id": "e1", "pubkey": "author-pubkey-1", "kind": float64(1), "content": "gm"}
	evs, tsReliable, err := normalizeNostrEvent(raw, typed, "wss://relay.moot.pub")
	if err != nil {
		t.Fatalf("normalizeNostrEvent: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	if evs[0].Actor != "author-pubkey-1" {
		t.Errorf("Actor = %q, want the author pubkey", evs[0].Actor)
	}
	if evs[0].Source != "nostr" {
		t.Errorf("Source = %q, want nostr", evs[0].Source)
	}
	if evs[0].Type != normalize.CatchAll {
		t.Errorf("Type = %q, want CatchAll for kind 1", evs[0].Type)
	}
	if !tsReliable {
		t.Error("tsReliable = false, want true for a positive created_at")
	}
}

// TestNormalizeNostrEventFutureDatedIsUnreliable is the regression guard for
// mallcoppro-174a: an author-chosen created_at far in the future must NOT be
// trusted to advance the resume high-water mark (which would blackout
// monitoring), yet the event must still be emitted (with ts≈now) so it is
// monitored. A near-now created_at within the skew window stays reliable.
func TestNormalizeNostrEventFutureDatedIsUnreliable(t *testing.T) {
	farFuture := time.Now().Add(72 * time.Hour).Unix() // well beyond maxCreatedAtSkew
	typed := nostrEvent{ID: "e-fut", PubKey: "attacker", Kind: 1, CreatedAt: farFuture}
	raw := map[string]any{"id": "e-fut", "pubkey": "attacker", "kind": float64(1)}
	evs, tsReliable, err := normalizeNostrEvent(raw, typed, "wss://relay.moot.pub")
	if err != nil {
		t.Fatalf("normalizeNostrEvent: %v", err)
	}
	if tsReliable {
		t.Error("tsReliable = true for a far-future created_at; the cursor would be poisoned (mallcoppro-174a)")
	}
	if len(evs) != 1 {
		t.Fatalf("want the event still emitted (monitored), got %d events", len(evs))
	}
	if evs[0].Timestamp.After(time.Now().Add(maxCreatedAtSkew)) {
		t.Errorf("emitted Timestamp %v is implausibly future; should fall back to ~now", evs[0].Timestamp)
	}

	// A created_at just inside the skew window is still trusted.
	nearNow := time.Now().Add(-time.Minute).Unix()
	typed2 := nostrEvent{ID: "e-now", PubKey: "author", Kind: 1, CreatedAt: nearNow}
	raw2 := map[string]any{"id": "e-now", "pubkey": "author", "kind": float64(1)}
	_, tsReliable2, err := normalizeNostrEvent(raw2, typed2, "wss://relay.moot.pub")
	if err != nil {
		t.Fatalf("normalizeNostrEvent (near-now): %v", err)
	}
	if !tsReliable2 {
		t.Error("tsReliable = false for a near-now created_at; want true")
	}
}

func TestNormalizeNostrEventDeletionMapsToDeleteGate(t *testing.T) {
	typed := nostrEvent{ID: "e2", PubKey: "author-2", Kind: 5, CreatedAt: 1700000001}
	raw := map[string]any{
		"id": "e2", "pubkey": "author-2", "kind": float64(5),
		"tags": []any{[]any{"e", "deleted-event-id"}},
	}
	evs, _, err := normalizeNostrEvent(raw, typed, "wss://relay.moot.pub")
	if err != nil {
		t.Fatalf("normalizeNostrEvent: %v", err)
	}
	if len(evs) != 1 || evs[0].Type != normalize.NostrDeleteEventType {
		t.Fatalf("evs = %+v, want single event of Type %q", evs, normalize.NostrDeleteEventType)
	}
}

// Missing/zero created_at must yield tsReliable=false so the caller never
// lets a fabricated timestamp advance the resume cursor (mallcoppro-a1e
// class of bug in project memory).
func TestNormalizeNostrEventMissingCreatedAtNotReliable(t *testing.T) {
	typed := nostrEvent{ID: "e3", PubKey: "author-3", Kind: 1}
	raw := map[string]any{"id": "e3", "pubkey": "author-3", "kind": float64(1)}
	evs, tsReliable, err := normalizeNostrEvent(raw, typed, "wss://relay.moot.pub")
	if err != nil {
		t.Fatalf("normalizeNostrEvent: %v", err)
	}
	if tsReliable {
		t.Error("tsReliable = true, want false when created_at is missing/zero")
	}
	if len(evs) != 1 || evs[0].Timestamp.IsZero() {
		t.Errorf("event must still be emitted with SOME timestamp: %+v", evs)
	}
}

func TestNormalizeNostrEventMissingIDErrors(t *testing.T) {
	typed := nostrEvent{PubKey: "author-4", Kind: 1}
	if _, _, err := normalizeNostrEvent(map[string]any{}, typed, "wss://relay.moot.pub"); err == nil {
		t.Fatal("expected error for event missing id")
	}
}

func TestNormalizeNostrEventMissingPubkeyErrors(t *testing.T) {
	typed := nostrEvent{ID: "e5", Kind: 1}
	if _, _, err := normalizeNostrEvent(map[string]any{}, typed, "wss://relay.moot.pub"); err == nil {
		t.Fatal("expected error for event missing pubkey")
	}
}

// --- pollRelay: real websocket, fake relay --------------------------------

// fakeRelay starts a real httptest websocket server. It records every raw
// client->relay message received (for read-only assertions) and, upon
// seeing the client's REQ, replies with the given canned frames in order.
func fakeRelay(t *testing.T, frames []string) (wsURL string, received func() []string, closeSrv func()) {
	t.Helper()
	var mu sync.Mutex
	var msgs []string

	handler := websocket.Handler(func(ws *websocket.Conn) {
		for {
			var raw string
			if err := websocket.Message.Receive(ws, &raw); err != nil {
				return
			}
			mu.Lock()
			msgs = append(msgs, raw)
			mu.Unlock()

			if strings.HasPrefix(raw, `["REQ"`) {
				for _, f := range frames {
					if err := websocket.Message.Send(ws, f); err != nil {
						return
					}
				}
			}
		}
	})
	srv := httptest.NewServer(handler)
	wsURL = "ws://" + strings.TrimPrefix(srv.URL, "http://")
	return wsURL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(msgs))
		copy(out, msgs)
		return out
	}, srv.Close
}

func TestPollRelayHappyPath(t *testing.T) {
	frames := []string{
		`["EVENT","mallcop-poll",{"id":"e1","pubkey":"pk1","kind":1,"created_at":1700000000,"content":"gm","tags":[],"sig":"s1"}]`,
		`["EVENT","mallcop-poll",{"id":"e2","pubkey":"pk2","kind":5,"created_at":1700000100,"tags":[["e","e1"]],"sig":"s2"}]`,
		`["EOSE","mallcop-poll"]`,
	}
	url, received, closeSrv := fakeRelay(t, frames)
	defer closeSrv()

	evs, maxSeen, err := pollRelay(url, time.Time{})
	if err != nil {
		t.Fatalf("pollRelay: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d: %+v", len(evs), evs)
	}
	wantMax := time.Unix(1700000100, 0).UTC()
	if !maxSeen.Equal(wantMax) {
		t.Errorf("maxSeen = %v, want %v", maxSeen, wantMax)
	}

	// Read-only guarantee: the client must never have sent anything but REQ
	// and CLOSE labels.
	for _, m := range received() {
		label, _, err := decodeRelayFrame(m)
		if err != nil {
			t.Fatalf("client sent unparseable message %q: %v", m, err)
		}
		if label != "REQ" && label != "CLOSE" {
			t.Fatalf("client sent a %q message; only REQ/CLOSE are allowed (read-only connector), got: %s", label, m)
		}
	}
}

// TestPollRelayMalformedFramesSkippedNotFatal proves malformed frames
// interleaved with good ones don't crash the poll and don't block the good
// events from being collected.
func TestPollRelayMalformedFramesSkippedNotFatal(t *testing.T) {
	frames := []string{
		`not even json`,
		`{}`,
		`["EVENT","mallcop-poll","not-an-object"]`,
		`["EVENT","mallcop-poll",{"id":"good1","pubkey":"pk1","kind":1,"created_at":1700000000,"tags":[]}]`,
		`["NOTICE","hello from relay"]`,
		`["EOSE","mallcop-poll"]`,
	}
	url, _, closeSrv := fakeRelay(t, frames)
	defer closeSrv()

	evs, _, err := pollRelay(url, time.Time{})
	if err != nil {
		t.Fatalf("pollRelay: %v", err)
	}
	if len(evs) != 1 || evs[0].Actor != "pk1" {
		t.Fatalf("want exactly the 1 good event, got %+v", evs)
	}
}

// TestPollRelayOversizedFrameSkipped shrinks maxMessageSize for the duration
// of the test so an oversized frame can be triggered without sending
// hundreds of KB over the wire, proving the size guard fires and the poll
// continues rather than crashing or hanging.
func TestPollRelayOversizedFrameSkipped(t *testing.T) {
	origMax := maxMessageSize
	maxMessageSize = 100
	defer func() { maxMessageSize = origMax }()

	oversized := `["EVENT","mallcop-poll",{"id":"` + strings.Repeat("x", 200) + `","pubkey":"pk1","kind":1,"created_at":1700000000}]`
	frames := []string{
		oversized,
		`["EVENT","mallcop-poll",{"id":"small1","pubkey":"pk2","kind":1,"created_at":1700000005,"tags":[]}]`,
		`["EOSE","mallcop-poll"]`,
	}
	url, _, closeSrv := fakeRelay(t, frames)
	defer closeSrv()

	evs, _, err := pollRelay(url, time.Time{})
	if err != nil {
		t.Fatalf("pollRelay: %v", err)
	}
	if len(evs) != 1 || evs[0].Actor != "pk2" {
		t.Fatalf("want exactly the 1 small event past the oversized one, got %+v", evs)
	}
}

// TestPollRelayClosedRejectionIsNotFatal: a relay that rejects the REQ
// outright (e.g. limit exceeds its NIP-11 max) sends CLOSED instead of
// EOSE. This must end the poll cleanly with zero events and no error —
// never be treated as a crash — while still logging the reason (manually
// verified against nostr-relay-prod's real "limit exceeds max" rejection;
// see eventLimit's doc comment).
func TestPollRelayClosedRejectionIsNotFatal(t *testing.T) {
	frames := []string{
		`["CLOSED","mallcop-poll","invalid: requested limit 2000 exceeds this relay's max of 500"]`,
	}
	url, _, closeSrv := fakeRelay(t, frames)
	defer closeSrv()

	evs, maxSeen, err := pollRelay(url, time.Time{})
	if err != nil {
		t.Fatalf("pollRelay: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("want 0 events for a rejected REQ, got %+v", evs)
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero", maxSeen)
	}
}

func TestPollRelaySendsSinceInREQ(t *testing.T) {
	url, received, closeSrv := fakeRelay(t, []string{`["EOSE","mallcop-poll"]`})
	defer closeSrv()

	floor := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	if _, _, err := pollRelay(url, floor); err != nil {
		t.Fatalf("pollRelay: %v", err)
	}

	msgs := received()
	if len(msgs) == 0 {
		t.Fatal("relay never received a message")
	}
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(msgs[0]), &arr); err != nil {
		t.Fatalf("REQ not valid JSON array: %v", err)
	}
	var filter map[string]any
	if err := json.Unmarshal(arr[2], &filter); err != nil {
		t.Fatalf("filter not an object: %v", err)
	}
	since, ok := filter["since"].(float64)
	if !ok {
		t.Fatalf("filter missing numeric since: %+v", filter)
	}
	if int64(since) != floor.Unix() {
		t.Errorf("since = %v, want %d", since, floor.Unix())
	}
}
