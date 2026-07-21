// Command nostr polls one or more nostr relays over a read-only websocket
// subscription and emits normalized mallcop events as JSONL to stdout, then
// exits (one-shot poll model matching cmd/azure — mallcop's runtime is a
// one-shot CLI).
//
// Usage:
//
//	nostr --relay-url wss://relay.moot.pub [--relay-url wss://other-relay/...] [--since <iso-timestamp>] [--cursor <cursor>]
//
// Config: --relay-url is repeatable; NOSTR_RELAY_URLS (comma-separated) is
// the env fallback when no --relay-url flag is given.
//
// READ-ONLY, by construction: this file sends exactly two kinds of
// client->relay message — "REQ" (open a subscription, in pollRelay) and
// "CLOSE" (end it, also in pollRelay). There is no code path anywhere in
// this package that constructs or sends an "EVENT" (publish) or "AUTH"
// (NIP-42) client message, and no NIP-86 relay-management HTTP call is ever
// made. That is the write-capable LAW connector's job, a different
// connector this repo does not implement here.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen = 2000

	// subscriptionID is the REQ subscription id used on every relay
	// connection. Nostr subscription ids only need to be unique within a
	// single connection, so a fixed constant is fine: this poller opens
	// exactly one subscription per relay per run.
	subscriptionID = "mallcop-poll"

	// eventLimit caps how many events a single REQ requests, bounding one
	// run's worst-case volume against a relay with a large backlog since
	// the floor. 500 matches the de-facto relay convention advertised via
	// NIP-11 "limitation.max_limit" (nostr-relay-prod's own NIP-11 doc
	// advertises exactly 500 — live-verified 2026-07-21 against
	// wss://nostr-relay-prod...azurecontainerapps.io: a REQ with limit=2000
	// got hard-rejected with a CLOSED frame, "requested limit 2000 exceeds
	// this relay's max of 500 — no silent truncation", rather than being
	// silently capped). A relay that allows a smaller max still simply
	// returns fewer events; this is a request ceiling, not a hard
	// requirement.
	eventLimit = 500

	// relayTimeout bounds how long a single relay (dial + drain) may take,
	// so one unresponsive relay cannot hang the whole one-shot run.
	relayTimeout = 20 * time.Second

	// maxCreatedAtSkew bounds how far into the future an event's
	// author-chosen created_at may be and still be trusted to advance the
	// resume high-water mark. nostr created_at is attacker-controlled: without
	// an upper bound, a single event dated far in the future would push the
	// emitted cursor past wall-clock, and every later run would resume from
	// that future timestamp and skip all real events until the clock caught up
	// — a durable monitoring blackout from one low-effort event (mallcoppro-174a).
	// One hour tolerates legitimate clock drift between the author and us while
	// rejecting implausible timestamps.
	maxCreatedAtSkew = time.Hour
)

// maxMessageSize bounds a single relay websocket frame. Legitimate nostr
// events are small (a few KB is typical; even long-form kind:30023 articles
// rarely approach this), but a hostile or malfunctioning relay must never be
// able to force this one-shot poller to buffer an unbounded amount of memory
// reading one frame. Enforced via websocket.Conn.MaxPayloadBytes (checked
// against the frame header BEFORE the payload is read off the wire — see
// dialRelay). It's a var (not const) so tests can shrink it to exercise the
// oversized-frame path without sending hundreds of KB over the wire.
var maxMessageSize = 256 * 1024

var cursorRE = regexp.MustCompile(`^[A-Za-z0-9+/=_\-&?%:.]+$`)

func validateCursor(cursor string) error {
	if len(cursor) > cursorMaxLen {
		return fmt.Errorf("invalid cursor: length %d exceeds maximum %d", len(cursor), cursorMaxLen)
	}
	if !cursorRE.MatchString(cursor) {
		return fmt.Errorf("invalid cursor: contains disallowed characters")
	}
	return nil
}

// sigKey derives the cursor HMAC key from the sorted, joined relay-URL set
// being polled — mirrors cmd/azure's per-subscription sigKey, scoped here to
// the exact relay set so a cursor minted for one relay set can never be
// replayed against a different one.
func sigKey(relayURLs []string) []byte {
	sorted := append([]string(nil), relayURLs...)
	sort.Strings(sorted)
	return []byte(fmt.Sprintf("mallcop-nostr-cursor:%s", strings.Join(sorted, ",")))
}

func encodeCursor(raw string, key []byte) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(raw))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b64))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return b64 + "." + sig
}

func decodeCursor(encoded string, key []byte) (string, error) {
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid cursor format: missing signature")
	}
	b64, sig := parts[0], parts[1]
	if err := validateCursor(b64); err != nil {
		return "", fmt.Errorf("invalid cursor payload: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b64))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid cursor: signature mismatch (tampered cursor rejected)")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("invalid cursor: base64 decode failed: %w", err)
	}
	return string(raw), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

// resolveFloor decodes an optional checkpoint cursor and combines it with
// --since to produce the effective query floor (the later of the two
// timestamps wins). Unlike cmd/azure, there is no legacy pre-highwater
// cursor format to migrate from (this is a brand-new connector), so an
// HMAC-valid cursor whose payload does not parse as RFC3339Nano is a hard
// failure, not a self-healing fallback.
func resolveFloor(cursorArg string, sinceTime time.Time, key []byte) (time.Time, error) {
	var cursorMark time.Time
	if cursorArg != "" {
		raw, err := decodeCursor(cursorArg, key)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid checkpoint cursor: payload is not a timestamp: %w", err)
		}
		cursorMark = ts.UTC()
	}

	floor := sinceTime
	if cursorMark.After(floor) {
		floor = cursorMark
	}
	return floor, nil
}

// nostrEvent is the subset of NIP-01 event fields the poller needs directly
// (actor, id, kind, timestamp). The FULL decoded event (see decodeEventFrame)
// is what actually gets passed to normalize.Nostr and stored as "raw".
type nostrEvent struct {
	ID        string `json:"id"`
	PubKey    string `json:"pubkey"`
	CreatedAt int64  `json:"created_at"`
	Kind      int    `json:"kind"`
}

// decodeRelayFrame parses one raw websocket text message as a nostr
// relay->client frame: a JSON array whose first element is the message
// label ("EVENT"/"EOSE"/"NOTICE"/"CLOSED"/...). It tolerates any malformed
// input — non-JSON, non-array, wrong arity, wrong element types — by
// returning an error; it never panics and never assumes relay-supplied
// structure is well-formed. This is the fuzz-safety boundary: every relay
// byte flows through here before anything else touches it.
func decodeRelayFrame(raw string) (label string, rest []json.RawMessage, err error) {
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		return "", nil, fmt.Errorf("frame is not a JSON array: %w", err)
	}
	if len(arr) == 0 {
		return "", nil, errors.New("empty frame array")
	}
	if err := json.Unmarshal(arr[0], &label); err != nil {
		return "", nil, fmt.Errorf("frame[0] is not a string label: %w", err)
	}
	if label == "" {
		return "", nil, errors.New("frame[0] is an empty/null message label")
	}
	return label, arr[1:], nil
}

// decodeEventFrame decodes an ["EVENT", subID, event] frame's rest slice
// (i.e. rest == [subID, event]) into both the fully decoded raw event map
// (for normalize.Nostr and the stored "raw" sub-object) and a typed
// nostrEvent for the fields the poller reads directly. Never panics on
// malformed content — every step is a checked JSON decode.
func decodeEventFrame(rest []json.RawMessage) (raw map[string]any, typed nostrEvent, err error) {
	if len(rest) < 2 {
		return nil, nostrEvent{}, fmt.Errorf("EVENT frame has %d element(s) after label, want >= 2", len(rest))
	}
	if err := json.Unmarshal(rest[1], &raw); err != nil {
		return nil, nostrEvent{}, fmt.Errorf("EVENT payload is not a JSON object: %w", err)
	}
	if err := json.Unmarshal(rest[1], &typed); err != nil {
		return nil, nostrEvent{}, fmt.Errorf("EVENT payload does not match the nostr event shape: %w", err)
	}
	return raw, typed, nil
}

// normalizeNostrEvent maps one decoded nostr event to one or more mallcop
// events. The actor is ALWAYS the event's author pubkey (per spec: so the
// new_actor detector's first-time-writer baseline works per pubkey, not per
// relay or per connector run). relayURL is recorded as Org for
// provenance/grouping — nostr has no tenant/account concept analogous to an
// Azure subscription or AWS account.
//
// tsReliable mirrors cmd/azure's normalizeEntry contract: true only when
// CreatedAt is a plausible unix timestamp — strictly positive AND not more
// than maxCreatedAtSkew into the future. A missing/zero OR implausibly
// future-dated created_at must never be allowed to advance the resume
// high-water mark — either would silently poison the cursor and skip real
// events on the next run (see cmd/azure's identical guard, mallcoppro-a1e in
// project memory, and the future-date vector mallcoppro-174a). An unreliable
// timestamp still emits the event (with ts=now) so it is monitored; it simply
// does not move the cursor.
func normalizeNostrEvent(raw map[string]any, typed nostrEvent, relayURL string) ([]*event.Event, bool, error) {
	if typed.ID == "" {
		return nil, false, errors.New("event missing id")
	}
	if typed.PubKey == "" {
		return nil, false, errors.New("event missing pubkey")
	}

	now := time.Now().UTC()
	tsReliable := typed.CreatedAt > 0 && typed.CreatedAt <= now.Add(maxCreatedAtSkew).Unix()
	ts := now
	if tsReliable {
		ts = time.Unix(typed.CreatedAt, 0).UTC()
	}

	baseID := sha256Hex("nostr:" + typed.ID)
	results := normalize.Nostr(typed.Kind, raw)
	out := make([]*event.Event, 0, len(results))
	for i, r := range results {
		payload, err := r.PayloadJSON(raw)
		if err != nil {
			return nil, false, fmt.Errorf("marshal payload: %w", err)
		}
		id := baseID
		if i > 0 {
			id = sha256Hex(fmt.Sprintf("nostr:%s:%d", typed.ID, i))
		}
		out = append(out, &event.Event{
			ID:        id,
			Source:    "nostr",
			Type:      r.Type,
			Actor:     typed.PubKey,
			Timestamp: ts,
			Org:       relayURL,
			Payload:   payload,
		})
	}
	return out, tsReliable, nil
}

// dialRelay opens a read-only websocket connection to relayURL and sets the
// max-payload-bytes guard (enforced by websocket.Message.Receive against the
// frame header BEFORE the oversized payload is read off the wire — see
// golang.org/x/net/websocket's Codec.Receive).
var dialRelay = func(relayURL string) (*websocket.Conn, error) {
	ws, err := websocket.Dial(relayURL, "", "https://mallcop.app")
	if err != nil {
		return nil, err
	}
	ws.MaxPayloadBytes = maxMessageSize
	return ws, nil
}

// pollRelay opens relayURL, sends a single read-only REQ subscription with
// since=floor, drains EVENTs until EOSE/CLOSED/deadline, sends CLOSE, and
// disconnects. The ONLY client->relay messages sent are "REQ" and "CLOSE" —
// see the package doc comment's read-only guarantee.
//
// Malformed or oversized frames are logged to stderr and skipped, never
// panicking and never aborting the whole relay connection over a single bad
// frame in the stream.
func pollRelay(relayURL string, floor time.Time) ([]*event.Event, time.Time, error) {
	ws, err := dialRelay(relayURL)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("dial: %w", err)
	}
	defer ws.Close()
	_ = ws.SetDeadline(time.Now().Add(relayTimeout))

	filter := map[string]any{"limit": eventLimit}
	if !floor.IsZero() {
		filter["since"] = floor.Unix()
	}
	if err := websocket.JSON.Send(ws, []any{"REQ", subscriptionID, filter}); err != nil {
		return nil, time.Time{}, fmt.Errorf("send REQ: %w", err)
	}

	var events []*event.Event
	var maxSeen time.Time

loop:
	for {
		var raw string
		if err := websocket.Message.Receive(ws, &raw); err != nil {
			if errors.Is(err, io.EOF) {
				break loop
			}
			if errors.Is(err, websocket.ErrFrameTooLarge) {
				fmt.Fprintf(os.Stderr, "warn: %s sent an oversized frame (> %d bytes), skipping\n", relayURL, maxMessageSize)
				continue loop
			}
			return events, maxSeen, fmt.Errorf("receive: %w", err)
		}

		label, rest, err := decodeRelayFrame(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: %s sent an unparseable frame, skipping: %v\n", relayURL, err)
			continue loop
		}

		switch label {
		case "EVENT":
			rawEv, typed, err := decodeEventFrame(rest)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s sent a malformed EVENT frame, skipping: %v\n", relayURL, err)
				continue loop
			}
			evs, tsReliable, err := normalizeNostrEvent(rawEv, typed, relayURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: %s: skipping event: %v\n", relayURL, err)
				continue loop
			}
			events = append(events, evs...)
			if tsReliable {
				for _, ev := range evs {
					if ev.Timestamp.After(maxSeen) {
						maxSeen = ev.Timestamp
					}
				}
			}
		case "EOSE":
			break loop
		case "CLOSED":
			// A relay sends CLOSED (instead of EOSE) both for a normal
			// server-initiated end-of-subscription AND for a rejected REQ
			// (e.g. a filter the relay refuses, like a limit above its
			// advertised NIP-11 max). Log the reason so a rejected REQ is
			// visible to the operator instead of silently looking like "no
			// events since the floor" — live-verified 2026-07-21 (see
			// eventLimit's doc comment).
			// CLOSED is ["CLOSED", <subscription_id>, <message>]; rest here
			// is [subscription_id, message].
			var reason string
			if len(rest) > 1 {
				_ = json.Unmarshal(rest[1], &reason)
			}
			if reason != "" {
				fmt.Fprintf(os.Stderr, "warn: %s closed the subscription: %s\n", relayURL, reason)
			}
			break loop
		case "NOTICE":
			var msg string
			if len(rest) > 0 {
				_ = json.Unmarshal(rest[0], &msg)
			}
			fmt.Fprintf(os.Stderr, "notice from %s: %s\n", relayURL, msg)
		default:
			// Unrecognized label (e.g. "OK", "AUTH") — ignore. This is a
			// read-only monitoring client: it never reacts to an AUTH
			// challenge and never inspects OK receipts (it never publishes).
		}
	}

	// Best-effort unsubscribe; a failure here doesn't affect the events
	// already collected.
	_ = websocket.JSON.Send(ws, []any{"CLOSE", subscriptionID})

	return events, maxSeen, nil
}

// stringSliceFlag implements flag.Value to support a repeatable
// --relay-url flag (the stdlib flag package has no built-in repeated-flag
// type).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func run() error {
	var relayURLs stringSliceFlag
	flag.Var(&relayURLs, "relay-url", "nostr relay websocket URL (repeatable)")
	since := flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
	cursorArg := flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	flag.Parse()

	if len(relayURLs) == 0 {
		if env := os.Getenv("NOSTR_RELAY_URLS"); env != "" {
			for _, u := range strings.Split(env, ",") {
				if u = strings.TrimSpace(u); u != "" {
					relayURLs = append(relayURLs, u)
				}
			}
		}
	}
	if len(relayURLs) == 0 {
		return fmt.Errorf("--relay-url (repeatable) or NOSTR_RELAY_URLS is required")
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(relayURLs)
	floor, err := resolveFloor(*cursorArg, sinceTime, key)
	if err != nil {
		return err
	}

	seen := make(map[string]bool)
	var allEvents []*event.Event
	var maxSeen time.Time
	for _, relayURL := range relayURLs {
		evs, relayMax, err := pollRelay(relayURL, floor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: %s: %v\n", relayURL, err)
			continue
		}
		for _, ev := range evs {
			if seen[ev.ID] {
				continue
			}
			seen[ev.ID] = true
			allEvents = append(allEvents, ev)
		}
		if relayMax.After(maxSeen) {
			maxSeen = relayMax
		}
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range allEvents {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	// Only emit a cursor when at least one event with a reliable timestamp
	// was emitted this run; otherwise the caller should keep using its
	// previous cursor (mirrors cmd/azure's identical guard).
	if !maxSeen.IsZero() {
		encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
		fmt.Fprintf(os.Stderr, "cursor: %s\n", encoded)
	}

	return bw.Flush()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
