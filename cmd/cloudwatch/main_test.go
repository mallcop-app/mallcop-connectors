package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	smithycbor "github.com/aws/smithy-go/encoding/cbor"
)

// --- cursor logic (pure, no AWS involved) -----------------------------------

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("us-east-1")
	raw := "2024-06-01T12:00:00Z"

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
	encoded := encodeCursor("2024-06-01T12:00:00Z", key)
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

func TestCursorWrongKey(t *testing.T) {
	key1 := sigKey("us-east-1")
	key2 := sigKey("ap-southeast-1")
	encoded := encodeCursor("cursor-value", key1)
	if _, err := decodeCursor(encoded, key2); err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestResolveFloorSinceOnly(t *testing.T) {
	key := sigKey("us-east-1")
	since := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	floor, err := resolveFloor("", since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(since) {
		t.Errorf("floor = %v, want %v", floor, since)
	}
}

func TestResolveFloorCursorNewerThanSince(t *testing.T) {
	key := sigKey("us-east-1")
	since := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	cursorMark := time.Date(2024, 6, 5, 0, 0, 0, 0, time.UTC)
	cursor := encodeCursor(cursorMark.Format(time.RFC3339Nano), key)

	floor, err := resolveFloor(cursor, since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(cursorMark) {
		t.Errorf("floor = %v, want cursor mark %v (cursor is newer)", floor, cursorMark)
	}
}

func TestResolveFloorSinceNewerThanCursor(t *testing.T) {
	key := sigKey("us-east-1")
	cursorMark := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	since := time.Date(2024, 6, 5, 0, 0, 0, 0, time.UTC)
	cursor := encodeCursor(cursorMark.Format(time.RFC3339Nano), key)

	floor, err := resolveFloor(cursor, since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(since) {
		t.Errorf("floor = %v, want since %v (since is newer)", floor, since)
	}
}

func TestResolveFloorTamperedCursorRejected(t *testing.T) {
	key := sigKey("us-east-1")
	cursor := encodeCursor(time.Now().Format(time.RFC3339Nano), key)
	tampered := cursor[:len(cursor)-1] + "X"
	if _, err := resolveFloor(tampered, time.Time{}, key); err == nil {
		t.Fatal("expected error for tampered cursor, got nil")
	}
}

// --- HistoryData parsing (pure) ---------------------------------------------

func TestParseHistoryDataWellFormed(t *testing.T) {
	data := `{"version":"1.0","oldState":{"stateValue":"OK"},"newState":{"stateValue":"ALARM","stateReason":"Threshold Crossed"}}`
	oldState, newState, reason := parseHistoryData(data, "fallback summary")
	if oldState != "OK" {
		t.Errorf("oldState = %q, want OK", oldState)
	}
	if newState != "ALARM" {
		t.Errorf("newState = %q, want ALARM", newState)
	}
	if reason != "Threshold Crossed" {
		t.Errorf("reason = %q, want %q", reason, "Threshold Crossed")
	}
}

func TestParseHistoryDataMalformedFallsBackToSummary(t *testing.T) {
	oldState, newState, reason := parseHistoryData("not json", "Alarm updated from OK to ALARM")
	if oldState != "unknown" || newState != "unknown" {
		t.Errorf("states = %q/%q, want unknown/unknown for malformed HistoryData", oldState, newState)
	}
	if reason != "Alarm updated from OK to ALARM" {
		t.Errorf("reason = %q, want the HistorySummary fallback", reason)
	}
}

func TestParseHistoryDataEmptyFallsBackToSummary(t *testing.T) {
	oldState, newState, reason := parseHistoryData("", "some summary")
	if oldState != "unknown" || newState != "unknown" {
		t.Errorf("states = %q/%q, want unknown/unknown for empty HistoryData", oldState, newState)
	}
	if reason != "some summary" {
		t.Errorf("reason = %q, want some summary", reason)
	}
}

func TestParseHistoryDataMissingReasonFallsBackToSummary(t *testing.T) {
	data := `{"oldState":{"stateValue":"ALARM"},"newState":{"stateValue":"OK"}}`
	_, _, reason := parseHistoryData(data, "recovered")
	if reason != "recovered" {
		t.Errorf("reason = %q, want recovered (newState has no stateReason)", reason)
	}
}

// --- wire-level tests: real *cloudwatch.Client against an httptest.Server --
//
// Unlike cmd/aws's fakeCloudTrail (a hand-written Go implementation of the
// cloudtrailAPI interface), these tests point the REAL AWS SDK v2
// *cloudwatch.Client at an httptest.Server via cloudwatch.Options.BaseEndpoint
// and hand-craft the wire response using smithy-go's public
// encoding/cbor package — CloudWatch's SDK client speaks Smithy's rpc-v2-cbor
// protocol (confirmed against the vendored v1.63.1: DescribeAlarms and
// DescribeAlarmHistory both serialize/deserialize as CBOR, not JSON or XML).
// This exercises the real request marshaling and response unmarshaling code
// path, catching wire bugs an interface-level Go fake would hide.

// cwFake is a scripted httptest.Server backing a *cloudwatch.Client. Each
// call increments callCount so a single fake can serve a canned response per
// operation without a full request router — cloudwatch's rpc-v2-cbor
// operations are distinguished only by URL path
// (/service/.../operation/<Name>), which fakeHandler inspects.
type cwFake struct {
	t *testing.T

	// describeAlarmsPages / describeAlarmHistoryPages are consumed in order,
	// one per call to the respective operation. Reading past the end serves
	// an empty response with no NextToken (pagination stops).
	describeAlarmsPages       []smithycbor.Map
	describeAlarmHistoryPages []smithycbor.Map

	alarmsCalls   int
	historyCalls  int
	gotStartDates []time.Time // one entry per DescribeAlarmHistory call; zero value means unset
	describeErr   bool        // when true, every DescribeAlarms/DescribeAlarmHistory call 500s
}

func (f *cwFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if f.describeErr {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(smithycbor.Encode(smithycbor.Map{"message": smithycbor.String("internal error")}))
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			f.t.Fatalf("read request body: %v", err)
		}

		var reqMap smithycbor.Map
		if len(body) > 0 {
			v, err := smithycbor.Decode(body)
			if err != nil {
				f.t.Fatalf("decode request body: %v", err)
			}
			reqMap, _ = v.(smithycbor.Map)
		}

		switch {
		case strings.Contains(r.URL.Path, "/DescribeAlarms"):
			var page smithycbor.Map
			if f.alarmsCalls < len(f.describeAlarmsPages) {
				page = f.describeAlarmsPages[f.alarmsCalls]
			} else {
				page = smithycbor.Map{}
			}
			f.alarmsCalls++
			writeCBOR(w, page)

		case strings.Contains(r.URL.Path, "/DescribeAlarmHistory"):
			if startTag, ok := reqMap["StartDate"].(*smithycbor.Tag); ok {
				ts, err := smithycbor.AsTime(startTag)
				if err != nil {
					f.t.Fatalf("decode StartDate: %v", err)
				}
				f.gotStartDates = append(f.gotStartDates, ts)
			} else {
				f.gotStartDates = append(f.gotStartDates, time.Time{})
			}

			var page smithycbor.Map
			if f.historyCalls < len(f.describeAlarmHistoryPages) {
				page = f.describeAlarmHistoryPages[f.historyCalls]
			} else {
				page = smithycbor.Map{}
			}
			f.historyCalls++
			writeCBOR(w, page)

		default:
			f.t.Fatalf("unexpected request path %q", r.URL.Path)
		}
	}
}

func writeCBOR(w http.ResponseWriter, v smithycbor.Value) {
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("smithy-protocol", "rpc-v2-cbor")
	w.WriteHeader(http.StatusOK)
	w.Write(smithycbor.Encode(v))
}

// newTestClient builds a real *cloudwatch.Client pointed at srv, with fake
// static credentials (never used for real auth — the fake server doesn't
// validate SigV4).
func newTestClient(t *testing.T, srv *httptest.Server) *cloudwatch.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIAFAKE", "secretfake", "")),
	)
	if err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
	url := srv.URL
	return cloudwatch.NewFromConfig(cfg, func(o *cloudwatch.Options) {
		o.BaseEndpoint = &url
	})
}

func cborTimestamp(ts time.Time) *smithycbor.Tag {
	return &smithycbor.Tag{ID: 1, Value: smithycbor.Float64(float64(ts.Unix()))}
}

func TestFetchAndNormalizeAlarmFiring(t *testing.T) {
	ts := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	fake := &cwFake{
		t: t,
		describeAlarmsPages: []smithycbor.Map{{
			"MetricAlarms": smithycbor.List{smithycbor.Map{
				"AlarmName":  smithycbor.String("high-cpu"),
				"Namespace":  smithycbor.String("AWS/EC2"),
				"MetricName": smithycbor.String("CPUUtilization"),
				"StateValue": smithycbor.String("ALARM"),
			}},
		}},
		describeAlarmHistoryPages: []smithycbor.Map{{
			"AlarmHistoryItems": smithycbor.List{smithycbor.Map{
				"AlarmName":       smithycbor.String("high-cpu"),
				"AlarmType":       smithycbor.String("MetricAlarm"),
				"HistoryItemType": smithycbor.String("StateUpdate"),
				"HistorySummary":  smithycbor.String("Alarm updated from OK to ALARM"),
				"HistoryData":     smithycbor.String(`{"version":"1.0","oldState":{"stateValue":"OK"},"newState":{"stateValue":"ALARM","stateReason":"Threshold Crossed: 1 datapoint [95.0] was greater than the threshold (90.0)."}}`),
				"Timestamp":       cborTimestamp(ts),
			}},
		}},
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client := newTestClient(t, srv)

	events, maxSeen, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchAndNormalize: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	ev := events[0]

	if ev.Source != "cloudwatch" {
		t.Errorf("Source = %q, want cloudwatch", ev.Source)
	}
	if ev.Type != "cloudwatch_alarm" {
		t.Errorf("Type = %q, want cloudwatch_alarm", ev.Type)
	}
	if ev.Org != "us-east-1" {
		t.Errorf("Org = %q, want us-east-1", ev.Org)
	}
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, ts)
	}
	if !maxSeen.Equal(ts) {
		t.Errorf("maxSeen = %v, want %v", maxSeen, ts)
	}

	var payload map[string]any
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["signal_class"] != "alert" {
		t.Errorf("signal_class = %v, want alert", payload["signal_class"])
	}
	if payload["severity"] != "high" {
		t.Errorf("severity = %v, want high", payload["severity"])
	}
	if payload["alarm_name"] != "high-cpu" {
		t.Errorf("alarm_name = %v, want high-cpu", payload["alarm_name"])
	}
	if payload["namespace"] != "AWS/EC2" {
		t.Errorf("namespace = %v, want AWS/EC2 (merged from DescribeAlarms)", payload["namespace"])
	}
	if payload["metric_name"] != "CPUUtilization" {
		t.Errorf("metric_name = %v, want CPUUtilization", payload["metric_name"])
	}
	if payload["old_state"] != "OK" {
		t.Errorf("old_state = %v, want OK", payload["old_state"])
	}
	if payload["new_state"] != "ALARM" {
		t.Errorf("new_state = %v, want ALARM", payload["new_state"])
	}
}

func TestFetchAndNormalizeSeverityMapping(t *testing.T) {
	cases := []struct {
		name         string
		historyData  string
		wantSeverity string
	}{
		{"alarm", `{"newState":{"stateValue":"ALARM"}}`, "high"},
		{"ok-recovery", `{"newState":{"stateValue":"OK"}}`, "info"},
		{"insufficient-data", `{"newState":{"stateValue":"INSUFFICIENT_DATA"}}`, "info"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
			fake := &cwFake{
				t: t,
				describeAlarmHistoryPages: []smithycbor.Map{{
					"AlarmHistoryItems": smithycbor.List{smithycbor.Map{
						"AlarmName":       smithycbor.String("a"),
						"HistoryItemType": smithycbor.String("StateUpdate"),
						"HistoryData":     smithycbor.String(tc.historyData),
						"Timestamp":       cborTimestamp(ts),
					}},
				}},
			}
			srv := httptest.NewServer(fake.handler())
			defer srv.Close()
			client := newTestClient(t, srv)

			events, _, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{})
			if err != nil {
				t.Fatalf("fetchAndNormalize: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("want 1 event, got %d", len(events))
			}
			var payload map[string]any
			if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if payload["severity"] != tc.wantSeverity {
				t.Errorf("severity = %v, want %v", payload["severity"], tc.wantSeverity)
			}
		})
	}
}

// TestFetchAndNormalizePagination proves DescribeAlarmHistory's NextToken is
// followed to completion (two pages, one item each) before fetchAndNormalize
// returns.
func TestFetchAndNormalizePagination(t *testing.T) {
	ts1 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	ts2 := time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)
	fake := &cwFake{
		t: t,
		describeAlarmHistoryPages: []smithycbor.Map{
			{
				"AlarmHistoryItems": smithycbor.List{smithycbor.Map{
					"AlarmName":       smithycbor.String("a"),
					"HistoryItemType": smithycbor.String("StateUpdate"),
					"HistoryData":     smithycbor.String(`{"newState":{"stateValue":"ALARM"}}`),
					"Timestamp":       cborTimestamp(ts1),
				}},
				"NextToken": smithycbor.String("page-2"),
			},
			{
				"AlarmHistoryItems": smithycbor.List{smithycbor.Map{
					"AlarmName":       smithycbor.String("b"),
					"HistoryItemType": smithycbor.String("StateUpdate"),
					"HistoryData":     smithycbor.String(`{"newState":{"stateValue":"OK"}}`),
					"Timestamp":       cborTimestamp(ts2),
				}},
			},
		},
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client := newTestClient(t, srv)

	events, maxSeen, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchAndNormalize: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events across 2 pages, got %d", len(events))
	}
	if fake.historyCalls != 2 {
		t.Errorf("historyCalls = %d, want 2 (NextToken must be followed)", fake.historyCalls)
	}
	if !maxSeen.Equal(ts2) {
		t.Errorf("maxSeen = %v, want %v (the later of the two pages)", maxSeen, ts2)
	}
}

// TestFetchAndNormalizeFloorForwarded proves the resume floor is sent as
// DescribeAlarmHistory's StartDate on the wire — not just held in a Go
// variable that never reaches the request.
func TestFetchAndNormalizeFloorForwarded(t *testing.T) {
	floor := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	fake := &cwFake{t: t, describeAlarmHistoryPages: []smithycbor.Map{{}}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client := newTestClient(t, srv)

	if _, _, err := fetchAndNormalize(context.Background(), client, "us-east-1", floor); err != nil {
		t.Fatalf("fetchAndNormalize: %v", err)
	}
	if len(fake.gotStartDates) != 1 {
		t.Fatalf("want 1 DescribeAlarmHistory call, got %d", len(fake.gotStartDates))
	}
	if !fake.gotStartDates[0].Equal(floor) {
		t.Errorf("StartDate sent = %v, want floor %v", fake.gotStartDates[0], floor)
	}
}

// TestFetchAndNormalizeTsReliableGuard proves a history item with no
// Timestamp field never advances maxSeen (the resume cursor) even though the
// event itself is still emitted with a fabricated time.Now() timestamp.
func TestFetchAndNormalizeTsReliableGuard(t *testing.T) {
	fake := &cwFake{
		t: t,
		describeAlarmHistoryPages: []smithycbor.Map{{
			"AlarmHistoryItems": smithycbor.List{smithycbor.Map{
				"AlarmName":       smithycbor.String("a"),
				"HistoryItemType": smithycbor.String("StateUpdate"),
				"HistoryData":     smithycbor.String(`{"newState":{"stateValue":"ALARM"}}`),
				// Timestamp deliberately omitted.
			}},
		}},
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client := newTestClient(t, srv)

	events, maxSeen, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchAndNormalize: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event even without a reliable timestamp, got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero (no reliably-timestamped item was seen)", maxSeen)
	}
}

// TestFetchAndNormalizeDeletedAlarmMissingContext proves a history item for
// an alarm no longer present in DescribeAlarms (deleted, but CloudWatch
// retains its history) still produces an event — with empty namespace/metric
// rather than a hard failure.
func TestFetchAndNormalizeDeletedAlarmMissingContext(t *testing.T) {
	ts := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	fake := &cwFake{
		t:                   t,
		describeAlarmsPages: []smithycbor.Map{{}}, // no current alarms
		describeAlarmHistoryPages: []smithycbor.Map{{
			"AlarmHistoryItems": smithycbor.List{smithycbor.Map{
				"AlarmName":       smithycbor.String("deleted-alarm"),
				"HistoryItemType": smithycbor.String("StateUpdate"),
				"HistoryData":     smithycbor.String(`{"newState":{"stateValue":"ALARM"}}`),
				"Timestamp":       cborTimestamp(ts),
			}},
		}},
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client := newTestClient(t, srv)

	events, _, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchAndNormalize: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	var payload map[string]any
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, ok := payload["namespace"]; ok {
		t.Error("namespace should be omitted for a deleted alarm with no DescribeAlarms match")
	}
}

// TestFetchAndNormalizeRedaction proves credential-shaped material anywhere
// in the raw AlarmHistoryItem is redacted before it reaches the payload —
// e.g. a AlarmContributorAttributes entry that happens to carry a
// sessionToken-shaped key. Redaction is internal/normalize's job
// (PayloadJSON -> redactCredentials); this test proves the connector actually
// routes the raw item through it.
func TestFetchAndNormalizeRedaction(t *testing.T) {
	ts := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	fake := &cwFake{
		t: t,
		describeAlarmHistoryPages: []smithycbor.Map{{
			"AlarmHistoryItems": smithycbor.List{smithycbor.Map{
				"AlarmName":       smithycbor.String("a"),
				"HistoryItemType": smithycbor.String("StateUpdate"),
				"HistoryData":     smithycbor.String(`{"newState":{"stateValue":"ALARM"}}`),
				"Timestamp":       cborTimestamp(ts),
				"AlarmContributorAttributes": smithycbor.Map{
					"sessionToken": smithycbor.String("FQoGZXIvYXdzEB0aDL-super-secret-session-token"),
				},
			}},
		}},
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client := newTestClient(t, srv)

	events, _, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchAndNormalize: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if strings.Contains(string(events[0].Payload), "super-secret-session-token") {
		t.Errorf("raw session token leaked into payload unredacted: %s", events[0].Payload)
	}
	if !strings.Contains(string(events[0].Payload), "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in payload, got: %s", events[0].Payload)
	}
}

// TestFetchAndNormalizeEmptyAccount proves a zero-alarm, zero-history account
// is a legitimate, well-formed empty result — not an error.
func TestFetchAndNormalizeEmptyAccount(t *testing.T) {
	fake := &cwFake{t: t}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client := newTestClient(t, srv)

	events, maxSeen, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{})
	if err != nil {
		t.Fatalf("fetchAndNormalize on an empty account: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("want 0 events for an empty account, got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero", maxSeen)
	}
}

// TestFetchAndNormalizeAPIError proves an upstream API error propagates
// (fail loud) rather than being swallowed into a silent empty result.
func TestFetchAndNormalizeAPIError(t *testing.T) {
	fake := &cwFake{t: t, describeErr: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client := newTestClient(t, srv)

	if _, _, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{}); err == nil {
		t.Fatal("expected an error from a failing DescribeAlarms call, got nil")
	}
}

// TestFetchAndNormalizeOnlyStateUpdateRequested proves the connector always
// filters DescribeAlarmHistory to HistoryItemType=StateUpdate — never
// ConfigurationUpdate/Action/AlarmContributor* items, which are not state
// transitions.
func TestFetchAndNormalizeOnlyStateUpdateRequested(t *testing.T) {
	var gotFilter smithycbor.Value
	fake := &cwFake{t: t, describeAlarmHistoryPages: []smithycbor.Map{{}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/DescribeAlarmHistory") {
			body, _ := io.ReadAll(r.Body)
			v, err := smithycbor.Decode(body)
			if err != nil {
				t.Fatalf("decode request: %v", err)
			}
			m, _ := v.(smithycbor.Map)
			gotFilter = m["HistoryItemType"]
			writeCBOR(w, smithycbor.Map{})
			return
		}
		fake.handler()(w, r)
	}))
	defer srv.Close()
	client := newTestClient(t, srv)

	if _, _, err := fetchAndNormalize(context.Background(), client, "us-east-1", time.Time{}); err != nil {
		t.Fatalf("fetchAndNormalize: %v", err)
	}
	s, ok := gotFilter.(smithycbor.String)
	if !ok || string(s) != "StateUpdate" {
		t.Errorf("HistoryItemType sent = %v, want StateUpdate", gotFilter)
	}
}
