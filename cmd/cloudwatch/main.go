// Command cloudwatch polls AWS CloudWatch alarm history for state
// TRANSITIONS (not steady-state alarm status) and emits normalized mallcop
// events as JSONL to stdout.
//
// This is an alert-stream connector (mallcoppro-ee9): a CloudWatch alarm
// state transition already IS an alert — CloudWatch itself decided a
// threshold was crossed — unlike the activity-stream connectors (aws,
// github, ...) which normalize raw activity that mallcop's OWN detectors
// then judge.
//
// Usage:
//
//	cloudwatch --region <region> [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: standard AWS credentials chain (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION),
// including GitHub Actions OIDC assume-role (same mallcop-monitor read-only role the aws
// connector uses — see docs/connector-setup.md).
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen = 200

	// maxPages is a hard stop against a runaway pagination loop (a stuck
	// NextToken that never terminates) for either DescribeAlarms or
	// DescribeAlarmHistory.
	maxPages = 1000
)

var cursorRE = regexp.MustCompile(`^[A-Za-z0-9+/=_\-]+$`)

func validateCursor(cursor string) error {
	if len(cursor) > cursorMaxLen {
		return fmt.Errorf("invalid cursor: length %d exceeds maximum %d", len(cursor), cursorMaxLen)
	}
	if strings.ContainsAny(cursor, "\n\r\x00") {
		return fmt.Errorf("invalid cursor: contains control characters")
	}
	if !cursorRE.MatchString(cursor) {
		return fmt.Errorf("invalid cursor: contains unexpected characters")
	}
	return nil
}

func sigKey(region string) []byte {
	return []byte(fmt.Sprintf("mallcop-cloudwatch-cursor:%s", region))
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
// timestamps wins), matching every other connector's --since/--cursor
// contract. Unlike cmd/aws's resolveFloor, there is no legacy-cursor
// migration here: cloudwatch is a brand-new connector, so every cursor it
// ever emits is already a high-water timestamp (PR #7's lesson applied from
// day one, not retrofitted).
func resolveFloor(cursorArg string, sinceTime time.Time, key []byte) (time.Time, error) {
	var cursorMark time.Time
	if cursorArg != "" {
		raw, err := decodeCursor(cursorArg, key)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		cursorMark, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid checkpoint cursor: bad timestamp %q: %w", raw, err)
		}
	}

	floor := sinceTime
	if cursorMark.After(floor) {
		floor = cursorMark
	}
	return floor, nil
}

// cloudwatchAPI is the subset of *cloudwatch.Client this connector uses.
// Tests point a real *cloudwatch.Client at an httptest.Server (via
// cloudwatch.Options.BaseEndpoint) rather than faking this interface in Go —
// that exercises the actual AWS SDK request/response wire protocol
// (smithy rpc-v2-cbor), catching serialization bugs a hand-rolled Go fake
// would hide.
type cloudwatchAPI interface {
	DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
	DescribeAlarmHistory(ctx context.Context, params *cloudwatch.DescribeAlarmHistoryInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmHistoryOutput, error)
}

var _ cloudwatchAPI = (*cloudwatch.Client)(nil)

// alarmContext is the subset of a MetricAlarm needed to enrich a history
// item's event payload. AlarmHistoryItem itself carries no namespace/metric —
// only DescribeAlarms does — so fetchAlarmContext builds a lookup table keyed
// by alarm name up front.
type alarmContext struct {
	namespace  string
	metricName string
}

// fetchAlarmContext pages DescribeAlarms to completion and returns a lookup
// table of every current metric alarm's namespace/metric, keyed by alarm
// name. An alarm whose history is being read may have since been deleted —
// CloudWatch retains history for deleted alarms — so a miss in this table is
// expected and handled gracefully by the caller (namespace/metric emitted
// empty, never a hard failure).
func fetchAlarmContext(ctx context.Context, client cloudwatchAPI) (map[string]alarmContext, error) {
	out := map[string]alarmContext{}
	input := &cloudwatch.DescribeAlarmsInput{}

	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("exceeded max pages (%d) polling DescribeAlarms — possible pagination loop", maxPages)
		}

		resp, err := client.DescribeAlarms(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("DescribeAlarms: %w", err)
		}

		for _, a := range resp.MetricAlarms {
			if a.AlarmName == nil {
				continue
			}
			var ac alarmContext
			if a.Namespace != nil {
				ac.namespace = *a.Namespace
			}
			if a.MetricName != nil {
				ac.metricName = *a.MetricName
			}
			out[*a.AlarmName] = ac
		}

		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		input.NextToken = resp.NextToken
	}

	return out, nil
}

// fetchAlarmHistory pages DescribeAlarmHistory (HistoryItemType=StateUpdate
// only — every OTHER history item type, e.g. ConfigurationUpdate or Action,
// is an admin/notification event, not an alarm state transition, and is out
// of scope for this connector) to completion, starting at floor.
func fetchAlarmHistory(ctx context.Context, client cloudwatchAPI, floor time.Time) ([]types.AlarmHistoryItem, error) {
	input := &cloudwatch.DescribeAlarmHistoryInput{
		HistoryItemType: types.HistoryItemTypeStateUpdate,
	}
	if !floor.IsZero() {
		input.StartDate = &floor
	}

	var all []types.AlarmHistoryItem
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("exceeded max pages (%d) polling DescribeAlarmHistory — possible pagination loop", maxPages)
		}

		resp, err := client.DescribeAlarmHistory(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("DescribeAlarmHistory: %w", err)
		}
		all = append(all, resp.AlarmHistoryItems...)

		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		input.NextToken = resp.NextToken
	}

	return all, nil
}

// historyStateData is the documented JSON shape of AlarmHistoryItem.HistoryData
// for a StateUpdate item: {"version":"1.0","oldState":{"stateValue":"OK",...},
// "newState":{"stateValue":"ALARM","stateReason":"...",...}}. It is treated as
// best-effort: HistoryData is an opaque string CloudWatch does not formally
// contract the schema of, so a parse failure must never abort the connector —
// see parseHistoryData.
type historyStateData struct {
	OldState struct {
		StateValue string `json:"stateValue"`
	} `json:"oldState"`
	NewState struct {
		StateValue  string `json:"stateValue"`
		StateReason string `json:"stateReason"`
	} `json:"newState"`
}

// parseHistoryData best-effort parses an AlarmHistoryItem's HistoryData JSON
// string into old/new state values and the new state's reason. On any parse
// failure (nil, empty, or unexpected shape) it falls back to
// HistorySummary/"unknown" rather than erroring — a StateUpdate item missing
// or carrying an unparsable HistoryData is still a real transition worth
// emitting; losing old_state/new_state fidelity is better than losing the
// event entirely (the honest-mapping rule from normalize.Mercury applies
// here too: never invent data, but never silently drop a real signal for
// want of a field).
func parseHistoryData(historyData, historySummary string) (oldState, newState, reason string) {
	if historyData != "" {
		var d historyStateData
		if err := json.Unmarshal([]byte(historyData), &d); err == nil {
			if d.OldState.StateValue != "" || d.NewState.StateValue != "" {
				reason = d.NewState.StateReason
				if reason == "" {
					reason = historySummary
				}
				return d.OldState.StateValue, d.NewState.StateValue, reason
			}
		}
	}
	return "unknown", "unknown", historySummary
}

// normalizeHistoryItem maps one raw CloudWatch AlarmHistoryItem to a mallcop
// event. alarms is the DescribeAlarms lookup table (namespace/metric context;
// may be missing an entry for a deleted alarm — handled gracefully).
//
// The second return value, tsReliable, is true only when the event's
// Timestamp came from the history item's own Timestamp field. A StateUpdate
// item without a Timestamp would be an API contract violation we've never
// observed live, but if it ever happens the fabricated time.Now() fallback
// must never be allowed to advance the resume high-water mark — same
// tsReliable guard as cmd/aws and cmd/github (PR #7 pattern).
func normalizeHistoryItem(item types.AlarmHistoryItem, alarms map[string]alarmContext, region string) (*event.Event, bool, error) {
	alarmName := ""
	if item.AlarmName != nil {
		alarmName = *item.AlarmName
	}

	historyData := ""
	if item.HistoryData != nil {
		historyData = *item.HistoryData
	}
	historySummary := ""
	if item.HistorySummary != nil {
		historySummary = *item.HistorySummary
	}

	ts := time.Now().UTC()
	tsReliable := false
	if item.Timestamp != nil {
		ts = item.Timestamp.UTC()
		tsReliable = true
	}

	oldState, newState, reason := parseHistoryData(historyData, historySummary)

	ac := alarms[alarmName]

	rawJSON, err := json.Marshal(item)
	if err != nil {
		return nil, false, fmt.Errorf("marshal history item: %w", err)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(rawJSON, &rawMap); err != nil {
		return nil, false, fmt.Errorf("decode history item: %w", err)
	}

	results := normalize.CloudWatchAlarm(alarmName, ac.namespace, ac.metricName, oldState, newState, reason)
	if len(results) != 1 {
		return nil, false, fmt.Errorf("unexpected result count %d from normalize.CloudWatchAlarm", len(results))
	}
	r := results[0]

	payload, err := r.PayloadJSON(rawMap)
	if err != nil {
		return nil, false, fmt.Errorf("marshal payload: %w", err)
	}

	// AlarmHistoryItem carries no explicit unique ID. A transition is
	// content-addressed instead: alarm name + timestamp + a hash of the raw
	// history record, so distinct transitions at the same timestamp (should
	// CloudWatch ever emit more than one) still get distinct IDs, and a
	// resumed run emitting the exact same boundary transition again produces
	// the exact same ID — core's per-ID dedupe (v0.11.3+) drops the repeat.
	idSrc := fmt.Sprintf("aws:cloudwatch:%s:%s:%d:%s", region, alarmName, ts.UnixNano(), sha256Hex(historyData+historySummary))

	return &event.Event{
		ID:        sha256Hex(idSrc),
		Source:    "cloudwatch",
		Type:      r.Type,
		Timestamp: ts,
		Org:       region,
		Payload:   payload,
	}, tsReliable, nil
}

// fetchAndNormalize fetches alarm context + history and normalizes every
// StateUpdate item into a mallcop event, returning the events plus the
// maximum reliably-timestamped event seen (the next run's resume cursor).
// Split out from run() so tests can inject a cloudwatchAPI client (a real
// *cloudwatch.Client pointed at an httptest.Server, or any other
// implementation) without needing real AWS credentials or touching stdout.
func fetchAndNormalize(ctx context.Context, client cloudwatchAPI, region string, floor time.Time) ([]*event.Event, time.Time, error) {
	alarms, err := fetchAlarmContext(ctx, client)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("fetch alarm context: %w", err)
	}

	items, err := fetchAlarmHistory(ctx, client, floor)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("fetch alarm history: %w", err)
	}

	var events []*event.Event
	var maxSeen time.Time
	for _, item := range items {
		ev, tsReliable, err := normalizeHistoryItem(item, alarms, region)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping alarm history item: %v\n", err)
			continue
		}
		events = append(events, ev)
		// Only a real source timestamp may advance the resume high-water
		// mark — see normalizeHistoryItem's tsReliable doc.
		if tsReliable && ev.Timestamp.After(maxSeen) {
			maxSeen = ev.Timestamp
		}
	}

	return events, maxSeen, nil
}

func run() error {
	var (
		region    = flag.String("region", "", "AWS region (overrides AWS_REGION env var)")
		since     = flag.String("since", "", "RFC3339 timestamp to filter alarm history (e.g. 2024-01-01T00:00:00Z)")
		cursorArg = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	)
	flag.Parse()

	awsRegion := *region
	if awsRegion == "" {
		awsRegion = os.Getenv("AWS_REGION")
	}
	if awsRegion == "" {
		awsRegion = os.Getenv("AWS_DEFAULT_REGION")
	}
	if awsRegion == "" {
		awsRegion = "us-east-1"
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(awsRegion)
	floor, err := resolveFloor(*cursorArg, sinceTime, key)
	if err != nil {
		return err
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	client := cloudwatch.NewFromConfig(cfg)

	events, maxSeen, err := fetchAndNormalize(ctx, client, awsRegion, floor)
	if err != nil {
		return err
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	// Only emit a cursor when at least one reliably-timestamped event was
	// emitted this run; zero such events means the caller should keep using
	// its previous cursor.
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
