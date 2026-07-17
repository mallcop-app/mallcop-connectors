package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

func strPtr(s string) *string   { return &s }
func f64Ptr(f float64) *float64 { return &f }
func boolPtr(b bool) *bool      { return &b }
func i32Ptr(i int32) *int32     { return &i }

// --- fake GuardDuty client (no network, no live creds) ----------------------

// fakeListFindingsPage is one page of a scripted ListFindings response.
type fakeListFindingsPage struct {
	ids       []string
	nextToken *string
}

// fakeGuardDuty implements guarddutyAPI entirely in memory, mirroring the
// fakeCloudTrail idiom in cmd/aws/aws_test.go. It records the FindingCriteria
// seen on every ListFindings call so tests can assert the resume floor was
// actually sent, and serves GetFindings from a fixed finding set keyed by ID.
type fakeGuardDuty struct {
	detectorIDs []string
	pages       []fakeListFindingsPage
	findings    map[string]types.Finding

	listCall           int
	gotFindingCriteria []*types.FindingCriteria
	getFindingsCalls   [][]string
}

func (f *fakeGuardDuty) ListDetectors(_ context.Context, _ *guardduty.ListDetectorsInput, _ ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: f.detectorIDs}, nil
}

func (f *fakeGuardDuty) ListFindings(_ context.Context, in *guardduty.ListFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	f.gotFindingCriteria = append(f.gotFindingCriteria, in.FindingCriteria)
	if f.listCall >= len(f.pages) {
		return &guardduty.ListFindingsOutput{}, nil
	}
	p := f.pages[f.listCall]
	f.listCall++
	return &guardduty.ListFindingsOutput{FindingIds: p.ids, NextToken: p.nextToken}, nil
}

func (f *fakeGuardDuty) GetFindings(_ context.Context, in *guardduty.GetFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error) {
	f.getFindingsCalls = append(f.getFindingsCalls, in.FindingIds)
	var out []types.Finding
	for _, id := range in.FindingIds {
		if fnd, ok := f.findings[id]; ok {
			out = append(out, fnd)
		}
	}
	return &guardduty.GetFindingsOutput{Findings: out}, nil
}

func testFinding(id, updatedAt string, severity float64) types.Finding {
	return types.Finding{
		Id:         strPtr(id),
		AccountId:  strPtr("111111111111"),
		Region:     strPtr("us-east-1"),
		Arn:        strPtr("arn:aws:guardduty:us-east-1:111111111111:detector/det-1/finding/" + id),
		Type:       strPtr("UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B"),
		Title:      strPtr("test finding " + id),
		CreatedAt:  strPtr(updatedAt),
		UpdatedAt:  strPtr(updatedAt),
		Severity:   f64Ptr(severity),
		Confidence: f64Ptr(5.0),
		Resource: &types.Resource{
			ResourceType: strPtr("AccessKey"),
			AccessKeyDetails: &types.AccessKeyDetails{
				UserName: strPtr("alice"),
			},
		},
		Service: &types.Service{
			DetectorId: strPtr("det-1"),
			Archived:   boolPtr(false),
			Count:      i32Ptr(1),
		},
	}
}

// --- cursor tests -------------------------------------------------------

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("us-east-1")
	raw := "2024-06-01T12:05:00.000000000Z"

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

func TestResolveFloorTamperedCursorHardFails(t *testing.T) {
	key := sigKey("us-east-1")
	encoded := encodeCursor("2024-06-01T12:00:00Z", key)
	parts := strings.SplitN(encoded, ".", 2)
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	if _, _, err := resolveFloor(tampered, time.Time{}, key); err == nil {
		t.Fatal("expected hard failure for tampered cursor, got nil")
	}
}

func TestResolveFloorNonTimestampPayloadHardFails(t *testing.T) {
	key := sigKey("us-east-1")
	// A brand-new connector has no legacy pagination-token cursor format to
	// self-heal from (unlike aws/github's PR #7 migration) — an HMAC-valid
	// but non-timestamp payload is just a bad cursor.
	badCursor := encodeCursor("not-a-timestamp", key)
	if _, _, err := resolveFloor(badCursor, time.Time{}, key); err == nil {
		t.Fatal("expected hard failure for non-timestamp cursor payload, got nil")
	}
}

func TestResolveFloorCursorWinsOverOlderSince(t *testing.T) {
	key := sigKey("us-east-1")
	cursorTS := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	cursor := encodeCursor(cursorTS.Format(time.RFC3339Nano), key)
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	floor, strict, err := resolveFloor(cursor, since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(cursorTS) {
		t.Errorf("floor = %v, want cursor timestamp %v", floor, cursorTS)
	}
	if !strict {
		t.Error("strict = false, want true when resuming from a cursor")
	}
}

func TestResolveFloorSinceWinsOverOlderCursor(t *testing.T) {
	key := sigKey("us-east-1")
	cursorTS := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	cursor := encodeCursor(cursorTS.Format(time.RFC3339Nano), key)
	since := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

	floor, strict, err := resolveFloor(cursor, since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(since) {
		t.Errorf("floor = %v, want since %v", floor, since)
	}
	if strict {
		t.Error("strict = true, want false when --since is newer than the cursor (inclusive semantics)")
	}
}

// --- normalizeFinding tests ----------------------------------------------

func TestNormalizeFinding(t *testing.T) {
	f := testFinding("finding-1", "2024-06-01T12:05:00.000Z", 5.5)
	ev, tsReliable, err := normalizeFinding(f)
	if err != nil {
		t.Fatalf("normalizeFinding: %v", err)
	}
	if ev.Source != "guardduty" {
		t.Errorf("Source = %q, want guardduty", ev.Source)
	}
	if ev.Type != "guardduty_finding" {
		t.Errorf("Type = %q, want guardduty_finding", ev.Type)
	}
	if ev.Actor != "alice" {
		t.Errorf("Actor = %q, want alice (from Resource.AccessKeyDetails.UserName)", ev.Actor)
	}
	if ev.Org != "111111111111" {
		t.Errorf("Org = %q, want account id", ev.Org)
	}
	if !tsReliable {
		t.Error("tsReliable = false, want true when UpdatedAt is present and parses")
	}
	wantTS := time.Date(2024, 6, 1, 12, 5, 0, 0, time.UTC)
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, wantTS)
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}

	var payload map[string]any
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("Payload is not valid JSON: %v", err)
	}
	if payload["signal_class"] != "alert" {
		t.Errorf("payload signal_class = %v, want alert", payload["signal_class"])
	}
	if payload["severity"] != 5.5 {
		t.Errorf("payload severity = %v, want 5.5", payload["severity"])
	}
}

// TestNormalizeFindingMissingUpdatedAtDoesNotPoisonReliability: a finding
// with no UpdatedAt falls back to time.Now() for display, but tsReliable must
// be false — the caller (fetchFindings) must not let it advance maxSeen.
func TestNormalizeFindingMissingUpdatedAtDoesNotPoisonReliability(t *testing.T) {
	f := types.Finding{Id: strPtr("finding-x"), Type: strPtr("SomeType")}
	ev, tsReliable, err := normalizeFinding(f)
	if err != nil {
		t.Fatalf("normalizeFinding: %v", err)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero, want a fallback time.Now()")
	}
	if tsReliable {
		t.Error("tsReliable = true, want false when UpdatedAt is missing (would poison the resume cursor to wall-clock now)")
	}
	if ev.Actor != "" {
		t.Errorf("Actor = %q, want empty when Resource is nil", ev.Actor)
	}
}

// --- listDetectorIDs tests -------------------------------------------------

func TestListDetectorIDs(t *testing.T) {
	client := &fakeGuardDuty{detectorIDs: []string{"det-1"}}
	ids, err := listDetectorIDs(context.Background(), client)
	if err != nil {
		t.Fatalf("listDetectorIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != "det-1" {
		t.Errorf("ids = %v, want [det-1]", ids)
	}
}

func TestListDetectorIDsEmpty(t *testing.T) {
	client := &fakeGuardDuty{}
	ids, err := listDetectorIDs(context.Background(), client)
	if err != nil {
		t.Fatalf("listDetectorIDs: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v, want empty (GuardDuty not enabled)", ids)
	}
}

// --- fetchFindings tests ----------------------------------------------------

// (a) complete pagination across ListFindings pages emits a cursor whose
// decoded payload is the max emitted finding UpdatedAt, and GetFindings is
// called once per ListFindings page with exactly that page's IDs.
func TestFetchFindingsCompletePaginationHighWaterCursor(t *testing.T) {
	f1 := testFinding("f1", "2024-06-01T12:00:00.000Z", 3.0)
	f2 := testFinding("f2", "2024-06-01T13:30:00.000Z", 7.0)
	client := &fakeGuardDuty{
		pages: []fakeListFindingsPage{
			{ids: []string{"f1"}, nextToken: strPtr("page-2")},
			{ids: []string{"f2"}},
		},
		findings: map[string]types.Finding{"f1": f1, "f2": f2},
	}

	events, maxSeen, err := fetchFindings(context.Background(), client, "det-1", time.Time{}, false)
	if err != nil {
		t.Fatalf("fetchFindings: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	if client.listCall != 2 {
		t.Fatalf("want 2 ListFindings calls, got %d", client.listCall)
	}
	if len(client.getFindingsCalls) != 2 {
		t.Fatalf("want 2 GetFindings calls (one per page), got %d", len(client.getFindingsCalls))
	}

	want := time.Date(2024, 6, 1, 13, 30, 0, 0, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v", maxSeen, want)
	}

	key := sigKey("us-east-1")
	encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, decoded); err != nil {
		t.Fatalf("cursor payload is not a timestamp: %v", err)
	}
}

// (b) a non-strict floor (--since) sends GreaterThanOrEqual in epoch millis;
// a strict floor (resumed cursor) sends GreaterThan.
func TestFetchFindingsFloorCriteria(t *testing.T) {
	floor := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

	client := &fakeGuardDuty{}
	if _, _, err := fetchFindings(context.Background(), client, "det-1", floor, false); err != nil {
		t.Fatalf("fetchFindings: %v", err)
	}
	if len(client.gotFindingCriteria) != 1 || client.gotFindingCriteria[0] == nil {
		t.Fatal("FindingCriteria not set for non-zero floor")
	}
	cond := client.gotFindingCriteria[0].Criterion["updatedAt"]
	if cond.GreaterThanOrEqual == nil || *cond.GreaterThanOrEqual != floor.UnixMilli() {
		t.Errorf("GreaterThanOrEqual = %v, want %d (non-strict/--since is inclusive)", cond.GreaterThanOrEqual, floor.UnixMilli())
	}
	if cond.GreaterThan != nil {
		t.Errorf("GreaterThan should be unset for non-strict floor, got %v", *cond.GreaterThan)
	}

	client2 := &fakeGuardDuty{}
	if _, _, err := fetchFindings(context.Background(), client2, "det-1", floor, true); err != nil {
		t.Fatalf("fetchFindings: %v", err)
	}
	cond2 := client2.gotFindingCriteria[0].Criterion["updatedAt"]
	if cond2.GreaterThan == nil || *cond2.GreaterThan != floor.UnixMilli() {
		t.Errorf("GreaterThan = %v, want %d (strict/resumed cursor excludes the boundary)", cond2.GreaterThan, floor.UnixMilli())
	}
	if cond2.GreaterThanOrEqual != nil {
		t.Errorf("GreaterThanOrEqual should be unset for strict floor, got %v", *cond2.GreaterThanOrEqual)
	}
}

// (c) zero events emitted -> caller (run()) must not print a "cursor:" line.
// fetchFindings itself signals this via a zero maxSeen.
func TestFetchFindingsZeroEventsNoCursor(t *testing.T) {
	client := &fakeGuardDuty{pages: []fakeListFindingsPage{{ids: nil}}}
	events, maxSeen, err := fetchFindings(context.Background(), client, "det-1", time.Time{}, false)
	if err != nil {
		t.Fatalf("fetchFindings: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("want 0 events, got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero", maxSeen)
	}
}

// (d) a page mixing a good-UpdatedAt finding with a missing-UpdatedAt finding
// must advance maxSeen to the good finding's time, not the fabricated
// time.Now() fallback used for the missing-UpdatedAt finding. Regression test
// for the high-water cursor poisoning bug (PR #7's tsReliable guard).
func TestFetchFindingsMissingUpdatedAtDoesNotPoisonMaxSeen(t *testing.T) {
	good := testFinding("f-good", "2024-06-01T12:00:00.000Z", 3.0)
	noTS := types.Finding{Id: strPtr("f-no-ts"), Type: strPtr("SomeType")} // normalizeFinding falls back to time.Now(), always after `good`

	client := &fakeGuardDuty{
		pages:    []fakeListFindingsPage{{ids: []string{"f-good", "f-no-ts"}}},
		findings: map[string]types.Finding{"f-good": good, "f-no-ts": noTS},
	}

	events, maxSeen, err := fetchFindings(context.Background(), client, "det-1", time.Time{}, false)
	if err != nil {
		t.Fatalf("fetchFindings: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events emitted (both, even the unreliable one), got %d", len(events))
	}
	want := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v (the fabricated now() timestamp must not advance the cursor)", maxSeen, want)
	}
}

// --- event.Event schema round-trip ----------------------------------------

func TestNormalizeFindingEventSchemaRoundtrip(t *testing.T) {
	f := testFinding("finding-rt", "2024-06-01T12:05:00.000Z", 5.5)
	ev, _, err := normalizeFinding(f)
	if err != nil {
		t.Fatalf("normalizeFinding: %v", err)
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
	if decoded.Source != "guardduty" {
		t.Errorf("Source mismatch: %q", decoded.Source)
	}
}
