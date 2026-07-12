package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// --- fake S3 client (no network, no live creds) -----------------------------

type fakeObject struct {
	key          string
	body         []byte
	lastModified time.Time
}

// fakeS3Client implements s3API entirely in memory over a fixed object set.
type fakeS3Client struct {
	objects []fakeObject
	gets    []string // records every key GetObject was called with
}

func (f *fakeS3Client) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := ""
	if in.Prefix != nil {
		prefix = *in.Prefix
	}
	delim := ""
	if in.Delimiter != nil {
		delim = *in.Delimiter
	}

	seenPrefix := map[string]bool{}
	var commonPrefixes []types.CommonPrefix
	var contents []types.Object

	for _, obj := range f.objects {
		if !strings.HasPrefix(obj.key, prefix) {
			continue
		}
		rest := obj.key[len(prefix):]
		if delim != "" {
			if idx := strings.Index(rest, delim); idx >= 0 {
				cp := prefix + rest[:idx+len(delim)]
				if !seenPrefix[cp] {
					seenPrefix[cp] = true
					cpCopy := cp
					commonPrefixes = append(commonPrefixes, types.CommonPrefix{Prefix: &cpCopy})
				}
				continue
			}
		}
		keyCopy := obj.key
		lm := obj.lastModified
		sz := int64(len(obj.body))
		contents = append(contents, types.Object{Key: &keyCopy, LastModified: &lm, Size: &sz})
	}

	sort.Slice(commonPrefixes, func(i, j int) bool { return *commonPrefixes[i].Prefix < *commonPrefixes[j].Prefix })
	sort.Slice(contents, func(i, j int) bool { return *contents[i].Key < *contents[j].Key })

	notTruncated := false
	return &s3.ListObjectsV2Output{
		CommonPrefixes: commonPrefixes,
		Contents:       contents,
		IsTruncated:    &notTruncated,
	}, nil
}

func (f *fakeS3Client) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := ""
	if in.Key != nil {
		key = *in.Key
	}
	f.gets = append(f.gets, key)
	for _, obj := range f.objects {
		if obj.key == key {
			return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(obj.body))}, nil
		}
	}
	return nil, io.ErrUnexpectedEOF
}

// --- fixtures ----------------------------------------------------------------

func gzipRecords(t *testing.T, records []map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"Records": records})
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func consoleLoginFailure(eventID, eventTime string) map[string]any {
	return map[string]any{
		"eventVersion":       "1.08",
		"eventID":            eventID,
		"eventTime":          eventTime,
		"eventName":          "ConsoleLogin",
		"awsRegion":          "us-east-1",
		"recipientAccountId": "111111111111",
		"userIdentity": map[string]any{
			"type":     "IAMUser",
			"userName": "alice",
			"arn":      "arn:aws:iam::111111111111:user/alice",
		},
		"responseElements": map[string]any{"ConsoleLogin": "Failure"},
		"errorMessage":     "Failed authentication",
	}
}

func attachUserPolicy(eventID, eventTime string) map[string]any {
	return map[string]any{
		"eventID":            eventID,
		"eventTime":          eventTime,
		"eventName":          "AttachUserPolicy",
		"awsRegion":          "us-east-1",
		"recipientAccountId": "111111111111",
		"userIdentity": map[string]any{
			"type":     "IAMUser",
			"userName": "bob",
			"arn":      "arn:aws:iam::111111111111:user/bob",
		},
		"requestParameters": map[string]any{
			"userName":  "carol",
			"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}

func getObjectRecord(eventID, eventTime string) map[string]any {
	return map[string]any{
		"eventID":            eventID,
		"eventTime":          eventTime,
		"eventName":          "GetObject",
		"awsRegion":          "us-west-2",
		"recipientAccountId": "222222222222",
		"sourceIPAddress":    "203.0.113.5",
		"userIdentity": map[string]any{
			"type":        "AssumedRole",
			"principalId": "AROAEXAMPLE:session1",
			"arn":         "arn:aws:sts::222222222222:assumed-role/DataRole/session1",
		},
		"requestParameters": map[string]any{
			"bucketName": "acme-data",
			"key":        "reports/q1.csv",
		},
	}
}

// buildFixtureBucket lays out an org-trail bucket with two accounts under one
// org, spanning two regions, with a digest sibling folder that must never be
// read.
func buildFixtureBucket(t *testing.T, day string, objBody []byte, obj2Body []byte, digestBody []byte, lastMod time.Time) []fakeObject {
	t.Helper()
	return []fakeObject{
		{
			key:          "AWSLogs/o-abc1234567/111111111111/CloudTrail/us-east-1/" + day + "/111111111111_CloudTrail_us-east-1_" + strings.ReplaceAll(day, "/", "") + "T0000Z_abc123.json.gz",
			body:         objBody,
			lastModified: lastMod,
		},
		{
			key:          "AWSLogs/o-abc1234567/222222222222/CloudTrail/us-west-2/" + day + "/222222222222_CloudTrail_us-west-2_" + strings.ReplaceAll(day, "/", "") + "T0000Z_def456.json.gz",
			body:         obj2Body,
			lastModified: lastMod,
		},
		{
			// Must never be read: digest folder sibling to CloudTrail/.
			key:          "AWSLogs/o-abc1234567/111111111111/CloudTrail-Digest/us-east-1/" + day + "/111111111111_CloudTrail-Digest_us-east-1_digest.json.gz",
			body:         digestBody,
			lastModified: lastMod,
		},
	}
}

// --- tests ---------------------------------------------------------------

func TestS3Mode_NormalizationAndDiscovery(t *testing.T) {
	today := time.Now().UTC()
	day := today.Format("2006/01/02")
	lastMod := today.Add(-1 * time.Hour)

	log1 := gzipRecords(t, []map[string]any{
		consoleLoginFailure("evt-1", today.Format(time.RFC3339)),
		attachUserPolicy("evt-2", today.Format(time.RFC3339)),
	})
	log2 := gzipRecords(t, []map[string]any{
		getObjectRecord("evt-3", today.Format(time.RFC3339)),
	})
	// Poison pill: if this were ever read, gunzip/json decode would fail
	// loudly and the test would catch it via an unexpected error return.
	digestBody := []byte("not a valid gzip stream")

	client := &fakeS3Client{objects: buildFixtureBucket(t, day, log1, log2, digestBody, lastMod)}

	since := today.Add(-24 * time.Hour)
	events, newMark, err := runS3Mode(context.Background(), client, "3dl-cloudtrail-458526671706", "AWSLogs/", since, time.Time{})
	if err != nil {
		t.Fatalf("runS3Mode: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("want 3 events, got %d: %+v", len(events), events)
	}

	byID := map[string]struct {
		typ   string
		actor string
		org   string
	}{}
	for _, ev := range events {
		byID[ev.ID] = struct {
			typ   string
			actor string
			org   string
		}{ev.Type, ev.Actor, ev.Org}
	}

	wantTypes := map[string]bool{"login_failure": false, "iam_policy_attach": false, "object_get": false}
	for _, ev := range events {
		if _, ok := wantTypes[ev.Type]; !ok {
			t.Errorf("unexpected Type %q on event %s", ev.Type, ev.ID)
			continue
		}
		wantTypes[ev.Type] = true

		switch ev.Type {
		case "login_failure":
			if ev.Actor != "alice" {
				t.Errorf("login_failure actor = %q, want alice", ev.Actor)
			}
			if ev.Org != "111111111111" {
				t.Errorf("login_failure org = %q, want 111111111111", ev.Org)
			}
		case "iam_policy_attach":
			if ev.Actor != "bob" {
				t.Errorf("iam_policy_attach actor = %q, want bob", ev.Actor)
			}
		case "object_get":
			// No userName -> falls back to last ARN path segment.
			if ev.Actor != "session1" {
				t.Errorf("object_get actor = %q, want session1 (arn fallback)", ev.Actor)
			}
			if ev.Org != "222222222222" {
				t.Errorf("object_get org = %q, want 222222222222", ev.Org)
			}
		}
	}
	for typ, seen := range wantTypes {
		if !seen {
			t.Errorf("expected a %q event, none seen", typ)
		}
	}

	// Digest folder must never be fetched.
	for _, k := range client.gets {
		if strings.Contains(k, "CloudTrail-Digest") {
			t.Errorf("GetObject called on digest key %q, must be skipped structurally", k)
		}
	}

	if newMark.IsZero() {
		t.Fatal("expected non-zero high-water mark")
	}
	if !newMark.Equal(lastMod) {
		t.Errorf("newMark = %v, want %v", newMark, lastMod)
	}
}

func TestS3Mode_SinceFiltering(t *testing.T) {
	today := time.Now().UTC()
	day := today.Format("2006/01/02")
	lastMod := today.Add(-1 * time.Hour)

	old := today.Add(-48 * time.Hour) // older than `since` below
	log1 := gzipRecords(t, []map[string]any{
		consoleLoginFailure("evt-old", old.Format(time.RFC3339)),
		attachUserPolicy("evt-new", today.Format(time.RFC3339)),
	})
	log2 := gzipRecords(t, []map[string]any{getObjectRecord("evt-3", today.Format(time.RFC3339))})

	client := &fakeS3Client{objects: buildFixtureBucket(t, day, log1, log2, nil, lastMod)}

	since := today.Add(-1 * time.Hour) // excludes evt-old (48h ago)
	events, _, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", since, time.Time{})
	if err != nil {
		t.Fatalf("runS3Mode: %v", err)
	}

	for _, ev := range events {
		if ev.Type == "login_failure" {
			t.Errorf("expected the old ConsoleLogin record to be filtered by --since, got event %+v", ev)
		}
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events after since-filtering, got %d", len(events))
	}
}

func TestS3Mode_CursorHighWaterAdvanceAndSkipOnResume(t *testing.T) {
	today := time.Now().UTC()
	day := today.Format("2006/01/02")
	lastMod := today.Add(-2 * time.Hour)

	log1 := gzipRecords(t, []map[string]any{consoleLoginFailure("evt-1", today.Format(time.RFC3339))})
	log2 := gzipRecords(t, []map[string]any{getObjectRecord("evt-3", today.Format(time.RFC3339))})

	client := &fakeS3Client{objects: buildFixtureBucket(t, day, log1, log2, nil, lastMod)}
	since := today.Add(-24 * time.Hour)

	events1, mark1, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", since, time.Time{})
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(events1) == 0 {
		t.Fatal("first run produced no events")
	}
	if !mark1.Equal(lastMod) {
		t.Errorf("mark1 = %v, want %v", mark1, lastMod)
	}

	// Resume with the mark from run 1: every object has LastModified <= mark1,
	// so nothing should be re-read or re-emitted.
	client.gets = nil
	events2, mark2, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", since, mark1)
	if err != nil {
		t.Fatalf("resume run: %v", err)
	}
	if len(events2) != 0 {
		t.Errorf("resume run should skip already-processed objects, got %d events", len(events2))
	}
	if len(client.gets) != 0 {
		t.Errorf("resume run should not call GetObject on already-processed objects, called: %v", client.gets)
	}
	if !mark2.Equal(mark1) {
		t.Errorf("mark2 = %v, want unchanged %v", mark2, mark1)
	}

	// A late-delivered object with a NEWER LastModified must still be picked up.
	newLastMod := lastMod.Add(1 * time.Hour)
	client.objects = append(client.objects, fakeObject{
		key:          "AWSLogs/o-abc1234567/111111111111/CloudTrail/us-east-1/" + day + "/111111111111_CloudTrail_us-east-1_late.json.gz",
		body:         gzipRecords(t, []map[string]any{attachUserPolicy("evt-late", today.Format(time.RFC3339))}),
		lastModified: newLastMod,
	})
	client.gets = nil
	events3, mark3, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", since, mark1)
	if err != nil {
		t.Fatalf("late-delivery run: %v", err)
	}
	if len(events3) != 1 {
		t.Fatalf("want 1 event from late-delivered object, got %d", len(events3))
	}
	if !mark3.Equal(newLastMod) {
		t.Errorf("mark3 = %v, want %v", mark3, newLastMod)
	}
}

func TestS3Mode_DigestAndInsightPrefixesSkippedEntirely(t *testing.T) {
	today := time.Now().UTC()
	day := today.Format("2006/01/02")
	lastMod := today.Add(-1 * time.Hour)

	objects := []fakeObject{
		{
			key:          "AWSLogs/111111111111/CloudTrail/us-east-1/" + day + "/log.json.gz",
			body:         gzipRecords(t, []map[string]any{consoleLoginFailure("evt-1", today.Format(time.RFC3339))}),
			lastModified: lastMod,
		},
		{
			key:          "AWSLogs/111111111111/CloudTrail-Digest/us-east-1/" + day + "/digest.json.gz",
			body:         []byte("garbage-not-gzip"),
			lastModified: lastMod,
		},
		{
			key:          "AWSLogs/111111111111/CloudTrail-Insight/us-east-1/" + day + "/insight.json.gz",
			body:         []byte("garbage-not-gzip"),
			lastModified: lastMod,
		},
	}
	client := &fakeS3Client{objects: objects}

	since := today.Add(-24 * time.Hour)
	events, _, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", since, time.Time{})
	if err != nil {
		t.Fatalf("runS3Mode should not error (digest/insight must be skipped, not read): %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event (CloudTrail/ only), got %d", len(events))
	}
	for _, k := range client.gets {
		if strings.Contains(k, "Digest") || strings.Contains(k, "Insight") {
			t.Errorf("GetObject called on %q, digest/insight must be skipped", k)
		}
	}
}

func TestS3Mode_NonOrgAccountLayout(t *testing.T) {
	// Account id directly under AWSLogs/ with no "o-..." org segment.
	today := time.Now().UTC()
	day := today.Format("2006/01/02")
	lastMod := today.Add(-1 * time.Hour)

	client := &fakeS3Client{objects: []fakeObject{
		{
			key:          "AWSLogs/333333333333/CloudTrail/eu-west-1/" + day + "/log.json.gz",
			body:         gzipRecords(t, []map[string]any{attachUserPolicy("evt-1", today.Format(time.RFC3339))}),
			lastModified: lastMod,
		},
	}}

	since := today.Add(-24 * time.Hour)
	events, _, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", since, time.Time{})
	if err != nil {
		t.Fatalf("runS3Mode: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event from non-org layout, got %d", len(events))
	}
	if events[0].Org != "111111111111" {
		t.Errorf("Org = %q, want 111111111111 (recipientAccountId from record)", events[0].Org)
	}
}

func TestS3Mode_OrgFallsBackToPathAccountIDWhenRecipientMissing(t *testing.T) {
	today := time.Now().UTC()
	day := today.Format("2006/01/02")
	lastMod := today.Add(-1 * time.Hour)

	// No recipientAccountId field at all in this record.
	rec := map[string]any{
		"eventID":   "evt-no-recipient",
		"eventTime": today.Format(time.RFC3339),
		"eventName": "CreateUser",
		"awsRegion": "us-east-1",
		"userIdentity": map[string]any{
			"type":     "IAMUser",
			"userName": "dave",
		},
		"requestParameters": map[string]any{"userName": "newguy"},
	}

	client := &fakeS3Client{objects: []fakeObject{
		{
			key:          "AWSLogs/444444444444/CloudTrail/us-east-1/" + day + "/log.json.gz",
			body:         gzipRecords(t, []map[string]any{rec}),
			lastModified: lastMod,
		},
	}}

	since := today.Add(-24 * time.Hour)
	events, _, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", since, time.Time{})
	if err != nil {
		t.Fatalf("runS3Mode: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Org != "444444444444" {
		t.Errorf("Org = %q, want path-derived account id 444444444444", events[0].Org)
	}
}

func TestS3Mode_FailsLoudOnGetObjectError(t *testing.T) {
	today := time.Now().UTC()
	day := today.Format("2006/01/02")

	client := &fakeS3Client{objects: []fakeObject{
		{
			key: "AWSLogs/111111111111/CloudTrail/us-east-1/" + day + "/log.json.gz",
			// no body registered under this exact key is impossible since we
			// set it; instead corrupt it so gunzip fails loudly.
			body:         []byte("not gzip data"),
			lastModified: today,
		},
	}}

	since := today.Add(-24 * time.Hour)
	_, _, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", since, time.Time{})
	if err == nil {
		t.Fatal("expected an error for an unreadable (corrupt gzip) trail object, got nil")
	}
}

func TestS3Mode_FailsLoudOnListError(t *testing.T) {
	client := &erroringListClient{}
	_, _, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", time.Time{}, time.Time{})
	if err == nil {
		t.Fatal("expected an error when ListObjectsV2 fails, got nil")
	}
}

type erroringListClient struct{}

func (e *erroringListClient) ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return nil, io.ErrClosedPipe
}
func (e *erroringListClient) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, io.ErrClosedPipe
}

// --- cursor + mode selection -------------------------------------------------

func TestSigKeyS3DistinctFromLookupEventsSigKey(t *testing.T) {
	region := "us-east-1"
	bucket := "us-east-1" // deliberately same string to prove namespacing, not value, separates modes
	lookupKey := sigKey(region)
	s3Key := sigKeyS3(bucket)

	raw := "2026-07-01T00:00:00Z"
	encoded := encodeCursor(raw, lookupKey)

	if _, err := decodeCursor(encoded, s3Key); err == nil {
		t.Fatal("a LookupEvents-mode cursor must not validate against the S3-mode key")
	}
}

func TestS3CursorRoundtrip(t *testing.T) {
	key := sigKeyS3("3dl-cloudtrail-458526671706")
	raw := time.Now().UTC().Format(time.RFC3339)

	encoded := encodeCursor(raw, key)
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if decoded != raw {
		t.Errorf("roundtrip mismatch: got %q, want %q", decoded, raw)
	}
}

func TestResolveTrailBucket(t *testing.T) {
	t.Run("flag wins", func(t *testing.T) {
		t.Setenv("AWS_TRAIL_BUCKET", "env-bucket")
		if got := resolveTrailBucket("flag-bucket"); got != "flag-bucket" {
			t.Errorf("resolveTrailBucket = %q, want flag-bucket", got)
		}
	})
	t.Run("falls back to env", func(t *testing.T) {
		t.Setenv("AWS_TRAIL_BUCKET", "env-bucket")
		if got := resolveTrailBucket(""); got != "env-bucket" {
			t.Errorf("resolveTrailBucket = %q, want env-bucket", got)
		}
	})
	t.Run("empty means LookupEvents mode", func(t *testing.T) {
		os.Unsetenv("AWS_TRAIL_BUCKET")
		if got := resolveTrailBucket(""); got != "" {
			t.Errorf("resolveTrailBucket = %q, want empty (LookupEvents mode)", got)
		}
	})
}

func TestResolveTrailPrefix(t *testing.T) {
	os.Unsetenv("AWS_TRAIL_PREFIX")
	if got := resolveTrailPrefix(""); got != "AWSLogs/" {
		t.Errorf("resolveTrailPrefix default = %q, want AWSLogs/", got)
	}
	t.Setenv("AWS_TRAIL_PREFIX", "custom")
	if got := resolveTrailPrefix(""); got != "custom/" {
		t.Errorf("resolveTrailPrefix should append trailing slash: got %q", got)
	}
}

func TestS3Mode_CursorResumeSpansMidnightBoundary(t *testing.T) {
	// A cursor-resumed run passes no --since (the persisted cursor wins in
	// mallcop's exec.go), so runS3Mode receives a zero since. An object
	// delivered late yesterday — LastModified AFTER the previous run's mark,
	// key under YESTERDAY's day prefix — must still be enumerated: startDate
	// must derive from the resume mark's date, not today, or the hourly
	// cadence silently drops every event delivered in the last minutes before
	// midnight UTC.
	now := time.Now().UTC()
	yesterday := now.Add(-24 * time.Hour)
	yDay := yesterday.Format("2006/01/02")
	mark := yesterday.Add(-1 * time.Hour)
	lateMod := yesterday.Add(30 * time.Minute)

	client := &fakeS3Client{objects: []fakeObject{{
		key:          "AWSLogs/o-abc1234567/111111111111/CloudTrail/us-east-1/" + yDay + "/111111111111_CloudTrail_us-east-1_latenight.json.gz",
		body:         gzipRecords(t, []map[string]any{attachUserPolicy("evt-midnight", yesterday.Format(time.RFC3339))}),
		lastModified: lateMod,
	}}}

	events, newMark, err := runS3Mode(context.Background(), client, "bucket", "AWSLogs/", time.Time{}, mark)
	if err != nil {
		t.Fatalf("runS3Mode: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event from the late pre-midnight object, got %d", len(events))
	}
	if !newMark.Equal(lateMod) {
		t.Errorf("newMark = %v, want %v", newMark, lateMod)
	}
}
