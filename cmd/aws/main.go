// Command aws polls AWS CloudTrail management events via AWS SDK v2
// and emits normalized mallcop events as JSONL to stdout.
//
// Usage:
//
//	aws --region <region> [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: standard AWS credentials chain (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION).
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
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen = 1000
	maxPages     = 0 // 0 = unlimited

	// legacyCursorFallback is the re-scan window used when an HMAC-valid
	// cursor is found to carry a pre-highwater LookupEvents NextToken
	// instead of a timestamp. See run()'s cursor decode for the migration.
	legacyCursorFallback = 24 * time.Hour
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
	return []byte(fmt.Sprintf("mallcop-aws-cursor:%s", region))
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
// timestamps wins). An HMAC-valid cursor whose payload does not parse as a
// timestamp is a legacy pre-highwater pagination token: resolveFloor never
// resumes it and never hard-fails on it — it self-heals by falling back to
// legacyCursorFallback and reports legacy=true so the caller can log the
// one-line warning. An HMAC-invalid (tampered) cursor still hard-fails.
func resolveFloor(cursorArg string, sinceTime time.Time, key []byte) (floor time.Time, legacy bool, err error) {
	var cursorMark time.Time
	if cursorArg != "" {
		raw, err := decodeCursor(cursorArg, key)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			legacy = true
			cursorMark = time.Now().UTC().Add(-legacyCursorFallback)
		} else {
			cursorMark = ts.UTC()
		}
	}

	// When both --cursor and --since are supplied, the later (more recent)
	// timestamp wins.
	floor = sinceTime
	if cursorMark.After(floor) {
		floor = cursorMark
	}
	return floor, legacy, nil
}

// normalizeEvent maps a raw CloudTrail event to one or more mallcop events. The
// canonical Type and detector-readable Payload come from the shared normalize
// library (NOT the raw CloudTrail eventName, which gates no detector). A single
// raw event may map to multiple canonical events.
//
// The second return value, tsReliable, is true only when the Timestamp on the
// returned events came from CloudTrail's own EventTime field. When EventTime
// is missing, ts falls back to time.Now().UTC() so the event still has SOME
// timestamp for display/dedupe purposes — but that fabricated value must
// never be allowed to advance the resume high-water mark (it would silently
// poison the cursor to "now" and cause the next run to skip every real event
// between the true high-water mark and now). Callers must gate maxSeen
// updates on tsReliable, not merely on ev.Timestamp being non-zero.
func normalizeEvent(e types.Event, region string) ([]*event.Event, bool, error) {
	rawJSON, err := json.Marshal(e)
	if err != nil {
		return nil, false, fmt.Errorf("marshal event: %w", err)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(rawJSON, &rawMap); err != nil {
		return nil, false, fmt.Errorf("decode event: %w", err)
	}

	actor := ""
	if e.Username != nil {
		actor = *e.Username
	}

	eventName := ""
	if e.EventName != nil {
		eventName = *e.EventName
	}

	ts := time.Now().UTC()
	tsReliable := false
	if e.EventTime != nil {
		ts = e.EventTime.UTC()
		tsReliable = true
	}

	idSrc := fmt.Sprintf("aws:cloudtrail:%s:%d", region, ts.UnixNano())
	if e.EventId != nil {
		idSrc = "aws:cloudtrail:" + *e.EventId
	}
	baseID := sha256Hex(idSrc)

	results := normalize.AWS(eventName, rawMap)
	out := make([]*event.Event, 0, len(results))
	for i, r := range results {
		payload, err := r.PayloadJSON(rawMap)
		if err != nil {
			return nil, false, fmt.Errorf("marshal payload: %w", err)
		}
		id := baseID
		if i > 0 {
			id = sha256Hex(fmt.Sprintf("%s:%d", idSrc, i))
		}
		out = append(out, &event.Event{
			ID:        id,
			Source:    "aws",
			Type:      r.Type,
			Actor:     actor,
			Timestamp: ts,
			Org:       region,
			Payload:   payload,
		})
	}
	return out, tsReliable, nil
}

// cloudtrailAPI is the subset of *cloudtrail.Client used by LookupEvents
// mode. Tests inject a fake implementation so no network or live creds are
// needed (mirrors s3trail.go's s3API interface for the S3 mode).
type cloudtrailAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// fetchEvents pages LookupEvents to completion and returns every event plus
// the maximum EventTime among them. floor is the effective query start
// (max of --since and any decoded cursor high-water mark, computed by the
// caller) and is passed as StartTime, which CloudTrail treats as an
// inclusive lower bound ("events that occur at or after"): a resumed run
// must never lose an event sharing the exact high-water timestamp with the
// last emitted event of the prior run. Re-emitted boundary duplicates are
// dropped downstream by mallcop core's per-ID dedupe (v0.11.3+). The
// connector never persists or resumes NextToken across runs — it is a
// one-shot continuation of THIS query only (mallcoppro-bb2).
func fetchEvents(ctx context.Context, client cloudtrailAPI, region string, floor time.Time) ([]*event.Event, time.Time, error) {
	input := &cloudtrail.LookupEventsInput{}
	if !floor.IsZero() {
		input.StartTime = &floor
	}

	var allEvents []*event.Event
	var maxSeen time.Time

	for {
		out, err := client.LookupEvents(ctx, input)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("LookupEvents: %w", err)
		}

		for _, e := range out.Events {
			evs, tsReliable, err := normalizeEvent(e, region)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping event: %v\n", err)
				continue
			}
			allEvents = append(allEvents, evs...)
			// Only a real source timestamp may advance the resume high-water
			// mark. A fabricated time.Now() fallback (missing/unparseable
			// EventTime) must never poison maxSeen to "now" — that would
			// silently skip every real event between the true high-water
			// mark and now on the next run.
			if tsReliable {
				for _, ev := range evs {
					if ev.Timestamp.After(maxSeen) {
						maxSeen = ev.Timestamp
					}
				}
			}
		}

		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		input.NextToken = out.NextToken
	}

	return allEvents, maxSeen, nil
}

func run() error {
	var (
		region      = flag.String("region", "", "AWS region (overrides AWS_REGION env var)")
		since       = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursorArg   = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
		trailBucket = flag.String("trail-bucket", "", "S3 bucket holding an org CloudTrail trail (overrides AWS_TRAIL_BUCKET); enables S3 org-trail mode")
	)
	flag.Parse()

	if bucket := resolveTrailBucket(*trailBucket); bucket != "" {
		return runS3(bucket, *since, *cursorArg)
	}

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
	floor, legacy, err := resolveFloor(*cursorArg, sinceTime, key)
	if err != nil {
		return err
	}
	if legacy {
		fmt.Fprintf(os.Stderr, "warn: legacy pagination-token cursor detected; discarding and re-scanning the last 24h\n")
	}

	cfg, err := config.LoadDefaultConfig(ctx(), config.WithRegion(awsRegion))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	client := cloudtrail.NewFromConfig(cfg)

	events, maxSeen, err := fetchEvents(ctx(), client, awsRegion, floor)
	if err != nil {
		return fmt.Errorf("fetch events: %w", err)
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	// Only emit a cursor when at least one event was emitted this run; zero
	// events means the caller should keep using its previous cursor.
	if !maxSeen.IsZero() {
		encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
		fmt.Fprintf(os.Stderr, "cursor: %s\n", encoded)
	}

	return bw.Flush()
}

func ctx() context.Context {
	return context.Background()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
