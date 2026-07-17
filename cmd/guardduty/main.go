// Command guardduty polls AWS GuardDuty findings via AWS SDK v2 and emits
// normalized mallcop events (Type=guardduty_finding) as JSONL to stdout.
//
// Flow: ListDetectors -> ListFindings (sorted ascending by updatedAt, paged) ->
// GetFindings (batched, one call per ListFindings page — GuardDuty caps both
// at 50 results). GuardDuty findings are already pre-triaged security alerts
// (see internal/normalize/guardduty.go), so every finding maps to the single
// canonical Type "guardduty_finding" with "signal_class":"alert" — no per-type
// gate branching like the aws/github connectors do for raw audit events.
//
// Usage:
//
//	guardduty --region <region> [--since <iso-timestamp>] [--cursor <cursor>]
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
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen = 1000

	// pageSize is GuardDuty's hard MaxResults cap, shared by ListFindings and
	// GetFindings — one GetFindings call exactly covers one ListFindings page.
	pageSize = 50
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
	return []byte(fmt.Sprintf("mallcop-guardduty-cursor:%s", region))
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
// --since to produce the effective query floor plus whether the boundary
// itself must be excluded (strict — a resumed cursor high-water mark, already
// emitted last run) or included (--since, matching every other connector's
// --since semantics). This is a brand-new connector with no prior cursor
// format in the wild, so — unlike aws/github's resolveFloor (PR #7) — there is
// no legacy pagination-token migration to self-heal: a cursor that decodes
// (HMAC-valid) but doesn't parse as a timestamp is just a hard error.
func resolveFloor(cursorArg string, sinceTime time.Time, key []byte) (floor time.Time, strict bool, err error) {
	var cursorMark time.Time
	if cursorArg != "" {
		raw, err := decodeCursor(cursorArg, key)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		cursorMark, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("invalid checkpoint cursor: bad timestamp %q: %w", raw, err)
		}
	}

	floor = sinceTime
	strict = false
	if !cursorMark.IsZero() && (sinceTime.IsZero() || !sinceTime.After(cursorMark)) {
		floor = cursorMark
		strict = true
	}
	return floor, strict, nil
}

// normalizeFinding maps one GuardDuty finding to a mallcop event.
//
// The second return value, tsReliable, is true only when the Timestamp on the
// returned event came from the finding's own UpdatedAt field. When UpdatedAt
// is missing or unparseable, ts falls back to time.Now().UTC() so the event
// still has SOME timestamp for display/dedupe purposes — but that fabricated
// value must never be allowed to advance the resume high-water mark (it would
// silently poison the cursor to "now" and cause the next run to skip every
// real finding between the true high-water mark and now). Callers must gate
// maxSeen updates on tsReliable (PR #7's tsReliable guard, same pattern as
// cmd/aws and cmd/github).
func normalizeFinding(f types.Finding) (*event.Event, bool, error) {
	id := ""
	if f.Id != nil {
		id = *f.Id
	}
	findingType := ""
	if f.Type != nil {
		findingType = *f.Type
	}
	accountID := ""
	if f.AccountId != nil {
		accountID = *f.AccountId
	}

	ts := time.Now().UTC()
	tsReliable := false
	if f.UpdatedAt != nil && *f.UpdatedAt != "" {
		parsed, err := time.Parse(time.RFC3339, *f.UpdatedAt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: failed to parse updatedAt timestamp %q: %v, falling back to time.Now()\n", *f.UpdatedAt, err)
		} else {
			ts = parsed.UTC()
			tsReliable = true
		}
	}

	actor := ""
	if f.Resource != nil && f.Resource.AccessKeyDetails != nil && f.Resource.AccessKeyDetails.UserName != nil {
		actor = *f.Resource.AccessKeyDetails.UserName
	}

	rawJSON, err := json.Marshal(f)
	if err != nil {
		return nil, false, fmt.Errorf("marshal finding: %w", err)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(rawJSON, &rawMap); err != nil {
		return nil, false, fmt.Errorf("decode finding: %w", err)
	}

	results := normalize.GuardDuty(findingType, rawMap)
	if len(results) == 0 {
		return nil, false, fmt.Errorf("normalize.GuardDuty returned no results for finding %s", id)
	}
	r := results[0]
	payload, err := r.PayloadJSON(rawMap)
	if err != nil {
		return nil, false, fmt.Errorf("marshal payload: %w", err)
	}

	return &event.Event{
		ID:        sha256Hex("aws:guardduty:" + id),
		Source:    "guardduty",
		Type:      r.Type,
		Actor:     actor,
		Timestamp: ts,
		Org:       accountID,
		Payload:   payload,
	}, tsReliable, nil
}

// guarddutyAPI is the subset of *guardduty.Client this connector uses. Tests
// inject a fake in-memory implementation (mirrors cmd/aws's cloudtrailAPI /
// s3API idiom) so pagination and cursor-floor logic are exercised without
// network or live creds; a separate httptest-backed test additionally proves
// the real *guardduty.Client (pointed at a fake HTTP server via
// guardduty.Options.BaseEndpoint) round-trips correctly end-to-end.
type guarddutyAPI interface {
	ListDetectors(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	ListFindings(ctx context.Context, params *guardduty.ListFindingsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error)
	GetFindings(ctx context.Context, params *guardduty.GetFindingsInput, optFns ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error)
}

// listDetectorIDs pages ListDetectors to completion. A region normally has at
// most one GuardDuty detector, but the API is paginated, so this handles the
// (rare) multi-detector case correctly rather than silently dropping results.
func listDetectorIDs(ctx context.Context, client guarddutyAPI) ([]string, error) {
	var ids []string
	var nextToken *string
	for {
		out, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ListDetectors: %w", err)
		}
		ids = append(ids, out.DetectorIds...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return ids, nil
}

// fetchFindings pages ListFindings (sorted ascending by updatedAt) for one
// detector, batches a GetFindings call per page (each page is <= pageSize
// finding IDs, matching GetFindings' own cap), and normalizes every finding.
//
// floor/strict encode the resume semantics: strict (a resumed cursor
// high-water mark) requires updatedAt > floor; non-strict (--since, or no
// floor at all) requires updatedAt >= floor. GuardDuty's updatedAt
// FindingCriteria takes Unix epoch milliseconds (documented on
// ListFindingsInput.FindingCriteria), not RFC3339.
func fetchFindings(ctx context.Context, client guarddutyAPI, detectorID string, floor time.Time, strict bool) ([]*event.Event, time.Time, error) {
	sortAttr := "updatedAt"
	limit := int32(pageSize)
	input := &guardduty.ListFindingsInput{
		DetectorId: &detectorID,
		MaxResults: &limit,
		SortCriteria: &types.SortCriteria{
			AttributeName: &sortAttr,
			OrderBy:       types.OrderByAsc,
		},
	}
	if !floor.IsZero() {
		millis := floor.UnixMilli()
		cond := types.Condition{}
		if strict {
			cond.GreaterThan = &millis
		} else {
			cond.GreaterThanOrEqual = &millis
		}
		input.FindingCriteria = &types.FindingCriteria{Criterion: map[string]types.Condition{"updatedAt": cond}}
	}

	var allEvents []*event.Event
	var maxSeen time.Time

	for {
		out, err := client.ListFindings(ctx, input)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("ListFindings: %w", err)
		}

		if len(out.FindingIds) > 0 {
			gout, err := client.GetFindings(ctx, &guardduty.GetFindingsInput{
				DetectorId: &detectorID,
				FindingIds: out.FindingIds,
			})
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("GetFindings: %w", err)
			}
			for _, f := range gout.Findings {
				ev, tsReliable, err := normalizeFinding(f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warn: skipping finding: %v\n", err)
					continue
				}
				allEvents = append(allEvents, ev)
				// Only a real source timestamp may advance the resume
				// high-water mark — see normalizeFinding's tsReliable doc.
				if tsReliable && ev.Timestamp.After(maxSeen) {
					maxSeen = ev.Timestamp
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
		region    = flag.String("region", "", "AWS region (overrides AWS_REGION env var)")
		since     = flag.String("since", "", "RFC3339 timestamp to filter findings (e.g. 2024-01-01T00:00:00Z)")
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
	floor, strict, err := resolveFloor(*cursorArg, sinceTime, key)
	if err != nil {
		return err
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	client := guardduty.NewFromConfig(cfg)

	detectorIDs, err := listDetectorIDs(ctx, client)
	if err != nil {
		return fmt.Errorf("list detectors: %w", err)
	}
	if len(detectorIDs) == 0 {
		// Not a failure: GuardDuty may simply not be enabled yet in this
		// account/region. Emit zero events (and zero cursor) rather than
		// erroring the whole scan (fail-loud is for real API failures, not
		// an absent optional source).
		fmt.Fprintln(os.Stderr, "warn: no GuardDuty detector found in this account/region — is GuardDuty enabled?")
	}

	var allEvents []*event.Event
	var maxSeen time.Time
	for _, id := range detectorIDs {
		evs, seen, err := fetchFindings(ctx, client, id, floor, strict)
		if err != nil {
			return fmt.Errorf("fetch findings for detector %s: %w", id, err)
		}
		allEvents = append(allEvents, evs...)
		if seen.After(maxSeen) {
			maxSeen = seen
		}
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range allEvents {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	// Only emit a cursor when at least one finding was emitted this run; zero
	// findings means the caller should keep using its previous cursor.
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
