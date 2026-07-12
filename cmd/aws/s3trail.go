// S3 org-trail mode: instead of polling CloudTrail LookupEvents (management
// events, 90-day retention, single-account), this mode reads an
// organization-wide CloudTrail trail delivered to S3 directly. It discovers
// org -> account -> region -> day prefixes, downloads and gunzips each
// CloudTrail log file, and normalizes every record through the existing
// normalize.AWS mapper (the same one LookupEvents mode uses) so both modes
// dedupe identically and gate the same detectors.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const defaultTrailPrefix = "AWSLogs/"

var accountIDRE = regexp.MustCompile(`^\d{12}$`)

// s3API is the subset of *s3.Client used by S3 org-trail mode. Tests inject a
// fake implementation so no network or live creds are needed.
type s3API interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// sigKeyS3 is the HMAC key for S3-mode cursors. Deliberately a different key
// namespace ("mallcop-aws-s3-cursor:") than sigKey's "mallcop-aws-cursor:" so
// a cursor minted by one mode is rejected by the other.
func sigKeyS3(bucket string) []byte {
	return []byte(fmt.Sprintf("mallcop-aws-s3-cursor:%s", bucket))
}

// resolveTrailBucket determines whether S3 org-trail mode is enabled: the
// -trail-bucket flag wins, else AWS_TRAIL_BUCKET. Empty means LookupEvents
// mode (the pre-existing default) runs unchanged.
func resolveTrailBucket(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("AWS_TRAIL_BUCKET")
}

func resolveTrailPrefix(flagVal string) string {
	p := flagVal
	if p == "" {
		p = os.Getenv("AWS_TRAIL_PREFIX")
	}
	if p == "" {
		p = defaultTrailPrefix
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// accountRef is a discovered (org, account) pair with its S3 key prefix.
type accountRef struct {
	prefix    string // e.g. "AWSLogs/o-abc1234567/123456789012/" or "AWSLogs/123456789012/"
	accountID string
	orgID     string // "" for non-org (account directly under AWSLogs/) layout
}

// cloudTrailLogFile is the top-level shape of a CloudTrail delivered log
// object: {"Records": [ ... ]}.
type cloudTrailLogFile struct {
	Records []map[string]any `json:"Records"`
}

// listCommonPrefixes lists one level of "directories" under prefix using
// delimiter "/", paginating over ContinuationToken.
func listCommonPrefixes(ctx context.Context, client s3API, bucket, prefix, delim string) ([]string, error) {
	var out []string
	var token *string
	for {
		resp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			Delimiter:         &delim,
			ContinuationToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("ListObjectsV2 (prefix=%s): %w", prefix, err)
		}
		for _, cp := range resp.CommonPrefixes {
			if cp.Prefix != nil {
				out = append(out, *cp.Prefix)
			}
		}
		if resp.IsTruncated == nil || !*resp.IsTruncated || resp.NextContinuationToken == nil {
			break
		}
		token = resp.NextContinuationToken
	}
	return out, nil
}

// listObjectsFlat lists all objects (no delimiter) under prefix, paginating
// over ContinuationToken.
func listObjectsFlat(ctx context.Context, client s3API, bucket, prefix string) ([]s3.ListObjectsV2Output, error) {
	// Kept generic-free: caller only needs Contents, so return raw pages.
	var pages []s3.ListObjectsV2Output
	var token *string
	for {
		resp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			ContinuationToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("ListObjectsV2 (prefix=%s): %w", prefix, err)
		}
		pages = append(pages, *resp)
		if resp.IsTruncated == nil || !*resp.IsTruncated || resp.NextContinuationToken == nil {
			break
		}
		token = resp.NextContinuationToken
	}
	return pages, nil
}

// discoverAccounts lists the org/account layer under the trail prefix. A
// segment starting with "o-" is treated as an org id (one more listing level
// down finds the 12-digit account ids beneath it); a bare 12-digit segment is
// an account id directly under the trail prefix.
func discoverAccounts(ctx context.Context, client s3API, bucket, prefix string) ([]accountRef, error) {
	top, err := listCommonPrefixes(ctx, client, bucket, prefix, "/")
	if err != nil {
		return nil, fmt.Errorf("discover accounts: %w", err)
	}
	var accounts []accountRef
	for _, p := range top {
		seg := strings.TrimSuffix(strings.TrimPrefix(p, prefix), "/")
		switch {
		case strings.HasPrefix(seg, "o-"):
			subs, err := listCommonPrefixes(ctx, client, bucket, p, "/")
			if err != nil {
				return nil, fmt.Errorf("discover accounts under org %s: %w", seg, err)
			}
			for _, sp := range subs {
				aseg := strings.TrimSuffix(strings.TrimPrefix(sp, p), "/")
				if accountIDRE.MatchString(aseg) {
					accounts = append(accounts, accountRef{prefix: sp, accountID: aseg, orgID: seg})
				}
			}
		case accountIDRE.MatchString(seg):
			accounts = append(accounts, accountRef{prefix: p, accountID: seg})
		}
	}
	return accounts, nil
}

// discoverCloudTrailPrefix returns the "<account-prefix>CloudTrail/" prefix
// for an account, or "" if the account has no CloudTrail folder yet.
// Sibling CloudTrail-Digest/ and CloudTrail-Insight/ folders (and anything
// else at this level) are recognized and skipped entirely.
func discoverCloudTrailPrefix(ctx context.Context, client s3API, bucket string, acct accountRef) (string, error) {
	subs, err := listCommonPrefixes(ctx, client, bucket, acct.prefix, "/")
	if err != nil {
		return "", fmt.Errorf("discover CloudTrail folder for account %s: %w", acct.accountID, err)
	}
	for _, sp := range subs {
		seg := strings.TrimSuffix(strings.TrimPrefix(sp, acct.prefix), "/")
		if seg == "CloudTrail" {
			return sp, nil
		}
		// CloudTrail-Digest/, CloudTrail-Insight/, or anything else: not a
		// CloudTrail record-events folder, skip.
	}
	return "", nil
}

// s3RecordActor extracts the actor per the fallback chain: userName, else
// last path segment of arn, else principalId, else type.
func s3RecordActor(rec map[string]any) string {
	ui, _ := rec["userIdentity"].(map[string]any)
	if ui == nil {
		return ""
	}
	if v, _ := ui["userName"].(string); v != "" {
		return v
	}
	if v, _ := ui["arn"].(string); v != "" {
		parts := strings.Split(v, "/")
		if last := parts[len(parts)-1]; last != "" {
			return last
		}
	}
	if v, _ := ui["principalId"].(string); v != "" {
		return v
	}
	if v, _ := ui["type"].(string); v != "" {
		return v
	}
	return ""
}

// recordToEvents normalizes one raw CloudTrail record via the existing
// normalize.AWS mapper (wrapped so awsInner() finds it, matching the shape
// the LookupEvents connector already produces) and builds mallcop events.
// A record that lacks the minimum fields to compute a stable ID/timestamp is
// a hard error (fail loud, never silently drop a record).
func recordToEvents(rec map[string]any, fallbackAccountID string) ([]*event.Event, error) {
	eventName, _ := rec["eventName"].(string)
	eventID, _ := rec["eventID"].(string)
	if eventID == "" {
		return nil, fmt.Errorf("record missing eventID")
	}
	tsStr, _ := rec["eventTime"].(string)
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return nil, fmt.Errorf("parse eventTime %q: %w", tsStr, err)
	}
	ts = ts.UTC()

	org, _ := rec["recipientAccountId"].(string)
	if org == "" {
		org = fallbackAccountID
	}
	actor := s3RecordActor(rec)

	// awsInner() (internal/normalize/aws.go) expects the raw event to carry
	// the CloudTrail detail document under "CloudTrailEvent" (string or
	// map). S3 org-trail records ARE that detail document directly, so wrap.
	wrapped := map[string]any{"CloudTrailEvent": rec}
	results := normalize.AWS(eventName, wrapped)

	idSrc := "aws:cloudtrail:" + eventID
	baseID := sha256Hex(idSrc)

	out := make([]*event.Event, 0, len(results))
	for i, r := range results {
		payload, err := r.PayloadJSON(rec)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
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
			Org:       org,
			Payload:   payload,
		})
	}
	return out, nil
}

// readCloudTrailFile downloads (plain GetObject; SSE-KMS decryption is
// server-side), gunzips, and JSON-decodes a CloudTrail log object, streaming
// rather than buffering the whole bucket's worth of files in memory at once.
func readCloudTrailFile(ctx context.Context, client s3API, bucket, key string) ([]map[string]any, error) {
	resp, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		return nil, fmt.Errorf("GetObject %s: %w", key, err)
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gunzip %s: %w", key, err)
	}
	defer gz.Close()

	var lf cloudTrailLogFile
	if err := json.NewDecoder(gz).Decode(&lf); err != nil {
		return nil, fmt.Errorf("decode %s: %w", key, err)
	}
	return lf.Records, nil
}

// isSkippablePrefix reports whether a key belongs to the CloudTrail-Digest/
// or CloudTrail-Insight/ sibling folders, which carry integrity digests /
// insight summaries, not events. Defense in depth alongside the structural
// skip in discoverCloudTrailPrefix.
func isSkippablePrefix(key string) bool {
	return strings.Contains(key, "CloudTrail-Digest/") || strings.Contains(key, "CloudTrail-Insight/")
}

// runS3Mode enumerates org -> account -> CloudTrail -> region -> day
// prefixes from since through today (UTC), downloads and normalizes every
// log object newer than resumeMark, and returns the events plus the new
// high-water mark (max S3 object LastModified processed). Any List/Get/parse
// error aborts immediately (fail loud) — a partially-readable trail must
// never look green.
func runS3Mode(ctx context.Context, client s3API, bucket, prefix string, since, resumeMark time.Time) ([]*event.Event, time.Time, error) {
	accounts, err := discoverAccounts(ctx, client, bucket, prefix)
	if err != nil {
		return nil, time.Time{}, err
	}

	startDate := since
	if startDate.IsZero() {
		// Cursor-resumed runs pass no --since (the cursor wins in exec.go).
		// Enumerate from the resume mark's UTC date, NOT today: an object
		// delivered late yesterday (LastModified after the mark) lives under
		// yesterday's day prefix, and a today-only listing would drop it —
		// a silent midnight-boundary event loss on every hourly cadence.
		if !resumeMark.IsZero() {
			startDate = resumeMark
		} else {
			startDate = time.Now().UTC()
		}
	}
	startDate = time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
	today := time.Now().UTC()

	var allEvents []*event.Event
	newMark := resumeMark

	for _, acct := range accounts {
		ctPrefix, err := discoverCloudTrailPrefix(ctx, client, bucket, acct)
		if err != nil {
			return nil, time.Time{}, err
		}
		if ctPrefix == "" {
			continue
		}

		regionPrefixes, err := listCommonPrefixes(ctx, client, bucket, ctPrefix, "/")
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("discover regions for account %s: %w", acct.accountID, err)
		}

		for _, regionPrefix := range regionPrefixes {
			for d := startDate; !d.After(today); d = d.AddDate(0, 0, 1) {
				dayPrefix := fmt.Sprintf("%s%04d/%02d/%02d/", regionPrefix, d.Year(), int(d.Month()), d.Day())
				pages, err := listObjectsFlat(ctx, client, bucket, dayPrefix)
				if err != nil {
					return nil, time.Time{}, fmt.Errorf("list objects %s: %w", dayPrefix, err)
				}

				for _, page := range pages {
					for _, obj := range page.Contents {
						if obj.Key == nil {
							continue
						}
						key := *obj.Key
						if isSkippablePrefix(key) || !strings.HasSuffix(key, ".json.gz") {
							continue
						}

						var lastMod time.Time
						if obj.LastModified != nil {
							lastMod = obj.LastModified.UTC()
						}
						if !resumeMark.IsZero() && !lastMod.IsZero() && !lastMod.After(resumeMark) {
							continue // already processed by a prior run
						}

						records, err := readCloudTrailFile(ctx, client, bucket, key)
						if err != nil {
							return nil, time.Time{}, err
						}

						for _, rec := range records {
							evs, err := recordToEvents(rec, acct.accountID)
							if err != nil {
								return nil, time.Time{}, fmt.Errorf("normalize record in %s: %w", key, err)
							}
							for _, ev := range evs {
								if !since.IsZero() && ev.Timestamp.Before(since) {
									continue
								}
								allEvents = append(allEvents, ev)
							}
						}

						if lastMod.After(newMark) {
							newMark = lastMod
						}
					}
				}
			}
		}
	}

	return allEvents, newMark, nil
}

// runS3 is the S3 org-trail mode entrypoint called from run() when
// AWS_TRAIL_BUCKET / -trail-bucket is set.
func runS3(bucket, sinceStr, cursorArg string) error {
	prefix := resolveTrailPrefix("")

	var sinceTime time.Time
	if sinceStr != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", sinceStr)
		}
	}

	key := sigKeyS3(bucket)
	var resumeMark time.Time
	if cursorArg != "" {
		raw, err := decodeCursor(cursorArg, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		resumeMark, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor payload: %w", err)
		}
	}

	awsRegion := os.Getenv("AWS_REGION")
	if awsRegion == "" {
		awsRegion = os.Getenv("AWS_DEFAULT_REGION")
	}
	if awsRegion == "" {
		awsRegion = "us-east-1"
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(awsRegion))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	client := s3.NewFromConfig(cfg)

	events, newMark, err := runS3Mode(context.Background(), client, bucket, prefix, sinceTime, resumeMark)
	if err != nil {
		return fmt.Errorf("s3 org-trail: %w", err)
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	if !newMark.IsZero() {
		encoded := encodeCursor(newMark.UTC().Format(time.RFC3339), key)
		fmt.Fprintf(os.Stderr, "cursor: %s\n", encoded)
	}

	return bw.Flush()
}
