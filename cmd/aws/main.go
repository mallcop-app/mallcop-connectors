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

// normalizeEvent maps a raw CloudTrail event to one or more mallcop events. The
// canonical Type and detector-readable Payload come from the shared normalize
// library (NOT the raw CloudTrail eventName, which gates no detector). A single
// raw event may map to multiple canonical events.
func normalizeEvent(e types.Event, region string) ([]*event.Event, error) {
	rawJSON, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(rawJSON, &rawMap); err != nil {
		return nil, fmt.Errorf("decode event: %w", err)
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
	if e.EventTime != nil {
		ts = e.EventTime.UTC()
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
			Org:       region,
			Payload:   payload,
		})
	}
	return out, nil
}

func fetchEvents(ctx context.Context, client *cloudtrail.Client, region string, since time.Time, nextToken string) ([]*event.Event, string, error) {
	input := &cloudtrail.LookupEventsInput{}
	if !since.IsZero() {
		input.StartTime = &since
	}
	if nextToken != "" {
		input.NextToken = &nextToken
	}

	var allEvents []*event.Event
	lastToken := ""

	for {
		out, err := client.LookupEvents(ctx, input)
		if err != nil {
			return nil, "", fmt.Errorf("LookupEvents: %w", err)
		}

		for _, e := range out.Events {
			evs, err := normalizeEvent(e, region)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping event: %v\n", err)
				continue
			}
			allEvents = append(allEvents, evs...)
		}

		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		lastToken = *out.NextToken
		input.NextToken = out.NextToken
	}

	return allEvents, lastToken, nil
}

func run() error {
	var (
		region    = flag.String("region", "", "AWS region (overrides AWS_REGION env var)")
		since     = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
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
	rawCursor := ""
	if *cursorArg != "" {
		var err error
		rawCursor, err = decodeCursor(*cursorArg, key)
		if err != nil {
			return fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
	}

	cfg, err := config.LoadDefaultConfig(ctx(), config.WithRegion(awsRegion))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	client := cloudtrail.NewFromConfig(cfg)

	events, nextToken, err := fetchEvents(ctx(), client, awsRegion, sinceTime, rawCursor)
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

	if nextToken != "" {
		encoded := encodeCursor(nextToken, key)
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
