//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/thirdiv/mallcop-connectors/pkg/event"
)

// TestAWSCloudTrailIntegration exercises the real CloudTrail LookupEvents API.
//
// Required env vars:
//
//	AWS_ACCESS_KEY_ID
//	AWS_SECRET_ACCESS_KEY
//	AWS_REGION (optional, defaults to us-east-1)
func TestAWSCloudTrailIntegration(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for integration tests")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
	client := cloudtrail.NewFromConfig(cfg)

	// Fetch last 7 days.
	since := time.Now().UTC().Add(-7 * 24 * time.Hour)
	events, _, err := fetchEvents(context.Background(), client, region, since, "")
	if err != nil {
		t.Fatalf("fetchEvents: %v", err)
	}

	t.Logf("fetched %d events from CloudTrail (last 7d)", len(events))

	// Encode JSONL and validate schema.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatalf("encode event: %v", err)
		}
	}

	scanner := bufio.NewScanner(&buf)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		var ev event.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Errorf("line %d: invalid JSON: %v", lineNum, err)
			continue
		}
		if ev.ID == "" {
			t.Errorf("line %d: ID empty", lineNum)
		}
		if ev.Source != "aws" {
			t.Errorf("line %d: Source = %q, want aws", lineNum, ev.Source)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("line %d: Timestamp zero", lineNum)
		}
	}
	t.Logf("validated %d JSONL events", lineNum)
}
