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
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

// TestCloudWatchIntegration exercises the real DescribeAlarms +
// DescribeAlarmHistory APIs against a live AWS account. Both calls are
// read-only (cloudwatch:DescribeAlarms, cloudwatch:DescribeAlarmHistory) —
// this test never creates, modifies, or deletes any AWS resource.
//
// A zero-alarm / zero-history account is a legitimate, passing result: the
// test asserts the connector ran cleanly and every emitted event (if any) is
// well-formed, not that history is non-empty.
//
// Required env vars:
//
//	AWS_ACCESS_KEY_ID
//	AWS_SECRET_ACCESS_KEY
//	AWS_REGION (optional, defaults to us-east-1)
func TestCloudWatchIntegration(t *testing.T) {
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
	client := cloudwatch.NewFromConfig(cfg)

	// Fetch the last 90 days of alarm state transitions (DescribeAlarmHistory
	// retains history for deleted alarms indefinitely, but bound the query to
	// keep the test fast on an account with a long history).
	since := time.Now().UTC().Add(-90 * 24 * time.Hour)
	events, maxSeen, err := fetchAndNormalize(context.Background(), client, region, since)
	if err != nil {
		t.Fatalf("fetchAndNormalize: %v", err)
	}

	t.Logf("fetched %d cloudwatch_alarm state-transition events from the last 90d (region=%s)", len(events), region)
	if len(events) == 0 {
		t.Log("zero alarm state transitions in the window — this is a legitimate empty result, not a failure (no alarms configured, or none have transitioned recently)")
	} else {
		t.Logf("high-water mark: %s", maxSeen.Format(time.RFC3339))
	}

	// Encode JSONL and validate schema, same shape every other connector's
	// integration test checks.
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
		if ev.Source != "cloudwatch" {
			t.Errorf("line %d: Source = %q, want cloudwatch", lineNum, ev.Source)
		}
		if ev.Type != "cloudwatch_alarm" {
			t.Errorf("line %d: Type = %q, want cloudwatch_alarm", lineNum, ev.Type)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("line %d: Timestamp zero", lineNum)
		}

		var payload map[string]any
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			t.Errorf("line %d: payload not JSON: %v", lineNum, err)
			continue
		}
		if payload["signal_class"] != "alert" {
			t.Errorf("line %d: signal_class = %v, want alert", lineNum, payload["signal_class"])
		}
		if payload["severity"] == nil || payload["severity"] == "" {
			t.Errorf("line %d: severity missing", lineNum)
		}
	}
	t.Logf("validated %d JSONL events", lineNum)
}
