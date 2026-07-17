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
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

// TestGuardDutyIntegration exercises the real GuardDuty API: ListDetectors ->
// ListFindings -> GetFindings against whatever detector exists in the
// target account/region.
//
// This is NOT a live-finding acceptance test — GuardDuty may be disabled in
// the target account (see mallcoppro-46b's feasibility-first gate; enabling
// GuardDuty is a Baron decision with cost implications, never done by this
// test). A zero-detector or zero-finding result is a PASS: it proves the API
// call chain and credentials are wired correctly. The acceptance bar for "a
// live GuardDuty finding flows end-to-end" is tracked separately in the rd
// item and is not this test's job — this test only proves the connector
// doesn't error against the real API.
//
// Required env vars:
//
//	AWS_ACCESS_KEY_ID
//	AWS_SECRET_ACCESS_KEY
//	AWS_REGION (optional, defaults to us-east-1)
func TestGuardDutyIntegration(t *testing.T) {
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
	client := guardduty.NewFromConfig(cfg)

	ids, err := listDetectorIDs(context.Background(), client)
	if err != nil {
		t.Fatalf("listDetectorIDs: %v", err)
	}
	t.Logf("found %d GuardDuty detector(s) in %s", len(ids), region)
	if len(ids) == 0 {
		t.Log("no detector found — GuardDuty is not enabled in this account/region (expected until the mallcoppro-46b gate is approved); API call chain verified up to ListDetectors")
		return
	}

	// Fetch last 30 days across every detector found.
	since := time.Now().UTC().Add(-30 * 24 * time.Hour)
	var allEvents []*event.Event
	for _, id := range ids {
		events, _, err := fetchFindings(context.Background(), client, id, since, false)
		if err != nil {
			t.Fatalf("fetchFindings(detector=%s): %v", id, err)
		}
		allEvents = append(allEvents, events...)
	}
	t.Logf("fetched %d findings from GuardDuty (last 30d)", len(allEvents))

	// Encode JSONL and validate schema — same shape assertion as
	// cmd/aws/aws_integration_test.go.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range allEvents {
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
		if ev.Source != "guardduty" {
			t.Errorf("line %d: Source = %q, want guardduty", lineNum, ev.Source)
		}
		if ev.Type != "guardduty_finding" {
			t.Errorf("line %d: Type = %q, want guardduty_finding", lineNum, ev.Type)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("line %d: Timestamp zero", lineNum)
		}
	}
	t.Logf("validated %d JSONL events", lineNum)
}
