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

	"github.com/thirdiv/mallcop-connectors/pkg/event"
)

// TestGCPAuditLogIntegration exercises the real Cloud Logging API.
//
// Required env vars:
//
//	GOOGLE_APPLICATION_CREDENTIALS — path to service account JSON key
//	GCP_PROJECT_ID (or GOOGLE_CLOUD_PROJECT)
func TestGCPAuditLogIntegration(t *testing.T) {
	creds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}

	if creds == "" || projectID == "" {
		t.Skip("GOOGLE_APPLICATION_CREDENTIALS and GCP_PROJECT_ID must be set")
	}

	ctx := context.Background()
	svc, err := newLoggingClient(ctx)
	if err != nil {
		t.Fatalf("newLoggingClient: %v", err)
	}

	since := time.Now().UTC().Add(-7 * 24 * time.Hour)
	events, _, err := fetchAuditLogs(ctx, svc, projectID, since, "")
	if err != nil {
		t.Fatalf("fetchAuditLogs: %v", err)
	}

	t.Logf("fetched %d events from GCP audit log (last 7d)", len(events))

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatalf("encode: %v", err)
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
		if ev.Source != "gcp" {
			t.Errorf("line %d: Source = %q, want gcp", lineNum, ev.Source)
		}
	}
	t.Logf("validated %d JSONL events", lineNum)
}
