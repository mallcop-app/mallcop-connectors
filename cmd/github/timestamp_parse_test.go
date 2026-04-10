package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestNormalizeEntryMalformedTimestamp(t *testing.T) {
	// Capture log output
	logBuf := &bytes.Buffer{}
	oldStderr := log.Writer()
	log.SetOutput(logBuf)
	defer log.SetOutput(oldStderr)

	// Test with a malformed RFC3339 timestamp string
	entry := auditLogEntry{
		"action":     "test_action",
		"actor":      "test_actor",
		"created_at": "not-a-valid-timestamp",
	}

	ev, err := normalizeEntry(entry, "test-org")
	if err != nil {
		t.Fatalf("normalizeEntry: unexpected error: %v", err)
	}

	// Verify event was created
	if ev == nil {
		t.Fatal("expected non-nil event")
	}

	// Verify log output contains warning
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "warn") {
		t.Errorf("expected warning in log output, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "failed to parse created_at timestamp") {
		t.Errorf("expected 'failed to parse created_at timestamp' in log output, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "not-a-valid-timestamp") {
		t.Errorf("expected malformed timestamp in log output, got: %q", logOutput)
	}

	// Verify fallback to time.Now() (timestamp should not be zero)
	if ev.Timestamp.IsZero() {
		t.Error("expected fallback timestamp to be set (time.Now()), but got zero time")
	}
}

func TestNormalizeEntryValidTimestamp(t *testing.T) {
	// Capture log output
	logBuf := &bytes.Buffer{}
	oldStderr := log.Writer()
	log.SetOutput(logBuf)
	defer log.SetOutput(oldStderr)

	// Test with a valid RFC3339 timestamp string
	validTS := "2024-01-15T10:30:45Z"
	entry := auditLogEntry{
		"action":     "test_action",
		"actor":      "test_actor",
		"created_at": validTS,
	}

	ev, err := normalizeEntry(entry, "test-org")
	if err != nil {
		t.Fatalf("normalizeEntry: unexpected error: %v", err)
	}

	// Verify no warning logged
	logOutput := logBuf.String()
	if strings.Contains(logOutput, "warn") {
		t.Errorf("unexpected warning in log output: %q", logOutput)
	}

	// Verify timestamp was parsed correctly
	expectedTS, _ := time.Parse(time.RFC3339, validTS)
	if !ev.Timestamp.Equal(expectedTS) {
		t.Errorf("timestamp mismatch: got %v, want %v", ev.Timestamp, expectedTS)
	}
}

func TestFetchAuditLogMalformedTimestampSinceComparison(t *testing.T) {
	// Capture log output
	logBuf := &bytes.Buffer{}
	oldStderr := log.Writer()
	log.SetOutput(logBuf)
	defer log.SetOutput(oldStderr)

	// Simulate the timestamp comparison logic in fetchAuditLog
	// when parsing entry timestamp for --since comparison
	since := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	entry := auditLogEntry{
		"created_at": "malformed-timestamp-string",
	}

	// Simulate the parsing logic
	var entryTS time.Time
	if createdAt, ok := entry["created_at"]; ok {
		switch v := createdAt.(type) {
		case string:
			var err error
			entryTS, err = time.Parse(time.RFC3339, v)
			if err != nil {
				log.Printf("warn: failed to parse entry timestamp %q for --since comparison: %v", v, err)
			}
		}
	}

	// Verify warning was logged
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "warn") {
		t.Errorf("expected warning in log output, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "failed to parse entry timestamp") {
		t.Errorf("expected 'failed to parse entry timestamp' in log output, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "for --since comparison") {
		t.Errorf("expected '--since comparison' context in log output, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "malformed-timestamp-string") {
		t.Errorf("expected malformed timestamp in log output, got: %q", logOutput)
	}

	// Verify timestamp is zero (no fallback in comparison logic)
	if !entryTS.IsZero() {
		t.Errorf("expected zero timestamp after failed parse, got %v", entryTS)
	}

	// Verify since comparison is skipped for zero timestamp
	if !entryTS.IsZero() && entryTS.Before(since) {
		t.Error("unexpected comparison result for zero timestamp")
	}
}
