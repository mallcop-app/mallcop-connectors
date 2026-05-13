//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

// TestOktaSystemLogIntegration exercises the real Okta System Log API.
//
// Required env vars:
//
//	OKTA_DOMAIN    — e.g. myorg.okta.com
//	OKTA_API_TOKEN — SSWS token with okta.logs.read scope
func TestOktaSystemLogIntegration(t *testing.T) {
	domain := os.Getenv("OKTA_DOMAIN")
	apiToken := os.Getenv("OKTA_API_TOKEN")

	if domain == "" || apiToken == "" {
		t.Skip("OKTA_DOMAIN and OKTA_API_TOKEN must be set")
	}

	conn := &connector{
		client:   http.DefaultClient,
		domain:   domain,
		apiToken: apiToken,
		since:    time.Now().UTC().Add(-7 * 24 * time.Hour),
	}

	events, _, err := conn.fetchSystemLog(context.Background())
	if err != nil {
		t.Fatalf("fetchSystemLog: %v", err)
	}

	t.Logf("fetched %d events from Okta System Log (last 7d)", len(events))

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
		if ev.Source != "okta" {
			t.Errorf("line %d: Source = %q, want okta", lineNum, ev.Source)
		}
	}
	t.Logf("validated %d JSONL events", lineNum)
}
