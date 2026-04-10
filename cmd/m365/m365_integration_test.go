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

	"github.com/thirdiv/mallcop-connectors/pkg/event"
)

// TestM365AuditLogIntegration exercises the real Office 365 Management Activity API.
//
// Required env vars:
//
//	M365_TENANT_ID
//	M365_CLIENT_ID
//	M365_CLIENT_SECRET
func TestM365AuditLogIntegration(t *testing.T) {
	tenantID := os.Getenv("M365_TENANT_ID")
	clientID := os.Getenv("M365_CLIENT_ID")
	clientSecret := os.Getenv("M365_CLIENT_SECRET")

	if tenantID == "" || clientID == "" || clientSecret == "" {
		t.Skip("M365_TENANT_ID, M365_CLIENT_ID, and M365_CLIENT_SECRET must be set")
	}

	token, err := getAccessToken(tenantID, clientID, clientSecret)
	if err != nil {
		t.Fatalf("getAccessToken: %v", err)
	}

	conn := &connector{
		client:      http.DefaultClient,
		accessToken: token,
		tenantID:    tenantID,
	}

	since := time.Now().UTC().Add(-24 * time.Hour)
	events, newIDs, err := conn.fetchAuditLog(context.Background(), since, nil)
	if err != nil {
		t.Fatalf("fetchAuditLog: %v", err)
	}

	t.Logf("fetched %d events from M365 audit log (last 24h)", len(events))
	t.Logf("last blob IDs: %v", newIDs)

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
		if ev.Source != "m365" {
			t.Errorf("line %d: Source = %q, want m365", lineNum, ev.Source)
		}
	}
	t.Logf("validated %d JSONL events", lineNum)
}
