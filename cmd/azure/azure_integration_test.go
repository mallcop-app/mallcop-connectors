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

// TestAzureActivityLogIntegration exercises the real Azure Monitor Activity Logs API.
//
// Required env vars:
//
//	AZURE_TENANT_ID
//	AZURE_CLIENT_ID
//	AZURE_CLIENT_SECRET
//	AZURE_SUBSCRIPTION_ID
func TestAzureActivityLogIntegration(t *testing.T) {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")

	if tenantID == "" || clientID == "" || clientSecret == "" || subscriptionID == "" {
		t.Skip("AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_SUBSCRIPTION_ID must be set")
	}

	token, err := getAccessToken(tenantID, clientID, clientSecret)
	if err != nil {
		t.Fatalf("getAccessToken: %v", err)
	}

	conn := &connector{
		client:         httpClient(),
		accessToken:    token,
		subscriptionID: subscriptionID,
		since:          time.Now().UTC().Add(-7 * 24 * time.Hour),
	}

	events, _, err := conn.fetchActivityLog(context.Background())
	if err != nil {
		t.Fatalf("fetchActivityLog: %v", err)
	}

	t.Logf("fetched %d events from Azure Activity Log (last 7d)", len(events))

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
		if ev.Source != "azure" {
			t.Errorf("line %d: Source = %q, want azure", lineNum, ev.Source)
		}
	}
	t.Logf("validated %d JSONL events", lineNum)
}

func httpClient() *http.Client {
	return http.DefaultClient
}
