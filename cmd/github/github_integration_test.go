//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

// TestGitHubAuditLogIntegration exercises the real GitHub API via GitHub App auth
// against the org specified by GITHUB_ORG env var.
//
// Required env vars:
//
//	GITHUB_APP_ID           — numeric GitHub App ID
//	GITHUB_INSTALLATION_ID  — numeric installation ID
//	GITHUB_PRIVATE_KEY_PATH — path to PEM private key file
//	GITHUB_ORG              — GitHub org name to query (e.g., "3dl-dev")
func TestGitHubAuditLogIntegration(t *testing.T) {
	appIDStr := os.Getenv("GITHUB_APP_ID")
	installIDStr := os.Getenv("GITHUB_INSTALLATION_ID")
	keyPath := os.Getenv("GITHUB_PRIVATE_KEY_PATH")
	orgName := os.Getenv("GITHUB_ORG")

	if appIDStr == "" || installIDStr == "" || keyPath == "" || orgName == "" {
		t.Skip("GITHUB_APP_ID, GITHUB_INSTALLATION_ID, GITHUB_PRIVATE_KEY_PATH, and GITHUB_ORG must be set")
	}

	var appID, installID int64
	if _, err := parseIntEnv(appIDStr, &appID); err != nil {
		t.Fatalf("invalid GITHUB_APP_ID: %v", err)
	}
	if _, err := parseIntEnv(installIDStr, &installID); err != nil {
		t.Fatalf("invalid GITHUB_INSTALLATION_ID: %v", err)
	}

	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, appID, installID, keyPath)
	if err != nil {
		t.Fatalf("create GitHub App installation transport: %v", err)
	}

	conn := &connector{
		client:         &http.Client{Transport: itr},
		org:            orgName,
		appID:          appID,
		installationID: installID,
		out:            bytes.NewBuffer(nil),
		maxPages:       1, // one page (up to 100 events) is sufficient for validation
	}

	ctx := context.Background()
	events, _, err := conn.fetchAuditLog(ctx)
	if err != nil {
		t.Fatalf("fetchAuditLog: %v", err)
	}

	if len(events) == 0 {
		t.Fatalf("expected ≥1 event from %s audit log, got 0", orgName)
	}
	t.Logf("fetched %d events", len(events))

	// Re-encode as JSONL and parse each line to validate schema.
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
		line := scanner.Bytes()
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Errorf("line %d: invalid JSON: %v", lineNum, err)
			continue
		}
		// Validate required fields.
		if ev.ID == "" {
			t.Errorf("line %d: event.ID is empty", lineNum)
		}
		if ev.Source != "github" {
			t.Errorf("line %d: event.Source = %q, want %q", lineNum, ev.Source, "github")
		}
		if ev.Type == "" {
			t.Errorf("line %d: event.Type is empty", lineNum)
		}
		if ev.Org == "" {
			t.Errorf("line %d: event.Org is empty", lineNum)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("line %d: event.Timestamp is zero", lineNum)
		}
		if ev.Payload == nil {
			t.Errorf("line %d: event.Payload is nil", lineNum)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan JSONL: %v", err)
	}
	if lineNum == 0 {
		t.Fatal("JSONL output contained no lines")
	}
	t.Logf("validated %d JSONL lines against Event schema", lineNum)
}

// parseIntEnv parses a string as int64 into dst.
func parseIntEnv(s string, dst *int64) (int64, error) {
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	if err != nil {
		return 0, err
	}
	*dst = v
	return v, nil
}
