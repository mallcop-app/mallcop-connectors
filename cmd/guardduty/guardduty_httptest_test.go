package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

// TestFetchFindingsOverRealWireProtocol points a REAL *guardduty.Client (the
// same type run() constructs in production) at a fake HTTP server via
// guardduty.Options.BaseEndpoint — the AWS SDK supports overriding the
// endpoint per-client, so this exercises the actual REST-JSON request
// serialization and response deserialization end-to-end (SigV4 signing over
// static test credentials, real JSON wire shapes: GET /detector, POST
// /detector/{id}/findings, POST /detector/{id}/findings/get), unlike
// guardduty_test.go's guarddutyAPI fakes, which stub the SDK call boundary
// directly and never touch HTTP or JSON codec behavior.
//
// The fixture response bodies use AWS's actual camelCase wire field names
// (accountId, createdAt, updatedAt, resource.accessKeyDetails.userName, ...)
// — deliberately NOT the PascalCase Go-field-name shape normalize.GuardDuty
// consumes (see internal/normalize/guardduty.go's doc comment): that PascalCase
// shape only exists after the SDK has already deserialized this exact wire
// response into a typed types.Finding and cmd/guardduty re-marshals it. This
// test proves that deserialization step is correct; guardduty_test.go proves
// what happens after it.
func TestFetchFindingsOverRealWireProtocol(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/detector", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("ListDetectors: method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"detectorIds":["det-1"]}`))
	})
	mux.HandleFunc("/detector/det-1/findings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("ListFindings: method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"findingIds":["finding-wire-1"]}`))
	})
	mux.HandleFunc("/detector/det-1/findings/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("GetFindings: method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"findings": [{
				"id": "finding-wire-1",
				"arn": "arn:aws:guardduty:us-east-1:111111111111:detector/det-1/finding/finding-wire-1",
				"accountId": "111111111111",
				"region": "us-east-1",
				"schemaVersion": "2.0",
				"type": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
				"title": "wire-protocol test finding",
				"description": "exercises the real REST-JSON codec",
				"severity": 7.5,
				"confidence": 8.0,
				"createdAt": "2024-06-01T12:00:00.000Z",
				"updatedAt": "2024-06-01T12:05:00.000Z",
				"resource": {
					"resourceType": "AccessKey",
					"accessKeyDetails": {
						"userName": "alice",
						"principalId": "AID123",
						"accessKeyId": "AKIAABC",
						"userType": "IAMUser"
					}
				},
				"service": {
					"detectorId": "det-1",
					"archived": false,
					"count": 2,
					"resourceRole": "TARGET",
					"eventFirstSeen": "2024-06-01T11:00:00.000Z",
					"eventLastSeen": "2024-06-01T12:05:00.000Z"
				}
			}]
		}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIAFAKE", "fake-secret", ""),
	}
	endpoint := server.URL
	client := guardduty.NewFromConfig(cfg, func(o *guardduty.Options) {
		o.BaseEndpoint = &endpoint
	})

	ids, err := listDetectorIDs(t.Context(), client)
	if err != nil {
		t.Fatalf("listDetectorIDs over real wire protocol: %v", err)
	}
	if len(ids) != 1 || ids[0] != "det-1" {
		t.Fatalf("detector ids = %v, want [det-1]", ids)
	}

	events, maxSeen, err := fetchFindings(t.Context(), client, "det-1", time.Time{}, false)
	if err != nil {
		t.Fatalf("fetchFindings over real wire protocol: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	ev := events[0]

	if ev.Source != "guardduty" {
		t.Errorf("Source = %q, want guardduty", ev.Source)
	}
	if ev.Type != "guardduty_finding" {
		t.Errorf("Type = %q, want guardduty_finding", ev.Type)
	}
	if ev.Actor != "alice" {
		t.Errorf("Actor = %q, want alice — proves resource.accessKeyDetails.userName deserialized correctly off the wire", ev.Actor)
	}
	if ev.Org != "111111111111" {
		t.Errorf("Org = %q, want account id", ev.Org)
	}
	wantTS := time.Date(2024, 6, 1, 12, 5, 0, 0, time.UTC)
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("Timestamp = %v, want %v — proves updatedAt deserialized correctly off the wire", ev.Timestamp, wantTS)
	}
	if !maxSeen.Equal(wantTS) {
		t.Errorf("maxSeen = %v, want %v", maxSeen, wantTS)
	}

	var payload map[string]any
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("Payload is not valid JSON: %v", err)
	}
	if payload["signal_class"] != "alert" {
		t.Errorf("payload signal_class = %v, want alert", payload["signal_class"])
	}
	if payload["severity"] != 7.5 {
		t.Errorf("payload severity = %v, want 7.5 — proves severity deserialized correctly off the wire", payload["severity"])
	}
	if payload["severity_label"] != "high" {
		t.Errorf("payload severity_label = %v, want high", payload["severity_label"])
	}
	if title, _ := payload["title"].(string); !strings.Contains(title, "wire-protocol") {
		t.Errorf("payload title = %v, want it to carry the wire-decoded title", payload["title"])
	}
}
