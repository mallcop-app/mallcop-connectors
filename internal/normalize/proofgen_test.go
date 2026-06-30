package normalize

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestEmitProofEvents is a helper (run explicitly via -run) that writes a
// representative set of NORMALIZED events to the path in MALLCOP_PROOF_OUT, in
// the mallcop event.Event JSONL shape, so `mallcop scan` can be run against real
// connector output. Skipped unless MALLCOP_PROOF_OUT is set.
func TestEmitProofEvents(t *testing.T) {
	out := os.Getenv("MALLCOP_PROOF_OUT")
	if out == "" {
		t.Skip("set MALLCOP_PROOF_OUT to emit proof events")
	}

	type ev struct {
		ID        string          `json:"id"`
		Source    string          `json:"source"`
		Type      string          `json:"type"`
		Actor     string          `json:"actor"`
		Timestamp time.Time       `json:"timestamp"`
		Org       string          `json:"org"`
		Payload   json.RawMessage `json:"payload"`
	}

	ts := time.Date(2026, 6, 18, 3, 0, 0, 0, time.UTC)
	var events []ev
	add := func(source, actor string, raw any, results []Result) {
		for i, r := range results {
			pj, err := r.PayloadJSON(raw)
			if err != nil {
				t.Fatalf("PayloadJSON: %v", err)
			}
			events = append(events, ev{
				ID:        source + "-proof-" + r.Type + "-" + string(rune('a'+i)),
				Source:    source,
				Type:      r.Type,
				Actor:     actor,
				Timestamp: ts,
				Org:       "proof-org",
				Payload:   pj,
			})
		}
	}

	// AWS: cross-account AssumeRole → trust_added (new-external-access).
	awsRaw := map[string]any{
		"CloudTrailEvent": `{"recipientAccountId":"111111111111",
			"requestParameters":{"roleArn":"arn:aws:iam::999999999999:role/attacker"}}`,
	}
	add("aws", "intruder@evil.com", awsRaw, AWS("AssumeRole", awsRaw))

	// AWS: StopLogging → cloudtrail_stop (config-drift, critical).
	awsStop := map[string]any{"CloudTrailEvent": `{"requestParameters":{"name":"prod-trail"}}`}
	add("aws", "intruder@evil.com", awsStop, AWS("StopLogging", awsStop))

	// Azure: roleAssignments/write granting Owner → role_assignment (priv-escalation).
	azRaw := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/rg",
		"properties": map[string]any{"roleDefinitionName": "Owner", "principalId": "victim"},
	}
	add("azure", "attacker@corp.com", azRaw, Azure("Microsoft.Authorization/roleAssignments/write", azRaw))

	// GCP: SetIamPolicy granting owner → fan-out iam_policy_attach + role_assignment.
	gcpRaw := map[string]any{
		"resourceName": "projects/p",
		"request": map[string]any{"policy": map[string]any{"bindings": []any{
			map[string]any{"role": "roles/owner", "members": []any{"user:evil@x.com"}},
		}}},
	}
	add("gcp", "deployer@corp.com", gcpRaw, GCP("google.iam.admin.v1.SetIamPolicy", gcpRaw))

	// M365: Consent to application → org.add_outside_collaborator (new-external-access).
	m365Raw := map[string]any{
		"ObjectId": "app-666",
		"ModifiedProperties": []any{
			map[string]any{"Name": "ConsentContext.DisplayName", "NewValue": "DataSiphon"},
		},
	}
	add("m365", "user@corp.com", m365Raw, M365("AzureActiveDirectory", "Consent to application.", m365Raw))

	// Okta: privilege grant of Super Admin → role_assignment (priv-escalation).
	oktaRaw := map[string]any{
		"target": []any{
			map[string]any{"type": "AppRole", "displayName": "Super Admin"},
			map[string]any{"type": "User", "alternateId": "victim@corp.com"},
		},
	}
	add("okta", "rogue-admin@corp.com", oktaRaw, Okta("user.account.privilege.grant", oktaRaw))

	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	t.Logf("wrote %d proof events to %s", len(events), out)
}
