package normalize

import "testing"

// rawFinding builds a decoded-map fixture matching what cmd/guardduty's
// normalizeFinding actually produces (json.Marshal(types.Finding{}) unmarshaled
// into map[string]any — PascalCase Go field names, see guardduty.go's doc
// comment for why).
func rawFinding(overrides map[string]any) map[string]any {
	m := map[string]any{
		"Id":          "finding-1",
		"AccountId":   "111111111111",
		"Region":      "us-east-1",
		"Arn":         "arn:aws:guardduty:us-east-1:111111111111:detector/det-1/finding/finding-1",
		"Type":        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
		"Title":       "Console login was performed with root credentials.",
		"Description": "Root credentials were used to sign in.",
		"CreatedAt":   "2024-06-01T12:00:00.000Z",
		"UpdatedAt":   "2024-06-01T12:05:00.000Z",
		"Severity":    5.5,
		"Confidence":  8.0,
		"Resource": map[string]any{
			"ResourceType": "AccessKey",
			"AccessKeyDetails": map[string]any{
				"UserName":    "alice",
				"PrincipalId": "AID123",
				"AccessKeyId": "AKIAABC",
			},
		},
		"Service": map[string]any{
			"DetectorId":     "det-1",
			"Archived":       false,
			"Count":          3.0,
			"ResourceRole":   "TARGET",
			"EventFirstSeen": "2024-06-01T11:00:00.000Z",
			"EventLastSeen":  "2024-06-01T12:05:00.000Z",
		},
	}
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

// TestGuardDutyAlwaysMapsToFindingType is the honesty-rule regression test
// (Mercury/Coinbase precedent): no raw GuardDuty finding type is ever
// stretched onto an existing admin-action gate — every finding is already a
// pre-triaged alert, so every finding type maps to the single canonical
// "guardduty_finding" type.
func TestGuardDutyAlwaysMapsToFindingType(t *testing.T) {
	types := []string{
		"UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
		"Recon:EC2/PortProbeUnprotectedPort",
		"CryptoCurrency:EC2/BitcoinTool.B",
		"Persistence:IAMUser/AnomalousBehavior",
		"SomeFutureUnknownFindingType",
	}
	for _, typ := range types {
		got := GuardDuty(typ, rawFinding(map[string]any{"Type": typ}))
		if len(got) != 1 {
			t.Fatalf("type %q: want 1 result, got %d", typ, len(got))
		}
		if got[0].Type != "guardduty_finding" {
			t.Errorf("type %q: Type = %q, want guardduty_finding", typ, got[0].Type)
		}
	}
}

func TestGuardDutySignalClassAlert(t *testing.T) {
	raw := rawFinding(nil)
	got := GuardDuty("UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", raw)
	r := wantType(t, got, "guardduty_finding")
	p := decode(t, r, raw)

	if p["signal_class"] != "alert" {
		t.Errorf("signal_class = %v, want alert", p["signal_class"])
	}
	if p["raw"] == nil {
		t.Error("payload missing raw")
	}
}

func TestGuardDutyFlatFields(t *testing.T) {
	raw := rawFinding(nil)
	got := GuardDuty("UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", raw)
	p := decode(t, got[0], raw)

	cases := map[string]any{
		"finding_id":       "finding-1",
		"finding_type":     "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
		"account_id":       "111111111111",
		"region":           "us-east-1",
		"title":            "Console login was performed with root credentials.",
		"description":      "Root credentials were used to sign in.",
		"resource_type":    "AccessKey",
		"principal":        "alice",
		"principal_id":     "AID123",
		"access_key_id":    "AKIAABC",
		"detector_id":      "det-1",
		"resource_role":    "TARGET",
		"event_first_seen": "2024-06-01T11:00:00.000Z",
		"event_last_seen":  "2024-06-01T12:05:00.000Z",
		"archived":         false,
		"count":            float64(3), // decoded back through JSON -> float64
		"severity":         5.5,
		"confidence":       8.0,
	}
	for k, want := range cases {
		if got := p[k]; got != want {
			t.Errorf("%s = %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}
}

func TestGuardDutySeverityLabel(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0.1, "low"},
		{3.9, "low"},
		{4.0, "medium"},
		{6.9, "medium"},
		{7.0, "high"},
		{8.9, "high"},
	}
	for _, tt := range tests {
		raw := rawFinding(map[string]any{"Severity": tt.score})
		got := GuardDuty("x", raw)
		p := decode(t, got[0], raw)
		if p["severity_label"] != tt.want {
			t.Errorf("severity %v: severity_label = %v, want %v", tt.score, p["severity_label"], tt.want)
		}
	}
}

// TestGuardDutyMissingResourceAndServiceOmitsFields: a finding with no
// Resource/Service sub-objects (both nil in the decoded map) must not panic
// and must not carry empty noise fields.
func TestGuardDutyMissingResourceAndServiceOmitsFields(t *testing.T) {
	raw := map[string]any{
		"Id":        "finding-2",
		"AccountId": "111111111111",
		"Region":    "us-east-1",
		"Type":      "SomeType",
		"Severity":  1.0,
	}
	got := GuardDuty("SomeType", raw)
	p := decode(t, got[0], raw)

	for _, k := range []string{"resource_type", "principal", "principal_id", "access_key_id", "detector_id", "resource_role", "archived", "count"} {
		if _, ok := p[k]; ok {
			t.Errorf("%s should be absent when Resource/Service are missing, got %v", k, p[k])
		}
	}
	if p["signal_class"] != "alert" {
		t.Errorf("signal_class = %v, want alert", p["signal_class"])
	}
}

// TestGuardDutyArchivedFindingSurfacesFalseNotOmitted: archived=false is a
// meaningful (not empty/noise) boolean and must round-trip, unlike the
// string fields set() elides when empty.
func TestGuardDutyArchivedFindingSurfacesFalseNotOmitted(t *testing.T) {
	raw := rawFinding(map[string]any{
		"Service": map[string]any{
			"DetectorId": "det-1",
			"Archived":   true,
			"Count":      1.0,
		},
	})
	p := decode(t, GuardDuty("x", raw)[0], raw)
	if p["archived"] != true {
		t.Errorf("archived = %v, want true", p["archived"])
	}
}
