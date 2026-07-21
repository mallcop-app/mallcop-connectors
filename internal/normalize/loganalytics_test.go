package normalize

import "testing"

// --- LogAnalytics (relay_security decision -> mallcop Type) ----------------

// TestLogAnalyticsAuthFailureDecisions covers every decision that represents
// a rejected write/auth attempt: the Type MUST be byte-equal to
// mallcop/core/detect/auth_failure_burst.go's authFailureEventTypes gate
// literal "login_failure" (verified by reading that file directly,
// 2026-07-21) so a burst of same-pubkey rejections fires auth-failure-burst.
func TestLogAnalyticsAuthFailureDecisions(t *testing.T) {
	cases := []string{
		"nip42_auth_failure",
		"unauthorized_writer",
		"balance_gate_rejected",
	}
	for _, decision := range cases {
		t.Run(decision, func(t *testing.T) {
			got := LogAnalytics(decision, "deadbeefpubkey", "203.0.113.5", "relay.moot.pub", "restricted: pubkey is not admitted to this relay's tenant write-allowlist")
			if len(got) != 1 {
				t.Fatalf("want 1 result, got %d: %+v", len(got), got)
			}
			r := got[0]
			if r.Type != "login_failure" {
				t.Errorf("Type = %q, want %q", r.Type, "login_failure")
			}
			if r.Type != LogAnalyticsAuthFailureEventType {
				t.Errorf("Type %q does not match exported LogAnalyticsAuthFailureEventType %q", r.Type, LogAnalyticsAuthFailureEventType)
			}
			p := decode(t, r, map[string]any{"decision": decision})
			if p["ip"] != "203.0.113.5" {
				t.Errorf("ip = %v, want 203.0.113.5", p["ip"])
			}
			if p["reason"] != "restricted: pubkey is not admitted to this relay's tenant write-allowlist" {
				t.Errorf("reason = %v", p["reason"])
			}
			if p["domain"] != "relay.moot.pub" {
				t.Errorf("domain = %v", p["domain"])
			}
		})
	}
}

// TestLogAnalyticsRateLimited asserts the Type equals rate_anomaly.go's
// inline ev.Type gate literal "rate_event" exactly.
func TestLogAnalyticsRateLimited(t *testing.T) {
	got := LogAnalytics("rate_limited", "", "198.51.100.7", "relay.moot.pub", "rate-limited: too many anonymous requests from this IP, try again later")
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(got), got)
	}
	r := got[0]
	if r.Type != "rate_event" {
		t.Errorf("Type = %q, want rate_event", r.Type)
	}
	if r.Type != LogAnalyticsRateEventType {
		t.Errorf("Type %q does not match exported LogAnalyticsRateEventType %q", r.Type, LogAnalyticsRateEventType)
	}
	p := decode(t, r, map[string]any{})
	if p["request_count"] != float64(1) && p["request_count"] != 1 {
		t.Errorf("request_count = %v, want 1", p["request_count"])
	}
	if p["ip"] != "198.51.100.7" {
		t.Errorf("ip = %v", p["ip"])
	}
}

// TestLogAnalyticsNIP86AdminCallFanOut asserts the unconditional two-way
// fan-out to config-drift's "iam_policy_attach" gate and priv-escalation's
// "role_assignment" gate, mirroring azure.go's Cosmos DB SQL role assignment
// mapping (both literals confirmed live in mallcop/core/detect/config_drift.go
// and priv_escalation.go's gate tables).
func TestLogAnalyticsNIP86AdminCallFanOut(t *testing.T) {
	got := LogAnalytics("nip86_admin_call", "adminpubkeyhex", "", "", "method=allowpubkey outcome=allow")
	if len(got) != 2 {
		t.Fatalf("want 2 fan-out results, got %d: %+v", len(got), got)
	}

	cd := wantType(t, got, "iam_policy_attach")
	cdp := decode(t, cd, map[string]any{})
	if cdp["policy_name"] != "allowpubkey" {
		t.Errorf("iam_policy_attach policy_name = %v, want allowpubkey", cdp["policy_name"])
	}
	if cdp["resource_name"] != "nostr-relay" {
		t.Errorf("iam_policy_attach resource_name = %v", cdp["resource_name"])
	}

	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, map[string]any{})
	if pep["role"] != "allowpubkey" {
		t.Errorf("role_assignment role = %v, want allowpubkey", pep["role"])
	}
	if pep["target_user"] != "adminpubkeyhex" {
		t.Errorf("role_assignment target_user = %v, want adminpubkeyhex", pep["target_user"])
	}
}

// TestLogAnalyticsNIP86AdminCallDenyStillFansOut proves the fan-out does NOT
// condition on outcome=allow vs outcome=deny — every admin call is a
// privileged-surface mutation attempt regardless of whether it succeeded,
// mirroring the Cosmos SQL role assignment precedent's unconditional
// fan-out.
func TestLogAnalyticsNIP86AdminCallDenyStillFansOut(t *testing.T) {
	got := LogAnalytics("nip86_admin_call", "", "", "", "method=banpubkey outcome=deny")
	if len(got) != 2 {
		t.Fatalf("want 2 fan-out results even for a denied call, got %d: %+v", len(got), got)
	}
}

// TestLogAnalyticsNIP09Tombstone asserts reuse of the SAME literal
// azure.go/gcp.go already use (and mallcop's detector proves) for
// audit-trail deletions — config-drift's configRuleByEventType has no
// ev.Source gate, so this fires identically whether the delete was observed
// via a raw nostr event or the relay's own accept-side security log.
func TestLogAnalyticsNIP09Tombstone(t *testing.T) {
	got := LogAnalytics("nip09_tombstone", "authorpubkeyhex", "", "", "tombstoned event id=abc123def456")
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(got), got)
	}
	r := got[0]
	if r.Type != "audit_trail_delete" {
		t.Errorf("Type = %q, want audit_trail_delete", r.Type)
	}
	p := decode(t, r, map[string]any{})
	if p["resource_name"] != "abc123def456" {
		t.Errorf("resource_name = %v, want abc123def456", p["resource_name"])
	}
}

// TestLogAnalyticsUnknownDecisionFallsBackToCatchAll proves a decision this
// connector doesn't recognize (e.g. a future seclog.Decision* added to the
// relay before this connector is updated) still reaches the type-less
// detectors instead of being dropped or crashing.
func TestLogAnalyticsUnknownDecisionFallsBackToCatchAll(t *testing.T) {
	got := LogAnalytics("some_future_decision", "pk", "1.2.3.4", "d", "detail text")
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d", len(got))
	}
	if got[0].Type != CatchAll {
		t.Errorf("Type = %q, want CatchAll (%q)", got[0].Type, CatchAll)
	}
}

// TestParseNIP86Method / TestParseTombstoneEventID exercise the detail-string
// parsers directly against the EXACT formats the relay's own source emits
// (nip86admin.go's `"method="+mp.MethodName()+" outcome="+outcome` and
// store.go's `"tombstoned event id="+evt.ID` — verified by reading both
// files, 2026-07-21) plus defensive malformed-input cases.
func TestParseNIP86Method(t *testing.T) {
	cases := []struct{ detail, want string }{
		{"method=allowpubkey outcome=allow", "allowpubkey"},
		{"method=listallowedpubkeys outcome=deny", "listallowedpubkeys"},
		{"no method here", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := parseNIP86Method(c.detail); got != c.want {
			t.Errorf("parseNIP86Method(%q) = %q, want %q", c.detail, got, c.want)
		}
	}
}

func TestParseTombstoneEventID(t *testing.T) {
	cases := []struct{ detail, want string }{
		{"tombstoned event id=abc123", "abc123"},
		{"no id here", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := parseTombstoneEventID(c.detail); got != c.want {
			t.Errorf("parseTombstoneEventID(%q) = %q, want %q", c.detail, got, c.want)
		}
	}
}
