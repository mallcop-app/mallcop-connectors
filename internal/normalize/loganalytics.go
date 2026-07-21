package normalize

import "strings"

// LogAnalytics maps a decoded relay_security structured log line (emitted by
// the nostr-relay's internal/seclog package, mallcoppro-813, and surfaced via
// Azure Log Analytics ContainerAppConsoleLogs_CL — cmd/loganalytics) to
// canonical mallcop events.
//
// decision/pubkey/remote/domain/detail are the five relay_security fields
// (see nostr-relay's internal/seclog/seclog.go doc comment: "{"msg":
// "relay_security","decision":<decision>,"pubkey":<pubkey>,"remote":<remote>,
// "domain":<domain>,"detail":<detail>}"). The decision literals below are
// byte-identical copies of nostr-relay's seclog.Decision* constants (verified
// against internal/seclog/seclog.go 2026-07-21) — this package cannot import
// that module (separate repo/module), so the strings are duplicated here
// rather than shared.
//
// decisionNIP42AuthFailure is defined in seclog.go but NOT currently wired to
// any call site in the relay (mallcoppro-813's live-proof escalation: no
// non-vendor khatru hook point exists for the raw NIP-42 AUTH envelope
// failure without hand-patching vendored khatru, which that item's scope
// forbade — accepted descope mallcoppro-a26). It is still mapped here
// (defensively, alongside the two decisions that DO fire in prod) in case a
// future relay change wires it in; today it will simply never appear in a
// live query result.
const (
	decisionNIP42AuthFailure    = "nip42_auth_failure"
	decisionUnauthorizedWriter  = "unauthorized_writer"
	decisionBalanceGateRejected = "balance_gate_rejected"
	decisionRateLimited         = "rate_limited"
	decisionNIP86AdminCall      = "nip86_admin_call"
	decisionNIP09Tombstone      = "nip09_tombstone"
)

// LogAnalyticsAuthFailureEventType is the canonical Type for every relay
// decision that represents a failed authentication/authorization attempt to
// write or connect (nip42_auth_failure, unauthorized_writer,
// balance_gate_rejected) — it MUST exactly equal
// mallcop/core/detect/auth_failure_burst.go's authFailureEventTypes gate
// literal ("login_failure") so a repeated-rejection burst from the same
// pubkey (credential-stuffing-shaped probing of the relay's write gates)
// fires auth-failure-burst exactly like a repeated failed console login
// would for any other connector.
const LogAnalyticsAuthFailureEventType = "login_failure"

// LogAnalyticsRateEventType is the canonical Type for a rate_limited
// decision — it MUST exactly equal mallcop/core/detect/rate_anomaly.go's
// inline ev.Type gate literal ("rate_event") so relay rate-limit rejections
// feed the rate/volume-anomaly detector.
const LogAnalyticsRateEventType = "rate_event"

// LogAnalytics maps a single relay_security line to one or more Results. An
// unrecognized decision string (a future seclog.Decision* the relay adds
// before this connector is updated) falls through to CatchAll rather than
// being dropped, so it still reaches the type-less detectors instead of
// silently vanishing.
func LogAnalytics(decision, pubkey, remote, domain, detail string) []Result {
	switch decision {

	// --- auth-failure-burst: nip42_auth_failure / unauthorized_writer /
	// balance_gate_rejected are all "this pubkey tried to do something that
	// requires standing and was rejected" — the same brute-force/probing
	// shape auth-failure-burst already detects for login_failure. actor
	// (the caller's pubkey) is set by cmd/loganalytics from the same
	// `pubkey` field, so repeated rejections from one pubkey accrue exactly
	// like repeated login_failure events from one username.
	case decisionNIP42AuthFailure, decisionUnauthorizedWriter, decisionBalanceGateRejected:
		p := map[string]any{"action": "auth_failure", "decision": decision}
		set(p, "reason", detail)
		set(p, "ip", remote)
		set(p, "source_ip", remote)
		set(p, "domain", domain)
		return []Result{{Type: LogAnalyticsAuthFailureEventType, Payload: p}}

	// --- rate-anomaly: one rejected request per line, so request_count is
	// always 1 (rateAnomalyEvaluate treats a missing/zero request_count as
	// 1 anyway; set explicitly for clarity that this is a single-request
	// signal, not a pre-aggregated burst count).
	case decisionRateLimited:
		p := map[string]any{"action": "rate_limited", "decision": decision, "request_count": 1}
		set(p, "reason", detail)
		set(p, "ip", remote)
		set(p, "domain", domain)
		return []Result{{Type: LogAnalyticsRateEventType, Payload: p}}

	// --- priv-escalation + config-drift fan-out: every NIP-86 relay
	// management API call (allow/ban/list/supportedmethods, allow AND deny
	// outcomes alike — nip86admin.go's RejectNonAdminAPICall logs this
	// decision for EVERY method call, not just grant-shaped ones) is an
	// admin mutation of the relay's write-allowlist surface. Unconditional
	// fan-out, mirroring azure.go's Microsoft.DocumentDB/databaseAccounts/
	// sqlRoleAssignments/write mapping (a Cosmos DB SQL RBAC grant, which
	// also fans out to iam_policy_attach + role_assignment unconditionally
	// because that gate has no "unprivileged tier" to condition on) — NIP-86
	// admin calls have no such tier either: this relay's whole write-
	// allowlist model is a single privileged surface.
	//
	// detail is "method=<name> outcome=<allow|deny>" (nip86admin.go); method
	// is parsed out for payload richness (role/policy_name) but the fan-out
	// itself does not condition on it or on outcome.
	case decisionNIP86AdminCall:
		method := parseNIP86Method(detail)
		cd := map[string]any{"action": "admin_call"}
		set(cd, "resource_name", "nostr-relay")
		set(cd, "policy_name", method)
		cd["change_description"] = "NIP-86 admin call: " + detail
		pe := map[string]any{"action": "role_assignment"}
		set(pe, "role", method)
		set(pe, "target_user", pubkey)
		set(pe, "principal_id", pubkey)
		set(pe, "resource_name", "nostr-relay")
		return []Result{
			{Type: "iam_policy_attach", Payload: cd},
			{Type: "role_assignment", Payload: pe},
		}

	// --- delete/drift family: "audit_trail_delete" is the SAME literal
	// azure.go's diagnosticSettings/delete and gcp.go's DeleteSink mappings
	// already use (config-drift's configRuleByEventType gates on it with NO
	// ev.Source check) — a relay accepting/applying a NIP-09 tombstone is
	// the same "a piece of the append-only record was told to disappear"
	// signal, just observed from the relay's own accept-side security log
	// rather than the raw nostr event. Written as a literal (not a shared
	// exported constant) to match the existing azure.go/gcp.go precedent —
	// each per-cloud mapper owns its own literal rather than importing
	// another mapper's.
	case decisionNIP09Tombstone:
		p := map[string]any{"action": "delete", "config_key": "nostr_event"}
		set(p, "resource_name", parseTombstoneEventID(detail))
		p["change_description"] = detail
		return []Result{{Type: "audit_trail_delete", Payload: p}}
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": "relay_security:" + decision}}}
}

// parseNIP86Method extracts the method name from a nip86admin.go detail
// string of the form "method=<name> outcome=<allow|deny>". Returns "" if the
// expected "method=" prefix isn't found (defensive: never panics on an
// unexpected detail shape).
func parseNIP86Method(detail string) string {
	const prefix = "method="
	idx := strings.Index(detail, prefix)
	if idx < 0 {
		return ""
	}
	rest := detail[idx+len(prefix):]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		return rest[:sp]
	}
	return rest
}

// parseTombstoneEventID extracts the deleted event id from a store.go detail
// string of the form "tombstoned event id=<id>". Returns "" if the expected
// "id=" suffix isn't found.
func parseTombstoneEventID(detail string) string {
	const marker = "id="
	idx := strings.LastIndex(detail, marker)
	if idx < 0 {
		return ""
	}
	return detail[idx+len(marker):]
}
