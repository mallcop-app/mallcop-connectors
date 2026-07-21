package normalize

import "strings"

// Nostr maps a decoded nostr event (NIP-01: id/pubkey/created_at/kind/tags/
// content/sig) to canonical mallcop Result(s).
//
// kind is the event's `kind` field. raw is the fully JSON-decoded event
// object, used both for tag inspection below and (by the caller, via
// Result.PayloadJSON) as the verbatim "raw" sub-object so injection-probe and
// secrets-exposure still scan the event's content/tags recursively.
//
// kind 5 is NIP-09 "Event Deletion Request" — the author asking relays to
// drop/hide a prior event. It maps to "audit_trail_delete", the SAME literal
// already used (and detector-proven) by Azure's diagnosticSettings/delete and
// GCP's DeleteSink mappings (see azure.go, gcp.go, and
// normalize_test.go's TestAzureDiagnosticDeleteAuditTrail /
// TestGCPDeleteSinkAuditTrailDelete) for "a piece of the append-only audit
// record was told to disappear." config-drift's configRuleByEventType
// (mallcop core/detect/config_drift.go) indexes purely by event Type string
// with NO ev.Source gate — unlike git-oops's branch_delete/tag_delete, which
// ALSO requires ev.Source in {github,gitlab,bitbucket,git} (git_oops.go) and
// so could never fire for ev.Source=="nostr" regardless of Type. That source
// gate is why branch_delete/tag_delete are NOT used here even though the item
// spec named them as candidates: picking either would compile fine and then
// silently never fire in production, exactly the failure mode this mapping
// exists to avoid.
//
// Every other kind maps to CatchAll (cloud_other), which still feeds the
// type-less detectors (unusual-timing, volume-anomaly, injection-probe,
// secrets-exposure, new-actor per-event baseline).
const NostrDeleteEventType = "audit_trail_delete"

func Nostr(kind int, raw map[string]any) []Result {
	if kind == 5 {
		p := map[string]any{"action": "delete", "config_key": "nostr_event"}
		set(p, "resource_name", nostrDeletedTargets(raw))
		p["change_description"] = "NIP-09 deletion request"
		return []Result{{Type: NostrDeleteEventType, Payload: p}}
	}

	p := map[string]any{"action": "nostr_event"}
	p["kind"] = kind
	return []Result{{Type: CatchAll, Payload: p}}
}

// nostrDeletedTargets extracts the event IDs targeted by a NIP-09 deletion
// request: every "e" tag's value, comma-joined. Returns "" when tags is
// absent, malformed, or carries no "e" tags — never panics on a hostile or
// malformed tags shape (every step is a comma-ok type assertion).
func nostrDeletedTargets(raw map[string]any) string {
	tagsAny, _ := raw["tags"].([]any)
	var ids []string
	for _, t := range tagsAny {
		tag, ok := t.([]any)
		if !ok || len(tag) < 2 {
			continue
		}
		name, _ := tag[0].(string)
		val, _ := tag[1].(string)
		if name == "e" && val != "" {
			ids = append(ids, val)
		}
	}
	return strings.Join(ids, ",")
}
