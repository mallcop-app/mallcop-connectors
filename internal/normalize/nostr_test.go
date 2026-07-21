package normalize

import "testing"

// TestNostrDeletionMapsToAuditTrailDelete pins the kind-5 (NIP-09) mapping to
// the exact byte-equal gate literal config-drift fires on. See nostr.go's doc
// comment for why "audit_trail_delete" (not branch_delete/tag_delete) is
// correct.
func TestNostrDeletionMapsToAuditTrailDelete(t *testing.T) {
	raw := map[string]any{
		"id":         "deadbeef",
		"pubkey":     "abc123",
		"created_at": float64(1700000000),
		"kind":       float64(5),
		"tags": []any{
			[]any{"e", "target-event-1"},
			[]any{"e", "target-event-2"},
			[]any{"unrelated-tag", "x"},
		},
		"content": "",
		"sig":     "sig-bytes",
	}
	got := Nostr(5, raw)
	r := wantType(t, got, "audit_trail_delete")
	p := decode(t, r, raw)
	if p["resource_name"] != "target-event-1,target-event-2" {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
	if p["action"] != "delete" {
		t.Errorf("action = %v, want delete", p["action"])
	}
}

// TestNostrDeleteTypeByteEqualToAzureAndGCP proves the chosen literal is
// byte-equal to the SAME string already used (and detector-gate-proven) by
// two other providers in this repo for the identical semantic — the
// strongest available in-repo proof short of importing mallcop's private
// config_drift rule table across a module boundary.
func TestNostrDeleteTypeByteEqualToAzureAndGCP(t *testing.T) {
	azureResults := Azure("microsoft.insights/diagnosticSettings/delete", map[string]any{"resourceId": "/x"})
	gcpResults := GCP("google.logging.v2.ConfigServiceV2.DeleteSink", map[string]any{"resourceName": "/y"})
	nostrResults := Nostr(5, map[string]any{})

	if len(azureResults) != 1 || len(gcpResults) != 1 || len(nostrResults) != 1 {
		t.Fatalf("expected single-result mappings: azure=%d gcp=%d nostr=%d", len(azureResults), len(gcpResults), len(nostrResults))
	}
	if azureResults[0].Type != NostrDeleteEventType {
		t.Errorf("azure delete Type = %q, want %q", azureResults[0].Type, NostrDeleteEventType)
	}
	if gcpResults[0].Type != NostrDeleteEventType {
		t.Errorf("gcp delete Type = %q, want %q", gcpResults[0].Type, NostrDeleteEventType)
	}
	if nostrResults[0].Type != NostrDeleteEventType {
		t.Errorf("nostr delete Type = %q, want %q", nostrResults[0].Type, NostrDeleteEventType)
	}
}

// TestNostrDeletionNoETagsStillFires: a kind-5 event with no "e" tags (or
// malformed tags) must still map to the delete type with an empty
// resource_name — never panic, never silently drop to CatchAll.
func TestNostrDeletionNoETagsStillFires(t *testing.T) {
	raw := map[string]any{"kind": float64(5), "tags": "not-an-array"}
	r := wantType(t, Nostr(5, raw), "audit_trail_delete")
	p := decode(t, r, raw)
	if p["resource_name"] != nil {
		t.Errorf("resource_name = %v, want absent/empty", p["resource_name"])
	}
}

// TestNostrTextNoteCatchAll: an ordinary kind-1 text note is not any known
// gate, so it must flow through CatchAll (still feeding the type-less
// detectors) rather than being force-mapped onto an unrelated gate.
func TestNostrTextNoteCatchAll(t *testing.T) {
	raw := map[string]any{"kind": float64(1), "content": "gm nostr"}
	r := wantType(t, Nostr(1, raw), CatchAll)
	p := decode(t, r, raw)
	if p["kind"] != float64(1) {
		t.Errorf("kind = %v, want 1", p["kind"])
	}
}

// TestNostrOtherKindsCatchAll sweeps a handful of other common kinds
// (metadata, contacts, reactions, relay-list) to confirm none accidentally
// collide with a gate.
func TestNostrOtherKindsCatchAll(t *testing.T) {
	for _, kind := range []int{0, 3, 6, 7, 10002} {
		r := wantType(t, Nostr(kind, map[string]any{"kind": float64(kind)}), CatchAll)
		if r.Type != CatchAll {
			t.Errorf("kind %d: Type = %q, want CatchAll", kind, r.Type)
		}
	}
}
