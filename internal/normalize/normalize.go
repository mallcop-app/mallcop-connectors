// Package normalize is the shared mallcop-connectors normalization library. It
// maps raw cloud audit events to the mallcop detector vocabulary: a canonical
// event Type string (which MUST exactly equal a mallcop detector gate constant
// or the detector silently never fires) plus a flat detector-readable Payload.
//
// Why this exists: every cloud connector previously set ev.Type to the raw
// provider event name (CloudTrail eventName, Azure operationName, GCP methodName,
// O365 Workload.Operation, Okta eventType). None of those strings match any
// mallcop detector gate, so only the type-less detectors (injection-probe,
// secrets-exposure, unusual-timing, volume-anomaly, new-actor per-event) ever
// fired — and even those got no enriched payload fields. This library fixes both:
// canonical Type + flat payload carrying the fields each detector reads.
//
// PAYLOAD SHAPE: we emit the production flat layout (Layout 2). Detectors that
// use payloadMeta() read flat top-level fields fine; detectors that json.Unmarshal
// directly into typed structs (config-drift, exfil-pattern, rate-anomaly,
// git-oops, dependency-tamper, malicious-skill) also require their fields at the
// top level — which the flat layout provides. We always include "action" at the
// top level (priv-escalation reads it from the raw map before payloadMeta) and a
// "raw" sub-object carrying the verbatim source event so injection-probe and
// secrets-exposure still scan every original string recursively.
package normalize

import "encoding/json"

// CatchAll is the inert event type emitted for raw events not in any per-cloud
// mapping table. It gates no detector, so unmapped events still flow to the
// type-less detectors (unusual-timing, volume-anomaly, injection-probe,
// secrets-exposure, new-actor per-event baseline) without crashing or producing
// a spurious gated finding.
const CatchAll = "cloud_other"

// Result carries the normalized Type and flat Payload for a single raw event.
// Some raw events fan out to MULTIPLE canonical events (e.g. a GCP SetIamPolicy
// that both drifts config AND assigns a privileged role), so per-cloud mappers
// return a slice of Result.
type Result struct {
	Type    string
	Payload map[string]any
}

// PayloadJSON marshals a Result payload to json.RawMessage, always attaching the
// verbatim raw source event under "raw" for recursive string scanning by
// injection-probe / secrets-exposure. A nil payload yields a payload carrying
// only "action" and "raw".
func (r Result) PayloadJSON(raw any) (json.RawMessage, error) {
	p := map[string]any{}
	for k, v := range r.Payload {
		p[k] = v
	}
	if _, ok := p["raw"]; !ok {
		p["raw"] = raw
	}
	return json.Marshal(p)
}

// --- shared accessors over decoded JSON maps -------------------------------

// mapStr reads a string at key k from m, returning "" when absent or non-string.
func mapStr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// subMap returns m[k] when it is an object, else nil.
func subMap(m map[string]any, k string) map[string]any {
	if m == nil {
		return nil
	}
	if sub, ok := m[k].(map[string]any); ok {
		return sub
	}
	return nil
}

// dig walks a chain of object keys, returning the final object or nil.
func dig(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		cur = subMap(cur, k)
		if cur == nil {
			return nil
		}
	}
	return cur
}

// digStr walks object keys then reads the final key as a string.
func digStr(m map[string]any, keys ...string) string {
	if len(keys) == 0 {
		return ""
	}
	parent := dig(m, keys[:len(keys)-1]...)
	if parent == nil {
		return ""
	}
	return mapStr(parent, keys[len(keys)-1])
}

// set assigns k=v on dst only when v is a non-empty string. Keeps the flat
// payload free of empty noise fields.
func set(dst map[string]any, k, v string) {
	if v != "" {
		dst[k] = v
	}
}

// jsonString marshals v to a compact JSON string for evidence fields like
// new_value. A nil or unmarshalable value yields "".
func jsonString(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
