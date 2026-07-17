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

import (
	"encoding/json"
	"strings"
)

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
	// Credential material (STS session tokens, secret keys) must never persist
	// verbatim in a stored payload — it ends up committed to the customer's
	// findings git branch. Scrub before it gets anywhere near json.Marshal.
	p["raw"] = redactCredentials(p["raw"])
	return json.Marshal(p)
}

// redactedValue replaces credential material found by redactCredentials.
const redactedValue = "[REDACTED]"

// credentialKeys are object keys (matched case-insensitively) whose values are
// live credential material and must never be stored verbatim. accessKeyId and
// expiration are identifiers, not secrets, and are deliberately left alone.
var credentialKeys = map[string]bool{
	"sessiontoken":    true,
	"secretaccesskey": true,
}

// redactCredentials walks a decoded JSON value (map[string]any / []any /
// scalars — the shape every connector's "raw" argument arrives in) and
// returns a copy with any object key in credentialKeys, at any depth,
// replaced by redactedValue. Non-container values pass through unchanged.
//
// One key is special-cased: "CloudTrailEvent". AWS's LookupEvents API (the
// default aws connector path, cmd/aws/main.go) returns each event with its
// inner CloudTrail record still JSON-encoded as a STRING under that key —
// unlike the S3 org-trail path, which hands us the record already decoded.
// A plain map/slice walk never looks inside a string, so
// responseElements.credentials.sessionToken would sail through unredacted
// and land verbatim in the customer's findings git branch. When we see
// "CloudTrailEvent" holding a string, we decode it, redact the decoded
// doc recursively, and re-encode it back into a string so the payload shape
// callers expect is preserved. We do NOT attempt this for any other string
// key — re-encoding an arbitrary string that happens to parse as JSON would
// silently reorder/reformat payload bytes that consumers may hash or compare.
func redactCredentials(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, sub := range val {
			if credentialKeys[strings.ToLower(k)] {
				out[k] = redactedValue
				continue
			}
			if strings.EqualFold(k, "CloudTrailEvent") {
				if s, ok := sub.(string); ok {
					out[k] = redactCloudTrailEventString(s)
					continue
				}
			}
			out[k] = redactCredentials(sub)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, sub := range val {
			out[i] = redactCredentials(sub)
		}
		return out
	default:
		return v
	}
}

// redactCloudTrailEventString decodes s as JSON, redacts credential material
// anywhere in the decoded document, and re-marshals it compactly. If s does
// not parse as JSON, it is returned unchanged — we never mangle a string that
// isn't actually an encoded CloudTrail record.
func redactCloudTrailEventString(s string) string {
	var doc any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return s
	}
	redacted := redactCredentials(doc)
	b, err := json.Marshal(redacted)
	if err != nil {
		return s
	}
	return string(b)
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
