package normalize

// GuardDuty maps a raw AWS GuardDuty finding to a single canonical mallcop
// event.
//
// raw is produced by cmd/guardduty's normalizeFinding via
// json.Marshal(types.Finding{...}) + json.Unmarshal into map[string]any. The
// GuardDuty Go SDK's generated types carry NO json struct tags (verified
// empirically: encoding/json falls back to the exported Go field names), so
// the decoded map uses PascalCase keys matching the SDK struct fields
// ("AccountId", "CreatedAt", "Resource", "Service", ...) — NOT AWS's
// camelCase wire format ("accountId", "createdAt", ...) that ListFindings /
// GetFindings actually send over HTTP. This is the same "SDK struct as
// decode source" pattern cmd/aws relies on for the outer CloudTrailEvent
// wrapper (see aws.go's awsInner); cmd/guardduty is this file's only caller
// and controls the shape end-to-end, so the mismatch with AWS's wire format
// is safe as long as both sides agree — they do, by construction.
//
// findingType is raw["Type"] (e.g. "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B"),
// passed explicitly (like AWS's eventName / Mercury's kind) since the
// connector already has it from the typed struct.
//
// HONESTY RULE (Mercury/Coinbase precedent): a GuardDuty finding is not a raw
// admin/IAM audit event — it is ALREADY a pre-triaged security alert (GuardDuty
// is itself a detector). Stretching individual finding types onto mallcop's
// admin-action gate vocabulary (role_assignment, config_change, secret_access,
// ...) would misrepresent an alert that already carries its own type
// taxonomy (finding_type in the payload) and severity score as if mallcop's
// detectors had derived it from scratch. So every finding maps uniformly to
// "guardduty_finding" with "signal_class":"alert" — this is the entry point
// for mallcop's alert-stream path (mallcoppro-46b), which treats
// signal_class=="alert" as pre-triaged and distinct from the type-less
// detectors (new-actor, unusual-timing, volume-anomaly, injection-probe,
// secrets-exposure) that infer risk from raw activity.
func GuardDuty(findingType string, raw map[string]any) []Result {
	resource := subMap(raw, "Resource")
	service := subMap(raw, "Service")
	accessKey := subMap(resource, "AccessKeyDetails")

	p := map[string]any{
		"signal_class": "alert",
		"finding_type": findingType,
	}
	set(p, "finding_id", mapStr(raw, "Id"))
	set(p, "title", mapStr(raw, "Title"))
	set(p, "description", mapStr(raw, "Description"))
	set(p, "account_id", mapStr(raw, "AccountId"))
	set(p, "region", mapStr(raw, "Region"))
	set(p, "arn", mapStr(raw, "Arn"))
	set(p, "created_at", mapStr(raw, "CreatedAt"))
	set(p, "updated_at", mapStr(raw, "UpdatedAt"))
	set(p, "resource_type", mapStr(resource, "ResourceType"))
	set(p, "principal", mapStr(accessKey, "UserName"))
	set(p, "principal_id", mapStr(accessKey, "PrincipalId"))
	set(p, "access_key_id", mapStr(accessKey, "AccessKeyId"))
	set(p, "detector_id", mapStr(service, "DetectorId"))
	set(p, "resource_role", mapStr(service, "ResourceRole"))
	set(p, "event_first_seen", mapStr(service, "EventFirstSeen"))
	set(p, "event_last_seen", mapStr(service, "EventLastSeen"))

	if sev, ok := raw["Severity"].(float64); ok {
		p["severity"] = sev
		p["severity_label"] = severityLabel(sev)
	}
	if conf, ok := raw["Confidence"].(float64); ok {
		p["confidence"] = conf
	}
	if archived, ok := service["Archived"].(bool); ok {
		p["archived"] = archived
	}
	if count, ok := service["Count"].(float64); ok {
		p["count"] = int64(count)
	}

	return []Result{{Type: "guardduty_finding", Payload: p}}
}

// severityLabel buckets a GuardDuty severity score into the documented
// Low/Medium/High tiers.
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html
func severityLabel(score float64) string {
	switch {
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}
