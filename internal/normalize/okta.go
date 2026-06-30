package normalize

import "strings"

// Okta maps a raw Okta System Log event to canonical mallcop events.
//
// eventType is raw["eventType"] (e.g. "user.session.start"). raw is the
// JSON-decoded Okta System Log event. Okta nests the client IP at
// client.ipAddress, geo at client.geographicalContext, the outcome reason at
// outcome.reason, and grant/role detail inside the target[] array of
// {type, displayName, alternateId, id} objects.
func Okta(eventType string, raw map[string]any) []Result {
	ip := digStr(raw, "client", "ipAddress")
	geo := oktaGeo(raw)
	outcomeReason := digStr(raw, "outcome", "reason")

	switch eventType {
	case "user.session.start":
		p := map[string]any{"action": "user.session.start"}
		set(p, "ip", ip)
		set(p, "source_ip", ip)
		set(p, "geo", geo)
		return []Result{{Type: "login", Payload: p}}

	case "user.session.end":
		return []Result{{Type: "login", Payload: map[string]any{"action": "user.session.end"}}}

	case "user.authentication.auth_via_mfa":
		// Outcome distinguishes success from failure.
		if strings.EqualFold(digStr(raw, "outcome", "result"), "SUCCESS") {
			p := map[string]any{"action": "login_success"}
			set(p, "ip", ip)
			set(p, "reason", "mfa_success")
			return []Result{{Type: "login_success", Payload: p}}
		}
		p := map[string]any{"action": "login_failure"}
		set(p, "ip", ip)
		set(p, "reason", outcomeReason)
		return []Result{{Type: "login_failure", Payload: p}}

	case "user.authentication.sso", "user.authentication.verify_push_response":
		p := map[string]any{"action": "login_failure"}
		set(p, "ip", ip)
		set(p, "reason", outcomeReason)
		return []Result{{Type: "login_failure", Payload: p}}

	case "user.account.privilege.grant":
		role := firstNonEmpty(oktaTarget(raw, "AppRole", "displayName"), oktaTarget(raw, "Role", "displayName"))
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"action": "role_assignment"}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", target)
		set(p, "principal_id", target)
		return []Result{{Type: "role_assignment", Payload: p}}

	case "group.user_membership.add":
		role := oktaTarget(raw, "UserGroup", "displayName")
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"action": "member_added"}
		set(p, "role", role)
		set(p, "target_user", target)
		set(p, "principal_id", target)
		return []Result{{Type: "member_added", Payload: p}}

	case "user.account.update_profile":
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"action": "permission_change"}
		set(p, "target_user", target)
		set(p, "principal_id", target)
		return []Result{{Type: "permission_change", Payload: p}}

	case "application.user_membership.add":
		role := oktaTarget(raw, "AppInstance", "displayName")
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"action": "collaborator_added"}
		set(p, "role", role)
		set(p, "target_user", target)
		set(p, "collaborator", target)
		return []Result{{Type: "collaborator_added", Payload: p}}

	case "policy.lifecycle.update":
		// MFA policy deactivation is a config-drift mfa_disabled; treat as such.
		policy := oktaTarget(raw, "Policy", "displayName")
		p := map[string]any{"config_key": "mfa_required"}
		set(p, "resource_name", policy)
		set(p, "policy_name", policy)
		p["old_value"] = "true"
		p["new_value"] = "false"
		set(p, "change_description", oktaDisplayMessage(raw))
		return []Result{{Type: "mfa_disabled", Payload: p}}

	case "user.mfa.factor.deactivate":
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"config_key": "mfa_factor"}
		set(p, "resource_name", target+" MFA factor")
		set(p, "target_user", target)
		p["old_value"] = "enrolled"
		p["new_value"] = "disabled"
		return []Result{{Type: "mfa_disabled", Payload: p}}

	case "user.mfa.factor.reset_all":
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"config_key": "mfa_factors"}
		set(p, "resource_name", target)
		set(p, "target_user", target)
		p["old_value"] = "enrolled"
		p["new_value"] = "all_reset"
		return []Result{{Type: "mfa_requirement_removed", Payload: p}}

	case "policy.lifecycle.create", "policy.lifecycle.delete":
		policy := oktaTarget(raw, "Policy", "displayName")
		p := map[string]any{"config_key": eventType}
		set(p, "resource_name", policy)
		set(p, "policy_name", policy)
		set(p, "change_description", oktaDisplayMessage(raw))
		return []Result{{Type: "setting_update", Payload: p}}

	case "system.agent.update":
		p := map[string]any{"config_key": "network_zone"}
		set(p, "resource_name", oktaTarget(raw, "", "displayName"))
		p["old_value"] = ""
		p["new_value"] = "zone changed"
		set(p, "change_description", oktaDisplayMessage(raw))
		return []Result{{Type: "config_change", Payload: p}}

	case "user.account.reset_password", "user.account.update_password":
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"action": "admin_action"}
		set(p, "target_user", target)
		return []Result{{Type: "admin_action", Payload: p}}

	case "user.lifecycle.create":
		p := map[string]any{"action": "user_provisioned"}
		set(p, "display_name", oktaTarget(raw, "User", "displayName"))
		set(p, "principal_id", oktaTarget(raw, "User", "alternateId"))
		return []Result{{Type: "user_provisioned", Payload: p}}

	case "user.lifecycle.delete":
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"action": "user_deactivated"}
		set(p, "target_user", target)
		return []Result{{Type: "admin_action", Payload: p}}

	case "application.lifecycle.create", "application.lifecycle.update":
		p := map[string]any{"config_key": "application"}
		set(p, "resource_name", oktaTarget(raw, "AppInstance", "displayName"))
		set(p, "change_description", oktaDisplayMessage(raw))
		return []Result{{Type: "setting_update", Payload: p}}

	case "system.api_token.create", "system.api_token.revoke":
		p := map[string]any{"action": "admin_action"}
		set(p, "target_user", oktaTarget(raw, "Token", "displayName"))
		return []Result{{Type: "admin_action", Payload: p}}

	case "user.session.impersonation.grant":
		target := oktaTarget(raw, "User", "alternateId")
		p := map[string]any{"action": "admin_action", "role": "impersonation", "permission": "impersonate"}
		set(p, "target_user", target)
		return []Result{{Type: "admin_action", Payload: p}}

	case "iam.resource.read":
		res := firstNonEmpty(oktaTarget(raw, "OAuthToken", "displayName"), oktaTarget(raw, "ServiceAccount", "displayName"))
		p := map[string]any{"action": "secret_access"}
		set(p, "target", res)
		set(p, "resource", res)
		set(p, "resource_id", oktaTarget(raw, "", "id"))
		return []Result{{Type: "secret_access", Payload: p}}

	case "application.provision.user":
		count := oktaTargetCount(raw)
		p := map[string]any{
			"action":            "bulk_export",
			"resource_count":    count,
			"bytes_transferred": int64(0),
		}
		set(p, "destination", oktaTarget(raw, "AppInstance", "displayName"))
		return []Result{{Type: "bulk_export", Payload: p}}

	case "user.account.report_suspicious_activity":
		p := map[string]any{"action": "login_failure"}
		set(p, "ip", ip)
		set(p, "reason", "suspicious_activity_reported")
		return []Result{{Type: "login_failure", Payload: p}}

	case "security.threat.detected":
		p := map[string]any{"action": "login_failure"}
		set(p, "ip", ip)
		set(p, "reason", outcomeReason)
		set(p, "geo", geo)
		return []Result{{Type: "login_failure", Payload: p}}

	case "policy.rule.add", "policy.rule.update", "policy.rule.delete":
		p := map[string]any{}
		set(p, "resource_name", oktaTarget(raw, "PolicyRule", "displayName"))
		set(p, "policy_name", oktaTarget(raw, "Policy", "displayName"))
		set(p, "change_description", oktaDisplayMessage(raw))
		return []Result{{Type: "firewall_rule_add", Payload: p}}
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": eventType}}}
}

// oktaTarget returns field f of the first target[] entry whose type == typ. An
// empty typ matches the first entry regardless of type.
func oktaTarget(raw map[string]any, typ, field string) string {
	arr, ok := raw["target"].([]any)
	if !ok {
		return ""
	}
	for _, e := range arr {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if typ == "" || mapStr(em, "type") == typ {
			return mapStr(em, field)
		}
	}
	return ""
}

func oktaTargetCount(raw map[string]any) int {
	arr, ok := raw["target"].([]any)
	if !ok {
		return 0
	}
	return len(arr)
}

func oktaGeo(raw map[string]any) string {
	geoCtx := dig(raw, "client", "geographicalContext")
	if geoCtx == nil {
		return ""
	}
	country := mapStr(geoCtx, "country")
	state := mapStr(geoCtx, "state")
	switch {
	case country != "" && state != "":
		return country + "/" + state
	case country != "":
		return country
	default:
		return state
	}
}

func oktaDisplayMessage(raw map[string]any) string {
	return mapStr(raw, "displayMessage")
}
