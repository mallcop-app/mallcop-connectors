package normalize

import "strings"

// M365 maps a raw Office 365 Management Activity record to canonical mallcop
// events.
//
// operation is record["Operation"] and workload is record["Workload"]. record is
// the JSON-decoded raw O365 record. Several O365 operations carry detail inside a
// ModifiedProperties[] array of {Name, NewValue, OldValue}; modProp() walks it.
func M365(workload, operation string, record map[string]any) []Result {
	resultStatus := mapStr(record, "ResultStatus")
	clientIP := firstNonEmpty(mapStr(record, "ClientIP"), mapStr(record, "ClientIPAddress"))
	objectID := mapStr(record, "ObjectId")

	switch operation {
	case "UserLoggedIn":
		p := map[string]any{"action": "login"}
		set(p, "ip", clientIP)
		set(p, "source_ip", clientIP)
		set(p, "geo", firstNonEmpty(digStr(record, "DeviceProperties", "OS"), mapStr(record, "Location")))
		return []Result{{Type: "login", Payload: p}}

	case "UserLoginFailed":
		p := map[string]any{"action": "login_failure"}
		set(p, "ip", clientIP)
		set(p, "reason", firstNonEmpty(mapStr(record, "LogonError"), mapStr(record, "ResultReason")))
		return []Result{{Type: "login_failure", Payload: p}}

	case "Add member to role.":
		role := modProp(record, "Role.DisplayName")
		target := firstNonEmpty(modProp(record, "Role.Member.UPN"), objectID)
		p := map[string]any{"action": "role_assignment"}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", target)
		set(p, "principal_id", target)
		return []Result{{Type: "role_assignment", Payload: p}}

	case "Add service principal.":
		p := map[string]any{"action": "service_principal_created"}
		set(p, "display_name", firstNonEmpty(modProp(record, "ServicePrincipal.DisplayName"), objectID))
		set(p, "principal_id", objectID)
		return []Result{{Type: "service_principal_created", Payload: p}}

	case "Add user.":
		p := map[string]any{"action": "user_created"}
		set(p, "display_name", firstNonEmpty(modProp(record, "DisplayName"), objectID))
		set(p, "principal_id", objectID)
		return []Result{{Type: "user_created", Payload: p}}

	case "Set domain authentication.", "Update domain.":
		domain := firstNonEmpty(modProp(record, "DomainName"), objectID)
		p := map[string]any{"action": "federation_settings_update"}
		set(p, "domain", domain)
		set(p, "domain_name", domain)
		return []Result{{Type: "federation_settings_update", Payload: p}}

	case "Set directory settings.":
		p := map[string]any{"action": "directory_settings_update"}
		set(p, "domain", firstNonEmpty(modProp(record, "AllowedToAddExternalUsers"), objectID))
		return []Result{{Type: "directory_settings_update", Payload: p}}

	case "Set federation settings on domain.":
		domain := firstNonEmpty(modProp(record, "DomainName"), objectID)
		p := map[string]any{"action": "trust_added"}
		set(p, "domain", domain)
		set(p, "domain_name", domain)
		return []Result{{Type: "trust_added", Payload: p}}

	case "Disable Strong Authentication.":
		target := firstNonEmpty(modProp(record, "UserPrincipalName"), objectID)
		p := map[string]any{}
		set(p, "resource_name", objectID)
		set(p, "target_user", target)
		set(p, "change_description", operation)
		p["old_value"] = "MFA_ENABLED"
		p["new_value"] = "MFA_DISABLED"
		return []Result{{Type: "mfa_disabled", Payload: p}}

	case "Update policy.", "Add policy.":
		p := map[string]any{}
		set(p, "resource_name", objectID)
		set(p, "policy_name", modProp(record, "DisplayName"))
		set(p, "change_description", operation)
		p["old_value"] = ""
		p["new_value"] = "policy changed"
		return []Result{{Type: "config_change", Payload: p}}

	case "MailItemsAccessed":
		count := intField(record, "OperationCount")
		p := map[string]any{
			"action":            "bulk_read",
			"bytes_transferred": int64(0),
			"files_accessed":    count,
			"resource_count":    count,
		}
		set(p, "destination", firstNonEmpty(clientIP, mapStr(record, "SessionId")))
		return []Result{{Type: "bulk_read", Payload: p}}

	case "FileDownloaded":
		p := map[string]any{
			"action":            "file_download",
			"bytes_transferred": int64Field(record, "FileSizeBytes"),
			"files_accessed":    1,
			"resource_count":    1,
		}
		set(p, "destination", clientIP)
		p["resources"] = []string{objectID}
		return []Result{{Type: "file_download", Payload: p}}

	case "FileSyncDownloadedFull":
		p := map[string]any{
			"action":            "bulk_export",
			"bytes_transferred": int64Field(record, "FileSizeBytes"),
			"files_accessed":    1,
			"resource_count":    1,
		}
		set(p, "destination", clientIP)
		return []Result{{Type: "bulk_export", Payload: p}}

	case "SiteCollectionAdminAdded", "PermissionLevelAdded":
		perm := firstNonEmpty(digStr(record, "EventData", "SitePermissions"), "SiteCollectionAdmin")
		target := firstNonEmpty(objectID, mapStr(record, "TargetUserOrGroupName"))
		p := map[string]any{"action": "permission_change"}
		set(p, "permission", perm)
		set(p, "permission_level", perm)
		set(p, "target_user", target)
		set(p, "principal_id", target)
		return []Result{{Type: "permission_change", Payload: p}}

	case "AnonymousLinkCreated", "SharingSet":
		collaborator := firstNonEmpty(mapStr(record, "TargetUserOrGroupName"), "anonymous")
		p := map[string]any{"action": "permission_change"}
		set(p, "permission", "AnonymousAccess")
		set(p, "target_user", objectID)
		set(p, "collaborator", collaborator)
		set(p, "member", collaborator)
		return []Result{{Type: "permission_change", Payload: p}}

	case "Set-Mailbox":
		p := map[string]any{}
		set(p, "resource_name", objectID)
		set(p, "change_description", operation)
		p["old_value"] = "AuditEnabled=True"
		p["new_value"] = "AuditEnabled=False"
		return []Result{{Type: "audit_log_disabled", Payload: p}}

	case "Add app role assignment to service principal.":
		role := modProp(record, "AppRole.Value")
		p := map[string]any{"action": "role_assignment"}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", modProp(record, "ServicePrincipal.DisplayName"))
		set(p, "principal_id", objectID)
		return []Result{{Type: "role_assignment", Payload: p}}

	case "Consent to application.":
		app := firstNonEmpty(modProp(record, "ConsentContext.DisplayName"), objectID)
		p := map[string]any{"action": "org.add_outside_collaborator"}
		set(p, "collaborator", app)
		set(p, "member", app)
		return []Result{{Type: "org.add_outside_collaborator", Payload: p}}

	case "MailboxLogin":
		p := map[string]any{"action": "resource_access"}
		set(p, "target", objectID)
		set(p, "resource", objectID)
		set(p, "resource_id", objectID)
		return []Result{{Type: "resource_access", Payload: p}}

	case "Send":
		recipients := stringSlice(record["Recipients"])
		p := map[string]any{
			"action":            "bulk_export",
			"bytes_transferred": int64(0),
			"files_accessed":    0,
			"resource_count":    len(recipients),
		}
		if len(recipients) > 0 {
			set(p, "destination", recipients[0])
		}
		return []Result{{Type: "bulk_export", Payload: p}}
	}

	// Failed-status logins arrive under varied operation strings — treat any
	// AzureActiveDirectory record with ResultStatus=Failed as a login_failure so
	// auth-failure-burst still sees it.
	if strings.EqualFold(resultStatus, "Failed") && strings.Contains(strings.ToLower(workload), "azureactivedirectory") {
		p := map[string]any{"action": "login_failure"}
		set(p, "ip", clientIP)
		set(p, "reason", firstNonEmpty(mapStr(record, "LogonError"), operation))
		return []Result{{Type: "login_failure", Payload: p}}
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": operation, "operation": workload + "." + operation}}}
}

// modProp walks record["ModifiedProperties"] for the entry whose Name == name and
// returns its NewValue as a string. O365 stores these as [{Name, NewValue, OldValue}].
func modProp(record map[string]any, name string) string {
	arr, ok := record["ModifiedProperties"].([]any)
	if !ok {
		return ""
	}
	for _, e := range arr {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if mapStr(em, "Name") == name {
			nv := em["NewValue"]
			if s, ok := nv.(string); ok {
				return s
			}
			// O365 sometimes wraps values in a JSON-array string; pass through.
			if s := jsonString(nv); s != "" && s != "null" {
				return strings.Trim(s, `"`)
			}
		}
	}
	return ""
}

func intField(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case string:
		// O365 emits OperationCount as a string sometimes.
		var n int
		for _, c := range v {
			if c < '0' || c > '9' {
				return n
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 0
}

func int64Field(m map[string]any, k string) int64 {
	if v, ok := m[k].(float64); ok {
		return int64(v)
	}
	return 0
}

func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
