package normalize

import "strings"

// Azure maps a raw Azure Activity Log entry to canonical mallcop events.
//
// opName is operationName.value (e.g. "Microsoft.Authorization/roleAssignments/write").
// entry is the JSON-decoded raw Activity Log entry. Azure puts the actor in
// "caller", the resource in "resourceId", and detail under "properties".
func Azure(opName string, entry map[string]any) []Result {
	props := subMap(entry, "properties")
	resourceID := mapStr(entry, "resourceId")
	caller := mapStr(entry, "caller")

	switch {
	case opName == "Microsoft.Authorization/roleAssignments/write":
		role := firstNonEmpty(mapStr(props, "roleDefinitionName"), mapStr(props, "roleDefinitionId"))
		principal := mapStr(props, "principalId")
		p := map[string]any{"action": "role_assignment"}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", principal)
		set(p, "principal_id", principal)
		set(p, "resource_name", resourceID)
		return []Result{{Type: "role_assignment", Payload: p}}

	case opName == "Microsoft.Authorization/roleAssignments/delete":
		role := mapStr(props, "roleDefinitionName")
		principal := mapStr(props, "principalId")
		p := map[string]any{"action": "delete"}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", principal)
		set(p, "principal_id", principal)
		set(p, "resource_name", resourceID)
		return []Result{{Type: "iam_change", Payload: p}}

	case opName == "Microsoft.Authorization/roleDefinitions/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "policy_name", mapStr(props, "roleName"))
		set(p, "change_description", "custom role definition written")
		return []Result{{Type: "iam_policy_create", Payload: p}}

	case opName == "Microsoft.Authorization/policyAssignments/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "policy_name", firstNonEmpty(mapStr(props, "displayName"), mapStr(props, "policyDefinitionId")))
		set(p, "change_description", "policy assignment created")
		return []Result{{Type: "iam_policy_attach", Payload: p}}

	case opName == "Microsoft.ManagedIdentity/userAssignedIdentities/assign":
		principal := mapStr(props, "principalId")
		p := map[string]any{"action": "iam_change", "role": "ManagedIdentity"}
		set(p, "target_user", principal)
		set(p, "principal_id", principal)
		set(p, "resource_name", resourceID)
		return []Result{{Type: "iam_change", Payload: p}}

	case opName == "Microsoft.ManagedIdentity/userAssignedIdentities/write":
		p := map[string]any{"action": "service_principal_created"}
		set(p, "display_name", firstNonEmpty(mapStr(props, "displayName"), lastSegment(resourceID)))
		set(p, "principal_id", mapStr(props, "principalId"))
		return []Result{{Type: "service_principal_created", Payload: p}}

	case opName == "Microsoft.Directory/users/add" || opName == "Microsoft.AAD/users/write":
		p := map[string]any{"action": "user_created"}
		set(p, "display_name", firstNonEmpty(mapStr(props, "displayName"), mapStr(props, "objectId")))
		set(p, "principal_id", mapStr(props, "objectId"))
		return []Result{{Type: "user_created", Payload: p}}

	case opName == "Microsoft.Directory/groupMembers/add" || opName == "Microsoft.AAD/groups/members/write":
		member := mapStr(props, "userPrincipalName")
		p := map[string]any{"action": "org.add_member"}
		set(p, "member", member)
		set(p, "role", "Member")
		return []Result{{Type: "org.add_member", Payload: p}}

	case strings.Contains(opName, "domains/federation") || opName == "Microsoft.AAD/federationSettings/write":
		domain := firstNonEmpty(mapStr(props, "domainName"), lastSegment(resourceID))
		p := map[string]any{"action": "federation_settings_update"}
		set(p, "domain", domain)
		set(p, "domain_name", domain)
		return []Result{{Type: "federation_settings_update", Payload: p}}

	case opName == "Microsoft.Network/networkSecurityGroups/securityRules/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "NSG security rule modified")
		p["new_value"] = "rule changed"
		return []Result{{Type: "security_group_modify", Payload: p}}

	case opName == "Microsoft.Network/azureFirewalls/write" ||
		strings.Contains(opName, "firewallPolicies/ruleCollectionGroups/write"):
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "firewall rule added")
		p["new_value"] = "rule added"
		return []Result{{Type: "firewall_rule_add", Payload: p}}

	case opName == "microsoft.insights/diagnosticSettings/write":
		p := map[string]any{"config_key": "diagnosticSettings"}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "audit log diagnostic setting modified")
		return []Result{{Type: "audit_log_disabled", Payload: p}}

	case opName == "microsoft.insights/diagnosticSettings/delete":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "diagnostic setting deleted")
		return []Result{{Type: "audit_trail_delete", Payload: p}}

	case opName == "Microsoft.Security/securityContacts/write" || opName == "Microsoft.Security/pricings/write":
		p := map[string]any{"config_key": lastSegment(resourceID)}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Defender config changed")
		return []Result{{Type: "config_change", Payload: p}}

	case opName == "Microsoft.KeyVault/vaults/secrets/read" ||
		opName == "Microsoft.KeyVault/vaults/secrets/getSecret/action":
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceID)
		set(p, "resource", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "secret_access", Payload: p}}

	case opName == "Microsoft.KeyVault/vaults/write":
		p := map[string]any{"config_key": "keyVaultAccessPolicies"}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Key Vault policy modified")
		return []Result{{Type: "config_change", Payload: p}}

	case opName == "Microsoft.Storage/storageAccounts/listKeys/action":
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "secret_access", Payload: p}}

	case strings.HasPrefix(opName, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"):
		p := map[string]any{"action": "bulk_read"}
		set(p, "target", resourceID)
		set(p, "resource", resourceID)
		opCount, _ := azFloat(props, "operationCount")
		p["files_accessed"] = int(opCount)
		p["resource_count"] = int(opCount)
		p["bytes_transferred"] = int64(0)
		set(p, "destination", firstNonEmpty(caller, mapStr(props, "clientIP")))
		return []Result{{Type: "bulk_read", Payload: p}}

	case opName == "Microsoft.Compute/virtualMachines/read":
		p := map[string]any{"action": "vm_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "vm_access", Payload: p}}

	case opName == "Microsoft.ContainerRegistry/registries/pull" ||
		opName == "Microsoft.ContainerRegistry/registries/repositories/content/read":
		p := map[string]any{"action": "registry_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "registry_access", Payload: p}}

	case opName == "Microsoft.Sql/servers/databases/export/action":
		p := map[string]any{"resource_count": 1}
		set(p, "destination", firstNonEmpty(mapStr(props, "storageUri"), resourceID))
		p["bytes_transferred"] = int64(0)
		return []Result{{Type: "data_export", Payload: p}}

	case opName == "Microsoft.Sql/servers/databases/read":
		p := map[string]any{"action": "database_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "database_access", Payload: p}}

	case strings.HasPrefix(opName, "Microsoft.AAD/conditionalAccessPolicies/"):
		p := map[string]any{"config_key": "conditionalAccessPolicy"}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Conditional Access / MFA policy modified or deleted")
		return []Result{{Type: "mfa_requirement_removed", Payload: p}}

	case opName == "Microsoft.Subscription/subscriptions/write" ||
		opName == "Microsoft.Management/managementGroups/subscriptions/write":
		p := map[string]any{"action": "admin_action", "role": "SubscriptionOwner"}
		set(p, "target_user", caller)
		return []Result{{Type: "admin_action", Payload: p}}
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": opName}}}
}

// lastSegment returns the final path segment of a slash-delimited string.
func lastSegment(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}

func azFloat(m map[string]any, k string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	if v, ok := m[k].(float64); ok {
		return v, true
	}
	return 0, false
}
