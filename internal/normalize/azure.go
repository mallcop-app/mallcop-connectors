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

	// --- relay-infra control plane (Microsoft.App / Container Apps) --------
	//
	// Confirmed live (az rest against the Activity Log API for
	// nostr-relay-prod, 2026-07-20): Azure represents a custom-hostname bind
	// as an ORDINARY containerApps/write PATCH (the customDomains change
	// rides in the write body) — there is no separate "hostname op" to match.
	// A captured real event showed exactly this: a containerApps/write whose
	// properties.statusCode was "BadRequest" with statusMessage.error.code
	// "InvalidCustomHostNameValidation" (missing TXT record for
	// asuid.relay.dontguess.ai). So one case covers both plain config changes
	// and hostname-bind attempts/failures.
	case opName == "Microsoft.App/containerApps/write" || opName == "Microsoft.App/managedEnvironments/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Container Apps resource written: "+opName)
		return []Result{{Type: "config_change", Payload: p}}

	case opName == "Microsoft.App/containerApps/listSecrets/action":
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "secret_access", Payload: p}}

	// --- relay-infra data plane (Microsoft.DocumentDB / Cosmos DB) ----------
	case opName == "Microsoft.DocumentDB/databaseAccounts/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Cosmos DB account configuration changed")
		return []Result{{Type: "config_change", Payload: p}}

	// sqlRoleAssignments/write grants a Cosmos DB SQL RBAC role to a
	// principal — the Cosmos-native analog of Microsoft.Authorization/
	// roleAssignments/write. It fans out exactly like the GCP SetIamPolicy
	// mapping: an iam_policy_attach for config-drift (a policy object was
	// attached) AND a role_assignment for priv-escalation (a principal's
	// effective access widened) — unconditionally, since Cosmos SQL role
	// assignments have no "unprivileged" tier the way GCP bindings do.
	case opName == "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write":
		principal := mapStr(props, "principalId")
		role := firstNonEmpty(mapStr(props, "roleDefinitionName"), mapStr(props, "roleDefinitionId"))
		cd := map[string]any{"action": "role_assignment"}
		set(cd, "resource_name", resourceID)
		set(cd, "policy_name", role)
		set(cd, "change_description", "Cosmos DB SQL role assignment written")
		pe := map[string]any{"action": "role_assignment"}
		set(pe, "role", role)
		set(pe, "role_name", role)
		set(pe, "target_user", principal)
		set(pe, "principal_id", principal)
		set(pe, "resource_name", resourceID)
		return []Result{
			{Type: "iam_policy_attach", Payload: cd},
			{Type: "role_assignment", Payload: pe},
		}

	case opName == "Microsoft.DocumentDB/databaseAccounts/listKeys/action" ||
		opName == "Microsoft.DocumentDB/databaseAccounts/readonlykeys/action":
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "secret_access", Payload: p}}

	// --- relay-infra supply chain (Microsoft.ContainerRegistry) -------------
	//
	// A registry push is a directly-authored artifact landing in the supply
	// chain — the closest fit in dependency-tamper's fixed vocabulary is
	// "dependency_add" with Direct: true (not a transitive lock-file change),
	// which also lets dependency-tamper's Rule 4 (direct-add check) evaluate.
	case opName == "Microsoft.ContainerRegistry/registries/push/write":
		repo := firstNonEmpty(mapStr(props, "repository"), lastSegment(resourceID))
		p := map[string]any{"action": "registry_push"}
		set(p, "package", repo)
		set(p, "ecosystem", "docker")
		set(p, "new_version", mapStr(props, "tag"))
		set(p, "registry", lastSegment(resourceID))
		p["direct"] = true
		return []Result{{Type: "dependency_add", Payload: p}}

	// --- relay-infra domain surface (Microsoft.Network/dnszones) ------------
	//
	// Record-set write/delete on a DNS zone is the domain-takeover surface for
	// relay.moot.pub (moot-rg) / relay.3dl.network (rg-dns): an attacker who
	// can rewrite an A/CNAME/TXT record can redirect or hijack the relay
	// hostname. Matched case-insensitively: a live capture (az monitor
	// activity-log list against moot-rg / rg-dns, 2026-07-20) showed the SAME
	// logical operation emitted with inconsistent casing across events
	// ("Microsoft.Network/dnsZones/A/write" vs "Microsoft.Network/dnszones/write"
	// for a zone-level op in the same subscription) — a case-sensitive switch
	// would silently drop half of these in production. Deliberately scoped to
	// RECORD-set ops only (not zone-level create/delete, dnssecConfigs, or
	// diagnosticSettings, which also end in "/write" under the same prefix).
	case isAzureDNSRecordChange(opName):
		p := map[string]any{"config_key": "dnsRecordSet"}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "DNS record set change: "+opName)
		return []Result{{Type: "config_change", Payload: p}}
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": opName}}}
}

// azureDNSRecordTypes are the DNS record-set resource-type segments Azure
// emits under Microsoft.Network/dnszones/<TYPE>/write|delete (verified against
// the live provider operation list: az provider operation show --namespace
// Microsoft.Network, plus a live Activity Log capture on moot-rg / rg-dns).
var azureDNSRecordTypes = []string{"a", "aaaa", "cname", "mx", "txt", "ns", "ptr", "srv", "caa", "ds", "soa", "tlsa"}

// isAzureDNSRecordChange reports whether opName is a per-record write or
// delete under Microsoft.Network/dnszones/<TYPE>/ — deliberately excluding the
// zone-level write/delete (creating/deleting the zone resource itself, which
// has no record-type segment) and any other dnszones sub-path
// (dnssecConfigs/*, providers/Microsoft.Insights/diagnosticSettings/*) that
// also happens to end in "/write" or "/delete". Case-insensitive: Azure's own
// Activity Log casing for this provider is not consistent (see the case
// comment above).
func isAzureDNSRecordChange(opName string) bool {
	lower := strings.ToLower(opName)
	for _, rt := range azureDNSRecordTypes {
		if lower == "microsoft.network/dnszones/"+rt+"/write" || lower == "microsoft.network/dnszones/"+rt+"/delete" {
			return true
		}
	}
	return false
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
