package normalize

import "strings"

// GCP maps a raw GCP Cloud Audit Log entry to canonical mallcop events.
//
// methodName is protoPayload.methodName (e.g. "SetIamPolicy",
// "storage.objects.get"). proto is the JSON-decoded protoPayload object. Several
// method names fan out to MULTIPLE canonical events (SetIamPolicy → both
// iam_policy_attach for config-drift AND role_assignment for priv-escalation when
// a binding grants an admin/owner/editor role).
func GCP(methodName string, proto map[string]any) []Result {
	resourceName := mapStr(proto, "resourceName")
	request := subMap(proto, "request")
	short := shortMethod(methodName)

	switch {
	case strings.HasSuffix(short, "SetIamPolicy"):
		results := []Result{}
		policy := subMap(request, "policy")
		bindings := bindingsOf(policy)
		p := map[string]any{"action": "SetIamPolicy"}
		set(p, "resource_name", resourceName)
		set(p, "policy_name", strings.Join(bindingRoles(bindings), ","))
		set(p, "change_description", "SetIamPolicy")
		set(p, "new_value", jsonString(bindings))
		results = append(results, Result{Type: "iam_policy_attach", Payload: p})
		// Secondary: a binding adding owner/editor/admin is a privilege escalation.
		if role, member, ok := privilegedBinding(bindings); ok {
			pe := map[string]any{"action": "role_assignment"}
			set(pe, "role", role)
			set(pe, "role_name", role)
			set(pe, "target_user", member)
			set(pe, "principal_id", member)
			results = append(results, Result{Type: "role_assignment", Payload: pe})
		}
		return results

	case strings.HasSuffix(short, "CreateServiceAccount"):
		resp := subMap(proto, "response")
		email := mapStr(resp, "email")
		p := map[string]any{"action": "user_created"}
		set(p, "display_name", firstNonEmpty(digStr(request, "serviceAccount", "displayName"), mapStr(request, "accountId"), email))
		set(p, "principal_id", email)
		set(p, "member", email)
		return []Result{{Type: "user_created", Payload: p}}

	case strings.HasSuffix(short, "CreateRole"), strings.HasSuffix(short, "UpdateRole"), strings.HasSuffix(short, "PatchRole"):
		p := map[string]any{"action": short}
		set(p, "resource_name", resourceName)
		set(p, "policy_name", digStr(request, "role", "name"))
		set(p, "change_description", short)
		set(p, "new_value", jsonString(subMap(request, "role")))
		return []Result{{Type: "iam_role_modify", Payload: p}}

	case strings.Contains(short, "assignRole"):
		role := mapStr(request, "role")
		member := mapStr(request, "member")
		p := map[string]any{"action": "role_assignment"}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", member)
		set(p, "principal_id", member)
		return []Result{{Type: "role_assignment", Payload: p}}

	case strings.Contains(short, "addGroupMember"):
		member := firstNonEmpty(digStr(request, "member", "email"), mapStr(request, "memberEmail"), mapStr(request, "email"))
		p := map[string]any{"action": "member_added"}
		set(p, "role", "member")
		set(p, "target_user", member)
		set(p, "principal_id", member)
		set(p, "display_name", member)
		set(p, "member", member)
		set(p, "collaborator", member)
		return []Result{{Type: "member_added", Payload: p}}

	case strings.Contains(short, "createUser"):
		email := firstNonEmpty(digStr(request, "user", "primaryEmail"), mapStr(request, "primaryEmail"))
		p := map[string]any{"action": "member_added"}
		set(p, "display_name", email)
		set(p, "principal_id", email)
		set(p, "member", email)
		return []Result{{Type: "member_added", Payload: p}}

	case strings.Contains(short, "DeleteLog"), strings.Contains(short, "DeleteSink"), strings.Contains(short, "DeleteBucket"):
		p := map[string]any{}
		set(p, "resource_name", resourceName)
		set(p, "policy_name", resourceName)
		set(p, "change_description", "log sink/bucket deleted")
		return []Result{{Type: "audit_trail_delete", Payload: p}}

	case strings.Contains(short, "UpdateSink"), strings.Contains(short, "UpdateBucket"):
		p := map[string]any{}
		set(p, "resource_name", resourceName)
		set(p, "change_description", "audit log sink modified")
		set(p, "new_value", jsonString(request))
		return []Result{{Type: "audit_log_disabled", Payload: p}}

	case strings.Contains(short, "turnOffTwoStepVerification"):
		p := map[string]any{}
		set(p, "resource_name", resourceName)
		set(p, "target_user", mapStr(proto, "resourceName"))
		set(p, "change_description", "MFA disabled")
		return []Result{{Type: "mfa_disabled", Payload: p}}

	case strings.HasPrefix(methodName, "compute.firewalls."):
		p := map[string]any{}
		set(p, "resource_name", resourceName)
		set(p, "change_description", methodName)
		set(p, "new_value", jsonString(request))
		return []Result{{Type: "firewall_rule_add", Payload: p}}

	case strings.HasPrefix(methodName, "compute.networks."), strings.HasPrefix(methodName, "compute.subnetworks."):
		p := map[string]any{}
		set(p, "resource_name", resourceName)
		set(p, "change_description", methodName)
		set(p, "new_value", jsonString(request))
		return []Result{{Type: "security_group_modify", Payload: p}}

	case strings.Contains(short, "addDomainAlias"), strings.Contains(short, "updateDomainAlias"):
		domain := firstNonEmpty(mapStr(request, "domainAliasName"), mapStr(request, "domainName"))
		p := map[string]any{"action": "federation_settings_update"}
		set(p, "domain", domain)
		set(p, "domain_name", domain)
		return []Result{{Type: "federation_settings_update", Payload: p}}

	case methodName == "storage.objects.get":
		p := map[string]any{
			"action":            "object_get",
			"files_accessed":    1,
			"resource_count":    1,
			"bytes_transferred": int64(0),
			"destination":       "gcp-storage",
			"resources":         []string{resourceName},
		}
		if sz, ok := gcpInt64(dig(proto, "requestMetadata"), "requestSize"); ok {
			p["bytes_transferred"] = sz
		}
		return []Result{{Type: "object_get", Payload: p}}

	case methodName == "storage.objects.list", methodName == "bigquery.tabledata.list":
		p := map[string]any{
			"action":            "list_objects",
			"files_accessed":    0,
			"resource_count":    1,
			"bytes_transferred": int64(0),
			"destination":       "gcp-storage",
			"resources":         []string{resourceName},
		}
		return []Result{{Type: "list_objects", Payload: p}}

	case strings.HasPrefix(methodName, "bigquery.jobs."):
		p := map[string]any{
			"action":            "data_export",
			"files_accessed":    1,
			"resource_count":    1,
			"bytes_transferred": int64(0),
			"destination":       "bigquery",
			"resources":         []string{resourceName},
		}
		return []Result{{Type: "data_export", Payload: p}}

	case strings.Contains(methodName, "instances.export"), strings.Contains(methodName, "sqladmin.instances.export"):
		p := map[string]any{
			"action":            "bulk_export",
			"files_accessed":    1,
			"resource_count":    1,
			"bytes_transferred": int64(0),
			"destination":       firstNonEmpty(digStr(request, "exportContext", "uri"), "gcs"),
			"resources":         []string{resourceName},
		}
		return []Result{{Type: "bulk_export", Payload: p}}

	case strings.Contains(short, "AccessSecretVersion"), strings.Contains(methodName, "secrets.access"):
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceName)
		set(p, "resource", resourceName)
		set(p, "resource_id", resourceName)
		return []Result{{Type: "secret_access", Payload: p}}

	case strings.Contains(methodName, "cloudsql.instances.login"), strings.Contains(short, "SqlInstancesService.Get"):
		p := map[string]any{"action": "database_access"}
		set(p, "target", resourceName)
		set(p, "resource", resourceName)
		set(p, "resource_id", resourceName)
		return []Result{{Type: "database_access", Payload: p}}

	case strings.Contains(short, "loginFailure"), strings.Contains(short, "login_verification"):
		p := map[string]any{"action": "login_failure"}
		set(p, "ip", digStr(proto, "requestMetadata", "callerIp"))
		set(p, "reason", digStr(proto, "status", "message"))
		return []Result{{Type: "login_failure", Payload: p}}

	case strings.HasSuffix(short, "login"), strings.Contains(short, "AdminService.login"):
		ip := digStr(proto, "requestMetadata", "callerIp")
		p := map[string]any{"action": "login"}
		set(p, "ip", ip)
		set(p, "source_ip", ip)
		return []Result{{Type: "login", Payload: p}}

	case strings.HasPrefix(methodName, "container.googleapis.com"), strings.Contains(methodName, "clusters.create"):
		p := map[string]any{"action": "resource_access"}
		set(p, "target", resourceName)
		set(p, "resource", resourceName)
		set(p, "resource_id", resourceName)
		return []Result{{Type: "resource_access", Payload: p}}

	case strings.Contains(methodName, "setOrgPolicy"), strings.Contains(methodName, "updateOrgPolicy"):
		p := map[string]any{"action": "config_change"}
		set(p, "resource_name", resourceName)
		set(p, "config_key", "orgPolicy")
		set(p, "new_value", jsonString(subMap(request, "policy")))
		set(p, "change_description", "org policy updated")
		return []Result{{Type: "config_change", Payload: p}}

	case methodName == "storage.buckets.setIamPolicy", methodName == "storage.buckets.update":
		p := map[string]any{}
		set(p, "resource_name", resourceName)
		set(p, "policy_name", resourceName)
		set(p, "change_description", "bucket IAM policy changed")
		set(p, "new_value", jsonString(request))
		return []Result{{Type: "iam_policy_create", Payload: p}}

	case strings.HasPrefix(methodName, "artifactregistry."), strings.Contains(methodName, "containerregistry"):
		p := map[string]any{"action": "registry_access"}
		set(p, "target", resourceName)
		set(p, "resource", resourceName)
		set(p, "resource_id", resourceName)
		return []Result{{Type: "registry_access", Payload: p}}
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": methodName}}}
}

// shortMethod returns the final dotted segment of a GCP methodName
// (e.g. "google.iam.admin.v1.SetIamPolicy" → "SetIamPolicy").
func shortMethod(m string) string {
	if m == "" {
		return ""
	}
	parts := strings.Split(m, ".")
	return parts[len(parts)-1]
}

func bindingsOf(policy map[string]any) []any {
	if policy == nil {
		return nil
	}
	if b, ok := policy["bindings"].([]any); ok {
		return b
	}
	return nil
}

func bindingRoles(bindings []any) []string {
	var roles []string
	for _, b := range bindings {
		if bm, ok := b.(map[string]any); ok {
			if r := mapStr(bm, "role"); r != "" {
				roles = append(roles, r)
			}
		}
	}
	return roles
}

// privilegedBinding returns the first binding whose role grants admin/owner/editor
// privilege, with its first member (user: prefix stripped).
func privilegedBinding(bindings []any) (role, member string, ok bool) {
	for _, b := range bindings {
		bm, isMap := b.(map[string]any)
		if !isMap {
			continue
		}
		r := strings.ToLower(mapStr(bm, "role"))
		if strings.Contains(r, "owner") || strings.Contains(r, "editor") || strings.Contains(r, "admin") {
			members, _ := bm["members"].([]any)
			m := ""
			if len(members) > 0 {
				m, _ = members[0].(string)
			}
			m = strings.TrimPrefix(m, "user:")
			m = strings.TrimPrefix(m, "serviceAccount:")
			return mapStr(bm, "role"), m, true
		}
	}
	return "", "", false
}

func gcpInt64(m map[string]any, k string) (int64, bool) {
	if m == nil {
		return 0, false
	}
	if v, ok := m[k].(float64); ok {
		return int64(v), true
	}
	return 0, false
}
