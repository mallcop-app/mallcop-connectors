package normalize

import (
	"encoding/json"
	"strings"
)

// AWS maps a raw CloudTrail event to canonical mallcop events.
//
// rawEvent is the JSON-decoded aws-sdk-go-v2 types.Event (the connector marshals
// types.Event then we decode it here, or the caller passes a map directly). The
// security-relevant fields live inside the CloudTrailEvent string field, which is
// itself a JSON document carrying sourceIPAddress, requestParameters,
// responseElements, errorMessage, awsRegion, recipientAccountId, etc. We unmarshal
// that inner document to extract detector fields.
//
// eventName is types.Event.EventName (already the raw CloudTrail eventName). We
// pass it explicitly because the connector reads it from the typed struct.
func AWS(eventName string, rawEvent map[string]any) []Result {
	// The inner CloudTrail document carries the real detail. It arrives either as
	// a JSON string under "CloudTrailEvent" (SDK shape) or already-decoded.
	inner := awsInner(rawEvent)

	sourceIP := mapStr(inner, "sourceIPAddress")
	region := mapStr(inner, "awsRegion")
	reqParams := subMap(inner, "requestParameters")
	respElems := subMap(inner, "responseElements")
	errMsg := mapStr(inner, "errorMessage")
	recipientAcct := mapStr(inner, "recipientAccountId")

	switch eventName {
	case "ConsoleLogin":
		typ := "login"
		consoleLogin := digStr(respElems, "ConsoleLogin")
		if strings.EqualFold(consoleLogin, "Failure") {
			typ = "login_failure"
		} else if strings.EqualFold(consoleLogin, "Success") {
			typ = "login_success"
		}
		p := map[string]any{"action": "ConsoleLogin"}
		set(p, "ip", sourceIP)
		set(p, "source_ip", sourceIP)
		if typ == "login" {
			set(p, "geo", region)
			set(p, "region", region)
		} else {
			reason := errMsg
			if reason == "" {
				reason = digStr(subMap(inner, "additionalEventData"), "MFAUsed")
			}
			set(p, "reason", reason)
		}
		return []Result{{Type: typ, Payload: p}}

	case "AddUserToGroup", "AddRoleToInstanceProfile", "AttachRolePolicy":
		role := mapStr(reqParams, "groupName")
		if role == "" {
			role = mapStr(reqParams, "roleName")
		}
		target := mapStr(reqParams, "userName")
		p := map[string]any{"action": eventName}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", target)
		set(p, "principal_id", target)
		return []Result{{Type: "role_assignment", Payload: p}}

	case "AttachUserPolicy", "AttachGroupPolicy", "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy":
		target := firstNonEmpty(mapStr(reqParams, "userName"), mapStr(reqParams, "groupName"), mapStr(reqParams, "roleName"))
		policyName := firstNonEmpty(mapStr(reqParams, "policyName"), mapStr(reqParams, "policyArn"))
		p := map[string]any{"action": eventName}
		set(p, "resource_name", mapStr(reqParams, "policyArn"))
		set(p, "policy_name", policyName)
		set(p, "target_user", target)
		set(p, "change_description", "policy attached")
		return []Result{{Type: "iam_policy_attach", Payload: p}}

	case "CreatePolicy", "CreatePolicyVersion":
		p := map[string]any{"action": eventName}
		set(p, "resource_name", digStr(subMap(respElems, "policy"), "arn"))
		set(p, "policy_name", mapStr(reqParams, "policyName"))
		set(p, "change_description", "IAM policy created")
		return []Result{{Type: "iam_policy_create", Payload: p}}

	case "UpdateRole", "PutRolePermissionsBoundary", "CreateRole":
		p := map[string]any{"action": eventName}
		set(p, "resource_name", mapStr(reqParams, "roleName"))
		set(p, "target_user", mapStr(reqParams, "roleName"))
		set(p, "change_description", "IAM role modified")
		return []Result{{Type: "iam_role_modify", Payload: p}}

	case "CreateAccessKey":
		target := mapStr(reqParams, "userName")
		p := map[string]any{"action": "CreateAccessKey", "role": "access-key-creator"}
		set(p, "target_user", target)
		set(p, "principal_id", target)
		return []Result{{Type: "admin_action", Payload: p}}

	case "DeleteTrail", "StopLogging":
		p := map[string]any{"action": eventName}
		set(p, "resource_name", mapStr(reqParams, "name"))
		set(p, "change_description", "CloudTrail logging disabled or trail deleted")
		return []Result{{Type: "cloudtrail_stop", Payload: p}}

	case "DeleteBucket", "PutBucketLogging":
		p := map[string]any{"action": eventName}
		set(p, "resource_name", mapStr(reqParams, "bucketName"))
		set(p, "change_description", "log storage bucket deleted or logging disabled")
		return []Result{{Type: "log_bucket_delete", Payload: p}}

	case "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
		"RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
		"CreateSecurityGroup", "DeleteSecurityGroup", "ModifyNetworkInterfaceAttribute":
		group := firstNonEmpty(mapStr(reqParams, "groupId"), mapStr(reqParams, "groupName"))
		p := map[string]any{"action": eventName}
		set(p, "resource_name", group)
		set(p, "change_description", eventName+" on "+group)
		p["old_value"] = ""
		p["new_value"] = "rules changed"
		return []Result{{Type: "security_group_modify", Payload: p}}

	case "DeactivateMFADevice", "DeleteVirtualMFADevice":
		target := mapStr(reqParams, "userName")
		p := map[string]any{"action": eventName}
		set(p, "target_user", target)
		set(p, "resource_name", firstNonEmpty(mapStr(reqParams, "serialNumber"), target))
		set(p, "change_description", "MFA device deactivated")
		return []Result{{Type: "mfa_disabled", Payload: p}}

	case "PutBucketPolicy", "PutBucketAcl":
		policy := mapStr(reqParams, "bucketPolicy")
		if len(policy) > 512 {
			policy = policy[:512]
		}
		p := map[string]any{"action": "PutBucketPolicy", "config_key": "bucket-policy"}
		set(p, "resource_name", mapStr(reqParams, "bucketName"))
		set(p, "new_value", policy)
		set(p, "change_description", "S3 bucket policy updated")
		return []Result{{Type: "config_change", Payload: p}}

	case "GetObject":
		bucket := mapStr(reqParams, "bucketName")
		key := mapStr(reqParams, "key")
		p := map[string]any{
			"action":         "GetObject",
			"resource_count": 1,
			"files_accessed": 1,
		}
		if cl, ok := awsInt64(respElems, "contentLength"); ok {
			p["bytes_transferred"] = cl
		} else {
			p["bytes_transferred"] = int64(0)
		}
		set(p, "destination", sourceIP)
		p["resources"] = []string{strings.TrimSuffix(bucket+"/"+key, "/")}
		return []Result{{Type: "object_get", Payload: p}}

	case "ListObjects", "ListObjectsV2":
		bucket := mapStr(reqParams, "bucketName")
		p := map[string]any{
			"action":            "ListObjects",
			"resource_count":    1,
			"files_accessed":    1,
			"bytes_transferred": int64(0),
		}
		set(p, "destination", sourceIP)
		p["resources"] = []string{bucket}
		return []Result{{Type: "list_objects", Payload: p}}

	case "GetSecretValue", "DescribeSecret":
		secret := mapStr(reqParams, "secretId")
		p := map[string]any{"action": eventName}
		set(p, "target", secret)
		set(p, "resource", secret)
		set(p, "resource_id", secret)
		return []Result{{Type: "secret_access", Payload: p}}

	case "CreateUser":
		name := mapStr(reqParams, "userName")
		p := map[string]any{"action": "CreateUser"}
		set(p, "display_name", name)
		set(p, "principal_id", name)
		set(p, "new_principal", name)
		return []Result{{Type: "user_created", Payload: p}}

	case "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity":
		roleArn := mapStr(reqParams, "roleArn")
		acct := arnAccountID(roleArn)
		p := map[string]any{"action": "AssumeRole"}
		set(p, "member", roleArn)
		// Cross-account: the assumed role belongs to a different account than home.
		if acct != "" && recipientAcct != "" && acct != recipientAcct {
			set(p, "domain", acct)
			set(p, "external_user", recipientAcct)
			return []Result{{Type: "trust_added", Payload: p}}
		}
		// Same-account assume is a role assignment, not external trust.
		set(p, "role", roleArn)
		set(p, "role_name", roleArn)
		return []Result{{Type: "role_assignment", Payload: p}}

	case "UpdateSAMLProvider", "CreateSAMLProvider":
		arn := mapStr(reqParams, "sAMLProviderArn")
		p := map[string]any{"action": eventName}
		set(p, "domain", arn)
		set(p, "domain_name", arn)
		return []Result{{Type: "federation_settings_update", Payload: p}}

	case "UpdateAccountPasswordPolicy":
		p := map[string]any{"action": eventName, "config_key": "password-policy"}
		set(p, "change_description", "account password policy updated")
		return []Result{{Type: "setting_update", Payload: p}}

	case "LookupEvents", "GetTrailStatus":
		p := map[string]any{
			"request_count": 1,
			"status_code":   200,
			"window_secs":   60,
		}
		set(p, "endpoint", "cloudtrail/"+eventName)
		return []Result{{Type: "api_request", Payload: p}}
	}

	// Unmapped: inert catch-all so type-less detectors still see the event.
	return []Result{{Type: CatchAll, Payload: map[string]any{"action": eventName}}}
}

// awsInner returns the decoded CloudTrailEvent inner document. It accepts the
// field as a JSON string (SDK marshaling) or an already-decoded object.
func awsInner(rawEvent map[string]any) map[string]any {
	if rawEvent == nil {
		return nil
	}
	switch v := rawEvent["CloudTrailEvent"].(type) {
	case string:
		var inner map[string]any
		if json.Unmarshal([]byte(v), &inner) == nil {
			return inner
		}
	case map[string]any:
		return v
	}
	return nil
}

// awsInt64 reads a numeric field as int64 from a decoded JSON map.
func awsInt64(m map[string]any, k string) (int64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[k].(type) {
	case float64:
		return int64(v), true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
	}
	return 0, false
}

// arnAccountID extracts the account id from arn:aws:iam::<account-id>:role/<name>.
func arnAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
