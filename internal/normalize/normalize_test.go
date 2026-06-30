package normalize

import (
	"encoding/json"
	"testing"
)

// decode runs a Result through PayloadJSON and returns the decoded flat payload.
func decode(t *testing.T, r Result, raw any) map[string]any {
	t.Helper()
	b, err := r.PayloadJSON(raw)
	if err != nil {
		t.Fatalf("PayloadJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	return m
}

func wantType(t *testing.T, got []Result, typ string) Result {
	t.Helper()
	for _, r := range got {
		if r.Type == typ {
			return r
		}
	}
	t.Fatalf("no result with Type %q; got %+v", typ, got)
	return Result{}
}

// --- AWS -------------------------------------------------------------------

func TestAWSConsoleLoginFailure(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"sourceIPAddress":"1.2.3.4","awsRegion":"us-east-1",
			"responseElements":{"ConsoleLogin":"Failure"},"errorMessage":"bad password"}`,
	}
	got := AWS("ConsoleLogin", raw)
	r := wantType(t, got, "login_failure")
	p := decode(t, r, raw)
	if p["ip"] != "1.2.3.4" {
		t.Errorf("ip = %v", p["ip"])
	}
	if p["reason"] != "bad password" {
		t.Errorf("reason = %v", p["reason"])
	}
}

func TestAWSAddUserToGroupRoleAssignment(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"requestParameters":{"groupName":"admins","userName":"bob"}}`,
	}
	r := wantType(t, AWS("AddUserToGroup", raw), "role_assignment")
	p := decode(t, r, raw)
	if p["role"] != "admins" || p["target_user"] != "bob" || p["action"] != "AddUserToGroup" {
		t.Errorf("payload = %+v", p)
	}
}

func TestAWSStopLoggingCloudTrailStop(t *testing.T) {
	raw := map[string]any{"CloudTrailEvent": `{"requestParameters":{"name":"my-trail"}}`}
	r := wantType(t, AWS("StopLogging", raw), "cloudtrail_stop")
	p := decode(t, r, raw)
	if p["resource_name"] != "my-trail" {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAWSGetObjectExfilFields(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"sourceIPAddress":"9.9.9.9","requestParameters":{"bucketName":"secrets","key":"db.dump"},
			"responseElements":{"contentLength":1048576}}`,
	}
	r := wantType(t, AWS("GetObject", raw), "object_get")
	p := decode(t, r, raw)
	if bt, ok := p["bytes_transferred"].(float64); !ok || int64(bt) != 1048576 {
		t.Errorf("bytes_transferred = %v", p["bytes_transferred"])
	}
	if p["destination"] != "9.9.9.9" {
		t.Errorf("destination = %v", p["destination"])
	}
}

func TestAWSAssumeRoleCrossAccountTrust(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"recipientAccountId":"111111111111",
			"requestParameters":{"roleArn":"arn:aws:iam::222222222222:role/cross"}}`,
	}
	r := wantType(t, AWS("AssumeRole", raw), "trust_added")
	p := decode(t, r, raw)
	if p["domain"] != "222222222222" {
		t.Errorf("domain = %v", p["domain"])
	}
}

func TestAWSUnmappedCatchAll(t *testing.T) {
	r := wantType(t, AWS("DescribeInstances", map[string]any{}), CatchAll)
	if r.Type != CatchAll {
		t.Errorf("want catch-all, got %q", r.Type)
	}
}

// --- Azure -----------------------------------------------------------------

func TestAzureRoleAssignment(t *testing.T) {
	entry := map[string]any{
		"caller":     "admin@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/rg",
		"properties": map[string]any{
			"roleDefinitionName": "Owner",
			"principalId":        "victim",
		},
	}
	r := wantType(t, Azure("Microsoft.Authorization/roleAssignments/write", entry), "role_assignment")
	p := decode(t, r, entry)
	if p["role"] != "Owner" || p["target_user"] != "victim" || p["action"] != "role_assignment" {
		t.Errorf("payload = %+v", p)
	}
}

func TestAzureDiagnosticDeleteAuditTrail(t *testing.T) {
	entry := map[string]any{"resourceId": "/diag/setting1"}
	r := wantType(t, Azure("microsoft.insights/diagnosticSettings/delete", entry), "audit_trail_delete")
	p := decode(t, r, entry)
	if p["resource_name"] != "/diag/setting1" {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureKeyVaultSecretAccess(t *testing.T) {
	entry := map[string]any{"resourceId": "/vault/secrets/db"}
	r := wantType(t, Azure("Microsoft.KeyVault/vaults/secrets/read", entry), "secret_access")
	p := decode(t, r, entry)
	if p["target"] != "/vault/secrets/db" {
		t.Errorf("target = %v", p["target"])
	}
}

func TestAzureUserAddNewActor(t *testing.T) {
	entry := map[string]any{"properties": map[string]any{"displayName": "svc-acct", "objectId": "obj-1"}}
	r := wantType(t, Azure("Microsoft.Directory/users/add", entry), "user_created")
	p := decode(t, r, entry)
	if p["display_name"] != "svc-acct" || p["principal_id"] != "obj-1" {
		t.Errorf("payload = %+v", p)
	}
}

// --- GCP -------------------------------------------------------------------

func TestGCPSetIamPolicyFanOut(t *testing.T) {
	proto := map[string]any{
		"resourceName": "projects/p",
		"request": map[string]any{
			"policy": map[string]any{
				"bindings": []any{
					map[string]any{"role": "roles/owner", "members": []any{"user:evil@x.com"}},
				},
			},
		},
	}
	got := GCP("google.iam.admin.v1.SetIamPolicy", proto)
	// Must produce BOTH config-drift (iam_policy_attach) AND priv-escalation (role_assignment).
	cd := wantType(t, got, "iam_policy_attach")
	if decode(t, cd, proto)["resource_name"] != "projects/p" {
		t.Errorf("iam_policy_attach missing resource_name")
	}
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, proto)
	if pep["role"] != "roles/owner" || pep["target_user"] != "evil@x.com" {
		t.Errorf("role_assignment payload = %+v", pep)
	}
}

func TestGCPCreateServiceAccountUserCreated(t *testing.T) {
	proto := map[string]any{
		"request":  map[string]any{"accountId": "svc"},
		"response": map[string]any{"email": "svc@p.iam.gserviceaccount.com"},
	}
	r := wantType(t, GCP("google.iam.admin.v1.CreateServiceAccount", proto), "user_created")
	p := decode(t, r, proto)
	if p["principal_id"] != "svc@p.iam.gserviceaccount.com" {
		t.Errorf("principal_id = %v", p["principal_id"])
	}
}

func TestGCPStorageGetObjectExfil(t *testing.T) {
	proto := map[string]any{
		"resourceName":    "projects/_/buckets/b/objects/o",
		"requestMetadata": map[string]any{"requestSize": float64(2048)},
	}
	r := wantType(t, GCP("storage.objects.get", proto), "object_get")
	p := decode(t, r, proto)
	if bt, ok := p["bytes_transferred"].(float64); !ok || int64(bt) != 2048 {
		t.Errorf("bytes_transferred = %v", p["bytes_transferred"])
	}
}

func TestGCPDeleteSinkAuditTrailDelete(t *testing.T) {
	proto := map[string]any{"resourceName": "projects/p/sinks/audit"}
	r := wantType(t, GCP("google.logging.v2.ConfigServiceV2.DeleteSink", proto), "audit_trail_delete")
	if decode(t, r, proto)["resource_name"] != "projects/p/sinks/audit" {
		t.Errorf("resource_name wrong")
	}
}

// --- M365 ------------------------------------------------------------------

func TestM365LoginFailure(t *testing.T) {
	rec := map[string]any{"ClientIP": "5.5.5.5", "LogonError": "InvalidPassword"}
	r := wantType(t, M365("AzureActiveDirectory", "UserLoginFailed", rec), "login_failure")
	p := decode(t, r, rec)
	if p["ip"] != "5.5.5.5" || p["reason"] != "InvalidPassword" {
		t.Errorf("payload = %+v", p)
	}
}

func TestM365AddMemberToRole(t *testing.T) {
	rec := map[string]any{
		"ObjectId": "alice@corp.com",
		"ModifiedProperties": []any{
			map[string]any{"Name": "Role.DisplayName", "NewValue": "Global Administrator"},
		},
	}
	r := wantType(t, M365("AzureActiveDirectory", "Add member to role.", rec), "role_assignment")
	p := decode(t, r, rec)
	if p["role"] != "Global Administrator" {
		t.Errorf("role = %v", p["role"])
	}
}

func TestM365FileDownloadedExfil(t *testing.T) {
	rec := map[string]any{"FileSizeBytes": float64(500000), "ClientIP": "7.7.7.7", "ObjectId": "/sites/x/doc.xlsx"}
	r := wantType(t, M365("SharePoint", "FileDownloaded", rec), "file_download")
	p := decode(t, r, rec)
	if bt, ok := p["bytes_transferred"].(float64); !ok || int64(bt) != 500000 {
		t.Errorf("bytes_transferred = %v", p["bytes_transferred"])
	}
}

func TestM365ConsentExternalAccess(t *testing.T) {
	rec := map[string]any{
		"ObjectId": "app-123",
		"ModifiedProperties": []any{
			map[string]any{"Name": "ConsentContext.DisplayName", "NewValue": "Sketchy App"},
		},
	}
	r := wantType(t, M365("AzureActiveDirectory", "Consent to application.", rec), "org.add_outside_collaborator")
	p := decode(t, r, rec)
	if p["collaborator"] != "Sketchy App" {
		t.Errorf("collaborator = %v", p["collaborator"])
	}
}

// --- Okta ------------------------------------------------------------------

func TestOktaPrivilegeGrant(t *testing.T) {
	raw := map[string]any{
		"target": []any{
			map[string]any{"type": "AppRole", "displayName": "Super Admin"},
			map[string]any{"type": "User", "alternateId": "victim@corp.com"},
		},
	}
	r := wantType(t, Okta("user.account.privilege.grant", raw), "role_assignment")
	p := decode(t, r, raw)
	if p["role"] != "Super Admin" || p["target_user"] != "victim@corp.com" {
		t.Errorf("payload = %+v", p)
	}
}

func TestOktaMFADeactivate(t *testing.T) {
	raw := map[string]any{
		"target": []any{map[string]any{"type": "User", "alternateId": "bob@corp.com"}},
	}
	r := wantType(t, Okta("user.mfa.factor.deactivate", raw), "mfa_disabled")
	p := decode(t, r, raw)
	if p["target_user"] != "bob@corp.com" {
		t.Errorf("target_user = %v", p["target_user"])
	}
}

func TestOktaLoginWithGeo(t *testing.T) {
	raw := map[string]any{
		"client": map[string]any{
			"ipAddress":           "203.0.113.1",
			"geographicalContext": map[string]any{"country": "RU", "state": "Moscow"},
		},
	}
	r := wantType(t, Okta("user.session.start", raw), "login")
	p := decode(t, r, raw)
	if p["ip"] != "203.0.113.1" || p["geo"] != "RU/Moscow" {
		t.Errorf("payload = %+v", p)
	}
}

func TestOktaUnmappedCatchAll(t *testing.T) {
	r := wantType(t, Okta("user.account.unlock", map[string]any{}), CatchAll)
	if r.Type != CatchAll {
		t.Errorf("want catch-all")
	}
}

// PayloadJSON always carries the raw event under "raw" for recursive scanning by
// injection-probe / secrets-exposure.
func TestPayloadCarriesRaw(t *testing.T) {
	raw := map[string]any{"weird": "AKIAIOSFODNN7EXAMPLE"}
	r := Result{Type: "login", Payload: map[string]any{"action": "login"}}
	p := decode(t, r, raw)
	if _, ok := p["raw"]; !ok {
		t.Fatalf("payload missing raw key: %+v", p)
	}
}
