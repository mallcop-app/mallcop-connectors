# Connector Setup Guide

How to connect each data source to a mallcop scan: the credentials each connector
needs, how to provision them (least-privilege, read-only), the `mallcop.yaml` block,
and the CI wiring. Examples use GitHub Actions (the `mallcop init` scaffold), but the
same env vars work anywhere `mallcop scan` runs.

- [How connectors work](#how-connectors-work)
- [Prerequisite: install the sibling binaries](#prerequisite-install-the-sibling-binaries-kindcloud-only)
- [GitHub](#github) · [Azure](#azure) · [AWS](#aws) · [Microsoft 365](#microsoft-365) · [GCP](#gcp) · [Okta](#okta)
- [Cost & tuning](#cost--tuning) · [Verifying a connector](#verifying-a-connector)

---

## How connectors work

A scan's sources are the `connectors:` list in `mallcop.yaml`. Three kinds:

| `kind` | Runs | Needs a sibling binary? |
|--------|------|--------------------------|
| `file` | reads a local events JSONL | no (built in) |
| `github` | in-process GitHub org connector | no (built into the mallcop binary) |
| `cloud` | forks a sibling binary `mallcop-connector-<source>` | **yes** — from this repo (`aws`, `azure`, `gcp`, `m365`, `okta`) |

Key behaviours to design around:

- **Fail-loud.** If *any* connector errors, the whole scan aborts (no partial run). So
  **add one source at a time** and prove it green before adding the next — a single
  mis-scoped credential otherwise takes down every other source.
- **`env:` is an allow-list.** A connector entry's `env: [NAME, …]` names exactly which
  environment variables are forwarded to the child process — scoped, never the full
  environment. A credential must be (a) present in the scan step's environment and
  (b) listed here, or the connector can't see it.
- **Incremental via cursor.** Cloud connectors take `--since` (first pull, before any
  cursor exists) and `--cursor` (resume point). Set `since:` in `mallcop.yaml` to bound
  the first pull. mallcop persists the cursor in the store and passes it on later runs.
- **Idempotent overlap is cheap.** With baseline gating (mallcop ≥ v0.11.1), re-pulling
  the same events across overlapping windows does **not** re-investigate already-seen
  actors — so a generous lookback costs almost nothing after the first scan.

The `Connector` fields (`mallcop.yaml`, strict-decoded — unknown keys are a hard error):

```yaml
connectors:
  - kind:    github | cloud | file
    id:      stable-id            # used for the cursor file + logs
    org:     my-org               # kind:github only
    source:  azure                # kind:cloud only — selects mallcop-connector-<source>
    binary:  connectors/bin/azure # kind:cloud only — explicit path to the sibling binary
    since:   3h                   # kind:cloud only — first-pull window (Go duration)
    args:    ["--flag","value"]   # kind:cloud only — extra flags appended after --since/--cursor
    env:     [VAR1, VAR2]         # kind:cloud only — env-var names forwarded to the child
    path:    ./events.jsonl       # kind:file only
```

---

## Prerequisite: install the sibling binaries (kind:cloud only)

The core `mallcop` release does **not** bundle the cloud connectors. Install them
alongside it and point each connector's `binary:` at the extracted path. In GitHub
Actions, add this after the step that installs the mallcop binary:

```yaml
- name: Install mallcop-connectors sibling binaries
  env:
    MALLCOP_ASSET: ${{ steps.platform.outputs.asset }}   # e.g. linux-amd64
    MALLCOP_CONNECTORS_VERSION: "v0.6.0"
  run: |
    set -euo pipefail
    base="https://github.com/mallcop-app/mallcop-connectors/releases/download/${MALLCOP_CONNECTORS_VERSION}"
    curl -fsSLO "${base}/mallcop-connectors-${MALLCOP_ASSET}.tar.gz"
    curl -fsSLO "${base}/mallcop-connectors-${MALLCOP_ASSET}.tar.gz.sha256"
    sha256sum -c "mallcop-connectors-${MALLCOP_ASSET}.tar.gz.sha256"
    mkdir -p connectors
    tar -xzf "mallcop-connectors-${MALLCOP_ASSET}.tar.gz" -C connectors   # -> connectors/bin/aws, /azure, ...
    chmod +x connectors/bin/* || true
```

The tarball extracts to `connectors/bin/<source>`, so each connector uses
`binary: connectors/bin/<source>`. Pin `MALLCOP_CONNECTORS_VERSION` and verify the
checksum — never build the connector from source in the deployment repo.

---

## GitHub

**Monitors:** your GitHub organization's audit/events feed (`GET /orgs/{org}/events`; the
Enterprise audit log with `GITHUB_AUDIT_LOG=1`). Built into the mallcop binary — **no
sibling binary needed.**

**Credentials — GitHub App installation (recommended):**
1. Create (or reuse) a GitHub App and **install it on your org**. Read scopes are enough
   (organization/members read; the app needs no write permissions to monitor).
2. Note the **App ID** and the **Installation ID** (`.../settings/installations/<id>` →
   the numeric id). Download the App **private key** (`.pem`).
3. Provide to the scan: `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, `GITHUB_APP_PRIVATE_KEY`.

> **Gotcha — secret naming.** GitHub Actions **forbids repo secret names starting with
> `GITHUB_`**. Store the PEM under a different name (e.g. `MALLCOP_GH_APP_PRIVATE_KEY`) and
> export it to the connector's real env var inside the `run:` body. App ID and
> installation ID are not secret — inline them.

Alternative: a PAT/OAuth token in `GITHUB_TOKEN` (BYO-token path). GHES: set `GITHUB_API_URL`.

**`mallcop.yaml`:**
```yaml
  - kind: github
    id: github-myorg
    org: my-org
```

**scan.yml (Run-scan step):**
```yaml
    env:
      MALLCOP_GH_APP_PRIVATE_KEY: ${{ secrets.MALLCOP_GH_APP_PRIVATE_KEY }}
    run: |
      export GITHUB_APP_ID="123456"
      export GITHUB_INSTALLATION_ID="98765432"
      export GITHUB_APP_PRIVATE_KEY="$MALLCOP_GH_APP_PRIVATE_KEY"
      export GITHUB_LOOKBACK="2h"     # match your scan cadence; default 24h
      mallcop scan
```

**Verify (zero cost):** mint an installation token and `GET /orgs/<org>/events` → expect `200`.

---

## Azure

**Monitors:** Azure Monitor **Activity Logs** for a subscription (control-plane
operations). `kind: cloud, source: azure`.

**Credentials — Entra service principal, Reader at subscription scope:**
```bash
az ad sp create-for-rbac --name mallcop-monitor-az \
  --role Reader \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
# -> appId (AZURE_CLIENT_ID), password (AZURE_CLIENT_SECRET), tenant (AZURE_TENANT_ID)
```
`Reader` (or `Monitoring Reader`) at the **subscription** scope is required — the
connector reads subscription-level Activity Logs, so a resource-group-scoped role is not
enough. Provide `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
`AZURE_SUBSCRIPTION_ID`.

> **Gotcha — set `since:`.** The Activity Log REST API **requires an `eventTimestamp`
> filter**. On the first pull (no cursor yet) mallcop derives that filter from `since:`.
> If you omit `since:`, the connector fails with `400 "The filter criteria is not
> specified."` A few hours (`3h`) is a good first-pull window.

**`mallcop.yaml`:**
```yaml
  - kind: cloud
    id: azure-mysub
    source: azure
    binary: connectors/bin/azure
    since: 3h
    env: [AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID]
```

**scan.yml (Run-scan step) —** inject from secrets (store under dedicated names so they
can't collide with any deploy SP secrets already on the repo):
```yaml
    env:
      AZURE_TENANT_ID:       ${{ secrets.MALLCOP_AZURE_TENANT_ID }}
      AZURE_CLIENT_ID:       ${{ secrets.MALLCOP_AZURE_CLIENT_ID }}
      AZURE_CLIENT_SECRET:   ${{ secrets.MALLCOP_AZURE_CLIENT_SECRET }}
      AZURE_SUBSCRIPTION_ID: ${{ secrets.MALLCOP_AZURE_SUBSCRIPTION_ID }}
```

**Verify (zero cost):** client-credentials token for `https://management.azure.com/.default`,
then `GET …/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&$filter=eventTimestamp ge '<ts>'`
→ expect `200`.

---

## AWS

**Monitors:** AWS **CloudTrail management events** for the account, via `LookupEvents`.
`kind: cloud, source: aws`. (Org-wide reading of the S3 org-trail objects across every
workload account is a planned connector enhancement — track it before relying on it.)

**Credentials — GitHub OIDC assume-role (recommended, no long-lived keys):**
1. Provision an IAM role (e.g. via Terraform) with the AWS-managed **`SecurityAudit`**
   policy (read-only: `cloudtrail:LookupEvents`, `DescribeTrails`, plus Config/IAM read
   for future detectors).
2. Trust GitHub OIDC, scoped to your deployment repo:
   `token.actions.githubusercontent.com:sub = "repo:<owner>/<repo>:*"`, `aud = sts.amazonaws.com`.
3. No secrets to store — the workflow assumes the role at run time.

**scan.yml** — add the OIDC permission and an assume-role step; `configure-aws-credentials`
exports `AWS_*` into the job environment, which the Run-scan step inherits:
```yaml
permissions:
  contents: write
  id-token: write          # required to mint the OIDC token

# ... after installing the connector binaries, before Run-scan:
- name: Configure AWS credentials (OIDC)
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/mallcop-monitor
    aws-region: us-east-1
```

**`mallcop.yaml`** — no `args` needed; `AWS_REGION` comes from the assume-role step:
```yaml
  - kind: cloud
    id: aws-myaccount
    source: aws
    binary: connectors/bin/aws
    since: 3h
    env: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION, AWS_DEFAULT_REGION]
```
Include `AWS_SESSION_TOKEN` in `env:` — OIDC credentials are temporary and won't
authenticate without it. Static keys work too (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
of a read-only IAM user), but OIDC avoids long-lived secrets.

**Verify:** OIDC roles can only be assumed from an Actions run in the trusted repo, so
verify with a branch `workflow_dispatch` rather than locally. The connector calls
`CloudTrail:LookupEvents`.

---

## Microsoft 365

**Monitors:** the Office 365 **Unified Audit Log** via the Management Activity API
(`Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.SharePoint`, `Audit.General`).
`kind: cloud, source: m365`.

**Credentials — Entra app registration with an application permission + admin consent:**
```bash
APPID=$(az ad app create --display-name "mallcop-monitor-m365" --sign-in-audience AzureADMyOrg \
  --required-resource-accesses '[{"resourceAppId":"c5393580-f805-4401-95e8-94b7a6ef2fc2",
     "resourceAccess":[{"id":"594c1fb6-4f81-4475-ae41-0c394909246c","type":"Role"}]}]' \
  --query appId -o tsv)
az ad sp create --id "$APPID"
az ad app permission admin-consent --id "$APPID"                      # needs Global Admin
az ad app credential reset --id "$APPID" --years 2 --query password -o tsv   # -> M365_CLIENT_SECRET
```
- `c5393580-f805-4401-95e8-94b7a6ef2fc2` = **Office 365 Management APIs**; role
  `594c1fb6-…` = **`ActivityFeed.Read` (Application)**.
- Provide `M365_TENANT_ID` (your tenant id), `M365_CLIENT_ID` (`$APPID`),
  `M365_CLIENT_SECRET`.

> **Prerequisite — the Unified Audit Log must be ON.** New app aside, the tenant's audit
> pipeline has to be enabled or the API returns `400 "Tenant does not exist"` on
> `subscriptions/start`. Enable it one of two ways:
> - **Purview portal:** Audit → **"Start recording user and admin activity."**
> - **Exchange Online PowerShell** (works headless, and around a broken Purview portal —
>   e.g. the `"Purview first party app service principal not present"` error):
>   ```powershell
>   $tok = az account get-access-token --resource https://outlook.office365.com --query accessToken -o tsv
>   Connect-ExchangeOnline -AccessToken $tok -Organization <tenant>.onmicrosoft.com -ShowBanner:$false
>   Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
>   ```
> Enabling takes up to ~60 min to apply and **up to ~24 h** before audit content flows.
> Then start the four content subscriptions once:
> `POST https://manage.office.com/api/v1.0/<tenant>/activity/feed/subscriptions/start?contentType=Audit.AzureActiveDirectory`
> (repeat for `Audit.Exchange`, `Audit.SharePoint`, `Audit.General`).

**`mallcop.yaml`:**
```yaml
  - kind: cloud
    id: m365-mytenant
    source: m365
    binary: connectors/bin/m365
    since: 3h
    env: [M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET]
```
**scan.yml:** inject `M365_TENANT_ID/CLIENT_ID/CLIENT_SECRET` from `MALLCOP_M365_*` secrets.

**Verify (zero cost):** client-credentials token for `https://manage.office.com/.default`,
then `GET …/activity/feed/subscriptions/list` → expect `200` (empty list is fine until
subscriptions are started and content has flowed).

---

## GCP

**Monitors:** GCP **Cloud Logging** audit log entries. `kind: cloud, source: gcp`.

**Credentials:** a service account with the **`roles/logging.viewer`** (or
`logging.privateLogViewer` for data-access logs) role. Download a JSON key. Provide
`GOOGLE_APPLICATION_CREDENTIALS` (path to the key file) and `GCP_PROJECT_ID`.

```yaml
  - kind: cloud
    id: gcp-myproject
    source: gcp
    binary: connectors/bin/gcp
    since: 3h
    args: ["--project", "<PROJECT_ID>"]
    env: [GOOGLE_APPLICATION_CREDENTIALS, GCP_PROJECT_ID]
```
In CI, write the JSON key from a secret to a file and point `GOOGLE_APPLICATION_CREDENTIALS`
at it. Prefer Workload Identity Federation over a downloaded key where possible.

---

## Okta

**Monitors:** the Okta **System Log** (`/api/v1/logs`). `kind: cloud, source: okta`.

**Credentials:** an Okta API token (SSWS) from a read-only admin, plus your org domain.
Provide `OKTA_DOMAIN` (e.g. `mycompany.okta.com`) and `OKTA_API_TOKEN`.

```yaml
  - kind: cloud
    id: okta-myorg
    source: okta
    binary: connectors/bin/okta
    since: 3h
    env: [OKTA_DOMAIN, OKTA_API_TOKEN]
```

---

## Cost & tuning

- **`since:` / lookback vs. cadence.** Match the first-pull window to roughly your scan
  interval, with a little overlap so a delayed or dropped scheduled run doesn't drop
  events. `since: 3h` on an hourly scan is a safe default.
- **Baseline gating keeps overlap free.** On mallcop ≥ v0.11.1, re-pulled events for
  already-seen actors are not re-investigated, so overlap costs ~0 committee inference.
- **Watch spend** via the inference provider's usage endpoint (`cost_usd`), not a balance
  figure. Bound a scan with `budgets.max_findings` and `budgets.scan_timeout` in
  `mallcop.yaml`.

## Verifying a connector

Work up the ladder — each rung is cheaper feedback than the next:

1. **Preflight (zero cost).** Mint the connector's credential yourself and hit the source
   API's list/read endpoint directly (see each connector's *Verify* note). A `200` proves
   the credential and its scope before you touch any config.
2. **Local smoke (zero inference).** Run `mallcop scan --config mallcop.yaml` with the
   credentials in your environment but **no inference key** — every finding force-escalates
   (no metered calls), so you confirm the config parses and the connector pulls events for
   free. A malformed config fails at load, before any connector runs.
3. **Branch dispatch (authoritative).** `workflow_dispatch` the scan on a branch. This runs
   the real workflow — binary install, credential injection, connector, inference, store
   push — without touching the scheduled run on `main`. Green here → merge.

Because connectors are fail-loud, **add and verify one source per pull request.**
