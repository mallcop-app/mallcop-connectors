# guardduty connector

Polls AWS **GuardDuty** findings for every detector in a region: `ListDetectors`
-> `ListFindings` (sorted ascending by `updatedAt`, paginated) -> `GetFindings`
(batched — one call per `ListFindings` page, since GuardDuty caps both APIs at
50 results).

Every GuardDuty finding is already a pre-triaged security alert — GuardDuty is
itself a detector, not a raw audit log — so unlike the `aws`/`github`
connectors (which branch raw event names onto mallcop's admin-action gate
vocabulary), every finding maps uniformly to the canonical type
`guardduty_finding` with `"signal_class":"alert"` in the payload. See
[`internal/normalize/guardduty.go`](../../internal/normalize/guardduty.go) for
the full field mapping and the honesty-rule rationale.

## Auth

Uses the standard AWS credentials chain (aws-sdk-go-v2). Set any of:

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Region (overridden by `--region` flag) |

AWS profiles (`~/.aws/credentials`) and instance/pod roles are also supported via the SDK chain.

## Required IAM permissions

Read-only:

```json
{
  "Effect": "Allow",
  "Action": ["guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings"],
  "Resource": "*"
}
```

(The AWS-managed `AmazonGuardDutyReadOnlyAccess` policy covers this and more.)

## Usage

```bash
mallcop-connector-guardduty --region us-east-1 [--since <iso-timestamp>] [--cursor <cursor>]
```

If GuardDuty has no detector enabled in the target account/region,
`ListDetectors` returns an empty list — the connector logs a warning to
stderr and exits 0 with zero events (not a failure; GuardDuty is often an
opt-in, billed source enabled separately from wiring the connector — see
[docs/connector-setup.md](../../docs/connector-setup.md#guardduty)).

## Cursor semantics

The `--since`/`--cursor` floor filters on the finding's `updatedAt` via
GuardDuty's native `FindingCriteria` (`Type: Timestamp in Unix Epoch
millisecond format`, per the API), not client-side filtering — so a resumed
run never re-scans findings the API itself can exclude.

- `--since` is **inclusive**: `updatedAt >= since` (matches every other
  connector's `--since` contract).
- A resumed `--cursor` (the prior run's high-water mark) is **strict/exclusive**:
  `updatedAt > cursor`, since the boundary finding was already emitted last run.
- When both are supplied, the later (more recent) timestamp wins, carrying
  that timestamp's own inclusive/exclusive rule.
- The cursor is HMAC-signed under `mallcop-guardduty-cursor:<region>` — brand
  new connector, so unlike `aws`/`github` there is no legacy pagination-token
  cursor format to migrate away from (PR #7's `tsReliable` guard against a
  fabricated-timestamp poisoning the resume high-water mark is still applied:
  a finding missing/unparseable `updatedAt` is still emitted, but never
  advances the cursor).

## Sample output

```json
{"id":"a1b2c3...","source":"guardduty","type":"guardduty_finding","actor":"alice","timestamp":"2024-06-01T12:05:00Z","org":"111111111111","payload":{"signal_class":"alert","finding_type":"UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B","severity":7.5,"severity_label":"high","title":"...", "raw":{...}}}
```

## Known limitations

- `actor` is populated from `resource.accessKeyDetails.userName` when present
  (the IAM principal associated with the finding). Findings without an IAM
  access-key principal (e.g. EC2/network-based findings) emit an empty actor —
  the flat payload's `resource_type` and `raw` sub-object still carry the full
  resource detail for downstream inference/detectors.
- One detector per region is the overwhelmingly common case; the connector
  correctly handles (and pages) multiple detectors in one region if present,
  emitting findings from all of them.
