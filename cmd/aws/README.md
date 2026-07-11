# aws connector

Two modes, selected automatically:

1. **LookupEvents mode** (default) — polls the CloudTrail `LookupEvents` API for
   management events in a single account/region.
2. **S3 org-trail mode** — reads an organization-wide CloudTrail trail delivered
   to S3 directly, covering every account and region the trail spans. Enabled
   by setting `AWS_TRAIL_BUCKET` (or `-trail-bucket`).

## Auth

Uses the standard AWS credentials chain (aws-sdk-go-v2). Set any of:

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Region (overridden by `--region` flag) |

AWS profiles (`~/.aws/credentials`) and instance/pod roles are also supported via the SDK chain.

## Required IAM permissions

LookupEvents mode:

```json
{
  "Effect": "Allow",
  "Action": ["cloudtrail:LookupEvents"],
  "Resource": "*"
}
```

S3 org-trail mode:

```json
{
  "Effect": "Allow",
  "Action": ["s3:ListBucket", "s3:GetObject"],
  "Resource": [
    "arn:aws:s3:::<trail-bucket>",
    "arn:aws:s3:::<trail-bucket>/*"
  ]
},
{
  "Effect": "Allow",
  "Action": ["kms:Decrypt"],
  "Resource": "<trail-KMS-key-arn>"
}
```

(KMS decryption for SSE-KMS-encrypted trail objects happens server-side on
`GetObject` — the connector never talks to KMS directly, but the calling
principal still needs `kms:Decrypt` on the trail's key.)

## Usage

```bash
# LookupEvents mode (default)
mallcop-connector-aws --region us-east-1 [--since <iso-timestamp>] [--cursor <cursor>]

# S3 org-trail mode
AWS_TRAIL_BUCKET=3dl-cloudtrail-458526671706 \
  mallcop-connector-aws --since <iso-timestamp> [--cursor <cursor>]
# or: mallcop-connector-aws -trail-bucket 3dl-cloudtrail-458526671706 ...
```

| Variable | Description |
|---|---|
| `AWS_TRAIL_BUCKET` / `-trail-bucket` | S3 bucket holding the org trail. Setting either enables S3 org-trail mode; unset runs LookupEvents mode unchanged. |
| `AWS_TRAIL_PREFIX` | Key prefix above the org/account layout. Default `AWSLogs/`. |

## S3 org-trail mode details

- Expects the standard organization trail layout:
  `<prefix><org-id>/<account-id>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/*.json.gz`,
  and also handles the non-org layout where an account id sits directly under
  the prefix (no `o-...` segment). Layout is discovered by listing with
  `delimiter=/`, not assumed.
- `CloudTrail-Digest/` and `CloudTrail-Insight/` sibling folders are recognized
  and skipped entirely — never listed for day-prefixes, never fetched.
- Each `.json.gz` object is downloaded (plain `GetObject`; SSE-KMS decryption
  is server-side) and streamed through gunzip + JSON decode one object at a
  time — the whole trail is never buffered in memory.
- Every `Records[]` entry is normalized through the same `normalize.AWS` mapper
  LookupEvents mode uses, so both modes produce identical canonical `Type`
  values and dedupe identically (`ID` = sha256 of `aws:cloudtrail:<eventID>`).
- `--since` filters at the record level (day-prefixes are still enumerated
  from the `--since` date through today UTC, since a day's objects can carry
  mixed event times).
- The cursor is a high-water mark: the max S3 object `LastModified` processed,
  HMAC-signed under a scope (`mallcop-aws-s3-cursor:<bucket>`) distinct from
  LookupEvents mode's cursor scope, so cursors are never interchangeable
  between modes. On resume, objects with `LastModified <=` the cursor mark are
  skipped — late-delivered objects always carry a newer `LastModified` even
  when their records describe older events, so this never drops data.
- Any list/get/parse error aborts the run (exit 1) — a partially-readable
  trail must never look green.

## Sample output

```json
{"id":"abc123","source":"aws","type":"AwsApiCall","actor":"arn:aws:iam::123456789012:user/alice","timestamp":"2024-01-15T10:30:00Z","org":"","payload":{"eventName":"CreateBucket",...}}
```

## Known limitations

- LookupEvents mode only fetches management events (control plane) — not data
  events, and CloudTrail `LookupEvents` is limited to the last 90 days. S3
  org-trail mode has neither limitation (it reads whatever the trail
  retains), provided the trail is configured to capture the event types you
  need.
