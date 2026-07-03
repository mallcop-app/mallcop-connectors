# aws connector

Polls AWS CloudTrail management events and emits normalized mallcop event JSONL to stdout.

## Auth

Uses the standard AWS credentials chain (aws-sdk-go-v2). Set any of:

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Region (overridden by `--region` flag) |

AWS profiles (`~/.aws/credentials`) and instance/pod roles are also supported via the SDK chain.

## Required IAM permissions

```json
{
  "Effect": "Allow",
  "Action": ["cloudtrail:LookupEvents"],
  "Resource": "*"
}
```

## Usage

```bash
mallcop-connector-aws --region us-east-1 [--since <iso-timestamp>] [--cursor <cursor>]
```

## Sample output

```json
{"id":"abc123","source":"aws","type":"AwsApiCall","actor":"arn:aws:iam::123456789012:user/alice","timestamp":"2024-01-15T10:30:00Z","org":"","payload":{"eventName":"CreateBucket",...}}
```

## Known limitations

- Only management events (control plane) are fetched — not data events.
- CloudTrail LookupEvents is limited to the last 90 days.
