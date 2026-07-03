# gcp connector

Polls GCP Cloud Logging audit log entries via the Cloud Logging API v2 and emits normalized mallcop event JSONL to stdout.

## Auth

Service account key file. Set:

| Variable | Description |
|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON key file |
| `GCP_PROJECT_ID` / `GOOGLE_CLOUD_PROJECT` | Target project ID (overridden by `--project` flag) |

## Required permissions

Grant the service account the `roles/logging.viewer` role on the target project (or the primitive `roles/viewer`).

## Usage

```bash
mallcop-connector-gcp --project <project-id> [--since <iso-timestamp>] [--cursor <cursor>]
```

## Sample output

```json
{"id":"abc123","source":"gcp","type":"activity","actor":"alice@example.com","timestamp":"2024-01-15T10:30:00Z","org":"","payload":{"methodName":"storage.buckets.create",...}}
```

## Known limitations

- Only `cloudaudit.googleapis.com/activity` (admin activity) logs are fetched by default.
- GCP log retention depends on your project's log sink configuration.
