# github connector

Polls the GitHub org audit log via GitHub App installation auth and emits normalized mallcop event JSONL to stdout.

## Auth

GitHub App installation. You need:

1. A GitHub App installed on your organization with **Read** access to **Organization administration** (for audit log).
2. The App ID, Installation ID, and private key PEM file.

| Flag | Description |
|---|---|
| `--app-id` | GitHub App ID (numeric) |
| `--installation-id` | App installation ID for your org |
| `--private-key-path` | Path to the App's private key PEM file |
| `--org` | GitHub organization name |

Alternatively, pass a pre-minted installation access token via `--installation-token` (skips App auth).

## Usage

```bash
mallcop-connector-github \
  --app-id 12345 \
  --installation-id 67890 \
  --private-key-path /path/to/private-key.pem \
  --org my-org \
  [--since <iso-timestamp>] \
  [--cursor <cursor>]
```

## Sample output

```json
{"id":"abc123","source":"github","type":"org.member_added","actor":"alice","timestamp":"2024-01-15T10:30:00Z","org":"my-org","payload":{"action":"member_added",...}}
```

## Known limitations

- GitHub audit log API requires the organization to be on a GitHub Enterprise or GitHub Teams plan.
- Audit log retention is 180 days for Enterprise, 7 days for Teams.
