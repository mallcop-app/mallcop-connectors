# okta connector

Polls the Okta System Log API (`/api/v1/logs`) and emits normalized mallcop event JSONL to stdout.

## Auth

SSWS API token. Set:

| Variable | Description |
|---|---|
| `OKTA_DOMAIN` | Your Okta domain, e.g. `myorg.okta.com` |
| `OKTA_API_TOKEN` | SSWS token from **Security > API > Tokens** |

## Required permissions

The API token must belong to a user (or service account) with at least the **Read-Only Administrator** role.

## Usage

```bash
okta [--since <iso-timestamp>] [--cursor <cursor>]
```

## Sample output

```json
{"id":"abc123","source":"okta","type":"user.session.start","actor":"alice@example.com","timestamp":"2024-01-15T10:30:00Z","org":"myorg","payload":{"eventType":"user.session.start",...}}
```

## Known limitations

- Okta System Log retention is 90 days by default.
- Rate limit is 60 requests/minute per token; the connector handles 429 responses with backoff.
- This connector is new in Go — there is no Python mallcop counterpart.
