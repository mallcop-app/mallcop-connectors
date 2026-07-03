# m365 connector

Polls the Office 365 Management Activity API (Unified Audit Log) and emits normalized mallcop event JSONL to stdout.

Content types fetched: `Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.SharePoint`, `Audit.General`.

## Auth

OAuth2 client credentials (app registration). Set:

| Variable | Description |
|---|---|
| `M365_TENANT_ID` | Azure AD tenant ID |
| `M365_CLIENT_ID` | Application (client) ID |
| `M365_CLIENT_SECRET` | Client secret |

## Required permissions

In your Azure AD app registration, add the following **application** permission (not delegated):

- `ActivityFeed.Read` (Office 365 Management APIs)

Grant admin consent after adding.

## Usage

```bash
mallcop-connector-m365 [--since <iso-timestamp>] [--cursor <cursor>]
```

## Sample output

```json
{"id":"abc123","source":"m365","type":"AzureActiveDirectory","actor":"alice@example.com","timestamp":"2024-01-15T10:30:00Z","org":"","payload":{"Operation":"UserLoggedIn",...}}
```

## Known limitations

- The Management Activity API requires the tenant to have an active Microsoft 365 subscription.
- Content blobs are available for up to 7 days after creation.
- Rate limits apply per content type; the connector handles 429 responses with backoff.
