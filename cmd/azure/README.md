# azure connector

Polls Azure Monitor Activity Logs via the REST API and emits normalized mallcop event JSONL to stdout.

## Auth

Service principal via OAuth2 client credentials. Set:

| Variable | Description |
|---|---|
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | Application (client) ID |
| `AZURE_CLIENT_SECRET` | Client secret |
| `AZURE_SUBSCRIPTION_ID` | Target subscription ID (overridden by `--subscription-id` flag) |

## Required permissions

Assign the built-in **Reader** role (or a custom role with `microsoft.insights/eventtypes/management/values/read`) on the target subscription.

## Usage

```bash
mallcop-connector-azure --subscription-id <id> [--since <iso-timestamp>] [--cursor <cursor>]
```

## Sample output

```json
{"id":"abc123","source":"azure","type":"Administrative","actor":"alice@example.com","timestamp":"2024-01-15T10:30:00Z","org":"","payload":{"operationName":"Microsoft.Storage/storageAccounts/write",...}}
```

## Known limitations

- Activity Log retention is 90 days in Azure.
- Only the `microsoft.insights/eventtypes/management` category is fetched (administrative operations).
