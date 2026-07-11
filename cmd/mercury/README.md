# mercury connector

Polls the Mercury Bank API for account transaction activity and emits normalized mallcop event JSONL to stdout.

## Auth

Bearer token. Set:

| Variable | Description |
|---|---|
| `MERCURY_API_TOKEN` | Mercury API token (format `secret-token:...`) |

## Required permissions

A read-only Mercury API token scoped to the workspace's accounts. The connector only issues `GET` requests (`/accounts`, `/account/{id}/transactions`).

## Usage

```bash
mallcop-connector-mercury [--since <iso-timestamp>] [--cursor <cursor>]
```

## Sample output

```json
{"id":"dbdd0064e06d3abe37802a53322e39e16eef0c7344b8587fc4b16eafa6dc1826","source":"mercury","type":"cloud_other","actor":"Microsoft","timestamp":"2026-07-09T12:38:07.606142Z","org":"5ca2f63a-17e8-11f1-a3a1-c735ac15f03b","payload":{"amount":-70.01,"currency":"USD","kind":"debitCardTransaction","direction":"outgoing","counterparty":"Microsoft",...}}
```

`actor` is the transaction counterparty name (not a Mercury user) — this deliberately feeds mallcop's new-actor detector: a never-seen counterparty on an outgoing transfer is exactly the signal this connector exists to produce. `org` is the Mercury account ID the transaction posted against.

## Cursor scheme

Unlike the opaque next-page cursors used by the Azure/AWS/Okta connectors, Mercury's cursor is a plain high-water mark: the RFC3339 (nanosecond precision) timestamp of the newest transaction (`postedAt`, falling back to `createdAt`) seen across all accounts in the run, HMAC-signed with a key derived from `MERCURY_API_TOKEN`. On resume, only transactions strictly newer than the mark are emitted. `--since` is independent and inclusive (`>= since`); when both are given, whichever names the later point in time wins, with the cursor's exclusive semantics applying only when the cursor itself sets the floor.

## Known limitations

- The transactions endpoint has no `hasMore`/next-token field; pagination termination is inferred from a page shorter than the requested page size, with a hard page-count safety cap per account as a guard against a runaway/looping upstream.
- All accounts under the token's workspace are polled every run (Mercury has no per-account webhook/stream); `--since`/`--cursor` bound the query window via the API's `start` query param plus a precise client-side filter.
- Amounts are assumed USD; Mercury's `currencyExchangeInfo` field (foreign-currency transactions) is passed through in the raw payload but not separately normalized.
