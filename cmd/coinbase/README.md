# coinbase connector

Polls the Coinbase App API v2 (retail/consumer accounts) for wallet transaction
history and emits normalized mallcop event JSONL to stdout.

## Auth

A Coinbase Developer Platform (CDP) API key, authenticated per-request with a
fresh short-lived Ed25519 JWT (not a static bearer token). Set:

| Variable | Description |
|---|---|
| `COINBASE_API_KEY` | CDP key **name**, format `organizations/{org_uuid}/apiKeys/{key_uuid}` |
| `COINBASE_API_SECRET` | base64 of the CDP key's 64-byte Ed25519 private key (seed\|\|pubkey) |

Create the key at <https://portal.cdp.coinbase.com/> (retail/consumer API key,
**not** an Advanced Trade / Exchange key — this connector talks to the `/v2/*`
App API).

## Required permissions

Create the key with **read-only** scopes:

- `wallet:accounts:read`
- `wallet:transactions:read`

Do not grant `wallet:transactions:send` or any trade/transfer scope — this
connector never needs write access, and a leaked read-only key can't move
funds.

## Usage

```bash
mallcop-connector-coinbase [--since <iso-timestamp>] [--cursor <cursor>]
```

## Design notes

- **Fresh JWT per request.** Coinbase CDP auth requires a new EdDSA JWT
  (`exp` = `nbf` + 120s) for every call, keyed to that call's exact method +
  host + path (query string excluded from the signed `uri` claim).
- **Account fan-out.** A retail account has ~250 per-currency wallet accounts
  (`GET /v2/accounts`), most dormant. On a first-ever run (no `--since`, no
  cursor) we only poll accounts with a nonzero current balance, to bound the
  cost of the initial backfill.
- **Resumed runs poll every account — deliberately, not by oversight.** The
  obvious optimization — skip accounts whose `updated_at` predates our resume
  mark — was tried and **live-verified to be broken**: probed against a real
  Coinbase retail account on 2026-07-11, a USDC wallet with recurring
  `interest` transactions through 2026-07-09 still reported
  `updated_at=2026-04-16T16:12:10Z` (its creation time) on `GET
  /v2/accounts/{id}`. The field does not track transaction or balance
  activity. Filtering on it would silently stop polling an account the moment
  it's "seen" once — including, worst case, an account mid-drain from a
  compromised key, which is exactly the scenario this connector exists to
  catch (see `actorFor` in `main.go`: a `send`'s destination address feeds the
  new-actor detector). So resumed runs fetch transactions for every account;
  `fetchTransactions`'s early-stop-at-cursor pagination still bounds a dormant
  account to one GET request per run.
- **Cursor** is an HMAC-signed high-water mark of the newest transaction
  `created_at` seen across all accounts (not a raw API page token — v2's
  pagination cursors are per-account and this connector fans out across many
  accounts per run).

## Sample output

```json
{"id":"61a0de4f...","source":"coinbase","type":"cloud_other","actor":"coinbase:USDC","timestamp":"2026-07-09T18:00:32Z","org":"5c3d381b-3b3a-5c44-9243-d7a0e85b2f6b","payload":{"amount":"0.028155","currency":"USDC","native_amount":"0.03","native_currency":"USD","status":"completed","tx_type":"interest","raw":{...}}}
```

## Known limitations

- Every mapped `type` is the inert catch-all (`cloud_other`) — no existing
  mallcop detector gate constant is semantically true for a crypto exchange
  transaction (send/receive/buy/sell/trade/staking_reward/interest/...). The
  flat payload (`amount`, `currency`, `native_amount`, `status`, `to_address`,
  `from`, `network_hash`, `title`, `subtitle`) still feeds the type-less
  detectors (new-actor, volume-anomaly, unusual-timing, injection-probe,
  secrets-exposure) and inference triage.
- v2 has no server-side `since` filter; `--since` is enforced client-side plus
  per-account pagination early-stop.
