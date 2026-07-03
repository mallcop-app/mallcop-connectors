# mallcop-connectors

> Data-source connectors for [mallcop](https://github.com/mallcop-app/mallcop) — single-binary ingestors that normalize cloud audit logs into mallcop event JSONL.

## Connectors

Each connector installs as `mallcop-connector-<source>` — namespaced so the
binaries never collide with the real vendor CLIs (`aws`, `gcp`, `okta`, ...)
already on your `$PATH`.

| Binary | Source | Service | Auth | Status |
|---|---|---|---|---|
| `mallcop-connector-aws` | `aws` | AWS CloudTrail | aws-sdk-go-v2 (env/profile) | stable |
| `mallcop-connector-azure` | `azure` | Azure Activity Log | Service principal (OAuth2) | stable |
| `mallcop-connector-gcp` | `gcp` | GCP Cloud Logging | Service account JSON | stable |
| `mallcop-connector-github` | `github` | GitHub Audit Log | GitHub App installation | stable |
| `mallcop-connector-m365` | `m365` | Office 365 Management Activity API | App registration | stable |
| `mallcop-connector-okta` | `okta` | Okta System Log | SSWS token | stable |

Each connector:
- Talks to the real upstream API (no mocks at runtime).
- Paginates with checkpoint cursors so partial runs resume correctly.
- Normalizes output to mallcop's `event.Event` JSONL shape.
- Is independently installable and pipeable.

## Install

The connectors ship with the vendor namespace (`mallcop-connector-<source>`).
This is a **build-output rename only** — the Go source, flags, and stdout JSONL
contract are unchanged (`go build -o mallcop-connector-<source> ./cmd/<source>`).

### Makefile / install.sh (recommended)

```bash
make install                     # build + install to /usr/local/bin
make install PREFIX=$HOME/.local # install to $HOME/.local/bin
make build                       # build to ./dist only
make list                        # print the installed binary names

# or, without make:
./install.sh                     # build + install to /usr/local/bin
PREFIX=$HOME/.local ./install.sh # install to $HOME/.local/bin
DISTONLY=1 ./install.sh          # build to ./dist only
```

### Plain `go build` (single connector)

`go build`/`go install` name a binary after its `cmd/<source>` directory (bare
`aws`, `gcp`, ...), which collides with the vendor CLIs. Build with an explicit
`-o` to get the namespaced name:

```bash
go build -o mallcop-connector-aws ./cmd/aws
# then move it onto your $PATH, e.g.
install -m 0755 mallcop-connector-aws /usr/local/bin/
```

### Release binaries

Pre-built, namespaced binaries for each platform are published on the
[releases page](https://github.com/mallcop-app/mallcop-connectors/releases)
(built via `.goreleaser.yaml`).

> **Note on `go install ...@latest`:** it emits a bare, unnamespaced binary
> (`aws`, `gcp`, ...) named after the `cmd/` directory, so it is **not**
> recommended — it will shadow or be shadowed by the vendor CLIs. Use the
> Makefile, `install.sh`, or the release binaries above.

## Quickstart

### aws

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1          # or --region flag
mallcop-connector-aws --region us-east-1 --since 2024-01-01T00:00:00Z
```

### azure

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_SUBSCRIPTION_ID=...     # or --subscription-id flag
mallcop-connector-azure --subscription-id <id> --since 2024-01-01T00:00:00Z
```

### gcp

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
export GCP_PROJECT_ID=my-project     # or --project flag
mallcop-connector-gcp --project my-project --since 2024-01-01T00:00:00Z
```

### github

```bash
mallcop-connector-github \
  --app-id 12345 \
  --installation-id 67890 \
  --private-key-path /path/to/private-key.pem \
  --org my-org \
  --since 2024-01-01T00:00:00Z
```

### m365

```bash
export M365_TENANT_ID=...
export M365_CLIENT_ID=...
export M365_CLIENT_SECRET=...
mallcop-connector-m365 --since 2024-01-01T00:00:00Z
```

### okta

```bash
export OKTA_DOMAIN=myorg.okta.com
export OKTA_API_TOKEN=...
mallcop-connector-okta --since 2024-01-01T00:00:00Z
```

## Output format

Each connector writes one JSON object per line to stdout:

```json
{"id":"abc123","source":"github","type":"org.member_added","actor":"alice","timestamp":"2024-01-15T10:30:00Z","org":"my-org","payload":{...}}
```

Pipe to `mallcop scan` or any JSONL processor.

## Configuration

Connector auth is env-driven. See [`cmd/<name>/README.md`](cmd/) for the specific environment variables, required IAM/API permissions, and known limitations of each connector.

## Resuming from a checkpoint

All connectors accept a `--cursor` flag. On success, the last cursor value is printed to stderr. Pass it back on the next run to resume without duplicates:

```bash
mallcop-connector-aws --region us-east-1 2>cursor.txt | mallcop scan
mallcop-connector-aws --region us-east-1 --cursor "$(cat cursor.txt)"
```

## Migrating from Python mallcop connectors

The Go connectors aim for behavioral parity with the Python connectors of the same name. Two changes worth noting:

- **Okta and GCP are new in Go** — no Python counterpart.
- **Not yet ported from Python**: `container_logs`, `supabase`, `vercel`, `openclaw_config_drift`. If you depend on these, stay on Python mallcop 0.5.x or contribute a Go port upstream.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
