# Contributing to mallcop-connectors

Thanks for your interest in contributing!

## How to contribute

1. **Open an issue first.** Before writing code, open an issue describing what you want to change and why. We'll discuss scope and approach before you invest time in a PR.

2. **Fork and branch.** Fork the repo, create a branch from `main`, and make your changes.

3. **Write tests.** All code changes require tests. Run `go test ./...` before submitting.

4. **Run the full suite.** Tests must pass before you submit a PR.

5. **Submit a PR.** Reference the issue number. Keep PRs focused — one change per PR.

## What we're looking for

- Bug fixes with reproducing test cases
- New connectors for cloud platforms (see existing connectors for the pattern)
- Improvements to checkpoint cursor handling or pagination
- Documentation improvements

## What we're NOT looking for

- Large refactors without prior discussion
- Features that add external service dependencies beyond the target connector's SDK
- Changes that weaken the connector's security properties (cursor HMAC, input validation)

## Development setup

```bash
git clone https://github.com/mallcop-app/mallcop-connectors.git
cd mallcop-connectors
go test ./...
```

## Running a specific connector locally

```bash
go run ./cmd/aws --region us-east-1 --since 2024-01-01T00:00:00Z
```

See each connector's `cmd/<name>/README.md` for auth setup.

## Adding a new connector

1. Create `cmd/<name>/main.go` following the pattern in an existing connector.
2. Add the connector to the table in the root `README.md`.
3. Create `cmd/<name>/README.md` with env vars, required permissions, and a sample event.
4. Write unit tests in `cmd/<name>/<name>_test.go`.
5. Integration tests (against the real API) go in `cmd/<name>/<name>_integration_test.go` — use `//go:build integration` so they don't run in CI by default.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.
