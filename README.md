# authsu

A self-hosted, passkey-only authentication service that runs as a Cloudflare Worker. Accounts have no usernames or passwords: an account is a passkey, and the only way to get one is an invitation from an admin.

It is written in Go, compiled to WebAssembly with [TinyGo](https://tinygo.org), and run on Cloudflare Workers through [`workers-go`](https://github.com/syumai/workers-go). Data lives in D1 (SQLite).

> **Status:** early. The tooling and project structure are in place; the invitation, registration and first-run flows described in the design docs are mostly not built yet. Today the Worker serves `/healthz` and `GET /api/first-run`, the first-run status check.

## Requirements

| Tool | Version |
|---|---|
| Go | the version in `go.mod` |
| TinyGo | pinned in `tools.env` |
| golangci-lint | pinned in `tools.env` |
| Node.js and npm | Node 22.12 or later (Wrangler is the only JavaScript tooling) |
| make | any |

`make check-tools` fails if your TinyGo or golangci-lint differs from the pin. On Linux amd64, `npm run setup:ci` installs the pinned TinyGo into `.tools/` for you.

## Quick start

```console
make setup   # npm ci, go mod download, verify tool versions
make setup-local  # once: create .dev.vars with the local secrets, if missing
make dev     # migrate the local database and serve the Worker on :8787
curl http://localhost:8787/healthz
make check   # fast gate: format, tidy, vet, lint, tests, coverage
make ci      # everything CI runs, including e2e; slow, run once before committing
make help    # every target
```

Run the Worker through `make dev`, not `npx wrangler dev`: the Makefile applies migrations and overrides the relying party with `localhost` values, which Wrangler on its own does not.

**Schema changes before the first production release:** nothing has shipped yet, so every schema change goes into the existing `migrations/0001_schema.sql`, edited in place (run `make db-reset` to pick it up locally). Do not add `0002` and later migrations until we start shipping to production; the append-only migration rules in [docs/DATABASE.md](docs/DATABASE.md) and [docs/runbook.md](docs/runbook.md) apply from that point on.

## Documentation

- Contributing, the scaffolding: how the project is built, checked, tested and shipped. Start with [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md), which links the rest:
  - [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): code structure and layering
  - [docs/TESTING.md](docs/TESTING.md): unit, coverage and e2e conventions
  - [docs/DATABASE.md](docs/DATABASE.md): migrations and D1 conventions
  - [docs/CI.md](docs/CI.md): lint, size budget, CI and supply chain
- [docs/runbook.md](docs/runbook.md): operating a deployment: configuration, migrations, deploying and upkeep.
- Design rationale (why, not a spec):
  - [docs/invitations_design.md](docs/invitations_design.md)
  - [docs/registration_design.md](docs/registration_design.md)
  - [docs/login_design.md](docs/login_design.md)
  - [docs/first_run_design.md](docs/first_run_design.md)

## License

[MIT](LICENSE)
