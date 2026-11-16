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
make dev     # migrate the local database and serve the Worker on :8787
curl http://localhost:8787/healthz
make check   # fast gate: format, tidy, vet, lint, tests, coverage
make ci      # everything CI runs, including e2e; slow, run once before committing
make help    # every target
```

Run the Worker through `make dev`, not `npx wrangler dev`: the Makefile builds with the dev flags and applies migrations, while Wrangler on its own builds the production configuration.

## Documentation

- [docs/devops.md](docs/devops.md): how the project is built, checked, tested and shipped. This is the authority on tooling and conventions; start here before changing anything.
- Design rationale (why, not a spec):
  - [docs/invitations_design.md](docs/invitations_design.md)
  - [docs/registration_design.md](docs/registration_design.md)
  - [docs/first_run_design.md](docs/first_run_design.md)

## License

[MIT](LICENSE)
