# authsu

A passkey-only authentication service: Go compiled with TinyGo to WebAssembly, running as a Cloudflare Worker, with D1 for storage. There is no TypeScript and no frontend framework; Wrangler (Node) is the only JavaScript tooling.

## Where to look first

- **[docs/devops.md](docs/devops.md) is the authority** on tooling, testing, CI and conventions: the generic scaffolding, with nothing specific to what authsu does. Read the relevant section before changing build, test, lint, CI or flag code.
- **[docs/runbook.md](docs/runbook.md)** covers operating a deployment: configuration, migrations, deploying, upkeep.
- `docs/*_design.md` explain why invitations, registration and first-run are shaped as they are. They are rationale, not specs: when they disagree with the code about what exists, the code wins.

## Where documentation goes

Ask whether a statement is about the generic scaffolding or about the product.

- **Scaffolding** (how code is built, tested, gated, shipped; the handler and error contract; the flag mechanism): `docs/devops.md`, and only when a principle or convention changes. Feature work should not need to touch it. It holds no product nouns (passkeys, sessions, invitations) and no inventories such as package lists, flag tables or current sizes: the code is the source for those.
- **Product behaviour and its rationale** (what a feature does, its configuration, its failure codes, why it is shaped as it is): that feature's `docs/*_design.md`, and the package godoc beside the code.
- **Procedures for operating a deployment**: `docs/runbook.md`.
- **How a specific test works**: comments in the test file.

## Cloudflare: check current docs

Your knowledge of Cloudflare Workers, D1 and Wrangler may be out of date. Retrieve current documentation before any Workers, D1 or Wrangler task, rather than relying on memory.

- https://developers.cloudflare.com/workers/ and https://developers.cloudflare.com/d1/
- MCP: `https://docs.mcp.cloudflare.com/mcp`
- Limits and quotas: the product's `/platform/limits/` page, e.g. `/workers/platform/limits/`
- Errors (including Error 1102, CPU or memory exceeded): https://developers.cloudflare.com/workers/observability/errors/

## Commands

The `Makefile` is the only entrypoint; CI runs the same targets. `make help` lists them.

| Command | Purpose |
|---|---|
| `make check` | Fast pre-commit gate: tool versions, format, tidy, vet, lint, unit tests, 100% coverage |
| `make ci` | Everything CI runs: `check`, the wasm size budget, and the e2e run |
| `make dev` | Run the Worker locally on :8787 with dev flags and a local D1 |
| `make fmt` | Format Go code |

Run the Worker with `make dev`. Bare `npx wrangler dev` builds the production configuration (no dev flags, no migrations).

## Conventions

The full rules, and the reasons, are in `docs/devops.md`. The ones that are easy to get wrong:

- **Test code lives only in `_test.go` files.** Fakes and helpers sit beside the tests that use them. There are no shared test packages. Consumers define small interfaces so each package's tests carry a tiny fake.
- **100% statement coverage of production code.** Make branches reachable by injecting the clock, entropy, and I/O. Only when that is impossible, mark a statement with `// coverage:ignore: <reason>` on the line directly above it; a missing reason or a misplaced marker fails the gate.
- **Logic stays out of `cmd/worker`.** It is wasm-only and cannot be unit-tested on the host, so it only wires platform resources into `internal/app`.
- **Feature flags are build tags with build-time dependency injection.** Behaviour that must be absent from production is an interface with ordinary, tested implementations; tagged files in `cmd/worker` only choose which one to wire (see `docs/devops.md`, "Feature flags"). Production code must never reference a dev-only type. Never read a flag from the environment or a request.
- **TinyGo's `net/http` differs from Go's.** `http.ServeMux` never matches method-qualified patterns such as `"GET /x"`; register plain paths and dispatch on `r.Method`. Host tests cannot catch this, so e2e tests are how you find out.
- **The linter is strict (nearly every linter enabled).** Fix the code rather than adding `//nolint`; when a suppression is genuinely needed it must name the linter and give a reason.
- **Binary size is gated.** Linking a heavy package such as `encoding/json` can add hundreds of KB under TinyGo and will fail `make size`. Raise the budget deliberately, in the PR that justifies it.
- **Migrations are append-only.** Never edit a migration that has landed on `main`; add a new one. Production migrations are applied by hand (see `docs/runbook.md`).
- **Do not add third-party GitHub Actions** without maintainer approval, and pin any action to a full commit SHA.
