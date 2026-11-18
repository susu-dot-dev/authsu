# authsu

A passkey-only authentication service: Go compiled with TinyGo to WebAssembly, running as a Cloudflare Worker, with D1 for storage. There is no TypeScript and no frontend framework; Wrangler (Node) is the only JavaScript tooling.

## Where to look

Read only what the task needs. The first five are generic scaffolding and hold no product nouns.

| If you are... | Read |
|---|---|
| Setting up, choosing which `make` target to run, or unsure of the workflow | [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) |
| Adding or moving a package, a route, a handler, an inbound value, or touching error handling | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Writing or changing tests, fakes, fixtures, e2e, or coverage exclusions | [docs/TESTING.md](docs/TESTING.md) |
| Writing a migration or any SQL, or touching the store | [docs/DATABASE.md](docs/DATABASE.md) |
| Changing lint config, the size budget, dependencies, workflows, or `tools.env` | [docs/CI.md](docs/CI.md) |
| Configuring, migrating, deploying or upkeeping a deployment | [docs/runbook.md](docs/runbook.md) |
| Changing a feature's behaviour | that feature's `docs/*_design.md` (rationale, not spec: when it disagrees with the code about what exists, the code wins) and the package godoc |
| Reviewing code | [docs/REVIEW.md](docs/REVIEW.md) |

Each document says where its own kind of content belongs; [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) has the overall map. Do not add content to a document because it is the closest one: put it with the code (godoc, test comments) or the feature's design doc unless it is a change to a scaffolding principle or convention.

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
| `make dev` | Run the Worker locally on :8787 with a local D1 |
| `make fmt` | Format Go code |

The e2e, and size checks are expensive to run. Minimize the times it must be run by focusing on make check for the dev cycle, and only running make e2e at the end. Save the e2e results to a log file, so you can immediately get logs upon error, rather than having to retry

## Conventions

The full rules, and the reasons, are in the documents listed above. The ones that are easy to get wrong:

- **Test code lives only in `_test.go` files.** Fakes and helpers sit in one fixtures file per package, beside the tests that use them. There are no shared test packages. Consumers define small interfaces so each package's tests carry a tiny fake, and tests drive the real route boundary rather than calling handlers directly.
- **100% statement coverage of production code.** Make branches reachable by injecting the clock, entropy, and I/O. Only when that is impossible, mark a statement with `// coverage:ignore: <reason>` on the line directly above it; a missing reason or a misplaced marker fails the gate.
- **Logic stays out of `cmd/worker`.** It is wasm-only and cannot be unit-tested on the host, so it only adapts platform resources (the D1 batch, the environment, logging) and hands them to `internal/app`.
- **Imports flow downward only.** Layers are `app` > features > `auth` > `store` > `input` > foundation (see `docs/ARCHITECTURE.md`). Skipping a layer is fine; importing upward or sideways is not, and feature packages never import each other. `depguard` in `.golangci.yml` enforces it and is the source of truth: place a new package in a layer there.
- **Parse inbound values, do not validate them.** Anything a client sends is parsed once into an `internal/input` type that only its parser can construct (a struct with an unexported field, never `type X string`). Parsers refuse and never rewrite (no trim, case-fold or normalise), and their bounds sit beside the type and must fit the migration CHECKs. Add a new kind of inbound value there, not in a handler.
- **All SQL lives in `internal/store`**, one method per atomic operation, every read and write through its one batch port. Feature code never holds a query or a `*sql.DB`; put authorization conditions in the write itself, never in a read before it.
- **Routes declare their access.** A feature exports `Routes(Deps) []auth.Route`, and each route says its credential and requirement (`Admin` or none) explicitly; `internal/auth` enforces them before the handler runs. A feature's tests include a route-declaration table.
- **No degraded mode.** Every `Deps` field is required and `Routes` panics on a missing one; `internal/app` validates completeness at start. Do not add nil checks that turn a missing dependency into a 503.
- **No "mint" wording.** Use create, issue and the like in identifiers, comments, error codes, test names and docs (`CreateSession`, `session_create_failed`).
- **There is one build.** No dev/prod variants, build tags for behaviour, or build-time dependency injection. The only build tags are `e2e` (for `e2e/`) and the `js && wasm` split of `cmd/worker`. Do not add a feature that exists only in some builds.
- **TinyGo's `net/http` differs from Go's.** `http.ServeMux` never matches method-qualified patterns such as `"GET /x"`; register plain paths and dispatch on `r.Method`. Host tests cannot catch this, so e2e tests are how you find out.
- **The linter is strict (nearly every linter enabled).** Fix the code rather than adding `//nolint`; when a suppression is genuinely needed it must name the linter and give a reason.
- **Migrations are append-only.** Never edit a migration that has landed on `main`; add a new one. Production migrations are applied by hand (see `docs/runbook.md`).
- **Do not add third-party GitHub Actions** without maintainer approval, and pin any action to a full commit SHA.
- **Code reviews must follow [docs/REVIEW.md](docs/REVIEW.md).** Before starting on tasks, agents should also read it to shape their behavior.
