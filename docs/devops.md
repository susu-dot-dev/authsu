# DevOps: tooling and conventions

## Principles

- **One entrypoint for everything.** The `Makefile` is the only interface to dev tooling. CI runs the same `make` targets a developer runs locally. No logic lives in workflow YAML that cannot be run locally.
- **Production is the default build.** Anything insecure or dev-only is opt-in via a build tag and not wired into the production binary.
- **Fail closed, fail loudly.** Gates are strict from the start. Loosening a gate requires a written reason in the commit.
- **Minimal supply chain.** This is a security-sensitive project. Prefer the standard library and first-party tooling, pin everything, and verify what is downloaded.
- **Reproducible locally.** Tool versions are pinned in one file and read by both the Makefile and CI.

## Stack

authsu is a Go service compiled with TinyGo to WebAssembly and run as a Cloudflare Worker via [`workers-go`](https://github.com/syumai/workers-go). Storage is D1 (SQLite). Wrangler (Node) is the only JavaScript tooling: it builds the Worker bundle, runs it locally under `workerd`, applies D1 migrations, and deploys.

## Task runner

`make` is the single entrypoint. `make help` lists targets. Targets named below are the contract; their recipes may change.

| Target | Purpose |
|---|---|
| `make setup` | Install JS deps (`npm ci`) and verify pinned tool versions |
| `make fmt` / `make fmt-check` | Format / verify formatting |
| `make lint` | golangci-lint |
| `make test` | Unit tests |
| `make coverage` | Unit tests with the 100% coverage gate |
| `make size` | Wasm size report and budget gate |
| `make build` | Production build |
| `make build-dev` | Dev build (all dev flags on) |
| `make dev` | Run the Worker locally with local D1 |
| `make test-e2e` / `make test-e2e-prod` | End-to-end tests against `wrangler dev` |
| `make check` | Fast pre-commit gate (no wasm build, no e2e) |
| `make ci` | Everything CI runs |
| `make deploy` | Production deploy, only ever with no flags, gated on checks |

## Repository layout

```
cmd/worker/             Worker entrypoint and build-time wiring (tiny; no logic)
  main.go               //go:build js && wasm   calls app.Run(deps())
  main_host.go          //go:build !(js && wasm) host stub so `go build ./...` works
  deps_<flag>_on.go     //go:build <flag>   selects the dev implementation
  deps_<flag>_off.go    //go:build !<flag>  selects the safe implementation
internal/app/           Builds the HTTP handler from a Deps struct; host-testable
internal/<domain>/      Domain packages (service, store interface, SQL store, ...)
internal/httpapi/       Routes, handlers, JSON helpers
e2e/                    Black-box tests against `wrangler dev` (build tag `e2e`)
migrations/             D1 migrations, NNNN_name.sql
scripts/                Shell scripts invoked by the Makefile
docs/                   Design rationale and this document
tools.env               Pinned tool versions and checksums (see Tool versions)
```

### Thin entrypoint, logic in `internal/app`

`cmd/worker/main.go` imports `workers-go`, which exists only for `js/wasm`, so it can never run in host unit tests. It is therefore kept to a few lines: obtain the D1 binding, call `app.Run(deps())`. Everything else (config, wiring, routing) lives in `internal/app` and is tested on the host against fakes. `cmd/worker` is excluded from coverage and is proven by the e2e tests.

## Code categories

| Category | Where | Counts toward coverage |
|---|---|---|
| Production code | non-`_test.go` files under `internal/` | Yes |
| Tests | `*_test.go` | No (excluded by the toolchain) |
| Test fakes and helpers | `*_test.go` only, beside the tests that use them (`fake_*_test.go`) | No |
| Wasm-only glue | `cmd/worker/` | No (explicit exclusion) |
| Dev tooling | `scripts/` (Go programs such as `scripts/covgate`) | No (explicit exclusion) |
| End-to-end tests | `e2e/` under build tag `e2e` | No |

Rules:

- **Test code lives only in `_test.go` files.** The Go toolchain never links these into a binary and never counts them in coverage, so there is nothing to configure or exclude. There are no shared `testutil` packages.
- **Consumers define small interfaces** (`Store`, `Authenticator`, ...) so each package's tests carry a tiny fake of exactly what they need. Cross-package fake duplication is accepted as the cost of this rule.
- **Tests are table-driven** with named cases and `t.Run`, and use the external test package (`foo_test`) unless internal access is genuinely required.
- **Time, randomness, and I/O are injected** (a clock, an `io.Reader` for entropy, a `*sql.DB`), so every branch is reachable from a test.

## Formatting and linting

- **Format:** `gofmt -s`. `make fmt-check` fails on any diff.
- **Linter:** [golangci-lint](https://golangci-lint.run) v2, driven by a committed `.golangci.yml`, pinned in `tools.env`.
- **Posture: maximal.** Start from `default: all` and disable linters one by one, each with a comment giving the reason (conflicts with another linter, does not apply to TinyGo, etc.). The disable list is chosen and reviewed in the lint commit.
- **Linted configurations:** the host build with production tags (no tags) and the host build with every dev flag on. The `js/wasm` target is not linted wholesale; only `cmd/worker` is vetted and linted under `GOOS=js GOARCH=wasm`, because it is the only code that exists solely there. Everything else is exercised by e2e.
- `//nolint` directives must name the linter and give a reason (enforced by `nolintlint`).

### Why not test or lint under `js/wasm`

`GOOS=js GOARCH=wasm` is the compile target of the Worker. The standard toolchain can compile and vet for it, but cannot practically run tests there: that needs a Node-based wasm test runner rather than `workerd`, and it would not exercise the Cloudflare bindings anyway. Logic is therefore kept out of wasm-only files (thin `main.go`) and tested on the host. The real TinyGo build is exercised by e2e.

## Unit tests and coverage

- `go test -race ./...` with the host toolchain, run with no tags (the production configuration).
- **100% statement coverage of all production code.** Not a total over most of it, and not `internal/` only: every non-test, non-excluded line.
- **Exclusions are explicit and reviewed**, never a path-based hiding place:
  - `cmd/worker/` (wasm-only glue, covered by e2e) and `scripts/` (dev tooling) are excluded by the coverage script. Scripts are still linted and formatted, but tests for them are optional.
  - Individual unreachable statements are marked with a comment of the form:

    ```go
    // coverage:ignore: crypto/rand.Read never fails on supported platforms
    ```

    The marker applies to the statement or block that follows. A reason after the second colon is mandatory. Our coverage script drops marked lines from the profile, fails on a marker with no reason, and prints the full list of ignores in CI output so each one is visible in review.
  - Before reaching for `coverage:ignore`, refactor to make the branch reachable (inject the reader, the clock, the failing dependency).
- Coverage is computed from `go test -coverprofile` (`-covermode=atomic`) over `./...` and checked by `scripts/covgate` (`make coverage`), which reads the profile, applies the exclusions above, and fails below 100%. It prints every honoured `coverage:ignore` and fails on a marker with no reason or one that is not directly above a statement.

### Coverage and feature flags (first iteration)

Dev-only implementations are not tagged (see [Feature flags](#feature-flags)), so every implementation compiles and is tested in the single no-tag run. Only the 3-line wiring files in `cmd/worker/` are tagged, and they are excluded from coverage. As a result, the first iteration needs no profile merging across tag configurations. If a future change puts real logic under a build tag, revisit this section (merge the no-tag and flags-on profiles, or require 100% per configuration) before merging it.

## Feature flags

A flag is a Go build tag. The default build is production with every flag off.

**Pattern: interface plus build-time dependency injection.**

1. Behaviour that varies is an interface (for example `Authenticator`) with ordinary, fully tested implementations, including the dev-only ones, in untagged files.
2. `internal/app` accepts a `Deps` struct holding one implementation per interface.
3. `cmd/worker` selects implementations with a pair of tiny tagged files per flag:
   - `deps_<flag>_off.go`: `//go:build !<flag>`: sets the safe field value.
   - `deps_<flag>_on.go`: `//go:build <flag>`: sets the dev-only field value.

   Each flag's pair sets exactly one `Deps` field, so flags compose independently.
4. The linker removes code unreachable from `main`, so a dev-only implementation that production wiring never references is not in the production binary. This was verified empirically for the standard Go and TinyGo toolchains: a string literal inside an untagged, unreferenced implementation is absent from the production wasm and present in the `-tags` build. This is a linker property rather than a language guarantee, so production code must never reference a dev-only type (see the rules below).

**Rules:**

- Flags are compile-time only. Never read a flag from the environment, a binding, or a request.
- Production code outside `cmd/worker` must never reference a dev-only type.
- `make deploy` refuses to run if any flag is set.

**Current flags:**

| Tag | Interface | Dev behaviour | Wiring |
|---|---|---|---|
| `debug_routes` | `diag.Diagnostics` | `diag.On` serves `GET /debug/info` | `cmd/worker/deps_debug_routes_{on,off}.go` |

`debug_routes` is a placeholder flag that exists to exercise the mechanism end to end; replace or remove it when a real flag (for example an insecure admin authenticator) lands. A nil `Deps` field always means the safe production behaviour.

**Mechanics:**

- `DEV_TAGS` in the Makefile lists every flag a dev build turns on. `make dev` and `make build-dev` use it; `make deploy` never does.
- Tags reach TinyGo through the `GO_TAGS` environment variable, via `package.json`. Running `npx wrangler dev` directly sets no tag, so it serves the production build; use `make dev` for the dev build.
- `make vet` and `make lint` run with and without `DEV_TAGS`, on the host and for the js/wasm entrypoint, so both wirings are type-checked and linted. `cmd/worker/main_host.go` builds the same `Deps` as the Worker for this reason.
- Adding a flag: add the interface and its implementations (untagged, tested), a `Deps` field, a `deps_<flag>_{on,off}.go` pair, and add the tag to `DEV_TAGS`. The wiring files are in `cmd/worker`, which is excluded from coverage; e2e proves the prod build does not serve dev behaviour.

## Wasm size budget

The Cloudflare Workers size limit (64 MiB uncompressed, with no compressed-size limit) is far above what this Worker needs, so the budget is a regression guard rather than a platform-limit guard. Binary size drives parse and startup cost, and a jump is the earliest signal that a heavy package got linked in by accident (for example, using `encoding/json` adds roughly 700 KB under TinyGo).

`make size` (`scripts/check-size.sh`):

- Builds the production wasm with TinyGo (`-no-debug`, no tags).
- **Fails if the raw size exceeds `MAX_WASM_BYTES`** (currently 1,400,000 bytes, about 1.5x the initial size of 923 KB). The budget is raised deliberately, in the PR that justifies it, by editing the default in `scripts/check-size.sh`.
- **Fails if a forbidden package is linked in:** `testing` and `net/http/httptest`, matched as whole import paths.
- Reports, without gating: gzip size, the top packages by flash, and which watched packages are linked, so a reviewer sees a newly linked heavy dependency. The watch list (`encoding/json`, `database/sql`, `crypto/tls`, `log/slog`) holds only heavy packages that are not in the baseline build. Packages already linked through workers-go and `net/http` (`net/http`, `reflect`, `fmt`, `crypto/x509`, `math/big`) are deliberately left off, since they would always print and hide real changes; add a package to `WATCH` when it is worth noticing.
- Only raw size gates. Wrangler's bundle size (wasm plus JS glue and source map) is not gated.

## D1 migrations

- Migrations are plain SQL files in `migrations/`, named `NNNN_description.sql`, applied in order by Wrangler (`wrangler d1 migrations apply`).
- Migrations are append-only. A migration that has landed on `main` is never edited; changes are new migrations.
- Local development applies migrations to a local persisted D1 state (`.wrangler/state`, git-ignored) via `make dev`; `make db-reset` deletes it.
- **CI verification:** the e2e harness applies every migration to a fresh local D1 on every run, so a broken migration fails CI.
- The D1 `database_id` in `wrangler.jsonc` is a placeholder until the first real deploy. Local dev and e2e do not need a real database.

## End-to-end tests

- Written in Go under `e2e/`, build tag `e2e`, so they are excluded from `go test ./...`.
- The Makefile builds the real Worker (TinyGo to wasm) first. The harness then:
  1. wipes a throwaway state directory,
  2. applies migrations,
  3. starts `wrangler dev --local` in its own process group on a fixed port,
  4. waits for readiness, drives the Worker over HTTP, and kills the process group on exit.
- Run twice: `make test-e2e` against the **dev build** (all flags on) and `make test-e2e-prod` against the **production build**, where dev-only behaviour must be provably unreachable.
- E2E exists for what the host cannot see: TinyGo `net/http` differences (notably `http.ServeMux` never matches method-qualified patterns like `"GET /x"`; use plain paths and dispatch on `r.Method`), the D1 driver, real SQLite behaviour, and Wrangler wiring.
- Dev and e2e use separate state directories so tests never touch data created while developing.

## Continuous integration

GitHub Actions, Linux only (`ubuntu-24.04`). Triggers: push to `main` and pull requests. Concurrency cancels superseded runs on the same ref.

**Supply chain stance:**

- `permissions: contents: read`, `persist-credentials: false`, no secrets, no deploy step.
- Only first-party `actions/*` plus [`golangci/golangci-lint-action`](https://github.com/golangci/golangci-lint-action) are allowed. All are pinned to full commit SHAs with the version in a trailing comment. Other third-party actions need explicit maintainer approval. TinyGo is **not** installed via a third-party action.
- TinyGo is installed by `scripts/install-tinygo.sh` (`npm run setup:ci`): it downloads the official release into `.tools/tinygo` (git-ignored), verifies it against the SHA-256 pinned in `tools.env`, and is idempotent. `npm run build` puts `.tools/tinygo/bin` on `PATH` when present, so `npm run setup:ci && npm run build` works without any PATH plumbing. CI and Cloudflare Workers Builds use the same script.
- Go comes from `go.mod` via `actions/setup-go`. Node is 22, and dependencies install with `npm ci --ignore-scripts`.
- `golangci-lint` is installed by `golangci/golangci-lint-action` in `install-only` mode, with the version taken from `tools.env`; `make lint` does the actual run, so CI and local use the same command. The action downloads the binary without a checksum pin, which is an accepted trade-off for this one third-party action.
- CI loads `tools.env` into the job environment (`cat tools.env >> "$GITHUB_ENV"`), so versions and checksums are never duplicated in the workflow.

**Jobs:** a `check` job that runs `make ci` (`make check`, which is tool versions, format, tidy check, vet, lint, unit tests and the coverage gate, plus the wasm size budget; later also govulncheck) and an `e2e` job (dev and prod builds) once the e2e harness exists. Both are required status checks on `main` via branch protection.

## Cloudflare Workers Builds

Workers Builds clones the repository and runs the dashboard build and deploy commands. Its image has Go (fetched per `go.mod`) and Node but no TinyGo, and it ignores the `build` section of `wrangler.jsonc`. Configure the project (Settings > Build) with:

| Setting | Value |
|---|---|
| Build command | `npm run setup:ci && npm run build` |
| Deploy command | `npx wrangler deploy` |

TinyGo's version and checksum come from `tools.env`, so bumping it there updates CI and Cloudflare together.

## Tool versions

`tools.env` is the single source of truth for pinned tool versions and checksums (TinyGo, golangci-lint, and any others). It is read by:

- the Makefile, so `make setup` / `make check-tools` fail when a local tool differs from the pin, and
- the CI workflow, which exports it into the job environment.

Bumping a tool means editing `tools.env` only. Checksums for downloaded tools are updated by hand in the same commit, and that commit states where the checksum was obtained.

## Dependency automation and vulnerability scanning

- **Dependabot** for the `gomod`, `npm`, and `github-actions` ecosystems, grouped, weekly. It also keeps the pinned action SHAs current.
- **govulncheck** is pinned through a `tool` directive in `go.mod` (so it is version-locked by `go.sum` and never `@latest`) and runs on pull requests and on a weekly schedule.
- `go mod tidy -diff` runs in CI; `go.mod` and `go.sum` must be tidy.
- Tool checksums in `tools.env` are not covered by Dependabot and are bumped manually.
