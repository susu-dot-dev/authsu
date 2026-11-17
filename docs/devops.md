# DevOps: tooling and conventions

This is the generic scaffolding: how code is built, tested, gated and shipped. It says nothing about what authsu does, and it should rarely change. Product behaviour belongs in the `*_design.md` files and package godoc; procedures for operating a deployment are in [runbook.md](runbook.md). The Makefile, `.golangci.yml`, the workflow YAML and the scripts are the precise reference, so this document gives the shape and the reasons and does not repeat them.

## Principles

- **One entrypoint.** The `Makefile` is the only interface to dev tooling. CI runs the same `make` targets a developer runs, so nothing in workflow YAML is unrunnable locally.
- **One build.** There are no dev and production variants of the binary: what runs locally, in e2e and in production is the same wasm, so what is tested is what is deployed.
- **Fail closed, fail loudly.** Gates are strict from the start. Loosening one needs a written reason in the commit.
- **Minimal supply chain.** Prefer the standard library and first-party tooling, pin everything, verify what is downloaded.
- **Reproducible locally.** Tool versions are pinned in one file, `tools.env`, read by both the Makefile and CI.

## Stack

Go compiled with TinyGo to WebAssembly, run as a Cloudflare Worker through [`workers-go`](https://github.com/syumai/workers-go), with D1 (SQLite) for storage. Wrangler (Node) is the only JavaScript tooling: it bundles the Worker, runs it locally under `workerd`, applies migrations and deploys.

## Workflow

`make help` lists the targets and is the contract; recipes may change.

- **While working,** run the narrowest thing that covers the change (`go test ./internal/<pkg>`, `make fmt`, `make lint`), then `make check` once the change is ready for a broader look. `make check` is fast and does no wasm build.
- **Before committing,** run `make ci` once, as the last step. It is everything CI runs. It is slow, mostly because of one TinyGo build (no incremental compilation, nearly all single-threaded); make skips that build when no Go source or build input changed.
- **Do not** run `make ci` after every edit, after documentation-only changes, or to re-check one target. If it fails, fix the cause with the narrow target that reproduces it, then run `make ci` once more.
- Run the Worker with `make dev`, not bare `npx wrangler dev`, which skips the migrations and the localhost relying party overrides.

## Code structure

- **`cmd/worker` is thin, wasm-only wiring.** It imports `workers-go`, which exists only for `js/wasm`, so it cannot run in host unit tests. It obtains platform resources and hands them to `internal/app`; it holds no logic and is excluded from coverage.
- **Logic lives in host-testable `internal/` packages**, tested against fakes. `internal/app` builds the handler from a `Platform`.
- **Handlers are pure** (`Request` to `Result[Response]`). One boundary, `internal/httpapi`, does everything that touches HTTP, and `internal/apierr` classifies failures so no cause or internal detail reaches a client. Their package docs are the contract.
- **TinyGo's `net/http` differs from Go's** (for example, `ServeMux` never matches method-qualified patterns). Host tests cannot catch this, which is a large part of why e2e tests exist.
- **Why not test or lint under `js/wasm`.** The toolchain can compile and vet for it but cannot practically run tests there, and `workerd` would not be the runner. So logic stays out of wasm-only files, only `cmd/worker` is vetted and linted for `js/wasm`, and the real TinyGo build is exercised by e2e.

## Testing

- **Test code lives only in `_test.go` files.** Fakes and helpers sit beside the tests that use them; there are no shared test packages. The toolchain never links these into a binary or counts them in coverage, so nothing needs configuring.
- **Consumers define small interfaces** so each package's tests carry a tiny fake of exactly what they need. Duplication across packages is the accepted cost.
- **Tests are table-driven**, with named cases and `t.Run`, in the external test package unless internal access is genuinely needed.
- **Time, randomness and I/O are injected**, so every branch is reachable from a test.
- **100% statement coverage of production code**, enforced by `scripts/covgate` (`make coverage`). Exclusions are explicit: `cmd/worker` and `scripts/` are excluded by the gate, and an individual unreachable statement is marked `// coverage:ignore: <reason>` on the line directly above it. A missing reason or misplaced marker fails the gate, and every honoured ignore is printed in CI. Before using one, refactor to make the branch reachable.
- **End-to-end tests** (`e2e/`, build tag `e2e`) drive the real Worker under `wrangler dev` with a simulated D1. They exist for what the host cannot see: TinyGo differences, the D1 driver, real SQLite behaviour and Wrangler wiring. The `Makefile` decides the build and the harness only runs it. Dev and e2e use separate state directories. Details are in the harness and test file comments.

## Lint, size and dependencies

- **Format** is `gofmt -s`. **Lint** is golangci-lint v2 with a posture of maximal: every linter on, disabled one by one with a stated reason in `.golangci.yml`. Fix the code rather than adding `//nolint`; a needed suppression must name the linter and give a reason.
- **Wasm size is budgeted** by `make size` as a regression guard, not a platform-limit guard: a jump is the earliest sign a heavy package was linked by accident (`encoding/json` is the usual suspect under TinyGo). The budget is raised deliberately, in the PR that justifies it, by editing the default in `scripts/check-size.sh`. Packages that must never be linked (`testing`, `net/http/httptest`) fail the check.
- **`go.mod` and `go.sum` must be tidy.** Dependabot keeps `gomod`, `npm` and `github-actions` current, and a scheduled workflow runs `govulncheck` and reports pins Dependabot cannot update (see [runbook.md](runbook.md)).

## Database

- Migrations are plain SQL in `migrations/`, named `NNNN_description.sql` and applied in order by Wrangler. They are **append-only**: one that has landed on `main` is never edited, and a change is a new migration.
- **No `CHECK` on open-ended values.** A set of values that grows with the code is validated in Go, because changing a `CHECK` in SQLite means rebuilding the table. `CHECK` is for invariants that will not change.
- **JSON columns are `TEXT`**, not `BLOB`: SQLite's JSONB is an internal format Go cannot write, and the blob path for JSON text is documented as bug compatibility.
- **D1 has no interactive transactions.** Its one atomic primitive is a batch, and `internal/atomic` holds the host-compilable half of it; a check-then-insert would race, so authorization conditions belong in the write itself. See that package's docs.
- **Go code never knows which database it talks to.** The Worker is bound as `DB` in every environment, and the e2e harness applies every migration to a fresh local database, so a broken migration fails CI.
- **Remote migrations are applied by hand.** Neither CI nor Workers Builds applies them. See [runbook.md](runbook.md).

## Continuous integration and supply chain

GitHub Actions, Linux only. CI runs the same `make` targets as local use, split into parallel jobs (lint, test, build, then size and e2e from the one build) so wall time is the slowest job, not the sum.

- **One required check.** An aggregate `CI` job depends on every other job and fails unless all succeeded, with cancelled and skipped counting as failures. Branch protection requires only that, so adding a job means adding it to the aggregate's `needs`, which is not gated otherwise. A target added to `make ci` or `make check` must also be added to the matching job.
- **Least privilege.** Read-only permissions, no persisted credentials, no secrets and no deploy step. Deploying is done by Cloudflare Workers Builds, not by CI.
- **Actions are pinned and few.** Only first-party `actions/*` plus `golangci/golangci-lint-action` are allowed, each pinned to a full commit SHA with the version in a trailing comment. Other third-party actions need maintainer approval. Toolchain setup is the local composite action `.github/actions/setup`.
- **Downloads are verified.** TinyGo is installed by `scripts/install-tinygo.sh` against the SHA-256 in `tools.env`, on every run, including when the tarball came from a cache. CI caches only that tarball, never an extracted tree: any pull request can write a cache, so an extracted tree would be executed unchecked.
- **The build artifact is trusted only within a run.** The Worker is built once and shared with the `size` and `e2e` jobs as a workflow artifact, which is created and consumed inside one run by jobs on the same commit. Never download an artifact from another run or workflow, publish it, or add a cross-run cache of `build/`.
- **Versions are in `tools.env`.** CI loads it into the job environment, so versions and checksums are never duplicated; keep it to plain `KEY=value` lines. Bumping a tool edits that file only, with the checksum's source named in the commit.
- **`PREBUILT=1`** makes `size` and `e2e` fail if `build/` is missing or stale instead of rebuilding, for jobs that have no TinyGo. Locally, leave it unset.
