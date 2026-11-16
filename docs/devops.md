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
| `make vuln` | govulncheck (pinned); scheduled in CI, not part of `make ci` |
| `make size` | Wasm size report and budget gate (builds `build/` if stale) |
| `make build` | Production build into `build/`, skipped when `build/` is up to date |
| `make build-dev` | Dev build (all dev flags on) |
| `make dev` | Run the Worker locally with local D1 |
| `make config-get` / `config-set-vars` / `config-set-secret` | Read and set `AUTH_HMAC_SECRET` and `RP_ID`, `RP_ORIGIN`, `RP_NAME` (see Secrets and variables) |
| `make test-e2e` | End-to-end tests against the production build under `wrangler dev` |
| `make check` | Fast gate for the edit loop (no wasm build, no e2e) |
| `make ci` | Everything CI runs. Slow: run it once, as the final pass before committing |
| `make deploy` | Production deploy, only ever with no flags, gated on checks |

### Which target when

`make ci` is slow mostly because of one TinyGo build (about 20 seconds, nearly all of it single-threaded; TinyGo has no incremental compilation). `size` and `test-e2e` share that one `build/`, and make skips it when no Go source, `go.mod`, `go.sum`, `package.json` or `tools.env` changed, so a repeat run after editing only tests, migrations or docs does not rebuild. Do not use `make ci` as a save-and-check loop.

- **While working:** run only the narrowest target that covers what you changed, and `make check` once a change is ready for a broader look. It is fast and has no wasm build.
  - Go logic: `go test ./internal/...` for the package you are editing, then `make check`.
  - Formatting or lint: `make fmt`, `make lint`.
  - A migration: apply it to a throwaway local database (`npx wrangler d1 migrations apply DB --local --persist-to <tmp dir>`) and exercise it with `wrangler d1 execute`, rather than a full e2e run.
- **Before committing:** run `make ci` once, as the last step, after the change is otherwise finished. If it fails, fix the cause with the narrow target that reproduces it, and run `make ci` once more at the end instead of after each fix.
- **Do not run `make ci` after every edit, after documentation-only changes, or to check that a single target still passes.** `make size` and `make test-e2e` are available on their own for the rare change that needs only one of them (for example, a dependency bump for `size`).

## Repository layout

```
cmd/worker/             Worker entrypoint and build-time wiring (tiny; no logic)
  main.go               //go:build js && wasm   calls workers.Serve(app.NewHandler(...))
  main_host.go          //go:build !(js && wasm) host stub so `go build ./...` works
  deps_<flag>_on.go     //go:build <flag>   selects the dev implementation
  deps_<flag>_off.go    //go:build !<flag>  selects the safe implementation
internal/app/           Builds the HTTP handler from a Deps struct; host-testable
internal/<domain>/      Domain packages (service, store interface, SQL store, ...)
internal/httpapi/       Request/Response, Handler, Serve (the net/http boundary), JSON helpers
internal/atomic/        Statement, Batch and ErrConflict: the host-compilable vocabulary for D1's atomic batch
internal/webauthn/      Strict verification of a passkey registration response (no I/O, no clock)
internal/apierr/        Structured error: Kind (HTTP status), Code, Description, Data, cause
internal/result/        Result[T]: chainable fallible steps (Then, Map, Check, MapErr)
e2e/                    Black-box tests against `wrangler dev` (build tag `e2e`)
migrations/             D1 migrations, NNNN_name.sql
scripts/                Shell scripts invoked by the Makefile
docs/                   Design rationale and this document
tools.env               Pinned tool versions and checksums (see Tool versions)
```

### Thin entrypoint, logic in `internal/app`

`cmd/worker/main.go` imports `workers-go`, which exists only for `js/wasm`, so it can never run in host unit tests. It is therefore kept to a few lines: obtain the D1 binding, call `workers.Serve(app.NewHandler(...))`. Everything else (config, wiring, routing) lives in `internal/app` and is tested on the host against fakes. `cmd/worker` is excluded from coverage and is proven by the e2e tests.

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

## HTTP handlers and errors

Handlers are pure: `func(httpapi.Request) result.Result[httpapi.Response]`. They never see an `http.ResponseWriter`, never pick a status for a failure and never log. `httpapi.Serve(method, logger, handler)` is the single place that touches HTTP:

- It answers any other method with 405 and `Allow`, so handlers do not check methods. Routes are registered through `app`'s router as plain paths (TinyGo's `ServeMux` ignores method-qualified patterns).
- It reads the body (capped at 1 MiB; over the cap is 413 `body_too_large`, any other read failure is Internal `body_read_failed`), calls the handler inside a `recover` (a panic becomes Internal `handler_panic`, so a nil step in a chain still gets the JSON error contract and a log line), and writes `Content-Type`, `Cache-Control: no-store` and the status once.
- It marshals a successful `Response.Body` with `encoding/json`. A body that cannot be marshalled becomes an Internal error.
- A response `Status` outside 200-599 (including the zero value) is an Internal `invalid_status` error rather than a panic in `net/http`.
- It converts a failure with `apierr.As`, passes the request (method, path, query, body) and the full error (cause included) to the injected `Logger`, and sends `{"error":{"code","message","data?"}}`. An error that was never classified, or is `Internal`, is sent as `{"code":"internal","message":"internal error"}` with no data, so causes, SQL and table names never reach a client.

`apierr.Error` carries a `Kind` (selects the status; the zero value `Internal` is the fail-closed default), a stable `Code`, a client-visible `Description`, optional `Data`, and a private cause for logs. `apierr.Wrap(err, kind, code, description)` is nil-safe and first-wins: if an `*apierr.Error` is already anywhere in the chain (found with `errors.AsType`, so `%w` and `errors.Join` work) it is kept, so the innermost classification survives. Do not put secrets in `Description` or `Data`. TinyGo's `runtime.Callers` returns no frames on wasm, so errors carry no stack; add context by wrapping with `fmt.Errorf("verb noun: %w", err)`.

Every failure should be a classified `apierr.Error` with its own `Code`; Internal (500) is the fail-closed fallback for the genuinely unknown, not a default to reach for. A database that errors is `Unavailable` (503) with a code naming the step (`first_run_users_check_failed`), a fixed client-safe description, and the driver error as the cause. The `Code` is what a log search or alert keys on, so give each failing step its own. Descriptions are fixed text, never `err.Error()`. Unknown paths are answered by `httpapi.NotFound` registered on `/` (via `ServeAny`), so they get the same JSON envelope as every other failure.

`result.Result[T]` makes a sequence of fallible steps one chain, for example `httpapi.Decode[In](req).Then(load).Check(allowed).Map(respond)`. The first failing step ends the chain and every later step is skipped. `Then` runs a step that may fail and may change the type, `Map` a step that cannot fail, `Check` a guard that passes the value through, and `MapErr` classifies or adds context to a failure. `result.Of(f())` adapts any `(T, error)` function (a failed Result always holds the zero value) and `.Get()` returns to ordinary Go, so a handler that is not a straight line can use plain `if err != nil` for that part and rejoin the chain. The type-changing methods are generic methods, which need Go 1.27.

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
| `debug_routes` | `diag.Diagnostics` | `diag.On` serves `GET /debug/info` (JSON) | `cmd/worker/deps_debug_routes_{on,off}.go` |

`debug_routes` is a placeholder flag that exists to exercise the mechanism end to end; replace or remove it when a real flag (for example an insecure admin authenticator) lands. A nil `Deps` field always means the safe production behaviour.

**Mechanics:**

- `DEV_TAGS` in the Makefile lists every flag a dev build turns on. `make dev` and `make build-dev` use it; `make deploy` never does.
- Tags reach TinyGo through the `GO_TAGS` environment variable, via `package.json`. Running `npx wrangler dev` directly sets no tag, so it serves the production build; use `make dev` for the dev build.
- `make vet` and `make lint` run with and without `DEV_TAGS`, on the host and for the js/wasm entrypoint, so both wirings are type-checked and linted. `cmd/worker/main_host.go` builds the same `Deps` as the Worker for this reason.
- Adding a flag: add the interface and its implementations (untagged, tested), a `Deps` field, a `deps_<flag>_{on,off}.go` pair, and add the tag to `DEV_TAGS`. The wiring files are in `cmd/worker`, which is excluded from coverage; e2e proves the prod build does not serve dev behaviour.

## Wasm size budget

The Cloudflare Workers size limit (64 MiB uncompressed, with no compressed-size limit) is far above what this Worker needs, so the budget is a regression guard rather than a platform-limit guard. Binary size drives parse and startup cost, and a jump is the earliest signal that a heavy package got linked in by accident (`encoding/json` adds roughly 700 KB under TinyGo; it is accepted because every `/api/` endpoint speaks JSON).

`make size` (`scripts/check-size.sh`):

- Builds the production wasm with TinyGo (`-no-debug`, no tags).
- **Fails if the raw size exceeds `MAX_WASM_BYTES`** (currently 2,600,000 bytes; the initial 923 KB budget was raised to 2,200,000 when `encoding/json` was adopted for all `/api/` endpoints, and again when passkey registration added `fxamacker/cbor` (about 138 KB) and the P-256 code behind `crypto/ecdh` (about 96 KB), bringing the production build to about 2.41 MB, then to about 2.53 MB with the registration endpoints). The budget is raised deliberately, in the PR that justifies it, by editing the default in `scripts/check-size.sh`.
- **Fails if a forbidden package is linked in:** `testing` and `net/http/httptest`, matched as whole import paths.
- Reports, without gating: gzip size, the top packages by flash, and which watched packages are linked, so a reviewer sees a newly linked heavy dependency. The watch list (`encoding/json`, `database/sql`, `crypto/tls`, `log/slog`) holds only heavy packages that are not in the baseline build. Packages already linked through workers-go and `net/http` (`net/http`, `reflect`, `fmt`, `crypto/x509`, `math/big`) are deliberately left off, since they would always print and hide real changes; add a package to `WATCH` when it is worth noticing.
- Only raw size gates. Wrangler's bundle size (wasm plus JS glue and source map) is not gated.

## Secrets and variables

| Name | Kind | Purpose |
|---|---|---|
| `FIRST_RUN_SECRET` | secret | Becomes the first-run invitation code (see `first_run_design.md`) |
| `AUTH_HMAC_SECRET` | secret | Root key material. Registration derives its challenge-signing key from it with a distinct context (`authsu/registration-challenge/v1`). At least 32 characters. Never use it directly, and never derive a key from it for anything where a signature is authorization (such as a session) without its own context |
| `RP_ID` | var | WebAuthn relying party ID. **Permanent**: a passkey is bound to it, so changing it invalidates every registered passkey |
| `RP_ORIGIN` | var | The one origin registration ceremonies are accepted from, such as `https://auth.example.com`. Compared as an exact string |
| `RP_NAME` | var | Relying party name the browser shows |

**How Cloudflare stores them.** To the Worker there is no difference: both arrive as string properties on `env`, and `workers-go` reads them the same way. The difference is in storage and visibility.

| | var | secret |
|---|---|---|
| Declared in | `vars` in `wrangler.jsonc`, so it is in git and ships with every deploy | Not in any file. Set on the deployed Worker with `wrangler secret put`, `wrangler secret bulk`, or the dashboard |
| Stored | Plaintext, as part of the Worker's configuration | Encrypted at rest on Cloudflare |
| Readable afterwards | Yes: dashboard, `wrangler.jsonc`, deploy logs | No. The dashboard and Wrangler show the name only, and `wrangler secret list` returns names, never values |
| Changing it | Edit the file and deploy | `wrangler secret put` creates a new Worker version and deploys it at once (`wrangler versions secret put` only creates the version, for gradual rollouts) |
| Survives `wrangler deploy` | Replaced by whatever `wrangler.jsonc` says, so a dashboard edit to a var is overwritten | Kept. A deploy never touches secrets |
| Local development | `vars` in `wrangler.jsonc` | `.dev.vars` (git-ignored), or `--env-file` as the e2e harness does |

So `RP_*` belong in `wrangler.jsonc` (non-sensitive, and reviewable in git), and `AUTH_HMAC_SECRET` must never be a var. Cloudflare also has account-wide Secrets Store bindings; this project does not use them.

**Helper commands.** `scripts/config.sh`, through `make`:

| Command | What it does |
|---|---|
| `make config-get` | Prints the `RP_*` values from `wrangler.jsonc`, whether the Worker has `AUTH_HMAC_SECRET` (name only: its value cannot be read back), and whether `.dev.vars` has one |
| `make config-set-vars RP_ID=auth.example.com RP_ORIGIN=https://auth.example.com RP_NAME="My Auth"` | Validates and writes the three vars into `wrangler.jsonc`, keeping its comments. Takes effect on the next `npx wrangler deploy` |
| `make config-set-secret` | Generates 32 random bytes (43 base64url characters), and uploads them with `wrangler secret put`, which deploys a new version |
| `make config-set-secret ARGS=--local` | The same, but writes `AUTH_HMAC_SECRET` into `.dev.vars` (mode 0600) for `make dev` |
| `make config-set-secret ARGS=--stdin` | Uploads a secret you supply on stdin instead of generating one |

The secret is passed to Wrangler on stdin, so it is never on a command line, never printed and never written to disk (except by `--local`, which is the point). The helpers refuse the two changes that cannot be undone, unless you opt in: replacing an existing `AUTH_HMAC_SECRET` (`CONFIRM_SECRET_ROTATE=1`; this invalidates every registration begun but not finished) and changing a non-`localhost` `RP_ID` (`CONFIRM_RP_ID_CHANGE=1`; this invalidates every registered passkey). `set-vars` also checks that `RP_ORIGIN` is an `https://` origin with no path (`http` only for localhost) and that `RP_ID` equals the origin's host or a parent domain of it.

The `RP_*` values in `wrangler.jsonc` are the deployment's own: set them with `make config-set-vars` before the first registration, and never leave a value you do not control there, because a passkey is bound to `RP_ID` for good. They are never used locally: `make dev` overrides them with `localhost` values (`--var`, see `DEV_RP_VARS` in the Makefile) and the e2e harness writes its own, so local runs cannot register passkeys against the real domain. They are configuration and not derived from the request, because a `Host` header is attacker-influenced and a Worker is reachable on several hostnames. Registration answers 503 `registration_not_configured` while any of them is missing or `AUTH_HMAC_SECRET` is too short.

## Atomic writes

D1 has no interactive transactions. Its only atomic primitive is `d1.Batch`, which runs statements as one transaction and rolls the whole batch back if any statement fails. It imports `syscall/js`, so `internal/` cannot import it. `internal/atomic` holds the host-compilable half: `Statement`, the `Batch` function type, and the `ErrConflict` and `ErrRejected` sentinels. `cmd/worker/main.go` supplies the one closure that converts to `d1.Statement`, calls `d1.Batch` and passes the error through `atomic.Classify`, and `app.Platform.Batch` carries it to the features that need it. A nil `Batch` makes those features answer 503 rather than panic, which is what the host stub gets.

`atomic.Classify` says why a batch was refused, by the extended result code D1 puts in the error text (`SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT_UNIQUE)`): `UNIQUE`, `PRIMARYKEY` and `NOTNULL` are `ErrConflict` (the write met existing data, or a row it needed was missing), and `CHECK`, `FOREIGNKEY` and any constraint code it does not recognise are `ErrRejected` (the schema refused something the code should have refused first). A feature maps them with `errors.Is`: registration answers 409 for a conflict and 500 `registration_accept_rejected` for a rejection, so a defect is not reported to the client as their conflict. D1 reports a failed batch as an untyped error whose text is SQLite's, so the text is all there is to match; the strings in `internal/atomic/atomic_test.go` are the real messages, captured with `wrangler d1 execute`. Anything that is not a constraint failure is returned as is, and callers treat it as unavailability.

A conditional `INSERT ... SELECT` that matches no rows is not an error, so it does not roll a batch back by itself. Make a later statement in the batch depend on the row existing (a `NOT NULL` foreign key filled from a subselect) so that "nothing was inserted" becomes a failed batch. Registration relies on this; see `internal/registration/sql.go`.

## D1 migrations

- Migrations are plain SQL files in `migrations/`, named `NNNN_description.sql`, applied in order by Wrangler (`wrangler d1 migrations apply`), which records applied files in the `d1_migrations` table.
- `migrations/` keeps a `.gitkeep` so the directory always exists: Wrangler treats an empty directory as a no-op but a missing one as an error.
- **No `CHECK` on open-ended values.** Columns whose set of values grows with the code (invitation `type`, user `role`) are validated in Go and carry no `CHECK`, because changing a `CHECK` in SQLite means rebuilding the table. `CHECK` is for invariants that will not change, such as `json_valid(...)` and `num_invites > 0`.
- **JSON columns are `TEXT`**, not `BLOB`: SQLite's binary JSONB is its own internal format that Go cannot write, and the legacy path that reads JSON text from a `BLOB` is documented as bug compatibility. We read these columns whole and decode them in Go, so there is no query-side speedup to chase.
- Migrations are append-only. A migration that has landed on `main` is never edited; changes are new migrations.
- The Worker is bound to D1 as `DB` in both environments (`wrangler.jsonc`), so Go code never knows which one it is talking to. The top-level `d1_databases` entry is the production database; `previews.d1_databases` rebinds `DB` to a separate preview database for Cloudflare Previews. Go code does not open the binding until a feature needs it, at which point `cmd/worker` opens it and passes a `*sql.DB` in through `Deps`.
- **Local development:** `make dev` applies migrations to a local persisted database in `.wrangler/state` (git-ignored) and then runs the Worker against it. `make migrate-local` applies them on their own; `make db-reset` deletes the state.
- **Dev and e2e state are separate.** E2E uses its own state directory (`.wrangler/e2e-state`) and wipes it on every run, so it never touches data created while developing.
- **CI verification:** the e2e harness applies every migration to a fresh local D1 on every run, so a broken migration fails CI.
- The `database_id` values in `wrangler.jsonc` are identifiers, not secrets. Local dev and e2e use the same `DB` binding name but are simulated locally (`--local`, with `--persist-to`), so they never reach the production or preview databases. Always pass `--local` for anything but a deliberate remote migration.
- **Remote migrations are applied by hand.** Neither CI nor Workers Builds applies them, so apply a new migration to the target database before deploying code that needs it.
  - **Production:** `npx wrangler d1 migrations apply DB --remote`.
  - **Preview database:** Wrangler resolves a migration target from the top-level `d1_databases`, so migrating the preview database needs a second config file, `wrangler.preview-migrations.jsonc`, with a top-level `d1_databases` entry (binding `PREVIEW_DB`, the preview `database_id`, `migrations_dir: "migrations"`), applied with `npx wrangler d1 migrations apply PREVIEW_DB --remote --config wrangler.preview-migrations.jsonc`. Its `database_id` must match `previews.d1_databases` in `wrangler.jsonc`; change both together.
  - **Iterating on an unmerged migration.** Wrangler records applied migrations by filename in `d1_migrations` and never re-runs or re-checks one, so editing a migration that has already been applied to the preview database is silently ignored there. While a migration is unmerged, the preview database is disposable: drop its tables and the `d1_migrations` rows (or recreate the database) and apply again. All Previews share that one database by default, so it reflects one branch's schema at a time; a branch that needs its own can point both config files at a separate database. Once a migration is on `main`, the append-only rule applies and the fix is a new migration.

## End-to-end tests

- Written in Go under `e2e/`, build tag `e2e`, so they are excluded from `go test ./...` (and so from coverage). `make vet` and `make lint` still check them with `-tags e2e`.
- **The Makefile decides the build, the harness only runs it.** `make test-e2e` depends on `build/app.wasm` (the production build, no tags), so it is built once, or not at all if `build/` is current. The harness runs wrangler with `--config wrangler.e2e.jsonc`, which is `wrangler.jsonc` without `build`, so wrangler serves that `build/` instead of running TinyGo again (that rebuild used to double the cost of every run and start-up was about 18s against about 1s now). Keep the two files in step by hand when a binding changes.
- `build/app.wasm` is a real file target whose inputs are the non-test Go files under `cmd/` and `internal/`, `go.mod`, `go.sum`, `package.json` and `tools.env`. Test files, `e2e/`, migrations and docs are not inputs. A dev build (`make build-dev`, or the rebuild `make dev` leaves behind) overwrites `build/app.wasm`, so both mark it stale afterwards (mtime reset) and the next `size` or `test-e2e` rebuilds production. If you change the build recipe somewhere other than `package.json`, add that file to `WASM_DEPS` in the Makefile.
- The harness then:
  1. wipes `E2E_STATE` (default `.wrangler/e2e-state`) and applies every migration to a fresh local D1,
  2. starts `wrangler dev --local` in its own process group on OS-chosen free ports (no collision with `make dev` or a parallel run),
  3. polls `/healthz` until the Worker answers, runs the tests over HTTP, and on exit signals the whole process group so wrangler and workerd never leak. On a failing run it prints wrangler's output.
- **Production build only.** There is no dev-flag e2e run: the artifact under test is the one that is deployed, which is also what proves dev-only behaviour is absent (a test may assert that a dev-only route is a 404). Unit tests and the lint/vet matrix cover the dev wirings on the host. If a flag ever needs wasm-level verification, add a separate e2e run for it then; it needs its own build output so it cannot be mistaken for the production `build/`.
- E2E exists for what the host cannot see: TinyGo `net/http` differences (notably `http.ServeMux` never matches method-qualified patterns like `"GET /x"`; use plain paths and dispatch on `r.Method`), the D1 driver, real SQLite behaviour, and Wrangler wiring.
- Dev and e2e use separate state directories so tests never touch data created while developing.
- **Secrets.** The harness starts the Worker with `FIRST_RUN_SECRET` and `AUTH_HMAC_SECRET` set to fixed, throwaway constants (`firstRunSecret` and `authHMACSecret` in `e2e/harness_test.go`), so tests can compute what the Worker should have stored for them. It also sets `RP_ID`, `RP_ORIGIN` and `RP_NAME`; the origin includes the port the harness picked, which is why the file is written after the port is known. It writes them to `e2e.env` inside the state directory and passes it with `wrangler dev --env-file`. The repository root is never read or written, so a developer's own `.dev.vars` is neither used by a test run nor overwritten by one. Wrangler loads `--env-file` values even when a `.dev.vars` exists (checked: the Worker saw the test value, not the `.dev.vars` one). Never put a real secret in the constant. A new secret means a new line in `writeEnvFile`.
- **Inspecting the database.** Tests reach the Worker's simulated D1 with `wrangler d1 execute DB --local --persist-to <state> --json` (the `query` helper in `e2e/firstrun_test.go`). Use it to assert on what was actually stored, which the HTTP response alone cannot show.
- **Registration e2e builds a real passkey response.** `e2e/register_test.go` takes the creation options the Worker returned, generates an ES256 key and builds a real `none` attestation over them, so nothing about the Worker is mocked. It is the only thing that proves the registration SQL (the conditional user insert, the credential's required reference to it, and the rollback), because the unit tests fake the database.
- **The database is shared and tests run in source order.** There is one Worker and one database for the whole run. A test that needs the invitations or users tables to be empty must run before the tests that fill them, and must clean up what it adds. `TestFirstRun` fills them and finishes with a user, so it runs last among the first-run tests.
- **Linting:** e2e code is linted like everything else, except that `gosec` is excluded under `e2e/` (see `.golangci.yml`): the harness launches `npx` and clears a state directory named by an environment variable by design. The one process-wide fixture (`target`) carries a `//nolint:gochecknoglobals` with its reason.

## Continuous integration

GitHub Actions, Linux only (`ubuntu-24.04`). Triggers: push to `main` and pull requests. Concurrency cancels superseded runs on the same ref.

**Supply chain stance:**

- `permissions: contents: read`, `persist-credentials: false`, no secrets, no deploy step.
- Only first-party `actions/*` plus [`golangci/golangci-lint-action`](https://github.com/golangci/golangci-lint-action) are allowed. All are pinned to full commit SHAs with the version in a trailing comment. Other third-party actions need explicit maintainer approval. TinyGo is **not** installed via a third-party action.
- TinyGo is installed by `scripts/install-tinygo.sh` (`npm run setup:ci`): it downloads the official release tarball into `.tools/cache`, verifies it against the SHA-256 pinned in `tools.env`, and extracts it to `.tools/tinygo` (both git-ignored). The tarball is verified on every run, including when it came from a cache; a cached tarball that fails the checksum is discarded and downloaded again, and a failed download leaves nothing behind. Re-runs skip extraction only when `.tools/tinygo.sha256` records the pinned hash. `npm run build` puts `.tools/tinygo/bin` on `PATH` when present, so `npm run setup:ci && npm run build` works without any PATH plumbing. CI and Cloudflare Workers Builds use the same script.
- **CI caches only the downloaded tarball** (`actions/cache` on `.tools/cache`, keyed by the TinyGo version and checksum from `tools.env`), never the extracted tree. A cache is unsigned and any pull request can read it, so a cached extracted tree would be executed unchecked; the tarball is cheap to re-verify, so a poisoned cache entry is rejected rather than trusted. The cache saves the 187 MB download but not the extraction. `actions/cache` is first-party and SHA-pinned like the others.
- Go comes from `go.mod` via `actions/setup-go`. Node is 22, and dependencies install with `npm ci --ignore-scripts`.
- `golangci-lint` is installed by `golangci/golangci-lint-action` in `install-only` mode, with the version taken from `tools.env`; `make lint` does the actual run, so CI and local use the same command. The action downloads the binary without a checksum pin, which is an accepted trade-off for this one third-party action.
- CI loads `tools.env` into the job environment, so versions and checksums are never duplicated in the workflow. `$GITHUB_ENV` accepts only `NAME=value` lines, so the step filters out comments and blank lines with `grep`; keep `tools.env` to plain `KEY=value` assignments.
- `npm ci --ignore-scripts` is safe for e2e: the `workerd` binary ships as a platform optional dependency (`@cloudflare/workerd-linux-64`) and runs without its postinstall script. This was verified by installing with `--ignore-scripts` in a clean clone and running `make test-e2e`.

**Jobs:** `make ci` is the local, serial equivalent of everything CI runs. The workflow splits it into parallel jobs that each call a subset of the same `make` targets, so wall time is the slowest job instead of the sum:

| Job | Targets | Needs |
|---|---|---|
| `lint` | `fmt-check tidy-check vet lint` | Go, golangci-lint |
| `test` | `test coverage` | Go |
| `build` | `build build/size-full.txt`, then uploads `build/` as the `worker-build` artifact | Go, Node, TinyGo |
| `size` | `size PREBUILT=1` | Go; downloads `worker-build` |
| `e2e` | `test-e2e PREBUILT=1` | Go, Node; downloads `worker-build` |

`build` is the only job that installs or runs TinyGo; `size` and `e2e` start when it finishes and run in parallel. The Worker is built once per run instead of five times, and TinyGo is installed once instead of three times.

- `check-tools` is not run in CI: it only verifies a developer's local installs, and CI installs the pinned versions itself.
- If you add a target to `make ci` or `make check`, add it to the matching job in `ci.yml` too, or CI will silently stop running it.
- Toolchain setup is the local composite action `.github/actions/setup` (loads `tools.env`, then installs Go and, on request, golangci-lint, Node plus `npm ci`, and TinyGo with the tarball cache described above). Jobs opt in to each tool, so `test` does not pay for TinyGo or Node, and only `build` pays for TinyGo. It is first-party code in this repository, and every action it uses is SHA-pinned.
- **The `worker-build` artifact is trusted because of how it is scoped.** The caches above are rejected as untrusted because any pull request can write one that a later run on another ref reads. A workflow artifact is different: it is created and consumed inside one workflow run, by jobs that all check out the same commit, and it expires after a day, so a pull request cannot hand a binary to someone else's run. Keep it that way: never download an artifact from another run or workflow (no `run-id`, no `github-token` input), never publish it, and never add a cross-run cache of `build/`. Upload and download use the first-party `actions/upload-artifact` and `actions/download-artifact`, SHA-pinned like the rest.
- **`PREBUILT=1`.** The `size` and `e2e` jobs have no TinyGo, so they pass `PREBUILT=1`: if `build/` is missing or older than its sources, make fails with a message instead of trying to rebuild or quietly testing something else. Downloaded files are newer than the checkout, so this does not normally trigger. Locally, leave it unset.
- The e2e job runs on its own runner, so it cannot collide on `E2E_STATE` or ports.
- **One required check.** The `CI` job (`needs` every other job, `if: always()`) fails unless every needed job succeeded; cancelled and skipped count as failures. Branch protection on `main` requires only `CI`, so adding a job means adding it to the `needs` list in `ci.yml`, not changing repository settings. A job missing from `needs` is not gated, so keep the list complete.
- Vulnerability scanning and pin upkeep run on a schedule instead, in `.github/workflows/scheduled.yml`.

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

- **Dependabot** (`.github/dependabot.yml`) covers the `gomod`, `npm`, and `github-actions` ecosystems, weekly, with one grouped pull request per ecosystem to limit noise. Security updates are separate and immediate, and Dependabot's default 3-day cooldown on new releases applies to version updates (not security updates). It also keeps the pinned action SHAs current, rewriting the SHA and the trailing version comment together.
- **govulncheck** is pinned through a `tool` directive in `go.mod` (version-locked by `go.sum`, never `@latest`), so Dependabot's `gomod` ecosystem keeps it current. `make vuln` runs `go tool govulncheck ./...`.
  - It runs only on a schedule (the `vuln` job in `.github/workflows/scheduled.yml`, Mondays plus manual dispatch), not on pull requests: advisories arrive without any code change, so a timer is what catches them. Run `make vuln` locally when adding a dependency.
  - The tool version matters: an old govulncheck panics inside its bundled `x/tools` when analysing code built by a newer Go. Dependabot bumping it is therefore load-bearing, and a panic in the scheduled run means the pin is stale, not that the code is vulnerable.
- `go mod tidy -diff` runs in CI; `go.mod` and `go.sum` must be tidy.
- **Manual upkeep.** Dependabot cannot update these, so the `upkeep` job in the same scheduled workflow runs `scripts/check-upkeep.sh` weekly and reports in the job summary:
  - the TinyGo and golangci-lint versions in `tools.env` (bump the version and checksum together, saying in the commit where the checksum came from), and
  - the `replace` of `workers-go` with the fork carrying D1 batch support, which should be dropped once upstream releases it.

  The job fails when a pin is behind (exit 1) or when a lookup itself failed (exit 2), so a broken check is never mistaken for "all current". The token stays read-only, so there is no issue or comment: a failed scheduled run, and GitHub's notification for it, is the reminder.
