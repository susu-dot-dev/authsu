# Contributing: principles, stack and workflow

How to work on this repository day to day. This is generic: it says nothing about what authsu does. For the rest of the scaffolding see [ARCHITECTURE.md](ARCHITECTURE.md), [TESTING.md](TESTING.md), [DATABASE.md](DATABASE.md) and [CI.md](CI.md). Product behaviour belongs in the `*_design.md` files and package godoc; procedures for operating a deployment are in [runbook.md](runbook.md). The Makefile, `.golangci.yml`, the workflow YAML and the scripts are the precise reference, so these documents give the shape and the reasons and do not repeat them.

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

## Error flow: Result first

Code that runs a sequence of fallible steps is written as a `result.Result` chain (`Of`, `Then`, `Map`, `Check`, `MapErr`), not as a repeated `if err != nil { return ..., err }`. The first failure ends the chain and every later step is skipped, so the happy path reads top to bottom and each step is a small named function that is tested on its own. Unit tests are exempt.

- **Keep the Result across function boundaries.** A function whose body is a chain returns `result.Result[T]`, and its caller continues the chain with `Then` instead of unwrapping it. This is the default, and it is what keeps `.Get()` and `.Err()` out of production code. Convert the helpers a chain calls (a parser, a step that reads a stored row) to return a `Result` too, rather than unwrapping at each one.
- **Unwrap only where a signature is fixed.** A chain ends in `.Get()` or `.Err()` when the function must return `(T, error)`: a public API that other packages or an interface pin down, a callback a library calls, or a `Store` method. Everywhere else, return the `Result`.
- **Fall back to `if err != nil` when a chain is the worse code.** Plain control flow is right when the steps do not feed each other (state carried through a closure or a side channel), when a function is two sequential calls that each add their own cause (`fmt.Errorf("%w: %w", ...)`), or when a function cannot fail at all and only turns a bad value into a safe one. Do not force a chain where it needs more machinery than the branches it replaces.
- **A chain that must end in `(T, error)` needs one suppression.** `wrapcheck` is on, and it decides from the `return` line alone that the error of a call into another package (here `result`) is unwrapped, so it flags `return chain.Get()`. It cannot see that every error in the chain is already classified (`apierr`, a parser's client error, or wrapped with what failed), and wrapping a classified error again would only change what the log shows. Put one `//nolint:wrapcheck // <reason>` on that `return` line, and make the reason say why the chain's errors are already classified. Assign the chain to a variable first when the chain itself would push the line past the length limit. Do not widen `wrapcheck` in `.golangci.yml` to ignore `Get` or `Err`: they are also how a raw, unwrapped foreign error would leave a chain, and the linter is what catches that.

## Where documentation goes

Ask what kind of statement it is.

- **How the code is shaped** (layering, the handler and error contract, the rules a package must follow): [ARCHITECTURE.md](ARCHITECTURE.md), and only when a principle or convention changes.
- **How code is tested**: [TESTING.md](TESTING.md). How one specific test works belongs in comments in that test file.
- **Schema and migration conventions**: [DATABASE.md](DATABASE.md).
- **How code is built, linted, gated and shipped**: [CI.md](CI.md).
- **Product behaviour and its rationale** (what a feature does, its configuration, its failure codes, why it is shaped as it is): that feature's `docs/*_design.md`, and the package godoc beside the code.
- **Procedures for operating a deployment**: [runbook.md](runbook.md).

The scaffolding documents hold no product nouns (passkeys, sessions, invitations) and no inventories such as package lists or current sizes: the code is the source for those. Feature work should not need to touch them.
