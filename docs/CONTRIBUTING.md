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

## Where documentation goes

Ask what kind of statement it is.

- **How the code is shaped** (layering, the handler and error contract, the rules a package must follow): [ARCHITECTURE.md](ARCHITECTURE.md), and only when a principle or convention changes.
- **How code is tested**: [TESTING.md](TESTING.md). How one specific test works belongs in comments in that test file.
- **Schema and migration conventions**: [DATABASE.md](DATABASE.md).
- **How code is built, linted, gated and shipped**: [CI.md](CI.md).
- **Product behaviour and its rationale** (what a feature does, its configuration, its failure codes, why it is shaped as it is): that feature's `docs/*_design.md`, and the package godoc beside the code.
- **Procedures for operating a deployment**: [runbook.md](runbook.md).

The scaffolding documents hold no product nouns (passkeys, sessions, invitations) and no inventories such as package lists or current sizes: the code is the source for those. Feature work should not need to touch them.
