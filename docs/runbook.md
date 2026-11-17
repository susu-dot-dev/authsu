# Runbook

Procedures for operating a deployment. [devops.md](devops.md) says how the project is built and checked; this says how to configure, migrate and deploy it. Cloudflare's tooling changes, so check current Wrangler and D1 documentation before relying on a command here.

## Secrets and variables

To the Worker a variable and a secret look the same: both are string properties on `env`. The difference is in storage and visibility.

| | var | secret |
|---|---|---|
| Declared in | `vars` in `wrangler.jsonc`, so it is in git and ships with every deploy | Not in any file. Set on the deployed Worker with `wrangler secret put`, `wrangler secret bulk`, or the dashboard |
| Stored | Plaintext, as part of the Worker's configuration | Encrypted at rest on Cloudflare |
| Readable afterwards | Yes: dashboard, `wrangler.jsonc`, deploy logs | No. Only the name is shown |
| Changing it | Edit the file and deploy | `wrangler secret put` creates a new Worker version and deploys it at once (`wrangler versions secret put` only creates the version, for gradual rollouts) |
| Survives `wrangler deploy` | Replaced by whatever `wrangler.jsonc` says, so a dashboard edit is overwritten | Kept. A deploy never touches secrets |
| Local development | `vars` in `wrangler.jsonc` | `.dev.vars` (git-ignored), or `--env-file` as the e2e harness does |

Anything non-sensitive belongs in `wrangler.jsonc`, where it is reviewable; anything sensitive must be a secret, never a var. This project does not use Cloudflare's account-wide Secrets Store.

Which names exist, what each is for and what happens when one is missing is part of the feature that reads it: see `internal/deploy`, [registration_design.md](registration_design.md), [login_design.md](login_design.md) and [first_run_design.md](first_run_design.md).

### Helper commands

`scripts/config.sh`, through `make`, manages the deployment's own configuration. `make config-get` shows what is set (secret names only: their values cannot be read back).

| Command | What it does |
|---|---|
| `make config-set-vars RP_ID=auth.example.com RP_ORIGIN=https://auth.example.com RP_NAME="My Auth"` | Validates and writes the relying party vars into `wrangler.jsonc`, keeping its comments. Takes effect on the next `npx wrangler deploy` |
| `make config-set-secret` | Generates 32 random bytes (43 base64url characters) and uploads them as `AUTH_HMAC_SECRET` with `wrangler secret put`, which deploys a new version |
| `make config-set-secret ARGS=--local` | The same, but writes `.dev.vars` (mode 0600) for `make dev` |
| `make config-set-secret ARGS=--stdin` | Uploads a secret you supply on stdin instead of generating one |

The secret is passed to Wrangler on stdin, so it is never on a command line, never printed and never written to disk (except by `--local`, which is the point).

Two changes cannot be undone, so the helpers refuse them unless you opt in:

- Replacing an existing `AUTH_HMAC_SECRET` (`CONFIRM_SECRET_ROTATE=1`). Ceremonies begun but not finished are invalidated.
- Changing a non-`localhost` `RP_ID` (`CONFIRM_RP_ID_CHANGE=1`). A passkey is bound to the relying party ID, so this invalidates every registered passkey.

`set-vars` also checks that `RP_ORIGIN` is an `https://` origin with no path (`http` only for localhost) and that `RP_ID` is the origin's host or a parent domain of it. Set the relying party vars before the first registration, and never leave a value in `wrangler.jsonc` that you do not control.

Local runs never use the committed values: `make dev` overrides them with `localhost` values (`DEV_RP_VARS` in the Makefile) and the e2e harness writes its own, so a local run cannot register passkeys against the real domain.

## Database migrations

Conventions for writing migrations are in [devops.md](devops.md). Applying them:

- **Local:** `make dev` applies migrations to a persisted local database in `.wrangler/state` (git-ignored) and serves the Worker against it. `make migrate-local` applies them on their own; `make db-reset` deletes the state. E2E uses a separate state directory that it wipes on every run.
- **Always pass `--local`** for anything that is not a deliberate remote migration. Local and e2e use the same `DB` binding name as production but are simulated.
- **Remote migrations are applied by hand.** Neither CI nor Workers Builds applies them, so apply a new migration to the target database before deploying code that needs it.
  - **Production:** `npx wrangler d1 migrations apply DB --remote`.
  - **Preview database:** Wrangler resolves a migration target from the top-level `d1_databases`, so the preview database needs a second config file, `wrangler.preview-migrations.jsonc`, with a top-level `d1_databases` entry (binding `PREVIEW_DB`, the preview `database_id`, `migrations_dir: "migrations"`). Apply with `npx wrangler d1 migrations apply PREVIEW_DB --remote --config wrangler.preview-migrations.jsonc`. Its `database_id` must match `previews.d1_databases` in `wrangler.jsonc`; change both together.
- **Iterating on an unmerged migration.** Wrangler records applied migrations by filename in `d1_migrations` and never re-runs or re-checks one, so editing a migration that is already applied to the preview database is silently ignored there. While a migration is unmerged, the preview database is disposable: drop its tables and the `d1_migrations` rows (or recreate the database) and apply again. All Previews share that one database by default, so it reflects one branch's schema at a time. Once a migration is on `main`, the append-only rule applies and the fix is a new migration.
- The `database_id` values in `wrangler.jsonc` are identifiers, not secrets.

## Deploying

Two paths, both running the same `npx wrangler deploy`.

**Cloudflare Workers Builds** clones the repository and runs the dashboard commands. Its image has Go (fetched per `go.mod`) and Node but no TinyGo, and it ignores the `build` section of `wrangler.jsonc`. Configure the project (Settings > Build) with:

| Setting | Value |
|---|---|
| Build command | `npm run setup:ci && npm run build` |
| Deploy command | `npx wrangler deploy` |

TinyGo's version and checksum come from `tools.env`, so bumping it there updates CI and Cloudflare together.

### The japikey_go module is private

Sessions depend on `github.com/susu-dot-dev/japikey_go`, a private repository, so `go mod download` fails without credentials: on a developer machine with no GitHub access, on CI, and on Workers Builds. This is the one place the "no secrets in CI" stance in [devops.md](devops.md) does not hold by itself. This section is temporary: publishing the module removes it.

Until then a build needs:

- `GOPRIVATE=github.com/susu-dot-dev`, so Go neither asks the public proxy nor checks the public checksum database for it, and
- git access to the repository. A developer with an SSH key needs one rewrite, because Go clones over `https://`: `git config --global url."git@github.com:susu-dot-dev/".insteadOf "https://github.com/susu-dot-dev/"`. CI would use an `https://` rewrite carrying a token.

Do not commit either. A token for CI should be a fine-grained, read-only, single-repository credential held as an Actions secret, and the jobs that run `go mod download` (`lint`, `test`, `build`) are the ones that need it. That is a deliberate change to the supply-chain stance and needs maintainer approval.

## Upkeep

Dependabot and the scheduled workflow (`.github/workflows/scheduled.yml`) do most of it. What they cannot do is reported by the weekly `upkeep` job (`scripts/check-upkeep.sh`), which fails when a pin is behind (exit 1) or when a lookup itself failed (exit 2), so a broken check is never mistaken for "all current". The token is read-only, so the reminder is the failed run and GitHub's notification for it.

- **TinyGo and golangci-lint** pins in `tools.env`: bump the version and checksum together, and say in the commit where the checksum came from.
- **The `workers-go` fork:** `go.mod` replaces `workers-go` with a fork carrying D1 batch support. Drop the `replace` once upstream releases it.
- **govulncheck** is pinned through a `tool` directive in `go.mod`, so Dependabot keeps it current. An old govulncheck panics inside its bundled `x/tools` when analysing code built by a newer Go: a panic in the scheduled run means the pin is stale, not that the code is vulnerable. Run `make vuln` locally when adding a dependency.
