# Runbook

Procedures for operating a deployment. [CONTRIBUTING.md](CONTRIBUTING.md) says how the project is built and checked; this says how to configure, migrate and deploy it. Cloudflare's tooling changes, so check current Wrangler and D1 documentation before relying on a command here.

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

Which names exist, what each is for and what happens when one is missing is part of the feature that reads it: see `internal/config`, [registration_design.md](registration_design.md), [login_design.md](login_design.md) and [first_run_design.md](first_run_design.md).

### Helper commands

`scripts/config.sh`, through `make`, manages the deployment's own configuration. `make config-get` shows what is set (secret names only: their values cannot be read back).

| Command | What it does |
|---|---|
| `make config-set-vars API_ORIGIN=https://auth.example.com UI_ORIGIN=https://example.com` | Validates and writes the two origins into `wrangler.jsonc`, keeping its comments. Takes effect on the next `npx wrangler deploy` |
| `make config-set-secret` | Generates 32 random bytes (43 base64url characters) and uploads them as `AUTH_HMAC_SECRET` with `wrangler secret put`, which deploys a new version |
| `make config-set-secret ARGS=--local` | The same, but writes `.dev.vars` (mode 0600) for `make dev` |
| `make config-set-secret ARGS=--stdin` | Uploads a secret you supply on stdin instead of generating one |

The secret is passed to Wrangler on stdin, so it is never on a command line, never printed and never written to disk (except by `--local`, which is the point).

Two changes cannot be undone, so the helpers refuse them unless you opt in:

- Replacing an existing `AUTH_HMAC_SECRET` (`CONFIRM_SECRET_ROTATE=1`). Ceremonies begun but not finished are invalidated.
- Changing the host of a non-`localhost` `UI_ORIGIN` (`CONFIRM_RP_ID_CHANGE=1`). The relying party ID is that host and a passkey is bound to it, so this invalidates every registered passkey. Changing `API_ORIGIN` does not, but it changes the session issuer and so ends every live session.

`set-vars` also checks that both values are bare origins (an `https://` origin with no path, query or user info, lower case; `http` only for localhost). Set them before the first registration, and never leave a value in `wrangler.jsonc` that you do not control.

Local runs never use the committed values: `make dev` overrides them with `localhost` values (`DEV_ORIGIN_VARS` in the Makefile) and the e2e harness writes its own, so a local run cannot register passkeys against the real domain.

### Frontend on another origin

The UI may be served from a different origin than the API (`https://susu.dev` calling `https://auth.susu.dev`). The Worker allows exactly one origin to call it from a browser, and it is `UI_ORIGIN`: there is no separate CORS setting. Why, and what that does and does not allow, is in [login_design.md](login_design.md#the-ui-on-another-origin).

- **`UI_ORIGIN` is the UI's origin**, not the Worker's, and **`API_ORIGIN` is the Worker's**. Passkey ceremonies run on the UI's page, so a `UI_ORIGIN` that is the API's host makes every registration and login fail with a wrong-origin error. The relying party ID and name are the host of `UI_ORIGIN`; there is nothing else to set.
- **The UI and API must share a registrable domain** (`susu.dev` and `auth.susu.dev`), or the session cookie, which is `SameSite=Lax`, will not be sent. Nothing checks this: a login that succeeds followed by an unauthenticated request is the symptom.
- **The UI must send credentials**: `fetch(url, { credentials: "include" })`, and `Content-Type: application/json` on every POST.
- **Locally**, `make dev` serves the API on :8787 and sets `API_ORIGIN` to `http://localhost:8787` and `UI_ORIGIN` to `http://localhost:3000` (`DEV_UI_PORT` in the Makefile), so run the UI dev server on that port, or override it: `make dev DEV_UI_PORT=5173`. A browser will not let a page on another origin read a response the Worker did not mark readable, so a UI on any other port fails with a CORS error.
- **Symptoms:** a CORS error in the browser console with no `Access-Control-Allow-Origin` on the response means the page's origin is not exactly `UI_ORIGIN` (scheme, host and port all count; no trailing slash), or `UI_ORIGIN` is not a valid bare origin and so allows nothing.

## Database migrations

Conventions for writing migrations are in [DATABASE.md](DATABASE.md). Applying them:

- **Local:** `make dev` applies migrations to a persisted local database in `.wrangler/state` (git-ignored) and serves the Worker against it. `make migrate-local` applies them on their own; `make db-reset` deletes the state. E2E uses a separate state directory that it wipes on every run.
- **Always pass `--local`** for anything that is not a deliberate remote migration. Local and e2e use the same `DB` binding name as production but are simulated.
- **Remote migrations are applied by hand.** Neither CI nor Workers Builds applies them, so apply a new migration to the target database before deploying code that needs it.
  - **Production:** `npx wrangler d1 migrations apply DB --remote`.
  - **Order matters for `0005_agents`.** Revoking a user writes the `agents` table, so apply this migration *before* deploying code that includes it; otherwise revoking an account fails until it is applied.
  - **Order matters for `0004_users_revoked_at`.** The session and login queries read `users.revoked_at`, so apply this migration *before* deploying code that includes it; otherwise every request fails to verify until it is applied.
- **Iterating on an unmerged migration.** Wrangler records applied migrations by filename in `d1_migrations` and never re-runs or re-checks one, so editing a migration that is already applied to a database is silently ignored there. Do that iteration against the local database (`make db-reset`, then `make migrate-local`), never a remote one. Once a migration is on `main`, the append-only rule applies and the fix is a new migration.
- The `database_id` in `wrangler.jsonc` is an identifier, not a secret.

## Deploying

Two paths, both running the same `npx wrangler deploy`.

**Cloudflare Workers Builds** clones the repository and runs the dashboard commands. Its image has Go (fetched per `go.mod`) and Node but no TinyGo, and it ignores the `build` section of `wrangler.jsonc`. Configure the project (Settings > Build) with:

| Setting | Value |
|---|---|
| Build command | `npm run setup:ci && npm run build` |
| Deploy command | `npx wrangler deploy` |

TinyGo's version and checksum come from `tools.env`, so bumping it there updates CI and Cloudflare together.

### Ceremonies in flight when the challenge format changes

A deploy that changes how challenges are signed (the shared layout in `internal/challenge` did) invalidates every challenge issued before it. A registration or login that began on the old version and finishes on the new one fails once (400 `invalid_challenge` or 401 `invalid_login`) and succeeds when retried. Challenges last five minutes, so prefer a quiet moment for such a deploy; nothing needs repairing afterwards. The same is true of rotating `AUTH_HMAC_SECRET`.

### The japikey_go module is private

Sessions depend on `github.com/susu-dot-dev/japikey_go`, a private repository, so `go mod download` fails without credentials: on a developer machine with no GitHub access, on CI, and on Workers Builds. This is the one place the "no secrets in CI" stance in [CI.md](CI.md) does not hold by itself. This section is temporary: publishing the module removes it.

Until then a build needs:

- `GOPRIVATE=github.com/susu-dot-dev`, so Go neither asks the public proxy nor checks the public checksum database for it, and
- git access to the repository. A developer with an SSH key needs one rewrite, because Go clones over `https://`: `git config --global url."git@github.com:susu-dot-dev/".insteadOf "https://github.com/susu-dot-dev/"`. CI would use an `https://` rewrite carrying a token.

Do not commit either. A token for CI should be a fine-grained, read-only, single-repository credential held as an Actions secret, and the jobs that run `go mod download` (`lint`, `test`, `build`) are the ones that need it. That is a deliberate change to the supply-chain stance and needs maintainer approval.

## Upkeep

Dependabot and the scheduled workflow (`.github/workflows/scheduled.yml`) do most of it. What they cannot do is reported by the weekly `upkeep` job (`scripts/check-upkeep.sh`), which fails when a pin is behind (exit 1) or when a lookup itself failed (exit 2), so a broken check is never mistaken for "all current". The token is read-only, so the reminder is the failed run and GitHub's notification for it.

- **TinyGo and golangci-lint** pins in `tools.env`: bump the version and checksum together, and say in the commit where the checksum came from.
- **The `workers-go` fork:** `go.mod` replaces `workers-go` with a fork carrying D1 batch support. Drop the `replace` once upstream releases it.
- **The Workers `compatibility_date`** in `wrangler.jsonc` and `wrangler.e2e.jsonc` (keep the two equal: e2e must test the date that is deployed). It is a deliberate pin, not "the newest": it is the runtime behaviour this code was tested against, and it may be any date the locked workerd supports. A date newer than the workerd bundled with the installed wrangler makes `wrangler dev` refuse to start (`newest date supported by this server binary`), so the date, not the wrangler minimum in `package.json`, is what decides how old a wrangler is acceptable: `package.json` allows the oldest wrangler whose workerd supports the date. The weekly check reports a date that is newer than the locked workerd supports, one that is more than 90 days behind it, and the two configs disagreeing. To bump it, read the [compatibility flag changes](https://developers.cloudflare.com/workers/configuration/compatibility-flags/) since the old date, raise both configs together, and raise the wrangler range in `package.json` to the oldest version whose workerd supports the new date (`npm view wrangler@<version> dependencies.workerd` gives its `1.YYYYMMDD.N`).
- **A wrangler that is not the project's.** `npx wrangler` uses `node_modules` when it exists and otherwise falls back to any globally installed wrangler, which can be older than `package-lock.json` pins. Run `make setup` (`npm ci`) first; `workerd` refusing the compatibility date is the usual symptom.
- **govulncheck** is pinned through a `tool` directive in `go.mod`, so Dependabot keeps it current. An old govulncheck panics inside its bundled `x/tools` when analysing code built by a newer Go: a panic in the scheduled run means the pin is stale, not that the code is vulnerable. Run `make vuln` locally when adding a dependency.
