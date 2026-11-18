# CI: lint, size, dependencies and supply chain

How code is linted, budgeted, gated and shipped. Generic scaffolding. Which `make` targets to run locally, and when, is in [CONTRIBUTING.md](CONTRIBUTING.md); procedures for operating a deployment are in [runbook.md](runbook.md).

## Lint, size and dependencies

- **Format** is `gofmt -s`. **Lint** is golangci-lint v2 with a posture of maximal: every linter on, disabled one by one with a stated reason in `.golangci.yml`. Fix the code rather than adding `//nolint`; a needed suppression must name the linter and give a reason.
- **Wasm size is budgeted** by `make size` as a regression guard, not a platform-limit guard: a jump is the earliest sign a heavy package was linked by accident (`encoding/json` is the usual suspect under TinyGo). The budget is raised deliberately, in the PR that justifies it, by editing the default in `scripts/check-size.sh`. Packages that must never be linked (`testing`, `net/http/httptest`) fail the check.
- **`go.mod` and `go.sum` must be tidy.** Dependabot keeps `gomod`, `npm` and `github-actions` current, and a scheduled workflow runs `govulncheck` and reports pins Dependabot cannot update (see [runbook.md](runbook.md)).

## Continuous integration and supply chain

GitHub Actions, Linux only. CI runs the same `make` targets as local use, split into parallel jobs (lint, test, build, then size and e2e from the one build) so wall time is the slowest job, not the sum.

- **One required check.** An aggregate `CI` job depends on every other job and fails unless all succeeded, with cancelled and skipped counting as failures. Branch protection requires only that, so adding a job means adding it to the aggregate's `needs`, which is not gated otherwise. A target added to `make ci` or `make check` must also be added to the matching job.
- **Least privilege.** Read-only permissions, no persisted credentials, no secrets and no deploy step. Deploying is done by Cloudflare Workers Builds, not by CI.
- **Actions are pinned and few.** Only first-party `actions/*` plus `golangci/golangci-lint-action` are allowed, each pinned to a full commit SHA with the version in a trailing comment. Other third-party actions need maintainer approval. Toolchain setup is the local composite action `.github/actions/setup`.
- **Downloads are verified.** TinyGo is installed by `scripts/install-tinygo.sh` against the SHA-256 in `tools.env`, on every run, including when the tarball came from a cache. CI caches only that tarball, never an extracted tree: any pull request can write a cache, so an extracted tree would be executed unchecked.
- **The build artifact is trusted only within a run.** The Worker is built once and shared with the `size` and `e2e` jobs as a workflow artifact, which is created and consumed inside one run by jobs on the same commit. Never download an artifact from another run or workflow, publish it, or add a cross-run cache of `build/`.
- **Versions are in `tools.env`.** CI loads it into the job environment, so versions and checksums are never duplicated; keep it to plain `KEY=value` lines. Bumping a tool edits that file only, with the checksum's source named in the commit.
- **`PREBUILT=1`** makes `size` and `e2e` fail if `build/` is missing or stale instead of rebuilding, for jobs that have no TinyGo. Locally, leave it unset.
