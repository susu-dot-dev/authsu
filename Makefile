# authsu developer commands. Run `make help`. See docs/CONTRIBUTING.md.

SHELL := /bin/bash
.DEFAULT_GOAL := help

include tools.env

# Local D1 state (git-ignored via .wrangler). Dev and e2e use different
# directories so e2e can wipe its own state without touching dev data.
DEV_STATE := .wrangler/state
# Origins for `make dev`, passed as --var so they override the deployment's
# API_ORIGIN and UI_ORIGIN in wrangler.jsonc. The API listens on DEV_PORT; the UI
# is a separate dev server on DEV_UI_PORT, and UI_ORIGIN is its origin because
# that is where passkey ceremonies run and what CORS allows (docs/runbook.md,
# "Frontend on another origin"). The relying party ID is derived from it.
DEV_PORT := 8787
DEV_UI_PORT := 3000
DEV_ORIGIN_VARS := --var API_ORIGIN:http://localhost:$(DEV_PORT) --var UI_ORIGIN:http://localhost:$(DEV_UI_PORT)

# E2E uses its own state, never the dev state.
E2E_STATE := .wrangler/e2e-state

# The wasm is a real file target, so it is built once and shared:
# `size`, `test-e2e` and CI's downstream jobs all consume the same build/. Make
# rebuilds it only when a Go source, the module files or the build recipe
# changed. TinyGo has no incremental compilation, so this is the only way to
# skip the ~20s compile. Tests, migrations and docs are not inputs.
WASM        := build/app.wasm
SIZE_REPORT := build/size-full.txt
WASM_DEPS   := $(shell git ls-files --cached --others --exclude-standard -- \
                 'cmd/*.go' 'internal/*.go' go.mod go.sum package.json tools.env \
                 | grep -v '_test\.go$$')

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z0-9_-]+:.*## /{printf "  \033[1m%-16s\033[0m %s\n",$$1,$$2}' $(MAKEFILE_LIST)

# ---- setup ------------------------------------------------------------------

.PHONY: setup
setup: check-tools ## Install JS deps and download Go modules
	npm ci
	go mod download

.PHONY: check-tools
check-tools: ## Verify local tool versions match tools.env
	@fail=0; \
	for t in go tinygo node npm golangci-lint; do \
	  command -v $$t >/dev/null || { echo "missing required tool: $$t"; fail=1; }; done; \
	[ $$fail -eq 0 ] || exit 1; \
	tg="$$(tinygo version | awk '{print $$3}')"; \
	[ "$$tg" = "$(TINYGO_VERSION)" ] || { echo "tinygo $$tg != pinned $(TINYGO_VERSION)"; fail=1; }; \
	gl="$$(golangci-lint --version | awk '{print $$4}')"; \
	[ "$$gl" = "$(GOLANGCI_LINT_VERSION)" ] || { echo "golangci-lint $$gl != pinned $(GOLANGCI_LINT_VERSION)"; fail=1; }; \
	exit $$fail

# ---- quality ----------------------------------------------------------------

# Go files to format: tracked plus untracked-but-not-ignored, so .gitignore
# keeps .tools/, node_modules/ and build/ out, and new files are still checked.
GO_FILES = $$(git ls-files --cached --others --exclude-standard -- '*.go')

.PHONY: fmt
fmt: ## Format Go code
	gofmt -s -w $(GO_FILES)

.PHONY: fmt-check
fmt-check: ## Fail if Go code is not gofmt-clean
	@out="$$(gofmt -s -l $(GO_FILES))"; if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet on the host (and e2e), plus the js/wasm entrypoint
	go vet ./...
	go vet -tags e2e ./e2e/...
	GOOS=js GOARCH=wasm go vet ./cmd/worker

# ---- tests ------------------------------------------------------------------

COVER_OUT := coverage.out

.PHONY: test
test: ## Unit tests (race detector on)
	go test -race ./...

.PHONY: coverage
coverage: ## Unit tests + 100% coverage gate (honours // coverage:ignore: <reason>)
	go test -covermode=atomic -coverprofile=$(COVER_OUT) ./...
	go run ./scripts/covgate -profile $(COVER_OUT)

.PHONY: coverage-html
coverage-html: ## Write coverage.html from the last `make coverage`
	go tool cover -html=$(COVER_OUT) -o coverage.html
	@echo "wrote coverage.html"

.PHONY: tidy-check
tidy-check: ## Fail if go.mod/go.sum are not tidy
	go mod tidy -diff

.PHONY: size
size: $(WASM) $(SIZE_REPORT) ## Wasm size report + budget (fails if over budget or test pkgs linked)
	WASM=$(WASM) SIZE_REPORT=$(SIZE_REPORT) ./scripts/check-size.sh

.PHONY: vuln
vuln: ## Scan dependencies for known vulnerabilities (pinned govulncheck)
	go tool govulncheck ./...

.PHONY: lint
lint: ## golangci-lint (host, e2e, and the js/wasm entrypoint)
	golangci-lint run ./...
	golangci-lint run --build-tags e2e ./e2e/...
	GOOS=js GOARCH=wasm golangci-lint run ./cmd/worker

# ---- build / local dev ------------------------------------------------------

# In CI only the `build` job has TinyGo; the jobs that download its artifact set
# PREBUILT=1 so a stale-looking build/ fails loudly instead of falling through
# to a TinyGo that is not installed (or silently testing a different binary).
$(WASM): $(WASM_DEPS)
	@if [ -n "$(PREBUILT)" ]; then \
	  echo "PREBUILT is set but $(WASM) is missing or older than its sources"; exit 1; fi
	npm run build

# `-size full` is a second link of the same program, only needed for the size
# report, so it is a separate target that `size` (and CI's build job) asks for.
$(SIZE_REPORT): $(WASM_DEPS)
	@if [ -n "$(PREBUILT)" ]; then \
	  echo "PREBUILT is set but $(SIZE_REPORT) is missing or older than its sources"; exit 1; fi
	@mkdir -p $(dir $@)
	PATH="$$PWD/.tools/tinygo/bin:$$PATH" tinygo build -o /dev/null -target wasm \
	  -size full ./cmd/worker >$@ 2>&1

.PHONY: build
build: $(WASM) ## Build the Worker -> build/

.PHONY: migrate-local
migrate-local: ## Apply D1 migrations to the local dev database
	npx wrangler d1 migrations apply DB --local --persist-to $(DEV_STATE)

.PHONY: db-reset
db-reset: ## Delete local dev database state
	rm -rf $(DEV_STATE)

.PHONY: dev
dev: migrate-local ## Run the Worker locally on :8787 (local D1, UI origin on :3000)
	npx wrangler dev --local --port $(DEV_PORT) --persist-to $(DEV_STATE) $(DEV_ORIGIN_VARS)

# ---- configuration ----------------------------------------------------------
# AUTH_HMAC_SECRET, OAUTH_SIGNING_KEY and FIRST_RUN_SECRET (secrets) and API_ORIGIN,
# UI_ORIGIN (vars).
# See docs/runbook.md, "Secrets and variables". scripts/config.sh does the work.

.PHONY: config-get
config-get: ## Show API_ORIGIN and UI_ORIGIN, whether AUTH_HMAC_SECRET, OAUTH_SIGNING_KEY and FIRST_RUN_SECRET are set (never their values)
	@./scripts/config.sh get

.PHONY: config-set-vars
config-set-vars: ## Write the origins into wrangler.jsonc: API_ORIGIN=... UI_ORIGIN=...
	@[ -n "$(API_ORIGIN)" ] && [ -n "$(UI_ORIGIN)" ] || { \
	  echo 'usage: make config-set-vars API_ORIGIN=https://auth.example.com UI_ORIGIN=https://example.com'; exit 2; }
	@./scripts/config.sh set-vars "$(API_ORIGIN)" "$(UI_ORIGIN)"

.PHONY: setup-local
setup-local: ## Create .dev.vars with AUTH_HMAC_SECRET, OAUTH_SIGNING_KEY and FIRST_RUN_SECRET if it is missing
	@./scripts/config.sh setup-local

.PHONY: config-set-secret
config-set-secret: ## Generate AUTH_HMAC_SECRET and upload it (ARGS=--local for .dev.vars, ARGS=--stdin to supply one)
	@./scripts/config.sh set-secret $(ARGS)

.PHONY: config-set-signing-key
config-set-signing-key: ## Generate OAUTH_SIGNING_KEY (RSA 2048) and upload it (ARGS=--local for .dev.vars; CONFIRM_SIGNING_KEY_ROTATE=1 to replace)
	@./scripts/config.sh set-signing-key $(ARGS)

.PHONY: config-set-first-run-secret
config-set-first-run-secret: ## Generate FIRST_RUN_SECRET (an invitation token), upload it and print it once (ARGS=--local for .dev.vars; CONFIRM_FIRST_RUN_ROTATE=1 to replace)
	@./scripts/config.sh set-first-run-secret $(ARGS)

# ---- end-to-end tests -------------------------------------------------------
# Runs the real Worker: the prebuilt wasm under `wrangler dev` (workerd with a
# simulated D1) on a throwaway state directory and a free port, driven over
# HTTP. wrangler.e2e.jsonc has no build.command, so wrangler serves exactly the
# build/ that make produced instead of rebuilding it.
#
# The suite is cut into slices that each run on their own Worker and database
# (docs/TESTING.md, "End-to-end tests"). Locally the harness runs E2E_SHARDS
# slices (default 2) as parallel processes; E2E_SHARDS=1 runs it all on one
# Worker. CI runs one slice per job instead: it sets E2E_SHARD_INDEX and
# E2E_SHARD_TOTAL, which this target passes through to the harness untouched.

.PHONY: test-e2e
test-e2e: $(WASM) ## End-to-end tests against the built Worker (E2E_SHARDS=n for n parallel Workers, default 2)
	E2E_STATE=$(E2E_STATE) go test -tags e2e -count=1 -timeout 10m ./e2e/...

.PHONY: clean
clean: ## Remove build outputs
	rm -rf build $(COVER_OUT) coverage.html $(E2E_STATE)

# ---- aggregate --------------------------------------------------------------

.PHONY: check
check: check-tools fmt-check tidy-check vet lint test coverage ## Fast pre-commit gate (no wasm build, no e2e)

# One build feeds both size and e2e. CI builds it once in a `build`
# job and hands build/ to the others as an artifact.
.PHONY: ci
ci: check size test-e2e ## Everything CI runs
