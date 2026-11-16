# authsu developer commands. Run `make help`. See docs/devops.md.
#
# Production is the default build. Compile-time feature flags are Go build tags
# passed to TinyGo via GO_TAGS; dev targets set DEV_TAGS, `deploy` never does.

SHELL := /bin/bash
.DEFAULT_GOAL := help

include tools.env

# Local D1 state (git-ignored via .wrangler). Dev and e2e use different
# directories so e2e can wipe its own state without touching dev data.
DEV_STATE := .wrangler/state

# E2E uses its own state and builds, never the dev state.
E2E_STATE := .wrangler/e2e-state

# Tags for dev builds and local development. Never used by `deploy`.
DEV_TAGS := debug_routes

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
vet: ## go vet on the host (prod and dev tags, e2e), plus the js/wasm entrypoint
	go vet ./...
	go vet -tags "$(DEV_TAGS)" ./...
	go vet -tags e2e ./e2e/...
	GOOS=js GOARCH=wasm go vet ./cmd/worker
	GOOS=js GOARCH=wasm go vet -tags "$(DEV_TAGS)" ./cmd/worker

# ---- tests ------------------------------------------------------------------

COVER_OUT := coverage.out

.PHONY: test
test: ## Unit tests (race detector on, production tags)
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
size: ## Production wasm size report + budget (fails if over budget or test pkgs linked)
	./scripts/check-size.sh

.PHONY: vuln
vuln: ## Scan dependencies for known vulnerabilities (pinned govulncheck)
	go tool govulncheck ./...

.PHONY: lint
lint: ## golangci-lint (host prod and dev tags, e2e, and the js/wasm entrypoint)
	golangci-lint run ./...
	golangci-lint run --build-tags "$(DEV_TAGS)" ./...
	golangci-lint run --build-tags e2e ./e2e/...
	GOOS=js GOARCH=wasm golangci-lint run ./cmd/worker
	GOOS=js GOARCH=wasm golangci-lint run --build-tags "$(DEV_TAGS)" ./cmd/worker

# ---- build / local dev ------------------------------------------------------

.PHONY: build
build: ## Production build (no flags) -> build/
	GO_TAGS= npm run build

.PHONY: build-dev
build-dev: ## Dev build (DEV_TAGS) -> build/
	GO_TAGS="$(DEV_TAGS)" npm run build

.PHONY: migrate-local
migrate-local: ## Apply D1 migrations to the local dev database
	npx wrangler d1 migrations apply DB --local --persist-to $(DEV_STATE)

.PHONY: db-reset
db-reset: ## Delete local dev database state
	rm -rf $(DEV_STATE)

.PHONY: dev
dev: migrate-local ## Run the Worker locally on :8787 (dev flags, local D1)
	GO_TAGS="$(DEV_TAGS)" npx wrangler dev --local --persist-to $(DEV_STATE)

# ---- end-to-end tests -------------------------------------------------------
# Builds the real Worker (TinyGo -> wasm), starts `wrangler dev` (workerd with a
# simulated D1) on a throwaway state directory and a free port, and drives it
# over HTTP. The Makefile decides the build tags; the harness only runs what was
# built and hands the same tags to wrangler's own rebuild.

.PHONY: test-e2e
test-e2e: ## End-to-end tests against the dev build (DEV_TAGS)
	GO_TAGS="$(DEV_TAGS)" npm run build
	E2E_STATE=$(E2E_STATE) E2E_GO_TAGS="$(DEV_TAGS)" go test -tags e2e -count=1 -timeout 5m ./e2e/...

.PHONY: test-e2e-prod
test-e2e-prod: ## End-to-end tests against the production build (no tags)
	GO_TAGS= npm run build
	E2E_STATE=$(E2E_STATE) E2E_GO_TAGS= go test -tags e2e -count=1 -timeout 5m ./e2e/...

.PHONY: clean
clean: ## Remove build outputs
	rm -rf build $(COVER_OUT) coverage.html $(E2E_STATE)

# ---- aggregate --------------------------------------------------------------

.PHONY: check
check: check-tools fmt-check tidy-check vet lint test coverage ## Fast pre-commit gate (no wasm build, no e2e)

.PHONY: ci
ci: check size test-e2e test-e2e-prod ## Everything CI runs
