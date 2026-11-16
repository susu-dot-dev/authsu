# authsu developer commands. Run `make help`. See docs/devops.md.
#
# Production is the default build. Compile-time feature flags are Go build tags
# passed to TinyGo via GO_TAGS; dev targets set DEV_TAGS, `deploy` never does.

SHELL := /bin/bash
.DEFAULT_GOAL := help

include tools.env

# Tags for dev builds and local development. Never used by `deploy`.
# (Empty until the first flag is added.)
DEV_TAGS :=

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

.PHONY: fmt
fmt: ## Format Go code
	gofmt -s -w .

.PHONY: fmt-check
fmt-check: ## Fail if Go code is not gofmt-clean
	@out="$$(gofmt -s -l .)"; if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet on the host, plus a compile check of the js/wasm entrypoint
	go vet ./...
	GOOS=js GOARCH=wasm go vet ./cmd/worker

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

.PHONY: lint
lint: ## golangci-lint (host, dev tags if any, and the js/wasm entrypoint)
	golangci-lint run ./...
	@if [ -n "$(DEV_TAGS)" ]; then golangci-lint run --build-tags "$(DEV_TAGS)" ./...; fi
	GOOS=js GOARCH=wasm golangci-lint run ./cmd/worker

# ---- build / local dev ------------------------------------------------------

.PHONY: build
build: ## Production build (no flags) -> build/
	GO_TAGS= npm run build

.PHONY: build-dev
build-dev: ## Dev build (DEV_TAGS) -> build/
	GO_TAGS="$(DEV_TAGS)" npm run build

.PHONY: dev
dev: ## Run the Worker locally on :8787 (dev flags)
	GO_TAGS="$(DEV_TAGS)" npx wrangler dev --local

.PHONY: clean
clean: ## Remove build outputs
	rm -rf build $(COVER_OUT) coverage.html

# ---- aggregate --------------------------------------------------------------

.PHONY: check
check: check-tools fmt-check vet lint test coverage ## Fast pre-commit gate (no wasm build, no e2e)
