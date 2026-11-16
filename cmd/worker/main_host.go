//go:build !(js && wasm)

// Command worker is the Cloudflare Worker entrypoint. It only runs as
// js/wasm; this host stub exists so `go build ./...`, `go vet` and linters
// work on a developer machine.
package main

import (
	"fmt"
	"os"

	"github.com/susu-dot-dev/authsu/internal/app"
)

func main() {
	// Build the same Deps as the Worker so the tag-selected wiring is
	// type-checked and linted on the host in every flag state. The platform
	// resources (D1, the Worker environment) exist only in js/wasm, so the
	// host stub supplies none.
	_ = app.NewHandler(app.Deps{Diagnostics: diagnostics()}, app.Platform{})

	fmt.Fprintln(os.Stderr, "authsu runs as a Cloudflare Worker; use `make dev`.")
	os.Exit(1)
}
