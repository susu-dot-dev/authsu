//go:build !(js && wasm)

// Command worker is the Cloudflare Worker entrypoint. It only runs as
// js/wasm; this host stub exists so `go build ./...`, `go vet` and linters
// work on a developer machine.
package main

import (
	"fmt"
	"os"
)

func main() {
	// The platform resources (D1, the Worker environment) exist only in
	// js/wasm, so there is nothing for the host to hand to internal/app.
	fmt.Fprintln(os.Stderr, "authsu runs as a Cloudflare Worker; use `make dev`.")
	os.Exit(1)
}
