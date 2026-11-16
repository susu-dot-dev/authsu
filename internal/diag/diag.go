// Package diag provides developer diagnostics endpoints.
//
// Diagnostics is an interface so the behaviour can be chosen at build time:
// cmd/worker wires On under the debug_routes build tag and Off otherwise. Both
// implementations are ordinary untagged code, so both are fully tested; only
// the wiring is tagged. See docs/devops.md ("Feature flags").
package diag

import (
	"fmt"
	"net/http"
	"runtime"
)

// Diagnostics registers diagnostic routes on a mux.
type Diagnostics interface {
	// Register adds this implementation's routes to mux. It may add none.
	Register(mux *http.ServeMux)
}

// Off registers nothing. It is the production implementation.
type Off struct{}

// Register implements Diagnostics.
func (Off) Register(*http.ServeMux) {}

// On registers developer-only routes. It must never be wired into a
// production build.
type On struct{}

// Register implements Diagnostics.
func (On) Register(mux *http.ServeMux) {
	mux.HandleFunc("/debug/info", info)
}

func info(writer http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(writer, "debug_routes=on\ngo=%s\nplatform=%s/%s\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
