// Package app builds the Worker's HTTP handler from its dependencies.
//
// It is the composition root that can be exercised on the host: cmd/worker
// supplies platform-specific dependencies (which only exist under js/wasm) in
// a Deps value, and everything else is plain Go tested against fakes.
package app

import (
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/diag"
)

// Deps holds the dependencies supplied by cmd/worker. Fields that vary between
// production and dev builds are selected there by build tag; a nil field means
// the safe production behaviour.
type Deps struct {
	// Diagnostics adds developer routes. Nil means none (production).
	Diagnostics diag.Diagnostics
}

// NewHandler returns the Worker's root HTTP handler.
//
// TinyGo's http.ServeMux never matches method-qualified patterns such as
// "GET /x", so register plain paths and dispatch on r.Method.
func NewHandler(deps Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)

	if deps.Diagnostics != nil {
		deps.Diagnostics.Register(mux)
	}

	return mux
}

func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}
