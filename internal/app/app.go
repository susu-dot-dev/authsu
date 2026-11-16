// Package app builds the Worker's HTTP handler from its dependencies.
package app

import (
	"database/sql"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/diag"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
)

// Deps holds the behaviour that cmd/worker selects at build time with build
// tags (see docs/devops.md, "Feature flags"). A nil field means the safe
// production behaviour.
//
// Deps is not a service registry. Features that are always on do not belong
// here: they are built inside this package from the Platform resources.
type Deps struct {
	// Diagnostics adds developer routes. Nil means none (production).
	Diagnostics diag.Diagnostics
}

// Platform holds the resources that exist only inside the Worker runtime, so
// cmd/worker has to supply them. It carries resources, never services.
type Platform struct {
	// DB is the D1 database.
	DB *sql.DB

	// Getenv reads a deploy-time secret or variable. It is called per request,
	// because the Worker's environment only exists while a request is handled.
	Getenv func(name string) string
}

// NewHandler returns the Worker's root HTTP handler.
//
// TinyGo's http.ServeMux never matches method-qualified patterns such as
// "GET /x", so register plain paths and dispatch on r.Method.
func NewHandler(deps Deps, platform Platform) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.Handle("/api/first-run", firstrun.Handler(platform.DB, platform.Getenv))

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
