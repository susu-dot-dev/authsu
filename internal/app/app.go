// Package app builds the Worker's HTTP handler from its dependencies.
package app

import (
	"database/sql"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/diag"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Deps are the build-time feature flags: pluggable behaviour that must differ
// between builds. It is not a service registry. Always-on features are built
// inside this package from Platform, so they exist in every build and cannot
// be forgotten by a caller.
type Deps struct {
	// Diagnostics adds developer routes. Nil means none (production).
	Diagnostics diag.Diagnostics
}

// Platform carries the resources the Worker runtime provides, never services.
type Platform struct {
	// DB is the D1 database.
	DB *sql.DB
	// Getenv reads a deploy-time secret or variable. It is called per request,
	// because the Worker's environment only exists while a request is handled.
	Getenv func(name string) string
	// Log records an error the HTTP boundary turned into a response, with the
	// request it failed on. Nil discards it.
	Log httpapi.Logger
}

// router registers handlers on a mux behind httpapi.Serve.
type router struct {
	mux *http.ServeMux
	log httpapi.Logger
}

// Handle implements diag.Router.
//
// TinyGo's http.ServeMux never matches method-qualified patterns such as
// "GET /x", so the path is registered plain and Serve enforces the method.
func (r router) Handle(method, path string, handler httpapi.Handler) {
	r.mux.Handle(path, httpapi.Serve(method, r.log, handler))
}

// NewHandler returns the Worker's HTTP handler.
func NewHandler(deps Deps, platform Platform) http.Handler {
	logger := platform.Log
	if logger == nil {
		logger = func(httpapi.Request, *apierr.Error) {}
	}

	routes := router{mux: http.NewServeMux(), log: logger}

	// "/" is the ServeMux catch-all: every path no other route claims, so an
	// unknown path gets the same JSON error as any other failure. It accepts
	// any method, because the answer to an unknown path does not depend on it.
	routes.mux.Handle("/", httpapi.ServeAny(logger, httpapi.NotFound))

	routes.Handle(http.MethodGet, "/healthz", healthz)
	routes.Handle(http.MethodGet, "/api/first-run", firstrun.Handler(platform.DB, platform.Getenv))

	if deps.Diagnostics != nil {
		deps.Diagnostics.Register(routes)
	}

	return routes.mux
}

// healthBody is the JSON response body of /healthz.
type healthBody struct {
	Status string `json:"status"`
}

func healthz(httpapi.Request) result.Result[httpapi.Response] {
	return result.Ok(httpapi.JSON(http.StatusOK, healthBody{Status: "ok"}))
}
