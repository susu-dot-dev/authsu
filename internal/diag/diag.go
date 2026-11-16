// Package diag provides developer diagnostics endpoints.
//
// Diagnostics is an interface so the behaviour can be chosen at build time:
// cmd/worker wires On under the debug_routes build tag and Off otherwise. Both
// implementations are ordinary untagged code, so both are fully tested; only
// the wiring is tagged. See docs/devops.md ("Feature flags").
package diag

import (
	"net/http"
	"runtime"

	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Router registers a handler for a path and the one method it accepts. It is
// implemented by the app, so diagnostics go through the same request and error
// handling as every other route.
type Router interface {
	Handle(method, path string, handler httpapi.Handler)
}

// Diagnostics registers diagnostic routes on a Router.
type Diagnostics interface {
	// Register adds this implementation's routes to router. It may add none.
	Register(router Router)
}

// Off registers nothing. It is the production implementation.
type Off struct{}

// Register implements Diagnostics.
func (Off) Register(Router) {}

// On registers developer-only routes. It must never be wired into a
// production build.
type On struct{}

// Register implements Diagnostics.
func (On) Register(router Router) {
	router.Handle(http.MethodGet, "/debug/info", info)
}

// infoBody is the JSON response body of /debug/info.
type infoBody struct {
	DebugRoutes string `json:"debugRoutes"`
	Go          string `json:"go"`
	Platform    string `json:"platform"`
}

func info(httpapi.Request) result.Result[httpapi.Response] {
	return result.Ok(httpapi.JSON(http.StatusOK, infoBody{
		DebugRoutes: "on",
		Go:          runtime.Version(),
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
	}))
}
