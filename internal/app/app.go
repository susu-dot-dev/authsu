// Package app builds the Worker's HTTP handler: it is the one place that knows
// which features exist.
//
// Each feature declares its endpoints as auth.Routes. app collects them, adds
// the health check, hands the whole table to auth.Handler (which authenticates
// and dispatches every route the same way) and puts CORS around the result.
// Nothing here decides who may do what: that is each route's own declaration.
//
// The runtime is fixed: the real clock, crypto/rand and UUIDv7 ids. The
// Platform supplies only what the Worker environment provides, and a
// feature's tests supply their own fakes, so there is no switch for tests here.
package app

import (
	"crypto/rand"
	"net/http"
	"slices"
	"time"
	"uuid"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/fetch"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/keys"
	"github.com/susu-dot-dev/authsu/internal/login"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/session"
	"github.com/susu-dot-dev/authsu/internal/store"
	"github.com/susu-dot-dev/authsu/internal/users"
)

// PathHealth is the health check.
const PathHealth = "/healthz"

// Platform carries the resources the Worker runtime provides, never services.
// Every field is required.
type Platform struct {
	// Exec runs database statements as one atomic batch (D1 in production).
	Exec store.Exec
	// Getenv reads a deploy-time secret or variable. It is called per request,
	// because the Worker's environment only exists while a request is handled.
	Getenv func(name string) string
	// Log records an error the HTTP boundary turned into a response, with the
	// request it failed on.
	Log httpapi.Logger
	// Fetch sends an outbound HTTP request (the platform's fetch in
	// production). It must not follow redirects; internal/fetch.GetJSON
	// applies every other limit.
	Fetch fetch.Doer
}

// NewHandler returns the Worker's HTTP handler. Every feature is built here
// from platform.
//
// It panics when a Platform field is nil, as every constructor in this
// codebase does for a missing dependency: the wiring is fixed in code, so the
// mistake is found by the first start, never by a request.
func NewHandler(platform Platform) http.Handler {
	for name, missing := range map[string]bool{
		"Exec": platform.Exec == nil, "Getenv": platform.Getenv == nil, "Log": platform.Log == nil,
		"Fetch": platform.Fetch == nil,
	} {
		if missing {
			panic("app: Platform." + name + " is required")
		}
	}

	db := store.New(platform.Exec)

	routes := slices.Concat(
		[]auth.Route{healthRoute()},
		firstrun.Routes(firstrun.Deps{Store: db, Now: time.Now, NewID: newID}),
		registration.Routes(registration.Deps{Store: db, Now: time.Now, Entropy: rand.Reader, NewID: newID}),
		login.Routes(login.Deps{
			Store: db, Now: time.Now, Entropy: rand.Reader, NewID: newID, IssueSession: auth.IssueSession,
		}),
		session.Routes(session.Deps{Store: db, Now: time.Now}),
		agents.Routes(agents.Deps{
			Store: db, Now: time.Now, NewID: newID, Entropy: rand.Reader, IssueAPIKey: auth.IssueAPIKey,
		}),
		keys.Routes(keys.Deps{
			Store: db, Now: time.Now, NewID: newID, Entropy: rand.Reader, IssueUserAPIKey: auth.IssueUserAPIKey,
		}),
		invitations.Routes(invitations.Deps{Store: db, Now: time.Now, Entropy: rand.Reader, NewID: newID}),
		users.Routes(users.Deps{Store: db, Now: time.Now, Log: platform.Log}),
		oauth.Routes(oauth.Deps{
			Store: db, Resources: resource.Select, Fetch: platform.Fetch, Now: time.Now, Entropy: rand.Reader,
			NewID: newID, MaxAgents: agents.MaxAgentsPerUser, Log: platform.Log,
		}),
	)

	handler := auth.Handler(routes, auth.Deps{
		Credentials: db, Now: time.Now, Getenv: platform.Getenv, Log: platform.Log,
	})

	// CORS is outermost so a preflight is answered before routing, which would
	// otherwise answer OPTIONS with 405. The one allowed origin is the UI's,
	// with credentials; the OAuth paths a client calls from a browser on any
	// origin are the public ones, without (oauth.PublicPaths); and the ones that
	// are navigated to or called by servers get no CORS at all
	// (oauth.NoCORSPaths).
	paths := httpapi.CORSPaths{Public: oauth.PublicPaths(), None: oauth.NoCORSPaths()}

	return httpapi.CORS(func() string { return allowedOrigin(platform.Getenv) }, paths, handler)
}

// newID returns a fresh UUIDv7 in canonical text form, the id of every row the
// services create.
func newID() string { return uuid.NewV7().String() }

// allowedOrigin returns the one origin allowed to call the API from a browser:
// UI_ORIGIN, the origin the UI is served from and the only one a passkey
// ceremony is accepted from. It is empty when it is unset or is not a bare
// origin, so "null", a wildcard or a path is never trusted.
func allowedOrigin(getenv func(string) string) string {
	ui, err := config.ParseOrigin(getenv(config.VarUIOrigin))
	if err != nil {
		return ""
	}

	return ui.String
}

// healthBody is the JSON response body of GET /healthz.
type healthBody struct {
	Status string `json:"status"`
}

// healthRoute is the liveness check. It needs no credential and touches
// neither the configuration nor the database, so it answers while the rest of
// the service is misconfigured or its database is down.
func healthRoute() auth.Route {
	return auth.Route{
		Method: http.MethodGet, Path: PathHealth, MaxBody: 0, Credential: auth.None,
		Handle: func(*auth.Call) result.Result[httpapi.Response] {
			return result.Ok(httpapi.JSON(http.StatusOK, healthBody{Status: "ok"}))
		},
	}
}
