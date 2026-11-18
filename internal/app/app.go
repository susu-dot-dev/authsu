// Package app builds the Worker's HTTP handler from its dependencies.
package app

import (
	"crypto/rand"
	"database/sql"
	"net/http"
	"time"
	"uuid"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/login"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/session"
	"github.com/susu-dot-dev/authsu/internal/users"
)

// Platform carries the resources the Worker runtime provides, never services.
type Platform struct {
	// DB is the D1 database.
	DB *sql.DB
	// Batch runs statements as one atomic unit. D1 offers that only inside the
	// Worker, so the platform supplies it. Nil disables the routes that write
	// (registration finish, login finish and logout answer 503).
	Batch atomic.Batch
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

// Handle registers handler for path and the one method it accepts.
//
// TinyGo's http.ServeMux never matches method-qualified patterns such as
// "GET /x", so the path is registered plain and Serve enforces the method.
func (r router) Handle(method, path string, handler httpapi.Handler) {
	r.mux.Handle(path, httpapi.Serve(method, r.log, handler))
}

// HandleLimited is Handle for a route whose bodies are small, refused with 413
// above maxBody bytes.
func (r router) HandleLimited(method, path string, maxBody int64, handler httpapi.Handler) {
	r.mux.Handle(path, httpapi.ServeLimited(method, maxBody, r.log, handler))
}

// HandleMethods registers one handler per method for path. wildcards names the
// {name} wildcards in path, which Serve copies into Request.PathValues.
func (r router) HandleMethods(path string, wildcards []string, handlers map[string]httpapi.Handler) {
	r.mux.Handle(path, httpapi.ServeMethods(r.log, wildcards, handlers))
}

// NewHandler returns the Worker's HTTP handler. Every feature is built here
// from platform.
func NewHandler(platform Platform) http.Handler {
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

	registrar := registration.NewService(registration.Deps{
		Reader:  sqlReader(platform.DB),
		Batch:   platform.Batch,
		Now:     time.Now,
		Entropy: rand.Reader,
		NewID:   newID,
	})
	routes.HandleLimited(http.MethodPost, "/api/register/begin", registration.MaxBeginBody,
		registrar.BeginHandler(platform.Getenv))
	routes.HandleLimited(http.MethodPost, "/api/register/finish", registration.MaxFinishBody,
		registrar.FinishHandler(platform.Getenv))

	authenticator := login.NewService(login.Deps{
		Reader:  loginReader(platform.DB),
		Batch:   platform.Batch,
		Now:     time.Now,
		Entropy: rand.Reader,
	})
	routes.Handle(http.MethodPost, "/api/login/begin", authenticator.BeginHandler(platform.Getenv))
	routes.Handle(http.MethodPost, "/api/login/finish", authenticator.FinishHandler(platform.Getenv))

	sessions := session.NewService(session.Deps{
		Reader: sessionReader(platform.DB),
		Batch:  platform.Batch,
		Now:    time.Now,
	})
	routes.Handle(http.MethodGet, "/api/session", sessions.WhoAmIHandler(platform.Getenv))
	routes.Handle(http.MethodPost, "/api/logout", sessions.LogoutHandler(platform.Getenv))

	routes.agents(platform, sessions)
	routes.admin(platform, sessions)

	// CORS is outermost so a preflight is answered before routing, which would
	// otherwise answer OPTIONS with 405. The one allowed origin is the UI's.
	return httpapi.CORS(func() string { return allowedOrigin(platform.Getenv) }, routes.mux)
}

// agents registers the agent API. Unlike the admin APIs it needs no role: every
// user has agents, and each route acts only on the signed-in user's own.
func (r router) agents(platform Platform, sessions *session.Service) {
	agentRoutes := agents.NewService(agents.Deps{
		Sessions: sessions,
		Reader:   agentReader(platform.DB),
		Batch:    platform.Batch,
		Now:      time.Now,
		NewID:    newID,
		Mint:     session.MintKey,
	}).Handlers(platform.Getenv)
	r.HandleMethods(agents.CollectionPath, nil, agentRoutes.Collection)
	r.HandleMethods(agents.ItemPath, agents.PathWildcards(), agentRoutes.Item)
}

// admin registers the admin APIs. Each authorises through sessions, which reads
// the caller's role from the account on every request.
func (r router) admin(platform Platform, sessions *session.Service) {
	invitationRoutes := invitations.NewService(invitations.Deps{
		Sessions: sessions,
		Reader:   invitationReader(platform.DB),
		Batch:    platform.Batch,
		Now:      time.Now,
		Entropy:  rand.Reader,
		NewID:    newID,
		Types:    invitations.CreatableTypes(),
	}).Handlers(platform.Getenv)
	r.HandleMethods(invitations.CollectionPath, nil, invitationRoutes.Collection)
	r.HandleMethods(invitations.ItemPath, invitations.PathWildcards(), invitationRoutes.Item)

	userRoutes := users.NewService(users.Deps{
		Sessions: sessions,
		Reader:   userReader(platform.DB),
		Batch:    platform.Batch,
		Now:      time.Now,
	}).Handlers(platform.Getenv)
	r.HandleMethods(users.CollectionPath, nil, userRoutes.Collection)
	r.HandleMethods(users.ItemPath, users.PathWildcards(), userRoutes.Item)
}

// newID returns a fresh UUIDv7 in canonical text form, the id of every row the
// services create.
func newID() string { return uuid.NewV7().String() }

// allowedOrigin returns the one origin allowed to call the API from a browser:
// UI_ORIGIN, the origin the UI is served from and the only one a passkey
// ceremony is accepted from. It is empty when it is unset or is not a bare
// origin (so "null", a wildcard or a path is never trusted), and when no getenv
// exists (the host stub), which allows nothing.
func allowedOrigin(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}

	ui, err := deploy.ParseOrigin(getenv(deploy.VarUIOrigin))
	if err != nil {
		return ""
	}

	return ui.String
}

// healthBody is the JSON response body of /healthz.
type healthBody struct {
	Status string `json:"status"`
}

func healthz(httpapi.Request) result.Result[httpapi.Response] {
	return result.Ok(httpapi.JSON(http.StatusOK, healthBody{Status: "ok"}))
}

// sqlReader returns the registration Reader over db, or nil when there is no
// database (the host stub), so registration answers 503 rather than panicking.
func sqlReader(db *sql.DB) registration.Reader {
	if db == nil {
		return nil
	}

	return registration.NewSQLReader(db)
}

// loginReader returns the login Reader over db, or nil when there is no database
// (the host stub), so login answers 503 rather than panicking.
func loginReader(db *sql.DB) login.Reader {
	if db == nil {
		return nil
	}

	return login.NewSQLReader(db)
}

// sessionReader returns the session Reader over db, or nil when there is no
// database, so the session routes answer 503 rather than panicking.
func sessionReader(db *sql.DB) session.Reader {
	if db == nil {
		return nil
	}

	return session.NewSQLReader(db)
}

// invitationReader returns the invitations Reader over db, or nil when there is
// no database, so the invitation routes answer 503 rather than panicking.
func invitationReader(db *sql.DB) invitations.Reader {
	if db == nil {
		return nil
	}

	return invitations.NewSQLReader(db)
}

// userReader returns the users Reader over db, or nil when there is no
// database, so the user routes answer 503 rather than panicking.
func userReader(db *sql.DB) users.Reader {
	if db == nil {
		return nil
	}

	return users.NewSQLReader(db)
}

// agentReader returns the agents Reader over db, or nil when there is no
// database, so the agent routes answer 503 rather than panicking.
func agentReader(db *sql.DB) agents.Reader {
	if db == nil {
		return nil
	}

	return agents.NewSQLReader(db)
}
