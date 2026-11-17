// Package app builds the Worker's HTTP handler from its dependencies.
package app

import (
	"crypto/rand"
	"database/sql"
	"net/http"
	"time"
	"uuid"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/login"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/session"
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
		NewID:   func() string { return uuid.NewV7().String() },
	})
	routes.Handle(http.MethodPost, "/api/register/begin", registrar.BeginHandler(platform.Getenv))
	routes.Handle(http.MethodPost, "/api/register/finish", registrar.FinishHandler(platform.Getenv))

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

	return routes.mux
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
