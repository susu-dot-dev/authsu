// Package users is the admin API for accounts described in
// docs/users_design.md: list them, read one, and revoke one.
//
//	GET    /api/user        list every account, revoked ones included
//	GET    /api/user/{id}   one account
//	DELETE /api/user/{id}   revoke it
//
// Every route is declared with a session credential and the auth.Admin
// requirement, so the boundary refuses a request without a session (401) and one
// from a signed-in account that is not an admin (403) before any handler here
// runs. The role is the one stored on the account, read on every request in the
// lookup that verifies the session (store.ActiveKey), so revoking an admin
// takes effect at once.
//
// Revoking is final and never deletes: the row stays, the account cannot log
// in, and none of its sessions verify. The last active admin cannot be
// revoked, because the only recovery from having none is wiping the database.
// An admin may revoke themselves, as long as another active admin remains.
//
// A stored profile that is not a JSON object is logged and served as an empty
// object: one corrupt row must not hide every other account from the admin who
// needs to find and revoke them, nor make a revocation that was applied look as
// if it failed.
//
// The package holds no SQL: the store owns it, including the last-admin guard,
// which must be part of the write (store.RevokeUser).
package users

import (
	"context"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Paths of the routes.
const (
	collectionPath = "/api/user"
	itemPath       = "/api/user/{id}"
)

// maxBody is the most a request body may be. No route reads a body, so this
// only bounds the work a client can make the boundary do before it is refused.
const maxBody = 1024

// Store is the part of the account store the routes use. *store.Store
// satisfies it. Failures of the database must come back classified, as the
// store does, because they are sent to the client as they are.
type Store interface {
	// ListUsers returns every account, revoked ones included, newest first.
	ListUsers(ctx context.Context) ([]store.User, error)
	// GetUser returns the account id, or store.ErrNotFound.
	GetUser(ctx context.Context, id input.ID) (store.User, error)
	// RevokeUser revokes the account id and returns it as the write left it:
	// store.ErrNotFound for no such account, store.ErrLastAdmin when the
	// account is the last active holder of adminRole.
	RevokeUser(ctx context.Context, id input.ID, adminRole string, now time.Time) (store.User, error)
}

// Deps are the collaborators of Routes. All are required.
type Deps struct {
	// Store holds the accounts.
	Store Store
	// Now is the clock, read once per revocation.
	Now func() time.Time
	// Log records an account whose stored profile is not a JSON object. The
	// request still succeeds, with an empty profile for that account, so the
	// entry is the only sign that the stored data is wrong.
	Log httpapi.Logger
}

// Routes returns the account routes. It panics when a dependency is missing:
// there is no degraded mode, and a deployment that lacks one is found at start
// and not by a request.
func Routes(deps Deps) []auth.Route {
	if deps.Store == nil {
		panic("users: Deps.Store is required")
	}

	if deps.Now == nil {
		panic("users: Deps.Now is required")
	}

	if deps.Log == nil {
		panic("users: Deps.Log is required")
	}

	api := handlers{store: deps.Store, now: deps.Now, log: deps.Log}

	return []auth.Route{
		{
			Method: http.MethodGet, Path: collectionPath, MaxBody: maxBody,
			Credential: auth.Session, Require: auth.Admin, Handle: api.list,
		},
		{
			Method: http.MethodGet, Path: itemPath, MaxBody: maxBody,
			Credential: auth.Session, Require: auth.Admin, Handle: api.get,
		},
		{
			Method: http.MethodDelete, Path: itemPath, MaxBody: maxBody,
			Credential: auth.Session, Require: auth.Admin, Handle: api.revoke,
		},
	}
}
