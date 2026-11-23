// Package users is the platform administrators' API for accounts described in
// docs/users_design.md: list them, read one, and revoke one.
//
//	GET    /api/user        list every account, revoked ones included
//	GET    /api/user/{id}   one account
//	DELETE /api/user/{id}   revoke it
//
// Every route is Authenticated and needs an admin scope (scope.UserRead or
// scope.UserRevoke), so the boundary refuses a request without a valid
// credential (401) and one from a caller who is not an administrator, or whose
// scopes fall short (403), before any handler here runs. The role is the one
// stored on the account, read on every request in the lookup that verifies the
// credential (store.ResolveSession, store.ResolveAPIKey), so revoking an admin
// takes effect at once.
//
// Revoking is final and never deletes: the row stays, in its organization, the
// account cannot log in, and none of its sessions, API keys or agents work. The
// last active admin cannot be revoked, because the only recovery from having none
// is wiping the database. An admin may revoke themselves, as long as another
// active admin remains.
//
// These routes are the platform administrators' only. An organization's own
// administrators revoke the accounts of their organization through
// DELETE /api/member/{id} (package orgs), which is the same write with the same
// rules: whoever may revoke an account is decided in that write, from the
// caller's standing, and not by the route. Here the caller is always a platform
// administrator, who may revoke any account.
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
	"github.com/susu-dot-dev/authsu/internal/scope"
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
	// RevokeUser revokes the account id on behalf of the caller and returns it
	// as the write left it: store.ErrNotFound for no such account (or a caller
	// who may not see it), store.ErrLastAdmin when the account is the last
	// active holder of adminRole. A caller who is a platform administrator is
	// refused nothing else.
	RevokeUser(ctx context.Context, id input.ID, caller, adminRole string, now time.Time) (store.User, error)
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
			Credential: auth.Authenticated, Access: auth.Needs(scope.UserRead), Handle: api.list,
		},
		{
			Method: http.MethodGet, Path: itemPath, MaxBody: maxBody,
			Credential: auth.Authenticated, Access: auth.Needs(scope.UserRead), Handle: api.get,
		},
		{
			Method: http.MethodDelete, Path: itemPath, MaxBody: maxBody,
			Credential: auth.Authenticated, Access: auth.Needs(scope.UserRevoke).WithoutAgents(), Handle: api.revoke,
		},
	}
}
