// Package invitations is the admin API for invitations described in
// docs/invitations_design.md: list them, create one, change how many accounts
// it may create, and revoke it.
//
//	GET    /api/invitation        list every invitation, revoked ones included
//	POST   /api/invitation        create an invitation
//	PATCH  /api/invitation/{id}   change the number of accounts it may create
//	DELETE /api/invitation/{id}   revoke it
//
// Every route needs a session (401) whose account is an admin (403): both are
// declared on the routes and enforced by the auth boundary before a handler
// runs. The role is the one stored on the account, read on each request, so
// demoting an admin takes effect at once.
//
// An invitation is identified by its id, never by its code. The code is shown
// once, in the response to the POST that created it; only its hash is stored
// (input.InvitationCode.Hash, the one place codes are hashed), so no route can
// return it again.
//
// Each request reads the clock once, and that reading is the request's "now":
// the expiry a create is checked against, the time a revoke records and the
// instant a status is derived at are the same moment.
package invitations

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// The routes' paths. The collection takes GET and POST; one invitation takes
// PATCH and DELETE.
const (
	CollectionPath = "/api/invitation"
	ItemPath       = CollectionPath + "/{id}"
)

// MaxBody is the largest request body any invitation route reads, in bytes.
// The biggest legitimate one is a create with a 256-character label that is
// all escapes (6 bytes each), about 1.6 KiB, so this leaves room and refuses
// anything that could only be an attempt to make the route read more.
const MaxBody = 4 << 10

// CodeBytes is the entropy of a generated code: 256 bits, which is 43
// base64url characters, matching what docs/invitations_design.md assumes.
const CodeBytes = 32

// Store is the part of the database the routes use. *store.Store satisfies it.
// Failures come back already classified (see the store package), and the routes
// send them as they are.
type Store interface {
	// ListInvitations returns every invitation, newest first.
	ListInvitations(ctx context.Context) ([]store.Invitation, error)
	// CreateInvitation inserts an invitation and returns the stored row.
	CreateInvitation(ctx context.Context, invitation store.NewInvitation) (store.Invitation, error)
	// UpdateNumInvites sets the cap and returns the row as the write left it
	// and whether it applied; store.ErrNotFound when there is no such row.
	UpdateNumInvites(ctx context.Context, id input.ID, n input.NumInvites) (store.Invitation, bool, error)
	// RevokeInvitation revokes as of now and returns the row as the write left
	// it; store.ErrNotFound when there is no such row.
	RevokeInvitation(ctx context.Context, id input.ID, now time.Time) (store.Invitation, error)
}

// Deps are the collaborators of the routes. All are required, and Routes panics
// on a missing one: a deployment that lacks a dependency is not an invitation
// service with a degraded mode.
type Deps struct {
	Store Store
	// Now is the clock.
	Now func() time.Time
	// Entropy supplies the random bytes of a code (crypto/rand.Reader in
	// production).
	Entropy io.Reader
	// NewID returns a fresh UUIDv7 in canonical text form.
	NewID func() string
}

// Routes returns the four invitation routes. It panics when a dependency is
// missing, a programming error.
func Routes(deps Deps) []auth.Route {
	handlers := newHandlers(deps)

	return []auth.Route{
		route(http.MethodGet, CollectionPath, handlers.list),
		route(http.MethodPost, CollectionPath, handlers.create),
		route(http.MethodPatch, ItemPath, handlers.update),
		route(http.MethodDelete, ItemPath, handlers.revoke),
	}
}

// route declares one admin-only route. Every invitation route is the same
// shape: the declaration is the whole of the access rule.
func route(method, path string, handle func(*auth.Call) result.Result[httpapi.Response]) auth.Route {
	return auth.Route{
		Method: method, Path: path, MaxBody: MaxBody,
		Credential: auth.Session, Require: auth.Admin, Handle: handle,
	}
}

// handlers carries the dependencies of the route handlers.
type handlers struct {
	store   Store
	now     func() time.Time
	entropy io.Reader
	newID   func() string
}

// newHandlers validates deps.
func newHandlers(deps Deps) *handlers {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Now": deps.Now == nil, "Entropy": deps.Entropy == nil, "NewID": deps.NewID == nil,
	} {
		if missing {
			panic("invitations: Deps." + name + " is required")
		}
	}

	return &handlers{store: deps.Store, now: deps.Now, entropy: deps.Entropy, newID: deps.NewID}
}
