// Package keys implements the API for a user's own API keys described in
// docs/permissions_design.md and docs/secrets_design.md: list them, issue one,
// read one, rename one, and revoke one.
//
//	GET    /api/key        one page of the caller's own keys, revoked and expired ones included
//	POST   /api/key        issue a key; its token is in the response, once
//	GET    /api/key/{id}   one of the caller's own keys
//	PATCH  /api/key/{id}   rename it
//	DELETE /api/key/{id}   revoke it
//
// "Own" is exact. These routes act for the signed-in user and only on that
// user's keys that belong to no agent: an agent's keys are issued with the
// agent (internal/agents) and end with it, and no route here lists, reads,
// renames or revokes one. Every route passes the session's user to the store as
// the owner of whatever it touches, and no request value ever names an owner,
// so a key of another user, and a key of an agent, are answered, by the store's
// own conditions, exactly as one that does not exist.
//
// Every route declares the scope it needs. Issuing a key requires a session (a
// person was present) and refuses agents whatever they hold, so a leaked key
// cannot be used to issue more keys and an agent cannot issue keys for itself.
// Renaming and revoking refuse agents as well, as for agents themselves: they
// are the user's to manage. A user's own key with the scope may list, read,
// rename and revoke the user's other keys.
//
// A key's token is returned only by the POST that created it. Only the token's
// hash is stored (secrets_design.md), so a lost token cannot be shown again: it
// is revoked and replaced. A key's scopes are fixed when it is issued and are
// never changed, so there is no route to change them.
//
// The key that is making a request is never revoked by DELETE: ending the
// credential in use is logout (POST /api/logout), which needs no scope, and a
// route that needs key:revoke must not become a second way to do it. The write
// excludes it, so asking to revoke it is answered as for a key that does not
// exist.
package keys

import (
	"context"
	"io"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// MaxKeysPerUser is how many keys of their own one user may have that are
// active (neither revoked nor expired). A starting value, like
// agents.MaxAgentsPerUser: it keeps a leaked session from filling the table,
// and a user who needs more revokes the ones they no longer use.
const MaxKeysPerUser = 50

// DefaultScopes is the scope list a create gives a key when the request names
// none: the default user bundle. It is written out in full, and never read as
// "none means default" (docs/permissions_design.md).
func DefaultScopes() scope.List { return scope.List{scope.DefaultUser} }

// Store is the part of the database the key routes use. Every method is scoped
// to one owner, the signed-in user, and to keys that belong to no agent: a key
// of another user, or of an agent, is not found. *store.Store satisfies it. A
// failure must come back classified (the store does), because it is sent as is.
type Store interface {
	// ListKeys returns a page of the owner's own keys, newest first.
	ListKeys(ctx context.Context, owner string, cursor input.Cursor, limit input.PageLimit) (store.KeyPage, error)
	// GetKey returns one of the owner's own keys, or store.ErrNotFound.
	GetKey(ctx context.Context, owner string, id input.ID) (store.Key, error)
	// CreateKey writes a key and its secret as one batch, or returns
	// store.ErrConflict when the owner is at the limit or was revoked, in which
	// case nothing was written.
	CreateKey(ctx context.Context, key store.NewKey) error
	// RenameKey renames one of the owner's own keys and returns it as the write
	// left it (a key that is no longer active is left as it is). It returns
	// store.ErrNotFound when the owner has no such key.
	RenameKey(ctx context.Context, owner string, id input.ID, name input.KeyName, now time.Time) (store.Key, error)
	// RevokeKey revokes one of the owner's own keys other than except, the
	// secret the request presented, and returns it as the write left it. It
	// returns store.ErrNotFound when the owner has no such key, which includes
	// except.
	RevokeKey(ctx context.Context, owner string, id input.ID, except string, now time.Time) (store.Key, error)
}

// Deps are the collaborators of Routes. All are required: Routes panics on a
// missing one, so a handler never meets a nil dependency.
type Deps struct {
	// Store holds the keys.
	Store Store

	// Now is the clock.
	Now func() time.Time

	// NewID returns a fresh UUIDv7 in canonical text form.
	NewID func() string

	// Entropy is the source of randomness a key's token is generated from
	// (crypto/rand.Reader in production).
	Entropy io.Reader

	// IssueUserAPIKey issues a user's own API key (auth.IssueUserAPIKey in
	// production). It is a dependency so a test can make issuing fail, which no
	// valid request does.
	IssueUserAPIKey func(r io.Reader, newID func() string, now time.Time, lifetime time.Duration) (auth.Issued, error)
}

// Status is where a key stands. It is derived from the row and the clock, never
// stored.
type Status string

// Statuses.
const (
	// StatusActive means the key can be presented.
	StatusActive Status = "active"
	// StatusRevoked means the key was revoked by its user, or with them.
	StatusRevoked Status = "revoked"
	// StatusExpired means the key reached its expiry without being revoked.
	StatusExpired Status = "expired"
)

// Key is one of a user's own keys as the user sees it. It never carries the
// token or its hash: the token is shown once, in the response to the create.
type Key struct {
	ID string `json:"id"`

	// Name is the label its user gave it.
	Name string `json:"name"`

	// Scopes is the key's scope list as stored, as written.
	Scopes []string `json:"scopes"`

	// Status is revoked before expired: a key that was revoked and has since
	// expired is revoked.
	Status Status `json:"status"`

	// ExpiresAt and CreatedAt are in Unix seconds. RevokedAt is absent when the
	// key is not revoked.
	ExpiresAt int64  `json:"expiresAt"`
	RevokedAt *int64 `json:"revokedAt,omitempty"`
	CreatedAt int64  `json:"createdAt"`
}

// present is the client's view of a stored key at now. A key is revoked once its
// revoked_at has come, as for every secret (a revocation set for later leaves it
// active until then, which is also how the store judges it), and a key whose
// expiry has passed is expired unless it was revoked.
func present(stored store.Key, now time.Time) Key {
	status := StatusActive

	switch {
	case stored.RevokedAt != nil && *stored.RevokedAt <= now.Unix():
		status = StatusRevoked
	case stored.ExpiresAt <= now.Unix():
		status = StatusExpired
	}

	return Key{
		ID: stored.ID, Name: stored.Name, Scopes: scope.Read(stored.Scope).Claim(), Status: status,
		ExpiresAt: stored.ExpiresAt, RevokedAt: stored.RevokedAt, CreatedAt: stored.CreatedAt,
	}
}
