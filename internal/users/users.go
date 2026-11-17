// Package users implements the admin API for accounts described in
// docs/users_design.md: list them, read one, and revoke one.
//
//	GET    /api/user        list every account, revoked ones included
//	GET    /api/user/{id}   one account
//	DELETE /api/user/{id}   revoke it
//
// Every route requires a session (401) whose account is an admin (403). The
// role is the one stored on the account, read on each request in the same
// lookup that verifies the session (see session.Verifier), so demoting or
// revoking an admin takes effect at once.
//
// Revoking is final and never deletes: the row stays, the account cannot log
// in, and none of its sessions verify. The last active admin cannot be
// revoked, because the only recovery from having none is wiping the database.
package users

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// Status is where an account stands. It is derived from the row, never stored.
type Status string

// Statuses.
const (
	// StatusActive means the account can log in.
	StatusActive Status = "active"
	// StatusRevoked means an admin revoked it.
	StatusRevoked Status = "revoked"
)

// User is one account as an admin sees it. It never carries the WebAuthn user
// handle, which is an identifier for authenticators, not for people.
type User struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	// InvitationID is the invitation the account was created from.
	InvitationID string `json:"invitationId"`
	// Profile is users.profile as stored: a JSON object, such as the name
	// given at registration.
	Profile json.RawMessage `json:"profile"`
	Status  Status          `json:"status"`
	// RevokedAt is absent when the account is not revoked.
	RevokedAt *int64 `json:"revokedAt,omitempty"`
	// CreatedAt is in Unix seconds.
	CreatedAt int64 `json:"createdAt"`
}

// Row is an account as stored.
type Row struct {
	ID           string
	Role         string
	InvitationID string
	Profile      string
	RevokedAt    *int64
	CreatedAt    int64
}

// StatusOf returns the status of r. Any revoked_at at all revokes, matching the
// session and login queries, which test only that it is set.
func StatusOf(r Row) Status {
	if r.RevokedAt != nil {
		return StatusRevoked
	}

	return StatusActive
}

// Reader is the read side of the account store.
type Reader interface {
	// List returns every account, revoked ones included, newest first.
	List(ctx context.Context) ([]Row, error)
	// Get returns one account, or an error wrapping ErrNotFound if there is
	// none with this id.
	Get(ctx context.Context, id string) (Row, error)
}

// Authenticator verifies a request's session. *session.Service is one.
type Authenticator interface {
	Authenticate(ctx context.Context, getenv func(string) string, req httpapi.Request) (session.Principal, error)
}

// Service is the account API.
type Service struct {
	sessions Authenticator
	reader   Reader
	batch    atomic.Batch
	now      func() time.Time
}

// Deps are the service's collaborators. The clock is injected so every branch
// is reachable from a test.
type Deps struct {
	Sessions Authenticator
	Reader   Reader
	// Batch performs the writes. Nil disables revocation.
	Batch atomic.Batch
	// Now is the clock.
	Now func() time.Time
}

// NewService returns a Service.
func NewService(deps Deps) *Service {
	return &Service{sessions: deps.Sessions, reader: deps.Reader, batch: deps.Batch, now: deps.Now}
}

// ErrNotFound is what Reader.Get reports for an id nothing has.
var ErrNotFound = errors.New("no such user")

var errNoStore = errors.New("no database is configured")
