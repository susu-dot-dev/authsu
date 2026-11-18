// Package agents implements the API for the agents described in
// docs/agents_design.md: list a user's agents, create one, rename one, and
// revoke one.
//
//	GET    /api/agent        one page of the caller's agents, revoked ones included
//	POST   /api/agent        create an agent and its first API key
//	GET    /api/agent/{id}   one of the caller's agents
//	PATCH  /api/agent/{id}   rename it
//	DELETE /api/agent/{id}   revoke it and its keys
//
// An agent is not an account. It is something a user has, so every route acts
// for the signed-in user and only on that user's agents: nobody, an admin
// included, creates, reads or changes an agent for someone else. An agent that
// belongs to another user is answered exactly as one that does not exist.
//
// Creating an agent hands out authority, so it needs a passkey-backed session:
// this API does not accept an API key yet, and nothing verifies one. The
// response to a create carries the agent's first key, once: only the public half
// is stored, so a lost key cannot be shown again. Agents are short-lived, and
// there is no rotation: replace an agent by revoking it and creating another.
//
// The scope lists in docs/permissions_design.md are not implemented. Every
// agent and key is written with the default agent bundle and nothing reads
// them back; the lists will be validated and enforced in a later change.
package agents

import (
	"context"
	"errors"
	"time"

	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// Limits on what a client may ask for and on what a user may have. The schema
// caps the name at 256 characters; these are the limits Go refuses first, so a
// client gets a proper error rather than a database rejection.
const (
	// MaxNameChars is the longest agent name, in characters (the schema counts
	// characters for TEXT).
	MaxNameChars = 256
	// MaxAgentsPerUser is how many agents one user may have, revoked ones
	// excluded. docs/agents_design.md calls for a per-user limit and leaves its
	// value open; this is a starting value.
	MaxAgentsPerUser = 25
	// KeyLifetime is how long an agent's key lasts. Like a session it is fixed
	// and never extended: an agent that outlives it is replaced.
	KeyLifetime = 90 * 24 * time.Hour
	// DefaultPageSize is how many agents a list returns when it is not asked
	// for a number.
	DefaultPageSize = 25
	// MaxPageSize is the most agents one list returns, whatever it is asked.
	MaxPageSize = 100
)

// FirstPage is the cursor of the first page. Ids are lowercase hex and dashes,
// and 'g' sorts above both, so every id is below it.
const FirstPage = "g"

// DefaultScopes is the scope list every agent and every agent key is created
// with. It names the default agent bundle. It is stored and signed into the
// key's token but nothing interprets it yet (docs/permissions_design.md).
const DefaultScopes = "default:agent"

// Status is where an agent stands. It is derived from the row, never stored.
type Status string

// Statuses.
const (
	// StatusActive means the agent's keys can act.
	StatusActive Status = "active"
	// StatusRevoked means the agent was revoked, by its user or with them.
	StatusRevoked Status = "revoked"
)

// Agent is one agent as its user sees it.
type Agent struct {
	ID string `json:"id"`
	// Name is the label its user gave it.
	Name string `json:"name"`
	// Scopes is the agent's scope list as stored.
	Scopes string `json:"scopes"`
	Status Status `json:"status"`
	// RevokedAt is absent when the agent is not revoked.
	RevokedAt *int64 `json:"revokedAt,omitempty"`
	// CreatedAt is in Unix seconds.
	CreatedAt int64 `json:"createdAt"`
}

// Row is an agent as stored. The owner is not part of it: every query is
// scoped to one, so a row is always the caller's.
type Row struct {
	ID        string
	Name      string
	Scopes    string
	RevokedAt *int64
	CreatedAt int64
}

// StatusOf returns the status of r. Any revoked_at at all revokes, as for users.
func StatusOf(r Row) Status {
	if r.RevokedAt != nil {
		return StatusRevoked
	}

	return StatusActive
}

// Reader is the read side of the agent store. Every method is scoped to one
// owner: an agent of another user is not found.
type Reader interface {
	// List returns up to limit of the user's agents with an id below before,
	// revoked ones included, newest first. FirstPage starts at the newest.
	List(ctx context.Context, userID, before string, limit int) ([]Row, error)
	// Get returns one of the user's agents, or an error wrapping ErrNotFound if
	// the user has none with this id.
	Get(ctx context.Context, userID, id string) (Row, error)
}

// Authenticator verifies a request's session. *session.Service is one.
type Authenticator interface {
	Authenticate(ctx context.Context, getenv func(string) string, req httpapi.Request) (session.Principal, error)
}

// Minter creates an API key. session.MintKey is one; it is a dependency so a
// test can make minting fail, which no valid request does.
type Minter func(issuer session.Issuer, spec session.Spec) (session.Key, error)

// Service is the agent API.
type Service struct {
	sessions Authenticator
	reader   Reader
	batch    atomic.Batch
	now      func() time.Time
	newID    func() string
	mint     Minter
}

// Deps are the service's collaborators. Time, identifiers and minting are
// injected so every branch is reachable from a test.
type Deps struct {
	Sessions Authenticator
	Reader   Reader
	// Batch performs the writes. Nil disables the routes that write.
	Batch atomic.Batch
	// Now is the clock.
	Now func() time.Time
	// NewID returns a fresh UUIDv7 in canonical text form.
	NewID func() string
	// Mint creates an API key (session.MintKey in production).
	Mint Minter
}

// NewService returns a Service. A Deps without Now, NewID or Mint cannot
// create an agent, so Batch is dropped and the routes that write answer 503,
// rather than a create panicking on a nil function.
func NewService(deps Deps) *Service {
	batch := deps.Batch
	if deps.Now == nil || deps.NewID == nil || deps.Mint == nil {
		batch = nil
	}

	return &Service{
		sessions: deps.Sessions, reader: deps.Reader, batch: batch,
		now: deps.Now, newID: deps.NewID, mint: deps.Mint,
	}
}

// ErrNotFound is what Reader.Get reports for an id the user has no agent with.
var ErrNotFound = errors.New("no such agent")

var errNoStore = errors.New("no database is configured")
