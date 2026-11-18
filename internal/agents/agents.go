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
// included, creates, reads or changes an agent for someone else. Every route
// therefore declares no requirement beyond a session, and passes the session's
// user to the store as the owner of whatever it touches. No request value ever
// names an owner, so an agent that belongs to another user is answered, by the
// store's own owner condition, exactly as one that does not exist.
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
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Limits on what a user may have.
const (
	// MaxAgentsPerUser is how many agents one user may have, revoked ones
	// excluded. docs/agents_design.md calls for a per-user limit and leaves its
	// value open; this is a starting value.
	MaxAgentsPerUser = 25

	// KeyLifetime is how long an agent's key lasts. Like a session it is fixed
	// and never extended: an agent that outlives it is replaced.
	KeyLifetime = 90 * 24 * time.Hour
)

// DefaultScopes is the scope list every agent and every agent key is created
// with. It names the default agent bundle. It is stored and signed into the
// key's token but nothing interprets it yet (docs/permissions_design.md).
const DefaultScopes = "default:agent"

// Store is the part of the database the agent routes use. Every method is
// scoped to one owner, the signed-in user: an agent of another user is not
// found. *store.Store satisfies it. A failure must come back classified (the
// store does), because it is sent as is.
type Store interface {
	// ListAgents returns a page of the owner's agents, newest first.
	ListAgents(ctx context.Context, owner string, cursor input.Cursor, limit input.PageLimit) (store.AgentPage, error)
	// GetAgent returns one of the owner's agents, or store.ErrNotFound.
	GetAgent(ctx context.Context, owner string, id input.ID) (store.Agent, error)
	// CreateAgent writes an agent and its first key as one batch, or returns
	// store.ErrConflict when the owner is at the limit or was revoked.
	CreateAgent(ctx context.Context, agent store.NewAgent) error
	// RenameAgent renames one of the owner's agents and returns it as the
	// write left it (a revoked agent keeps its name), or store.ErrNotFound.
	RenameAgent(ctx context.Context, owner string, id input.ID, name input.AgentName) (store.Agent, error)
	// RevokeAgent revokes one of the owner's agents and its keys and returns
	// the agent as the write left it, or store.ErrNotFound.
	RevokeAgent(ctx context.Context, owner string, id input.ID, now time.Time) (store.Agent, error)
}

// Deps are the collaborators of Routes. All are required: Routes panics on a
// missing one, so a handler never meets a nil dependency.
type Deps struct {
	// Store holds the agents.
	Store Store

	// Now is the clock.
	Now func() time.Time

	// NewID returns a fresh UUIDv7 in canonical text form.
	NewID func() string

	// CreateKey creates an API key (auth.CreateKey in production). It is a
	// dependency so a test can make creation fail, which no valid request does.
	CreateKey func(auth.Issuer, auth.KeySpec) (auth.Key, error)
}

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

// present is the client's view of a stored agent. Any revoked_at at all
// revokes, as for users.
func present(stored store.Agent) Agent {
	status := StatusActive
	if stored.RevokedAt != nil {
		status = StatusRevoked
	}

	return Agent{
		ID: stored.ID, Name: stored.Name, Scopes: stored.Scopes, Status: status,
		RevokedAt: stored.RevokedAt, CreatedAt: stored.CreatedAt,
	}
}
