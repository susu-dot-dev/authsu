// Package agents implements the API for the agents described in
// docs/agents_design.md: list a user's agents, create one (optionally with its
// labels), change one (rename it, add and remove its labels), and revoke one.
//
//	GET    /api/agent        one page of the caller's agents, revoked ones included;
//	                         ?label=x keeps only those that have the label x,
//	                         ?sandbox=id only those in that sandbox
//	POST   /api/agent        create an agent, its first API key and its labels, if any,
//	                         optionally in a sandbox (sandboxId)
//	GET    /api/agent/{id}   one of the caller's agents
//	PATCH  /api/agent/{id}   rename it, and add and remove labels, atomically
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
// Every route declares the scope it needs (docs/permissions_design.md). A user
// may call them with a session or an API key; an agent may use only the routes
// its scopes allow, and never rename or revoke (agents are peers under their
// user, so those refuse agents whatever they hold).
//
// Creating an agent hands out authority. A user chooses the new agent's scopes
// and its first key's freely: the user's role bounds every request, so neither
// can exceed what the user may do. An agent that holds agent:create is bounded
// by itself: the new agent has the creating agent's scopes, and its key may hold
// only entries of the creating key's own list. The response to a create carries
// the agent's first key, once: only the key's hash is stored, so a lost key
// cannot be shown again. Agents are short-lived, and there is no rotation:
// replace an agent by revoking it and creating another.
//
// An agent may be confined to a sandbox (docs/orgs_design.md). A user creates
// one by naming a sandbox they administer that has not expired, and the write
// checks that, so anything else is a 404 as for an agent that does not exist. An
// agent creating an agent always puts it in its own sandbox (or in none, for an
// ordinary agent): the new agent's sandbox is read from the creating agent's row
// in the write, and a request that names a different one is refused. An agent
// that is confined reaches only the agents of its own sandbox, here and in every
// route it may call (an ordinary agent likewise reaches only ordinary agents),
// while a user reaches all of their own, whichever sandbox they are in. These
// are the only routes a sandboxed agent may use at all (auth.Access.InSandbox).
//
// A create may give the new agent labels, whoever is creating. They are written
// in the same batch as the agent and its key, so a create gives the agent all of
// them or creates nothing, and the agent is never seen without them. Labels are
// the owner's own bookkeeping and carry no authority, so, unlike scopes, they
// are not bounded by the creating agent and are not copied from it. Edits after
// creation are PATCH's (add and remove), never a replacement of the whole set.
package agents

import (
	"context"
	"io"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// MaxAgentsPerUser is how many agents one user may have, revoked ones
// excluded. docs/agents_design.md calls for a per-user limit and leaves its
// value open; this is a starting value.
const MaxAgentsPerUser = 25

// DefaultScopes is the scope list a user's create gives an agent and its key
// when the request names none: the default agent bundle. It is written out in
// full, and never read as "none means default" (docs/permissions_design.md).
func DefaultScopes() scope.List { return scope.List{scope.DefaultAgent} }

// Store is the part of the database the agent routes use. Every method is
// scoped to one owner, the signed-in user: an agent of another user is not
// found. *store.Store satisfies it. A failure must come back classified (the
// store does), because it is sent as is.
type Store interface {
	// ListAgents returns a page of the agents the reach allows, newest first,
	// only those with the filter's label and in the filter's sandbox when they
	// are set.
	ListAgents(
		ctx context.Context, reach store.AgentReach, cursor input.Cursor, limit input.PageLimit, filter store.AgentFilter,
	) (store.AgentPage, error)
	// GetAgent returns one of the agents the reach allows, or store.ErrNotFound.
	GetAgent(ctx context.Context, reach store.AgentReach, id input.ID) (store.Agent, error)
	// CreateAgent writes an agent, its first key and its labels as one batch and
	// returns the agent's scope list and sandbox as the write stored them, or
	// returns store.ErrSandboxUnavailable when a user named a sandbox that is
	// not an unexpired sandbox they administer, or store.ErrConflict when the
	// owner is at the limit or was revoked, in which case nothing was written,
	// labels included.
	CreateAgent(ctx context.Context, agent store.NewAgent) (store.CreatedAgent, error)
	// PatchAgent renames one of the owner's agents and adds and removes its
	// labels as one batch, and returns it as the batch left it (a revoked agent
	// is left as it is). It returns store.ErrNotFound when the owner has no such
	// agent, and store.ErrConflict when the patch would leave the agent with
	// more labels than patch.MaxLabels, in which case nothing changed.
	PatchAgent(ctx context.Context, owner string, id input.ID, patch store.AgentPatch) (store.Agent, error)
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

	// Entropy is the source of randomness a key's token is generated from
	// (crypto/rand.Reader in production).
	Entropy io.Reader

	// IssueAPIKey issues an API key (auth.IssueAPIKey in production). It is a
	// dependency so a test can make issuing fail, which no valid request does.
	IssueAPIKey func(r io.Reader, newID func() string, now time.Time, lifetime time.Duration) (auth.Issued, error)
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

	// Name is the display name its user gave it.
	Name string `json:"name"`

	// Scopes is the agent's scope list as stored, as written.
	Scopes []string `json:"scopes"`
	Status Status   `json:"status"`

	// RevokedAt is absent when the agent is not revoked.
	RevokedAt *int64 `json:"revokedAt,omitempty"`

	// CreatedAt is in Unix seconds.
	CreatedAt int64 `json:"createdAt"`

	// Labels are the agent's labels, in ascending order. It is always present,
	// and an empty list for an agent with none.
	Labels []string `json:"labels"`

	// SandboxID is the sandbox the agent is confined to. It is absent for an
	// ordinary agent.
	SandboxID *string `json:"sandboxId,omitempty"`
}

// present is the client's view of a stored agent. Any revoked_at at all
// revokes, as for users.
func present(stored store.Agent) Agent {
	status := StatusActive
	if stored.RevokedAt != nil {
		status = StatusRevoked
	}

	return Agent{
		ID: stored.ID, Name: stored.Name, Scopes: scope.Read(stored.Scopes).Claim(), Status: status,
		RevokedAt: stored.RevokedAt, CreatedAt: stored.CreatedAt, Labels: stored.Labels, SandboxID: stored.SandboxID,
	}
}
