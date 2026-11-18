package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// KindAPIKey is japikeys.kind of an API key, such as an agent's. CreateAgent
// writes it. It is bound as an argument and not written into the SQL, so this
// constant is the only place the text is written, and it is the value the auth
// layer derives the token's audience from.
const KindAPIKey = "api_key"

// Error codes of the agent operations. They are stable: clients and dashboards
// may match on them.
const (
	CodeAgentListFailed     = "agent_list_failed"
	CodeAgentListRejected   = "agent_list_rejected"
	CodeAgentLookupFailed   = "agent_lookup_failed"
	CodeAgentLookupRejected = "agent_lookup_rejected"
	CodeAgentCreateFailed   = "agent_create_failed"
	CodeAgentCreateRejected = "agent_create_rejected"
	CodeAgentUpdateFailed   = "agent_update_failed"
	CodeAgentUpdateRejected = "agent_update_rejected"
	CodeAgentRevokeFailed   = "agent_revoke_failed"
	CodeAgentRevokeRejected = "agent_revoke_rejected"
)

// agentsDescription is the client-safe text of every agent operation's
// Unavailable error.
const agentsDescription = "agents are temporarily unavailable"

// agentsFirstPage is the cursor bound of the first page. Ids are lowercase hex
// and dashes, and 'g' sorts above both, so every id is below it. It keeps the
// list query one statement with one shape for every page, and it is internal:
// callers pass an input.Cursor, which is empty for the first page.
const agentsFirstPage = "g"

// Agent is one agent as stored. The owner is not part of it: every operation is
// scoped to one, so an agent is always the caller's.
type Agent struct {
	ID     string
	Name   string
	Scopes string

	// RevokedAt is when the agent was revoked, in Unix seconds, or nil. Any
	// value at all revokes.
	RevokedAt *int64

	// CreatedAt is in Unix seconds.
	CreatedAt int64
}

// readAgent reads one agent row, in the column order every agent statement
// selects or returns: id, name, scopes, revoked_at, created_at.
func readAgent(r *row) Agent {
	// Struct fields are evaluated in order, which is the column order.
	return Agent{
		ID: r.text(), Name: r.text(), Scopes: r.text(),
		RevokedAt: r.optInteger(), CreatedAt: r.integer(),
	}
}

// agentListQuery reads one page of a user's agents, revoked ones included,
// newest first. The id is a UUIDv7, so it is in creation order and is both the
// sort key and the cursor: the page is the agents with an id below the cursor,
// and the cursor is the id of the last agent of the previous page. Keyset
// paging never skips or repeats an agent that exists throughout, whatever is
// created or revoked in between, which an offset would. A page asks for one row
// more than it returns, so the caller can tell whether there is a next page
// without counting.
//
// The owner is part of the match, so a user's page holds only their agents.
//
// Arguments, by number: ?1 user id, ?2 cursor (the id to start below;
// agentsFirstPage for the first page), ?3 rows wanted.
const agentListQuery = `
SELECT id, name, scopes, revoked_at, created_at
FROM agents
WHERE user_id = ?1 AND id < ?2
ORDER BY id DESC
LIMIT ?3`

// AgentPage is one page of a user's agents, newest first.
type AgentPage struct {
	Agents []Agent

	// Next is the cursor of the following page: the id of the last agent of
	// this one. It is empty on the last page. It is an id the database
	// returned and not something a client sent, so it is a plain string.
	Next string
}

// ListAgents returns up to limit of the user's agents with an id below the
// cursor, revoked ones included, newest first. An empty cursor starts at the
// newest agent. owner is the authenticated user's id.
//
// It reads one row more than the page holds. If that row is there, there is a
// next page, and it starts below the last agent that is returned.
func (s *Store) ListAgents(
	ctx context.Context, owner string, cursor input.Cursor, limit input.PageLimit,
) (AgentPage, error) {
	o := op{failed: CodeAgentListFailed, rejected: CodeAgentListRejected, description: agentsDescription}

	before := agentsFirstPage
	if id, ok := cursor.ID(); ok {
		before = id.String()
	}

	// A PageLimit made by its parser is at least 1; the zero value is read as 1
	// and not as a page that could never name a next one.
	size := max(limit.Int(), 1)
	wanted := size + 1

	agents, err := queryAll(ctx, s, o,
		Statement{Query: agentListQuery, Args: []any{owner, before, int64(wanted)}}, readAgent)
	if err != nil {
		return AgentPage{}, err
	}

	// More rows than LIMIT allows is the database not doing what the query says.
	if len(agents) > wanted {
		return AgentPage{}, o.defect(fmt.Errorf("%w: %d rows, want at most %d", errRowCount, len(agents), wanted))
	}

	if len(agents) < wanted {
		return AgentPage{Agents: agents, Next: ""}, nil
	}

	agents = agents[:size]

	return AgentPage{Agents: agents, Next: agents[len(agents)-1].ID}, nil
}

// agentGetQuery reads one agent of a user. The owner is part of the match, so
// another user's agent is not found, which is what the caller is told for an id
// that does not exist at all.
//
// Arguments: id, user id.
const agentGetQuery = `
SELECT id, name, scopes, revoked_at, created_at
FROM agents
WHERE id = ? AND user_id = ?`

// GetAgent returns one of the user's agents. It returns ErrNotFound when the
// user has none with this id, which includes an id that belongs to someone else.
func (s *Store) GetAgent(ctx context.Context, owner string, id input.ID) (Agent, error) {
	o := op{failed: CodeAgentLookupFailed, rejected: CodeAgentLookupRejected, description: agentsDescription}

	return queryOne(ctx, s, o, Statement{Query: agentGetQuery, Args: []any{id.String(), owner}}, readAgent)
}

// insertAgentQuery creates an agent for a user, if the user may have another.
// The conditions are part of the write, because D1 has no interactive
// transaction and a count read before it would race with another create:
//
//   - the owner must be an active account. The owner is read from users here,
//     not trusted from the request, so an account revoked after the request was
//     authenticated gets no agent;
//   - the owner must have fewer than ?6 active agents. The count is taken in
//     the write, so two creates at the limit cannot both succeed.
//
// A conditional INSERT ... SELECT that matches nothing is not an error, so the
// key insert that follows in the same batch depends on this row existing (see
// insertAgentKeyQuery), which turns "no agent was created" into a failed batch.
//
// RETURNING gives the scopes the row was written with, so a caller reports what
// is stored and not what it offered.
//
// Arguments, by number: ?1 id, ?2 name, ?3 scopes, ?4 created_at, ?5 user id,
// ?6 the maximum active agents a user may have.
const insertAgentQuery = `
INSERT INTO agents (id, user_id, name, scopes, created_at)
SELECT ?1, u.id, ?2, ?3, ?4
FROM users u
WHERE u.id = ?5
  AND u.revoked_at IS NULL
  AND (SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL) < ?6
RETURNING scopes`

// insertAgentByAgentQuery creates an agent on behalf of another agent of the
// same user. It is insertAgentQuery with two differences, both part of the
// write for the same reason as its other conditions:
//
//   - the new agent's scopes are the creating agent's, read from that agent's
//     row here and never taken from the request. An agent cannot give a new
//     agent more than it has, and a request cannot misstate what it has;
//   - the creating agent must belong to the owner and still be active, so an
//     agent revoked after the request was authenticated creates nothing.
//
// RETURNING gives the scopes the row was written with, which here are the
// creating agent's as the write read them: the only place they are known, since
// they are not an argument.
//
// Arguments, by number: ?1 id, ?2 name, ?3 the creating agent's id, ?4
// created_at, ?5 user id, ?6 the maximum active agents a user may have.
const insertAgentByAgentQuery = `
INSERT INTO agents (id, user_id, name, scopes, created_at)
SELECT ?1, u.id, ?2, c.scopes, ?4
FROM users u
JOIN agents c ON c.user_id = u.id AND c.id = ?3 AND c.revoked_at IS NULL
WHERE u.id = ?5
  AND u.revoked_at IS NULL
  AND (SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL) < ?6
RETURNING scopes`

// insertAgentKeyQuery stores an agent's API key. The key's owner and the agent
// it belongs to are read from the agent's row, in the write, so the key's
// subject is the agent's owner by construction. If the agent was not created
// (the user was at the limit, or was revoked in the meantime, or the creating
// agent was revoked) the subselect is NULL, user_id is NOT NULL, and the whole
// batch fails as a conflict, which rolls the agent insert back with it. Without
// this the batch would commit with no key.
//
// granted_from and credential_id stay NULL: only a login grants those, and the
// table's CHECK requires an API key to have neither.
//
// Arguments, in order: kid, agent id (for the subselect), kind, jwk,
// expires_at, agent id, scope, created_at.
const insertAgentKeyQuery = `
INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, agent_id, scope, created_at)
VALUES (?, (SELECT user_id FROM agents WHERE id = ?), ?, ?, ?, ?, ?, ?)`

// NewAgent is an agent and its first API key, as a create writes them. The
// caller has already made the key: the store only records it.
type NewAgent struct {
	// ID is the new agent's id, and Owner the user it belongs to.
	ID    string
	Owner string

	// Name is the label the user gave it.
	Name input.AgentName

	// Scopes is the agent's scope list as JSON. When CreatedBy is empty it is
	// written to the agent's row as it is. When CreatedBy is set it is not used:
	// the row gets the creating agent's scopes, read in the write. Either way
	// CreateAgent returns what the row holds.
	Scopes string

	// KeyScope is the key's scope list as JSON: the scope claim signed into its
	// token, copied to the key's row.
	KeyScope string

	// CreatedBy is the id of the agent that is creating this one, or "" when its
	// user is. The new agent is an ordinary agent of the same owner either way,
	// and nothing records who created it: the id only chooses where the scopes
	// come from and what must still be active (see insertAgentByAgentQuery).
	CreatedBy string

	// MaxActive is how many active agents a user may have: the create is
	// refused when the owner already has that many.
	MaxActive int

	// KeyID is the key's kid, KeyJWK its public JWK as JSON, and KeyExpiresAt
	// when it stops working.
	KeyID        string
	KeyJWK       string
	KeyExpiresAt time.Time

	// CreatedAt is when the agent and its key were created.
	CreatedAt time.Time
}

// CreateAgent writes an agent and its first key as one batch: either both exist
// or neither does. See insertAgentQuery and insertAgentKeyQuery for how the
// owner being revoked or at the limit fails the batch and not just the first
// statement.
//
// It returns the scope list the agent's row was written with, as the write
// left it. For an agent created by another agent that is the creating agent's
// list as the write read it, so the caller reports what is stored even if the
// creating agent's scopes changed after the request was verified.
//
// It returns ErrConflict in that case: the owner already has MaxActive active
// agents, the account was revoked after the request was authenticated, or the
// creating agent was revoked. The write cannot tell which, and a revoked
// account has no session to be told on.
// The id and the kid are fresh UUIDv7s, so no other constraint can conflict.
func (s *Store) CreateAgent(ctx context.Context, agent NewAgent) (string, error) {
	o := op{failed: CodeAgentCreateFailed, rejected: CodeAgentCreateRejected, description: agentsDescription}

	insert := Statement{Query: insertAgentQuery, Args: []any{
		agent.ID, agent.Name.String(), agent.Scopes, agent.CreatedAt.Unix(), agent.Owner, int64(agent.MaxActive),
	}}

	if agent.CreatedBy != "" {
		insert = Statement{Query: insertAgentByAgentQuery, Args: []any{
			agent.ID, agent.Name.String(), agent.CreatedBy, agent.CreatedAt.Unix(), agent.Owner, int64(agent.MaxActive),
		}}
	}

	stored, err := result.Of(s.run(ctx, o, insert,
		Statement{Query: insertAgentKeyQuery, Args: []any{
			agent.KeyID, agent.ID, KindAPIKey, agent.KeyJWK, agent.KeyExpiresAt.Unix(),
			agent.ID, agent.KeyScope, agent.CreatedAt.Unix(),
		}},
	)).
		Then(func(results []Result) (string, error) { return one(results[0].Rows, o, readScopes) }).
		MapErr(func(err error) error { return agentInsertShape(o, err) }).
		Get()

	return stored, err //nolint:wrapcheck // every error in the chain is already classified by run, one or agentInsertShape
}

// agentInsertShape classifies a failure to read the row an agent insert
// returns. The key insert names the agent's row, so a batch that succeeded
// without it is not a conflict or a missing agent: the database did not do what
// the statements say, which is a defect. Any other error is returned as it is.
func agentInsertShape(o op, err error) error {
	if errors.Is(err, ErrNotFound) {
		return o.defect(fmt.Errorf("%w: the insert returned no row", errRowCount))
	}

	return err
}

// readScopes reads the one column an agent insert returns.
func readScopes(r *row) string { return r.text() }

// agentRenameQuery renames an agent, unless it is revoked. A revoked agent is
// final, as for invitations: changing it would suggest it could be revived.
//
// The row is matched by id and owner alone, and the CASE decides whether the
// name changes, so RETURNING reports the row as the statement left it, and the
// outcome is read off it. The agent was renamed if it is not revoked. No row
// returned means the user has no such agent.
//
// RETURNING is the columns readAgent reads, in that order.
//
// Arguments, by number: ?1 name, ?2 id, ?3 user id.
const agentRenameQuery = `
UPDATE agents
SET name = CASE WHEN revoked_at IS NULL THEN ?1 ELSE name END
WHERE id = ?2 AND user_id = ?3
RETURNING id, name, scopes, revoked_at, created_at`

// RenameAgent renames one of the user's agents and returns the agent as the
// write left it. A revoked agent keeps its name and is returned as it is: the
// row comes back from the same statement that decided, so there is no read in
// between to disagree, and the caller reads RevokedAt to tell it was refused.
// It returns ErrNotFound when the user has no such agent.
//
// The statement sets nothing the code has not checked, so a constraint failure
// of any kind is a defect on our side, a conflict included.
func (s *Store) RenameAgent(ctx context.Context, owner string, id input.ID, name input.AgentName) (Agent, error) {
	o := op{failed: CodeAgentUpdateFailed, rejected: CodeAgentUpdateRejected, description: agentsDescription}

	results, err := s.run(ctx, o,
		Statement{Query: agentRenameQuery, Args: []any{name.String(), id.String(), owner}})
	if err != nil {
		return Agent{}, rejectAgentConflict(o, err)
	}

	return one(results[0].Rows, o, readAgent)
}

// agentRevokeQuery revokes an agent now. The row is matched by id and owner, so
// a user can revoke only their own agents, and one that is already revoked
// keeps its earlier time (the COALESCE), so revoking twice succeeds and cannot
// move the revocation later. RETURNING gives the row as it was left, and no row
// returned means the user has no such agent.
//
// RETURNING is the columns readAgent reads, in that order.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 id, ?3 user id.
const agentRevokeQuery = `
UPDATE agents
SET revoked_at = COALESCE(revoked_at, ?1)
WHERE id = ?2 AND user_id = ?3
RETURNING id, name, scopes, revoked_at, created_at`

// agentRevokeKeysQuery revokes every key of an agent, in the same batch as
// agentRevokeQuery and after it. It applies only if the agent is revoked once
// agentRevokeQuery has run, and only to keys of that owner's agent. A key whose
// revocation is already due keeps its time; one scheduled for later is brought
// forward.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 agent id, ?3 user id.
const agentRevokeKeysQuery = `
UPDATE japikeys
SET revoked_at = ?1
WHERE agent_id = ?2
  AND user_id = ?3
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND EXISTS (SELECT 1 FROM agents WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NOT NULL)`

// RevokeAgent revokes one of the user's agents and every key it holds, as one
// batch, and returns the agent as the write left it. Revoking an agent that is
// already revoked succeeds and keeps the earlier time, so the call is
// idempotent. Other agents of the same user are not touched. It returns
// ErrNotFound when the user has no such agent, in which case no key is touched
// either.
//
// As for RenameAgent, a constraint failure of any kind is a defect.
func (s *Store) RevokeAgent(ctx context.Context, owner string, id input.ID, now time.Time) (Agent, error) {
	o := op{failed: CodeAgentRevokeFailed, rejected: CodeAgentRevokeRejected, description: agentsDescription}

	results, err := s.run(ctx, o,
		Statement{Query: agentRevokeQuery, Args: []any{now.Unix(), id.String(), owner}},
		Statement{Query: agentRevokeKeysQuery, Args: []any{now.Unix(), id.String(), owner}},
	)
	if err != nil {
		return Agent{}, rejectAgentConflict(o, err)
	}

	return one(results[0].Rows, o, readAgent)
}

// rejectAgentConflict turns a conflict into a defect for an operation that
// writes nothing a constraint of the data could refuse: run passes a conflict
// through for the operation to hand to its feature, and there is none here.
// Any other error is returned as is.
func rejectAgentConflict(o op, err error) error {
	if errors.Is(err, ErrConflict) {
		return o.defect(err)
	}

	return err
}
