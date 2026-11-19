package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

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

	// Labels are the agent's labels, in ascending order. It is never nil.
	Labels []string
}

// readAgent reads one agent row, in the column order every agent statement
// selects or returns: id, name, scopes, revoked_at, created_at, labels.
//
// labels is the agent's labels as the text of a JSON array, sorted, and "[]" for
// none. Every statement computes it with a subselect over agent_labels, and not
// a join, so a read stays one row per agent, which keyset paging and LIMIT
// depend on (a join repeats the agent once per label). The label alphabet has no
// character JSON escapes, so the text decodes to the labels exactly. Each query
// writes the subselect out in full, because the queries are single literals that
// a test reads.
func readAgent(r *row) Agent {
	// Struct fields are evaluated in order, which is the column order.
	agent := Agent{
		ID: r.text(), Name: r.text(), Scopes: r.text(),
		RevokedAt: r.optInteger(), CreatedAt: r.integer(), Labels: nil,
	}

	agent.Labels = r.labels()

	return agent
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
// ?4 is the label to filter by, or NULL for no filter, so every page has one
// shape. The filter is a semi-join on agent_labels' primary key, not a join, so
// an agent with the label is one row however many labels it has. The labels
// column still lists ALL of the agent's labels, not only the one filtered by.
//
// Arguments, by number: ?1 user id, ?2 cursor (the id to start below;
// agentsFirstPage for the first page), ?3 rows wanted, ?4 the label or NULL.
const agentListQuery = `
SELECT id, name, scopes, revoked_at, created_at,
  (SELECT json_group_array(label)
   FROM (SELECT label FROM agent_labels WHERE agent_id = agents.id ORDER BY label)) AS labels
FROM agents
WHERE user_id = ?1 AND id < ?2
  AND (?4 IS NULL OR EXISTS (SELECT 1 FROM agent_labels f WHERE f.agent_id = agents.id AND f.label = ?4))
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
// newest agent. owner is the authenticated user's id. A label filter limits the
// page to agents that have that label.
//
// It reads one row more than the page holds. If that row is there, there is a
// next page, and it starts below the last agent that is returned.
func (s *Store) ListAgents(
	ctx context.Context, owner string, cursor input.Cursor, limit input.PageLimit, filter input.LabelFilter,
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

	// No filter is a NULL, which the query reads as "any label".
	var label any
	if filtered, ok := filter.Label(); ok {
		label = filtered.String()
	}

	agents, err := queryAll(ctx, s, o,
		Statement{Query: agentListQuery, Args: []any{owner, before, int64(wanted), label}}, readAgent)
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
SELECT id, name, scopes, revoked_at, created_at,
  (SELECT json_group_array(label)
   FROM (SELECT label FROM agent_labels WHERE agent_id = agents.id ORDER BY label)) AS labels
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

// insertAgentKeyQuery writes an agent's API key's own row, after its secret
// (insertSecretQuery, in the same batch). The key's owner and the agent it
// belongs to are read from the agent's row, in the write, so the key's subject
// is the agent's owner by construction. If the agent was not created (the user
// was at the limit, or was revoked in the meantime, or the creating agent was
// revoked) the subselects are NULL, user_id is NOT NULL, and the whole batch
// fails as a conflict, which rolls the agent insert and the secret back with
// it. Without this the batch would commit with no key. The secret is written
// before this statement and does not depend on the agent, which is why a
// refused agent must fail here and not earlier.
//
// agent_id is read from the agent's row too, and not bound, so it can never
// name an agent the owner does not have; a NULL one would make a user's own
// key, but user_id fails first.
//
// The key's name is the agent's name, read from its row here: an agent's first
// key is not named by the client, and listing it beside the user's own keys
// should say whose it is. Renaming the agent later does not rename the key (a
// key's name is its own, changed by PATCH /api/key/{id}).
//
// Arguments, by number: ?1 key id, ?2 kind, ?3 agent id (for the subselects),
// ?4 scope.
const insertAgentKeyQuery = `
INSERT INTO api_keys (id, kind, user_id, agent_id, name, scope)
VALUES (?1, ?2, (SELECT user_id FROM agents WHERE id = ?3), (SELECT id FROM agents WHERE id = ?3),
        (SELECT name FROM agents WHERE id = ?3), ?4)`

// insertAgentLabelQuery gives a new agent one label, in the batch that creates
// it. Like insertAgentKeyQuery it reads the agent's id from the agent's row, in
// the write: if the agent was not created (the user was at the limit, or was
// revoked in the meantime, or the creating agent was revoked) the subselect is
// NULL, agent_id is NOT NULL, and the whole batch fails as a conflict, which
// rolls the agent insert back with it. A plain VALUES (?1, ?2) would instead
// fail on the foreign key, which is a defect and not the conflict this is.
//
// There is no cap here, unlike agentLabelAddQuery: the agent has just been
// created in the same batch, so it has no labels, and the labels written are
// the parsed set, which input.ParseLabelSet bounds at input.MaxLabelsPerCreate
// and refuses to repeat. No ON CONFLICT clause either, for the same reason: a
// repeat would be a defect and must not be hidden.
//
// Arguments, by number: ?1 agent id, ?2 label.
const insertAgentLabelQuery = `
INSERT INTO agent_labels (agent_id, label)
VALUES ((SELECT id FROM agents WHERE id = ?1), ?2)`

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

	// KeyScope is the key's scope list as JSON, stored on the key's row. It is
	// authoritative: nothing updates it.
	KeyScope string

	// CreatedBy is the id of the agent that is creating this one, or "" when its
	// user is. The new agent is an ordinary agent of the same owner either way,
	// and nothing records who created it: the id only chooses where the scopes
	// come from and what must still be active (see insertAgentByAgentQuery).
	CreatedBy string

	// Labels are the labels the new agent starts with, possibly none. They are
	// written in the same batch as the agent, so an agent is never seen
	// without them and a create that cannot give them creates nothing.
	Labels input.LabelSet

	// MaxActive is how many active agents a user may have: the create is
	// refused when the owner already has that many.
	MaxActive int

	// KeyID is the key's id, which is also its secret's id. KeyHash is the
	// SHA-256 of the key's token (32 bytes): the token itself is never stored.
	// KeyExpiresAt is when it stops working.
	KeyID        string
	KeyHash      []byte
	KeyExpiresAt time.Time

	// CreatedAt is when the agent and its key were created.
	CreatedAt time.Time
}

// CreateAgent writes an agent, its first key (the key's secret, then its own
// row) and its labels as one batch: either all of them exist or none does. See
// insertAgentQuery,
// insertAgentKeyQuery and insertAgentLabelQuery for how the owner being revoked
// or at the limit fails the batch and not just the first statement.
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
// The id and the key's id are fresh UUIDv7s and the key's hash that of 256
// random bits, so no other constraint can conflict.
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

	secret := insertSecret(agent.KeyID, KindAPIKey, agent.KeyHash, agent.KeyExpiresAt.Unix(), agent.CreatedAt.Unix())

	key := Statement{Query: insertAgentKeyQuery, Args: []any{agent.KeyID, KindAPIKey, agent.ID, agent.KeyScope}}

	labels := agent.Labels.Labels()
	labelInserts := make([]Statement, len(labels))

	for i, label := range labels {
		labelInserts[i] = Statement{Query: insertAgentLabelQuery, Args: []any{agent.ID, label.String()}}
	}

	// The agent, its key's secret, its key, then each label: the key and every
	// label read the agent's row, so none of them can be written for an agent
	// that was not, and the key's failure rolls back the secret before it.
	statements := slices.Concat([]Statement{insert, secret, key}, labelInserts)

	stored, err := result.Of(s.run(ctx, o, statements...)).
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

// agentPatchReadQuery is the last statement of PatchAgent: it reads the agent as
// the batch left it. The batch is one transaction, so this reads the writes
// before it and nothing another request did in between.
//
// The outcome is read off the row, as for rename: no row is no such agent for
// this owner (the earlier statements matched nothing too), and revoked_at set
// means the earlier statements, which skip a revoked agent, changed nothing.
//
// It is a SELECT of its own, and not a RETURNING of one write, because the
// rename and the label writes are separate statements and the read must see all
// of them.
//
// Arguments, by number: ?1 id, ?2 user id.
const agentPatchReadQuery = `
SELECT id, name, scopes, revoked_at, created_at,
  (SELECT json_group_array(label)
   FROM (SELECT label FROM agent_labels WHERE agent_id = agents.id ORDER BY label)) AS labels
FROM agents
WHERE id = ?1 AND user_id = ?2`

// agentLabelRemoveQuery removes one label from an agent, unless the agent is not
// the owner's or is revoked. Removing a label the agent does not have matches no
// row and is not an error, so removal is idempotent. The owner and the agent
// being active are part of the DELETE, because D1 has no interactive
// transaction and a read before it could be stale by the time it ran.
//
// Arguments, by number: ?1 agent id, ?2 label, ?3 user id.
const agentLabelRemoveQuery = `
DELETE FROM agent_labels
WHERE agent_id = ?1 AND label = ?2
  AND EXISTS (SELECT 1 FROM agents a WHERE a.id = ?1 AND a.user_id = ?3 AND a.revoked_at IS NULL)`

// agentLabelAddQuery adds one label to an agent, if the agent is the owner's, is
// not revoked, and either already has the label or has fewer than ?4 labels.
//
//   - The agent row is selected under the owner and active conditions, so another
//     user's agent, a revoked one and a missing one match no row and nothing is
//     inserted: the final read reports why.
//   - ON CONFLICT DO NOTHING makes adding a label the agent has a no-op, so the
//     call is idempotent and two requests adding the same label both succeed.
//   - The cap is part of the write: the count is taken here, not read earlier, so
//     two requests adding different labels at the cap cannot both succeed. The
//     agent_id is a CASE that is NULL when the agent is at the cap and lacks the
//     label, and agent_id is NOT NULL, so that case is a constraint failure,
//     which fails the whole batch and rolls back the removals and adds before it:
//     a patch that would exceed the cap changes nothing, and is not partly
//     applied. A conditional INSERT ... SELECT that matched nothing would be
//     silent, and the batch would commit the rest. The label being present is
//     checked in the CASE too, because the conflict is only found after the
//     CASE has run, and re-adding a label at the cap must not fail.
//
// A NOT NULL failure is therefore this statement's, and only this statement's,
// ErrConflict: every other guard matches no row instead.
//
// Arguments, by number: ?1 agent id, ?2 label, ?3 user id, ?4 the most labels an
// agent may have.
const agentLabelAddQuery = `
INSERT INTO agent_labels (agent_id, label)
SELECT CASE
         WHEN (SELECT count(*) FROM agent_labels l WHERE l.agent_id = a.id) < ?4
           OR EXISTS (SELECT 1 FROM agent_labels l WHERE l.agent_id = a.id AND l.label = ?2)
         THEN a.id
       END, ?2
FROM agents a
WHERE a.id = ?1 AND a.user_id = ?3 AND a.revoked_at IS NULL
ON CONFLICT DO NOTHING`

// agentPatchRenameQuery renames an agent as part of a patch, unless it is
// revoked. A revoked agent is final, as for invitations: changing it would
// suggest it could be revived. It has no RETURNING: PatchAgent reads the agent
// once, after every write, with agentPatchReadQuery, so the outcome and the row
// are the same instant.
//
// Arguments, by number: ?1 name, ?2 id, ?3 user id.
const agentPatchRenameQuery = `
UPDATE agents
SET name = ?1
WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NULL`

// AgentPatch is a change to one agent: a new name, and labels to add and remove.
// Each part is optional. The labels are applied removals first, then additions,
// so a patch at the label limit may swap one label for another.
type AgentPatch struct {
	// Name is the new name, or nil to keep it.
	Name *input.AgentName

	// Labels are the labels to add and remove.
	Labels input.LabelPatch

	// MaxLabels is how many labels an agent may have: the patch is refused when
	// it would leave the agent with more.
	MaxLabels int
}

// PatchAgent applies a patch to one of the user's agents as one batch: the new
// name, the removed labels, then the added labels, then a read of the agent. Either
// every part takes effect or none does, so a patch that would exceed MaxLabels
// changes nothing, not even the name.
//
// It returns the agent as the batch left it. A revoked agent is returned
// unchanged, for the caller to refuse: every write skips a revoked agent, so the
// row comes back with revoked_at set. It returns
// ErrNotFound when the user has no such agent, which includes one that belongs
// to someone else. It returns ErrConflict when the patch would leave the agent
// with more than MaxLabels labels.
//
// A patch that changes nothing is valid and returns the agent. Every other
// constraint failure is a defect on our side (a label is bounded by its parser,
// and nothing else the batch writes can collide), but the label cap's
// ErrConflict is the batch working as designed, so it is returned as is.
func (s *Store) PatchAgent(ctx context.Context, owner string, id input.ID, patch AgentPatch) (Agent, error) {
	o := op{failed: CodeAgentUpdateFailed, rejected: CodeAgentUpdateRejected, description: agentsDescription}

	statements := make([]Statement, 0, 1+len(patch.Labels.Remove())+len(patch.Labels.Add())+1)

	if patch.Name != nil {
		statements = append(statements,
			Statement{Query: agentPatchRenameQuery, Args: []any{patch.Name.String(), id.String(), owner}})
	}

	for _, label := range patch.Labels.Remove() {
		statements = append(statements,
			Statement{Query: agentLabelRemoveQuery, Args: []any{id.String(), label.String(), owner}})
	}

	for _, label := range patch.Labels.Add() {
		statements = append(statements,
			Statement{Query: agentLabelAddQuery, Args: []any{id.String(), label.String(), owner, int64(patch.MaxLabels)}})
	}

	// The read is last, so it sees every write. It is the only statement whose
	// rows are read.
	statements = append(statements, Statement{Query: agentPatchReadQuery, Args: []any{id.String(), owner}})

	results, err := s.run(ctx, o, statements...)
	if err != nil {
		return Agent{}, err
	}

	return one(results[len(results)-1].Rows, o, readAgent)
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
RETURNING id, name, scopes, revoked_at, created_at,
  (SELECT json_group_array(label)
   FROM (SELECT label FROM agent_labels WHERE agent_id = agents.id ORDER BY label)) AS labels`

// agentRevokeKeysQuery revokes the secret of every key of an agent, in the same
// batch as agentRevokeQuery and after it. It applies only if the agent is
// revoked once agentRevokeQuery has run, and only to keys of that owner's agent.
// A secret whose revocation is already due keeps its time; one scheduled for
// later is brought forward.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 agent id, ?3 user id.
const agentRevokeKeysQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE id IN (SELECT id FROM api_keys WHERE agent_id = ?2 AND user_id = ?3)
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND EXISTS (SELECT 1 FROM agents WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NOT NULL)`

// RevokeAgent revokes one of the user's agents and every key it holds, as one
// batch, and returns the agent as the write left it. Revoking an agent that is
// already revoked succeeds and keeps the earlier time, so the call is
// idempotent. Other agents of the same user are not touched. It returns
// ErrNotFound when the user has no such agent, in which case no key is touched
// either.
//
// As for PatchAgent, a constraint failure of any kind is a defect.
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
