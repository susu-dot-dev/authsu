package agents

// selectColumns are the columns of an agent row, in the order scanRow and
// rowOfValues read them. The owner is not selected: every query is scoped to
// one, so the caller already knows it.
const selectColumns = `
SELECT id, name, scopes, revoked_at, created_at
FROM agents`

// listQuery reads one page of a user's agents, revoked ones included, newest
// first. The id is a UUIDv7, so it is in creation order and is both the sort
// key and the cursor: the page is the agents with an id below the cursor, and
// the cursor is the id of the last agent of the previous page. Keyset paging
// never skips or repeats an agent that exists throughout, whatever is created
// or revoked in between, which an offset would. A page asks for one row more
// than it returns, so the caller can tell whether there is a next page without
// counting.
//
// Arguments: user id, cursor (the id to start below; FirstPage for the first
// page), rows wanted.
const listQuery = selectColumns + `
WHERE user_id = ?1 AND id < ?2
ORDER BY id DESC
LIMIT ?3`

// getQuery reads one agent of a user. The owner is part of the match, so
// another user's agent is not found, which is what the caller is told for an
// id that does not exist at all. Arguments: id, user id.
const getQuery = selectColumns + `
WHERE id = ? AND user_id = ?`

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
// insertKeyQuery), which turns "no agent was created" into a failed batch.
//
// Arguments, in order: id, name, scopes, created_at, user id, limit (the
// maximum active agents a user may have), user id again for the count.
const insertAgentQuery = `
INSERT INTO agents (id, user_id, name, scopes, created_at)
SELECT ?1, u.id, ?2, ?3, ?4
FROM users u
WHERE u.id = ?5
  AND u.revoked_at IS NULL
  AND (SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL) < ?6`

// insertKeyQuery stores an agent's API key. The key's owner and the agent it
// belongs to are read from the agent's row, in the write, so the key's subject
// is the agent's owner by construction. If the agent was not created (the user
// was at the limit, or was revoked in the meantime) the subselects are NULL,
// user_id is NOT NULL, and the whole batch fails as a conflict, which rolls the
// agent insert back with it. Without this the batch would commit with no key.
//
// granted_from and credential_id stay NULL: only a login grants those, and the
// table's CHECK requires an API key to have neither.
//
// Arguments, in order: kid, agent id (for the subselect), jwk, expires_at,
// agent id, scope, created_at.
const insertKeyQuery = `
INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, agent_id, scope, created_at)
VALUES (?, (SELECT user_id FROM agents WHERE id = ?), 'api_key', ?, ?, ?, ?, ?)`

// renameQuery renames an agent, unless it is revoked. A revoked agent is
// final, as for invitations: changing it would suggest it could be revived.
//
// The row is matched by id and owner alone, and the CASE decides whether the
// name changes (as in invitations), so RETURNING reports the row as the
// statement left it, and the outcome is read off it. The agent was renamed if
// it is not revoked. No row returned means the user has no such agent.
//
// RETURNING is the columns of selectColumns, in that order, so rowOfValues
// reads it.
//
// Arguments, by number: ?1 name, ?2 id, ?3 user id.
const renameQuery = `
UPDATE agents
SET name = CASE WHEN revoked_at IS NULL THEN ?1 ELSE name END
WHERE id = ?2 AND user_id = ?3
RETURNING id, name, scopes, revoked_at, created_at`

// revokeQuery revokes an agent now. The row is matched by id and owner, so a
// user can revoke only their own agents, and one that is already revoked keeps
// its earlier time (the COALESCE), so revoking twice succeeds and cannot move
// the revocation later. RETURNING gives the row as it was left, and no row
// returned means the user has no such agent.
//
// RETURNING is the columns of selectColumns, in that order.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 id, ?3 user id.
const revokeQuery = `
UPDATE agents
SET revoked_at = COALESCE(revoked_at, ?1)
WHERE id = ?2 AND user_id = ?3
RETURNING id, name, scopes, revoked_at, created_at`

// revokeKeysQuery revokes every key of an agent, in the same batch as
// revokeQuery and after it. It applies only if the agent is revoked once
// revokeQuery has run, and only to keys of that owner's agent. A key whose
// revocation is already due keeps its time; one scheduled for later is brought
// forward.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 agent id, ?3 user id.
const revokeKeysQuery = `
UPDATE japikeys
SET revoked_at = ?1
WHERE agent_id = ?2
  AND user_id = ?3
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND EXISTS (SELECT 1 FROM agents WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NOT NULL)`
