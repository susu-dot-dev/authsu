package store

import (
	"context"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// The kinds of secret (secrets.kind). Each is the one value its kind's table
// fixes with CHECK (kind = '...'), and a test holds the two together. The queries
// bind them as arguments and never write them as literals, so these constants
// are the only place in Go that spells them.
const (
	KindInvitation = "invitation"
	KindSession    = "session"
	KindAPIKey     = "api_key"

	// KindOAuthGrant is an OAuth grant: the authorization code, then the refresh
	// token that replaces it under the same id. KindOAuthAccess is the access
	// token of a grant, of which a grant has at most one.
	KindOAuthGrant  = "oauth_grant"
	KindOAuthAccess = "oauth_access"
)

// Error codes of the secret operations. They are stable: clients and dashboards
// may match on them.
const (
	CodeSessionVerifyFailed   = "session_verify_failed"
	CodeSessionVerifyRejected = "session_verify_rejected"
	CodeLoginAcceptFailed     = "login_accept_failed"
	CodeLoginAcceptRejected   = "login_accept_rejected"
	CodeSessionLogoutFailed   = "session_logout_failed"
	CodeSessionLogoutRejected = "session_logout_rejected"
)

// sessionsDescription is the client-safe text of the Unavailable error of the
// operations that resolve or end a credential.
const sessionsDescription = "sessions are temporarily unavailable"

// activeSecretPredicate is the one definition of "this secret is active":
// not revoked as of now and not expired. Revocation is a time and not a flag,
// compared with now, so a revocation scheduled for later leaves the secret
// active until it comes, and the same text would serve one; nothing schedules
// one today.
//
// Every query that decides whether a presented secret may be used includes it,
// so they cannot disagree. It is a constant, and a query that uses it is a
// concatenation of constants, because the queries are checked as text; the
// alias is therefore fixed. The secrets table is s wherever it is used.
//
// Arguments, in order: now, now (unix seconds).
//
//nolint:gosec // SQL naming the secrets table, not a credential
const activeSecretPredicate = `(s.revoked_at IS NULL OR s.revoked_at > ?) AND s.expires_at > ?`

// insertSecretQuery writes the base row of a secret. The row of its kind's
// table is written by a later statement of the same batch, which fails when
// this row is not there, so neither takes effect without the other.
//
// The hash is UNIQUE, so a collision fails the insert and cannot make two
// secrets indistinguishable; the id is the primary key.
//
// Arguments, in order: id, kind, hash, expires_at, created_at.
//
//nolint:gosec // SQL naming the secrets table, not a credential
const insertSecretQuery = `
INSERT INTO secrets (id, kind, hash, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)`

// insertSecret is the statement that writes a secret's base row. The times are
// Unix seconds.
func insertSecret(id, kind string, hash []byte, expiresAt, createdAt int64) Statement {
	return Statement{Query: insertSecretQuery, Args: []any{id, kind, hash, expiresAt, createdAt}}
}

// resolveSessionQuery reads a presented session token's hash. It is one
// statement that reads the secret, the session's own row and the account, so
// whether the session is valid, whose it is and what role the account holds now
// all come from the same instant.
//
// The session resolves only while its secret is active (activeSecretPredicate)
// and the account is not revoked. The role and the account's revocation are
// read from the account every time, so a role change or a revoked account takes
// effect on the next request and not when the session was created. A token
// carries nothing that could go stale (docs/secrets_design.md).
//
// The kind is bound twice over: s.kind = ? asks for a session, and the join to
// sessions is on the id and the kind together, as the schema's foreign key is.
// A hash that belongs to another kind of secret therefore resolves to nothing.
//
// The account's organization is read from the account in the same statement, as
// its role is: "" when it belongs to none.
//
// Arguments, in order: hash, kind, now, now (unix seconds).
const resolveSessionQuery = `
SELECT s.id AS id, x.user_id AS user_id, u.role AS role, s.expires_at AS expires_at,
       COALESCE(u.org_id, '') AS org_id
FROM secrets s
JOIN sessions x ON x.id = s.id AND x.kind = s.kind
JOIN users u ON u.id = x.user_id
WHERE s.hash = ?
  AND s.kind = ?
  AND ` + activeSecretPredicate + `
  AND u.revoked_at IS NULL`

// ActiveSession is a session that may be used, with the account it belongs to.
type ActiveSession struct {
	// ID is the session's secret id.
	ID string

	// UserID is the account the session is for.
	UserID string

	// Role is the account's current role, not the one at the session's
	// creation.
	Role string

	// ExpiresAt is when the session stops being active.
	ExpiresAt time.Time

	// OrgID is the standard organization the account belongs to now, or "".
	OrgID string
}

// ResolveSession reads the session the token names if it is active at now: not
// revoked, not expired, and its account not revoked. It reports false when
// there is no such session, so an unknown, wrong-kind, expired, revoked and
// revoked-account token are indistinguishable.
func (s *Store) ResolveSession(
	ctx context.Context, token input.SessionToken, now time.Time,
) (ActiveSession, bool, error) {
	o := op{failed: CodeSessionVerifyFailed, rejected: CodeSessionVerifyRejected,
		description: sessionsDescription}

	unix := now.Unix()

	return find(ctx, s, o,
		Statement{Query: resolveSessionQuery, Args: []any{token.Hash(), KindSession, unix, unix}},
		func(r *row) ActiveSession {
			// Struct fields are evaluated in order, which is the column order.
			return ActiveSession{
				ID: r.text(), UserID: r.text(), Role: r.text(), ExpiresAt: r.timestamp(), OrgID: r.text(),
			}
		})
}

// resolveAPIKeyQuery reads a presented API key's hash, as resolveSessionQuery
// reads a session's: the secret, the key's own row and the account in one
// statement, with the same active predicate, the same bound kind and the same
// join on the id and the kind.
//
// A key that belongs to an agent also reads the agent's scopes from the agent's
// row, in the same statement, and is active only while the agent is not
// revoked: a key never outlives its agent, whether or not the agent's
// revocation reached the key's own secret. The LEFT JOIN is on the key's own
// agent_id, so a key with none matches no agent and reads ” for both.
//
// The key's own scope is read as stored. It is authoritative and nothing
// updates it (docs/permissions_design.md).
//
// The account's organization is read as for a session, and the agent's sandbox
// is read with the agent, "" for an ordinary agent and for a key with none. A
// key of an agent in a sandbox is active only while that sandbox is standing:
// it must exist and not have expired as of now, which is read here, in the
// statement that resolves the credential, because nothing deletes an expired
// sandbox on time and the boundary must hold without it (docs/orgs_design.md,
// principle 4). A sandbox that is gone cannot be told apart from one that has
// expired, and neither can from an unknown key, and the sandbox's kind is
// bound by the agent's own sandbox_kind, as the schema's foreign key is.
//
// Arguments, in order: hash, kind, then now three times (unix seconds).
const resolveAPIKeyQuery = `
SELECT s.id AS id, k.user_id AS user_id, u.role AS role, s.expires_at AS expires_at,
       COALESCE(k.agent_id, '') AS agent_id, COALESCE(a.scopes, '') AS agent_scopes, k.scope AS scope,
       COALESCE(u.org_id, '') AS org_id, COALESCE(a.sandbox_id, '') AS sandbox_id
FROM secrets s
JOIN api_keys k ON k.id = s.id AND k.kind = s.kind
JOIN users u ON u.id = k.user_id
LEFT JOIN agents a ON a.id = k.agent_id
WHERE s.hash = ?
  AND s.kind = ?
  AND ` + activeSecretPredicate + `
  AND u.revoked_at IS NULL
  AND (k.agent_id IS NULL OR (a.id IS NOT NULL AND a.revoked_at IS NULL))
  AND (a.sandbox_id IS NULL
       OR EXISTS (SELECT 1 FROM orgs g
                  WHERE g.id = a.sandbox_id AND g.kind = a.sandbox_kind AND g.expires_at > ?))`

// ActiveAPIKey is an API key that may be used, with the account it acts for.
type ActiveAPIKey struct {
	// ID is the key's secret id.
	ID string

	// UserID is the account whose authority the key carries.
	UserID string

	// Role is the account's current role.
	Role string

	// ExpiresAt is when the key stops being active.
	ExpiresAt time.Time

	// AgentID is the agent the key belongs to, or "" for a user's own key. A
	// key whose agent is revoked is not active and is not returned.
	AgentID string

	// AgentScopes is the agent's scope list as stored, read now and not when
	// the key was created, or "" when the key has no agent.
	AgentScopes string

	// Scope is the key's own scope list as stored.
	Scope string

	// OrgID is the standard organization the account belongs to now, or "".
	OrgID string

	// SandboxID is the sandbox the key's agent is confined to, or "" for a
	// user's own key and for an ordinary agent. A key whose sandbox has
	// expired or is gone is not active and is not returned.
	SandboxID string
}

// ResolveAPIKey reads the API key the token names if it is active at now: not
// revoked, not expired, its account not revoked and, when it belongs to an
// agent, that agent not revoked and its sandbox, if it has one, standing and
// unexpired. It reports false otherwise, so an unknown, wrong-kind, expired and
// revoked key are indistinguishable.
func (s *Store) ResolveAPIKey(
	ctx context.Context, token input.APIKeyToken, now time.Time,
) (ActiveAPIKey, bool, error) {
	o := op{failed: CodeSessionVerifyFailed, rejected: CodeSessionVerifyRejected,
		description: sessionsDescription}

	unix := now.Unix()

	return find(ctx, s, o,
		Statement{Query: resolveAPIKeyQuery, Args: []any{token.Hash(), KindAPIKey, unix, unix, unix}},
		func(r *row) ActiveAPIKey {
			// Struct fields are evaluated in order, which is the column order.
			return ActiveAPIKey{
				ID: r.text(), UserID: r.text(), Role: r.text(), ExpiresAt: r.timestamp(),
				AgentID: r.text(), AgentScopes: r.text(), Scope: r.text(), OrgID: r.text(), SandboxID: r.text(),
			}
		})
}

// revokeSecretQuery ends a session or an API key of one user, now.
//
// The secret must be the user's, in the write itself: the caller's verified
// read is not what makes the revocation safe, so an id that is not the user's
// is answered as one that does not exist, whatever else it names (an
// invitation, another user's key). The kind is not a condition beyond that: a
// request ends the credential it presented, session or key, and the user's two
// tables are exactly those.
//
// Only a secret that is not yet revoked as of now is changed. A secret
// scheduled to be revoked later is brought forward to now, and one that is
// already revoked keeps its earlier time, so revoking twice cannot move a
// revocation later, and the number of rows it changes is the outcome: one means
// this request ended the secret, none means it was unknown, not the user's or
// already ended, perhaps by a concurrent request. The caller answers that as
// any request without a valid credential.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 secret id, ?3 user id.
const revokeSecretQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE id = ?2
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND id IN (SELECT id FROM sessions WHERE user_id = ?3
             UNION ALL
             SELECT id FROM api_keys WHERE user_id = ?3)`

// RevokeSecret ends the session or API key id of the user as of now. It reports
// false when there was nothing to end: the secret is unknown, is not the
// user's, or was already revoked, perhaps by a concurrent request. Both failure
// codes of the operation are the session_logout pair.
func (s *Store) RevokeSecret(ctx context.Context, userID, id string, now time.Time) (bool, error) {
	o := op{failed: CodeSessionLogoutFailed, rejected: CodeSessionLogoutRejected,
		description: sessionsDescription}

	results, err := s.run(ctx, o, Statement{Query: revokeSecretQuery, Args: []any{now.Unix(), id, userID}})
	if err != nil {
		return false, err
	}

	return changedOnce(o, results[0])
}
