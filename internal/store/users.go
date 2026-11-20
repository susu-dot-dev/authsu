package store

import (
	"context"
	"errors"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// Error codes of the user operations. They are stable: clients and dashboards
// may match on them.
const (
	CodeUserListFailed     = "user_list_failed"
	CodeUserListRejected   = "user_list_rejected"
	CodeUserLookupFailed   = "user_lookup_failed"
	CodeUserLookupRejected = "user_lookup_rejected"
	CodeUserRevokeFailed   = "user_revoke_failed"
	CodeUserRevokeRejected = "user_revoke_rejected"
)

// usersDescription is the client-safe text of every user operation's failure.
const usersDescription = "users are temporarily unavailable"

// ErrLastAdmin is what RevokeUser reports when it refused to revoke the account
// because it is the last active administrator: the only recovery from having
// none is wiping the database (docs/users_design.md).
var ErrLastAdmin = errors.New("the last active administrator cannot be revoked")

// User is an account as stored. It never carries the WebAuthn user handle,
// which is an identifier for authenticators and not for people.
type User struct {
	ID   string
	Role string

	// InvitationID is the invitation the account was created from.
	InvitationID string

	// Profile is users.profile as stored: JSON text of an object, such as the
	// name given at registration.
	Profile string

	// RevokedAt is when the account was revoked, in Unix seconds, and nil for
	// an account that is not revoked. Any value at all revokes, matching the
	// session and login queries, which test only that it is set.
	RevokedAt *int64

	// CreatedAt is when the account was created, in Unix seconds.
	CreatedAt int64
}

// readUser reads one account row, in the column order every user statement
// selects or returns: id, role, invitation_id, profile, revoked_at, created_at.
func readUser(r *row) User {
	// Struct fields are evaluated in order, which is the column order.
	return User{
		ID: r.text(), Role: r.text(), InvitationID: r.text(), Profile: r.text(),
		RevokedAt: r.optInteger(), CreatedAt: r.integer(),
	}
}

// listUsersQuery reads every account, revoked ones included, newest first. The
// id is a UUIDv7, so it breaks ties between accounts created in the same second
// in creation order. The user handle is not selected: nothing returns it.
const listUsersQuery = `
SELECT id, role, invitation_id, profile, revoked_at, created_at
FROM users
ORDER BY created_at DESC, id DESC`

// ListUsers returns every account, revoked ones included, newest first. There
// is no paging: it returns the whole table.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	o := op{failed: CodeUserListFailed, rejected: CodeUserListRejected, description: usersDescription}

	return queryAll(ctx, s, o, Statement{Query: listUsersQuery, Args: nil}, readUser)
}

// getUserQuery reads one account. Arguments: id.
const getUserQuery = `
SELECT id, role, invitation_id, profile, revoked_at, created_at
FROM users
WHERE id = ?`

// GetUser returns the account id, or ErrNotFound when there is none.
func (s *Store) GetUser(ctx context.Context, id input.ID) (User, error) {
	o := op{failed: CodeUserLookupFailed, rejected: CodeUserLookupRejected, description: usersDescription}

	return queryOne(ctx, s, o, Statement{Query: getUserQuery, Args: []any{id.String()}}, readUser)
}

// revokeUserQuery revokes an account now, unless it is the last active admin.
//
// The guard is part of the write, not a read before it, because D1 has no
// interactive transaction: two admins revoking each other at the same moment
// would each see the other still active, and both writes would apply, leaving
// no admin at all. D1 runs one statement at a time, so here the second write
// sees the first one's revocation and is refused.
//
// The row is matched by id alone, and the guard decides what revoked_at
// becomes:
//
//   - already revoked: it keeps its earlier time (the COALESCE), so revoking
//     twice succeeds and cannot move the revocation later;
//   - not an admin, or an admin while another active admin exists: now;
//   - the last active admin: the CASE has no ELSE, so it stays NULL.
//
// RETURNING gives the row as the statement left it, so the outcome is read off
// the row: revoked_at set means the account is revoked, NULL means the guard
// refused. No row returned means no such account. Nothing is read again
// afterwards, which could see a different state.
//
// RETURNING is the columns of listUsersQuery, in that order, so readUser reads
// it.
//
// The admin role is a parameter because which role administers is defined in a
// higher layer; this package only compares it.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 id, ?3 the admin role.
const revokeUserQuery = `
UPDATE users
SET revoked_at = COALESCE(revoked_at, CASE
      WHEN role <> ?3
        OR EXISTS (SELECT 1 FROM users other
                   WHERE other.id <> users.id
                     AND other.role = ?3
                     AND other.revoked_at IS NULL)
      THEN ?1
    END)
WHERE id = ?2
RETURNING id, role, invitation_id, profile, revoked_at, created_at`

// revokeUserSecretsQuery revokes every session, every API key and every OAuth
// grant of the account, with the grants' access tokens, in the same batch as
// revokeUserQuery and after it. The keys and grants of the account's agents are
// among them: a key's or grant's user_id is its agent's owner. Resolving already
// refuses any session or key of a revoked account (it reads users.revoked_at),
// and so does introspection of an access token, so this is not what ends them. It keeps the secrets table
// honest: a secret listed later reads as revoked, and a future kind of secret
// whose resolve forgot to check the account would still be refused.
//
// It applies only if the account is revoked once revokeUserQuery has run, so a
// refused revocation (the last admin) changes no secret. A secret whose
// revocation is already due keeps its time; one scheduled for later is brought
// forward. The account's invitations are not among them: an invitation belongs
// to no account.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 user id.
const revokeUserSecretsQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE id IN (SELECT id FROM sessions WHERE user_id = ?2
             UNION ALL
             SELECT id FROM api_keys WHERE user_id = ?2
             UNION ALL
             SELECT id FROM oauth_grants WHERE user_id = ?2
             UNION ALL
             SELECT t.id FROM oauth_access_tokens t JOIN oauth_grants g ON g.id = t.grant_id WHERE g.user_id = ?2)
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND revoked_at IS NOT NULL)`

// revokeUserAgentsQuery revokes every agent of the account, in the same batch
// as revokeUserQuery and after it, because an agent's authority is borrowed
// from its user (docs/agents_design.md). The agents' keys are already revoked
// by revokeUserSecretsQuery, which matches every key of the account; this keeps
// the agents table honest, so an agent lists as revoked and cannot be renamed.
//
// It applies only if the account is revoked once revokeUserQuery has run, so a
// refused revocation (the last admin) changes no agent. An agent that is
// already revoked keeps its earlier time.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 user id.
const revokeUserAgentsQuery = `
UPDATE agents
SET revoked_at = ?1
WHERE user_id = ?2
  AND revoked_at IS NULL
  AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND revoked_at IS NOT NULL)`

// RevokeUser revokes the account id, its secrets and its agents, in that order, as
// one batch, and returns the account as the write left it. adminRole is the
// role the last-admin guard protects.
//
// Revoking an account that is already revoked succeeds and keeps the earlier
// time, so the call is idempotent. It returns ErrNotFound when there is no such
// account, and ErrLastAdmin when the account is the last active administrator
// (the batch then changed nothing; see revokeUserQuery for why the check is
// inside the write).
//
// No statement sets a constrained column to anything but a time, so a constraint
// failure of any kind is a defect on our side and is reported as the operation's
// "_rejected" 500. That includes a conflict, which run hands back as the bare
// ErrConflict sentinel because most operations let their feature decide what it
// means: here there is no client-resolvable meaning, and a feature must never
// have to map a conflict this operation cannot produce.
func (s *Store) RevokeUser(ctx context.Context, id input.ID, adminRole string, now time.Time) (User, error) {
	o := op{failed: CodeUserRevokeFailed, rejected: CodeUserRevokeRejected, description: usersDescription}

	unix := now.Unix()

	results, err := s.run(ctx, o,
		Statement{Query: revokeUserQuery, Args: []any{unix, id.String(), adminRole}},
		Statement{Query: revokeUserSecretsQuery, Args: []any{unix, id.String()}},
		Statement{Query: revokeUserAgentsQuery, Args: []any{unix, id.String()}},
	)
	if errors.Is(err, ErrConflict) {
		return User{}, o.defect(err)
	}

	if err != nil {
		return User{}, err
	}

	user, err := one(results[0].Rows, o, readUser)
	if err != nil {
		return User{}, err
	}

	if user.RevokedAt == nil {
		return User{}, ErrLastAdmin
	}

	return user, nil
}
