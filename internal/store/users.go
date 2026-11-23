package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
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
// because it is the last active platform administrator: the only recovery from
// having none is wiping the database (docs/users_design.md).
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

// The conditions of revoking an account, as SQL text over tu, the account's row,
// with ?1 its id, ?2 the caller's id and ?3 the role of a platform administrator
// (which role administers is defined in a higher layer, so this package only
// compares it). They are part of the write and not a read before it: D1 has no
// interactive transaction, so a read could be stale by the time the write ran.
const (
	// callerIsPlatformAdmin holds when the caller is an unrevoked platform
	// administrator.
	callerIsPlatformAdmin = `EXISTS (SELECT 1 FROM users pa WHERE pa.id = ?2 AND pa.revoked_at IS NULL AND pa.role = ?3)`

	// callerMayRevokeTarget holds when the caller may revoke the account: a
	// platform administrator may revoke any account, and an administrator of the
	// account's organization may revoke it unless it is a platform administrator
	// or the caller themself. Both require the caller to be unrevoked
	// (callerAdministersTargetOrg does), so an account revoked after its request
	// was authenticated revokes nothing.
	//
	// The guard that an organization keeps an unrevoked administrator is this
	// condition itself, and needs no statement of its own. A caller who is not a
	// platform administrator revokes only as an unrevoked administrator of the
	// account's organization who is not the account, so the organization keeps
	// at least them. A platform administrator may revoke its last administrator,
	// and is then the way such an organization is managed (docs/orgs_design.md,
	// principle 3).
	callerMayRevokeTarget = callerAdministersTargetOrg + ` AND ((tu.role <> ?3 AND tu.id <> ?2) OR ` +
		callerIsPlatformAdmin + `)`

	// platformAdminRemains holds when revoking the account would not leave the
	// platform without an unrevoked administrator: the account is already
	// revoked (and keeps its earlier time), is not an administrator, or another
	// unrevoked administrator exists. It is one with the rest of the write because
	// two administrators revoking each other at the same moment would each see
	// the other still active, and both writes would apply, leaving none. D1 runs
	// one batch at a time, so the second sees the first's revocation and is
	// refused.
	platformAdminRemains = `(tu.revoked_at IS NOT NULL OR tu.role <> ?3
    OR EXISTS (SELECT 1 FROM users other
               WHERE other.id <> tu.id AND other.role = ?3 AND other.revoked_at IS NULL))`

	// revokeAllowed holds when the caller may revoke the account now. Every
	// statement of the revocation carries it, so a refused revocation changes
	// nothing, not even the secrets or agents of an account that is already
	// revoked.
	revokeAllowed = callerMayRevokeTarget + ` AND ` + platformAdminRemains
)

// revokeStandingQuery reads an account the caller may see, as the first
// statement of a revocation, so that a revocation that matched nothing can say
// why from the state the write saw (the batch is one transaction). It returns the
// columns of readMember, then whether the account is a platform administrator,
// whether the caller administers the account's organization (or is a platform
// administrator), and whether the caller may revoke it before the last
// platform administrator is considered. No row is an account that does not
// exist or that the caller may not see, which is the same answer for both.
//
// Arguments, by number: ?1 account id, ?2 caller id, ?3 the platform
// administrator role.
const revokeStandingQuery = `
SELECT tu.id AS id, tu.org_id AS org_id,
       EXISTS (SELECT 1 FROM org_admins ta WHERE ta.org_id = tu.org_id AND ta.user_id = tu.id) AS is_admin,
       tu.revoked_at AS revoked_at, tu.created_at AS created_at,
       tu.role = ?3 AS platform_admin,
       ` + callerAdministersTargetOrg + ` AS administers,
       ` + callerMayRevokeTarget + ` AS may_revoke
FROM users tu
WHERE tu.id = ?1 AND ` + callerSeesTargetOrg

// revokeUserQuery revokes an account now, if the caller may (revokeAllowed).
//
// An account that is already revoked keeps its earlier time (the COALESCE), so
// revoking twice succeeds, for anyone who may revoke it, and cannot move the
// revocation later. RETURNING gives the row as the statement left it, so the
// outcome is the row and not a second read that could see a different state. No
// row means nothing matched: the account does not exist, the caller may not
// revoke it, or it is the last unrevoked platform administrator, and
// revokeStandingQuery, which ran before, says which.
//
// RETURNING is the columns of listUsersQuery, in that order, so readUser reads
// it. It is the last statement of the batch: the secrets and agents are revoked
// by the statements before it, which carry the same conditions.
//
// Arguments, by number: ?1 account id, ?2 caller id, ?3 the platform
// administrator role, ?4 revoked_at (unix seconds).
const revokeUserQuery = `
UPDATE users AS tu
SET revoked_at = COALESCE(tu.revoked_at, ?4)
WHERE tu.id = ?1 AND ` + revokeAllowed + `
RETURNING id, role, invitation_id, profile, revoked_at, created_at`

// revokeUserSecretsQuery revokes every session, every API key and every OAuth
// grant of the account, with the grants' access tokens, in the same batch as
// revokeUserQuery and before it. The keys and grants of the account's agents are
// among them: a key's or grant's user_id is its agent's owner. Resolving already
// refuses any session or key of a revoked account (it reads users.revoked_at),
// and so does introspection of an access token, so this is not what ends them. It
// keeps the secrets table honest: a secret listed later reads as revoked, and a
// future kind of secret whose resolve forgot to check the account would still be
// refused.
//
// It applies only when the caller may revoke the account (revokeAllowed, the
// same condition as revokeUserQuery's, which therefore revokes it in the same
// batch), so a refused revocation changes no secret. It runs before the account
// is revoked because the caller's authority is judged on the state the whole
// batch started from: afterwards, an administrator who revoked themself would no
// longer be one. A secret whose revocation is already due keeps its time; one
// scheduled for later is brought forward. The account's invitations are not among
// them: an invitation belongs to no account.
//
// Arguments, by number: ?1 account id, ?2 caller id, ?3 the platform
// administrator role, ?4 revoked_at (unix seconds).
const revokeUserSecretsQuery = `
UPDATE secrets
SET revoked_at = ?4
WHERE id IN (SELECT id FROM sessions WHERE user_id = ?1
             UNION ALL
             SELECT id FROM api_keys WHERE user_id = ?1
             UNION ALL
             SELECT id FROM oauth_grants WHERE user_id = ?1
             UNION ALL
             SELECT t.id FROM oauth_access_tokens t JOIN oauth_grants g ON g.id = t.grant_id WHERE g.user_id = ?1)
  AND (revoked_at IS NULL OR revoked_at > ?4)
  AND EXISTS (SELECT 1 FROM users tu WHERE tu.id = ?1 AND ` + revokeAllowed + `)`

// revokeUserAgentsQuery revokes every agent of the account, in the same batch
// as revokeUserQuery and before it, because an agent's authority is borrowed
// from its user (docs/agents_design.md). The agents' keys are already revoked
// by revokeUserSecretsQuery, which matches every key of the account; this keeps
// the agents table honest, so an agent lists as revoked and cannot be renamed.
//
// It applies only when the caller may revoke the account, as
// revokeUserSecretsQuery does, so a refused revocation changes no agent. An agent
// that is already revoked keeps its earlier time.
//
// Arguments, by number: ?1 account id, ?2 caller id, ?3 the platform
// administrator role, ?4 revoked_at (unix seconds).
const revokeUserAgentsQuery = `
UPDATE agents
SET revoked_at = ?4
WHERE user_id = ?1
  AND revoked_at IS NULL
  AND EXISTS (SELECT 1 FROM users tu WHERE tu.id = ?1 AND ` + revokeAllowed + `)`

// revokeStanding is an account the caller may see, with what the caller may do
// to it (see revokeStandingQuery).
type revokeStanding struct {
	member        Member
	platformAdmin bool
	administers   bool
	mayRevoke     bool
}

// readRevokeStanding reads the columns of readMember and then platform_admin,
// administers and may_revoke.
func readRevokeStanding(r *row) revokeStanding {
	member := readMember(r)

	return revokeStanding{member: member, platformAdmin: r.boolean(), administers: r.boolean(), mayRevoke: r.boolean()}
}

// revocation is what a revocation left: the account as the write returned it,
// and the member it was as the batch started, which carries the organization.
type revocation struct {
	user   User
	member Member
}

// revoke revokes the account id for the caller, its secrets and its agents, as
// one batch, for the operation o. It returns ErrNotFound when the account does
// not exist or the caller may not see it, ErrAccountRevoked when the caller was
// revoked (which is why they may not see it), and otherwise why a revocation that
// the caller may not make was refused (refusedRevoke).
//
// No statement sets a constrained column to anything but a time, so a constraint
// failure of any kind is a defect on our side and is reported as the operation's
// "_rejected" 500. That includes a conflict, which run hands back as the bare
// ErrConflict sentinel because most operations let their feature decide what it
// means: here there is no client-resolvable meaning, and a feature must never
// have to map a conflict this operation cannot produce.
func (s *Store) revoke(
	ctx context.Context, o op, id input.ID, caller, adminRole string, now time.Time,
) (revocation, error) {
	args := []any{id.String(), caller, adminRole, now.Unix()}

	return outcome(s.runChecked(ctx, o,
		Statement{Query: revokeStandingQuery, Args: args[:3]},
		Statement{Query: revokeUserSecretsQuery, Args: args},
		Statement{Query: revokeUserAgentsQuery, Args: args},
		Statement{Query: revokeUserQuery, Args: args},
		Statement{Query: callerStandingQuery, Args: []any{caller}},
	).
		Then(func(results []Result) (revocation, error) {
			return lookup(results[0].Rows, o, readRevokeStanding).
				Then(func(standing found[revokeStanding]) (revokeStanding, error) {
					if !standing.ok {
						return revokeStanding{}, unseen(o, results[4].Rows)
					}

					return standing.value, nil
				}).
				Then(func(standing revokeStanding) (revocation, error) {
					user, err := wroteOr(o, results[3].Rows, readUser, func() (User, error) {
						return User{}, refusedRevoke(o, standing, id.String() == caller)
					})

					return revocation{user: user, member: standing.member}, err
				}).
				Get()
		}),
	)
}

// refusedRevoke is why a revocation that matched nothing was refused, for a
// caller who can see the account, read off the standing statement that ran
// before it in the same batch. self is whether the caller is the account.
//
// A caller who does not administer the account's organization is told so. One who
// does and may not revoke it is an organization administrator facing a platform
// administrator or themself. One who may is a platform administrator facing the
// last unrevoked platform administrator (an account that is already revoked is
// never refused). Anything else is a defect.
func refusedRevoke(o op, standing revokeStanding, self bool) error {
	switch {
	case !standing.administers:
		return ErrNotAdmin
	case standing.mayRevoke && standing.platformAdmin:
		return ErrLastAdmin
	case !standing.mayRevoke && standing.platformAdmin:
		return ErrPlatformAdminTarget
	case !standing.mayRevoke && self:
		return ErrSelfRevoke
	default:
		return o.defect(fmt.Errorf("%w: nothing matched for a caller who may revoke", errChanges))
	}
}

// RevokeUser revokes the account id on behalf of the caller, with its secrets and
// its agents, as one batch, and returns the account as the write left it.
// adminRole is the role of a platform administrator, who may revoke any account
// and is the role the last-administrator guard protects.
//
// Revoking an account that is already revoked succeeds and keeps the earlier
// time, so the call is idempotent. It returns ErrNotFound when there is no such
// account or the caller may not see it, ErrAccountRevoked when the caller was
// revoked, ErrNotAdmin when the caller can see it
// but is neither a platform administrator nor an administrator of its
// organization, ErrPlatformAdminTarget and ErrSelfRevoke for an organization
// administrator who tried to revoke a platform administrator or themself, and
// ErrLastAdmin when the account is the last active platform administrator. A
// refused call changed nothing (see revokeAllowed for why the checks are inside
// the write).
func (s *Store) RevokeUser(
	ctx context.Context, id input.ID, caller, adminRole string, now time.Time,
) (User, error) {
	o := op{failed: CodeUserRevokeFailed, rejected: CodeUserRevokeRejected, description: usersDescription}

	return outcome(result.Of(s.revoke(ctx, o, id, caller, adminRole, now)).
		Map(func(done revocation) User { return done.user }))
}
