package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// Error codes of the invitation operations. They are stable: clients and
// dashboards may match on them.
const (
	CodeInvitationListFailed     = "invitation_list_failed"
	CodeInvitationListRejected   = "invitation_list_rejected"
	CodeInvitationCreateFailed   = "invitation_create_failed"
	CodeInvitationCreateRejected = "invitation_create_rejected"
	CodeInvitationUpdateFailed   = "invitation_update_failed"
	CodeInvitationUpdateRejected = "invitation_update_rejected"
	CodeInvitationRevokeFailed   = "invitation_revoke_failed"
	CodeInvitationRevokeRejected = "invitation_revoke_rejected"
)

// invitationsDescription is the client-safe text of every invitation
// operation's Unavailable error.
const invitationsDescription = "invitations are temporarily unavailable"

// MaxInvitationTypeLen is the longest invitation type the invitations.type
// column accepts (its CHECK is length(type) BETWEEN 1 AND 64). Types are chosen
// by code, never by a client, so this is checked where they are configured.
const MaxInvitationTypeLen = 64

// Invitation is one invitation as an admin sees it, with its use count. It
// never carries the token or its hash: no query here selects them.
type Invitation struct {
	ID    string
	Type  string
	Label string

	// NumInvites is how many accounts it may create.
	NumInvites int64

	// Uses is how many accounts it has created: the users that point at it. The
	// account is the redemption (docs/invitations_design.md).
	Uses int64

	// ExpiresAt is when it stops working, in Unix seconds. Every invitation
	// expires.
	ExpiresAt int64

	// RevokedAt and CreatedBy are nil when not set (Unix seconds for the
	// time). CreatedBy is also nil for the first-run invitation, which no
	// account created.
	RevokedAt *int64
	CreatedBy *string

	// CreatedAt is in Unix seconds.
	CreatedAt int64
}

// readInvitation reads the nine columns every invitation statement returns, in
// this order: id, type, label, num_invites, uses, expires_at, revoked_at,
// created_by, created_at.
func readInvitation(r *row) Invitation {
	// Struct fields are evaluated in order, which is the column order.
	return Invitation{
		ID: r.text(), Type: r.text(), Label: r.text(),
		NumInvites: r.integer(), Uses: r.integer(),
		ExpiresAt: r.integer(), RevokedAt: r.optInteger(), CreatedBy: r.optText(),
		CreatedAt: r.integer(),
	}
}

// listInvitationsQuery reads every invitation, revoked ones included, newest
// first. An invitation's expiry, revocation and creation time are on its
// secret, which is joined on the id and the kind together, as the schema's
// foreign key is. The id is a UUIDv7, so it breaks ties between invitations
// created in the same second in creation order.
//
// The use count is the number of users pointing at the invitation. The token
// and its hash are not selected: nothing here can return them. The count has an
// alias of its own, because a batch returns rows keyed by column name.
//
// Arguments: none.
const listInvitationsQuery = `
SELECT i.id AS id, i.type AS type, i.label AS label, i.num_invites AS num_invites,
       (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) AS uses,
       s.expires_at AS expires_at, s.revoked_at AS revoked_at, i.created_by AS created_by,
       s.created_at AS created_at
FROM invitations i
JOIN secrets s ON s.id = i.id AND s.kind = i.kind
ORDER BY s.created_at DESC, i.id DESC`

// ListInvitations returns every invitation, revoked ones included, newest
// first. It is not paged: the list is the admin's own and short. The result is
// empty and not nil when there are none.
func (s *Store) ListInvitations(ctx context.Context) ([]Invitation, error) {
	o := op{failed: CodeInvitationListFailed, rejected: CodeInvitationListRejected,
		description: invitationsDescription}

	return queryAll(ctx, s, o, Statement{Query: listInvitationsQuery, Args: nil}, readInvitation)
}

// readInvitationQuery is the last statement of an invitation create and revoke:
// it reads the invitation as the batch left it, with the columns of
// listInvitationsQuery. The batch is one transaction, so this reads the writes
// before it and nothing another request did in between, which is what makes the
// response the database's view and not the caller's copy of what it sent.
//
// It is a SELECT of its own because an invitation's row and its secret are two
// tables, and no single write can return both. No row means no such
// invitation.
//
// Arguments: id.
const readInvitationQuery = `
SELECT i.id AS id, i.type AS type, i.label AS label, i.num_invites AS num_invites,
       (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) AS uses,
       s.expires_at AS expires_at, s.revoked_at AS revoked_at, i.created_by AS created_by,
       s.created_at AS created_at
FROM invitations i
JOIN secrets s ON s.id = i.id AND s.kind = i.kind
WHERE i.id = ?`

// insertInvitationQuery writes the invitation's own row, after its secret, in
// the same batch. The creator is an admin, who is a user, so created_by is
// bound to a real account (a FOREIGN KEY, which makes an unknown creator a
// defect and not a client error). The foreign key on the id and the kind
// together is what ties the row to the secret the previous statement wrote.
//
// Arguments, in order: id, kind, type, label, num_invites, created_by.
const insertInvitationQuery = `
INSERT INTO invitations (id, kind, type, label, num_invites, created_by)
VALUES (?, ?, ?, ?, ?, ?)`

// errGeneratedValueTaken is the cause of a create that collided with a row on a
// value the server generated.
var errGeneratedValueTaken = errors.New("a generated invitation id or token hash is already taken")

// NewInvitation is an invitation to create. The token is generated by the
// server, so it arrives as its hash, and so do the id and the time.
type NewInvitation struct {
	// ID is the new invitation's id (a UUIDv7 in canonical text form), which is
	// also its secret's id.
	ID string

	// TokenHash is the SHA-256 of the token (input.InvitationToken.Hash): the
	// token itself is never stored.
	TokenHash []byte

	// Type is what the invitation grants. The caller decides which types it may
	// create.
	Type string

	// Label is a note for admins. It may be empty.
	Label input.InvitationLabel

	// NumInvites is how many accounts it may create.
	NumInvites input.NumInvites

	// ExpiresAt is when it stops working. Every invitation expires.
	ExpiresAt input.Expiry

	// CreatedBy is the id of the admin creating it.
	CreatedBy string

	// CreatedAt is when it was created.
	CreatedAt time.Time
}

// CreateInvitation writes an invitation's secret and its own row as one batch,
// then reads the invitation back in the same batch, and returns the row as the
// database stored it.
//
// There is no conflict outcome. The id and the token hash are both generated by
// the server (a UUIDv7 and the hash of 256 random bits), so a UNIQUE collision
// is not something the client did or can resolve by changing its request: it
// is a defect (or an entropy failure), reported under
// CodeInvitationCreateRejected like a CHECK or FOREIGN KEY refusal. The client
// may simply try again, which generates a new token.
func (s *Store) CreateInvitation(ctx context.Context, invitation NewInvitation) (Invitation, error) {
	o := op{failed: CodeInvitationCreateFailed, rejected: CodeInvitationCreateRejected,
		description: invitationsDescription}

	results, err := s.run(ctx, o,
		insertSecret(invitation.ID, KindInvitation, invitation.TokenHash,
			invitation.ExpiresAt.Unix(), invitation.CreatedAt.Unix()),
		Statement{Query: insertInvitationQuery, Args: []any{
			invitation.ID, KindInvitation, invitation.Type, invitation.Label.String(),
			invitation.NumInvites.Int64(), invitation.CreatedBy,
		}},
		Statement{Query: readInvitationQuery, Args: []any{invitation.ID}},
	)
	if errors.Is(err, ErrConflict) {
		// The text is kept for the log, but the sentinel is not: a feature that
		// looks for ErrConflict in the chain must not see this as the client's.
		return Invitation{}, o.defect(fmt.Errorf("%w: %s", errGeneratedValueTaken, err.Error()))
	}

	if err != nil {
		return Invitation{}, err
	}

	created, err := one(results[2].Rows, o, readInvitation)
	if errors.Is(err, ErrNotFound) {
		// The row was written by this batch, so the read always returns it.
		return Invitation{}, o.defect(fmt.Errorf("%w: the invitation just written was not found", errRowCount))
	}

	return created, err
}

// updateNumInvitesQuery changes how many accounts an invitation may create. It
// is a conditional write, because D1 has no interactive transaction and a
// read-then-write would race with a registration finishing in between:
//
//   - The invitation must not be revoked as of now. A revoked invitation is
//     final, and changing it would suggest it could be revived. Revocation is on
//     the invitation's secret, which must exist. It counts as revoked only once
//     its revoked_at has come, as everywhere a secret's activity is decided
//     (activeSecretPredicate), so one revoked for later can still be changed.
//   - The new cap must not be below the accounts it has already created. The
//     count is read in the write itself, so an account created after the
//     handler looked cannot be left over the cap.
//
// A WHERE that carried those conditions would match nothing when they fail, and
// a write that matches nothing says nothing about why. So the row is matched by
// id alone, the conditions decide whether the SET changes it (the CASE), and
// RETURNING reports the row as the statement left it together with whether the
// change applied. The statement is one transaction, so the row, its secret, its
// count of accounts and the verdict are all the same instant: nothing can slip
// in between the write and the account of it. No row returned means no such
// invitation.
//
// The verdict is the CASE's own test, written out again, and not derived from
// the new num_invites: setting the cap to the value it already has would
// otherwise look the same as a refusal. Nothing in the statement changes the
// secret or the users table, so the test reads the same in RETURNING as it did
// in the SET.
//
// RETURNING is "applied" (1 or 0) followed by the columns of
// listInvitationsQuery in the same order, the secret's read by subselect: a
// write to one table cannot join another. Each column has a distinct name,
// which D1's batch results need: columns that share one collapse into one.
//
// Arguments, by number: ?1 the new num_invites, ?2 the same value (compared
// with the count), ?3 id, ?4 now (unix seconds).
const updateNumInvitesQuery = `
UPDATE invitations
SET num_invites = CASE
      WHEN EXISTS (SELECT 1 FROM secrets s
                   WHERE s.id = invitations.id AND s.kind = invitations.kind
                     AND (s.revoked_at IS NULL OR s.revoked_at > ?4))
       AND (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) <= ?2
      THEN ?1
      ELSE num_invites
    END
WHERE id = ?3
RETURNING
  (EXISTS (SELECT 1 FROM secrets s
           WHERE s.id = invitations.id AND s.kind = invitations.kind
             AND (s.revoked_at IS NULL OR s.revoked_at > ?4))
   AND (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) <= ?2) AS applied,
  id, type, label, num_invites,
  (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) AS uses,
  (SELECT s.expires_at FROM secrets s WHERE s.id = invitations.id AND s.kind = invitations.kind) AS expires_at,
  (SELECT s.revoked_at FROM secrets s WHERE s.id = invitations.id AND s.kind = invitations.kind) AS revoked_at,
  created_by,
  (SELECT s.created_at FROM secrets s WHERE s.id = invitations.id AND s.kind = invitations.kind) AS created_at`

// UpdateNumInvites sets how many accounts an invitation may create. It returns
// the invitation as the write left it and whether the change applied.
//
// It does not apply, and the invitation comes back unchanged, when the
// invitation is revoked as of now or when it has already created more accounts than n;
// the returned row says which (RevokedAt, Uses), as of the same instant the
// write ran. It returns ErrNotFound when there is no such invitation.
func (s *Store) UpdateNumInvites(
	ctx context.Context, id input.ID, n input.NumInvites, now time.Time,
) (Invitation, bool, error) {
	o := op{failed: CodeInvitationUpdateFailed, rejected: CodeInvitationUpdateRejected,
		description: invitationsDescription}

	type verdict struct {
		applied    bool
		invitation Invitation
	}

	got, err := queryOne(ctx, s, o,
		Statement{Query: updateNumInvitesQuery, Args: []any{n.Int64(), n.Int64(), id.String(), now.Unix()}},
		func(r *row) verdict {
			// Evaluated in order: the verdict is the first column.
			return verdict{applied: r.boolean(), invitation: readInvitation(r)}
		})
	if err != nil {
		return Invitation{}, false, err
	}

	return got.invitation, got.applied, nil
}

// revokeInvitationSecretQuery revokes an invitation's secret now. One whose
// revocation has already come keeps its earlier time, so revoking twice cannot
// move a revocation later; one scheduled for later is brought forward to now,
// so a revoke always takes effect at once (as with sessions). The min of the
// stored time and now is both rules: COALESCE reads "never revoked" as now.
// Neither row is ever
// deleted: accounts reference the invitation, and the audit question "who came
// from this token?" must stay answerable.
//
// The secret is matched by id and by the invitation kind, so this can never
// revoke the secret of anything else. The statement reports nothing of its own;
// readInvitationQuery follows it in the same batch and gives the row as the
// batch left it, so both ways a revoke can end are the same answer, which the
// caller reads off the row: it was revoked now, or it already was. Neither is
// told apart, because neither differs to the client. No row read means no such
// invitation, which a WHERE on revoked_at could not distinguish from one that
// was already revoked.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 id, ?3 kind.
const revokeInvitationSecretQuery = `
UPDATE secrets
SET revoked_at = min(COALESCE(revoked_at, ?1), ?1)
WHERE id = ?2 AND kind = ?3`

// RevokeInvitation revokes an invitation as of now and returns it as the batch
// left it. Revoking one that is already revoked succeeds and changes nothing,
// so the call is idempotent: the earlier revocation time is kept, and a
// revocation scheduled for later is brought forward to now. It returns
// ErrNotFound when there is no such invitation.
//
// Nothing the batch writes can collide with data, so a constraint failure of any
// kind is a defect on our side and is reported as the operation's "_rejected"
// 500, including the conflict that run hands back bare.
func (s *Store) RevokeInvitation(ctx context.Context, id input.ID, now time.Time) (Invitation, error) {
	o := op{failed: CodeInvitationRevokeFailed, rejected: CodeInvitationRevokeRejected,
		description: invitationsDescription}

	results, err := s.run(ctx, o,
		Statement{Query: revokeInvitationSecretQuery, Args: []any{now.Unix(), id.String(), KindInvitation}},
		Statement{Query: readInvitationQuery, Args: []any{id.String()}},
	)
	if errors.Is(err, ErrConflict) {
		return Invitation{}, o.defect(err)
	}

	if err != nil {
		return Invitation{}, err
	}

	return one(results[1].Rows, o, readInvitation)
}
