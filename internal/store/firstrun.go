package store

import (
	"context"
	"errors"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// Error codes of the first-run operations. They are stable: clients and
// dashboards may match on them.
const (
	CodeFirstRunCheckFailed    = "first_run_check_failed"
	CodeFirstRunCheckRejected  = "first_run_check_rejected"
	CodeFirstRunCreateFailed   = "first_run_create_failed"
	CodeFirstRunCreateRejected = "first_run_create_rejected"
)

// firstRunDescription is the client-safe text of both operations' failures.
const firstRunDescription = "first-run status is temporarily unavailable"

// firstRunStateQuery reads, in one statement, the two facts first-run status is
// made of, so they describe one instant: a pair read as two statements could
// see an account appear (or an invitation get created) between them.
//
// Arguments: first-run type.
const firstRunStateQuery = `
SELECT EXISTS (SELECT 1 FROM users) AS has_users,
       EXISTS (SELECT 1 FROM invitations WHERE type = ?) AS has_first_run_invitation`

// FirstRunState is where first-run setup stands in the database.
type FirstRunState struct {
	// HasUsers is whether any account exists. Setup is over once one does.
	HasUsers bool

	// HasFirstRunInvitation is whether an invitation of type InvitationFirstRun
	// exists, redeemed or not.
	HasFirstRunInvitation bool
}

// FirstRunState reads whether any account and any first-run invitation exist,
// as one snapshot.
func (s *Store) FirstRunState(ctx context.Context) (FirstRunState, error) {
	o := op{failed: CodeFirstRunCheckFailed, rejected: CodeFirstRunCheckRejected, description: firstRunDescription}

	// A SELECT of two EXISTS always returns exactly one row, so no row at all is
	// not "not found" but a malformed result.
	state, err := queryOne(ctx, s, o, Statement{Query: firstRunStateQuery, Args: []any{InvitationFirstRun}},
		func(r *row) FirstRunState {
			// Struct fields are evaluated in order, which is the column order.
			return FirstRunState{HasUsers: r.boolean(), HasFirstRunInvitation: r.boolean()}
		})
	if errors.Is(err, ErrNotFound) {
		return FirstRunState{}, o.defect(err)
	}

	return state, err
}

// insertFirstRunSecretQuery is the first statement of the first-run batch: it
// writes the secret of the first-run invitation, but only while there is no
// invitation and no account at all.
//
// The emptiness conditions are part of the insert itself, so two racing status
// checks cannot both create it: D1 runs a batch to its end before the next
// one starts, so the second sees the first's invitation and inserts nothing.
//
// Secrets of other kinds do not matter to the condition. Sessions and API keys
// exist only for accounts, so while there is no account there are none, and a
// secret of any kind never makes an invitation exist. What this insert must not
// do is leave a secret behind without its invitation, which the next statement
// prevents (see insertFirstRunInvitationQuery).
//
// Arguments, in order: id, kind, hash, expires_at, created_at.
//
//nolint:gosec // SQL naming the secrets table, not a credential
const insertFirstRunSecretQuery = `
INSERT INTO secrets (id, kind, hash, expires_at, created_at)
SELECT ?, ?, ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM invitations)
  AND NOT EXISTS (SELECT 1 FROM users)`

// insertFirstRunInvitationQuery is the second statement of the first-run batch:
// the invitation's own row, written only if the statement before it wrote this
// call's secret. The id is fresh for every call, so a secret with this id and
// kind exists only if the previous statement of this batch inserted it, and no
// other caller's secret can satisfy the condition. The two inserts therefore
// stand or fall together: when the conditions refused the secret there is
// nothing for the invitation to attach to and it is not written, and when the
// secret was written the invitation is, in the same transaction. Were the
// invitation insert to fail on a constraint, the batch would roll the secret
// back with it.
//
// RETURNING makes the statement report its own outcome: one row means this call
// created the invitation, no rows means the conditions refused it. Nothing is
// read back afterwards, because a later read cannot tell this insert's row from
// one written by another caller.
//
// created_by is NULL: no account created it. num_invites is 1.
//
// Arguments, in order: id, kind, type, label, the secret's id, the secret's
// kind.
const insertFirstRunInvitationQuery = `
INSERT INTO invitations (id, kind, type, label, num_invites)
SELECT ?, ?, ?, ?, 1
WHERE EXISTS (SELECT 1 FROM secrets WHERE id = ? AND kind = ?)
RETURNING id`

// CreateFirstRunInvitation creates the single-use first-run invitation for the
// token, but only while there is no invitation and no account at all. It
// reports true when this call created it, and false when the conditions refused
// it, in which case nothing was written.
//
// The secret and the invitation are one batch of two statements, the second
// conditional on the first having written its row, so neither half exists
// without the other. The invitation expires at expiresAt.
//
// The database never refuses a first-run create for a reason a client could
// resolve, so a constraint failure of any kind is a defect on our side and is
// reported as the operation's "_rejected" 500. That includes the token's hash
// already being taken, which is only possible if a secret exists without its
// invitation.
func (s *Store) CreateFirstRunInvitation(
	ctx context.Context, id string, token input.InvitationToken, label string, expiresAt, now time.Time,
) (bool, error) {
	o := op{failed: CodeFirstRunCreateFailed, rejected: CodeFirstRunCreateRejected, description: firstRunDescription}

	results, err := s.run(ctx, o,
		Statement{Query: insertFirstRunSecretQuery, Args: []any{
			id, KindInvitation, token.Hash(), expiresAt.Unix(), now.Unix(),
		}},
		Statement{Query: insertFirstRunInvitationQuery, Args: []any{
			id, KindInvitation, InvitationFirstRun, label, id, KindInvitation,
		}},
	)
	if errors.Is(err, ErrConflict) {
		return false, o.defect(err)
	}

	if err != nil {
		return false, err
	}

	_, created, err := findRow(results[1].Rows, o, func(r *row) string { return r.text() })

	return created, err
}
