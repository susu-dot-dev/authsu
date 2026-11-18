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

// insertFirstRunQuery inserts the first-run invitation for a code. It reports
// whether this call inserted it.
//
// The emptiness conditions are part of the insert itself, so two racing status
// checks cannot both create it: the database admits exactly one. RETURNING
// makes the statement report its own outcome: one row means this call inserted
// the invitation, no rows means the conditions refused it. Nothing is read back
// afterwards, because a later read cannot tell this insert's row from one
// written by another caller.
//
// Arguments, in order: id, code_hash, type, label, created_at.
const insertFirstRunQuery = `
INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at)
SELECT ?, ?, ?, ?, 1, ?
WHERE NOT EXISTS (SELECT 1 FROM invitations)
  AND NOT EXISTS (SELECT 1 FROM users)
RETURNING id`

// CreateFirstRunInvitation inserts the single-use first-run invitation for code,
// but only while there is no invitation and no account at all. It reports true
// when this call inserted it, and false when the conditions refused it.
func (s *Store) CreateFirstRunInvitation(
	ctx context.Context, id string, code input.InvitationCode, label string, now time.Time,
) (bool, error) {
	o := op{failed: CodeFirstRunCreateFailed, rejected: CodeFirstRunCreateRejected, description: firstRunDescription}

	_, created, err := find(ctx, s, o,
		Statement{Query: insertFirstRunQuery, Args: []any{id, code.Hash(), InvitationFirstRun, label, now.Unix()}},
		func(r *row) string { return r.text() })

	return created, err
}
