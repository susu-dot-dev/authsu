package store

import (
	"context"
	"errors"
)

// Error codes of the first-run operation. They are stable: clients and
// dashboards may match on them.
const (
	CodeFirstRunCheckFailed   = "first_run_check_failed"
	CodeFirstRunCheckRejected = "first_run_check_rejected"
)

// firstRunDescription is the client-safe text of the operation's failures.
const firstRunDescription = "first-run status is temporarily unavailable"

// firstRunStateQuery reads, in one statement, the three facts first-run status
// is made of, so they describe one instant: facts read as separate statements
// could see an account appear (or an invitation get created) between them.
//
// Arguments: first-run type.
const firstRunStateQuery = `
SELECT EXISTS (SELECT 1 FROM users) AS has_users,
       EXISTS (SELECT 1 FROM invitations) AS has_invitations,
       EXISTS (SELECT 1 FROM invitations WHERE type = ?) AS has_first_run_invitation`

// FirstRunState is where first-run setup stands in the database.
type FirstRunState struct {
	// HasUsers is whether any account exists. Setup is over once one does.
	HasUsers bool

	// HasInvitations is whether any invitation exists, of any type. The
	// first-run invitation can be created only while none does.
	HasInvitations bool

	// HasFirstRunInvitation is whether an invitation of type InvitationFirstRun
	// exists, redeemed or not.
	HasFirstRunInvitation bool
}

// FirstRunState reads whether any account and any first-run invitation exist,
// as one snapshot.
func (s *Store) FirstRunState(ctx context.Context) (FirstRunState, error) {
	o := op{failed: CodeFirstRunCheckFailed, rejected: CodeFirstRunCheckRejected, description: firstRunDescription}

	// A SELECT of three EXISTS always returns exactly one row, so no row at all is
	// not "not found" but a malformed result.
	state, err := queryOne(ctx, s, o, Statement{Query: firstRunStateQuery, Args: []any{InvitationFirstRun}},
		func(r *row) FirstRunState {
			// Struct fields are evaluated in order, which is the column order.
			return FirstRunState{HasUsers: r.boolean(), HasInvitations: r.boolean(), HasFirstRunInvitation: r.boolean()}
		})
	if errors.Is(err, ErrNotFound) {
		return FirstRunState{}, o.defect(err)
	}

	return state, err
}
