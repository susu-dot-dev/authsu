//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

const firstRunDescription = "first-run status is temporarily unavailable"

// TestFirstRunState holds how the one-statement snapshot is read: each of the
// three answers, in the order the query names them.
func TestFirstRunState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		row  []any
		want store.FirstRunState
	}{
		{name: "an empty system", row: row(int64(0), int64(0), int64(0))},
		{name: "a first-run invitation waiting", row: row(int64(0), int64(1), int64(1)),
			want: store.FirstRunState{HasInvitations: true, HasFirstRunInvitation: true}},
		{name: "an invitation of another type and no account", row: row(int64(0), int64(1), int64(0)),
			want: store.FirstRunState{HasInvitations: true}},
		{name: "users and no invitation at all", row: row(int64(1), int64(0), int64(0)),
			want: store.FirstRunState{HasUsers: true}},
		{name: "users and an invitation of another type", row: row(int64(1), int64(1), int64(0)),
			want: store.FirstRunState{HasUsers: true, HasInvitations: true}},
		{name: "setup is over", row: row(int64(1), int64(1), int64(1)),
			want: store.FirstRunState{HasUsers: true, HasInvitations: true, HasFirstRunInvitation: true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.row))

			got, err := fake.store().FirstRunState(context.Background())

			checkErr(t, err, nil)

			if got != test.want {
				t.Errorf("state = %+v, want %+v", got, test.want)
			}

			// One statement carries every answer, so they are one snapshot, and
			// it is a read: nothing in it writes.
			checkStatements(t, fake, wantStatement{
				fragments: []string{
					"SELECT EXISTS (SELECT 1 FROM users) AS has_users",
					"EXISTS (SELECT 1 FROM invitations) AS has_invitations",
					"EXISTS (SELECT 1 FROM invitations WHERE type = ?) AS has_first_run_invitation",
				},
				args: []any{store.InvitationFirstRun},
			})
		})
	}
}

// TestFirstRunStateDefects holds that anything but a single row of three
// booleans is a defect: the SELECT of three EXISTS always returns one.
func TestFirstRunStateDefects(t *testing.T) {
	t.Parallel()

	three := row(int64(0), int64(0), int64(0))

	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "no row at all", rows: nil},
		{name: "two rows", rows: [][]any{three, three}},
		{name: "a count and not a boolean", rows: [][]any{row(int64(2), int64(0), int64(0))}},
		{name: "a float", rows: [][]any{row(float64(1), int64(0), int64(0))}},
		{name: "text", rows: [][]any{row(int64(0), "1", int64(0))}},
		{name: "NULL", rows: [][]any{row(nil, int64(0), int64(0))}},
		{name: "NULL in the last column", rows: [][]any{row(int64(0), int64(0), nil)}},
		{name: "a column too few", rows: [][]any{row(int64(0), int64(0))}},
		{name: "a column too many", rows: [][]any{row(int64(0), int64(0), int64(0), int64(0))}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := newFake(returning(test.rows...)).store().FirstRunState(context.Background())

			checkErr(t, err, defectOf(store.CodeFirstRunCheckRejected))

			if got != (store.FirstRunState{}) {
				t.Errorf("a defective row returned %+v", got)
			}
		})
	}
}

// TestFirstRunStateFailures holds how a failed batch is reported.
func TestFirstRunStateFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeFirstRunCheckFailed, store.CodeFirstRunCheckRejected, firstRunDescription,
		func(s *store.Store) error { return lastErr(s.FirstRunState(context.Background())) })
}

// TestFirstRunCodes pins the wire codes the operation reports.
func TestFirstRunCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeFirstRunCheckFailed, "first_run_check_failed"},
		{store.CodeFirstRunCheckRejected, "first_run_check_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}
