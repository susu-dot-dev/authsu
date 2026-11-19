//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const firstRunDescription = "first-run status is temporarily unavailable"

// TestFirstRunState holds how the one-statement snapshot is read: each of the
// four answers.
func TestFirstRunState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		row  []any
		want store.FirstRunState
	}{
		{name: "an empty system", row: row(int64(0), int64(0))},
		{name: "an invitation waiting", row: row(int64(0), int64(1)),
			want: store.FirstRunState{HasFirstRunInvitation: true}},
		{name: "users and no first-run invitation", row: row(int64(1), int64(0)),
			want: store.FirstRunState{HasUsers: true}},
		{name: "setup is over", row: row(int64(1), int64(1)),
			want: store.FirstRunState{HasUsers: true, HasFirstRunInvitation: true}},
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

			// One statement carries both answers, so they are one snapshot.
			checkStatements(t, fake, wantStatement{
				fragments: []string{
					"EXISTS (SELECT 1 FROM users) AS has_users",
					"EXISTS (SELECT 1 FROM invitations WHERE type = ?) AS has_first_run_invitation",
				},
				args: []any{store.InvitationFirstRun},
			})
		})
	}
}

// TestFirstRunStateDefects holds that anything but a single row of two
// booleans is a defect: the SELECT of two EXISTS always returns one.
func TestFirstRunStateDefects(t *testing.T) {
	t.Parallel()

	two := row(int64(0), int64(0))

	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "no row at all", rows: nil},
		{name: "two rows", rows: [][]any{two, two}},
		{name: "a count and not a boolean", rows: [][]any{row(int64(2), int64(0))}},
		{name: "a float", rows: [][]any{row(float64(1), int64(0))}},
		{name: "text", rows: [][]any{row(int64(0), "1")}},
		{name: "NULL", rows: [][]any{row(nil, int64(0))}},
		{name: "a column too few", rows: [][]any{row(int64(0))}},
		{name: "a column too many", rows: [][]any{row(int64(0), int64(0), int64(0))}},
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

// firstRunBatch is the outcome of the first-run batch: the secret insert, which
// returns nothing, then the invitation insert, which returned rows.
func firstRunBatch(rows ...[]any) outcome {
	return outcome{results: []store.Result{{Changes: 0, Rows: nil}, {Changes: 0, Rows: rows}}, err: nil}
}

// TestCreateFirstRunInvitation holds that the second insert's RETURNING is the
// outcome: one row is "this call created it" and none is "the conditions
// refused it".
func TestCreateFirstRunInvitation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rows    [][]any
		created bool
	}{
		{name: "this call created it", rows: [][]any{row("inv-1")}, created: true},
		{name: "an invitation or an account already exists", rows: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(firstRunBatch(test.rows...))
			token := mustInvitationToken(t, 2)
			expires := now.Add(input.ExpiryHorizon)

			created, err := fake.store().CreateFirstRunInvitation(
				context.Background(), "inv-1", token, "First run: initial administrator", expires, now)

			checkErr(t, err, nil)

			if created != test.created {
				t.Errorf("created = %v, want %v", created, test.created)
			}

			checkStatements(t, fake,
				wantStatement{
					fragments: []string{
						"INSERT INTO secrets (id, kind, hash, expires_at, created_at)",
						"SELECT ?, ?, ?, ?, ?",
						// The emptiness conditions are part of the insert, so two
						// racing status checks cannot both create the invitation.
						"WHERE NOT EXISTS (SELECT 1 FROM invitations)",
						"AND NOT EXISTS (SELECT 1 FROM users)",
					},
					args: []any{"inv-1", store.KindInvitation, token.Hash(), expires.Unix(), now.Unix()},
				},
				wantStatement{
					fragments: []string{
						"INSERT INTO invitations (id, kind, type, label, num_invites)",
						"SELECT ?, ?, ?, ?, 1",
						// The invitation is written only if this call's secret
						// is there: the id is fresh, so only the statement before
						// it can have written one, and the pair stands or falls
						// together.
						"WHERE EXISTS (SELECT 1 FROM secrets WHERE id = ? AND kind = ?)",
						"RETURNING id",
					},
					args: []any{
						"inv-1", store.KindInvitation, store.InvitationFirstRun, "First run: initial administrator",
						"inv-1", store.KindInvitation,
					},
				},
			)
		})
	}
}

// TestCreateFirstRunInvitationDefects holds that a RETURNING that is not at most
// one text id is a defect, and never "created".
func TestCreateFirstRunInvitationDefects(t *testing.T) {
	t.Parallel()

	for name, rows := range defectResults(row("inv-1"), "text") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			created, err := newFake(firstRunBatch(rows...)).store().
				CreateFirstRunInvitation(context.Background(), "inv-1", mustInvitationToken(t, 2), "", now, now)

			checkErr(t, err, defectOf(store.CodeFirstRunCreateRejected))

			if created {
				t.Error("a defective result reported the invitation as created")
			}
		})
	}
}

// TestCreateFirstRunInvitationFailures holds how a failed batch is reported. A
// conflict is a defect: the id is fresh, and a taken hash means a secret exists
// without its invitation, which is the schema and the code disagreeing and not
// something a client can resolve.
func TestCreateFirstRunInvitationFailures(t *testing.T) {
	t.Parallel()

	runDefectFailures(t, 2, store.CodeFirstRunCreateFailed, store.CodeFirstRunCreateRejected, firstRunDescription,
		func(s *store.Store) error {
			return lastErr(s.CreateFirstRunInvitation(
				context.Background(), "inv-1", mustInvitationToken(t, 2), "", now, now))
		})
}

// TestFirstRunCodes pins the wire codes the operations report.
func TestFirstRunCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeFirstRunCheckFailed, "first_run_check_failed"},
		{store.CodeFirstRunCheckRejected, "first_run_check_rejected"},
		{store.CodeFirstRunCreateFailed, "first_run_create_failed"},
		{store.CodeFirstRunCreateRejected, "first_run_create_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}
