//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	usersDescription = "users are temporarily unavailable"

	// userAdminRole is the role the caller passes to RevokeUser. The store only
	// compares it; which role administers is defined in a higher layer.
	userAdminRole = "admin"

	// The admin and member accounts of the fixtures.
	userID1 = "01890000-0000-7000-8000-000000000001"
	userID2 = "01890000-0000-7000-8000-000000000002"
)

// mustUserID parses an account id.
func mustUserID(tb testing.TB, raw string) input.ID {
	tb.Helper()

	id, err := input.ParseID(raw)
	if err != nil {
		tb.Fatalf("parse id %q: %v", raw, err)
	}

	return id
}

// userRowOf is the row of an account: id, role, invitation_id, profile,
// revoked_at (nil when not revoked), created_at.
func userRowOf(id, role string, revokedAt any, createdAt int64) []any {
	return row(id, role, "inv-1", `{"name":"Ada"}`, revokedAt, createdAt)
}

// activeUserRow is an active admin account.
func activeUserRow() []any { return userRowOf(userID1, userAdminRole, nil, 1_700_000_000) }

// revokedUserRow is a member account revoked at 1_700_000_050.
func revokedUserRow() []any { return userRowOf(userID2, "member", int64(1_700_000_050), 1_699_999_000) }

// userDefects are rows that are not the account row every statement returns.
// Each row is a defect, however it is read.
func userDefects() []struct {
	name string
	row  []any
} {
	return []struct {
		name string
		row  []any
	}{
		{name: "id is NULL", row: with(activeUserRow(), 0, nil)},
		{name: "id is an integer", row: with(activeUserRow(), 0, int64(1))},
		{name: "role is NULL", row: with(activeUserRow(), 1, nil)},
		{name: "role is a blob", row: with(activeUserRow(), 1, []byte("admin"))},
		{name: "invitation id is NULL", row: with(activeUserRow(), 2, nil)},
		{name: "profile is NULL", row: with(activeUserRow(), 3, nil)},
		{name: "profile is a blob", row: with(activeUserRow(), 3, []byte("{}"))},
		{name: "revoked_at is a float", row: with(activeUserRow(), 4, 1.7e9)},
		{name: "revoked_at is text", row: with(activeUserRow(), 4, "now")},
		{name: "created_at is NULL", row: with(activeUserRow(), 5, nil)},
		{name: "created_at is a float", row: with(activeUserRow(), 5, 1.7e9)},
		{name: "created_at is text", row: with(activeUserRow(), 5, "yesterday")},
		{name: "a column too few", row: activeUserRow()[:5]},
		{name: "a column too many", row: append(activeUserRow(), "extra")},
		{name: "an empty row", row: row()},
	}
}

// checkNumberedStatements is checkStatements for statements of numbered
// parameters (?1, ?2, ...): the helper in fixtures_test.go counts "?" marks,
// which is one per use, and a numbered parameter may be used several times.
// Here the parameters used must be exactly 1..len(args), with no unnumbered
// mark mixed in, so a numbering slip is caught even where a fragment is not.
func checkNumberedStatements(t *testing.T, fake *fakeExec, want ...wantStatement) {
	t.Helper()

	if len(fake.calls) != 1 {
		t.Fatalf("exec called %d times, want exactly one batch", len(fake.calls))
	}

	got := fake.calls[0]
	if len(got) != len(want) {
		t.Fatalf("batch has %d statements, want %d", len(got), len(want))
	}

	for i, expected := range want {
		query := squash(got[i].Query)

		for _, fragment := range expected.fragments {
			if !strings.Contains(query, fragment) {
				t.Errorf("statement %d lacks %q:\n%s", i, fragment, query)
			}
		}

		if !reflect.DeepEqual(got[i].Args, expected.args) {
			t.Errorf("statement %d args = %#v, want %#v", i, got[i].Args, expected.args)
		}

		checkNumbering(t, i, query, len(got[i].Args))
	}
}

// checkNumbering asserts that a query uses exactly the parameters ?1 to ?args.
func checkNumbering(t *testing.T, at int, query string, args int) {
	t.Helper()

	numbered := regexp.MustCompile(`\?(\d+)`)
	used := map[int]bool{}

	for _, match := range numbered.FindAllStringSubmatch(query, -1) {
		number, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatalf("statement %d: parameter %q: %v", at, match[0], err)
		}

		used[number] = true
	}

	if strings.Count(query, "?") != len(numbered.FindAllString(query, -1)) {
		t.Errorf("statement %d mixes unnumbered and numbered parameters:\n%s", at, query)
	}

	for number := 1; number <= args; number++ {
		if !used[number] {
			t.Errorf("statement %d never uses ?%d:\n%s", at, number, query)
		}
	}

	if len(used) != args {
		t.Errorf("statement %d uses %d distinct parameters for %d args:\n%s", at, len(used), args, query)
	}
}

// userColumns is the column list every statement that reads an account names.
// The WebAuthn user handle is not in it: nothing returns it.
const userColumns = "id, role, invitation_id, profile, revoked_at, created_at"

// TestListUsersDecoding holds how the rows of the list become accounts, in the
// order the database returned them.
func TestListUsersDecoding(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_050)

	tests := []struct {
		name string
		rows [][]any
		want []store.User
	}{
		{name: "no accounts is an empty list, not nil", rows: nil, want: []store.User{}},
		{name: "an active account", rows: [][]any{activeUserRow()}, want: []store.User{
			{ID: userID1, Role: userAdminRole, InvitationID: "inv-1", Profile: `{"name":"Ada"}`, RevokedAt: nil,
				CreatedAt: 1_700_000_000},
		}},
		{name: "a revoked account", rows: [][]any{revokedUserRow()}, want: []store.User{
			{ID: userID2, Role: "member", InvitationID: "inv-1", Profile: `{"name":"Ada"}`, RevokedAt: &revokedAt,
				CreatedAt: 1_699_999_000},
		}},
		{name: "the order is the database's", rows: [][]any{revokedUserRow(), activeUserRow()}, want: []store.User{
			{ID: userID2, Role: "member", InvitationID: "inv-1", Profile: `{"name":"Ada"}`, RevokedAt: &revokedAt,
				CreatedAt: 1_699_999_000},
			{ID: userID1, Role: userAdminRole, InvitationID: "inv-1", Profile: `{"name":"Ada"}`, RevokedAt: nil,
				CreatedAt: 1_700_000_000},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, err := fake.store().ListUsers(context.Background())

			checkErr(t, err, nil)

			if got == nil || !reflect.DeepEqual(got, test.want) {
				t.Errorf("users = %#v, want %#v", got, test.want)
			}
		})
	}
}

// TestListUsersDefects holds that a list with a row that is not an account is a
// defect as a whole: a broken row is not skipped, and nothing partial is
// returned.
func TestListUsersDefects(t *testing.T) {
	t.Parallel()

	for _, defect := range userDefects() {
		t.Run(defect.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(activeUserRow(), defect.row))

			got, err := fake.store().ListUsers(context.Background())

			checkErr(t, err, defectOf(store.CodeUserListRejected))

			if got != nil {
				t.Errorf("a defective list returned %#v", got)
			}
		})
	}
}

// TestListUsersStatement pins the list: every account, revoked ones included,
// newest first with the id breaking ties, and without the user handle.
func TestListUsersStatement(t *testing.T) {
	t.Parallel()

	fake := newFake(returning())

	_, err := fake.store().ListUsers(context.Background())
	checkErr(t, err, nil)

	checkStatements(t, fake, wantStatement{
		fragments: []string{
			"SELECT " + userColumns + " FROM users ORDER BY created_at DESC, id DESC",
		},
		args: nil,
	})

	// No filter: a revoked account is listed too.
	query := squash(fake.calls[0][0].Query)
	if strings.Contains(query, "WHERE") || strings.Contains(query, "user_handle") {
		t.Errorf("list is filtered or selects the user handle:\n%s", query)
	}
}

// TestListUsersFailures holds how a failed or malformed batch is reported.
func TestListUsersFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeUserListFailed, store.CodeUserListRejected, usersDescription,
		func(s *store.Store) error { return lastErr(s.ListUsers(context.Background())) })
}

// TestGetUserOutcomes holds the outcomes of a lookup: the account, or
// ErrNotFound, and a defect for a result that is not one account row.
func TestGetUserOutcomes(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_050)

	tests := []struct {
		name     string
		rows     [][]any
		want     store.User
		notFound bool
		defect   bool
	}{
		{name: "an active account", rows: [][]any{activeUserRow()},
			want: store.User{ID: userID1, Role: userAdminRole, InvitationID: "inv-1", Profile: `{"name":"Ada"}`,
				RevokedAt: nil, CreatedAt: 1_700_000_000}},
		{name: "a revoked account is still found", rows: [][]any{revokedUserRow()},
			want: store.User{ID: userID2, Role: "member", InvitationID: "inv-1", Profile: `{"name":"Ada"}`,
				RevokedAt: &revokedAt, CreatedAt: 1_699_999_000}},
		{name: "no such account", rows: nil, notFound: true},
		{name: "an empty result", rows: [][]any{}, notFound: true},
		{name: "two rows for one primary key", rows: [][]any{activeUserRow(), revokedUserRow()}, defect: true},
		{name: "a row that does not decode", rows: [][]any{row()}, defect: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, err := fake.store().GetUser(context.Background(), mustUserID(t, userID1))

			switch {
			case test.notFound:
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("error = %v, want ErrNotFound", err)
				}

				if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
					t.Errorf("not found %v is classified; the feature must decide that", err)
				}
			case test.defect:
				checkErr(t, err, defectOf(store.CodeUserLookupRejected))
			default:
				checkErr(t, err, nil)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("user = %#v, want %#v", got, test.want)
			}
		})
	}
}

// TestGetUserDefects holds that a row that is not an account is a defect and
// never "no such account".
func TestGetUserDefects(t *testing.T) {
	t.Parallel()

	for _, defect := range userDefects() {
		t.Run(defect.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(defect.row))

			got, err := fake.store().GetUser(context.Background(), mustUserID(t, userID1))

			checkErr(t, err, defectOf(store.CodeUserLookupRejected))

			if !reflect.DeepEqual(got, store.User{}) {
				t.Errorf("a defective row returned %#v", got)
			}
		})
	}
}

// TestGetUserStatement pins that the account is looked up by its id alone, and
// that the id is bound as its text.
func TestGetUserStatement(t *testing.T) {
	t.Parallel()

	for _, id := range []string{userID1, userID2} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, err := fake.store().GetUser(context.Background(), mustUserID(t, id))
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}

			checkStatements(t, fake, wantStatement{
				fragments: []string{"SELECT " + userColumns + " FROM users WHERE id = ?"},
				args:      []any{id},
			})
		})
	}
}

// TestGetUserFailures holds how a failed or malformed batch is reported.
func TestGetUserFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeUserLookupFailed, store.CodeUserLookupRejected, usersDescription,
		func(s *store.Store) error { return lastErr(s.GetUser(context.Background(), mustUserID(t, userID1))) })
}

// memberUser is the member account of revokedUserRow, revoked at the given time.
func memberUser(revokedAt *int64) store.User {
	return store.User{ID: userID2, Role: "member", InvitationID: "inv-1", Profile: `{"name":"Ada"}`,
		RevokedAt: revokedAt, CreatedAt: 1_699_999_000}
}

// revokeBatch is the outcome of RevokeUser's three-statement batch: the account
// statement returned rows and the secrets and agent statements changed the given
// number of rows each.
func revokeBatch(keys, agents int64, rows ...[]any) outcome {
	return outcome{err: nil, results: []store.Result{
		{Changes: 0, Rows: rows},
		{Changes: keys, Rows: nil},
		{Changes: agents, Rows: nil},
	}}
}

// TestRevokeUserOutcomes holds how the row the account statement returned
// becomes the operation's result: revoked_at set is a revocation, NULL is the
// last-admin guard refusing, and no row is no such account.
func TestRevokeUserOutcomes(t *testing.T) {
	t.Parallel()

	justNow := now.Unix()
	earlier := int64(1_700_000_050)

	tests := []struct {
		name    string
		outcome outcome
		want    store.User
		err     error
		defect  bool
	}{
		{name: "this call revoked an admin who is not the last",
			outcome: revokeBatch(0, 0, userRowOf(userID1, userAdminRole, justNow, 1_700_000_000)),
			want: store.User{ID: userID1, Role: userAdminRole, InvitationID: "inv-1", Profile: `{"name":"Ada"}`,
				RevokedAt: &justNow, CreatedAt: 1_700_000_000}},
		{name: "this call revoked a member with keys and agents",
			outcome: revokeBatch(3, 2, userRowOf(userID2, "member", justNow, 1_699_999_000)),
			want:    memberUser(&justNow)},
		{name: "already revoked keeps the earlier time",
			outcome: revokeBatch(0, 0, revokedUserRow()), want: memberUser(&earlier)},
		{name: "the last active admin is refused", outcome: revokeBatch(0, 0, activeUserRow()),
			err: store.ErrLastAdmin},
		{name: "no such account", outcome: revokeBatch(0, 0), err: store.ErrNotFound},
		{name: "two rows for one primary key", outcome: revokeBatch(0, 0, revokedUserRow(), revokedUserRow()),
			defect: true},
		{name: "two rows, the first refused", outcome: revokeBatch(0, 0, activeUserRow(), revokedUserRow()),
			defect: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(test.outcome)

			got, err := fake.store().RevokeUser(context.Background(), mustUserID(t, userID1), userAdminRole, now)

			switch {
			case test.defect:
				checkErr(t, err, defectOf(store.CodeUserRevokeRejected))
			case test.err != nil:
				if !errors.Is(err, test.err) {
					t.Fatalf("error = %v, want %v", err, test.err)
				}

				if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
					t.Errorf("outcome %v is classified; the feature must decide that", err)
				}
			default:
				checkErr(t, err, nil)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("user = %#v, want %#v", got, test.want)
			}
		})
	}
}

// TestRevokeUserDefects holds that a returned row that is not an account is a
// defect, and never a revocation, a refusal or a missing account.
func TestRevokeUserDefects(t *testing.T) {
	t.Parallel()

	for _, defect := range userDefects() {
		t.Run(defect.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(revokeBatch(0, 0, defect.row))

			got, err := fake.store().RevokeUser(context.Background(), mustUserID(t, userID1), userAdminRole, now)

			checkErr(t, err, defectOf(store.CodeUserRevokeRejected))

			if !reflect.DeepEqual(got, store.User{}) {
				t.Errorf("a defective row returned %#v", got)
			}
		})
	}
}

// TestRevokeUserStatements pins the batch: the three statements in order, the
// guards that decide what each does, and the exact arguments in placeholder
// order. The role is bound, and not written in the SQL.
func TestRevokeUserStatements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
		role string
		at   int64
	}{
		{name: "an admin role and an account", id: userID1, role: userAdminRole, at: now.Unix()},
		{name: "another role and another account", id: userID2, role: "owner", at: 1_700_000_999},
	}

	// The account must be revoked, as the statement left it, for the secrets and
	// agents statements to apply: this is the condition that lets a refused
	// revocation change nothing else.
	followsRevocation := "AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND revoked_at IS NOT NULL)"

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(revokeBatch(0, 0, userRowOf(test.id, "member", test.at, 1)))

			_, err := fake.store().RevokeUser(context.Background(), mustUserID(t, test.id), test.role, time.Unix(test.at, 0))
			checkErr(t, err, nil)

			checkNumberedStatements(t, fake,
				wantStatement{
					fragments: []string{
						// The account: keeps an earlier time, refuses to leave
						// no active admin, matches by id alone, and returns the
						// row as it was left.
						"UPDATE users SET revoked_at = COALESCE(revoked_at, CASE",
						"WHEN role <> ?3",
						"OR EXISTS (SELECT 1 FROM users other WHERE other.id <> users.id " +
							"AND other.role = ?3 AND other.revoked_at IS NULL)",
						"THEN ?1 END)",
						"WHERE id = ?2",
						"RETURNING " + userColumns,
					},
					args: []any{test.at, test.id, test.role},
				},
				wantStatement{
					fragments: []string{
						// The user's sessions, keys and OAuth grants with their access
						// tokens, those of its agents included: a due time is kept.
						"UPDATE secrets SET revoked_at = ?1",
						"WHERE id IN (SELECT id FROM sessions WHERE user_id = ?2 UNION ALL SELECT id FROM api_keys " +
							"WHERE user_id = ?2 UNION ALL SELECT id FROM oauth_grants WHERE user_id = ?2 " +
							"UNION ALL SELECT t.id FROM oauth_access_tokens t JOIN oauth_grants g ON g.id = t.grant_id " +
							"WHERE g.user_id = ?2)",
						"AND (revoked_at IS NULL OR revoked_at > ?1)",
						followsRevocation,
					},
					args: []any{test.at, test.id},
				},
				wantStatement{
					fragments: []string{
						// The agents: one already revoked keeps its time.
						"UPDATE agents SET revoked_at = ?1",
						"WHERE user_id = ?2",
						"AND revoked_at IS NULL",
						followsRevocation,
					},
					args: []any{test.at, test.id},
				},
			)
		})
	}
}

// TestRevokeUserGuardIsNotABareLiteral holds that no role is written into the
// SQL: it is the caller's, bound as an argument.
func TestRevokeUserGuardIsNotABareLiteral(t *testing.T) {
	t.Parallel()

	fake := newFake(revokeBatch(0, 0, revokedUserRow()))

	_, err := fake.store().RevokeUser(context.Background(), mustUserID(t, userID2), "customrole", now)
	checkErr(t, err, nil)

	for i, statement := range fake.calls[0] {
		if query := squash(statement.Query); strings.Contains(query, "admin") || strings.Contains(query, "customrole") {
			t.Errorf("statement %d writes a role into the SQL:\n%s", i, query)
		}
	}

	if args := fake.calls[0][0].Args; !slices.Contains(args, any("customrole")) {
		t.Errorf("role is not bound: args = %#v", args)
	}
}

// TestRevokeUserFailures holds how a failed or malformed batch is reported.
// Every constraint failure is a defect here, a conflict included: this write
// can violate no constraint a client could cause, so a conflict is the schema
// disagreeing with the code and comes back as the 500 "_rejected", and never as
// the bare ErrConflict the other operations hand to their feature.
func TestRevokeUserFailures(t *testing.T) {
	t.Parallel()

	for _, f := range infraFailures(3, store.CodeUserRevokeFailed, store.CodeUserRevokeRejected, usersDescription) {
		if f.conflict {
			f.conflict = false
			f.want = *defectOf(store.CodeUserRevokeRejected)
		}

		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			got, err := fake.store().RevokeUser(context.Background(), mustUserID(t, userID1), userAdminRole, now)

			checkFailure(t, err, f)

			if !reflect.DeepEqual(got, store.User{}) {
				t.Errorf("a failed revoke returned %#v", got)
			}

			if len(fake.calls) != 1 {
				t.Errorf("exec called %d times, want 1", len(fake.calls))
			}
		})
	}
}

// TestUserCodes pins the wire codes the operations report. Clients and
// dashboards match on them, so they change only deliberately.
func TestUserCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeUserListFailed, "user_list_failed"},
		{store.CodeUserListRejected, "user_list_rejected"},
		{store.CodeUserLookupFailed, "user_lookup_failed"},
		{store.CodeUserLookupRejected, "user_lookup_rejected"},
		{store.CodeUserRevokeFailed, "user_revoke_failed"},
		{store.CodeUserRevokeRejected, "user_revoke_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}
