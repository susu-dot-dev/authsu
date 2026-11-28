//nolint:goconst,prealloc // table-driven tests repeat case names and inputs, and append defect tables to their cases
package store_test

import (
	"context"
	"errors"
	"fmt"
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

// listUsers runs ListUsers for the first page of the given size.
func listUsers(t *testing.T, s *store.Store, limit string) (store.UserPage, error) {
	t.Helper()

	page, err := s.ListUsers(context.Background(), orgCursorOf(t), orgLimitOf(t, limit))
	if err != nil {
		return store.UserPage{}, fmt.Errorf("list users: %w", err)
	}

	return page, nil
}

// TestListUsersDecoding holds how the rows of a page become accounts, in the
// order the database returned them, and how the extra row that a page asks for
// becomes the cursor of the next one and is not itself returned.
func TestListUsersDecoding(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_050)

	active := store.User{
		ID: userID1, Role: userAdminRole, InvitationID: "inv-1", Profile: `{"name":"Ada"}`, RevokedAt: nil,
		CreatedAt: 1_700_000_000,
	}
	revoked := store.User{
		ID: userID2, Role: "member", InvitationID: "inv-1", Profile: `{"name":"Ada"}`, RevokedAt: &revokedAt,
		CreatedAt: 1_699_999_000,
	}

	tests := []struct {
		name  string
		limit string
		rows  [][]any
		want  store.UserPage
	}{
		{name: "no accounts is an empty page, not nil", limit: "2", rows: nil, want: store.UserPage{Users: []store.User{}}},
		{name: "an active account", limit: "2", rows: [][]any{activeUserRow()},
			want: store.UserPage{Users: []store.User{active}}},
		{name: "a revoked account", limit: "2", rows: [][]any{revokedUserRow()},
			want: store.UserPage{Users: []store.User{revoked}}},
		{name: "the order is the database's", limit: "2", rows: [][]any{revokedUserRow(), activeUserRow()},
			want: store.UserPage{Users: []store.User{revoked, active}}},
		{name: "one more than the limit has a next page, which is the last row kept", limit: "1",
			rows: [][]any{revokedUserRow(), activeUserRow()},
			want: store.UserPage{Users: []store.User{revoked}, Next: userID2}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, err := listUsers(t, fake.store(), test.limit)

			checkErr(t, err, nil)

			if got.Users == nil || !reflect.DeepEqual(got, test.want) {
				t.Errorf("page = %#v, want %#v", got, test.want)
			}
		})
	}
}

// TestListUsersDefects holds that a page with a row that is not an account is a
// defect as a whole: a broken row is not skipped, and nothing partial is
// returned. So is a page with more rows than the query asked for.
func TestListUsersDefects(t *testing.T) {
	t.Parallel()

	for _, defect := range userDefects() {
		t.Run(defect.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(activeUserRow(), defect.row))

			got, err := listUsers(t, fake.store(), "5")

			checkErr(t, err, defectOf(store.CodeUserListRejected))

			if got.Users != nil || got.Next != "" {
				t.Errorf("a defective page returned %#v", got)
			}
		})
	}

	t.Run("more rows than were asked for", func(t *testing.T) {
		t.Parallel()

		fake := newFake(returning(activeUserRow(), revokedUserRow(), activeUserRow()))

		got, err := listUsers(t, fake.store(), "1")

		checkErr(t, err, defectOf(store.CodeUserListRejected))

		if got.Users != nil || got.Next != "" {
			t.Errorf("a defective page returned %#v", got)
		}
	})
}

// TestListUsersStatement pins the page: every account, revoked ones included,
// newest first, below the cursor and one row more than the limit, and without
// the user handle.
func TestListUsersStatement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		limit  string
		cursor []string
		before string
		wanted int64
	}{
		{name: "the first page", limit: "2", before: "g", wanted: 3},
		{name: "after a cursor", limit: "1", cursor: []string{userID1}, before: userID1, wanted: 2},
		{name: "the default limit", limit: "", before: "g", wanted: input.DefaultPageLimit + 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			limit := []string{}
			if test.limit != "" {
				limit = []string{test.limit}
			}

			_, err := fake.store().ListUsers(
				context.Background(), orgCursorOf(t, test.cursor...), orgLimitOf(t, limit...))
			checkErr(t, err, nil)

			checkStatements(t, fake, wantStatement{
				fragments: []string{
					"SELECT " + userColumns + " FROM users WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
				},
				args: []any{test.before, test.wanted},
			})

			// No filter beyond the cursor: a revoked account is listed too.
			query := squash(fake.calls[0][0].Query)
			if strings.Contains(query, "revoked_at IS") || strings.Contains(query, "user_handle") {
				t.Errorf("list is filtered or selects the user handle:\n%s", query)
			}
		})
	}
}

// TestListUsersFailures holds how a failed or malformed batch is reported.
func TestListUsersFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeUserListFailed, store.CodeUserListRejected, usersDescription,
		func(s *store.Store) error { return lastErr(listUsers(t, s, "5")) })
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

// standingOf is the first statement's row of a revocation: the member's columns
// (the organization of the tests, administrator or not, revoked or not), then
// whether the account is a platform administrator, whether the caller
// administers its organization, and whether the caller may revoke it.
func standingOf(id string, revoked any, platform, administers, may int64) []any {
	return append(memberRowOf(id, 0, revoked), platform, administers, may)
}

// revokeBatch is the outcome of the five statements of a revocation: the standing
// of the account first, the secrets and agents statements, the account statement,
// which returned the given rows, and the caller's standing last, which is not read
// unless the standing found no account.
func revokeBatch(standing []any, rows ...[]any) outcome {
	results := map[int][][]any{3: rows}
	if standing != nil {
		results[0] = [][]any{standing}
	}

	return batchOf(5, results)
}

// revokeStandingKinds are the column kinds of a revocation's standing row.
func revokeStandingKinds() []string {
	return append(memberKinds(), "integer", "integer", "integer")
}

// TestRevokeUserOutcomes holds how the standing row and the row the account
// statement returned become the operation's result: a row returned is a
// revocation (the earlier time of one that was already revoked), and no row is
// why the standing says: no standing is no such account (or one the caller may
// not see), and otherwise the caller's refusal.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRevokeUserOutcomes(t *testing.T) {
	t.Parallel()

	justNow := now.Unix()
	earlier := int64(1_700_000_050)

	revoking := func(id, caller string) func(*store.Store) (store.User, error) {
		return func(s *store.Store) (store.User, error) {
			return s.RevokeUser(context.Background(), mustUserID(t, id), caller, userAdminRole, now)
		}
	}

	// The caller is another account.
	runOpCases(t, []opCase[store.User]{
		{name: "this call revoked an account",
			out:  revokeBatch(standingOf(userID2, nil, 0, 1, 1), userRowOf(userID2, "member", justNow, 1_699_999_000)),
			want: memberUser(&justNow)},
		{name: "this call revoked an administrator who is not the last",
			out: revokeBatch(standingOf(userID2, nil, 1, 1, 1), userRowOf(userID2, userAdminRole, justNow, 1_700_000_000)),
			want: store.User{ID: userID2, Role: userAdminRole, InvitationID: "inv-1", Profile: `{"name":"Ada"}`,
				RevokedAt: &justNow, CreatedAt: 1_700_000_000}},
		{name: "already revoked keeps the earlier time",
			out:  revokeBatch(standingOf(userID2, earlier, 0, 1, 1), revokedUserRow()),
			want: memberUser(&earlier)},
		{name: "no such account, or one the caller may not see", out: revokeBatch(nil), err: store.ErrNotFound},
		{name: "no such account, and the caller is not revoked", out: callerIs(0, revokeBatch(nil)),
			err: store.ErrNotFound},
		{name: "the caller may not see the account because they are revoked", out: callerIs(1, revokeBatch(nil)),
			err: store.ErrAccountRevoked},
		{name: "a revoked caller's standing is not read when the account was seen",
			out: callerIs(1, revokeBatch(standingOf(userID2, nil, 0, 0, 0))), err: store.ErrNotAdmin},
		{name: "a caller who does not administer the organization",
			out: revokeBatch(standingOf(userID2, nil, 0, 0, 0)), err: store.ErrNotAdmin},
		{name: "a member of the organization who does not administer it",
			out: revokeBatch(standingOf(userID2, earlier, 0, 0, 0)), err: store.ErrNotAdmin},
		{name: "an organization administrator and a platform administrator",
			out: revokeBatch(standingOf(userID2, nil, 1, 1, 0)), err: store.ErrPlatformAdminTarget},
		{name: "an organization administrator and a revoked platform administrator",
			out: revokeBatch(standingOf(userID2, earlier, 1, 1, 0)), err: store.ErrPlatformAdminTarget},
		{name: "the last active platform administrator",
			out: revokeBatch(standingOf(userID2, nil, 1, 1, 1)), err: store.ErrLastAdmin},
		{name: "nothing matched for a caller who may revoke an ordinary account",
			out: revokeBatch(standingOf(userID2, nil, 0, 1, 1)), defect: true},
		{name: "nothing matched for an organization administrator who may not, and not for a reason",
			out: revokeBatch(standingOf(userID2, nil, 0, 1, 0)), defect: true},
		{name: "two rows for one primary key", out: revokeBatch(standingOf(userID2, nil, 0, 1, 1),
			revokedUserRow(), revokedUserRow()), defect: true},
		{name: "a row returned without a standing", out: revokeBatch(nil, revokedUserRow()), err: store.ErrNotFound},
	}, store.CodeUserRevokeRejected, revoking(userID2, userID1))

	// The caller is the account: refused as themself, when they may not.
	runOpCases(t, []opCase[store.User]{
		{name: "an organization administrator revoking themself",
			out: revokeBatch(standingOf(userID1, nil, 0, 1, 0)), err: store.ErrSelfRevoke},
		{name: "a platform administrator revoking themself, another remaining",
			out: revokeBatch(standingOf(userID1, nil, 1, 1, 1), userRowOf(userID1, userAdminRole, justNow, 1)),
			want: store.User{ID: userID1, Role: userAdminRole, InvitationID: "inv-1", Profile: `{"name":"Ada"}`,
				RevokedAt: &justNow, CreatedAt: 1},
		},
		{name: "the sole platform administrator revoking themself",
			out: revokeBatch(standingOf(userID1, nil, 1, 1, 1)), err: store.ErrLastAdmin},
	}, store.CodeUserRevokeRejected, revoking(userID1, userID1))

	cases := []opCase[store.User]{}

	for name, rows := range defectResults(standingOf(userID2, nil, 0, 1, 1), revokeStandingKinds()...) {
		cases = append(cases, opCase[store.User]{name: "a defective standing: " + name,
			out: batchOf(5, map[int][][]any{0: rows, 3: {revokedUserRow()}}), defect: true})
	}

	for _, defect := range userDefects() {
		cases = append(cases, opCase[store.User]{name: "a defective account row: " + defect.name,
			out: revokeBatch(standingOf(userID2, nil, 0, 1, 1), defect.row), defect: true})
	}

	cases = append(cases, callerDefectCases[store.User](5)...)

	runOpCases(t, cases, store.CodeUserRevokeRejected, revoking(userID2, userID1))
}

// The statements of a revocation, as fragments of their squashed text. The caller
// may revoke the account when they administer its organization (or are a platform
// administrator) and the account is neither a platform administrator nor the
// caller, unless the caller is a platform administrator themself; the last active
// platform administrator is never revoked. Every statement of the batch carries
// the same conditions, so a refusal changes nothing.
//
//nolint:gochecknoglobals // fixed lists shared by the table tests
var (
	revokeMayFragment = "AND ((tu.role <> ?3 AND tu.id <> ?2) OR EXISTS (SELECT 1 FROM users pa " +
		"WHERE pa.id = ?2 AND pa.revoked_at IS NULL AND pa.role = ?3))"
	revokeRemainsFragment = "AND (tu.revoked_at IS NOT NULL OR tu.role <> ?3 OR EXISTS (SELECT 1 FROM users other " +
		"WHERE other.id <> tu.id AND other.role = ?3 AND other.revoked_at IS NULL))"
)

// revokeAllowedFragments is every fragment a statement carrying revokeAllowed has.
func revokeAllowedFragments() []string {
	return append(slices.Clone(targetAdministersFragments), revokeMayFragment, revokeRemainsFragment)
}

// TestRevokeUserStatements pins the batch: the five statements in order, the
// conditions that decide what each does, and the exact arguments in placeholder
// order. The role is bound, and not written in the SQL.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRevokeUserStatements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		id     string
		caller string
		role   string
		at     int64
	}{
		{name: "an admin role and an account", id: userID2, caller: userID1, role: userAdminRole, at: now.Unix()},
		{name: "another role, account and caller", id: userID1, caller: callerID, role: "owner", at: 1_700_000_999},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(revokeBatch(standingOf(test.id, nil, 0, 1, 1), userRowOf(test.id, "member", test.at, 1)))

			_, err := fake.store().RevokeUser(
				context.Background(), mustUserID(t, test.id), test.caller, test.role, time.Unix(test.at, 0))
			checkErr(t, err, nil)

			exists := "EXISTS (SELECT 1 FROM users tu WHERE tu.id = ?1 AND "

			checkNumberedStatements(t, fake,
				wantStatement{
					fragments: append([]string{
						// The standing: the account as the caller may see it, and
						// what the caller may do to it, as the write sees it.
						"FROM users tu WHERE tu.id = ?1 AND",
						"tu.org_id AS org_id",
						"tu.role = ?3 AS platform_admin",
						"AS administers", "AS may_revoke",
					}, append(slices.Clone(targetSeesFragments), revokeMayFragment)...),
					args: []any{test.id, test.caller, test.role},
				},
				wantStatement{
					fragments: append([]string{
						// The user's sessions, keys and OAuth grants with their access
						// tokens, those of its agents included: a due time is kept.
						"UPDATE secrets SET revoked_at = ?4",
						"WHERE id IN (SELECT id FROM sessions WHERE user_id = ?1 UNION ALL SELECT id FROM api_keys " +
							"WHERE user_id = ?1 UNION ALL SELECT id FROM oauth_grants WHERE user_id = ?1 " +
							"UNION ALL SELECT t.id FROM oauth_access_tokens t JOIN oauth_grants g ON g.id = t.grant_id " +
							"WHERE g.user_id = ?1)",
						"AND (revoked_at IS NULL OR revoked_at > ?4)",
						exists,
					}, revokeAllowedFragments()...),
					args: []any{test.id, test.caller, test.role, test.at},
				},
				wantStatement{
					fragments: append([]string{
						// The agents: one already revoked keeps its time.
						"UPDATE agents SET revoked_at = ?4",
						"WHERE user_id = ?1 AND revoked_at IS NULL",
						exists,
					}, revokeAllowedFragments()...),
					args: []any{test.id, test.caller, test.role, test.at},
				},
				wantStatement{
					fragments: append([]string{
						// The account: keeps an earlier time, matches by id, and
						// returns the row as it was left.
						"UPDATE users AS tu SET revoked_at = COALESCE(tu.revoked_at, ?4) WHERE tu.id = ?1 AND",
						"RETURNING " + userColumns,
					}, revokeAllowedFragments()...),
					args: []any{test.id, test.caller, test.role, test.at},
				},
				wantStatement{
					fragments: callerStandingStatement().fragments,
					args:      []any{test.caller},
				},
			)
		})
	}
}

// TestRevokeUserGuardIsNotABareLiteral holds that no role is written into the
// SQL: it is the caller's, bound as an argument.
func TestRevokeUserGuardIsNotABareLiteral(t *testing.T) {
	t.Parallel()

	fake := newFake(revokeBatch(standingOf(userID2, nil, 0, 1, 1), revokedUserRow()))

	_, err := fake.store().RevokeUser(context.Background(), mustUserID(t, userID2), userID1, "customrole", now)
	checkErr(t, err, nil)

	for i, statement := range fake.calls[0] {
		query := squash(statement.Query)

		if strings.Contains(query, "'admin'") || strings.Contains(query, "'customrole'") {
			t.Errorf("statement %d writes a role into the SQL:\n%s", i, query)
		}

		// Every statement that judges the caller's authority binds the role; the
		// caller's standing, which does not, has the caller's id alone.
		if strings.Contains(query, "?3") != slices.Contains(statement.Args, any("customrole")) {
			t.Errorf("statement %d binds the role only if it uses it: args = %#v", i, statement.Args)
		}
	}
}

// TestRevokeUserFailures holds how a failed or malformed batch is reported.
// Every constraint failure is a defect here, a conflict included: this write
// can violate no constraint a client could cause, so a conflict is the schema
// disagreeing with the code and comes back as the 500 "_rejected", and never as
// the bare ErrConflict the other operations hand to their feature.
func TestRevokeUserFailures(t *testing.T) {
	t.Parallel()

	runDefectFailures(t, 5, store.CodeUserRevokeFailed, store.CodeUserRevokeRejected, usersDescription,
		func(s *store.Store) error {
			return lastErr(s.RevokeUser(context.Background(), mustUserID(t, userID1), userID1, userAdminRole, now))
		})
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
