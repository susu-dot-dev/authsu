//nolint:goconst,prealloc // table-driven tests repeat case names and inputs, and append defect tables to their cases
package store_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file tests the organization operations. As for every operation, the SQL
// itself runs only in the end-to-end tests: here the statements are pinned
// (the fragments that carry each guard, and the arguments in placeholder order),
// and so are the decoding of every returned row and what each outcome becomes.

const (
	orgsDescription = "organizations are temporarily unavailable"

	// The ids the organization tests name. The platform administrator's role is
	// bound as an argument, and these are its test spelling.
	orgTestID = "01890000-0000-7000-8000-0000000000b1"
	callerID  = "01890000-0000-7000-8000-000000000001"
	targetID  = "01890000-0000-7000-8000-000000000002"
	adminRole = "admin"
)

func orgNameOf(tb testing.TB, raw string) input.OrgName {
	tb.Helper()

	name, err := input.ParseOrgName(raw)
	if err != nil {
		tb.Fatalf("parse org name %q: %v", raw, err)
	}

	return name
}

func orgCursorOf(tb testing.TB, values ...string) input.Cursor {
	tb.Helper()

	cursor, err := input.ParseCursor(values)
	if err != nil {
		tb.Fatalf("parse cursor %q: %v", values, err)
	}

	return cursor
}

func orgLimitOf(tb testing.TB, values ...string) input.PageLimit {
	tb.Helper()

	limit, err := input.ParsePageLimit(values)
	if err != nil {
		tb.Fatalf("parse limit %q: %v", values, err)
	}

	return limit
}

// batchOf is the outcome of a batch of n statements, the ones named in rows
// returning those rows and the others none.
func batchOf(n int, rows map[int][][]any) outcome {
	results := make([]store.Result, n)
	for at, returned := range rows {
		results[at] = store.Result{Changes: 0, Rows: returned}
	}

	return outcome{results: results, err: nil}
}

// callerIs sets the last statement of a batch, the caller's standing
// (callerStandingQuery), to a row of one column: whether the caller is revoked.
func callerIs(revoked int64, out outcome) outcome {
	results := slices.Clone(out.results)
	results[len(results)-1] = store.Result{Changes: 0, Rows: [][]any{row(revoked)}}

	return outcome{results: results, err: out.err}
}

// callerDefectCases are the ways the caller's standing, the last of a batch of
// n statements, can fail to be one row of one flag, when no write said why:
// every one is a defect and never a guess at which refusal it was.
func callerDefectCases[T any](n int) []opCase[T] {
	return []opCase[T]{
		{name: "the caller's standing has a column too many",
			out: batchOf(n, map[int][][]any{n - 1: {row(int64(1), int64(1))}}), defect: true},
		{name: "the caller's standing is not a flag", out: callerIs(2, batchOf(n, nil)), defect: true},
		{name: "the caller's standing is text", out: batchOf(n, map[int][][]any{n - 1: {row("1")}}), defect: true},
		{name: "two caller standing rows", out: batchOf(n, map[int][][]any{n - 1: {row(int64(1)), row(int64(1))}}),
			defect: true},
	}
}

// callerStandingStatement is the wanted last statement of a write that can be
// refused: the caller's standing, with the caller's id as its one argument.
func callerStandingStatement() wantStatement {
	return wantStatement{
		fragments: []string{"SELECT u.revoked_at IS NOT NULL AS revoked FROM users u WHERE u.id = ?1"},
		args:      []any{callerID},
	}
}

// orgRowOf is the row of an organization: id, kind, name, created_by,
// expires_at, created_at.
func orgRowOf(id, kind string, expires any) []any {
	return row(id, kind, "Acme", callerID, expires, int64(1_700_000_000))
}

// standardRow and sandboxRow are a standard organization and a sandbox that
// expires at the given time.
func standardRow() []any                   { return orgRowOf(orgTestID, store.OrgKindStandard, nil) }
func sandboxRow(at int64) []any            { return orgRowOf(orgTestID, store.OrgKindSandbox, at) }
func standing(of []any, admin int64) []any { return append(slices.Clip(of), admin) }

// orgKinds are the column kinds of an organization row, for defectResults.
func orgKinds() []string {
	return []string{"text", "text", "text", "text", "optInteger", "integer"}
}

// opCase is one outcome of an operation: what the fake database answers, and
// the value or the sentinel the operation must return. A defect is the
// operation's "_rejected" 500, with no value.
type opCase[T any] struct {
	name   string
	out    outcome
	want   T
	err    error
	defect bool
}

// runOpCases runs call against each case's outcome and checks what comes back.
func runOpCases[T any](t *testing.T, cases []opCase[T], rejected string, call func(*store.Store) (T, error)) {
	t.Helper()

	var zero T

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(test.out)

			got, err := call(fake.store())

			switch {
			case test.defect:
				checkErr(t, err, defectOf(rejected))

				if !reflect.DeepEqual(got, zero) {
					t.Errorf("a defect returned %#v", got)
				}

				return
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
				t.Errorf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

// rowDefectCases returns, for each way row can fail to be a valid row of kinds,
// the case that puts it at statement at of a batch of n and expects a defect.
func rowDefectCases[T any](n, at int, valid []any, kinds ...string) []opCase[T] {
	var cases []opCase[T]

	for name, rows := range defectResults(valid, kinds...) {
		cases = append(cases, opCase[T]{
			name: "a defective row: " + name, out: batchOf(n, map[int][][]any{at: rows}), defect: true,
		})
	}

	return cases
}

// orgWriteStatements is the length of the batch of every write that can be
// refused: the write, why it was refused, and the caller's standing.
const orgWriteStatements = 3

// runOpFailures holds how a failed or malformed batch of an organization or member
// write is reported. No operation here writes a constraint a client could cause,
// so a conflict is the schema disagreeing with the code and is the "_rejected" 500.
func runOpFailures(t *testing.T, failed, rejected string, call func(*store.Store) error) {
	t.Helper()

	runDefectFailures(t, orgWriteStatements, failed, rejected, orgsDescription, call)
}

// longAt is an instant well after now, as a sandbox's expiry in a row.
const longAt = int64(1_900_000_456)

// soonAt is when a sandbox created at now expires.
func soonAt() time.Time { return now.Add(7 * 24 * time.Hour) }

// createCall is CreateSandbox with the largest values it can carry.
func createCall(t *testing.T) func(*store.Store) (store.Org, error) {
	t.Helper()

	return func(s *store.Store) (store.Org, error) {
		return s.CreateSandbox(context.Background(), store.NewSandbox{
			ID: orgTestID, Name: orgNameOf(t, "Acme"), Creator: callerID, ExpiresAt: soonAt(), Limit: 5, CreatedAt: now,
		})
	}
}

// TestCreateSandboxOutcomes: the row the insert returned is the sandbox, and
// otherwise the creator's standing says why: gone or revoked first, and what is
// left is the limit.
func TestCreateSandboxOutcomes(t *testing.T) {
	t.Parallel()

	expires := longAt
	stored := store.Org{
		ID: orgTestID, Kind: store.OrgKindSandbox, Name: "Acme", CreatedBy: callerID, ExpiresAt: &expires,
		CreatedAt: 1_700_000_000,
	}

	refused := func(revoked int64) outcome { return batchOf(3, map[int][][]any{2: {row(revoked)}}) }

	cases := []opCase[store.Org]{
		{name: "a sandbox was created", out: batchOf(3, map[int][][]any{0: {sandboxRow(longAt)}}), want: stored},
		{name: "the standing is not read when it was", out: batchOf(3, map[int][][]any{
			0: {sandboxRow(longAt)}, 2: {row(int64(1))},
		}), want: stored},
		{name: "the creator is gone", out: batchOf(3, nil), err: store.ErrAccountRevoked},
		{name: "the creator is revoked", out: refused(1), err: store.ErrAccountRevoked},
		{name: "the creator is at the limit", out: refused(0), err: store.ErrSandboxLimit},
	}

	cases = append(cases, rowDefectCases[store.Org](3, 0, sandboxRow(longAt), orgKinds()...)...)
	cases = append(cases,
		opCase[store.Org]{name: "two rows for one id", out: batchOf(3, map[int][][]any{
			0: {sandboxRow(longAt), sandboxRow(longAt)},
		}), defect: true},
		opCase[store.Org]{name: "the standing has a column too many", out: batchOf(3, map[int][][]any{
			2: {row(int64(0), int64(0))},
		}), defect: true},
		opCase[store.Org]{name: "the standing is not a flag", out: refused(2), defect: true},
		opCase[store.Org]{name: "two standing rows", out: batchOf(3, map[int][][]any{
			2: {row(int64(0)), row(int64(0))},
		}), defect: true},
	)

	runOpCases(t, cases, store.CodeOrgCreateRejected, createCall(t))
}

// TestCreateSandboxStatements pins the batch: the three statements in order, the
// guards that decide what each does, and the exact arguments in placeholder
// order. The sandbox kind is bound, and so is the sandbox's expiry, as the
// schema's CHECK requires.
func TestCreateSandboxStatements(t *testing.T) {
	t.Parallel()

	fake := newFake(batchOf(3, map[int][][]any{0: {sandboxRow(longAt)}}))

	_, err := createCall(t)(fake.store())
	checkErr(t, err, nil)

	checkNumberedStatements(t, fake,
		wantStatement{
			fragments: []string{
				"INSERT INTO orgs (id, kind, name, created_by, expires_at, created_at)",
				// The creator is read from users, unrevoked, and nothing about
				// the organization it belongs to is asked: it keeps it.
				"FROM users u WHERE u.id = ?7 AND u.revoked_at IS NULL",
				// The limit is counted in the write: the sandboxes that have not
				// expired, and no other kind.
				"(SELECT count(*) FROM orgs g WHERE g.created_by = u.id AND g.kind = ?5 AND g.expires_at > ?4) < ?6",
				"RETURNING id, kind, name, created_by, expires_at, created_at",
			},
			args: []any{
				orgTestID, "Acme", soonAt().Unix(), now.Unix(), store.OrgKindSandbox, int64(5), callerID,
			},
		},
		wantStatement{
			fragments: []string{
				"INSERT INTO org_admins (org_id, user_id, created_at)",
				"SELECT o.id, o.created_by, ?2 FROM orgs o WHERE o.id = ?1",
			},
			args: []any{orgTestID, now.Unix()},
		},
		wantStatement{
			fragments: []string{"SELECT u.revoked_at IS NOT NULL AS revoked FROM users u WHERE u.id = ?1"},
			args:      []any{callerID},
		},
	)
}

// TestCreateSandboxJudgesTheLimitAtTheRequestSecond: the count of the sandboxes a
// user holds takes those that expire after the create's whole second, so one
// whose expiry is this very second is not counted, and the new sandbox's own
// expiry is whole seconds too. A fraction of a second in the clock changes
// neither. (The comparison itself runs in the end-to-end tests; the operator is
// pinned in TestCreateSandboxStatements.)
func TestCreateSandboxJudgesTheLimitAtTheRequestSecond(t *testing.T) {
	t.Parallel()

	for _, fraction := range []time.Duration{0, time.Millisecond, 999 * time.Millisecond} {
		t.Run(fraction.String(), func(t *testing.T) {
			t.Parallel()

			at := now.Add(fraction)
			fake := newFake(batchOf(3, map[int][][]any{0: {sandboxRow(longAt)}}))

			_, err := fake.store().CreateSandbox(context.Background(), store.NewSandbox{
				ID: orgTestID, Name: orgNameOf(t, "Acme"), Creator: callerID,
				ExpiresAt: at.Add(7 * 24 * time.Hour), Limit: 25, CreatedAt: at,
			})
			checkErr(t, err, nil)

			insert := fake.calls[0][0]
			if !strings.Contains(squash(insert.Query), "g.expires_at > ?4") {
				t.Errorf("the count does not compare with ?4 strictly:\n%s", insert.Query)
			}

			if insert.Args[2] != now.Add(7*24*time.Hour).Unix() || insert.Args[3] != now.Unix() {
				t.Errorf("expiry and creation time = %v and %v, want whole seconds %d and %d",
					insert.Args[2], insert.Args[3], now.Add(7*24*time.Hour).Unix(), now.Unix())
			}
		})
	}
}

// TestCreateSandboxFailures holds how a failed or malformed batch is reported.
func TestCreateSandboxFailures(t *testing.T) {
	t.Parallel()

	runOpFailures(t, store.CodeOrgCreateFailed, store.CodeOrgCreateRejected,
		func(s *store.Store) error { return lastErr(createCall(t)(s)) })
}

// TestOrgActive: an organization works unless it is a sandbox whose expiry has
// come, and an expiry of this very second is over.
func TestOrgActive(t *testing.T) {
	t.Parallel()

	at := now.Unix()
	before, after := at-1, at+1

	tests := []struct {
		name string
		org  store.Org
		want bool
	}{
		{name: "a standard organization", org: store.Org{}, want: true},
		{name: "a sandbox before its expiry", org: store.Org{ExpiresAt: &after}, want: true},
		{name: "a sandbox at its expiry", org: store.Org{ExpiresAt: &at}, want: false},
		{name: "a sandbox past its expiry", org: store.Org{ExpiresAt: &before}, want: false},
	}

	for _, test := range tests {
		if got := test.org.Active(now); got != test.want {
			t.Errorf("%s: Active = %t, want %t", test.name, got, test.want)
		}
	}
}

// TestGetOrg: the organization the caller may see, or not found.
func TestGetOrg(t *testing.T) {
	t.Parallel()

	call := func(s *store.Store) (store.Org, error) {
		return s.GetOrg(context.Background(), mustUserID(t, orgTestID), callerID, adminRole)
	}

	expires := longAt

	cases := []opCase[store.Org]{
		{name: "an organization", out: returning(standardRow()), want: store.Org{
			ID: orgTestID, Kind: store.OrgKindStandard, Name: "Acme", CreatedBy: callerID, CreatedAt: 1_700_000_000,
		}},
		{name: "a sandbox", out: returning(sandboxRow(longAt)), want: store.Org{
			ID: orgTestID, Kind: store.OrgKindSandbox, Name: "Acme", CreatedBy: callerID, ExpiresAt: &expires,
			CreatedAt: 1_700_000_000,
		}},
		{name: "none the caller may see", out: returning(), err: store.ErrNotFound},
	}

	for name, rows := range defectResults(standardRow(), orgKinds()...) {
		cases = append(cases, opCase[store.Org]{name: "a defective row: " + name, out: returning(rows...), defect: true})
	}

	runOpCases(t, cases, store.CodeOrgLookupRejected, call)

	t.Run("the statement", func(t *testing.T) {
		t.Parallel()

		fake := newFake(returning(standardRow()))

		_, err := call(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake, wantStatement{
			fragments: append([]string{"FROM orgs o WHERE o.id = ?1 AND"}, seesFragments...),
			args:      []any{orgTestID, callerID, adminRole},
		})
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runFailures(t, 1, store.CodeOrgLookupFailed, store.CodeOrgLookupRejected, orgsDescription,
			func(s *store.Store) error { return lastErr(call(s)) })
	})
}

// seesOf are the conditions that make the organization a SQL expression names
// visible to the caller: the account is unrevoked, and is a platform
// administrator, belongs to the organization, or administers it. Every statement
// that asks it, for whatever the organization is called there (?1, a user's
// organization), has this text with its own expression for org, and
// it is written out here on purpose: changing who may see an organization is a
// change to security behaviour, and must change these lines with it.
func seesOf(org string) []string {
	return []string{
		"EXISTS (SELECT 1 FROM (SELECT " + org + " AS org_id) subject, users actor " +
			"WHERE actor.id = ?2 AND actor.revoked_at IS NULL",
		"AND (actor.role = ?3 OR actor.org_id = subject.org_id OR EXISTS (SELECT 1 FROM org_admins oa " +
			"WHERE oa.org_id = subject.org_id AND oa.user_id = actor.id)))",
	}
}

// administersOf are the conditions of an administrator of the organization a SQL
// expression names: the platform role, or a row of org_admins, and never mere
// membership. See seesOf.
func administersOf(org string) []string {
	return []string{
		"EXISTS (SELECT 1 FROM (SELECT " + org + " AS org_id) subject, users actor " +
			"WHERE actor.id = ?2 AND actor.revoked_at IS NULL",
		"AND (actor.role = ?3 OR EXISTS (SELECT 1 FROM org_admins oa " +
			"WHERE oa.org_id = subject.org_id AND oa.user_id = actor.id)))",
	}
}

// seesFragments and administersFragments are those of the organization with the
// id ?1.
//
//nolint:gochecknoglobals // fixed lists shared by the table tests
var (
	seesFragments        = seesOf("?1")
	administersFragments = administersOf("?1")
)

// TestListOrgs: one page of keyset paging, with the page window from the cursor
// and the limit.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestListOrgs(t *testing.T) {
	t.Parallel()

	listing := func(size string, cursor ...string) func(*store.Store) (store.OrgPage, error) {
		return func(s *store.Store) (store.OrgPage, error) {
			return s.ListOrgs(context.Background(), callerID, adminRole, orgCursorOf(t, cursor...), orgLimitOf(t, size))
		}
	}

	second := orgRowOf("01890000-0000-7000-8000-0000000000b0", store.OrgKindStandard, nil)
	third := orgRowOf("01890000-0000-7000-8000-0000000000af", store.OrgKindStandard, nil)

	wantOrg := func(id string) store.Org {
		return store.Org{ID: id, Kind: store.OrgKindStandard, Name: "Acme", CreatedBy: callerID, CreatedAt: 1_700_000_000}
	}

	cases := []struct {
		name string
		rows [][]any
		want store.OrgPage
	}{
		{name: "no organization is an empty page", rows: nil, want: store.OrgPage{Orgs: []store.Org{}}},
		{name: "fewer than the limit is the last page", rows: [][]any{standardRow()},
			want: store.OrgPage{Orgs: []store.Org{wantOrg(orgTestID)}}},
		{name: "exactly the limit is the last page", rows: [][]any{standardRow(), second},
			want: store.OrgPage{Orgs: []store.Org{wantOrg(orgTestID), wantOrg("01890000-0000-7000-8000-0000000000b0")}}},
		{name: "one more than the limit has a next page", rows: [][]any{standardRow(), second, third},
			want: store.OrgPage{
				Orgs: []store.Org{wantOrg(orgTestID), wantOrg("01890000-0000-7000-8000-0000000000b0")},
				Next: "01890000-0000-7000-8000-0000000000b0",
			}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, err := listing("2")(fake.store())
			checkErr(t, err, nil)

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("page = %#v, want %#v", got, test.want)
			}
		})
	}

	t.Run("more rows than were asked for is a defect", func(t *testing.T) {
		t.Parallel()

		fake := newFake(returning(standardRow(), second, third, standardRow()))

		got, err := listing("2")(fake.store())

		checkErr(t, err, defectOf(store.CodeOrgListRejected))

		if !reflect.DeepEqual(got, store.OrgPage{}) {
			t.Errorf("a defect returned %#v", got)
		}
	})

	for name, rows := range defectResults(standardRow(), orgKinds()...) {
		if name == "two rows" {
			continue // two rows are a page of one and a next, not a defect
		}

		t.Run("a defective row: "+name, func(t *testing.T) {
			t.Parallel()

			_, err := listing("2")(newFake(returning(rows...)).store())

			checkErr(t, err, defectOf(store.CodeOrgListRejected))
		})
	}

	statements := []struct {
		name   string
		call   func(*store.Store) (store.OrgPage, error)
		before string
		wanted int64
	}{
		{name: "the first page", call: listing("25"), before: "g", wanted: 26},
		{name: "after a cursor", call: listing("1", orgTestID), before: orgTestID, wanted: 2},
		{name: "a zero limit is read as one", call: func(s *store.Store) (store.OrgPage, error) {
			return s.ListOrgs(context.Background(), callerID, adminRole, input.Cursor{}, input.PageLimit{})
		}, before: "g", wanted: 2},
	}

	for _, test := range statements {
		t.Run("statement: "+test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, err := test.call(fake.store())
			checkErr(t, err, nil)

			checkNumberedStatements(t, fake, wantStatement{
				fragments: []string{
					// Which organizations are looked at comes from the caller's own
					// standing, one source each, and not from testing the caller
					// against every organization there is: every organization only
					// for an unrevoked platform administrator, the ones the caller
					// administers (read in order from org_admins_user_id), and the
					// one they belong to. Each source starts after the cursor.
					"FROM orgs o WHERE o.id IN (",
					"SELECT id FROM (SELECT g.id AS id FROM orgs g WHERE g.id < ?2 AND EXISTS (SELECT 1 FROM users a " +
						"WHERE a.id = ?1 AND a.revoked_at IS NULL AND a.role = ?4) ORDER BY g.id DESC LIMIT ?3)",
					"UNION SELECT id FROM (SELECT oa.org_id AS id FROM org_admins oa WHERE oa.user_id = ?1 " +
						"AND oa.org_id < ?2 AND EXISTS (SELECT 1 FROM users a WHERE a.id = ?1 AND a.revoked_at IS NULL) " +
						"ORDER BY oa.org_id DESC LIMIT ?3)",
					"UNION SELECT a.org_id FROM users a WHERE a.id = ?1 AND a.revoked_at IS NULL AND a.org_id < ?2)",
					"ORDER BY o.id DESC LIMIT ?3",
				},
				args: []any{callerID, test.before, test.wanted, adminRole},
			})
		})
	}

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runFailures(t, 1, store.CodeOrgListFailed, store.CodeOrgListRejected, orgsDescription,
			func(s *store.Store) error { return lastErr(listing("2")(s)) })
	})
}

// TestRenameOrg: the row the update returned is the renamed organization, and
// otherwise the standing statement of the same batch says why.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRenameOrg(t *testing.T) {
	t.Parallel()

	call := func(s *store.Store) (store.Org, error) {
		return s.RenameOrg(context.Background(), mustUserID(t, orgTestID), orgNameOf(t, "New"), callerID, adminRole, now)
	}

	expired := now.Unix() - 1
	live := now.Unix() + 1

	renamed := store.Org{
		ID: orgTestID, Kind: store.OrgKindStandard, Name: "Acme", CreatedBy: callerID, CreatedAt: 1_700_000_000,
	}

	refused := func(of []any, admin int64) outcome { return batchOf(3, map[int][][]any{1: {standing(of, admin)}}) }

	cases := []opCase[store.Org]{
		{name: "renamed", out: batchOf(3, map[int][][]any{0: {standardRow()}}), want: renamed},
		{name: "renamed: the caller's standing is not read", out: callerIs(1, batchOf(3, map[int][][]any{
			0: {standardRow()},
		})), want: renamed},
		{name: "the caller may not see it", out: batchOf(3, nil), err: store.ErrNotFound},
		{name: "the caller may not see it, and is not revoked", out: callerIs(0, batchOf(3, nil)), err: store.ErrNotFound},
		{name: "the caller may not see it, because they are revoked", out: callerIs(1, batchOf(3, nil)),
			err: store.ErrAccountRevoked},
		{name: "the caller sees it and does not administer it", out: refused(standardRow(), 0), err: store.ErrNotAdmin},
		{name: "the sandbox has expired", out: refused(sandboxRow(expired), 1), err: store.ErrExpired},
		{name: "the sandbox expires this very second", out: refused(sandboxRow(now.Unix()), 1), err: store.ErrExpired},
		{name: "an active organization the write did not rename is a defect",
			out: refused(standardRow(), 1), defect: true},
		{name: "an active sandbox the write did not rename is a defect", out: refused(sandboxRow(live), 1), defect: true},
		{name: "the standing is not a flag", out: refused(standardRow(), 2), defect: true},
	}

	cases = append(cases, callerDefectCases[store.Org](3)...)
	cases = append(cases, rowDefectCases[store.Org](3, 0, standardRow(), orgKinds()...)...)
	cases = append(cases, rowDefectCases[store.Org](3, 1, standing(standardRow(), 1), append(orgKinds(), "integer")...)...)

	runOpCases(t, cases, store.CodeOrgUpdateRejected, call)

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(batchOf(3, map[int][][]any{0: {standardRow()}}))

		_, err := call(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: append([]string{
					"UPDATE orgs SET name = ?4 WHERE id = ?1",
					// An expired sandbox is final.
					"AND (expires_at IS NULL OR expires_at > ?5) AND",
					"RETURNING id, kind, name, created_by, expires_at, created_at",
				}, administersFragments...),
				args: []any{orgTestID, callerID, adminRole, "New", now.Unix()},
			},
			wantStatement{
				fragments: append([]string{
					"o.created_at AS created_at, " +
						"EXISTS (SELECT 1 FROM (SELECT ?1 AS org_id) subject, users actor",
					"AS administers FROM orgs o WHERE o.id = ?1 AND",
				}, seesFragments...),
				args: []any{orgTestID, callerID, adminRole},
			},
			callerStandingStatement(),
		)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runOpFailures(t, store.CodeOrgUpdateFailed, store.CodeOrgUpdateRejected,
			func(s *store.Store) error { return lastErr(call(s)) })
	})
}

// TestDeleteSandbox: a returned row from the delete is the deleted sandbox, and
// otherwise the standing statement says why nothing was deleted.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestDeleteSandbox(t *testing.T) {
	t.Parallel()

	call := func(s *store.Store) (store.Org, error) {
		return s.DeleteSandbox(context.Background(), mustUserID(t, orgTestID), callerID, adminRole)
	}

	expires := longAt

	refused := func(of []any, admin int64) outcome { return batchOf(3, map[int][][]any{1: {standing(of, admin)}}) }

	cases := []opCase[store.Org]{
		{name: "a sandbox was deleted", out: batchOf(3, map[int][][]any{0: {sandboxRow(longAt)}}),
			want: store.Org{
				ID: orgTestID, Kind: store.OrgKindSandbox, Name: "Acme", CreatedBy: callerID, ExpiresAt: &expires,
				CreatedAt: 1_700_000_000,
			}},
		{name: "the caller may not see it", out: batchOf(3, nil), err: store.ErrNotFound},
		{name: "the caller may not see it, and is not revoked", out: callerIs(0, batchOf(3, nil)), err: store.ErrNotFound},
		{name: "the caller may not see it, because they are revoked", out: callerIs(1, batchOf(3, nil)),
			err: store.ErrAccountRevoked},
		{name: "a revoked caller's standing is not read when the write said why", out: callerIs(1, refused(standardRow(), 0)),
			err: store.ErrNotAdmin},
		{name: "the caller sees a sandbox and does not administer it", out: refused(sandboxRow(longAt), 0),
			err: store.ErrNotAdmin},
		{name: "the caller sees a standard organization and does not administer it", out: refused(standardRow(), 0),
			err: store.ErrNotAdmin},
		{name: "the caller administers a standard organization", out: refused(standardRow(), 1),
			err: store.ErrNotSandbox},
		{name: "a sandbox the caller administers that nothing matched is a defect",
			out: refused(sandboxRow(longAt), 1), defect: true},
		{name: "an expired sandbox the caller administers that nothing matched is a defect",
			out: refused(sandboxRow(now.Unix()-1), 1), defect: true},
		{name: "the standing is not a flag", out: refused(standardRow(), 2), defect: true},
	}

	cases = append(cases, callerDefectCases[store.Org](3)...)
	cases = append(cases, rowDefectCases[store.Org](3, 0, sandboxRow(longAt), orgKinds()...)...)
	cases = append(cases, rowDefectCases[store.Org](3, 1, standing(standardRow(), 1),
		append(orgKinds(), "integer")...)...)

	runOpCases(t, cases, store.CodeOrgDeleteRejected, call)

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(batchOf(3, map[int][][]any{0: {sandboxRow(longAt)}}))

		_, err := call(fake.store())
		checkErr(t, err, nil)

		// The delete names the sandbox kind and no expiry: an expired sandbox is
		// deleted too, and a standard organization never is.
		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: append([]string{
					"DELETE FROM orgs WHERE id = ?1 AND kind = ?4 AND",
					"RETURNING id, kind, name, created_by, expires_at, created_at",
				}, administersFragments...),
				args: []any{orgTestID, callerID, adminRole, store.OrgKindSandbox},
			},
			wantStatement{
				fragments: []string{"AS administers FROM orgs o WHERE o.id = ?1 AND"},
				args:      []any{orgTestID, callerID, adminRole},
			},
			callerStandingStatement(),
		)

		if query := squash(fake.calls[0][0].Query); strings.Contains(query, "expires_at >") {
			t.Errorf("the delete is conditioned on the expiry: %q", query)
		}
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runOpFailures(t, store.CodeOrgDeleteFailed, store.CodeOrgDeleteRejected,
			func(s *store.Store) error { return lastErr(call(s)) })
	})
}

// TestOrgCodes pins the wire codes the operations report.
func TestOrgCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeOrgCreateFailed, "org_create_failed"},
		{store.CodeOrgCreateRejected, "org_create_rejected"},
		{store.CodeOrgListFailed, "org_list_failed"},
		{store.CodeOrgListRejected, "org_list_rejected"},
		{store.CodeOrgLookupFailed, "org_lookup_failed"},
		{store.CodeOrgLookupRejected, "org_lookup_rejected"},
		{store.CodeOrgUpdateFailed, "org_update_failed"},
		{store.CodeOrgUpdateRejected, "org_update_rejected"},
		{store.CodeOrgDeleteFailed, "org_delete_failed"},
		{store.CodeOrgDeleteRejected, "org_delete_rejected"},
		{store.CodeMemberListFailed, "member_list_failed"},
		{store.CodeMemberListRejected, "member_list_rejected"},
		{store.CodeMemberUpdateFailed, "member_update_failed"},
		{store.CodeMemberUpdateRejected, "member_update_rejected"},
		{store.CodeMemberRevokeFailed, "member_revoke_failed"},
		{store.CodeMemberRevokeRejected, "member_revoke_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}
