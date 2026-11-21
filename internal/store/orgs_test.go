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
	orgTestID  = "01890000-0000-7000-8000-0000000000b1"
	callerID   = "01890000-0000-7000-8000-000000000001"
	targetID   = "01890000-0000-7000-8000-000000000002"
	offerTestI = "01890000-0000-7000-8000-0000000000c1"
	adminRole  = "admin"
)

func orgKindOf(tb testing.TB, raw string) input.OrgKind {
	tb.Helper()

	kind, err := input.ParseOrgKind(raw)
	if err != nil {
		tb.Fatalf("parse org kind %q: %v", raw, err)
	}

	return kind
}

func orgNameOf(tb testing.TB, raw string) input.OrgName {
	tb.Helper()

	name, err := input.ParseOrgName(raw)
	if err != nil {
		tb.Fatalf("parse org name %q: %v", raw, err)
	}

	return name
}

func orgRoleOf(tb testing.TB, raw string) input.OrgRole {
	tb.Helper()

	role, err := input.ParseOrgRole(raw)
	if err != nil {
		tb.Fatalf("parse org role %q: %v", raw, err)
	}

	return role
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

// orgRowOf is the row of an organization: id, kind, name, created_by,
// expires_at, revoked_at, created_at.
func orgRowOf(id, kind string, expires, revoked any) []any {
	return row(id, kind, "Acme", callerID, expires, revoked, int64(1_700_000_000))
}

// standardRow and sandboxRow are an active organization and a sandbox that
// expires at the given time.
func standardRow() []any                   { return orgRowOf(orgTestID, store.OrgKindStandard, nil, nil) }
func sandboxRow(at int64) []any            { return orgRowOf(orgTestID, store.OrgKindSandbox, at, nil) }
func revokedRow(at int64) []any            { return orgRowOf(orgTestID, store.OrgKindStandard, nil, at) }
func standing(of []any, admin int64) []any { return append(slices.Clip(of), admin) }

// orgKinds are the column kinds of an organization row, for defectResults.
func orgKinds() []string {
	return []string{"text", "text", "text", "text", "optInteger", "optInteger", "integer"}
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

// runOpFailures holds how a failed or malformed batch of n statements is
// reported. No operation here writes a constraint a client could cause, so a
// conflict is the schema disagreeing with the code and is the "_rejected" 500.
func runOpFailures(t *testing.T, n int, failed, rejected string, call func(*store.Store) error) {
	t.Helper()

	runDefectFailures(t, n, failed, rejected, orgsDescription, call)
}

// longAt is an instant well after now, as a sandbox's expiry in a row.
const longAt = int64(1_900_000_456)

// soonAt is when a sandbox created at now expires.
func soonAt() time.Time { return now.Add(7 * 24 * time.Hour) }

// createCall is CreateOrg of the kind with the largest values it can carry.
func createCall(t *testing.T, kind string) func(*store.Store) (store.Org, error) {
	t.Helper()

	return func(s *store.Store) (store.Org, error) {
		return s.CreateOrg(context.Background(), store.NewOrg{
			ID: orgTestID, Kind: orgKindOf(t, kind), Name: orgNameOf(t, "Acme"), Creator: callerID, ExpiresAt: soonAt(),
			Limit: 5, CreatedAt: now,
		})
	}
}

// TestCreateOrgOutcomes: the row the insert returned is the organization, and
// otherwise the creator's standing says why: gone or revoked first, then
// already a member (for a standard organization only), and what is left is the
// limit.
func TestCreateOrgOutcomes(t *testing.T) {
	t.Parallel()

	stored := store.Org{
		ID: orgTestID, Kind: store.OrgKindStandard, Name: "Acme", CreatedBy: callerID, CreatedAt: 1_700_000_000,
	}
	expires := longAt
	sandbox := stored
	sandbox.Kind, sandbox.ExpiresAt = store.OrgKindSandbox, &expires

	refused := func(revoked, member int64) outcome {
		return batchOf(4, map[int][][]any{3: {row(revoked, member)}})
	}

	cases := []opCase[store.Org]{
		{name: "a standard organization was created", out: batchOf(4, map[int][][]any{0: {standardRow()}}), want: stored},
		{name: "the standing is not read when it was", out: batchOf(4, map[int][][]any{
			0: {standardRow()}, 3: {row(int64(1), int64(1))},
		}), want: stored},
		{name: "the creator is gone", out: batchOf(4, nil), err: store.ErrAccountRevoked},
		{name: "the creator is revoked", out: refused(1, 0), err: store.ErrAccountRevoked},
		{name: "the creator is revoked and a member: revoked first", out: refused(1, 1), err: store.ErrAccountRevoked},
		{name: "the creator belongs to an organization", out: refused(0, 1), err: store.ErrAlreadyMember},
		{name: "the creator is at the limit", out: refused(0, 0), err: store.ErrOrgLimit},
	}

	cases = append(cases, rowDefectCases[store.Org](4, 0, standardRow(), orgKinds()...)...)
	cases = append(cases,
		opCase[store.Org]{name: "two rows for one id", out: batchOf(4, map[int][][]any{0: {standardRow(), standardRow()}}),
			defect: true},
		opCase[store.Org]{name: "the standing has a column too few", out: batchOf(4, map[int][][]any{3: {row(int64(0))}}),
			defect: true},
		opCase[store.Org]{name: "the standing is not a flag", out: batchOf(4, map[int][][]any{3: {row(int64(2), int64(0))}}),
			defect: true},
		opCase[store.Org]{name: "two standing rows", out: batchOf(4, map[int][][]any{
			3: {row(int64(0), int64(0)), row(int64(0), int64(0))},
		}), defect: true},
	)

	runOpCases(t, cases, store.CodeOrgCreateRejected, createCall(t, store.OrgKindStandard))

	// A sandbox is refused for a member of an organization only by the limit:
	// it needs no free membership.
	runOpCases(t, []opCase[store.Org]{
		{name: "a sandbox for a member of an organization is not refused for it", out: refused(0, 1), err: store.ErrOrgLimit},
		{name: "a sandbox was created", out: batchOf(4, map[int][][]any{0: {sandboxRow(longAt)}}), want: sandbox},
		{name: "a sandbox with a revoked creator", out: refused(1, 0), err: store.ErrAccountRevoked},
	}, store.CodeOrgCreateRejected, createCall(t, store.OrgKindSandbox))
}

// TestCreateOrgStatements pins the batch: the four statements in order, the
// guards that decide what each does, and the exact arguments in placeholder
// order. The kinds are bound, and a sandbox's expiry is bound and a standard
// organization's is NULL, as the schema's CHECKs require.
func TestCreateOrgStatements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    string
		expires any
	}{
		{name: "a standard organization", kind: store.OrgKindStandard, expires: nil},
		{name: "a sandbox", kind: store.OrgKindSandbox, expires: soonAt().Unix()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(batchOf(4, map[int][][]any{0: {standardRow()}}))

			_, err := createCall(t, test.kind)(fake.store())
			checkErr(t, err, nil)

			checkNumberedStatements(t, fake,
				wantStatement{
					fragments: []string{
						"INSERT INTO orgs (id, kind, name, created_by, expires_at, revoked_at, created_at)",
						// The creator is read from users, unrevoked, and a standard
						// organization needs one that belongs to none.
						"FROM users u WHERE u.id = ?6 AND u.revoked_at IS NULL AND (?2 <> ?7 OR u.org_id IS NULL)",
						// The limit is counted in the write: every standard organization
						// ever created, and the sandboxes that have not expired.
						"(SELECT count(*) FROM orgs g WHERE g.created_by = u.id AND g.kind = ?2 " +
							"AND (?2 = ?7 OR g.expires_at > ?5)) < ?8",
						"RETURNING id, kind, name, created_by, expires_at, revoked_at, created_at",
					},
					args: []any{
						orgTestID, test.kind, "Acme", test.expires, now.Unix(), callerID, store.OrgKindStandard, int64(5),
					},
				},
				wantStatement{
					fragments: []string{
						"UPDATE users SET org_id = ?1 WHERE id = ?2 AND org_id IS NULL AND ?3 = ?4",
						"AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = ?1 AND o.created_by = ?2)",
					},
					args: []any{orgTestID, callerID, test.kind, store.OrgKindStandard},
				},
				wantStatement{
					fragments: []string{
						"INSERT INTO org_admins (org_id, user_id, created_at)",
						"SELECT o.id, o.created_by, ?2 FROM orgs o WHERE o.id = ?1",
					},
					args: []any{orgTestID, now.Unix()},
				},
				wantStatement{
					fragments: []string{"SELECT u.revoked_at IS NOT NULL AS revoked, u.org_id IS NOT NULL AS member FROM users u"},
					args:      []any{callerID},
				},
			)
		})
	}
}

// TestCreateSandboxJudgesTheLimitAtTheRequestSecond: the count of the sandboxes a
// user holds takes those that expire after the create's whole second, so one
// whose expiry is this very second is not counted, and the new sandbox's own
// expiry is whole seconds too. A fraction of a second in the clock changes
// neither. (The comparison itself runs in the end-to-end tests; the operator is
// pinned in TestCreateOrgStatements.)
func TestCreateSandboxJudgesTheLimitAtTheRequestSecond(t *testing.T) {
	t.Parallel()

	for _, fraction := range []time.Duration{0, time.Millisecond, 999 * time.Millisecond} {
		t.Run(fraction.String(), func(t *testing.T) {
			t.Parallel()

			at := now.Add(fraction)
			fake := newFake(batchOf(4, map[int][][]any{0: {sandboxRow(longAt)}}))

			_, err := fake.store().CreateOrg(context.Background(), store.NewOrg{
				ID: orgTestID, Kind: orgKindOf(t, store.OrgKindSandbox), Name: orgNameOf(t, "Acme"), Creator: callerID,
				ExpiresAt: at.Add(7 * 24 * time.Hour), Limit: 25, CreatedAt: at,
			})
			checkErr(t, err, nil)

			insert := fake.calls[0][0]
			if !strings.Contains(squash(insert.Query), "g.expires_at > ?5") {
				t.Errorf("the count does not compare with ?5 strictly:\n%s", insert.Query)
			}

			if insert.Args[3] != now.Add(7*24*time.Hour).Unix() || insert.Args[4] != now.Unix() {
				t.Errorf("expiry and creation time = %v and %v, want whole seconds %d and %d",
					insert.Args[3], insert.Args[4], now.Add(7*24*time.Hour).Unix(), now.Unix())
			}
		})
	}
}

// TestCreateOrgFailures holds how a failed or malformed batch is reported.
func TestCreateOrgFailures(t *testing.T) {
	t.Parallel()

	runOpFailures(t, 4, store.CodeOrgCreateFailed, store.CodeOrgCreateRejected,
		func(s *store.Store) error { return lastErr(createCall(t, store.OrgKindStandard)(s)) })
}

// TestOrgActive: an organization works unless it is revoked or its expiry has
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
		{name: "a revoked one", org: store.Org{RevokedAt: &at}, want: false},
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
// organization, an offer's), has this text with its own expression for org, and
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

	second := orgRowOf("01890000-0000-7000-8000-0000000000b0", store.OrgKindStandard, nil, nil)
	third := orgRowOf("01890000-0000-7000-8000-0000000000af", store.OrgKindStandard, nil, nil)

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

	refused := func(of []any, admin int64) outcome { return batchOf(2, map[int][][]any{1: {standing(of, admin)}}) }

	cases := []opCase[store.Org]{
		{name: "renamed", out: batchOf(2, map[int][][]any{0: {standardRow()}}), want: renamed},
		{name: "the caller may not see it", out: batchOf(2, nil), err: store.ErrNotFound},
		{name: "the caller sees it and does not administer it", out: refused(standardRow(), 0), err: store.ErrNotAdmin},
		{name: "the organization is revoked", out: refused(revokedRow(expired), 1), err: store.ErrInactive},
		{name: "the sandbox has expired", out: refused(sandboxRow(expired), 1), err: store.ErrInactive},
		{name: "the sandbox expires this very second", out: refused(sandboxRow(now.Unix()), 1), err: store.ErrInactive},
		{name: "an active organization the write did not rename is a defect",
			out: refused(standardRow(), 1), defect: true},
		{name: "an active sandbox the write did not rename is a defect", out: refused(sandboxRow(live), 1), defect: true},
		{name: "the standing is not a flag", out: refused(standardRow(), 2), defect: true},
	}

	cases = append(cases, rowDefectCases[store.Org](2, 0, standardRow(), orgKinds()...)...)
	cases = append(cases, rowDefectCases[store.Org](2, 1, standing(standardRow(), 1), append(orgKinds(), "integer")...)...)

	runOpCases(t, cases, store.CodeOrgUpdateRejected, call)

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(batchOf(2, map[int][][]any{0: {standardRow()}}))

		_, err := call(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: append([]string{
					"UPDATE orgs SET name = ?4 WHERE id = ?1",
					// A revoked organization and an expired sandbox are final.
					"AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?5) AND",
					"RETURNING id, kind, name, created_by, expires_at, revoked_at, created_at",
				}, administersFragments...),
				args: []any{orgTestID, callerID, adminRole, "New", now.Unix()},
			},
			wantStatement{
				fragments: append([]string{
					"o.revoked_at AS revoked_at, o.created_at AS created_at, " +
						"EXISTS (SELECT 1 FROM (SELECT ?1 AS org_id) subject, users actor",
					"AS administers FROM orgs o WHERE o.id = ?1 AND",
				}, seesFragments...),
				args: []any{orgTestID, callerID, adminRole},
			},
		)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runOpFailures(t, 2, store.CodeOrgUpdateFailed, store.CodeOrgUpdateRejected,
			func(s *store.Store) error { return lastErr(call(s)) })
	})
}

// TestRevokeOrg: a returned row from the revoking update is a revoked standard
// organization, one from the sandbox delete is a deleted sandbox, and otherwise
// the standing statement says why neither happened.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRevokeOrg(t *testing.T) {
	t.Parallel()

	call := func(s *store.Store) (store.OrgEnd, error) {
		return s.RevokeOrg(context.Background(), mustUserID(t, orgTestID), callerID, adminRole, now)
	}

	at := now.Unix()
	expires := longAt

	refused := func(of []any, admin int64) outcome { return batchOf(6, map[int][][]any{5: {standing(of, admin)}}) }

	cases := []opCase[store.OrgEnd]{
		{name: "a standard organization was revoked", out: batchOf(6, map[int][][]any{0: {revokedRow(at)}}),
			want: store.OrgEnd{Org: store.Org{
				ID: orgTestID, Kind: store.OrgKindStandard, Name: "Acme", CreatedBy: callerID, RevokedAt: &at,
				CreatedAt: 1_700_000_000,
			}}},
		{name: "a sandbox was deleted", out: batchOf(6, map[int][][]any{4: {sandboxRow(longAt)}}),
			want: store.OrgEnd{Deleted: true, Org: store.Org{
				ID: orgTestID, Kind: store.OrgKindSandbox, Name: "Acme", CreatedBy: callerID, ExpiresAt: &expires,
				CreatedAt: 1_700_000_000,
			}}},
		{name: "the caller may not see it", out: batchOf(6, nil), err: store.ErrNotFound},
		{name: "the caller sees it and does not administer it", out: refused(standardRow(), 0), err: store.ErrNotAdmin},
		{name: "an organization the caller administers that nothing matched is a defect",
			out: refused(standardRow(), 1), defect: true},
		{name: "a revoked organization the caller administers is inactive", out: refused(revokedRow(at-1), 1),
			err: store.ErrInactive},
	}

	cases = append(cases, rowDefectCases[store.OrgEnd](6, 0, revokedRow(at), orgKinds()...)...)
	cases = append(cases, rowDefectCases[store.OrgEnd](6, 4, sandboxRow(longAt), orgKinds()...)...)
	cases = append(cases, rowDefectCases[store.OrgEnd](6, 5, standing(standardRow(), 1),
		append(orgKinds(), "integer")...)...)

	runOpCases(t, cases, store.CodeOrgRevokeRejected, call)

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(batchOf(6, map[int][][]any{0: {revokedRow(at)}}))

		_, err := call(fake.store())
		checkErr(t, err, nil)

		// The statements that follow the revocation apply only to a revoked
		// standard organization, and are written with the same standing as the
		// revocation, so a caller who may not revoke changes nothing at all.
		revokedOrg := "AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = ?1 AND o.kind = ?4 AND o.revoked_at IS NOT NULL)"

		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: append([]string{
					"UPDATE orgs SET revoked_at = COALESCE(revoked_at, ?4) WHERE id = ?1 AND kind = ?5 AND",
					"RETURNING id, kind, name, created_by, expires_at, revoked_at, created_at",
				}, administersFragments...),
				args: []any{orgTestID, callerID, adminRole, at, store.OrgKindStandard},
			},
			wantStatement{
				fragments: append([]string{"UPDATE users SET org_id = NULL WHERE org_id = ?1 AND", revokedOrg},
					administersFragments...),
				args: []any{orgTestID, callerID, adminRole, store.OrgKindStandard},
			},
			wantStatement{
				fragments: append([]string{"DELETE FROM org_offers WHERE org_id = ?1 AND", revokedOrg},
					administersFragments...),
				args: []any{orgTestID, callerID, adminRole, store.OrgKindStandard},
			},
			wantStatement{
				fragments: append([]string{"DELETE FROM org_admins WHERE org_id = ?1 AND", revokedOrg},
					administersFragments...),
				args: []any{orgTestID, callerID, adminRole, store.OrgKindStandard},
			},
			wantStatement{
				fragments: append([]string{
					"DELETE FROM orgs WHERE id = ?1 AND kind = ?4 AND",
					"RETURNING id, kind, name, created_by, expires_at, revoked_at, created_at",
				}, administersFragments...),
				args: []any{orgTestID, callerID, adminRole, store.OrgKindSandbox},
			},
			wantStatement{
				fragments: []string{"AS administers FROM orgs o WHERE o.id = ?1 AND"},
				args:      []any{orgTestID, callerID, adminRole},
			},
		)

		// The order matters: the administrator rows go last, because the caller's
		// own standing may be one of them and the other statements need it.
		order := []string{
			"UPDATE orgs", "UPDATE users", "DELETE FROM org_offers", "DELETE FROM org_admins", "DELETE FROM orgs",
		}
		for i, prefix := range order {
			if query := squash(fake.calls[0][i].Query); !strings.HasPrefix(query, prefix) {
				t.Errorf("statement %d = %q, want it to start with %q", i, query, prefix)
			}
		}
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runOpFailures(t, 6, store.CodeOrgRevokeFailed, store.CodeOrgRevokeRejected,
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
		{store.CodeOrgRevokeFailed, "org_revoke_failed"},
		{store.CodeOrgRevokeRejected, "org_revoke_rejected"},
		{store.CodeMemberListFailed, "member_list_failed"},
		{store.CodeMemberListRejected, "member_list_rejected"},
		{store.CodeMemberUpdateFailed, "member_update_failed"},
		{store.CodeMemberUpdateRejected, "member_update_rejected"},
		{store.CodeMemberRemoveFailed, "member_remove_failed"},
		{store.CodeMemberRemoveRejected, "member_remove_rejected"},
		{store.CodeOfferCreateFailed, "offer_create_failed"},
		{store.CodeOfferCreateRejected, "offer_create_rejected"},
		{store.CodeOfferListFailed, "offer_list_failed"},
		{store.CodeOfferListRejected, "offer_list_rejected"},
		{store.CodeOfferAcceptFailed, "offer_accept_failed"},
		{store.CodeOfferAcceptRejected, "offer_accept_rejected"},
		{store.CodeOfferRevokeFailed, "offer_revoke_failed"},
		{store.CodeOfferRevokeRejected, "offer_revoke_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}
