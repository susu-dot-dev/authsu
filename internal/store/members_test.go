//nolint:goconst,prealloc // table-driven tests repeat case names and inputs, and append defect tables to their cases
package store_test

import (
	"context"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// memberRowOf is the row of a member: id, org_id, is_admin, revoked_at,
// created_at.
func memberRowOf(id string, admin int64, revoked any) []any {
	return row(id, orgTestID, admin, revoked, int64(1_700_000_001))
}

// memberStandingOf is the standing statement's row for a member: the member's row
// and whether the caller administers their organization.
func memberStandingOf(id string, admin int64, revoked any, administers int64) []any {
	return append(memberRowOf(id, admin, revoked), administers)
}

// memberKinds are the column kinds of a member row, for defectResults.
func memberKinds() []string { return []string{"text", "text", "integer", "optInteger", "integer"} }

// wantMember is the member a row of memberRowOf decodes to.
func wantMember(id string, admin bool, revoked *int64) store.Member {
	return store.Member{ID: id, OrgID: orgTestID, Admin: admin, RevokedAt: revoked, CreatedAt: 1_700_000_001}
}

// TestListMembers: the members and why there may be none are read in one batch,
// and the organization decides first.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestListMembers(t *testing.T) {
	t.Parallel()

	listing := func(size string, cursor ...string) func(*store.Store) (store.MemberPage, error) {
		return func(s *store.Store) (store.MemberPage, error) {
			return s.ListMembers(context.Background(), mustUserID(t, orgTestID), callerID, adminRole,
				orgCursorOf(t, cursor...), orgLimitOf(t, size))
		}
	}

	revoked := int64(1_700_000_100)
	listed := func(rows ...[]any) outcome {
		return batchOf(2, map[int][][]any{0: rows, 1: {standardRow()}})
	}

	cases := []opCase[store.MemberPage]{
		{name: "nobody is an empty page, not nil", out: listed(),
			want: store.MemberPage{Members: []store.Member{}}},
		{name: "members, an administrator and a revoked account", out: listed(
			memberRowOf(callerID, 1, nil), memberRowOf(targetID, 0, revoked)),
			want: store.MemberPage{Members: []store.Member{
				wantMember(callerID, true, nil), wantMember(targetID, false, &revoked),
			}}},
		{name: "one more than the page has a next", out: listed(
			memberRowOf(callerID, 0, nil), memberRowOf(targetID, 0, nil), memberRowOf(orgTestID, 0, nil)),
			want: store.MemberPage{Members: []store.Member{
				wantMember(callerID, false, nil), wantMember(targetID, false, nil),
			}, Next: targetID}},
		{name: "the caller may not see the organization", out: batchOf(2, map[int][][]any{
			0: {memberRowOf(callerID, 0, nil)},
		}), err: store.ErrNotFound},
		{name: "a sandbox has no members", out: batchOf(2, map[int][][]any{1: {sandboxRow(longAt)}}),
			err: store.ErrNotStandard},
		{name: "more rows than were asked for", out: listed(
			memberRowOf(callerID, 0, nil), memberRowOf(callerID, 0, nil), memberRowOf(callerID, 0, nil),
			memberRowOf(callerID, 0, nil)), defect: true},
	}

	for name, rows := range defectResults(memberRowOf(callerID, 0, nil), memberKinds()...) {
		if name == "two rows" {
			continue
		}

		cases = append(cases, opCase[store.MemberPage]{name: "a defective member row: " + name, out: listed(rows...),
			defect: true})
	}

	for name, rows := range defectResults(standardRow(), orgKinds()...) {
		cases = append(cases, opCase[store.MemberPage]{name: "a defective organization row: " + name,
			out: batchOf(2, map[int][][]any{1: rows}), defect: true})
	}

	runOpCases(t, cases, store.CodeMemberListRejected, listing("2"))

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(listed())

		_, err := listing("25", orgTestID)(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: append([]string{
					"FROM users u WHERE u.org_id = ?1 AND u.id < ?4 AND",
					"ORDER BY u.id DESC LIMIT ?5",
					"EXISTS (SELECT 1 FROM org_admins ma WHERE ma.org_id = u.org_id AND ma.user_id = u.id) AS is_admin",
				}, seesFragments...),
				args: []any{orgTestID, callerID, adminRole, orgTestID, int64(26)},
			},
			wantStatement{
				fragments: append([]string{"FROM orgs o WHERE o.id = ?1 AND"}, seesFragments...),
				args:      []any{orgTestID, callerID, adminRole},
			},
		)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runFailures(t, 2, store.CodeMemberListFailed, store.CodeMemberListRejected, orgsDescription,
			func(s *store.Store) error { return lastErr(listing("2")(s)) })
	})
}

// TestSetMemberAdmin: the standing statement and the one change of the batch
// say what happened. Promoting an administrator and demoting a member who is not
// one succeed.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestSetMemberAdmin(t *testing.T) {
	t.Parallel()

	setting := func(admin bool) func(*store.Store) (store.Member, error) {
		return func(s *store.Store) (store.Member, error) {
			return s.SetMemberAdmin(context.Background(), mustUserID(t, targetID), admin, callerID, adminRole, now)
		}
	}

	revoked := int64(1_700_000_100)

	// batch is the outcome of the two statements: the standing and the change.
	batch := func(standing []any, changed bool) outcome {
		changes := [][]any(nil)
		if changed {
			changes = [][]any{row(targetID)}
		}

		return batchOf(2, map[int][][]any{0: {standing}, 1: changes})
	}
	missing := batchOf(2, map[int][][]any{1: {row(targetID)}})

	promote := []opCase[store.Member]{
		{name: "promoted", out: batch(memberStandingOf(targetID, 0, nil, 1), true),
			want: wantMember(targetID, true, nil)},
		{name: "promoting an administrator succeeds", out: batch(memberStandingOf(targetID, 1, nil, 1), true),
			want: wantMember(targetID, true, nil)},
		{name: "a revoked member keeps their revocation", out: batch(memberStandingOf(targetID, 0, revoked, 1), true),
			want: wantMember(targetID, true, &revoked)},
		{name: "no such member", out: missing, err: store.ErrNotFound},
		{name: "the caller does not administer", out: batch(memberStandingOf(targetID, 0, nil, 0), false),
			err: store.ErrNotAdmin},
		{name: "the caller does not administer, and the write is not read either",
			out: batch(memberStandingOf(targetID, 0, nil, 0), true), err: store.ErrNotAdmin},
		{name: "a promotion that matched nothing for a caller who administers is a defect",
			out: batch(memberStandingOf(targetID, 0, nil, 1), false), defect: true},
		{name: "the standing is not a flag", out: batch(memberStandingOf(targetID, 0, nil, 2), true), defect: true},
		{name: "a changed row that is not an id", out: batchOf(2, map[int][][]any{
			0: {memberStandingOf(targetID, 0, nil, 1)}, 1: {row(int64(1))},
		}), defect: true},
		{name: "two changed rows", out: batchOf(2, map[int][][]any{
			0: {memberStandingOf(targetID, 0, nil, 1)}, 1: {row(targetID), row(targetID)},
		}), defect: true},
	}

	for name, rows := range defectResults(memberStandingOf(targetID, 0, nil, 1), append(memberKinds(), "integer")...) {
		promote = append(promote, opCase[store.Member]{name: "a defective standing: " + name,
			out: batchOf(2, map[int][][]any{0: rows, 1: {row(targetID)}}), defect: true})
	}

	runOpCases(t, promote, store.CodeMemberUpdateRejected, setting(true))

	runOpCases(t, []opCase[store.Member]{
		{name: "demoted", out: batch(memberStandingOf(targetID, 1, nil, 1), true), want: wantMember(targetID, false, nil)},
		{name: "demoting a member who is not an administrator succeeds",
			out: batch(memberStandingOf(targetID, 0, nil, 1), false), want: wantMember(targetID, false, nil)},
		{name: "the last administrator is refused", out: batch(memberStandingOf(targetID, 1, nil, 1), false),
			err: store.ErrLastOrgAdmin},
		{name: "no such member", out: missing, err: store.ErrNotFound},
		{name: "the caller does not administer", out: batch(memberStandingOf(targetID, 1, nil, 0), false),
			err: store.ErrNotAdmin},
	}, store.CodeMemberUpdateRejected, setting(false))

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		standingFragments := append([]string{
			"FROM users tu WHERE tu.id = ?1 AND tu.org_id IS NOT NULL AND",
			"EXISTS (SELECT 1 FROM org_admins ta WHERE ta.org_id = tu.org_id AND ta.user_id = tu.id) AS is_admin",
			"AS administers",
		}, targetAdministersFragments...)

		standingStatement := wantStatement{
			fragments: append(standingFragments, targetSeesFragments...),
			args:      []any{targetID, callerID, adminRole},
		}

		promoting := newFake(batch(memberStandingOf(targetID, 0, nil, 1), true))

		_, err := setting(true)(promoting.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, promoting, standingStatement, wantStatement{
			fragments: append([]string{
				"INSERT INTO org_admins (org_id, user_id, created_at) SELECT tu.org_id, tu.id, ?4 FROM users tu",
				// The organization must be active, and the caller administers it.
				"AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = tu.org_id AND o.revoked_at IS NULL) AND",
				// Promoting an administrator matches and changes nothing, so a row
				// is returned either way.
				"ON CONFLICT (org_id, user_id) DO UPDATE SET created_at = org_admins.created_at RETURNING user_id",
			}, targetAdministersFragments...),
			args: []any{targetID, callerID, adminRole, now.Unix()},
		})

		demoting := newFake(batch(memberStandingOf(targetID, 1, nil, 1), true))

		_, err = setting(false)(demoting.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, demoting, standingStatement, wantStatement{
			fragments: append([]string{
				"DELETE FROM org_admins WHERE user_id = ?1 AND EXISTS (SELECT 1 FROM users tu",
				"WHERE tu.id = ?1 AND tu.org_id = org_admins.org_id AND",
				// The last-administrator guard is part of the delete.
				otherAdminFragment,
				"RETURNING user_id",
			}, targetAdministersFragments...),
			args: []any{targetID, callerID, adminRole},
		})
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		for _, admin := range []bool{true, false} {
			runOpFailures(t, 2, store.CodeMemberUpdateFailed, store.CodeMemberUpdateRejected,
				func(s *store.Store) error { return lastErr(setting(admin)(s)) })
		}
	})
}

// targetAdministersFragments and targetSeesFragments are the conditions of the
// writes whose subject is a user: the same as for an organization, over the
// organization of the user (tu.org_id), with the user's id as ?1.
//
//nolint:gochecknoglobals // fixed lists shared by the table tests
var (
	targetAdministersFragments = administersOf("tu.org_id")
	targetSeesFragments        = seesOf("tu.org_id")
)

// otherAdminFragment is the guard that an organization keeps an unrevoked
// administrator besides the member, or that the member is revoked and so does
// not count.
const otherAdminFragment = "(tu.revoked_at IS NOT NULL OR EXISTS (SELECT 1 FROM org_admins oa2 " +
	"JOIN users u2 ON u2.id = oa2.user_id WHERE oa2.org_id = tu.org_id AND oa2.user_id <> tu.id " +
	"AND u2.revoked_at IS NULL))"

// TestRemoveMember: the standing statement before the writes, the guarded
// delete of the administrator row, and the release of the user say what
// happened.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRemoveMember(t *testing.T) {
	t.Parallel()

	removing := func(id string) func(*store.Store) (store.Member, error) {
		return func(s *store.Store) (store.Member, error) {
			return s.RemoveMember(context.Background(), mustUserID(t, id), callerID, adminRole)
		}
	}

	batch := func(standing []any, released bool) outcome {
		changes := [][]any(nil)
		if released {
			changes = [][]any{row(targetID)}
		}

		return batchOf(3, map[int][][]any{0: {standing}, 2: changes})
	}

	revoked := int64(1_700_000_100)

	// An administrator who is removed is shown as no longer one.
	runOpCases(t, []opCase[store.Member]{
		{name: "a member is removed", out: batch(memberStandingOf(targetID, 0, nil, 1), true),
			want: wantMember(targetID, false, nil)},
		{name: "an administrator is removed and is shown as no longer one",
			out: batch(memberStandingOf(targetID, 1, nil, 1), true), want: wantMember(targetID, false, nil)},
		{name: "a revoked member is removed", out: batch(memberStandingOf(targetID, 0, revoked, 1), true),
			want: wantMember(targetID, false, &revoked)},
		{name: "a member who is not an administrator of it is refused",
			out: batch(memberStandingOf(targetID, 0, nil, 0), false), err: store.ErrNotAdmin},
		{name: "the last administrator is refused", out: batch(memberStandingOf(targetID, 1, nil, 1), false),
			err: store.ErrLastOrgAdmin},
		{name: "no such member", out: batchOf(3, map[int][][]any{2: {row(targetID)}}), err: store.ErrNotFound},
		{name: "the standing is not a flag", out: batch(memberStandingOf(targetID, 0, nil, 2), true), defect: true},
		{name: "two released rows are not what the update says", out: batchOf(3, map[int][][]any{
			0: {memberStandingOf(targetID, 0, nil, 1)}, 2: {row(targetID), row(targetID)},
		}), defect: true},
		{name: "a released row that is not an id", out: batchOf(3, map[int][][]any{
			0: {memberStandingOf(targetID, 0, nil, 1)}, 2: {row(int64(1))},
		}), defect: true},
	}, store.CodeMemberRemoveRejected, removing(targetID))

	// Leaving is removing oneself: refused as the last administrator, and not as
	// a stranger, whatever the caller administers.
	runOpCases(t, []opCase[store.Member]{
		{name: "the user leaves", out: batch(memberStandingOf(callerID, 0, nil, 0), true),
			want: wantMember(callerID, false, nil)},
		{name: "the last administrator cannot leave", out: batch(memberStandingOf(callerID, 1, nil, 0), false),
			err: store.ErrLastOrgAdmin},
		{name: "no longer belongs to an organization", out: batchOf(3, nil), err: store.ErrNotFound},
	}, store.CodeMemberRemoveRejected, removing(callerID))

	cases := []opCase[store.Member]{}

	for name, rows := range defectResults(memberStandingOf(targetID, 0, nil, 1), append(memberKinds(), "integer")...) {
		cases = append(cases, opCase[store.Member]{name: "a defective standing: " + name,
			out: batchOf(3, map[int][][]any{0: rows, 2: {row(targetID)}}), defect: true})
	}

	runOpCases(t, cases, store.CodeMemberRemoveRejected, removing(targetID))

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(batch(memberStandingOf(targetID, 0, nil, 1), true))

		_, err := removing(targetID)(fake.store())
		checkErr(t, err, nil)

		// The user may remove themself, or the caller administers the organization.
		mayRemove := "((tu.id = ?2 AND tu.revoked_at IS NULL) OR EXISTS " +
			"(SELECT 1 FROM (SELECT tu.org_id AS org_id) subject, users actor"

		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: []string{"FROM users tu WHERE tu.id = ?1 AND tu.org_id IS NOT NULL AND", "AS administers"},
				args:      []any{targetID, callerID, adminRole},
			},
			wantStatement{
				fragments: append([]string{
					"DELETE FROM org_admins WHERE user_id = ?1 AND EXISTS (SELECT 1 FROM users tu",
					"WHERE tu.id = ?1 AND tu.org_id = org_admins.org_id AND " + mayRemove,
					otherAdminFragment,
				}, targetAdministersFragments...),
				args: []any{targetID, callerID, adminRole},
			},
			wantStatement{
				fragments: append([]string{
					"UPDATE users AS tu SET org_id = NULL WHERE tu.id = ?1 AND tu.org_id IS NOT NULL AND " + mayRemove,
					// Only a user who is no longer an administrator is released: the
					// delete before it refused to remove the last one.
					"AND NOT EXISTS (SELECT 1 FROM org_admins ta WHERE ta.org_id = tu.org_id AND ta.user_id = tu.id)",
					"RETURNING id",
				}, targetAdministersFragments...),
				args: []any{targetID, callerID, adminRole},
			},
		)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runOpFailures(t, 3, store.CodeMemberRemoveFailed, store.CodeMemberRemoveRejected,
			func(s *store.Store) error { return lastErr(removing(targetID)(s)) })
	})
}
