package store

import (
	"context"
	"fmt"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Error codes of the member operations. They are stable: clients and dashboards
// may match on them.
const (
	CodeMemberListFailed     = "member_list_failed"
	CodeMemberListRejected   = "member_list_rejected"
	CodeMemberUpdateFailed   = "member_update_failed"
	CodeMemberUpdateRejected = "member_update_rejected"
	CodeMemberRemoveFailed   = "member_remove_failed"
	CodeMemberRemoveRejected = "member_remove_rejected"
)

// Member is a user of a standard organization as it is shown to those who may
// see it.
type Member struct {
	// ID is the user's id.
	ID string

	// OrgID is the organization the user belongs to.
	OrgID string

	// Admin is whether the user administers the organization.
	Admin bool

	// RevokedAt is when the user's account was revoked, in Unix seconds, or nil.
	// A revoked member keeps belonging to the organization until removed, and
	// does not count as an administrator.
	RevokedAt *int64

	// CreatedAt is when the account was created, in Unix seconds.
	CreatedAt int64
}

// readMember reads one member row, in the column order every member statement
// selects: id, org_id, is_admin, revoked_at, created_at.
func readMember(r *row) Member {
	// Struct fields are evaluated in order, which is the column order.
	return Member{ID: r.text(), OrgID: r.text(), Admin: r.boolean(), RevokedAt: r.optInteger(), CreatedAt: r.integer()}
}

// memberStanding is a member with whether the caller may administer the
// organization they belong to.
type memberStanding struct {
	member     Member
	administer bool
}

// readMemberStanding reads the columns of readMember and then administers.
func readMemberStanding(r *row) memberStanding {
	member := readMember(r)

	return memberStanding{member: member, administer: r.boolean()}
}

// The conditions the member writes state about who is acting, for a statement
// whose subject is a user and whose organization is that user's own: ?1 is the
// user's id, ?2 the caller's id, ?3 the role of a platform administrator, and tu
// is the user's row, so tu.org_id is the organization. They are the conditions of
// orgs.go built over that column, so who sees and who administers an organization
// is the same rule here as there, and as for callerAdministersOrg they are part of
// the write and require the caller to be unrevoked.
const (
	// callerAdministersTargetOrg holds when the caller administers the user's
	// organization, or is a platform administrator.
	callerAdministersTargetOrg = orgSubjectFrom + `tu.org_id` + callerAdministersOrgTo

	// callerSeesTargetOrg holds when the caller may see the user's organization:
	// belongs to it, administers it, or is a platform administrator. The user
	// themself is among those who belong to it.
	callerSeesTargetOrg = orgSubjectFrom + `tu.org_id` + callerSeesOrgTo

	// callerMayRemoveTarget holds when the caller may take the user out of their
	// organization: the user themself (leaving), or one who administers it.
	callerMayRemoveTarget = `((tu.id = ?2 AND tu.revoked_at IS NULL) OR ` + callerAdministersTargetOrg + `)`

	// otherAdminRemains holds when the user's organization would still have an
	// unrevoked administrator other than the user, or when the user is revoked
	// and so is not counted: the organization is never left without one
	// (docs/orgs_design.md, principle 3).
	otherAdminRemains = `(tu.revoked_at IS NOT NULL
    OR EXISTS (SELECT 1 FROM org_admins oa2 JOIN users u2 ON u2.id = oa2.user_id
               WHERE oa2.org_id = tu.org_id AND oa2.user_id <> tu.id AND u2.revoked_at IS NULL))`
)

// listMembersQuery reads one page of the members of a standard organization the
// caller may see, newest first (a user's id is a UUIDv7, so it is the sort key
// and the cursor). Visibility is part of the match, so a caller who may not see
// the organization gets no member, whatever follows. A page asks for one row
// more than it returns, so the caller can tell whether there is a next page.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 cursor (orgsFirstPage for the first page), ?5 rows
// wanted.
const listMembersQuery = `
SELECT u.id AS id, u.org_id AS org_id,
       EXISTS (SELECT 1 FROM org_admins ma WHERE ma.org_id = u.org_id AND ma.user_id = u.id) AS is_admin,
       u.revoked_at AS revoked_at, u.created_at AS created_at
FROM users u
WHERE u.org_id = ?1 AND u.id < ?4 AND ` + callerSeesOrg + `
ORDER BY u.id DESC
LIMIT ?5`

// MemberPage is one page of the members of an organization, newest first.
type MemberPage struct {
	Members []Member

	// Next is the cursor of the following page: the id of the last member of
	// this one. It is empty on the last page.
	Next string
}

// ListMembers returns up to limit of the members of a standard organization the
// caller may see, with an id below the cursor, newest first. The members and why
// there may be none (the caller may not see it, or it is a sandbox) are read in
// the same batch, so the answer is one state.
//
// It returns ErrNotFound when the caller may not see the organization, and
// ErrNotStandard when it is a sandbox, which has no members.
func (s *Store) ListMembers(
	ctx context.Context, id input.ID, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
) (MemberPage, error) {
	o := op{failed: CodeMemberListFailed, rejected: CodeMemberListRejected, description: orgsDescription}

	before, size := pageWindow(cursor, limit)

	return outcome(result.Of(s.run(ctx, o,
		Statement{Query: listMembersQuery, Args: []any{id.String(), caller, adminRole, before, int64(size + 1)}},
		Statement{Query: getOrgQuery, Args: []any{id.String(), caller, adminRole}},
	)).
		Then(func(results []Result) (MemberPage, error) {
			return pageOf(o,
				lookup(results[1].Rows, o, readOrg).
					Then(found[Org].orNotFound).
					Check(standardOrg).
					Then(func(Org) ([]Member, error) { return all(results[0].Rows, o, readMember) }),
				size, func(member Member) string { return member.ID },
				func(members []Member, next string) MemberPage { return MemberPage{Members: members, Next: next} })
		}),
	)
}

// standardOrg is the guard of what only a standard organization has (members,
// offers): a sandbox has none.
func standardOrg(org Org) error {
	if org.Kind != OrgKindStandard {
		return ErrNotStandard
	}

	return nil
}

// memberStandingQuery reads a user who belongs to an organization, with whether
// they administer it and whether the caller does, as the first statement of a
// write to a member: the write's conditions are the same text over the same
// batch, so it reads the state the write saw. No row is a user who belongs to no
// organization or one the caller may not see, which is the same answer for both.
//
// Arguments, by number: ?1 user id, ?2 caller id, ?3 the platform
// administrator role.
const memberStandingQuery = `
SELECT tu.id AS id, tu.org_id AS org_id,
       EXISTS (SELECT 1 FROM org_admins ta WHERE ta.org_id = tu.org_id AND ta.user_id = tu.id) AS is_admin,
       tu.revoked_at AS revoked_at, tu.created_at AS created_at,
       ` + callerAdministersTargetOrg + ` AS administers
FROM users tu
WHERE tu.id = ?1 AND tu.org_id IS NOT NULL AND ` + callerSeesTargetOrg

// promoteMemberQuery makes a member of an active standard organization an
// administrator of it, if the caller administers it. A member who already is one
// is matched too and left as they are (the upsert changes nothing), so promoting
// twice succeeds, and RETURNING gives a row either way, which is how the caller
// learns that the write took effect.
//
// Arguments, by number: ?1 user id, ?2 caller id, ?3 the platform
// administrator role, ?4 created_at.
const promoteMemberQuery = `
INSERT INTO org_admins (org_id, user_id, created_at)
SELECT tu.org_id, tu.id, ?4
FROM users tu
WHERE tu.id = ?1 AND tu.org_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = tu.org_id AND o.revoked_at IS NULL)
  AND ` + callerAdministersTargetOrg + `
ON CONFLICT (org_id, user_id) DO UPDATE SET created_at = org_admins.created_at
RETURNING user_id`

// demoteMemberQuery stops a member administering their organization, if the
// caller administers it and an unrevoked administrator other than the member
// remains (otherAdminRemains). The guard is part of the delete, because D1 has no
// interactive transaction: two administrators demoting each other at the same
// moment would each see the other still there, and both writes would apply. D1
// runs one batch at a time, so the second sees the first's and is refused.
//
// RETURNING gives a row when the member was an administrator and is not any more.
// No row is a member who was not one (nothing to do), a caller who may not, or
// the last administrator: the standing statement before it tells them apart.
//
// Arguments, by number: ?1 user id, ?2 caller id, ?3 the platform
// administrator role.
const demoteMemberQuery = `
DELETE FROM org_admins
WHERE user_id = ?1
  AND EXISTS (SELECT 1 FROM users tu
              WHERE tu.id = ?1 AND tu.org_id = org_admins.org_id
                AND ` + callerAdministersTargetOrg + `
                AND ` + otherAdminRemains + `)
RETURNING user_id`

// removeMemberAdminQuery deletes the administrator row of a user who is leaving
// their organization or being removed from it, if the caller may remove them and
// the organization keeps an unrevoked administrator (otherAdminRemains). It is
// the first of the two writes of RemoveMember, so that the second sees whether
// the user is still an administrator: it removes the user only when they are not,
// which is the last-administrator guard without stating it twice.
//
// Arguments, by number: ?1 user id, ?2 caller id, ?3 the platform
// administrator role.
const removeMemberAdminQuery = `
DELETE FROM org_admins
WHERE user_id = ?1
  AND EXISTS (SELECT 1 FROM users tu
              WHERE tu.id = ?1 AND tu.org_id = org_admins.org_id
                AND ` + callerMayRemoveTarget + `
                AND ` + otherAdminRemains + `)`

// removeMemberQuery takes a user out of their organization, if the caller may
// remove them and they no longer administer it (removeMemberAdminQuery has run
// before it and refused to remove the last administrator). RETURNING gives a row
// when the user was released.
//
// Arguments, by number: ?1 user id, ?2 caller id, ?3 the platform
// administrator role.
const removeMemberQuery = `
UPDATE users AS tu SET org_id = NULL
WHERE tu.id = ?1 AND tu.org_id IS NOT NULL
  AND ` + callerMayRemoveTarget + `
  AND NOT EXISTS (SELECT 1 FROM org_admins ta WHERE ta.org_id = tu.org_id AND ta.user_id = tu.id)
RETURNING id`

// SetMemberAdmin makes a member of a standard organization an administrator of it,
// or stops them being one, as one batch, and returns the member as the write left
// them. The caller must administer the member's organization, or be a platform
// administrator. Promoting an administrator and demoting a member who is not one
// succeed and change nothing.
//
// It returns ErrNotFound when the user belongs to no organization or the caller
// may not see it, ErrNotAdmin when the caller can see it but does not administer
// it, and ErrLastOrgAdmin when demoting would leave the organization without an
// unrevoked administrator.
func (s *Store) SetMemberAdmin(
	ctx context.Context, id input.ID, admin bool, caller, adminRole string, now time.Time,
) (Member, error) {
	o := op{failed: CodeMemberUpdateFailed, rejected: CodeMemberUpdateRejected, description: orgsDescription}

	args := []any{id.String(), caller, adminRole}

	change := Statement{Query: demoteMemberQuery, Args: args}
	if admin {
		change = Statement{Query: promoteMemberQuery, Args: []any{id.String(), caller, adminRole, now.Unix()}}
	}

	return outcome(s.runChecked(ctx, o, Statement{Query: memberStandingQuery, Args: args}, change).
		Then(func(results []Result) (Member, error) {
			return memberBefore(o, results[0].Rows).
				Check(callerAdministers).
				Then(func(before memberStanding) (Member, error) {
					return applied(o, results[1].Rows).
						Then(func(took bool) (Member, error) { return memberChanged(o, before.member, admin, took) }).
						Get()
				}).
				Get()
		}),
	)
}

// memberChanged is the outcome of a promotion or demotion the caller may make:
// the member as the batch left them, or why the change was refused. took is
// whether the change's statement returned its row. A demotion of a member who
// was not an administrator succeeds with nothing to do, and one that matched
// nothing for an administrator is the guard refusing to take the last one.
func memberChanged(o op, member Member, admin, took bool) (Member, error) {
	was := member.Admin
	member.Admin = admin

	switch {
	case took, !admin && !was:
		return member, nil
	case !admin:
		return Member{}, ErrLastOrgAdmin
	default:
		return Member{}, o.defect(fmt.Errorf("%w: a promotion matched nothing for a caller who administers", errChanges))
	}
}

// applied reports whether a write that returns one text column (a user's id or an
// organization's) took effect: it returned its one row. More than one row, or a
// row that is not one text column, is a defect.
func applied(o op, rows [][]any) result.Result[bool] {
	return lookup(rows, o, func(r *row) string { return r.text() }).
		Map(func(wrote found[string]) bool { return wrote.ok })
}

// memberBefore reads the standing statement of a write to a member, which is
// ErrNotFound when it has no row.
func memberBefore(o op, rows [][]any) result.Result[memberStanding] {
	return lookup(rows, o, readMemberStanding).Then(found[memberStanding].orNotFound)
}

// callerAdministers is the guard of a write to a member that only an
// administrator of their organization may make.
func callerAdministers(before memberStanding) error {
	if !before.administer {
		return ErrNotAdmin
	}

	return nil
}

// RemoveMember takes a user out of the organization they belong to, and out of
// its administrators if they are one, as one batch, and returns the member as
// they were, no longer an administrator. The user themself may leave; otherwise
// the caller must administer the organization or be a platform administrator.
//
// It returns ErrNotFound when the user belongs to no organization or the caller
// may not see it, ErrNotAdmin when the caller can see it but is neither the user
// nor an administrator, and ErrLastOrgAdmin when the user is the organization's
// last unrevoked administrator, in which case nothing changed.
func (s *Store) RemoveMember(ctx context.Context, id input.ID, caller, adminRole string) (Member, error) {
	o := op{failed: CodeMemberRemoveFailed, rejected: CodeMemberRemoveRejected, description: orgsDescription}

	args := []any{id.String(), caller, adminRole}

	return outcome(s.runChecked(ctx, o,
		Statement{Query: memberStandingQuery, Args: args},
		Statement{Query: removeMemberAdminQuery, Args: args},
		Statement{Query: removeMemberQuery, Args: args},
	).
		Then(func(results []Result) (Member, error) {
			return memberBefore(o, results[0].Rows).
				Then(func(before memberStanding) (Member, error) {
					return applied(o, results[2].Rows).
						Then(func(took bool) (Member, error) { return memberRemoved(before, took, id.String() == caller) }).
						Get()
				}).
				Get()
		}),
	)
}

// memberRemoved is the outcome of taking a user out of their organization: the
// member as they were, no longer an administrator, or why they stayed. self is
// whether the user was removing themself, who is refused only by the last
// administrator guard and never for not administering.
func memberRemoved(before memberStanding, took, self bool) (Member, error) {
	member := before.member
	member.Admin = false

	switch {
	case took:
		return member, nil
	case !before.administer && !self:
		return Member{}, ErrNotAdmin
	default:
		return Member{}, ErrLastOrgAdmin
	}
}
