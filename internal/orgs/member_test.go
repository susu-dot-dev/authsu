//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package orgs_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// memberJSON is the exact JSON of storedMember(id, admin), active.
func memberJSON(id string, admin bool) string {
	return fmt.Sprintf(`{"id":"%s","orgId":"%s","admin":%t,"status":"active","createdAt":1700000001}`, id, orgID, admin)
}

// TestListMembers: one page of the members of the organization in the path,
// with their administrator flag and whether their account is revoked.
func TestListMembers(t *testing.T) {
	t.Parallel()

	target := "/api/org/" + orgID + "/member"
	call := func(cursor string, limit int) string {
		return fmt.Sprintf("ListMembers id=%s caller=%s role=%s cursor=%s limit=%d",
			orgID, userID, auth.RoleAdmin, cursor, limit)
	}

	revoked := storedMember(otherID, false)
	revoked.RevokedAt = new(past)

	cases := []routeCase{
		{name: "a page with a next", method: http.MethodGet, target: target,
			program: func(s *fakeStore) {
				s.members.value = store.MemberPage{
					Members: []store.Member{storedMember(userID, true), revoked}, Next: otherID,
				}
			},
			status: http.StatusOK,
			want: line(`{"members":[` + memberJSON(userID, true) + `,{"id":"` + otherID + `","orgId":"` + orgID +
				`","admin":false,"status":"revoked","createdAt":1700000001,"revokedAt":` + itoa(past) + `}],"next":"` +
				otherID + `"}`),
			calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "the last page", method: http.MethodGet, target: target + "?limit=1&cursor=" + cursorID,
			program: func(s *fakeStore) {
				s.members.value = store.MemberPage{Members: []store.Member{storedMember(userID, false)}}
			},
			status: http.StatusOK, want: line(`{"members":[` + memberJSON(userID, false) + `]}`),
			calls: []string{call(cursorID, 1)}},
		{name: "nobody is an empty list, not null", method: http.MethodGet, target: target,
			status: http.StatusOK, want: line(`{"members":[]}`), calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "an organization the caller may not see", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.members.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyOrgNotFound, logged: "org_not_found", calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "a sandbox has no members", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.members.err = store.ErrNotStandard }, status: http.StatusConflict,
			want: bodyNotStd, logged: "org_not_standard", calls: []string{call("-", input.DefaultPageLimit)}},
	}

	cases = addFailures(cases, http.MethodGet, target, "", store.CodeMemberListFailed,
		[]string{call("-", input.DefaultPageLimit)}, func(s *fakeStore, err error) { s.members.err = err })

	cases = append(cases, queryFailures(target)...)

	runCases(t, cases)
}

// TestSetMemberAdmin: {id} is the user's id, the body says whether they are to
// administer, and every outcome of the store is its own answer.
func TestSetMemberAdmin(t *testing.T) {
	t.Parallel()

	target := "/api/member/" + otherID
	call := func(admin bool) string {
		return fmt.Sprintf("SetMemberAdmin id=%s admin=%t caller=%s role=%s at=%d",
			otherID, admin, userID, auth.RoleAdmin, now)
	}

	cases := []routeCase{
		{name: "promoted", method: http.MethodPatch, target: target, body: `{"admin":true}`,
			program: func(s *fakeStore) { s.setAdmin.value = storedMember(otherID, true) },
			status:  http.StatusOK, want: line(memberJSON(otherID, true)), calls: []string{call(true)}},
		{name: "demoted", method: http.MethodPatch, target: target, body: `{"admin":false}`,
			program: func(s *fakeStore) { s.setAdmin.value = storedMember(otherID, false) },
			status:  http.StatusOK, want: line(memberJSON(otherID, false)), calls: []string{call(false)}},
		{name: "a platform administrator", method: http.MethodPatch, target: target, body: `{"admin":true}`,
			role:    roleAdmin,
			program: func(s *fakeStore) { s.setAdmin.value = storedMember(otherID, true) },
			status:  http.StatusOK, want: line(memberJSON(otherID, true)), calls: []string{call(true)}},
		{name: "not found", method: http.MethodPatch, target: target, body: `{"admin":true}`,
			program: func(s *fakeStore) { s.setAdmin.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyMemberNotFound, logged: "member_not_found", calls: []string{call(true)}},
		{name: "the caller is not an administrator", method: http.MethodPatch, target: target, body: `{"admin":true}`,
			program: func(s *fakeStore) { s.setAdmin.err = store.ErrNotAdmin }, status: http.StatusForbidden,
			want: bodyNotAdmin, logged: "org_admin_required", calls: []string{call(true)}},
		{name: "the last administrator", method: http.MethodPatch, target: target, body: `{"admin":false}`,
			program: func(s *fakeStore) { s.setAdmin.err = store.ErrLastOrgAdmin }, status: http.StatusConflict,
			want: bodyLastOrg, logged: "org_last_admin", calls: []string{call(false)}},
	}

	cases = addFailures(cases, http.MethodPatch, target, `{"admin":true}`, store.CodeMemberUpdateFailed,
		[]string{call(true)}, func(s *fakeStore, err error) { s.setAdmin.err = err })

	cases = append(cases, bodyFailures(http.MethodPatch, target, []badBody{
		{name: "no admin", body: `{}`, code: "missing_admin"},
		{name: "a null admin", body: `{"admin":null}`, code: "missing_admin"},
		{name: "an admin that is not a flag", body: `{"admin":"yes"}`, code: "invalid_field_type"},
		{name: "an admin that is a number", body: `{"admin":1}`, code: "invalid_field_type"},
		{name: "another field", body: `{"admin":true,"orgId":"` + orgID + `"}`, code: "unknown_field"},
		{name: "an empty body", body: ``, code: "empty_body"},
	})...)
	cases = append(cases, bodyFailures(http.MethodPatch, "/api/member/x", []badBody{
		{name: "an id that is not an id", body: `{"admin":true}`, code: input.CodeInvalidID},
	})...)

	runCases(t, cases)
}

// TestRemoveMember: {id} is the user's id, and the same route is leaving.
func TestRemoveMember(t *testing.T) {
	t.Parallel()

	call := func(id string) string {
		return fmt.Sprintf("RemoveMember id=%s caller=%s role=%s", id, userID, auth.RoleAdmin)
	}

	cases := []routeCase{
		{name: "removed", method: http.MethodDelete, target: "/api/member/" + otherID,
			program: func(s *fakeStore) { s.removeMember.value = storedMember(otherID, false) },
			status:  http.StatusOK, want: line(memberJSON(otherID, false)), calls: []string{call(otherID)}},
		{name: "leaving", method: http.MethodDelete, target: "/api/member/" + userID,
			program: func(s *fakeStore) { s.removeMember.value = storedMember(userID, false) },
			status:  http.StatusOK, want: line(memberJSON(userID, false)), calls: []string{call(userID)}},
		{name: "not found", method: http.MethodDelete, target: "/api/member/" + otherID,
			program: func(s *fakeStore) { s.removeMember.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyMemberNotFound, logged: "member_not_found", calls: []string{call(otherID)}},
		{name: "the caller is not an administrator", method: http.MethodDelete, target: "/api/member/" + otherID,
			program: func(s *fakeStore) { s.removeMember.err = store.ErrNotAdmin }, status: http.StatusForbidden,
			want: bodyNotAdmin, logged: "org_admin_required", calls: []string{call(otherID)}},
		{name: "the last administrator", method: http.MethodDelete, target: "/api/member/" + userID,
			program: func(s *fakeStore) { s.removeMember.err = store.ErrLastOrgAdmin }, status: http.StatusConflict,
			want: bodyLastOrg, logged: "org_last_admin", calls: []string{call(userID)}},
	}

	cases = addFailures(cases, http.MethodDelete, "/api/member/"+otherID, "", store.CodeMemberRemoveFailed,
		[]string{call(otherID)}, func(s *fakeStore, err error) { s.removeMember.err = err })

	cases = append(cases, bodyFailures(http.MethodDelete, "/api/member/"+orgID+"0", []badBody{
		{name: "an id that is too long", body: "", code: input.CodeInvalidID},
	})...)

	runCases(t, cases)
}
