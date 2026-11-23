//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package orgs_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/orgs"
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

	// A revoked member who administered the organization is listed as revoked and
	// no longer an administrator: a revoked account counts for nothing.
	revokedAdmin := storedMember(userID, true)
	revokedAdmin.RevokedAt = new(past)

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
		{name: "a revoked administrator is not shown as one", method: http.MethodGet, target: target,
			program: func(s *fakeStore) {
				s.members.value = store.MemberPage{Members: []store.Member{revokedAdmin}}
			},
			status: http.StatusOK, want: line(`{"members":[` + revokedMemberJSON(userID, past) + `]}`),
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

	cases = append(cases, directionRefusals(target, call)...)

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

// directionRefusals are the refusals that do not depend on the direction of the
// change: a revoked caller is unauthenticated whether they promote or demote,
// and a revoked member is a 409 whichever way the store reports it.
func directionRefusals(target string, call func(bool) string) []routeCase {
	cases := make([]routeCase, 0, 8)

	for _, direction := range []bool{true, false} {
		for name, refusal := range map[string]struct {
			err    error
			status int
			body   string
			logged string
		}{
			"the caller was revoked meanwhile": {store.ErrAccountRevoked, http.StatusUnauthorized,
				bodyUnauthenticated, "unauthenticated"},
			"the caller was revoked meanwhile, however the store wraps it": {fmt.Errorf("set: %w", store.ErrAccountRevoked),
				http.StatusUnauthorized, bodyUnauthenticated, "unauthenticated"},
			"the member is revoked": {store.ErrMemberRevoked, http.StatusConflict, bodyMemberRevoked, orgs.CodeMemberRevoked},
			"the member is revoked, however the store wraps it": {fmt.Errorf("set: %w", store.ErrMemberRevoked),
				http.StatusConflict, bodyMemberRevoked, orgs.CodeMemberRevoked},
		} {
			cases = append(cases, routeCase{
				name: fmt.Sprintf("%s (admin=%t)", name, direction), method: http.MethodPatch, target: target,
				body:    fmt.Sprintf(`{"admin":%t}`, direction),
				program: func(s *fakeStore) { s.setAdmin.err = refusal.err },
				status:  refusal.status, want: refusal.body, logged: refusal.logged, calls: []string{call(direction)},
			})
		}
	}

	return cases
}

// revokedMemberJSON is the exact JSON of a member revoked at the given time:
// never an administrator, whatever the stored row says.
func revokedMemberJSON(id string, at int64) string {
	return fmt.Sprintf(`{"id":"%s","orgId":"%s","admin":false,"status":"revoked","createdAt":1700000001,"revokedAt":%d}`,
		id, orgID, at)
}

// TestRevokeMember: {id} is the user's id, the response is the member as
// revoked, and every outcome of the store is its own answer: refusals that tell
// the caller what they may not do (403), what the state does not allow (409), and
// the same 404 for a user who does not exist and one the caller may not see.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRevokeMember(t *testing.T) {
	t.Parallel()

	call := func(id string) string {
		return fmt.Sprintf("RevokeMember id=%s caller=%s role=%s at=%d", id, userID, auth.RoleAdmin, now)
	}

	target := "/api/member/" + otherID

	revoked := func(id string, admin bool) store.Member {
		member := storedMember(id, admin)
		member.RevokedAt = new(exactlyNow)

		return member
	}

	refusal := func(err error, status int, body, logged string) routeCase {
		return routeCase{method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.revokeMember.err = err }, status: status,
			want: body, logged: logged, calls: []string{call(otherID)}}
	}

	cases := []routeCase{
		{name: "revoked", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.revokeMember.value = revoked(otherID, false) },
			status:  http.StatusOK, want: line(revokedMemberJSON(otherID, exactlyNow)), calls: []string{call(otherID)}},
		{name: "an administrator is shown as revoked, and no longer one", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.revokeMember.value = revoked(otherID, true) },
			status:  http.StatusOK, want: line(revokedMemberJSON(otherID, exactlyNow)), calls: []string{call(otherID)}},
		{name: "revoked again, with the earlier time", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) {
				member := storedMember(otherID, false)
				member.RevokedAt = new(past)
				s.revokeMember.value = member
			},
			status: http.StatusOK, want: line(revokedMemberJSON(otherID, past)), calls: []string{call(otherID)}},
		{name: "a platform administrator", method: http.MethodDelete, target: target, role: roleAdmin,
			program: func(s *fakeStore) { s.revokeMember.value = revoked(otherID, false) },
			status:  http.StatusOK, want: line(revokedMemberJSON(otherID, exactlyNow)), calls: []string{call(otherID)}},
	}

	for name, c := range map[string]routeCase{
		"not found": refusal(store.ErrNotFound, http.StatusNotFound, bodyMemberNotFound, "member_not_found"),
		"the caller does not administer the organization": refusal(store.ErrNotAdmin, http.StatusForbidden,
			bodyNotAdmin, "org_admin_required"),
		"the member is a platform administrator": refusal(store.ErrPlatformAdminTarget, http.StatusForbidden,
			errorBody("platform_admin_protected", "only a platform administrator may revoke a platform administrator"),
			"platform_admin_protected"),
		"the caller is the member": refusal(store.ErrSelfRevoke, http.StatusForbidden,
			errorBody("self_revoke_refused", "an organization administrator may not revoke themself"),
			"self_revoke_refused"),
		"the last active platform administrator": refusal(store.ErrLastAdmin, http.StatusConflict,
			errorBody("user_last_admin", "the last active administrator cannot be revoked"), "user_last_admin"),
		"the caller's account was revoked while the request ran": refusal(store.ErrAccountRevoked,
			http.StatusUnauthorized, bodyUnauthenticated, "unauthenticated"),
	} {
		c.name = name
		cases = append(cases, c)
	}

	cases = addFailures(cases, http.MethodDelete, target, "", store.CodeMemberRevokeFailed,
		[]string{call(otherID)}, func(s *fakeStore, err error) { s.revokeMember.err = err })

	cases = append(cases, bodyFailures(http.MethodDelete, "/api/member/"+orgID+"0", []badBody{
		{name: "an id that is too long", body: "", code: input.CodeInvalidID},
	})...)

	runCases(t, cases)
}
