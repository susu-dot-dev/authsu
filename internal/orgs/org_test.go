//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package orgs_test

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// routeCase is one request to a route, with the store programmed to answer it
// and what the client and the store must see.
type routeCase struct {
	name string
	// method, target and body are the request. role is the signed-in account's
	// role, roleMember when empty.
	method, target, body string
	role                 string
	// program sets the store's outcomes.
	program func(*fakeStore)
	status  int
	// body is the exact response body.
	want string
	// logged is the code of the error the boundary logged, "" for a success.
	logged string
	// calls are the store calls that must have been made, in order.
	calls []string
}

// runCases signs in as userID and sends each case's request once.
func runCases(t *testing.T, cases []routeCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)

			role := tc.role
			if role == "" {
				role = roleMember
			}

			cookie := rg.signIn(userID, role)

			if tc.program != nil {
				tc.program(rg.store)
			}

			rec := rg.as(cookie, tc.method, tc.target, tc.body)

			if tc.want == "" {
				// A refusal that carries a message of the parser's: its status, its
				// code in the body and in the log, and nothing else is the case.
				wantRefusal(t, rg, rec, tc.status, tc.logged)
			} else {
				wantResponse(t, rg, rec, tc.status, tc.want, tc.logged)
			}

			wantCalls(t, rg.store.calls, tc.calls)
		})
	}
}

// itoa formats an integer as JSON writes it.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// orgJSON is the exact JSON of an organization.
func orgJSON(id, kind, name string, expires *int64, status string) string {
	out := `{"id":"` + id + `","kind":"` + kind + `","name":"` + name + `","createdBy":"` + userID +
		`","createdAt":1700000000`

	if expires != nil {
		out += `,"expiresAt":` + itoa(*expires)
	}

	return out + `,"status":"` + status + `"}`
}

// activeOrgJSON is the JSON of storedOrg(id): an active standard organization.
func activeOrgJSON(id string) string {
	return orgJSON(id, "standard", "Acme", nil, "active")
}

// line is a response body: one JSON document and the newline the writer adds.
func line(document string) string { return document + "\n" }

// The exact bodies of the failures the organization routes map the store's
// outcomes to.
const (
	bodyNotAdmin = `{"error":{"code":"org_admin_required","message":"administering the organization is required"}}` + "\n"
	bodyExpired  = `{"error":{"code":"sandbox_expired","message":"the sandbox has expired"}}` + "\n"
	bodyNotStd   = `{"error":{"code":"org_not_standard","message":"a sandbox has no members"}}` + "\n"
	bodyNotSbx   = `{"error":{"code":"org_not_sandbox","message":"only a sandbox can be deleted"}}` + "\n"
	bodyLastOrg  = `{"error":{"code":"org_last_admin","message":"an organization must keep an administrator"}}` + "\n"
	bodySbxLimit = `{"error":{"code":"sandbox_limit_reached",` +
		`"message":"a user may hold a limited number of sandboxes"}}` + "\n"
)

// storeFailures are the failures of the store that every route passes through as
// they are: a database that is down (503 under the operation's code) and an
// error nobody classified (500). set programs the operation under test.
func storeFailures(code string) []struct {
	name   string
	err    error
	status int
	want   string
	logged string
} {
	return []struct {
		name   string
		err    error
		status int
		want   string
		logged string
	}{
		{name: "the database is down", err: unavailable(code), status: http.StatusServiceUnavailable,
			want: bodyUnavailable(code), logged: code},
		{name: "an unclassified failure", err: errIO, status: http.StatusInternalServerError, want: bodyInternal,
			logged: "internal"},
	}
}

// addFailures appends the shared failure cases for a route to cases.
func addFailures(
	cases []routeCase, method, target, body, code string, calls []string, set func(*fakeStore, error),
) []routeCase {
	for _, failure := range storeFailures(code) {
		err := failure.err

		cases = append(cases, routeCase{
			name: failure.name, method: method, target: target, body: body, role: "",
			program: func(s *fakeStore) { set(s, err) }, status: failure.status, want: failure.want,
			logged: failure.logged, calls: calls,
		})
	}

	return cases
}

// TestCreateSandbox: POST /api/org creates a sandbox and nothing else. The name is
// parsed, the limit and the expiry are the server's, and every outcome of the
// store is its own answer. A kind is not a field of the request: no body can ask
// for a standard organization.
func TestCreateSandbox(t *testing.T) {
	t.Parallel()

	const target = "/api/org"

	call := fmt.Sprintf("CreateSandbox id=%s name=Scratch creator=%s expires=%d limit=25 at=%d",
		newID, userID, inAWeek, now)

	cases := []routeCase{
		{name: "a sandbox", method: http.MethodPost, target: target, body: `{"name":"Scratch"}`,
			program: func(s *fakeStore) { s.create = reply[store.Org]{value: storedSandbox(newID, inAWeek)} },
			status:  http.StatusCreated,
			want:    line(orgJSON(newID, "sandbox", "Scratch", new(inAWeek), "active")), calls: []string{call}},
		{name: "a platform administrator creates like anyone", method: http.MethodPost, target: target,
			role: roleAdmin, body: `{"name":"Scratch"}`,
			program: func(s *fakeStore) { s.create = reply[store.Org]{value: storedSandbox(newID, inAWeek)} },
			status:  http.StatusCreated,
			want:    line(orgJSON(newID, "sandbox", "Scratch", new(inAWeek), "active")), calls: []string{call}},
		{name: "the sandbox limit", method: http.MethodPost, target: target, body: `{"name":"Scratch"}`,
			program: func(s *fakeStore) { s.create.err = store.ErrSandboxLimit },
			status:  http.StatusConflict, want: bodySbxLimit, logged: "sandbox_limit_reached", calls: []string{call}},
		{name: "the account was revoked meanwhile", method: http.MethodPost, target: target,
			body:    `{"name":"Scratch"}`,
			program: func(s *fakeStore) { s.create.err = store.ErrAccountRevoked },
			status:  http.StatusUnauthorized, want: bodyUnauthenticated, logged: "unauthenticated",
			calls: []string{call}},
	}

	cases = addFailures(cases, http.MethodPost, target, `{"name":"Scratch"}`, store.CodeOrgCreateFailed,
		[]string{call}, func(s *fakeStore, err error) { s.create.err = err })

	cases = append(cases, bodyFailures(http.MethodPost, target, []badBody{
		{name: "a kind of standard", body: `{"kind":"standard","name":"Acme"}`, code: "unknown_field"},
		{name: "a kind of sandbox", body: `{"kind":"sandbox","name":"Scratch"}`, code: "unknown_field"},
		{name: "no name", body: `{}`, code: input.CodeInvalidOrgName},
		{name: "an empty name", body: `{"name":""}`, code: input.CodeInvalidOrgName},
		{name: "a name with a control character", body: `{"name":"a\u0000b"}`, code: input.CodeInvalidOrgName},
		{name: "a name of 257 characters", body: `{"name":"` + strings.Repeat("x", 257) + `"}`,
			code: input.CodeInvalidOrgName},
		{name: "a name that is not text", body: `{"name":1}`, code: "invalid_field_type"},
		{name: "an unknown field", body: `{"name":"Acme","expiresAt":1}`, code: "unknown_field"},
		{name: "a repeated field", body: `{"name":"Acme","name":"Acme"}`, code: "duplicate_field"},
		{name: "an empty body", body: ``, code: "empty_body"},
		{name: "not JSON", body: `{`, code: "invalid_json"},
		{name: "trailing data", body: `{"name":"Acme"} {}`, code: "trailing_data"},
	})...)

	runCases(t, cases)
}

// badBody is a request body a route refuses before it reaches the store.
type badBody struct {
	name string
	body string
	code string
}

// bodyFailures are the cases of bodies a route refuses with a 400 and its code,
// without calling the store.
func bodyFailures(method, target string, bodies []badBody) []routeCase {
	cases := make([]routeCase, 0, len(bodies))

	for _, bad := range bodies {
		cases = append(cases, routeCase{
			name: "refuses " + bad.name, method: method, target: target, body: bad.body, role: "", program: nil,
			status: http.StatusBadRequest, want: "", logged: bad.code, calls: nil,
		})
	}

	return cases
}

// TestRenameOrg: the name is parsed, the id is the path's, and every outcome of
// the store is its own answer.
func TestRenameOrg(t *testing.T) {
	t.Parallel()

	target := "/api/org/" + orgID
	call := fmt.Sprintf("RenameOrg id=%s name=New caller=%s role=%s at=%d", orgID, userID, auth.RoleAdmin, now)

	renamed := storedOrg(orgID)
	renamed.Name = "New"

	cases := []routeCase{
		{name: "renamed", method: http.MethodPatch, target: target, body: `{"name":"New"}`,
			program: func(s *fakeStore) { s.rename.value = renamed }, status: http.StatusOK,
			want: line(orgJSON(orgID, "standard", "New", nil, "active")), calls: []string{call}},
		{name: "a sandbox that has expired is shown as expired", method: http.MethodPatch, target: target,
			body: `{"name":"New"}`,
			program: func(s *fakeStore) {
				s.rename.value = storedSandbox(orgID, past)
			},
			status: http.StatusOK,
			want:   line(orgJSON(orgID, "sandbox", "Scratch", new(past), "expired")),
			calls:  []string{call}},
		{name: "not found", method: http.MethodPatch, target: target, body: `{"name":"New"}`,
			program: func(s *fakeStore) { s.rename.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyOrgNotFound, logged: "org_not_found", calls: []string{call}},
		{name: "the caller is not an administrator", method: http.MethodPatch, target: target, body: `{"name":"New"}`,
			program: func(s *fakeStore) { s.rename.err = store.ErrNotAdmin }, status: http.StatusForbidden,
			want: bodyNotAdmin, logged: "org_admin_required", calls: []string{call}},
		{name: "the sandbox has expired", method: http.MethodPatch, target: target, body: `{"name":"New"}`,
			program: func(s *fakeStore) { s.rename.err = store.ErrExpired }, status: http.StatusConflict,
			want: bodyExpired, logged: "sandbox_expired", calls: []string{call}},
		{name: "the account was revoked meanwhile", method: http.MethodPatch, target: target, body: `{"name":"New"}`,
			program: func(s *fakeStore) { s.rename.err = store.ErrAccountRevoked }, status: http.StatusUnauthorized,
			want: bodyUnauthenticated, logged: "unauthenticated", calls: []string{call}},
		{name: "the account was revoked meanwhile, however the store wraps it", method: http.MethodPatch, target: target,
			body:    `{"name":"New"}`,
			program: func(s *fakeStore) { s.rename.err = fmt.Errorf("rename: %w", store.ErrAccountRevoked) },
			status:  http.StatusUnauthorized, want: bodyUnauthenticated, logged: "unauthenticated",
			calls: []string{call}},
	}

	cases = addFailures(cases, http.MethodPatch, target, `{"name":"New"}`, store.CodeOrgUpdateFailed, []string{call},
		func(s *fakeStore, err error) { s.rename.err = err })

	cases = append(cases, bodyFailures(http.MethodPatch, target, []badBody{
		{name: "no name", body: `{}`, code: input.CodeInvalidOrgName},
		{name: "an empty name", body: `{"name":""}`, code: input.CodeInvalidOrgName},
		{name: "a kind", body: `{"name":"New","kind":"sandbox"}`, code: "unknown_field"},
		{name: "an empty body", body: ``, code: "empty_body"},
	})...)
	cases = append(cases, bodyFailures(http.MethodPatch, "/api/org/not-an-id", []badBody{
		{name: "an id that is not an id", body: `{"name":"New"}`, code: input.CodeInvalidID},
	})...)

	runCases(t, cases)
}

// TestDeleteSandbox: a sandbox is deleted and shown as deleted, and a standard
// organization is refused, to a caller who can see it.
func TestDeleteSandbox(t *testing.T) {
	t.Parallel()

	target := "/api/org/" + orgID
	call := fmt.Sprintf("DeleteSandbox id=%s caller=%s role=%s", orgID, userID, auth.RoleAdmin)

	cases := []routeCase{
		{name: "a sandbox is deleted", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.remove.value = storedSandbox(orgID, future) },
			status:  http.StatusOK,
			want:    line(orgJSON(orgID, "sandbox", "Scratch", new(future), "deleted")),
			calls:   []string{call}},
		{name: "an expired sandbox is deleted, and shown as deleted", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.remove.value = storedSandbox(orgID, past) },
			status:  http.StatusOK,
			want:    line(orgJSON(orgID, "sandbox", "Scratch", new(past), "deleted")),
			calls:   []string{call}},
		{name: "a platform administrator deletes like an administrator", method: http.MethodDelete, target: target,
			role:    roleAdmin,
			program: func(s *fakeStore) { s.remove.value = storedSandbox(orgID, future) },
			status:  http.StatusOK,
			want:    line(orgJSON(orgID, "sandbox", "Scratch", new(future), "deleted")),
			calls:   []string{call}},
		{name: "not found", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.remove.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyOrgNotFound, logged: "org_not_found", calls: []string{call}},
		{name: "the caller is not an administrator", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.remove.err = store.ErrNotAdmin }, status: http.StatusForbidden,
			want: bodyNotAdmin, logged: "org_admin_required", calls: []string{call}},
		{name: "a standard organization is never deleted", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.remove.err = store.ErrNotSandbox }, status: http.StatusConflict,
			want: bodyNotSbx, logged: "org_not_sandbox", calls: []string{call}},
		{name: "the account was revoked meanwhile", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.remove.err = store.ErrAccountRevoked }, status: http.StatusUnauthorized,
			want: bodyUnauthenticated, logged: "unauthenticated", calls: []string{call}},
	}

	cases = addFailures(cases, http.MethodDelete, target, "", store.CodeOrgDeleteFailed, []string{call},
		func(s *fakeStore, err error) { s.remove.err = err })

	cases = append(cases, bodyFailures(http.MethodDelete, "/api/org/"+strings.ToUpper(orgID), []badBody{
		{name: "an id in upper case", body: "", code: input.CodeInvalidID},
	})...)

	runCases(t, cases)
}

// TestGetOrg: the organizations the caller may see, shown with the status the
// clock decides.
func TestGetOrg(t *testing.T) {
	t.Parallel()

	target := "/api/org/" + orgID
	call := fmt.Sprintf("GetOrg id=%s caller=%s role=%s", orgID, userID, auth.RoleAdmin)

	cases := []routeCase{
		{name: "a standard organization", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.get.value = storedOrg(orgID) }, status: http.StatusOK,
			want: line(activeOrgJSON(orgID)), calls: []string{call}},
		{name: "a sandbox that has not expired", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.get.value = storedSandbox(orgID, future) }, status: http.StatusOK,
			want:  line(orgJSON(orgID, "sandbox", "Scratch", new(future), "active")),
			calls: []string{call}},
		{name: "a sandbox that expires this very second is expired", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.get.value = storedSandbox(orgID, exactlyNow) }, status: http.StatusOK,
			want:  line(orgJSON(orgID, "sandbox", "Scratch", new(exactlyNow), "expired")),
			calls: []string{call}},
		{name: "a sandbox that has expired", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.get.value = storedSandbox(orgID, past) }, status: http.StatusOK,
			want:  line(orgJSON(orgID, "sandbox", "Scratch", new(past), "expired")),
			calls: []string{call}},
		{name: "not found", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.get.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyOrgNotFound, logged: "org_not_found", calls: []string{call}},
	}

	cases = addFailures(cases, http.MethodGet, target, "", store.CodeOrgLookupFailed, []string{call},
		func(s *fakeStore, err error) { s.get.err = err })

	runCases(t, cases)
}

// TestListOrgs: one page, with the cursor and the limit parsed and handed on.
func TestListOrgs(t *testing.T) {
	t.Parallel()

	call := func(cursor string, limit int) string {
		return fmt.Sprintf("ListOrgs caller=%s role=%s cursor=%s limit=%d", userID, auth.RoleAdmin, cursor, limit)
	}

	page := store.OrgPage{Orgs: []store.Org{storedOrg(orgID), storedSandbox(sandboxID, future)}, Next: sandboxID}

	cases := []routeCase{
		{name: "the first page, with a next", method: http.MethodGet, target: "/api/org",
			program: func(s *fakeStore) { s.list.value = page }, status: http.StatusOK,
			want: line(`{"orgs":[` + activeOrgJSON(orgID) + `,` +
				orgJSON(sandboxID, "sandbox", "Scratch", new(future), "active") +
				`],"next":"` + sandboxID + `"}`),
			calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "the last page has no next", method: http.MethodGet, target: "/api/org?limit=100&cursor=" + cursorID,
			program: func(s *fakeStore) { s.list.value = store.OrgPage{Orgs: []store.Org{storedOrg(orgID)}} },
			status:  http.StatusOK, want: line(`{"orgs":[` + activeOrgJSON(orgID) + `]}`),
			calls: []string{call(cursorID, 100)}},
		{name: "nothing is an empty list, not null", method: http.MethodGet, target: "/api/org",
			status: http.StatusOK, want: line(`{"orgs":[]}`), calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "a platform administrator asks the same", method: http.MethodGet, target: "/api/org", role: roleAdmin,
			status: http.StatusOK, want: line(`{"orgs":[]}`), calls: []string{call("-", input.DefaultPageLimit)}},
	}

	cases = addFailures(cases, http.MethodGet, "/api/org", "", store.CodeOrgListFailed,
		[]string{call("-", input.DefaultPageLimit)}, func(s *fakeStore, err error) { s.list.err = err })

	cases = append(cases, queryFailures("/api/org")...)

	runCases(t, cases)
}

// queryFailures are the page parameters a list refuses with a 400, whatever it
// lists, without calling the store.
func queryFailures(path string) []routeCase {
	bad := []badBody{
		{name: "a limit of zero", body: "?limit=0", code: input.CodeInvalidLimit},
		{name: "a limit above the maximum", body: "?limit=101", code: input.CodeInvalidLimit},
		{name: "a limit that is not a number", body: "?limit=ten", code: input.CodeInvalidLimit},
		{name: "a repeated limit", body: "?limit=1&limit=2", code: input.CodeInvalidLimit},
		{name: "a cursor that is not an id", body: "?cursor=abc", code: input.CodeInvalidCursor},
		{name: "an empty cursor", body: "?cursor=", code: input.CodeInvalidCursor},
		{name: "a repeated cursor", body: "?cursor=" + cursorID + "&cursor=" + cursorID, code: input.CodeInvalidCursor},
	}

	cases := make([]routeCase, 0, len(bad))

	for _, query := range bad {
		cases = append(cases, routeCase{
			name: "refuses " + query.name, method: http.MethodGet, target: path + query.body, body: "", role: "",
			program: nil, status: http.StatusBadRequest, want: "", logged: query.code, calls: nil,
		})
	}

	return cases
}
