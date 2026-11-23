//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestOrgsActForTheCaller: the organization routes act for the signed-in user.
// Through the real stack, the caller in each statement is the token's account and
// never anything in the request, the platform administrator role is bound as an
// argument (and is the same whatever role the caller has: the write decides), and
// a mutation is one batch of exactly the statements the store declares.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestOrgsActForTheCaller(t *testing.T) {
	t.Parallel()

	const (
		orgRow = "00000000-0000-7000-8000-0000000000c1"
		admin  = "admin"
	)

	tests := []struct {
		name         string
		role         string
		method, path string
		body         string
		// results is the answer to the route's one batch.
		results []store.Result
		status  int
		// statements is how many statements the batch has, and args the
		// arguments of the first.
		statements int
		args       []any
	}{
		{name: "a member lists organizations", role: roleMember, method: http.MethodGet, path: "/api/org?limit=5",
			results: []store.Result{{}}, status: http.StatusOK, statements: 1,
			args: []any{memberID, "g", int64(6), admin}},
		{name: "a platform administrator lists with the same arguments", role: roleAdmin, method: http.MethodGet,
			path: "/api/org?limit=5&caller=" + adminID, results: []store.Result{{}}, status: http.StatusOK,
			statements: 1, args: []any{memberID, "g", int64(6), admin}},
		{name: "reading one organization", role: roleMember, method: http.MethodGet, path: "/api/org/" + someID,
			results: []store.Result{{}}, status: http.StatusNotFound, statements: 1,
			args: []any{someID, memberID, admin}},
		{name: "revoking a member is one batch of five statements", role: roleMember, method: http.MethodDelete,
			path:    "/api/member/" + someID,
			results: []store.Result{{}, {}, {}, {}, {}}, status: http.StatusNotFound, statements: 5,
			args: []any{someID, memberID, admin}},
		{name: "deleting a sandbox is one batch of three", role: roleMember, method: http.MethodDelete,
			path:    "/api/org/" + someID,
			results: []store.Result{{}, {}, {}}, status: http.StatusNotFound, statements: 3,
			args: []any{someID, memberID, admin}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, memberID)

			script := []step{signedIn.activeSessionStep(tt.role)}
			if tt.statements > 0 {
				script = append(script, step{match: "", results: tt.results, err: nil})
			}

			h := newHarness(t, fullEnv(), script...)

			rec := h.do(request{method: tt.method, path: tt.path, body: tt.body, cookies: []*http.Cookie{signedIn.cookie}})
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body)
			}

			if tt.statements == 0 {
				return
			}

			batch := h.exec.calls[1]
			if len(batch) != tt.statements {
				t.Fatalf("batch has %d statements, want %d", len(batch), tt.statements)
			}

			got := batch[0].Args
			if len(got) < len(tt.args) || !sameArgs(got[:len(tt.args)], tt.args) {
				t.Errorf("first statement args = %v, want it to start with %v", got, tt.args)
			}

			if strings.Contains(describe(batch), memberID) || strings.Contains(describe(batch), adminID) {
				t.Errorf("a caller's id is written into the SQL text: %s", describe(batch))
			}
		})
	}
}

// sameArgs reports whether two argument lists are equal.
func sameArgs(got, want []any) bool {
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}

// revokedCallerRoute is a route that writes on behalf of the caller, with the
// statements of the store's one batch for it. The batch ends in the caller's own
// standing (the store's callerStandingQuery), which is what tells a write the
// caller was refused because they are revoked (401) from one they may not see
// (404).
type revokedCallerRoute struct {
	name         string
	role         string
	method, path string
	body         string
	// statements is the size of the route's batch, and notFound the code of the
	// 404 for a caller who may not see what they asked about.
	statements int
	notFound   string
}

// writeRoutes are the routes whose write is refused to a revoked caller.
func writeRoutes() []revokedCallerRoute {
	return []revokedCallerRoute{
		{name: "rename an org", role: roleMember, method: http.MethodPatch, path: "/api/org/" + someID,
			body: `{"name":"New"}`, statements: 3, notFound: "org_not_found"},
		{name: "delete a sandbox", role: roleMember, method: http.MethodDelete, path: "/api/org/" + someID,
			statements: 3, notFound: "org_not_found"},
		{name: "promote a member", role: roleMember, method: http.MethodPatch, path: "/api/member/" + someID,
			body: `{"admin":true}`, statements: 3, notFound: "member_not_found"},
		{name: "demote a member", role: roleMember, method: http.MethodPatch, path: "/api/member/" + someID,
			body: `{"admin":false}`, statements: 3, notFound: "member_not_found"},
		{name: "revoke a member", role: roleMember, method: http.MethodDelete, path: "/api/member/" + someID,
			statements: 5, notFound: "member_not_found"},
		{name: "revoke a user", role: roleAdmin, method: http.MethodDelete, path: "/api/user/" + someID,
			statements: 5, notFound: "user_not_found"},
	}
}

// TestRevokedCallerIsUnauthenticatedOnWrites: through the real stack and the real
// SQL's result handling, a write that matched nothing for a caller whose account
// was revoked after the request was authenticated is a 401 and not the 404 a
// caller who may not see the thing gets, whichever route it is, and the caller's
// standing is told apart from the others': active, and not an account at all,
// are the same 404. Nothing but the one batch is run.
func TestRevokedCallerIsUnauthenticatedOnWrites(t *testing.T) {
	t.Parallel()

	standings := []struct {
		name    string
		rows    [][]any
		status  int
		wantErr string
	}{
		{name: "revoked", rows: [][]any{{int64(1)}}, status: http.StatusUnauthorized, wantErr: "unauthenticated"},
		{name: "active", rows: [][]any{{int64(0)}}, status: http.StatusNotFound},
		{name: "not an account", rows: nil, status: http.StatusNotFound},
	}

	for _, route := range writeRoutes() {
		for _, standing := range standings {
			t.Run(route.name+"/"+standing.name, func(t *testing.T) {
				t.Parallel()

				signedIn := newSession(t, memberID)
				results := batchOf(route.statements)
				results[route.statements-1] = store.Result{Changes: 0, Rows: standing.rows}

				h := newHarness(t, fullEnv(), signedIn.activeSessionStep(route.role),
					step{match: "", results: results, err: nil})

				rec := h.do(request{method: route.method, path: route.path, body: route.body,
					cookies: []*http.Cookie{signedIn.cookie}})

				wantCode := standing.wantErr
				if wantCode == "" {
					wantCode = route.notFound
				}

				if rec.Code != standing.status || !strings.Contains(rec.Body.String(), `"code":"`+wantCode+`"`) {
					t.Errorf("= %d %s, want %d %q", rec.Code, rec.Body, standing.status, wantCode)
				}

				if got := h.exec.callCount(); got != 2 {
					t.Errorf("Exec calls = %d, want the session read and one batch", got)
				}

				// The last statement is the caller's standing, for the token's account.
				batch := h.lastCall()
				if last := batch[len(batch)-1]; len(last.Args) != 1 || last.Args[0] != memberID {
					t.Errorf("the standing statement's args = %v, want only the caller %s", last.Args, memberID)
				}
			})
		}
	}
}

// TestReadsOfARevokedCallerStayNotFound: a read has no standing statement, so a
// caller who sees nothing (a revoked account's reads see nothing) gets the same
// 404 as any caller who may not see it, and an empty page, never a 401. Only a
// write tells the caller why.
func TestReadsOfARevokedCallerStayNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		batch   int
		status  int
		contain string
	}{
		{name: "get an org", path: "/api/org/" + someID, batch: 1, status: http.StatusNotFound, contain: "org_not_found"},
		{name: "list the members of an org", path: "/api/org/" + someID + "/member", batch: 2,
			status: http.StatusNotFound, contain: "org_not_found"},
		{name: "list orgs", path: "/api/org", batch: 1, status: http.StatusOK, contain: `"orgs":[]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, memberID)
			h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleMember),
				step{match: "", results: batchOf(tt.batch), err: nil})

			rec := h.do(request{method: http.MethodGet, path: tt.path, cookies: []*http.Cookie{signedIn.cookie}})
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), tt.contain) {
				t.Errorf("= %d %s, want %d containing %q", rec.Code, rec.Body, tt.status, tt.contain)
			}
		})
	}
}

// errInvitationCreatorGone is what D1 says when the invitation's creator is not
// an unrevoked account at the write (the type column is NULL).
var errInvitationCreatorGone = errors.New(
	"D1_ERROR: NOT NULL constraint failed: invitations.type: SQLITE_CONSTRAINT_NOTNULL")

// errInvitationOrgGone is what D1 says when the organization an invitation
// names does not exist, or is not a standard one, at the write.
var errInvitationOrgGone = errors.New(
	"D1_ERROR: NOT NULL constraint failed: invitation_orgs.org_id: SQLITE_CONSTRAINT_NOTNULL")

// TestInvitationCreateOfARevokedAdmin: through the real stack and store, the
// batch that fails because the creator is revoked at the write is a 401, the
// batch that fails because the organization cannot be named is a 404, and any
// other constraint failure is neither.
func TestInvitationCreateOfARevokedAdmin(t *testing.T) {
	t.Parallel()

	const orgBody = `{"type":"member","numInvites":1,"orgId":"` + someID + `","orgRole":"member"}`

	tests := []struct {
		name   string
		body   string
		err    error
		status int
		code   string
	}{
		{name: "the creator is revoked", body: `{"type":"member","numInvites":1}`, err: errInvitationCreatorGone,
			status: http.StatusUnauthorized, code: "unauthenticated"},
		{name: "the creator is revoked, naming an organization", body: orgBody, err: errInvitationCreatorGone,
			status: http.StatusUnauthorized, code: "unauthenticated"},
		{name: "the organization cannot be named", body: orgBody, err: errInvitationOrgGone,
			status: http.StatusNotFound, code: "org_not_found"},
		{name: "another not-null failure is a defect", body: orgBody, err: errD1NotNull,
			status: http.StatusInternalServerError, code: "internal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, adminID)
			h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleAdmin),
				step{match: "", results: nil, err: store.Classify(tt.err)})

			rec := h.do(request{method: http.MethodPost, path: "/api/invitation", body: tt.body,
				cookies: []*http.Cookie{signedIn.cookie}})
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
				t.Errorf("= %d %s, want %d %q", rec.Code, rec.Body, tt.status, tt.code)
			}

			if strings.Contains(rec.Body.String(), "susu_inv_") {
				t.Errorf("a refused create returned a token: %s", rec.Body)
			}
		})
	}
}

// credentialCase is a credential the access matrix tries on every route that
// changes who administers an organization or who is revoked.
type credentialCase struct {
	name string
	// agent is whether the key belongs to an agent, whose scopes are agentScopes.
	agent       bool
	agentScopes string
	// keyScope is the stored scope list of the key; "" is a session.
	keyScope string
	// holds is the scopes (of those the routes below need) the credential
	// effectively has, written out by hand and not derived from the code.
	holds []scope.Scope
}

// accessRoute is a route of the access matrix.
type accessRoute struct {
	name         string
	method, path string
	body         string
	needs        scope.Scope
	statements   int
}

// TestDefaultUserKeysAndAgentsAtTheRevokingRoutes is the permission-confusion
// table through the real stack: for every route that changes organizations, member
// administration or accounts, every kind of credential, and the role, what the
// boundary does. A session has everything. A user's default key lacks
// member:revoke and the admin scopes, and has them only when it names them. An
// agent is refused (403 forbidden) whenever it holds the scope, whatever it
// holds, and lacks it (403 insufficient_scope) when it does not, so an agent with
// every scope is no more able than one with none. Where the credential is let
// through the store's one batch is run (404 here, for an empty answer), and in
// every refusal nothing but the credential was read.
//
//nolint:funlen // the case tables are the test; splitting them would only scatter the cases
func TestDefaultUserKeysAndAgentsAtTheRevokingRoutes(t *testing.T) {
	t.Parallel()

	routes := []accessRoute{
		{"rename an org", http.MethodPatch, "/api/org/" + someID, `{"name":"New"}`, scope.OrgUpdate, 3},
		{"delete a sandbox", http.MethodDelete, "/api/org/" + someID, "", scope.SandboxRevoke, 3},
		{"set member admin", http.MethodPatch, "/api/member/" + someID, `{"admin":true}`, scope.MemberUpdate, 3},
		{"revoke a member", http.MethodDelete, "/api/member/" + someID, "", scope.MemberRevoke, 5},
		{"revoke a user", http.MethodDelete, "/api/user/" + someID, "", scope.UserRevoke, 5},
	}

	everything := []scope.Scope{
		scope.OrgUpdate, scope.SandboxRevoke, scope.MemberUpdate, scope.MemberRevoke, scope.UserRevoke,
	}
	defaultUser := []scope.Scope{scope.OrgUpdate, scope.SandboxRevoke, scope.MemberUpdate}

	const (
		session     = ""
		userDefault = `["default:user"]`
		agentBundle = `["default:agent"]`
		allNamed    = `["org:update","sandbox:revoke","member:update","member:revoke","user:revoke"]`
		revokers    = `["user:revoke","member:revoke","invitation:create"]`
		sessionAll  = `["default:session"]`
	)

	creds := []credentialCase{
		{name: "a session", agent: false, agentScopes: "", keyScope: session, holds: everything},
		{name: "a user key with no explicit scopes", agent: false, agentScopes: "", keyScope: userDefault,
			holds: defaultUser},
		{name: "a user key naming default:user and member:revoke", agent: false, agentScopes: "",
			keyScope: `["default:user","member:revoke"]`,
			holds:    []scope.Scope{scope.OrgUpdate, scope.SandboxRevoke, scope.MemberUpdate, scope.MemberRevoke}},
		{name: "a user key naming default:user and user:revoke", agent: false, agentScopes: "",
			keyScope: `["default:user","user:revoke"]`,
			holds:    []scope.Scope{scope.OrgUpdate, scope.SandboxRevoke, scope.MemberUpdate, scope.UserRevoke}},
		{name: "a user key naming only member:revoke", agent: false, agentScopes: "", keyScope: `["member:revoke"]`,
			holds: []scope.Scope{scope.MemberRevoke}},
		{name: "a user key naming every scope", agent: false, agentScopes: "", keyScope: allNamed, holds: everything},
		{name: "a user key with the session bundle", agent: false, agentScopes: "", keyScope: sessionAll, holds: everything},
		{name: "an agent holding every scope", agent: true, agentScopes: sessionAll, keyScope: sessionAll, holds: everything},
		{name: "an agent whose scopes are all named", agent: true, agentScopes: allNamed, keyScope: allNamed,
			holds: everything},
		{name: "an agent holding only the revoking scopes", agent: true, agentScopes: revokers, keyScope: revokers,
			holds: []scope.Scope{scope.MemberRevoke, scope.UserRevoke}},
		{name: "an agent whose key is the default user bundle", agent: true, agentScopes: sessionAll,
			keyScope: userDefault, holds: defaultUser},
		{name: "an agent whose agent is the default user bundle", agent: true, agentScopes: userDefault,
			keyScope: sessionAll, holds: defaultUser},
		{name: "an agent with the default agent bundle", agent: true, agentScopes: agentBundle, keyScope: agentBundle,
			holds: nil},
	}

	for _, route := range routes {
		for _, cred := range creds {
			for _, role := range []string{roleAdmin, roleMember} {
				t.Run(route.name+"/"+cred.name+"/"+role, func(t *testing.T) {
					t.Parallel()

					checkAccess(t, route, cred, role)
				})
			}
		}
	}
}

// refusal is what the boundary answers a credential: a status and the code it
// is under, or (calls == 2) nothing, for a request that reached the route.
type refusal struct {
	status int
	code   string
	// calls is how many times the database is called: 1 for the credential's
	// read alone, 2 when the route's batch ran too.
	calls int
}

// expectedAccess is the documented order of the boundary's checks: the role for an
// admin scope, then the scope, then agents.
func expectedAccess(route accessRoute, cred credentialCase, role string) refusal {
	switch {
	case scope.IsAdmin(route.needs) && role != roleAdmin:
		return refusal{status: http.StatusForbidden, code: auth.CodeForbidden, calls: 1}
	case !slices.Contains(cred.holds, route.needs):
		return refusal{status: http.StatusForbidden, code: auth.CodeInsufficientScope, calls: 1}
	case cred.agent:
		return refusal{status: http.StatusForbidden, code: auth.CodeForbidden, calls: 1}
	default:
		return refusal{status: http.StatusNotFound, code: "_not_found", calls: 2}
	}
}

// presented is the first read of the credential and the way the request carries
// it: the session cookie, or the key as a bearer.
func presented(t *testing.T, cred credentialCase, role string) (step, request) {
	t.Helper()

	if cred.keyScope == "" {
		signedIn := newSession(t, adminID)

		return signedIn.activeSessionStep(role), request{cookies: []*http.Cookie{signedIn.cookie}}
	}

	key := newAPIKey(t)
	agentID := ""

	if cred.agent {
		agentID = agentRowID
	}

	return key.keyStep(adminID, role, agentID, cred.agentScopes, cred.keyScope), request{headers: key.headers}
}

// checkAccess sends the route's request with the credential as role, and checks
// the boundary's answer and how far the request got.
func checkAccess(t *testing.T, route accessRoute, cred credentialCase, role string) {
	t.Helper()

	first, req := presented(t, cred, role)
	req.method, req.path, req.body = route.method, route.path, route.body

	want := expectedAccess(route, cred, role)

	script := []step{first}
	if want.calls == 2 {
		script = append(script, step{match: "", results: batchOf(route.statements), err: nil})
	}

	h := newHarness(t, fullEnv(), script...)

	rec := h.do(req)
	// What runs is the route's own 404 for an empty answer, whose code ends in
	// _not_found, and a refusal of the boundary is its code.
	if rec.Code != want.status || !strings.Contains(rec.Body.String(), want.code) {
		t.Errorf("= %d %s, want %d containing %q", rec.Code, rec.Body, want.status, want.code)
	}

	if got := h.exec.callCount(); got != want.calls {
		t.Errorf("Exec calls = %d, want %d", got, want.calls)
	}
}
