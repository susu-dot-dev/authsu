//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package orgs_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/orgs"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// catalogRoute is one route as a client calls it.
type catalogRoute struct {
	name   string
	method string
	// path is the declared path, with its {id} wildcard.
	path string
	// target is the request target, called for the ids of the fixtures.
	target string
	// body is a body the route accepts, or "".
	body  string
	scope scope.Scope
	// reads is true for a route an agent may use when its scopes allow, and false
	// for one that refuses every agent.
	reads bool
	// limit is the body cap the route must declare.
	limit int64
}

const (
	bodyCap  = 8 << 10
	smallCap = 1 << 10
)

// catalog is every route the package declares, in the order Routes returns them.
func catalog() []catalogRoute {
	return []catalogRoute{
		{name: "create sandbox", method: http.MethodPost, path: "/api/org", target: "/api/org",
			body: `{"name":"Scratch"}`, scope: scope.SandboxCreate, reads: false, limit: bodyCap},
		{name: "list orgs", method: http.MethodGet, path: "/api/org", target: "/api/org",
			scope: scope.OrgRead, reads: true, limit: smallCap},
		{name: "get org", method: http.MethodGet, path: "/api/org/{id}", target: "/api/org/" + orgID,
			scope: scope.OrgRead, reads: true, limit: smallCap},
		{name: "rename org", method: http.MethodPatch, path: "/api/org/{id}", target: "/api/org/" + orgID,
			body: `{"name":"New"}`, scope: scope.OrgUpdate, reads: false, limit: bodyCap},
		{name: "delete sandbox", method: http.MethodDelete, path: "/api/org/{id}", target: "/api/org/" + orgID,
			scope: scope.SandboxRevoke, reads: false, limit: smallCap},
		{name: "list members", method: http.MethodGet, path: "/api/org/{id}/member", target: "/api/org/" + orgID + "/member",
			scope: scope.MemberRead, reads: true, limit: smallCap},
		{name: "set member admin", method: http.MethodPatch, path: "/api/member/{id}", target: "/api/member/" + otherID,
			body: `{"admin":true}`, scope: scope.MemberUpdate, reads: false, limit: smallCap},
		{name: "revoke member", method: http.MethodDelete, path: "/api/member/{id}", target: "/api/member/" + otherID,
			scope: scope.MemberRevoke, reads: false, limit: smallCap},
	}
}

// TestRouteDeclarations is the permission-confusion test: each route is the
// method and path that is documented, needs a credential and exactly its own
// scope, refuses agents unless it only reads, and never opts in to a sandbox.
// None is an admin scope: who looks after an organization is decided by the
// store, so a member's credential is never turned away by the role gate.
func TestRouteDeclarations(t *testing.T) {
	t.Parallel()

	declared := orgs.Routes(orgs.Deps{Store: &fakeStore{}, Now: time.Now, NewID: func() string { return newID }})

	cases := catalog()
	if len(declared) != len(cases) {
		t.Fatalf("Routes declares %d routes, want %d", len(declared), len(cases))
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			checkDeclared(t, declared[i], tc)
		})
	}
}

// checkDeclared checks one declared route against its catalog entry.
func checkDeclared(t *testing.T, got auth.Route, tc catalogRoute) {
	t.Helper()

	if got.Method != tc.method || got.Path != tc.path {
		t.Errorf("route = %s %s, want %s %s", got.Method, got.Path, tc.method, tc.path)
	}

	want := auth.Needs(tc.scope)
	if !tc.reads {
		want = want.WithoutAgents()
	}

	if got.Credential != auth.Authenticated || got.Access != want {
		t.Errorf("Credential = %v, Access = %+v, want Authenticated and %+v", got.Credential, got.Access, want)
	}

	if got.Access.SandboxOK {
		t.Error("the route opts in to a sandbox, which no organization route may")
	}

	if scope.IsAdmin(tc.scope) {
		t.Errorf("%s is an admin scope: who administers an organization is the store's to decide", tc.scope)
	}

	if got.Handle == nil || got.MaxBody != tc.limit {
		t.Errorf("Handle nil = %t, MaxBody = %d, want a handler and %d", got.Handle == nil, got.MaxBody, tc.limit)
	}
}

// TestRoutesRefuseMissingDependencies: there is no degraded mode, so a
// deployment that is missing a dependency fails at construction.
func TestRoutesRefuseMissingDependencies(t *testing.T) {
	t.Parallel()

	id := func() string { return newID }

	cases := []struct {
		name string
		deps orgs.Deps
	}{
		{name: "no store", deps: orgs.Deps{Store: nil, Now: time.Now, NewID: id}},
		{name: "no clock", deps: orgs.Deps{Store: &fakeStore{}, Now: nil, NewID: id}},
		{name: "no id source", deps: orgs.Deps{Store: &fakeStore{}, Now: time.Now, NewID: nil}},
		{name: "nothing", deps: orgs.Deps{Store: nil, Now: nil, NewID: nil}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("Routes did not panic")
				}
			}()

			orgs.Routes(tc.deps)
		})
	}
}

// outcome is what the boundary must answer a credential, by route kind.
type outcome struct {
	// status is the refusal's status, and code the code it is logged under;
	// status 0 means the route runs and the store is asked once.
	status int
	code   string
}

// callerKind is a kind of credential the matrix signs in with.
type callerKind struct {
	name string
	send func(r *rig, route catalogRoute) request
	// outcome says what the boundary must answer on a route that changes
	// something, and reading what it must answer on one that only reads.
	changing, reading outcome
}

// TestCredentialMatrix is the boundary seen through every route: a credential
// that is not enough for the route never reaches the store, and one that is does.
// For each route it signs in as each kind of caller, and asserts the status, the
// error code and whether the store was called.
func TestCredentialMatrix(t *testing.T) {
	t.Parallel()

	for _, route := range catalog() {
		for _, caller := range callerKinds() {
			t.Run(route.name+"/"+caller.name, func(t *testing.T) {
				t.Parallel()

				want := caller.changing
				if route.reads {
					want = caller.reading
				}

				rg := newRig(t)
				rec := rg.serve(caller.send(rg, route))

				if want.status == 0 {
					// The route ran: the store was asked exactly once.
					if len(rg.store.calls) != 1 {
						t.Errorf("store calls = %q (status %d), want exactly one", rg.store.calls, rec.Code)
					}

					return
				}

				if rec.Code != want.status || len(rg.logged) != 1 || rg.logged[0].Code != want.code {
					t.Errorf("= %d, logged %v; want %d %q", rec.Code, rg.logged, want.status, want.code)
				}

				wantCalls(t, rg.store.calls, nil)
			})
		}
	}
}

// scopes is a scope list of the given scopes.
func scopes(names ...scope.Scope) scope.List {
	list := make(scope.List, 0, len(names))

	for _, name := range names {
		list = append(list, string(name))
	}

	return list
}

// keyed is a request signed with the key spec makes of the route.
func keyed(r *rig, route catalogRoute, spec keySpec) request {
	return request{method: route.method, target: route.target, body: route.body, authorization: r.signInKey(spec)}
}

// callerKinds are the credentials the matrix tries on every route.
func callerKinds() []callerKind {
	forbidden := outcome{status: http.StatusForbidden, code: auth.CodeForbidden}
	lacks := outcome{status: http.StatusForbidden, code: auth.CodeInsufficientScope}
	confined := outcome{status: http.StatusForbidden, code: auth.CodeSandboxConfined}
	unauth := outcome{status: http.StatusUnauthorized, code: auth.CodeUnauthenticated}
	runs := outcome{status: 0, code: ""}

	agentOf := func(route catalogRoute, sandbox string) keySpec {
		return keySpec{
			scope: scopes(route.scope), agent: "agent-1", agentScopes: scopes(route.scope), sandbox: sandbox,
		}
	}

	return []callerKind{
		{name: "no credential", changing: unauth, reading: unauth,
			send: func(_ *rig, route catalogRoute) request {
				return request{method: route.method, target: route.target, body: route.body}
			}},
		{name: "a user key with only another scope", changing: lacks, reading: lacks,
			send: func(r *rig, route catalogRoute) request {
				return keyed(r, route, keySpec{scope: scopes(scope.AgentRead)})
			}},
		{name: "a user key with the scope", changing: runs, reading: runs,
			send: func(r *rig, route catalogRoute) request {
				return keyed(r, route, keySpec{scope: scopes(route.scope)})
			}},
		// An agent never changes organizations, whatever its scopes, and may read
		// them when it has the scope.
		{name: "an agent key with the scope", changing: forbidden, reading: runs,
			send: func(r *rig, route catalogRoute) request { return keyed(r, route, agentOf(route, "")) }},
		{name: "an agent key whose agent lacks the scope", changing: lacks, reading: lacks,
			send: func(r *rig, route catalogRoute) request {
				spec := agentOf(route, "")
				spec.agentScopes = scopes(scope.AgentRead)

				return keyed(r, route, spec)
			}},
		{name: "an agent of a sandbox with the scope", changing: confined, reading: confined,
			send: func(r *rig, route catalogRoute) request { return keyed(r, route, agentOf(route, sandboxID)) }},
	}
}

// TestEverySessionReachesEveryRoute is the positive half of the matrix: a
// member's session reaches every route, whatever it does, and no route needs
// the platform administrator role.
func TestEverySessionReachesEveryRoute(t *testing.T) {
	t.Parallel()

	for _, route := range catalog() {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.as(rg.signIn(userID, roleMember), route.method, route.target, route.body)

			if len(rg.store.calls) != 1 {
				t.Errorf("store calls = %q, want exactly one", rg.store.calls)
			}
		})
	}
}

// TestBoundaryRefusalsBeforeTheStore: a request the boundary refuses for its
// shape, whatever the route, never reaches the store: a body one byte over the
// route's cap, a query string over it, a body of the wrong media type, and a
// method the path does not take.
func TestBoundaryRefusalsBeforeTheStore(t *testing.T) {
	t.Parallel()

	for _, route := range catalog() {
		unsafe := route.method != http.MethodGet

		cases := []struct {
			name   string
			req    request
			status int
			code   string
		}{
			{name: "a body over the cap",
				req:    request{method: route.method, target: route.target, body: strings.Repeat(" ", int(route.limit)+1)},
				status: http.StatusRequestEntityTooLarge, code: "body_too_large"},
			{name: "a query string over the cap",
				req: request{method: route.method, target: route.target + "?x=" + strings.Repeat("a", int(route.limit)),
					body: route.body},
				status: http.StatusRequestEntityTooLarge, code: "body_too_large"},
			{name: "a method the path does not take",
				req:    request{method: http.MethodPut, target: route.target, body: route.body},
				status: http.StatusMethodNotAllowed, code: ""},
		}

		if unsafe {
			cases = append(cases, struct {
				name   string
				req    request
				status int
				code   string
			}{name: "a body that is not JSON",
				req:    request{method: route.method, target: route.target, body: route.body, contentType: "text/plain"},
				status: http.StatusUnsupportedMediaType, code: "unsupported_media_type"})
		}

		for _, tc := range cases {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				tc.req.cookies = []*http.Cookie{rg.signIn(userID, roleMember)}
				rec := rg.serve(tc.req)

				if rec.Code != tc.status {
					t.Errorf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body)
				}

				wantCalls(t, rg.store.calls, nil)
			})
		}
	}
}

// bundleCaller is a credential of the bundle matrix: the lists it carries, and the
// scopes of the catalog it effectively holds, written out by hand.
type bundleCaller struct {
	name string
	// agent is whether an agent acts, with agentList as its list.
	agent     bool
	agentList scope.List
	keyList   scope.List
	holds     []scope.Scope
}

// TestBundlesAtTheCatalog is the bundle half of the credential matrix: a user's
// default key has every route's scope but member:revoke, which it has only when
// it names it; a key with the session bundle has all; and an agent, whatever it
// holds, is refused (forbidden) on every route that changes something it holds,
// and lacks the scope (insufficient scope) on one it does not.
func TestBundlesAtTheCatalog(t *testing.T) {
	t.Parallel()

	every := make([]scope.Scope, 0, len(catalog()))

	for _, route := range catalog() {
		every = append(every, route.scope)
	}

	withoutRevoke := slices.DeleteFunc(slices.Clone(every), func(s scope.Scope) bool { return s == scope.MemberRevoke })

	callers := []bundleCaller{
		{name: "a default:user key", keyList: scopes(scope.DefaultUser), holds: withoutRevoke},
		{name: "a default:user key that names member:revoke", keyList: scopes(scope.DefaultUser, scope.MemberRevoke),
			holds: every},
		{name: "a key naming only member:revoke", keyList: scopes(scope.MemberRevoke),
			holds: []scope.Scope{scope.MemberRevoke}},
		{name: "a default:session key", keyList: scopes(scope.DefaultSession), holds: every},
		{name: "an agent holding everything", agent: true, keyList: scopes(scope.DefaultSession),
			agentList: scopes(scope.DefaultSession), holds: every},
		{name: "an agent of the default:user bundle", agent: true, keyList: scopes(scope.DefaultSession),
			agentList: scopes(scope.DefaultUser), holds: withoutRevoke},
		{name: "an agent holding the revoking scopes", agent: true, keyList: scopes(scope.DefaultSession),
			agentList: scopes(scope.UserRevoke, scope.MemberRevoke, scope.InvitationCreate),
			holds:     []scope.Scope{scope.MemberRevoke}},
		{name: "an agent of the default:agent bundle", agent: true, keyList: scopes(scope.DefaultAgent),
			agentList: scopes(scope.DefaultAgent), holds: nil},
	}

	for _, route := range catalog() {
		for _, caller := range callers {
			t.Run(route.name+"/"+caller.name, func(t *testing.T) {
				t.Parallel()

				spec := keySpec{scope: caller.keyList, agent: "", agentScopes: nil, sandbox: ""}
				if caller.agent {
					spec.agent, spec.agentScopes = "agent-1", caller.agentList
				}

				rg := newRig(t)
				rec := rg.serve(keyed(rg, route, spec))

				switch {
				case !slices.Contains(caller.holds, route.scope):
					wantRefused(t, rg, rec, auth.CodeInsufficientScope)
				case caller.agent && !route.reads:
					wantRefused(t, rg, rec, auth.CodeForbidden)
				case len(rg.store.calls) != 1:
					t.Errorf("= %d, store calls = %q, want the route to run once", rec.Code, rg.store.calls)
				}
			})
		}
	}
}

// wantRefused checks a 403 of the boundary with code, logged once, and that the
// store was never called.
func wantRefused(t *testing.T, rg *rig, rec *httptest.ResponseRecorder, code string) {
	t.Helper()

	if rec.Code != http.StatusForbidden || len(rg.logged) != 1 || rg.logged[0].Code != code {
		t.Errorf("= %d, logged %v; want 403 %q", rec.Code, rg.logged, code)
	}

	wantCalls(t, rg.store.calls, nil)
}
