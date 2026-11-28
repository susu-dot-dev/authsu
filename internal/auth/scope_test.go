//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

const (
	agentOne   = "00000000-0000-7000-8000-0000000000a1"
	orgOne     = "00000000-0000-7000-8000-0000000000b1"
	sandboxOne = "00000000-0000-7000-8000-0000000000c1"
)

// scopedRoutes is a route table where each route declares one access rule, so a
// request's outcome shows exactly which rule it met. Every route records its
// call, and refusals never reach it.
func (r *rig) scopedRoutes() []auth.Route {
	declare := func(path string, access auth.Access) auth.Route {
		return r.getRoute(path, auth.Authenticated, access)
	}

	return []auth.Route{
		declare("/open", auth.Open()),
		declare("/agent-read", auth.Needs(scope.AgentRead)),
		declare("/agent-create", auth.Needs(scope.AgentCreate)),
		declare("/agent-update", auth.Needs(scope.AgentUpdate).WithoutAgents()),
		declare("/key-create", auth.Needs(scope.KeyCreate).Sessions().WithoutAgents()),
		declare("/user-read", auth.Needs(scope.UserRead)),
		declare("/invitation-create", auth.Needs(scope.InvitationCreate)),
		declare("/open-no-agents", auth.Open().WithoutAgents()),
		declare("/open-sessions", auth.Open().Sessions()),
		declare("/sandbox-open", auth.Open().InSandbox()),
		declare("/sandbox-read", auth.Needs(scope.AgentRead).InSandbox()),
		declare("/sandbox-admin", auth.Needs(scope.UserRead).InSandbox()),
		declare("/sandbox-no-agents", auth.Needs(scope.AgentUpdate).InSandbox().WithoutAgents()),
		declare("/sandbox-sessions", auth.Open().Sessions().InSandbox()),
	}
}

// scopedOutcome is what a request to a scoped route must produce: allowed, or a
// 403 under one of the two codes an access refusal has.
type scopedOutcome uint8

const (
	allowed scopedOutcome = iota
	noScope
	forbiddenAccess
	confined
	grantRefused
)

// status is the HTTP status of the outcome.
func (o scopedOutcome) status() int {
	if o == allowed {
		return http.StatusOK
	}

	return http.StatusForbidden
}

// code is the error code of a refusal, and "" for a success.
func (o scopedOutcome) code() string {
	switch o {
	case allowed:
		return ""
	case noScope:
		return auth.CodeInsufficientScope
	case forbiddenAccess:
		return auth.CodeForbidden
	case confined:
		return auth.CodeSandboxConfined
	case grantRefused:
		return auth.CodeGrantNotAccepted
	}

	return ""
}

// accessCase is one row of the permission table: a credential (a session, a
// user's key, an agent's key) with what it carries and the account's role, the
// route, and the answer.
type accessCase struct {
	name string
	// key builds the request's credential on the rig and returns the
	// Authorization value or the cookie.
	key  credentialFn
	path string
	want scopedOutcome
}

// Names the permission tables share.
const (
	bundleSession = scope.DefaultSession
	bundleUser    = scope.DefaultUser
	bundleAgent   = scope.DefaultAgent
	scopeRead     = "agent:read"
	scopeCreate   = "agent:create"
)

// sessionCases: a session is every scope, limited by the role.
func sessionCases() []accessCase {
	return []accessCase{
		{"session of a member: an open route", member(session), "/open", allowed},
		{"session of a member: a user scope", member(session), "/agent-create", allowed},
		{"session of a member: an admin route is the role's 403", member(session), "/user-read", forbiddenAccess},
		{"session of a member: an admin create is the role's 403", member(session), "/invitation-create", forbiddenAccess},
		{"session of an admin: an admin scope", admin(session), "/user-read", allowed},
		{"session of an admin: another admin scope", admin(session), "/invitation-create", allowed},
		{"session of an admin: a session-only route", admin(session), "/key-create", allowed},
		{"session of an admin: a session route", admin(session), "/open-sessions", allowed},
		{"session: a route that refuses agents", member(session), "/open-no-agents", allowed},
	}
}

// userKeyCases: a user's own API key is limited by what it names.
func userKeyCases() []accessCase {
	return []accessCase{
		{"user bundle: a user scope", userKey(bundleUser), "/agent-read", allowed},
		{"user bundle: an admin scope is not in it", adminKey(bundleUser), "/user-read", noScope},
		{"admin with the session bundle: an admin scope", adminKey(bundleSession), "/user-read", allowed},
		{
			"member with the session bundle: the role gates the admin scope",
			userKey(bundleSession), "/user-read", forbiddenAccess,
		},
		{"one scope: that scope", userKey(scopeRead), "/agent-read", allowed},
		{"one scope: another scope", userKey(scopeRead), "/agent-create", noScope},
		{"no scopes: an open route", userKey(), "/open", allowed},
		{"no scopes: a scoped route", userKey(), "/agent-read", noScope},
		{"a route that wants a session", userKey(bundleSession), "/open-sessions", forbiddenAccess},
		{"create key needs a session", userKey(bundleSession), "/key-create", forbiddenAccess},
		{"no agent, so a route that refuses agents is fine", userKey(bundleUser), "/open-no-agents", allowed},
		{"an unknown name grants nothing", userKey("nope:read"), "/agent-read", noScope},
		{"an unknown name beside a known one", userKey("nope:read", scopeRead), "/agent-read", allowed},
		{"a damaged stored list grants nothing", userKeyStored("not json"), "/agent-read", noScope},
		{"a damaged stored list still opens an open route", userKeyStored("not json"), "/open", allowed},
		{"a stored list that is not strings grants nothing", userKeyStored(`[1]`), "/agent-read", noScope},
	}
}

// agentKeyCases: an agent's key is the intersection of its key and its agent.
func agentKeyCases() []accessCase {
	both := func(l ...string) credentialFn { return agentKey(list(l...), list(l...)) }

	return []accessCase{
		{"key and agent both allow", both(scopeRead), "/agent-read", allowed},
		{"the key allows, the agent does not", agentKey(list(scopeRead), list()), "/agent-read", noScope},
		{"the agent allows, the key does not", agentKey(list(), list(scopeRead)), "/agent-read", noScope},
		{"bundles intersect", agentKey(list(bundleUser), list(bundleAgent)), "/agent-read", allowed},
		{"outside the agent's bundle", agentKey(list(bundleUser), list(bundleAgent)), "/agent-create", noScope},
		{
			"the agent has it explicitly, the key by bundle",
			agentKey(list(bundleUser), list(bundleAgent, scopeCreate)), "/agent-create", allowed,
		},
		{
			"a key of the session bundle is still capped by the agent",
			agentKey(list(bundleSession), list(bundleAgent)), "/agent-create", noScope,
		},
		{"an open route", agentKey(list(), list()), "/open", allowed},
		{"refused where agents are refused, whatever its scopes", both(bundleSession), "/agent-update", forbiddenAccess},
		{"refused on an open route that refuses agents", agentKey(list(), list()), "/open-no-agents", forbiddenAccess},
		{"never a session route", both(bundleSession), "/open-sessions", forbiddenAccess},
		{"of a member naming admin scopes is the role's 403", both(bundleSession), "/user-read", forbiddenAccess},
		{
			"of an admin with both lists naming it",
			adminAgent(list(bundleSession), list(bundleSession)), "/user-read", allowed,
		},
		{
			"of an admin whose agent does not name it",
			adminAgent(list(bundleSession), list(bundleAgent)), "/user-read", noScope,
		},
		{"of an admin whose key does not name it", adminAgent(list(bundleAgent), list(bundleSession)), "/user-read", noScope},
		{
			"a stored list that is not a list grants nothing",
			agentKeyStored(list(scopeRead), "not json"), "/agent-read", noScope,
		},
		{"a stored list that is empty text grants nothing", agentKeyStored(list(scopeRead), ""), "/agent-read", noScope},
	}
}

// sandboxCases: an agent of a sandbox is refused on every route that does not
// opt in with InSandbox, whatever else the route requires or the agent holds
// (the sandbox check is the first), and on a route that does it is judged by the
// remaining checks as any caller is. An ordinary agent and a user are never
// refused for it.
func sandboxCases() []accessCase {
	every := func(l ...string) credentialFn { return sandboxKey(list(l...), list(l...), roleMember) }
	everyAdmin := func(l ...string) credentialFn { return sandboxKey(list(l...), list(l...), auth.RoleAdmin) }

	return []accessCase{
		// Not opted in: refused, however the rest of the access reads.
		{"sandbox agent: an open route is refused", every(bundleSession), "/open", confined},
		{"sandbox agent: an open route with no scopes is refused", every(), "/open", confined},
		{"sandbox agent: a scoped route is refused", every(bundleSession), "/agent-read", confined},
		{"sandbox agent: a route it lacks the scope for is the sandbox's 403", every(), "/agent-read", confined},
		{"sandbox agent: a route that refuses agents is the sandbox's 403", every(bundleSession), "/agent-update", confined},
		{"sandbox agent: a session route is the sandbox's 403", every(bundleSession), "/open-sessions", confined},
		{"sandbox agent: an open route that refuses agents", every(), "/open-no-agents", confined},
		{"sandbox agent: an admin route of a member is the sandbox's 403", every(bundleSession), "/user-read", confined},
		{"sandbox agent of an admin: an admin route is the sandbox's 403", everyAdmin(bundleSession), "/user-read", confined},
		{"sandbox agent of an admin: an admin create", everyAdmin(bundleSession), "/invitation-create", confined},
		// Opted in: the other checks decide.
		{"sandbox agent: an opted-in open route", every(), "/sandbox-open", allowed},
		{"sandbox agent: an opted-in scoped route", every(scopeRead), "/sandbox-read", allowed},
		{"sandbox agent: an opted-in route it lacks the scope for", every(), "/sandbox-read", noScope},
		{
			"sandbox agent: the key alone has the scope",
			sandboxKey(list(scopeRead), list(), roleMember), "/sandbox-read", noScope,
		},
		{
			"sandbox agent: the agent alone has the scope",
			sandboxKey(list(), list(scopeRead), roleMember), "/sandbox-read", noScope,
		},
		{"sandbox agent of a member: an opted-in admin scope is the role's 403",
			every(bundleSession), "/sandbox-admin", forbiddenAccess},
		{"sandbox agent of an admin: an opted-in admin scope", everyAdmin(bundleSession), "/sandbox-admin", allowed},
		{"sandbox agent: an opted-in route that refuses agents", every(bundleSession), "/sandbox-no-agents", forbiddenAccess},
		{"sandbox agent: an opted-in session route", every(bundleSession), "/sandbox-sessions", forbiddenAccess},
		// Neither a user nor an ordinary agent is a sandbox's.
		{"a user's key: an opted-in route", userKey(scopeRead), "/sandbox-read", allowed},
		{"a session: an opted-in route", member(session), "/sandbox-open", allowed},
		{"an ordinary agent: an opted-in route", agentKey(list(scopeRead), list(scopeRead)), "/sandbox-read", allowed},
		{
			"an ordinary agent: a route that is not opted in",
			agentKey(list(scopeRead), list(scopeRead)), "/agent-read", allowed,
		},
		{"a member of an organization: a route that is not opted in", orgKey(scopeRead), "/agent-read", allowed},
	}
}

// TestAccessMatrix is the permission table, one row per credential, route and
// answer. It drives the real boundary, so the declaration, the key's stored
// scopes, the agent's row and the role are all the real ones.
func TestAccessMatrix(t *testing.T) {
	t.Parallel()

	for _, group := range [][]accessCase{sessionCases(), userKeyCases(), agentKeyCases(), sandboxCases()} {
		for _, test := range group {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				header, cookie := test.key(r)

				rec := r.serveWith(r.scopedRoutes(), test.path, optionalHeader(header), optionalCookie(cookie))

				checkOutcome(t, r, rec, test.want)
			})
		}
	}
}

// optionalHeader is the Authorization values to send: none for "".
func optionalHeader(header string) []string {
	if header == "" {
		return nil
	}

	return []string{header}
}

// optionalCookie is the cookies to send: none for nil.
func optionalCookie(cookie *http.Cookie) []*http.Cookie {
	if cookie == nil {
		return nil
	}

	return []*http.Cookie{cookie}
}

// checkOutcome checks a response against the outcome of a scoped route: a
// success ran the handler once, and a refusal never reached it, was logged once
// under its code, and says the code in its body.
func checkOutcome(t *testing.T, r *rig, rec *httptest.ResponseRecorder, want scopedOutcome) {
	t.Helper()

	if rec.Code != want.status() {
		t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, want.status())
	}

	if want == allowed {
		if len(r.handled) != 1 {
			t.Errorf("handler ran %d times, want once", len(r.handled))
		}

		return
	}

	if len(r.handled) != 0 {
		t.Errorf("a refused request reached its handler %d times", len(r.handled))
	}

	if len(r.logged) != 1 || r.logged[0].Code != want.code() {
		t.Errorf("logged = %v, want one %s", r.logged, want.code())
	}

	if !strings.Contains(rec.Body.String(), `"code":"`+want.code()+`"`) {
		t.Errorf("body = %s, want code %s", rec.Body, want.code())
	}
}

func list(names ...string) scope.List { return scope.List(slices.Clone(names)) }

// credentialFn builds a credential on a rig.
type credentialFn = func(*rig) (string, *http.Cookie)

// session is a stored session for a user with role.
func session(role string) credentialFn {
	return func(r *rig) (string, *http.Cookie) { return "", sessionCookie(r.sessionFor(role)) }
}

func member(f func(string) credentialFn) credentialFn { return f(roleMember) }
func admin(f func(string) credentialFn) credentialFn  { return f(auth.RoleAdmin) }

// userKey is a stored API key of a member with the given scope names.
func userKey(names ...string) credentialFn { return keyOf(roleMember, names...) }

// adminKey is a stored API key of an administrator with the given scope names.
func adminKey(names ...string) credentialFn { return keyOf(auth.RoleAdmin, names...) }

func keyOf(role string, names ...string) credentialFn {
	return func(r *rig) (string, *http.Cookie) {
		return bearer(r.apiKey(bearerSpec{scope: list(names...), role: role})), nil
	}
}

// userKeyStored is a stored API key of a member whose stored scope text is text
// as it is.
func userKeyStored(text string) credentialFn {
	return func(r *rig) (string, *http.Cookie) {
		return bearer(r.apiKey(bearerSpec{role: roleMember}.withStoredScope(text))), nil
	}
}

// agentKey is a stored API key of an agent of a member: the key's list and the
// agent's list.
func agentKey(key, agent scope.List) credentialFn { return agentOf(roleMember, key, agent.JSON()) }

// adminAgent is agentKey for an administrator's agent.
func adminAgent(key, agent scope.List) credentialFn {
	return agentOf(auth.RoleAdmin, key, agent.JSON())
}

// agentKeyStored is agentKey with the agent's list as the raw stored text.
func agentKeyStored(key scope.List, stored string) credentialFn {
	return agentOf(roleMember, key, stored)
}

func agentOf(role string, key scope.List, agentStored string) credentialFn {
	return func(r *rig) (string, *http.Cookie) {
		return bearer(r.apiKey(bearerSpec{scope: key, role: role, agent: agentOne, agentScopes: agentStored})), nil
	}
}

// sandboxKey is a stored API key of an agent of a member (or an admin) that is
// confined to a sandbox.
func sandboxKey(key, agent scope.List, role string) credentialFn {
	return func(r *rig) (string, *http.Cookie) {
		return bearer(r.apiKey(bearerSpec{
			scope: key, role: role, agent: agentOne, agentScopes: agent.JSON(), sandbox: sandboxOne,
		})), nil
	}
}

// orgKey is a stored API key of a member of an organization.
func orgKey(names ...string) credentialFn {
	return func(r *rig) (string, *http.Cookie) {
		return bearer(r.apiKey(bearerSpec{scope: list(names...), role: roleMember, org: orgOne})), nil
	}
}

// TestCredentialIsJudgedBeforeAccess: a bad credential is 401 on every route, a
// good one that lacks what the route needs is 403, and neither learns anything
// about the route's rule from the other. 401 means signed out and 403 means not
// allowed.
func TestCredentialIsJudgedBeforeAccess(t *testing.T) {
	t.Parallel()

	routes := []string{"/open", "/agent-read", "/user-read", "/key-create", "/agent-update", "/open-no-agents"}

	for _, path := range routes {
		t.Run(path+" with no credential", func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			rec := r.serveWith(r.scopedRoutes(), path, nil, nil)
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("response = %d %q, want the same 401 as every route", rec.Code, rec.Body)
			}
		})

		t.Run(path+" with a revoked agent's key", func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			key := r.apiKey(bearerSpec{
				scope: list(scope.DefaultSession), agent: agentOne, agentScopes: list(scope.DefaultSession).JSON(),
			})
			// The store reports nothing active for a key whose agent is revoked.
			r.unstore(key)

			rec := r.serveWith(r.scopedRoutes(), path, []string{bearer(key)}, nil)
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("response = %d %q, want 401", rec.Code, rec.Body)
			}
		})
	}
}

// TestSandboxIsRefusedBeforeThePathIDIsRead: a sandboxed agent on a route that
// has not opted in is refused whatever the id in the path is, so it learns
// nothing about the route's ids, and the handler never runs.
func TestSandboxIsRefusedBeforeThePathIDIsRead(t *testing.T) {
	t.Parallel()

	for name, target := range map[string]string{
		"a malformed id": pathItems + "not-an-id", "a well-formed id": pathItems + agentOne,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			header, _ := sandboxKey(list(), list(), roleMember)(r)

			rec := r.serveWith(r.standardRoutes(), target, []string{header}, nil)

			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), auth.CodeSandboxConfined) ||
				len(r.handled) != 0 {
				t.Errorf("response = %d %s, handled %d times", rec.Code, rec.Body, len(r.handled))
			}
		})
	}
}

// TestAccessOrder pins the order of the checks, which decides what a caller who
// fails several of them is told: the sandbox, then the role for an admin scope,
// then the scope, then the session requirement, then agents.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestAccessOrder(t *testing.T) {
	t.Parallel()

	everything := auth.Needs(scope.UserRead).Sessions().WithoutAgents()

	tests := []struct {
		name     string
		who      auth.Principal
		access   auth.Access
		wantCode string
		wantText string
	}{
		{
			name:     "a sandboxed agent that fails everything else is told about the sandbox first",
			who:      auth.Principal{Role: roleMember, Kind: auth.KindAPIKey, AgentID: agentOne, SandboxID: sandboxOne},
			access:   everything,
			wantCode: auth.CodeSandboxConfined, wantText: "an agent of a sandbox may not do this",
		},
		{
			name:     "an opted-in route then tells a member about the role",
			who:      auth.Principal{Role: roleMember, Kind: auth.KindAPIKey, AgentID: agentOne, SandboxID: sandboxOne},
			access:   everything.InSandbox(),
			wantCode: auth.CodeForbidden, wantText: "administrator access is required",
		},
		{
			name: "an opted-in route then tells an admin without the scope about the scope",
			who: auth.Principal{
				Role: auth.RoleAdmin, Kind: auth.KindAPIKey, AgentID: agentOne, SandboxID: sandboxOne,
			},
			access:   everything.InSandbox(),
			wantCode: auth.CodeInsufficientScope, wantText: "this credential lacks the scope user:read",
		},
		{
			name: "an opted-in route then tells an admin with the scope about the session",
			who: auth.Principal{
				Role: auth.RoleAdmin, Kind: auth.KindAPIKey, AgentID: agentOne, SandboxID: sandboxOne,
				Scope: list(scope.DefaultSession), AgentScope: list(scope.DefaultSession),
			},
			access:   everything.InSandbox(),
			wantCode: auth.CodeForbidden, wantText: "a signed-in session is required",
		},
		{
			name:     "an open route refuses a sandboxed agent too",
			who:      auth.Principal{Role: roleMember, Kind: auth.KindAPIKey, AgentID: agentOne, SandboxID: sandboxOne},
			access:   auth.Open(),
			wantCode: auth.CodeSandboxConfined, wantText: "an agent of a sandbox may not do this",
		},
		{
			name:     "a member without the scope on an admin route is told about the role",
			who:      auth.Principal{Role: roleMember, Kind: auth.KindAPIKey, AgentID: agentOne},
			access:   everything,
			wantCode: auth.CodeForbidden, wantText: "administrator access is required",
		},
		{
			name:     "an admin without the scope is told about the scope",
			who:      auth.Principal{Role: auth.RoleAdmin, Kind: auth.KindAPIKey, AgentID: agentOne},
			access:   everything,
			wantCode: auth.CodeInsufficientScope, wantText: "this credential lacks the scope user:read",
		},
		{
			name: "an admin with the scope but a key is told it needs a session",
			who: auth.Principal{
				Role: auth.RoleAdmin, Kind: auth.KindAPIKey, AgentID: agentOne,
				Scope: list(scope.DefaultSession), AgentScope: list(scope.DefaultSession),
			},
			access:   everything,
			wantCode: auth.CodeForbidden, wantText: "a signed-in session is required",
		},
		{
			name: "a session of an agent cannot exist, so agents are the last",
			who: auth.Principal{
				Role: auth.RoleAdmin, Kind: auth.KindSession, AgentID: agentOne,
				Scope: list(scope.DefaultSession), AgentScope: list(scope.DefaultSession),
			},
			access:   everything,
			wantCode: auth.CodeForbidden, wantText: "an agent may not do this",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			failure := apierr.As(auth.CheckAccess(test.access, test.who))
			if failure == nil {
				t.Fatal("the access was not refused")
			}

			if failure.Kind != apierr.Forbidden || failure.Code != test.wantCode || failure.Description != test.wantText {
				t.Errorf("refusal = %v %s %q, want 403 %s %q", failure.Kind, failure.Code, failure.Description,
					test.wantCode, test.wantText)
			}
		})
	}
}

// TestAccessPasses: the same access, met in full, is not refused; and the
// zero-value pieces of it (no scope, no flags) refuse nothing.
func TestAccessPasses(t *testing.T) {
	t.Parallel()

	session := auth.Principal{
		Role: auth.RoleAdmin, Kind: auth.KindSession,
		Scope: list(scope.DefaultSession), AgentScope: list(scope.DefaultSession),
	}

	for name, access := range map[string]auth.Access{
		"open":                          auth.Open(),
		"open in a sandbox":             auth.Open().InSandbox(),
		"everything in a sandbox":       auth.Needs(scope.UserRead).Sessions().WithoutAgents().InSandbox(),
		"a scope":                       auth.Needs(scope.UserRead),
		"a scope and a session":         auth.Needs(scope.UserRead).Sessions(),
		"a scope and no agents":         auth.Needs(scope.UserRead).WithoutAgents(),
		"a scope, a session, no agents": auth.Needs(scope.UserRead).Sessions().WithoutAgents(),
	} {
		err := auth.CheckAccess(access, session)
		if err != nil {
			t.Errorf("%s: refused a session of an admin with every scope: %v", name, err)
		}
	}
}

// TestAccessBuildersDoNotShareState: Sessions and WithoutAgents return copies,
// so a shared base cannot be changed by deriving from it.
func TestAccessBuildersDoNotShareState(t *testing.T) {
	t.Parallel()

	base := auth.Needs(scope.AgentRead)
	_ = base.Sessions()
	_ = base.WithoutAgents()
	_ = base.InSandbox()

	if base != auth.Needs(scope.AgentRead) {
		t.Errorf("deriving from an Access changed it: %+v", base)
	}

	if auth.Open().InSandbox() == auth.Open() || !auth.Open().InSandbox().SandboxOK || auth.Open().SandboxOK {
		t.Error("InSandbox must set only SandboxOK, on a copy")
	}

	if auth.Needs(scope.AgentRead).InSandbox().Sessions() != auth.Needs(scope.AgentRead).Sessions().InSandbox() {
		t.Error("the order of the builders changed what they declare")
	}

	if auth.Open() == (auth.Access{}) {
		t.Error("Open() is the zero Access: a route that forgot its access would be indistinguishable")
	}
}
