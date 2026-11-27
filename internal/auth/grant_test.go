//nolint:goconst,lll,dupword // table-driven tests repeat case names and inputs on purpose, and the case table is the test; a constant or a line break per row would hide it
package auth_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/secret"
)

// This file holds the OAuth grant as a credential of authsu's own API
// (docs/permissions_design.md): how a bearer token is told to be one, who it
// speaks for, and that a route accepts it only by opting in. The store's own
// conditions (a revoked grant, an expired token, a sandboxed agent, a token of
// another resource) are not run here: the store's tests hold the statement's text
// (one shared constant for introspection and resolution) and its arguments, and
// the e2e tests (TestGrantLivenessAtTheAPI) run it against the real database.
// Here the fake reports what the store would, and the boundary is held to
// resolving and narrowing what it is given.

// grantRoutes is a route table where each route declares one access rule, so a
// request's outcome shows exactly which rule it met. A route accepts a grant
// only where its name says so.
func (r *rig) grantRoutes() []auth.Route {
	declare := func(path string, access auth.Access) auth.Route {
		return r.getRoute(path, auth.Authenticated, access)
	}

	return []auth.Route{
		// Not opted in: every shape of access a route has.
		declare("/open", auth.Open()),
		declare("/agent-read", auth.Needs(scope.AgentRead)),
		declare("/agent-create", auth.Needs(scope.AgentCreate)),
		declare("/open-no-agents", auth.Open().WithoutAgents()),
		declare("/open-sessions", auth.Open().Sessions()),
		declare("/user-read", auth.Needs(scope.UserRead)),
		declare("/sandbox-open", auth.Open().InSandbox()),
		declare("/sandbox-read", auth.Needs(scope.AgentRead).InSandbox()),
		declare("/everything", auth.Needs(scope.AgentRead).Sessions().WithoutAgents().InSandbox()),
		// Opted in.
		declare("/grant-open", auth.Open().FromGrants()),
		declare("/grant-agent-read", auth.Needs(scope.AgentRead).FromGrants()),
		declare("/grant-agent-create", auth.Needs(scope.AgentCreate).FromGrants()),
		declare("/grant-org-read", auth.Needs(scope.OrgRead).FromGrants()),
		declare("/grant-user-read", auth.Needs(scope.UserRead).FromGrants()),
		declare("/grant-no-agents", auth.Needs(scope.AgentRead).FromGrants().WithoutAgents()),
		declare("/grant-sessions", auth.Open().FromGrants().Sessions()),
		declare("/grant-sandbox", auth.Open().FromGrants().InSandbox()),
		// Opted in and let through the refusal of agents, as a grant only.
		declare("/grant-as-user", auth.Needs(scope.SandboxCreate).WithoutAgents().FromGrants().GrantsAsUser()),
		declare("/grant-as-user-sessions", auth.Open().WithoutAgents().FromGrants().GrantsAsUser().Sessions()),
	}
}

// grantAccessCase is one row of the permission table for an OAuth grant: the
// token as stored, the route, and the answer.
type grantAccessCase struct {
	name string
	spec grantSpec
	path string
	want scopedOutcome
}

// grantAgentList is an agent list that allows everything a login may ask for.
func grantAgentList() string {
	return list("agent:read", "agent:create", "org:read", "sandbox:create", "sandbox:revoke").JSON()
}

// Names the grant tables share: the token's scope text, and the agent's list.
const (
	tokenAll = "profile agent:read agent:create org:read sandbox:create sandbox:revoke"
	agentOK  = `["agent:read","agent:create","org:read"]`
	none     = "[]"
)

// bundleList is the stored list that names one bundle.
func bundleList(bundle string) string { return list(bundle).JSON() }

// grantAt is a case: a token with this scope text and agent list, at path.
func grantAt(name, tokenScope, agentList, path string, want scopedOutcome) grantAccessCase {
	return grantAccessCase{name, grantSpec{scope: tokenScope, agentScopes: agentList}, path, want}
}

// grantRefusalCases: a grant is refused on every route that has not opted in,
// whatever the route's access reads and whatever the grant and its agent hold,
// and with its own code and not another check's.
func grantRefusalCases() []grantAccessCase {
	generous := grantSpec{scope: "agent:read agent:create org:read", role: auth.RoleAdmin, agentScopes: grantAgentList()}
	empty := grantSpec{scope: "profile", agentScopes: none}
	paths := []string{
		"/open", "/agent-read", "/agent-create", "/open-no-agents", "/open-sessions", "/user-read",
		"/sandbox-open", "/sandbox-read", "/everything",
	}

	cases := make([]grantAccessCase, 0, 2*len(paths))

	for _, path := range paths {
		cases = append(cases,
			grantAccessCase{"a generous grant is refused at " + path, generous, path, grantRefused},
			grantAccessCase{"a grant with nothing is refused at " + path, empty, path, grantRefused},
		)
	}

	return cases
}

// intersectionCases: on a route that opted in, the grant is judged as an API key
// is: its own list, narrowed by the agent's.
func intersectionCases() []grantAccessCase {
	const read, create = "/grant-agent-read", "/grant-agent-create"

	return []grantAccessCase{
		grantAt("both allow", "agent:read", agentOK, read, allowed),
		grantAt("the token allows, the agent does not", "agent:read", none, read, noScope),
		grantAt("the agent allows, the token does not", "org:read", agentOK, read, noScope),
		grantAt("an agent with an empty list leaves the token nothing", tokenAll, none, read, noScope),
		grantAt("an agent with an empty list still allows an open route", tokenAll, none, "/grant-open", allowed),
		grantAt("a token with only profile and an open route", "profile", agentOK, "/grant-open", allowed),
		grantAt("a token with only profile and a scoped route", "profile openid", agentOK, read, noScope),
		grantAt("every scope on both sides", tokenAll, grantAgentList(), create, allowed),
		grantAt("a narrower token than the agent", "org:read", grantAgentList(), create, noScope),
		grantAt("the narrower token still has its own scope", "org:read", grantAgentList(), "/grant-org-read", allowed),
		grantAt("an agent bundle is expanded now", "agent:read", bundleList(scope.DefaultAgent), read, allowed),
		grantAt("an agent bundle that lacks the scope", "agent:create", bundleList(scope.DefaultAgent), create, noScope),
		grantAt("the session bundle is no wider than the token", "agent:read", bundleList(scope.DefaultSession), create, noScope),
		grantAt("the org scope", "org:read", grantAgentList(), "/grant-org-read", allowed),
	}
}

// damagedAgentCases: an agent's stored list that is not a list of names grants
// nothing, and does not make the credential unusable.
func damagedAgentCases() []grantAccessCase {
	cases := make([]grantAccessCase, 0, len(damaged()))

	for name, text := range damaged() {
		cases = append(cases, grantAt("an agent list that is damaged: "+name, tokenAll, text, "/grant-agent-read", noScope))
	}

	return append(cases,
		grantAt("an agent list that is damaged still opens an open route", tokenAll, "not json", "/grant-open", allowed))
}

// scopeTextCases: names the allowlist does not hold are no part of the token's
// list, however the stored text is spelled.
func scopeTextCases() []grantAccessCase {
	const read = "/grant-agent-read"

	session := bundleList(scope.DefaultSession)

	return []grantAccessCase{
		grantAt("a name that is no scope", "nope:read", grantAgentList(), read, noScope),
		grantAt("an authsu scope the login does not define still opens an open route", "key:read", session, "/grant-open", allowed),
		grantAt("an authsu scope the login does not define is not a scope of the token", "grant:read", session, read, noScope),
		grantAt("a bundle in the token's scope is not expanded", scope.DefaultUser, session, read, noScope),
		grantAt("the session bundle in the token's scope is not expanded", scope.DefaultSession, session, read, noScope),
		grantAt("a scope in another case", "Agent:Read", grantAgentList(), read, noScope),
		grantAt("a scope with a space inside", "agent: read", grantAgentList(), read, noScope),
		grantAt("a stored scope that is empty", "", grantAgentList(), read, noScope),
		grantAt("a stored scope that is only spaces", "   ", grantAgentList(), read, noScope),
		grantAt("a stored scope with a doubled space keeps its names", "profile  agent:read", grantAgentList(), read, allowed),
		grantAt("a stored scope with a leading space keeps its names", " agent:read", grantAgentList(), read, allowed),
		grantAt("a stored scope with a tab is not split by it", "agent:read\torg:read", grantAgentList(), read, noScope),
		grantAt("a stored scope with a newline is not split by it", "agent:read\nprofile", grantAgentList(), read, noScope),
		grantAt("a stored scope of the MCP resource", "mcp:read mcp:write", grantAgentList(), read, noScope),
	}
}

// roleCases: the role gates admin scopes, so neither list can grant what the
// role does not; and the other checks of an opted-in route still apply.
func roleCases() []grantAccessCase {
	session := bundleList(scope.DefaultSession)
	adminToken := func(tokenScope string) grantSpec {
		return grantSpec{scope: tokenScope, role: auth.RoleAdmin, agentScopes: session}
	}

	return []grantAccessCase{
		grantAt("a member with an admin scope on the route is the role's 403", tokenAll, session, "/grant-user-read", forbiddenAccess),
		{"an admin without the admin scope in a list is the scope's 403", adminToken(tokenAll), "/grant-user-read", noScope},
		{"an admin's token naming an admin scope gets none from the allowlist, which holds none",
			adminToken("user:read"), "/grant-user-read", noScope},
		grantAt("an opted-in route that refuses agents refuses a grant, which has one", tokenAll, grantAgentList(),
			"/grant-no-agents", forbiddenAccess),
		grantAt("an opted-in session route refuses a grant", tokenAll, grantAgentList(), "/grant-sessions", forbiddenAccess),
		grantAt("a route that lets a grant past the refusal of agents admits it", tokenAll, grantAgentList(),
			"/grant-as-user", allowed),
		grantAt("and still needs the scope of the token", "agent:read", grantAgentList(), "/grant-as-user", noScope),
		grantAt("and still needs the scope of the agent", tokenAll, none, "/grant-as-user", noScope),
		grantAt("and still refuses a grant where a session is required", tokenAll, grantAgentList(),
			"/grant-as-user-sessions", forbiddenAccess),
		grantAt("an opted-in sandbox route is no different: a grant has no sandbox", tokenAll, grantAgentList(),
			"/grant-sandbox", allowed),
	}
}

// TestGrantAccessMatrix is the permission table for an OAuth grant: a grant is
// refused wherever a route has not opted in, and judged like an API key where it
// has. It drives the real boundary, with the real route declarations.
func TestGrantAccessMatrix(t *testing.T) {
	t.Parallel()

	names := map[string]bool{}

	for _, test := range slices.Concat(grantRefusalCases(), intersectionCases(), damagedAgentCases(), scopeTextCases(), roleCases()) {
		if names[test.name] {
			t.Fatalf("two cases are named %q", test.name)
		}

		names[test.name] = true

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			issued := r.grant(test.spec)

			rec := r.serveWith(r.grantRoutes(), test.path, []string{bearer(issued)}, nil)

			checkOutcome(t, r, rec, test.want)

			if len(r.creds.calls) != 1 || r.creds.calls[0].kind != auth.KindGrant {
				t.Errorf("store reads = %+v, want one read of a grant", r.creds.calls)
			}
		})
	}
}

// TestGrantIsRefusedWhateverElseIsWrongWithTheRequest: the grant's refusal comes
// first, before the sandbox, the role, the scope, the session and the agents, so
// the answer does not depend on anything else about the caller, and the path id
// is not read.
func TestGrantIsRefusedWhateverElseIsWrongWithTheRequest(t *testing.T) {
	t.Parallel()

	for name, target := range map[string]string{
		"a route with no id": "/everything", "a malformed id": pathItems + "not-an-id", "a well-formed id": pathItems + agentOne,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			issued := r.grant(grantSpec{scope: "agent:read", agentScopes: "[]"})

			rec := r.serveWith(append(r.standardRoutes(), r.grantRoutes()...), target, []string{bearer(issued)}, nil)

			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), auth.CodeGrantNotAccepted) || len(r.handled) != 0 {
				t.Errorf("response = %d %s, handled %d times", rec.Code, rec.Body, len(r.handled))
			}
		})
	}
}

// accessOrderCase is a Principal built by hand, an access and the refusal.
type accessOrderCase struct {
	name     string
	who      auth.Principal
	access   auth.Access
	wantCode string
	wantText string
}

const grantRefusalText = "an OAuth access token may not be used here"

// grantOrderCases are callers of KindGrant that fail several checks, so the
// first of them is what they are told.
func grantOrderCases() []accessOrderCase {
	everything := auth.Needs(scope.UserRead).Sessions().WithoutAgents()
	grantOf := func(role string) auth.Principal {
		return auth.Principal{Role: role, Kind: auth.KindGrant, AgentID: agentOne}
	}
	holding := auth.Principal{
		Role: auth.RoleAdmin, Kind: auth.KindGrant, AgentID: agentOne,
		Scope: list(scope.DefaultSession), AgentScope: list(scope.DefaultSession),
	}
	sandboxed := grantOf(roleMember)
	sandboxed.SandboxID = sandboxOne

	return []accessOrderCase{
		{"a grant that fails everything else is told about the grant first", sandboxed, everything,
			auth.CodeGrantNotAccepted, grantRefusalText},
		{"an open route refuses a grant too", grantOf(roleMember), auth.Open(), auth.CodeGrantNotAccepted, grantRefusalText},
		{"an open route that refuses agents refuses a grant for the grant's own reason", grantOf(roleMember),
			auth.Open().WithoutAgents(), auth.CodeGrantNotAccepted, grantRefusalText},
		{"a sandbox opt-in is not a grant opt-in", grantOf(roleMember), auth.Open().InSandbox(),
			auth.CodeGrantNotAccepted, grantRefusalText},
		{"an opted-in route then tells a member about the role", grantOf(roleMember), everything.FromGrants(),
			auth.CodeForbidden, "administrator access is required"},
		{"an opted-in route then tells an admin without the scope about the scope", grantOf(auth.RoleAdmin),
			everything.FromGrants(), auth.CodeInsufficientScope, "this credential lacks the scope user:read"},
		{"an opted-in route then tells an admin with the scope about the session", holding, everything.FromGrants(),
			auth.CodeForbidden, "a signed-in session is required"},
		{"an opted-in route for agents last refuses the agent", holding,
			auth.Needs(scope.UserRead).WithoutAgents().FromGrants(), auth.CodeForbidden, "an agent may not do this"},
	}
}

// TestAccessOrderWithGrants pins where the grant's check is among the others, on
// a Principal built by hand, so it decides what a caller who fails several is
// told: the grant first.
func TestAccessOrderWithGrants(t *testing.T) {
	t.Parallel()

	for _, test := range grantOrderCases() {
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

// TestFromGrantsIsOnlyAboutGrants: the builder returns a copy that sets only
// its own flag, so a shared base cannot be changed by deriving from it.
func TestFromGrantsIsOnlyAboutGrants(t *testing.T) {
	t.Parallel()

	base := auth.Needs(scope.AgentRead)
	derived := base.FromGrants()

	if base.GrantOK || !derived.GrantOK || derived == base {
		t.Error("FromGrants must set only GrantOK, on a copy")
	}

	only := auth.Open().FromGrants()
	if only == auth.Open() || only.SandboxOK || only.NoAgents || only.SessionOnly || only.Scope != "" {
		t.Errorf("FromGrants must set only GrantOK: %+v", only)
	}
}

// TestGrantsAsUserRelaxesNoAgentsForGrantsOnly: on a route that refuses agents and
// declares GrantsAsUser, a grant passes the refusal and nothing else does: an
// agent's API key, with the same lists, is still refused, and so is a grant on a
// route that did not declare it.
func TestGrantsAsUserRelaxesNoAgentsForGrantsOnly(t *testing.T) {
	t.Parallel()

	held := list("sandbox:create")
	access := auth.Needs(scope.SandboxCreate).WithoutAgents().FromGrants().GrantsAsUser()
	plain := auth.Needs(scope.SandboxCreate).WithoutAgents().FromGrants()

	tests := []struct {
		name     string
		kind     string
		sandbox  string
		access   auth.Access
		wantCode string
		wantText string
	}{
		{"a grant on a route that declares it", auth.KindGrant, "", access, "", ""},
		{"a grant on a route that does not", auth.KindGrant, "", plain, auth.CodeForbidden, "an agent may not do this"},
		{"an agent's key on a route that declares it", auth.KindAPIKey, "", access, auth.CodeForbidden, "an agent may not do this"},
		{"an agent's key of a sandbox on a route that declares it", auth.KindAPIKey, sandboxOne, access,
			auth.CodeSandboxConfined, "an agent of a sandbox may not do this"},
		{"a grant with a sandbox on a route that declares it", auth.KindGrant, sandboxOne, access,
			auth.CodeSandboxConfined, "an agent of a sandbox may not do this"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			who := auth.Principal{
				Role: roleMember, Kind: test.kind, AgentID: agentOne, SandboxID: test.sandbox, Scope: held, AgentScope: held,
			}

			err := auth.CheckAccess(test.access, who)

			if test.wantCode == "" {
				if err != nil {
					t.Errorf("refused: %v", err)
				}

				return
			}

			failure := apierr.As(err)
			if err == nil || failure.Code != test.wantCode || failure.Description != test.wantText {
				t.Errorf("refusal = %v, want %s %q", failure, test.wantCode, test.wantText)
			}
		})
	}
}

// TestGrantsAsUserIsOnlyAboutNoAgents: the builder sets only its own flag, on a
// copy, and does not by itself admit a grant or refuse agents.
func TestGrantsAsUserIsOnlyAboutNoAgents(t *testing.T) {
	t.Parallel()

	base := auth.Needs(scope.SandboxCreate)
	derived := base.GrantsAsUser()

	if base.GrantAsUserOK || !derived.GrantAsUserOK || derived.GrantOK || derived.NoAgents || derived == base {
		t.Error("GrantsAsUser must set only GrantAsUserOK, on a copy")
	}
}

// TestFromGrantsIsDeclared: an Access that opts in is no less declared than one
// that does not, and the order of the builders does not matter.
func TestFromGrantsIsDeclared(t *testing.T) {
	t.Parallel()

	if auth.Open() == (auth.Access{}) || auth.Open().FromGrants() == (auth.Access{}) {
		t.Error("an Access that opts in is no less declared than one that does not")
	}

	forward := auth.Needs(scope.AgentRead).FromGrants().Sessions().InSandbox()
	backward := auth.Needs(scope.AgentRead).InSandbox().Sessions().FromGrants()

	if forward != backward {
		t.Error("the order of the builders changed what they declare")
	}
}

// TestSessionsAndKeysNeverMeetTheGrantCheck: a session and a key are admitted by
// a route that is not for grants, as they always were.
func TestSessionsAndKeysNeverMeetTheGrantCheck(t *testing.T) {
	t.Parallel()

	for name, kind := range map[string]string{"session": auth.KindSession, "API key": auth.KindAPIKey} {
		who := auth.Principal{Role: roleMember, Kind: kind, Scope: list("agent:read")}

		err := auth.CheckAccess(auth.Needs(scope.AgentRead), who)
		if err != nil {
			t.Errorf("a %s was refused a route that is not for grants: %v", name, err)
		}
	}
}

// grantCases: the bearer token of an OAuth grant, in every shape, at the
// boundary. A token that parses as an access token is resolved as a grant and
// nothing else; every other value is refused by the key's parser, as before.
func grantCases() []boundaryCase {
	grant := func(r *rig) auth.Issued {
		return r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList()})
	}
	token := func(r *rig) string { return grant(r).Token }
	around := func(before, after string) carryFn {
		return header(func(r *rig) string { return before + token(r) + after })
	}
	// A value that does not start with the access prefix as it is written (a space
	// before it) is not an access token to the boundary, and is refused by the key's
	// parser, as every other value is; one that does, and is malformed, is refused by
	// the access token's.
	parseKey := unauthenticated(0, input.CodeInvalidAPIKey).viaKey()
	parseAccess := unauthenticated(0, input.CodeInvalidAccessToken).viaGrant().withCalls(0)
	// A header that is not a Bearer is refused before the tag is read, so no kind
	// was asked for: the kind of the read is the zero one, and there is none.
	notBearer := unauthenticated(0, logNotBearer).viaKey()
	gone := unauthenticated(1, logNotActive).viaGrant()
	failed := unavailable(errDB, "on fire").viaGrant()
	refusedRoute := outcome{
		status: http.StatusForbidden, body: errorBody(auth.CodeGrantNotAccepted, "an OAuth access token may not be used here"),
		code: auth.CodeGrantNotAccepted, storeCalls: 1, kind: auth.KindGrant,
	}

	return []boundaryCase{
		rowOf("grant: valid, at a route that accepts it", "/grant-agent-read", header(func(r *rig) string { return "Bearer " + token(r) }),
			ok(1).viaGrant()),
		rowOf("grant: valid, at a route that does not", "/open", header(func(r *rig) string { return "Bearer " + token(r) }), refusedRoute),
		rowOf("grant: scheme in lower case", "/grant-agent-read", around("bearer ", ""), ok(1).viaGrant()),
		rowOf("grant: scheme in upper case", "/grant-agent-read", around("BEARER ", ""), ok(1).viaGrant()),
		rowOf("grant: no scheme", "/grant-agent-read", around("", ""), notBearer),
		rowOf("grant: another scheme", "/grant-agent-read", around("Token ", ""), notBearer),
		rowOf("grant: two spaces before the token", "/grant-agent-read", around("Bearer  ", ""), parseKey),
		rowOf("grant: a trailing space", "/grant-agent-read", around("Bearer ", " "), parseAccess),
		rowOf("grant: the token twice in one header", "/grant-agent-read",
			header(func(r *rig) string { t := token(r); return "Bearer " + t + " " + t }), parseAccess),
		rowOf("grant: a failing store", "/grant-agent-read", func(r *rig) carried {
			issued := grant(r)
			r.creds.err = errDB

			return carried{headers: []string{bearer(issued)}}
		}, failed),
		rowOf("grant: a token that was never stored", "/grant-agent-read",
			header(func(r *rig) string { return "Bearer " + r.issueAccessToken().Token }), gone),
		rowOf("grant: a token that is no longer active", "/grant-agent-read", func(r *rig) carried {
			issued := grant(r)
			delete(r.creds.grants, issued.Token)

			return carried{headers: []string{bearer(issued)}}
		}, gone),
		rowOf("grant: a token of a grant for another resource", "/grant-agent-read", func(r *rig) carried {
			issued := r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList(), resource: resource.ProductionURL})

			return carried{headers: []string{bearer(issued)}}
		}, gone),
		rowOf("grant: a token of a grant for the other deployment's login resource", "/grant-agent-read", func(r *rig) carried {
			issued := r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList(), resource: resource.DevelopmentLoginURL})

			return carried{headers: []string{bearer(issued)}}
		}, gone),
	}
}

// withCalls is the outcome with another number of store reads.
func (o outcome) withCalls(n int) outcome {
	o.storeCalls = n

	return o
}

// grantBothCarriers: a request that carries a cookie and an access token is as
// ambiguous as one with a key, and is refused before either is resolved.
func grantBothCarriers() []boundaryCase {
	token := func(r *rig) string {
		return "Bearer " + r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList()}).Token
	}

	both := func(headers func(*rig) string) carryFn {
		return func(r *rig) carried {
			return carried{headers: []string{headers(r)}, cookies: []*http.Cookie{sessionCookie(r.session())}}
		}
	}

	return []boundaryCase{
		rowOf("both: a valid session and a valid access token", "/grant-agent-read", both(token), unauthenticated(0, logBoth)),
		rowOf("both: a valid session and a garbage access token", "/grant-agent-read",
			both(func(*rig) string { return "Bearer susu_at_garbage" }), unauthenticated(0, logBoth)),
		rowOf("both: an empty cookie and a valid access token", "/grant-agent-read", func(r *rig) carried {
			return carried{headers: []string{token(r)}, cookies: []*http.Cookie{requestCookie(auth.CookieName, "")}}
		}, unauthenticated(0, logBoth)),
		rowOf("both: two Authorization headers, one an access token", "/grant-agent-read", func(r *rig) carried {
			return carried{headers: []string{token(r), "Bearer " + r.issueKey().Token}}
		}, unauthenticated(0, logTwoHeaders)),
	}
}

// grantKindCases: the bearer header is told what it holds by its tag, and a
// token of another kind is never resolved as a grant, nor a grant's body as
// another kind.
func grantKindCases() []boundaryCase {
	asBearer := func(token func(*rig) string) carryFn {
		return header(func(r *rig) string { return "Bearer " + token(r) })
	}
	body := func(r *rig) string {
		return strings.TrimPrefix(r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList()}).Token,
			secret.Prefix(secret.TagOAuthAccess))
	}
	under := func(tag secret.Tag) func(*rig) string {
		return func(r *rig) string { return secret.Prefix(tag) + body(r) }
	}

	parseKey := unauthenticated(0, input.CodeInvalidAPIKey).viaKey()

	return []boundaryCase{
		// A refresh token, a code, a session and an invitation are bearer secrets of
		// other places: the key's parser refuses each before the store is read.
		rowOf("kind: a refresh token as a bearer", "/grant-agent-read",
			asBearer(func(r *rig) string { return r.foreign(secret.TagOAuthRefresh) }), parseKey),
		rowOf("kind: a code as a bearer", "/grant-agent-read",
			asBearer(func(r *rig) string { return r.foreign(secret.TagOAuthCode) }), parseKey),
		rowOf("kind: a refresh token with a stored access token's body", "/grant-agent-read",
			asBearer(under(secret.TagOAuthRefresh)), parseKey),
		rowOf("kind: a code with a stored access token's body", "/grant-agent-read",
			asBearer(under(secret.TagOAuthCode)), parseKey),
		rowOf("kind: a session token with a stored access token's body", "/grant-agent-read",
			asBearer(under(secret.TagSession)), parseKey),
		rowOf("kind: an invitation with a stored access token's body", "/grant-agent-read",
			asBearer(under(secret.TagInvitation)), parseKey),
		// The same body under the key tag is another token: it parses as a key, is
		// asked of the store as a key, and is found nothing.
		rowOf("kind: a stored access token's body under the key tag", "/grant-agent-read",
			asBearer(under(secret.TagAPIKey)), unauthenticated(1, logNotActive).viaKey()),
		// A stored key's body under the access token tag is a grant lookup, and finds
		// nothing: the kinds are different hashes.
		rowOf("kind: a stored key's body under the access tag", "/grant-agent-read",
			asBearer(func(r *rig) string {
				return secret.Prefix(secret.TagOAuthAccess) +
					strings.TrimPrefix(r.apiKey(bearerSpec{scope: list()}).Token, secret.Prefix(secret.TagAPIKey))
			}), unauthenticated(1, logNotActive).viaGrant()),
		// The tag is compared as written.
		rowOf("kind: the access prefix in upper case", "/grant-agent-read",
			asBearer(func(r *rig) string { return strings.ToUpper(secret.Prefix(secret.TagOAuthAccess)) + body(r) }), parseKey),
		rowOf("kind: the access prefix in mixed case", "/grant-agent-read",
			asBearer(func(r *rig) string { return "susu_AT_" + body(r) }), parseKey),
		rowOf("kind: the brand in another case", "/grant-agent-read",
			asBearer(func(r *rig) string { return "SUSU_at_" + body(r) }), parseKey),
		rowOf("kind: a space before the prefix", "/grant-agent-read",
			asBearer(func(r *rig) string { return " " + secret.Prefix(secret.TagOAuthAccess) + body(r) }), parseKey),
		rowOf("kind: a lookalike tag", "/grant-agent-read",
			asBearer(func(r *rig) string { return "susu_att_" + body(r) }), parseKey),
		rowOf("kind: a prefix of the access tag", "/grant-agent-read",
			asBearer(func(r *rig) string { return "susu_a_" + body(r) }), parseKey),
	}
}

// TestGrantBearerMatrix is the table of what a bearer token that is, or is meant
// to be, an OAuth access token does at the boundary.
func TestGrantBearerMatrix(t *testing.T) {
	t.Parallel()

	names := map[string]bool{}

	for _, group := range [][]boundaryCase{grantCases(), grantBothCarriers(), grantKindCases()} {
		for _, tc := range group {
			if names[tc.name] {
				t.Fatalf("two cases are named %q", tc.name)
			}

			names[tc.name] = true

			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				r := newRig(t).with(tc.env)
				rec := r.serveCtx(r.grantRoutes(), tc.target, tc.presented(r), tc.cancelled)

				tc.checkResponse(t, r, rec)

				if got := len(r.handled); got != boolToInt(tc.want.handled) {
					t.Errorf("route ran %d times, want ran = %v", got, tc.want.handled)
				}

				if len(r.creds.calls) != tc.want.storeCalls {
					t.Errorf("store read %d times, want %d: %v", len(r.creds.calls), tc.want.storeCalls, r.creds.calls)
				}

				for _, call := range r.creds.calls {
					if call.kind != tc.want.kind || !call.now.Equal(r.now) {
						t.Errorf("store read = %+v, want kind %q at %v", call, tc.want.kind, r.now)
					}
				}
			})
		}
	}
}

// TestGrantRefusalsAreTheSameBytesAsEveryOther: whatever was wrong with an access
// token, the client gets the same 401, byte for byte, as for a session or a key.
func TestGrantRefusalsAreTheSameBytesAsEveryOther(t *testing.T) {
	t.Parallel()

	refusals := 0

	for _, group := range [][]boundaryCase{grantCases(), grantBothCarriers(), grantKindCases()} {
		for _, tc := range group {
			if tc.want.status != http.StatusUnauthorized {
				continue
			}

			refusals++

			r := newRig(t).with(tc.env)
			rec := r.serveCtx(r.grantRoutes(), tc.target, tc.presented(r), false)

			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated || len(r.handled) != 0 ||
				rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("WWW-Authenticate") != "" {
				t.Errorf("%s: %d %q %v", tc.name, rec.Code, rec.Body, rec.Header())
			}
		}
	}

	if refusals < 20 {
		t.Fatalf("only %d refusals were collected", refusals)
	}
}

// grantPrincipalCase is a stored access token and the Principal it must give.
type grantPrincipalCase struct {
	name string
	spec grantSpec
	want principalWant
}

// principalOf is a case: a token with this scope text and agent list (stored),
// and the lists the principal must carry and what is effective, for a member.
func principalOf(name, tokenScope, agentList string, credential, agent, effective []string) grantPrincipalCase {
	return grantPrincipalCase{
		name: name, spec: grantSpec{scope: tokenScope, agentScopes: agentList},
		want: principalWant{scope: credential, agentScope: agent, effective: sorted(effective...)},
	}
}

// grantPrincipalCases: the credential's list is the authsu names of the token's
// scope that the login resource allows now, and everything else about who the
// token speaks for is the stored row's.
func grantPrincipalCases() []grantPrincipalCase {
	every := []string{"sandbox:create", "sandbox:revoke", "org:read", "agent:create", "agent:read"}
	agentAll := grantAgentList()
	allNames := []string{"agent:read", "agent:create", "org:read", "sandbox:create", "sandbox:revoke"}
	session := bundleList(scope.DefaultSession)
	just := func(names ...string) []string { return names }
	admin := principalOf("the role and the organization are the stored row's", "agent:read", agentAll,
		just("agent:read"), allNames, just("agent:read"))
	admin.spec.role, admin.spec.org = auth.RoleAdmin, orgOne
	admin.want.role, admin.want.orgID = auth.RoleAdmin, orgOne

	return []grantPrincipalCase{
		principalOf("the whole login scope: openid and profile are dropped",
			"openid profile sandbox:create sandbox:revoke org:read agent:create agent:read", agentAll, every, allNames, every),
		principalOf("a token narrower than the grant: only what the token carries",
			"agent:read", agentAll, just("agent:read"), allNames, just("agent:read")),
		principalOf("a token the agent narrows", "agent:read agent:create", list("agent:read").JSON(),
			just("agent:read", "agent:create"), just("agent:read"), just("agent:read")),
		principalOf("the first-party agent of phase 2 has an empty list: nothing is effective",
			"profile agent:read org:read", none, just("agent:read", "org:read"), just(), just()),
		principalOf("openid and profile alone are no authsu scopes", "openid profile", agentAll, just(), allNames, just()),
		principalOf("order is kept as written", "org:read agent:read", agentAll,
			just("org:read", "agent:read"), allNames, just("agent:read", "org:read")),
		principalOf("a repeated name is held once", "agent:read agent:read", agentAll,
			just("agent:read"), allNames, just("agent:read")),
		principalOf("a name outside the allowlist is dropped, an authsu scope or not",
			"agent:read key:create user:read nope:x mcp:read", session,
			just("agent:read"), just(scope.DefaultSession), just("agent:read")),
		principalOf("a bundle is not a name of the allowlist and is dropped, not expanded",
			"default:user agent:read", session, just("agent:read"), just(scope.DefaultSession), just("agent:read")),
		principalOf("an empty stored scope is an empty list", "", agentAll, just(), allNames, just()),

		// How the stored text is cut into names (grantScope) is pinned here, as the
		// resolver will meet it. The text always comes from input.OAuthScopes, whose
		// names are separated by one space, so these are damaged values: each fails
		// closed (a name is kept only if it is spelled exactly as the allowlist
		// spells it, and anything else is no name) and never widens.
		principalOf("tokenisation: doubled spaces drop the empty names between, keep the rest",
			"agent:read  agent:create", agentAll, just("agent:read", "agent:create"), allNames, just("agent:read", "agent:create")),
		principalOf("tokenisation: many spaces", "agent:read     org:read", agentAll,
			just("agent:read", "org:read"), allNames, just("agent:read", "org:read")),
		principalOf("tokenisation: a leading space", " agent:read", agentAll, just("agent:read"), allNames, just("agent:read")),
		principalOf("tokenisation: a trailing space", "agent:read ", agentAll, just("agent:read"), allNames, just("agent:read")),
		principalOf("tokenisation: only spaces", "   ", agentAll, just(), allNames, just()),
		principalOf("tokenisation: a tab is not a separator, so the name is not one",
			"agent:read\torg:read", agentAll, just(), allNames, just()),
		principalOf("tokenisation: a tab beside a space", "agent:read\t org:read", agentAll,
			just("org:read"), allNames, just("org:read")),
		principalOf("tokenisation: a newline is not a separator", "agent:read\norg:read", agentAll, just(), allNames, just()),
		principalOf("tokenisation: a NUL inside a name is not that name", "agent:\x00read org:read", agentAll,
			just("org:read"), allNames, just("org:read")),
		principalOf("tokenisation: a NUL after a name is not that name", "agent:read\x00 org:read", agentAll,
			just("org:read"), allNames, just("org:read")),
		principalOf("tokenisation: a NUL alone", "\x00", agentAll, just(), allNames, just()),
		principalOf("tokenisation: uppercase is not folded", "AGENT:READ Agent:Read agent:Read", agentAll, just(), allNames, just()),
		principalOf("tokenisation: a name that is a prefix of an allowed one", "agent:rea agent:read:x agent:", agentAll,
			just(), allNames, just()),
		principalOf("tokenisation: a non-breaking space is not a separator", "agent:read\u00a0org:read", agentAll,
			just(), allNames, just()),
		principalOf("tokenisation: the order and repeats across doubled spaces", "org:read  agent:read  org:read", agentAll,
			just("org:read", "agent:read"), allNames, just("agent:read", "org:read")),
		principalOf("an agent list that is damaged is empty, so is the intersection",
			"agent:read", "not json", just("agent:read"), just(), just()),
		admin,
	}
}

// TestGrantPrincipal: who an access token speaks for is the stored row, read now,
// and its permissions are those of a key: its own list, narrowed by the agent's.
func TestGrantPrincipal(t *testing.T) {
	t.Parallel()

	for _, test := range grantPrincipalCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			issued := r.grant(test.spec)

			want := test.want
			want.secretID, want.expiresAt, want.kind = issued.ID, issued.ExpiresAt, auth.KindGrant

			want.agentID = agentOne
			if want.role == "" {
				want.role = roleMember
			}

			rec := r.serveWith(r.grantRoutes(), "/grant-open", []string{bearer(issued)}, nil)
			if rec.Code != http.StatusOK || len(r.handled) != 1 {
				t.Fatalf("status = %d, ran %d times: %s", rec.Code, len(r.handled), rec.Body)
			}

			checkPrincipal(t, r.handled[0].Principal, want)

			if got := r.handled[0].Principal.SandboxID; got != "" {
				t.Errorf("SandboxID = %q, want none: a grant of a sandboxed agent never resolves", got)
			}
		})
	}
}

// TestGrantSandboxIsTheRows: the principal's sandbox is the stored row's, and not
// assumed to be none. The statement admits no sandboxed agent, so this is a
// defence against its being relaxed: a grant whose row carried a sandbox is
// confined by the boundary like any sandboxed agent, refused on a route that has
// not opted in to sandboxes, and carrying the sandbox on one that has, and is
// never silently the user's whole reach.
func TestGrantSandboxIsTheRows(t *testing.T) {
	t.Parallel()

	const sandbox = "00000000-0000-7000-8000-0000000005a1"

	tests := []struct {
		name   string
		path   string
		status int
		code   string
		want   string
	}{
		{"a route that is not in a sandbox refuses it", "/grant-open", http.StatusForbidden, auth.CodeSandboxConfined, ""},
		{"a route in a sandbox carries it", "/grant-sandbox", http.StatusOK, "", sandbox},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			issued := r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList(), sandbox: sandbox})

			rec := r.serveWith(r.grantRoutes(), test.path, []string{bearer(issued)}, nil)
			if rec.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, test.status, rec.Body)
			}

			if test.status != http.StatusOK {
				wantFailure(t, r, rec, test.status, rec.Body.String(), test.code, nil)

				return
			}

			if got := r.handled[0].Principal.SandboxID; got != test.want {
				t.Errorf("SandboxID = %q, want %q", got, test.want)
			}
		})
	}
}

// TestGrantAsksTheLoginResourceOfTheDeployment: the resource a grant is looked
// up for is the login resource of the table API_ORIGIN selects, and only that
// one. The token's scope is narrowed by that table's allowlist, so a deployment
// whose allowlist drops a name cuts the live grants that hold it, the next
// request.
func TestGrantAsksTheLoginResourceOfTheDeployment(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env  map[string]string
		want string
	}{
		"production": {env: nil, want: resource.ProductionLoginURL},
		"a localhost origin selects the development table": {
			env: map[string]string{config.VarAPIOrigin: "http://localhost:8787"}, want: resource.DevelopmentLoginURL,
		},
		"a localhost origin without a port": {
			env: map[string]string{config.VarAPIOrigin: "http://localhost"}, want: resource.DevelopmentLoginURL,
		},
		"an https localhost is production": {
			env: map[string]string{config.VarAPIOrigin: "https://localhost"}, want: resource.ProductionLoginURL,
		},
		"a lookalike of localhost is production": {
			env: map[string]string{config.VarAPIOrigin: "http://localhost.evil.com"}, want: resource.ProductionLoginURL,
		},
		"an origin that does not parse is production": {
			env: map[string]string{config.VarAPIOrigin: "not an origin"}, want: resource.ProductionLoginURL,
		},
		"no origin at all is production": {
			env: map[string]string{config.VarAPIOrigin: ""}, want: resource.ProductionLoginURL,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t).with(tt.env)
			issued := r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList(), resource: tt.want})

			rec := r.serveWith(r.grantRoutes(), "/grant-agent-read", []string{bearer(issued)}, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body)
			}

			if len(r.creds.calls) != 1 || r.creds.calls[0].resource != tt.want {
				t.Errorf("store reads = %+v, want one for the resource %s", r.creds.calls, tt.want)
			}

			// A token of the other deployment's login resource, the MCP resource's or
			// of no resource is found nothing.
			for _, other := range []string{
				resource.ProductionLoginURL, resource.DevelopmentLoginURL, resource.ProductionURL, resource.DevelopmentURL,
			} {
				if other == tt.want {
					continue
				}

				r := newRig(t).with(tt.env)
				elsewhere := r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList(), resource: other})

				rec := r.serveWith(r.grantRoutes(), "/grant-agent-read", []string{bearer(elsewhere)}, nil)
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("a token for %s was accepted by a deployment whose login resource is %s: %d", other, tt.want, rec.Code)
				}
			}
		})
	}
}

// TestGrantIsReadLiveEveryRequest: the grant's scope, the agent's list and the
// role are the store's at each request, so a change to any of them takes effect
// on the next request with the same token, and nothing is remembered.
func TestGrantIsReadLiveEveryRequest(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	issued := r.grant(grantSpec{scope: "agent:read", agentScopes: list("agent:read").JSON()})

	change := func(edit func(*fakeGrant)) {
		held := r.creds.grants[issued.Token]
		edit(&held)
		r.creds.grants[issued.Token] = held
	}

	revoke := func(*fakeGrant) { delete(r.creds.grants, issued.Token) }

	steps := []struct {
		name string
		edit func(*fakeGrant)
		path string
		want int
	}{
		{"as issued", func(*fakeGrant) {}, "/grant-agent-read", http.StatusOK},
		{"the agent's list loses the scope", func(g *fakeGrant) { g.row.AgentScopes = "[]" }, "/grant-agent-read", http.StatusForbidden},
		{"the agent's list gets it back", func(g *fakeGrant) { g.row.AgentScopes = `["agent:read"]` }, "/grant-agent-read", http.StatusOK},
		{"a refresh narrows the token", func(g *fakeGrant) { g.row.Scope = "profile" }, "/grant-agent-read", http.StatusForbidden},
		{"the token is widened by a new grant", func(g *fakeGrant) { g.row.Scope = "agent:read" }, "/grant-agent-read", http.StatusOK},
		{"the user is promoted", func(g *fakeGrant) { g.row.Role = auth.RoleAdmin }, "/grant-agent-read", http.StatusOK},
		{"the allowlist never grants the admin scope the role would", func(g *fakeGrant) {
			g.row.Scope, g.row.AgentScopes = "user:read", list(scope.DefaultSession).JSON()
		}, "/grant-user-read", http.StatusForbidden},
		{"the grant is revoked", nil, "/grant-agent-read", http.StatusUnauthorized},
	}

	for _, step := range steps {
		if step.edit == nil {
			revoke(nil)
		} else {
			change(step.edit)
		}

		rec := r.serveWith(r.grantRoutes(), step.path, []string{bearer(issued)}, nil)
		if rec.Code != step.want {
			t.Errorf("%s: status = %d, want %d: %s", step.name, rec.Code, step.want, rec.Body)
		}

		r.logged = nil
	}
}

// TestGrantIsNotASession: a grant never passes where a session is needed, for
// every route shape, even one that opts in to grants, and the principal's kind
// is the grant's whatever the stored row says.
func TestGrantIsNotASession(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	issued := r.grant(grantSpec{scope: "agent:read", role: auth.RoleAdmin, agentScopes: list(scope.DefaultSession).JSON()})

	rec := r.serveWith(r.grantRoutes(), "/grant-sessions", []string{bearer(issued)}, nil)
	wantFailure(t, r, rec, http.StatusForbidden,
		errorBody(auth.CodeForbidden, "a signed-in session is required"), auth.CodeForbidden, nil)

	if len(r.handled) != 0 {
		t.Error("a grant reached a session-only route")
	}
}

// TestGrantNeedsADeploymentWithALoginResource: a grant is looked up only for the
// login resource of the deployment. A boundary built with a resource table that
// has none resolves nothing, and is a refusal like any inactive credential, never
// a crash and never a different answer.
func TestGrantNeedsADeploymentWithALoginResource(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	issued := r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList()})

	deps := r.deps()
	deps.Resources = func(string) resource.Table { return resource.Table{} }

	rec := r.serveWithDepsCarried(deps, r.grantRoutes(), "/grant-agent-read", []string{bearer(issued)}, nil)

	if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated || len(r.handled) != 0 {
		t.Errorf("response = %d %q, handled %d times", rec.Code, rec.Body, len(r.handled))
	}

	if len(r.creds.calls) != 0 {
		t.Errorf("the store was read %d times for a deployment with no login resource", len(r.creds.calls))
	}

	if len(r.logged) != 1 || !strings.Contains(chainText(r.logged[0]), "no first-party login resource") {
		t.Errorf("logged = %v", r.logged)
	}
}

// TestSessionsAndKeysNeverAskForTheResourceTable: only a request that presents an
// access token reads API_ORIGIN or the resource table, so a session or a key is
// resolved as it always was, whatever the deployment's origin says.
func TestSessionsAndKeysNeverAskForTheResourceTable(t *testing.T) {
	t.Parallel()

	r := newRig(t).with(map[string]string{config.VarAPIOrigin: ""})

	asked := 0
	deps := r.deps()
	deps.Resources = func(string) resource.Table {
		asked++

		return resource.Table{}
	}

	session := r.session()
	key := r.apiKey(bearerSpec{scope: list()})

	for _, call := range []struct {
		header  []string
		cookies []*http.Cookie
	}{{nil, []*http.Cookie{sessionCookie(session)}}, {[]string{bearer(key)}, nil}} {
		rec := r.serveWithDepsCarried(deps, r.standardRoutes(), pathMe, call.header, call.cookies)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d: %s", rec.Code, rec.Body)
		}
	}

	if asked != 0 {
		t.Errorf("the resource table was asked for %d times by a session and a key", asked)
	}
}

// TestGrantDependenciesAreRequired: a boundary built without the resource
// selector panics when it is built, like every other missing dependency, and not
// when the first grant arrives.
func TestGrantDependenciesAreRequired(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	deps := r.deps()
	deps.Resources = nil

	defer func() {
		if recover() == nil {
			t.Error("a boundary without Resources was built")
		}
	}()

	auth.Handler(r.grantRoutes(), deps)
}

// TestGrantKindIsTheStoresKind: the kind a grant's principal carries is the one
// the store records for an access token, so the two cannot drift.
func TestGrantKindIsTheStoresKind(t *testing.T) {
	t.Parallel()

	if auth.KindGrant != "oauth_access" {
		t.Errorf("KindGrant = %q", auth.KindGrant)
	}

	kinds := []string{auth.KindSession, auth.KindAPIKey, auth.KindGrant}

	seen := map[string]bool{}

	for _, kind := range kinds {
		if seen[kind] {
			t.Errorf("two kinds are %q", kind)
		}

		seen[kind] = true
	}
}

// TestGrantLifetimeIsTheTokensOwn: the principal's expiry is the access token's,
// read now.
func TestGrantLifetimeIsTheTokensOwn(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	issued := r.grant(grantSpec{scope: "agent:read", agentScopes: grantAgentList()})

	rec := r.serveWith(r.grantRoutes(), "/grant-open", []string{bearer(issued)}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	if got, want := r.handled[0].Principal.ExpiresAt, r.now.Add(auth.AccessTokenLifetime); !got.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", got, want)
	}

	if r.handled[0].Principal.ExpiresAt.Sub(r.now) != 15*time.Minute {
		t.Errorf("a grant's token lives %v", r.handled[0].Principal.ExpiresAt.Sub(r.now))
	}
}
