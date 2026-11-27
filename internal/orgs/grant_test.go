//nolint:goconst,lll // table-driven tests repeat case names and inputs on purpose, and the case table is the test; a constant or a line break per row would hide it
package orgs_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file is the OAuth grant's half of the organization routes
// (docs/oauth_design.md): the first-party app's access token reads organizations
// and creates and deletes sandboxes, and reaches nothing else here. It drives the
// real boundary over the real route declarations.

// everyLoginScope is the token text of a login grant that holds every authsu
// scope the login resource defines.
const everyLoginScope = "profile sandbox:create sandbox:revoke org:read agent:create agent:read"

// loginAgent is the first-party agent's list: every scope a login can hold.
func loginAgent() scope.List {
	return scopes(scope.SandboxCreate, scope.SandboxRevoke, scope.OrgRead, scope.AgentCreate, scope.AgentRead)
}

// grantCase is one grant presented to one route and what the boundary answers.
type grantCase struct {
	name string
	// route is the catalog entry, by name.
	route string
	spec  grantSpec
	// status is the refusal's status, 0 when the route runs and the store is
	// asked once; code is the refusal's code.
	status int
	code   string
}

// grantCases: the four routes a grant may use are permitted when the token and
// its agent both hold the scope, and lack it when either does not; every other
// route is refused with the grant's own code, however much the grant holds.
func grantCases() []grantCase {
	generous := grantSpec{scope: everyLoginScope, agentScopes: loginAgent(), role: roleAdmin}
	lacks := outcome{status: http.StatusForbidden, code: auth.CodeInsufficientScope}

	var cases []grantCase

	for _, route := range catalog() {
		switch {
		case route.grant:
			holds := string(route.scope)
			cases = append(cases,
				grantCase{route.name + ": the token and the agent hold the scope", route.name,
					grantSpec{scope: "profile " + holds, agentScopes: scopes(route.scope)}, 0, ""},
				grantCase{route.name + ": the token lacks the scope", route.name,
					grantSpec{scope: "profile", agentScopes: loginAgent()}, lacks.status, lacks.code},
				grantCase{route.name + ": the token holds another scope only", route.name,
					grantSpec{scope: "profile agent:read", agentScopes: loginAgent()}, lacks.status, lacks.code},
				grantCase{route.name + ": the agent lacks the scope", route.name,
					grantSpec{scope: everyLoginScope, agentScopes: scopes(scope.AgentRead)}, lacks.status, lacks.code},
				grantCase{route.name + ": the agent's list is empty", route.name,
					grantSpec{scope: everyLoginScope, agentScopes: scopes()}, lacks.status, lacks.code},
				grantCase{route.name + ": a member with everything is let in, no role is needed", route.name,
					grantSpec{scope: everyLoginScope, agentScopes: loginAgent(), role: roleMember}, 0, ""},
				grantCase{route.name + ": an administrator is no different", route.name, generous, 0, ""},
			)
		default:
			cases = append(cases, grantCase{route.name + ": refused whatever the grant holds", route.name, generous,
				http.StatusForbidden, auth.CodeGrantNotAccepted})
		}
	}

	return cases
}

// TestGrantAtTheCatalog is the permission table of a grant over every route.
func TestGrantAtTheCatalog(t *testing.T) {
	t.Parallel()

	names := map[string]bool{}

	for _, test := range grantCases() {
		if names[test.name] {
			t.Fatalf("two cases are named %q", test.name)
		}

		names[test.name] = true

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			at := slices.IndexFunc(catalog(), func(route catalogRoute) bool { return route.name == test.route })
			route := catalog()[at]

			rg := newRig(t)
			rec := rg.serve(request{
				method: route.method, target: route.target, body: route.body, authorization: rg.signInGrant(test.spec),
			})

			if test.status == 0 {
				if len(rg.store.calls) != 1 {
					t.Errorf("store calls = %q (status %d), want exactly one", rg.store.calls, rec.Code)
				}

				return
			}

			wantRefused(t, rg, rec, test.code)
		})
	}
}

// TestGrantActsAsTheUser: a grant that runs a route is the user to the store: it
// is asked as the grant's user, never as the agent, and with NO platform role (an
// empty one), whatever the user's role is. The platform administrator's override
// is a power of a person's session; a grant manages only the sandboxes its user
// administers (auth.Principal.PlatformRole, and the write's own condition,
// store.platformOverride). The same routes asked with a session or a key pass the
// platform role, which is how the grant is told apart.
func TestGrantActsAsTheUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		route  string
		prefix string
	}{
		{"create sandbox", "create sandbox", "CreateSandbox id=" + newID + " name=Scratch creator=" + userID},
		{"list orgs", "list orgs", "ListOrgs caller=" + userID + " role= "},
		{"get org", "get org", "GetOrg id=" + orgID + " caller=" + userID + " role="},
		{"delete sandbox", "delete sandbox", "DeleteSandbox id=" + orgID + " caller=" + userID + " role="},
	}

	// Whatever the user's role: the admin user's grant is no administrator either.
	for _, user := range []string{roleMember, roleAdmin} {
		spec := grantSpec{scope: everyLoginScope, agentScopes: loginAgent(), role: user}

		for _, test := range tests {
			t.Run(user+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				at := slices.IndexFunc(catalog(), func(route catalogRoute) bool { return route.name == test.route })
				route := catalog()[at]

				rg := newRig(t)
				rg.serve(request{
					method: route.method, target: route.target, body: route.body, authorization: rg.signInGrant(spec),
				})

				if len(rg.store.calls) != 1 || !strings.HasPrefix(rg.store.calls[0], test.prefix) ||
					strings.Contains(rg.store.calls[0], "role=admin") {
					t.Errorf("store calls = %q, want one starting %q, with no platform role", rg.store.calls, test.prefix)
				}
			})
		}
	}
}

// TestGrantDeletesOnlyASandboxTheUserAdministers: whose sandbox a grant may delete
// is the store's answer for the user, mapped as for a session: another user's, or
// one that does not exist, is not found; a standard organization is never deleted.
func TestGrantDeletesOnlyASandboxTheUserAdministers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"another user's sandbox is not found", store.ErrNotFound, http.StatusNotFound, "org_not_found"},
		{"a sandbox the user sees and does not administer", store.ErrNotAdmin, http.StatusForbidden, "org_admin_required"},
		{"a standard organization", store.ErrNotSandbox, http.StatusConflict, "org_not_sandbox"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.store.remove = reply[store.Org]{err: test.err}

			rec := rg.serve(request{
				method: http.MethodDelete, target: "/api/org/" + sandboxID,
				authorization: rg.signInGrant(grantSpec{scope: everyLoginScope, agentScopes: loginAgent()}),
			})

			if rec.Code != test.status || len(rg.logged) != 1 || rg.logged[0].Code != test.code {
				t.Errorf("= %d, logged %v; want %d %q", rec.Code, rg.logged, test.status, test.code)
			}
		})
	}
}

// TestAgentKeysStillRefusedWhereTheyWere: letting a grant through the refusal of
// agents lets nothing else through. An agent's API key, whatever scopes it and
// its agent hold, is refused on the writes it always was, and a sandboxed agent
// everywhere.
func TestAgentKeysStillRefusedWhereTheyWere(t *testing.T) {
	t.Parallel()

	for _, route := range catalog() {
		if !route.grant || route.reads {
			continue
		}

		for name, sandbox := range map[string]string{"an agent key": "", "an agent key of a sandbox": sandboxID} {
			t.Run(route.name+"/"+name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				header := rg.signInKey(keySpec{
					scope: loginAgent(), agent: "agent-1", agentScopes: loginAgent(), sandbox: sandbox,
				})

				code := auth.CodeForbidden
				if sandbox != "" {
					code = auth.CodeSandboxConfined
				}

				wantRefused(t, rg, rg.serve(request{
					method: route.method, target: route.target, body: route.body, authorization: header,
				}), code)
			})
		}
	}
}

// TestGrantAndSessionAreNotMixed: a request carrying a grant's token and a
// session cookie is ambiguous and is refused before any route runs.
func TestGrantAndSessionAreNotMixed(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.serve(request{
		method: http.MethodGet, target: "/api/org", cookies: []*http.Cookie{rg.signIn(otherID, roleMember)},
		authorization: rg.signInGrant(grantSpec{scope: everyLoginScope, agentScopes: loginAgent()}),
	})

	if rec.Code != http.StatusUnauthorized || len(rg.store.calls) != 0 {
		t.Errorf("= %d, store calls %q; want 401 and none", rec.Code, rg.store.calls)
	}
}
