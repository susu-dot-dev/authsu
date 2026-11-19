package keys_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// credential builds a request's credential on a rig and returns how to present
// it: a cookie for a session, an Authorization value for an API key.
type credential struct {
	name string
	// session is true for a passkey session.
	session bool
	spec    keySpec
}

// everyScope is a list that names every scope, admin ones included, so a
// credential is never refused for lacking one.
func everyScope() scope.List { return scope.List{scope.DefaultSession} }

// credentials are the kinds of caller the key routes meet: a session, a user's
// own key (with and without the scopes), and an agent's key (whose own scopes
// and whose agent's scopes must both allow).
func credentials() []credential {
	return []credential{
		{name: "a session", session: true},
		{name: "a user key holding every scope", spec: keySpec{owner: userA, role: roleMember, scope: everyScope()}},
		{name: "a user key holding the user bundle", spec: keySpec{
			owner: userA, role: roleMember, scope: scope.List{scope.DefaultUser},
		}},
		{name: "a user key with no scopes", spec: keySpec{owner: userA, role: roleMember, scope: scope.List{}}},
		{name: "an agent holding every scope", spec: keySpec{
			owner: userA, role: roleMember, scope: everyScope(), agent: agentA1, agentScopes: everyScope().JSON(),
		}},
		{name: "an agent whose key holds every scope but whose own list is empty", spec: keySpec{
			owner: userA, role: roleMember, scope: everyScope(), agent: agentA1, agentScopes: "[]",
		}},
	}
}

// present sends the request of route with c's credential.
func (c credential) present(rg *rig, route keyRoute) *httptest.ResponseRecorder {
	if c.session {
		return rg.as(rg.signIn(userA, roleMember), route.method, route.target, route.body)
	}

	header, _ := rg.signInKey(c.spec)

	return rg.withKey(header, route.method, route.target, route.body)
}

// outcome is what a credential gets from a route: a status and, for a refusal,
// the code it was logged under.
type outcome struct {
	status int
	code   string
}

// expectations is the outcome for each credential, in credentials()'s order, per
// route.
//
// Creating needs a session, and refuses agents whatever they hold. The scope is
// checked first, then session-only, then agents.
func expectations() map[string][]outcome {
	const (
		ok        = http.StatusOK
		okCreated = http.StatusCreated
		noScope   = auth.CodeInsufficientScope
		noAccess  = auth.CodeForbidden
	)

	scopeless := outcome{http.StatusForbidden, noScope}
	refused := outcome{http.StatusForbidden, noAccess}
	allowed := outcome{ok, ""}

	return map[string][]outcome{
		routeList:   {allowed, allowed, allowed, scopeless, allowed, scopeless},
		routeGet:    {allowed, allowed, allowed, scopeless, allowed, scopeless},
		routeCreate: {{okCreated, ""}, refused, refused, scopeless, refused, scopeless},
		routePatch:  {allowed, allowed, allowed, scopeless, refused, scopeless},
		routeRevoke: {allowed, allowed, allowed, scopeless, refused, scopeless},
	}
}

// TestAccessMatrix is the permission-confusion table of the whole API: every
// credential against every route, and the one answer each must get. A refusal is
// always before the handler: the store is never read and nothing is written.
//
//   - a session may do everything (its scopes are every scope);
//   - a user's own key may list, read, rename and revoke if it names the scope,
//     and may never issue keys (that needs a session);
//   - an agent may list and read keys it holds key:read for, and never create,
//     rename or revoke whatever it holds (agents are peers under their user).
func TestAccessMatrix(t *testing.T) {
	t.Parallel()

	want := expectations()

	for _, route := range everyRoute() {
		for i, cred := range credentials() {
			t.Run(route.name+"/"+cred.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(keyA1, nameCI, 1, nil))

				rec := cred.present(rg, route)
				expected := want[route.name][i]

				if rec.Code != expected.status {
					t.Fatalf("%s with %s = %d %s, want %d", route.name, cred.name, rec.Code, rec.Body, expected.status)
				}

				if expected.code == "" {
					return
				}

				if len(rg.logged) != 1 || rg.logged[0].Code != expected.code {
					t.Errorf("logged %v, want one %q", rg.logged, expected.code)
				}

				if rg.writes() != 0 || len(rg.issueCalls) != 0 || len(rg.store.calls) != 0 {
					t.Errorf("a refused request reached the store (%+v) or issued %d keys", rg.store.calls, len(rg.issueCalls))
				}
			})
		}
	}
}
