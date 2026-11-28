//nolint:goconst,lll // table-driven tests repeat case names and inputs on purpose, and the case table is the test; a constant or a line break per row would hide it
package agents_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// This file is the OAuth grant's half of the agent routes
// (docs/oauth_design.md): the first-party app's access token lists and reads the
// agents of the sandboxes the user administers, and creates agents only inside
// one, with lists both the token and its agent hold. It
// drives the real boundary, so the route declarations are what is tested.

const (
	// tokenAgents is the scope text of a login grant that holds the agent scopes,
	// and tokenAll every authsu scope the login resource defines.
	tokenAgents = "profile agent:read agent:create"
	tokenAll    = "profile sandbox:create sandbox:revoke org:read agent:create agent:read"

	// damagedList is a stored agent list that is not a list of names.
	damagedList = "not a list"

	codeGrantNeedsSandbox   = agents.CodeGrantNeedsSandbox
	codeGrantScopesExceeded = agents.CodeGrantScopesExceeded
)

// agentGrantList is the first-party agent's list: every scope a login can hold.
func agentGrantList() string {
	return scope.List{"sandbox:create", "sandbox:revoke", "org:read", "agent:create", "agent:read"}.JSON()
}

// grantRig is a rig with user A's sandboxes and agents, and a first-party agent.
func grantRig(t *testing.T) *rig {
	t.Helper()

	return sandboxRig(t)
}

// asGrant sends method target with body, authorized by a grant of spec. A create
// carries a publicKey, as every client's does, unless the body names one.
func (r *rig) asGrant(spec grantSpec, method, target, body string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.withKey(r.signInGrant(spec), method, target, body)
}

// TestGrantReadsRoutes: each read route is permitted when both the token and the
// agent hold the scope, lacks the scope when either does not, and the list and
// the read reach only the agents of the sandboxes the user administers.
func TestGrantReadsRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		spec   grantSpec
		target string
		want   int
		code   string
	}{
		{"list, token and agent hold agent:read", grantSpec{scope: tokenAgents, agentScopes: agentGrantList()}, collection, http.StatusOK, ""},
		{"get, token and agent hold agent:read", grantSpec{scope: tokenAgents, agentScopes: agentGrantList()}, itemPrefix + agentInMine1, http.StatusOK, ""},
		{"get an ordinary agent of the user: not the app's business", grantSpec{scope: tokenAgents, agentScopes: agentGrantList()}, itemPrefix + agentA1, http.StatusNotFound, agents.CodeNotFound},
		{"get an agent in a sandbox the user does not administer", grantSpec{scope: tokenAgents, agentScopes: agentGrantList()}, itemPrefix + agentInDemoted, http.StatusNotFound, agents.CodeNotFound},
		{"list, the token lacks it", grantSpec{scope: "profile org:read", agentScopes: agentGrantList()}, collection, http.StatusForbidden, auth.CodeInsufficientScope},
		{"get, the token lacks it", grantSpec{scope: "profile org:read", agentScopes: agentGrantList()}, itemPrefix + agentInMine1, http.StatusForbidden, auth.CodeInsufficientScope},
		{"list, the agent lacks it", grantSpec{scope: tokenAgents, agentScopes: `["org:read"]`}, collection, http.StatusForbidden, auth.CodeInsufficientScope},
		{"get, the agent lacks it", grantSpec{scope: tokenAgents, agentScopes: `["org:read"]`}, itemPrefix + agentInMine1, http.StatusForbidden, auth.CodeInsufficientScope},
		{"list, the agent's list is empty", grantSpec{scope: tokenAgents, agentScopes: `[]`}, collection, http.StatusForbidden, auth.CodeInsufficientScope},
		{"list, the agent's list is damaged", grantSpec{scope: tokenAgents, agentScopes: damagedList}, collection, http.StatusForbidden, auth.CodeInsufficientScope},
		{"get, an agent of another user is not found", grantSpec{scope: tokenAgents, agentScopes: agentGrantList()}, itemPrefix + agentB1, http.StatusNotFound, agents.CodeNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rg := grantRig(t)
			rec := rg.asGrant(test.spec, http.MethodGet, test.target, "")

			if rec.Code != test.want {
				t.Fatalf("status = %d, body %s, want %d", rec.Code, rec.Body, test.want)
			}

			if test.code != "" {
				wantCode(t, rg, rec, test.want, test.code)
			}
		})
	}
}

// agentInDemoted is an agent of user A in a sandbox that user A owns agents in but
// no longer administers (sandboxDemoted is administered by user B).
const (
	sandboxDemoted = "00000000-0000-7000-8000-0000000005d1"
	agentInDemoted = "00000000-0000-7000-8000-0000000006d1"
)

// TestGrantListShowsOnlyAgentsOfSandboxesTheUserAdministers: a grant manages the
// user's sandboxes, so what it reaches is the agents in the sandboxes the user
// administers, whatever agent holds it, and nothing else: no ordinary agent of the
// user's, no agent of a sandbox someone else administers, and no one else's.
func TestGrantListShowsOnlyAgentsOfSandboxesTheUserAdministers(t *testing.T) {
	t.Parallel()

	rg := grantRig(t)
	rg.store.sandboxes[sandboxDemoted] = fakeSandbox{admin: userB, expired: false}
	rg.seed(userA, withSandbox(stored(agentInDemoted, "in demoted", 700, nil), sandboxDemoted))

	rec := rg.asGrant(grantSpec{scope: tokenAgents, agentScopes: agentGrantList()}, http.MethodGet, collection+"?limit=100", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	var page agents.ListResponse

	err := json.Unmarshal(rec.Body.Bytes(), &page)
	if err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}

	got := make([]string, 0, len(page.Agents))
	for _, agent := range page.Agents {
		got = append(got, agent.ID)
	}

	want := []string{agentInSecond, agentInMine2, agentInMine1}
	if !slices.Equal(got, want) {
		t.Errorf("the list = %v, want only the agents of the sandboxes the user administers %v", got, want)
	}

	call := rg.store.calls[len(rg.store.calls)-1]
	if call.owner != userA || call.confined {
		t.Errorf("list was made as owner %q confined=%t, want the user's, not confined to one sandbox", call.owner, call.confined)
	}
}

// grantCreate is one create through a grant and what must come of it.
type grantCreate struct {
	name string
	spec grantSpec
	body map[string]any
	want int
	// code is the code logged on a refusal.
	code string
	// agentList and keyList are what the new agent and its key must hold on
	// success.
	agentList, keyList []string
	sandbox            string
}

// grantAllowed is a token and an agent that hold every login scope.
func grantAllowed() grantSpec { return grantSpec{scope: tokenAll, agentScopes: agentGrantList()} }

// namedBody is the body of a create into the user's sandbox, with extra members.
func namedBody(extra map[string]any) map[string]any {
	body := map[string]any{"name": "box", "sandboxId": sandboxMine}
	maps.Copy(body, extra)

	return body
}

// grantCreates are the creates a login grant may attempt. The grant holds the
// agent and sandbox scopes in its token and in its agent, so a list is allowed
// when each of its entries is an entry of both lists as written.
func grantCreates() []grantCreate {
	return slices.Concat(grantCreatesWithinTheGrant(), grantCreatesBoundByTheAgent(), grantCreatesRefused())
}

// grantCreatesWithinTheGrant are the creates the token and its agent both allow,
// and the refusals of the request's own shape.
func grantCreatesWithinTheGrant() []grantCreate {
	allowed, named := grantAllowed(), namedBody
	held := []string{"sandbox:create", "sandbox:revoke", "org:read", "agent:create", "agent:read"}

	return []grantCreate{
		{name: "a sandbox the user administers, lists defaulting to the grant's own", spec: allowed, body: named(nil),
			want: http.StatusCreated, agentList: held, keyList: held, sandbox: sandboxMine},
		{name: "a narrower agent and key list", spec: allowed,
			body: named(map[string]any{fieldScopes: []string{"agent:read"}, fieldKeyScopes: []string{"agent:read"}}),
			want: http.StatusCreated, agentList: []string{"agent:read"}, keyList: []string{"agent:read"}, sandbox: sandboxMine},
		{name: "an empty list is a credential that holds nothing", spec: allowed,
			body: named(map[string]any{fieldScopes: []string{}, fieldKeyScopes: []string{}}),
			want: http.StatusCreated, agentList: []string{}, keyList: []string{}, sandbox: sandboxMine},
		{name: "no sandbox is refused", spec: allowed, body: map[string]any{"name": "box"},
			want: http.StatusForbidden, code: codeGrantNeedsSandbox},
		{name: "a null sandbox is no sandbox", spec: allowed, body: map[string]any{"name": "box", "sandboxId": nil},
			want: http.StatusForbidden, code: codeGrantNeedsSandbox},
		{name: "an agent list beyond the grant's", spec: grantSpec{scope: tokenAgents, agentScopes: agentGrantList()},
			body: named(map[string]any{fieldScopes: []string{"org:read"}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "a key list beyond the grant's", spec: grantSpec{scope: tokenAgents, agentScopes: agentGrantList()},
			body: named(map[string]any{fieldKeyScopes: []string{"sandbox:create"}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
	}
}

// grantCreatesBoundByTheAgent are the creates where the agent's list and the
// token's differ. The agent's list is the primary ceiling, and the token's only
// narrows it, so a list is allowed only when its entries are in both, as written,
// and an absent one defaults to the entries in both, in the token's order.
func grantCreatesBoundByTheAgent() []grantCreate {
	named := namedBody

	return []grantCreate{
		{name: "the agent is narrower than the token: the default is the agent's", spec: grantSpec{scope: tokenAll, agentScopes: `["agent:create","org:read"]`},
			body: named(nil), want: http.StatusCreated, agentList: []string{"org:read", "agent:create"}, keyList: []string{"org:read", "agent:create"}, sandbox: sandboxMine},
		{name: "the agent is narrower than the token: a request within the agent", spec: grantSpec{scope: tokenAll, agentScopes: `["agent:create","org:read"]`},
			body: named(map[string]any{fieldScopes: []string{"org:read"}, fieldKeyScopes: []string{"agent:create"}}),
			want: http.StatusCreated, agentList: []string{"org:read"}, keyList: []string{"agent:create"}, sandbox: sandboxMine},
		{name: "the agent is narrower than the token: an agent list beyond the agent's", spec: grantSpec{scope: tokenAll, agentScopes: `["agent:create"]`},
			body: named(map[string]any{fieldScopes: []string{"sandbox:revoke", "org:read"}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "the agent is narrower than the token: a key list beyond the agent's", spec: grantSpec{scope: tokenAll, agentScopes: `["agent:create"]`},
			body: named(map[string]any{fieldKeyScopes: []string{"org:read"}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "the token is narrower than the agent: a list beyond the token's", spec: grantSpec{scope: "profile agent:create org:read", agentScopes: agentGrantList()},
			body: named(map[string]any{fieldScopes: []string{"sandbox:revoke"}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "the token is narrower than the agent: the default is the token's", spec: grantSpec{scope: "profile agent:create org:read", agentScopes: agentGrantList()},
			body: named(nil), want: http.StatusCreated, agentList: []string{"agent:create", "org:read"}, keyList: []string{"agent:create", "org:read"}, sandbox: sandboxMine},
		{name: "the token and the agent are disjoint but for the route's scope: the default is that one", spec: grantSpec{scope: "profile agent:create org:read", agentScopes: `["agent:create","sandbox:create"]`},
			body: named(nil), want: http.StatusCreated, agentList: []string{"agent:create"}, keyList: []string{"agent:create"}, sandbox: sandboxMine},
		{name: "the token and the agent are disjoint but for the route's scope: the token's other scope", spec: grantSpec{scope: "profile agent:create org:read", agentScopes: `["agent:create","sandbox:create"]`},
			body: named(map[string]any{fieldKeyScopes: []string{"org:read"}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "the token and the agent are disjoint but for the route's scope: the agent's other scope", spec: grantSpec{scope: "profile agent:create org:read", agentScopes: `["agent:create","sandbox:create"]`},
			body: named(map[string]any{fieldScopes: []string{"sandbox:create"}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "the agent's list is a bundle: members of it are not entries", spec: grantSpec{scope: tokenAll, agentScopes: scope.List{scope.DefaultAgent}.JSON()},
			body: named(map[string]any{fieldScopes: []string{"agent:read"}}),
			want: http.StatusForbidden, code: auth.CodeInsufficientScope},
	}
}

// grantCreatesRefused are the other refusals: bundles, admin scopes, the sandbox
// and the scope the route itself needs.
func grantCreatesRefused() []grantCreate {
	allowed, named := grantAllowed(), namedBody

	return []grantCreate{
		{name: "a bundle is not an entry of the grant's list", spec: allowed,
			body: named(map[string]any{fieldScopes: []string{scope.DefaultAgent}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "the session bundle", spec: allowed,
			body: named(map[string]any{fieldKeyScopes: []string{scope.DefaultSession}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "an admin scope the grant cannot hold", spec: allowed,
			body: named(map[string]any{fieldScopes: []string{"user:read"}}),
			want: http.StatusForbidden, code: codeGrantScopesExceeded},
		{name: "a sandbox of another user", spec: allowed, body: map[string]any{"name": "box", "sandboxId": sandboxOther},
			want: http.StatusNotFound, code: codeSandboxNotFound},
		{name: "a sandbox that has expired", spec: allowed, body: map[string]any{"name": "box", "sandboxId": sandboxExpired},
			want: http.StatusNotFound, code: codeSandboxNotFound},
		{name: "a sandbox that does not exist", spec: allowed, body: map[string]any{"name": "box", "sandboxId": sandboxNone},
			want: http.StatusNotFound, code: codeSandboxNotFound},
		{name: "the token lacks agent:create", spec: grantSpec{scope: "profile agent:read", agentScopes: agentGrantList()}, body: named(nil),
			want: http.StatusForbidden, code: auth.CodeInsufficientScope},
		{name: "the agent lacks agent:create", spec: grantSpec{scope: tokenAll, agentScopes: `["agent:read"]`}, body: named(nil),
			want: http.StatusForbidden, code: auth.CodeInsufficientScope},
		{name: "a token holding only the sandbox scopes cannot create agents", spec: grantSpec{scope: "profile sandbox:create", agentScopes: agentGrantList()}, body: named(nil),
			want: http.StatusForbidden, code: auth.CodeInsufficientScope},
	}
}

// TestGrantCreate is the create table through a grant: only into a sandbox the
// user administers, lists within the grant's own, and the write is the user's
// (the new agent is not a copy of the first-party agent's row).
func TestGrantCreate(t *testing.T) {
	t.Parallel()

	for _, test := range grantCreates() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rg := grantRig(t)
			before := len(rg.store.calls)

			encoded, err := json.Marshal(test.body)
			if err != nil {
				t.Fatal(err)
			}

			rec := rg.asGrant(test.spec, http.MethodPost, collection, string(encoded))

			if rec.Code != test.want {
				t.Fatalf("status = %d, body %s, want %d", rec.Code, rec.Body, test.want)
			}

			if test.want == http.StatusCreated {
				checkGrantCreated(t, rg, rec, test)

				return
			}

			wantCode(t, rg, rec, test.want, test.code)

			// A refusal of the request itself writes nothing: only the store's own
			// refusal of a sandbox reaches it.
			if test.want == http.StatusForbidden && len(rg.store.calls) != before {
				t.Errorf("the store was called for a refused request: %+v", rg.store.calls[before:])
			}
		})
	}
}

// checkGrantCreated checks the response and the write of a create through a
// grant that succeeded.
func checkGrantCreated(t *testing.T, rg *rig, rec *httptest.ResponseRecorder, test grantCreate) {
	t.Helper()

	var response agents.CreateResponse

	err := json.Unmarshal(rec.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}

	if !slices.Equal(response.Agent.Scopes, test.agentList) || !slices.Equal(response.Key.Scopes, test.keyList) {
		t.Errorf("agent %v, key %v; want %v and %v", response.Agent.Scopes, response.Key.Scopes, test.agentList, test.keyList)
	}

	if response.Agent.SandboxID == nil || *response.Agent.SandboxID != test.sandbox {
		t.Errorf("sandbox = %v, want %s", response.Agent.SandboxID, test.sandbox)
	}

	written := rg.store.calls[len(rg.store.calls)-1].agent
	if written.CreatedBy != "" || written.Owner != userA || written.Sandbox.String() != test.sandbox {
		t.Errorf("write = creator %q owner %q sandbox %q, want no creator agent, the user, %s",
			written.CreatedBy, written.Owner, written.Sandbox, test.sandbox)
	}
}

// TestGrantCreateSealsTheKey: a grant is not a session, so the new agent's key is
// returned only sealed to the public key the request supplies, and a request
// that supplies none is refused with nothing created.
func TestGrantCreateSealsTheKey(t *testing.T) {
	t.Parallel()

	spec := grantSpec{scope: tokenAll, agentScopes: agentGrantList()}
	body := `{"name":"box","sandboxId":"` + sandboxMine + `"}`

	t.Run("sealed to the supplied key", func(t *testing.T) {
		t.Parallel()

		rg := grantRig(t)
		pair := newClientPair(t)
		rec := rg.serve(request{
			method: http.MethodPost, target: collection,
			body:          `{"name":"box","sandboxId":"` + sandboxMine + `","publicKey":` + marshalString(pair.public) + `}`,
			authorization: rg.signInGrant(spec),
		})

		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
		}

		var response agents.CreateResponse

		err := json.Unmarshal(rec.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("body %q: %v", rec.Body, err)
		}

		token := rg.issueCalls[0].issued.Token
		if response.Key.Token != "" || response.Key.Sealed == "" || strings.Contains(rec.Body.String(), token) {
			t.Fatalf("key = %+v, want a sealed token only", response.Key)
		}

		if got := pair.open(t, response.Key.Sealed); got != token {
			t.Errorf("opened %q, want the issued token", got)
		}
	})

	t.Run("no public key is refused before anything is written", func(t *testing.T) {
		t.Parallel()

		rg := grantRig(t)
		before := len(rg.store.calls)
		rec := rg.serve(request{method: http.MethodPost, target: collection, body: body, authorization: rg.signInGrant(spec)})

		wantCode(t, rg, rec, http.StatusBadRequest, auth.CodePublicKeyRequired)

		if len(rg.store.calls) != before || len(rg.issueCalls) != 0 {
			t.Errorf("a refused request wrote %+v and issued %d keys", rg.store.calls[before:], len(rg.issueCalls))
		}
	})
}

// TestGrantIsRefusedOnTheOtherAgentRoutes: renaming and revoking an agent never
// take a grant, however much it and its agent hold, and nothing is written.
func TestGrantIsRefusedOnTheOtherAgentRoutes(t *testing.T) {
	t.Parallel()

	spec := grantSpec{scope: tokenAll, agentScopes: scope.List{scope.DefaultSession}.JSON(), role: roleAdmin}

	for _, route := range everyRoute() {
		if route.name == routeList || route.name == routeCreate || route.name == routeGet {
			continue
		}

		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			rg := grantRig(t)
			rec := rg.asGrant(spec, route.method, route.target, route.body)

			wantCode(t, rg, rec, http.StatusForbidden, auth.CodeGrantNotAccepted)

			if rg.writes() != 0 {
				t.Errorf("a refused request wrote: %+v", rg.store.calls)
			}
		})
	}
}

// TestAgentKeyCreateIsUnchangedByGrants: an agent's own API key creates as it
// did, by copying its agent's row, and a grant's rules do not apply to it.
func TestAgentKeyCreateIsUnchangedByGrants(t *testing.T) {
	t.Parallel()

	rg := grantRig(t)
	rg.store.rows[0].agent.Scopes = scope.List{scope.DefaultAgent, agentCreate}.JSON()

	header := agentCaller(rg, scope.List{scope.DefaultAgent, agentCreate}, scope.List{scope.DefaultAgent, agentCreate})
	rec := rg.withKey(header, http.MethodPost, collection, `{"name":"child"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	written := rg.store.calls[len(rg.store.calls)-1].agent
	if written.CreatedBy != agentA1 {
		t.Errorf("CreatedBy = %q, want the creating agent %s", written.CreatedBy, agentA1)
	}

	// An ordinary agent needs no sandbox: the grant's rule is the grant's alone.
	if written.Sandbox.String() != "" {
		t.Errorf("sandbox = %q, want none", written.Sandbox)
	}
}
