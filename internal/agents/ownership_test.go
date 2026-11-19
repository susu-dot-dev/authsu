package agents_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestAnotherUsersAgentIsNotFound is the permission-confusion test of the
// item routes. User B names user A's agent, as a member and as an administrator
// (an admin has no extra reach here): the store is asked with B as the owner,
// the answer is the 404 a missing agent gets, byte for byte, and A's agent is
// unchanged. The control is A making the same request, which works.
func TestAnotherUsersAgentIsNotFound(t *testing.T) {
	t.Parallel()

	routes := []agentRoute{
		{name: routeGet, method: http.MethodGet, target: itemPrefix + agentA1, body: ""},
		{name: routePatch, method: http.MethodPatch, target: itemPrefix + agentA1, body: `{"name":"hijacked"}`},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + agentA1, body: ""},
	}

	for _, route := range routes {
		for _, role := range []string{roleMember, roleAdmin} {
			t.Run(route.name+"/"+role, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))
				rg.seed(userB, stored(agentB1, "bravo", 2, nil))
				cookieB := rg.signIn(userB, role)

				// B asks for A's agent.
				others := rg.as(cookieB, route.method, route.target, route.body)

				wantFailure(t, rg, others, http.StatusNotFound, bodyNotFound, codeNotFound)

				if len(rg.store.calls) != 1 || rg.store.calls[0].owner != userB || rg.store.calls[0].id != agentA1 {
					t.Errorf("store calls = %+v, want one for owner %s and agent %s", rg.store.calls, userB, agentA1)
				}

				// An agent nobody has is answered with the same bytes.
				rg.logged = nil
				missing := rg.as(cookieB, route.method, strings.Replace(route.target, agentA1, nobody, 1), route.body)

				if missing.Code != others.Code || missing.Body.String() != others.Body.String() {
					t.Errorf("another user's agent = %d %q, a missing one = %d %q: they must be identical",
						others.Code, others.Body.String(), missing.Code, missing.Body.String())
				}

				// Nothing of A's changed.
				if got := rg.store.agent(t, agentA1); !sameAgent(got, stored(agentA1, nameAlpha, 1, nil)) {
					t.Errorf("A's agent became %+v", got)
				}

				// The control: the owner's own request is not refused.
				rg.logged = nil
				rg.store.calls = nil

				own := rg.as(rg.signIn(userA, roleMember), route.method, route.target, route.body)
				if own.Code != http.StatusOK {
					t.Errorf("the owner's request = %d %q, want 200", own.Code, own.Body.String())
				}
			})
		}
	}
}

// TestTheOwnerIsAlwaysTheSession: whatever else a request says, every store
// call is made for the user the session belongs to, on every route. The
// requests below all try to name user A while signed in as user B.
func TestTheOwnerIsAlwaysTheSession(t *testing.T) {
	t.Parallel()

	noise := "?owner=" + userA + "&userId=" + userA + "&user_id=" + userA + "&sub=" + userA

	routes := []agentRoute{
		{name: routeList, method: http.MethodGet, target: collection + noise, body: ""},
		{name: routeCreate, method: http.MethodPost, target: collection + noise, body: bodyAssistant},
		{name: routeGet, method: http.MethodGet, target: itemPrefix + agentA1 + noise, body: ""},
		{name: routePatch, method: http.MethodPatch, target: itemPrefix + agentA1 + noise, body: bodyX},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + agentA1 + noise, body: ""},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))

			rg.as(rg.signIn(userB, roleMember), route.method, route.target, route.body)

			if len(rg.store.calls) != 1 {
				t.Fatalf("store calls = %+v, want exactly one", rg.store.calls)
			}

			call := rg.store.calls[0]

			if call.owner != userB {
				t.Errorf("owner = %q, want the session's user %q", call.owner, userB)
			}

			if got := rg.store.agent(t, agentA1); !sameAgent(got, stored(agentA1, nameAlpha, 1, nil)) {
				t.Errorf("A's agent became %+v", got)
			}
		})
	}
}

// TestABodyCannotNameAnOwner: the bodies of the writes have no member that could
// say who owns an agent, which key it gets, or what state it is in, and a
// request that tries is refused whole. (A create does take scopes and keyScopes,
// and a rename takes neither: see TestRenameTakesNoScopes.)
func TestABodyCannotNameAnOwner(t *testing.T) {
	t.Parallel()

	members := []string{
		"userId", "user_id", "owner", "ownerId", "sub", "act", "scope",
		"id", "kind", "status", "revokedAt", "scope", "keyScope", "createdBy", "agentId",
	}

	targets := []agentRoute{
		{name: routeCreate, method: http.MethodPost, target: collection, body: ""},
		{name: routePatch, method: http.MethodPatch, target: itemPrefix + agentB1, body: ""},
	}

	for _, route := range targets {
		for _, member := range members {
			t.Run(route.name+"/"+member, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userB, stored(agentB1, "bravo", 2, nil))

				body := `{"name":"x","` + member + `":"` + userA + `"}`
				rec := rg.as(rg.signIn(userB, roleMember), route.method, route.target, body)

				wantFailure(t, rg, rec, http.StatusBadRequest,
					errorBody(codeUnknownField, "request body has an unknown field"), codeUnknownField)
				rg.untouched()
			})
		}
	}
}

// TestListsHoldOnlyTheCallersAgents: a page is the caller's agents and no one
// else's, including when the caller's cursor is an id of someone else's.
func TestListsHoldOnlyTheCallersAgents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		who    string
		target string
		want   string
	}{
		{
			name: "A", who: userA, target: collection,
			want: `{"agents":[` + agentJSON(agentA2, "alpha two", 3, nil) + `,` + agentJSON(agentA1, nameAlpha, 1, nil) + `]}`,
		},
		{
			name: "B", who: userB, target: collection,
			want: `{"agents":[` + agentJSON(agentB1, "bravo", 2, nil) + `,` + agentJSON(agentB0, "zero", 4, nil) + `]}`,
		},
		{
			name: "B with a cursor that is A's agent", who: userB, target: collection + "?cursor=" + agentA2,
			want: `{"agents":[` + agentJSON(agentB0, "zero", 4, nil) + `]}`,
		},
		{name: "a user with none", who: "00000000-0000-7000-8000-0000000000dd", target: collection, want: bodyNoAgents},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 1, nil), stored(agentA2, "alpha two", 3, nil))
			rg.seed(userB, stored(agentB1, "bravo", 2, nil), stored(agentB0, "zero", 4, nil))

			rec := rg.as(rg.signIn(tt.who, roleMember), http.MethodGet, tt.target, "")

			wantOK(t, rg, rec, http.StatusOK, tt.want+"\n")
		})
	}
}

// TestRenameTakesNoScopes: a rename changes the name and nothing else, so scopes
// are not a member of its body. An agent's scopes are fixed when it is created.
func TestRenameTakesNoScopes(t *testing.T) {
	t.Parallel()

	for _, member := range []string{"scopes", "keyScopes"} {
		t.Run(member, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))

			body := `{"name":"x","` + member + `":["user:read"]}`
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, body)

			wantFailure(t, rg, rec, http.StatusBadRequest,
				errorBody(codeUnknownField, "request body has an unknown field"), codeUnknownField)
			rg.untouched()
		})
	}
}
