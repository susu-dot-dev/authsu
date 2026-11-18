package agents_test

import (
	"net/http"
	"testing"
)

// TestGet: one of the caller's agents, as the store holds it, with the status
// derived from its revocation.
func TestGet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		agent string
		want  string
	}{
		{name: "an active agent", agent: agentA1, want: agentJSON(agentA1, nameAlpha, 100, nil)},
		{name: "a revoked agent", agent: agentA2, want: agentJSON(agentA2, "beta", 200, new(int64(250)))},
		{name: "a revoked agent at the epoch", agent: agentA3, want: agentJSON(agentA3, "gamma", 300, new(int64(0)))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 100, nil), stored(agentA2, "beta", 200, new(int64(250))),
				stored(agentA3, "gamma", 300, new(int64(0))))

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, itemPrefix+tt.agent, "")

			wantOK(t, rg, rec, http.StatusOK, tt.want+"\n")

			if len(rg.store.calls) != 1 || rg.store.calls[0].method != methodGet ||
				rg.store.calls[0].owner != userA || rg.store.calls[0].id != tt.agent {
				t.Errorf("store calls = %+v, want one get of %s for %s", rg.store.calls, tt.agent, userA)
			}
		})
	}
}

// TestGetOfAnAgentThatDoesNotExist is the 404 every other user's agent also gets.
func TestGetOfAnAgentThatDoesNotExist(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, itemPrefix+nobody, "")

	wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, codeNotFound)
}

// TestAnIdThatIsNotAnAgentIdNeverReachesTheStore: every item route parses the
// id first, and refuses anything but a canonical lower-case UUID, with no
// store call and no key.
func TestAnIdThatIsNotAnAgentIdNeverReachesTheStore(t *testing.T) {
	t.Parallel()

	ids := []struct {
		name string
		id   string
	}{
		{name: "words", id: "nope"},
		{name: "upper case", id: "00000000-0000-7000-8000-0000000000A1"},
		{name: "too long", id: agentA1 + "0"},
		{name: "too short", id: agentA1[:35]},
		{name: "no dashes", id: "000000000000700080000000000000a1"},
		{name: "misplaced dashes", id: "0000000-00000-7000-8000-0000000000a1"},
		{name: "braces", id: "%7B" + agentA1 + "%7D"},
		{name: "a urn prefix", id: "urn:uuid:" + agentA1},
		{name: "not hex", id: "00000000-0000-7000-8000-0000000000g1"},
		{name: "a sql comment", id: "00000000-0000-7000-8000-0000000000--"},
		{name: "a sql injection", id: "%27%20OR%20%271%27%3D%271"},
		{name: "a wildcard", id: "%25"},
		{name: "a newline", id: "00000000-0000-7000-8000-0000000000a%0a"},
		{name: "a NUL", id: "00000000-0000-7000-8000-0000000000a%00"},
		{name: "an arabic-indic digit", id: "00000000-0000-7000-8000-0000000000%D9%A0%D9%A0"},
		{name: "the first-page sentinel", id: "g"},
	}

	routes := []agentRoute{
		{name: routeGet, method: http.MethodGet, target: "", body: ""},
		{name: routeRename, method: http.MethodPatch, target: "", body: bodyX},
		{name: routeRevoke, method: http.MethodDelete, target: "", body: ""},
	}

	for _, route := range routes {
		for _, tt := range ids {
			t.Run(route.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

				rec := rg.as(rg.signIn(userA, roleMember), route.method, itemPrefix+tt.id, route.body)

				wantFailure(t, rg, rec, http.StatusBadRequest, bodyInvalidID, codeInvalidID)
				rg.untouched()
			})
		}
	}
}
