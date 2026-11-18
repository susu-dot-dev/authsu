package agents_test

import (
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestRevoke: the agent comes back as the write left it, revoked at the
// request's time, or at the earlier time it already had: revoking twice
// succeeds and never moves the revocation later. The store is asked, for the
// session's user, to revoke exactly the agent in the path, as of the clock.
func TestRevoke(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		agent func(*rig) store.Agent
		// revokedAt is the revocation the response shows.
		revokedAt func(*rig) int64
	}{
		{
			name:      "a fresh agent",
			agent:     func(*rig) store.Agent { return stored(agentA1, nameAlpha, 100, nil) },
			revokedAt: func(rg *rig) int64 { return rg.now.Unix() },
		},
		{
			name:      "an agent revoked already",
			agent:     func(*rig) store.Agent { return stored(agentA1, nameAlpha, 100, new(int64(150))) },
			revokedAt: func(*rig) int64 { return 150 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, tt.agent(rg), stored(agentA2, "beta", 200, nil))

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodDelete, itemPrefix+agentA1, "")

			wantOK(t, rg, rec, http.StatusOK, agentJSON(agentA1, nameAlpha, 100, new(tt.revokedAt(rg)))+"\n")

			want := storeCall{method: methodRevoke, owner: userA, id: agentA1, now: rg.now}
			if len(rg.store.calls) != 1 || !rg.store.calls[0].now.Equal(want.now) ||
				rg.store.calls[0].method != want.method || rg.store.calls[0].owner != want.owner ||
				rg.store.calls[0].id != want.id {
				t.Errorf("store calls = %+v, want one %+v", rg.store.calls, want)
			}

			// Only the one agent.
			if other := rg.store.agent(t, agentA2); other.RevokedAt != nil {
				t.Errorf("another agent was revoked: %+v", other)
			}
		})
	}
}

// TestRevokeOfAnAgentThatDoesNotExist: the 404 every other user's agent gets.
func TestRevokeOfAnAgentThatDoesNotExist(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodDelete, itemPrefix+nobody, "")

	wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, codeNotFound)

	if got := rg.store.agent(t, agentA1); got.RevokedAt != nil {
		t.Errorf("another agent was revoked: %+v", got)
	}
}
