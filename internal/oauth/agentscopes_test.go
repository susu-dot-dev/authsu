//nolint:goconst,lll,funlen // table-driven tests repeat inputs on purpose, and the case table is the test; a constant or a line break per row would hide it
package oauth_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/resource"
)

// This file holds what a grant does to the list of the agent that holds it
// (docs/permissions_design.md, "Where scopes live"): the agent authsu creates for
// a grant is given the grant's authsu names, a first-party login's agent keeps
// the union of every sign-in's names pruned to the allowlist, and an agent the
// user attached is never written. The fake store models the write as plain Go, so
// the real statement's own text is held in internal/store and its behaviour in
// e2e; what is held here is the feature's side: which names it hands the write,
// for which kind of agent, and that the access token's permission follows.

// loginEvery is every authsu name of the login resource, in its order.
var loginEvery = resource.LoginAuthsuScopes() //nolint:gochecknoglobals // a fixed table shared by the tests

// signIn is one sign-in of userA at the trusted client asking for scope.
type signIn struct {
	scope string
}

// loginAgentScopes runs the sign-ins in order through the real routes (authorize,
// consent, token exchange) and returns the list of the agent that held the last.
func loginAgentScopes(t *testing.T, r *rig, sign []signIn) (string, []string) {
	t.Helper()

	var agent string

	for _, one := range sign {
		params := loginParams()
		params.Set("scope", one.scope)

		loginTokens(t, r, params)

		agent = r.store.rows[len(r.store.rows)-1].grant.AgentID
	}

	return agent, r.store.agentScopes[agent]
}

// TestFirstPartyAgentListFollowsTheSignIns: a first-party login's agent is created
// with exactly the allowlisted names of the first sign-in, gains the names of a
// later one (a union), never loses one a later sign-in leaves out, and never holds
// a name that is not authsu's, whatever the request names.
func TestFirstPartyAgentListFollowsTheSignIns(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		signIns []signIn
		want    []string
	}{
		"the profile alone leaves the list empty": {
			signIns: []signIn{{"openid email profile offline_access"}}, want: []string{},
		},
		"the first sign-in creates the agent with the names asked for": {
			signIns: []signIn{{"openid profile agent:read org:read"}}, want: []string{"org:read", "agent:read"},
		},
		"every name": {
			signIns: []signIn{{"openid profile " + joinNames(loginEvery)}}, want: loginEvery,
		},
		"the list is in the allowlist's order, not the request's": {
			signIns: []signIn{{"profile agent:read sandbox:create org:read"}},
			want:    []string{"sandbox:create", "org:read", "agent:read"},
		},
		"a later sign-in asking for more unions": {
			signIns: []signIn{{"profile agent:read"}, {"profile org:read sandbox:create"}},
			want:    []string{"sandbox:create", "org:read", "agent:read"},
		},
		"a later sign-in asking for less keeps the earlier names": {
			signIns: []signIn{{"profile agent:read org:read"}, {"profile agent:read"}}, want: []string{"org:read", "agent:read"},
		},
		"a later sign-in asking for nothing keeps them all": {
			signIns: []signIn{{"profile agent:read org:read"}, {"openid profile"}}, want: []string{"org:read", "agent:read"},
		},
		"a repeat of the same names changes nothing": {
			signIns: []signIn{{"profile agent:read"}, {"profile agent:read"}, {"profile agent:read"}}, want: []string{"agent:read"},
		},
		"three sign-ins, each adding one": {
			signIns: []signIn{{"profile agent:read"}, {"profile org:read"}, {"profile agent:create"}},
			want:    []string{"org:read", "agent:create", "agent:read"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, held := loginAgentScopes(t, loginRig(t), tt.signIns)

			if !slices.Equal(held, tt.want) {
				t.Errorf("the agent holds %v, want %v", held, tt.want)
			}
		})
	}
}

// joinNames is names separated by one space.
func joinNames(names []string) string { return strings.Join(names, " ") }

// TestFirstPartyAgentListIsPrunedToTheAllowlist: a name the agent holds that the
// allowlist does not (it was removed from the login resource since, or it is a
// bundle or a name the code no longer knows) is dropped at the next sign-in, while
// the names still allowed are kept. The stale row is what an earlier deployment
// left, simulated by writing it into the agent.
func TestFirstPartyAgentListIsPrunedToTheAllowlist(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		stale []string
		scope string
		want  []string
	}{
		"a name removed from the allowlist is dropped":    {[]string{"agent:read", "removed:scope"}, "profile org:read", []string{"org:read", "agent:read"}},
		"a bundle is dropped":                             {[]string{"default:agent", "agent:read"}, "profile", []string{"agent:read"}},
		"an admin scope the agent held is dropped":        {[]string{"user:read", "org:read"}, "profile", []string{"org:read"}},
		"only stale names leave the list empty":           {[]string{"removed:scope", "other:scope"}, "profile", []string{}},
		"a stale name is not revived by being re-asked":   {[]string{"removed:scope"}, "profile agent:read", []string{"agent:read"}},
		"a held duplicate is written once":                {[]string{"agent:read", "agent:read"}, "profile", []string{"agent:read"}},
		"a held name out of order is put in the order":    {[]string{"agent:read", "sandbox:create"}, "profile", []string{"sandbox:create", "agent:read"}},
		"a name that only differs in case is not a match": {[]string{"Agent:Read", "AGENT:READ"}, "profile", []string{}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			agent, _ := loginAgentScopes(t, r, []signIn{{"profile"}})

			r.store.agentScopes[agent] = tt.stale

			_, held := loginAgentScopes(t, r, []signIn{{tt.scope}})

			if !slices.Equal(held, tt.want) {
				t.Errorf("the agent holds %v, want %v", held, tt.want)
			}
		})
	}
}

// TestFirstPartyAgentListWithTwoSignInsInterleaved: two sign-ins whose writes
// land in either order, each having been decided against the same earlier list
// (which is how racing requests meet the database), end in the union of both. The
// write computes the list from the row, never from a read that preceded it, so the
// later write cannot lose the earlier one's names.
func TestFirstPartyAgentListWithTwoSignInsInterleaved(t *testing.T) {
	t.Parallel()

	for name, order := range map[string][]string{
		"one then the other":   {"profile agent:read", "profile org:read"},
		"the other then one":   {"profile org:read", "profile agent:read"},
		"one twice, the other": {"profile agent:read", "profile org:read", "profile agent:read"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			cookie, _ := r.signIn(userA)

			// Both requests are authorized and pending before either writes.
			pending := make([]string, len(order))

			for i, asked := range order {
				params := loginParams()
				params.Set("scope", asked)
				pending[i] = loginPending(t, r, params)
			}

			var agent string

			for _, text := range pending {
				loginConsent(r, cookie, text)

				agent = r.store.rows[len(r.store.rows)-1].grant.AgentID
			}

			if want := []string{"org:read", "agent:read"}; !slices.Equal(r.store.agentScopes[agent], want) {
				t.Errorf("the agent holds %v, want the union %v", r.store.agentScopes[agent], want)
			}
		})
	}
}

// TestFirstPartyAgentListIsPerAgent: one user's sign-in never writes another
// user's agent, and a revoked agent is replaced by a fresh one that starts from
// the sign-in's own names and not from the revoked agent's list.
func TestFirstPartyAgentListIsPerAgent(t *testing.T) {
	t.Parallel()

	t.Run("another user's agent is untouched", func(t *testing.T) {
		t.Parallel()

		r := loginRig(t)
		r.store.firstPartyAgents[userB+"|"+trustedClient] = agentB1
		r.store.agentScopes[agentB1] = []string{"org:read"}

		params := loginParams()
		params.Set("scope", "profile agent:read")
		loginTokens(t, r, params)

		if got := r.store.agentScopes[agentB1]; !slices.Equal(got, []string{"org:read"}) {
			t.Errorf("another user's agent holds %v, want it unchanged", got)
		}
	})

	t.Run("a revoked agent is replaced and starts from the sign-in", func(t *testing.T) {
		t.Parallel()

		r := loginRig(t)
		agent, _ := loginAgentScopes(t, r, []signIn{{"profile org:read sandbox:create"}})
		r.store.revokedAgents[agent] = true

		fresh, held := loginAgentScopes(t, r, []signIn{{"profile agent:read"}})

		if fresh == agent || !slices.Equal(held, []string{"agent:read"}) {
			t.Errorf("agent %s holds %v, want a fresh agent holding only agent:read", fresh, held)
		}

		if got := r.store.agentScopes[agent]; !slices.Equal(got, []string{"sandbox:create", "org:read"}) {
			t.Errorf("the revoked agent holds %v, want it left as it was", got)
		}
	})
}

// TestThirdPartyConsentAgentHoldsNothing: a new agent a person creates at consent
// for a third-party client holds an empty list, whatever the request named: the
// grant's resource is not the login resource, so none of its scopes is an authsu
// name, and the list is the grant's authsu names, which are none.
func TestThirdPartyConsentAgentHoldsNothing(t *testing.T) {
	t.Parallel()

	for name, scopes := range map[string]string{
		"one scope":   "mcp:read",
		"both scopes": "mcp:read mcp:write",
		"with openid": "mcp:write openid mcp:read",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			r.approve(func(v url.Values) { v.Set("scope", scopes) })

			agent := r.store.rows[0].grant.AgentID

			if held, found := r.store.agentScopes[agent]; !found || len(held) != 0 {
				t.Errorf("the new agent holds %v (found %v), want the empty list", held, found)
			}
		})
	}
}

// TestAttachedAgentListIsNeverWritten: an agent the user chose to attach at consent
// keeps its list exactly, whatever the grant carries and whatever the list is. The
// grant carries its own claim and so can never widen the agent, and with a narrower
// list the grant simply gets less.
func TestAttachedAgentListIsNeverWritten(t *testing.T) {
	t.Parallel()

	for name, held := range map[string][]string{
		"an empty list":      {},
		"a narrower list":    {"org:read"},
		"a wider list":       loginEvery,
		"a bundle":           {"default:agent"},
		"a name not allowed": {"user:read", "removed:scope"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			r.store.agentScopes[agentA1] = slices.Clone(held)

			text := r.pending(nil)
			cookie, _ := r.signIn(userA)

			rec := r.consent(cookie, consentJSON(t, map[string]any{
				"request": text, "approve": true, "agent": map[string]any{"id": agentA1},
			}))
			redirectOf(t, rec, redirectURL)

			if got := r.store.agentScopes[agentA1]; !slices.Equal(got, held) {
				t.Errorf("the attached agent holds %v, want %v untouched", got, held)
			}

			if grant := r.store.rows[0].grant; grant.AgentID != agentA1 || grant.NewAgent != nil || grant.FirstParty {
				t.Errorf("grant = %+v, want one attached to the agent, creating nothing", grant)
			}
		})
	}
}

// TestRefusedGrantLeavesTheAgentList: a consent the write refuses (a replay, a
// session that ended, an account revoked, the agent limit) writes nothing, the
// agent's list included, because the list is part of the same batch.
func TestRefusedGrantLeavesTheAgentList(t *testing.T) {
	t.Parallel()

	tests := map[string]func(r *rig, agent string){
		"the session ended": func(r *rig, _ string) {
			for id := range r.store.authTimes {
				r.store.endedSessions[id] = true
			}
		},
		"the account is revoked": func(r *rig, _ string) { r.store.inactiveUsers[userA] = true },
		// The agent was revoked and the user is at the limit counting it as gone,
		// so the fresh agent the write would create has no room.
		"the user is at the limit and the login's agent was revoked": func(r *rig, agent string) {
			r.store.revokedAgents[agent] = true
			r.store.activeAgents[userA] = 26
		},
	}

	for name, spoil := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			agent, held := loginAgentScopes(t, r, []signIn{{"profile org:read"}})
			before := slices.Clone(held)

			cookie, _ := r.signIn(userA)
			params := loginParams()
			params.Set("scope", "profile agent:read sandbox:create")
			text := loginPending(t, r, params)

			spoil(r, agent)

			rec := r.consent(cookie, loginBody(t, text, true, nil))
			if rec.Code == http.StatusOK {
				t.Fatalf("consent = %d, want a refusal", rec.Code)
			}

			if got := r.store.agentScopes[agent]; !slices.Equal(got, before) {
				t.Errorf("the agent holds %v after a refused grant, want %v", got, before)
			}
		})
	}

	t.Run("a replay", func(t *testing.T) {
		t.Parallel()

		r := loginRig(t)
		cookie, _ := r.signIn(userA)
		params := loginParams()
		params.Set("scope", "profile org:read")
		text := loginPending(t, r, params)

		loginConsent(r, cookie, text)

		agent := r.store.rows[0].grant.AgentID
		before := slices.Clone(r.store.agentScopes[agent])

		// The same request again: a replay, which the list must not grow from.
		r.store.agentScopes[agent] = before

		rec := r.consent(cookie, loginBody(t, text, true, nil))
		if rec.Code == http.StatusOK {
			t.Fatalf("a replayed consent = %d, want a refusal", rec.Code)
		}

		if got := r.store.agentScopes[agent]; !slices.Equal(got, before) {
			t.Errorf("the agent holds %v after a replay, want %v", got, before)
		}
	})
}

// TestLoginAccessTokenIsPermittedByTheAgentList: end to end through the route
// boundary. After a first-party login (consent, then the code exchange), the access
// token presented as a bearer at a route that opts in with FromGrants and needs one
// of the login scopes is permitted when the sign-in asked for that scope, and is
// refused for lacking it when it did not. The agent's list was set by the consent,
// so this is the whole path from the request's scope to a permission.
func TestLoginAccessTokenIsPermittedByTheAgentList(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		asked   string
		allowed []string
	}{
		"nothing but the profile":      {"openid profile", nil},
		"one scope":                    {"openid profile sandbox:create", []string{"sandbox:create"}},
		"two scopes":                   {"profile org:read agent:read", []string{"org:read", "agent:read"}},
		"every scope":                  {"profile " + joinNames(loginEvery), loginEvery},
		"the order of asking is moot":  {"profile agent:read sandbox:create", []string{"sandbox:create", "agent:read"}},
		"email and offline_access too": {"openid email profile offline_access agent:create", []string{"agent:create"}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			params := loginParams()
			params.Set("scope", tt.asked)
			tokens := loginTokens(t, r, params)

			for _, probe := range loginEvery {
				rec := r.serve(request{
					method: http.MethodGet, target: "/probe/" + probe, contentType: "-",
					authorization: "Bearer " + tokens.access,
				})

				if slices.Contains(tt.allowed, probe) {
					if rec.Code != http.StatusNoContent {
						t.Errorf("%s with the scope asked for = %d %s, want 204", probe, rec.Code, rec.Body.String())
					}

					continue
				}

				if rec.Code != http.StatusForbidden {
					t.Errorf("%s without the scope = %d %s, want 403", probe, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

// TestLoginAccessTokenIsNarrowedByTheAgent: the access token's own scope names a
// scope, but the agent that holds the grant does not hold it any more (its list was
// cut, as an owner may), so the boundary refuses it: the agent's list is the
// ceiling and the token only narrows it.
func TestLoginAccessTokenIsNarrowedByTheAgent(t *testing.T) {
	t.Parallel()

	r := loginRig(t)
	params := loginParams()
	params.Set("scope", "profile org:read agent:read")
	tokens := loginTokens(t, r, params)

	agent := r.store.rows[0].grant.AgentID
	r.store.agentScopes[agent] = []string{"org:read"}

	for probe, want := range map[string]int{"org:read": http.StatusNoContent, "agent:read": http.StatusForbidden} {
		rec := r.serve(request{
			method: http.MethodGet, target: "/probe/" + probe, contentType: "-", authorization: "Bearer " + tokens.access,
		})

		if rec.Code != want {
			t.Errorf("%s = %d, want %d", probe, rec.Code, want)
		}
	}
}

// TestAttachedAgentWithKeysIsNotWidenedByAGrant: an agent with an API key, which
// the user attached to a third-party grant, keeps its list, so its key's effective
// permission is what it was before the grant. A first-party sign-in does not touch
// it either: the login's agent is the one authsu keeps, never this one.
func TestAttachedAgentWithKeysIsNotWidenedByAGrant(t *testing.T) {
	t.Parallel()

	r := loginRig(t)
	r.store.agentScopes[agentA1] = []string{"org:read"}

	// A third-party grant attached to the agent, then a first-party login.
	text := r.pending(nil)
	cookie, _ := r.signIn(userA)
	redirectOf(t, r.consent(cookie, consentJSON(t, map[string]any{
		"request": text, "approve": true, "agent": map[string]any{"id": agentA1},
	})), redirectURL)

	params := loginParams()
	params.Set("scope", "profile "+joinNames(loginEvery))
	loginTokens(t, r, params)

	if got := r.store.agentScopes[agentA1]; !slices.Equal(got, []string{"org:read"}) {
		t.Errorf("the user's agent holds %v, want it as it was", got)
	}
}

// TestConsentWithoutALoginResource: a table with no login resource has no
// allowlist, so a consent writes an agent no authsu names. The consent reads the
// table to open its sealed request and again for the allowlist; the zero table
// from the second read on is the one way to meet the case from outside the
// resource package, and the third-party consent still creates its agent and grant,
// with an empty list.
func TestConsentWithoutALoginResource(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	text := r.pending(nil)
	cookie, _ := r.signIn(userA)

	// The consent opens the sealed request with the first table it reads, and reads
	// the allowlist from the second.
	r.looked = 0
	r.tables = func(call int, origin string) resource.Table {
		if call == 1 {
			return resource.Select(origin)
		}

		return resource.Table{}
	}

	redirectOf(t, r.consent(cookie, approval(t, text, "Claude Code")), redirectURL)

	grant := r.store.rows[0].grant
	if len(grant.Allowlist) != 0 {
		t.Errorf("allowlist = %v, want none", grant.Allowlist)
	}

	if held := r.store.agentScopes[grant.AgentID]; len(held) != 0 {
		t.Errorf("the new agent holds %v, want the empty list", held)
	}
}
