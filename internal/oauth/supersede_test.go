//nolint:goconst,funlen,lll // table-driven tests repeat inputs on purpose, and the case table is the test; a constant or a line break per row would hide it
package oauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/secret"
)

// This file holds what an exchange does to the other grants of the same user,
// client and resource (docs/oauth_design.md, "One live grant per user, client and
// resource"): a code that is exchanged ends the grants consented before it, with
// their access tokens, and nothing else. The fake store models the write as plain
// Go and the real statement is held in internal/store and e2e; what is held here is
// the feature's side, through the routes: which grant stays live in every order of
// consent and exchange, and that a refused exchange ends nothing.

// grantSpec is one grant a scenario consents to: whose, for which client and
// resource.
type grantSpec struct {
	user     string
	client   string
	resource string
}

// consented is a grant that was approved, its code not yet exchanged.
type consented struct {
	spec grantSpec
	code string
	form url.Values
}

// consentTo approves a grant of spec, as its user, and returns the code. A client of
// another origin is given a document first.
func (r *rig) consentTo(spec grantSpec) consented {
	r.t.Helper()

	r.net.answers[spec.client] = served(document(spec.client, redirectURL))

	// No openid: the grant of another resource is stood in by rewriting its stored
	// resource, which an ID token's signing would read back against the table.
	code := r.approveFor(spec.user, func(v url.Values) {
		v.Set("client_id", spec.client)
		v.Set("scope", "mcp:read")
	})

	return consented{
		spec: spec, code: code,
		form: withParams(codeForm(code), setParam("client_id", spec.client)),
	}
}

// exchange spends the code.
func (r *rig) exchange(c consented) *httptest.ResponseRecorder {
	r.t.Helper()

	r.now = r.now.Add(time.Second)

	return r.postForm(oauth.PathToken, c.form)
}

// supersedeScenario is a sequence of consents followed by exchanges, in an order the
// table names, and what must be live at the end.
type supersedeScenario struct {
	grants []grantSpec

	// exchanges are the indexes of grants, in the order their codes are exchanged.
	exchanges []int

	// live are the indexes of the exchanged grants whose access and refresh tokens
	// must work at the end. Every other exchanged grant must not.
	live []int
}

func supersedeScenarios() map[string]supersedeScenario {
	same := grantSpec{user: userA, client: clientURL, resource: resourceURL}
	otherClient := grantSpec{user: userA, client: otherClientURL, resource: resourceURL}
	otherUser := grantSpec{user: userB, client: clientURL, resource: resourceURL}
	otherResourceGrant := grantSpec{user: userA, client: clientURL, resource: resource.ProductionLoginURL}

	return map[string]supersedeScenario{
		"the newer exchanged ends the older": {
			grants: []grantSpec{same, same}, exchanges: []int{0, 1}, live: []int{1},
		},
		"the newer exchanged first ends the older's unexchanged code": {
			grants: []grantSpec{same, same}, exchanges: []int{1, 0}, live: []int{1},
		},
		"an older code exchanged after the newer never ends the newer": {
			grants: []grantSpec{same, same, same}, exchanges: []int{2, 0, 1}, live: []int{2},
		},
		"three in consent order leave the last": {
			grants: []grantSpec{same, same, same}, exchanges: []int{0, 1, 2}, live: []int{2},
		},
		"the middle one exchanged ends the first only": {
			grants: []grantSpec{same, same, same}, exchanges: []int{1, 0}, live: []int{1},
		},
		"another client's grant stays": {
			grants: []grantSpec{same, otherClient}, exchanges: []int{0, 1}, live: []int{0, 1},
		},
		"another client's older grant stays when the newer is exchanged": {
			grants: []grantSpec{otherClient, same}, exchanges: []int{0, 1}, live: []int{0, 1},
		},
		"another user's grant stays": {
			grants: []grantSpec{otherUser, same}, exchanges: []int{0, 1}, live: []int{0, 1},
		},
		"another resource's grant stays": {
			grants: []grantSpec{otherResourceGrant, same}, exchanges: []int{0, 1}, live: []int{0, 1},
		},
		"only the matching one of a mixed set is ended": {
			grants: []grantSpec{otherClient, otherUser, otherResourceGrant, same, same}, exchanges: []int{0, 1, 2, 3, 4},
			live: []int{0, 1, 2, 4},
		},
		"a grant exchanged alone ends nothing": {
			grants: []grantSpec{same}, exchanges: []int{0}, live: []int{0},
		},
	}
}

// TestExchangeSupersedesOlderGrants: through the routes, with every combination of
// consent order and exchange order the table names, exactly the grants that are
// newest for their user, client and resource are live, and their tokens work while
// every other exchanged grant's access token is inactive and its refresh token is
// refused. A grant ends only because a newer consent of the same user, client and
// resource was exchanged.
func TestExchangeSupersedesOlderGrants(t *testing.T) {
	t.Parallel()

	for name, tt := range supersedeScenarios() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			codes := r.consentAll(tt.grants)
			issued := r.exchangeAll(tt, codes)

			for i, tokens := range issued {
				wantLive := slices.Contains(tt.live, i)

				if got := r.activeAt(tokens.access, tt.grants[i].resource); got != wantLive {
					t.Errorf("grant %d: access token live = %v, want %v", i, got, wantLive)
				}

				refresh := r.postForm(oauth.PathToken,
					withParams(refreshForm(tokens.refresh), setParam("client_id", tt.grants[i].client)))
				if got := refresh.Code == http.StatusOK; got != wantLive {
					t.Errorf("grant %d: refresh token works = %v, want %v", i, got, wantLive)
				}
			}
		})
	}
}

// consentAll consents to every grant in order, which is the order of their ids.
func (r *rig) consentAll(specs []grantSpec) []consented {
	r.t.Helper()

	codes := make([]consented, len(specs))

	for i, spec := range specs {
		codes[i] = r.consentTo(spec)

		// Only the MCP resource is one a third-party client may name, so a grant
		// of another resource is stood in by the stored resource, as
		// TestTokenCodeOfAnotherResource does.
		if spec.resource != resourceURL {
			r.store.rows[i].grant.Resource = loginResourceID(r.t)
			r.store.rows[i].grant.Scope = loginScopeList(r.t)
		}
	}

	return codes
}

// exchangeAll exchanges the codes in the scenario's order and returns the tokens of
// the exchanges that succeeded, by grant. An exchange that fails must be of a grant
// a newer one had already ended, and is refused as invalid_grant.
func (r *rig) exchangeAll(tt supersedeScenario, codes []consented) map[int]tokenBody {
	r.t.Helper()

	issued := map[int]tokenBody{}

	for _, i := range tt.exchanges {
		rec := r.exchange(codes[i])

		if rec.Code == http.StatusOK {
			issued[i] = wantTokens(r.t, rec)

			continue
		}

		if !supersededBefore(tt, i) {
			r.t.Fatalf("exchange of grant %d = %d %s, want 200", i, rec.Code, rec.Body)
		}

		wantOAuthError(r.t, rec, http.StatusBadRequest, oauthGrant)
	}

	return issued
}

// loginResourceID is the first-party login resource, which a third-party client
// cannot name and so a test stands a grant of it in by its stored resource.
func loginResourceID(t *testing.T) input.ResourceID {
	t.Helper()

	id, err := input.ParseResourceID(resource.ProductionLoginURL, productionTable())
	if err != nil {
		t.Fatal(err)
	}

	return id
}

// loginScopeList is the scope of such a grant: the login resource's profile.
func loginScopeList(t *testing.T) input.OAuthScopes {
	t.Helper()

	scopes, err := input.ParseFirstPartyScopes("profile", true, loginResourceID(t).Entry())
	if err != nil {
		t.Fatal(err)
	}

	return scopes
}

// activeAt is active for a resource: the access token of a grant of the other
// resource is asked about there.
func (r *rig) activeAt(token, target string) bool {
	r.t.Helper()

	rec := r.postForm(oauth.PathIntrospect, introspectForm(token, target))
	if rec.Code != http.StatusOK {
		r.t.Fatalf("introspect = %d %s", rec.Code, rec.Body)
	}

	return decodeNumbers(r.t, rec.Body.Bytes())["active"] == true
}

// supersededBefore reports whether grant i was ended by an exchange earlier in the
// scenario than its own: a grant of the same user, client and resource consented
// after it and exchanged before it.
func supersededBefore(tt supersedeScenario, i int) bool {
	position := map[int]int{}
	for at, grant := range tt.exchanges {
		position[grant] = at
	}

	for newer := i + 1; newer < len(tt.grants); newer++ {
		earlier, exchanged := position[newer]
		if exchanged && earlier < position[i] && tt.grants[newer] == tt.grants[i] {
			return true
		}
	}

	return false
}

// TestFailedExchangeSupersedesNothing: an exchange that is refused ends no other
// grant, whatever it was refused for: the older grant's tokens work after, and the
// newer grant's code is still good for the client that presents it right.
func TestFailedExchangeSupersedesNothing(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		form    func(url.Values)
		advance time.Duration
		code    string
	}{
		"a wrong verifier": {
			form: setParam("code_verifier", "x"+verifierVal[1:]), code: oauthGrant,
		},
		"a wrong redirect URI": {
			form: setParam("redirect_uri", "https://client.example.com/other"), code: oauthGrant,
		},
		"an expired code": {advance: 2 * time.Minute, code: oauthGrant},
		"another client": {
			form: setParam("client_id", otherClientURL), code: oauthGrant,
		},
		"a code that is not one": {
			form: setParam("code", tokenOf(t, secret.TagOAuthCode)), code: oauthGrant,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			spec := grantSpec{user: userA, client: clientURL, resource: resourceURL}

			older := r.consentTo(spec)
			olderTokens := wantTokens(t, r.exchange(older))
			newer := r.consentTo(spec)

			// The older grant was exchanged before the newer was consented, so it
			// is live now.
			if !r.active(olderTokens.access) {
				t.Fatal("the older grant is not live before the newer is exchanged")
			}

			r.now = r.now.Add(tt.advance)

			rec := r.postForm(oauth.PathToken, withParams(newer.form, tt.form))
			wantOAuthError(t, rec, http.StatusBadRequest, tt.code)

			if !r.active(olderTokens.access) {
				t.Error("the older grant's access token was ended by a refused exchange")
			}

			if !r.refreshWorks(olderTokens.refresh) {
				t.Error("the older grant's refresh token was ended by a refused exchange")
			}
		})
	}

	t.Run("a replayed code", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		spec := grantSpec{user: userA, client: clientURL, resource: resourceURL}

		second := r.consentTo(spec)
		wantTokens(t, r.exchange(second))

		// A newer consent exchanged afterwards ends the second. Replaying the second's
		// code is a replay: it ends nothing, in particular not the newest grant.
		third := r.consentTo(spec)
		thirdTokens := wantTokens(t, r.exchange(third))

		wantOAuthError(t, r.exchange(second), http.StatusBadRequest, oauthGrant)

		if !r.active(thirdTokens.access) {
			t.Error("a replayed code of an older grant ended the newest grant")
		}
	})

	t.Run("a revoked code", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		cookie, _ := r.signIn(userA)
		spec := grantSpec{user: userA, client: clientURL, resource: resourceURL}

		older := r.consentTo(spec)
		olderTokens := wantTokens(t, r.exchange(older))
		newer := r.consentTo(spec)

		r.as(cookie, http.MethodDelete, grantPath(r.store.rows[1].grant.ID))
		wantOAuthError(t, r.exchange(newer), http.StatusBadRequest, oauthGrant)

		if !r.active(olderTokens.access) {
			t.Error("the older grant was ended by the exchange of a revoked code")
		}
	})

	t.Run("a revoked agent", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		spec := grantSpec{user: userA, client: clientURL, resource: resourceURL}

		older := r.consentTo(spec)
		olderTokens := wantTokens(t, r.exchange(older))
		newer := r.consentTo(spec)

		r.store.revokedAgents[r.store.rows[1].grant.AgentID] = true

		wantOAuthError(t, r.exchange(newer), http.StatusBadRequest, oauthGrant)

		if !r.active(olderTokens.access) {
			t.Error("the older grant was ended by the exchange of a grant whose agent is revoked")
		}
	})
}

// TestSupersessionKeepsTheEarlierRevocation: an older grant that was already revoked
// keeps the time of its revocation, and one that was never exchanged is ended at the
// exchange of the newer.
func TestSupersessionKeepsTheEarlierRevocation(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)
	spec := grantSpec{user: userA, client: clientURL, resource: resourceURL}

	revoked := r.consentTo(spec)
	wantTokens(t, r.exchange(revoked))

	revokedAt := r.now.Add(time.Minute)
	r.now = revokedAt

	r.as(cookie, http.MethodDelete, grantPath(r.store.rows[0].grant.ID))

	unexchanged := r.consentTo(spec)
	newest := r.consentTo(spec)

	// Within the code's life, and long after the first revocation.
	r.now = r.now.Add(10 * time.Second)
	wantTokens(t, r.exchange(newest))

	if got := r.store.rows[0].revokedAt; got == nil || !got.Equal(revokedAt) {
		t.Errorf("the revoked grant's revocation = %v, want it kept at %v", got, revokedAt)
	}

	if got := r.store.rows[1].revokedAt; got == nil {
		t.Error("the unexchanged older grant was not ended")
	}

	wantOAuthError(t, r.exchange(unexchanged), http.StatusBadRequest, oauthGrant)
}

// TestSupersessionNeverRevokesTheAgent: the agent is shared by the user's grants
// and is not ended with a grant that is superseded.
func TestSupersessionNeverRevokesTheAgent(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)

	// Two grants attached to the same existing agent.
	attach := func() string {
		text := r.pending(nil)
		rec := r.consent(cookie, consentJSON(t, map[string]any{
			"request": text, "approve": true, "agent": map[string]any{"id": agentA1},
		}))

		return redirectOf(t, rec, redirectURL).Get("code")
	}

	first, second := attach(), attach()

	wantTokens(t, r.postForm(oauth.PathToken, codeForm(first)))
	wantTokens(t, r.postForm(oauth.PathToken, codeForm(second)))

	if r.store.revokedAgents[agentA1] {
		t.Error("the agent was revoked")
	}

	if r.store.rows[0].revokedAt == nil || r.store.rows[1].revokedAt != nil {
		t.Errorf("revoked = %v and %v, want the older grant ended and the newer live",
			r.store.rows[0].revokedAt, r.store.rows[1].revokedAt)
	}
}

// TestSupersessionOfFirstPartyLogins: a person signing in again at the first-party
// client ends the earlier login's grant and its access token at the exchange,
// and the access token of the new login works as a bearer at authsu's own API while
// the old one is refused, and the agent that holds both is the same and stays.
func TestSupersessionOfFirstPartyLogins(t *testing.T) {
	t.Parallel()

	r := loginRig(t)
	params := loginParams()
	params.Set("scope", "profile org:read")

	first := loginTokens(t, r, params)
	second := loginTokens(t, r, params)

	probe := func(token string) int {
		return r.serve(request{
			method: http.MethodGet, target: "/probe/org:read", contentType: "-", authorization: "Bearer " + token,
		}).Code
	}

	if got := probe(second.access); got != http.StatusNoContent {
		t.Errorf("the new login's access token = %d, want 204", got)
	}

	if got := probe(first.access); got != http.StatusUnauthorized {
		t.Errorf("the earlier login's access token = %d, want 401", got)
	}

	refresh := r.postForm(oauth.PathToken, withParams(
		url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.refresh}, "client_id": {trustedClient}}))
	wantOAuthError(t, refresh, http.StatusBadRequest, oauthGrant)

	if r.store.rows[0].grant.AgentID != r.store.rows[1].grant.AgentID {
		t.Fatal("the two logins are held by different agents")
	}

	if r.store.revokedAgents[r.store.rows[1].grant.AgentID] {
		t.Error("the login's agent was revoked")
	}

	if got := probe(second.access); got != http.StatusNoContent {
		t.Errorf("the new login's access token after = %d, want 204", got)
	}
}
