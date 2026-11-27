//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_firstparty_test.go drives the first-party login of docs/oauth_design.md
// through the real Worker: the trusted client (http://localhost:9894, the
// development table's entry, because the Worker's API_ORIGIN is localhost), the
// login resource, consent with no agent, and the ID token verified against the
// key set with the standard library.
//
// The trusted client's id is fixed by the Worker's code, so the document is served
// from this process on that port, and the tests that use it cannot run beside
// another that does: they take the port in firstPartyClient and skip when it is
// taken, which would be a developer's own Pages on the same machine.

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	// The development table's trusted client and the login resource, which are
	// resource.DevelopmentClientID and resource.DevelopmentLoginURL, restated so a
	// change to either is a visible test change.
	trustedClientID = "http://localhost:9894/oauth/client.json"
	loginResource   = "http://localhost:9894"
	trustedRedirect = "http://localhost:9894/oidc"
	trustedAddress  = "127.0.0.1:9894"

	loginScopes = "openid email profile offline_access"

	// pkceMethod is the one code_challenge_method the server supports.
	pkceMethod = "S256"
)

// firstPartyMu serialises the tests that take the trusted client's port.
var firstPartyMu sync.Mutex //nolint:gochecknoglobals // one port, so one holder at a time

// firstPartyClient serves the trusted client's metadata document on its fixed
// port until the test ends, and returns an oauthClient for it. Its redirect is
// the one the document lists.
func firstPartyClient(t *testing.T) *oauthClient {
	t.Helper()

	firstPartyMu.Lock()
	t.Cleanup(firstPartyMu.Unlock)

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", trustedAddress)
	if err != nil {
		t.Skipf("the trusted client's port %s is taken: %v", trustedAddress, err)
	}

	client := &oauthClient{name: "Pages", id: trustedClientID, redirect: trustedRedirect}
	client.server = &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(client.handle)}}
	client.server.Start()

	t.Cleanup(func() {
		client.server.CloseClientConnections()
		client.server.Close()
	})

	return client
}

// loginQuery is the authorization request the Pages app sends: the login
// resource, with the scopes of a standard OpenID Connect client.
func loginQuery(c *oauthClient, p pkce) url.Values {
	query := c.authorizeQuery(p)
	query.Set(paramResource, loginResource)
	query.Set("scope", loginScopes)

	return query
}

// loginPage is the page of the UI an acceptable login request is sent to.
func loginPage(t *testing.T, got reply) string {
	t.Helper()

	if got.status != http.StatusFound || !strings.HasPrefix(got.location(), target.origin+"/oauth/login?request=") {
		t.Fatalf("authorize = %d Location %q, want 302 to %s/oauth/login", got.status, got.location(), target.origin)
	}

	return got.locationURL(t).Query().Get("request")
}

// TestFirstPartyLogin is the whole login through the real Worker: authorize, to the
// page that only signs in, consent with no agent, the client's token exchange, the
// ID token verified with the key set and its profile claims, and what the grant is.
//
//nolint:paralleltest // shares one database
func TestFirstPartyLogin(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)
	pub, kid := oaPublicKey(t)
	pair := newPKCE()
	query := loginQuery(client, pair)

	text := loginPage(t, authorize(t, query))

	// The UI reads what was asked: the profile scope of the login resource, with
	// the two OpenID Connect names read.
	view := get(t, pathOAuthRequest+"?request="+url.QueryEscape(text), "")
	if view.status != http.StatusOK || !strings.Contains(view.body, `"resource":"`+loginResource+`"`) ||
		!strings.Contains(view.body, `"scopes":["profile"]`) || !strings.Contains(view.body, `"openid":true`) {
		t.Errorf("request view = %d %s", view.status, view.body)
	}

	// No agent is named, and none is the user's: authsu creates it.
	expectCount(t, tableAgents+" WHERE user_id = ?", "0", holder.userID)

	approval := consent(t, holder.session, text, true, nil)
	redirect := consentRedirect(t, approval)
	code := redirect.Query().Get("code")
	expectToken(t, code, tagOAuthCode)

	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != trustedRedirect ||
		redirect.Query().Get("state") != query.Get("state") || redirect.Query().Get("iss") != target.apiOrigin {
		t.Errorf("redirect = %s, want the client's with its state and the issuer", redirect)
	}

	grantID := idOfToken(t, code)
	agentID := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", grantID)

	if got := scalar(t, "SELECT name || '|' || first_party || '|' || first_party_client || '|' || scopes FROM agents WHERE id = ?",
		agentID); got != "Pages|1|"+trustedClientID+"|[]" {
		t.Errorf("the agent = %q, want one named for the client, flagged, kept for it and with no authsu scopes (the request named none)", got)
	}

	if got := scalar(t, "SELECT resource || '|' || scope FROM oauth_grants WHERE id = ?", grantID); got != loginResource+"|openid profile" {
		t.Errorf("the grant = %q, want the login resource with openid profile stored", got)
	}

	tokenReply := (approved{client: client, pkce: pair, query: query, code: code}).exchange(t)
	issued := mustTokens(t, tokenReply)

	if issued.Scope != "openid profile" || issued.RefreshToken == "" {
		t.Errorf("token response = %+v, want scope openid profile and a refresh token", issued)
	}

	claims := oaVerifyJWT(t, issued.IDToken, pub, kid)

	want := map[string]any{
		"iss": target.apiOrigin, "sub": holder.userID, "aud": client.id, "nonce": query.Get("nonce"),
		"name": "Admin", "email": testEmail, "email_verified": false,
	}
	for name, value := range want {
		if claims[name] != value {
			t.Errorf("claim %s = %v, want %v", name, claims[name], value)
		}
	}

	if len(claims) != len(want)+3 {
		t.Errorf("the ID token has claims %v, want %d members and iat, exp, auth_time", claims, len(want))
	}

	// The access token is the login resource's: live there, inactive at the MCP resource.
	live, _ := introspect(t, issued.AccessToken, loginResource)
	if !live.Active || live.Aud != loginResource || live.Sub != holder.userID || live.AgentID != agentID {
		t.Errorf("introspection = %+v", live)
	}

	expectInactive(t, "the login token at the MCP resource", issued.AccessToken, oauthResource)

	// The refresh token works and the grant keeps the login resource.
	refreshed := mustTokens(t, (approved{client: client}).refresh(t, issued.RefreshToken))
	if refreshed.IDToken != "" || refreshed.Scope != "openid profile" {
		t.Errorf("refresh = %+v", refreshed)
	}
}

// TestFirstPartyAgentIsKept: the agent of a first-party login is listed by the API
// with firstParty true, is kept for the next login, is counted against the limit,
// and revoking it ends its grants, and is no lockout: the next login is held by
// a fresh agent and works.
//
//nolint:paralleltest // shares one database
func TestFirstPartyAgentIsKept(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)

	login := func() string {
		pending := loginPage(t, authorize(t, loginQuery(client, newPKCE())))
		redirect := consentRedirect(t, consent(t, holder.session, pending, true, nil))

		return idOfToken(t, redirect.Query().Get("code"))
	}

	first, second := login(), login()

	expectCount(t, tableAgents+" WHERE user_id = ?", "1", holder.userID)
	expectCount(t, tableOAuthGrants+" WHERE agent_id = (SELECT id FROM agents LIMIT 1)", "2")

	// The user sees it, flagged, so a UI can group it.
	list := get(t, pathAgent, holder.session)
	if list.status != http.StatusOK || !strings.Contains(list.body, `"firstParty":true`) || !strings.Contains(list.body, `"name":"Pages"`) {
		t.Fatalf("GET /api/agent = %d %s, want the first-party agent flagged", list.status, list.body)
	}

	// An agent the user makes is not.
	made := post(t, pathAgent, mustJSON(t, map[string]any{"name": "mine"}), holder.session)
	if made.status != http.StatusCreated || strings.Contains(made.body, "firstParty") {
		t.Errorf("POST /api/agent = %d %s, want an agent with no firstParty member", made.status, made.body)
	}

	// Revoking the agent ends both of its grants.
	agentID := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", first)
	del(t, pathAgent+"/"+agentID, holder.session).expect(t, "revoke the first-party agent", http.StatusOK, "")

	for _, id := range []string{first, second} {
		if got := scalar(t, "SELECT revoked_at IS NOT NULL FROM secrets WHERE id = ?", id); got != "1" {
			t.Errorf("grant %s revoked = %q, want 1", id, got)
		}
	}

	// A revoked agent is not revived and does not lock the person out: signing in
	// again creates a fresh agent and a fresh grant, which works, while the revoked
	// agent and its grants stay as they were.
	pending := loginPage(t, authorize(t, loginQuery(client, newPKCE())))
	again := idOfToken(t, consentRedirect(t, consent(t, holder.session, pending, true, nil)).Query().Get("code"))
	fresh := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", again)

	if fresh == agentID {
		t.Errorf("the login after the revocation was held by the revoked agent %s", agentID)
	}

	expectCount(t, tableAgents+" WHERE user_id = ? AND first_party = 1", "2", holder.userID)
	expectCount(t, tableAgents+" WHERE user_id = ? AND first_party = 1 AND revoked_at IS NULL", "1", holder.userID)
	expectCount(t, tableAgents+" WHERE id = ? AND revoked_at IS NULL", "1", fresh)

	if got := scalar(t, "SELECT revoked_at IS NULL FROM secrets WHERE id = ?", again); got != "1" {
		t.Errorf("the new grant is revoked = %q, want it live", got)
	}

	for _, id := range []string{first, second} {
		if got := scalar(t, "SELECT revoked_at IS NOT NULL FROM secrets WHERE id = ?", id); got != "1" {
			t.Errorf("old grant %s revoked = %q, want it still revoked", id, got)
		}
	}

	// The next login finds the fresh agent, as it did the first.
	pending = loginPage(t, authorize(t, loginQuery(client, newPKCE())))
	third := idOfToken(t, consentRedirect(t, consent(t, holder.session, pending, true, nil)).Query().Get("code"))

	if got := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", third); got != fresh {
		t.Errorf("the next login agent = %q, want the fresh agent %q", got, fresh)
	}
}

// TestFirstPartyTwoUsers: the agent is kept per user and client. A second user's
// first login creates an agent of their own and is not attached to the first
// user's, and revoking the first user's agent does not touch the second's.
//
//nolint:paralleltest // shares one database
func TestFirstPartyTwoUsers(t *testing.T) {
	holder := newOAuthHolder(t)
	other, otherSession := secondUser(t)
	client := firstPartyClient(t)

	login := func(session string) string {
		pending := loginPage(t, authorize(t, loginQuery(client, newPKCE())))

		return idOfToken(t, consentRedirect(t, consent(t, session, pending, true, nil)).Query().Get("code"))
	}

	agentOf := func(grant string) string { return scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", grant) }

	a1, b1 := agentOf(login(holder.session)), agentOf(login(otherSession))

	if a1 == b1 {
		t.Fatalf("both users' logins were held by agent %s", a1)
	}

	for user, agent := range map[string]string{holder.userID: a1, other: b1} {
		if got := scalar(t, "SELECT user_id FROM agents WHERE id = ? AND first_party = 1", agent); got != user {
			t.Errorf("agent %s belongs to %q, want %q", agent, got, user)
		}
	}

	del(t, pathAgent+"/"+a1, holder.session).expect(t, "revoke the first user's agent", http.StatusOK, "")

	if b2 := agentOf(login(otherSession)); b2 != b1 {
		t.Errorf("the second user's login agent = %s, want their own, kept, agent %s", b2, b1)
	}

	if a2 := agentOf(login(holder.session)); a2 == a1 || a2 == b1 {
		t.Errorf("the first user's login after revocation = agent %s, want a fresh one (not %s or %s)", a2, a1, b1)
	}

	expectCount(t, tableAgents+" WHERE first_party = 1 AND revoked_at IS NULL", "2")
}

// TestFirstPartyLoginAtTheAgentLimit: a user at the agent limit who has no agent
// for the client is refused as for any consent that creates one, and one who has
// it signs in again, because nothing is added.
//
//nolint:paralleltest // shares one database
func TestFirstPartyLoginAtTheAgentLimit(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)

	for i := range maxAgents {
		seedAgent(t, idN("d200", i+1), holder.userID, "bulk")
	}

	pending := loginPage(t, authorize(t, loginQuery(client, newPKCE())))
	consent(t, holder.session, pending, true, nil).expect(t, "the 26th agent", http.StatusConflict, codeAgentLimit)
	expectCount(t, tableOAuthGrants, "0")
	expectCount(t, tableAgents, "25")
	expectNoOrphanSecrets(t)

	// Free one place, sign in, and be at the limit again: the next login finds the agent.
	del(t, pathAgent+"/"+idN("d200", 1), holder.session).expect(t, "revoke one", http.StatusOK, "")

	pending = loginPage(t, authorize(t, loginQuery(client, newPKCE())))
	consent(t, holder.session, pending, true, nil).expect(t, "login with a place free", http.StatusOK, "")
	expectCount(t, "agents WHERE revoked_at IS NULL", "25")

	pending = loginPage(t, authorize(t, loginQuery(client, newPKCE())))
	consent(t, holder.session, pending, true, nil).expect(t, "a login at the limit with the agent", http.StatusOK, "")
	expectCount(t, "agents WHERE revoked_at IS NULL", "25")
	expectCount(t, tableOAuthGrants, "2")

	// A revoked first-party agent frees its place and is not counted: but the
	// user who then fills it with another agent has none for the client and is at
	// the limit, refused as the 26th agent is.
	first := scalar(t, "SELECT id FROM agents WHERE first_party = 1")
	del(t, pathAgent+"/"+first, holder.session).expect(t, "revoke the first-party agent", http.StatusOK, "")
	seedAgent(t, idN("d200", 100), holder.userID, "bulk")
	expectCount(t, "agents WHERE revoked_at IS NULL", "25")

	pending = loginPage(t, authorize(t, loginQuery(client, newPKCE())))
	consent(t, holder.session, pending, true, nil).expect(t, "a login at the limit after revocation", http.StatusConflict, codeAgentLimit)
	expectCount(t, tableOAuthGrants, "2")
	expectNoOrphanSecrets(t)

	// With a place free again, the same login creates a fresh agent.
	del(t, pathAgent+"/"+idN("d200", 2), holder.session).expect(t, "revoke one", http.StatusOK, "")

	pending = loginPage(t, authorize(t, loginQuery(client, newPKCE())))
	consent(t, holder.session, pending, true, nil).expect(t, "a login with a place free after revocation", http.StatusOK, "")
	expectCount(t, "agents WHERE first_party = 1 AND revoked_at IS NULL", "1")
	expectCount(t, "agents WHERE revoked_at IS NULL", "25")
}

// TestFirstPartyRaces: first-party logins racing each other and a revocation. Whichever
// wins, the user has at most one active agent for the client, every live grant of
// the client is held by it, nothing answers 5xx, and no secret is left without
// its row.
//
//nolint:paralleltest // shares one database
func TestFirstPartyRaces(t *testing.T) {
	client := firstPartyClient(t)

	type race struct {
		name string
		// run races the calls against the user and returns the replies.
		run func(t *testing.T, session, userID string, pending []string) []reply
		// pendings is how many different pending requests the race needs.
		pendings int
		// atMost is the most active agents for the client the race may end with, and
		// atLeast the fewest: a revocation may win last and leave none.
		atLeast, atMost int
	}

	login := func(session, pending string) reply { return consent(t, session, pending, true, nil) }

	races := []race{
		{name: "different logins of a first login", pendings: 4, atLeast: 1, atMost: 1,
			run: func(_ *testing.T, session, _ string, pending []string) []reply {
				return oaRace(len(pending), func(i int) reply { return login(session, pending[i]) })
			}},
		{name: "the same login submitted twice", pendings: 1, atLeast: 1, atMost: 1,
			run: func(_ *testing.T, session, _ string, pending []string) []reply {
				return oaRace(3, func(int) reply { return login(session, pending[0]) })
			}},
		{name: "a login racing the revocation of the agent it would find", pendings: 3, atLeast: 0, atMost: 1,
			run: func(t *testing.T, session, userID string, pending []string) []reply {
				t.Helper()

				// One login first, so there is an agent to revoke.
				first := login(session, pending[0])
				first.expect(t, "the first login", http.StatusOK, "")

				agent := scalar(t, "SELECT id FROM agents WHERE user_id = ? AND first_party = 1", userID)

				return oaRace(3, func(i int) reply {
					if i == 0 {
						return del(t, pathAgent+"/"+agent, session)
					}

					return login(session, pending[i])
				})
			}},
	}

	for _, test := range races {
		t.Run(test.name, func(t *testing.T) {
			for round := range oaRaceRounds {
				holder := newOAuthHolder(t)
				pending := make([]string, test.pendings)

				for i := range pending {
					pending[i] = loginPage(t, authorize(t, loginQuery(client, newPKCE())))
				}

				replies := test.run(t, holder.session, holder.userID, pending)
				t.Logf("round %d: %v", round, oaTally(replies))
				oaNo5xx(t, test.name, replies)

				active, err := strconv.Atoi(count(t, tableAgents+" WHERE user_id = ? AND first_party = 1 AND revoked_at IS NULL", holder.userID))
				if err != nil || active < test.atLeast || active > test.atMost {
					t.Errorf("round %d: %d active first-party agents (%v), want %d to %d", round, active, err, test.atLeast, test.atMost)
				}

				expectNoOrphanSecrets(t)

				// Every live grant of the client is held by an active agent of the user.
				expectCount(t, tableOAuthGrants+" g JOIN secrets s ON s.id = g.id AND s.revoked_at IS NULL "+
					"JOIN agents a ON a.id = g.agent_id WHERE a.revoked_at IS NOT NULL", "0")
			}
		})
	}
}

// TestFirstPartyRefusals: an untrusted client is refused the login resource, a
// trusted client is refused an MCP scope through the no-agent path, and a
// first-party login cannot be attached to an agent.
//
//nolint:paralleltest // shares one database
func TestFirstPartyRefusals(t *testing.T) {
	holder := newOAuthHolder(t)
	trusted := firstPartyClient(t)
	ordinary := newOAuthClient(t)

	t.Run("an untrusted client is refused the login resource", func(t *testing.T) {
		query := ordinary.authorizeQuery(newPKCE())
		query.Set(paramResource, loginResource)
		query.Set("scope", "profile")

		got := authorize(t, query)
		redirect := got.locationURL(t)

		if got.status != http.StatusFound || !strings.HasPrefix(got.location(), ordinary.redirect) ||
			redirect.Query().Get("error") != "invalid_target" || redirect.Query().Get("code") != "" {
			t.Errorf("authorize = %d %s, want a redirect to the client with invalid_target", got.status, got.location())
		}
	})

	t.Run("a trusted client cannot get an MCP scope through the login resource", func(t *testing.T) {
		for _, scope := range []string{"openid profile mcp:read", "mcp:write", "email mcp:read"} {
			query := loginQuery(trusted, newPKCE())
			query.Set("scope", scope)

			got := authorize(t, query)
			if got.locationURL(t).Query().Get("error") != "invalid_scope" {
				t.Errorf("scope %q: authorize = %d %s, want invalid_scope", scope, got.status, got.location())
			}
		}
	})

	t.Run("a trusted client asking for the MCP resource must choose an agent", func(t *testing.T) {
		query := trusted.authorizeQuery(newPKCE())
		pending := pendingOf(t, authorize(t, query))

		consent(t, holder.session, pending, true, nil).expect(t, "no agent for an MCP grant", http.StatusBadRequest, codeInvalidConsent)
		expectCount(t, tableOAuthGrants, "0")
	})

	t.Run("a login cannot name an agent", func(t *testing.T) {
		seedAgent(t, idAgentA, holder.userID, "mine")

		pending := loginPage(t, authorize(t, loginQuery(trusted, newPKCE())))

		for _, choice := range []map[string]string{newAgentChoice("x"), agentChoiceID(idAgentA)} {
			consent(t, holder.session, pending, true, choice).expect(t, "a login naming an agent", http.StatusBadRequest, codeInvalidConsent)
		}

		expectCount(t, tableOAuthGrants, "0")
		expectCount(t, tableAgents, "1")
	})

	t.Run("the redirect URI must be the document's", func(t *testing.T) {
		query := loginQuery(trusted, newPKCE())
		query.Set(paramRedirectURI, "http://localhost:9894/elsewhere")

		got := authorize(t, query)
		if got.status != http.StatusFound || !strings.HasPrefix(got.location(), target.origin+"/oauth/error?error=invalid_redirect_uri") {
			t.Errorf("authorize = %d %s, want the UI's error page", got.status, got.location())
		}
	})
}

// TestFirstPartyDiscovery: the OpenID Connect discovery document says what the
// Pages app's client needs: the code flow with S256, no client authentication,
// RS256, the profile claims, and a key set whose key a verifier can use.
//
//nolint:paralleltest // shares one database
func TestFirstPartyDiscovery(t *testing.T) {
	got := get(t, pathOpenIDConfig, "")
	if got.status != http.StatusOK {
		t.Fatalf("GET %s = %d %s", pathOpenIDConfig, got.status, got.body)
	}

	var doc map[string]any

	err := json.Unmarshal([]byte(got.body), &doc)
	if err != nil {
		t.Fatalf("the discovery document %q: %v", got.body, err)
	}

	list := func(name string) []string {
		items, _ := doc[name].([]any)
		out := make([]string, len(items))

		for i, item := range items {
			out[i], _ = item.(string)
		}

		return out
	}

	for name, wanted := range map[string][]string{
		"response_types_supported":              {"code"},
		"grant_types_supported":                 {"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      {pkceMethod},
		"token_endpoint_auth_methods_supported": {"none"},
		"id_token_signing_alg_values_supported": {"RS256"},
		"subject_types_supported":               {"public"},
	} {
		if !slices.Equal(list(name), wanted) {
			t.Errorf("%s = %v, want %v", name, list(name), wanted)
		}
	}

	for _, claim := range []string{"name", "email", "email_verified"} {
		if !slices.Contains(list("claims_supported"), claim) {
			t.Errorf("claims_supported = %v, want %s", list("claims_supported"), claim)
		}
	}

	for _, scope := range []string{"openid", "profile", "email", "offline_access"} {
		if !slices.Contains(list("scopes_supported"), scope) {
			t.Errorf("scopes_supported = %v, want %s", list("scopes_supported"), scope)
		}
	}

	if doc["issuer"] != target.apiOrigin || doc["jwks_uri"] != target.apiOrigin+pathJWKS ||
		doc["token_endpoint"] != target.apiOrigin+pathOAuthToken {
		t.Errorf("issuer %v, jwks_uri %v, token_endpoint %v", doc["issuer"], doc["jwks_uri"], doc["token_endpoint"])
	}

	// oaPublicKey checks kid, use sig, alg RS256 and the exponent.
	oaPublicKey(t)
}

// agentListOf is the stored scope list of the agent a user's first-party login
// keeps, as the text the column holds.
func agentListOf(t *testing.T, userID string) string {
	t.Helper()

	return scalar(t, "SELECT scopes FROM agents WHERE user_id = ? AND first_party = 1 AND revoked_at IS NULL", userID)
}

// signInAsking runs one first-party login of the user asking for scope.
func signInAsking(t *testing.T, client *oauthClient, session, scope string) {
	t.Helper()

	query := loginQuery(client, newPKCE())
	query.Set("scope", scope)

	pending := loginPage(t, authorize(t, query))
	consent(t, session, pending, true, nil).expect(t, "a login asking for "+scope, http.StatusOK, "")
}

// TestFirstPartyAgentScopes runs the real statement that sets a first-party
// login's agent's list, in the real database: the first sign-in creates the agent
// with the names asked for, a later one unions, a smaller one keeps the earlier
// names, a stale or foreign name is pruned to the allowlist, and the list is in
// the allowlist's order, each name once. A name that is not authsu's is never
// written. The row is the stored text, so what is held is the JSON as written.
//
//nolint:paralleltest // shares one database
func TestFirstPartyAgentScopes(t *testing.T) {
	client := firstPartyClient(t)

	type step struct {
		// stale, when set, is written into the agent's row before the sign-in.
		stale string
		ask   string
		want  string
	}

	tests := []struct {
		name  string
		steps []step
	}{
		{name: "the profile alone", steps: []step{{ask: "openid profile", want: `[]`}}},
		{name: "the first sign-in creates the list", steps: []step{
			{ask: "openid profile agent:read org:read", want: `["org:read","agent:read"]`},
		}},
		{name: "a later sign-in unions, in the allowlist's order", steps: []step{
			{ask: "profile agent:read", want: `["agent:read"]`},
			{ask: "profile sandbox:create org:read", want: `["sandbox:create","org:read","agent:read"]`},
		}},
		{name: "a later sign-in asking for less keeps the earlier names", steps: []step{
			{ask: "profile agent:read org:read", want: `["org:read","agent:read"]`},
			{ask: "profile agent:read", want: `["org:read","agent:read"]`},
			{ask: "openid profile", want: `["org:read","agent:read"]`},
		}},
		{name: "a name removed from the allowlist is pruned", steps: []step{
			{ask: "profile org:read", want: `["org:read"]`},
			{stale: `["org:read","removed:scope","default:agent","user:read"]`, ask: "profile", want: `["org:read"]`},
		}},
		{name: "a damaged list is repaired and never fails the sign-in", steps: []step{
			{ask: "profile org:read", want: `["org:read"]`},
			{stale: `not json`, ask: "profile agent:read", want: `["agent:read"]`},
			{stale: `{"org:read":1}`, ask: "profile", want: `[]`},
			{stale: `[1,null,"org:read",["x"]]`, ask: "profile", want: `["org:read"]`},
			{stale: `"org:read"`, ask: "profile", want: `[]`},
		}},
		{name: "every name fits the column", steps: []step{
			{ask: "profile sandbox:create sandbox:revoke org:read agent:create agent:read",
				want: `["sandbox:create","sandbox:revoke","org:read","agent:create","agent:read"]`},
			{stale: `["a","b"]`, ask: "profile agent:read", want: `["agent:read"]`},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			holder := newOAuthHolder(t)

			for i, one := range test.steps {
				if one.stale != "" {
					seed(t, "UPDATE agents SET scopes = ? WHERE user_id = ? AND first_party = 1", one.stale, holder.userID)
				}

				signInAsking(t, client, holder.session, one.ask)

				if got := agentListOf(t, holder.userID); got != one.want {
					t.Errorf("step %d (%s): the agent's list = %s, want %s", i, one.ask, got, one.want)
				}
			}

			expectNoOrphanSecrets(t)
		})
	}
}

// TestFirstPartyAgentScopesNeverReachOtherAgents: the update of a login's agent
// list writes only the agent authsu keeps for the client. A user's own agent, a
// revoked first-party agent, a first-party agent of another user and a sandboxed
// agent keep their lists through a sign-in that asks for every scope, and a user
// agent the user attaches to a third-party grant is not widened by it.
//
//nolint:paralleltest // shares one database
func TestFirstPartyAgentScopesNeverReachOtherAgents(t *testing.T) {
	holder := newOAuthHolder(t)
	other, _ := secondUser(t)
	client := firstPartyClient(t)

	const own, revoked, foreign = "d300", "d301", "d302"

	seedAgent(t, idN(own, 1), holder.userID, "mine")
	seed(t, "UPDATE agents SET scopes = ? WHERE id = ?", `["org:read"]`, idN(own, 1))

	seed(t, "INSERT INTO agents (id, user_id, name, scopes, created_at, first_party, first_party_client, revoked_at) "+
		"VALUES (?, ?, 'old', ?, 1, 1, ?, 2)", idN(revoked, 1), holder.userID, `["agent:create"]`, trustedClientID)
	seed(t, "INSERT INTO agents (id, user_id, name, scopes, created_at, first_party, first_party_client) "+
		"VALUES (?, ?, 'theirs', ?, 1, 1, ?)", idN(foreign, 1), other, `["agent:create"]`, trustedClientID)

	signInAsking(t, client, holder.session, "profile sandbox:create sandbox:revoke org:read agent:create agent:read")

	for id, want := range map[string]string{
		idN(own, 1): `["org:read"]`, idN(revoked, 1): `["agent:create"]`, idN(foreign, 1): `["agent:create"]`,
	} {
		if got := scalar(t, "SELECT scopes FROM agents WHERE id = ?", id); got != want {
			t.Errorf("agent %s holds %s, want %s untouched", id, got, want)
		}
	}

	// The login's own agent is the fresh one, holding what was asked.
	if got := agentListOf(t, holder.userID); got != `["sandbox:create","sandbox:revoke","org:read","agent:create","agent:read"]` {
		t.Errorf("the login's agent holds %s", got)
	}

	// An agent the user attaches to a third-party grant is never written.
	approveWith(t, newOAuthClient(t), holder.session, agentChoiceID(idN(own, 1)), nil)

	if got := scalar(t, "SELECT scopes FROM agents WHERE id = ?", idN(own, 1)); got != `["org:read"]` {
		t.Errorf("an attached agent holds %s, want it untouched", got)
	}
}

// TestThirdPartyConsentAgentHoldsNoAuthsuScopes: the agent a person creates at the
// consent of a third-party client has the empty list, whatever MCP scopes were
// approved, because none of them is an authsu name.
//
//nolint:paralleltest // shares one database
func TestThirdPartyConsentAgentHoldsNoAuthsuScopes(t *testing.T) {
	holder := newOAuthHolder(t)

	approved := approve(t, newOAuthClient(t), holder.session, newAgentChoice("tool"))
	agent := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", idOfToken(t, approved.code))

	if got := scalar(t, "SELECT scopes FROM agents WHERE id = ? AND first_party = 0", agent); got != "[]" {
		t.Errorf("the new agent holds %s, want the empty list", got)
	}
}
