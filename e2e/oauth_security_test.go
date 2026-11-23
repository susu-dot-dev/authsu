//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_security_test.go: permission and type confusion across the OAuth surface
// through the real Worker. Every credential kind is presented where it does not
// belong, every token is shown to the endpoints that must not honour it, and one
// user reaches for another's grant. Each refusal must be the same refusal an
// unauthenticated stranger gets, never an oracle for what exists.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// oaIssued is a grant with its tokens, issued to a user through the real flow.
type oaIssued struct {
	a      approved
	tokens tokens
	grant  string
}

// oaIssue approves a request for the session (choosing agent) and exchanges the
// code.
func oaIssue(t *testing.T, session string, agent map[string]string) oaIssued {
	t.Helper()

	client := newOAuthClient(t)
	a := approve(t, client, session, agent)
	grant := idOfToken(t, a.code)
	issued := a.mustExchange(t)

	return oaIssued{a: a, tokens: issued, grant: grant}
}

// TestOAuthTokensAsBearers: the OAuth tokens are never credentials of authsu's own
// API, and no other credential kind opens an OAuth route that wants a session.
//
//nolint:paralleltest // shares one database
func TestOAuthTokensAsBearers(t *testing.T) {
	holder := newOAuthHolder(t)
	issued := oaIssue(t, holder.session, newAgentChoice("bearer agent"))

	// A pending code too, which was never exchanged.
	pending := approve(t, newOAuthClient(t), holder.session, newAgentChoice("unspent"))

	routes := []struct{ method, path string }{
		{http.MethodGet, pathSession}, {http.MethodGet, pathAgent}, {http.MethodGet, pathGrant},
		{http.MethodGet, pathGrant + "/" + issued.grant}, {http.MethodDelete, pathGrant + "/" + issued.grant},
		{http.MethodPost, pathAgent}, {http.MethodGet, pathUser}, {http.MethodGet, pathInvitation},
	}

	bearers := []struct{ name, token string }{
		{"the access token", issued.tokens.AccessToken},
		{"the refresh token", issued.tokens.RefreshToken},
		{"an unspent code", pending.code},
		{"a made-up access token", newToken(tagOAuthAccess)},
		{"a made-up refresh token", newToken(tagOAuthRefresh)},
	}

	for _, route := range routes {
		for _, bearer := range bearers {
			got := send(t, request{method: route.method, path: route.path, bearer: bearer.token, body: bodyFor(route.method)})
			got.expect(t, route.method+" "+route.path+" with "+bearer.name, http.StatusUnauthorized, codeUnauthenticated)

			// The same answer as having sent nothing at all: no oracle.
			none := send(t, request{method: route.method, path: route.path, body: bodyFor(route.method)})
			if got.body != none.body {
				t.Errorf("%s %s with %s: %q differs from the answer to no credential, %q", route.method, route.path, bearer.name, got.body, none.body)
			}
		}
	}

	// The same tokens as the session cookie.
	for _, bearer := range bearers {
		get(t, pathSession, bearer.token).expect(t, "the cookie holding "+bearer.name, http.StatusUnauthorized, codeUnauthenticated)
	}

	// Nothing the failed attempts did changed the grant.
	if got, _ := introspect(t, issued.tokens.AccessToken, oauthResource); !got.Active {
		t.Errorf("the access token stopped working after being refused as a bearer")
	}
}

// bodyFor is a body for an unsafe method, which a JSON route needs.
func bodyFor(method string) []byte {
	if method == http.MethodPost {
		return []byte(`{"name":"x"}`)
	}

	return nil
}

// TestOAuthGrantRoutesPermissions: the grant routes are the user's own. Another
// user's grant is not found, a key without the scope is refused, and an agent
// cannot revoke.
//
//nolint:paralleltest // shares one database
func TestOAuthGrantRoutesPermissions(t *testing.T) {
	holder := newOAuthHolder(t)
	other, otherSession := secondUser(t)

	mine := oaIssue(t, holder.session, newAgentChoice("mine"))
	theirs := oaIssue(t, otherSession, newAgentChoice("theirs"))

	seedAgent(t, idAgentA, holder.userID, "keyed")

	userKey := seedAPIKey(t, idN("d300", 1), holder.userID, "")
	agentKey := seedAPIKey(t, idN("d300", 2), holder.userID, idAgentA)

	// Each user sees only their own.
	for _, tt := range []struct {
		name, session, want, not string
	}{
		{"the first user", holder.session, mine.grant, theirs.grant},
		{"the second user", otherSession, theirs.grant, mine.grant},
	} {
		list := get(t, pathGrant, tt.session)
		if list.status != http.StatusOK || !strings.Contains(list.body, tt.want) || strings.Contains(list.body, tt.not) {
			t.Errorf("%s: the list = %d %s, want only %s", tt.name, list.status, list.body, tt.want)
		}
	}

	// Reading or revoking another user's grant is 404, the same as a grant that
	// does not exist.
	for _, tt := range []struct {
		name, method, id, session string
	}{
		{"reading another user's grant", http.MethodGet, theirs.grant, holder.session},
		{"revoking another user's grant", http.MethodDelete, theirs.grant, holder.session},
		{"reading a grant that does not exist", http.MethodGet, idMissing, holder.session},
		{"revoking a grant that does not exist", http.MethodDelete, idMissing, holder.session},
		{"the other user reading the first's grant", http.MethodGet, mine.grant, otherSession},
		{"the other user revoking the first's grant", http.MethodDelete, mine.grant, otherSession},
	} {
		got := send(t, request{method: tt.method, path: pathGrant + "/" + tt.id, token: tt.session})
		got.expect(t, tt.name, http.StatusNotFound, "grant_not_found")
	}

	// The same answer for another user's and for a missing grant.
	a := get(t, pathGrant+"/"+theirs.grant, holder.session)
	b := get(t, pathGrant+"/"+idMissing, holder.session)

	if a.body != b.body {
		t.Errorf("another user's grant answers %q, a missing one %q: an oracle", a.body, b.body)
	}

	// None of it touched either user's tokens.
	for name, token := range map[string]string{"mine": mine.tokens.AccessToken, "theirs": theirs.tokens.AccessToken} {
		if got, _ := introspect(t, token, oauthResource); !got.Active {
			t.Errorf("%s: the access token stopped working", name)
		}
	}

	// Credentials without the scope or that are agents.
	for _, tt := range []struct {
		name   string
		req    request
		status int
		code   string
	}{
		{"a user key listing grants", request{path: pathGrant, bearer: userKey}, 403, codeInsufficient},
		{"an agent key listing grants", request{path: pathGrant, bearer: agentKey}, 403, codeInsufficient},
		{"an agent key reading a grant", request{path: pathGrant + "/" + mine.grant, bearer: agentKey}, 403, codeInsufficient},
		{"a user key revoking a grant", request{method: http.MethodDelete, path: pathGrant + "/" + mine.grant, bearer: userKey}, 403, codeInsufficient},
		{"an agent key revoking a grant", request{method: http.MethodDelete, path: pathGrant + "/" + mine.grant, bearer: agentKey}, 403, codeInsufficient},
		{"no credential listing grants", request{path: pathGrant}, 401, codeUnauthenticated},
		{"no credential revoking a grant", request{method: http.MethodDelete, path: pathGrant + "/" + mine.grant}, 401, codeUnauthenticated},
		{"a malformed id", request{path: pathGrant + "/not-an-id", token: holder.session}, 400, codeInvalidID},
	} {
		send(t, tt.req).expect(t, tt.name, tt.status, tt.code)
	}

	if got, _ := introspect(t, mine.tokens.AccessToken, oauthResource); !got.Active {
		t.Errorf("a refused revocation revoked the grant")
	}

	// The grant's own agent is not its holder's session: the grant stays the user's.
	_ = other

	expectNoOrphanSecrets(t)
}

// TestOAuthTokenConfusion: every token kind presented at every endpoint that is not
// its own. The answer must be an inactive introspection or an invalid_grant, never
// success, and must change nothing.
//
//nolint:paralleltest // shares one database
func TestOAuthTokenConfusion(t *testing.T) {
	holder := newOAuthHolder(t)
	issued := oaIssue(t, holder.session, newAgentChoice("confusion"))
	unspent := approve(t, newOAuthClient(t), holder.session, newAgentChoice("unspent"))
	userKey := seedAPIKey(t, idN("d400", 1), holder.userID, "")

	foreign := []struct{ name, token string }{
		{"an unspent authorization code", unspent.code},
		{"the refresh token", issued.tokens.RefreshToken},
		{"a session token", holder.session},
		{"an API key", userKey},
		{"an invitation token", firstRunSecret},
		{"a made-up access token", newToken(tagOAuthAccess)},
		{"an access token of 42 characters", issued.tokens.AccessToken[:len(issued.tokens.AccessToken)-1]},
		{"the access token in upper case", strings.ToUpper(issued.tokens.AccessToken)},
		{"the access token with a space", issued.tokens.AccessToken + " "},
		{"the access token with a newline", issued.tokens.AccessToken + "\n"},
		{"nothing sensible", "x"},
	}

	t.Run("introspection answers inactive for anything but the access token", func(t *testing.T) {
		for _, tt := range foreign {
			expectInactive(t, tt.name, tt.token, oauthResource)
		}
	})

	t.Run("text that is not text is a malformed request, not a token", func(t *testing.T) {
		for _, token := range []string{issued.tokens.AccessToken + "\x00", "\xff"} {
			got := postForm(t, pathOAuthIntrospect, url.Values{paramToken: {token}, paramResource: {oauthResource}})
			got.expectOAuth(t, "introspecting a token that is not text", http.StatusBadRequest, "invalid_request")

			got = postForm(t, pathOAuthRevoke, url.Values{paramToken: {token}, paramClientID: {issued.a.client.id}})
			got.expectOAuth(t, "revoking a token that is not text", http.StatusBadRequest, "invalid_request")
		}
	})

	t.Run("a token is inactive at any other resource", func(t *testing.T) {
		for _, resource := range []string{
			"https://auth.susu.dev/mcp", oauthResource + "/", strings.ToUpper(oauthResource), oauthResource + "?x=1",
			"http://localhost:8788", "http://localhost:8789/mcp", "http://127.0.0.1:8788/mcp", target.apiOrigin, "x", "%00",
		} {
			expectInactive(t, "the access token at "+resource, issued.tokens.AccessToken, resource)
		}
	})

	t.Run("introspection needs both parameters and refuses repeats", func(t *testing.T) {
		for _, tt := range []struct{ name, body string }{
			{"no token", "resource=" + url.QueryEscape(oauthResource)},
			{"no resource", "token=" + issued.tokens.AccessToken},
			{"nothing", ""},
			{"a repeated token", "token=" + issued.tokens.AccessToken + "&token=" + newToken(tagOAuthAccess) + "&resource=" + url.QueryEscape(oauthResource)},
			{"a repeated resource", "token=" + issued.tokens.AccessToken + "&resource=" + url.QueryEscape(oauthResource) + "&resource=x"},
		} {
			postRaw(t, pathOAuthIntrospect, tt.body).
				expectOAuth(t, tt.name, http.StatusBadRequest, "invalid_request")
		}
	})

	t.Run("the token endpoint refuses a token of another kind as a refresh token", func(t *testing.T) {
		for _, tt := range []struct{ name, token string }{
			{"an unspent authorization code", unspent.code},
			{"the access token", issued.tokens.AccessToken},
			{"a session token", holder.session},
			{"an API key", userKey},
		} {
			issued.a.refresh(t, tt.token).expectOAuth(t, tt.name+" as a refresh token", http.StatusBadRequest, "invalid_grant")
		}

		// The access token as a code, and the refresh token as a code.
		for _, token := range []string{issued.tokens.AccessToken, issued.tokens.RefreshToken} {
			form := unspent.codeForm()
			form.Set("code", token)
			postForm(t, pathOAuthToken, form).expectOAuth(t, "a token as a code", http.StatusBadRequest, "invalid_grant")
		}

		// The refresh token of another client.
		other := newOAuthClient(t)
		form := issued.a.refreshForm(issued.tokens.RefreshToken)
		form.Set("client_id", other.id)
		postForm(t, pathOAuthToken, form).expectOAuth(t, "the refresh token under another client", http.StatusBadRequest, "invalid_grant")
	})

	t.Run("revocation under the wrong client changes nothing", func(t *testing.T) {
		other := newOAuthClient(t)

		for _, token := range []string{issued.tokens.AccessToken, issued.tokens.RefreshToken} {
			got := postForm(t, pathOAuthRevoke, url.Values{"token": {token}, "client_id": {other.id}})
			if got.status != http.StatusOK {
				t.Errorf("revoke under another client = %d %s, want 200 (RFC 7009)", got.status, got.body)
			}
		}

		if got, _ := introspect(t, issued.tokens.AccessToken, oauthResource); !got.Active {
			t.Errorf("the access token was revoked by another client")
		}

		// The refresh token still works for its own client, and rotates.
		rotated := mustTokens(t, issued.a.refresh(t, issued.tokens.RefreshToken))
		issued.tokens = rotated
	})

	t.Run("revocation of things that are not tokens is 200", func(t *testing.T) {
		for _, tt := range foreign {
			got := postForm(t, pathOAuthRevoke, url.Values{"token": {tt.token}, "client_id": {issued.a.client.id}})
			if got.status != http.StatusOK {
				t.Errorf("revoking %s = %d %s, want 200", tt.name, got.status, got.body)
			}
		}

		// ...and none of it was a revocation of anything real.
		if got, _ := introspect(t, issued.tokens.AccessToken, oauthResource); !got.Active {
			t.Errorf("the access token stopped working")
		}

		for _, tt := range []struct{ name, body string }{
			{"no client_id", "token=" + issued.tokens.AccessToken},
			{"no token", "client_id=" + url.QueryEscape(issued.a.client.id)},
			{"an unparsable client_id", "token=" + issued.tokens.AccessToken + "&client_id=x"},
			{"a repeated token", "token=a&token=b&client_id=" + url.QueryEscape(issued.a.client.id)},
		} {
			got := postRaw(t, pathOAuthRevoke, tt.body)
			if got.status != http.StatusBadRequest {
				t.Errorf("revoke with %s = %d %s, want 400", tt.name, got.status, got.body)
			}
		}
	})

	t.Run("revoking the access token leaves the refresh token", func(t *testing.T) {
		got := postForm(t, pathOAuthRevoke, url.Values{"token": {issued.tokens.AccessToken}, "client_id": {issued.a.client.id}, "token_type_hint": {"access_token"}})
		if got.status != http.StatusOK {
			t.Fatalf("revoke = %d %s", got.status, got.body)
		}

		expectInactive(t, "the revoked access token", issued.tokens.AccessToken, oauthResource)

		rotated := mustTokens(t, issued.a.refresh(t, issued.tokens.RefreshToken))
		if got, _ := introspect(t, rotated.AccessToken, oauthResource); !got.Active {
			t.Errorf("a refresh after revoking only the access token gave an inactive token")
		}

		issued.tokens = rotated
	})

	t.Run("revoking the refresh token revokes the grant and its access token", func(t *testing.T) {
		got := postForm(t, pathOAuthRevoke, url.Values{"token": {issued.tokens.RefreshToken}, "client_id": {issued.a.client.id}})
		if got.status != http.StatusOK {
			t.Fatalf("revoke = %d %s", got.status, got.body)
		}

		expectInactive(t, "the access token of a revoked grant", issued.tokens.AccessToken, oauthResource)
		issued.a.refresh(t, issued.tokens.RefreshToken).expectOAuth(t, "the revoked refresh token", http.StatusBadRequest, "invalid_grant")

		// The user sees the grant as revoked.
		view := get(t, pathGrant+"/"+issued.grant, holder.session)
		if view.status != http.StatusOK || !strings.Contains(view.body, `"revokedAt"`) {
			t.Errorf("the grant after revocation = %d %s, want revokedAt", view.status, view.body)
		}
	})

	t.Run("a spent code is not a refresh token and the unspent code still works", func(t *testing.T) {
		if got := unspent.exchange(t); got.status != http.StatusOK {
			t.Errorf("the unspent code after all of that = %d %s, want 200", got.status, got.body)
		}
	})
}

// TestOAuthExpiry: a token past its expiry is dead whatever else is true of it.
// The clock is the database's, so the test ages a token by moving its expiry.
//
//nolint:paralleltest // shares one database
func TestOAuthExpiry(t *testing.T) {
	holder := newOAuthHolder(t)

	t.Run("an access token", func(t *testing.T) {
		issued := oaIssue(t, holder.session, newAgentChoice("expiry"))

		seed(t, "UPDATE secrets SET expires_at = strftime('%s','now') - 1 WHERE hash = ?", tokenHash(issued.tokens.AccessToken))
		expectInactive(t, "an expired access token", issued.tokens.AccessToken, oauthResource)

		// The refresh token still gives a fresh one.
		fresh := mustTokens(t, issued.a.refresh(t, issued.tokens.RefreshToken))
		if got, _ := introspect(t, fresh.AccessToken, oauthResource); !got.Active {
			t.Errorf("a refresh after the access token expired gave an inactive token")
		}
	})

	t.Run("a refresh token", func(t *testing.T) {
		issued := oaIssue(t, holder.session, newAgentChoice("expiry"))

		seed(t, "UPDATE secrets SET expires_at = strftime('%s','now') - 1 WHERE hash = ?", tokenHash(issued.tokens.RefreshToken))
		issued.a.refresh(t, issued.tokens.RefreshToken).expectOAuth(t, "an expired refresh token", http.StatusBadRequest, "invalid_grant")
	})

	t.Run("a code older than a minute", func(t *testing.T) {
		client := newOAuthClient(t)
		a := approve(t, client, holder.session, newAgentChoice("expiry"))

		seed(t, "UPDATE secrets SET created_at = strftime('%s','now') - 120, expires_at = strftime('%s','now') - 60 WHERE hash = ?", tokenHash(a.code))
		a.exchange(t).expectOAuth(t, "a code after its minute", http.StatusBadRequest, "invalid_grant")
	})
}
