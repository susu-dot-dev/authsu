//go:build e2e

//nolint:goconst // table-driven tests repeat case inputs on purpose; a constant per row would hide the table
package e2e_test

// oauth_limits_test.go: the size caps of the OAuth routes that the form-route
// tests do not reach (the query strings of the authorization endpoint and the
// request view, the consent body, and the discovery and grant routes), each at one
// byte under its cap, at it and one over, through the real boundary; the widest
// request a client may legitimately send; and a refresh after the access token's
// secret was swept, which the schema tests only reach with raw SQL.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The caps of internal/oauth, restated so that a change to one is a visible
// change to the test (MaxQuery, MaxConsentBody, MaxDiscoveryBody, MaxGrantQuery).
const (
	oaMaxQuery     = 8 << 10
	oaMaxConsent   = 12 << 10
	oaMaxDiscovery = 1 << 10
	oaMaxGrant     = 1 << 10
)

// oaQueryOf is a query string of exactly size bytes whose only parameter is an
// unknown one, so the route sees a well-formed query it has no use for.
func oaQueryOf(size int) string {
	const name = "x="

	return name + strings.Repeat("a", size-len(name))
}

// TestOAuthQueryCaps: a query string is refused 413 when it is one byte over the
// cap of its route, before anything is read, and is not refused for its size at
// the cap or below it. What the route then makes of a query it can do nothing
// with is its own answer, never the boundary's.
//
//nolint:paralleltest // shares one database
func TestOAuthQueryCaps(t *testing.T) {
	newAdmin(t)

	routes := []struct {
		name string
		path string
		cap  int
		// oauthFormat is whether the route answers in the RFC 6749 error format.
		oauthFormat bool
	}{
		{"the authorization endpoint", pathOAuthAuthorize, oaMaxQuery, true},
		{"the request view", pathOAuthRequest, oaMaxQuery, false},
		{"the grant list", pathGrant, oaMaxGrant, false},
		{"the authorization server metadata", pathOAuthMetadata, oaMaxDiscovery, false},
		{"the OpenID configuration", pathOpenIDConfig, oaMaxDiscovery, false},
		{"the key set", pathJWKS, oaMaxDiscovery, false},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			for _, tt := range []struct {
				name string
				size int
				over bool
			}{
				{"one byte under the cap", route.cap - 1, false},
				{"exactly the cap", route.cap, false},
				{"one byte over the cap", route.cap + 1, true},
				{"far over the cap", route.cap * 4, true},
			} {
				got := send(t, request{path: route.path + "?" + oaQueryOf(tt.size), keepRedirect: true})

				switch {
				case tt.over && route.oauthFormat:
					got.expectOAuth(t, tt.name, http.StatusRequestEntityTooLarge, "invalid_request")
				case tt.over:
					got.expect(t, tt.name, http.StatusRequestEntityTooLarge, "query_too_large")
				case got.status == http.StatusRequestEntityTooLarge:
					t.Errorf("%s: %d %s, a query within the cap was refused for its size", tt.name, got.status, got.body)
				}
			}
		})
	}
}

// TestOAuthConsentBodyCap: the consent body is capped at 12 KiB, which holds the
// largest body there can be, and a body one byte over is refused 413 before it is
// read, by a user with a session and by a stranger alike. The largest legitimate
// body is a sealed request at its longest (5516 base64url characters) with the
// longest agent name, 256 characters each written as a surrogate pair escape of 12
// bytes, which is 8636 bytes: the cap leaves room over it, and this test is what
// says so should either side change.
//
//nolint:paralleltest // shares one database
func TestOAuthConsentBodyCap(t *testing.T) {
	holder := newOAuthHolder(t)

	pad := func(size int) []byte {
		prefix := `{"request":"x","approve":false,"pad":"`
		suffix := `"}`

		return []byte(prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix)
	}

	for _, tt := range []struct {
		name  string
		size  int
		token string
		over  bool
	}{
		{"one byte under the cap, signed in", oaMaxConsent - 1, holder.session, false},
		{"exactly the cap, signed in", oaMaxConsent, holder.session, false},
		{"one byte over the cap, signed in", oaMaxConsent + 1, holder.session, true},
		{"one byte over the cap, signed out", oaMaxConsent + 1, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := post(t, pathOAuthConsent, pad(tt.size), tt.token)

			switch {
			case tt.over:
				got.expect(t, tt.name, http.StatusRequestEntityTooLarge, "body_too_large")
			case got.status == http.StatusRequestEntityTooLarge:
				t.Errorf("%s: %d %s, a body within the cap was refused for its size", tt.name, got.status, got.body)
			}
		})
	}
}

// oaFullyEncoded writes a query with every byte of every name and value
// percent-encoded, which is the widest form of it a client can send.
func oaFullyEncoded(query url.Values) string {
	var raw strings.Builder

	for name, values := range query {
		for _, value := range values {
			if raw.Len() > 0 {
				raw.WriteByte('&')
			}

			raw.WriteString(oaEncodeAll(name))
			raw.WriteByte('=')
			raw.WriteString(oaEncodeAll(value))
		}
	}

	return raw.String()
}

// oaEncodeAll percent-encodes every byte of s.
func oaEncodeAll(s string) string {
	const digits = "0123456789ABCDEF"

	var out strings.Builder

	for _, b := range []byte(s) {
		out.WriteByte('%')
		out.WriteByte(digits[b>>4])
		out.WriteByte(digits[b&15])
	}

	return out.String()
}

// oaWidestDocument serves the document of a client whose client_id and
// redirect_uri are 512 bytes and whose name is 128, and returns the three.
func oaWidestDocument(t *testing.T, client *oauthClient) (string, string, string) {
	t.Helper()

	pad := func(base string) string { return base + strings.Repeat("a", 512-len(base)) }

	longID := pad(strings.TrimSuffix(client.id, "/client.json") + "/client.json/")
	longRedirect := pad(strings.TrimSuffix(client.redirect, "/callback") + "/callback/")
	longName := strings.Repeat("N", 128)

	if len(longID) != 512 || len(longRedirect) != 512 {
		t.Fatalf("client_id is %d bytes and redirect_uri %d, want 512 each", len(longID), len(longRedirect))
	}

	client.servesWith(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", jsonType)
		_, _ = w.Write(mustJSON(t, map[string]any{
			paramClientID: longID, memberClientName: longName, memberRedirects: []string{longRedirect},
			memberAuthMethod: authMethodNone,
		}))
	})

	return longID, longRedirect, longName
}

// TestOAuthWidestAuthorizeRequest: the widest request a client may legitimately
// send is not refused for its size, and what it carries survives to the
// database. Every value is at the longest its parser accepts: a client_id and a
// redirect_uri of 512 bytes, a resource-sized state and nonce, and a client_name of
// 128 bytes, and each is written with every byte percent-encoded, which triples
// it. The query must fit under the cap, the sealed request must fit its payload,
// the person must reach the consent page, and approving with the longest agent
// name (256 code points of four bytes, so 1024 bytes) must write the grant, and
// the exchange must work. This is the one request through the real route to the
// real INSERT at the widest values, which the store tests reach only against a
// fake database and the schema tests only with SQL.
//
//nolint:paralleltest // shares one database
func TestOAuthWidestAuthorizeRequest(t *testing.T) {
	holder := newOAuthHolder(t)

	client := newOAuthClient(t)

	longID, longRedirect, longName := oaWidestDocument(t, client)

	pair := newPKCE()
	query := client.authorizeQuery(pair)
	query.Set(paramClientID, longID)
	query.Set(paramRedirectURI, longRedirect)

	// The state and the nonce may hold any visible character, and a double quote
	// and a backslash are the two JSON writes as two bytes, which the sealed
	// payload is sized for.
	query.Set("state", strings.Repeat(`"`, 256))
	query.Set(paramNonce, strings.Repeat(`\`, 128))

	raw := oaFullyEncoded(query)

	if len(raw) > oaMaxQuery || len(raw) < oaMaxQuery/2 {
		t.Fatalf("the widest request is %d bytes, want it between %d and the cap %d", len(raw), oaMaxQuery/2, oaMaxQuery)
	}

	t.Logf("the widest request is %d bytes of the %d allowed", len(raw), oaMaxQuery)

	got := send(t, request{path: pathOAuthAuthorize + "?" + raw, keepRedirect: true})
	pending := pendingOf(t, got)

	// The longest agent name there can be: 256 code points of four bytes.
	agentName := strings.Repeat("\U00010000", 256)

	approval := consentRedirect(t, consent(t, holder.session, pending, true, newAgentChoice(agentName)))
	if got := approval.Query().Get("state"); got != query.Get("state") {
		t.Errorf("approved state = %q, want the %d quotes that were sent", got, len(query.Get("state")))
	}

	code := approval.Query().Get("code")
	expectToken(t, code, tagOAuthCode)

	// The grant holds every value at its bound, byte for byte.
	grant := idOfToken(t, code)
	for column, want := range map[string]string{
		"client_id": longID, "redirect_uri": longRedirect, "client_name": longName, "nonce": query.Get(paramNonce),
	} {
		if got := scalar(t, "SELECT "+column+" FROM oauth_grants WHERE id = ?", grant); got != want {
			t.Errorf("oauth_grants.%s = %d bytes, want the %d that were sent", column, len(got), len(want))
		}
	}

	expectCount(t, "agents WHERE name = ?", "1", agentName)

	// And the grant works: the code is exchanged at the redirect_uri it names.
	exchanged := mustTokens(t, postForm(t, pathOAuthToken, url.Values{
		paramGrantType: {grantTypeCode}, paramClientID: {longID}, paramCode: {code},
		paramRedirectURI: {longRedirect}, "code_verifier": {pair.verifier},
	}))

	if live, _ := introspect(t, exchanged.AccessToken, oauthResource); !live.Active || live.ClientID != longID {
		t.Errorf("introspection = %+v, want a live token of the 512-byte client", live)
	}
}

// TestOAuthRefreshAfterTheAccessSecretIsSwept: a refresh of a grant whose access
// token's secret is gone issues a new access token and does not fail. Deleting
// the access token's secret takes its oauth_access_tokens row with it and keeps
// the grant, which is what a sweep of expired secrets does after 15 minutes, so
// the refresh must insert the access token's row and secret, not only replace
// them. The scope asked for narrows the grant's, and the token swept away is not
// live.
//
//nolint:paralleltest // shares one database
func TestOAuthRefreshAfterTheAccessSecretIsSwept(t *testing.T) {
	holder := newOAuthHolder(t)

	for _, tt := range []struct {
		name  string
		scope string
		want  string
	}{
		{"no scope asked for", "", oauthScopes},
		{"a narrower scope", "mcp:read", "mcp:read"},
		{"the whole scope, in another order", "openid mcp:write mcp:read", "openid mcp:write mcp:read"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			issued := oaIssue(t, holder.session, newAgentChoice("swept "+tt.name))
			access := mustSecretOf(t, issued.tokens.AccessToken)

			seed(t, "DELETE FROM secrets WHERE id = ?", access.id)
			expectCount(t, "oauth_access_tokens WHERE grant_id = ?", "0", issued.grant)
			expectInactive(t, "the access token whose secret was swept", issued.tokens.AccessToken, oauthResource)

			form := issued.a.refreshForm(issued.tokens.RefreshToken)
			if tt.scope != "" {
				form.Set("scope", tt.scope)
			}

			got := postForm(t, pathOAuthToken, form)
			refreshed := mustTokens(t, got)

			expectToken(t, refreshed.AccessToken, tagOAuthAccess)

			if refreshed.AccessToken == issued.tokens.AccessToken || refreshed.Scope != tt.want {
				t.Errorf("refreshed = %+v, want a new access token with scope %q", refreshed, tt.want)
			}

			live, _ := introspect(t, refreshed.AccessToken, oauthResource)
			if !live.Active || live.Scope != tt.want {
				t.Errorf("introspection = %+v, want a live token with scope %q", live, tt.want)
			}

			expectInactive(t, "the swept access token", issued.tokens.AccessToken, oauthResource)

			expectCount(t, "oauth_access_tokens WHERE grant_id = ?", "1", issued.grant)
			expectCount(t, "secrets WHERE id = ?", "1", issued.grant)
			expectNoOrphanSecrets(t)

			// The refresh token was rotated, so the one that was used is spent.
			issued.a.refresh(t, issued.tokens.RefreshToken).
				expectOAuth(t, "the refresh token that was used", http.StatusBadRequest, "invalid_grant")
		})
	}
}
