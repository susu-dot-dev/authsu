//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,maintidx,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_token_test.go: the form routes of the OAuth server (token, revocation,
// introspection) against the real TinyGo build: how a form body is read, which
// media types and sizes the boundary lets through, and what a token request that
// is wrong in each way is told. A request refused before it is parsed writes
// nothing and spends nothing, which each case proves by spending the code
// afterwards.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// oaFormRoutes are the form routes with their body caps (oauth.MaxTokenBody,
// MaxRevokeBody and MaxIntrospectBody).
func oaFormRoutes() []struct {
	path string
	cap  int
} {
	return []struct {
		path string
		cap  int
	}{
		{pathOAuthToken, 8 << 10}, {pathOAuthRevoke, 4 << 10}, {pathOAuthIntrospect, 2 << 10},
	}
}

// TestOAuthFormRoutesBoundary: the boundary's checks on the three form routes, in
// the order they apply: the method (405 with Allow), the media type (415), the
// size (413), and then the form itself. Every refusal is in the RFC 6749 error
// format, and none is cacheable.
//
//nolint:paralleltest // shares one database
func TestOAuthFormRoutesBoundary(t *testing.T) {
	reset(t)

	for _, route := range oaFormRoutes() {
		t.Run(route.path, func(t *testing.T) {
			typed := func(contentType, body string) reply {
				return send(t, request{
					method: http.MethodPost, path: route.path, body: []byte(body),
					headers: map[string]string{"Content-Type": contentType},
				})
			}

			// The form with nothing in it: past the boundary, refused by the route.
			t.Run("a form is read", func(t *testing.T) {
				for _, contentType := range []string{
					formType, formType + "; charset=utf-8", formType + ";charset=UTF-8", "Application/X-WWW-Form-Urlencoded",
				} {
					got := typed(contentType, "")
					got.expectOAuth(t, "an empty form as "+contentType, http.StatusBadRequest, "invalid_request")
				}
			})

			t.Run("another media type is refused", func(t *testing.T) {
				for _, tt := range []struct{ name, contentType string }{
					{"JSON", jsonType},
					{"none", ""},
					{"text", "text/plain"},
					{"multipart", "multipart/form-data; boundary=x"},
					{"another charset", formType + "; charset=latin1"},
					{"another parameter", formType + "; boundary=x"},
					{"a prefix of the type", "application/x-www-form-urlencoded2"},
					{"the type as a parameter", "text/plain; type=" + formType},
				} {
					got := typed(tt.contentType, "token=x&resource=y")
					got.expectOAuth(t, tt.name, http.StatusUnsupportedMediaType, "invalid_request")

					if !strings.Contains(got.header.Get("Cache-Control"), "no-store") {
						t.Errorf("%s: Cache-Control = %q on an OAuth error", tt.name, got.header.Get("Cache-Control"))
					}
				}
			})

			t.Run("the body cap is exact", func(t *testing.T) {
				for _, size := range []int{route.cap - 1, route.cap} {
					got := typed(formType, strings.Repeat("&", size))
					got.expectOAuth(t, fmt.Sprintf("a form of %d bytes", size), http.StatusBadRequest, "invalid_request")
				}

				got := typed(formType, strings.Repeat("&", route.cap+1))
				got.expectOAuth(t, "a form one byte over its cap", http.StatusRequestEntityTooLarge, "invalid_request")

				// The media type is judged before the size (a 415, not a 413).
				typed(jsonType, strings.Repeat("&", route.cap+1)).
					expectOAuth(t, "JSON over the cap", http.StatusUnsupportedMediaType, "invalid_request")
			})

			t.Run("other methods", func(t *testing.T) {
				for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
					got := send(t, request{method: method, path: route.path, body: []byte("token=x"), headers: map[string]string{"Content-Type": formType}})
					got.expectOAuth(t, method+" "+route.path, http.StatusMethodNotAllowed, "invalid_request")

					if got.header.Get("Allow") != http.MethodPost {
						t.Errorf("%s %s: Allow = %q, want POST", method, route.path, got.header.Get("Allow"))
					}
				}
			})

			t.Run("a credential does not turn a form into a request of the user's", func(t *testing.T) {
				holder := newOAuthHolder(t)

				// A cookie or a key on a form route is ignored: the route has no
				// credential, so what the form says is all there is.
				got := send(t, request{
					method: http.MethodPost, path: route.path, token: holder.session, body: []byte(""),
					headers: map[string]string{"Content-Type": formType},
				})
				got.expectOAuth(t, "an empty form with a session cookie", http.StatusBadRequest, "invalid_request")
			})
		})
	}

	t.Run("the other direction: a form to a JSON route", func(t *testing.T) {
		holder := newOAuthHolder(t)

		for _, route := range []struct {
			method, path string
			token        string
		}{
			{http.MethodPost, pathOAuthConsent, holder.session},
			{http.MethodPost, pathOAuthConsent, ""},
			{http.MethodPost, pathAgent, holder.session},
			{http.MethodPost, pathLoginBegin, ""},
		} {
			got := send(t, request{
				method: route.method, path: route.path, token: route.token, body: []byte("request=x&approve=true"),
				headers: map[string]string{"Content-Type": formType},
			})
			got.expect(t, "a form to "+route.path, http.StatusUnsupportedMediaType, codeUnsupportedType)

			// The refusal is the API's own format, not RFC 6749's.
			if got.oauthError() != "" {
				t.Errorf("%s answered a wrong media type in the OAuth format: %s", route.path, got.body)
			}
		}
	})

	t.Run("a JSON body to the consent route is read", func(t *testing.T) {
		holder := newOAuthHolder(t)

		got := post(t, pathOAuthConsent, []byte(`{}`), holder.session)
		got.expect(t, "an empty JSON answer", http.StatusBadRequest, "invalid_consent")
	})
}

// TestOAuthTokenRequests: the token endpoint's reading of a form, one request per
// row against a fresh authorization code. A request refused for the form it sent
// (a repeated or malformed parameter) must leave the code unspent, and one that
// succeeds must spend it.
//
//nolint:paralleltest // shares one database
func TestOAuthTokenRequests(t *testing.T) {
	holder := newOAuthHolder(t)
	seedAgent(t, idAgentA, holder.userID, "form agent")

	// pair is the one pair name=value of a form, percent-encoded as a client does.
	pair := func(name, value string) string { return name + "=" + url.QueryEscape(value) }

	// form is the correct form for an approval, as a list of pairs in order.
	form := func(a approved) []string {
		return []string{
			pair("grant_type", "authorization_code"), pair("client_id", a.client.id), pair("code", a.code),
			pair("redirect_uri", a.client.redirect), pair("code_verifier", a.pkce.verifier),
		}
	}

	// without removes the pairs named name, and with replaces them.
	without := func(pairs []string, name string) []string {
		var out []string

		for _, p := range pairs {
			if !strings.HasPrefix(p, name+"=") {
				out = append(out, p)
			}
		}

		return out
	}

	with := func(pairs []string, name, value string) []string {
		return append(without(pairs, name), pair(name, value))
	}

	otherClient := newOAuthClient(t)
	wrongVerifier := newPKCE().verifier

	cases := []struct {
		name string
		// body builds the raw body from the correct pairs.
		body func(a approved, pairs []string) string
		// status and code are the answer; code "" is a success.
		status int
		code   string
		// spent is whether the code is spent after the request: only a success
		// spends it. A request that was refused for its form must not have.
		spent bool
		// unspent holds the code was not spent by a request refused for its form.
		unspent bool
	}{
		{name: "the correct form", status: 200, spent: true},
		{name: "reordered", body: func(_ approved, p []string) string { return strings.Join([]string{p[4], p[3], p[2], p[1], p[0]}, "&") }, status: 200, spent: true},
		{name: "a percent-encoded name", body: func(a approved, p []string) string {
			return strings.Join(append(without(p, "code"), "%63ode="+url.QueryEscape(a.code)), "&")
		}, status: 200, spent: true},
		{name: "unknown parameters, repeated, are ignored", body: func(_ approved, p []string) string {
			return strings.Join(append(p, "foo=1", "foo=2", "client_secret=x"), "&")
		}, status: 200, spent: true},
		{name: "empty pairs are skipped", body: func(_ approved, p []string) string { return "&&" + strings.Join(p, "&&") + "&" }, status: 200, spent: true},
		{name: "a resource that is the grant's", body: func(_ approved, p []string) string {
			return strings.Join(with(p, "resource", oauthResource), "&")
		}, status: 200, spent: true},

		{name: "a repeated code", body: func(a approved, p []string) string { return strings.Join(append(p, pair("code", a.code)), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "a repeated code spelled with an encoded name", body: func(a approved, p []string) string {
			return strings.Join(append(p, "%63ode="+url.QueryEscape(a.code)), "&")
		}, status: 400, code: "invalid_request", unspent: true},
		{name: "a repeated code, the first empty", body: func(_ approved, p []string) string { return "code=&" + strings.Join(p, "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "a repeated client_id", body: func(a approved, p []string) string {
			return strings.Join(append(p, pair("client_id", a.client.id)), "&")
		}, status: 400, code: "invalid_request", unspent: true},
		{name: "a repeated grant_type", body: func(_ approved, p []string) string {
			return strings.Join(append(p, pair("grant_type", "refresh_token")), "&")
		}, status: 400, code: "invalid_request", unspent: true},
		{name: "a repeated redirect_uri", body: func(a approved, p []string) string {
			return strings.Join(append(p, pair("redirect_uri", a.client.redirect)), "&")
		}, status: 400, code: "invalid_request", unspent: true},
		{name: "a repeated code_verifier", body: func(a approved, p []string) string {
			return strings.Join(append(p, pair("code_verifier", a.pkce.verifier)), "&")
		}, status: 400, code: "invalid_request", unspent: true},
		{name: "a repeated resource", body: func(_ approved, p []string) string {
			return strings.Join(append(p, pair("resource", oauthResource), pair("resource", oauthResource)), "&")
		}, status: 400, code: "invalid_request", unspent: true},
		{name: "an empty code is no code", body: func(_ approved, p []string) string { return strings.Join(with(p, "code", ""), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "a code with no equals sign", body: func(_ approved, p []string) string { return strings.Join(append(without(p, "code"), "code"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "a broken escape in an unknown parameter", body: func(_ approved, p []string) string { return strings.Join(append(p, "foo=%zz"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "a broken escape in an unknown name", body: func(_ approved, p []string) string { return strings.Join(append(p, "%zz=1"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "a truncated escape", body: func(_ approved, p []string) string { return strings.Join(p, "&") + "&foo=%4" }, status: 400, code: "invalid_request", unspent: true},
		{name: "a parameter with no name", body: func(_ approved, p []string) string { return strings.Join(append(p, "=x"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "a NUL in a value", body: func(_ approved, p []string) string { return strings.Join(with(p, "code_verifier", "a\x00b"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "invalid UTF-8 in a value", body: func(_ approved, p []string) string {
			return strings.Join(append(without(p, "client_id"), "client_id=%ff"), "&")
		}, status: 400, code: "invalid_request", unspent: true},
		{name: "a semicolon is not a separator", body: func(_ approved, p []string) string { return strings.Join(p, ";") }, status: 400, code: "unsupported_grant_type", unspent: true},
		{name: "a plus in a value is a space and so is not a code", body: func(a approved, p []string) string {
			return strings.Join(with(p, "code", strings.ReplaceAll(a.code, "_", "+")), "&")
		}, status: 400, code: "invalid_grant", unspent: true},
		{name: "no grant_type", body: func(_ approved, p []string) string { return strings.Join(without(p, "grant_type"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "no client_id", body: func(_ approved, p []string) string { return strings.Join(without(p, "client_id"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "no code", body: func(_ approved, p []string) string { return strings.Join(without(p, "code"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "no redirect_uri", body: func(_ approved, p []string) string { return strings.Join(without(p, "redirect_uri"), "&") }, status: 400, code: "invalid_request", unspent: true},
		{name: "no code_verifier", body: func(_ approved, p []string) string { return strings.Join(without(p, "code_verifier"), "&") }, status: 400, code: "invalid_request", unspent: true},

		{name: "an unsupported grant type", body: func(_ approved, p []string) string { return strings.Join(with(p, "grant_type", "password"), "&") }, status: 400, code: "unsupported_grant_type", unspent: true},
		{name: "a grant type in another case", body: func(_ approved, p []string) string {
			return strings.Join(with(p, "grant_type", "Authorization_Code"), "&")
		}, status: 400, code: "unsupported_grant_type", unspent: true},
		{name: "a grant type with a trailing space", body: func(_ approved, p []string) string {
			return strings.Join(with(p, "grant_type", "authorization_code "), "&")
		}, status: 400, code: "unsupported_grant_type", unspent: true},
		{name: "a client_id that does not parse", body: func(_ approved, p []string) string { return strings.Join(with(p, "client_id", "nope"), "&") }, status: 400, code: "invalid_client", unspent: true},
		{name: "a resource that is not in the table", body: func(_ approved, p []string) string {
			return strings.Join(with(p, "resource", "https://elsewhere.example/mcp"), "&")
		}, status: 400, code: "invalid_target", unspent: true},
		{name: "a refresh token as the code", body: func(_ approved, p []string) string {
			return strings.Join(with(p, "code", newToken(tagOAuthRefresh)), "&")
		}, status: 400, code: "invalid_grant", unspent: true},
		{name: "an access token as the code", body: func(_ approved, p []string) string {
			return strings.Join(with(p, "code", newToken(tagOAuthAccess)), "&")
		}, status: 400, code: "invalid_grant", unspent: true},
		{name: "a session token as the code", body: func(_ approved, p []string) string { return strings.Join(with(p, "code", newToken(tagSession)), "&") }, status: 400, code: "invalid_grant", unspent: true},
		{name: "a code that was never issued", body: func(_ approved, p []string) string { return strings.Join(with(p, "code", newToken(tagOAuthCode)), "&") }, status: 400, code: "invalid_grant", unspent: true},
		{name: "a code of 42 characters", body: func(a approved, p []string) string {
			return strings.Join(with(p, "code", a.code[:len(a.code)-1]), "&")
		}, status: 400, code: "invalid_grant", unspent: true},
		{name: "a verifier of 42 characters", body: func(a approved, p []string) string {
			return strings.Join(with(p, "code_verifier", a.pkce.verifier[:42]), "&")
		}, status: 400, code: "invalid_grant", unspent: true},
		{name: "a verifier of 129 characters", body: func(a approved, p []string) string {
			return strings.Join(with(p, "code_verifier", a.pkce.verifier+strings.Repeat("a", 129-len(a.pkce.verifier))), "&")
		}, status: 400, code: "invalid_grant", unspent: true},
		{name: "a verifier that does not match", body: func(_ approved, p []string) string { return strings.Join(with(p, "code_verifier", wrongVerifier), "&") }, status: 400, code: "invalid_grant"},
		{name: "the challenge as the verifier (plain)", body: func(a approved, p []string) string {
			return strings.Join(with(p, "code_verifier", a.pkce.challenge), "&")
		}, status: 400, code: "invalid_grant"},
		{name: "another redirect_uri", body: func(a approved, p []string) string {
			return strings.Join(with(p, "redirect_uri", strings.Replace(a.client.redirect, "127.0.0.1:", "127.0.0.1:1", 1)), "&")
		}, status: 400, code: "invalid_grant"},
		{name: "a redirect_uri with a query added", body: func(a approved, p []string) string {
			return strings.Join(with(p, "redirect_uri", a.client.redirect+"?x=1"), "&")
		}, status: 400, code: "invalid_grant"},
		{name: "another client's id", body: func(_ approved, p []string) string { return strings.Join(with(p, "client_id", otherClient.id), "&") }, status: 400, code: "invalid_grant"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client := newOAuthClient(t)
			a := approve(t, client, holder.session, agentChoiceID(idAgentA))

			body := strings.Join(form(a), "&")
			if tt.body != nil {
				body = tt.body(a, form(a))
			}

			got := postRaw(t, pathOAuthToken, body)

			if tt.code == "" {
				issued := mustTokens(t, got)
				expectToken(t, issued.AccessToken, tagOAuthAccess)
			} else {
				got.expectOAuth(t, tt.name, tt.status, tt.code)

				if strings.Contains(got.body, a.code) || strings.Contains(got.body, a.pkce.verifier) {
					t.Errorf("the error body repeats a secret of the request: %s", got.body)
				}
			}

			// The code, afterwards: spent by a success, and by nothing else that
			// was refused for the form it came in.
			retry := a.exchange(t)

			switch {
			case tt.spent:
				retry.expectOAuth(t, "the code after a success", http.StatusBadRequest, "invalid_grant")
			case tt.unspent:
				if retry.status != http.StatusOK {
					t.Errorf("the code after a refused form = %d %s, want it still good", retry.status, retry.body)
				}
			}

			if leaks := bndLeaks(got.body); len(leaks) != 0 {
				t.Errorf("the response matches leak patterns %v: %s", leaks, got.body)
			}
		})
	}
}

// TestOAuthRefreshScopeEncoding: "+" and "%20" in a refresh request's scope are
// both a space, and "%2B" is a plus, which no scope contains.
//
//nolint:paralleltest // shares one database
func TestOAuthRefreshScopeEncoding(t *testing.T) {
	holder := newOAuthHolder(t)
	client := newOAuthClient(t)
	a := approve(t, client, holder.session, newAgentChoice("refresh agent"))
	current := a.mustExchange(t).RefreshToken

	base := func() string {
		return "grant_type=refresh_token&client_id=" + url.QueryEscape(client.id) + "&refresh_token=" + url.QueryEscape(current)
	}

	var scopes []string

	for _, tt := range []struct {
		name  string
		scope string
		code  string
	}{
		{"plus", "mcp:read+mcp:write", ""},
		{"%20", "mcp:read%20mcp:write", ""},
		{"a literal plus", "mcp:read%2Bmcp:write", "invalid_scope"},
		{"an unknown scope", "mcp:delete", "invalid_scope"},
	} {
		got := postRaw(t, pathOAuthToken, base()+"&scope="+tt.scope)

		if tt.code != "" {
			got.expectOAuth(t, tt.name, http.StatusBadRequest, tt.code)

			continue
		}

		issued := mustTokens(t, got)
		scopes = append(scopes, issued.Scope)
		current = issued.RefreshToken
	}

	if len(scopes) != 2 || scopes[0] != scopes[1] {
		t.Errorf("the scopes of a refresh with plus and with %%20 = %q, want the same", scopes)
	}
}
