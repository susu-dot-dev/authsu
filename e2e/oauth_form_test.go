//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,maintidx,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_form_test.go: what only the real TinyGo build can show about how the OAuth
// endpoints read a request: the strict form and query parser (duplicates,
// "+" against "%20", broken encodings, unknown parameters), the media type and the
// size cap of every form route, the authorization endpoint's 302 (and only 302)
// with its two kinds of error redirect, and the other-media-type refusals in both
// directions.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// oaOutcome is what an authorization request came to.
type oaOutcome struct {
	// kind is "consent" (a 302 to the UI's consent page), "ui-error" (a 302 to
	// the UI's error page), "client-error" (a 302 to the client's redirect URI
	// with an error) or "other" (anything else).
	kind   string
	code   string
	params url.Values
}

// oaClassify reads a reply of the authorization endpoint.
func oaClassify(t *testing.T, c *oauthClient, got reply) oaOutcome {
	t.Helper()

	if got.status != http.StatusFound || got.body != "" {
		return oaOutcome{kind: "other", code: got.status2()}
	}

	location := got.locationURL(t)
	params := location.Query()
	base := *location
	base.RawQuery = ""

	switch {
	case strings.HasPrefix(got.location(), target.origin+"/oauth/consent?"):
		return oaOutcome{kind: "consent", params: params}
	case base.String() == target.origin+"/oauth/error":
		return oaOutcome{kind: "ui-error", code: params.Get("error"), params: params}
	case base.String() == c.redirect:
		return oaOutcome{kind: "client-error", code: params.Get("error"), params: params}
	default:
		return oaOutcome{kind: "other", code: got.location()}
	}
}

// status2 is a reply's status and body, for a failure message.
func (r reply) status2() string { return http.StatusText(r.status) + " " + r.body }

// TestOAuthAuthorizeOutcomes: every way an authorization request can be wrong, and
// where the browser is sent. Before the client's document has vouched for the
// redirect URI, never to the client: to the UI's error page with the code and
// nothing else, and without fetching anything when the request alone is wrong.
// After, to the client with error, a fixed description, the issuer and the state
// if it was usable.
//
//nolint:paralleltest // shares one database
func TestOAuthAuthorizeOutcomes(t *testing.T) {
	newAdmin(t)

	const (
		uiError     = "ui-error"
		clientError = "client-error"
		consentPage = "consent"
	)

	cases := []struct {
		name   string
		mutate func(c *oauthClient, q url.Values)
		kind   string
		code   string
		// fetched is whether the Worker fetched the client's document.
		fetched bool
		// state is whether the client's state comes back with an error.
		noState bool
	}{
		{name: "a valid request", kind: consentPage, fetched: true},
		{name: "no scope means the defaults", mutate: func(_ *oauthClient, q url.Values) { q.Del("scope") }, kind: consentPage, fetched: true},
		{name: "no state and no nonce", mutate: func(_ *oauthClient, q url.Values) { q.Del("state"); q.Del("nonce") }, kind: consentPage, fetched: true},
		{name: "unknown parameters are ignored, repeated or not", mutate: func(_ *oauthClient, q url.Values) {
			q.Add("foo", "1")
			q.Add("foo", "2")
			q.Set("prompt", "login")
		}, kind: consentPage, fetched: true},
		{name: "a loopback redirect URI on another port", mutate: func(_ *oauthClient, q url.Values) {
			q.Set("redirect_uri", "http://127.0.0.1:1/callback")
		}, kind: consentPage, fetched: true},

		// Before the redirect URI is trusted.
		{name: "no client_id", mutate: func(_ *oauthClient, q url.Values) { q.Del("client_id") }, kind: uiError, code: "invalid_request"},
		{name: "an empty client_id", mutate: func(_ *oauthClient, q url.Values) { q.Set("client_id", "") }, kind: uiError, code: "invalid_request"},
		{name: "two client_ids", mutate: func(c *oauthClient, q url.Values) { q.Add("client_id", c.id) }, kind: uiError, code: "invalid_request"},
		{name: "no redirect_uri", mutate: func(_ *oauthClient, q url.Values) { q.Del("redirect_uri") }, kind: uiError, code: "invalid_request"},
		{name: "two redirect_uris", mutate: func(c *oauthClient, q url.Values) { q.Add("redirect_uri", c.redirect) }, kind: uiError, code: "invalid_request"},
		{name: "a client_id that is not a URL", mutate: func(_ *oauthClient, q url.Values) { q.Set("client_id", "not a url") }, kind: uiError, code: "invalid_client"},
		{name: "a client_id with no path", mutate: func(c *oauthClient, q url.Values) {
			q.Set("client_id", strings.TrimSuffix(c.id, "/client.json"))
		}, kind: uiError, code: "invalid_client"},
		{name: "a client_id with a query", mutate: func(c *oauthClient, q url.Values) { q.Set("client_id", c.id+"?x=1") }, kind: uiError, code: "invalid_client"},
		{name: "a client_id with a fragment", mutate: func(c *oauthClient, q url.Values) { q.Set("client_id", c.id+"#x") }, kind: uiError, code: "invalid_client"},
		{name: "a client_id with userinfo", mutate: func(c *oauthClient, q url.Values) {
			q.Set("client_id", strings.Replace(c.id, "http://", "http://user@", 1))
		}, kind: uiError, code: "invalid_client"},
		{name: "a client_id with a dot segment", mutate: func(c *oauthClient, q url.Values) {
			q.Set("client_id", strings.Replace(c.id, "/client.json", "/a/../client.json", 1))
		}, kind: uiError, code: "invalid_client"},
		{name: "a client_id with an upper-case host", mutate: func(c *oauthClient, q url.Values) {
			q.Set("client_id", strings.Replace(c.id, "localhost", "LOCALHOST", 1))
		}, kind: uiError, code: "invalid_client"},
		{name: "a client_id on an IP address", mutate: func(c *oauthClient, q url.Values) {
			q.Set("client_id", strings.Replace(c.id, "localhost", "127.0.0.1", 1))
		}, kind: uiError, code: "invalid_client"},
		{name: "a client_id on a localhost lookalike", mutate: func(c *oauthClient, q url.Values) {
			q.Set("client_id", strings.Replace(c.id, "localhost", "localhost.evil.example", 1))
		}, kind: uiError, code: "invalid_client"},
		{name: "a client_id over https on localhost", mutate: func(c *oauthClient, q url.Values) {
			q.Set("client_id", strings.Replace(c.id, "http://", "https://", 1))
		}, kind: uiError, code: "invalid_client"},
		{name: "a client_id on a reserved name", mutate: func(_ *oauthClient, q url.Values) {
			q.Set("client_id", "https://client.example/client.json")
		}, kind: uiError, code: "invalid_client"},
		{name: "a client_id of 513 bytes", mutate: func(c *oauthClient, q url.Values) {
			q.Set("client_id", c.id+strings.Repeat("a", 513-len(c.id)))
		}, kind: uiError, code: "invalid_client"},
		{name: "a redirect_uri that is not a URL", mutate: func(_ *oauthClient, q url.Values) { q.Set("redirect_uri", "javascript:alert(1)") }, kind: uiError, code: "invalid_redirect_uri"},
		{name: "a custom-scheme redirect_uri", mutate: func(_ *oauthClient, q url.Values) { q.Set("redirect_uri", "myapp://callback") }, kind: uiError, code: "invalid_redirect_uri"},
		{name: "a redirect_uri on localhost when the document lists 127.0.0.1", mutate: func(c *oauthClient, q url.Values) {
			q.Set("redirect_uri", strings.Replace(c.redirect, "127.0.0.1", "localhost", 1))
		}, kind: uiError, code: "invalid_redirect_uri", fetched: true},
		{name: "a redirect_uri of 513 bytes", mutate: func(c *oauthClient, q url.Values) {
			q.Set("redirect_uri", c.redirect+strings.Repeat("a", 513-len(c.redirect)))
		}, kind: uiError, code: "invalid_redirect_uri"},
		{name: "a redirect_uri the document does not list", mutate: func(c *oauthClient, q url.Values) {
			q.Set("redirect_uri", c.redirect+"/other")
		}, kind: uiError, code: "invalid_redirect_uri", fetched: true},
		{name: "an https redirect_uri the document does not list", mutate: func(_ *oauthClient, q url.Values) {
			q.Set("redirect_uri", "https://evil.example/callback")
		}, kind: uiError, code: "invalid_redirect_uri", fetched: true},
		{name: "a redirect_uri with an added query", mutate: func(c *oauthClient, q url.Values) {
			q.Set("redirect_uri", c.redirect+"?x=1")
		}, kind: uiError, code: "invalid_redirect_uri", fetched: true},

		// After it: the client is told.
		{name: "no response_type", mutate: func(_ *oauthClient, q url.Values) { q.Del("response_type") }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "the implicit flow", mutate: func(_ *oauthClient, q url.Values) { q.Set("response_type", "token") }, kind: clientError, code: "unsupported_response_type", fetched: true},
		{name: "no code_challenge", mutate: func(_ *oauthClient, q url.Values) { q.Del("code_challenge") }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "a code_challenge of 42 characters", mutate: func(_ *oauthClient, q url.Values) {
			q.Set("code_challenge", q.Get("code_challenge")[:42])
		}, kind: clientError, code: "invalid_request", fetched: true},
		{name: "no code_challenge_method", mutate: func(_ *oauthClient, q url.Values) { q.Del("code_challenge_method") }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "the plain method", mutate: func(_ *oauthClient, q url.Values) { q.Set("code_challenge_method", "plain") }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "the method in lower case", mutate: func(_ *oauthClient, q url.Values) { q.Set("code_challenge_method", "s256") }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "a repeated code_challenge", mutate: func(_ *oauthClient, q url.Values) { q.Add("code_challenge", q.Get("code_challenge")) }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "a state with a control character", mutate: func(_ *oauthClient, q url.Values) { q.Set("state", "a\x01b") }, kind: clientError, code: "invalid_request", fetched: true, noState: true},
		{name: "a repeated state is not echoed", mutate: func(_ *oauthClient, q url.Values) { q.Add("state", "other") }, kind: clientError, code: "invalid_request", fetched: true, noState: true},
		{name: "a state of 257 bytes", mutate: func(_ *oauthClient, q url.Values) { q.Set("state", strings.Repeat("s", 257)) }, kind: clientError, code: "invalid_request", fetched: true, noState: true},
		{name: "a state of 256 bytes", mutate: func(_ *oauthClient, q url.Values) { q.Set("state", strings.Repeat("s", 256)) }, kind: consentPage, fetched: true},
		{name: "a non-ASCII nonce", mutate: func(_ *oauthClient, q url.Values) { q.Set("nonce", "n\u00e9") }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "a nonce of 129 bytes", mutate: func(_ *oauthClient, q url.Values) { q.Set("nonce", strings.Repeat("n", 129)) }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "a nonce of 128 bytes", mutate: func(_ *oauthClient, q url.Values) { q.Set("nonce", strings.Repeat("n", 128)) }, kind: consentPage, fetched: true},
		{name: "no resource", mutate: func(_ *oauthClient, q url.Values) { q.Del("resource") }, kind: clientError, code: "invalid_target", fetched: true},
		{name: "the production resource under the development table", mutate: func(_ *oauthClient, q url.Values) { q.Set("resource", "https://auth.susu.dev/mcp") }, kind: clientError, code: "invalid_target", fetched: true},
		{name: "a resource with a trailing slash", mutate: func(_ *oauthClient, q url.Values) { q.Set("resource", oauthResource+"/") }, kind: clientError, code: "invalid_target", fetched: true},
		{name: "two resources", mutate: func(_ *oauthClient, q url.Values) { q.Add("resource", oauthResource) }, kind: clientError, code: "invalid_request", fetched: true},
		{name: "only openid", mutate: func(_ *oauthClient, q url.Values) { q.Set("scope", "openid") }, kind: clientError, code: "invalid_scope", fetched: true},
		{name: "an unknown scope", mutate: func(_ *oauthClient, q url.Values) { q.Set("scope", "mcp:read mcp:delete") }, kind: clientError, code: "invalid_scope", fetched: true},
		{name: "a scope of another resource", mutate: func(_ *oauthClient, q url.Values) { q.Set("scope", "default:user") }, kind: clientError, code: "invalid_scope", fetched: true},
		{name: "a repeated scope name", mutate: func(_ *oauthClient, q url.Values) { q.Set("scope", strings.Repeat("mcp:read ", 2)) }, kind: clientError, code: "invalid_scope", fetched: true},
		{name: "scopes separated by a comma", mutate: func(_ *oauthClient, q url.Values) { q.Set("scope", "mcp:read,mcp:write") }, kind: clientError, code: "invalid_scope", fetched: true},
		{name: "scopes separated by two spaces", mutate: func(_ *oauthClient, q url.Values) { q.Set("scope", "mcp:read  mcp:write") }, kind: clientError, code: "invalid_scope", fetched: true},
		{name: "a scope list of 300 bytes", mutate: func(_ *oauthClient, q url.Values) {
			q.Set("scope", "mcp:read "+strings.Repeat("x", 291))
		}, kind: clientError, code: "invalid_scope", fetched: true},
		{name: "a repeated scope parameter", mutate: func(_ *oauthClient, q url.Values) { q.Add("scope", "mcp:read") }, kind: clientError, code: "invalid_request", fetched: true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client := newOAuthClient(t)
			query := client.authorizeQuery(newPKCE())

			if tt.mutate != nil {
				tt.mutate(client, query)
			}

			// An invalid state is not representable in a query that Go built, so
			// the control character is percent-encoded by Encode and arrives as is.
			got := authorize(t, query)
			outcome := oaClassify(t, client, got)

			if outcome.kind != tt.kind || outcome.code != tt.code {
				t.Fatalf("outcome = %s %q (%d %s), want %s %q", outcome.kind, outcome.code, got.status, got.location(), tt.kind, tt.code)
			}

			if fetched := client.hits.Load() != 0; fetched != tt.fetched {
				t.Errorf("fetched the client's document = %v, want %v", fetched, tt.fetched)
			}

			switch tt.kind {
			case uiError:
				// The error page is told the code and nothing the client sent.
				if len(outcome.params) != 1 {
					t.Errorf("UI error query = %v, want only the error code", outcome.params)
				}
			case clientError:
				if outcome.params.Get("iss") != target.apiOrigin || outcome.params.Get("error_description") == "" ||
					len(outcome.params.Get("error_description")) > 200 {
					t.Errorf("client error params = %v, want iss %s and a short fixed description", outcome.params, target.apiOrigin)
				}

				if tt.noState {
					if outcome.params.Has("state") {
						t.Errorf("an unusable state was echoed: %v", outcome.params)
					}
				} else if outcome.params.Get("state") != query.Get("state") {
					t.Errorf("state = %q, want %q", outcome.params.Get("state"), query.Get("state"))
				}

				if code := outcome.params.Get("code"); code != "" {
					t.Errorf("an error redirect carries a code: %v", outcome.params)
				}
			}

			if leaks := bndLeaks(got.location()); len(leaks) != 0 {
				t.Errorf("the redirect matches leak patterns %v: %s", leaks, got.location())
			}
		})
	}

	// Nothing an authorization request does writes anything.
	expectCount(t, tableOAuthGrants, "0")
	expectCount(t, "secrets WHERE kind IN ('oauth_grant', 'oauth_access')", "0")
}

// TestOAuthAuthorizeQueryEncoding: how the real TinyGo build reads the query
// string of the authorization endpoint. "+" and "%20" are both a space, and "%2B"
// is a plus; names are matched after decoding; a state with every kind of
// reserved character comes back exactly; a broken or hostile encoding is an
// invalid_request that is never redirected to the client's own page.
//
//nolint:paralleltest // shares one database
func TestOAuthAuthorizeQueryEncoding(t *testing.T) {
	holder := newOAuthHolder(t)

	const everyPrintable = ` !"#$%&'()*+,-./:;<=>?@[\]^_{|}~`

	cases := []struct {
		name string
		// raw builds the raw query string from the pieces that must stay valid.
		raw func(c *oauthClient, p pkce) string
		// kind and code: see oaClassify. scopes is what the consent page shows.
		kind   string
		code   string
		scopes string
		// state, when set, must come back exactly on an approval.
		state string
	}{
		{name: "plus is a space", raw: oaRaw("scope=mcp:read+mcp:write+openid"), kind: "consent", scopes: "mcp:read mcp:write openid"},
		{name: "%20 is a space", raw: oaRaw("scope=mcp:read%20mcp:write%20openid"), kind: "consent", scopes: "mcp:read mcp:write openid"},
		{name: "%2B is a plus, not a separator", raw: oaRaw("scope=mcp:read%2Bmcp:write"), kind: "client-error", code: "invalid_scope"},
		{name: "a percent-encoded name", raw: oaRaw("%73cope=mcp:read"), kind: "consent", scopes: "mcp:read"},
		{name: "a percent-encoded name that repeats a plain one", raw: oaRaw("scope=mcp:read&%73cope=mcp:write"), kind: "client-error", code: "invalid_request"},
		{name: "a semicolon is not a separator", raw: oaRaw("scope=mcp:read;resource=x"), kind: "client-error", code: "invalid_scope"},
		{name: "empty pairs are skipped", raw: oaRaw("&&scope=mcp:read&"), kind: "consent", scopes: "mcp:read"},
		{name: "an empty scope is no scope", raw: oaRaw("scope="), kind: "consent", scopes: "mcp:read mcp:write"},
		{name: "a scope with no equals sign is no scope", raw: oaRaw("scope"), kind: "consent", scopes: "mcp:read mcp:write"},
		{name: "a broken percent escape anywhere", raw: oaRaw("foo=%zz&scope=mcp:read"), kind: "ui-error", code: "invalid_request"},
		{name: "a truncated percent escape", raw: oaRaw("scope=mcp:read%2"), kind: "ui-error", code: "invalid_request"},
		{name: "a parameter with no name", raw: oaRaw("=x&scope=mcp:read"), kind: "ui-error", code: "invalid_request"},
		{name: "a NUL in a recognised value", raw: oaRaw("scope=mcp:read%00"), kind: "client-error", code: "invalid_request"},
		{name: "invalid UTF-8 in a recognised value", raw: oaRaw("nonce=%ff"), kind: "client-error", code: "invalid_request"},
		{name: "a state with every printable ASCII character", raw: oaRaw("state=" + url.QueryEscape(everyPrintable)), kind: "consent", scopes: "mcp:read mcp:write", state: everyPrintable},
		{name: "a state with every printable character, in an error redirect", raw: oaRaw("state=" + url.QueryEscape(everyPrintable) + "&response_type=token"), kind: "client-error", code: "invalid_request", state: everyPrintable},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client := newOAuthClient(t)
			p := newPKCE()
			raw := tt.raw(client, p)

			got := authorizeRaw(t, raw)
			outcome := oaClassify(t, client, got)

			if outcome.kind != tt.kind || outcome.code != tt.code {
				t.Fatalf("outcome = %s %q (%d %s), want %s %q", outcome.kind, outcome.code, got.status, got.location(), tt.kind, tt.code)
			}

			if tt.state != "" && outcome.kind == "client-error" && outcome.params.Get("state") != tt.state {
				t.Errorf("state came back as %q, want %q", outcome.params.Get("state"), tt.state)
			}

			if outcome.kind != "consent" {
				return
			}

			pending := outcome.params.Get("request")

			var shown struct {
				Scopes []string `json:"scopes"`
				OpenID bool     `json:"openid"`
			}

			view := get(t, pathOAuthRequest+"?request="+url.QueryEscape(pending), "")

			err := json.Unmarshal([]byte(view.body), &shown)
			if err != nil || view.status != http.StatusOK {
				t.Fatalf("the request view = %d %s: %v", view.status, view.body, err)
			}

			var wantScopes []string

			for name := range strings.FieldsSeq(tt.scopes) {
				if name != "openid" {
					wantScopes = append(wantScopes, name)
				}
			}

			if !slices.Equal(shown.Scopes, wantScopes) || shown.OpenID != strings.Contains(tt.scopes, "openid") {
				t.Errorf("the request view shows %v openid=%v, want scopes %q", shown.Scopes, shown.OpenID, tt.scopes)
			}

			if tt.state != "" {
				answer := consentRedirect(t, consent(t, holder.session, pending, true, newAgentChoice("state agent")))
				if answer.Query().Get("state") != tt.state {
					t.Errorf("approved state = %q, want %q", answer.Query().Get("state"), tt.state)
				}
			}
		})
	}

	t.Run("a query string over its cap is refused before anything is read", func(t *testing.T) {
		client := newOAuthClient(t)
		q := client.authorizeQuery(newPKCE())
		q.Set("foo", strings.Repeat("a", 9<<10))

		got := authorize(t, q)
		got.expectOAuth(t, "authorize with a 9 KiB query", http.StatusRequestEntityTooLarge, "invalid_request")

		if client.hits.Load() != 0 {
			t.Errorf("fetched the client's document for a request over its cap")
		}
	})
}

// oaRaw makes the raw query of an authorization request from the extra pairs,
// after the parameters that do not change. A scope or other parameter in extra
// replaces nothing: the case must not repeat what it sets by default, so the
// default scope is left out whenever the pairs name one.
func oaRaw(extra string) func(c *oauthClient, p pkce) string {
	return func(c *oauthClient, p pkce) string {
		base := "response_type=code&client_id=" + url.QueryEscape(c.id) + "&redirect_uri=" + url.QueryEscape(c.redirect) +
			"&code_challenge=" + p.challenge + "&code_challenge_method=S256&resource=" + url.QueryEscape(oauthResource)

		return base + "&" + extra
	}
}

// authorizeRaw sends the authorization request with the query string as it is.
func authorizeRaw(t *testing.T, raw string) reply {
	t.Helper()

	return send(t, request{path: pathOAuthAuthorize + "?" + raw, keepRedirect: true})
}
