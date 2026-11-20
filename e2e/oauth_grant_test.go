//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_grant_test.go: what a grant carries and how it can change: the scope a
// refresh may narrow it to (never widen), the ID token that exists only when asked
// for and carries a nonce only when one was sent, and a grant the user revokes
// before the client has exchanged its code.

import (
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestOAuthRefreshScope: a refresh asks for the grant's scope or for less, and is
// answered with the scope the access token carries, which introspection reports.
// Asking for more, for another resource's scope or for nothing a resource has is
// invalid_scope and rotates nothing: the same refresh token works afterwards.
//
//nolint:paralleltest // shares one database
func TestOAuthRefreshScope(t *testing.T) {
	holder := newOAuthHolder(t)
	client := newOAuthClient(t)

	a := approve(t, client, holder.session, newAgentChoice("scoped"))
	current := a.mustExchange(t)

	refresh := func(scope string, extra url.Values) reply {
		form := a.refreshForm(current.RefreshToken)
		if scope != "" {
			form.Set("scope", scope)
		}

		maps.Copy(form, extra)

		return postForm(t, pathOAuthToken, form)
	}

	// Each refusal is made first, against the current token, and then the token is
	// shown to be as good as before.
	for _, tt := range []struct{ name, scope string }{
		{"a scope of another resource", "default:user"},
		{"an unknown scope", "mcp:delete"},
		{"only openid", "openid"},
		{"a repeated scope", strings.Repeat("mcp:read ", 2)},
		{"a scope that is a lookalike", "mcp:read2"},
	} {
		refresh(tt.scope, nil).expectOAuth(t, tt.name, http.StatusBadRequest, "invalid_scope")
	}

	refresh("", url.Values{paramResource: {"https://elsewhere.example/mcp"}}).
		expectOAuth(t, "a resource that is not the grant's", http.StatusBadRequest, "invalid_target")

	// Nothing above rotated the token.
	if got := mustTokens(t, refresh("", nil)); got.Scope != oauthScopes {
		t.Errorf("a refresh with no scope = %q, want the grant's %q", got.Scope, oauthScopes)
	} else {
		current = got
	}

	// Narrowing: the response and the introspection say so.
	narrow := mustTokens(t, refresh("mcp:read", nil))
	if narrow.Scope != "mcp:read" {
		t.Errorf("a refresh for mcp:read answered with scope %q", narrow.Scope)
	}

	if got, _ := introspect(t, narrow.AccessToken, oauthResource); !got.Active || got.Scope != "mcp:read" {
		t.Errorf("the narrowed access token introspects as %+v, want active with mcp:read", got)
	}

	expectInactive(t, "the access token that was replaced by the narrower one", current.AccessToken, oauthResource)

	current = narrow

	// A narrowed access token does not narrow the grant: the next refresh may ask
	// for everything the grant holds again, and "+" and "%20" are both a space.
	wide := postRaw(t, pathOAuthToken,
		"grant_type=refresh_token&client_id="+url.QueryEscape(client.id)+"&refresh_token="+url.QueryEscape(current.RefreshToken)+
			"&scope=mcp:write+mcp:read&resource="+url.QueryEscape(oauthResource))
	widened := mustTokens(t, wide)

	if got, _ := introspect(t, widened.AccessToken, oauthResource); !got.Active || strings.Fields(got.Scope)[0] != "mcp:write" || len(strings.Fields(got.Scope)) != 2 {
		t.Errorf("a refresh for both scopes introspects as %+v", got)
	}

	// A grant that holds one scope cannot be refreshed into two.
	only := approveWith(t, newOAuthClient(t), holder.session, newAgentChoice("read only"),
		func(q url.Values) { q.Set("scope", "mcp:read") })
	first := only.mustExchange(t)

	if first.Scope != "mcp:read" || first.IDToken != "" {
		t.Errorf("the exchange of an mcp:read grant = scope %q, id_token %q", first.Scope, first.IDToken)
	}

	form := only.refreshForm(first.RefreshToken)
	form.Set("scope", "mcp:read mcp:write")
	postForm(t, pathOAuthToken, form).expectOAuth(t, "a refresh for more than the grant holds", http.StatusBadRequest, "invalid_scope")

	form.Set("scope", "mcp:write")
	postForm(t, pathOAuthToken, form).expectOAuth(t, "a refresh for a scope the grant lacks", http.StatusBadRequest, "invalid_scope")

	form.Set("scope", "mcp:read openid")
	if got := postForm(t, pathOAuthToken, form); got.status == http.StatusOK && !strings.Contains(got.body, `"scope":"mcp:read`) {
		t.Errorf("a refresh naming openid on a grant without it = %d %s", got.status, got.body)
	}

	// The refusals rotated nothing: the original refresh token still works.
	again := only.refreshForm(first.RefreshToken)
	if got := postForm(t, pathOAuthToken, again); got.status != http.StatusOK && got.oauthError() != "invalid_grant" {
		t.Errorf("a refresh after refusals = %d %s", got.status, got.body)
	}
}

// TestOAuthIDTokenVariants: the ID token exists only when openid was asked for, and
// has exactly the claims that were earned: a nonce claim only if a nonce was sent.
// This is the TinyGo encoding of an optional claim and of an absent member.
//
//nolint:paralleltest // shares one database
func TestOAuthIDTokenVariants(t *testing.T) {
	holder := newOAuthHolder(t)
	pub, kid := oaPublicKey(t)

	for _, tt := range []struct {
		name   string
		mutate func(url.Values)
		scope  string
		// idToken is whether an ID token is issued, and claims how many it has.
		idToken bool
		claims  int
	}{
		{"openid and a nonce", nil, oauthScopes, true, 7},
		{"openid and no nonce", func(q url.Values) { q.Del(paramNonce) }, oauthScopes, true, 6},
		{"a nonce and no openid", func(q url.Values) { q.Set("scope", "mcp:read mcp:write") }, "mcp:read mcp:write", false, 0},
		{"no scope at all", func(q url.Values) { q.Del("scope") }, "mcp:read mcp:write", false, 0},
		{"only one scope and openid", func(q url.Values) { q.Set("scope", "openid mcp:write") }, "openid mcp:write", true, 7},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := approveWith(t, newOAuthClient(t), holder.session, newAgentChoice("id token"), tt.mutate)
			got := a.mustExchange(t)

			if got.Scope != tt.scope {
				t.Errorf("scope = %q, want %q", got.Scope, tt.scope)
			}

			if !tt.idToken {
				if got.IDToken != "" || strings.Contains(a.exchange(t).body, "id_token") {
					t.Errorf("an ID token was issued without openid: %q", got.IDToken)
				}

				return
			}

			claims := oaVerifyJWT(t, got.IDToken, pub, kid)
			if len(claims) != tt.claims {
				t.Errorf("claims = %v, want %d", claims, tt.claims)
			}

			_, hasNonce := claims["nonce"]
			if want := a.query.Get(paramNonce) != ""; hasNonce != want {
				t.Errorf("nonce claim present = %v, want %v", hasNonce, want)
			}

			// The refresh never issues one.
			if refreshed := mustTokens(t, a.refresh(t, got.RefreshToken)); refreshed.IDToken != "" {
				t.Errorf("a refresh issued an ID token")
			}
		})
	}
}

// TestOAuthGrantBeforeExchange: a grant the user revokes before its code is
// exchanged is listed, revoked, and never yields a token.
//
//nolint:paralleltest // shares one database
func TestOAuthGrantBeforeExchange(t *testing.T) {
	holder := newOAuthHolder(t)
	a := approve(t, newOAuthClient(t), holder.session, newAgentChoice("unexchanged"))
	grant := idOfToken(t, a.code)

	list := get(t, pathGrant, holder.session)
	if list.status != http.StatusOK || !strings.Contains(list.body, grant) {
		t.Fatalf("the grant of an unexchanged code is not listed: %d %s", list.status, list.body)
	}

	del(t, pathGrant+"/"+grant, holder.session).expect(t, "revoking an unexchanged grant", http.StatusOK, "")
	a.exchange(t).expectOAuth(t, "the code of a revoked grant", http.StatusBadRequest, "invalid_grant")
	expectCount(t, "secrets WHERE kind = ?", "0", kindOAuthAccess)
}
