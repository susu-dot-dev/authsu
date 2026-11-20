//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// revokeForm is a revocation of token by the client.
func revokeForm(token, client string) url.Values {
	return url.Values{"token": {token}, "client_id": {client}}
}

// wantRevoked asserts the one answer to every well-formed revocation: 200, no body,
// not cached.
func wantRevoked(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != noStore ||
		rec.Header().Get("Content-Type") != "" {
		t.Errorf("= %d %q %q %q, want 200 with no body", rec.Code, rec.Body, rec.Header().Get("Content-Type"),
			rec.Header().Get("Cache-Control"))
	}
}

// refreshWorks reports whether the refresh token is still good, and so spends it.
func (r *rig) refreshWorks(token string) bool {
	r.t.Helper()

	return r.postForm(oauth.PathToken, refreshForm(token)).Code == http.StatusOK
}

// revocation is a revocation that is well formed, and its effect.
type revocation struct {
	token  func(tokenBody) string
	client string
	hint   string

	// wantOp is the store operation it comes to; wantAccess and wantRefreshes are
	// whether the access token is still live and the refresh token still works.
	wantOp        string
	wantAccess    bool
	wantRefreshes bool
}

// refreshOf and accessOf pick a token of a grant's tokens.
func refreshOf(b tokenBody) string { return b.refresh }
func accessOf(b tokenBody) string  { return b.access }

// revocations are the revocations that are well formed, with their effects.
func revocations() map[string]revocation {
	return map[string]revocation{
		"a refresh token": {token: refreshOf, client: clientURL, wantOp: opRevokeRT},
		"a refresh token with its hint": {
			token: refreshOf, client: clientURL, hint: "refresh_token", wantOp: opRevokeRT,
		},
		"a refresh token with the wrong hint": {
			token: refreshOf, client: clientURL, hint: "access_token", wantOp: opRevokeRT,
		},
		"a refresh token with a hint that is not a token type": {
			token: refreshOf, client: clientURL, hint: "id_token", wantOp: opRevokeRT,
		},
		"an access token": {
			token: accessOf, client: clientURL, wantOp: opRevokeAT, wantRefreshes: true,
		},
		"an access token with its hint": {
			token: accessOf, client: clientURL, hint: "access_token", wantOp: opRevokeAT, wantRefreshes: true,
		},
		"an access token with the wrong hint": {
			token: accessOf, client: clientURL, hint: "refresh_token", wantOp: opRevokeAT, wantRefreshes: true,
		},
		"a refresh token under another client": {
			token: refreshOf, client: otherClientURL, wantOp: opRevokeRT, wantAccess: true, wantRefreshes: true,
		},
		"an access token under another client": {
			token: accessOf, client: otherClientURL, wantOp: opRevokeAT, wantAccess: true, wantRefreshes: true,
		},
	}
}

// TestRevokeTokens: a client revokes a token it holds. A refresh token takes its
// grant and its access token with it; an access token revokes only itself, so the
// client can refresh. The store is given the token, the client and the instant. A
// token under another client's id revokes nothing, and the client is not told.
func TestRevokeTokens(t *testing.T) {
	t.Parallel()

	for name, tt := range revocations() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			tokens := r.exchanged(nil)
			r.now = r.now.Add(time.Minute)

			form := revokeForm(tt.token(tokens), tt.client)
			if tt.hint != "" {
				form.Set("token_type_hint", tt.hint)
			}

			wantRevoked(t, r.postForm(oauth.PathRevoke, form))

			if len(r.logged) != 0 {
				t.Errorf("logged %v", r.loggedCodes())
			}

			call := r.store.calls[len(r.store.calls)-1]
			wantClient, _ := input.ParseClientID(tt.client, productionTable())

			if call.op != tt.wantOp || call.token != tt.token(tokens) || call.client != wantClient || !call.now.Equal(r.now) {
				t.Errorf("store call = %+v, want %s of the token for %s at %v", call, tt.wantOp, tt.client, r.now)
			}

			if r.active(tokens.access) != tt.wantAccess || r.refreshWorks(tokens.refresh) != tt.wantRefreshes {
				t.Errorf("the access token is live: %t, the refresh token works: %t, want %t and %t",
					r.active(tokens.access), r.refreshWorks(tokens.refresh), tt.wantAccess, tt.wantRefreshes)
			}
		})
	}
}

// notOurs are tokens, and text, that are not a refresh or an access token.
func notOurs() map[string]string {
	refresh := tokenOf2(secret.TagOAuthRefresh)
	access := tokenOf2(secret.TagOAuthAccess)
	overhead := len("token=&client_id=") + len(url.QueryEscape(clientURL))
	room := oauth.MaxRevokeBody - overhead

	//nolint:gosec // none of these is a credential: they are generated, and nothing stores them
	return map[string]string{
		"a code":                       tokenOf2(secret.TagOAuthCode),
		"a session":                    tokenOf2(secret.TagSession),
		"an API key":                   tokenOf2(secret.TagAPIKey),
		"an invitation":                tokenOf2(secret.TagInvitation),
		"garbage":                      "x",
		"a token with no body":         "susu_rt_",
		"a refresh token cut short":    refresh[:len(refresh)-1],
		"an access token and a letter": access + "A",
		"an access token in capitals":  strings.ToUpper(access),
		"an access token and a space":  " " + access,
		"a JWT":                        "eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
		"as long as the body allows":   strings.Repeat("a", room),
	}
}

// TestRevokeIsTheSameForEveryTokenThatIsNotOurs: a token that is not a refresh or an
// access token (a code, a session, an API key, an invitation, anything that is not
// well-formed) is answered exactly as a revoked one is, and nothing is written: the
// endpoint is no oracle (RFC 7009 section 2.2).
func TestRevokeIsTheSameForEveryTokenThatIsNotOurs(t *testing.T) {
	t.Parallel()

	reference := newRig(t)
	known := reference.exchanged(nil)
	wantAnswer := reference.postForm(oauth.PathRevoke, revokeForm(known.refresh, clientURL))

	for name, token := range notOurs() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.postForm(oauth.PathRevoke, revokeForm(token, clientURL))

			wantRevoked(t, rec)

			if rec.Code != wantAnswer.Code || rec.Body.String() != wantAnswer.Body.String() {
				t.Errorf("answer = %d %q, differs from the answer for a token that was revoked", rec.Code, rec.Body)
			}

			if len(r.store.calls) != 0 {
				t.Errorf("store calls = %+v, want none for a token that is not ours", r.store.calls)
			}
		})
	}
}

// TestRevokeOfATokenNobodyHolds: a well-formed refresh or access token that nothing
// stores reaches the store, and is answered the same.
func TestRevokeOfATokenNobodyHolds(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	for _, tag := range []secret.Tag{secret.TagOAuthRefresh, secret.TagOAuthAccess} {
		wantRevoked(t, r.postForm(oauth.PathRevoke, revokeForm(tokenOf2(tag), clientURL)))
	}

	if len(r.store.calls) != 2 || r.store.calls[0].op != opRevokeRT || r.store.calls[1].op != opRevokeAT {
		t.Errorf("store calls = %+v, want a refresh and an access revocation", r.store.calls)
	}
}

// TestRevokeRefusesAMalformedRequest: a request that is not well formed is refused,
// and nothing is asked of the store.
func TestRevokeRefusesAMalformedRequest(t *testing.T) {
	t.Parallel()

	good := revokeForm(tokenOf2(secret.TagOAuthRefresh), clientURL)
	hintTwice := func(v url.Values) { v.Add("token_type_hint", "access_token"); v.Add("token_type_hint", "access_token") }

	tests := map[string]refusal{
		"no token":                  refuse(oauthRequest, drop("token")),
		"an empty token":            refuse(oauthRequest, setParam("token", "")),
		"no client_id":              refuse(oauthRequest, drop("client_id")),
		"an empty client_id":        refuse(oauthRequest, setParam("client_id", "")),
		"a client_id that is bad":   refuse(oauthClient, setParam("client_id", "client")),
		"a client_id on http":       refuse(oauthClient, setParam("client_id", "http://client.example.com/c")),
		"token twice":               refuse(oauthRequest, func(v url.Values) { v.Add("token", "x") }),
		"client_id twice":           refuse(oauthRequest, twice("client_id")),
		"the hint twice":            refuse(oauthRequest, hintTwice),
		"a broken percent-encoding": rawRefusal(oauthRequest, "token=%zz&client_id=x"),
		"an empty body":             rawRefusal(oauthRequest, ""),
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			body := withParams(good, tt.form).Encode()
			if tt.form == nil {
				body = tt.raw
			}

			wantOAuthError(t, r.postRaw(oauth.PathRevoke, body), http.StatusBadRequest, tt.code)

			if len(r.store.calls) != 0 {
				t.Errorf("store calls = %+v, want none", r.store.calls)
			}
		})
	}
}

// TestRevokeIsAFormEndpoint: the form is the one body, and it is bounded.
func TestRevokeIsAFormEndpoint(t *testing.T) {
	t.Parallel()

	wantFormEndpoint(t, oauth.PathRevoke, oauth.MaxRevokeBody)
}

// TestRevokeStoreFailures: the store's failure is the answer, classified and with
// fixed text. This is the one way a well-formed revocation is not a 200.
func TestRevokeStoreFailures(t *testing.T) {
	t.Parallel()

	for name, tt := range storeOutcomes(store.CodeOAuthRevokeFailed) {
		if tt.status == http.StatusBadRequest {
			continue
		}

		for _, tag := range []secret.Tag{secret.TagOAuthRefresh, secret.TagOAuthAccess} {
			t.Run(name+"/"+string(tag), func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				r.store.failure = tt.failure

				rec := r.postForm(oauth.PathRevoke, revokeForm(tokenOf2(tag), clientURL))

				wantOAuthError(t, rec, tt.status, tt.code)

				if strings.Contains(rec.Body.String(), "fire") {
					t.Errorf("body = %s, want no cause", rec.Body)
				}
			})
		}
	}

	t.Run("a deployment that is not configured", func(t *testing.T) {
		t.Parallel()

		env := fullEnv()
		delete(env, config.SecretHMAC)

		r := newRigWith(t, env)

		wantOAuthError(t, r.postForm(oauth.PathRevoke, revokeForm(tokenOf2(secret.TagOAuthRefresh), clientURL)),
			http.StatusServiceUnavailable, oauthUnavailble)
	})
}
