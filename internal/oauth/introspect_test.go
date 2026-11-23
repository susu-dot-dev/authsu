//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// inactiveBody is the one answer for everything that is not a live access token
// for the resource.
const inactiveBody = `{"active":false}` + "\n"

// introspectForm asks about token at resource.
func introspectForm(token, target string) url.Values {
	return url.Values{"token": {token}, "resource": {target}}
}

// liveRig is a rig with one live grant, approved for openid and one scope, whose
// code was exchanged 30 seconds after consent, at the instant it returns, and
// whose clock is 5 minutes on.
func liveRig(t *testing.T) (*rig, tokenBody, time.Time) {
	t.Helper()

	r := newRig(t)
	code := r.approve(setParam("scope", "openid mcp:read"))

	r.now = r.now.Add(30 * time.Second)
	issuedAt := r.now
	tokens := wantTokens(t, r.postForm(oauth.PathToken, codeForm(code)))
	r.now = r.now.Add(5 * time.Minute)

	return r, tokens, issuedAt
}

// TestIntrospectActive: a live access token is described exactly: who it speaks
// for (the user, and the agent that holds the grant), what it may do (the grant's
// scopes, the only limit), for whom it was issued and for what resource, and when
// it was issued and stops. The numbers are integers within 2^53-1. The store is
// asked with the token, the resource the caller named and the instant.
func TestIntrospectActive(t *testing.T) {
	t.Parallel()

	r, tokens, issuedAt := liveRig(t)

	rec := r.postForm(oauth.PathIntrospect, introspectForm(tokens.access, resourceURL))
	wantNotCachedJSON(t, rec, http.StatusOK)

	got := decodeNumbers(t, rec.Body.Bytes())

	if !all(len(got) == 10, got["active"] == true, got["scope"] == "openid mcp:read", got["client_id"] == clientURL,
		got["token_type"] == "Bearer", got["sub"] == userA, got["agent_id"] == newAgentID,
		got["aud"] == resourceURL, got["iss"] == apiOrigin) {
		t.Errorf("answer = %v, want the 10 members of a live token", got)
	}

	if wantInteger(t, "iat", got["iat"]) != issuedAt.Unix() ||
		wantInteger(t, "exp", got["exp"]) != issuedAt.Add(15*time.Minute).Unix() {
		t.Errorf("iat %v, exp %v, want %d and 15 minutes later", got["iat"], got["exp"], issuedAt.Unix())
	}

	call := r.store.calls[len(r.store.calls)-1]
	if !all(call.op == opIntrospect, call.token == tokens.access, call.resource.String() == resourceURL,
		call.now.Equal(r.now), len(r.logged) == 0) {
		t.Errorf("store call = %+v, logged %v, want the token, the resource and %v", call, r.loggedCodes(), r.now)
	}
}

// TestIntrospectAfterARefresh: a refresh replaces the access token and its issue
// time, and the replaced token is inactive.
func TestIntrospectAfterARefresh(t *testing.T) {
	t.Parallel()

	r, tokens, _ := liveRig(t)
	r.now = r.now.Add(time.Minute)

	next := wantTokens(t, r.postForm(oauth.PathToken, refreshForm(tokens.refresh)))
	got := decodeNumbers(t, r.postForm(oauth.PathIntrospect, introspectForm(next.access, resourceURL)).Body.Bytes())

	if got["active"] != true || wantInteger(t, "iat", got["iat"]) != r.now.Unix() ||
		wantInteger(t, "exp", got["exp"]) != r.now.Add(15*time.Minute).Unix() {
		t.Errorf("answer = %v, want a token issued at %d", got, r.now.Unix())
	}

	if r.active(tokens.access) {
		t.Error("the replaced access token is still live")
	}
}

// inactive is a question that is answered {"active":false}.
type inactive struct {
	token    func(tokenBody) string
	resource string

	// undo changes the world after the token was issued, and grantFor gives the
	// grant another resource (of the development table).
	undo     func(*rig)
	grantFor string

	// wantAsked is whether the store is asked: it is when the token parses as an
	// access token and the resource is the table's.
	wantAsked bool
}

// literal is a token that is not the grant's.
func literal(token string) func(tokenBody) string { return func(tokenBody) string { return token } }

// inactives are the questions that are answered inactive: every way a token can
// fail to be a live access token for the resource.
func inactives() map[string]inactive {
	devURL := resource.DevelopmentURL
	own := func(token func(tokenBody) string) inactive { return inactive{token: token, resource: resourceURL} }
	nobodys := tokenOf2(secret.TagOAuthAccess)

	asked := func(edit func(*inactive)) inactive {
		tc := own(accessOf)
		tc.wantAsked = true
		edit(&tc)

		return tc
	}
	askedAbout := func(target string) inactive {
		tc := own(accessOf)
		tc.resource = target

		return tc
	}
	of := func(token string) inactive { return own(literal(token)) }

	return map[string]inactive{
		"the refresh token":                   own(refreshOf),
		"a code":                              of(tokenOf2(secret.TagOAuthCode)),
		"a session token":                     of(tokenOf2(secret.TagSession)),
		"an API key":                          of(tokenOf2(secret.TagAPIKey)),
		"an invitation":                       of(tokenOf2(secret.TagInvitation)),
		"garbage":                             of("x"),
		"an access token in capitals":         own(func(b tokenBody) string { return strings.ToUpper(b.access) }),
		"an access token and a space":         own(func(b tokenBody) string { return b.access + " " }),
		"a resource of the development table": askedAbout(devURL),
		"a resource that is unknown":          askedAbout("https://other.example.com/mcp"),
		"the resource with a trailing slash":  askedAbout(resourceURL + "/"),
		"the resource in capitals":            askedAbout(strings.ToUpper(resourceURL)),
		"the resource with its port written":  askedAbout("https://auth.susu.dev:443/mcp"),
		"a resource with a space":             askedAbout(resourceURL + " "),
		"an access token nobody holds":        asked(func(c *inactive) { c.token = literal(nobodys) }),
		"a token revoked by its client": asked(func(c *inactive) {
			c.undo = func(r *rig) { r.store.rows[0].accessRevoked = true }
		}),
		"a token of a grant that was revoked": asked(func(c *inactive) {
			c.undo = func(r *rig) { now := r.now; r.store.rows[0].revokedAt = &now }
		}),
		"a token of an account that was revoked": asked(func(c *inactive) {
			c.undo = func(r *rig) { r.store.inactiveUsers[userA] = true }
		}),
		"a token of an agent that was revoked": asked(func(c *inactive) {
			c.undo = func(r *rig) { r.store.revokedAgents[newAgentID] = true }
		}),
		"a token at the instant it expires": asked(func(c *inactive) {
			c.undo = func(r *rig) { r.now = r.now.Add(auth.AccessTokenLifetime) }
		}),
		"a token for another resource": asked(func(c *inactive) { c.grantFor = devURL }),
	}
}

// TestIntrospectIsInactiveForEverythingElse: a token that is not a live access
// token for the resource is {"active":false}, and every way of not being one is
// the same answer: no error, no hint. A token that cannot be an access token
// never reaches the store.
func TestIntrospectIsInactiveForEverythingElse(t *testing.T) {
	t.Parallel()

	for name, tt := range inactives() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			tokens := r.exchanged(nil)

			tt.arrange(t, r)

			before := len(r.store.calls)
			rec := r.postForm(oauth.PathIntrospect, introspectForm(tt.token(tokens), tt.resource))

			if !all(rec.Code == http.StatusOK, rec.Body.String() == inactiveBody,
				rec.Header().Get("Content-Type") == jsonType) {
				t.Errorf("= %d %q, want 200 %q", rec.Code, rec.Body, inactiveBody)
			}

			if asked := len(r.store.calls) - before; (asked == 1) != tt.wantAsked || asked > 1 {
				t.Errorf("store was asked %d times, want it asked: %t", asked, tt.wantAsked)
			}

			if len(r.logged) != 0 {
				t.Errorf("logged %v: inactive is an answer, not a failure", r.loggedCodes())
			}
		})
	}
}

// arrange changes the world after the token was issued: the case's undo, and the
// grant's resource if it names one.
func (c inactive) arrange(t *testing.T, r *rig) {
	t.Helper()

	if c.grantFor != "" {
		target, err := input.ParseResourceID(c.grantFor, resource.Select("http://localhost:8787"))
		if err != nil {
			t.Fatal(err)
		}

		r.store.rows[0].grant.Resource = target
	}

	if c.undo != nil {
		c.undo(r)
	}
}

// TestIntrospectAsAThenB: a token for resource A, asked about as B, is inactive, and
// as A is live: the development table's resource is not one of this deployment's.
func TestIntrospectAsAThenB(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	tokens := r.exchanged(nil)

	rec := r.postForm(oauth.PathIntrospect, introspectForm(tokens.access, resource.DevelopmentURL))
	if rec.Body.String() != inactiveBody {
		t.Errorf("as B: %q, want %q", rec.Body, inactiveBody)
	}

	if !r.active(tokens.access) {
		t.Error("as A: the token is not live")
	}
}

// TestIntrospectRefusesAMalformedRequest: a caller that does not say which token
// and which resource has not asked a question. The store is not asked.
func TestIntrospectRefusesAMalformedRequest(t *testing.T) {
	t.Parallel()

	good := introspectForm(tokenOf2(secret.TagOAuthAccess), resourceURL)

	tests := map[string]refusal{
		"no token":          refuse(oauthRequest, drop("token")),
		"an empty token":    refuse(oauthRequest, setParam("token", "")),
		"no resource":       refuse(oauthRequest, drop("resource")),
		"an empty resource": refuse(oauthRequest, setParam("resource", "")),
		"token twice":       refuse(oauthRequest, twice("token")),
		"resource twice":    refuse(oauthRequest, twice("resource")),
		"a broken encoding": rawRefusal(oauthRequest, "token=%zz&resource=x"),
		"an empty body":     rawRefusal(oauthRequest, ""),
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			body := withParams(good, tt.form).Encode()
			if tt.form == nil {
				body = tt.raw
			}

			wantOAuthError(t, r.postRaw(oauth.PathIntrospect, body), http.StatusBadRequest, tt.code)

			if len(r.store.calls) != 0 {
				t.Errorf("store calls = %+v, want none", r.store.calls)
			}
		})
	}
}

// TestIntrospectNeedsNoCredentialAndReadsNone: the endpoint asks nothing of its
// caller, and a credential it is sent changes nothing: a session, an API key and
// an Authorization header that is garbage are all answered as no credential is.
//
//nolint:tparallel // the rows share one rig, whose fake store appends to its call record unguarded
func TestIntrospectNeedsNoCredentialAndReadsNone(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	tokens := r.exchanged(nil)
	body := introspectForm(tokens.access, resourceURL).Encode()

	reference := r.postRaw(oauth.PathIntrospect, body)
	if !strings.Contains(reference.Body.String(), `"active":true`) {
		t.Fatalf("= %d %q, want a live token", reference.Code, reference.Body)
	}

	//nolint:gosec // a request cookie carries no attributes
	garbage := &http.Cookie{Name: auth.CookieName, Value: "x"}

	//nolint:paralleltest // the rows share one rig, whose fake store appends to its call record unguarded
	for name, req := range map[string]request{
		"a session of another user":      {cookies: []*http.Cookie{r.cookieFor(userB)}},
		"an API key":                     {authorization: r.signInKey(userB, "")},
		"a garbage bearer":               {authorization: "Bearer nonsense"},
		"the token itself as the bearer": {authorization: "Bearer " + tokens.access},
		"a garbage cookie":               {cookies: []*http.Cookie{garbage}},
	} {
		req.method, req.target, req.body, req.contentType = http.MethodPost, oauth.PathIntrospect, body, formType

		// Serial: the rows share one rig and so one store.
		t.Run(name, func(t *testing.T) {
			rec := r.serve(req)

			if rec.Code != reference.Code || rec.Body.String() != reference.Body.String() {
				t.Errorf("= %d %q, want what no credential gets: %q", rec.Code, rec.Body, reference.Body)
			}
		})
	}
}

// TestIntrospectIsAFormEndpoint: the form is the one body, and it is bounded.
func TestIntrospectIsAFormEndpoint(t *testing.T) {
	t.Parallel()

	wantFormEndpoint(t, oauth.PathIntrospect, oauth.MaxIntrospectBody)
}

// TestIntrospectFailures: a store that cannot answer is not "inactive": a
// resource server must tell the two apart, so it is the store's classified
// failure, with fixed text.
func TestIntrospectFailures(t *testing.T) {
	t.Parallel()

	for name, tt := range storeOutcomes(store.CodeOAuthIntrospectFailed) {
		if tt.status == http.StatusBadRequest {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			r.store.failure = tt.failure

			rec := r.postForm(oauth.PathIntrospect, introspectForm(tokenOf2(secret.TagOAuthAccess), resourceURL))

			wantOAuthError(t, rec, tt.status, tt.code)

			if strings.Contains(rec.Body.String(), "fire") {
				t.Errorf("body = %s, want no cause", rec.Body)
			}
		})
	}

	t.Run("a deployment that is not configured", func(t *testing.T) {
		t.Parallel()

		env := fullEnv()
		delete(env, config.SecretHMAC)

		r := newRigWith(t, env)

		wantOAuthError(t, r.postForm(oauth.PathIntrospect, introspectForm(tokenOf2(secret.TagOAuthAccess), resourceURL)),
			http.StatusServiceUnavailable, oauthUnavailble)
	})
}

// TestIntrospectInTheDevelopmentDeployment: the audience is the development
// table's resource, and the production one is not a resource there.
func TestIntrospectInTheDevelopmentDeployment(t *testing.T) {
	t.Parallel()

	r := newRigWith(t, devEnv())
	r.net.answers[clientURL] = served(document(clientURL, redirectURL))

	tokens := r.exchanged(setParam("resource", resource.DevelopmentURL))

	rec := r.postForm(oauth.PathIntrospect, introspectForm(tokens.access, resource.DevelopmentURL))
	answer := decodeNumbers(t, rec.Body.Bytes())

	if answer["active"] != true || answer["aud"] != resource.DevelopmentURL || answer["iss"] != "http://localhost:8787" {
		t.Errorf("answer = %v, want a live token for the development resource", answer)
	}

	rec = r.postForm(oauth.PathIntrospect, introspectForm(tokens.access, resourceURL))
	if rec.Body.String() != inactiveBody {
		t.Errorf("as the production resource: %q, want %q", rec.Body, inactiveBody)
	}
}
