package oauth_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/oauth"
)

// publishedKey is the public key the key set publishes, read as a relying party
// reads it: from /.well-known/jwks.json, n and e decoded, nothing else trusted.
func publishedKey(t *testing.T, r *rig) (*rsa.PublicKey, string) {
	t.Helper()

	keys := keySetOf(t, r.get(oauth.PathJWKS))
	if len(keys) != 1 {
		t.Fatalf("the key set has %d keys, want 1", len(keys))
	}

	modulus, err := b64decode(keys[0]["n"])
	if err != nil {
		t.Fatal(err)
	}

	exponent, err := b64decode(keys[0]["e"])
	if err != nil {
		t.Fatal(err)
	}

	exp := int(new(big.Int).SetBytes(exponent).Int64())

	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exp}, keys[0]["kid"]
}

// flow is a client's walk through the endpoints, over one rig.
type flow struct {
	t      *testing.T
	r      *rig
	cookie *http.Cookie
}

// begin sends the client to the UI, reads the request as the UI does, and has the
// user approve it, creating an agent. It returns the code.
func (f *flow) begin() string {
	f.t.Helper()

	params := authorizeParams()
	params.Set("scope", "openid mcp:read mcp:write")
	params.Set("nonce", "flow-nonce")

	text := wantConsentRedirect(f.t, f.r, f.r.authorize(params))

	view := decodeObject(f.t, f.r.get(requestTarget(text)))
	if view["clientName"] != clientName || view["resource"] != resourceURL || view["openid"] != true {
		f.t.Fatalf("request view = %v", view)
	}

	f.r.now = f.r.now.Add(20 * time.Second)

	return redirectOf(f.t, f.r.consent(f.cookie, approval(f.t, text, "Flow Agent")), redirectURL).Get("code")
}

// exchange exchanges the code and checks the ID token against the key the key set
// publishes.
func (f *flow) exchange(code string) tokenBody {
	f.t.Helper()

	f.r.now = f.r.now.Add(5 * time.Second)
	tokens := wantTokens(f.t, f.r.postForm(oauth.PathToken, codeForm(code)))

	public, kid := publishedKey(f.t, f.r)
	parts := strings.Split(tokens.idToken, ".")
	signature, _ := b64decode(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature)
	if err != nil {
		f.t.Fatalf("the ID token does not verify against the published key: %v", err)
	}

	claims := verifiedIDToken(f.t, tokens.idToken)
	if _, wantKid := signingPublic(f.t); wantKid != kid || claims["nonce"] != "flow-nonce" || claims["sub"] != userA ||
		wantInteger(f.t, "auth_time", claims["auth_time"]) != f.r.now.Add(-25*time.Second).Unix() {
		f.t.Errorf("claims = %v, kid %q", claims, kid)
	}

	return tokens
}

// introspects is what a resource server is told of the token.
func (f *flow) introspects(token string) map[string]any {
	f.t.Helper()

	return decodeNumbers(f.t, f.r.postForm(oauth.PathIntrospect, introspectForm(token, resourceURL)).Body.Bytes())
}

// TestTheWholeFlow: a client takes the flow from end to end through the real
// boundary and routes, over a store that models the writes: it is sent to the UI,
// the UI reads the request and the user approves, the code is exchanged for tokens
// and an ID token that verifies against the published key, a resource server asks
// what the access token is, the client refreshes and the replaced tokens stop, the
// access token is revoked and refreshed into another, and the user revokes the grant
// from their list, after which nothing of it works and every endpoint still answers
// as it should.
func TestTheWholeFlow(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)
	f := &flow{t: t, r: r, cookie: cookie}

	code := f.begin()
	tokens := f.exchange(code)

	asked := f.introspects(tokens.access)
	if asked["active"] != true || asked["sub"] != userA || asked["scope"] != "openid mcp:read mcp:write" ||
		asked["aud"] != resourceURL {
		t.Fatalf("introspection = %v", asked)
	}

	last := f.refreshAndRevoke(tokens)

	f.userRevokes(last)

	wantRevoked(t, r.postForm(oauth.PathRevoke, revokeForm(last.refresh, clientURL)))
	wantOAuthError(t, r.postForm(oauth.PathToken, codeForm(code)), http.StatusBadRequest, oauthGrant)
}

// refreshAndRevoke refreshes the client's tokens, which stops the old ones, then
// revokes the new access token and is refreshed into another.
func (f *flow) refreshAndRevoke(tokens tokenBody) tokenBody {
	f.t.Helper()

	f.r.now = f.r.now.Add(10 * time.Minute)
	next := wantTokens(f.t, f.r.postForm(oauth.PathToken, refreshForm(tokens.refresh)))

	if f.r.active(tokens.access) || !f.r.active(next.access) || next.idToken != "" {
		f.t.Fatalf("after a refresh: old access live %t, new live %t, ID token %q",
			f.r.active(tokens.access), f.r.active(next.access), next.idToken)
	}

	if f.r.refreshWorks(tokens.refresh) {
		f.t.Fatal("a refresh token worked twice")
	}

	wantRevoked(f.t, f.r.postForm(oauth.PathRevoke, revokeForm(next.access, clientURL)))

	if f.r.active(next.access) {
		f.t.Fatal("a revoked access token is live")
	}

	last := wantTokens(f.t, f.r.postForm(oauth.PathToken, refreshForm(next.refresh)))
	if !f.r.active(last.access) {
		f.t.Fatal("the refreshed access token is not live")
	}

	return last
}

// userRevokes has the user see the grant in their list and revoke it, after which
// its tokens do not work and a resource server is told inactive.
func (f *flow) userRevokes(tokens tokenBody) {
	f.t.Helper()

	listed := pageOf(f.t, f.r.as(f.cookie, http.MethodGet, oauth.PathGrants))
	if len(listed.ids) != 1 || listed.ids[0] != grantID {
		f.t.Fatalf("grants = %v, want the one", listed)
	}

	revoked := f.r.as(f.cookie, http.MethodDelete, grantPath(grantID))
	if revoked.Code != http.StatusOK || !strings.Contains(revoked.Body.String(), `"revokedAt"`) {
		f.t.Fatalf("revoke = %d %q", revoked.Code, revoked.Body)
	}

	if f.r.active(tokens.access) || f.r.refreshWorks(tokens.refresh) {
		f.t.Error("a revoked grant's tokens work")
	}

	rec := f.r.postForm(oauth.PathIntrospect, introspectForm(tokens.access, resourceURL))
	if rec.Body.String() != inactiveBody {
		f.t.Errorf("introspection = %q, want %q", rec.Body, inactiveBody)
	}
}
