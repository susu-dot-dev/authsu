//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/japikey_go"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// jwtParts decodes the header and the claims of a JWT, without verifying it.
func jwtParts(t *testing.T, token string) (map[string]any, map[string]any) {
	t.Helper()

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		t.Fatalf("token has %d segments", len(segments))
	}

	decode := func(segment string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatalf("segment: %v", err)
		}

		var out map[string]any

		err = json.Unmarshal(raw, &out)
		if err != nil {
			t.Fatalf("json: %v", err)
		}

		return out
	}

	return decode(segments[0]), decode(segments[1])
}

// storedJWK decodes the one key in a stored JWK document.
func storedJWK(t *testing.T, document string) map[string]any {
	t.Helper()

	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}

	err := json.Unmarshal([]byte(document), &parsed)
	if err != nil || len(parsed.Keys) != 1 {
		t.Fatalf("jwk = %s: %v", document, err)
	}

	return parsed.Keys[0]
}

func TestConstants(t *testing.T) {
	t.Parallel()

	// Kinds are the strings the database stores; the store's own constants are
	// the same values, so a key is read under the kind it was written with.
	for name, pair := range map[string][2]string{
		"session": {auth.KindSession, store.KindSession},
		"api_key": {auth.KindAPIKey, store.KindAPIKey},
	} {
		if pair[0] != name || pair[1] != name {
			t.Errorf("kind %q = auth %q, store %q", name, pair[0], pair[1])
		}
	}

	if auth.SessionLifetime != 14*24*time.Hour {
		t.Errorf("SessionLifetime = %v", auth.SessionLifetime)
	}

	if auth.CookieName != "__Host-session" {
		t.Errorf("CookieName = %q", auth.CookieName)
	}
}

// TestAudience: every kind has its own audience, so a token for one kind is
// never accepted as another.
func TestAudience(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		auth.KindSession: audSession,
		auth.KindAPIKey:  audForAPI,
		"anything":       "authsu/anything",
		"":               "authsu/",
	}

	seen := map[string]string{}

	for kind, want := range tests {
		got := auth.Audience(kind)
		if got != want {
			t.Errorf("Audience(%q) = %q, want %q", kind, got, want)
		}

		if previous, clash := seen[got]; clash {
			t.Errorf("%q and %q share the audience %q", kind, previous, got)
		}

		seen[got] = kind
	}
}

func TestIssuerFor(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		origin       string
		wantBase     string
		wantInsecure bool
	}{
		"https":           {origin: apiOrigin, wantBase: apiOrigin + "/keys", wantInsecure: false},
		"https with port": {origin: apiOrigin + ":8443", wantBase: apiOrigin + ":8443/keys", wantInsecure: false},
		"localhost http":  {origin: localOrigin, wantBase: localIssuer, wantInsecure: true},
		"localhost https": {origin: "https://localhost", wantBase: "https://localhost/keys", wantInsecure: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := auth.IssuerFor(origin(t, tt.origin))
			if got.Base != tt.wantBase || got.Insecure != tt.wantInsecure {
				t.Errorf("issuer = %+v, want base %q insecure %v", got, tt.wantBase, tt.wantInsecure)
			}
		})
	}
}

// keyCase is a key to create and the claims it must carry beyond the
// registered ones.
type keyCase struct {
	spec    auth.KeySpec
	wantAud string
	// wantScope is the scope claim: always present, an array, empty when the
	// key has no scopes.
	wantScope []any
	wantPick  map[string]any
}

func keyCases(expires time.Time) map[string]keyCase {
	spec := func(kind string, list scope.List, claims map[string]any) auth.KeySpec {
		return auth.KeySpec{Kind: kind, Subject: userID, Expires: expires, Scope: list, Claims: claims}
	}

	return map[string]keyCase{
		"a session key with no scopes": {spec(auth.KindSession, nil, nil), audSession, []any{}, nil},
		"an api key with empty scopes": {spec(auth.KindAPIKey, scope.List{}, nil), audForAPI, []any{}, nil},
		"an api key with one scope": {
			spec(auth.KindAPIKey, scope.List{"agent:read"}, nil), audForAPI, []any{"agent:read"}, nil,
		},
		"an api key with a bundle": {
			spec(auth.KindAPIKey, scope.List{scope.DefaultAgent, "agent:create"}, nil),
			audForAPI, []any{scope.DefaultAgent, "agent:create"}, nil,
		},
		"an api key with an act claim": {
			spec(auth.KindAPIKey, scope.List{scope.DefaultAgent}, map[string]any{"act": map[string]any{claimSub: "agent-1"}}),
			audForAPI, []any{scope.DefaultAgent}, map[string]any{"act": map[string]any{claimSub: "agent-1"}},
		},
		"claims cannot override the reserved ones or the scope": {
			spec(auth.KindSession, scope.List{"agent:read"}, map[string]any{
				claimSub: otherUserID, claimIss: "https://evil.example.com/keys/x", claimAud: audForAPI,
				claimExp: 1, claimIat: 1, claimVer: "japikey-v1", claimScope: []any{"user:revoke"},
			}),
			audSession, []any{"agent:read"}, nil,
		},
	}
}

// claimProblems lists the registered claims of a created key that are wrong.
func claimProblems(key auth.Key, claims map[string]any, issuer auth.Issuer, tt keyCase) []string {
	want := map[string]any{
		claimSub: tt.spec.Subject, claimAud: tt.wantAud, claimIss: issuer.Base + "/" + key.ID.String(),
		claimVer: versionV2, claimExp: float64(tt.spec.Expires.Unix()),
	}

	maps.Copy(want, tt.wantPick)

	var problems []string

	for name, value := range want {
		if !reflect.DeepEqual(claims[name], value) {
			problems = append(problems, name)
		}
	}

	if !reflect.DeepEqual(claims[claimScope], tt.wantScope) {
		problems = append(problems, claimScope)
	}

	// The row's copy is the claim by construction: it is the same list.
	if key.Scope != tt.spec.Scope.JSON() {
		problems = append(problems, "Key.Scope")
	}

	return problems
}

// TestCreateKeyClaims: the token is signed with the claims the verifier
// requires, bound to the issuer, the kind's audience and the key's id.
func TestCreateKeyClaims(t *testing.T) {
	t.Parallel()

	issuer := auth.IssuerFor(origin(t, apiOrigin))
	expires := time.Now().Add(time.Hour).Truncate(time.Second)

	for name, tt := range keyCases(expires) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := auth.CreateKey(issuer, tt.spec)
			if err != nil {
				t.Fatalf("CreateKey: %v", err)
			}

			header, claims := jwtParts(t, key.JWT)

			if header["kid"] != key.ID.String() || header["alg"] != "ES256" {
				t.Errorf("header = %v, want kid %s and ES256", header, key.ID)
			}

			if problems := claimProblems(key, claims, issuer, tt); len(problems) != 0 {
				t.Errorf("claims %v are wrong in %v", claims, problems)
			}

			if iat, _ := claims[claimIat].(float64); time.Since(time.Unix(int64(iat), 0)).Abs() > time.Minute {
				t.Errorf("iat = %v, want about now", claims[claimIat])
			}

			if _, isEC := key.PublicKey.(*ecdsa.PublicKey); !isEC || !key.ExpiresAt.Equal(expires) {
				t.Errorf("PublicKey is %T, ExpiresAt = %v", key.PublicKey, key.ExpiresAt)
			}
		})
	}
}

// TestCreateKeyStoresOnlyThePublicKey holds the property the design rests on:
// the private half is discarded, so nothing that is stored can sign.
func TestCreateKeyStoresOnlyThePublicKey(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	first, second := r.createKey(r.issuer, auth.KindSession), r.createKey(r.issuer, auth.KindSession)

	jwk := storedJWK(t, first.JWK)

	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, found := jwk[private]; found {
			t.Errorf("the stored JWK has the private member %q", private)
		}
	}

	if jwk["kid"] != first.ID.String() || jwk["kty"] != "EC" {
		t.Errorf("jwk = %v", jwk)
	}

	// The document must fit the column's CHECK (migrations/0002).
	if len(first.JWK) > 2048 {
		t.Errorf("the JWK is %d bytes, over the 2048 the column allows", len(first.JWK))
	}

	// Every key is new.
	if first.ID == second.ID || first.JWT == second.JWT || first.JWK == second.JWK {
		t.Error("two keys are not independent")
	}
}

// TestStoredJWKReadsBackAsThePublicKey: what is stored is what verification
// reads, and it is the public half of the key that signed the token.
func TestStoredJWKReadsBackAsThePublicKey(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	key := r.createKey(r.issuer, auth.KindSession)

	var parsed japikey.JWKS

	err := json.Unmarshal([]byte(key.JWK), &parsed)
	if err != nil {
		t.Fatalf("JWK: %v", err)
	}

	public, err := parsed.GetPublicKey(key.ID)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	if ec, isEC := public.(*ecdsa.PublicKey); !isEC || !ec.Equal(key.PublicKey) {
		t.Errorf("stored key = %v, want the key's public half", public)
	}
}

// TestCreateSession is CreateKey for a session: the kind, the subject and the
// expiry are the arguments, and nothing else is signed in.
func TestCreateSession(t *testing.T) {
	t.Parallel()

	issuer := auth.IssuerFor(origin(t, apiOrigin))
	expires := time.Now().Add(auth.SessionLifetime)

	key, err := auth.CreateSession(issuer, userID, expires)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	_, claims := jwtParts(t, key.JWT)

	want := map[string]any{
		claimSub: userID, claimAud: audSession, claimIss: issuer.Base + "/" + key.ID.String(),
		claimExp: float64(expires.Unix()), claimVer: versionV2,
		// A session is every scope: the default:session bundle, signed as an array.
		claimScope: []any{"default:session"},
	}

	for name, value := range want {
		if !reflect.DeepEqual(claims[name], value) {
			t.Errorf("claim %q = %v, want %v", name, claims[name], value)
		}
	}

	// The registered claims, the scope and iat: no role and nothing else is in
	// the token.
	if len(claims) != len(want)+1 {
		t.Errorf("claims = %v, want only %d claims and iat", claims, len(want))
	}

	if key.Scope != `["default:session"]` {
		t.Errorf("Key.Scope = %q, want the stored copy of the claim", key.Scope)
	}
}

// TestCreateKeyRefusesWhatCannotBeIssued: a key that could never verify is an
// error at creation, not a token handed to a client.
func TestCreateKeyRefusesWhatCannotBeIssued(t *testing.T) {
	t.Parallel()

	secure := auth.IssuerFor(origin(t, apiOrigin))
	soon := time.Now().Add(time.Hour)

	tests := map[string]struct {
		issuer  auth.Issuer
		subject string
		expires time.Time
	}{
		"empty subject":    {secure, "", soon},
		"already expired":  {secure, userID, time.Now().Add(-time.Hour)},
		"expires too soon": {secure, userID, time.Now().Add(time.Second)},
		"not a url":        {auth.Issuer{Base: "not a url", Insecure: false}, userID, soon},
		"no issuer":        {auth.Issuer{Base: "", Insecure: false}, userID, soon},
		"http without the allowance": {
			auth.Issuer{Base: localIssuer, Insecure: false}, userID, soon,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := auth.CreateSession(tt.issuer, tt.subject, tt.expires)
			if err == nil {
				t.Error("CreateSession succeeded, want an error")
			}

			spec := auth.KeySpec{Kind: auth.KindAPIKey, Subject: tt.subject, Expires: tt.expires, Claims: nil}

			_, err = auth.CreateKey(tt.issuer, spec)
			if err == nil {
				t.Error("CreateKey succeeded, want an error")
			}
		})
	}
}

func TestCreateKeyAllowsHTTPWhereTheOriginDoes(t *testing.T) {
	t.Parallel()

	local := auth.IssuerFor(origin(t, localOrigin))

	_, err := auth.CreateSession(local, userID, time.Now().Add(time.Hour))
	if err != nil {
		t.Errorf("CreateSession for a localhost issuer: %v", err)
	}
}

func TestCreateKeyFailsWhenTheJWKCannotBeEncoded(t *testing.T) {
	t.Parallel()

	issuer := auth.IssuerFor(origin(t, apiOrigin))
	spec := auth.KeySpec{Kind: auth.KindSession, Subject: userID, Expires: time.Now().Add(time.Hour), Claims: nil}

	_, err := auth.CreateKeyWith(func(any) ([]byte, error) { return nil, errEncode }, issuer, spec)
	if err == nil || !strings.Contains(err.Error(), errEncode.Error()) {
		t.Errorf("err = %v, want it to carry %v", err, errEncode)
	}
}

// TestKindsAreNotInterchangeable: a key created for one kind carries that
// kind's audience, so a boundary that pins its own refuses it.
func TestKindsAreNotInterchangeable(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{auth.KindSession, auth.KindAPIKey} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			key := r.createKey(r.issuer, kind)

			_, claims := jwtParts(t, key.JWT)
			if claims[claimAud] != auth.Audience(kind) {
				t.Errorf("audience = %v, want %q", claims[claimAud], auth.Audience(kind))
			}

			r.put(key, kind)

			rec := r.get(pathMe, sessionCookie(key))
			if (rec.Code == http.StatusOK) != (kind == auth.KindSession) {
				t.Errorf("a %s key as a session: status %d", kind, rec.Code)
			}
		})
	}
}

// cookieCase is a cookie and what must be true of it.
type cookieCase struct {
	cookie     *http.Cookie
	wantValue  string
	wantMaxAge int
	wantExpiry time.Time
	wantInHdr  []string
}

func setCookieCases() map[string]cookieCase {
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	key := auth.Key{JWT: "header.claims.signature", ExpiresAt: expires} //nolint:exhaustruct // only what the cookie reads

	return map[string]cookieCase{
		"issued": {
			auth.SessionCookie(key), "header.claims.signature", 0, expires,
			[]string{
				"__Host-session=header.claims.signature", "Path=/", "Expires=Wed, 02 Jan 2030 03:04:05 GMT",
				"HttpOnly", "Secure", "SameSite=Lax",
			},
		},
		"cleared": {
			auth.ClearSessionCookie(), "", -1, time.Time{},
			[]string{"__Host-session=;", "Path=/", "Max-Age=0", "HttpOnly", "Secure", "SameSite=Lax"},
		},
	}
}

// TestSessionCookie: the attributes are the whole point, so each is asserted,
// on the cookie and as the browser receives it.
func TestSessionCookie(t *testing.T) {
	t.Parallel()

	for name, tt := range setCookieCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tt.checkIdentity(t)
			tt.checkAttributes(t)
			tt.checkHeader(t)
		})
	}
}

// checkIdentity checks the cookie's name, value and lifetime.
func (tt cookieCase) checkIdentity(t *testing.T) {
	t.Helper()

	c := tt.cookie

	if c.Name != auth.CookieName || c.Value != tt.wantValue || c.MaxAge != tt.wantMaxAge {
		t.Errorf("cookie = %+v", c)
	}

	if !c.Expires.Equal(tt.wantExpiry) {
		t.Errorf("Expires = %v, want %v", c.Expires, tt.wantExpiry)
	}
}

// checkAttributes checks what __Host- requires, what keeps the cookie to this
// host, and what keeps it from script and from other sites.
func (tt cookieCase) checkAttributes(t *testing.T) {
	t.Helper()

	c := tt.cookie

	if !c.Secure || c.Path != "/" || c.Domain != "" {
		t.Errorf("Secure = %v, Path = %q, Domain = %q: want Secure, /, none", c.Secure, c.Path, c.Domain)
	}

	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("HttpOnly = %v, SameSite = %v: want HttpOnly and Lax", c.HttpOnly, c.SameSite)
	}
}

// checkHeader checks the Set-Cookie line.
func (tt cookieCase) checkHeader(t *testing.T) {
	t.Helper()

	header := tt.cookie.String()

	for _, part := range tt.wantInHdr {
		if !strings.Contains(header, part) {
			t.Errorf("Set-Cookie %q does not contain %q", header, part)
		}
	}

	if strings.Contains(header, "Domain") {
		t.Errorf("Set-Cookie %q has a Domain", header)
	}
}

// TestSessionCookieAsABrowserParsesIt: the attributes survive serialisation.
func TestSessionCookieAsABrowserParsesIt(t *testing.T) {
	t.Parallel()

	for name, tt := range setCookieCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsed, err := http.ParseSetCookie(tt.cookie.String())
			if err != nil {
				t.Fatalf("ParseSetCookie: %v", err)
			}

			if parsed.Name != auth.CookieName || !parsed.Secure || !parsed.HttpOnly ||
				parsed.Path != "/" || parsed.SameSite != http.SameSiteLaxMode || parsed.Domain != "" {
				t.Errorf("parsed = %+v", parsed)
			}
		})
	}
}

// TestLoginGrant: the grant is the SHA-256 of the challenge, so a replay of the
// same challenge collides in the unique column.
func TestLoginGrant(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"a challenge": []byte("0123456789abcdef0123456789abcdef"),
		"empty input": {},
		"nil":         nil,
		"one byte":    {0},
		"binary":      {0, 255, 1, 254, 2, 253},
		"long":        []byte(strings.Repeat("x", 1000)),
	}

	for name, challenge := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want := sha256.Sum256(challenge)

			got := auth.LoginGrant(challenge)
			if string(got) != string(want[:]) || len(got) != 32 {
				t.Errorf("LoginGrant = %x, want %x", got, want)
			}

			if string(auth.LoginGrant(challenge)) != string(got) {
				t.Error("not deterministic: a replay would not collide")
			}
		})
	}

	if string(auth.LoginGrant([]byte("a"))) == string(auth.LoginGrant([]byte("b"))) {
		t.Error("different challenges have the same grant")
	}
}

// TestIssuerBindsAKeyToItsAPI: a token created for one API origin does not
// verify on another, because the issuer is part of what is signed.
func TestIssuerBindsAKeyToItsAPI(t *testing.T) {
	t.Parallel()

	for _, other := range []string{"https://other.example.com", apiOrigin + ":8443", localOrigin} {
		t.Run(other, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			key, err := auth.CreateSession(auth.IssuerFor(origin(t, other)), userID, r.now.Add(time.Hour))
			if err != nil {
				t.Fatalf("CreateSession: %v", err)
			}

			r.put(key, auth.KindSession)

			if rec := r.get(pathMe, sessionCookie(key)); rec.Code != http.StatusUnauthorized || len(r.keys.calls) != 0 {
				t.Errorf("status %d, store read %d times, want 401 and no reads", rec.Code, len(r.keys.calls))
			}
		})
	}
}

// TestCreatedKeysFitTheSchema is the seam between the keys auth creates and the
// japikeys table that stores them: the id and the JWK of every kind of key must
// fit the CHECKs of the migrations, read from their text so that a changed
// limit is noticed here and not by a failing insert in production.
func TestCreatedKeysFitTheSchema(t *testing.T) {
	t.Parallel()

	maxJWK := migrationLimits(t, `length\(jwk\) <= (\d+)`)[0]
	kidLength := migrationLimits(t, `length\(kid\) = (\d+)`)[0]
	kidAlphabet := regexp.MustCompile(`^[0-9a-f-]+$`)

	r := newRig(t)

	for _, kind := range []string{auth.KindSession, auth.KindAPIKey} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			// Keys are random, so several are checked: a coordinate is not
			// always the same length.
			for range 20 {
				key := r.createKey(r.issuer, kind)

				if len(key.JWK) > maxJWK {
					t.Fatalf("the JWK is %d bytes; the schema allows %d", len(key.JWK), maxJWK)
				}

				if id := key.ID.String(); len(id) != kidLength || !kidAlphabet.MatchString(id) {
					t.Fatalf("the kid %q is not %d characters of lowercase hex and dashes", id, kidLength)
				}
			}
		})
	}
}

// TestCreatedTokensAreAcceptedAsTokens is the seam between the tokens auth
// creates and the input.Token the boundary parses every cookie into: a token
// that parser refuses could be issued, set as a cookie, and never accepted. It
// holds for each kind of key, with the claims an agent's key carries and with
// the longest issuer a deployment's origin could give (a 253-character host),
// and leaves room to spare under the bound.
func TestCreatedTokensAreAcceptedAsTokens(t *testing.T) {
	t.Parallel()

	label := strings.Repeat("a", 63)
	host := strings.Join([]string{label, label, label, "com"}, ".")
	longest := auth.Issuer{Base: "https://" + host + "/keys", Insecure: false}

	issuers := map[string]auth.Issuer{"the test issuer": newRig(t).issuer, "the longest issuer": longest}
	// The largest scope list a client can have accepted: every scope and every
	// bundle, each once (input.ParseScopeList refuses a repeat).
	largest := append(allScopeNames(), scope.DefaultSession, scope.DefaultUser, scope.DefaultAgent)

	type spec struct {
		scopes scope.List
		claims map[string]any
	}

	actorClaim := map[string]any{claimAct: map[string]any{claimSub: "01234567-89ab-7def-8123-456789abcdef"}}

	specs := map[string]spec{
		"no scopes":                           {scopes: nil, claims: nil},
		"an agent's claims":                   {scopes: scope.List{scope.DefaultAgent}, claims: actorClaim},
		"the largest scope list and an actor": {scopes: largest, claims: actorClaim},
	}

	for issuerName, issuer := range issuers {
		for specName, extra := range specs {
			for _, kind := range []string{auth.KindSession, auth.KindAPIKey} {
				t.Run(issuerName+"/"+specName+"/"+kind, func(t *testing.T) {
					t.Parallel()

					key, err := auth.CreateKey(issuer, auth.KeySpec{
						Kind: kind, Subject: "01234567-89ab-7def-8123-456789abcdef",
						Expires: time.Now().Add(time.Hour), Scope: extra.scopes, Claims: extra.claims,
					})
					if err != nil {
						t.Fatalf("CreateKey: %v", err)
					}

					token, err := input.ParseToken(key.JWT)
					if err != nil || token.String() != key.JWT {
						t.Fatalf("the boundary would refuse the token it issued (%d bytes): %v", len(key.JWT), err)
					}

					if len(key.JWT) > input.MaxTokenBytes/2 {
						t.Errorf("the token is %d bytes, over half of the %d the boundary accepts", len(key.JWT), input.MaxTokenBytes)
					}
				})
			}
		}
	}
}

// allScopeNames is every scope's name.
func allScopeNames() []string {
	names := make([]string, 0, len(scope.Scopes()))

	for _, s := range scope.Scopes() {
		names = append(names, string(s))
	}

	return names
}
