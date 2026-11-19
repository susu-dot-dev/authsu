//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// challengeOf is the S256 challenge of a verifier.
func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// idAfter is the id the routes hand out as their nth: the first two are the
// grant's and its agent's, which consent asks for.
func idAfter(n int) string { return fmt.Sprintf("00000000-0000-7000-8000-%012x", 0x2000+n) }

// tokenOf2 is tokenOf for a table built outside a test: the entropy is a fixed
// sequence, and generating a token cannot fail.
func tokenOf2(tag secret.Tag) string {
	token, err := secret.Generate(&sequence{reads: 1 << 40}, tag)
	if err != nil {
		panic(err)
	}

	return token
}

// exchangeCase is a code exchange that succeeds.
type exchangeCase struct {
	// edit changes the authorization request; form changes the token request.
	edit func(url.Values)
	form func(url.Values)

	// registered is the redirect URI the client's document lists, if not the
	// usual ones.
	registered string

	// wantScope is what the grant holds, and so what is answered; wantNonce is
	// the nonce the ID token carries, if any; wantRedirect and wantVerifier are
	// what the exchange presents.
	wantScope    string
	wantNonce    string
	wantRedirect string
	wantVerifier string
}

// usual is an exchange of the default request, which the cases edit.
func usual(edit func(*exchangeCase)) exchangeCase {
	tc := exchangeCase{wantScope: "mcp:read mcp:write", wantRedirect: redirectURL, wantVerifier: verifierVal}

	if edit != nil {
		edit(&tc)
	}

	return tc
}

// exchanges are the code exchanges that succeed.
func exchanges() map[string]exchangeCase {
	short := strings.Repeat("a", input.MinCodeVerifierLen)
	long := strings.Repeat("Z-._~", 25) + "abc"
	loopback := "http://127.0.0.1:5555/cb"
	query := redirectURL + "?tenant=a"

	withVerifier := func(verifier string) exchangeCase {
		return usual(func(c *exchangeCase) {
			c.edit, c.form, c.wantVerifier = setParam("code_challenge", challengeOf(verifier)),
				setParam("code_verifier", verifier), verifier
		})
	}

	return map[string]exchangeCase{
		"the default scopes": usual(nil),
		"one scope": usual(func(c *exchangeCase) {
			c.edit, c.wantScope = setParam("scope", "mcp:write"), "mcp:write"
		}),
		"openid with a nonce": usual(func(c *exchangeCase) {
			c.edit = func(v url.Values) { v.Set("scope", "openid mcp:read"); v.Set("nonce", "n-0S6_WzA2Mj") }
			c.wantScope, c.wantNonce = "openid mcp:read", "n-0S6_WzA2Mj"
		}),
		"openid without a nonce": usual(func(c *exchangeCase) {
			c.edit, c.wantScope = setParam("scope", "openid mcp:read mcp:write"), "openid mcp:read mcp:write"
		}),
		"a nonce without openid is never shown": usual(func(c *exchangeCase) { c.edit = setParam("nonce", "n1") }),
		"a loopback redirect URI on the port that was asked for": usual(func(c *exchangeCase) {
			c.edit, c.form, c.wantRedirect = setParam("redirect_uri", loopback), setParam("redirect_uri", loopback), loopback
		}),
		"a redirect URI with a query": usual(func(c *exchangeCase) {
			c.edit, c.form, c.registered, c.wantRedirect = setParam("redirect_uri", query),
				setParam("redirect_uri", query), query, query
		}),
		"the resource named, which is the grant's": usual(func(c *exchangeCase) {
			c.form = setParam("resource", resourceURL)
		}),
		"parameters of the other grant type and unknown ones are ignored": usual(func(c *exchangeCase) {
			c.form = func(v url.Values) {
				v.Set("refresh_token", "not a token")
				v.Set("scope", "no such scope")
				v.Add("audience", "x")
				v.Add("audience", "y")
			}
		}),
		"a verifier of the shortest length": withVerifier(short),
		"a verifier of the longest length":  withVerifier(long),
	}
}

// TestTokenExchangesACode: the code of an approved request is exchanged, through
// the real boundary, for a refresh token, an access token and (for openid) an ID
// token. The store is given exactly what the request presented and what was
// issued, the hashes and expiries at the lifetimes of the design, at the one
// instant of the request, and the answer is the RFC 6749 section 5.1 response.
func TestTokenExchangesACode(t *testing.T) {
	t.Parallel()

	for name, tt := range exchanges() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			if tt.registered != "" {
				r.net.answers[clientURL] = served(document(clientURL, tt.registered))
			}

			code := r.approve(tt.edit)
			r.now = r.now.Add(30 * time.Second)

			got := wantTokens(t, r.postForm(oauth.PathToken, withParams(codeForm(code), tt.form)))

			wantTokenShape(t, got, tt)
			wantExchangeCall(t, r, code, got, tt)
			wantIDToken(t, r, got, tt)

			if len(r.logged) != 0 {
				t.Errorf("logged %v, want nothing", r.loggedCodes())
			}
		})
	}
}

// wantTokenShape asserts the members of a token response, and that the tokens in
// it are what the parsers accept.
func wantTokenShape(t *testing.T, got tokenBody, tt exchangeCase) {
	t.Helper()

	wantMembers := 5
	if got.idToken != "" {
		wantMembers = 6
	}

	if len(got.members) != wantMembers || member(t, got.members, "token_type") != "Bearer" ||
		wantInteger(t, "expires_in", got.members["expires_in"]) != 900 || got.scope != tt.wantScope {
		t.Errorf("response = %v, want %d members, Bearer, 900 and scope %q", got.members, wantMembers, tt.wantScope)
	}

	_, accessErr := input.ParseAccessToken(got.access)
	_, refreshErr := input.ParseRefreshToken(got.refresh)

	if accessErr != nil || refreshErr != nil {
		t.Errorf("tokens = %q and %q, want an access token and a refresh token: %v %v",
			got.access, got.refresh, accessErr, refreshErr)
	}
}

// wantExchangeCall asserts the store's second call (after consent's) was the
// exchange, with exactly these arguments.
func wantExchangeCall(t *testing.T, r *rig, code string, got tokenBody, tt exchangeCase) {
	t.Helper()

	if len(r.store.calls) != 2 || r.store.calls[1].op != opExchange {
		t.Fatalf("store calls = %+v, want the consent write and then the exchange", r.store.calls)
	}

	call := r.store.calls[1]
	wantCode, _ := input.ParseAuthorizationCode(code)
	wantClient, _ := input.ParseClientID(clientURL, productionTable())
	wantRedirect, _ := input.ParseRedirectURI(tt.wantRedirect)
	wantVerifier, _ := input.ParseCodeVerifier(tt.wantVerifier)
	exchange := call.exchange

	if exchange.Code != wantCode || exchange.ClientID != wantClient || exchange.RedirectURI != wantRedirect ||
		exchange.Verifier != wantVerifier || exchange.Verifier.Challenge().String() != challengeOf(tt.wantVerifier) {
		t.Errorf("exchange = %+v, want code %s, client %s, redirect %s, verifier %s",
			exchange, code, clientURL, tt.wantRedirect, tt.wantVerifier)
	}

	wantIssued(t, r, call, got)
}

// wantIssued asserts that what the store was given to record is the tokens that
// were answered, at the lifetimes of the design, at the request's instant.
func wantIssued(t *testing.T, r *rig, call storeCall, got tokenBody) {
	t.Helper()

	tokens := call.exchange.Tokens
	if call.op == opRefresh {
		tokens = call.refresh.Tokens
	}

	if string(tokens.RefreshHash) != string(hashOfToken(got.refresh)) ||
		string(tokens.AccessHash) != string(hashOfToken(got.access)) {
		t.Error("the hashes recorded are not the hashes of the tokens answered")
	}

	if !tokens.RefreshExpiresAt.Equal(r.now.Add(30*24*time.Hour)) ||
		!tokens.AccessExpiresAt.Equal(r.now.Add(15*time.Minute)) || !call.now.Equal(r.now) {
		t.Errorf("refresh expires %v, access expires %v, now %v, want 30 days and 15 minutes after %v",
			tokens.RefreshExpiresAt, tokens.AccessExpiresAt, call.now, r.now)
	}

	if tokens.AccessID != idAfter(r.handed) {
		t.Errorf("access id = %q after %d ids, want the last one handed out, %q",
			tokens.AccessID, r.handed, idAfter(r.handed))
	}
}

// wantIDToken asserts that an ID token is answered exactly when the grant asked
// for openid, and that it says what the design says.
func wantIDToken(t *testing.T, r *rig, got tokenBody, tt exchangeCase) {
	t.Helper()

	if !strings.Contains(" "+tt.wantScope+" ", " openid ") {
		if got.idToken != "" {
			t.Errorf("id_token = %q for a grant that did not ask for openid", got.idToken)
		}

		return
	}

	claims := verifiedIDToken(t, got.idToken)
	issued := wantInteger(t, "iat", claims["iat"])

	if !all(claims["iss"] == apiOrigin, claims["sub"] == userA, claims["aud"] == clientURL) {
		t.Errorf("claims = %v, want iss %s, sub %s, aud %s", claims, apiOrigin, userA, clientURL)
	}

	if !all(issued == r.now.Unix(), wantInteger(t, "exp", claims["exp"]) == issued+300,
		wantInteger(t, "auth_time", claims["auth_time"]) == r.now.Add(-30*time.Second).Unix()) {
		t.Errorf("iat %v, exp %v, auth_time %v, want %d, +300 and the sign-in 30 seconds earlier",
			claims["iat"], claims["exp"], claims["auth_time"], r.now.Unix())
	}

	wantNonce(t, claims, tt.wantNonce)
}

// wantNonce asserts that the claims carry the nonce, and no other member than the
// six of an ID token and the nonce, or carry none when there was none.
func wantNonce(t *testing.T, claims map[string]any, nonce string) {
	t.Helper()

	wantMembers := 6
	if nonce != "" {
		wantMembers = 7
	}

	got, hasNonce := claims["nonce"]
	if !all(len(claims) == wantMembers, hasNonce == (nonce != ""), !hasNonce || got == nonce) {
		t.Errorf("claims = %v, want %d members and nonce %q", claims, wantMembers, nonce)
	}
}

// refusal is a token request that is refused, with this OAuth code, before the
// store is asked. The status is always 400.
type refusal struct {
	form func(url.Values)
	// raw, when set, is the body sent instead of the form.
	raw  string
	code string
}

// refuse is a refusal of a form edited by edit.
func refuse(code string, edit func(url.Values)) refusal { return refusal{form: edit, code: code} }

// rawRefusal is a refusal of the body as it is.
func rawRefusal(code, raw string) refusal { return refusal{raw: raw, code: code} }

// merged is the union of refusals tables.
func merged(tables ...map[string]refusal) map[string]refusal {
	out := map[string]refusal{}

	for _, table := range tables {
		maps.Copy(out, table)
	}

	return out
}

// refusedAsToken is a refusal of the parameter holding a token that is not of the
// kind the grant takes: every other kind of token, as the code or refresh token.
func refusedAsToken(param string, kinds ...secret.Tag) map[string]refusal {
	rows := map[string]refusal{}

	for _, tag := range kinds {
		rows["a "+string(tag)+" token as "+param] = refuse(oauthGrant, setParam(param, tokenOf2(tag)))
	}

	return rows
}

// The OAuth codes of the rows below.
const (
	oauthRequest    = "invalid_request"
	oauthClient     = "invalid_client"
	oauthGrant      = "invalid_grant"
	oauthScope      = "invalid_scope"
	oauthTarget     = "invalid_target"
	oauthGrantType  = "unsupported_grant_type"
	oauthServer     = "server_error"
	oauthUnavailble = "temporarily_unavailable"
)

// resourceTwice names the resource twice.
func resourceTwice(v url.Values) {
	v.Add("resource", resourceURL)
	v.Add("resource", resourceURL)
}

// formRefusals are the requests that cannot be read, whatever the grant type.
func formRefusals() map[string]refusal {
	return map[string]refusal{
		"no grant_type":                 {form: drop("grant_type"), code: oauthRequest},
		"an empty grant_type":           refuse(oauthRequest, setParam("grant_type", "")),
		"grant_type twice":              refuse(oauthRequest, twice("grant_type")),
		"no client_id":                  refuse(oauthRequest, drop("client_id")),
		"an empty client_id":            refuse(oauthRequest, setParam("client_id", "")),
		"client_id twice":               refuse(oauthRequest, twice("client_id")),
		"resource twice":                refuse(oauthRequest, resourceTwice),
		"a malformed percent-encoding":  rawRefusal(oauthRequest, "grant_type=authorization_code&code=%zz"),
		"a parameter with no name":      rawRefusal(oauthRequest, "=x&grant_type=authorization_code"),
		"a NUL in a recognised value":   rawRefusal(oauthRequest, "grant_type=authorization_code&client_id=a%00"),
		"an invalid UTF-8 value":        rawRefusal(oauthRequest, "grant_type=authorization_code&code=%ff"),
		"an unknown resource":           refuse(oauthTarget, setParam("resource", "https://other.example.com/mcp")),
		"a resource with a trailing /":  refuse(oauthTarget, setParam("resource", resourceURL+"/")),
		"the development resource":      refuse(oauthTarget, setParam("resource", "http://localhost:8788/mcp")),
		"grant_type=password":           refuse(oauthGrantType, setParam("grant_type", "password")),
		"grant_type=client_credentials": refuse(oauthGrantType, setParam("grant_type", "client_credentials")),
		"grant_type in another case":    refuse(oauthGrantType, setParam("grant_type", "Authorization_Code")),
		"grant_type with a space":       refuse(oauthGrantType, setParam("grant_type", "authorization_code ")),
		"grant_type with both":          refuse(oauthGrantType, setParam("grant_type", "authorization_code refresh_token")),
		"a client_id that is http":      refuse(oauthClient, setParam("client_id", "http://client.example.com/c.json")),
		"a client_id that is an IP":     refuse(oauthClient, setParam("client_id", "https://192.0.2.1/c.json")),
		"a client_id that is no URL":    refuse(oauthClient, setParam("client_id", "client")),
		"a client_id with a fragment":   refuse(oauthClient, setParam("client_id", clientURL+"#x")),
		"a client_id with no path":      refuse(oauthClient, setParam("client_id", "https://client.example.com")),
		"a client_id over the bound": refuse(oauthClient,
			setParam("client_id", longURL(input.MaxClientIDBytes+1))),
	}
}

// codeRefusals are the authorization_code requests that are refused. Each is a
// request that is valid but for one thing.
func codeRefusals() map[string]refusal {
	upperCode := strings.ToUpper(tokenOf2(secret.TagOAuthCode))
	tooShort := strings.Repeat("a", input.MinCodeVerifierLen-1)
	tooLong := strings.Repeat("a", input.MaxCodeVerifierLen+1)

	own := map[string]refusal{
		"no code":                               refuse(oauthRequest, drop("code")),
		"code twice":                            refuse(oauthRequest, twice("code")),
		"no redirect_uri":                       refuse(oauthRequest, drop("redirect_uri")),
		"redirect_uri twice":                    refuse(oauthRequest, twice("redirect_uri")),
		"no code_verifier":                      refuse(oauthRequest, drop("code_verifier")),
		"code_verifier twice":                   refuse(oauthRequest, twice("code_verifier")),
		"a redirect_uri that is no URL":         refuse(oauthGrant, setParam("redirect_uri", "callback")),
		"a redirect_uri with a fragment":        refuse(oauthGrant, setParam("redirect_uri", redirectURL+"#x")),
		"a redirect_uri on http":                refuse(oauthGrant, setParam("redirect_uri", "http://client.example.com/cb")),
		"a redirect_uri with a custom scheme":   refuse(oauthGrant, setParam("redirect_uri", "myapp://cb")),
		"a code of the wrong length":            refuse(oauthGrant, setParam("code", "susu_code_short")),
		"a code that is garbage":                refuse(oauthGrant, setParam("code", "nonsense")),
		"a code in capitals":                    refuse(oauthGrant, setParam("code", upperCode)),
		"a verifier of 42 characters":           refuse(oauthGrant, setParam("code_verifier", tooShort)),
		"a verifier of 129 characters":          refuse(oauthGrant, setParam("code_verifier", tooLong)),
		"a verifier with a plus sign":           refuse(oauthGrant, setParam("code_verifier", verifierVal[:42]+"+")),
		"a verifier with a space":               refuse(oauthGrant, setParam("code_verifier", verifierVal[:42]+" ")),
		"a verifier that is a padded challenge": refuse(oauthGrant, setParam("code_verifier", challengeVal+"=")),
	}

	return merged(own, formRefusals(), refusedAsToken(paramCode,
		secret.TagOAuthRefresh, secret.TagOAuthAccess, secret.TagSession, secret.TagAPIKey, secret.TagInvitation))
}

// paramCode is the name of the code parameter.
const paramCode = "code"

// scopeTwice sends the scope parameter twice.
func scopeTwice(v url.Values) {
	v.Set("scope", "mcp:read")
	v.Add("scope", "mcp:write")
}

// refreshRefusals are the refresh_token requests that are refused.
func refreshRefusals() map[string]refusal {
	refreshToken := tokenOf2(secret.TagOAuthRefresh)

	repeated := strings.Join([]string{"mcp:read", "mcp:read"}, " ")
	plus := "grant_type=refresh_token&client_id=" + url.QueryEscape(clientURL) + "&refresh_token=" + refreshToken +
		"&scope=mcp%3Aread%2Bmcp%3Awrite"

	own := map[string]refusal{
		"no refresh_token":              refuse(oauthRequest, drop("refresh_token")),
		"refresh_token twice":           refuse(oauthRequest, twice("refresh_token")),
		"scope twice":                   refuse(oauthRequest, scopeTwice),
		"an unknown scope":              refuse(oauthScope, setParam("scope", "mcp:admin")),
		"a scope of another resource":   refuse(oauthScope, setParam("scope", "api:read")),
		"a scope repeated in itself":    refuse(oauthScope, setParam("scope", repeated)),
		"a scope with a literal plus":   rawRefusal(oauthScope, plus),
		"a scope with a comma":          refuse(oauthScope, setParam("scope", "mcp:read,mcp:write")),
		"a scope with two spaces":       refuse(oauthScope, setParam("scope", "mcp:read  mcp:write")),
		"a scope with a trailing space": refuse(oauthScope, setParam("scope", "mcp:read ")),
		"a scope in capitals":           refuse(oauthScope, setParam("scope", "MCP:READ")),
		"a scope of only openid":        refuse(oauthScope, setParam("scope", "openid")),
		"the resource named, and a scope that is not its": refuse(oauthScope,
			func(v url.Values) { v.Set("resource", resourceURL); v.Set("scope", "mcp:admin") }),
		"a refresh token that is garbage": refuse(oauthGrant, setParam("refresh_token", "x")),
	}

	return merged(own, formRefusals(), refusedAsToken("refresh_token",
		secret.TagOAuthCode, secret.TagOAuthAccess, secret.TagSession, secret.TagAPIKey, secret.TagInvitation))
}

// TestTokenRefusesTheRequest: a request that cannot be answered is refused with
// the code RFC 6749 section 5.2 gives it, in the OAuth error format, before
// anything is issued, written or read from the entropy source: the store is
// never asked, and no id is handed out.
func TestTokenRefusesTheRequest(t *testing.T) {
	t.Parallel()

	type kind struct {
		base func() url.Values
		rows map[string]refusal
	}

	kinds := map[string]kind{
		"authorization_code": {func() url.Values { return codeForm(tokenOf2(secret.TagOAuthCode)) }, codeRefusals()},
		"refresh_token": {func() url.Values {
			return withParams(refreshForm(tokenOf2(secret.TagOAuthRefresh)), setParam("scope", "mcp:read"))
		}, refreshRefusals()},
	}

	for grantType, k := range kinds {
		for name, tt := range k.rows {
			t.Run(grantType+"/"+name, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)

				body := withParams(k.base(), tt.form).Encode()
				if tt.raw != "" {
					body = tt.raw
				}

				wantOAuthError(t, r.postRaw(oauth.PathToken, body), http.StatusBadRequest, tt.code)

				if len(r.store.calls) != 0 || r.handed != 0 {
					t.Errorf("store calls %+v and %d ids for a refused request", r.store.calls, r.handed)
				}
			})
		}
	}
}

// TestTokenIsAFormEndpoint: the form is the one body the endpoint takes, and it is
// bounded.
func TestTokenIsAFormEndpoint(t *testing.T) {
	t.Parallel()

	wantFormEndpoint(t, oauth.PathToken, oauth.MaxTokenBody)

	t.Run("a body at the limit is read", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		good := codeForm(tokenOf(t, secret.TagOAuthCode)).Encode()
		pad := "&junk=" + strings.Repeat("a", oauth.MaxTokenBody-len(good)-len("&junk="))

		wantOAuthError(t, r.postRaw(oauth.PathToken, good+pad), http.StatusBadRequest, oauthGrant)

		if len(r.store.calls) != 1 {
			t.Errorf("store calls = %d, want the one exchange", len(r.store.calls))
		}
	})

	t.Run("an empty form", func(t *testing.T) {
		t.Parallel()

		wantOAuthError(t, newRig(t).postRaw(oauth.PathToken, ""), http.StatusBadRequest, oauthRequest)
	})
}

// storeOutcome is what the store says to a token request, and what the client is
// told.
type storeOutcome struct {
	failure error
	status  int
	code    string
	logged  string
}

// storeOutcomes are the failures the store reports, for an operation that failed
// with code.
func storeOutcomes(code string) map[string]storeOutcome {
	unavailable := apierr.New(apierr.Unavailable, code, "tokens are temporarily unavailable").WithCause(errDB)
	internal := apierr.New(apierr.Internal, code, "tokens are temporarily unavailable").WithCause(errDB)

	return map[string]storeOutcome{
		"nothing matched": {store.ErrInvalidGrant, http.StatusBadRequest, oauthGrant, oauthGrant},
		"nothing matched, wrapped": {
			fmt.Errorf("exchange: %w", store.ErrInvalidGrant), http.StatusBadRequest, oauthGrant, oauthGrant,
		},
		"the database is unavailable": {unavailable, http.StatusServiceUnavailable, oauthUnavailble, code},
		"a defect of the write":       {internal, http.StatusInternalServerError, oauthServer, code},
		"a failure nobody classified": {errDB, http.StatusInternalServerError, oauthServer, "internal"},
	}
}

// TestTokenStoreOutcomes: what the store says is what the client is told, and
// only that. A rejected code is invalid_grant, and every other failure is the
// store's classified error: the OAuth format sends it as server_error or
// temporarily_unavailable, with fixed text and never the cause.
func TestTokenStoreOutcomes(t *testing.T) {
	t.Parallel()

	forms := map[string]func() url.Values{
		"authorization_code": func() url.Values { return codeForm(tokenOf2(secret.TagOAuthCode)) },
		"refresh_token":      func() url.Values { return refreshForm(tokenOf2(secret.TagOAuthRefresh)) },
	}

	for grantType, form := range forms {
		for name, tt := range storeOutcomes(store.CodeOAuthExchangeFailed) {
			t.Run(grantType+"/"+name, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				r.store.failure = tt.failure

				rec := r.postForm(oauth.PathToken, form())

				wantOAuthError(t, rec, tt.status, tt.code)

				if strings.Contains(rec.Body.String(), "fire") {
					t.Errorf("body = %s, want the fixed text and no cause", rec.Body)
				}

				if got := r.loggedCodes(); len(got) != 1 || got[0] != tt.logged {
					t.Errorf("logged %v, want [%s]", got, tt.logged)
				}
			})
		}
	}
}

// TestTokenCodeIsBoundToWhatWasApproved: a code presented with another client,
// another redirect URI or another verifier is refused as invalid_grant and is not
// spent: the client that holds the right values still exchanges it, once.
func TestTokenCodeIsBoundToWhatWasApproved(t *testing.T) {
	t.Parallel()

	tests := map[string]func(url.Values){
		"another redirect URI":            setParam("redirect_uri", loopbackURL),
		"the redirect URI with a slash":   setParam("redirect_uri", redirectURL+"/"),
		"another client":                  setParam("client_id", otherClientURL),
		"another verifier":                setParam("code_verifier", strings.Repeat("b", 43)),
		"the verifier cut by a character": setParam("code_verifier", verifierVal[:42]+"."),
	}

	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			code := r.approve(nil)

			wantOAuthError(t, r.postForm(oauth.PathToken, withParams(codeForm(code), edit)), http.StatusBadRequest, oauthGrant)

			if len(r.store.calls) != 2 || r.handed != 3 {
				t.Errorf("store calls = %d, ids = %d, want the exchange the store refused", len(r.store.calls), r.handed)
			}

			wantTokens(t, r.postForm(oauth.PathToken, codeForm(code)))
			wantOAuthError(t, r.postForm(oauth.PathToken, codeForm(code)), http.StatusBadRequest, oauthGrant)
		})
	}
}

// TestTokenCodeLifetime: a code is good for its 60 seconds, to the second, and the
// store is given the instant of the request and the code's life, which it judges
// from consent: the secret's own expiry is the retention of the replay guard, ten
// minutes, and a code is not good for that long.
func TestTokenCodeLifetime(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		after time.Duration
		works bool
	}{
		"at once":                     {0, true},
		"one second before it lapses": {auth.CodeLifetime - time.Second, true},
		"the instant it lapses":       {auth.CodeLifetime, false},
		"one second after":            {auth.CodeLifetime + time.Second, false},
		"while the row is still kept": {oauth.PendingLifetime - time.Second, false},
		"after the row may go":        {oauth.PendingLifetime + time.Second, false},
		"a day later":                 {24 * time.Hour, false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			code := r.approve(nil)
			r.now = r.now.Add(tt.after)

			rec := r.postForm(oauth.PathToken, codeForm(code))

			if (rec.Code == http.StatusOK) != tt.works || !r.store.calls[1].now.Equal(r.now) {
				t.Errorf("= %d %q, want it to work: %t, with the store given %v", rec.Code, rec.Body, tt.works, r.now)
			}

			if got := r.store.calls[1].exchange.CodeLifetime; got != auth.CodeLifetime {
				t.Errorf("the store was given a code life of %v, want %v", got, auth.CodeLifetime)
			}
		})
	}
}

// TestTokenCodeOfARevokedAccountOrAgent: a code whose account or agent was revoked
// since consent is the same invalid_grant.
func TestTokenCodeOfARevokedAccountOrAgent(t *testing.T) {
	t.Parallel()

	for name, undo := range map[string]func(*rig){
		"an account that was revoked": func(r *rig) { r.store.inactiveUsers[userA] = true },
		"an agent that was revoked":   func(r *rig) { r.store.revokedAgents[newAgentID] = true },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			code := r.approve(nil)
			undo(r)

			wantOAuthError(t, r.postForm(oauth.PathToken, codeForm(code)), http.StatusBadRequest, oauthGrant)
		})
	}
}

// otherResource is a resource of another table than the production one the rigs
// use, which no request can name or approve there: a grant that holds it is one
// the routes cannot create, and is how a test stands for a table with a second
// entry.
func otherResource(t *testing.T) input.ResourceID {
	t.Helper()

	id, err := input.ParseResourceID(resource.DevelopmentURL, resource.Select("http://localhost:8787"))
	if err != nil {
		t.Fatal(err)
	}

	return id
}

// TestTokenCodeOfAnotherResource: a resource that is an entry of the table but is
// not the grant's is an invalid_target, and the code is not spent: the client that
// asks again for its own resource exchanges it.
func TestTokenCodeOfAnotherResource(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	code := r.approve(nil)
	r.store.rows[0].grant.Resource = otherResource(t)

	form := withParams(codeForm(code), setParam("resource", resourceURL))
	wantOAuthError(t, r.postForm(oauth.PathToken, form), http.StatusBadRequest, oauthTarget)

	call := r.store.calls[len(r.store.calls)-1]
	if call.exchange.Resource == nil || call.exchange.Resource.String() != resourceURL {
		t.Errorf("the store was asked for resource %v, want %s", call.exchange.Resource, resourceURL)
	}

	r.store.rows[0].grant.Resource = mustProductionResource(t)

	wantTokens(t, r.postForm(oauth.PathToken, codeForm(code)))
}

// refusedRefresh is a refresh of a live token that asks for more than the grant
// allows.
type refusedRefresh struct {
	edit func(url.Values) // the authorization request
	form func(url.Values) // the refresh request

	// elsewhere is whether the grant is for a resource other than the one the
	// request names, as it would be in a table with a second entry.
	elsewhere bool
	code      string
}

// refusedRefreshes are the refreshes that are refused by the write.
func refusedRefreshes() map[string]refusedRefresh {
	return map[string]refusedRefresh{
		"a scope the grant does not hold": {
			edit: setParam("scope", "mcp:read"), form: setParam("scope", "mcp:write"), code: oauthScope,
		},
		"a superset of the grant's scope": {
			edit: setParam("scope", "mcp:read"), form: setParam("scope", "mcp:read mcp:write"), code: oauthScope,
		},
		"openid, which the grant does not hold": {
			form: setParam("scope", "openid mcp:read"), code: oauthScope,
		},
		"a resource that is not the grant's": {
			form: setParam("resource", resourceURL), elsewhere: true, code: oauthTarget,
		},
		"the resource and the scope both wrong, the resource first": {
			edit: setParam("scope", "mcp:read"), elsewhere: true, code: oauthTarget,
			form: func(v url.Values) { v.Set("resource", resourceURL); v.Set("scope", "mcp:write") },
		},
	}
}

// TestTokenRefreshWithMoreThanTheGrant: a refresh that asks for a scope the grant
// does not hold (RFC 6749 section 6) or a resource that is not its (RFC 8707) is
// refused with invalid_scope or invalid_target, and nothing is rotated: the same
// refresh token, and the access token the client holds, still work. The refusal
// is the store's, from the write, so the handler never decides it from a read.
func TestTokenRefreshWithMoreThanTheGrant(t *testing.T) {
	t.Parallel()

	for name, tt := range refusedRefreshes() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			first := r.exchanged(tt.edit)

			if tt.elsewhere {
				r.store.rows[0].grant.Resource = otherResource(t)
			}

			rec := r.postForm(oauth.PathToken, withParams(refreshForm(first.refresh), tt.form))
			wantOAuthError(t, rec, http.StatusBadRequest, tt.code)

			r.store.rows[0].grant.Resource = mustProductionResource(t)

			if !r.active(first.access) {
				t.Error("the access token was replaced by a refresh that was refused")
			}

			second := wantTokens(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)))
			if second.refresh == first.refresh || second.scope != first.scope {
				t.Errorf("the refresh token that was refused was not good afterwards: %v", second.members)
			}
		})
	}
}

// mustProductionResource is the production resource.
func mustProductionResource(t *testing.T) input.ResourceID {
	t.Helper()

	id, err := input.ParseResourceID(resourceURL, productionTable())
	if err != nil {
		t.Fatal(err)
	}

	return id
}

// refreshCase is a refresh that succeeds.
type refreshCase struct {
	edit func(url.Values) // the authorization request
	form func(url.Values) // the refresh request

	// grant is the scope the grant holds, if it is not both resource scopes, and
	// want the scope the access token is issued with: the one asked for, or the
	// grant's.
	grant string
	want  string
}

// refreshes are the refreshes that succeed.
func refreshes() map[string]refreshCase {
	const both = "mcp:read mcp:write"

	return map[string]refreshCase{
		"nothing more, which is the grant's scope": {grant: both, want: both},
		"a scope equal to the grant's":             {form: setParam("scope", both), grant: both, want: both},
		"a scope that is narrower, which narrows the token": {
			form: setParam("scope", "mcp:read"), grant: both, want: "mcp:read",
		},
		"the other scope alone":    {form: setParam("scope", "mcp:write"), grant: both, want: "mcp:write"},
		"a scope in another order": {form: setParam("scope", "mcp:write mcp:read"), grant: both, want: "mcp:write mcp:read"},
		"a grant that asked for openid, and no scope": {
			edit:  func(v url.Values) { v.Set("scope", "openid mcp:read"); v.Set("nonce", "n") },
			grant: "openid mcp:read", want: "openid mcp:read",
		},
		"the openid scope, which the grant holds and which asks for no new ID token": {
			edit: setParam("scope", "openid mcp:read"), form: setParam("scope", "openid mcp:read"),
			grant: "openid mcp:read", want: "openid mcp:read",
		},
		"less than a grant that asked for openid": {
			edit: setParam("scope", "openid mcp:read"), form: setParam("scope", "mcp:read"),
			grant: "openid mcp:read", want: "mcp:read",
		},
		"the resource named": {form: setParam("resource", resourceURL), grant: both, want: both},
		"the resource named, and a scope of it": {
			form:  func(v url.Values) { v.Set("resource", resourceURL); v.Set("scope", "mcp:write") },
			grant: both, want: "mcp:write",
		},
		"parameters of the code grant, which are ignored": {
			form:  func(v url.Values) { v.Set("code", "x"); v.Set("code_verifier", "y"); v.Set("redirect_uri", "z") },
			grant: both, want: both,
		},
	}
}

// TestTokenRefresh: a refresh token is exchanged for the next pair, through the
// boundary. The store is given the refresh token's hash and the client, the scope
// and the resource that were asked for (nil when none was), and what was issued,
// at the one instant. The answer carries the access token's scope, which is the
// one asked for or the grant's, with no ID token whatever the grant asked for; and
// introspection of the new token reports the same scope. The old refresh token
// and access token stop at once.
func TestTokenRefresh(t *testing.T) {
	t.Parallel()

	for name, tt := range refreshes() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			first := r.exchanged(tt.edit)
			r.now = r.now.Add(10 * time.Minute)

			if first.scope != tt.grant {
				t.Fatalf("the grant holds %q, want %q", first.scope, tt.grant)
			}

			form := withParams(refreshForm(first.refresh), tt.form)
			second := wantTokens(t, r.postForm(oauth.PathToken, form))

			wantRefreshedPair(t, first, second, tt.want)
			wantRefreshCall(t, r, first, second)
			wantAsked(t, r.store.calls[len(r.store.calls)-1].refresh, form)

			if got := r.scopeOf(second.access); got != tt.want {
				t.Errorf("introspection reports scope %q, want %q", got, tt.want)
			}

			// The old refresh token is spent, once, and the old access token is replaced.
			wantOAuthError(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)), http.StatusBadRequest, oauthGrant)

			if !r.active(second.access) || r.active(first.access) {
				t.Error("the new access token is not live, or the old one still is")
			}
		})
	}
}

// wantRefreshedPair asserts the answer to a refresh: a new pair of the scope, an
// access token that lives its 900 seconds, and no ID token.
func wantRefreshedPair(t *testing.T, first, second tokenBody, scope string) {
	t.Helper()

	if _, hasID := second.members["id_token"]; hasID || len(second.members) != 5 || second.scope != scope ||
		wantInteger(t, "expires_in", second.members["expires_in"]) != 900 || second.access == first.access ||
		second.refresh == first.refresh {
		t.Errorf("refresh = %v after %v, want a new pair, scope %q, no ID token", second.members, first.members, scope)
	}
}

// scopeOf is the scope introspection reports for the access token.
func (r *rig) scopeOf(token string) string {
	r.t.Helper()

	rec := r.postForm(oauth.PathIntrospect, url.Values{"token": {token}, "resource": {resourceURL}})

	scope, _ := decodeNumbers(r.t, rec.Body.Bytes())["scope"].(string)

	return scope
}

// wantAsked asserts the refresh the store was given names the scope and the
// resource the request sent, as they were written, and none when it sent none.
func wantAsked(t *testing.T, got store.RefreshExchange, form url.Values) {
	t.Helper()

	gotScope, gotResource := "", ""
	if got.Scope != nil {
		gotScope = got.Scope.String()
	}

	if got.Resource != nil {
		gotResource = got.Resource.String()
	}

	if gotScope != form.Get("scope") || gotResource != form.Get("resource") {
		t.Errorf("the store was asked for scope %q and resource %q, want %q and %q",
			gotScope, gotResource, form.Get("scope"), form.Get("resource"))
	}
}

// wantRefreshCall asserts the store's last call was the refresh of first into second.
func wantRefreshCall(t *testing.T, r *rig, first, second tokenBody) {
	t.Helper()

	call := r.store.calls[len(r.store.calls)-1]
	wantToken, _ := input.ParseRefreshToken(first.refresh)
	wantClient, _ := input.ParseClientID(clientURL, productionTable())

	if call.op != opRefresh || call.refresh.Token != wantToken || call.refresh.ClientID != wantClient {
		t.Errorf("store call = %+v, want the refresh of the first token by %s", call, clientURL)
	}

	wantIssued(t, r, call, second)
}

// TestTokenRefreshIsBoundToTheClientAndTheKind: a refresh token under another client,
// and a token of another kind in its place, are invalid_grant, and the first is not
// spent.
func TestTokenRefreshIsBoundToTheClientAndTheKind(t *testing.T) {
	t.Parallel()

	t.Run("another client", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		first := r.exchanged(nil)

		wantOAuthError(t, r.postForm(oauth.PathToken,
			withParams(refreshForm(first.refresh), setParam("client_id", otherClientURL))), http.StatusBadRequest, oauthGrant)

		wantTokens(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)))
	})

	t.Run("an access token as the refresh token", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		first := r.exchanged(nil)

		wantOAuthError(t, r.postForm(oauth.PathToken, refreshForm(first.access)), http.StatusBadRequest, oauthGrant)
		wantTokens(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)))
	})

	t.Run("an account or an agent that was revoked", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		first := r.exchanged(nil)
		r.store.revokedAgents[newAgentID] = true

		wantOAuthError(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)), http.StatusBadRequest, oauthGrant)
	})
}

// TestTokenRefreshLifetime: a refresh token lasts 30 days from the exchange that
// issued it, to the second, so a grant that is used does not lapse.
func TestTokenRefreshLifetime(t *testing.T) {
	t.Parallel()

	t.Run("one second before it lapses, and then again", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		first := r.exchanged(nil)

		r.now = r.now.Add(auth.RefreshTokenLifetime - time.Second)
		second := wantTokens(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)))

		r.now = r.now.Add(auth.RefreshTokenLifetime - time.Second)
		wantTokens(t, r.postForm(oauth.PathToken, refreshForm(second.refresh)))
	})

	t.Run("at 30 days", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		first := r.exchanged(nil)

		r.now = r.now.Add(auth.RefreshTokenLifetime)
		wantOAuthError(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)), http.StatusBadRequest, oauthGrant)

		if !r.store.calls[len(r.store.calls)-1].now.Equal(r.now) {
			t.Error("the store was not given the request's instant")
		}
	})

	t.Run("it needs no signing key", func(t *testing.T) {
		t.Parallel()

		env := fullEnv()
		r := newRigWith(t, env)
		first := r.exchanged(nil)

		delete(env, config.SecretOAuthSigningKey)

		wantTokens(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)))
	})
}

// active reports whether the access token is live at the resource, asked as a
// resource server does.
func (r *rig) active(token string) bool {
	r.t.Helper()

	rec := r.postForm(oauth.PathIntrospect, url.Values{"token": {token}, "resource": {resourceURL}})
	if rec.Code != http.StatusOK {
		r.t.Fatalf("introspect = %d %s", rec.Code, rec.Body)
	}

	return decodeNumbers(r.t, rec.Body.Bytes())["active"] == true
}

// TestTokenNeedsTheSigningKey: the signing key is loaded for every code exchange
// before anything is issued or written, so a deployment without a valid key
// answers 503 and spends nothing: the code works once the key is there.
func TestTokenNeedsTheSigningKey(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"a missing key": "", "a key that is not base64url": "not a key!", "a key that is truncated": testSigningKey[:200],
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := fullEnv()
			r := newRigWith(t, env)
			code := r.approve(nil)

			env[config.SecretOAuthSigningKey] = value
			handedBefore := r.handed

			rec := r.postForm(oauth.PathToken, codeForm(code))

			wantOAuthError(t, rec, http.StatusServiceUnavailable, oauthUnavailble)

			body := rec.Body.String()
			if !strings.Contains(body, "the service is not configured") || strings.Contains(body, "OAUTH") {
				t.Errorf("body = %s, want the fixed text and no detail", body)
			}

			if len(r.store.calls) != 1 || r.handed != handedBefore {
				t.Errorf("store calls %d, ids %d -> %d: the request issued or wrote something",
					len(r.store.calls), handedBefore, r.handed)
			}

			env[config.SecretOAuthSigningKey] = testSigningKey

			wantTokens(t, r.postForm(oauth.PathToken, codeForm(code)))
		})
	}

	t.Run("a deployment that is not configured", func(t *testing.T) {
		t.Parallel()

		env := fullEnv()
		r := newRigWith(t, env)

		delete(env, config.SecretHMAC)

		wantOAuthError(t, r.postForm(oauth.PathToken, codeForm(tokenOf(t, secret.TagOAuthCode))),
			http.StatusServiceUnavailable, oauthUnavailble)
	})
}

// TestTokenEntropyFailure: a failure of the entropy source is the server's, and
// is told as server_error before the store is asked.
func TestTokenEntropyFailure(t *testing.T) {
	t.Parallel()

	forms := map[string]func() url.Values{
		"authorization_code": func() url.Values { return codeForm(tokenOf2(secret.TagOAuthCode)) },
		"refresh_token":      func() url.Values { return refreshForm(tokenOf2(secret.TagOAuthRefresh)) },
	}

	for name, reads := range map[string]int{"the refresh token": 0, "the access token": 1} {
		for grantType, form := range forms {
			t.Run(grantType+"/"+name, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				calls := 0
				r.entropy = readerFunc(func(p []byte) (int, error) {
					if calls == reads {
						return 0, errEntropy
					}

					calls++

					return len(p), nil
				})

				rec := r.postForm(oauth.PathToken, form())

				wantOAuthError(t, rec, http.StatusInternalServerError, oauthServer)

				if len(r.store.calls) != 0 || strings.Contains(rec.Body.String(), "entropy") {
					t.Errorf("store calls %d, body %s", len(r.store.calls), rec.Body)
				}
			})
		}
	}
}

// TestTokenAGrantThatDoesNotParse: what the store reports of a grant is read
// back through the parsers, and a value that no longer parses, or an ID token
// that cannot be signed, is the service's defect: server_error, and not a
// token the client could not use. (The code is spent by then: it is the one case
// where a client must start again, and it is a defect of the data.)
func TestTokenAGrantThatDoesNotParse(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*store.Exchanged){
		"a resource that is not in the table": func(g *store.Exchanged) { g.Resource = "https://gone.example.com/mcp" },
		"a scope that is not the resource's":  func(g *store.Exchanged) { g.Scope = "openid mcp:gone" },
		"an auth_time beyond what a client reads exactly": func(g *store.Exchanged) {
			g.AuthTime = time.Unix(1<<53, 0)
		},
	}

	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			code := r.approve(setParam("scope", "openid mcp:read"))
			r.store.edit = edit

			rec := r.postForm(oauth.PathToken, codeForm(code))

			wantOAuthError(t, rec, http.StatusInternalServerError, oauthServer)

			if strings.Contains(rec.Body.String(), "gone") || len(r.logged) != 1 {
				t.Errorf("body = %s, logged %v, want the fixed text and one logged failure", rec.Body, r.loggedCodes())
			}
		})
	}
}

// TestTokenScopeSpelling: a space in a scope is the same whether it is sent as a
// plus or as %20, and a plus sign that is meant is %2B, which no scope contains.
func TestTokenScopeSpelling(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		scope  string
		status int
	}{
		"a plus":              {"mcp%3Aread+mcp%3Awrite", http.StatusOK},
		"%20":                 {"mcp%3Aread%20mcp%3Awrite", http.StatusOK},
		"a literal colon":     {"mcp:read+mcp:write", http.StatusOK},
		"a fully encoded one": {url.QueryEscape("mcp:read") + "%20" + url.QueryEscape("mcp:write"), http.StatusOK},
		"an encoded plus":     {"mcp%3Aread%2Bmcp%3Awrite", http.StatusBadRequest},
		"a doubled plus":      {"mcp%3Aread++mcp%3Awrite", http.StatusBadRequest},
		"a trailing plus":     {"mcp%3Aread+", http.StatusBadRequest},
		"a leading %20":       {"%20mcp%3Aread", http.StatusBadRequest},
		"an encoded NUL":      {"mcp%3Aread%00", http.StatusBadRequest},
		"an invalid UTF-8":    {"mcp%3Aread%ff", http.StatusBadRequest},
		"a tab":               {"mcp%3Aread%09mcp%3Awrite", http.StatusBadRequest},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			first := r.exchanged(nil)

			rec := r.postRaw(oauth.PathToken, "grant_type=refresh_token&client_id="+url.QueryEscape(clientURL)+
				"&refresh_token="+first.refresh+"&scope="+tt.scope)

			if rec.Code != tt.status {
				t.Fatalf("= %d %q, want %d", rec.Code, rec.Body, tt.status)
			}

			if tt.status == http.StatusOK && wantTokens(t, rec).scope != first.scope {
				t.Errorf("scope = %q, want the grant's %q", wantTokens(t, rec).scope, first.scope)
			}
		})
	}
}

// TestTokenLifetimes pins the lifetimes that the clients rely on.
func TestTokenLifetimes(t *testing.T) {
	t.Parallel()

	if oauth.IDTokenLifetime != 5*time.Minute || auth.AccessTokenLifetime != 15*time.Minute ||
		auth.RefreshTokenLifetime != 30*24*time.Hour || auth.CodeLifetime != time.Minute {
		t.Errorf("lifetimes = %v %v %v %v",
			oauth.IDTokenLifetime, auth.AccessTokenLifetime, auth.RefreshTokenLifetime, auth.CodeLifetime)
	}
}

// TestTokenAccessLifetimeIsConsistent: the lifetime an access token is issued
// with, the expires_in the response states, and the exp and iat introspection
// reports are one number, whichever grant type issued it and at whatever
// fraction of a second. exp and iat are whole seconds, so a clock at x.999 truncates
// to x: iat is the second the request began in, and exp is exactly 900 seconds
// after it, up to one second before the token's real expiry and never after it.
func TestTokenAccessLifetimeIsConsistent(t *testing.T) {
	t.Parallel()

	const lifetime = int64(auth.AccessTokenLifetime / time.Second)

	grantTypes := map[string]func(r *rig, first tokenBody) tokenBody{
		"an exchange": func(r *rig, _ tokenBody) tokenBody { return r.exchanged(nil) },
		"a refresh": func(r *rig, first tokenBody) tokenBody {
			return wantTokens(t, r.postForm(oauth.PathToken, refreshForm(first.refresh)))
		},
	}

	fractions := map[string]time.Duration{
		"on the second":                 0,
		"a millisecond after":           time.Millisecond,
		"half a second after":           500 * time.Millisecond,
		"a millisecond before the next": 999 * time.Millisecond,
	}

	for grantName, issue := range grantTypes {
		for fractionName, fraction := range fractions {
			t.Run(grantName+" "+fractionName, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				first := r.exchanged(nil)

				r.now = r.now.Truncate(time.Second).Add(time.Minute + fraction)
				issuedAt := r.now

				issued := issue(r, first)

				got := decodeNumbers(t, r.postForm(oauth.PathIntrospect, introspectForm(issued.access, resourceURL)).Body.Bytes())
				iat, exp := wantInteger(t, "iat", got["iat"]), wantInteger(t, "exp", got["exp"])
				expiresIn := wantInteger(t, "expires_in", issued.members["expires_in"])

				if iat != issuedAt.Unix() {
					t.Errorf("iat = %d, want the second the request began in, %d", iat, issuedAt.Unix())
				}

				if exp-iat != lifetime || expiresIn != lifetime {
					t.Errorf("exp - iat = %d and expires_in = %d, want %d for both", exp-iat, expiresIn, lifetime)
				}

				// A whole-second exp is never later than the token's real expiry.
				if realExpiry := issuedAt.Add(auth.AccessTokenLifetime); time.Unix(exp, 0).After(realExpiry) {
					t.Errorf("exp = %s is after the real expiry %s", time.Unix(exp, 0).UTC(), realExpiry.UTC())
				}
			})
		}
	}
}
