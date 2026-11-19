//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/oauth"
)

// The fixed descriptions that go with each code of the authorization endpoint.
// They are pinned here so a change to what a client is told is a visible one.
const (
	descInvalidRequest = "the request is missing a parameter, repeats one, or has one that is not valid"
	descInvalidScope   = "the scope is not valid for the resource"
	descInvalidTarget  = "the resource is missing or is not one this server issues tokens for"
	descUnsupported    = "the response type is not supported"
	descServerError    = "the server could not complete the request"
)

// wantUIError asserts that rec sent the browser to the UI's error page with
// exactly code, and never to the client: nothing of the client's, its host, its
// redirect URI or anything it sent, is in the location. The failure is logged
// once under the same code.
func wantUIError(t *testing.T, r *rig, rec *httptest.ResponseRecorder, code string) {
	t.Helper()

	location := rec.Header().Get("Location")

	if rec.Code != http.StatusFound || location != uiOrigin+"/oauth/error?error="+code {
		t.Errorf("= %d %q, want 302 to the UI's error page with %q", rec.Code, location, code)
	}

	if strings.Contains(location, clientHost) || strings.Contains(location, "127.0.0.1") {
		t.Errorf("the location %q holds something of the client's", location)
	}

	if rec.Body.Len() != 0 {
		t.Errorf("a redirect has a body %q", rec.Body)
	}

	if got := r.loggedCodes(); !slices.Equal(got, []string{code}) {
		t.Errorf("logged %v, want [%s]", got, code)
	}

	if len(r.store.calls) != 0 {
		t.Error("the request reached the store")
	}
}

// wantClientError asserts that rec sent the browser back to redirect with the
// error code, its fixed description, the issuer, and the state if one is given
// (and no state if not), and nothing else, with the existing query of redirect
// kept in front.
func wantClientError(
	t *testing.T, r *rig, rec *httptest.ResponseRecorder, redirect, code, description, state string,
) {
	t.Helper()

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (%s)", rec.Code, rec.Body)
	}

	location := rec.Header().Get("Location")
	want := url.Values{"error": {code}, "error_description": {description}, "iss": {apiOrigin}}

	if state != "" {
		want.Set("state", state)
	}

	if got := addedParams(t, location, redirect); !reflect.DeepEqual(got, want) {
		t.Errorf("added parameters = %v, want %v", got, want)
	}

	if strings.ContainsAny(location, " \t\r\n\"<>") {
		t.Errorf("location %q is not safe for a header", location)
	}

	if got := r.loggedCodes(); !slices.Equal(got, []string{code}) {
		t.Errorf("logged %v, want [%s]", got, code)
	}

	if len(r.store.calls) != 0 {
		t.Error("the request reached the store")
	}
}

// longURL is an https URL on the client's host with a path that makes the whole
// URL n bytes.
func longURL(n int) string {
	prefix := "https://" + clientHost + "/"

	return prefix + strings.Repeat("a", n-len(prefix))
}

// preTrust is one case of an authorization request that fails before its
// redirect URI is trusted.
type preTrust struct {
	// edit changes the parameters of a valid request, and raw replaces the whole
	// query string when it is set.
	edit func(url.Values)
	raw  string
	// answer replaces what the client's document URL serves, and cancelled sends
	// the request with a context that has already ended.
	answer    *fetchAnswer
	cancelled bool

	wantCode    string
	wantFetches int
}

// The codes of the errors before the redirect URI is trusted.
const (
	invalidRequest  = "invalid_request"
	invalidClient   = "invalid_client"
	invalidRedirect = "invalid_redirect_uri"
	unavailable     = "temporarily_unavailable"
)

// runPreTrust runs every case: each must be answered by a redirect to the UI's
// error page with its code and by nothing to the client, and must cost the
// number of fetches it says.
func runPreTrust(t *testing.T, tests map[string]preTrust) {
	t.Helper()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			if tt.answer != nil {
				r.net.answers[clientURL] = *tt.answer
			}

			params := authorizeParams()
			if tt.edit != nil {
				tt.edit(params)
			}

			target := oauth.PathAuthorize + "?" + params.Encode()
			if tt.raw != "" {
				target = oauth.PathAuthorize + "?" + strings.TrimSpace(tt.raw)
			}

			ctx := t.Context()

			if tt.cancelled {
				var cancel context.CancelFunc

				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			rec := r.serve(request{method: http.MethodGet, target: target, ctx: ctx})

			wantUIError(t, r, rec, tt.wantCode)

			// A cancelled request may or may not have started its fetch.
			if got := len(r.net.sent()); !tt.cancelled && got != tt.wantFetches {
				t.Errorf("fetched %d times, want %d", got, tt.wantFetches)
			}
		})
	}
}

// setParam is an edit that sets one parameter.
func setParam(name, value string) func(url.Values) {
	return func(v url.Values) { v.Set(name, value) }
}

// TestAuthorizeRefusesTheParametersOfTheClient: a missing or repeated client_id
// or redirect_uri, or a query that cannot be read, is an invalid_request, and
// costs no fetch: which of two values was meant cannot be known.
func TestAuthorizeRefusesTheParametersOfTheClient(t *testing.T) {
	t.Parallel()

	escaped := url.QueryEscape(clientURL)
	redirect := url.QueryEscape(redirectURL)

	runPreTrust(t, map[string]preTrust{
		"no parameters":      {raw: " ", wantCode: invalidRequest},
		"client_id missing":  {edit: func(v url.Values) { v.Del("client_id") }, wantCode: invalidRequest},
		"client_id empty":    {edit: setParam("client_id", ""), wantCode: invalidRequest},
		"client_id twice":    {edit: func(v url.Values) { v.Add("client_id", clientURL) }, wantCode: invalidRequest},
		"redirect_uri empty": {edit: setParam("redirect_uri", ""), wantCode: invalidRequest},
		"client_id twice, different": {
			edit:     func(v url.Values) { v.Add("client_id", "https://evil.example.com/x.json") },
			wantCode: invalidRequest,
		},
		"redirect_uri missing": {edit: func(v url.Values) { v.Del("redirect_uri") }, wantCode: invalidRequest},
		"redirect_uri twice": {
			edit: func(v url.Values) { v.Add("redirect_uri", redirectURL) }, wantCode: invalidRequest,
		},
		"redirect_uri twice, one is registered": {
			edit:     func(v url.Values) { v.Add("redirect_uri", "https://evil.example.com/cb") },
			wantCode: invalidRequest,
		},
		"a name repeated by its encoding": {
			raw:      "client_id=" + escaped + "&%63lient_id=" + escaped + "&redirect_uri=" + redirect,
			wantCode: invalidRequest,
		},
		"broken percent-encoding": {raw: "client_id=%zz&redirect_uri=" + redirect, wantCode: invalidRequest},
		"broken percent-encoding in an unknown parameter": {
			raw: "x=%zz&client_id=" + escaped + "&redirect_uri=" + redirect, wantCode: invalidRequest,
		},
		"NUL in the client_id": {raw: "client_id=a%00b&redirect_uri=" + redirect, wantCode: invalidRequest},
		"invalid UTF-8 in the redirect_uri": {
			raw: "client_id=" + escaped + "&redirect_uri=%ff", wantCode: invalidRequest,
		},
	})
}

// TestAuthorizeRefusesAClientIDThatCannotBeFetched: whatever is wrong with the
// client_id's spelling, it is an invalid_client before any fetch is made, so a
// request cannot make this server reach a name or an address it must not.
func TestAuthorizeRefusesAClientIDThatCannotBeFetched(t *testing.T) {
	t.Parallel()

	tests := map[string]preTrust{}

	for name, id := range map[string]string{ //nolint:gosec // the userinfo is a case: no credential
		"http":                    "http://client.example.com/c.json",
		"localhost in production": "http://localhost:9000/c.json",
		"an upper-case host":      "https://Client.example.com/c.json",
		"a query":                 clientURL + "?x=1",
		"a fragment":              clientURL + "#x",
		"userinfo":                "https://u:p@client.example.com/c.json",
		"an IPv4 host":            "https://127.0.0.1/c.json",
		"an IPv6 host":            "https://[::1]/c.json",
		"a decimal IP host":       "https://2130706433/c.json",
		"a reserved name":         "https://metadata.internal/c.json",
		"no path":                 "https://client.example.com",
		"the root path":           "https://client.example.com/",
		"a dot segment":           "https://client.example.com/a/../c.json",
		"an encoded dot":          "https://client.example.com/%2e%2e/c.json",
		"the default port":        "https://client.example.com:443/c.json",
		"a custom scheme":         "myapp://client/c.json",
		"javascript":              "javascript:alert(1)",
		"relative":                "/c.json",
		"one over the bound":      longURL(513),
		"a space":                 "https://client.example.com/a b.json",
		"not ASCII":               "https://client.example.com/\u00e9.json",
		"a backslash":             `https://client.example.com\.evil.com/c.json`,
	} {
		tests["client_id: "+name] = preTrust{edit: setParam("client_id", id), wantCode: invalidClient}
	}

	runPreTrust(t, tests)
}

// TestAuthorizeRefusesARedirectURIThatCannotBeOne: a redirect_uri that is not a
// valid redirect URI at all is an invalid_redirect_uri before the fetch, and the
// lookalikes of a registered one are among them.
func TestAuthorizeRefusesARedirectURIThatCannotBeOne(t *testing.T) {
	t.Parallel()

	tests := map[string]preTrust{}

	for name, uri := range map[string]string{
		"a custom scheme":      "myapp://cb",
		"javascript":           "javascript:alert(1)",
		"http, not loopback":   "http://client.example.com/callback",
		"https localhost":      "https://localhost/cb",
		"localhost lookalike":  "http://localhost.evil.example.com/cb",
		"upper-case localhost": "http://LOCALHOST/cb",
		"localhost userinfo":   "http://localhost@evil.example.com/cb",
		"localhost, port 80":   "http://localhost:80/cb",
		"https loopback":       "https://127.0.0.1/cb",
		"a fragment lookalike": "https://evil.example.com#@client.example.com",
		"userinfo":             "https://client.example.com@evil.example.com/callback",
		"a fragment":           redirectURL + "#x",
		"an upper-case host":   "https://Client.example.com/callback",
		"a loopback lookalike": "http://127.0.0.1.evil.example.com/cb",
		"the default port":     "https://client.example.com:443/callback",
		"a backslash":          `https://evil.example.com\@client.example.com/cb`,
		"one over the bound":   longURL(513),
		"relative":             "/callback",
	} {
		tests["redirect_uri: "+name] = preTrust{edit: setParam("redirect_uri", uri), wantCode: invalidRedirect}
	}

	runPreTrust(t, tests)
}

// TestAuthorizeRefusesARedirectURIThatIsNotRegistered: a redirect_uri that is
// valid and that the client's document does not list is refused after the
// document is fetched: the match is exact, except for the port of a loopback
// address, so no part of a registered URI may differ.
func TestAuthorizeRefusesARedirectURIThatIsNotRegistered(t *testing.T) {
	t.Parallel()

	tests := map[string]preTrust{}

	for name, uri := range map[string]string{
		"another host":                   "https://evil.example.com/callback",
		"a trailing slash":               redirectURL + "/",
		"another case in the path":       "https://client.example.com/Callback",
		"an added query":                 redirectURL + "?x=1",
		"another port":                   "https://client.example.com:8443/callback",
		"another path":                   "https://client.example.com/other",
		"a loopback of another path":     "http://127.0.0.1:5555/other",
		"the other loopback address":     "http://[::1]/cb",
		"localhost with another path":    "http://localhost:5555/other",
		"https for a registered http":    "https://client.example.com/cb",
		"a loopback with an added query": "http://127.0.0.1:5555/cb?x=1",
	} {
		tests["redirect_uri: "+name] = preTrust{
			edit: setParam("redirect_uri", uri), wantCode: invalidRedirect, wantFetches: 1,
		}
	}

	runPreTrust(t, tests)
}

// TestAuthorizeLoopbackHostsAreDistinct: localhost, 127.0.0.1 and [::1] are three
// hosts. A document that registers one admits that one on any port, and neither
// of the others, whichever way round: a client that registered only localhost
// (as MCP clients do) is served, and is not served at an address, and the reverse.
func TestAuthorizeLoopbackHostsAreDistinct(t *testing.T) {
	t.Parallel()

	hosts := map[string]string{"localhost": "localhost", "IPv4": "127.0.0.1", "IPv6": "[::1]"}
	refused := map[string]preTrust{}

	for registeredName, registered := range hosts {
		for askedName, asked := range hosts {
			answer := served(document(clientURL, "http://"+registered+":1234/cb"))
			redirect := setParam("redirect_uri", "http://"+asked+":5555/cb")

			if registeredName == askedName {
				t.Run("registered "+registeredName+", asked "+askedName, func(t *testing.T) {
					t.Parallel()

					r := newRig(t)
					r.net.answers[clientURL] = answer

					if text := r.pending(redirect); text == "" {
						t.Error("no pending request")
					}
				})

				continue
			}

			refused["registered "+registeredName+", asked "+askedName] = preTrust{
				edit: redirect, answer: &answer, wantCode: invalidRedirect, wantFetches: 1,
			}
		}
	}

	runPreTrust(t, refused)
}

// TestAuthorizeRefusesADocumentThatIsNotTheClients: a document that could not be
// fetched, or is not the client's, is an invalid_client, and one that could not
// be fetched in time, so that trying again may work, is
// temporarily_unavailable. Nothing it says is believed unless it is exactly the
// document of the client_id.
func TestAuthorizeRefusesADocumentThatIsNotTheClients(t *testing.T) {
	t.Parallel()

	member := `"client_id":"` + clientURL + `","client_name":"X"`
	registered := `"redirect_uris":["` + redirectURL + `"]`
	oversized := document(clientURL, redirectURL) + strings.Repeat(" ", 5*1024)

	tests := map[string]preTrust{
		"fetch: connection refused":   {answer: &fetchAnswer{err: errNet}, wantCode: unavailable, wantFetches: 1},
		"fetch: the caller went away": {cancelled: true, wantCode: unavailable},
	}

	for name, answer := range map[string]fetchAnswer{
		"fetch: 404":                  {status: 404, contentType: jsonType, body: "{}"},
		"fetch: 500":                  {status: 500, contentType: jsonType, body: "{}"},
		"fetch: a redirect":           {status: 302, contentType: jsonType, location: "https://evil.example.com/c.json"},
		"fetch: html":                 {status: 200, contentType: "text/html", body: document(clientURL, redirectURL)},
		"fetch: over 5 KiB":           {status: 200, contentType: jsonType, body: oversized},
		"document: not JSON":          {status: 200, contentType: jsonType, body: "<html>"},
		"document: another client_id": served(document("https://client.example.com/other.json", redirectURL)),
		"document: no redirect_uris":  served(`{` + member + `}`),
		"document: no name":           served(`{"client_id":"` + clientURL + `",` + registered + `}`),
		"document: a client secret":   served(`{` + member + `,"client_secret":"s",` + registered + `}`),
		"document: a shared-secret authentication method": served(
			`{` + member + `,"token_endpoint_auth_method":"client_secret_basic",` + registered + `}`),
		"document: a repeated member":       served(`{` + member + `,"client_name":"Y",` + registered + `}`),
		"document: an invalid redirect uri": served(document(clientURL, "myapp://cb")),
	} {
		tests[name] = preTrust{answer: &answer, wantCode: invalidClient, wantFetches: 1}
	}

	runPreTrust(t, tests)
}

// postTrust is one case of an authorization request that fails after its
// redirect URI is trusted.
type postTrust struct {
	edit        func(url.Values)
	raw         string
	wantCode    string
	description string
	wantState   string
}

// The state of a valid request, which is echoed in an error unless the case says
// it cannot be.
const sent = "xyz"

// invalid is a postTrust that is an invalid_request with the state echoed.
func invalid(edit func(url.Values)) postTrust {
	return postTrust{edit: edit, wantCode: invalidRequest, description: descInvalidRequest, wantState: sent}
}

// runPostTrust runs every case: each must be answered by a redirect to the
// client with its code, the fixed description, the issuer and the state it
// says, after exactly one fetch.
func runPostTrust(t *testing.T, tests map[string]postTrust) {
	t.Helper()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			params := authorizeParams()
			if tt.edit != nil {
				tt.edit(params)
			}

			target := oauth.PathAuthorize + "?" + params.Encode()
			if tt.raw != "" {
				target = oauth.PathAuthorize + "?" + tt.raw
			}

			rec := r.get(target)

			wantClientError(t, r, rec, redirectURL, tt.wantCode, tt.description, tt.wantState)

			if got := len(r.net.sent()); got != 1 {
				t.Errorf("fetched %d times, want 1", got)
			}
		})
	}
}

// TestAuthorizeRefusesTheResponseTypeAndPKCE: the response type is code, and the
// challenge is S256 of a verifier, with the method named: RFC 7636 reads an
// absent method as plain, which protects nothing, so absent and plain are both
// refused.
func TestAuthorizeRefusesTheResponseTypeAndPKCE(t *testing.T) {
	t.Parallel()

	unsupported := func(value string) postTrust {
		return postTrust{
			edit: setParam("response_type", value), wantCode: "unsupported_response_type",
			description: descUnsupported, wantState: sent,
		}
	}
	without := func(name string) postTrust { return invalid(func(v url.Values) { v.Del(name) }) }
	twice := func(name, value string) postTrust { return invalid(func(v url.Values) { v.Add(name, value) }) }
	set := func(name, value string) postTrust { return invalid(setParam(name, value)) }

	runPostTrust(t, map[string]postTrust{
		"response_type missing":    without("response_type"),
		"response_type token":      unsupported("token"),
		"response_type code token": unsupported("code token"),
		"response_type upper case": unsupported("CODE"),
		"response_type twice":      twice("response_type", "code"),

		"code_challenge missing":         without("code_challenge"),
		"code_challenge too short":       set("code_challenge", challengeVal[:42]),
		"code_challenge too long":        set("code_challenge", challengeVal+"A"),
		"code_challenge padded":          set("code_challenge", challengeVal[:42]+"="),
		"code_challenge standard base64": set("code_challenge", strings.Replace(challengeVal, "-", "+", 1)),
		"code_challenge last character":  set("code_challenge", challengeVal[:42]+"N"),
		"code_challenge twice":           twice("code_challenge", challengeVal),

		"method missing":    without("code_challenge_method"),
		"method plain":      set("code_challenge_method", "plain"),
		"method lower case": set("code_challenge_method", "s256"),
		"method other":      set("code_challenge_method", "S512"),
		"method twice":      twice("code_challenge_method", "S256"),
	})
}

// TestAuthorizeRefusesTheNonceResourceAndScope: the nonce, the resource and the
// scope are each held to their parsers. The resource is required, and exactly
// one of the table's, and a scope must name something of it.
func TestAuthorizeRefusesTheNonceResourceAndScope(t *testing.T) {
	t.Parallel()

	nonce := func(value string) postTrust { return invalid(setParam("nonce", value)) }
	target := func(edit func(url.Values)) postTrust {
		return postTrust{edit: edit, wantCode: "invalid_target", description: descInvalidTarget, wantState: sent}
	}
	scope := func(value string) postTrust {
		return postTrust{
			edit: setParam("scope", value), wantCode: "invalid_scope", description: descInvalidScope, wantState: sent,
		}
	}

	runPostTrust(t, map[string]postTrust{
		"nonce over the bound":           nonce(strings.Repeat("n", 129)),
		"nonce with a control character": nonce("a\x01b"),
		"nonce not ASCII":                nonce("\u00e9"),

		"resource missing":           target(func(v url.Values) { v.Del("resource") }),
		"resource unknown":           target(setParam("resource", "https://evil.example.com/mcp")),
		"resource trailing slash":    target(setParam("resource", resourceURL+"/")),
		"resource in another case":   target(setParam("resource", strings.ToUpper(resourceURL))),
		"resource of the dev table":  target(setParam("resource", "http://localhost:8788/mcp")),
		"resource twice":             invalid(func(v url.Values) { v.Add("resource", resourceURL) }),
		"scope unknown":              scope("mcp:admin"),
		"scope of authsu's own":      scope("agent:read"),
		"scope that is a bundle":     scope("default:user"),
		"scope only openid":          scope("openid"),
		"scope repeated":             scope(strings.Join([]string{"mcp:read", "mcp:read"}, " ")),
		"scope openid repeated":      scope(strings.Join([]string{"openid", "openid", "mcp:read"}, " ")),
		"scope with a double space":  scope("mcp:read  mcp:write"),
		"scope with a leading space": scope(" mcp:read"),
		"scope with a comma":         scope("mcp:read,mcp:write"),
		"scope in another case":      scope("MCP:READ"),
		"scope over the bound":       scope(strings.Repeat("a", 257)),
		"scope with an encoded plus": {
			raw: authorizeRaw("scope=mcp:read%2Bmcp:write"), wantCode: "invalid_scope",
			description: descInvalidScope, wantState: sent,
		},
		"scope twice": invalid(func(v url.Values) { v.Add("scope", "mcp:read"); v.Add("scope", "mcp:write") }),
	})
}

// TestAuthorizeEchoesOnlyAUsableState: the state goes back only if it parsed and
// was sent once, because what a parser refused must not go into a URL. Every
// other error reports it, and a repeated scope does not cost the client its
// state. The checks are made in a fixed order, so the first failure is the one
// reported.
func TestAuthorizeEchoesOnlyAUsableState(t *testing.T) {
	t.Parallel()

	spec := `a b&c=d?e#f%g+h"i\j<k>l`
	longState := strings.Repeat("s", 256)
	noState := func(edit func(url.Values)) postTrust {
		return postTrust{edit: edit, wantCode: invalidRequest, description: descInvalidRequest}
	}
	spoilt := func(edit func(url.Values), state string) postTrust {
		return postTrust{edit: edit, wantCode: invalidRequest, description: descInvalidRequest, wantState: state}
	}
	noType := func(v url.Values) { v.Del("response_type") }

	runPostTrust(t, map[string]postTrust{
		"state over the bound": noState(setParam("state", strings.Repeat("s", 257))),
		"state with a control": noState(setParam("state", "a\x01b")),
		"state not ASCII":      noState(setParam("state", "\u00e9")),
		"state twice":          noState(func(v url.Values) { v.Add("state", "second") }),
		"state with NUL": {
			raw: authorizeRaw("state=a%00b"), wantCode: invalidRequest, description: descInvalidRequest,
		},
		"no state to echo": noState(func(v url.Values) { v.Del("state"); noType(v) }),
		"state at the bound": spoilt(
			func(v url.Values) { v.Set("state", longState); noType(v) }, longState),
		"state with every reserved": spoilt(func(v url.Values) { v.Set("state", spec); noType(v) }, spec),
		"a repeated scope": spoilt(func(v url.Values) {
			v.Add("scope", "mcp:read")
			v.Add("scope", "mcp:read")
		}, sent),

		"response_type before the challenge": {
			edit:     func(v url.Values) { v.Set("response_type", "token"); v.Del("code_challenge") },
			wantCode: "unsupported_response_type", description: descUnsupported, wantState: sent,
		},
		"the challenge before the method": spoilt(func(v url.Values) {
			v.Del("code_challenge")
			v.Set("code_challenge_method", "plain")
		}, sent),
		"the resource before the scope": {
			edit:     func(v url.Values) { v.Del("resource"); v.Set("scope", "nope") },
			wantCode: "invalid_target", description: descInvalidTarget, wantState: sent,
		},
	})
}

// authorizeRaw is the query of a valid request with extra, a raw pair, in place
// of the parameter it names.
func authorizeRaw(extra string) string {
	name, _, _ := strings.Cut(extra, "=")
	params := authorizeParams()
	params.Del(name)

	return params.Encode() + "&" + extra
}

// TestAuthorizeErrorRedirectsKeepTheRegisteredQuery: the error goes to the
// redirect URI the client asked for, which the document registered, and the
// parameters are added to its query and never in place of it, for a redirect URI
// with no query, one with a query, and one that ends where a parameter would
// start. A loopback redirect keeps the port the client asked for.
func TestAuthorizeErrorRedirectsKeepTheRegisteredQuery(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		registered string
		asked      string
	}{
		"no query":             {redirectURL, redirectURL},
		"a query":              {redirectURL + "?tenant=a&x=1", redirectURL + "?tenant=a&x=1"},
		"ends with a question": {redirectURL + "?", redirectURL + "?"},
		"ends with an ampersand": {
			redirectURL + "?tenant=a&", redirectURL + "?tenant=a&",
		},
		"a query that holds a redirect": {
			redirectURL + "?next=https%3A%2F%2Fgood.example.com", redirectURL + "?next=https%3A%2F%2Fgood.example.com",
		},
		"a loopback with another port": {"http://127.0.0.1/cb", "http://127.0.0.1:5555/cb"},
		"a loopback with a port, registered with another": {
			"http://127.0.0.1:1234/cb", "http://127.0.0.1:5555/cb",
		},
		"an IPv6 loopback":             {"http://[::1]/cb", "http://[::1]:5555/cb"},
		"localhost, with another port": {"http://localhost/cb", "http://localhost:5555/cb"},
		"localhost, registered with a port": {
			"http://localhost:1234/cb", "http://localhost/cb",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			r.net.answers[clientURL] = served(document(clientURL, tt.registered))

			params := authorizeParams()
			params.Set("redirect_uri", tt.asked)
			params.Set("response_type", "token")

			rec := r.authorize(params)

			wantClientError(t, r, rec, tt.asked, "unsupported_response_type", descUnsupported, "xyz")
		})
	}
}

// TestAuthorizeServerFault: a failure of the server's own after the redirect
// URI is trusted (its entropy failing) is reported to the client as
// server_error, with the fixed description and never the cause, and the
// cause is in the log.
func TestAuthorizeServerFault(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	r.entropy = brokenReader{}

	rec := r.authorize(authorizeParams())

	wantClientError(t, r, rec, redirectURL, "server_error", descServerError, "xyz")

	if len(r.logged) != 1 || !strings.Contains(r.logged[0].Error(), errEntropy.Error()) {
		t.Errorf("the cause is not in the log: %v", r.logged)
	}

	if strings.Contains(rec.Header().Get("Location"), "broken") {
		t.Errorf("the location holds the cause: %s", rec.Header().Get("Location"))
	}
}

// pendingFields decodes the payload of a sealed request that the authorization
// endpoint sent the UI, after checking that it opens at now and not at its
// expiry.
func pendingFields(t *testing.T, r *rig, text string) map[string]any {
	t.Helper()

	sealed, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil {
		t.Fatalf("the request %q is not unpadded base64url: %v", text, err)
	}

	cfg := r.config()

	payload, err := challenge.OpenSealed(cfg.OAuthRequestKey, sealed, r.now, oauth.PendingLifetime)
	if err != nil {
		t.Fatalf("the sealed request does not open now: %v", err)
	}

	_, err = challenge.OpenSealed(cfg.OAuthRequestKey, sealed, r.now.Add(oauth.PendingLifetime), oauth.PendingLifetime)
	if err == nil {
		t.Error("the sealed request still opens at its lifetime")
	}

	_, err = challenge.OpenSealed(
		cfg.OAuthRequestKey, sealed, r.now.Add(oauth.PendingLifetime-1), oauth.PendingLifetime)
	if err != nil {
		t.Errorf("the sealed request does not open until its last second: %v", err)
	}

	var fields map[string]any

	err = json.Unmarshal(payload, &fields)
	if err != nil {
		t.Fatalf("the payload %q is not a JSON object: %v", payload, err)
	}

	return fields
}

// sealedCase is a case of an acceptable authorization request.
type sealedCase struct {
	env    map[string]string
	client string
	edit   func(url.Values)
	// payload is what the sealed payload holds beyond the members every request
	// has (wantPayload).
	payload map[string]any
}

// sealedCases are the acceptable requests, and what each seals.
func sealedCases() map[string]sealedCase {
	const (
		defaults = "mcp:read mcp:write"
		reserved = `a b&c=d?e#f%g+h"i\j<k>l`
	)

	return map[string]sealedCase{
		"the minimal request: the resource's default scope, no nonce": {
			edit:    func(v url.Values) { v.Del("state") },
			payload: map[string]any{"scope": defaults},
		},
		"every parameter": {
			edit:    func(v url.Values) { v.Set("nonce", "n-0S6_WzA2Mj"); v.Set("scope", "openid mcp:write") },
			payload: map[string]any{"scope": "openid mcp:write", "nonce": "n-0S6_WzA2Mj", "state": "xyz"},
		},
		"a single scope": {
			edit: setParam("scope", "mcp:read"), payload: map[string]any{"scope": "mcp:read", "state": "xyz"},
		},
		"scopes in the client's order": {
			edit:    setParam("scope", "mcp:write mcp:read"),
			payload: map[string]any{"scope": "mcp:write mcp:read", "state": "xyz"},
		},
		"a loopback redirect keeps the port that was asked for": {
			edit:    setParam("redirect_uri", "http://127.0.0.1:5555/cb"),
			payload: map[string]any{"scope": defaults, "state": "xyz", "redirectUri": "http://127.0.0.1:5555/cb"},
		},
		"a state with every reserved character": {
			edit: setParam("state", reserved), payload: map[string]any{"scope": defaults, "state": reserved},
		},
		"parameters this server does not know are ignored, repeated or not": {
			edit: func(v url.Values) {
				v.Add("prompt", "consent")
				v.Add("prompt", "login")
				v.Set("login_hint", "a@b.example")
			},
			payload: map[string]any{"scope": defaults, "state": "xyz"},
		},
		"the development deployment, and a localhost client": {
			env: devEnv(), client: "http://localhost:9000/client.json",
			edit: func(v url.Values) {
				v.Set("client_id", "http://localhost:9000/client.json")
				v.Set("redirect_uri", "http://127.0.0.1:9000/cb")
				v.Set("resource", "http://localhost:8788/mcp")
			},
			payload: map[string]any{
				"scope": defaults, "state": "xyz", "redirectUri": "http://127.0.0.1:9000/cb",
				"clientId": "http://localhost:9000/client.json", "resource": "http://localhost:8788/mcp",
			},
		},
	}
}

// TestAuthorizeSealsTheRequest: an acceptable request answers 302 to the UI's
// consent page with the parsed request sealed in the one query parameter, and
// the client's document was fetched once, by a GET that carried nothing but what
// is needed to ask for JSON. The payload holds exactly the values that parsed,
// the client's name, a random value and when it lapses, and nothing the client
// sent that this server does not use.
func TestAuthorizeSealsTheRequest(t *testing.T) {
	t.Parallel()

	for name, tt := range sealedCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := tt.env
			if env == nil {
				env = fullEnv()
			}

			r := newRigWith(t, env)

			if tt.client != "" {
				r.net.answers[tt.client] = served(document(tt.client, "http://127.0.0.1:9000/cb"))
			}

			params := authorizeParams()
			tt.edit(params)

			text := wantConsentRedirect(t, r, r.authorize(params))
			fields := pendingFields(t, r, text)

			wantPayload(t, r, fields, tt.payload)
			wantOneFetch(t, r, fmt.Sprint(fields["clientId"]))
		})
	}
}

// wantConsentRedirect asserts that rec sent the browser to the UI's consent page
// with exactly one query parameter, request, and that nothing was logged or
// written, and returns the request.
func wantConsentRedirect(t *testing.T, r *rig, rec *httptest.ResponseRecorder) string {
	t.Helper()

	to, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusFound || to.Scheme+"://"+to.Host != r.config().UI.String ||
		to.Path != "/oauth/consent" || len(to.Query()) != 1 || to.RawQuery != "request="+to.Query().Get("request") {
		t.Fatalf("= %d %q (%v), want 302 to the UI's consent page with one request parameter",
			rec.Code, rec.Header().Get("Location"), err)
	}

	if len(r.logged) != 0 || len(r.store.calls) != 0 {
		t.Errorf("logged %v, store calls %v", r.loggedCodes(), r.store.calls)
	}

	return to.Query().Get("request")
}

// wantOneFetch asserts that the client's document was fetched once, by a GET of
// url with only the headers that ask for JSON and no body.
func wantOneFetch(t *testing.T, r *rig, wantURL string) {
	t.Helper()

	sent := r.net.sent()
	if len(sent) != 1 {
		t.Fatalf("fetched %d times, want 1", len(sent))
	}

	req := sent[0]

	if req.Method != http.MethodGet || req.URL.String() != wantURL || (req.Body != nil && req.Body != http.NoBody) {
		t.Errorf("fetch = %s %s with a body %v, want a GET of %s", req.Method, req.URL, req.Body, wantURL)
	}

	if got := req.Header; len(got) != 1 || got.Get("Accept") != jsonType {
		t.Errorf("the fetch sent headers %v, want only Accept: application/json", got)
	}
}

// wantPayload asserts the sealed payload: the defaults every request shares,
// overridden by what a case says, the client's name, the lapse time, and a
// random value of 16 bytes.
func wantPayload(t *testing.T, r *rig, got, overrides map[string]any) {
	t.Helper()

	want := map[string]any{
		"clientId": clientURL, "clientName": clientName, "redirectUri": redirectURL,
		"codeChallenge": challengeVal, "resource": resourceURL,
		"expiresAt": float64(r.now.Add(oauth.PendingLifetime).Unix()),
	}

	maps.Copy(want, overrides)

	random, ok := got["random"].(string)
	if !ok {
		t.Fatalf("no random value in %v", got)
	}

	raw, err := base64.RawURLEncoding.Strict().DecodeString(random)
	if err != nil || len(raw) != 16 {
		t.Errorf("random = %q (%d bytes, %v), want 16 bytes of unpadded base64url", random, len(raw), err)
	}

	delete(got, "random")

	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload = %v\nwant      %v", got, want)
	}
}

// TestAuthorizeIsRandomised: two identical requests give two sealed values,
// because the value carries randomness; sealing is deterministic and a single
// use guard keyed on it would otherwise treat two requests as one.
func TestAuthorizeIsRandomised(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	first, second := r.pending(nil), r.pending(nil)

	if first == second {
		t.Errorf("two identical requests were sealed to the same value %s", first)
	}

	if len(first) != len(second) {
		t.Errorf("lengths differ: %d, %d", len(first), len(second))
	}
}

// TestAuthorizeTheWidestRequest: a request with every value at the largest its
// parser accepts, and the widest the worst case of JSON escaping can make them,
// is sealed, and its target can be opened: the bounds of the parsers fit the
// sealed payload and the consent page's URL.
func TestAuthorizeTheWidestRequest(t *testing.T) {
	t.Parallel()

	widestClient := longURL(512)
	widestRedirect := longURL(512)

	r := newRig(t)
	r.net.answers[widestClient] = served(document(widestClient, widestRedirect))

	params := authorizeParams()
	params.Set("client_id", widestClient)
	params.Set("redirect_uri", widestRedirect)
	params.Set("state", strings.Repeat(`"`, 256))
	params.Set("nonce", strings.Repeat(`\`, 128))
	params.Set("scope", "openid mcp:read mcp:write")

	text := r.pending(func(v url.Values) {
		for key := range v {
			v.Del(key)
		}

		maps.Copy(v, params)
	})

	fields := pendingFields(t, r, text)

	if fields["state"] != strings.Repeat(`"`, 256) || fields["nonce"] != strings.Repeat(`\`, 128) ||
		fields["clientId"] != widestClient || fields["redirectUri"] != widestRedirect {
		t.Errorf("the widest request did not survive sealing: %v", fields)
	}

	if len(text) > 8<<10 {
		t.Errorf("the request in the consent URL is %d bytes, over the query bound", len(text))
	}
}

// TestAuthorizeOverTheQueryBound: a query string over the route's bound is
// refused by the boundary, in the OAuth error format and before anything is
// fetched, as is one at the bound that is not what the route reads.
func TestAuthorizeOverTheQueryBound(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	rec := r.get(oauth.PathAuthorize + "?" + authorizeParams().Encode() + "&pad=" + strings.Repeat("a", oauth.MaxQuery))

	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"error":"invalid_request"`) {
		t.Errorf("= %d %s, want 413 in the OAuth error format", rec.Code, rec.Body)
	}

	if len(r.net.sent()) != 0 || len(r.store.calls) != 0 {
		t.Error("the request reached the network or the store")
	}
}

// TestAuthorizeNeedsNoCredentialAndSendsNone: the fetch carries no cookie and
// no Authorization header even when the request that caused it had both, and a
// credential on the authorization request changes nothing about the answer.
func TestAuthorizeNeedsNoCredentialAndSendsNone(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)

	rec := r.serve(request{
		method: http.MethodGet, target: oauth.PathAuthorize + "?" + authorizeParams().Encode(),
		cookies: []*http.Cookie{cookie}, authorization: "Bearer nonsense",
	})

	location := rec.Header().Get("Location")

	if rec.Code != http.StatusFound || !strings.HasPrefix(location, uiOrigin+"/oauth/consent?request=") {
		t.Errorf("= %d %q, want the consent page", rec.Code, location)
	}

	if len(r.net.sent()) != 1 {
		t.Fatalf("fetched %d times, want 1", len(r.net.sent()))
	}

	header := r.net.sent()[0].Header

	if header.Get("Cookie") != "" || header.Get("Authorization") != "" || len(r.net.sent()[0].Cookies()) != 0 {
		t.Errorf("the fetch carried a credential: %v", header)
	}
}
