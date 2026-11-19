package httpapi_test

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

// publicPaths is the set the app will pass: the paths with no credentials.
func publicPaths() []string {
	return []string{
		pathMetadata, "/.well-known/openid-configuration", pathJWKS,
		pathExchange, pathRevoke,
	}
}

// noCORSPaths is the other set the app will pass: the paths that are navigated
// to or called by servers, and get no CORS at all.
func noCORSPaths() []string { return []string{pathAuth, pathIntrospect} }

// corsPaths is both sets, as the app passes them.
func corsPaths() httpapi.CORSPaths {
	return httpapi.CORSPaths{Public: publicPaths(), None: noCORSPaths()}
}

// corsBoth is every route the tests ask about, behind CORS with both sets: the
// public ones, the ones with no CORS, look-alikes of them and private ones, each
// answering GET and POST.
func corsBoth(allowed string) http.Handler {
	mux := http.NewServeMux()
	ok := respond(httpapi.JSON(http.StatusOK, 1))
	logger := func(httpapi.Request, *apierr.Error) {}
	others := []string{pathExchangeDir, "/oauth/token/x", "/oauth", "/x", "/OAUTH/TOKEN", pathAuthDir}

	for _, path := range slices.Concat(publicPaths(), noCORSPaths(), others) {
		mux.Handle(path, serveMethods(logger, nil, map[string]httpapi.Handler{http.MethodGet: ok, http.MethodPost: ok}))
	}

	return httpapi.CORS(func() string { return allowed }, corsPaths(), mux)
}

// corsOutcome is what a request to a path from an origin gets.
type corsOutcome struct {
	path, origin string
	allowOrigin  string
	allowCreds   string
	vary         []string
}

// corsOutcomeOf builds a corsOutcome.
func corsOutcomeOf(path, origin, allowOrigin, allowCreds string, vary ...string) corsOutcome {
	return corsOutcome{path, origin, allowOrigin, allowCreds, vary}
}

func corsPublicCases() map[string]corsOutcome {
	const (
		star = "*"
		none = ""
	)

	return map[string]corsOutcome{
		"public, a stranger":      corsOutcomeOf(pathExchange, evilOrigin, star, none),
		"public, the UI origin":   corsOutcomeOf(pathExchange, uiOrigin, star, none),
		"public, no origin":       corsOutcomeOf(pathExchange, "", star, none),
		"public, the null origin": corsOutcomeOf(pathExchange, nullOrigin, star, none),
		"revoke":                  corsOutcomeOf(pathRevoke, evilOrigin, star, none),
		"metadata":                corsOutcomeOf(pathMetadata, evilOrigin, star, none),
		"openid configuration":    corsOutcomeOf("/.well-known/openid-configuration", evilOrigin, star, none),
		"jwks":                    corsOutcomeOf(pathJWKS, evilOrigin, star, none),
		"private, the UI origin":  corsOutcomeOf("/x", uiOrigin, uiOrigin, credsTrue, originName),
		"private, a stranger":     corsOutcomeOf("/x", evilOrigin, none, none, originName),
		"private, no origin":      corsOutcomeOf("/x", "", none, none),
		// A path with no CORS gets no header of any kind, the UI origin's too, and
		// no Vary because the answer does not depend on the origin.
		"authorize, a stranger":                corsOutcomeOf(pathAuth, evilOrigin, none, none),
		"authorize, the UI origin":             corsOutcomeOf(pathAuth, uiOrigin, none, none),
		"authorize, no origin":                 corsOutcomeOf(pathAuth, "", none, none),
		"authorize, the null origin":           corsOutcomeOf(pathAuth, nullOrigin, none, none),
		"introspect, a stranger":               corsOutcomeOf(pathIntrospect, evilOrigin, none, none),
		"introspect, the UI origin":            corsOutcomeOf(pathIntrospect, uiOrigin, none, none),
		"introspect, no origin":                corsOutcomeOf(pathIntrospect, "", none, none),
		"authorize look-alike":                 corsOutcomeOf(pathAuthDir, uiOrigin, uiOrigin, credsTrue, originName),
		"authorize with a query":               corsOutcomeOf(pathAuth+"?x=/x", uiOrigin, none, none),
		"trailing slash is another path":       corsOutcomeOf(pathExchangeDir, evilOrigin, none, none, originName),
		"a sub-path is another path":           corsOutcomeOf("/oauth/token/x", evilOrigin, none, none, originName),
		"a prefix is another path":             corsOutcomeOf("/oauth", evilOrigin, none, none, originName),
		"another case is another path":         corsOutcomeOf("/OAUTH/TOKEN", evilOrigin, none, none, originName),
		"a look-alike keeps the UI policy":     corsOutcomeOf(pathExchangeDir, uiOrigin, uiOrigin, credsTrue, originName),
		"a query string is not part of a path": corsOutcomeOf(pathExchange+"?x=/oauth/revoke", evilOrigin, star, none),
	}
}

// TestCORSPublicPolicy: on a public path every origin, and none, gets
// Allow-Origin: * and never credentials, even the UI's origin, which on any
// other path is the one origin that gets credentials; on a path with no CORS
// nobody, the UI's origin included, gets any header; and a path outside the sets
// (a look-alike, a prefix, a sibling) keeps the credentialed policy exactly. The
// sets are matched as whole strings.
func TestCORSPublicPolicy(t *testing.T) {
	t.Parallel()

	for name, tt := range corsPublicCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil)
			if tt.origin != "" {
				req.Header.Set(originName, tt.origin)
			}

			rec := httptest.NewRecorder()
			corsBoth(uiOrigin).ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}

			if got := rec.Header().Get(allowOrigin); got != tt.allowOrigin {
				t.Errorf("Allow-Origin = %q, want %q", got, tt.allowOrigin)
			}

			if got := rec.Header().Get(allowCreds); got != tt.allowCreds {
				t.Errorf("Allow-Credentials = %q, want %q", got, tt.allowCreds)
			}

			if got := rec.Header().Values("Vary"); !slices.Equal(got, tt.vary) {
				t.Errorf("Vary = %v, want %v", got, tt.vary)
			}
		})
	}
}

// preflightCase is a preflight and what it is answered with.
type preflightCase struct {
	path, origin, method, requested string
	wantStatus                      int
	want                            map[string]string
	wantAbsent                      []string
}

const star = "*"

// publicPreflight is a preflight that a public path answers for origin.
func publicPreflight(path, origin, method, requested string, methods, headers string) preflightCase {
	want := map[string]string{allowOrigin: star}
	absent := []string{allowCreds}

	for header, value := range map[string]string{allowMethods: methods, allowHeaders: headers} {
		if value == "" {
			absent = append(absent, header)
		} else {
			want[header] = value
		}
	}

	return preflightCase{path, origin, method, requested, http.StatusNoContent, want, absent}
}

// refusedPreflight is a preflight that falls through to the route, which answers 405.
func refusedPreflight(path, origin, method string) preflightCase {
	return preflightCase{
		path, origin, method, lowerCT, http.StatusMethodNotAllowed, map[string]string{},
		[]string{allowOrigin, allowMethods, allowCreds},
	}
}

func preflightCases() map[string]preflightCase {
	post, get := http.MethodPost, http.MethodGet

	return map[string]preflightCase{
		"public POST from a stranger":    publicPreflight(pathExchange, evilOrigin, post, lowerCT, post, contentType),
		"public POST from the UI origin": publicPreflight(pathExchange, uiOrigin, post, lowerCT, post, contentType),
		"public GET":                     publicPreflight(pathJWKS, evilOrigin, get, "", get, contentType),
		"public DELETE is refused":       publicPreflight(pathRevoke, evilOrigin, http.MethodDelete, "", "", contentType),
		"public PATCH is refused":        publicPreflight(pathRevoke, evilOrigin, http.MethodPatch, "", "", contentType),
		"public PUT is refused":          publicPreflight(pathExchange, evilOrigin, http.MethodPut, "", "", contentType),
		"public with the Authorization header is refused": publicPreflight(
			pathExchange, evilOrigin, post, "content-type, authorization", post, ""),
		"public with a custom header is refused": publicPreflight(pathExchange, evilOrigin, post, "x-evil", post, ""),
		"private from the UI origin": {
			"/x", uiOrigin, post, lowerCT, http.StatusNoContent,
			map[string]string{
				allowOrigin: uiOrigin, allowCreds: credsTrue, allowMethods: post, allowHeaders: contentType,
			}, nil,
		},
		"private from a stranger": refusedPreflight("/x", evilOrigin, post),
		// A path with no CORS answers no preflight, for the UI's origin either: the
		// preflight falls through to the route, which answers 405 with no header.
		"authorize from a stranger":            refusedPreflight(pathAuth, evilOrigin, get),
		"authorize from the UI origin":         refusedPreflight(pathAuth, uiOrigin, get),
		"authorize, a POST from the UI origin": refusedPreflight(pathAuth, uiOrigin, post),
		"introspect from a stranger":           refusedPreflight(pathIntrospect, evilOrigin, post),
		"introspect from the UI origin":        refusedPreflight(pathIntrospect, uiOrigin, post),
		"a look-alike of authorize, the UI origin": {
			pathAuthDir, uiOrigin, get, lowerCT, http.StatusNoContent,
			map[string]string{allowOrigin: uiOrigin, allowCreds: credsTrue, allowMethods: get, allowHeaders: contentType}, nil,
		},
		"a look-alike path from a stranger": refusedPreflight(pathExchangeDir, evilOrigin, post),
	}
}

// TestCORSPublicPreflight: a preflight on a public path is answered for any
// origin, for GET and POST and the Content-Type header only, with no
// credentials; on a private path it is answered for the UI origin alone, as
// before; on a path with no CORS it is answered for nobody.
func TestCORSPublicPreflight(t *testing.T) {
	t.Parallel()

	for name, tt := range preflightCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, tt.path, nil)
			req.Header.Set(originName, tt.origin)
			req.Header.Set("Access-Control-Request-Method", tt.method)

			if tt.requested != "" {
				req.Header.Set("Access-Control-Request-Headers", tt.requested)
			}

			rec := httptest.NewRecorder()
			corsBoth(uiOrigin).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			for _, header := range slices.Sorted(maps.Keys(tt.want)) {
				if got := rec.Header().Get(header); got != tt.want[header] {
					t.Errorf("%s = %q, want %q", header, got, tt.want[header])
				}
			}

			for _, header := range tt.wantAbsent {
				if got := rec.Header().Values(header); len(got) != 0 {
					t.Errorf("%s = %v, want absent", header, got)
				}
			}
		})
	}
}

// TestCORSPublicBareOptionsIsNotAPreflight: an OPTIONS that names no method
// falls through to the route (405) and still carries Allow-Origin: *.
func TestCORSPublicBareOptionsIsNotAPreflight(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, pathExchange, nil)
	req.Header.Set(originName, evilOrigin)

	rec := httptest.NewRecorder()
	corsBoth(uiOrigin).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get(allowMethods) != "" {
		t.Errorf("status = %d, Allow-Methods = %q", rec.Code, rec.Header().Get(allowMethods))
	}

	if got := rec.Header().Get(allowOrigin); got != star {
		t.Errorf("Allow-Origin = %q, want *", got)
	}
}

// TestCORSPublicPolicyNeedsNoConfiguration: the public policy does not depend on
// UI_ORIGIN, so a deployment with none still serves discovery to browsers; and
// an empty set makes every path credentialed.
func TestCORSPublicPolicyNeedsNoConfiguration(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, pathExchange, nil)
	req.Header.Set(originName, evilOrigin)

	rec := httptest.NewRecorder()
	corsBoth("").ServeHTTP(rec, req)

	if got := rec.Header().Get(allowOrigin); got != star {
		t.Errorf("Allow-Origin = %q, want *", got)
	}

	mux := http.NewServeMux()
	handler := serve(http.MethodGet, func(httpapi.Request, *apierr.Error) {}, respond(httpapi.JSON(http.StatusOK, 1)))
	mux.Handle(pathExchange, handler)

	rec = httptest.NewRecorder()
	httpapi.CORS(func() string { return uiOrigin }, httpapi.CORSPaths{}, mux).ServeHTTP(rec, req)

	if got := rec.Header().Get(allowOrigin); got != "" {
		t.Errorf("with no public paths Allow-Origin = %q, want none", got)
	}
}

// TestCORSPublicResponsesAreNotCredentialed: a public response, a failure
// included, is readable by script from any origin and carries nothing that
// would let a credentialed one read it.
func TestCORSPublicResponsesAreNotCredentialed(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathExchange, strings.NewReader(""))
	req.Header.Set(originName, uiOrigin)
	req.Header.Set("Content-Type", formType) // the JSON-only route below refuses it: a failure

	rec := httptest.NewRecorder()
	corsBoth(uiOrigin).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}

	if got := corsHeaders(rec); !slices.Equal(got, []string{allowOrigin}) {
		t.Errorf("CORS headers = %v, want only Allow-Origin", got)
	}
}

// TestCORSNoPolicyAnswersNoHeaderOfAnyKind: on a path with no CORS the real
// response, a failure included, carries no header that starts with Access-Control-
// and no Vary, whatever the origin and with the UI's configured or not.
func TestCORSNoPolicyAnswersNoHeaderOfAnyKind(t *testing.T) {
	t.Parallel()

	for _, path := range noCORSPaths() {
		for _, allowed := range []string{uiOrigin, ""} {
			allowing := "allowing " + allowed
			if allowed == "" {
				allowing = "UI unset"
			}

			for _, origin := range []string{"", uiOrigin, evilOrigin, nullOrigin} {
				from := "from " + origin
				if origin == "" {
					from = "no origin"
				}

				for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
					t.Run(path+" "+method+" "+from+" "+allowing, func(t *testing.T) {
						t.Parallel()

						req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(""))
						req.Header.Set("Content-Type", formType) // the JSON-only route refuses a POST: a failure
						req.Header.Set("Access-Control-Request-Method", http.MethodPost)

						if origin != "" {
							req.Header.Set(originName, origin)
						}

						rec := httptest.NewRecorder()
						corsBoth(allowed).ServeHTTP(rec, req)

						if got := corsHeaders(rec); len(got) != 0 || len(rec.Header().Values("Vary")) != 0 {
							t.Errorf("= %d with CORS headers %v and Vary %v, want none", rec.Code, got, rec.Header().Values("Vary"))
						}
					})
				}
			}
		}
	}
}

// TestCORSAPathInTwoPoliciesPanics: a route is in exactly one policy, and a set
// that says otherwise is refused when the handler is built, not when a request
// arrives.
func TestCORSAPathInTwoPoliciesPanics(t *testing.T) {
	t.Parallel()

	tests := map[string]httpapi.CORSPaths{
		"one path in both":      {Public: []string{pathExchange, pathAuth}, None: []string{pathAuth}},
		"a path twice in one":   {Public: []string{pathExchange, pathExchange}},
		"a path twice in none":  {None: []string{pathAuth, pathAuth}},
		"the same, many others": {Public: publicPaths(), None: append(noCORSPaths(), pathRevoke)},
	}

	for name, paths := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				got := recover()

				text, _ := got.(string)
				if !strings.Contains(text, "more than one policy") {
					t.Errorf("recovered %v, want the panic that names a path in more than one policy", got)
				}
			}()

			httpapi.CORS(func() string { return uiOrigin }, paths, http.NewServeMux())
		})
	}
}
