//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/oauth"
)

// corsHeaders returns the response's Access-Control-* header names.
func corsHeaders(header http.Header) []string {
	var names []string

	for name := range header {
		if strings.HasPrefix(name, "Access-Control-") {
			names = append(names, name)
		}
	}

	return names
}

// allowsOnly reports whether header answers a preflight by allowing origin,
// with credentials, for method alone and for the Content-Type header alone.
func allowsOnly(header http.Header, origin, method string) bool {
	return header.Get("Access-Control-Allow-Origin") == origin &&
		header.Get("Access-Control-Allow-Credentials") == "true" &&
		header.Get("Access-Control-Allow-Methods") == method &&
		header.Get("Access-Control-Allow-Headers") == "Content-Type"
}

// TestCORSPreflight: the origin the UI runs passkey ceremonies from may
// preflight every route of the API that has the credentialed policy (answered
// before routing, which would otherwise answer OPTIONS with 405), and no other
// origin gets any CORS header. A preflight never reaches the database.
func TestCORSPreflight(t *testing.T) {
	t.Parallel()

	for _, route := range inventory() {
		if route.public || route.noCORS {
			continue
		}

		t.Run(route.method+" "+pathPattern(route.path), func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullEnv())

			preflight := func(origin string) (int, http.Header) {
				rec := h.do(request{
					method: http.MethodOptions, path: route.path, noContentType: true,
					headers: map[string]string{
						"Origin":                         origin,
						"Access-Control-Request-Method":  route.method,
						"Access-Control-Request-Headers": "content-type",
					},
				})

				return rec.Code, rec.Header()
			}

			code, header := preflight(uiOrigin)
			if code != http.StatusNoContent || !allowsOnly(header, uiOrigin, route.method) {
				t.Errorf("UI origin preflight = %d %v, want 204 allowing %s", code, header, route.method)
			}

			for _, origin := range []string{
				"https://evil.example", apiOrigin, uiOrigin + ".evil.example", "null", "http://example.com", "HTTPS://EXAMPLE.COM",
			} {
				code, header := preflight(origin)
				if code < http.StatusBadRequest || len(corsHeaders(header)) != 0 {
					t.Errorf("origin %q preflight = %d %v, want a refusal with no CORS header", origin, code, header)
				}
			}

			if got := h.exec.callCount(); got != 0 {
				t.Errorf("Exec calls = %d, want 0", got)
			}
		})
	}
}

// TestCORSOnRealResponses: CORS is outermost, so even a failure that the
// auth boundary produced carries the headers the UI needs to read it, and a
// foreign origin's request gets none (and still the answer it would have had).
func TestCORSOnRealResponses(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		origin      string
		wantAllowed bool
	}{
		"the UI":      {origin: uiOrigin, wantAllowed: true},
		"a stranger":  {origin: "https://evil.example", wantAllowed: false},
		"no origin":   {origin: "", wantAllowed: false},
		"the API one": {origin: apiOrigin, wantAllowed: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullEnv())
			headers := map[string]string{}

			if tt.origin != "" {
				headers["Origin"] = tt.origin
			}

			rec := h.do(request{method: http.MethodGet, path: "/api/session", headers: headers})

			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("= %d %s, want the 401 whatever the origin", rec.Code, rec.Body)
			}

			header := rec.Header()
			if tt.wantAllowed {
				if header.Get("Access-Control-Allow-Origin") != tt.origin ||
					header.Get("Access-Control-Allow-Credentials") != "true" {
					t.Errorf("headers = %v, want the origin allowed with credentials", header)
				}
			} else if len(corsHeaders(header)) != 0 {
				t.Errorf("response carries %v", corsHeaders(header))
			}

			wantVary := tt.origin != ""
			if got := strings.Contains(rec.Header().Get("Vary"), "Origin"); got != wantVary {
				t.Errorf("Vary: Origin = %t, want %t", got, wantVary)
			}
		})
	}
}

// TestCORSTrustsOnlyAWellFormedOrigin: a UI_ORIGIN that is unset or is not a
// bare origin allows nothing, even to a request that sends exactly that string.
// Otherwise a configuration slip such as "null" (which every sandboxed iframe
// and data: URL sends) or "*" would hand a hostile page credentialed, readable
// access.
func TestCORSTrustsOnlyAWellFormedOrigin(t *testing.T) {
	t.Parallel()

	for _, configured := range []string{
		"", "null", "*", "example.com", "https://example.com/", "https://example.com/x",
		"http://example.com", "HTTPS://EXAMPLE.COM", "https://user@example.com", " https://example.com",
	} {
		t.Run("UI_ORIGIN="+configured, func(t *testing.T) {
			t.Parallel()

			env := fullEnv()
			env["UI_ORIGIN"] = configured
			h := newHarness(t, env)

			origin := configured
			if origin == "" {
				origin = uiOrigin
			}

			rec := h.do(request{
				method: http.MethodOptions, path: "/healthz", noContentType: true,
				headers: map[string]string{"Origin": origin, "Access-Control-Request-Method": http.MethodGet},
			})

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405 (the preflight is not answered)", rec.Code)
			}

			if names := corsHeaders(rec.Header()); len(names) != 0 {
				t.Errorf("UI_ORIGIN %q: response carries %v", configured, names)
			}
		})
	}
}

// TestCORSAllowsALocalhostUI: the development origin is a bare http origin on
// localhost, which is valid.
func TestCORSAllowsALocalhostUI(t *testing.T) {
	t.Parallel()

	const local = "http://localhost:3000"

	env := fullEnv()
	env["UI_ORIGIN"] = local
	h := newHarness(t, env)

	rec := h.do(request{
		method: http.MethodOptions, path: "/api/session", noContentType: true,
		headers: map[string]string{"Origin": local, "Access-Control-Request-Method": http.MethodGet},
	})

	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != local {
		t.Errorf("= %d %v, want 204 allowing %s", rec.Code, rec.Header(), local)
	}
}

// publicHeaders are the preflight headers of a call from origin.
func publicHeaders(origin, method string) map[string]string {
	headers := map[string]string{
		"Access-Control-Request-Method": method, "Access-Control-Request-Headers": "content-type",
	}

	if origin != "" {
		headers["Origin"] = origin
	}

	return headers
}

// TestCORSPublicPaths: the discovery documents, the key set and the token
// endpoints are called from a browser on any origin, without credentials: every
// origin, the UI's included, is answered with the wildcard and never with
// Allow-Credentials, so a page on another site reads what an anonymous visitor
// would. A preflight is answered for GET and POST and the one Content-Type
// header.
func TestCORSPublicPaths(t *testing.T) {
	t.Parallel()

	origins := []string{uiOrigin, "https://evil.example", apiOrigin, "null", "http://localhost:1234"}

	for _, path := range oauth.PublicPaths() {
		for _, origin := range origins {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				t.Run(method+" "+path+" from "+origin, func(t *testing.T) {
					t.Parallel()

					h := newHarness(t, fullEnv())
					rec := h.do(request{
						method: http.MethodOptions, path: path, noContentType: true,
						headers: publicHeaders(origin, method),
					})
					header := rec.Header()

					if rec.Code != http.StatusNoContent || header.Get("Access-Control-Allow-Origin") != "*" ||
						header.Get("Access-Control-Allow-Credentials") != "" ||
						header.Get("Access-Control-Allow-Methods") != method ||
						header.Get("Access-Control-Allow-Headers") != "Content-Type" {
						t.Errorf("= %d %v, want 204 allowing every origin without credentials", rec.Code, header)
					}

					if got := h.exec.callCount(); got != 0 {
						t.Errorf("Exec calls = %d, want 0", got)
					}
				})
			}
		}
	}
}

// TestCORSPublicPathsAllowOnlyGETAndPOST: a preflight on a public path is not
// answered for any other method.
func TestCORSPublicPathsAllowOnlyGETAndPOST(t *testing.T) {
	t.Parallel()

	for _, path := range oauth.PublicPaths() {
		for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
			t.Run(method+" "+path+" is not allowed", func(t *testing.T) {
				t.Parallel()

				h := newHarness(t, fullEnv())
				rec := h.do(request{
					method: http.MethodOptions, path: path, noContentType: true,
					headers: publicHeaders("https://evil.example", method),
				})

				if rec.Header().Get("Access-Control-Allow-Methods") != "" {
					t.Errorf("a preflight for %s was allowed: %v", method, rec.Header())
				}
			})
		}
	}
}

// TestCORSPublicResponses: a real response on a public path carries the wildcard
// and no credentials, whatever origin asked, the UI's included: a route is in
// exactly one policy.
func TestCORSPublicResponses(t *testing.T) {
	t.Parallel()

	for _, route := range inventory() {
		if !route.public {
			continue
		}

		for _, origin := range []string{"", uiOrigin, "https://evil.example"} {
			t.Run(route.path+" from "+origin, func(t *testing.T) {
				t.Parallel()

				h := newHarness(t, fullEnv())
				headers := map[string]string{}

				if origin != "" {
					headers["Origin"] = origin
				}

				rec := h.do(route.request(headers))
				header := rec.Header()

				if rec.Code != route.wantStatus || header.Get("Access-Control-Allow-Origin") != "*" ||
					header.Get("Access-Control-Allow-Credentials") != "" || header.Get("Vary") != "" {
					t.Errorf("= %d %v, want %d with the wildcard, no credentials and no Vary", rec.Code, header, route.wantStatus)
				}
			})
		}
	}
}

// TestCORSPrivatePathsNextToPublicOnes: a path that is not exactly one of the
// public paths or of the paths with no CORS keeps the credentialed policy: the
// pages of the UI's own API, and near-misses of the others. A stranger gets
// nothing, and the UI gets its credentialed answer, never the wildcard.
func TestCORSPrivatePathsNextToPublicOnes(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/api/oauth/request", "/api/oauth/consent", "/oauth/authorize/", "/oauth/introspect/", "/OAUTH/INTROSPECT",
		"/oauth/token/", "/OAUTH/TOKEN", "/oauth/token/x", "/.well-known/jwks.json/", "/.well-known/",
		"/.well-known/jwks.json.", "/.well-known/other", "/api/session",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullEnv())

			stranger := h.do(request{
				method: http.MethodOptions, path: path, noContentType: true,
				headers: publicHeaders("https://evil.example", http.MethodGet),
			})
			if stranger.Code < http.StatusBadRequest || len(corsHeaders(stranger.Header())) != 0 {
				t.Errorf("a stranger = %d %v, want a refusal with no CORS header", stranger.Code, stranger.Header())
			}

			ui := h.do(request{
				method: http.MethodOptions, path: path, noContentType: true,
				headers: publicHeaders(uiOrigin, http.MethodGet),
			})
			if ui.Code != http.StatusNoContent || !allowsOnly(ui.Header(), uiOrigin, http.MethodGet) {
				t.Errorf("the UI = %d %v, want its credentialed answer", ui.Code, ui.Header())
			}
		})
	}
}

// TestCORSPolicySetsMatchTheRoutes: the sets the app passes are exactly the routes
// the inventory marks, so a route is in one policy and the tests above cover each
// one that is in a set. A path is never in both.
func TestCORSPolicySetsMatchTheRoutes(t *testing.T) {
	t.Parallel()

	var public, none []string

	for _, route := range inventory() {
		if route.public && route.noCORS {
			t.Errorf("%s %s is marked both public and with no CORS", route.method, route.path)
		}

		if route.public && !slices.Contains(public, route.path) {
			public = append(public, route.path)
		}

		if route.noCORS && !slices.Contains(none, route.path) {
			none = append(none, route.path)
		}
	}

	wantPublic := slices.Sorted(slices.Values(oauth.PublicPaths()))
	if got := slices.Sorted(slices.Values(public)); !slices.Equal(got, wantPublic) {
		t.Errorf("public routes %v, want PublicPaths %v", got, wantPublic)
	}

	wantNone := slices.Sorted(slices.Values(oauth.NoCORSPaths()))
	if got := slices.Sorted(slices.Values(none)); !slices.Equal(got, wantNone) {
		t.Errorf("routes with no CORS %v, want NoCORSPaths %v", got, wantNone)
	}
}

// TestCORSNoCORSPaths: the authorization endpoint and introspection are navigated
// to or called by servers, so they answer no origin with any CORS header, the
// UI's included, on a real response or on a preflight. A preflight is not
// answered as allowed (it is the route's own 405), and never reaches the database,
// so a script on any page cannot read either, with or without the user's cookies.
func TestCORSNoCORSPaths(t *testing.T) {
	t.Parallel()

	origins := []string{uiOrigin, "https://evil.example", apiOrigin, "null", ""}

	for _, route := range inventory() {
		if !route.noCORS {
			continue
		}

		for _, origin := range origins {
			t.Run("preflight "+route.path+" from "+origin, func(t *testing.T) {
				t.Parallel()

				wantNoCORSPreflight(t, route, origin)
			})

			t.Run("response "+route.path+" from "+origin, func(t *testing.T) {
				t.Parallel()

				wantNoCORSResponse(t, route, origin)
			})
		}
	}
}

// wantNoCORSPreflight asserts a preflight of the route from origin is the route's
// own 405 with no CORS header, and never reaches the database.
func wantNoCORSPreflight(t *testing.T, route inventoryRoute, origin string) {
	t.Helper()

	h := newHarness(t, fullEnv())
	headers := map[string]string{
		"Access-Control-Request-Method": route.method, "Access-Control-Request-Headers": "content-type",
	}

	if origin != "" {
		headers["Origin"] = origin
	}

	rec := h.do(request{method: http.MethodOptions, path: route.path, noContentType: true, headers: headers})

	if rec.Code != http.StatusMethodNotAllowed || len(corsHeaders(rec.Header())) != 0 || rec.Header().Get("Vary") != "" {
		t.Errorf("= %d %v, want the route's 405 with no CORS header and no Vary", rec.Code, rec.Header())
	}

	if got := h.exec.callCount(); got != 0 {
		t.Errorf("Exec calls = %d, want 0", got)
	}
}

// wantNoCORSResponse asserts the real response of the route to origin has no CORS
// header and no Vary.
func wantNoCORSResponse(t *testing.T, route inventoryRoute, origin string) {
	t.Helper()

	h := newHarness(t, fullEnv())
	headers := map[string]string{}

	if origin != "" {
		headers["Origin"] = origin
	}

	rec := h.do(route.request(headers))

	if rec.Code != route.wantStatus || len(corsHeaders(rec.Header())) != 0 || rec.Header().Get("Vary") != "" {
		t.Errorf("= %d %v, want %d with no CORS header and no Vary", rec.Code, rec.Header(), route.wantStatus)
	}
}
