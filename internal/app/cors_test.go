//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
	"net/http"
	"strings"
	"testing"
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
// preflight every route of the API (answered before routing, which would
// otherwise answer OPTIONS with 405), and no other origin gets any CORS header.
// A preflight never reaches the database.
func TestCORSPreflight(t *testing.T) {
	t.Parallel()

	for _, route := range inventory() {
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
