package app_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/app"
)

// corsRoute is a path and one method it takes.
type corsRoute struct{ path, method string }

// corsRoutes are the API routes, one entry per method each takes.
func corsRoutes() []corsRoute {
	return []corsRoute{
		{"/healthz", http.MethodGet},
		{"/api/first-run", http.MethodGet},
		{beginPath, http.MethodPost}, {finishPath, http.MethodPost},
		{loginBeginPath, http.MethodPost}, {loginFinishPath, http.MethodPost},
		{sessionPath, http.MethodGet}, {logoutPath, http.MethodPost},
		{invitationPath, http.MethodGet}, {invitationPath, http.MethodPost},
		{invitationItem, http.MethodPatch}, {invitationItem, http.MethodDelete},
	}
}

// TestCORSAllowsOnlyTheRelyingPartyOrigin checks the wiring: the origin the UI
// runs passkey ceremonies from (UI_ORIGIN) may preflight and call every route
// from a browser, before routing would have answered an OPTIONS with 405, and
// no other origin can.
func TestCORSAllowsOnlyTheRelyingPartyOrigin(t *testing.T) {
	t.Parallel()

	for _, route := range corsRoutes() {
		path, method := route.path, route.method

		t.Run(method+" "+path, func(t *testing.T) {
			t.Parallel()

			handler := app.NewHandler(app.Platform{Getenv: registrationEnv})

			preflight := func(origin string) *httptest.ResponseRecorder {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, path, nil)
				req.Header.Set("Origin", origin)
				req.Header.Set("Access-Control-Request-Method", method)
				req.Header.Set("Access-Control-Request-Headers", "content-type")

				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				return rec
			}

			allowed := preflight(testOrigin)
			if allowed.Code != http.StatusNoContent ||
				allowed.Header().Get("Access-Control-Allow-Origin") != testOrigin ||
				allowed.Header().Get("Access-Control-Allow-Credentials") != "true" ||
				allowed.Header().Get("Access-Control-Allow-Methods") != method {
				t.Errorf("RP origin preflight = %d %v, want 204 allowing %s", allowed.Code, allowed.Header(), method)
			}

			refused := preflight("https://evil.example")
			if refused.Code < 400 {
				t.Errorf("foreign preflight = %d, want a refusal", refused.Code)
			}

			for name := range refused.Header() {
				if strings.HasPrefix(name, "Access-Control-") {
					t.Errorf("foreign preflight carries %s", name)
				}
			}
		})
	}
}

// TestCORSNeedsConfiguration: with no UI_ORIGIN, or no environment at all (the
// host stub), no origin is allowed.
func TestCORSNeedsConfiguration(t *testing.T) {
	t.Parallel()

	platforms := map[string]app.Platform{
		"no getenv":    {},
		"empty origin": {Getenv: func(string) string { return "" }},
	}

	for name, platform := range platforms {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/healthz", nil)
			req.Header.Set("Origin", testOrigin)
			req.Header.Set("Access-Control-Request-Method", http.MethodGet)

			rec := httptest.NewRecorder()
			app.NewHandler(platform).ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("= %d %v, want 405 with no CORS header", rec.Code, rec.Header())
			}
		})
	}
}

// TestCORSTrustsOnlyAWellFormedOrigin: a UI_ORIGIN that is not a bare origin
// allows nothing, even to a request that sends exactly that string. Otherwise a
// configuration slip such as "null" (which every sandboxed iframe and data: URL
// sends) or "*" would hand a hostile page credentialed, readable access.
func TestCORSTrustsOnlyAWellFormedOrigin(t *testing.T) {
	t.Parallel()

	malformed := []string{
		"null", "*", "example.com", "https://example.com/", "https://example.com/x", "http://example.com",
	}

	for _, configured := range malformed {
		t.Run(configured, func(t *testing.T) {
			t.Parallel()

			platform := app.Platform{Getenv: func(name string) string {
				if name == "UI_ORIGIN" {
					return configured
				}

				return ""
			}}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/healthz", nil)
			req.Header.Set("Origin", configured)
			req.Header.Set("Access-Control-Request-Method", http.MethodGet)

			rec := httptest.NewRecorder()
			app.NewHandler(platform).ServeHTTP(rec, req)

			for name := range rec.Header() {
				if strings.HasPrefix(name, "Access-Control-") {
					t.Errorf("UI_ORIGIN %q: response carries %s", configured, name)
				}
			}
		})
	}
}
