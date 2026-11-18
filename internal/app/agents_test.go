package app_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/app"
)

const (
	agentPath = "/api/agent"
	agentID   = "00000000-0000-7000-8000-0000000000aa"
	agentItem = agentPath + "/" + agentID
)

// agentRoutes are the agent routes, one entry per method each takes, with a
// body that passes the handler's own validation, so what is under test is the
// wiring.
func agentRoutes() map[string]struct{ method, path, body string } {
	return map[string]struct{ method, path, body string }{
		caseList:   {http.MethodGet, agentPath, ""},
		"create":   {http.MethodPost, agentPath, `{"name":"x"}`},
		"get":      {http.MethodGet, agentItem, ""},
		"rename":   {http.MethodPatch, agentItem, `{"name":"y"}`},
		caseRevoke: {http.MethodDelete, agentItem, ""},
	}
}

// TestAgentRoutesAnswerTheirMethods checks the wiring of the two paths: the
// collection takes GET and POST, one agent takes GET, PATCH and DELETE, and
// anything else is a 405 whose Allow header names the methods.
func TestAgentRoutesAnswerTheirMethods(t *testing.T) {
	t.Parallel()

	paths := map[string]string{caseCollection: agentPath, caseItem: agentItem}
	allowed := map[string][]string{
		caseCollection: {http.MethodGet, http.MethodPost},
		caseItem:       {http.MethodDelete, http.MethodGet, http.MethodPatch},
	}

	for name, path := range paths {
		// Allow lists the methods sorted, so the expectation is built the same way.
		allow := strings.Join(allowed[name], ", ")

		for _, method := range []string{
			http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		} {
			t.Run(name+" "+method, func(t *testing.T) {
				t.Parallel()

				rec := httptest.NewRecorder()
				app.NewHandler(app.Platform{}).ServeHTTP(rec, newRequest(t, method, path, nil))

				if slices.Contains(allowed[name], method) {
					// With no database the route is found and answers 503 (or
					// 400 for a write with no body), never 404 or 405.
					if rec.Code == http.StatusMethodNotAllowed || rec.Code == http.StatusNotFound {
						t.Errorf("%s %s = %d, want it routed", method, path, rec.Code)
					}

					return
				}

				if got := rec.Header().Get("Allow"); rec.Code != http.StatusMethodNotAllowed || got != allow {
					t.Errorf("%s %s = %d, Allow = %q, want 405 and %q", method, path, rec.Code, got, allow)
				}
			})
		}
	}
}

// TestAgentRoutesWithoutADatabaseAreUnavailable: with no database (the host
// stub) every agent route answers 503, not a panic and not a 401.
func TestAgentRoutesWithoutADatabaseAreUnavailable(t *testing.T) {
	t.Parallel()

	for name, rt := range agentRoutes() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			app.NewHandler(app.Platform{Getenv: loginEnv}).
				ServeHTTP(rec, newRequest(t, rt.method, rt.path, strings.NewReader(rt.body)))

			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"agents_not_configured"`) {
				t.Errorf("%s = %d %s, want 503 agents_not_configured", name, rec.Code, rec.Body)
			}
		})
	}
}

// TestAgentRoutesRequireASession: with a database but no session cookie, every
// route is a 401.
func TestAgentRoutesRequireASession(t *testing.T) {
	t.Parallel()

	for name, rt := range agentRoutes() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			platform := app.Platform{DB: failingDB(t), Getenv: loginEnv}

			rec := httptest.NewRecorder()
			app.NewHandler(platform).ServeHTTP(rec, newRequest(t, rt.method, rt.path, strings.NewReader(rt.body)))

			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"unauthenticated"`) {
				t.Errorf("%s = %d %s, want 401 unauthenticated", name, rec.Code, rec.Body)
			}
		})
	}
}

// TestAgentWritesRequireJSON: POST, PATCH and DELETE change something, so they
// carry the CSRF defence; GET does not need a Content-Type.
func TestAgentWritesRequireJSON(t *testing.T) {
	t.Parallel()

	for _, rt := range []struct{ method, path string }{
		{http.MethodPost, agentPath}, {http.MethodPatch, agentItem}, {http.MethodDelete, agentItem},
	} {
		for _, contentType := range []string{"", "text/csv", "application/xml"} {
			t.Run(rt.method+" "+contentType, func(t *testing.T) {
				t.Parallel()

				req := httptest.NewRequestWithContext(t.Context(), rt.method, rt.path, nil)
				if contentType != "" {
					req.Header.Set("Content-Type", contentType)
				}

				rec := httptest.NewRecorder()
				app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, req)

				if rec.Code != http.StatusUnsupportedMediaType {
					t.Errorf("%s (%q) = %d %s, want 415", rt.method, contentType, rec.Code, rec.Body)
				}
			})
		}
	}

	rec := httptest.NewRecorder()
	app.NewHandler(app.Platform{Getenv: loginEnv}).
		ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, agentItem, nil))

	if rec.Code == http.StatusUnsupportedMediaType {
		t.Error("GET needed a Content-Type")
	}
}

// TestAgentItemNeedsExactlyOneSegment: a longer or empty id is not a route.
func TestAgentItemNeedsExactlyOneSegment(t *testing.T) {
	t.Parallel()

	for _, path := range []string{agentPath + "/", agentItem + "/extra", agentPath + "x"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, newRequest(t, http.MethodGet, path, nil))

			if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"not_found"`) {
				t.Errorf("GET %s = %d %s, want 404 not_found", path, rec.Code, rec.Body)
			}
		})
	}
}
