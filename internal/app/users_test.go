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
	userPath = "/api/user"
	userID   = "00000000-0000-7000-8000-0000000000aa"
	userItem = userPath + "/" + userID
)

// userRoutes are the user routes, one entry per method each takes.
func userRoutes() []struct{ method, path string } {
	return []struct{ method, path string }{
		{http.MethodGet, userPath}, {http.MethodGet, userItem}, {http.MethodDelete, userItem},
	}
}

// TestUserRoutesAnswerTheirMethods checks the wiring of the two paths: the
// collection takes GET, one account takes GET and DELETE, and anything else is
// a 405 whose Allow header names the methods.
func TestUserRoutesAnswerTheirMethods(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path    string
		allowed []string
		allow   string
	}{
		"collection": {path: userPath, allowed: []string{http.MethodGet}, allow: "GET"},
		"item":       {path: userItem, allowed: []string{http.MethodGet, http.MethodDelete}, allow: "DELETE, GET"},
	}

	for name, tt := range tests {
		for _, method := range []string{
			http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		} {
			t.Run(name+" "+method, func(t *testing.T) {
				t.Parallel()

				rec := httptest.NewRecorder()
				app.NewHandler(app.Platform{}).ServeHTTP(rec, newRequest(t, method, tt.path, nil))

				if slices.Contains(tt.allowed, method) {
					// With no database the route is found and answers 503.
					if rec.Code == http.StatusMethodNotAllowed || rec.Code == http.StatusNotFound {
						t.Errorf("%s %s = %d, want it routed", method, tt.path, rec.Code)
					}

					return
				}

				if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != tt.allow {
					t.Errorf("%s %s = %d, Allow = %q, want 405 and %q",
						method, tt.path, rec.Code, rec.Header().Get("Allow"), tt.allow)
				}
			})
		}
	}
}

// TestUserRoutesWithoutADatabaseAreUnavailable: with no database (the host
// stub) every user route answers 503, not a panic and not a 401.
func TestUserRoutesWithoutADatabaseAreUnavailable(t *testing.T) {
	t.Parallel()

	for _, rt := range userRoutes() {
		name := rt.method + " " + rt.path

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, newRequest(t, rt.method, rt.path, nil))

			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"users_not_configured"`) {
				t.Errorf("%s = %d %s, want 503 users_not_configured", name, rec.Code, rec.Body)
			}
		})
	}
}

// TestUserRoutesRequireASession: with a database but no session cookie, every
// route is a 401.
func TestUserRoutesRequireASession(t *testing.T) {
	t.Parallel()

	for _, rt := range userRoutes() {
		name := rt.method + " " + rt.path

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			platform := app.Platform{DB: failingDB(t), Getenv: loginEnv}

			rec := httptest.NewRecorder()
			app.NewHandler(platform).ServeHTTP(rec, newRequest(t, rt.method, rt.path, nil))

			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"unauthenticated"`) {
				t.Errorf("%s = %d %s, want 401 unauthenticated", name, rec.Code, rec.Body)
			}
		})
	}
}

// TestUserRevokeRequiresJSON: DELETE changes something, so it carries the CSRF
// defence; GET does not need a Content-Type.
func TestUserRevokeRequiresJSON(t *testing.T) {
	t.Parallel()

	for _, contentType := range []string{"", "text/csv", "application/xml"} {
		t.Run(contentType, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, userItem, nil)
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}

			rec := httptest.NewRecorder()
			app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, req)

			if rec.Code != http.StatusUnsupportedMediaType {
				t.Errorf("DELETE (%q) = %d %s, want 415", contentType, rec.Code, rec.Body)
			}
		})
	}

	rec := httptest.NewRecorder()
	app.NewHandler(app.Platform{Getenv: loginEnv}).
		ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, userItem, nil))

	if rec.Code == http.StatusUnsupportedMediaType {
		t.Error("GET needed a Content-Type")
	}
}

// TestUserItemNeedsExactlyOneSegment: a longer or empty id is not a route.
func TestUserItemNeedsExactlyOneSegment(t *testing.T) {
	t.Parallel()

	for _, path := range []string{userPath + "/", userItem + "/extra", userPath + "x"} {
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
