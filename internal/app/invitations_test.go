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
	invitationPath = "/api/invitation"
	invitationID   = "00000000-0000-7000-8000-0000000000aa"
	invitationItem = invitationPath + "/" + invitationID
)

// TestInvitationRoutesAnswerTheirMethods checks the wiring of the two paths:
// the collection takes GET and POST, one invitation takes PATCH and DELETE, and
// anything else is a 405 whose Allow header names the methods.
func TestInvitationRoutesAnswerTheirMethods(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path    string
		allowed []string
		allow   string
	}{
		caseCollection: {path: invitationPath, allowed: []string{http.MethodGet, http.MethodPost}, allow: "GET, POST"},
		caseItem: {
			path: invitationItem, allowed: []string{http.MethodPatch, http.MethodDelete}, allow: "DELETE, PATCH",
		},
	}

	for name, tt := range tests {
		for _, method := range []string{
			http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		} {
			t.Run(name+" "+method, func(t *testing.T) {
				t.Parallel()

				rec := httptest.NewRecorder()
				req := newRequest(t, method, tt.path, nil)
				app.NewHandler(app.Platform{}).ServeHTTP(rec, req)

				if allowed := slices.Contains(tt.allowed, method); allowed {
					// With no database the route is found and answers 503, which
					// is not a 405: the method reached its handler.
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

// TestInvitationRoutesWithoutADatabaseAreUnavailable: with no database (the host
// stub) every invitation route answers 503, not a panic and not a 401.
func TestInvitationRoutesWithoutADatabaseAreUnavailable(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ method, path string }{
		caseList:   {http.MethodGet, invitationPath},
		"create":   {http.MethodPost, invitationPath},
		"update":   {http.MethodPatch, invitationItem},
		caseRevoke: {http.MethodDelete, invitationItem},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body := strings.NewReader(`{"type":"x","numInvites":1}`)
			if tt.method == http.MethodPatch {
				body = strings.NewReader(`{"numInvites":2}`)
			}

			rec := httptest.NewRecorder()
			app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, newRequest(t, tt.method, tt.path, body))

			if tt.method == http.MethodPost {
				// Create validates its body first, and no type is creatable, so a
				// well-formed request for an unknown type is refused as such.
				if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_invitation_type"`) {
					t.Errorf("%s = %d %s, want 400 invalid_invitation_type", name, rec.Code, rec.Body)
				}

				return
			}

			const code = `"invitations_not_configured"`

			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), code) {
				t.Errorf("%s = %d %s, want 503 invitations_not_configured", name, rec.Code, rec.Body)
			}
		})
	}
}

// TestInvitationRoutesRequireASession: with a database but no session cookie,
// every route is a 401, whatever else is wrong with the request.
func TestInvitationRoutesRequireASession(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ method, path, body string }{
		caseList:   {http.MethodGet, invitationPath, ""},
		"update":   {http.MethodPatch, invitationItem, `{"numInvites":2}`},
		caseRevoke: {http.MethodDelete, invitationItem, ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			platform := app.Platform{DB: failingDB(t), Getenv: loginEnv}

			rec := httptest.NewRecorder()
			app.NewHandler(platform).ServeHTTP(rec, newRequest(t, tt.method, tt.path, strings.NewReader(tt.body)))

			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"unauthenticated"`) {
				t.Errorf("%s = %d %s, want 401 unauthenticated", name, rec.Code, rec.Body)
			}
		})
	}
}

// TestInvitationItemNeedsExactlyOneSegment: the id is one path segment. A longer
// or empty one is not a route, so it gets the JSON 404 and not a handler.
func TestInvitationItemNeedsExactlyOneSegment(t *testing.T) {
	t.Parallel()

	for _, path := range []string{invitationPath + "/", invitationItem + "/extra", invitationPath + "x"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, newRequest(t, http.MethodDelete, path, nil))

			if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"not_found"`) {
				t.Errorf("DELETE %s = %d %s, want 404 not_found", path, rec.Code, rec.Body)
			}
		})
	}
}

// TestInvitationRoutesRequireJSON checks the CSRF defence on the routes that
// change something: PATCH, DELETE and POST are refused with 415 before any
// handler runs, unless the request is application/json. GET changes nothing and
// needs no Content-Type.
func TestInvitationRoutesRequireJSON(t *testing.T) {
	t.Parallel()

	routes := []struct{ method, path string }{
		{http.MethodPost, invitationPath},
		{http.MethodPatch, invitationItem},
		{http.MethodDelete, invitationItem},
	}

	for _, rt := range routes {
		for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
			t.Run(rt.method+" "+contentType, func(t *testing.T) {
				t.Parallel()

				rec := httptest.NewRecorder()
				req := httptest.NewRequestWithContext(t.Context(), rt.method, rt.path, nil)

				if contentType != "" {
					req.Header.Set("Content-Type", contentType)
				}

				app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, req)

				if rec.Code != http.StatusUnsupportedMediaType ||
					!strings.Contains(rec.Body.String(), `"unsupported_media_type"`) {
					t.Errorf("%s %s (%q) = %d %s, want 415", rt.method, rt.path, contentType, rec.Code, rec.Body)
				}
			})
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, invitationPath, nil)
	app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, req)

	if rec.Code == http.StatusUnsupportedMediaType {
		t.Error("GET needed a Content-Type")
	}
}
