package session_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// TestRouteDeclarations pins every route's method, path, credential and
// requirement. It is the permission-confusion test: both routes need a session
// and no particular role, because a caller may always read and end their own
// session; a requirement added to one would lock members out of logging out.
func TestRouteDeclarations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		path       string
		credential auth.Credential
		admin      bool
	}{
		{name: "who am i", method: http.MethodGet, path: "/api/session", credential: auth.Session, admin: false},
		{name: "logout", method: http.MethodPost, path: "/api/logout", credential: auth.Session, admin: false},
	}

	routes := newRig(t).routes()

	if len(routes) != len(tests) {
		t.Fatalf("Routes returned %d routes, want %d", len(routes), len(tests))
	}

	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := routes[index]

			if route.Method != tt.method || route.Path != tt.path {
				t.Errorf("route = %s %s, want %s %s", route.Method, route.Path, tt.method, tt.path)
			}

			if route.Credential != tt.credential {
				t.Errorf("Credential = %v, want %v", route.Credential, tt.credential)
			}

			if (route.Require != nil) != tt.admin {
				t.Errorf("Require set = %t, want %t", route.Require != nil, tt.admin)
			}

			if route.MaxBody != 0 {
				t.Errorf("MaxBody = %d, want the default", route.MaxBody)
			}

			if route.Handle == nil {
				t.Error("Handle is nil")
			}
		})
	}
}

// TestPathConstants keeps the exported paths in step with the routes.
func TestPathConstants(t *testing.T) {
	t.Parallel()

	if session.PathSession != "/api/session" || session.PathLogout != "/api/logout" {
		t.Errorf("paths = %q and %q", session.PathSession, session.PathLogout)
	}
}

// TestRoutesRequireEveryDependency checks that a missing dependency is found
// when the routes are built, not by a request.
func TestRoutesRequireEveryDependency(t *testing.T) {
	t.Parallel()

	complete := newRig(t)
	deps := session.Deps{Store: complete.store, Now: func() time.Time { return complete.logoutNow }}

	tests := []struct {
		name   string
		mutate func(*session.Deps)
	}{
		{name: "no store", mutate: func(d *session.Deps) { d.Store = nil }},
		{name: "no clock", mutate: func(d *session.Deps) { d.Now = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			broken := deps
			tt.mutate(&broken)

			defer func() {
				if recover() == nil {
					t.Error("Routes did not panic")
				}
			}()

			session.Routes(broken)
		})
	}
}
