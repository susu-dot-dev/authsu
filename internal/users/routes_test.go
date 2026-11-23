package users_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/users"
)

// TestRouteDeclarations is the permission-confusion test: each route is the
// method and path that is documented, needs a session, and requires an
// administrator. The boundary enforces what is declared here, so a route that
// lost its requirement would be open to every signed-in account.
func TestRouteDeclarations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method string
		path   string
		scope  scope.Scope
		// noAgents is whether an agent is refused whatever scopes it holds:
		// revoking an account is for a person.
		noAgents bool
	}{
		{name: opList, method: http.MethodGet, path: "/api/user", scope: scope.UserRead},
		{name: "get", method: http.MethodGet, path: "/api/user/{id}", scope: scope.UserRead},
		{name: "revoke", method: http.MethodDelete, path: "/api/user/{id}", scope: scope.UserRevoke, noAgents: true},
	}

	declared := users.Routes(users.Deps{Store: &fakeStore{}, Now: time.Now, Log: noLog})

	if len(declared) != len(cases) {
		t.Fatalf("Routes declares %d routes, want %d", len(declared), len(cases))
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			checkDeclared(t, declared[i], tc.method, tc.path, tc.scope, tc.noAgents)
		})
	}
}

// checkDeclared checks one route: where it is, that it needs a credential, that
// its access is exactly its own admin scope (so the boundary requires the
// administrator role as well) and refuses agents when noAgents, and that it
// reads no body.
func checkDeclared(t *testing.T, got auth.Route, method, path string, needs scope.Scope, noAgents bool) {
	t.Helper()

	if got.Method != method || got.Path != path {
		t.Errorf("route = %s %s, want %s %s", got.Method, got.Path, method, path)
	}

	want := auth.Needs(needs)
	if noAgents {
		want = want.WithoutAgents()
	}

	if got.Credential != auth.Authenticated || got.Access != want {
		t.Errorf("Credential = %v, Access = %+v, want Authenticated and %+v", got.Credential, got.Access, want)
	}

	if !scope.IsAdmin(needs) {
		t.Errorf("%s is not an admin scope: a member could use the route", needs)
	}

	// No route reads a body, so each asks for a small cap.
	if got.Handle == nil || got.MaxBody <= 0 || got.MaxBody > 1024 {
		t.Errorf("Handle nil = %t, MaxBody = %d, want a handler and a small positive cap", got.Handle == nil, got.MaxBody)
	}
}

// TestRoutesRefuseMissingDependencies: there is no degraded mode, so a
// deployment that is missing a dependency fails at construction.
func TestRoutesRefuseMissingDependencies(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		deps users.Deps
	}{
		{name: "no store", deps: users.Deps{Store: nil, Now: time.Now, Log: noLog}},
		{name: "no clock", deps: users.Deps{Store: &fakeStore{}, Now: nil, Log: noLog}},
		{name: "no log", deps: users.Deps{Store: &fakeStore{}, Now: time.Now, Log: nil}},
		{name: "nothing", deps: users.Deps{Store: nil, Now: nil, Log: nil}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("Routes did not panic")
				}
			}()

			users.Routes(tc.deps)
		})
	}
}

// noLog is a Log that discards, for tests that do not look at it.
func noLog(httpapi.Request, *apierr.Error) {}
