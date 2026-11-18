//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package users_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
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
	}{
		{name: opList, method: http.MethodGet, path: "/api/user"},
		{name: "get", method: http.MethodGet, path: "/api/user/{id}"},
		{name: "revoke", method: http.MethodDelete, path: "/api/user/{id}"},
	}

	declared := users.Routes(users.Deps{Store: &fakeStore{}, Now: time.Now, Log: noLog})

	if len(declared) != len(cases) {
		t.Fatalf("Routes declares %d routes, want %d", len(declared), len(cases))
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := declared[i]

			if got.Method != tc.method || got.Path != tc.path {
				t.Errorf("route = %s %s, want %s %s", got.Method, got.Path, tc.method, tc.path)
			}

			if got.Credential != auth.Session {
				t.Errorf("Credential = %v, want auth.Session", got.Credential)
			}

			if got.Handle == nil {
				t.Error("Handle is nil")
			}

			// No route reads a body, so each asks for a small cap.
			if got.MaxBody <= 0 || got.MaxBody > 1024 {
				t.Errorf("MaxBody = %d, want a small positive cap", got.MaxBody)
			}

			if got.Require == nil {
				t.Fatal("Require is nil: any signed-in account may use the route")
			}

			wantRequirement(t, got.Require)
		})
	}
}

// wantRequirement checks that require lets only an administrator through, by
// behaviour: the same function as auth.Admin, or one that behaves like it.
func wantRequirement(t *testing.T, require func(auth.Principal) error) {
	t.Helper()

	principals := []struct {
		name string
		role string
		ok   bool
	}{
		{name: "administrator", role: auth.RoleAdmin, ok: true},
		{name: "member", role: roleMember, ok: false},
		{name: "no role", role: "", ok: false},
		{name: "upper-case admin", role: "Admin", ok: false},
		{name: "padded admin", role: " admin", ok: false},
	}

	for _, who := range principals {
		err := require(auth.Principal{
			UserID: adminID, Role: who.role, KeyID: "", CredentialID: "", Kind: auth.KindSession, ExpiresAt: time.Time{},
		})

		if who.ok {
			if err != nil {
				t.Errorf("%s: Require = %v, want nil", who.name, err)
			}

			continue
		}

		failure := apierr.As(err)
		if err == nil || failure.Kind != apierr.Forbidden || failure.Code != auth.CodeForbidden {
			t.Errorf("%s: Require = %v, want 403 forbidden", who.name, err)
		}
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
