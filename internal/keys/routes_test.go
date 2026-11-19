package keys_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/keys"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// TestRouteDeclarations is the permission-confusion test of the route table:
// every route of the API, and for each the credential and the exact access it
// declares. Every key route is the caller's own business, so none is an admin
// scope. Issuing needs a session (a person was present) and refuses agents, and
// renaming and revoking refuse agents too: keys are the user's to manage.
func TestRouteDeclarations(t *testing.T) {
	t.Parallel()

	want := []struct {
		method, path string
		access       auth.Access
	}{
		{http.MethodGet, collection, auth.Needs(scope.KeyRead)},
		{http.MethodPost, collection, auth.Needs(scope.KeyCreate).Sessions().WithoutAgents()},
		{http.MethodGet, itemPattern, auth.Needs(scope.KeyRead)},
		{http.MethodPatch, itemPattern, auth.Needs(scope.KeyUpdate).WithoutAgents()},
		{http.MethodDelete, itemPattern, auth.Needs(scope.KeyRevoke).WithoutAgents()},
	}

	routes := keys.Routes(newRig(t).deps())

	if len(routes) != len(want) {
		t.Fatalf("Routes returned %d routes, want %d: %+v", len(routes), len(want), routes)
	}

	for _, expected := range want {
		t.Run(expected.method+" "+expected.path, func(t *testing.T) {
			t.Parallel()

			at := slices.IndexFunc(routes, func(route auth.Route) bool {
				return route.Method == expected.method && route.Path == expected.path
			})
			if at < 0 {
				t.Fatalf("no route %s %s in %+v", expected.method, expected.path, routes)
			}

			route := routes[at]

			if route.Credential != auth.Authenticated {
				t.Errorf("Credential = %v, want Authenticated", route.Credential)
			}

			if route.Access != expected.access {
				t.Errorf("Access = %+v, want %+v", route.Access, expected.access)
			}

			if scope.IsAdmin(route.Access.Scope) {
				t.Errorf("%s is an admin scope; a key route is for the caller's own keys", route.Access.Scope)
			}

			if route.MaxBody != keys.MaxBody || route.Handle == nil {
				t.Errorf("MaxBody = %d (want %d), Handle nil = %t", route.MaxBody, keys.MaxBody, route.Handle == nil)
			}
		})
	}
}

// TestRoutesPanicOnAMissingDependency: a Deps is complete or Routes refuses it,
// so no handler meets a nil dependency.
func TestRoutesPanicOnAMissingDependency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		without func(*keys.Deps)
		mention string
	}{
		{name: "store", without: func(d *keys.Deps) { d.Store = nil }, mention: "Store"},
		{name: "clock", without: func(d *keys.Deps) { d.Now = nil }, mention: "Now"},
		{name: "ids", without: func(d *keys.Deps) { d.NewID = nil }, mention: "NewID"},
		{name: "entropy", without: func(d *keys.Deps) { d.Entropy = nil }, mention: "Entropy"},
		{name: "key issuing", without: func(d *keys.Deps) { d.IssueUserAPIKey = nil }, mention: "IssueUserAPIKey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			deps := newRig(t).deps()
			tt.without(&deps)

			defer func() {
				got, _ := recover().(string)
				if !strings.Contains(got, "Deps."+tt.mention) {
					t.Errorf("panic = %q, want it to name Deps.%s", got, tt.mention)
				}
			}()

			keys.Routes(deps)
			t.Error("Routes did not panic")
		})
	}
}

// TestLimits pins the values the design and the clients rely on.
func TestLimits(t *testing.T) {
	t.Parallel()

	if keys.MaxKeysPerUser != 50 {
		t.Errorf("MaxKeysPerUser = %d, want 50", keys.MaxKeysPerUser)
	}

	if got := keys.DefaultScopes().JSON(); got != defaultUserJSON {
		t.Errorf("DefaultScopes = %s, want the default:user bundle", got)
	}

	if input.DefaultKeyLifetime().Duration() != 90*24*time.Hour || auth.MaxUserKeyLifetime != 365*24*time.Hour {
		t.Errorf("lifetimes = %v and %v, want 90 days and a year",
			input.DefaultKeyLifetime().Duration(), auth.MaxUserKeyLifetime)
	}

	// The default scopes the API hands a user's key are written out in full as
	// the user bundle, which holds every non-admin scope (docs/permissions_design.md).
	if len(keys.DefaultScopes()) != 1 || keys.DefaultScopes()[0] != scope.DefaultUser {
		t.Errorf("DefaultScopes = %v", keys.DefaultScopes())
	}
}

// keyRoute is one route of the API with a request that is valid for it.
type keyRoute struct {
	name, method, target, body string
}

// everyRoute is each route, called as a signed-in user's valid request would.
func everyRoute() []keyRoute {
	return []keyRoute{
		{name: routeList, method: http.MethodGet, target: collection, body: ""},
		{name: routeCreate, method: http.MethodPost, target: collection, body: bodyCI},
		{name: routeGet, method: http.MethodGet, target: itemPrefix + keyA1, body: ""},
		{name: routePatch, method: http.MethodPatch, target: itemPrefix + keyA1, body: bodyRenamed},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + keyA1, body: ""},
	}
}

// situation changes a valid request into one that carries no valid credential,
// and says what the client is told.
type situation struct {
	name    string
	change  func(*rig, *request)
	status  int
	body    string
	logCode string
}

// anonymous is a situation whose answer is the one 401.
func anonymous(name string, change func(*rig, *request)) situation {
	return situation{
		name: name, change: change, status: http.StatusUnauthorized, body: bodyUnauth, logCode: auth.CodeUnauthenticated,
	}
}

// withCookie is a change that sends cookie.
func withCookie(cookie *http.Cookie) func(*rig, *request) {
	return func(_ *rig, req *request) { req.cookies = []*http.Cookie{cookie} }
}

// withoutAValidCredential are the ways a request has no credential.
func withoutAValidCredential() []situation {
	return []situation{
		anonymous("no credential", func(*rig, *request) {}),
		anonymous("empty cookie", withCookie(sessionCookie(""))),
		anonymous("not a token", withCookie(sessionCookie("not.a token"))),
		anonymous("a session of nobody the store knows", func(rg *rig, req *request) {
			cookie := rg.signIn(userA, roleMember)
			clear(rg.creds.sessions)

			req.cookies = []*http.Cookie{cookie}
		}),
		anonymous("an api key of nobody the store knows", func(rg *rig, req *request) {
			header, _ := rg.signInKey(keySpec{owner: userA, role: roleMember, scope: scope.List{scope.DefaultUser}})
			clear(rg.creds.keys)

			req.authorization = header
		}),
		anonymous("an api key presented as the session", func(rg *rig, req *request) {
			header, _ := rg.signInKey(keySpec{owner: userA, role: roleMember, scope: scope.List{scope.DefaultUser}})

			req.cookies = []*http.Cookie{sessionCookie(strings.TrimPrefix(header, "Bearer "))}
		}),
		anonymous("a session presented as an api key", func(rg *rig, req *request) {
			req.authorization = "Bearer " + rg.signIn(userA, roleMember).Value
		}),
		anonymous("a session and an api key together", func(rg *rig, req *request) {
			header, _ := rg.signInKey(keySpec{owner: userA, role: roleMember, scope: scope.List{scope.DefaultUser}})

			req.cookies = []*http.Cookie{rg.signIn(userA, roleMember)}
			req.authorization = header
		}),
	}
}

// TestEveryRouteNeedsACredential: whatever is presented in place of a valid
// credential, the answer is the one 401, the handler never runs, and nothing is
// written or created.
func TestEveryRouteNeedsACredential(t *testing.T) {
	t.Parallel()

	for _, route := range everyRoute() {
		for _, sit := range withoutAValidCredential() {
			t.Run(route.name+"/"+sit.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(keyA1, nameCI, 1, nil))

				req := request{method: route.method, target: route.target, body: route.body}
				sit.change(rg, &req)

				rec := rg.serve(req)

				wantFailure(t, rg, rec, sit.status, sit.body, sit.logCode)
				rg.untouched()
			})
		}
	}
}

// TestInvalidInputIsRefusedAfterAuthentication: a request that is both invalid
// and unauthenticated is told only that it is not signed in, never what is wrong
// with it, so an anonymous caller learns nothing about the routes' inputs. That
// includes the path id: it is parsed only once the caller is known.
func TestInvalidInputIsRefusedAfterAuthentication(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, method, target, body string }{
		{"list with a bad limit", http.MethodGet, collection + "?limit=0", ""},
		{"create with a bad name", http.MethodPost, collection, `{"name":""}`},
		{"create with a body that is not json", http.MethodPost, collection, `{`},
		{"rename with no name", http.MethodPatch, itemPrefix + keyA1, `{}`},
		{"get with a bad id", http.MethodGet, itemPrefix + "nope", ""},
		{"revoke with a bad id", http.MethodDelete, itemPrefix + strings.ToUpper(keyA1), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.serve(request{method: tt.method, target: tt.target, body: tt.body})

			wantFailure(t, rg, rec, http.StatusUnauthorized, bodyUnauth, auth.CodeUnauthenticated)
			rg.untouched()
		})
	}
}

// refusal is a request that is answered before its route is reached.
type refusal struct {
	name   string
	req    request
	status int
	allow  string
	code   string
}

// refusals are the requests the boundary answers before a credential is read.
func refusals() []refusal {
	const (
		collectionAllow = "GET, POST"
		itemAllow       = "DELETE, GET, PATCH"
	)

	item := itemPrefix + keyA1

	return []refusal{
		{"put to the collection", request{method: http.MethodPut, target: collection},
			http.StatusMethodNotAllowed, collectionAllow, codeNotAllowed},
		{"delete of the collection", request{method: http.MethodDelete, target: collection},
			http.StatusMethodNotAllowed, collectionAllow, codeNotAllowed},
		{"post to a key", request{method: http.MethodPost, target: item},
			http.StatusMethodNotAllowed, itemAllow, codeNotAllowed},
		{"put to a key", request{method: http.MethodPut, target: item},
			http.StatusMethodNotAllowed, itemAllow, codeNotAllowed},
		{"post without a content type", request{method: http.MethodPost, target: collection, contentType: "-"},
			http.StatusUnsupportedMediaType, "", "unsupported_media_type"},
		{"delete as a form", request{method: http.MethodDelete, target: item, contentType: "text/plain"},
			http.StatusUnsupportedMediaType, "", "unsupported_media_type"},
		{"an unknown path", request{method: http.MethodGet, target: "/api/keys"},
			http.StatusNotFound, "", codeNoRoute},
		{"a key path without an id", request{method: http.MethodGet, target: itemPrefix},
			http.StatusNotFound, "", codeNoRoute},
		{"a key's subpath", request{method: http.MethodGet, target: item + "/token"},
			http.StatusNotFound, "", codeNoRoute},
	}
}

// TestPathsAndMethods: the collection answers GET and POST, a key answers GET,
// PATCH and DELETE, and every other method or path is refused before the store
// is read.
func TestPathsAndMethods(t *testing.T) {
	t.Parallel()

	for _, tt := range refusals() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			req := tt.req
			req.cookies = []*http.Cookie{rg.signIn(userA, roleMember)}

			rec := rg.serve(req)

			if rec.Code != tt.status {
				t.Errorf("status = %d, want %d", rec.Code, tt.status)
			}

			if got := rec.Header().Get("Allow"); got != tt.allow {
				t.Errorf("Allow = %q, want %q", got, tt.allow)
			}

			if len(rg.logged) != 1 || rg.logged[0].Code != tt.code {
				t.Errorf("logged %v, want one %q", rg.logged, tt.code)
			}

			rg.untouched()
		})
	}
}

// TestAnyRoleMayUseTheirKeys: there is no role check. A key is something every
// user has, so an administrator, a member and an account whose role is empty are
// the same to this API, on every route.
func TestAnyRoleMayUseTheirKeys(t *testing.T) {
	t.Parallel()

	statuses := map[string]int{
		routeList: http.StatusOK, routeCreate: http.StatusCreated, routeGet: http.StatusOK,
		routePatch: http.StatusOK, routeRevoke: http.StatusOK,
	}

	for _, role := range []string{roleAdmin, roleMember, ""} {
		for _, route := range everyRoute() {
			t.Run(route.name+"/role "+role, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(keyA1, nameCI, 1, nil))

				rec := rg.as(rg.signIn(userA, role), route.method, route.target, route.body)

				if rec.Code != statuses[route.name] {
					t.Errorf("%s as %q = %d %q, want %d", route.name, role, rec.Code, rec.Body.String(), statuses[route.name])
				}
			})
		}
	}
}
