package agents_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
)

// TestRouteDeclarations is the permission-confusion test of the route table:
// every route of the API, and for each the credential it needs and the
// requirement it adds. Every agent route is the caller's own business, so each
// needs a session and nothing more; in particular none is an administrator's.
func TestRouteDeclarations(t *testing.T) {
	t.Parallel()

	want := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/agent"},
		{http.MethodPost, "/api/agent"},
		{http.MethodGet, itemPattern},
		{http.MethodPatch, itemPattern},
		{http.MethodDelete, itemPattern},
	}

	routes := agents.Routes(newRig(t).deps())

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

			if route.Credential != auth.Session {
				t.Errorf("Credential = %v, want Session", route.Credential)
			}

			if route.Require != nil {
				t.Error("Require is set; every agent route is open to any signed-in user, for their own agents")
			}

			if route.MaxBody != agents.MaxBody {
				t.Errorf("MaxBody = %d, want %d", route.MaxBody, agents.MaxBody)
			}

			if route.Handle == nil {
				t.Error("Handle is nil")
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
		without func(*agents.Deps)
		mention string
	}{
		{name: "store", without: func(d *agents.Deps) { d.Store = nil }, mention: "Store"},
		{name: "clock", without: func(d *agents.Deps) { d.Now = nil }, mention: "Now"},
		{name: "ids", without: func(d *agents.Deps) { d.NewID = nil }, mention: "NewID"},
		{name: "key creation", without: func(d *agents.Deps) { d.CreateKey = nil }, mention: "CreateKey"},
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

			agents.Routes(deps)
			t.Error("Routes did not panic")
		})
	}
}

// TestLimits pins the values the design and the clients rely on.
func TestLimits(t *testing.T) {
	t.Parallel()

	if agents.MaxAgentsPerUser != 25 {
		t.Errorf("MaxAgentsPerUser = %d, want 25", agents.MaxAgentsPerUser)
	}

	if agents.KeyLifetime != 90*24*time.Hour {
		t.Errorf("KeyLifetime = %v, want 90 days", agents.KeyLifetime)
	}

	if agents.DefaultScopes != "default:agent" {
		t.Errorf("DefaultScopes = %q, want default:agent", agents.DefaultScopes)
	}
}

// agentRoute is one route of the API with a request that is valid for it.
type agentRoute struct {
	name, method, target, body string
}

// everyRoute is each route, called as a signed-in user's valid request would.
func everyRoute() []agentRoute {
	return []agentRoute{
		{name: routeList, method: http.MethodGet, target: collection, body: ""},
		{name: routeCreate, method: http.MethodPost, target: collection, body: bodyAssistant},
		{name: routeGet, method: http.MethodGet, target: itemPrefix + agentA1, body: ""},
		{name: routeRename, method: http.MethodPatch, target: itemPrefix + agentA1, body: bodyRenamed},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + agentA1, body: ""},
	}
}

// situation changes a valid request into one that carries no valid session,
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

// withoutAValidSession are the ways a request has no session.
func withoutAValidSession() []situation {
	return []situation{
		anonymous("no cookie", func(*rig, *request) {}),
		anonymous("empty cookie", withCookie(sessionCookie(""))),
		anonymous("not a token", withCookie(sessionCookie("not.a token"))),
		anonymous("a session of nobody the store knows", func(rg *rig, req *request) {
			cookie := rg.signIn(userA, roleMember)
			clear(rg.keys.rows)

			req.cookies = []*http.Cookie{cookie}
		}),
		anonymous("an agent's own api key presented as the session", func(rg *rig, req *request) {
			origin, err := config.ParseOrigin(apiOrigin)
			if err != nil {
				rg.t.Fatal(err)
			}

			key, err := auth.CreateKey(auth.IssuerFor(origin), auth.KeySpec{
				Kind: auth.KindAPIKey, Subject: userA, Expires: time.Now().Add(time.Hour),
				Claims: map[string]any{claimAct: map[string]any{claimSub: agentA1}, claimScope: agents.DefaultScopes},
			})
			if err != nil {
				rg.t.Fatal(err)
			}

			req.cookies = []*http.Cookie{sessionCookie(key.JWT)}
		}),
		{
			name: "the deployment is not configured",
			change: func(rg *rig, req *request) {
				req.cookies = []*http.Cookie{rg.signIn(userA, roleMember)}
				delete(rg.env, config.VarAPIOrigin)
			},
			status: http.StatusServiceUnavailable,
			body:   errorBody(auth.CodeNotConfigured, "the service is not configured"), logCode: auth.CodeNotConfigured,
		},
	}
}

// TestEveryRouteNeedsASession: whatever is presented in place of a session, the
// answer is the one 401 (a revoked key and an unknown one cannot be told apart),
// the handler never runs, and nothing is written or created.
func TestEveryRouteNeedsASession(t *testing.T) {
	t.Parallel()

	for _, route := range everyRoute() {
		for _, sit := range withoutAValidSession() {
			t.Run(route.name+"/"+sit.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))

				req := request{method: route.method, target: route.target, body: route.body}
				sit.change(rg, &req)

				rec := rg.serve(req)

				wantFailure(t, rg, rec, sit.status, sit.body, sit.logCode)
				rg.untouched()
			})
		}
	}
}

// TestTwoSessionCookiesAreRefused: a request that carries two session cookies
// is ambiguous, even when both are valid, and acts for neither user.
func TestTwoSessionCookiesAreRefused(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.serve(request{
		method: http.MethodGet, target: collection,
		cookies: []*http.Cookie{rg.signIn(userA, roleMember), rg.signIn(userB, roleMember)},
	})

	wantFailure(t, rg, rec, http.StatusUnauthorized, bodyUnauth, auth.CodeUnauthenticated)
	rg.untouched()
}

// TestInvalidInputIsRefusedAfterAuthentication: a request that is both invalid
// and unauthenticated is told only that it is not signed in, never what is wrong
// with it, so an anonymous caller learns nothing about the routes' inputs. That
// includes the path id: it is parsed only once the caller is known.
func TestInvalidInputIsRefusedAfterAuthentication(t *testing.T) {
	t.Parallel()

	unauthenticated := func(name, method, target, body string) situation {
		return situation{
			name: name, change: func(_ *rig, req *request) {
				req.method, req.target, req.body = method, target, body
			},
			status: http.StatusUnauthorized, body: bodyUnauth, logCode: auth.CodeUnauthenticated,
		}
	}

	tests := []situation{
		unauthenticated("list with a bad limit", http.MethodGet, collection+"?limit=0", ""),
		unauthenticated("create with a bad name", http.MethodPost, collection, `{"name":""}`),
		unauthenticated("create with a body that is not json", http.MethodPost, collection, `{`),
		unauthenticated("rename with no name", http.MethodPatch, itemPrefix+agentA1, `{}`),
		unauthenticated("get with a bad id", http.MethodGet, itemPrefix+"nope", ""),
		unauthenticated("revoke with a bad id", http.MethodDelete, itemPrefix+strings.ToUpper(agentA1), ""),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)

			var req request

			tt.change(rg, &req)

			rec := rg.serve(req)

			wantFailure(t, rg, rec, tt.status, tt.body, tt.logCode)
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

// refusals are the requests the boundary answers before a session is read.
func refusals() []refusal {
	const (
		collectionAllow = "GET, POST"
		itemAllow       = "DELETE, GET, PATCH"
	)

	item := itemPrefix + agentA1

	return []refusal{
		{"put to the collection", request{method: http.MethodPut, target: collection},
			http.StatusMethodNotAllowed, collectionAllow, codeNotAllowed},
		{"delete of the collection", request{method: http.MethodDelete, target: collection},
			http.StatusMethodNotAllowed, collectionAllow, codeNotAllowed},
		{"post to an agent", request{method: http.MethodPost, target: item},
			http.StatusMethodNotAllowed, itemAllow, codeNotAllowed},
		{"put to an agent", request{method: http.MethodPut, target: item},
			http.StatusMethodNotAllowed, itemAllow, codeNotAllowed},
		{"post without a content type", request{method: http.MethodPost, target: collection, contentType: "-"},
			http.StatusUnsupportedMediaType, "", "unsupported_media_type"},
		{"delete as a form", request{method: http.MethodDelete, target: item, contentType: "text/plain"},
			http.StatusUnsupportedMediaType, "", "unsupported_media_type"},
		{"an unknown path", request{method: http.MethodGet, target: "/api/agents"},
			http.StatusNotFound, "", codeNoRoute},
		{"an agent path without an id", request{method: http.MethodGet, target: itemPrefix},
			http.StatusNotFound, "", codeNoRoute},
		{"an agent's subpath", request{method: http.MethodGet, target: item + "/keys"},
			http.StatusNotFound, "", codeNoRoute},
	}
}

// TestPathsAndMethods: the collection answers GET and POST, an agent answers
// GET, PATCH and DELETE, and every other method or path is refused before the
// store is read.
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

// TestAnyRoleMayUseTheirAgents: there is no role check. An agent is something
// every user has, so an administrator, a member and an account whose role is
// empty are the same to this API, on every route.
func TestAnyRoleMayUseTheirAgents(t *testing.T) {
	t.Parallel()

	statuses := map[string]int{
		routeList: http.StatusOK, routeCreate: http.StatusCreated, routeGet: http.StatusOK,
		routeRename: http.StatusOK, routeRevoke: http.StatusOK,
	}

	for _, role := range []string{roleAdmin, roleMember, ""} {
		for _, route := range everyRoute() {
			t.Run(route.name+"/role "+role, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))

				rec := rg.as(rg.signIn(userA, role), route.method, route.target, route.body)

				if rec.Code != statuses[route.name] {
					t.Errorf("%s as %q = %d %q, want %d", route.name, role, rec.Code, rec.Body.String(), statuses[route.name])
				}
			})
		}
	}
}
