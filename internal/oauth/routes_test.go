package oauth_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// routeWant is what a route declares.
type routeWant struct {
	method, path string
	credential   auth.Credential
	access       auth.Access
	media        httpapi.Media
	errors       httpapi.ErrorFormat
	maxBody      int64
}

// TestRouteDeclarations is the permission-confusion test of the route table:
// every route, and for each the credential, the exact access, the media type,
// the error format and the body cap it declares. Only consent authorizes, and it
// needs a session and refuses agents; the token endpoints need no credential and
// take a form; the grant routes are the user's own and need their scope, and
// revoking refuses agents.
func TestRouteDeclarations(t *testing.T) {
	t.Parallel()

	// A route that needs no credential declares no access.
	none := auth.Access{}

	jsonRoute := httpapi.MediaJSON
	formRoute := httpapi.MediaForm

	read := auth.Needs(scope.GrantRead)
	revoke := auth.Needs(scope.GrantRevoke).WithoutAgents()

	want := []routeWant{
		{http.MethodGet, oauth.PathMetadata, auth.None, none, jsonRoute, httpapi.ErrorsAPI, oauth.MaxDiscoveryBody},
		{
			http.MethodGet, oauth.PathOpenIDConfiguration, auth.None, none, jsonRoute, httpapi.ErrorsAPI,
			oauth.MaxDiscoveryBody,
		},
		{http.MethodGet, oauth.PathJWKS, auth.None, none, jsonRoute, httpapi.ErrorsAPI, oauth.MaxDiscoveryBody},
		{http.MethodGet, oauth.PathAuthorize, auth.None, none, jsonRoute, httpapi.ErrorsOAuth, oauth.MaxQuery},
		{http.MethodGet, oauth.PathRequest, auth.None, none, jsonRoute, httpapi.ErrorsAPI, oauth.MaxQuery},
		{
			http.MethodPost, oauth.PathConsent, auth.Authenticated, auth.Open().Sessions().WithoutAgents(),
			jsonRoute, httpapi.ErrorsAPI, oauth.MaxConsentBody,
		},
		{http.MethodPost, oauth.PathToken, auth.None, none, formRoute, httpapi.ErrorsOAuth, oauth.MaxTokenBody},
		{http.MethodPost, oauth.PathRevoke, auth.None, none, formRoute, httpapi.ErrorsOAuth, oauth.MaxRevokeBody},
		{
			http.MethodPost, oauth.PathIntrospect, auth.None, none, formRoute, httpapi.ErrorsOAuth,
			oauth.MaxIntrospectBody,
		},
		{http.MethodGet, oauth.PathGrants, auth.Authenticated, read, jsonRoute, httpapi.ErrorsAPI, oauth.MaxGrantQuery},
		{http.MethodGet, oauth.PathGrant, auth.Authenticated, read, jsonRoute, httpapi.ErrorsAPI, oauth.MaxGrantQuery},
		{
			http.MethodDelete, oauth.PathGrant, auth.Authenticated, revoke, jsonRoute, httpapi.ErrorsAPI,
			oauth.MaxGrantQuery,
		},
	}

	routes := oauth.Routes(newRig(t).deps())

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

			wantRoute(t, routes[at], expected)
		})
	}
}

// wantRoute asserts one route's declaration.
func wantRoute(t *testing.T, route auth.Route, expected routeWant) {
	t.Helper()

	if route.Credential != expected.credential {
		t.Errorf("Credential = %v, want %v", route.Credential, expected.credential)
	}

	if route.Access != expected.access {
		t.Errorf("Access = %+v, want %+v", route.Access, expected.access)
	}

	if route.Media != expected.media || route.Errors != expected.errors {
		t.Errorf("Media = %v, Errors = %v, want %v and %v", route.Media, route.Errors, expected.media, expected.errors)
	}

	if route.MaxBody != expected.maxBody || route.Handle == nil {
		t.Errorf("MaxBody = %d (want %d), Handle nil = %t", route.MaxBody, expected.maxBody, route.Handle == nil)
	}
}

// TestPublicPaths: the paths that get the credential-less CORS policy are
// exactly the ones the design names. The authorization endpoint is navigated to
// and introspection is called by servers, so neither is, and nor is anything of
// the first party's.
func TestPublicPaths(t *testing.T) {
	t.Parallel()

	wantPaths := []string{
		"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/.well-known/jwks.json",
		"/oauth/token", "/oauth/revoke",
	}

	public := oauth.PublicPaths()

	if !slices.Equal(public, wantPaths) {
		t.Errorf("PublicPaths = %v, want %v", public, wantPaths)
	}

	notPublic := []string{
		oauth.PathIntrospect, oauth.PathAuthorize, oauth.PathRequest, oauth.PathConsent, oauth.PathGrants, oauth.PathGrant,
	}

	for _, path := range notPublic {
		t.Run("not public: "+path, func(t *testing.T) {
			t.Parallel()

			if slices.Contains(public, path) {
				t.Errorf("%s is public: it is called by servers, navigated to, or the first party's", path)
			}
		})
	}
}

// TestNoCORSPaths: the paths that get no CORS at all are exactly the authorization
// endpoint, which is navigated to, and introspection, which servers call. They are
// not public (disjoint from PublicPaths), and every route at one needs no
// credential: with none there is nothing a cross-origin script could be handed.
func TestNoCORSPaths(t *testing.T) {
	t.Parallel()

	none := oauth.NoCORSPaths()

	if want := []string{"/oauth/authorize", "/oauth/introspect"}; !slices.Equal(none, want) {
		t.Errorf("NoCORSPaths = %v, want %v", none, want)
	}

	for _, path := range none {
		t.Run("disjoint from the public paths: "+path, func(t *testing.T) {
			t.Parallel()

			if slices.Contains(oauth.PublicPaths(), path) {
				t.Errorf("%s is in both policies", path)
			}
		})
	}

	for _, route := range oauth.Routes(newRig(t).deps()) {
		if !slices.Contains(none, route.Path) {
			continue
		}

		t.Run("takes no credential: "+route.Method+" "+route.Path, func(t *testing.T) {
			t.Parallel()

			if route.Credential != auth.None {
				t.Errorf("%s %s has no CORS and takes a credential", route.Method, route.Path)
			}
		})
	}
}

// TestRoutesAtAPublicPathAreNotAuthenticated: every route at a public path needs no
// credential (a cookie can mean nothing there), every discovery route is public, and
// every route that takes a form needs no credential, because a form is no defence
// against a forged cross-site request.
func TestRoutesAtAPublicPathAreNotAuthenticated(t *testing.T) {
	t.Parallel()

	public := oauth.PublicPaths()

	for _, route := range oauth.Routes(newRig(t).deps()) {
		isPublic := slices.Contains(public, route.Path)
		discovery := strings.HasPrefix(route.Path, "/.well-known/")
		authenticated := route.Credential != auth.None

		if (isPublic && authenticated) || (discovery && !isPublic) || (route.Media == httpapi.MediaForm && authenticated) {
			t.Errorf("%s %s: public %t, discovery %t, authenticated %t",
				route.Method, route.Path, isPublic, discovery, authenticated)
		}
	}
}

// TestRoutesPanicOnAMissingDependency: a Deps is complete or Routes refuses it,
// so no handler meets a nil dependency.
func TestRoutesPanicOnAMissingDependency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		without func(*oauth.Deps)
		mention string
	}{
		{name: "store", without: func(d *oauth.Deps) { d.Store = nil }, mention: "Store"},
		{name: "resources", without: func(d *oauth.Deps) { d.Resources = nil }, mention: "Resources"},
		{name: "fetch", without: func(d *oauth.Deps) { d.Fetch = nil }, mention: "Fetch"},
		{name: "clock", without: func(d *oauth.Deps) { d.Now = nil }, mention: "Now"},
		{name: "entropy", without: func(d *oauth.Deps) { d.Entropy = nil }, mention: "Entropy"},
		{name: "ids", without: func(d *oauth.Deps) { d.NewID = nil }, mention: "NewID"},
		{name: "agent limit unset", without: func(d *oauth.Deps) { d.MaxAgents = 0 }, mention: "MaxAgents"},
		{name: "agent limit negative", without: func(d *oauth.Deps) { d.MaxAgents = -1 }, mention: "MaxAgents"},
		{name: "log", without: func(d *oauth.Deps) { d.Log = nil }, mention: "Log"},
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

			oauth.Routes(deps)
			t.Error("Routes did not panic")
		})
	}
}

// TestLimits pins the values the design and the clients rely on.
func TestLimits(t *testing.T) {
	t.Parallel()

	if oauth.PendingLifetime != 10*time.Minute {
		t.Errorf("PendingLifetime = %v, want 10 minutes", oauth.PendingLifetime)
	}

	if oauth.MaxQuery != 8<<10 || oauth.MaxConsentBody != 12<<10 || oauth.MaxDiscoveryBody != 1<<10 {
		t.Errorf("limits = %d, %d, %d", oauth.MaxQuery, oauth.MaxConsentBody, oauth.MaxDiscoveryBody)
	}
}

// TestOnlyGETAnswersTheGETRoutes: a method a route does not declare is 405 with
// the Allow header, and HEAD is not implied by GET.
func TestOnlyGETAnswersTheGETRoutes(t *testing.T) {
	t.Parallel()

	paths := []string{
		oauth.PathMetadata, oauth.PathOpenIDConfiguration, oauth.PathJWKS, oauth.PathAuthorize, oauth.PathRequest,
	}

	for _, path := range paths {
		for _, method := range []string{
			http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		} {
			t.Run(method+" "+path, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				rec := r.serve(request{method: method, target: path})

				if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
					t.Errorf("= %d Allow %q, want 405 with GET", rec.Code, rec.Header().Get("Allow"))
				}

				if len(r.net.sent()) != 0 || len(r.store.calls) != 0 {
					t.Error("the request reached the network or the store")
				}
			})
		}
	}

	t.Run("consent is POST only", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		rec := r.serve(request{method: http.MethodGet, target: oauth.PathConsent})

		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
			t.Errorf("= %d Allow %q, want 405 with POST", rec.Code, rec.Header().Get("Allow"))
		}
	})
}
