//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// inventoryRoute is one route the Worker serves. The inventory is the complete
// public surface of the API: a route added without being listed here is caught
// by TestOnlyTheInventoryIsRouted, and one that is dropped by
// TestEveryRouteIsRouted.
//
// Each carries what a request with no credential gets: a route that needs a
// session is a 401 and never touches the database, and for a route that needs
// none it is the answer to a request that is refused or answered before any
// database work (or with the scripted one).
type inventoryRoute struct {
	method string
	path   string
	// session is true when the route requires a session cookie.
	session bool
	// public is true when the route is in the credential-less CORS policy:
	// any origin may call it, and none gets credentials.
	public bool
	// noCORS is true when the route has no CORS policy at all: it is navigated
	// to or called by servers, and no origin, the UI's included, is answered
	// with a CORS header.
	noCORS bool
	// form is true when the route takes application/x-www-form-urlencoded and
	// answers in the RFC 6749 error format: the token endpoints.
	form bool
	// body is a request body that a route needing no credential refuses (or
	// answers) without touching the database.
	body string
	// script is the database's answers, for the routes that do read it.
	script []step
	// wantStatus and wantBody are the answer to the request.
	wantStatus int
	wantBody   string
	// wantCalls is the number of Exec calls the request makes.
	wantCalls int
}

// formType is the media type of a route that takes a form.
const formType = "application/x-www-form-urlencoded"

// request is the request to send to the route: its body, and the media type it
// takes, with the extra headers.
func (r inventoryRoute) request(headers map[string]string) request {
	out := map[string]string{}
	maps.Copy(out, headers)

	if r.form {
		out["Content-Type"] = formType
	}

	return request{method: r.method, path: r.path, body: r.body, headers: out}
}

func inventory() []inventoryRoute {
	return slices.Concat(coreInventory(), oauthInventory())
}

// oauthInventory is the OAuth routes of the inventory.
func oauthInventory() []inventoryRoute {
	return []inventoryRoute{
		{
			method: http.MethodGet, path: "/.well-known/oauth-authorization-server", public: true,
			wantStatus: http.StatusOK, wantBody: `"issuer":"` + apiOrigin + `"`,
		},
		{
			method: http.MethodGet, path: "/.well-known/openid-configuration", public: true,
			wantStatus: http.StatusOK, wantBody: `"id_token_signing_alg_values_supported":["RS256"]`,
		},
		{
			method: http.MethodGet, path: "/.well-known/jwks.json", public: true,
			wantStatus: http.StatusOK, wantBody: `{"keys":[{"kty":"RSA"`,
		},
		{
			// An authorization request with nothing in it is the UI's error page.
			method: http.MethodGet, path: "/oauth/authorize", noCORS: true,
			wantStatus: http.StatusFound, wantBody: "",
		},
		{
			method: http.MethodGet, path: "/api/oauth/request",
			wantStatus: http.StatusBadRequest, wantBody: `"code":"invalid_oauth_request"`,
		},
		{
			method: http.MethodPost, path: "/api/oauth/consent", session: true,
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
		},
		// The token endpoints take a form and no credential: an empty one is the
		// client's mistake, answered in the RFC 6749 format.
		{
			method: http.MethodPost, path: "/oauth/token", public: true, form: true,
			wantStatus: http.StatusBadRequest, wantBody: `"error":"invalid_request"`,
		},
		{
			method: http.MethodPost, path: "/oauth/revoke", public: true, form: true,
			wantStatus: http.StatusBadRequest, wantBody: `"error":"invalid_request"`,
		},
		{
			method: http.MethodPost, path: "/oauth/introspect", form: true, noCORS: true,
			wantStatus: http.StatusBadRequest, wantBody: `"error":"invalid_request"`,
		},
		{
			method: http.MethodGet, path: "/api/grant", session: true,
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
		},
		{
			method: http.MethodGet, path: "/api/grant/" + someID, session: true,
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
		},
		{
			method: http.MethodDelete, path: "/api/grant/" + someID, session: true,
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
		},
	}
}

// coreInventory is every other route of the inventory.
func coreInventory() []inventoryRoute {
	const (
		emptyObject  = `{}`
		invalidField = `"error":{"code":"invalid_`
	)

	sessionRoute := func(method, path string) inventoryRoute {
		return inventoryRoute{
			method: method, path: path, session: true,
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
		}
	}

	return []inventoryRoute{
		{
			method: http.MethodGet, path: "/healthz",
			wantStatus: http.StatusOK, wantBody: `{"status":"ok"}` + "\n",
		},
		{
			method: http.MethodGet, path: "/api/first-run",
			script:     []step{{match: "has_users", results: rows([]any{int64(1), int64(1)}), err: nil}},
			wantStatus: http.StatusOK, wantBody: `{"status":"invitation_accepted"}` + "\n", wantCalls: 1,
		},
		{
			method: http.MethodPost, path: "/api/register/begin", body: emptyObject,
			wantStatus: http.StatusBadRequest, wantBody: invalidField,
		},
		{
			method: http.MethodPost, path: "/api/register/finish", body: emptyObject,
			wantStatus: http.StatusBadRequest, wantBody: invalidField,
		},
		{
			method: http.MethodPost, path: "/api/login/begin", body: emptyObject,
			wantStatus: http.StatusOK, wantBody: `"allowCredentials":[]`,
		},
		{
			method: http.MethodPost, path: "/api/login/finish", body: emptyObject,
			wantStatus: http.StatusUnauthorized, wantBody: `"error":{"code":"invalid_login"`,
		},
		sessionRoute(http.MethodGet, "/api/session"),
		sessionRoute(http.MethodPost, "/api/logout"),
		sessionRoute(http.MethodGet, "/api/agent"),
		sessionRoute(http.MethodPost, "/api/agent"),
		sessionRoute(http.MethodGet, "/api/agent/"+someID),
		sessionRoute(http.MethodPatch, "/api/agent/"+someID),
		sessionRoute(http.MethodDelete, "/api/agent/"+someID),
		sessionRoute(http.MethodGet, "/api/key"),
		sessionRoute(http.MethodPost, "/api/key"),
		sessionRoute(http.MethodGet, "/api/key/"+someID),
		sessionRoute(http.MethodPatch, "/api/key/"+someID),
		sessionRoute(http.MethodDelete, "/api/key/"+someID),
		sessionRoute(http.MethodGet, "/api/invitation"),
		sessionRoute(http.MethodPost, "/api/invitation"),
		sessionRoute(http.MethodPatch, "/api/invitation/"+someID),
		sessionRoute(http.MethodDelete, "/api/invitation/"+someID),
		sessionRoute(http.MethodGet, "/api/user"),
		sessionRoute(http.MethodGet, "/api/user/"+someID),
		sessionRoute(http.MethodDelete, "/api/user/"+someID),
	}
}

// pathPattern is a route path with its id wildcard, which is how routes are
// grouped by path.
func pathPattern(path string) string {
	if before, ok := strings.CutSuffix(path, someID); ok {
		return before + "{id}"
	}

	return path
}

// TestEveryRouteIsRouted: every route of the inventory answers, as the feature
// that owns it decides, and a request to a route that needs a session and has
// none is a 401 that never reaches the database. That is the permission seam
// at the app level: if a feature declared a route without a credential, or
// the app left a feature out, it shows here.
func TestEveryRouteIsRouted(t *testing.T) {
	t.Parallel()

	for _, route := range inventory() {
		t.Run(route.method+" "+pathPattern(route.path), func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullEnv(), route.script...)
			rec := h.do(route.request(nil))

			if rec.Code != route.wantStatus {
				t.Errorf("status = %d, want %d: %s", rec.Code, route.wantStatus, rec.Body)
			}

			if got := rec.Body.String(); !strings.Contains(got, route.wantBody) {
				t.Errorf("body = %q, want it to contain %q", got, route.wantBody)
			}

			if route.session && rec.Body.String() != route.wantBody {
				t.Errorf("body = %q, want exactly %q", rec.Body, route.wantBody)
			}

			if got := h.exec.callCount(); got != route.wantCalls {
				t.Errorf("Exec calls = %d, want %d", got, route.wantCalls)
			}
		})
	}
}

// TestSessionRoutesNeedNoConfiguration: a token carries nothing that has to be
// checked against the deployment's configuration, so who is calling is decided
// by the database alone. With the deployment unconfigured, a session route
// without a credential is the 401 it always is and never touches the database,
// and a valid session is recognised (a route that needs configuration of its
// own, such as login, still says so).
func TestSessionRoutesNeedNoConfiguration(t *testing.T) {
	t.Parallel()

	for _, route := range inventory() {
		if !route.session {
			continue
		}

		t.Run(route.method+" "+pathPattern(route.path), func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, map[string]string{})
			rec := h.do(request{method: route.method, path: route.path})

			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("= %d %s, want the one 401", rec.Code, rec.Body)
			}

			if got := h.exec.callCount(); got != 0 {
				t.Errorf("Exec calls = %d, want 0", got)
			}
		})
	}

	t.Run("a valid session is recognised", func(t *testing.T) {
		t.Parallel()

		signedIn := newSession(t, memberID)
		h := newHarness(t, map[string]string{}, signedIn.activeSessionStep(roleMember))

		rec := h.do(request{method: http.MethodGet, path: pathSession, cookies: []*http.Cookie{signedIn.cookie}})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"userId":"`+memberID+`"`) {
			t.Errorf("= %d %s, want 200 for the signed-in user", rec.Code, rec.Body)
		}
	})
}

// TestOnlyTheInventoryIsRouted: a path answers exactly the methods the
// inventory lists for it, and any other is 405 with the Allow header of those.
// HEAD is not implied by GET.
func TestOnlyTheInventoryIsRouted(t *testing.T) {
	t.Parallel()

	allowed := map[string][]string{}

	for _, route := range inventory() {
		allowed[route.path] = append(allowed[route.path], route.method)
	}

	all := []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
	}

	for path, methods := range allowed {
		slices.Sort(methods)

		for _, method := range all {
			if slices.Contains(methods, method) {
				continue
			}

			t.Run(method+" "+pathPattern(path), func(t *testing.T) {
				t.Parallel()

				h := newHarness(t, fullEnv())
				rec := h.do(request{method: method, path: path})

				if rec.Code != http.StatusMethodNotAllowed {
					t.Errorf("status = %d, want 405: %s", rec.Code, rec.Body)
				}

				if got, want := rec.Header().Get("Allow"), strings.Join(methods, ", "); got != want {
					t.Errorf("Allow = %q, want %q", got, want)
				}

				if got := h.exec.callCount(); got != 0 {
					t.Errorf("Exec calls = %d, want 0", got)
				}
			})
		}
	}
}

// TestUnknownPathsAreNotFound: every path no route claims, near-misses
// included, is the JSON 404, whatever the method, without touching the
// database.
func TestUnknownPathsAreNotFound(t *testing.T) {
	t.Parallel()

	unknown := []string{
		"/", "/nope", "/healthz/", "/healthz/x", "/api", "/api/", "/api/sessions", "/api/session/",
		"/api/session/x", "/api/agent/", "/api/agents", "/api/agent/" + someID + "/keys",
		"/api/key/", "/api/keys", "/api/key/" + someID + "/token", "/api/key/" + someID + "/",
		"/api/user/" + someID + "/", "/api/users", "/api/invitation/" + someID + "/uses",
		"/api/register", "/api/login", "/api/refresh", "/API/session", "/api/first-run/x", "/keys/x",
	}

	for _, path := range unknown {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			t.Run("unknown "+method+" "+path, func(t *testing.T) {
				t.Parallel()

				h := newHarness(t, fullEnv())
				rec := h.do(request{method: method, path: path})

				if rec.Code != http.StatusNotFound || rec.Body.String() != bodyNotFound {
					t.Errorf("= %d %s, want the JSON 404", rec.Code, rec.Body)
				}

				if got := h.exec.callCount(); got != 0 {
					t.Errorf("Exec calls = %d, want 0", got)
				}
			})
		}
	}
}

// TestCredentialIsJudgedBeforeAPathID: on every route that has an id, for every
// method it takes, a request that does not present a credential is refused as
// such whatever the id is: a malformed id is never answered before the caller
// is known, so it is the 401 any request without a credential gets, and the
// database is not read.
func TestCredentialIsJudgedBeforeAPathID(t *testing.T) {
	t.Parallel()

	badIDs := map[string]string{
		"word":                       "nope",
		"upper case":                 strings.ToUpper(someID),
		"no dashes":                  strings.ReplaceAll(someID, "-", ""),
		"trailing":                   someID + "0",
		"percent-encoded upper case": someID[:35] + "%41",
	}

	for _, route := range inventory() {
		if !strings.HasSuffix(route.path, someID) {
			continue
		}

		for name, bad := range badIDs {
			t.Run(route.method+" "+pathPattern(route.path)+" "+name, func(t *testing.T) {
				t.Parallel()

				path := strings.TrimSuffix(route.path, someID) + bad

				h := newHarness(t, fullEnv())
				rec := h.do(request{method: route.method, path: path})

				if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
					t.Errorf("= %d %s, want the one 401", rec.Code, rec.Body)
				}

				if got := h.exec.callCount(); got != 0 {
					t.Errorf("Exec calls = %d, want 0", got)
				}
			})
		}
	}
}

// TestUnsafeRoutesRequireTheirMediaType: the CSRF defence is wired to every route
// that takes a method other than GET: a request without the media type the route
// takes is a 415 before any credential check, even with an empty body. A route
// takes application/json, except the token endpoints, which take a form and no
// credential, so that a cookie can mean nothing there, and which answer in the
// RFC 6749 format.
func TestUnsafeRoutesRequireTheirMediaType(t *testing.T) {
	t.Parallel()

	for _, route := range inventory() {
		if route.method == http.MethodGet {
			continue
		}

		wrong := []string{"", "text/plain", formType, "multipart/form-data"}
		wantBody := `"unsupported_media_type"`

		if route.form {
			wrong = []string{"", "text/plain", jsonType, "multipart/form-data"}
			wantBody = `"error":"invalid_request"`
		}

		for _, contentType := range wrong {
			label := contentType
			if contentType == "" {
				label = "no content type"
			}

			t.Run(route.method+" "+pathPattern(route.path)+" "+label, func(t *testing.T) {
				t.Parallel()

				h := newHarness(t, fullEnv())
				req := request{method: route.method, path: route.path, noContentType: contentType == ""}
				if contentType != "" {
					req.headers = map[string]string{"Content-Type": contentType}
				}

				rec := h.do(req)

				if rec.Code != http.StatusUnsupportedMediaType || !strings.Contains(rec.Body.String(), wantBody) {
					t.Errorf("= %d %s, want 415 containing %s", rec.Code, rec.Body, wantBody)
				}

				if got := h.exec.callCount(); got != 0 {
					t.Errorf("Exec calls = %d, want 0", got)
				}
			})
		}
	}
}

// TestBodyLimits: each route's body cap, as declared by its feature, holds
// through the app. A body of exactly the cap is read (and refused or answered
// as the route decides), one byte more is 413 without the route running. Every
// route of the inventory has a row, so a route cannot be added, or its cap
// lost, without this table noticing: a route that writes is never unbounded.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestBodyLimits(t *testing.T) {
	t.Parallel()

	type limitCase struct {
		method, path string
		limit        int
		// atLimit is the status of a body of exactly the cap: a body of
		// spaces is not a JSON document, so a route that reads it refuses it.
		atLimit int
		// script is what the route reads from the database when it answers
		// the body at the cap. A body over the cap never gets that far.
		script []step
	}

	const (
		defaultCap = httpapi.DefaultMaxBody
		unauth     = http.StatusUnauthorized
	)

	tests := map[string]limitCase{
		"health": {http.MethodGet, "/healthz", defaultCap, http.StatusOK, nil},
		"first run": {http.MethodGet, "/api/first-run", defaultCap, http.StatusOK,
			[]step{{match: "has_users", results: rows([]any{int64(1), int64(1)}), err: nil}}},
		"register begin":    {http.MethodPost, "/api/register/begin", 4 << 10, http.StatusBadRequest, nil},
		"register finish":   {http.MethodPost, "/api/register/finish", 32 << 10, http.StatusBadRequest, nil},
		"login begin":       {http.MethodPost, "/api/login/begin", 1 << 10, http.StatusOK, nil},
		"login finish":      {http.MethodPost, "/api/login/finish", 16 << 10, http.StatusBadRequest, nil},
		"session":           {http.MethodGet, "/api/session", defaultCap, unauth, nil},
		"logout":            {http.MethodPost, "/api/logout", defaultCap, unauth, nil},
		"agent list":        {http.MethodGet, "/api/agent", 8 << 10, unauth, nil},
		"agent create":      {http.MethodPost, "/api/agent", 8 << 10, unauth, nil},
		"agent get":         {http.MethodGet, "/api/agent/" + someID, 8 << 10, unauth, nil},
		"agent rename":      {http.MethodPatch, "/api/agent/" + someID, 8 << 10, unauth, nil},
		"agent revoke":      {http.MethodDelete, "/api/agent/" + someID, 8 << 10, unauth, nil},
		"key list":          {http.MethodGet, "/api/key", 8 << 10, unauth, nil},
		"key create":        {http.MethodPost, "/api/key", 8 << 10, unauth, nil},
		"key get":           {http.MethodGet, "/api/key/" + someID, 8 << 10, unauth, nil},
		"key rename":        {http.MethodPatch, "/api/key/" + someID, 8 << 10, unauth, nil},
		"key revoke":        {http.MethodDelete, "/api/key/" + someID, 8 << 10, unauth, nil},
		"invitation list":   {http.MethodGet, "/api/invitation", 4 << 10, unauth, nil},
		"invitation create": {http.MethodPost, "/api/invitation", 4 << 10, unauth, nil},
		"invitation patch":  {http.MethodPatch, "/api/invitation/" + someID, 4 << 10, unauth, nil},
		"invitation revoke": {http.MethodDelete, "/api/invitation/" + someID, 4 << 10, unauth, nil},
		"user list":         {http.MethodGet, "/api/user", 1024, unauth, nil},
		"user get":          {http.MethodGet, "/api/user/" + someID, 1024, unauth, nil},
		"user revoke":       {http.MethodDelete, "/api/user/" + someID, 1024, unauth, nil},

		"oauth metadata":       {http.MethodGet, "/.well-known/oauth-authorization-server", 1024, http.StatusOK, nil},
		"openid configuration": {http.MethodGet, "/.well-known/openid-configuration", 1024, http.StatusOK, nil},
		"key set":              {http.MethodGet, "/.well-known/jwks.json", 1024, http.StatusOK, nil},
		"oauth authorize":      {http.MethodGet, "/oauth/authorize", 8 << 10, http.StatusFound, nil},
		"oauth request":        {http.MethodGet, "/api/oauth/request", 8 << 10, http.StatusBadRequest, nil},
		"oauth consent":        {http.MethodPost, "/api/oauth/consent", 12 << 10, unauth, nil},
		"oauth token":          {http.MethodPost, "/oauth/token", 8 << 10, http.StatusBadRequest, nil},
		"oauth revoke":         {http.MethodPost, "/oauth/revoke", 4 << 10, http.StatusBadRequest, nil},
		"oauth introspect":     {http.MethodPost, "/oauth/introspect", 2 << 10, http.StatusBadRequest, nil},
		"grant list":           {http.MethodGet, "/api/grant", 1 << 10, unauth, nil},
		"grant get":            {http.MethodGet, "/api/grant/" + someID, 1 << 10, unauth, nil},
		"grant revoke":         {http.MethodDelete, "/api/grant/" + someID, 1 << 10, unauth, nil},
	}

	t.Run("every route has a row", func(t *testing.T) {
		t.Parallel()

		covered := map[string]bool{}
		for _, tt := range tests {
			covered[tt.method+" "+pathPattern(tt.path)] = true
		}

		for _, route := range inventory() {
			if key := route.method + " " + pathPattern(route.path); !covered[key] {
				t.Errorf("route %s has no body-limit row", key)
			}
		}

		if len(tests) != len(inventory()) {
			t.Errorf("%d rows for %d routes", len(tests), len(inventory()))
		}
	})

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullEnv(), tt.script...)
			headers := mediaHeaders(tt.path)

			rec := h.do(request{method: tt.method, path: tt.path, body: strings.Repeat(" ", tt.limit), headers: headers})
			if rec.Code != tt.atLimit {
				t.Errorf("body of %d bytes: status = %d, want %d: %s", tt.limit, rec.Code, tt.atLimit, rec.Body)
			}

			wantBody := overLimitBody(tt.path)

			rec = h.do(request{method: tt.method, path: tt.path, body: strings.Repeat(" ", tt.limit+1), headers: headers})
			if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), wantBody) {
				t.Errorf("body of %d bytes: = %d %s, want 413 containing %s", tt.limit+1, rec.Code, rec.Body, wantBody)
			}

			if got := h.exec.callCount(); got != len(tt.script) {
				t.Errorf("Exec calls = %d, want %d (all from the body at the cap)", got, len(tt.script))
			}
		})
	}
}

// mediaHeaders is the Content-Type header a route takes, when it is not JSON.
func mediaHeaders(path string) map[string]string {
	if isForm(path) {
		return map[string]string{"Content-Type": formType}
	}

	return map[string]string{}
}

// isForm reports whether the route at path takes a form.
func isForm(path string) bool {
	return slices.ContainsFunc(inventory(), func(route inventoryRoute) bool { return route.form && route.path == path })
}

// overLimitBody is what a body over a route's cap is answered with: the detailed
// code, except on the endpoints that answer in the RFC 6749 format, which has no
// room for it.
func overLimitBody(path string) string {
	if path == "/oauth/authorize" || isForm(path) {
		return `"error":"invalid_request"`
	}

	return `"body_too_large"`
}

// TestNoneRoutes: what each route that needs no credential does, through the
// real stack, for the requests a stranger can make. The database is read only
// where the feature needs it, and the outcome of a failing database is the
// store's classified error and not a cause.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestNoneRoutes(t *testing.T) {
	t.Parallel()

	const firstRunQuery = "has_users"

	state := func(users, invitation any) []store.Result { return rows([]any{users, invitation}) }

	tests := map[string]struct {
		env        map[string]string
		method     string
		path       string
		body       string
		script     []step
		wantStatus int
		wantBody   string   // a fragment
		wantLogged []string // every failure the app logged, client errors too
	}{
		"first run: an account exists": {
			env: fullEnv(), method: http.MethodGet, path: "/api/first-run",
			script:     []step{{match: firstRunQuery, results: state(int64(1), int64(0)), err: nil}},
			wantStatus: http.StatusOK, wantBody: `{"status":"invitation_accepted"}`,
		},
		"first run: invitation waiting": {
			env: fullEnv(), method: http.MethodGet, path: "/api/first-run",
			script:     []step{{match: firstRunQuery, results: state(int64(0), int64(1)), err: nil}},
			wantStatus: http.StatusOK, wantBody: `{"status":"invitation_pending"}`,
		},
		"first run: nothing, no secret": {
			env: fullEnv(), method: http.MethodGet, path: "/api/first-run",
			script:     []step{{match: firstRunQuery, results: state(int64(0), int64(0)), err: nil}},
			wantStatus: http.StatusOK, wantBody: `{"status":"missing_secret"}`,
		},
		"first run: database down": {
			env: fullEnv(), method: http.MethodGet, path: "/api/first-run",
			script:     []step{{match: firstRunQuery, results: nil, err: errDB}},
			wantStatus: http.StatusServiceUnavailable, wantBody: `"first-run status is temporarily unavailable"`,
			wantLogged: []string{store.CodeFirstRunCheckFailed},
		},
		"first run: boolean as float": {
			env: fullEnv(), method: http.MethodGet, path: "/api/first-run",
			script:     []step{{match: firstRunQuery, results: state(float64(1), int64(0)), err: nil}},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeFirstRunCheckRejected},
		},
		"register begin: not redeemable": {
			env: fullEnv(), method: http.MethodPost, path: "/api/register/begin",
			body:       `{"invitationCode":"` + someCode + `","name":"Alice"}`,
			script:     []step{{match: readInvitation, results: rows(), err: nil}},
			wantStatus: http.StatusForbidden, wantBody: `"invalid_invitation"`,
			wantLogged: []string{"invalid_invitation"},
		},
		"register begin: redeemable": {
			env: fullEnv(), method: http.MethodPost, path: "/api/register/begin",
			body:       `{"invitationCode":"` + someCode + `","name":"Alice"}`,
			script:     []step{{match: readInvitation, results: rows([]any{"first_run"}), err: nil}},
			wantStatus: http.StatusOK, wantBody: `"userVerification":"required"`,
		},
		"register begin: type as a blob": {
			env: fullEnv(), method: http.MethodPost, path: "/api/register/begin",
			body:       `{"invitationCode":"` + someCode + `","name":"Alice"}`,
			script:     []step{{match: readInvitation, results: rows([]any{[]byte("first_run")}), err: nil}},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeInvitationCheckRejected},
		},
		"register begin: unconfigured": {
			env: map[string]string{}, method: http.MethodPost, path: "/api/register/begin",
			body:       `{"invitationCode":"` + someCode + `","name":"Alice"}`,
			wantStatus: http.StatusServiceUnavailable, wantBody: `"not_configured"`,
			wantLogged: []string{"not_configured"},
		},
		"register begin: malformed code makes no query": {
			env: fullEnv(), method: http.MethodPost, path: "/api/register/begin",
			body:       `{"invitationCode":"not a code!","name":"Alice"}`,
			wantStatus: http.StatusBadRequest, wantBody: `"invalid_invitation"`,
			wantLogged: []string{"invalid_invitation"},
		},
		"register begin: not JSON": {
			env: fullEnv(), method: http.MethodPost, path: "/api/register/begin", body: `nope`,
			wantStatus: http.StatusBadRequest, wantBody: `"invalid_json"`, wantLogged: []string{"invalid_json"},
		},
		"login begin": {
			env: fullEnv(), method: http.MethodPost, path: "/api/login/begin",
			wantStatus: http.StatusOK, wantBody: `"rpId":"example.com"`,
		},
		"login begin: unconfigured": {
			env: map[string]string{}, method: http.MethodPost, path: "/api/login/begin",
			wantStatus: http.StatusServiceUnavailable, wantBody: `"not_configured"`,
			wantLogged: []string{"not_configured"},
		},
		"login finish: not JSON": {
			env: fullEnv(), method: http.MethodPost, path: "/api/login/finish", body: `nope`,
			wantStatus: http.StatusBadRequest, wantBody: `"invalid_json"`, wantLogged: []string{"invalid_json"},
		},
		"health needs no configuration": {
			env: map[string]string{}, method: http.MethodGet, path: "/healthz",
			wantStatus: http.StatusOK, wantBody: `{"status":"ok"}`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tt.env, tt.script...)
			rec := h.do(request{method: tt.method, path: tt.path, body: tt.body})

			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("= %d %s, want %d containing %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if got := h.exec.callCount(); got != len(tt.script) {
				t.Errorf("Exec calls = %d, want %d", got, len(tt.script))
			}

			if got := h.loggedCodes(); !slices.Equal(got, tt.wantLogged) {
				t.Errorf("logged codes = %v, want %v", got, tt.wantLogged)
			}

			if strings.Contains(rec.Body.String(), errDB.Error()) {
				t.Errorf("body leaks the cause: %s", rec.Body)
			}
		})
	}
}
