//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
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

func inventory() []inventoryRoute {
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
			rec := h.do(request{method: route.method, path: route.path, body: route.body})

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

// TestSessionRoutesNeedConfiguration: with the deployment unconfigured, a
// session route cannot tell who is calling, which is 503 and not a 401 (an
// outage is not a sign-out), and never touches the database.
func TestSessionRoutesNeedConfiguration(t *testing.T) {
	t.Parallel()

	for _, route := range inventory() {
		if !route.session {
			continue
		}

		t.Run(route.method+" "+pathPattern(route.path), func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, map[string]string{})
			rec := h.do(request{method: route.method, path: route.path})

			want := `{"error":{"code":"not_configured","message":"the service is not configured"}}` + "\n"
			if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != want {
				t.Errorf("= %d %s, want 503 not_configured", rec.Code, rec.Body)
			}

			if got := h.exec.callCount(); got != 0 {
				t.Errorf("Exec calls = %d, want 0", got)
			}
		})
	}
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
		"/api/user/" + someID + "/", "/api/users", "/api/invitation/" + someID + "/uses",
		"/api/register", "/api/login", "/api/refresh", "/API/session", "/api/first-run/x", "/keys/x/.well-known/jwks.json",
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
// is known, so it is 503 not_configured with no configuration at all and 401
// without a session, and the database is not read for either.
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

				// No configuration at all: the service is not configured.
				h := newHarness(t, map[string]string{})
				rec := h.do(request{method: route.method, path: path})

				if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"not_configured"`) {
					t.Errorf("unconfigured = %d %s, want 503 not_configured", rec.Code, rec.Body)
				}

				if got := h.exec.callCount(); got != 0 {
					t.Errorf("Exec calls = %d, want 0", got)
				}
			})
		}
	}
}

// TestUnsafeRoutesRequireJSON: the CSRF defence is wired to every route that
// takes a method other than GET: a request without application/json is a 415
// before any credential check, even with an empty body.
func TestUnsafeRoutesRequireJSON(t *testing.T) {
	t.Parallel()

	for _, route := range inventory() {
		if route.method == http.MethodGet {
			continue
		}

		for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
			t.Run(route.method+" "+pathPattern(route.path)+" "+contentType, func(t *testing.T) {
				t.Parallel()

				h := newHarness(t, fullEnv())
				req := request{method: route.method, path: route.path, noContentType: contentType == ""}
				if contentType != "" {
					req.headers = map[string]string{"Content-Type": contentType}
				}

				rec := h.do(req)

				if rec.Code != http.StatusUnsupportedMediaType ||
					!strings.Contains(rec.Body.String(), `"unsupported_media_type"`) {
					t.Errorf("= %d %s, want 415 unsupported_media_type", rec.Code, rec.Body)
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
		"invitation list":   {http.MethodGet, "/api/invitation", 4 << 10, unauth, nil},
		"invitation create": {http.MethodPost, "/api/invitation", 4 << 10, unauth, nil},
		"invitation patch":  {http.MethodPatch, "/api/invitation/" + someID, 4 << 10, unauth, nil},
		"invitation revoke": {http.MethodDelete, "/api/invitation/" + someID, 4 << 10, unauth, nil},
		"user list":         {http.MethodGet, "/api/user", 1024, unauth, nil},
		"user get":          {http.MethodGet, "/api/user/" + someID, 1024, unauth, nil},
		"user revoke":       {http.MethodDelete, "/api/user/" + someID, 1024, unauth, nil},
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

			rec := h.do(request{method: tt.method, path: tt.path, body: strings.Repeat(" ", tt.limit)})
			if rec.Code != tt.atLimit {
				t.Errorf("body of %d bytes: status = %d, want %d: %s", tt.limit, rec.Code, tt.atLimit, rec.Body)
			}

			rec = h.do(request{method: tt.method, path: tt.path, body: strings.Repeat(" ", tt.limit+1)})
			if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"body_too_large"`) {
				t.Errorf("body of %d bytes: = %d %s, want 413 body_too_large", tt.limit+1, rec.Code, rec.Body)
			}

			if got := h.exec.callCount(); got != len(tt.script) {
				t.Errorf("Exec calls = %d, want %d (all from the body at the cap)", got, len(tt.script))
			}
		})
	}
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
			script:     []step{{match: "FROM invitations i", results: rows(), err: nil}},
			wantStatus: http.StatusForbidden, wantBody: `"invalid_invitation"`,
			wantLogged: []string{"invalid_invitation"},
		},
		"register begin: redeemable": {
			env: fullEnv(), method: http.MethodPost, path: "/api/register/begin",
			body:       `{"invitationCode":"` + someCode + `","name":"Alice"}`,
			script:     []step{{match: "FROM invitations i", results: rows([]any{"first_run"}), err: nil}},
			wantStatus: http.StatusOK, wantBody: `"userVerification":"required"`,
		},
		"register begin: type as a blob": {
			env: fullEnv(), method: http.MethodPost, path: "/api/register/begin",
			body:       `{"invitationCode":"` + someCode + `","name":"Alice"}`,
			script:     []step{{match: "FROM invitations i", results: rows([]any{[]byte("first_run")}), err: nil}},
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
