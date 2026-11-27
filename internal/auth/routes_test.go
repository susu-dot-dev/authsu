//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// panicOf runs build and reports whether it panicked, and with what.
func panicOf(build func()) (string, bool) {
	var (
		message  string
		panicked bool
	)

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				message, panicked = fmt.Sprint(recovered), true
			}
		}()

		build()
	}()

	return message, panicked
}

func okHandle(*auth.Call) result.Result[httpapi.Response] {
	return result.Ok(httpapi.JSON(http.StatusOK, nil))
}

// goodRoute is a valid declaration; each case below spoils one thing about it.
func goodRoute() auth.Route {
	return auth.Route{
		Method: http.MethodGet, Path: "/x/{id}", MaxBody: 0, Credential: auth.Authenticated,
		Access: auth.Needs(scope.UserRead), Handle: okHandle,
	}
}

// spoiled is goodRoute changed by change.
func spoiled(change func(*auth.Route)) []auth.Route {
	route := goodRoute()
	change(&route)

	return []auth.Route{route}
}

func withPath(path string) []auth.Route {
	return spoiled(func(r *auth.Route) { r.Path = path })
}

func withMethod(method string) []auth.Route {
	return spoiled(func(r *auth.Route) { r.Method = method })
}

func withCredential(credential auth.Credential) []auth.Route {
	return spoiled(func(r *auth.Route) { r.Credential = credential })
}

// withForm is a form route: a POST, which has a body to give a type to, with
// credential and access as given.
func withForm(credential auth.Credential, method string) []auth.Route {
	return spoiled(func(r *auth.Route) {
		r.Method, r.Media, r.Credential, r.Access = method, httpapi.MediaForm, credential, accessFor(credential)
	})
}

func withMedia(media httpapi.Media) []auth.Route {
	return spoiled(func(r *auth.Route) { r.Media = media })
}

func withErrors(format httpapi.ErrorFormat) []auth.Route {
	return spoiled(func(r *auth.Route) { r.Errors = format })
}

func withMaxBody(maxBody int64) []auth.Route {
	return spoiled(func(r *auth.Route) { r.MaxBody = maxBody })
}

// What the panic of each kind of mistake says.
const (
	saysMethod  = "the method is not"
	saysSlash   = "the path must start with /"
	saysWhole   = "whole {id} segment"
	saysKind    = "Credential must be None or Authenticated"
	saysMaxBody = "MaxBody must be from 0"
	saysMedia   = "Media must be"
	saysErrors  = "Errors must be"
	saysForm    = "no CSRF defence"
	saysNoBody  = "has no body"

	saysGrantsAsUser = "GrantsAsUser relaxes WithoutAgents"
)

// routeProblems are the mistakes in one route's declaration.
func routeProblems() map[string]struct {
	routes []auth.Route
	want   string
} {
	type problem = struct {
		routes []auth.Route
		want   string
	}

	return map[string]problem{
		"nil Handle":             {spoiled(func(r *auth.Route) { r.Handle = nil }), "Handle is nil"},
		"credential not set":     {withCredential(0), saysKind},
		"credential not known":   {withCredential(99), saysKind},
		"Access on a None route": {withCredential(auth.None), "Access needs an authenticated"},
		"Access not declared":    {spoiled(func(r *auth.Route) { r.Access = auth.Access{} }), "Access must be declared"},
		"Access names no such scope": {
			spoiled(func(r *auth.Route) { r.Access = auth.Needs("nope:read") }), "scope that does not exist",
		},
		"GrantsAsUser alone": {
			spoiled(func(r *auth.Route) { r.Access = auth.Needs(scope.UserRead).GrantsAsUser() }), saysGrantsAsUser,
		},
		"GrantsAsUser without FromGrants": {
			spoiled(func(r *auth.Route) { r.Access = auth.Needs(scope.UserRead).WithoutAgents().GrantsAsUser() }),
			saysGrantsAsUser,
		},
		"GrantsAsUser without WithoutAgents": {
			spoiled(func(r *auth.Route) { r.Access = auth.Needs(scope.UserRead).FromGrants().GrantsAsUser() }),
			saysGrantsAsUser,
		},
		"Media not known":             {withMedia(2), saysMedia},
		"Errors not known":            {withErrors(2), saysErrors},
		"a form on an Authenticated":  {withForm(auth.Authenticated, http.MethodPost), saysForm},
		"a form PATCH, Authenticated": {withForm(auth.Authenticated, http.MethodPatch), saysForm},
		"a form on a GET":             {withForm(auth.None, http.MethodGet), saysNoBody},
		"a form on a HEAD":            {withForm(auth.None, http.MethodHead), saysNoBody},
		"negative MaxBody":            {withMaxBody(-1), saysMaxBody},
		"MaxBody over the default":    {withMaxBody(httpapi.DefaultMaxBody + 1), saysMaxBody},
		"no method":                   {withMethod(""), saysMethod},
		"lower-case method":           {withMethod("get"), saysMethod},
		"OPTIONS is the preflight's":  {withMethod(http.MethodOptions), saysMethod},
		"CONNECT":                     {withMethod(http.MethodConnect), saysMethod},
		"TRACE":                       {withMethod(http.MethodTrace), saysMethod},
		"a method in the path":        {withPath("GET /x/{id}"), saysSlash},
		"a host in the path":          {withPath("example.com/x"), saysSlash},
		"empty path":                  {withPath(""), saysSlash},
	}
}

// wildcardProblems are the mistakes in a path's wildcards.
func wildcardProblems() map[string]struct {
	routes []auth.Route
	want   string
} {
	type problem = struct {
		routes []auth.Route
		want   string
	}

	return map[string]problem{
		"a wildcard twice":               {withPath("/x/{id}/y/{id}"), "only one {id}"},
		"two different wildcards":        {withPath("/x/{first}/{second}"), "only wildcard a path may have is {id}"},
		"a wildcard with another name":   {withPath("/x/{name}"), "only wildcard a path may have is {id}"},
		"a wildcard that is part of one": {withPath("/x/a{id}"), saysWhole},
		"a wildcard with a tail":         {withPath("/x/{id}z"), saysWhole},
		"an unclosed wildcard":           {withPath("/x/{id"), saysWhole},
		"an unopened wildcard":           {withPath("/x/id}"), saysWhole},
		"a nested wildcard":              {withPath("/x/{{id}}"), saysWhole},
		"a wildcard without a name":      {withPath("/x/{}"), "only wildcard a path may have is {id}"},
		"a multi-segment wildcard":       {withPath("/x/{id...}"), "only wildcard a path may have is {id}"},
		"a path the mux refuses":         {withPath("/x/{a b}"), ""},
	}
}

// duplicateProblems are routes that cannot both be declared.
func duplicateProblems() map[string]struct {
	routes []auth.Route
	want   string
} {
	type problem = struct {
		routes []auth.Route
		want   string
	}

	other := goodRoute()
	other.Access = auth.Open()

	renamed := goodRoute()
	renamed.Method = http.MethodPost
	renamed.Path = "/x/{other}"

	return map[string]problem{
		"the same route twice":                     {[]auth.Route{goodRoute(), goodRoute()}, "declared twice"},
		"the same method and path, other rules":    {[]auth.Route{goodRoute(), other}, "declared twice"},
		"two names for one path shape (the mux's)": {[]auth.Route{goodRoute(), renamed}, ""},
	}
}

// depProblems are missing collaborators.
func depProblems() map[string]struct {
	change func(*auth.Deps)
	want   string
} {
	return map[string]struct {
		change func(*auth.Deps)
		want   string
	}{
		"no Credentials": {func(d *auth.Deps) { d.Credentials = nil }, "Deps.Credentials"},
		"no Now":         {func(d *auth.Deps) { d.Now = nil }, "Deps.Now"},
		"no Getenv":      {func(d *auth.Deps) { d.Getenv = nil }, "Deps.Getenv"},
		"no Log":         {func(d *auth.Deps) { d.Log = nil }, "Deps.Log"},
	}
}

// TestHandlerPanicsOnAProgrammingError: a bad route table or missing
// dependency is found when the handler is built, never by a request, and the
// message names what is wrong. Each case changes one thing about a valid
// declaration.
func TestHandlerPanicsOnAProgrammingError(t *testing.T) {
	t.Parallel()

	for _, group := range []map[string]struct {
		routes []auth.Route
		want   string
	}{routeProblems(), wildcardProblems(), duplicateProblems()} {
		for name, tt := range group {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				message, panicked := panicOf(func() { auth.Handler(tt.routes, newRig(t).deps()) })
				if !panicked || !strings.Contains(message, tt.want) {
					t.Errorf("panicked = %v with %q, want a panic containing %q", panicked, message, tt.want)
				}
			})
		}
	}

	for name, tt := range depProblems() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			deps := newRig(t).deps()
			tt.change(&deps)

			// Without routes too: the dependencies are checked first.
			for _, routes := range [][]auth.Route{nil, {goodRoute()}} {
				message, panicked := panicOf(func() { auth.Handler(routes, deps) })
				if !panicked || !strings.Contains(message, tt.want) {
					t.Errorf("panicked = %v with %q, want a panic containing %q", panicked, message, tt.want)
				}
			}
		})
	}
}

// route is a route that is valid on its own.
func route(method, path string, credential auth.Credential, maxBody int64) auth.Route {
	return auth.Route{
		Method: method, Path: path, MaxBody: maxBody, Credential: credential,
		Access: accessFor(credential), Handle: okHandle,
	}
}

// TestHandlerAcceptsEveryValidDeclaration: the counterpart of the panics, so a
// check that is too strict is found too.
func TestHandlerAcceptsEveryValidDeclaration(t *testing.T) {
	t.Parallel()

	get, none, session := http.MethodGet, auth.None, auth.Authenticated

	tests := map[string][]auth.Route{
		"no routes":                     nil,
		"MaxBody exactly the default":   {route("POST", "/m", none, httpapi.DefaultMaxBody)},
		"MaxBody of one":                {route("POST", "/m", none, 1)},
		"the same path in two methods":  {route(get, "/m/{id}", session, 0), route("DELETE", "/m/{id}", session, 0)},
		"the same method on two paths":  {route(get, "/m", none, 0), route(get, "/n", none, 0)},
		"a path and its wildcard child": {route(get, "/m", none, 0), route(get, "/m/{id}", none, 0)},
		"an exact root":                 {route(get, "/{$}", none, 0)},
		"the root":                      {route(get, "/", none, 0)},
		"a form POST that is None":      {withForm(auth.None, http.MethodPost)[0]},
		"a form PUT that is None":       {withForm(auth.None, http.MethodPut)[0]},
		"a form PATCH that is None":     {withForm(auth.None, http.MethodPatch)[0]},
		"a form DELETE that is None":    {withForm(auth.None, http.MethodDelete)[0]},
		"OAuth errors, Authenticated":   withErrors(httpapi.ErrorsOAuth),
		"a grant let through the refusal of agents": spoiled(func(r *auth.Route) {
			r.Access = auth.Needs(scope.UserRead).WithoutAgents().FromGrants().GrantsAsUser()
		}),
		"JSON media said out loud": withMedia(httpapi.MediaJSON),
		"API errors said out loud": withErrors(httpapi.ErrorsAPI),
		"every method": {
			route("GET", "/m", none, 0), route("HEAD", "/m", none, 0), route("POST", "/m", none, 0),
			route("PUT", "/m", none, 0), route("PATCH", "/m", none, 0), route("DELETE", "/m", none, 0),
		},
	}

	for name, routes := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if message, panicked := panicOf(func() { auth.Handler(routes, newRig(t).deps()) }); panicked {
				t.Errorf("Handler panicked: %s", message)
			}
		})
	}
}

// record is a route body that records which route ran.
func (r *rig) record(name string) func(*auth.Call) result.Result[httpapi.Response] {
	return func(call *auth.Call) result.Result[httpapi.Response] {
		r.ran = append(r.ran, name)
		r.handled = append(r.handled, call)

		return result.Ok(httpapi.JSON(http.StatusOK, name))
	}
}

// dispatchTable is a path that answers three methods, and a path that answers
// one.
func (r *rig) dispatchTable() []auth.Route {
	return []auth.Route{
		r.recording(http.MethodPatch, patternMulti, auth.Authenticated, auth.Open(), "patch"),
		r.recording(http.MethodGet, patternMulti, auth.None, auth.Access{}, "get"),
		r.recording(http.MethodDelete, patternMulti, auth.Authenticated, auth.Needs(scope.UserRead), "delete"),
		r.recording(http.MethodGet, pathSingle, auth.Authenticated, auth.Open(), "single"),
	}
}

// recording is a route whose body records its name.
func (r *rig) recording(
	method, path string, credential auth.Credential, access auth.Access, name string,
) auth.Route {
	return auth.Route{
		Method: method, Path: path, MaxBody: 0, Credential: credential, Access: access, Handle: r.record(name),
	}
}

// dispatchCase is one request against dispatchTable.
type dispatchCase struct {
	method, target string
	session        bool
	wantStatus     int
	wantRan        []string
	wantAllow      string
}

const (
	allowMulti   = "DELETE, GET, PATCH"
	patternMulti = "/multi/{id}"
	pathMulti    = "/multi/"
	pathSingle   = "/single"
	pathLimits   = "/limits"
	pathOther    = "/other"
)

func dispatchCases() map[string]dispatchCase {
	multi, bad := pathMulti+itemID, pathMulti+"NOPE"

	return map[string]dispatchCase{
		"get is declared":          {http.MethodGet, multi, false, 200, []string{"get"}, ""},
		"patch is declared":        {http.MethodPatch, multi, true, 200, []string{"patch"}, ""},
		"delete is declared":       {http.MethodDelete, multi, true, 200, []string{"delete"}, ""},
		"patch without a session":  {http.MethodPatch, multi, false, 401, nil, ""},
		"put is not declared":      {http.MethodPut, multi, true, 405, nil, allowMulti},
		"post is not declared":     {http.MethodPost, multi, true, 405, nil, allowMulti},
		"head is not get":          {http.MethodHead, multi, true, 405, nil, allowMulti},
		"options is not declared":  {http.MethodOptions, multi, true, 405, nil, allowMulti},
		"a made-up method":         {"BREW", multi, true, 405, nil, allowMulti},
		"a lower-case method":      {"get", multi, true, 405, nil, allowMulti},
		"405 before a bad id":      {http.MethodPut, bad, false, 405, nil, allowMulti},
		"405 before the cookie":    {http.MethodPost, pathSingle, false, 405, nil, "GET"},
		"single path, its method":  {http.MethodGet, pathSingle, true, 200, []string{"single"}, ""},
		"the cred beats a bad id":  {http.MethodPatch, bad, false, 401, nil, ""},
		"a bad id, signed in":      {http.MethodPatch, bad, true, 400, nil, ""},
		"a bad id on a none route": {http.MethodGet, bad, false, 400, nil, ""},
	}
}

// TestMethodDispatch: one path, several methods. The request's method picks the
// route; one the path does not have is 405 with the others in Allow, sorted,
// and nothing else runs: not the credential check, not the store.
func TestMethodDispatch(t *testing.T) {
	t.Parallel()

	for name, tt := range dispatchCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			var cookies []*http.Cookie
			if tt.session {
				cookies = []*http.Cookie{sessionCookie(r.session())}
			}

			rec := r.serve(r.dispatchTable(), request{method: tt.method, target: tt.target, cookies: cookies})

			if rec.Code != tt.wantStatus || rec.Header().Get("Allow") != tt.wantAllow {
				t.Errorf("response = %d Allow %q, want %d Allow %q (%s)",
					rec.Code, rec.Header().Get("Allow"), tt.wantStatus, tt.wantAllow, rec.Body)
			}

			if !slices.Equal(r.ran, tt.wantRan) {
				t.Errorf("ran %v, want %v", r.ran, tt.wantRan)
			}

			if tt.wantStatus == http.StatusMethodNotAllowed &&
				(len(r.creds.calls) != 0 || len(r.logged) != 1 || r.logged[0].Code != "method_not_allowed") {
				t.Errorf("store read %d times, logged %v: want no reads and method_not_allowed", len(r.creds.calls), r.logged)
			}
		})
	}
}

const (
	small   = 16
	medium  = 64
	oneMiB  = 1 << 20
	overOne = oneMiB + 1
)

// limitTable is a path whose methods have different body limits, and another
// path with its own.
func (r *rig) limitTable() []auth.Route {
	return []auth.Route{
		r.limited(http.MethodPost, pathLimits, small, auth.None, "post"),
		r.limited(http.MethodPatch, pathLimits, medium, auth.Authenticated, "patch"),
		r.limited(http.MethodPut, pathLimits, 0, auth.None, "put"),
		r.limited(http.MethodDelete, pathLimits, httpapi.DefaultMaxBody, auth.None, "delete"),
		r.limited(http.MethodPost, pathOther, medium, auth.None, "other"),
	}
}

// limited is a route with a body limit whose body records its name.
func (r *rig) limited(method, path string, maxBody int64, credential auth.Credential, name string) auth.Route {
	return auth.Route{
		Method: method, Path: path, MaxBody: maxBody,
		Credential: credential, Access: accessFor(credential), Handle: r.record(name),
	}
}

type limitCase struct {
	method, path string
	bodyLen      int
	session      bool
	want         int
}

func limitCases() map[string]limitCase {
	limits, other := pathLimits, pathOther

	return map[string]limitCase{
		"post at its limit":                   {http.MethodPost, limits, small, false, 200},
		"post one over":                       {http.MethodPost, limits, small + 1, false, 413},
		"post empty":                          {http.MethodPost, limits, 0, false, 200},
		"post is not held to patch's limit":   {http.MethodPost, limits, medium, false, 413},
		"patch at its limit":                  {http.MethodPatch, limits, medium, true, 200},
		"patch one over":                      {http.MethodPatch, limits, medium + 1, true, 413},
		"patch is not held to post's limit":   {http.MethodPatch, limits, small + 1, true, 200},
		"patch over the limit, no session":    {http.MethodPatch, limits, medium + 1, false, 413},
		"patch under the limit, no session":   {http.MethodPatch, limits, 1, false, 401},
		"zero means the default":              {http.MethodPut, limits, oneMiB, false, 200},
		"zero, one over the default":          {http.MethodPut, limits, overOne, false, 413},
		"the default exactly":                 {http.MethodDelete, limits, oneMiB, false, 200},
		"the default, one over":               {http.MethodDelete, limits, overOne, false, 413},
		"another path keeps its own limit":    {http.MethodPost, other, medium, false, 200},
		"another path, one over its limit":    {http.MethodPost, other, medium + 1, false, 413},
		"another path is not held to a limit": {http.MethodPost, other, small + 1, false, 200},
	}
}

// TestBodyLimitsArePerMethod: each method of a path is measured against its own
// limit, a body at the limit is delivered whole and one byte more is 413
// before the route, the credential check and the store, and a limit on one
// method does not constrain another.
func TestBodyLimitsArePerMethod(t *testing.T) {
	t.Parallel()

	for name, tt := range limitCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			var cookies []*http.Cookie
			if tt.session {
				cookies = []*http.Cookie{sessionCookie(r.session())}
			}

			rec := r.serve(r.limitTable(), request{
				method: tt.method, target: tt.path, body: strings.Repeat("a", tt.bodyLen), cookies: cookies,
			})
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tt.want, rec.Body)
			}

			tt.checkRoute(t, r, rec)
		})
	}
}

// checkRoute checks what the route and the store saw of the request.
func (tt limitCase) checkRoute(t *testing.T, r *rig, rec *httptest.ResponseRecorder) {
	t.Helper()

	switch tt.want {
	case http.StatusOK:
		if len(r.handled) != 1 || len(r.handled[0].Request.Body) != tt.bodyLen {
			t.Errorf("route got %d calls, want one with a %d-byte body", len(r.handled), tt.bodyLen)
		}
	case http.StatusRequestEntityTooLarge:
		if len(r.handled) != 0 || len(r.creds.calls) != 0 || !strings.Contains(rec.Body.String(), "body_too_large") {
			t.Errorf("route ran %d times, store read %d times, body %q: want neither and body_too_large",
				len(r.handled), len(r.creds.calls), rec.Body)
		}
	}
}

const textPlain = "text/plain"

// TestUnsafeMethodsNeedJSONBeforeAuth: the CSRF rule is httpapi's and holds for
// every route the boundary registers, before the credential or the store.
func TestUnsafeMethodsNeedJSONBeforeAuth(t *testing.T) {
	t.Parallel()

	const none = "-"

	tests := map[string]struct {
		method, contentType string
		credential          auth.Credential
		want                int
	}{
		"post as json":              {http.MethodPost, "", auth.None, 200},
		"post as json+utf8":         {http.MethodPost, "application/json; charset=utf-8", auth.None, 200},
		"post as text":              {http.MethodPost, textPlain, auth.None, 415},
		"post as a form":            {http.MethodPost, "application/x-www-form-urlencoded", auth.None, 415},
		"post without a type":       {http.MethodPost, none, auth.None, 415},
		"patch without a type":      {http.MethodPatch, none, auth.None, 415},
		"delete as text":            {http.MethodDelete, textPlain, auth.None, 415},
		"get needs no type":         {http.MethodGet, none, auth.None, 200},
		"session post as text":      {http.MethodPost, textPlain, auth.Authenticated, 415},
		"session post without type": {http.MethodPost, none, auth.Authenticated, 415},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			routes := []auth.Route{{
				Method: tt.method, Path: "/c", MaxBody: 0,
				Credential: tt.credential, Access: accessFor(tt.credential), Handle: r.record("c"),
			}}

			rec := r.serve(routes, request{method: tt.method, target: "/c", contentType: tt.contentType})
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}

			// Refused before the route and before the credential: the store is
			// never read for a request httpapi turned away.
			if tt.want == http.StatusUnsupportedMediaType && (len(r.ran) != 0 || len(r.creds.calls) != 0) {
				t.Errorf("route ran %d times, store read %d times", len(r.ran), len(r.creds.calls))
			}
		})
	}
}

// TestUnknownPathsAreTheJSON404: a path no route claims, in any method, is the
// JSON not_found, without reading the store.
func TestUnknownPathsAreTheJSON404(t *testing.T) {
	t.Parallel()

	targets := map[string]string{
		"nothing there":            "/nope",
		"a trailing slash":         pathMe + "/",
		"a longer path":            pathMe + "/extra",
		"a shorter path":           "/m",
		"a wildcard without value": pathItems,
		"no wildcard":              "/items",
		"a wildcard and more":      pathItems + itemID + "/x",
		"the root":                 "/",
		"a public path and more":   pathPublic + "/" + itemID + "/x",
		"a nearby case":            "/ME",
	}

	for name, target := range targets {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions} {
			t.Run(name+"/"+method, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				rec := r.serve(r.standardRoutes(), request{
					method: method, target: target, contentType: "-", cookies: []*http.Cookie{sessionCookie(r.session())},
				})

				wantFailure(t, r, rec, http.StatusNotFound, bodyNotFound, "not_found", nil)

				if len(r.creds.calls) != 0 || len(r.handled) != 0 {
					t.Errorf("store read %d times, route ran %d times", len(r.creds.calls), len(r.handled))
				}
			})
		}
	}
}

// TestARouteMayClaimTheRoot: the catch-all is only a default. A route on "/"
// answers every path no other route has, by its own rules, and the exact-root
// pattern does not.
func TestARouteMayClaimTheRoot(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path, target, method string
		want, wantRan        int
	}{
		"/ claims any path":        {"/", "/anything/at/all", http.MethodGet, 200, 1},
		"/ claims the root":        {"/", "/", http.MethodGet, 200, 1},
		"/ has its own methods":    {"/", "/anything", http.MethodDelete, 405, 0},
		"{$} claims only the root": {"/{$}", "/", http.MethodGet, 200, 1},
		"{$} leaves the rest 404":  {"/{$}", "/anything", http.MethodGet, 404, 0},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			routes := []auth.Route{{
				Method: http.MethodGet, Path: tt.path, MaxBody: 0,
				Credential: auth.None, Access: accessFor(auth.None), Handle: r.record("root"),
			}}

			rec := r.serve(routes, request{method: tt.method, target: tt.target})
			if rec.Code != tt.want || len(r.ran) != tt.wantRan {
				t.Errorf("status = %d, ran %d times, want %d and %d", rec.Code, len(r.ran), tt.want, tt.wantRan)
			}
		})
	}
}

// resultCase is what a route returns and what the client must then receive.
type resultCase struct {
	handle     func(*auth.Call) result.Result[httpapi.Response]
	wantStatus int
	wantBody   string
	wantCookie string
}

// returns is a route body that always answers res.
func returns(res result.Result[httpapi.Response]) func(*auth.Call) result.Result[httpapi.Response] {
	return func(*auth.Call) result.Result[httpapi.Response] { return res }
}

func panics(*auth.Call) result.Result[httpapi.Response] { panic(errDB) }

func resultCases() map[string]resultCase {
	created := result.Ok(httpapi.JSON(http.StatusCreated, map[string]int{"n": 1}))
	conflict := result.Fail[httpapi.Response](apierr.New(apierr.Conflict, "taken", "already taken").WithCause(errDB))
	plain := result.Fail[httpapi.Response](errDB)
	cleared := result.Ok(httpapi.Response{Status: http.StatusNoContent, Body: nil}.WithCookies(auth.ClearSessionCookie()))

	return map[string]resultCase{
		"success":                 {returns(created), 201, `{"n":1}` + "\n", ""},
		"a classified failure":    {returns(conflict), 409, errorBody("taken", "already taken"), ""},
		"an unclassified failure": {returns(plain), 500, bodyInternal, ""},
		"a panic":                 {panics, 500, bodyInternal, ""},
		"the session cookie is cleared": {
			returns(cleared), 204, "", "__Host-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
		},
	}
}

// TestHandleResultsReachTheClient: what a route returns is sent by httpapi, so
// its failures are redacted by the same contract, and the route's cookies are
// set.
func TestHandleResultsReachTheClient(t *testing.T) {
	t.Parallel()

	for name, tt := range resultCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			routes := []auth.Route{{
				Method: http.MethodGet, Path: "/h", MaxBody: 0,
				Credential: auth.None, Access: accessFor(auth.None), Handle: tt.handle,
			}}

			rec := r.serve(routes, request{target: "/h"})
			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if got := rec.Header().Get("Set-Cookie"); got != tt.wantCookie {
				t.Errorf("Set-Cookie = %q, want %q", got, tt.wantCookie)
			}
		})
	}
}
