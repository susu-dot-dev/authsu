package auth_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

const (
	formType = "application/x-www-form-urlencoded"
	noType   = "-"
	oneParam = "a=1"

	pathForm     = "/form"
	pathJSONOnly = "/json"
	pathQuery    = "/query"
	pathBounce   = "/bounce"
	pathOAuthMe  = "/oauth-me"
	pathMixed    = "/mixed"
)

// echoParams is a route body that answers the parameters a and b it read with
// the strict parser, from the body or from the query.
func (r *rig) echoParams(fromBody bool) func(*auth.Call) result.Result[httpapi.Response] {
	return func(call *auth.Call) result.Result[httpapi.Response] {
		r.handled = append(r.handled, call)

		parse := call.Request.QueryParams
		if fromBody {
			parse = call.Request.FormParams
		}

		return parse("a", "b").Map(func(params httpapi.Params) httpapi.Response {
			a, hasA := params.Get("a")
			b, hasB := params.Get("b")

			return httpapi.JSON(http.StatusOK, map[string]any{"a": a, "hasA": hasA, "b": b, "hasB": hasB})
		})
	}
}

// mediaRoutes declares one route of each combination the boundary supports.
func (r *rig) mediaRoutes() []auth.Route {
	return []auth.Route{
		// The OAuth endpoints' shape: a form body, no credential, RFC errors.
		{
			Method: http.MethodPost, Path: pathForm, MaxBody: 64, Credential: auth.None,
			Media: httpapi.MediaForm, Errors: httpapi.ErrorsOAuth, Handle: r.echoParams(true),
		},
		// The default: JSON, API errors.
		{
			Method: http.MethodPost, Path: pathJSONOnly, MaxBody: 0, Credential: auth.None,
			Handle: r.capture,
		},
		// A GET that reads its query string and fails in the RFC format.
		{
			Method: http.MethodGet, Path: pathQuery, MaxBody: 64, Credential: auth.None,
			Errors: httpapi.ErrorsOAuth, Handle: r.echoParams(false),
		},
		// An authorization endpoint's answer: a redirect.
		{
			Method: http.MethodGet, Path: pathBounce, MaxBody: 0, Credential: auth.None,
			Handle: func(*auth.Call) result.Result[httpapi.Response] {
				return result.Ok(httpapi.Redirect(http.StatusFound, "https://client.example/cb?code=1"))
			},
		},
		// A credentialed route that answers in the RFC format: the 401 is too.
		{
			Method: http.MethodGet, Path: pathOAuthMe, MaxBody: 0, Credential: auth.Authenticated,
			Access: auth.Open(), Errors: httpapi.ErrorsOAuth, Handle: r.capture,
		},
		// One path, a form method and a JSON method.
		{
			Method: http.MethodPost, Path: pathMixed, MaxBody: 0, Credential: auth.None,
			Media: httpapi.MediaForm, Handle: r.capture,
		},
		{Method: http.MethodPatch, Path: pathMixed, MaxBody: 0, Credential: auth.None, Handle: r.capture},
	}
}

// mediaCase is a request to the media routes and what the boundary must do.
type mediaCase struct {
	req        request
	wantStatus int
	wantBody   string
	// wantHandled is whether the route's handler ran: it does for a request
	// that passed the boundary, even if the handler then refused its
	// parameters.
	wantHandled bool
}

const (
	unsupportedForm = `{"error":"invalid_request","error_description":` +
		`"request Content-Type must be application/x-www-form-urlencoded"}` + "\n"
	tooLarge    = `{"error":"invalid_request","error_description":"request body is too large"}` + "\n"
	queryLarge  = `{"error":"invalid_request","error_description":"request query string is too large"}` + "\n"
	dupParam    = `{"error":"invalid_request","error_description":"a parameter was sent more than once"}` + "\n"
	unauthOAuth = `{"error":"invalid_client","error_description":"not signed in"}` + "\n"
)

func form(body string) request {
	return request{method: http.MethodPost, target: pathForm, body: body, contentType: formType}
}

// mediaCases are every request the tests send, by name.
func mediaCases() map[string]mediaCase {
	all := map[string]mediaCase{}

	for _, group := range []map[string]mediaCase{formCases(), jsonCases(), queryCases(), mixedCases()} {
		for name, tt := range group {
			if _, twice := all[name]; twice {
				panic("two cases are named " + name)
			}

			all[name] = tt
		}
	}

	return all
}

// wantJSON is the 415 of a JSON route.
func wantJSON() string {
	return errorBody("unsupported_media_type", "request Content-Type must be application/json")
}

// wantForm is the 415 of a form route in the API's format.
func wantForm() string {
	return errorBody("unsupported_media_type", "request Content-Type must be "+formType)
}

// formCases are requests to the form route: a form body, no credential, RFC
// errors.
func formCases() map[string]mediaCase {
	post := http.MethodPost
	filler := strings.Repeat("x", 62)

	return map[string]mediaCase{
		"form to a form route": {
			form("a=1&b=%2B&x=y"), http.StatusOK, `{"a":"1","b":"+","hasA":true,"hasB":true}` + "\n", true,
		},
		"form with a charset": {
			request{method: post, target: pathForm, body: oneParam, contentType: formType + "; charset=UTF-8"},
			http.StatusOK, `{"a":"1","b":"","hasA":true,"hasB":false}` + "\n", true,
		},
		"an empty form":          {form(""), http.StatusOK, `{"a":"","b":"","hasA":false,"hasB":false}` + "\n", true},
		"a duplicated parameter": {form("a=1&a=2"), http.StatusBadRequest, dupParam, true},
		"a form at the body limit": {
			form("a=" + filler), http.StatusOK, `{"a":"` + filler + `","b":"","hasA":true,"hasB":false}` + "\n", true,
		},
		"an oversized form": {form("a=" + strings.Repeat("a", 65)), http.StatusRequestEntityTooLarge, tooLarge, false},
		"JSON to a form route": {
			request{method: post, target: pathForm, body: `{"a":"1"}`, contentType: jsonType},
			http.StatusUnsupportedMediaType, unsupportedForm, false,
		},
		"no type to a form route": {
			request{method: post, target: pathForm, body: oneParam, contentType: noType},
			http.StatusUnsupportedMediaType, unsupportedForm, false,
		},
		"text to a form route": {
			request{method: post, target: pathForm, body: oneParam, contentType: "text/plain"},
			http.StatusUnsupportedMediaType, unsupportedForm, false,
		},
		"a form with another charset": {
			request{method: post, target: pathForm, body: oneParam, contentType: formType + "; charset=latin1"},
			http.StatusUnsupportedMediaType, unsupportedForm, false,
		},
		"the wrong method on a form route": {
			request{method: http.MethodGet, target: pathForm},
			http.StatusMethodNotAllowed, `{"error":"invalid_request","error_description":"method not allowed"}` + "\n", false,
		},
	}
}

// jsonCases are requests to the default route: JSON, API errors.
func jsonCases() map[string]mediaCase {
	post := http.MethodPost

	return map[string]mediaCase{
		"a form to a JSON route": {
			request{method: post, target: pathJSONOnly, body: oneParam, contentType: formType},
			http.StatusUnsupportedMediaType, wantJSON(), false,
		},
		"JSON to a JSON route": {
			request{method: post, target: pathJSONOnly, body: "{}", contentType: jsonType}, http.StatusOK, bodyOK, true,
		},
		"no type to a JSON route": {
			request{method: post, target: pathJSONOnly, body: "{}", contentType: noType},
			http.StatusUnsupportedMediaType, wantJSON(), false,
		},
	}
}

// queryCases are requests to the routes that read a query string, redirect, or
// answer a credentialed request in the RFC format.
func queryCases() map[string]mediaCase {
	get := http.MethodGet

	return map[string]mediaCase{
		"a query": {
			request{method: get, target: pathQuery + "?a=x+y&b=%20&c=1", contentType: noType},
			http.StatusOK, `{"a":"x y","b":" ","hasA":true,"hasB":true}` + "\n", true,
		},
		"a duplicated query parameter": {
			request{method: get, target: pathQuery + "?b=1&b=1", contentType: noType}, http.StatusBadRequest, dupParam, true,
		},
		"an oversized query": {
			request{method: get, target: pathQuery + "?a=" + strings.Repeat("a", 65), contentType: noType},
			http.StatusRequestEntityTooLarge, queryLarge, false,
		},
		"a redirect": {request{method: get, target: pathBounce, contentType: noType}, http.StatusFound, "", false},
		"a refused credential, in the route's format": {
			request{method: get, target: pathOAuthMe, contentType: noType}, http.StatusUnauthorized, unauthOAuth, false,
		},
	}
}

// mixedCases are requests to one path that takes a form on one method and JSON
// on another.
func mixedCases() map[string]mediaCase {
	post, patch := http.MethodPost, http.MethodPatch

	return map[string]mediaCase{
		"a form to the form method": {
			request{method: post, target: pathMixed, body: oneParam, contentType: formType}, http.StatusOK, bodyOK, true,
		},
		"JSON to the form method": {
			request{method: post, target: pathMixed, body: "{}", contentType: jsonType},
			http.StatusUnsupportedMediaType, wantForm(), false,
		},
		"JSON to the JSON method": {
			request{method: patch, target: pathMixed, body: "{}", contentType: jsonType}, http.StatusOK, bodyOK, true,
		},
		"a form to the JSON method": {
			request{method: patch, target: pathMixed, body: oneParam, contentType: formType},
			http.StatusUnsupportedMediaType, wantJSON(), false,
		},
	}
}

// TestMediaAndErrorFormatThroughTheBoundary drives the routes of mediaRoutes
// through auth.Handler: each route is held to its own media type, answers a
// refusal in its own error format, and reaches its handler only for a request
// that passed every check.
func TestMediaAndErrorFormatThroughTheBoundary(t *testing.T) {
	t.Parallel()

	for name, tt := range mediaCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.serve(r.mediaRoutes(), tt.req)

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("status = %d, body = %q, want %d, %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if tt.wantHandled != (len(r.handled) == 1) {
				t.Errorf("the route ran %d times, want %t", len(r.handled), tt.wantHandled)
			}

			if tt.req.target == pathBounce {
				checkRedirect(t, rec)
			}
		})
	}
}

// checkRedirect checks the one redirect route: a 302 with its Location, no body
// and no cache.
func checkRedirect(t *testing.T, rec interface {
	Header() http.Header
}) {
	t.Helper()

	if got := rec.Header().Get("Location"); got != "https://client.example/cb?code=1" {
		t.Errorf("Location = %q", got)
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestEveryCombinationOfMediaAndFormat declares every route shape the boundary
// takes and checks that the declaration reaches the wire: a route is built with
// its Media and Errors, and answers the wrong Content-Type in the format it
// declared and with the type it wants.
func TestEveryCombinationOfMediaAndFormat(t *testing.T) {
	t.Parallel()

	media := map[string]struct {
		media httpapi.Media
		want  string
		wrong string
	}{
		"json (default)": {httpapi.MediaJSON, "application/json", formType},
		"form":           {httpapi.MediaForm, formType, jsonType},
	}

	formats := map[string]struct {
		format httpapi.ErrorFormat
		render func(want string) string
	}{
		"api errors": {httpapi.ErrorsAPI, func(want string) string {
			return errorBody("unsupported_media_type", "request Content-Type must be "+want)
		}},
		"oauth errors": {httpapi.ErrorsOAuth, func(want string) string {
			return fmt.Sprintf(`{"error":"invalid_request","error_description":"request Content-Type must be %s"}`, want) + "\n"
		}},
	}

	for mediaName, m := range media {
		for formatName, f := range formats {
			t.Run(mediaName+"/"+formatName, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				routes := []auth.Route{{
					Method: http.MethodPost, Path: "/x", MaxBody: 0, Credential: auth.None,
					Media: m.media, Errors: f.format, Handle: r.capture,
				}}

				rec := r.serve(routes, request{method: http.MethodPost, target: "/x", body: oneParam, contentType: m.wrong})
				if rec.Code != http.StatusUnsupportedMediaType || rec.Body.String() != f.render(m.want) || len(r.handled) != 0 {
					t.Errorf("status = %d, body = %q, handled %d", rec.Code, rec.Body, len(r.handled))
				}

				rec = r.serve(routes, request{method: http.MethodPost, target: "/x", body: oneParam, contentType: m.want})
				if rec.Code != http.StatusOK || len(r.handled) != 1 {
					t.Errorf("status = %d, handled %d, want 200 and one", rec.Code, len(r.handled))
				}
			})
		}
	}
}
