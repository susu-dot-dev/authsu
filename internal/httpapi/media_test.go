package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

const (
	formType = "application/x-www-form-urlencoded"

	apiUnsupportedJSON = `{"error":{"code":"unsupported_media_type",` +
		`"message":"request Content-Type must be application/json"}}` + "\n"
	apiUnsupportedForm = `{"error":{"code":"unsupported_media_type",` +
		`"message":"request Content-Type must be application/x-www-form-urlencoded"}}` + "\n"
	oauthUnsupportedJSON = `{"error":"invalid_request",` +
		`"error_description":"request Content-Type must be application/json"}` + "\n"
	oauthUnsupportedForm = `{"error":"invalid_request",` +
		`"error_description":"request Content-Type must be application/x-www-form-urlencoded"}` + "\n"
)

// mediaHeader is one Content-Type header the matrix sends, and whether a JSON
// route and a form route accept it.
type mediaHeader struct {
	lines      []string
	json, form bool
}

// mediaHeaders are the Content-Type headers the boundary has a rule for.
func mediaHeaders() map[string]mediaHeader {
	only := func(json, form bool, lines ...string) mediaHeader { return mediaHeader{lines, json, form} }
	neither := func(lines ...string) mediaHeader { return only(false, false, lines...) }

	return map[string]mediaHeader{
		"missing":                 neither(),
		emptyValue:                neither(""),
		"json":                    only(true, false, jsonType),
		"json upper case":         only(true, false, "Application/JSON"),
		"json utf-8":              only(true, false, jsonType+"; charset=utf-8"),
		"json latin1":             neither(jsonType + "; charset=latin1"),
		"json with charset twice": only(true, false, jsonType+"; charset=utf-8; charset=utf-8"),
		"form":                    only(false, true, formType),
		"form upper case":         only(false, true, "Application/X-WWW-Form-URLEncoded"),
		"form padded":             only(false, true, " "+formType+" "),
		"form utf-8":              only(false, true, formType+"; charset=utf-8"),
		"form UTF-8 no space":     only(false, true, formType+";charset=UTF-8"),
		"form latin1":             neither(formType + "; charset=iso-8859-1"),
		"form utf-16":             neither(formType + "; charset=utf-16"),
		"form with a boundary":    neither(formType + "; boundary=x"),
		"form with empty param":   neither(formType + ";"),
		"form charset then junk":  neither(formType + "; charset=utf-8; x=y"),
		"form as a prefix":        neither(formType + "x"),
		"form with a NUL":         neither(formType + "\x00"),
		"form twice":              neither(formType, formType),
		"form and json lines":     neither(formType, jsonType),
		"json then form lines":    neither(jsonType, formType),
		"form and json in a line": neither(formType + ", " + jsonType),
		"text/plain":              neither(plainType),
		"multipart":               neither("multipart/form-data; boundary=x"),
		"form as a parameter":     neither("text/plain; " + formType),
		"wildcard":                neither("*/*"),
		"form with a json suffix": neither(formType + "+json"),
		"another form-like type":  neither(formType + "2"),
		"type with no subtype":    neither("application"),
	}
}

// mediaRoute is a route declaration the matrix drives and the 415 it answers a
// refused request with.
type mediaRoute struct {
	media       httpapi.Media
	errors      httpapi.ErrorFormat
	unsupported string
}

// TestMediaMatrix drives every route media type against every Content-Type
// header the boundary has a rule for, in both error formats. A request that
// passes reaches the handler; any other is 415 and never does, whatever the
// body, and the refusal is written in the route's format and names the type
// the route wants.
func TestMediaMatrix(t *testing.T) {
	t.Parallel()

	routes := map[string]mediaRoute{
		"json, api errors":    {httpapi.MediaJSON, httpapi.ErrorsAPI, apiUnsupportedJSON},
		"json, oauth errors":  {httpapi.MediaJSON, httpapi.ErrorsOAuth, oauthUnsupportedJSON},
		"form, api errors":    {httpapi.MediaForm, httpapi.ErrorsAPI, apiUnsupportedForm},
		"form, oauth errors":  {httpapi.MediaForm, httpapi.ErrorsOAuth, oauthUnsupportedForm},
		"default (zero) json": {0, 0, apiUnsupportedJSON},
	}

	for routeName, route := range routes {
		for headerName, header := range mediaHeaders() {
			t.Run(routeName+"/"+headerName, func(t *testing.T) {
				t.Parallel()

				checkMedia(t, route, header)
			})
		}
	}
}

// checkMedia sends a POST with header to route and checks the verdict.
func checkMedia(t *testing.T, route mediaRoute, header mediaHeader) {
	t.Helper()

	handled := false
	handler := func(httpapi.Request) result.Result[httpapi.Response] {
		handled = true

		return result.Ok(httpapi.JSON(http.StatusOK, 1))
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(oneParam))

	for _, line := range header.lines {
		req.Header.Add("Content-Type", line)
	}

	serveRoute(http.MethodPost, httpapi.MethodRoute{
		Handler: handler, MaxBody: 0, Media: route.media, Errors: route.errors,
	}).ServeHTTP(rec, req)

	passes := header.json
	if route.media == httpapi.MediaForm {
		passes = header.form
	}

	if passes {
		if rec.Code != http.StatusOK || !handled {
			t.Errorf("status = %d, handled = %t, want 200 and handled", rec.Code, handled)
		}

		return
	}

	if rec.Code != http.StatusUnsupportedMediaType || handled || rec.Body.String() != route.unsupported {
		t.Errorf("status = %d, handled = %t, body = %q, want 415, not handled, %q",
			rec.Code, handled, rec.Body, route.unsupported)
	}
}

// TestMediaIsPerMethod: one path may take JSON on one method and a form on
// another, and each is held to its own rule.
func TestMediaIsPerMethod(t *testing.T) {
	t.Parallel()

	ok := respond(httpapi.JSON(http.StatusOK, 1))
	handler := httpapi.ServeRoutes(func(httpapi.Request, *apierr.Error) {}, nil, map[string]httpapi.MethodRoute{
		http.MethodPost:  {Handler: ok, MaxBody: 0, Media: httpapi.MediaForm, Errors: httpapi.ErrorsAPI},
		http.MethodPatch: {Handler: ok, MaxBody: 0, Media: httpapi.MediaJSON, Errors: httpapi.ErrorsAPI},
	})

	tests := []struct {
		name                string
		method, contentType string
		want                int
	}{
		{"POST takes a form", http.MethodPost, formType, http.StatusOK},
		{"POST refuses JSON", http.MethodPost, jsonType, http.StatusUnsupportedMediaType},
		{"PATCH takes JSON", http.MethodPatch, jsonType, http.StatusOK},
		{"PATCH refuses a form", http.MethodPatch, formType, http.StatusUnsupportedMediaType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/x", strings.NewReader(""))
			req.Header.Set("Content-Type", tt.contentType)
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Errorf("%s with %s = %d, want %d", tt.method, tt.contentType, rec.Code, tt.want)
			}
		})
	}
}

// TestSafeMethodsIgnoreMedia: a GET reads no body, so a form route's media type
// does not make a GET need one.
func TestSafeMethodsIgnoreMedia(t *testing.T) {
	t.Parallel()

	for name, media := range map[string]httpapi.Media{
		"a JSON route": httpapi.MediaJSON,
		"a form route": httpapi.MediaForm,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
			serveRoute(http.MethodGet, httpapi.MethodRoute{
				Handler: respond(httpapi.JSON(http.StatusOK, 1)), MaxBody: 0, Media: media, Errors: httpapi.ErrorsAPI,
			}).ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("GET on media %d = %d, want 200", media, rec.Code)
			}
		})
	}
}

// TestServeRoutesRefusesAnUnknownDeclaration: a route table is fixed in code,
// so a Media or ErrorFormat that does not exist is found at construction.
func TestServeRoutesRefusesAnUnknownDeclaration(t *testing.T) {
	t.Parallel()

	ok := respond(httpapi.JSON(http.StatusOK, 1))
	tests := map[string]httpapi.MethodRoute{
		"unknown media":  {Handler: ok, MaxBody: 0, Media: 2, Errors: httpapi.ErrorsAPI},
		"unknown errors": {Handler: ok, MaxBody: 0, Media: httpapi.MediaJSON, Errors: 2},
	}

	for name, route := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("ServeRoutes did not panic")
				}
			}()

			serveRoute(http.MethodPost, route)
		})
	}
}
