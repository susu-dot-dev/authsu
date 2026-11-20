package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

const clientURL = "https://client.example/cb?code=abc&state=xyz&iss=https%3A%2F%2Fauth.example"

// redirectCase is a response a handler returns and what the boundary does
// with it: the status it answers, the Location it sends, and the code it logs
// for a handler bug.
type redirectCase struct {
	resp       httpapi.Response
	wantStatus int
	wantCode   string
	wantHeader string
}

// sent is a redirect the boundary sends as it is.
func sent(status int, location string) redirectCase {
	return redirectCase{httpapi.Redirect(status, location), status, "", location}
}

// refusedStatus is a status and Location that do not agree: a handler bug.
func refusedStatus(status int, location string) redirectCase {
	return redirectCase{httpapi.Redirect(status, location), http.StatusInternalServerError, codeInvalidStatus, ""}
}

// refusedLocation is a redirect whose Location is not printable ASCII.
func refusedLocation(location string) redirectCase {
	return redirectCase{
		httpapi.Redirect(http.StatusFound, location), http.StatusInternalServerError, codeInvalidRedirect, "",
	}
}

func redirectCases() map[string]redirectCase {
	const host = "https://a.example/"

	return map[string]redirectCase{
		"302":                       sent(http.StatusFound, clientURL),
		"303":                       sent(http.StatusSeeOther, clientURL),
		"a relative location":       sent(http.StatusFound, "/oauth/error?error=x"),
		"302 with no location":      refusedStatus(http.StatusFound, ""),
		"303 with no location":      refusedStatus(http.StatusSeeOther, ""),
		"300":                       refusedStatus(http.StatusMultipleChoices, clientURL),
		"300 with no location":      refusedStatus(http.StatusMultipleChoices, ""),
		"301":                       refusedStatus(http.StatusMovedPermanently, clientURL),
		"304":                       refusedStatus(http.StatusNotModified, clientURL),
		"304 with no location":      refusedStatus(http.StatusNotModified, ""),
		"307":                       refusedStatus(http.StatusTemporaryRedirect, clientURL),
		"308":                       refusedStatus(http.StatusPermanentRedirect, clientURL),
		"399 with no location":      refusedStatus(399, ""),
		"200 with a location":       refusedStatus(http.StatusOK, clientURL),
		"204 with a location":       refusedStatus(http.StatusNoContent, clientURL),
		"400 with a location":       refusedStatus(http.StatusBadRequest, clientURL),
		"500 with a location":       refusedStatus(http.StatusInternalServerError, clientURL),
		"CR LF in the location":     refusedLocation(host + "\r\nSet-Cookie: x=1"),
		"LF in the location":        refusedLocation(host + "\nx"),
		"a tab in the location":     refusedLocation(host + "\tx"),
		"a space in the location":   refusedLocation(host + "a b"),
		"NUL in the location":       refusedLocation(host + "\x00"),
		"DEL in the location":       refusedLocation(host + "\x7f"),
		"non-ASCII in the location": refusedLocation(host + "é"),
		"a bare 0x80 byte":          refusedLocation(host + "\x80"),
	}
}

// TestRedirect: a Location is valid only with 302 or 303, and a 302 or 303 only
// with a Location. Every other pair is a handler bug, answered Internal
// invalid_status, and nothing of the response (not even a header) is sent.
func TestRedirect(t *testing.T) {
	t.Parallel()

	for name, tt := range redirectCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var logged []*apierr.Error

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
			httpapi.ServeRoutes(func(_ httpapi.Request, e *apierr.Error) { logged = append(logged, e) }, nil,
				map[string]httpapi.MethodRoute{http.MethodGet: {Handler: respond(tt.resp), MaxBody: 0, Media: 0, Errors: 0}}).
				ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus || rec.Header().Get("Location") != tt.wantHeader {
				t.Errorf("status = %d, Location = %q, want %d, %q",
					rec.Code, rec.Header().Get("Location"), tt.wantStatus, tt.wantHeader)
			}

			if tt.wantCode == "" {
				if len(logged) != 0 {
					t.Errorf("logged %v, want nothing", logged)
				}

				return
			}

			if len(logged) != 1 || logged[0].Code != tt.wantCode || rec.Body.String() != internalBody {
				t.Errorf("logged %v, body %q, want one %s and the bare internal error", logged, rec.Body, tt.wantCode)
			}
		})
	}
}

// TestRedirectCarriesNoBodyAndKeepsCookies: a redirect is a status, a Location
// and any cookies, and has no Content-Type because it has no body.
func TestRedirectCarriesNoBodyAndKeepsCookies(t *testing.T) {
	t.Parallel()

	cookie := &http.Cookie{Name: "n", Value: "v", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	serveRoute(http.MethodGet, httpapi.MethodRoute{
		Handler: respond(httpapi.Redirect(http.StatusFound, clientURL).WithCookies(cookie)), MaxBody: 0, Media: 0, Errors: 0,
	}).ServeHTTP(rec, req)

	if rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
		t.Errorf("body = %q, Content-Type = %q, want neither", rec.Body, rec.Header().Get("Content-Type"))
	}

	if got := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(got, "n=v") {
		t.Errorf("Set-Cookie = %q, want the cookie", got)
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestRedirectOnAnOAuthRoute: a redirect is not an error, so it is sent as is
// and the OAuth format touches only failures.
func TestRedirectOnAnOAuthRoute(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	serveRoute(http.MethodGet, httpapi.MethodRoute{
		Handler: respond(httpapi.Redirect(http.StatusFound, clientURL)), MaxBody: 0, Media: 0, Errors: httpapi.ErrorsOAuth,
	}).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != clientURL {
		t.Errorf("status = %d, Location = %q", rec.Code, rec.Header().Get("Location"))
	}
}
