package httpapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// oauthBodyOf is the RFC 6749 section 5.2 body for code and description.
func oauthBodyOf(code, description string) string {
	return fmt.Sprintf(`{"error":%q,"error_description":%q}`, code, description) + "\n"
}

// oauthRoute answers a form POST with handler, in the OAuth error format.
func oauthRoute(handler httpapi.Handler) http.Handler {
	return serveRoute(http.MethodPost, httpapi.MethodRoute{
		Handler: handler, MaxBody: 0, Media: httpapi.MediaForm, Errors: httpapi.ErrorsOAuth,
	})
}

// postForm sends a form POST to h.
func postForm(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", formType)
	h.ServeHTTP(rec, req)

	return rec
}

// oauthErrorCase is a code given to OAuthError and what a route sends for it.
type oauthErrorCase struct {
	code       string
	wantStatus int
	wantBody   string
}

// standard is a code that is sent as itself with the standard status.
func standard(code string, status int) oauthErrorCase {
	return oauthErrorCase{code, status, oauthBodyOf(code, "why")}
}

// failsClosed is a code OAuthError does not know: it is a server error.
func failsClosed(code string) oauthErrorCase {
	return oauthErrorCase{code, http.StatusInternalServerError, oauthBodyOf(errServer, descInternal)}
}

func oauthErrorCases() map[string]oauthErrorCase {
	bad := http.StatusBadRequest

	return map[string]oauthErrorCase{
		"invalid_request":          standard(httpapi.OAuthInvalidRequest, bad),
		"invalid_client":           standard(httpapi.OAuthInvalidClient, bad),
		"invalid_grant":            standard(httpapi.OAuthInvalidGrant, bad),
		"unauthorized_client":      standard(httpapi.OAuthUnauthorizedClient, bad),
		"unsupported_grant_type":   standard(httpapi.OAuthUnsupportedGrantType, bad),
		"invalid_scope":            standard(httpapi.OAuthInvalidScope, bad),
		"unsupported_token_type":   standard(httpapi.OAuthUnsupportedTokenType, bad),
		"invalid_target":           standard(httpapi.OAuthInvalidTarget, bad),
		"temporarily_unavailable":  standard(httpapi.OAuthTemporarilyUnavailable, http.StatusServiceUnavailable),
		"server_error is internal": failsClosed(httpapi.OAuthServerError),
		"an unknown code":          failsClosed("invalid_clent"),
		"an empty code":            failsClosed(""),
		"a non-oauth code":         failsClosed("not_found"),
	}
}

// TestOAuthError: each code a handler can emit has its standard status, is sent
// as itself with the handler's description, and is logged under the same code.
func TestOAuthError(t *testing.T) {
	t.Parallel()

	for name, tt := range oauthErrorCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var logged []*apierr.Error

			handler := httpapi.ServeRoutes(func(_ httpapi.Request, e *apierr.Error) { logged = append(logged, e) }, nil,
				map[string]httpapi.MethodRoute{http.MethodPost: {
					Handler: failWith(httpapi.OAuthError(tt.code, "why")), MaxBody: 0,
					Media: httpapi.MediaForm, Errors: httpapi.ErrorsOAuth,
				}})

			rec := postForm(t, handler, "")

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("status = %d, body = %q, want %d, %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if got := rec.Header().Get("Content-Type"); got != jsonType {
				t.Errorf("Content-Type = %q, want %s", got, jsonType)
			}

			if len(logged) != 1 {
				t.Errorf("logged %d errors, want 1", len(logged))
			}
		})
	}
}

// TestOAuthErrorOnAnAPIRoute: OAuthError is only a classified apierr, so on a
// route that did not declare the OAuth format it is sent in the API's own.
func TestOAuthErrorOnAnAPIRoute(t *testing.T) {
	t.Parallel()

	rec := postJSON(t, serve(http.MethodPost, func(httpapi.Request, *apierr.Error) {},
		failWith(httpapi.OAuthError(httpapi.OAuthInvalidGrant, "why"))))

	want := `{"error":{"code":"invalid_grant","message":"why"}}` + "\n"
	if rec.Code != http.StatusBadRequest || rec.Body.String() != want {
		t.Errorf("status = %d, body = %q, want 400, %q", rec.Code, rec.Body, want)
	}
}

func postJSON(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(""))
	req.Header.Set("Content-Type", jsonType)
	h.ServeHTTP(rec, req)

	return rec
}

// failureCase is a failure a handler returns and what an OAuth route sends.
type failureCase struct {
	err        error
	wantStatus int
	wantCode   string
	wantDesc   string
}

// failure is an apierr of kind with code "x" and description "d", sent as code
// under the status of kind.
func failure(kind apierr.Kind, status int, code string) failureCase {
	return failureCase{apierr.New(kind, "x", "d"), status, code, "d"}
}

// internalFailure is a failure that is sent as the bare server error.
func internalFailure(err error) failureCase {
	return failureCase{err, http.StatusInternalServerError, errServer, descInternal}
}

func failureCases() map[string]failureCase {
	badData := apierr.New(apierr.BadRequest, "x", "d").WithData(map[string]string{"k": "v"})

	return map[string]failureCase{
		"bad request":  failure(apierr.BadRequest, http.StatusBadRequest, errInvalidRequest),
		"not found":    failure(apierr.NotFound, http.StatusNotFound, errInvalidRequest),
		"method":       failure(apierr.MethodNotAllowed, http.StatusMethodNotAllowed, errInvalidRequest),
		"conflict":     failure(apierr.Conflict, http.StatusConflict, errInvalidRequest),
		"too large":    failure(apierr.PayloadTooLarge, http.StatusRequestEntityTooLarge, errInvalidRequest),
		"media type":   failure(apierr.UnsupportedMediaType, http.StatusUnsupportedMediaType, errInvalidRequest),
		"unauthorized": failure(apierr.Unauthorized, http.StatusUnauthorized, errClient),
		"forbidden":    failure(apierr.Forbidden, http.StatusForbidden, "unauthorized_client"),
		"rate limited": failure(apierr.RateLimited, http.StatusTooManyRequests, errUnavailable),
		"unavailable":  failure(apierr.Unavailable, http.StatusServiceUnavailable, errUnavailable),
		"unknown kind": {apierr.New(apierr.Kind(99), "x", "d"), http.StatusInternalServerError, errServer, "d"},
		"internal":     internalFailure(apierr.New(apierr.Internal, "x", "table users").WithData("secret")),
		"unclassified": internalFailure(errCause),
		"wrapped": {
			fmt.Errorf("ctx: %w", apierr.New(apierr.BadRequest, "x", "d")), http.StatusBadRequest, errInvalidRequest, "d",
		},
		"data is not sent": {badData, http.StatusBadRequest, errInvalidRequest, "d"},
		"an oauth code on its own kind": {
			apierr.New(apierr.BadRequest, "invalid_grant", "d"), http.StatusBadRequest, "invalid_grant", "d",
		},
		"an oauth code under another status": {
			apierr.New(apierr.Unauthorized, errClient, "d"), http.StatusUnauthorized, errClient, "d",
		},
		"an oauth code on an internal failure": internalFailure(apierr.New(apierr.Internal, "invalid_grant", "d")),
	}
}

// TestOAuthFormatOfEveryFailure: whatever a handler (or the boundary around it)
// fails with is sent in the RFC format, under the OAuth code of its kind, with
// the status of its kind. An Internal failure never shows its description,
// code or data, whatever code it carries.
func TestOAuthFormatOfEveryFailure(t *testing.T) {
	t.Parallel()

	for name, tt := range failureCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := postForm(t, oauthRoute(failWith(tt.err)), "")

			want := oauthBodyOf(tt.wantCode, tt.wantDesc)
			if rec.Code != tt.wantStatus || rec.Body.String() != want {
				t.Errorf("status = %d, body = %q, want %d, %q", rec.Code, rec.Body, tt.wantStatus, want)
			}
		})
	}
}

// TestOAuthFormatOfBoundaryFailures: the failures the boundary itself produces,
// before and around a handler, are in the route's format. An API route's are
// unchanged.
func TestOAuthFormatOfBoundaryFailures(t *testing.T) {
	t.Parallel()

	ok := respond(httpapi.Response{Status: http.StatusNoContent})
	panics := func(httpapi.Request) result.Result[httpapi.Response] { panic("nil step") }

	tests := map[string]struct {
		handler     httpapi.Handler
		method      string
		contentType string
		body        string
		wantStatus  int
		wantBody    string
		wantAllow   string
	}{
		"wrong method": {
			ok, http.MethodGet, "", "", http.StatusMethodNotAllowed,
			oauthBodyOf(errInvalidRequest, "method not allowed"), "POST",
		},
		"wrong media type": {
			ok, http.MethodPost, jsonType, "{}", http.StatusUnsupportedMediaType,
			oauthBodyOf(errInvalidRequest, "request Content-Type must be application/x-www-form-urlencoded"), "",
		},
		"missing media type": {
			ok, http.MethodPost, "-", oneParam, http.StatusUnsupportedMediaType,
			oauthBodyOf(errInvalidRequest, "request Content-Type must be application/x-www-form-urlencoded"), "",
		},
		"body too large": {
			ok, http.MethodPost, formType, strings.Repeat("a", 2<<20), http.StatusRequestEntityTooLarge,
			oauthBodyOf(errInvalidRequest, "request body is too large"), "",
		},
		"panic": {
			panics, http.MethodPost, formType, "", http.StatusInternalServerError,
			oauthBodyOf(errServer, descInternal), "",
		},
		"invalid status": {
			respond(httpapi.Response{Status: 0}), http.MethodPost, formType, "", http.StatusInternalServerError,
			oauthBodyOf(errServer, descInternal), "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/oauth/token", strings.NewReader(tt.body))

			if tt.contentType != "" && tt.contentType != "-" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			oauthRoute(tt.handler).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody || rec.Header().Get("Allow") != tt.wantAllow {
				t.Errorf("status = %d, body = %q, Allow = %q, want %d, %q, %q",
					rec.Code, rec.Body, rec.Header().Get("Allow"), tt.wantStatus, tt.wantBody, tt.wantAllow)
			}
		})
	}
}

// TestOAuthRoutesAreNotCached: RFC 6749 section 5.1 asks for no-store and
// Pragma: no-cache on a token response, and the OAuth format carries both on
// every response, success and failure. A route in the API's format sends no
// Pragma.
func TestOAuthRoutesAreNotCached(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		handler httpapi.Handler
		errors  httpapi.ErrorFormat
		method  string
		pragma  string
	}{
		"oauth success":    {respond(httpapi.JSON(http.StatusOK, 1)), httpapi.ErrorsOAuth, http.MethodPost, noCache},
		"oauth failure":    {failWith(errCause), httpapi.ErrorsOAuth, http.MethodPost, noCache},
		"oauth wrong verb": {respond(httpapi.JSON(http.StatusOK, 1)), httpapi.ErrorsOAuth, http.MethodDelete, noCache},
		"api success":      {respond(httpapi.JSON(http.StatusOK, 1)), httpapi.ErrorsAPI, http.MethodPost, ""},
		"api failure":      {failWith(errCause), httpapi.ErrorsAPI, http.MethodPost, ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/x", strings.NewReader(""))
			req.Header.Set("Content-Type", formType)
			serveRoute(http.MethodPost, httpapi.MethodRoute{
				Handler: tt.handler, MaxBody: 0, Media: httpapi.MediaForm, Errors: tt.errors,
			}).ServeHTTP(rec, req)

			if got := rec.Header().Get("Pragma"); got != tt.pragma {
				t.Errorf("Pragma = %q, want %q", got, tt.pragma)
			}

			if got := rec.Header().Get("Cache-Control"); got != noStore {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

// TestPathLevelFailuresUseTheFormatTheMethodsAgreeOn: a 405 belongs to the path,
// not to any method, so it is in the OAuth format only when every method of the
// path declares it.
func TestPathLevelFailuresUseTheFormatTheMethodsAgreeOn(t *testing.T) {
	t.Parallel()

	ok := respond(httpapi.JSON(http.StatusOK, 1))
	route := func(format httpapi.ErrorFormat) httpapi.MethodRoute {
		return httpapi.MethodRoute{Handler: ok, MaxBody: 0, Media: httpapi.MediaJSON, Errors: format}
	}

	tests := map[string]struct {
		routes map[string]httpapi.MethodRoute
		want   string
		pragma string
	}{
		"all oauth": {
			routes: map[string]httpapi.MethodRoute{
				http.MethodPost: route(httpapi.ErrorsOAuth), http.MethodPatch: route(httpapi.ErrorsOAuth),
			},
			want: oauthBodyOf(errInvalidRequest, "method not allowed"), pragma: noCache,
		},
		"all api": {
			routes: map[string]httpapi.MethodRoute{
				http.MethodPost: route(httpapi.ErrorsAPI), http.MethodPatch: route(httpapi.ErrorsAPI),
			},
			want: `{"error":{"code":"method_not_allowed","message":"method not allowed"}}` + "\n", pragma: "",
		},
		"mixed, oauth first": {
			routes: map[string]httpapi.MethodRoute{
				http.MethodPatch: route(httpapi.ErrorsOAuth), http.MethodPost: route(httpapi.ErrorsAPI),
			},
			want: `{"error":{"code":"method_not_allowed","message":"method not allowed"}}` + "\n", pragma: "",
		},
		"mixed, api first": {
			routes: map[string]httpapi.MethodRoute{
				http.MethodPatch: route(httpapi.ErrorsAPI), http.MethodPost: route(httpapi.ErrorsOAuth),
			},
			want: `{"error":{"code":"method_not_allowed","message":"method not allowed"}}` + "\n", pragma: "",
		},
		"one oauth method": {
			routes: map[string]httpapi.MethodRoute{http.MethodPost: route(httpapi.ErrorsOAuth)},
			want:   oauthBodyOf(errInvalidRequest, "method not allowed"), pragma: noCache,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/x", nil)
			httpapi.ServeRoutes(func(httpapi.Request, *apierr.Error) {}, nil, tt.routes).ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed || rec.Body.String() != tt.want {
				t.Errorf("status = %d, body = %q, want 405, %q", rec.Code, rec.Body, tt.want)
			}

			if got := rec.Header().Get("Pragma"); got != tt.pragma {
				t.Errorf("Pragma = %q, want %q", got, tt.pragma)
			}
		})
	}
}
