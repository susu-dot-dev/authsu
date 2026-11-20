package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// This file holds what the routes share: the OAuth error codes and how a
// failure is turned into one, the builders of the URLs a response redirects to,
// and the small helpers every route uses. A route's own file holds only the
// route.

// Names of the parameters that more than one file reads or writes.
const (
	paramError = "error"
	paramState = "state"
	paramCode  = "code"
)

// Error codes of the API routes of this package (the ones under /api, in the
// API's error format). The failure of a store, a body, a parameter or a name
// has its own code in store, httpapi or input. They are stable: clients and
// dashboards may match on them.
const (
	// CodeInvalidPending is the one answer to a pending request that cannot be
	// used: missing, malformed, signed for something else, forged, expired, or
	// holding a value that does not parse (a request that was sealed by another
	// version of the service, say). 400. The causes are only in the log, because
	// telling a forged request from an expired one would be an oracle for no
	// benefit: the answer to both is to start again from the client.
	CodeInvalidPending = "invalid_oauth_request"

	// CodeInvalidConsent is a consent body that is well-formed JSON but is not
	// an answer: no approve, or an approval that does not choose exactly one
	// agent, or a refusal that names one. 400.
	CodeInvalidConsent = "invalid_consent"

	// CodeConsentReplayed is an approval of a request that was already
	// approved. 409. Nothing was created by this call.
	CodeConsentReplayed = "consent_replayed"

	// CodeAgentLimit is an approval that would create an agent for a user who
	// already has the most they may. 409. Its value is agents' CodeLimit, which
	// is what a client already handles for creating an agent.
	CodeAgentLimit = "agent_limit_reached"

	// CodeAgentNotFound is an approval that names an agent the user does not
	// have: it does not exist, is another user's, or is revoked. 404, alike for
	// all three, as everywhere an owner's rows are looked up. Its value is
	// agents' CodeNotFound.
	CodeAgentNotFound = "agent_not_found"

	// CodeIssueFailed is an authorization code that could not be issued (the
	// entropy source failed), before anything was written. 500.
	CodeIssueFailed = "oauth_code_issue_failed"

	// CodeConsentFailed is a consent write that the database refused for a
	// reason the store cannot name, which for fresh ids and hashes is a defect.
	// 500.
	CodeConsentFailed = "oauth_consent_failed"
)

// The OAuth error codes of the authorization endpoint (RFC 6749 section 4.1.2.1,
// RFC 8707 section 2), as they are written to a client and to the UI. The codes
// httpapi names are its constants; the others are this endpoint's own.
const (
	oauthInvalidRequest      = httpapi.OAuthInvalidRequest
	oauthInvalidClient       = httpapi.OAuthInvalidClient
	oauthInvalidGrant        = httpapi.OAuthInvalidGrant
	oauthUnsupportedGrant    = httpapi.OAuthUnsupportedGrantType
	oauthInvalidScope        = httpapi.OAuthInvalidScope
	oauthInvalidTarget       = httpapi.OAuthInvalidTarget
	oauthServerError         = httpapi.OAuthServerError
	oauthTemporarilyDown     = httpapi.OAuthTemporarilyUnavailable
	oauthAccessDenied        = "access_denied"
	oauthUnsupportedResponse = "unsupported_response_type"

	// oauthInvalidRedirectURI is not an RFC 6749 code: no response is ever
	// redirected with it, because it is what a request whose redirect URI is
	// not trusted is told, and that is only ever shown by the UI.
	oauthInvalidRedirectURI = "invalid_redirect_uri"
)

// describe is the fixed, client-safe text that goes with an OAuth error code. It
// never holds a cause, a parameter's value or anything else that came from the
// request, because it is written into a URL the client reads.
func describe(code string) string {
	text, known := descriptions()[code]
	if !known {
		return "the server could not complete the request"
	}

	return text
}

// descriptions are the texts of the codes this package sends.
func descriptions() map[string]string {
	return map[string]string{
		oauthInvalidRequest: "the request is missing a parameter, repeats one, or has one that is not valid",
		oauthInvalidClient:  "the client could not be identified",
		oauthInvalidGrant: "the code or refresh token is not valid, or was issued to another client, " +
			"or the redirect URI or code verifier does not match",
		oauthUnsupportedGrant:    "the grant type is not supported",
		oauthInvalidRedirectURI:  "the redirect URI is missing or is not one the client registered",
		oauthInvalidScope:        "the scope is not valid for the resource",
		oauthInvalidTarget:       "the resource is missing or is not one this server issues tokens for",
		oauthUnsupportedResponse: "the response type is not supported",
		oauthAccessDenied:        "the user denied the request",
		oauthTemporarilyDown:     "the client's metadata could not be fetched; try again",
	}
}

// failure is the classified error for an OAuth error code: its status is the
// standard one for the code, its description is describe's, and its cause, which
// only the log sees, is what actually went wrong. It is what a chain returns for
// a failure of an OAuth request, and what an ErrorsOAuth route sends as it is.
func failure(code string, cause error) *apierr.Error {
	kind := apierr.BadRequest

	switch code {
	case oauthServerError:
		kind = apierr.Internal
	case oauthTemporarilyDown:
		kind = apierr.Unavailable
	}

	return apierr.New(kind, code, describe(code)).WithCause(cause)
}

// refusing returns a MapErr step that turns any failure into failure(code), with
// the failure it replaces as the cause.
func refusing(code string) func(error) error {
	return func(cause error) error { return failure(code, cause) }
}

// oauthCode is the OAuth error code a failure is reported under: its own, when
// it is one this package classified, and server_error for anything else, so an
// unclassified failure never leaks its code.
func oauthCode(err error) string {
	found := apierr.As(err)
	if found.Kind == apierr.Internal {
		return oauthServerError
	}

	return found.Code
}

// open declares a GET route that needs no credential and answers in the API's
// error format.
func open(path string, maxBody int64, handle func(*auth.Call) result.Result[httpapi.Response]) auth.Route {
	return auth.Route{
		Method: http.MethodGet, Path: path, MaxBody: maxBody, Credential: auth.None, Handle: handle,
	}
}

// openOAuth declares a GET route that needs no credential and answers in the
// RFC 6749 error format: the routes of the OAuth endpoints proper.
func openOAuth(path string, maxBody int64, handle func(*auth.Call) result.Result[httpapi.Response]) auth.Route {
	return auth.Route{
		Method: http.MethodGet, Path: path, MaxBody: maxBody, Credential: auth.None, Errors: httpapi.ErrorsOAuth,
		Handle: handle,
	}
}

// form declares a POST route of the standard token endpoints: it takes
// application/x-www-form-urlencoded, needs no credential (the boundary refuses a
// form on a route that has one, because a form is no defence against a forged
// cross-site request and a cookie must not mean anything here) and answers in
// the RFC 6749 error format.
func form(path string, maxBody int64, handle func(*auth.Call) result.Result[httpapi.Response]) auth.Route {
	return auth.Route{
		Method: http.MethodPost, Path: path, MaxBody: maxBody, Media: httpapi.MediaForm, Errors: httpapi.ErrorsOAuth,
		Credential: auth.None, Handle: handle,
	}
}

// requiredAs reads the parameter name, which must have been sent, and parses it.
// A missing one is an invalid_request, and one that does not parse is the OAuth
// error invalid.
func requiredAs[T any](
	params httpapi.Params, name, invalid string, parse func(string) (T, error),
) result.Result[T] {
	return required(params, name).
		MapErr(refusing(oauthInvalidRequest)).
		Then(func(raw string) (T, error) {
			return result.Of(parse(raw)).MapErr(refusing(invalid)).Get()
		})
}

// table is the resource table of the deployment: the one for its API_ORIGIN.
func (d Deps) table(cfg config.Config) resource.Table {
	return d.Resources(cfg.API.String)
}

// withQuery returns base with params appended to its query. The base is a
// redirect URI a client registered, which may already have a query (and may end
// in the "?" or "&" that introduces one), and RFC 6749 section 3.1.2 requires
// that query to be kept, so the parameters are added after it and never in its
// place. The parameters are form-encoded, so the result is printable ASCII
// without spaces, which a Location header requires.
func withQuery(base string, params url.Values) string {
	separator := "?"

	switch {
	case strings.HasSuffix(base, "?") || strings.HasSuffix(base, "&"):
		separator = ""
	case strings.Contains(base, "?"):
		separator = "&"
	}

	return base + separator + params.Encode()
}

// uiPage is the URL of a page of the UI, with params as its query.
func uiPage(cfg config.Config, path string, params url.Values) string {
	return withQuery(cfg.UI.String+path, params)
}

// redirect is the 302 every authorization response is.
func redirect(location string) httpapi.Response {
	return httpapi.Redirect(http.StatusFound, location)
}

// encode writes v as JSON without HTML escaping, which is what the sealed
// request is budgeted for (input's TestPendingRequestFitsItsPayload): with Go's
// default, '<', '>' and '&' are written as six bytes each. v is only ever a
// struct of strings and numbers, so it cannot fail to encode.
func encode(v any) []byte {
	var out bytes.Buffer

	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)

	err := encoder.Encode(v)
	// coverage:ignore: a struct of strings and integers always encodes
	if err != nil {
		panic("oauth: encode: " + err.Error())
	}

	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}

// hashOf is the SHA-256 of b: the value a single-use record keeps instead of b.
func hashOf(b []byte) []byte {
	sum := sha256.Sum256(b)

	return sum[:]
}
