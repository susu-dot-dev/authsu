package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/susu-dot-dev/authsu/internal/apierr"
)

// The OAuth error codes a handler may emit through OAuthError, from RFC 6749
// section 5.2 (the token endpoint), RFC 7009 section 2.2.1 (revocation) and RFC
// 8707 section 2 (resource indicators).
const (
	// OAuthInvalidRequest is a request that is missing a parameter, repeats
	// one, or is otherwise malformed. 400.
	OAuthInvalidRequest = "invalid_request"
	// OAuthInvalidClient is a client_id that is not valid. 400: authsu's
	// clients are public and never authenticate through the Authorization
	// header, which is the case RFC 6749 section 5.2 gives 401 to.
	OAuthInvalidClient = "invalid_client"
	// OAuthInvalidGrant is an authorization code or refresh token that is
	// invalid, expired, revoked, or issued to another client or redirect URI,
	// or a PKCE verifier that does not match. 400.
	OAuthInvalidGrant = "invalid_grant"
	// OAuthUnauthorizedClient is a client that may not use the grant type. 400.
	OAuthUnauthorizedClient = "unauthorized_client"
	// OAuthUnsupportedGrantType is a grant_type authsu does not implement. 400.
	OAuthUnsupportedGrantType = "unsupported_grant_type"
	// OAuthInvalidScope is a scope that is unknown, repeated or beyond what the
	// grant allows. 400.
	OAuthInvalidScope = "invalid_scope"
	// OAuthUnsupportedTokenType is a token_type_hint authsu does not implement
	// (RFC 7009). 400.
	OAuthUnsupportedTokenType = "unsupported_token_type"
	// OAuthInvalidTarget is a resource that is not one authsu issues tokens
	// for (RFC 8707). 400.
	OAuthInvalidTarget = "invalid_target"
	// OAuthServerError is an unexpected failure. 500; the description is
	// always the fixed "internal error".
	OAuthServerError = "server_error"
	// OAuthTemporarilyUnavailable is a service that cannot answer now, a
	// database that is down or a deployment that is not configured. 503.
	OAuthTemporarilyUnavailable = "temporarily_unavailable"
)

// oauthKinds is every error code OAuthError accepts, with the apierr kind that
// gives its status. It is also the set of codes a failure may carry to be shown
// as itself on an ErrorsOAuth route.
func oauthKinds() map[string]apierr.Kind {
	return map[string]apierr.Kind{
		OAuthInvalidRequest:         apierr.BadRequest,
		OAuthInvalidClient:          apierr.BadRequest,
		OAuthInvalidGrant:           apierr.BadRequest,
		OAuthUnauthorizedClient:     apierr.BadRequest,
		OAuthUnsupportedGrantType:   apierr.BadRequest,
		OAuthInvalidScope:           apierr.BadRequest,
		OAuthUnsupportedTokenType:   apierr.BadRequest,
		OAuthInvalidTarget:          apierr.BadRequest,
		OAuthServerError:            apierr.Internal,
		OAuthTemporarilyUnavailable: apierr.Unavailable,
	}
}

// errUnknownOAuthCode is the cause when OAuthError is given a code that is not
// one of the constants above.
var errUnknownOAuthCode = errors.New("unknown OAuth error code")

// OAuthError returns the failure a handler on an ErrorsOAuth route returns to
// answer with a specific OAuth error code: code is one of the OAuth constants of
// this package and description is fixed, client-safe text (printable ASCII
// without quotes or backslashes, as RFC 6749 section 5.2 requires; never
// err.Error()). Its status is the standard one for the code, and its apierr
// code is the OAuth code, so the log and the response agree.
//
// A code that is not one of the constants is a programming error and comes back
// as an Internal error, which is sent as server_error, so a typo fails closed.
//
// What an ErrorsOAuth route sends for any failure, not only these:
//
//   - an Internal failure is {"error":"server_error","error_description":"internal
//     error"} with 500, whatever its code and description;
//   - a failure whose Code is one of the OAuth codes is sent as that code with
//     its own status and description;
//   - any other failure is sent under the OAuth code of its kind, with its own
//     status and description: BadRequest, NotFound, MethodNotAllowed, Conflict,
//     PayloadTooLarge and UnsupportedMediaType are invalid_request (so the
//     parameter errors of ParseParams, a 413 and a 415 are), Unauthorized is
//     invalid_client, Forbidden is unauthorized_client, RateLimited and
//     Unavailable (a store failure, 503 not_configured) are
//     temporarily_unavailable.
//
// The detailed apierr code (body_too_large, duplicate_parameter) is in the log,
// not in this format, which has nowhere to put it.
func OAuthError(code, description string) *apierr.Error {
	kind, known := oauthKinds()[code]
	if !known {
		return apierr.New(apierr.Internal, "unknown_oauth_error", "internal error").
			WithCause(fmt.Errorf("%w: %q", errUnknownOAuthCode, code))
	}

	return apierr.New(kind, code, description)
}

// oauthCodeOf is the OAuth error code failure is sent under.
func oauthCodeOf(failure *apierr.Error) string {
	if failure.Kind == apierr.Internal {
		return OAuthServerError
	}

	if _, known := oauthKinds()[failure.Code]; known {
		return failure.Code
	}

	switch failure.Kind { //nolint:exhaustive // Internal is handled above, and a kind this does not know fails closed
	case apierr.BadRequest, apierr.NotFound, apierr.MethodNotAllowed, apierr.Conflict, apierr.PayloadTooLarge,
		apierr.UnsupportedMediaType:
		return OAuthInvalidRequest
	case apierr.Unauthorized:
		return OAuthInvalidClient
	case apierr.Forbidden:
		return OAuthUnauthorizedClient
	case apierr.RateLimited, apierr.Unavailable:
		return OAuthTemporarilyUnavailable
	default:
		return OAuthServerError
	}
}

// oauthBody is the JSON shape of an RFC 6749 section 5.2 error response.
type oauthBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description"` //nolint:tagliatelle // RFC 6749 section 5.2 names this member
}

// marshalOAuthError builds the RFC 6749 error body. Internal errors expose no
// description, as in marshalError. It cannot fail: it encodes two strings.
func marshalOAuthError(failure *apierr.Error) []byte {
	body := oauthBody{Error: oauthCodeOf(failure), Description: failure.Description}
	if failure.Kind == apierr.Internal {
		body.Description = "internal error"
	}

	data, err := json.Marshal(body)
	// coverage:ignore: a struct of two strings always encodes
	if err != nil {
		return []byte(`{"error":"server_error","error_description":"internal error"}` + "\n")
	}

	return append(data, '\n')
}
