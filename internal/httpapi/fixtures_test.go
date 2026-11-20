package httpapi_test

import (
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

// Strings that more than one test file spells.
const (
	noStore         = "no-store"
	noCache         = "no-cache"
	emptyValue      = "empty value"
	oneParam        = "a=1"
	nullOrigin      = "null"
	lowerCT         = "content-type"
	pathExchange    = "/oauth/token"
	pathRevoke      = "/oauth/revoke"
	pathJWKS        = "/.well-known/jwks.json"
	credsTrue       = "true"
	pathMetadata    = "/.well-known/oauth-authorization-server"
	pathAuth        = "/oauth/authorize"
	pathAuthDir     = "/oauth/authorize/"
	pathIntrospect  = "/oauth/introspect"
	pathExchangeDir = "/oauth/token/"
	codeTooBig      = "body_too_large"

	allowOrigin  = "Access-Control-Allow-Origin"
	allowCreds   = "Access-Control-Allow-Credentials"
	allowMethods = "Access-Control-Allow-Methods"
	allowHeaders = "Access-Control-Allow-Headers"

	codeInvalidStatus   = "invalid_status"
	codeInvalidRedirect = "invalid_redirect"
	codeDuplicate       = "duplicate_parameter"
	codeEncoding        = "invalid_encoding"
	codeParamName       = "invalid_parameter_name"
	codeText            = "invalid_text"

	errInvalidRequest = "invalid_request"
	errServer         = "server_error"
	errUnavailable    = "temporarily_unavailable"
	errClient         = "invalid_client"
	descInternal      = "internal error"
	scopeName         = "scope"
)

// serve is a path that answers one method with handler and the default body
// limit: the shape of a route with nothing but a method.
func serve(method string, logger httpapi.Logger, handler httpapi.Handler) http.Handler {
	return serveMethods(logger, nil, map[string]httpapi.Handler{method: handler})
}

// serveMethods is a path that answers each method of handlers with its own
// handler and the default body limit.
func serveMethods(logger httpapi.Logger, wildcards []string, handlers map[string]httpapi.Handler) http.Handler {
	routes := make(map[string]httpapi.MethodRoute, len(handlers))

	for method, handler := range handlers {
		routes[method] = httpapi.MethodRoute{Handler: handler, MaxBody: 0}
	}

	return httpapi.ServeRoutes(logger, wildcards, routes)
}

// serveRoute is a path that answers one method with route as declared.
func serveRoute(method string, route httpapi.MethodRoute) http.Handler {
	return httpapi.ServeRoutes(func(httpapi.Request, *apierr.Error) {}, nil, map[string]httpapi.MethodRoute{method: route})
}
