package httpapi_test

import (
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/httpapi"
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
