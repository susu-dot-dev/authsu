package httpapi

import (
	"net/http"
	"slices"
	"strings"
)

// Header names used by CORS.
const (
	headerOrigin      = "Origin"
	headerVary        = "Vary"
	headerAllowOrigin = "Access-Control-Allow-Origin"
	headerAllowCreds  = "Access-Control-Allow-Credentials"
	headerAllowMeths  = "Access-Control-Allow-Methods"
	headerAllowHdrs   = "Access-Control-Allow-Headers"
	headerMaxAge      = "Access-Control-Max-Age"
	headerReqMethod   = "Access-Control-Request-Method"
)

// corsMethods are the methods a preflight may be answered for: the ones the API
// has routes for. PATCH and DELETE are not CORS-safelisted, so they always
// need a preflight, and so are as protected as POST; every unsafe method also
// requires Content-Type: application/json (see Serve).
func corsMethods() []string {
	return []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete}
}

// preflightMaxAge is how long, in seconds, a browser may cache a preflight
// answer. Browsers cap it themselves (Chromium at two hours).
const preflightMaxAge = "600"

// CORS wraps next so that the one origin getOrigin returns may call it from
// script in a browser; every other origin is treated exactly as before, which
// is to say it is never answered with a CORS header.
//
// The trust decision is deliberately small:
//
//   - One origin, compared exactly as a whole string against the value
//     getOrigin returns for this request. There is no list, no wildcard and no
//     pattern, so there is nothing to bypass with a look-alike host
//     ("https://susu.dev.evil.example") or a parent-domain trick. An empty
//     result allows nothing, so an unconfigured deployment sends no CORS
//     headers at all.
//   - Credentials are allowed, because the session is a cookie. That is only
//     safe with a specific origin, never "*", which is why a wildcard is not
//     expressible.
//   - A preflight (OPTIONS carrying Access-Control-Request-Method) from the
//     allowed origin is answered here, with 204, before routing. From any
//     other origin it falls through to next, which answers it as it always
//     has (405 or 404, no CORS headers), so the browser refuses the real
//     request.
//
// This keeps the CSRF defence described in the package doc intact: every
// unsafe route still requires Content-Type: application/json, which a
// browser sends cross-origin only after a preflight succeeds, and a preflight
// now succeeds for exactly the origin that is meant to be calling. A hostile
// origin still cannot get one.
//
// Responses carry "Vary: Origin" whenever the request has an Origin header,
// whether or not it was allowed, so a shared cache never serves one origin's
// answer to another.
func CORS(getOrigin func() string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		origin := req.Header.Get(headerOrigin)
		if origin == "" {
			next.ServeHTTP(writer, req)

			return
		}

		// The answer depends on Origin, allowed or not.
		writer.Header().Add(headerVary, headerOrigin)

		allowed := getOrigin()
		if allowed == "" || origin != allowed {
			next.ServeHTTP(writer, req)

			return
		}

		writer.Header().Set(headerAllowOrigin, origin)
		writer.Header().Set(headerAllowCreds, "true")

		if isPreflight(req) {
			answerPreflight(writer, req)

			return
		}

		next.ServeHTTP(writer, req)
	})
}

// isPreflight reports whether req is a CORS preflight: an OPTIONS request that
// names the method it asks about. A bare OPTIONS is not one.
func isPreflight(req *http.Request) bool {
	return req.Method == http.MethodOptions && req.Header.Get(headerReqMethod) != ""
}

// answerPreflight answers an allowed origin's preflight. It does not look at
// which route was asked about: every route's real method and header rules are
// enforced when the real request arrives, so the preflight only has to say that
// the browser may try.
//
// The requested method is echoed only when it is one this API uses (GET, POST,
// PATCH and DELETE), and the only request header allowed is Content-Type, which
// is all the frontend sends. A request for anything else gets no Allow-Methods
// and the browser refuses.
func answerPreflight(writer http.ResponseWriter, req *http.Request) {
	header := writer.Header()
	header.Add(headerVary, headerReqMethod)
	header.Add(headerVary, "Access-Control-Request-Headers")

	method := req.Header.Get(headerReqMethod)
	if slices.Contains(corsMethods(), method) {
		header.Set(headerAllowMeths, method)
	}

	if headersAllowed(req.Header.Get("Access-Control-Request-Headers")) {
		header.Set(headerAllowHdrs, "Content-Type")
	}

	header.Set(headerMaxAge, preflightMaxAge)
	header.Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

// headersAllowed reports whether every header a preflight asks to send is
// Content-Type. An empty request is allowed: nothing beyond the safelist was
// asked for.
func headersAllowed(requested string) bool {
	for name := range strings.SplitSeq(requested, ",") {
		name = strings.TrimSpace(name)
		if name != "" && !strings.EqualFold(name, "content-type") {
			return false
		}
	}

	return true
}
