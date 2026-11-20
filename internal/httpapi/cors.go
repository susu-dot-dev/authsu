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
// requires Content-Type: application/json (see ServeRoutes).
func corsMethods() []string {
	return []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete}
}

// publicMethods are the methods a preflight may be answered for on a public
// path: discovery documents are read with GET, and the token and revocation
// endpoints are POSTed to. Nothing public changes or deletes by another method.
func publicMethods() []string {
	return []string{http.MethodGet, http.MethodPost}
}

// preflightMaxAge is how long, in seconds, a browser may cache a preflight
// answer. Browsers cap it themselves (Chromium at two hours).
const preflightMaxAge = "600"

// CORSPaths are the paths that have a CORS policy of their own, matched against
// the request's URL path exactly (see CORS). Every other path has the
// credentialed policy.
type CORSPaths struct {
	// Public are the paths any origin may call, without credentials.
	Public []string

	// None are the paths that get no CORS at all: no header, on a preflight or
	// on the real request, whatever the origin. They are called by something
	// that is not a script in a browser (a navigation, a server), so no
	// cross-origin read of them is wanted, not even the first party's.
	None []string
}

// corsPolicy is the policy of one path.
type corsPolicy int

const (
	policyCredentialed corsPolicy = iota
	policyPublic
	policyNone
)

// policies indexes the paths by policy. A path in more than one set is a defect
// of the caller, found when the handler is built and never when a request
// arrives, so it panics.
func (p CORSPaths) policies() map[string]corsPolicy {
	out := make(map[string]corsPolicy, len(p.Public)+len(p.None))

	for policy, paths := range map[corsPolicy][]string{policyPublic: p.Public, policyNone: p.None} {
		for _, path := range paths {
			if _, taken := out[path]; taken {
				panic("httpapi: CORS path " + path + " is in more than one policy")
			}

			out[path] = policy
		}
	}

	return out
}

// CORS wraps next with three policies, chosen by the request's path.
//
// # The credentialed policy (every path not in paths)
//
// The one origin getOrigin returns may call from script in a browser; every
// other origin is treated exactly as before, which is to say it is never
// answered with a CORS header.
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
//     expressible here.
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
//
// # The public policy (paths.Public)
//
// Any origin may call, without credentials. Every response carries
// "Access-Control-Allow-Origin: *" and never Allow-Credentials, so a browser
// withholds the session cookie from such a request and refuses to expose a
// response to a credentialed one: whatever a page on another site reads here,
// it reads as an anonymous visitor. It is for the OAuth discovery documents,
// the key set, and the token and revocation endpoints, which authenticate by
// what the request carries and never by a cookie, and which a client in a
// browser must be able to call (docs/oauth_design.md). A route is in exactly
// one policy: the UI origin gets no credentialed answer on a public path.
//
// The answer does not depend on Origin, so these responses carry no Vary. A
// preflight is answered here with 204 for GET and POST and the one header
// Content-Type, as above. Every route's own method and Content-Type rules still
// apply to the real request.
//
// # No policy (paths.None)
//
// The request is passed to next untouched and the response carries no CORS
// header and no Vary: Origin, whatever the origin, the UI's own included. A
// preflight is not answered here, so it falls through to next like any other
// OPTIONS (a 405 or a 404 with no CORS headers) and the browser refuses the real
// request. It is for the endpoints that are navigated to or called by servers,
// which a page of another site, or of the first party, has no business reading
// from script: the authorization endpoint and introspection
// (docs/oauth_design.md).
//
// Paths are matched against the request's URL path exactly, as a whole string:
// no prefix, no wildcard, no case folding and no trailing-slash tolerance, so a
// path the sets do not name ("/oauth/token/", "/OAUTH/TOKEN", "/oauth/token/x")
// keeps the credentialed policy. The sets are small and fixed in code, and a
// prefix would silently publish a route added under it. A path in both sets
// panics when the handler is built: a route is in exactly one policy.
func CORS(getOrigin func() string, paths CORSPaths, next http.Handler) http.Handler {
	policies := paths.policies()
	credentialed := credentialedCORS(getOrigin, next)

	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		switch policies[req.URL.Path] {
		case policyPublic:
			writer.Header().Set(headerAllowOrigin, "*")

			if isPreflight(req) {
				answerPreflight(writer, req, publicMethods())

				return
			}

			next.ServeHTTP(writer, req)
		case policyNone:
			next.ServeHTTP(writer, req)
		case policyCredentialed:
			credentialed.ServeHTTP(writer, req)
		}
	})
}

// credentialedCORS is the one-origin policy with credentials.
func credentialedCORS(getOrigin func() string, next http.Handler) http.Handler {
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
			answerPreflight(writer, req, corsMethods())

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
// The requested method is echoed only when it is one of allowed (the methods
// the policy's routes use), and the only request header allowed is
// Content-Type, which is all the frontend sends. A request for anything else
// gets no Allow-Methods and the browser refuses.
func answerPreflight(writer http.ResponseWriter, req *http.Request, allowed []string) {
	header := writer.Header()
	header.Add(headerVary, headerReqMethod)
	header.Add(headerVary, "Access-Control-Request-Headers")

	method := req.Header.Get(headerReqMethod)
	if slices.Contains(allowed, method) {
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
