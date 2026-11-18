// Package auth is the boundary between a request and the feature that handles
// it: it decides who is calling and whether they may, and a feature's handler
// runs only after that is settled.
//
// A feature declares its endpoints as Routes and hands them to Handler. For
// each request Handler does, in this order:
//
//  1. Everything httpapi does first: the method (405 with Allow), the
//     Content-Type of an unsafe method (415), and the body up to the route's
//     MaxBody (413). Nothing below runs for a request that fails here.
//  2. For a Session route: loads the configuration (503 not_configured), reads
//     the one __Host-session cookie, parses it as an input.Token, verifies the
//     JWT with the session audience and this API's issuer, reads the key's row
//     and checks that the signed subject is the row's owner. Every verdict on
//     the token is one answer, 401 unauthenticated (see Unauthenticated); a
//     failure of the store is 503 session_verify_failed.
//  3. Runs the route's Require on the Principal (403 forbidden for Admin).
//  4. Parses the route's {id} wildcard, if it has one, as an input.ID (400
//     invalid_id). This is after the credential, so a caller who may not use
//     the route learns nothing about what a valid id looks like or whether the
//     route exists for it.
//  5. Runs Handle.
//
// A 401 means one thing: the caller's credential is not valid, so a client
// should treat the user as signed out. A 403 means the credential is valid and
// the caller may not do this; the client keeps the session.
//
// A route that fails any step never reaches its handler. A route is None or
// Session, and says which: leaving it out is a programming error, not a public
// route (see Handler).
//
// What the boundary does not do: it never writes. Reads of the account happen
// in the same primary-key read that finds the key, so a revoked account or a
// changed role takes effect on the next request (store.ActiveKey).
package auth

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Error codes the boundary produces. They are stable: clients and dashboards
// may match on them. A store failure while verifying a session has the code
// store.CodeSessionVerifyFailed; an id that does not parse has
// input.CodeInvalidID.
const (
	// CodeUnauthenticated is the one answer to a request without a valid
	// credential.
	CodeUnauthenticated = "unauthenticated"
	// CodeForbidden means the caller is signed in but may not do this.
	CodeForbidden = "forbidden"
	// CodeNotConfigured means the deployment's configuration is missing or
	// invalid: the service is broken, not the request.
	CodeNotConfigured = "not_configured"
)

// Credential is the kind of proof of identity a route requires.
//
// Adding a kind (a bearer API key, say) is local to this package: a constant
// here, the case in Handler's authentication step that reads the token from
// the request, and the call to the shared token verification with the kind's
// audience. No route and no feature changes.
type Credential uint8

const (
	// The zero Credential is not a kind: a route that does not say which it
	// needs is refused when the handler is built, so forgetting the field
	// cannot publish a route.
	_ Credential = iota

	// None is a route open to anyone, such as the endpoints a person uses
	// before they have a session. It never reads the cookie or the store.
	None

	// Session is a route that needs a valid login session, carried in the
	// __Host-session cookie.
	Session
)

// Principal is who a verified credential speaks for. Every field comes from
// the stored key and its account, read at the time of the request, never from
// the token's claims except the subject, which must agree with the row.
type Principal struct {
	// UserID is the account.
	UserID string
	// Role is the account's role now, not at the key's creation.
	Role string
	// KeyID is the kid of the token presented.
	KeyID string
	// CredentialID is the passkey the session was issued for, or "" for a key
	// that has none.
	CredentialID string
	// Kind is the kind of key presented (KindSession).
	Kind string
	// ExpiresAt is when the key stops being active.
	ExpiresAt time.Time
}

// Route is one method of one path, with everything the boundary enforces for
// it.
type Route struct {
	// Method is the HTTP method: GET, HEAD, POST, PUT, PATCH or DELETE.
	Method string
	// Path is the ServeMux pattern without a method, such as "/api/agents/{id}".
	// A path has at most one wildcard, and it is named "id": it is a whole
	// segment, and it is parsed as an input.ID after the credential and the
	// requirement, before Handle. Several routes may share a path.
	Path string
	// MaxBody caps the request body in bytes. Zero means
	// httpapi.DefaultMaxBody, which is also the most a route may ask for.
	MaxBody int64
	// Credential says what the caller must present. It must be set.
	Credential Credential
	// Require decides whether the authenticated caller may use the route; nil
	// means any authenticated caller may. It must be nil for a route with
	// Credential None, which has no caller to ask about. A requirement returns
	// a classified error (Admin is 403) and is a pure function of the Principal.
	Require func(Principal) error
	// Handle answers the request. It runs only after every check has passed,
	// with Call.Principal set for a Session route.
	Handle func(*Call) result.Result[httpapi.Response]
}

// Call is what a route's Handle sees: the request, the verified caller, and the
// path id.
type Call struct {
	// Request is the HTTP request. Its PathValues are the raw wildcard text;
	// use ID for the parsed values.
	Request httpapi.Request
	// Principal is the verified caller. It is the zero value for a None route.
	Principal Principal
	// Getenv reads a deploy-time secret or variable. It is called per request,
	// because the Worker's environment only exists while a request is handled.
	Getenv func(string) string

	id    input.ID
	hasID bool

	cfg       config.Config
	cfgErr    error
	cfgLoaded bool
}

// ID returns the parsed value of the route's {id} wildcard. It was parsed
// before Handle ran, so this cannot fail on a route whose Path has one. The
// route has no other wildcard to name, so there is no name to get wrong. Asking
// a route without one is a programming error and panics, which the boundary
// reports as an internal error rather than returning an empty id that a query
// would treat as "no such row".
func (c *Call) ID() input.ID {
	if !c.hasID {
		panic("auth: route has no {id} wildcard")
	}

	return c.id
}

// Config returns the deployment configuration, loading it on first use and
// remembering the outcome for the rest of the request. Missing or invalid
// configuration is 503 not_configured, with the reason only in the log.
func (c *Call) Config() (config.Config, error) {
	if !c.cfgLoaded {
		cfg, err := config.Load(c.Getenv)

		c.cfg = cfg
		c.cfgErr = apierr.Wrap(err, apierr.Unavailable, CodeNotConfigured, "the service is not configured")
		c.cfgLoaded = true
	}

	return c.cfg, c.cfgErr
}

// Deps are the collaborators of Handler. All are required.
type Deps struct {
	// Keys reads the stored key a session token names. *store.Store satisfies
	// it. A failure must come back classified (store does), because it is sent
	// as is.
	Keys KeyReader
	// Now is the clock, used to decide whether a stored key is still active.
	Now func() time.Time
	// Getenv reads the deploy-time configuration. See Call.Getenv.
	Getenv func(string) string
	// Log records an error the boundary turned into a response, with the
	// request and the cause. It is where the reason for a 401 is.
	Log httpapi.Logger
}

// methods are the HTTP methods a route may use. OPTIONS is not among them: it
// belongs to the CORS preflight, which is answered before routing.
func methods() []string {
	return []string{
		http.MethodGet, http.MethodHead, http.MethodPost,
		http.MethodPut, http.MethodPatch, http.MethodDelete,
	}
}

// Handler returns the http.Handler for routes: routes are grouped by path, each
// path dispatches on the request's method with its own body limit, and every
// path no route claims is answered by the JSON 404 (httpapi.NotFound). A route
// that claims "/" replaces that catch-all and so answers every unknown path.
//
// Handler validates routes and deps and panics on a programming error: a nil
// dependency, an unknown method, a path that does not start with "/", a nil
// Handle, a Credential that is not None or Session (including one that was
// never set), a Require on a None route, a MaxBody that is negative or above
// httpapi.DefaultMaxBody, the same method and path twice, a wildcard that is
// not a whole {name} segment or that appears twice in a path, and a path the
// ServeMux itself refuses. It panics, rather than returning an error, because a
// route table is fixed in code: the failure is found by the first test or the
// first start, never by a request. It does this once, at construction; a
// request never panics for these reasons.
func Handler(routes []Route, deps Deps) http.Handler {
	checkDeps(deps)

	paths := groupRoutes(routes)
	router := &router{keys: deps.Keys, now: deps.Now, getenv: deps.Getenv}
	mux := http.NewServeMux()

	for _, path := range slices.Sorted(maps.Keys(paths)) {
		group := paths[path]
		byMethod := make(map[string]httpapi.MethodRoute, len(group.routes))

		for method, route := range group.routes {
			byMethod[method] = httpapi.MethodRoute{Handler: router.handler(route, group.wildcards), MaxBody: route.MaxBody}
		}

		mux.Handle(path, httpapi.ServeRoutes(deps.Log, group.wildcards, byMethod))
	}

	if _, claimed := paths["/"]; !claimed {
		mux.Handle("/", httpapi.ServeAny(deps.Log, httpapi.NotFound))
	}

	return mux
}

// checkDeps panics when a dependency is missing.
func checkDeps(deps Deps) {
	for name, missing := range map[string]bool{
		"Keys": deps.Keys == nil, "Now": deps.Now == nil, "Getenv": deps.Getenv == nil, "Log": deps.Log == nil,
	} {
		if missing {
			panic("auth: Deps." + name + " is required")
		}
	}
}

// pathRoutes are the routes that share a path.
type pathRoutes struct {
	// wildcards are the names of the path's {name} wildcards, in order.
	wildcards []string
	routes    map[string]Route
}

// groupRoutes validates routes and groups them by path.
func groupRoutes(routes []Route) map[string]*pathRoutes {
	paths := map[string]*pathRoutes{}

	for _, route := range routes {
		wildcards, problem := wildcardNames(route.Path)
		if problem == "" {
			problem = routeProblem(route)
		}

		if problem != "" {
			panic(fmt.Sprintf("auth: route %s %q: %s", route.Method, route.Path, problem))
		}

		group, known := paths[route.Path]
		if !known {
			group = &pathRoutes{wildcards: wildcards, routes: map[string]Route{}}
			paths[route.Path] = group
		}

		if _, duplicate := group.routes[route.Method]; duplicate {
			panic(fmt.Sprintf("auth: route %s %q is declared twice", route.Method, route.Path))
		}

		group.routes[route.Method] = route
	}

	return paths
}

// routeProblem describes what is wrong with route apart from its path
// wildcards, or returns "".
func routeProblem(route Route) string {
	switch {
	case !slices.Contains(methods(), route.Method):
		return "the method is not GET, HEAD, POST, PUT, PATCH or DELETE"
	case !strings.HasPrefix(route.Path, "/"):
		return "the path must start with /"
	case route.Handle == nil:
		return "Handle is nil"
	case route.Credential != None && route.Credential != Session:
		return "Credential must be None or Session"
	case route.Credential == None && route.Require != nil:
		return "Require needs an authenticated caller, and a None route has none"
	case route.MaxBody < 0 || route.MaxBody > httpapi.DefaultMaxBody:
		return "MaxBody must be from 0 to httpapi.DefaultMaxBody"
	}

	return ""
}

// wildcardNames returns the names of the wildcards in path, which is "id" for a
// path that has one and nothing for a path that has none, or a description of
// why the path's wildcards are not acceptable. A path has at most one wildcard
// and it is a whole segment named "id", so a handler asks for it without a name
// and cannot misspell it. "{$}", which anchors a path's end, is not a wildcard.
func wildcardNames(path string) ([]string, string) {
	var names []string

	for segment := range strings.SplitSeq(path, "/") {
		if !strings.ContainsAny(segment, "{}") {
			continue
		}

		name, whole := strings.CutPrefix(segment, "{")
		name, closed := strings.CutSuffix(name, "}")

		switch {
		case !whole || !closed || strings.ContainsAny(name, "{}"):
			return nil, "a wildcard must be a whole {id} segment"
		case name == "$":
			continue
		case name != "id":
			return nil, "the only wildcard a path may have is {id}"
		case len(names) > 0:
			return nil, "a path may have only one {id} wildcard"
		}

		names = append(names, name)
	}

	return names, ""
}

// router carries what every route's pipeline needs.
type router struct {
	keys   KeyReader
	now    func() time.Time
	getenv func(string) string
}

// handler returns the httpapi handler for route: it authenticates, applies the
// requirement, parses the path id and only then calls route.Handle. The
// credential comes first, so a caller who may not use the route is refused
// before anything about the request, a malformed id included, is judged.
func (r *router) handler(route Route, wildcards []string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		call := r.newCall(req)

		call, err := result.Of(call, r.authenticate(route.Credential, call)).
			Check(func(call *Call) error { return require(route.Require, call.Principal) }).
			Then(func(call *Call) (*Call, error) { return call, call.parseID(wildcards) }).
			Get()
		if err != nil {
			return result.Fail[httpapi.Response](err)
		}

		return route.Handle(call)
	}
}

// newCall builds the Call for req. Its id is not parsed yet.
func (r *router) newCall(req httpapi.Request) *Call {
	return &Call{
		Request: req, Principal: Principal{}, Getenv: r.getenv, id: input.ID{}, hasID: false,
		cfg: config.Config{}, cfgErr: nil, cfgLoaded: false,
	}
}

// parseID parses the route's {id} wildcard, if it has one, as an input.ID.
func (c *Call) parseID(wildcards []string) error {
	if len(wildcards) == 0 {
		return nil
	}

	id, err := input.ParseID(c.Request.PathValues[wildcards[0]])
	if err != nil {
		return err //nolint:wrapcheck // the parser's error is already the classified client error
	}

	c.id, c.hasID = id, true

	return nil
}

// authenticate fills call.Principal for credential. A None route has no step:
// it does not read the cookie, the configuration or the store.
func (r *router) authenticate(credential Credential, call *Call) error {
	if credential != Session {
		return nil
	}

	principal, err := r.session(call)
	if err != nil {
		return err
	}

	call.Principal = principal

	return nil
}

// require applies a route's requirement, if it has one.
func require(requirement func(Principal) error, principal Principal) error {
	if requirement == nil {
		return nil
	}

	return requirement(principal)
}
