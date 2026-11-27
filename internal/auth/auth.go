// Package auth is the boundary between a request and the feature that handles
// it: it decides who is calling and whether they may, and a feature's handler
// runs only after that is settled.
//
// A feature declares its endpoints as Routes and hands them to Handler. For
// each request Handler does, in this order:
//
//  1. Everything httpapi does first: the method (405 with Allow), the
//     Content-Type of an unsafe method (415: the route's Media, which is JSON
//     unless it declares a form), and the body and query string up to the
//     route's MaxBody (413). Nothing below runs for a request that fails here.
//     Every failure, this step's and the later ones, is written in the route's
//     Errors format.
//  2. For an Authenticated route: reads the credential, which is either the
//     one __Host-session cookie (a session) or an "Authorization: Bearer"
//     token (an API key, or an OAuth grant's access token, told apart by the
//     token's tag) and never both. The cookie accepts only a session token; the
//     header accepts only the two kinds, so a token of any other kind, or
//     anything that is not a token, is refused here, before the store is read.
//     A token that parses is resolved in the store (store.ResolveSession,
//     store.ResolveAPIKey, store.ResolveGrant), which reads the secret, its
//     account and, for an agent's credential, the agent in one statement and
//     finds it only while every part is active (an agent's sandbox, when it has
//     one, included: a key of an expired or deleted sandbox is not active, and
//     a grant of an agent in a sandbox never resolves). Every verdict on the
//     credential is one answer, 401 unauthenticated (see Unauthenticated); a
//     failure of the store is 503 session_verify_failed. Verifying a session or
//     a key needs no configuration: a token carries nothing to check. A grant
//     reads API_ORIGIN, for the login resource it must be for.
//  3. Works out the effective scopes: the credential's scope list (a session's
//     is SessionScope, a key's is the one stored with it, a grant's is the
//     authsu names of its access token's scope, within the login resource's
//     allowlist now), narrowed by the agent's scopes when an agent is acting
//     (docs/permissions_design.md).
//  4. Applies the route's Access (403): an OAuth grant on a route that has not
//     opted in with FromGrants (grant_not_accepted), a sandboxed agent on a
//     route that has not opted in with InSandbox (sandbox_confined), then the
//     administrator role for an admin scope, then the scope, then session-only,
//     then no-agents.
//  5. Parses the route's {id} wildcard, if it has one, as an input.ID (400
//     invalid_id). This is after the credential, so a caller who may not use
//     the route learns nothing about what a valid id looks like or whether the
//     route exists for it.
//  6. Runs Handle.
//
// A 401 means one thing: the caller's credential is not valid, so a client
// should treat the user as signed out. A 403 means the credential is valid and
// the caller may not do this; the client keeps the session.
//
// A route that fails any step never reaches its handler. A route is None or
// Authenticated, and says which, and an Authenticated route declares its
// Access: leaving either out is a programming error, not a public route (see
// Handler).
//
// What the boundary does not do: it never writes. The account is read in the
// same statement that finds the credential, so a revoked account or a changed
// role takes effect on the next request (store.ResolveSession,
// store.ResolveAPIKey). A handler that needs the deployment's configuration asks
// for it (Call.Config), and is answered 503 not_configured if it is missing.
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
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// Error codes the boundary produces. They are stable: clients and dashboards
// may match on them. A store failure while verifying a session has the code
// store.CodeSessionVerifyFailed; an id that does not parse has
// input.CodeInvalidID; a refused Access has CodeForbidden or
// CodeInsufficientScope.
const (
	// CodeUnauthenticated is the one answer to a request without a valid
	// credential.
	CodeUnauthenticated = "unauthenticated"
	// CodeNotConfigured means the deployment's configuration is missing or
	// invalid: the service is broken, not the request.
	CodeNotConfigured = "not_configured"
)

// Credential is what a route requires of the request's proof of identity.
//
// There are two answers, not one per kind of credential: an Authenticated
// route accepts whichever valid credential the request carries (a session in
// the cookie, an API key or an OAuth access token as a bearer token), and Access
// decides which kinds and which callers may use the route. Adding a kind of
// credential is local to this package: a constant in issue.go, the place the
// request is read, and the resolver of its token. No route and no feature
// changes, and a route accepts the new kind only if its Access says so when the
// kind is one an outside service holds (Access.FromGrants).
type Credential uint8

const (
	// The zero Credential is not a kind: a route that does not say which it
	// needs is refused when the handler is built, so forgetting the field
	// cannot publish a route.
	_ Credential = iota

	// None is a route open to anyone, such as the endpoints a person uses
	// before they have a session. It never reads the credential or the store.
	None

	// Authenticated is a route that needs a valid credential: a login session in the
	// __Host-session cookie, or an API key or an OAuth access token as a bearer
	// token.
	Authenticated
)

// Principal is who a verified credential speaks for. Every field comes from
// the stored rows read for the request, never from the token, which carries
// nothing.
type Principal struct {
	// UserID is the account. It is the user whose authority is being used,
	// even when an agent is acting.
	UserID string
	// Role is the account's role now, not at the credential's issue.
	Role string
	// SecretID is the id of the session, API key or access token presented: the
	// identifier it is listed and revoked by.
	SecretID string
	// Kind is the kind of credential presented (KindSession, KindAPIKey or
	// KindGrant).
	Kind string
	// ExpiresAt is when the credential stops being active.
	ExpiresAt time.Time

	// OrgID is the standard organization the account belongs to, read with the
	// account.
	OrgID string
	// AgentID is the agent acting, or "" when the user is.
	AgentID string
	// SandboxID is the sandbox the acting agent is confined to, read with the
	// agent, or "" for a user, a session and an ordinary agent. A request with
	// one is refused by every route that does not opt in with
	// Access.InSandbox, and a route that does must confine what it reads and
	// writes to this sandbox.
	SandboxID string
	// Scope is the credential's own scope list: SessionScope for a session, the
	// key row's list exactly as stored for an API key, and for a grant the authsu
	// names of its access token's scope that the login resource allows now. A
	// list that is damaged reads as empty.
	Scope scope.List
	// AgentScope is the acting agent's scope list exactly as stored, read now,
	// or empty when no agent is acting.
	//
	// Scope, AgentScope, AgentID and Role are the inputs of what the request
	// may do, and Authority is the one place they are combined: nothing reads
	// them to decide that on its own, so no second, narrower or wider rule can
	// drift from it.
	AgentScope scope.List
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
	// Media is the Content-Type an unsafe request must carry: the zero value,
	// httpapi.MediaJSON, or httpapi.MediaForm for the standard OAuth endpoints.
	// A form is a CORS-safelisted type, so it gives no CSRF defence: a route
	// that declares it must be None, so that no cookie can make a forged
	// cross-site request mean anything, and must be a method with a body. A GET
	// or HEAD reads no body and leaves it unset.
	Media httpapi.Media
	// Errors is the format of every failure of the route, the boundary's
	// included: the zero value, httpapi.ErrorsAPI, or httpapi.ErrorsOAuth for
	// the RFC 6749 format (see httpapi.OAuthError).
	Errors httpapi.ErrorFormat
	// Credential says what the caller must present. It must be set.
	Credential Credential
	// Access says what an authenticated caller must have to use the route:
	// Open() for a valid credential and nothing more, or Needs(scope) with
	// whatever else it requires. It must be declared for an Authenticated
	// route, and must be left as the zero value for a None route, which has no
	// caller to ask about.
	Access Access
	// Handle answers the request. It runs only after every check has passed,
	// with Call.Principal set for an Authenticated route.
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

	signing       config.SigningKey
	signingErr    error
	signingLoaded bool
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

// SigningKey returns the OAuth signing key, loading it on first use and
// remembering the outcome for the rest of the request. It is separate from
// Config because parsing an RSA key is expensive under wasm, so only the
// handlers that sign or publish with it pay for it. A missing or invalid key is
// 503 not_configured, with the reason only in the log, like the rest of the
// configuration.
func (c *Call) SigningKey() (config.SigningKey, error) {
	if !c.signingLoaded {
		key, err := config.LoadSigningKey(c.Getenv)

		c.signing = key
		c.signingErr = apierr.Wrap(err, apierr.Unavailable, CodeNotConfigured, "the service is not configured")
		c.signingLoaded = true
	}

	return c.signing, c.signingErr
}

// Deps are the collaborators of Handler. All are required.
type Deps struct {
	// Credentials resolves the token a request presents. *store.Store satisfies
	// it. A failure must come back classified (store does), because it is sent
	// as is.
	Credentials CredentialReader
	// Resources selects the table of resource servers for an API_ORIGIN
	// (resource.Select in production). It is a function because the
	// configuration is read per request. Only an OAuth access token's
	// resolution asks it, for the first-party login resource, the one resource
	// whose tokens authsu's own API accepts.
	Resources func(apiOrigin string) resource.Table
	// Now is the clock, used to decide whether a stored credential is still
	// active.
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
// Handle, a Credential that is not None or Authenticated (including one that
// was never set), an Access that is not declared on an Authenticated route or
// is set on a None route, a Media or Errors that does not exist, a form Media
// on a route that is Authenticated or that is a GET or HEAD, a MaxBody that is
// negative or above
// httpapi.DefaultMaxBody, the same method and path twice, a wildcard that is
// not a whole {name} segment or that appears twice in a path, and a path the
// ServeMux itself refuses. It panics, rather than returning an error, because a
// route table is fixed in code: the failure is found by the first test or the
// first start, never by a request. It does this once, at construction; a
// request never panics for these reasons.
func Handler(routes []Route, deps Deps) http.Handler {
	checkDeps(deps)

	paths := groupRoutes(routes)
	router := &router{creds: deps.Credentials, resources: deps.Resources, now: deps.Now, getenv: deps.Getenv}
	mux := http.NewServeMux()

	for _, path := range slices.Sorted(maps.Keys(paths)) {
		group := paths[path]
		byMethod := make(map[string]httpapi.MethodRoute, len(group.routes))

		for method, route := range group.routes {
			byMethod[method] = httpapi.MethodRoute{
				Handler: router.handler(route, group.wildcards), MaxBody: route.MaxBody, Media: route.Media, Errors: route.Errors,
			}
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
		"Credentials": deps.Credentials == nil, "Resources": deps.Resources == nil, "Now": deps.Now == nil,
		"Getenv": deps.Getenv == nil, "Log": deps.Log == nil,
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
	case route.Credential != None && route.Credential != Authenticated:
		return "Credential must be None or Authenticated"
	case route.MaxBody < 0 || route.MaxBody > httpapi.DefaultMaxBody:
		return "MaxBody must be from 0 to httpapi.DefaultMaxBody"
	}

	return mediaProblem(route)
}

// mediaProblem describes what is wrong with a route's Media or Errors, or
// returns "" and goes on to the route's Access. A form body is no CSRF defence,
// so a form route may not rely on a cookie; and a method with no body has no
// media type to declare.
func mediaProblem(route Route) string {
	switch {
	case route.Media != httpapi.MediaJSON && route.Media != httpapi.MediaForm:
		return "Media must be httpapi.MediaJSON or httpapi.MediaForm"
	case route.Errors != httpapi.ErrorsAPI && route.Errors != httpapi.ErrorsOAuth:
		return "Errors must be httpapi.ErrorsAPI or httpapi.ErrorsOAuth"
	case route.Media != httpapi.MediaForm:
	case route.Credential != None:
		return "a form Media is no CSRF defence, so the route must be None"
	case route.Method == http.MethodGet || route.Method == http.MethodHead:
		return "a GET or HEAD has no body, so Media does not apply"
	}

	return accessProblem(route)
}

// accessProblem describes what is wrong with a route's Access, or returns "".
// A None route has no caller to ask about, so it declares none; an
// Authenticated route must declare its access explicitly, and may name only a
// scope that exists, so a typo in a route table fails at start.
func accessProblem(route Route) string {
	switch {
	case route.Credential == None && route.Access != (Access{}):
		return "Access needs an authenticated caller, and a None route has none"
	case route.Credential == Authenticated && !route.Access.declared:
		return "Access must be declared: use auth.Open() or auth.Needs(scope)"
	case route.Access.Scope != "" && !slices.Contains(scope.Scopes(), route.Access.Scope):
		return "Access names a scope that does not exist"
	case route.Access.GrantAsUserOK && (!route.Access.GrantOK || !route.Access.NoAgents):
		return "GrantsAsUser relaxes WithoutAgents for a grant, so it needs FromGrants and WithoutAgents"
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
	creds     CredentialReader
	resources func(apiOrigin string) resource.Table
	now       func() time.Time
	getenv    func(string) string
}

// handler returns the httpapi handler for route: it authenticates, applies the
// access, parses the path id and only then calls route.Handle. The
// credential comes first, so a caller who may not use the route is refused
// before anything about the request, a malformed id included, is judged.
func (r *router) handler(route Route, wildcards []string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		call := r.newCall(req)

		call, err := r.authenticate(route.Credential, call).
			Check(func(call *Call) error { return route.access(call.Principal) }).
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
		signing: config.SigningKey{}, signingErr: nil, signingLoaded: false,
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
// it does not read the cookie, the header or the store.
func (r *router) authenticate(credential Credential, call *Call) result.Result[*Call] {
	if credential != Authenticated {
		return result.Ok(call)
	}

	return r.credential(call).
		Map(func(principal Principal) *Call {
			call.Principal = principal

			return call
		})
}

// access applies a route's Access. A None route has none.
func (route Route) access(principal Principal) error {
	if route.Credential != Authenticated {
		return nil
	}

	return route.Access.check(principal)
}
