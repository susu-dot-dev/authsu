package auth

import (
	"context"
	"errors"
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
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// CredentialReader is the part of the store the boundary resolves a presented
// token with. *store.Store satisfies it. Each method reads the secret, the row
// of its kind, the account and, for an agent's key, the agent in one statement,
// and reports false unless every part is active at now. A failure must come
// back classified (the store does), because it is sent as it is.
type CredentialReader interface {
	// ResolveSession returns the session the token names, with its account.
	ResolveSession(ctx context.Context, token input.SessionToken, now time.Time) (store.ActiveSession, bool, error)
	// ResolveAPIKey returns the API key the token names, with its account and,
	// when it belongs to one, its agent.
	ResolveAPIKey(ctx context.Context, token input.APIKeyToken, now time.Time) (store.ActiveAPIKey, bool, error)
	// ResolveGrant returns the OAuth access token the token names, if it is
	// active for exactly the login resource, with its account and its agent.
	ResolveGrant(
		ctx context.Context, token input.AccessToken, loginResource input.ResourceID, now time.Time,
	) (store.ActiveGrant, bool, error)
}

// Why a request was refused. They are causes for the log: the client is told
// only that it is not signed in, because saying whether a credential exists,
// was revoked or expired would be an oracle.
var (
	errNoCredential    = errors.New("no credential")
	errAmbiguousCookie = errors.New("more than one session cookie")
	errAmbiguousBearer = errors.New("more than one Authorization header")
	errBothCredentials = errors.New("both a session cookie and a bearer token")
	errNotBearer       = errors.New("the Authorization header is not a Bearer token")
	errNotActive       = errors.New("no active credential")
	errNoLoginResource = errors.New("the deployment has no first-party login resource")
)

// Unauthenticated is the one answer to a credential that is not valid: 401
// unauthenticated, "not signed in". No credential, a malformed or wrong-kind
// token, an unknown, expired or revoked one and a revoked account all get it,
// so a caller learns nothing about which. cause is for the log only.
//
// The boundary returns it for every verdict on a credential. A feature that
// learns during the request that its caller's session is gone (a logout that
// lost a race with another revocation, say) returns it too, so the caller is
// told what any request without a session is told.
func Unauthenticated(cause error) error {
	return unauthenticated(cause)
}

// unauthenticated is Unauthenticated as the classified error itself, so the
// boundary's own steps return what they build.
func unauthenticated(cause error) *apierr.Error {
	return apierr.New(apierr.Unauthorized, CodeUnauthenticated, "not signed in").WithCause(cause)
}

// unavailable is a failure to resolve that says nothing about the token: the
// store could not be read. The store classifies its own failures (a classified
// error is returned as it is); anything else becomes 503
// session_verify_failed.
func unavailable(cause error) error {
	return apierr.Wrap(cause, apierr.Unavailable, store.CodeSessionVerifyFailed, "sessions are temporarily unavailable")
}

// credential authenticates an Authenticated route: it reads the one credential
// the request carries, parses it as the kind its carrier and its tag say, and
// resolves it in the store.
//
// The credential is the session cookie or the bearer token, and a request may
// carry only one. A session and a bearer token are different kinds of proof (a
// person was present for one), the cookie is what a browser attaches without
// being asked, and the header is what software chooses to send. A request with
// both is ambiguous, and picking one would let whoever controls the other
// decide, so it is refused, as two cookies are.
//
// The cookie accepts exactly one kind, a session token. The header accepts two,
// told apart by the token's own tag (secret.TagAPIKey, "susu_key_", or
// secret.TagOAuthAccess, "susu_at_"), which names the kind and which no other
// kind shares: an API key, and an OAuth grant's access token. Anything else in
// the header (a session, a refresh token, a code, an invitation, garbage) is
// refused by the parser of the API key, as it always was, before the store is
// read. A token that is neither is therefore one refusal, and a token of one
// kind is never resolved as the other. The tag is compared as written, so a
// prefix in another case is neither.
//
// A session or a key needs nothing of the deployment's configuration: a token
// carries nothing to check, so resolving it is a read of the store and the
// clock. A grant also needs to know which resource it must be for, the
// deployment's first-party login resource, which comes from API_ORIGIN
// (resource.Select), so only a request that presents an access token reads it.
func (r *router) credential(call *Call) result.Result[Principal] {
	return requestToken(call.Request).
		MapErr(func(cause error) error { return unauthenticated(cause) }).
		Then(func(resolve resolver) (Principal, error) {
			return resolve(call, r).Get()
		})
}

// resolver resolves one parsed token in the store, and says who it speaks for.
// It closes over the token, so the carrier and the tag that read it decide which
// kind it is resolved as. It is given the call, for the request's context and
// environment, and the router, for the store, the clock and the resource table.
type resolver func(call *Call, r *router) result.Result[Principal]

// carriers is what a request holds in each of the two places a credential may
// be: the cookie and the Authorization header. A carrier that is not used is
// the zero value, and has says whether it was present at all, which an empty
// value is.
type carriers struct {
	cookie, bearer       string
	hasCookie, hasBearer bool
}

// requestToken reads the one token a request carries and returns how to
// resolve it: as a session for the cookie, as an API key or an OAuth access
// token, by its tag, for a bearer token.
func requestToken(req httpapi.Request) result.Result[resolver] {
	return cookieValue(req.Cookies).
		Map(func(c cookie) carriers { return carriers{cookie: c.value, hasCookie: c.present} }).
		Then(func(held carriers) (carriers, error) {
			return bearerValue(req.Authorization).
				Map(func(b bearerHeader) carriers {
					held.bearer, held.hasBearer = b.value, b.present

					return held
				}).
				Get()
		}).
		Then(func(held carriers) (resolver, error) { return choose(held).Get() })
}

// choose picks the carrier the request used, and refuses a request that used
// both or neither.
func choose(held carriers) result.Result[resolver] {
	switch {
	case held.hasCookie && held.hasBearer:
		return result.Fail[resolver](errBothCredentials)
	case held.hasCookie:
		return result.Of(input.ParseSessionToken(held.cookie)).Map(resolveSession)
	case held.hasBearer:
		return chooseBearer(held.bearer)
	default:
		return result.Fail[resolver](errNoCredential)
	}
}

// chooseBearer picks the kind of the bearer token by its tag: an access token
// when it starts with the whole prefix of one, an API key otherwise. The key's
// parser is the fallback, so every other value (a session token, a refresh
// token, garbage) is refused by it with the code it always had. The two
// prefixes are distinct and neither is a prefix of the other, so the choice is
// unambiguous, and each parser still checks the whole shape.
func chooseBearer(value string) result.Result[resolver] {
	if strings.HasPrefix(value, secret.Prefix(secret.TagOAuthAccess)) {
		return result.Of(input.ParseAccessToken(value)).Map(resolveGrant)
	}

	return result.Of(input.ParseAPIKeyToken(value)).Map(resolveAPIKey)
}

// cookieValue returns the value of the session cookie. The request must carry
// at most one cookie of that name: several are refused rather than picking one.
// A client (or a sibling subdomain, or a proxy) that sends two has made the
// request ambiguous, and choosing the first or the last would let whoever
// controls the other one decide which session is meant. The __Host- prefix
// makes browsers refuse a duplicate set from a sibling subdomain, so a
// legitimate browser sends one. Counting includes an empty value, so an empty
// cookie beside a good one is ambiguous too.
func cookieValue(cookies []*http.Cookie) result.Result[cookie] {
	var found cookie

	count := 0

	for _, candidate := range cookies {
		if candidate.Name == CookieName {
			found.value = candidate.Value
			count++
		}
	}

	if count > 1 {
		return result.Fail[cookie](errAmbiguousCookie)
	}

	found.present = count == 1

	return result.Ok(found)
}

// cookie is what a request holds in the session cookie: its value, and whether
// the cookie was there at all, which an empty value is.
type cookie struct {
	value   string
	present bool
}

// bearerScheme is the Authorization scheme of an API key. The scheme name is
// case-insensitive (RFC 9110), and exactly one space separates it from the
// token.
const bearerScheme = "bearer "

// bearerValue returns the token of the Authorization header. At most one header
// may be present, and when it is it must be a Bearer token: another scheme
// (Basic, say) is refused and not ignored, so a client that sent a credential
// is told it was not understood and is never treated as having sent none. The
// value is returned as it is; the token parser refuses anything outside the
// alphabet, including extra whitespace.
func bearerValue(values []string) result.Result[bearerHeader] {
	switch len(values) {
	case 0:
		return result.Ok(bearerHeader{})
	case 1:
		scheme := len(bearerScheme)
		if len(values[0]) < scheme || !strings.EqualFold(values[0][:scheme], bearerScheme) {
			return result.Fail[bearerHeader](errNotBearer)
		}

		return result.Ok(bearerHeader{value: values[0][scheme:], present: true})
	default:
		return result.Fail[bearerHeader](errAmbiguousBearer)
	}
}

// bearerHeader is what a request holds in the Authorization header: the token
// after the scheme, and whether the header was there at all.
type bearerHeader struct {
	value   string
	present bool
}

// resolveSession resolves token as a session.
func resolveSession(token input.SessionToken) resolver {
	return func(call *Call, r *router) result.Result[Principal] {
		active, found, err := r.creds.ResolveSession(call.Request.Context, token, r.now())

		return resolved(sessionPrincipal(active), found, err)
	}
}

// resolveAPIKey resolves token as an API key.
func resolveAPIKey(token input.APIKeyToken) resolver {
	return func(call *Call, r *router) result.Result[Principal] {
		active, found, err := r.creds.ResolveAPIKey(call.Request.Context, token, r.now())

		return resolved(keyPrincipal(active), found, err)
	}
}

// resolveGrant resolves token as an OAuth grant's access token at authsu's own
// API. The deployment's login resource is read first, from API_ORIGIN: it is the
// only resource whose tokens are good here, and its scopes are the allowlist the
// principal is narrowed by at this request. A deployment whose API_ORIGIN does
// not parse is the production table, as everywhere (resource.Select), so a
// mistake only selects the stricter one; a table with no login resource
// resolves nothing, and is a refusal like any inactive token.
func resolveGrant(token input.AccessToken) resolver {
	return func(call *Call, r *router) result.Result[Principal] {
		return login(r.resources(call.Getenv(config.VarAPIOrigin))).
			Then(func(target loginTarget) (Principal, error) {
				active, found, err := r.creds.ResolveGrant(call.Request.Context, token, target.id, r.now())

				return resolved(grantPrincipal(active, target.entry), found, err).Get()
			})
	}
}

// loginTarget is the first-party login resource of a table, as the entry whose
// scopes are the allowlist and as the parsed id the store is asked for.
type loginTarget struct {
	entry resource.Entry
	id    input.ResourceID
}

// login finds the first-party login resource of table and parses its URL as a
// resource id. A table has none only when it is empty, which is a refusal like
// any credential that is not active.
func login(table resource.Table) result.Result[loginTarget] {
	entry, found := table.Login()
	if !found {
		return result.Fail[loginTarget](unauthenticated(errNoLoginResource))
	}

	id, err := input.ParseResourceID(entry.URL, table)
	// coverage:ignore: an entry's own URL is exactly the URL Lookup finds it by
	if err != nil {
		return result.Fail[loginTarget](unauthenticated(err))
	}

	return result.Ok(loginTarget{entry: entry, id: id})
}

// resolved is the outcome of a read of a credential. A failure of the store is
// 503, and never a 401: a client must not take an outage for a sign-out. A
// credential that is not there (unknown, wrong kind in the store, expired,
// revoked, or its account or agent revoked, which the store reports alike) is
// unauthenticated.
func resolved(who Principal, found bool, err error) result.Result[Principal] {
	switch {
	case err != nil:
		return result.Fail[Principal](unavailable(err))
	case !found:
		return result.Fail[Principal](unauthenticated(errNotActive))
	default:
		return result.Ok(who)
	}
}

// sessionPrincipal is who a session speaks for. Its scopes are the constant
// SessionScope, not stored: a session is the user acting in person, limited
// only by the role. Everything else is the row's, read now.
func sessionPrincipal(active store.ActiveSession) Principal {
	granted := SessionScope()

	return Principal{
		UserID:     active.UserID,
		Role:       active.Role,
		SecretID:   active.ID,
		Kind:       KindSession,
		ExpiresAt:  active.ExpiresAt,
		OrgID:      active.OrgID,
		AgentID:    "",
		SandboxID:  "",
		Scope:      granted,
		AgentScope: scope.List{},
	}
}

// keyPrincipal is who an API key speaks for. The key's scope list is the one
// stored with it, and the agent's is the agent's row read now; a stored list
// that is damaged reads as empty and grants nothing (scope.Read).
func keyPrincipal(active store.ActiveAPIKey) Principal {
	keyScope := scope.Read(active.Scope)
	agentScope := scope.Read(active.AgentScopes)

	return Principal{
		UserID:     active.UserID,
		Role:       active.Role,
		SecretID:   active.ID,
		Kind:       KindAPIKey,
		ExpiresAt:  active.ExpiresAt,
		OrgID:      active.OrgID,
		AgentID:    active.AgentID,
		SandboxID:  active.SandboxID,
		Scope:      keyScope,
		AgentScope: agentScope,
	}
}

// grantPrincipal is who an OAuth grant's access token speaks for at authsu's own
// API. The token is treated exactly as an API key is, so nothing about it is
// special in what a request may do (Authority): its own list is the access
// token's scope, and the agent's list narrows it, both as read now.
//
// The token's scope is the OAuth scope, space-delimited: the scopes of the login
// resource that were asked for, which may be narrower than the grant's after a
// refresh. Only the names that are authsu's own scopes at this request are the
// credential's list (grantScope): openid and profile are the OAuth flow's and
// are dropped, and a name no longer in the login resource's allowlist is dropped
// too, so removing a scope from the allowlist cuts the live grants that hold it
// on their next request. What is kept is exactly the names, in order, never
// expanded: a bundle is not a name the allowlist can hold (resource.Entry), so
// none is ever the list's.
func grantPrincipal(active store.ActiveGrant, login resource.Entry) Principal {
	return Principal{
		UserID:     active.UserID,
		Role:       active.Role,
		SecretID:   active.ID,
		Kind:       KindGrant,
		ExpiresAt:  active.ExpiresAt,
		OrgID:      active.OrgID,
		AgentID:    active.AgentID,
		SandboxID:  active.SandboxID,
		Scope:      grantScope(active.Scope, login),
		AgentScope: scope.Read(active.AgentScopes),
	}
}

// grantScope is the credential list of an access token's stored scope text: the
// names of it that are in the login resource's authsu scopes, in the order
// written, each once. Everything else is dropped: openid and profile, which are
// not authsu's; a name that is not in the allowlist, whether it never was or was
// removed since; a bundle, which is never in it; a repeat; and the empty names
// that a doubled, leading or trailing space splits into.
//
// The text is cut on the single space only, and a name is kept only if it is
// exactly an entry of the allowlist: it is not trimmed or case-folded, and a tab,
// a newline, a NUL or a non-breaking space is no separator, so "agent:read\tfoo"
// is one name that matches nothing. That is not the parser's rule
// (input.OAuthScopes.Names refuses a doubled space and every other separator, and
// is what writes the text), and this is the more lenient reading of a value the
// parser could never have written; it errs only towards dropping a name, never
// towards keeping one the allowlist does not hold, so a damaged value fails
// closed and can only narrow. TestGrantPrincipal pins each of those outcomes.
func grantScope(stored string, login resource.Entry) scope.List {
	allowed := login.AuthsuScopes()
	kept := scope.List{}

	for name := range strings.SplitSeq(stored, " ") {
		if slices.Contains(allowed, name) && !slices.Contains(kept, name) {
			kept = append(kept, name)
		}
	}

	return kept
}
