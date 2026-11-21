package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
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
// the request carries, parses it as the kind its carrier accepts, and resolves
// it in the store.
//
// The credential is the session cookie or the bearer token, and a request may
// carry only one. A session and an API key are different kinds of proof (a
// person was present for one), the cookie is what a browser attaches without
// being asked, and the header is what software chooses to send. A request with
// both is ambiguous, and picking one would let whoever controls the other
// decide, so it is refused, as two cookies are.
//
// Each carrier accepts exactly one kind: the cookie only a session token, the
// header only an API key. The parser refuses a token of the other kind, or
// anything that is not a token, before the store is read, so a wrong-kind token
// costs no lookup. Nothing here needs the deployment's configuration: a token
// carries nothing to check, so resolving it is a read of the store and the
// clock.
func (r *router) credential(call *Call) result.Result[Principal] {
	return requestToken(call.Request).
		MapErr(func(cause error) error { return unauthenticated(cause) }).
		Then(func(resolve resolver) (Principal, error) {
			return resolve(call.Request.Context, r.creds, r.now()).Get()
		})
}

// resolver resolves one parsed token in the store at a time, and says who it
// speaks for. It closes over the token, so the carrier that read it decides
// which kind it is resolved as.
type resolver func(ctx context.Context, creds CredentialReader, now time.Time) result.Result[Principal]

// carriers is what a request holds in each of the two places a credential may
// be: the cookie and the Authorization header. A carrier that is not used is
// the zero value, and has says whether it was present at all, which an empty
// value is.
type carriers struct {
	cookie, bearer       string
	hasCookie, hasBearer bool
}

// requestToken reads the one token a request carries and returns how to
// resolve it: as a session for the cookie, as an API key for a bearer token.
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
		return result.Of(input.ParseAPIKeyToken(held.bearer)).Map(resolveAPIKey)
	default:
		return result.Fail[resolver](errNoCredential)
	}
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
	return func(ctx context.Context, creds CredentialReader, now time.Time) result.Result[Principal] {
		active, found, err := creds.ResolveSession(ctx, token, now)

		return resolved(sessionPrincipal(active), found, err)
	}
}

// resolveAPIKey resolves token as an API key.
func resolveAPIKey(token input.APIKeyToken) resolver {
	return func(ctx context.Context, creds CredentialReader, now time.Time) result.Result[Principal] {
		active, found, err := creds.ResolveAPIKey(ctx, token, now)

		return resolved(keyPrincipal(active), found, err)
	}
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
		Effective:  granted.Expand(),
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
		Effective:  effective(keyScope, agentScope, active.AgentID != ""),
	}
}

// effective is what a request may do: the credential's scopes, narrowed by the
// agent's when an agent is acting. Each layer can only narrow the one above it,
// so this is an intersection and never a union, and the user's role is not in
// it (Access checks the role for admin scopes).
func effective(credential, agent scope.List, agentActing bool) scope.Set {
	granted := credential.Expand()
	if !agentActing {
		return granted
	}

	return granted.Intersect(agent.Expand())
}
