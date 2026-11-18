package auth

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/susu-dot-dev/japikey_go"
	japikeyerrors "github.com/susu-dot-dev/japikey_go/errors"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// KeyReader is the part of the store the boundary reads a token's key with.
// *store.Store satisfies it.
type KeyReader interface {
	// ActiveKey returns the key kid of the given kind with its account and, for
	// an agent's key, the agent, if it exists, has not expired, is not revoked
	// at now, and its account and agent are not revoked. It reports false when
	// there is no such key.
	ActiveKey(ctx context.Context, kid, kind string, now time.Time) (store.ActiveKey, bool, error)
}

// Why a token was refused. They are causes for the log: the client is told
// only that it is not signed in, because saying whether a key exists, was
// revoked or expired would be an oracle.
var (
	errNoCredential    = errors.New("no credential")
	errAmbiguousCookie = errors.New("more than one session cookie")
	errAmbiguousBearer = errors.New("more than one Authorization header")
	errBothCredentials = errors.New("both a session cookie and a bearer token")
	errNotBearer       = errors.New("the Authorization header is not a Bearer token")
	errNoKey           = errors.New("no active key")
	errNotOwner        = errors.New("token subject is not the key's owner")
	errWrongActor      = errors.New("token actor is not the key's agent")
	errMalformedActor  = errors.New("token act claim is not an object naming an agent")
	errStoredKey       = errors.New("stored key is not a valid public key")
)

// Unauthenticated is the one answer to a credential that is not valid: 401
// unauthenticated, "not signed in". No cookie, malformed, unknown, revoked,
// expired, wrong audience or issuer, a bad signature and a revoked account all
// get it, so a caller learns nothing about which. cause is for the log only.
//
// The boundary returns it for every verdict on a token. A feature that learns
// during the request that its caller's session is gone (a logout that lost a
// race with another revocation, say) returns it too, so the caller is told what
// any request without a session is told.
func Unauthenticated(cause error) error {
	return unauthenticated(cause)
}

// unauthenticated is Unauthenticated as the classified error itself, so the
// boundary's own steps return what they build.
func unauthenticated(cause error) *apierr.Error {
	return apierr.New(apierr.Unauthorized, CodeUnauthenticated, "not signed in").WithCause(cause)
}

// unavailable is a failure to verify that says nothing about the token: the
// store or the stored key could not be read. The store classifies its own
// failures (a classified error is returned as it is); anything else becomes
// 503 session_verify_failed.
func unavailable(cause error) error {
	return apierr.Wrap(cause, apierr.Unavailable, store.CodeSessionVerifyFailed, "sessions are temporarily unavailable")
}

// credential authenticates an Authenticated route: configuration, then the
// credential the request carries, then the token.
//
// The credential is the session cookie or the bearer token, and a request may
// carry only one. A session and an API key are different kinds of proof (a
// person was present for one), the cookie is what a browser attaches without
// being asked, and the header is what software chooses to send. A request with
// both is ambiguous, and picking one would let whoever controls the other
// decide, so it is refused, as two cookies are.
func (r *router) credential(call *Call) result.Result[Principal] {
	return result.Of(call.Config()).
		Then(func(cfg config.Config) (Principal, error) {
			return requestToken(call.Request).
				MapErr(func(cause error) error { return unauthenticated(cause) }).
				Then(func(presented presentedToken) (Principal, error) {
					return r.verify(call.Request.Context, IssuerFor(cfg.API), presented.kind, presented.token).Get()
				}).
				Get()
		})
}

// presentedToken is the one token a request carries and the kind of key it must
// be.
type presentedToken struct {
	kind  string
	token input.Token
}

// carriers is what a request holds in each of the two places a credential may
// be: the cookie and the Authorization header. A carrier that is not used is
// the zero value, and has says whether it was present at all, which an empty
// value is.
type carriers struct {
	cookie, bearer       string
	hasCookie, hasBearer bool
}

// requestToken reads the one token a request carries and says which kind of key
// it must be: KindSession for the cookie, KindAPIKey for a bearer token.
func requestToken(req httpapi.Request) result.Result[presentedToken] {
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
		Then(func(held carriers) (presentedToken, error) { return choose(held).Get() })
}

// choose picks the carrier the request used, and refuses a request that used
// both or neither.
func choose(held carriers) result.Result[presentedToken] {
	switch {
	case held.hasCookie && held.hasBearer:
		return result.Fail[presentedToken](errBothCredentials)
	case held.hasCookie:
		return parseKind(KindSession, held.cookie)
	case held.hasBearer:
		return parseKind(KindAPIKey, held.bearer)
	default:
		return result.Fail[presentedToken](errNoCredential)
	}
}

// parseKind parses raw as a token of kind. A value that is not a token (empty,
// oversized, outside the alphabet) is refused before any parsing of it.
func parseKind(kind, raw string) result.Result[presentedToken] {
	return result.Of(input.ParseToken(raw)).
		Map(func(token input.Token) presentedToken { return presentedToken{kind: kind, token: token} })
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
// value is returned as it is; ParseToken refuses anything outside the alphabet,
// including extra whitespace.
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

// verify checks token as a key of kind and returns who it speaks for.
//
// japikey checks the token itself: format, algorithm (pinned from the signed
// version), issuer equal to "<base>/<kid>", expiry, and the audience, which is
// the kind's, so a key of another kind cannot be presented as this one. The
// lookup callback adds what only the database knows: the key must exist and
// be active at now (store.ActiveKey: not revoked, not expired, account not
// revoked), and its stored JWK must be a valid public key for that kid. Then
// the signed subject must be the account the row belongs to, and the signed
// actor must be the agent the row belongs to (both absent for a key with no
// agent).
//
// japikey reads the wall clock itself for the token's own claims; now is used
// for the row.
//
// Anything japikey refuses as a token is Unauthenticated. Anything else is a
// failure of ours (the store, the stored key, a cancelled request) and says
// nothing about the token, so it is 503 and never 401: a client must not take
// an outage for a sign-out.
func (r *router) verify(ctx context.Context, issuer Issuer, kind string, token input.Token) result.Result[Principal] {
	var (
		found store.ActiveKey
		// lookupErr is why the lookup failed, if it did. japikey reduces any
		// failure of the callback to a fixed message, so the cause is kept here
		// and used in place of it: it is what the log needs.
		lookupErr error
	)

	lookup := func(ctx context.Context, kid uuid.UUID) (crypto.PublicKey, error) {
		read := r.activeKey(ctx, kid, kind)
		if read.refusal != nil {
			lookupErr = read.cause

			return nil, read.refusal
		}

		found = read.key

		return read.public, nil
	}

	return result.Of(japikey.Verify(ctx, token.String(), japikey.VerifyConfig{
		BaseIssuerURL:     issuer.Base,
		AllowInsecureHTTP: issuer.Insecure,
		Timeout:           0,
		Audience:          Audience(kind),
	}, lookup)).
		// found and lookupErr are set by lookup, which Verify has run by now.
		MapErr(func(err error) error { return verifyError(err, lookupErr) }).
		Then(func(verified *japikey.VerificationResult) (Principal, error) {
			return principalOf(verified.Claims, verified.KeyID.String(), kind, found).Get()
		})
}

// keyRead is the outcome of reading a stored key for japikey's lookup.
type keyRead struct {
	key    store.ActiveKey
	public crypto.PublicKey
	// refusal is the error japikey is to see, and nil when the key was read.
	refusal error
	// cause is why the read failed when the failure is ours (the store, the
	// stored key) and not the token's, and nil for a key that is simply not
	// active: that is a refusal and never a 503.
	cause error
}

// activeKey reads the stored key kid of kind and its public key.
func (r *router) activeKey(ctx context.Context, kid uuid.UUID, kind string) keyRead {
	key, ok, err := r.keys.ActiveKey(ctx, kid.String(), kind, r.now())
	if err != nil {
		return keyRead{refusal: fmt.Errorf("read key %s: %w", kid, err), cause: err}
	}

	if !ok {
		return keyRead{refusal: japikeyerrors.NewKeyNotFoundError(errNoKey.Error())}
	}

	public, err := parseStoredKey(key.JWK, kid)
	if err != nil {
		return keyRead{refusal: err, cause: err}
	}

	return keyRead{key: key, public: public}
}

// principalOf binds a verified token's claims to the row that was read for it,
// and says who the key speaks for.
//
// The signed subject must be the account the row belongs to, and the signed
// actor must be the agent the row belongs to (both absent for a key with no
// agent): a token with an actor and a row with none, or the reverse, or another
// agent, is not the key the row describes. The role, the account and the
// agent's scopes are the row's, read now. Only the key's own scope is the
// token's, because it cannot change while the token is valid.
func principalOf(claims map[string]any, keyID, kind string, found store.ActiveKey) result.Result[Principal] {
	return result.Ok(claims).
		Check(func(claims map[string]any) error { return ownedBy(claims, found) }).
		Then(func(claims map[string]any) (map[string]any, error) { return actedBy(claims, found).Get() }).
		Map(func(claims map[string]any) Principal {
			keyScope := scope.FromClaim(claims["scope"])
			agentScope := scope.Read(found.AgentScopes)

			return Principal{
				UserID:       found.UserID,
				Role:         found.Role,
				KeyID:        keyID,
				CredentialID: found.CredentialID,
				Kind:         kind,
				ExpiresAt:    found.ExpiresAt,
				AgentID:      found.AgentID,
				KeyScope:     keyScope,
				AgentScope:   agentScope,
				Effective:    effective(keyScope, agentScope, found.AgentID != ""),
			}
		})
}

// ownedBy checks that the token's signed subject is the account the row
// belongs to.
func ownedBy(claims map[string]any, found store.ActiveKey) error {
	subject, _ := claims["sub"].(string)
	if subject != found.UserID {
		return unauthenticated(errNotOwner)
	}

	return nil
}

// actedBy checks that the token's signed actor is the agent the row belongs to,
// and that the claim is well formed.
func actedBy(claims map[string]any, found store.ActiveKey) result.Result[map[string]any] {
	return result.Of(actor(claims)).
		MapErr(func(cause error) error { return unauthenticated(cause) }).
		Check(func(agent string) error { return sameAgent(agent, found) }).
		Map(func(string) map[string]any { return claims })
}

// sameAgent checks that the agent a token names is the one the row belongs to.
func sameAgent(agent string, found store.ActiveKey) error {
	if agent != found.AgentID {
		return unauthenticated(errWrongActor)
	}

	return nil
}

// actor returns the agent the token's act claim names, or "" when the claim is
// absent. A claim that is present but is not the {"sub": "<agent id>"} object an
// agent's key carries (another type, null, no sub, an empty sub) is an error,
// whatever the row holds: this service writes the claim in one shape only, so
// any other is not a token it issued and is refused, and is never read as "no
// actor" and let through for a key that has no agent.
func actor(claims map[string]any) (string, error) {
	act, present := claims["act"]
	if !present {
		return "", nil
	}

	object, ok := act.(map[string]any)
	if !ok {
		return "", errMalformedActor
	}

	sub, ok := object["sub"].(string)
	if !ok || sub == "" {
		return "", errMalformedActor
	}

	return sub, nil
}

// effective is what a request may do: the key's scopes, narrowed by the
// agent's when an agent is acting. Each layer can only narrow the one above it,
// so this is an intersection and never a union, and the user's role is not in
// it (Access checks the role for admin scopes).
func effective(key, agent scope.List, agentActing bool) scope.Set {
	keyScopes := key.Expand()
	if !agentActing {
		return keyScopes
	}

	return keyScopes.Intersect(agent.Expand())
}

// verifyError classifies a failed japikey.Verify. lookupErr is the lookup
// callback's own error when it failed, which japikey's wrapping would hide.
func verifyError(err, lookupErr error) error {
	if lookupErr != nil {
		return unavailable(lookupErr)
	}

	if _, refused := errors.AsType[*japikey.UnauthorizedError](err); refused {
		return unauthenticated(err)
	}

	return unavailable(err)
}

// parseStoredKey reads the public key out of the stored JWK document. The
// document is the {"keys":[...]} form japikey writes; japikey's parser is
// strict about its members, and the key id in it must be the row's. Any failure
// is the stored row being wrong, which the caller reports as the store being
// unavailable: it says nothing about the token.
func parseStoredKey(document []byte, kid uuid.UUID) (crypto.PublicKey, error) {
	var parsed japikey.JWKS

	err := json.Unmarshal(document, &parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStoredKey, err)
	}

	key, err := parsed.GetPublicKey(kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStoredKey, err)
	}

	return key, nil
}
