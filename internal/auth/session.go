package auth

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
	"uuid"

	"github.com/susu-dot-dev/japikey_go"
	japikeyerrors "github.com/susu-dot-dev/japikey_go/errors"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// KeyReader is the part of the store the boundary reads a token's key with.
// *store.Store satisfies it.
type KeyReader interface {
	// ActiveKey returns the key kid of the given kind with its account, if it
	// exists, has not expired, is not revoked at now, and its account is not
	// revoked. It reports false when there is no such key.
	ActiveKey(ctx context.Context, kid, kind string, now time.Time) (store.ActiveKey, bool, error)
}

// Why a token was refused. They are causes for the log: the client is told
// only that it is not signed in, because saying whether a key exists, was
// revoked or expired would be an oracle.
var (
	errNoCookie        = errors.New("no session cookie")
	errAmbiguousCookie = errors.New("more than one session cookie")
	errNoKey           = errors.New("no active key")
	errNotOwner        = errors.New("token subject is not the key's owner")
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

// session authenticates a Session route: configuration, then the cookie, then
// the token.
func (r *router) session(call *Call) (Principal, error) {
	cfg, err := call.Config()
	if err != nil {
		return Principal{}, err
	}

	token, err := sessionToken(call.Request.Cookies)
	if err != nil {
		return Principal{}, unauthenticated(err)
	}

	return r.verify(call.Request.Context, IssuerFor(cfg.API), KindSession, token)
}

// sessionToken returns the token in the session cookie. The request must carry
// exactly one cookie of that name: none is a request without a session, and
// several are refused rather than picking one. A client (or a sibling
// subdomain, or a proxy) that sends two has made the request ambiguous, and
// choosing the first or the last would let whoever controls the other one
// decide which session is meant. The __Host- prefix makes browsers refuse a
// duplicate set from a sibling subdomain, so a legitimate browser sends one.
// Counting includes an empty value, so an empty cookie beside a good one is
// ambiguous too.
//
// A value that is not a token (empty, oversized, outside the alphabet) is
// refused before any parsing of it.
func sessionToken(cookies []*http.Cookie) (input.Token, error) {
	var (
		value string
		count int
	)

	for _, cookie := range cookies {
		if cookie.Name == CookieName {
			value = cookie.Value
			count++
		}
	}

	switch count {
	case 0:
		return input.Token{}, errNoCookie
	case 1:
		return input.ParseToken(value) //nolint:wrapcheck // only a cause for the log
	default:
		return input.Token{}, errAmbiguousCookie
	}
}

// verify checks token as a key of kind and returns who it speaks for.
//
// japikey checks the token itself: format, algorithm (pinned from the signed
// version), issuer equal to "<base>/<kid>", expiry, and the audience, which is
// the kind's, so a key of another kind cannot be presented as this one. The
// lookup callback adds what only the database knows: the key must exist and
// be active at now (store.ActiveKey: not revoked, not expired, account not
// revoked), and its stored JWK must be a valid public key for that kid. Then
// the signed subject must be the account the row belongs to.
//
// japikey reads the wall clock itself for the token's own claims; now is used
// for the row.
//
// Anything japikey refuses as a token is Unauthenticated. Anything else is a
// failure of ours (the store, the stored key, a cancelled request) and says
// nothing about the token, so it is 503 and never 401: a client must not take
// an outage for a sign-out.
func (r *router) verify(ctx context.Context, issuer Issuer, kind string, token input.Token) (Principal, error) {
	var (
		found store.ActiveKey
		// lookupErr is why the lookup failed, if it did. japikey reduces any
		// failure of the callback to a fixed message, so the cause is kept here
		// and used in place of it: it is what the log needs.
		lookupErr error
	)

	lookup := func(ctx context.Context, kid uuid.UUID) (crypto.PublicKey, error) {
		key, ok, err := r.keys.ActiveKey(ctx, kid.String(), kind, r.now())
		if err != nil {
			lookupErr = err

			return nil, fmt.Errorf("read key %s: %w", kid, err)
		}

		if !ok {
			return nil, japikeyerrors.NewKeyNotFoundError(errNoKey.Error())
		}

		public, err := parseStoredKey(key.JWK, kid)
		if err != nil {
			lookupErr = err

			return nil, err
		}

		found = key

		return public, nil
	}

	verified, err := japikey.Verify(ctx, token.String(), japikey.VerifyConfig{
		BaseIssuerURL:     issuer.Base,
		AllowInsecureHTTP: issuer.Insecure,
		Timeout:           0,
		Audience:          Audience(kind),
	}, lookup)
	if err != nil {
		return Principal{}, verifyError(err, lookupErr)
	}

	// The signed subject must be the account the row belongs to.
	subject, _ := verified.Claims["sub"].(string)
	if subject != found.UserID {
		return Principal{}, unauthenticated(errNotOwner)
	}

	return Principal{
		UserID:       found.UserID,
		Role:         found.Role,
		KeyID:        verified.KeyID.String(),
		CredentialID: found.CredentialID,
		Kind:         kind,
		ExpiresAt:    found.ExpiresAt,
	}, nil
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
