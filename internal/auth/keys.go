package auth

import (
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"time"
	"uuid"

	"github.com/susu-dot-dev/japikey_go"

	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Kinds of key in japikeys. The schema does not constrain the column, so a new
// kind needs no migration; Go interprets it.
const (
	// KindSession is a login session, carried in a cookie.
	KindSession = store.KindSession
	// KindAPIKey is a key presented as a bearer token, by a user's software or
	// by an agent. Nothing verifies one yet: only creation exists.
	KindAPIKey = store.KindAPIKey
)

// Audience is the token's audience for a kind. Each credential is verified with
// the audience it expects, so a token created for one kind cannot be presented
// as another: the kind is in the database so it can be queried and in the
// signed token so it cannot be forged.
func Audience(kind string) string { return "authsu/" + kind }

// SessionLifetime is how long a session lasts. It is a starting value, not part
// of the design. A session is not extended or renewed: the lifetime is the
// whole of it, and it is what bounds how long a stolen cookie is good for.
const SessionLifetime = 14 * 24 * time.Hour

// CookieName is the session cookie. The __Host- prefix makes browsers refuse
// the cookie unless it is Secure, has Path=/ and has no Domain, so a sibling
// subdomain cannot set or shadow it.
const CookieName = "__Host-session"

// Issuer is what the creation and the verification of a token agree on: the
// base of the issuer URL (the token's iss is "<base>/<kid>"). It is derived
// from the API origin, the identity of this service, so there is no separate
// setting to get wrong.
type Issuer struct {
	// Base is the base issuer URL, such as "https://auth.example.com/keys".
	Base string
	// Insecure permits an http base. It is true only for a localhost origin,
	// where a developer or an e2e run has no TLS.
	Insecure bool
}

// issuerPath is appended to the origin to form the base issuer. japikey's own
// layout serves a key's JWKS at "<iss>/.well-known/jwks.json"; nothing is
// served there yet, but the issuer is shaped so it could be.
const issuerPath = "/keys"

// IssuerFor derives the Issuer from the API origin, which config.ParseOrigin
// has already validated as a bare origin (https, or http for localhost only).
// A token is only accepted by the service whose origin it was created for: the
// same key under another API origin has another issuer.
func IssuerFor(api config.Origin) Issuer {
	return Issuer{Base: api.String + issuerPath, Insecure: api.Insecure}
}

// Key is a created key, ready to store.
type Key struct {
	// ID is the kid.
	ID uuid.UUID
	// JWT is the bearer token. It is sent to the client and never stored.
	JWT string
	// JWK is the public key as the JSON document japikey defines.
	JWK string
	// ExpiresAt is the token's exp.
	ExpiresAt time.Time
	// PublicKey is the public half, for tests and callers that verify at once.
	PublicKey crypto.PublicKey
	// Scope is the scope list signed into the token, as the JSON array stored
	// on the key's row. Callers store this and never rebuild it, so the row's
	// copy is the claim by construction.
	Scope string
}

// KeySpec describes a key to create.
type KeySpec struct {
	// Kind is the kind of key, which decides the token's audience.
	Kind string
	// Subject is the token's sub: the user, always, even for an agent's key.
	Subject string
	// Expires is the token's exp.
	Expires time.Time
	// Scope is the key's scope list. It is signed into the token as the scope
	// claim, an array of strings: always present, and empty for a key that may
	// use only the routes that need no scope.
	Scope scope.List
	// Claims are extra claims to sign into the token, such as act. japikey
	// writes its own claims (sub, iss, aud, exp, iat, ver) after these, and
	// the scope claim is written after them too, so none can be overridden
	// from here.
	Claims map[string]any
}

// SessionScope is the scope list every session is created with: the
// default:session bundle, which is every scope. A session is the user acting in
// person, so it is limited only by the user's role (admin scopes need the
// administrator role whatever a token says). A session is not narrowed at
// login: a stronger step-up would be its own mechanism, not a smaller session.
func SessionScope() scope.List { return scope.List{scope.DefaultSession} }

// CreateSession creates a session key for userID that expires at expires: a
// fresh key pair, one signed JWT, and the public key as a JWK document. The
// private key is not returned and not kept. It carries SessionScope.
//
// The token carries no role. The role is read from the account on every
// request (store.ActiveKey joins it in the same primary-key read that finds the
// key), so a role change or a revoked account takes effect on the next request;
// a claim could only be stale (docs/users_design.md).
func CreateSession(issuer Issuer, userID string, expires time.Time) (Key, error) {
	return createKey(json.Marshal, issuer, KeySpec{
		Kind: KindSession, Subject: userID, Expires: expires, Scope: SessionScope(), Claims: nil,
	})
}

// CreateKey creates a key as spec describes: a fresh key pair, one signed JWT,
// and the public key as a JWK document. The private key is not returned and not
// kept.
func CreateKey(issuer Issuer, spec KeySpec) (Key, error) {
	return createKey(json.Marshal, issuer, spec)
}

// createKey is CreateKey with the JSON encoder injected, so that its failure,
// which no valid key causes, is reachable from a test.
func createKey(marshal func(any) ([]byte, error), issuer Issuer, spec KeySpec) (Key, error) {
	claims := make(map[string]any, len(spec.Claims)+1)
	maps.Copy(claims, spec.Claims)

	// The scope claim is written last, from the one list that is also returned
	// for storage, so a caller's Claims cannot override it and the row's copy
	// cannot differ from it.
	claims["scope"] = spec.Scope.Claim()

	created := result.Of(japikey.NewJAPIKey(japikey.Config{
		Subject:           spec.Subject,
		Issuer:            issuer.Base,
		Audience:          Audience(spec.Kind),
		ExpiresAt:         spec.Expires,
		Claims:            claims, // a map[string]any is assignable to jwt.MapClaims
		AllowInsecureHTTP: issuer.Insecure,
	})).
		MapErr(func(err error) error { return fmt.Errorf("create %s key: %w", spec.Kind, err) }).
		Then(func(created *japikey.JAPIKey) (Key, error) {
			return encodeKey(marshal, created, spec).Get()
		})

	return created.Get() //nolint:wrapcheck // every error in the chain is wrapped with what failed
}

// encodeKey builds the Key for a created japikey: its public key as a JWKS
// document, encoded as JSON, beside the token and the scope list that was signed
// into it.
func encodeKey(marshal func(any) ([]byte, error), created *japikey.JAPIKey, spec KeySpec) result.Result[Key] {
	return result.Of(created.ToJWKS()).
		// coverage:ignore: ToJWKS only fails for a nil key or a nil id, which NewJAPIKey never returns
		MapErr(func(err error) error { return fmt.Errorf("build JWKS: %w", err) }).
		Then(func(document *japikey.JWKS) ([]byte, error) {
			return result.Of(marshal(document)).
				MapErr(func(err error) error { return fmt.Errorf("encode JWKS: %w", err) }).
				Get()
		}).
		Map(func(jwk []byte) Key {
			return Key{
				ID:        created.KeyID,
				JWT:       created.JWT,
				JWK:       string(jwk),
				ExpiresAt: spec.Expires,
				PublicKey: created.PublicKey,
				Scope:     spec.Scope.JSON(),
			}
		})
}

// LoginGrant is the granted_from value for the session a login challenge
// produced: the SHA-256 of the challenge. The column is unique, so a replayed
// login produces the same value and collides with the session the first one
// made.
func LoginGrant(challenge []byte) []byte {
	sum := sha256.Sum256(challenge)

	return sum[:]
}

// SessionCookie builds the session cookie for key. It is HttpOnly (page script
// cannot read it), Secure (not sent over plain HTTP), Path=/ with no Domain
// (which the __Host- prefix requires, and which keeps it to this host), and
// SameSite=Lax: a session survives a user following a link to the site, and is
// withheld from cross-site subrequests and POSTs, which is also what stops
// another site from triggering a logout. The UI may be on another origin than
// this API, but it must be on the same site (susu.dev and auth.susu.dev;
// localhost on two ports), so the UI's credentialed fetches still carry the
// cookie. SameSite compares registrable domains, not origins, which is why Lax
// suffices and None is not needed.
func SessionCookie(key Key) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    key.JWT,
		Path:     "/",
		Expires:  key.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearSessionCookie expires the session cookie in the browser. It carries the
// same attributes as SessionCookie, because a browser only replaces a cookie
// that has the same name, path and domain.
func ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
