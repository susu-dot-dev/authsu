// Package session verifies and ends the sessions described in
// docs/login_design.md, and mints the keys they are made of.
//
// A session is a japikey: a fresh ES256 key pair whose private half was
// discarded right after it signed one JWT. The JWT travels in an HttpOnly,
// Secure cookie; the public half is a row in japikeys. Verifying a request is
// one primary-key read plus the signature check.
//
// A session lasts a fixed time and is never extended: when it ends the user
// signs in with their passkey again. Login (internal/login) is the only thing
// that issues one, in the same atomic write that consumes its challenge.
package session

import (
	"context"
	"crypto"
	"crypto/sha256"
	"time"
	"uuid"
)

// Kinds of key in japikeys. The schema does not constrain the column, so a new
// kind needs no migration; Go interprets it.
const (
	// KindSession is a login session, carried in a cookie.
	KindSession = "session"
	// KindAPIKey is a key presented as a bearer token, by a user's software or
	// by an agent. Nothing verifies one yet: only minting exists.
	KindAPIKey = "api_key"
)

// Audience is the token's audience for a kind. Each route verifies with the
// audience it expects, so a token minted for one kind cannot be presented as
// another: the kind is in the database so it can be queried and in the signed
// token so it cannot be forged.
func Audience(kind string) string { return "authsu/" + kind }

// Lifetime is how long a session lasts. It is a starting value, not part of the
// design. A session is not extended or renewed: the lifetime is the whole of it,
// and it is what bounds how long a stolen cookie is good for.
const Lifetime = 14 * 24 * time.Hour

// CookieName is the session cookie. The __Host- prefix makes browsers refuse
// the cookie unless it is Secure, has Path=/ and has no Domain, so a sibling
// subdomain cannot set or shadow it.
const CookieName = "__Host-session"

// Key is a minted session key, ready to store.
type Key struct {
	// ID is the kid.
	ID uuid.UUID
	// JWT is the bearer token. It is sent to the client and never stored.
	JWT string
	// JWK is the public key as the JSON document japikey defines.
	JWK []byte
	// ExpiresAt is the token's exp.
	ExpiresAt time.Time
	// PublicKey is the public half, for tests and callers that verify at once.
	PublicKey crypto.PublicKey
}

// LoginGrant is the granted_from value for the session a login challenge
// produced: the SHA-256 of the challenge. The column is unique, so a replayed
// login produces the same value and collides with the session the first one
// made.
func LoginGrant(challenge []byte) []byte {
	sum := sha256.Sum256(challenge)

	return sum[:]
}

// Principal is who a verified session token speaks for.
type Principal struct {
	// UserID is the account.
	UserID string
	// KeyID is the kid of the token presented.
	KeyID string
	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
	// CredentialID is the passkey the session was issued for.
	CredentialID string
	// Role is the account's role.
	Role string
}

// Reader is the read side of the key store.
type Reader interface {
	// ActiveKey returns the public JWK of a session key and who it belongs to,
	// if the key exists, has not expired and is not revoked at now.
	ActiveKey(ctx context.Context, kid string, now time.Time) (ActiveKey, bool, error)
}

// ActiveKey is a stored key that is currently usable.
type ActiveKey struct {
	// JWK is the stored public key document.
	JWK []byte
	// UserID is the account.
	UserID string
	// CredentialID is the passkey the session was issued for.
	CredentialID string
	// Role is the account's role.
	Role string
	// ExpiresAt is the stored copy of exp.
	ExpiresAt time.Time
}
