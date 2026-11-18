package session

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/susu-dot-dev/japikey_go"

	"github.com/susu-dot-dev/authsu/internal/deploy"
)

// Issuer is what the minting and verifying of a token agree on: the base of
// the issuer URL (the token's iss is "<base>/<kid>"). It is derived from the
// API origin, the identity of this service, so there is no separate setting to
// get wrong.
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

// IssuerFor derives the Issuer from the API origin, which deploy.ParseOrigin
// has already validated as a bare origin (https, or http for localhost only).
func IssuerFor(api deploy.Origin) Issuer {
	return Issuer{Base: api.String + issuerPath, Insecure: api.Insecure}
}

// Mint creates a session key for userID that expires at expires: a fresh key
// pair, one signed JWT, and the public key as a JWK document. The private key is
// not returned and not kept.
func Mint(issuer Issuer, userID string, expires time.Time) (Key, error) {
	return mintWith(json.Marshal, issuer, Spec{
		Kind: KindSession, Subject: userID, Expires: expires, Claims: nil,
	})
}

// Spec describes a key to mint.
type Spec struct {
	// Kind is the kind of key, which decides the token's audience.
	Kind string
	// Subject is the token's sub: the user, always, even for an agent's key.
	Subject string
	// Expires is the token's exp.
	Expires time.Time
	// Claims are extra claims to sign into the token, such as act and scope.
	// japikey writes its own claims (sub, iss, aud, exp, iat, ver) after
	// these, so none of them can be overridden from here.
	Claims map[string]any
}

// MintKey creates a key as Spec describes: a fresh key pair, one signed JWT, and
// the public key as a JWK document. The private key is not returned and not kept.
func MintKey(issuer Issuer, spec Spec) (Key, error) {
	return mintWith(json.Marshal, issuer, spec)
}

// mintWith is MintKey with the JSON encoder injected, so that its failure, which
// no valid key causes, is reachable from a test.
func mintWith(marshal func(any) ([]byte, error), issuer Issuer, spec Spec) (Key, error) {
	minted, err := japikey.NewJAPIKey(japikey.Config{
		Subject:           spec.Subject,
		Issuer:            issuer.Base,
		Audience:          Audience(spec.Kind),
		ExpiresAt:         spec.Expires,
		Claims:            spec.Claims, // a map[string]any is assignable to jwt.MapClaims
		AllowInsecureHTTP: issuer.Insecure,
	})
	if err != nil {
		return Key{}, fmt.Errorf("mint %s key: %w", spec.Kind, err)
	}

	document, err := minted.ToJWKS()
	// coverage:ignore: ToJWKS only fails for a nil key or a nil id, which NewJAPIKey never returns
	if err != nil {
		return Key{}, fmt.Errorf("build JWKS: %w", err)
	}

	jwk, err := marshal(document)
	if err != nil {
		return Key{}, fmt.Errorf("encode JWKS: %w", err)
	}

	return Key{
		ID:        minted.KeyID,
		JWT:       minted.JWT,
		JWK:       jwk,
		ExpiresAt: spec.Expires,
		PublicKey: minted.PublicKey,
	}, nil
}
