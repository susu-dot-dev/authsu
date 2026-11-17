package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/susu-dot-dev/japikey_go"
)

// Issuer is what the minting and verifying of a token agree on: the base of
// the issuer URL (the token's iss is "<base>/<kid>"). It is derived from the
// configured origin, so there is no separate setting to get wrong.
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

var errBadOrigin = errors.New("origin is not an http(s) origin")

// IssuerFor derives the Issuer from the relying party origin. The origin must be
// a bare origin: a scheme and a host, with an optional numeric port and nothing
// else (no user info, path, query or fragment). https is accepted for any host;
// plain http only for the host "localhost", so a session cookie is never put on
// a network by a configuration mistake. The host is compared whole: a prefix
// test would accept "localhost.example.com".
func IssuerFor(origin string) (Issuer, error) {
	parsed, err := url.Parse(origin)
	if err != nil || !bareOrigin(parsed) || parsed.String() != origin {
		return Issuer{}, fmt.Errorf("%w: %q", errBadOrigin, origin)
	}

	insecure := parsed.Scheme == "http" && parsed.Hostname() == "localhost"
	if parsed.Scheme != "https" && !insecure {
		return Issuer{}, fmt.Errorf("%w: %q", errBadOrigin, origin)
	}

	return Issuer{Base: origin + issuerPath, Insecure: insecure}, nil
}

// bareOrigin reports whether u is a scheme, a host and an optional port, with
// nothing after the authority.
func bareOrigin(u *url.URL) bool {
	return u.Hostname() != "" && u.User == nil && noTrailer(u) && validPort(u)
}

// noTrailer reports whether u has nothing after its authority: no path, query
// (even an empty one) or fragment, and is not an opaque URL.
func noTrailer(u *url.URL) bool {
	return u.Opaque == "" && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// validPort reports whether u has no port or a numeric one. url.Parse accepts
// "host:" with an empty port and Port() reports "" for it as for no port, so the
// colon is checked on the host itself.
func validPort(u *url.URL) bool {
	if strings.HasSuffix(u.Host, ":") {
		return false
	}

	return strings.Trim(u.Port(), "0123456789") == ""
}

// Mint creates a session key for userID that expires at expires: a fresh key
// pair, one signed JWT, and the public key as a JWK document. The private key is
// not returned and not kept.
func Mint(issuer Issuer, userID string, expires time.Time) (Key, error) {
	return mintWith(json.Marshal, issuer, userID, expires)
}

// mintWith is Mint with the JSON encoder injected, so that its failure, which
// no valid key causes, is reachable from a test.
func mintWith(marshal func(any) ([]byte, error), issuer Issuer, userID string, expires time.Time) (Key, error) {
	minted, err := japikey.NewJAPIKey(japikey.Config{
		Subject:           userID,
		Issuer:            issuer.Base,
		Audience:          Audience(KindSession),
		ExpiresAt:         expires,
		Claims:            nil,
		AllowInsecureHTTP: issuer.Insecure,
	})
	if err != nil {
		return Key{}, fmt.Errorf("mint session key: %w", err)
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
		ExpiresAt: expires,
		PublicKey: minted.PublicKey,
	}, nil
}
