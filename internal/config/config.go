// Package config reads the deployment's configuration: the root secret and the
// two origins everything else is derived from. Registration, login, sessions
// and CORS all need them, and none should depend on another for them.
//
// There are two origins, and they are deliberately separate:
//
//   - API_ORIGIN is where this Worker is served, such as "https://auth.example.com".
//     It is the identity of the service: the session issuer is derived from it.
//   - UI_ORIGIN is where the UI is served, such as "https://example.com". Passkey
//     ceremonies run on the UI's pages, so the browser writes this origin into
//     clientDataJSON, and the relying party ID is its host. It is also the one
//     origin allowed to call the API from a browser (see httpapi.CORS).
//
// The relying party ID and name are not settings: both are the host of
// UI_ORIGIN, so there is nothing that can disagree with it.
package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

// Environment names read by the handlers.
const (
	// SecretHMAC is the Worker secret that is the root key material. Each
	// purpose derives its own key from it with its own context (Config's
	// RegistrationKey and LoginKey); it is never exposed or used directly, and
	// never for anything where a signature is authorization (such as a
	// session).
	SecretHMAC = "AUTH_HMAC_SECRET" //nolint:gosec // the name of a secret, not its value
	// SecretFirstRun is the Worker secret whose value becomes the first-run
	// invitation code (see FirstRunSecret).
	SecretFirstRun = "FIRST_RUN_SECRET"
	// VarAPIOrigin is the origin this Worker is served from, such as
	// "https://auth.example.com". The session issuer is derived from it.
	VarAPIOrigin = "API_ORIGIN"
	// VarUIOrigin is the origin the UI is served from, such as
	// "https://example.com". Passkey ceremonies are accepted from it alone, its
	// host is the relying party ID, and it is the one origin CORS allows.
	VarUIOrigin = "UI_ORIGIN"
)

// MinSecretLen is the shortest AUTH_HMAC_SECRET accepted: 32 random bytes is 43
// base64url characters, so anything shorter is not a generated value.
const MinSecretLen = 32

// MinFirstRunSecretLen is the shortest FIRST_RUN_SECRET accepted. A
// browser-generated value is 32 random bytes, which is 43 base64url
// characters; anything shorter is not a generated value.
const MinFirstRunSecretLen = 32

// Errors Load returns. They describe the deployment, not the request.
var (
	// ErrSecret means the root secret is missing or too short.
	ErrSecret = errors.New("signing secret is missing or too short")
	// ErrOrigin means an origin setting is missing or is not a bare origin.
	ErrOrigin = errors.New("origin configuration is missing or invalid")
)

// Origin is a validated bare origin: a scheme, a host and an optional port.
type Origin struct {
	// String is the origin exactly as configured, such as
	// "https://auth.example.com:8443". It is what a browser sends in an Origin
	// header and writes into clientDataJSON.
	String string
	// Host is the hostname alone: no scheme and no port.
	Host string
	// Insecure is true for plain http, which is accepted for the host
	// "localhost" only.
	Insecure bool
}

// ParseOrigin validates value as a bare origin: a scheme and a host, with an
// optional numeric port and nothing else (no user info, path, query or
// fragment). https is accepted for any host; plain http only for the host
// "localhost", so a session cookie is never put on a network by a
// configuration mistake. The host is compared whole: a prefix test would
// accept "localhost.example.com".
//
// The value must round-trip through url.URL unchanged, so a value that parses
// but would be written differently (an upper-case scheme or host, a trailing
// slash) is refused: a browser's Origin header is compared against it as a
// whole string, and a spelling that no browser sends would never match.
func ParseOrigin(value string) (Origin, error) {
	parsed, err := url.Parse(value)
	if err != nil || !bare(parsed) || parsed.String() != value || value != strings.ToLower(value) {
		return Origin{}, fmt.Errorf("%w: %q", ErrOrigin, value)
	}

	insecure := parsed.Scheme == "http" && parsed.Hostname() == "localhost"
	if parsed.Scheme != "https" && !insecure {
		return Origin{}, fmt.Errorf("%w: %q", ErrOrigin, value)
	}

	return Origin{String: value, Host: parsed.Hostname(), Insecure: insecure}, nil
}

// bare reports whether u is a scheme, a host and an optional port, with
// nothing after the authority.
func bare(u *url.URL) bool {
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

// Derivation contexts. Each key Config exposes is derived from the root secret
// with its own context, so a challenge created for one ceremony can never open
// as another. The strings are part of the signed format: changing one
// invalidates the challenges in flight, so they carry a version suffix.
const (
	registrationContext = "authsu/registration-challenge/v1"
	loginContext        = "authsu/login-challenge/v1"
)

// derivationContexts is the one registry of contexts. Adding a derived key to
// Config means adding its context here, where the tests assert that no two
// are equal: two keys that shared a context would be one key.
func derivationContexts() []string {
	return []string{registrationContext, loginContext}
}

// Config is the deployment configuration for one request.
type Config struct {
	// RegistrationKey signs and opens registration challenges. It is derived
	// from the root secret and is the key for no other purpose.
	RegistrationKey []byte
	// LoginKey signs and opens login challenges. It is derived from the root
	// secret and is the key for no other purpose.
	LoginKey []byte
	// API is the origin this Worker is served from.
	API Origin
	// UI is the origin the UI is served from.
	UI Origin
	// RP is the relying party: the UI's host as the ID, and the UI's origin as
	// the one origin ceremonies are accepted from.
	RP webauthn.RelyingParty
	// RPName is shown by the browser. It is the relying party ID.
	RPName string
}

// Load reads and validates the configuration. getenv is called per request,
// because the Worker's environment only exists while a request is handled.
func Load(getenv func(string) string) (Config, error) {
	secret := getenv(SecretHMAC)
	if len(secret) < MinSecretLen {
		return Config{}, ErrSecret
	}

	api, ui, err := Origins(getenv)
	if err != nil {
		return Config{}, err
	}

	return Config{
		RegistrationKey: deriveKey(secret, registrationContext),
		LoginKey:        deriveKey(secret, loginContext),
		API:             api,
		UI:              ui,
		RP:              webauthn.RelyingParty{ID: ui.Host, Origin: ui.String},
		RPName:          ui.Host,
	}, nil
}

// Origins reads and validates just the two origins, for callers that need no
// secret.
func Origins(getenv func(string) string) (Origin, Origin, error) {
	api, err := ParseOrigin(getenv(VarAPIOrigin))
	if err != nil {
		return Origin{}, Origin{}, fmt.Errorf("%s: %w", VarAPIOrigin, err)
	}

	ui, err := ParseOrigin(getenv(VarUIOrigin))
	if err != nil {
		return Origin{}, Origin{}, fmt.Errorf("%s: %w", VarUIOrigin, err)
	}

	return api, ui, nil
}

// deriveKey derives the key for one purpose from the root secret. Distinct
// contexts give independent keys, so a key made for one purpose reveals nothing
// about another.
func deriveKey(root, context string) []byte {
	mac := hmac.New(sha256.New, []byte(root))
	mac.Write([]byte(context))

	return mac.Sum(nil)
}

// FirstRunSecret reads FIRST_RUN_SECRET, the secret whose value becomes the
// first-run invitation code. It returns the value exactly as configured, or ""
// when it is not set. It does not judge the value: config is a foundation
// package and knows nothing of invitation codes, so the caller checks the
// length (MinFirstRunSecretLen) and parses it into an invitation code.
func FirstRunSecret(getenv func(string) string) string {
	return getenv(SecretFirstRun)
}
