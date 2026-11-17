// Package deploy reads the deployment's configuration: the root secret and the
// relying party values every WebAuthn ceremony shares. Registration and login
// both need them, and neither should depend on the other for them.
package deploy

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

// Environment names read by the handlers.
const (
	// SecretHMAC is the Worker secret that is the root key material. Each
	// purpose derives its own key from it with its own context (see
	// DeriveKey); it must never be used directly, and never for anything where
	// a signature is authorization (such as a session).
	SecretHMAC = "AUTH_HMAC_SECRET" //nolint:gosec // the name of a secret, not its value
	// VarRPID is the relying party ID, such as "auth.example.com".
	VarRPID = "RP_ID"
	// VarRPOrigin is the one origin ceremonies are accepted from, such as
	// "https://auth.example.com".
	VarRPOrigin = "RP_ORIGIN"
	// VarRPName is the relying party name shown by the browser.
	VarRPName = "RP_NAME"
)

// MinSecretLen is the shortest AUTH_HMAC_SECRET accepted: 32 random bytes is 43
// base64url characters, so anything shorter is not a generated value.
const MinSecretLen = 32

// Errors Load returns. They describe the deployment, not the request.
var (
	// ErrSecret means the root secret is missing or too short.
	ErrSecret = errors.New("signing secret is missing or too short")
	// ErrRelyingParty means a relying party value is missing.
	ErrRelyingParty = errors.New("relying party configuration is missing")
)

// Config is the deployment configuration for one request.
type Config struct {
	// Root is the root secret. Callers derive keys from it, and never use it
	// directly.
	Root string
	// RP is the relying party.
	RP webauthn.RelyingParty
	// RPName is shown by the browser.
	RPName string
}

// Load reads and validates the configuration. getenv is called per request,
// because the Worker's environment only exists while a request is handled.
func Load(getenv func(string) string) (Config, error) {
	secret := getenv(SecretHMAC)
	if len(secret) < MinSecretLen {
		return Config{}, ErrSecret
	}

	rp := webauthn.RelyingParty{ID: getenv(VarRPID), Origin: getenv(VarRPOrigin)}
	name := getenv(VarRPName)

	if rp.ID == "" || rp.Origin == "" || name == "" {
		return Config{}, ErrRelyingParty
	}

	return Config{Root: secret, RP: rp, RPName: name}, nil
}

// DeriveKey derives the key for one purpose from the root secret. Distinct
// contexts give independent keys, so a key made for one purpose reveals nothing
// about another.
func DeriveKey(root, context string) []byte {
	mac := hmac.New(sha256.New, []byte(root))
	mac.Write([]byte(context))

	return mac.Sum(nil)
}
