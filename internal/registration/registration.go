// Package registration implements POST /api/register/begin and
// POST /api/register/finish, the two steps of passkey registration described in
// docs/registration_design.md: turn an invitation code into an account and its
// first passkey, with no side effect until finish.
//
// Begin writes nothing. It checks the invitation as a courtesy (so a wrong code
// fails before the user's biometric prompt) and returns the WebAuthn creation
// options, with a challenge that is signed rather than stored. Finish is the
// one point of acceptance: it verifies the challenge and the passkey, then
// creates the account and credential in a single database batch whose
// conditions enforce the invitation.
package registration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/susu-dot-dev/authsu/internal/atomic"
)

// Environment names read by the handlers.
const (
	// SecretHMAC is the Worker secret that is the root key material for
	// signing registration challenges. Each purpose derives its own key from
	// it; it must never be used directly, and never for anything where a
	// signature is authorization (such as a session).
	SecretHMAC = "AUTH_HMAC_SECRET" //nolint:gosec // the name of a secret, not its value
	// VarRPID is the relying party ID, such as "auth.example.com".
	VarRPID = "RP_ID"
	// VarRPOrigin is the one origin ceremonies are accepted from, such as
	// "https://auth.example.com".
	VarRPOrigin = "RP_ORIGIN"
	// VarRPName is the relying party name shown by the browser.
	VarRPName = "RP_NAME"
)

// MinSecretLen is the shortest AUTH_HMAC_SECRET accepted: 32 random bytes is
// 43 base64url characters, so anything shorter is not a generated value.
const MinSecretLen = 32

// ChallengeTTL is how long a begin response stays valid. It is also the
// timeout sent in the creation options. WebAuthn recommends 5 to 10 minutes.
const ChallengeTTL = 5 * time.Minute

// derivationContext separates the registration challenge key from any other
// key derived from the root secret.
const derivationContext = "authsu/registration-challenge/v1"

// Roles. An invitation type maps to a role here, in Go, because the schema
// deliberately has no CHECK on either (see docs/devops.md).
const (
	// RoleAdmin may administer the deployment.
	RoleAdmin = "admin"
)

// RoleFor maps an invitation type to the role its accounts get, and reports
// whether the type is known. An unknown type has no role: registration
// refuses it rather than inventing one.
func RoleFor(invitationType string) (string, bool) {
	if invitationType == firstRunType {
		return RoleAdmin, true
	}

	return "", false
}

// firstRunType is invitations.type of the first-run invitation. It is repeated
// from internal/firstrun, which owns it, so this package need not import that
// one; a test pins the two together.
const firstRunType = "first_run"

// Reader answers the read-only question begin and finish ask.
//
// It is separate from the batch function so that begin, which must have no side effects,
// holds only a type that cannot write.
type Reader interface {
	// RedeemableInvitationType returns the type of the invitation with this
	// code hash if it is currently redeemable (not revoked, not expired, under
	// its cap, and for first run no account yet), and false if there is no such
	// invitation. It is advisory: the write at finish decides authoritatively.
	RedeemableInvitationType(ctx context.Context, codeHash []byte, now time.Time) (string, bool, error)
}

// Service is the registration service.
type Service struct {
	reader  Reader
	batch   atomic.Batch
	now     func() time.Time
	entropy io.Reader
	newID   func() string
	// marshal encodes the JSON columns. It is json.Marshal; it is a field so
	// that its failure, which no value of the types we pass can cause, is
	// reachable from a test.
	marshal func(any) ([]byte, error)
}

// Deps are the service's collaborators. Time, randomness and identifiers are
// injected so every branch is reachable from a test.
type Deps struct {
	Reader Reader
	// Batch performs the atomic write finish ends with. Nil disables finish.
	Batch atomic.Batch
	// Now is the clock.
	Now func() time.Time
	// Entropy supplies random bytes (crypto/rand.Reader in production).
	Entropy io.Reader
	// NewID returns a fresh UUIDv7 in canonical text form.
	NewID func() string
}

// NewService returns a Service.
func NewService(deps Deps) *Service {
	return &Service{
		reader:  deps.Reader,
		batch:   deps.Batch,
		now:     deps.Now,
		entropy: deps.Entropy,
		newID:   deps.NewID,
		marshal: json.Marshal,
	}
}

var (
	errSecretMissing = errors.New("signing secret is missing or too short")
	errNoDatabase    = errors.New("no database is configured")
	errConfigMissing = errors.New("relying party configuration is missing")
)

// deriveKey derives the challenge-signing key from the root secret. Distinct
// contexts give independent keys, so a key made for one purpose reveals
// nothing about another.
func deriveKey(root string) []byte {
	mac := hmac.New(sha256.New, []byte(root))
	mac.Write([]byte(derivationContext))

	return mac.Sum(nil)
}

// codeHash is how invitation codes are looked up: the SHA-256 of the code,
// matching what internal/firstrun stores.
func codeHash(code string) []byte {
	sum := sha256.Sum256([]byte(code))

	return sum[:]
}
