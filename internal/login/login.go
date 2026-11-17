// Package login implements POST /api/login/begin and POST /api/login/finish, the
// two steps of passkey login described in docs/login_design.md.
//
// Login is usernameless: begin sends an empty list of allowed credentials, so
// the browser offers whichever passkey the user picks, and finish learns who
// they are from the credential id in the response.
//
// Begin writes nothing. It returns request options with a challenge that is
// signed rather than stored. Finish verifies the assertion and then, in one
// database batch, issues the session and records what it was granted from: the
// hash of the challenge, in a unique column, which is what makes a login
// single use.
package login

import (
	"context"
	"io"
	"time"

	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// ChallengeTTL is how long a begin response stays valid. It is also the timeout
// sent in the request options. WebAuthn recommends 5 to 10 minutes.
const ChallengeTTL = 5 * time.Minute

// derivationContext separates the login challenge key from every other key
// derived from the root secret, registration's included, so a challenge minted
// for one ceremony can never verify as the other.
const derivationContext = "authsu/login-challenge/v1"

// Credential is a stored passkey and the account it signs in.
type Credential struct {
	// ID is the credential's row id.
	ID string
	// UserID is the account.
	UserID string
	// PublicKey is the canonical COSE_Key written at registration.
	PublicKey []byte
	// Flags are the stored flags (UP, UV, BE, BS).
	Flags uint8
	// UserHandle is the account's WebAuthn user handle.
	UserHandle []byte
	// Role is the account's role.
	Role string
}

// Reader answers the one read finish needs.
type Reader interface {
	// CredentialByID returns the credential with this authenticator-chosen id,
	// joined to its account, and false if there is none.
	CredentialByID(ctx context.Context, credentialID []byte) (Credential, bool, error)
}

// Service is the login service.
type Service struct {
	reader  Reader
	batch   atomic.Batch
	now     func() time.Time
	entropy io.Reader
	// mint creates a session key. It is session.Mint; it is a field so that its
	// failure, which a valid configuration does not cause, is reachable from a
	// test.
	mint func(session.Issuer, string, time.Time) (session.Key, error)
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
}

// NewService returns a Service.
func NewService(deps Deps) *Service {
	return &Service{
		reader:  deps.Reader,
		batch:   deps.Batch,
		now:     deps.Now,
		entropy: deps.Entropy,
		mint:    session.Mint,
	}
}
