// Package login implements POST /api/login/begin and POST /api/login/finish, the
// two steps of passkey login described in docs/login_design.md.
//
// Login is usernameless: begin sends an empty list of allowed credentials, so
// the browser offers whichever passkey the user picks, and finish learns who
// they are from the credential id in the response.
//
// Begin writes nothing. It returns request options with a challenge that is
// signed rather than stored. Finish verifies the assertion and then, in one
// store operation, issues the session and records what it was granted from:
// the hash of the challenge, in a unique column, which is what makes a login
// single use.
//
// Both routes are open (auth.None): the caller has no session yet. Every
// assertion that fails to verify gets the one answer, 401 invalid_login, so a
// failed login reveals nothing about which check failed.
package login

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// The routes.
const (
	// PathBegin is the route that starts a login.
	PathBegin = "/api/login/begin"
	// PathFinish is the route that completes one.
	PathFinish = "/api/login/finish"
)

const (
	// ChallengeTTL is how long a begin response stays valid. It is also the
	// timeout sent in the request options. WebAuthn recommends 5 to 10
	// minutes. It must stay far below auth.SessionLifetime: the challenge's
	// single use is recorded on the session row, so the row must outlive the
	// challenge (docs/login_design.md).
	ChallengeTTL = 5 * time.Minute

	// MaxBeginBody caps the begin request, which carries nothing the server
	// reads: a client sends an empty object.
	MaxBeginBody = 1 << 10

	// MaxFinishBody caps the finish request, so the server never parses more
	// than a legitimate one could hold (a real one is under 2 KiB). It is the
	// sum of what the members may legally be, with room for JSON syntax: id
	// and rawId (1023 bytes each, base64url), clientDataJSON (2048) and the
	// fixed-size authenticator data, signature and user handle. Anything
	// larger fails a member's own bound anyway, so refusing it here costs no
	// honest client.
	MaxFinishBody = 16 << 10
)

// Store is the part of the store login uses. *store.Store satisfies it.
type Store interface {
	// CredentialByID finds the passkey the authenticator's credential id
	// names, and reports false when there is none or its account is revoked.
	CredentialByID(ctx context.Context, credentialID []byte) (store.Credential, bool, error)

	// CreateSession records the flags the login reported and issues the
	// session in one operation, and reports store.ErrConflict when the login
	// cannot stand (a replay, a deleted passkey, a revoked account).
	CreateSession(ctx context.Context, session store.NewSession) error
}

// Deps are the collaborators of the routes. All are required. Time and
// randomness are injected so every branch is reachable from a test.
type Deps struct {
	// Store reads and writes the database.
	Store Store
	// Now is the clock.
	Now func() time.Time
	// Entropy supplies random bytes (crypto/rand.Reader in production). It is
	// where the challenge's nonce comes from.
	Entropy io.Reader
	// CreateSession creates the session key: auth.CreateSession in production.
	// It is injected so that its failure, which a valid configuration does not
	// cause, is reachable from a test.
	CreateSession func(issuer auth.Issuer, userID string, expires time.Time) (auth.Key, error)
}

// handlers carries the dependencies the two handlers share.
type handlers struct {
	store         Store
	now           func() time.Time
	entropy       io.Reader
	createSession func(auth.Issuer, string, time.Time) (auth.Key, error)
}

// Routes returns the login routes. It panics when a dependency is missing: the
// wiring is fixed in code, so the mistake is found by the first test or start,
// never by a request.
func Routes(deps Deps) []auth.Route {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Now": deps.Now == nil, "Entropy": deps.Entropy == nil,
		"CreateSession": deps.CreateSession == nil,
	} {
		if missing {
			panic("login: Deps." + name + " is required")
		}
	}

	handle := &handlers{
		store: deps.Store, now: deps.Now, entropy: deps.Entropy, createSession: deps.CreateSession,
	}

	return []auth.Route{
		{
			Method: http.MethodPost, Path: PathBegin, MaxBody: MaxBeginBody,
			Credential: auth.None, Handle: handle.begin,
		},
		{
			Method: http.MethodPost, Path: PathFinish, MaxBody: MaxFinishBody,
			Credential: auth.None, Handle: handle.finish,
		},
	}
}
