// Package registration implements POST /api/register/begin and
// POST /api/register/finish, the two steps of passkey registration described in
// docs/registration_design.md: turn an invitation token into an account and its
// first passkey, with no side effect until finish.
//
// Begin writes nothing. It checks the invitation as a courtesy (so a wrong token
// fails before the user's biometric prompt) and returns the WebAuthn creation
// options, with a challenge that is signed rather than stored: the invitation
// token and the account name are bound into it, and its nonce is the user
// handle. Finish is the one point of acceptance: it verifies the passkey and
// the challenge, then creates the account and credential in one store
// operation whose conditions enforce the invitation.
//
// The first admin registers like anyone else, with the first-run secret as the
// invitation token (docs/first_run_design.md). That invitation is not stored
// beforehand: finish's write creates it in the same batch as the account, when
// the token is the configured FIRST_RUN_SECRET and the database has no
// invitation and no account, and begin accepts the token in the same case. Both
// are decided against the configuration read on that request.
//
// Both routes are open (auth.None): the caller has no session yet.
package registration

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// The routes.
const (
	// PathBegin is the route that starts a registration.
	PathBegin = "/api/register/begin"
	// PathFinish is the route that completes one.
	PathFinish = "/api/register/finish"
)

const (
	// ChallengeTTL is how long a begin response stays valid. It is also the
	// timeout sent in the creation options. WebAuthn recommends 5 to 10
	// minutes.
	ChallengeTTL = 5 * time.Minute

	// FirstRunLabel is the admin-facing label of the first-run invitation, so it
	// is recognisable in an invitation list.
	FirstRunLabel = "First run: initial administrator"

	// MaxBeginBody caps the begin request, which is two short strings (a real
	// one is about 100 bytes). A name is escaped in JSON, at worst six bytes
	// per byte, so this leaves room for the longest valid one.
	MaxBeginBody = 4 << 10

	// MaxFinishBody caps the finish request, so the server never parses more
	// than a legitimate one could hold (a real one is under 1 KiB). It is the
	// sum of what the members may legally be, with room for JSON syntax and
	// escaping: id and rawId (1023 bytes each, base64url), clientDataJSON
	// (2048) and attestationObject (4096) as base64url, the name and invitation token, and
	// the transports. Anything larger fails a member's own bound anyway, so
	// refusing it here costs no honest client.
	MaxFinishBody = 32 << 10
)

// Store is the part of the store registration uses. *store.Store satisfies it.
type Store interface {
	// RedeemableInvitationType returns the type of the invitation the token names
	// when it is redeemable at now, and false when it is not. firstRun is the
	// configured first-run token, or nil: a token equal to it is redeemable as
	// the first-run invitation while there is no invitation and no account, even
	// though none is stored yet. It is advisory: CreateAccount decides.
	RedeemableInvitationType(
		ctx context.Context, token input.InvitationToken, firstRun *input.InvitationToken, now time.Time,
	) (string, bool, error)

	// CreateAccount creates the account and its first passkey, creating the
	// first-run invitation in the same batch when the token is the configured
	// first-run secret and the database is empty. It reports store.ErrConflict
	// when the registration cannot stand.
	CreateAccount(ctx context.Context, account store.NewAccount) error
}

// Deps are the collaborators of the routes. All are required. Time,
// randomness and identifiers are injected so every branch is reachable from a
// test.
type Deps struct {
	// Store reads and writes the database.
	Store Store
	// Now is the clock.
	Now func() time.Time
	// Entropy supplies random bytes (crypto/rand.Reader in production). It
	// is where the challenge's nonce, which is the user handle, comes from.
	Entropy io.Reader
	// NewID returns a fresh UUIDv7 in canonical text form, for the user, the
	// credential row and the first-run invitation, should this registration
	// create it.
	NewID func() string
}

// handlers carries the dependencies the two handlers share.
type handlers struct {
	store   Store
	now     func() time.Time
	entropy io.Reader
	newID   func() string
}

// Routes returns the registration routes. It panics when a dependency is
// missing: the wiring is fixed in code, so the mistake is found by the first
// test or start, never by a request.
func Routes(deps Deps) []auth.Route {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Now": deps.Now == nil, "Entropy": deps.Entropy == nil, "NewID": deps.NewID == nil,
	} {
		if missing {
			panic("registration: Deps." + name + " is required")
		}
	}

	handle := &handlers{store: deps.Store, now: deps.Now, entropy: deps.Entropy, newID: deps.NewID}

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
