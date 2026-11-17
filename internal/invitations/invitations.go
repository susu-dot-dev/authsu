// Package invitations implements the admin API for invitations described in
// docs/invitations_design.md: list them, create one, change how many accounts
// it may create, and revoke it.
//
//	GET    /api/invitation        list every invitation, revoked ones included
//	POST   /api/invitation        create an invitation
//	PATCH  /api/invitation/{id}   change the number of accounts it may create
//	DELETE /api/invitation/{id}   revoke it
//
// Every route requires a session (401) whose account is an admin (403). The
// role is the one stored on the account, read on each request, so demoting an
// admin takes effect at once.
//
// An invitation is identified by its id, never by its code. The code is shown
// once, in the response to the POST that created it; only its hash is stored,
// so no route can return it again.
package invitations

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// Limits on what a client may ask for. The schema has no upper bound on
// num_invites, and the label is capped at 256 characters by a CHECK; these are
// the limits Go refuses first, so a client gets a proper error rather than a
// database rejection.
const (
	// MaxNumInvites is the most accounts one invitation may create.
	MaxNumInvites = 10_000
	// MaxLabelChars is the longest label, in characters (the schema counts
	// characters for TEXT).
	MaxLabelChars = 256
	// CodeBytes is the entropy of a generated code: 256 bits, which is 43
	// base64url characters, matching what docs/invitations_design.md assumes.
	CodeBytes = 32
)

// CreatableTypes are the types an invitation may be created with. A type
// decides the role an account created from it gets, and that mapping lives in
// internal/registration. None is creatable through this API yet: first run is
// minted only by GET /api/first-run, because it is bound to there being no
// account at all. Adding a type here, and its role in registration.RoleFor, is
// what makes POST accept it.
func CreatableTypes() []string { return nil }

// Status is where an invitation stands now. It is derived from the row and the
// clock, never stored.
type Status string

// Statuses, in the order they are decided: a revoked invitation is revoked
// even if it has also expired or been used up.
const (
	// StatusRevoked means an admin revoked it.
	StatusRevoked Status = "revoked"
	// StatusExpired means its expiry has passed.
	StatusExpired Status = "expired"
	// StatusExhausted means it has created as many accounts as it may.
	StatusExhausted Status = "exhausted"
	// StatusActive means it can still be redeemed.
	StatusActive Status = "active"
)

// Invitation is one invitation as an admin sees it. It never carries the code
// or its hash.
type Invitation struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	// NumInvites is how many accounts it may create.
	NumInvites int64 `json:"numInvites"`
	// Uses is how many accounts it has created: the users that point at it.
	Uses   int64  `json:"uses"`
	Status Status `json:"status"`
	// ExpiresAt, RevokedAt and CreatedBy are absent when not set.
	ExpiresAt *int64  `json:"expiresAt,omitempty"`
	RevokedAt *int64  `json:"revokedAt,omitempty"`
	CreatedBy *string `json:"createdBy,omitempty"`
	// CreatedAt is in Unix seconds.
	CreatedAt int64 `json:"createdAt"`
}

// Row is an invitation as stored, with its use count. Status is derived from
// it by StatusOf.
type Row struct {
	ID         string
	Type       string
	Label      string
	NumInvites int64
	Uses       int64
	ExpiresAt  *int64
	RevokedAt  *int64
	CreatedBy  *string
	CreatedAt  int64
}

// StatusOf returns the status of r at now. Revocation, expiry and the cap
// follow the same rules as the redemption query in internal/registration: any
// revoked_at at all revokes (even one set in the future), and an invitation
// expires at, not after, its expires_at.
func StatusOf(r Row, now time.Time) Status {
	switch {
	case r.RevokedAt != nil:
		return StatusRevoked
	case r.ExpiresAt != nil && *r.ExpiresAt <= now.Unix():
		return StatusExpired
	case r.Uses >= r.NumInvites:
		return StatusExhausted
	default:
		return StatusActive
	}
}

// Reader is the read side of the invitation store.
type Reader interface {
	// List returns every invitation, revoked ones included, newest first.
	List(ctx context.Context) ([]Row, error)
	// Get returns one invitation, or an error wrapping ErrNotFound if there is
	// none with this id.
	Get(ctx context.Context, id string) (Row, error)
}

// Service is the invitation API.
type Service struct {
	sessions Authenticator
	reader   Reader
	batch    atomic.Batch
	now      func() time.Time
	entropy  io.Reader
	newID    func() string
	// creatable is the set of types POST accepts.
	creatable map[string]struct{}
}

// Authenticator verifies a request's session. *session.Service is one.
type Authenticator interface {
	Authenticate(ctx context.Context, getenv func(string) string, req httpapi.Request) (session.Principal, error)
}

// Deps are the service's collaborators. Time, randomness and identifiers are
// injected so every branch is reachable from a test.
type Deps struct {
	Sessions Authenticator
	Reader   Reader
	// Batch performs the writes. Nil disables the routes that write.
	Batch atomic.Batch
	// Now is the clock.
	Now func() time.Time
	// Entropy supplies random bytes for codes (crypto/rand.Reader in
	// production).
	Entropy io.Reader
	// NewID returns a fresh UUIDv7 in canonical text form.
	NewID func() string
	// Types are the invitation types POST accepts. Production passes
	// CreatableTypes(); it is a dependency so a test can exercise creation
	// while no type is creatable.
	Types []string
}

// NewService returns a Service.
func NewService(deps Deps) *Service {
	return &Service{
		sessions:  deps.Sessions,
		reader:    deps.Reader,
		batch:     deps.Batch,
		now:       deps.Now,
		entropy:   deps.Entropy,
		newID:     deps.NewID,
		creatable: typeSet(deps.Types),
	}
}

func typeSet(types []string) map[string]struct{} {
	set := make(map[string]struct{}, len(types))
	for _, name := range types {
		set[name] = struct{}{}
	}

	return set
}

// ErrNotFound is what Reader.Get reports for an id nothing has.
var ErrNotFound = errors.New("no such invitation")

var errNoStore = errors.New("no database is configured")

// codeHash is how invitation codes are stored and looked up: the SHA-256 of the
// code, matching internal/registration and internal/firstrun.
func codeHash(code string) []byte {
	sum := sha256.Sum256([]byte(code))

	return sum[:]
}

// newCode returns a fresh code: CodeBytes of entropy, base64url without
// padding.
func newCode(entropy io.Reader) result.Result[string] {
	raw := make([]byte, CodeBytes)

	return result.Of(io.ReadFull(entropy, raw)).
		Map(func(int) string { return base64.RawURLEncoding.EncodeToString(raw) })
}

// firstRunType is the type minted only by GET /api/first-run.
const firstRunType = firstrun.InvitationType
