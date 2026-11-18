// Package firstrun implements GET /api/first-run, the bootstrap status check
// described in docs/first_run_design.md: it reports where first-run setup
// stands and, when the deployment is configured and the system is empty,
// creates the first-run invitation.
//
// The route is open to anyone (it is what a person with no account reads), and
// that is safe because of what it says and does. It says one of three words and
// never the secret or the code. The write it may make records only the hash of a
// secret the caller does not hold, and only while the database has no invitation
// and no account, so whoever's request makes it, the outcome is the same.
package firstrun

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Path is the path of GET /api/first-run.
const Path = "/api/first-run"

// InvitationLabel is the admin-facing label of the first-run invitation, so it
// is recognisable in an invitation list.
const InvitationLabel = "First run: initial administrator"

// CodeBlocked is the error code of a database in which first-run can never
// finish: see Routes.
const CodeBlocked = "first_run_blocked"

// Status is the state of first-run setup.
type Status string

const (
	// StatusMissingSecret means the owner still has to configure the secret,
	// or has configured one that is not valid.
	StatusMissingSecret Status = "missing_secret"
	// StatusInvitationPending means the first-run invitation exists and is
	// waiting to be redeemed.
	StatusInvitationPending Status = "invitation_pending"
	// StatusInvitationAccepted means an account exists, so setup is over.
	StatusInvitationAccepted Status = "invitation_accepted"
)

// Store is the part of the database first-run reads and writes. *store.Store
// satisfies it. Failures must come back classified, as the store's do, because
// they are sent as they are.
type Store interface {
	// FirstRunState reads whether any account and any first-run invitation
	// exist, as one snapshot.
	FirstRunState(ctx context.Context) (store.FirstRunState, error)
	// CreateFirstRunInvitation inserts the first-run invitation for code, only
	// while there is no invitation and no account. It reports whether this
	// call inserted it.
	CreateFirstRunInvitation(
		ctx context.Context, id string, code input.InvitationCode, label string, now time.Time,
	) (bool, error)
}

// Deps are the collaborators of Routes. All are required.
type Deps struct {
	// Store reads the state and creates the invitation.
	Store Store
	// Now is the clock, the invitation's creation time.
	Now func() time.Time
	// NewID returns a fresh UUIDv7 in canonical text form, the invitation's id.
	NewID func() string
}

// statusBody is the JSON response body. It holds the status and nothing else:
// neither the code nor the secret may ever be in a response.
type statusBody struct {
	Status Status `json:"status"`
}

// errBlocked is the cause of CodeBlocked.
var errBlocked = errors.New("an invitation or an account exists, but no first-run invitation and no account")

// Routes returns the first-run route, for auth.Handler. It panics when a
// dependency is missing: the route would fail on first use, and a missing
// dependency is a wiring mistake to find at start, not in a request.
//
// GET /api/first-run needs no credential: see the package comment.
func Routes(deps Deps) []auth.Route {
	if deps.Store == nil || deps.Now == nil || deps.NewID == nil {
		panic("firstrun: Deps.Store, Deps.Now and Deps.NewID are required")
	}

	return []auth.Route{{
		Method: http.MethodGet, Path: Path, MaxBody: 0,
		Credential: auth.None, Handle: deps.status,
	}}
}

// status answers GET /api/first-run.
func (d Deps) status(call *auth.Call) result.Result[httpapi.Response] {
	ctx := call.Request.Context

	return result.Of(d.Store.FirstRunState(ctx)).
		Then(func(state store.FirstRunState) (Status, error) { return d.advance(call, state) }).
		Map(func(status Status) httpapi.Response { return httpapi.JSON(http.StatusOK, statusBody{Status: status}) })
}

// settled is the status a snapshot determines without the secret, if it does.
// Once an account exists setup is over, and the secret is not consulted at all:
// one left in the deployment is inert. Otherwise an existing first-run
// invitation is waiting to be redeemed.
func settled(state store.FirstRunState) (Status, bool) {
	switch {
	case state.HasUsers:
		return StatusInvitationAccepted, true
	case state.HasFirstRunInvitation:
		return StatusInvitationPending, true
	default:
		return "", false
	}
}

// advance moves setup along from state: when the snapshot does not settle the
// status, a valid secret is turned into the first-run invitation.
func (d Deps) advance(call *auth.Call, state store.FirstRunState) (Status, error) {
	status, done := settled(state)
	if done {
		return status, nil
	}

	code, ok := firstRunCode(call.Getenv)
	if !ok {
		return StatusMissingSecret, nil
	}

	ctx := call.Request.Context

	created, err := d.Store.CreateFirstRunInvitation(ctx, d.NewID(), code, InvitationLabel, d.Now())
	if err != nil {
		return "", err //nolint:wrapcheck // the store's error is already the classified client error
	}

	if created {
		return StatusInvitationPending, nil
	}

	return d.afterRefusal(ctx)
}

// firstRunCode turns the configured first-run secret into the invitation code.
// It reports false when the secret is missing, is shorter than
// config.MinFirstRunSecretLen bytes, or is not a valid invitation code (it is
// used as one: it must be 1 to input.MaxInvitationCodeBytes characters of the
// base64url alphabet). A rejected value is never described, so the secret
// cannot leak through an error or a log line.
func firstRunCode(getenv func(string) string) (input.InvitationCode, bool) {
	secret := config.FirstRunSecret(getenv)
	if len(secret) < config.MinFirstRunSecretLen {
		return input.InvitationCode{}, false
	}

	code, err := input.ParseInvitationCode(secret)
	if err != nil {
		return input.InvitationCode{}, false
	}

	return code, true
}

// afterRefusal answers a request whose insert the database refused.
//
// The insert is conditional on there being no invitation and no account, and
// the snapshot this request read said there were none, so the database changed
// in between (or never matched the snapshot). Saying "missing secret" would be
// wrong: the owner may have set a valid one, and would be told to set it again.
// So the state is read again, which tells what changed:
//
//   - a concurrent status check created the first-run invitation: pending;
//   - an account appeared: accepted;
//   - neither: an invitation of another type exists and no account does. No
//     first-run invitation can ever be created in that database (the design's
//     stage 1), so setup cannot finish and no secret will help. The owner is
//     told so, with the design's remedy: wipe and redeploy (see "Recovery is a
//     wipe"), rather than being left waiting for a status that never comes.
func (d Deps) afterRefusal(ctx context.Context) (Status, error) {
	state, err := d.Store.FirstRunState(ctx)
	if err != nil {
		return "", err //nolint:wrapcheck // the store's error is already the classified client error
	}

	status, done := settled(state)
	if !done {
		return "", apierr.Wrap(errBlocked, apierr.Conflict, CodeBlocked,
			"first-run setup cannot finish with this database: wipe it and redeploy")
	}

	return status, nil
}
