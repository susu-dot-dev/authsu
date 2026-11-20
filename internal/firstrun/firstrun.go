// Package firstrun implements GET /api/first-run, the bootstrap status check
// described in docs/first_run_design.md: it reports where first-run setup
// stands.
//
// The route only reads. The first-run invitation is not created here: the
// registration that redeems the configured secret creates it, in the same write
// as the account (internal/registration). So "pending" means "the secret is
// configured and the system is empty, so registering with it will work", not
// "an invitation row exists".
//
// The route is open to anyone (it is what a person with no account reads), and
// that is safe because of what it says. It says one of three words and never the
// secret or the token.
package firstrun

import (
	"context"
	"errors"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Path is the path of GET /api/first-run.
const Path = "/api/first-run"

// CodeBlocked is the error code of a database in which first-run can never
// finish: see Routes.
const CodeBlocked = "first_run_blocked"

// Status is the state of first-run setup.
type Status string

const (
	// StatusMissingSecret means the owner still has to configure the secret,
	// or has configured one that is not valid.
	StatusMissingSecret Status = "missing_secret"
	// StatusInvitationPending means the first-run invitation is waiting to be
	// redeemed: it exists, or the secret is configured and the system is empty,
	// so the registration that redeems the secret creates it.
	StatusInvitationPending Status = "invitation_pending"
	// StatusInvitationAccepted means an account exists, so setup is over.
	StatusInvitationAccepted Status = "invitation_accepted"
)

// Store is the part of the database first-run reads. *store.Store satisfies
// it. Failures must come back classified, as the store's do, because they are
// sent as they are.
type Store interface {
	// FirstRunState reads whether any account, any invitation and any first-run
	// invitation exist, as one snapshot.
	FirstRunState(ctx context.Context) (store.FirstRunState, error)
}

// Deps are the collaborators of Routes. All are required.
type Deps struct {
	// Store reads the state.
	Store Store
}

// statusBody is the JSON response body. It holds the status and nothing else:
// neither the token nor the secret may ever be in a response.
type statusBody struct {
	Status Status `json:"status"`
}

// errBlocked is the cause of CodeBlocked.
var errBlocked = errors.New("an invitation exists, but no first-run invitation and no account")

// Routes returns the first-run route, for auth.Handler. It panics when a
// dependency is missing: the route would fail on first use, and a missing
// dependency is a wiring mistake to find at start, not in a request.
//
// GET /api/first-run needs no credential: see the package comment.
func Routes(deps Deps) []auth.Route {
	if deps.Store == nil {
		panic("firstrun: Deps.Store is required")
	}

	return []auth.Route{{
		Method: http.MethodGet, Path: Path, MaxBody: 0,
		Credential: auth.None, Handle: deps.status,
	}}
}

// status answers GET /api/first-run.
func (d Deps) status(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.FirstRunState(call.Request.Context)).
		Map(func(state store.FirstRunState) Status { return statusOf(state, call.Getenv) }).
		Then(blockedOr).
		Map(func(status Status) httpapi.Response { return httpapi.JSON(http.StatusOK, statusBody{Status: status}) })
}

// statusOf is the status a snapshot and the configuration determine. Once an
// account exists setup is over, and the secret is not consulted at all: one left
// in the deployment is inert. Otherwise an existing first-run invitation is
// waiting to be redeemed, and with none a valid secret on a database with no
// invitation is too, because registering with it creates the invitation. A
// database with an invitation of another type and no account can never finish
// (the design's stage 1), whatever the secret.
func statusOf(state store.FirstRunState, getenv func(string) string) Status {
	switch {
	case state.HasUsers:
		return StatusInvitationAccepted
	case state.HasFirstRunInvitation:
		return StatusInvitationPending
	case state.HasInvitations:
		return statusBlocked
	case input.FirstRunSecret(getenv) != nil:
		return StatusInvitationPending
	default:
		return StatusMissingSecret
	}
}

// statusBlocked is the internal status of a database in which first-run can
// never finish. It is never sent: blockedOr turns it into CodeBlocked.
const statusBlocked Status = "blocked"

// blockedOr turns the blocked status into its error and passes any other.
func blockedOr(status Status) (Status, error) {
	if status == statusBlocked {
		return "", apierr.Wrap(errBlocked, apierr.Conflict, CodeBlocked,
			"first-run setup cannot finish with this database: wipe it and redeploy")
	}

	return status, nil
}
