// Package firstrun implements GET /api/first-run, the bootstrap status check
// described in docs/first_run_design.md: it reports where first-run setup
// stands and, when the deployment is configured and the system is empty, mints
// the first-run invitation.
package firstrun

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"
	"uuid"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// InvitationType is the invitations.type of the first-run invitation.
const InvitationType = "first_run"

// InvitationLabel is the admin-facing label of the first-run invitation, so it
// is recognisable in an invitation list.
const InvitationLabel = "First run: initial administrator"

// SecretName is the Worker secret whose value becomes the first-run code.
const SecretName = "FIRST_RUN_SECRET"

// MinSecretLen is the shortest FIRST_RUN_SECRET accepted. A browser-generated
// value is 32 random bytes, which is 43 base64url characters; anything shorter
// is not a generated value.
const MinSecretLen = 32

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

// Handler returns the GET /api/first-run handler. getenv reads deploy-time
// secrets; it is called per request, because the Worker's environment only
// exists while a request is handled. The response never contains the code or
// the secret.
func Handler(db *sql.DB, getenv func(string) string) httpapi.Handler {
	return newService(db, time.Now).handler(getenv)
}

// Error codes. Each failing step has its own, so a log line or an alert names
// the step. They are stable: clients and dashboards may match on them.
const (
	CodeUsersCheckFailed      = "first_run_users_check_failed"
	CodeInvitationCheckFailed = "first_run_invitation_check_failed"
	CodeMintFailed            = "first_run_mint_failed"
)

// unavailable classifies a database failure in the step named by code. The
// database erroring is the service being unavailable, not a fault in the
// request, and the client can only retry. The description is fixed text; the
// SQL error stays in the cause, which only the log sees.
func unavailable(code string, err error) error {
	return apierr.Wrap(err, apierr.Unavailable, code, "first-run status is temporarily unavailable")
}

// statusBody is the JSON response body.
type statusBody struct {
	Status Status `json:"status"`
}

func (s *service) handler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return result.Of(s.check(req.Context, getenv)).
			Map(func(status Status) httpapi.Response {
				return httpapi.JSON(http.StatusOK, statusBody{Status: status})
			})
	}
}

type service struct {
	db  *sql.DB
	now func() time.Time
}

// newService returns a service over db. now supplies the clock for created_at.
func newService(db *sql.DB, now func() time.Time) *service {
	return &service{db: db, now: now}
}

func (s *service) check(ctx context.Context, getenv func(string) string) (Status, error) {
	var users bool

	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM users)`,
	).Scan(&users)
	if err != nil {
		return "", unavailable(CodeUsersCheckFailed, fmt.Errorf("check for users: %w", err))
	}

	if users {
		return StatusInvitationAccepted, nil
	}

	var pending bool

	err = s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM invitations WHERE type = ?)`,
		InvitationType,
	).Scan(&pending)
	if err != nil {
		return "", unavailable(CodeInvitationCheckFailed, fmt.Errorf("check for first-run invitation: %w", err))
	}

	if pending {
		return StatusInvitationPending, nil
	}

	secret := getenv(SecretName)
	if len(secret) < MinSecretLen {
		return StatusMissingSecret, nil
	}

	minted, err := s.mint(ctx, secret)
	if err != nil {
		return "", err
	}

	if minted {
		return StatusInvitationPending, nil
	}

	return StatusMissingSecret, nil
}

// mint inserts the first-run invitation for code. It reports whether this call
// inserted it.
//
// The emptiness condition is part of the insert itself, so two racing status
// checks cannot both mint: the database admits exactly one. RETURNING makes the
// statement report its own outcome: one row means this call inserted the
// invitation, no rows means the condition refused it. Nothing is read back
// afterwards, because a later read cannot tell this insert's row from one
// written by another caller.
func (s *service) mint(ctx context.Context, code string) (bool, error) {
	sum := sha256.Sum256([]byte(code))

	var id string

	err := s.db.QueryRowContext(ctx,
		`INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at)
		 SELECT ?, ?, ?, ?, 1, ?
		 WHERE NOT EXISTS (SELECT 1 FROM invitations)
		   AND NOT EXISTS (SELECT 1 FROM users)
		 RETURNING id`,
		uuid.NewV7().String(), // id
		sum[:],                // code_hash
		InvitationType,        // type
		InvitationLabel,       // label
		s.now().Unix(),        // created_at
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, unavailable(CodeMintFailed, fmt.Errorf("mint first-run invitation: %w", err))
	}

	return true, nil
}
