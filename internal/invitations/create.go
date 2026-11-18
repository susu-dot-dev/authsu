package invitations

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Error codes of the create route, beside the input codes of the values it
// parses (input.CodeInvalidLabel, input.CodeInvalidNumInvites,
// input.CodeInvalidExpiresAt). They are stable: clients and dashboards may
// match on them. A store failure has the code of its operation
// (store.CodeInvitationCreateFailed and its siblings).
const (
	// CodeInvalidType is a type that cannot be created.
	CodeInvalidType = "invalid_invitation_type"
	// CodeCodeFailed is a code that could not be generated. It is the service's
	// own failure and the client sees a bare internal error.
	CodeCodeFailed = "invitation_code_failed"
)

// invalidType is the refusal of a type that cannot be created. It does not echo
// the type, and does not say whether the type exists but is not creatable.
func invalidType() *apierr.Error {
	return apierr.New(apierr.BadRequest, CodeInvalidType, "invitation type is not supported")
}

// createBody is the body of POST /api/invitation, as the client sent it.
type createBody struct {
	// Type is what the invitation grants: "member" or "admin", the role of the
	// account that registers with it (auth.CreatableInvitationType).
	Type string `json:"type"`
	// NumInvites is how many accounts it may create.
	NumInvites int64 `json:"numInvites"`
	// Label is a note for admins. Optional.
	Label string `json:"label"`
	// ExpiresAt is when it stops working, in Unix seconds. Optional.
	ExpiresAt *int64 `json:"expiresAt"`
}

// Created is the body of a created invitation. Code is the only time it is ever
// returned.
type Created struct {
	Invitation

	// Code is what to hand to the invitee. It is not stored, and cannot be
	// shown again: a lost code is revoked and replaced.
	Code string `json:"code"`
}

// createCommand is a create request whose values have all been parsed.
type createCommand struct {
	invitationType string
	label          input.InvitationLabel
	numInvites     input.NumInvites
	expires        *input.Expiry
	createdBy      string
	// now is the request's clock reading, the one the expiry was checked
	// against and the creation time.
	now time.Time
}

// create answers POST /api/invitation: parse everything, generate the code,
// store only its hash, and return the stored row with the code.
func (h *handlers) create(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[createBody](call.Request).
		Then(func(body createBody) (createCommand, error) { return h.parseCreate(call.Principal, body) }).
		Then(func(cmd createCommand) (Created, error) { return h.createInvitation(call, cmd) }).
		Map(func(out Created) httpapi.Response { return httpapi.JSON(http.StatusCreated, out) })
}

// parseCreate turns the raw body into a command, refusing the first value that
// is not valid: type, numInvites, label, expiresAt.
func (h *handlers) parseCreate(principal auth.Principal, body createBody) (createCommand, error) {
	cmd := createCommand{
		invitationType: "", label: input.InvitationLabel{}, numInvites: input.NumInvites{}, expires: nil,
		createdBy: principal.UserID, now: h.now(),
	}

	if !auth.CreatableInvitationType(body.Type) {
		return cmd, invalidType()
	}

	cmd.invitationType = body.Type

	var err error

	cmd.numInvites, err = input.ParseNumInvites(body.NumInvites)
	if err != nil {
		return cmd, err //nolint:wrapcheck // the parser's error is already the classified client error
	}

	cmd.label, err = input.ParseInvitationLabel(body.Label)
	if err != nil {
		return cmd, err //nolint:wrapcheck // the parser's error is already the classified client error
	}

	if body.ExpiresAt == nil {
		return cmd, nil
	}

	expiry, err := input.ParseExpiry(*body.ExpiresAt, cmd.now)
	if err != nil {
		return cmd, err //nolint:wrapcheck // the parser's error is already the classified client error
	}

	cmd.expires = &expiry

	return cmd, nil
}

// createInvitation generates the code and writes the invitation holding only its
// hash. The response is the row the database stored, so it is the database's
// view, with the code that is not in it. The store's failures are already
// classified, and wrapping one here keeps that.
func (h *handlers) createInvitation(call *auth.Call, cmd createCommand) (Created, error) {
	code, err := h.newCode()
	if err != nil {
		return Created{}, err
	}

	row, err := h.store.CreateInvitation(call.Request.Context, store.NewInvitation{
		ID: h.newID(), CodeHash: code.Hash(), Type: cmd.invitationType, Label: cmd.label,
		NumInvites: cmd.numInvites, ExpiresAt: cmd.expires, CreatedBy: cmd.createdBy, CreatedAt: cmd.now,
	})
	if err != nil {
		return Created{}, fmt.Errorf("create invitation: %w", err)
	}

	return Created{Invitation: present(row, cmd.now), Code: code.String()}, nil
}

// newCode returns a fresh code: CodeBytes of entropy, base64url without
// padding, parsed like any other code so that the hash that is stored and the
// hash a registration looks up come from one place. The entropy source failing,
// or giving too little, is the service's failure, as is a code that does not
// parse (which no 32 bytes can cause).
func (h *handlers) newCode() (input.InvitationCode, error) {
	raw := make([]byte, CodeBytes)

	_, err := io.ReadFull(h.entropy, raw)
	if err != nil {
		return input.InvitationCode{}, codeFailed(err)
	}

	code, err := input.ParseInvitationCode(base64.RawURLEncoding.EncodeToString(raw))
	// coverage:ignore: 32 bytes always encode to 43 base64url characters, which always parse
	if err != nil {
		return input.InvitationCode{}, codeFailed(err)
	}

	return code, nil
}

// codeFailed is the internal error for a code that could not be generated. It
// is built with New and not Wrap: a parser's error is a classified 400, and Wrap
// would keep that, but a code the server generated that does not parse is the
// server's defect and not the client's.
func codeFailed(cause error) *apierr.Error {
	return apierr.New(apierr.Internal, CodeCodeFailed, "internal error").
		WithCause(fmt.Errorf("generate invitation code: %w", cause))
}
