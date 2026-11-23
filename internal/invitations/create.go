package invitations

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Error codes of the create route, beside the input codes of the values it
// parses (input.CodeInvalidLabel, input.CodeInvalidNumInvites,
// input.CodeInvalidExpiresAt, input.CodeInvalidID for orgId and
// input.CodeInvalidOrgRole for orgRole, input.CodeMissingOrgID and
// input.CodeMissingOrgRole for one without the other). They are stable: clients and dashboards may
// match on them. A store failure has the code of its operation
// (store.CodeInvitationCreateFailed and its siblings).
const (
	// CodeInvalidType is a type that cannot be created.
	CodeInvalidType = "invalid_invitation_type"
	// CodeOrgNotFound is a create that names an organization that does not
	// exist or is a sandbox, as of the write. It is the same answer for each,
	// and nothing was created.
	CodeOrgNotFound = "org_not_found"
	// CodeCodeFailed is a token that could not be generated. It is the
	// service's own failure and the client sees a bare internal error. The name
	// is kept from when the value was called a code.
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
	// ExpiresAt is when it stops working, in Unix seconds. Optional: without
	// it the invitation expires input.ExpiryHorizon after it is created.
	ExpiresAt *int64 `json:"expiresAt"`
	// OrgID and OrgRole are the optional organization the invitation names:
	// whoever registers with it joins that standard organization, as a "member"
	// or an "admin" of it. Each needs the other, so a role is never assumed and
	// an organization is never named with none. Without them, the account that
	// registers is given an organization of its own.
	OrgID   *string `json:"orgId"`
	OrgRole *string `json:"orgRole"`
	// PublicKey is the key the token is sealed to: the base64url of the suite
	// byte and an X25519 public key (input.PublicKey). A session may omit it
	// and be sent the token as it is; any other credential must send it
	// (auth.Recipient).
	PublicKey *string `json:"publicKey"`
}

// Created is the body of a created invitation. Code, the invitation token, is
// returned this once and never again.
type Created struct {
	Invitation

	// Code is the invitation token ("susu_inv_" and 43 base64url characters) to
	// hand to the invitee. It is not stored, and cannot be shown again: a lost
	// token is revoked and replaced. It is absent when the request carried a
	// public key, and Sealed is present instead.
	Code string `json:"code,omitempty"`

	// Sealed is the token sealed to the request's public key (internal/seal).
	// It is absent when Code is present.
	Sealed string `json:"sealed,omitempty"`
}

// createCommand is a create request whose values have all been parsed.
type createCommand struct {
	invitationType string
	label          input.InvitationLabel
	numInvites     input.NumInvites
	expires        input.Expiry
	createdBy      string
	// org is the organization the invitation names, which may be none.
	org input.InvitationOrg
	// recipient is the key the token is sealed to, the zero value when the
	// caller is to be sent it as it is.
	recipient input.PublicKey
	// now is the request's clock reading, the one the expiry was checked
	// against and the creation time.
	now time.Time
}

// create answers POST /api/invitation: parse everything, generate the token,
// store only its hash, and return the stored row with the token.
func (h *handlers) create(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[createBody](call.Request).
		Then(func(body createBody) (createCommand, error) { return h.parseCreate(call.Principal, body).Get() }).
		Then(func(cmd createCommand) (Created, error) { return h.createInvitation(call, cmd).Get() }).
		Map(func(out Created) httpapi.Response { return httpapi.JSON(http.StatusCreated, out) })
}

// parseCreate turns the raw body into a command, refusing the first value that
// is not valid: type, numInvites, label, expiresAt, then the organization (orgId, orgRole).
// An expiresAt the client leaves out is now + input.ExpiryHorizon, and is parsed like a chosen one, so
// every invitation's expiry has passed the same check. The default is a whole
// second, as a chosen one is, and truncating now's fraction can only move it
// earlier, so it is never past the horizon the parser allows.
func (h *handlers) parseCreate(principal auth.Principal, body createBody) result.Result[createCommand] {
	cmd := createCommand{
		invitationType: "", label: input.InvitationLabel{}, numInvites: input.NumInvites{}, expires: input.Expiry{},
		createdBy: principal.UserID, now: h.now(),
	}

	if !auth.CreatableInvitationType(body.Type) {
		return result.Fail[createCommand](invalidType())
	}

	cmd.invitationType = body.Type

	expiresAt := cmd.now.Add(input.ExpiryHorizon).Unix()
	if body.ExpiresAt != nil {
		expiresAt = *body.ExpiresAt
	}

	return result.Of(input.ParseNumInvites(body.NumInvites)).
		Map(func(numInvites input.NumInvites) createCommand { cmd.numInvites = numInvites; return cmd }).
		Then(func(cmd createCommand) (createCommand, error) {
			return result.Of(input.ParseInvitationLabel(body.Label)).
				Map(func(label input.InvitationLabel) createCommand { cmd.label = label; return cmd }).
				Get()
		}).
		Then(func(cmd createCommand) (createCommand, error) {
			return result.Of(input.ParseExpiry(expiresAt, cmd.now)).
				Map(func(expires input.Expiry) createCommand { cmd.expires = expires; return cmd }).
				Get()
		}).
		Then(func(cmd createCommand) (createCommand, error) {
			return result.Of(input.ParseInvitationOrg(body.OrgID, body.OrgRole)).
				Map(func(org input.InvitationOrg) createCommand { cmd.org = org; return cmd }).
				Get()
		}).
		Then(func(cmd createCommand) (createCommand, error) {
			return auth.Recipient(principal, body.PublicKey).
				Map(func(to input.PublicKey) createCommand { cmd.recipient = to; return cmd }).
				Get()
		})
}

// orgNotFound is the refusal of an organization that cannot be named. It does
// not say which of the ways it cannot be.
func orgNotFound(cause error) error {
	return apierr.Wrap(cause, apierr.NotFound, CodeOrgNotFound, "no such organization")
}

// createInvitation generates the token and writes the invitation holding only
// its hash. The response is the row the database stored, so it is the
// database's view, with the token that is not in it, sealed to the caller's key
// when there is one. It is sealed before the write, so a key that cannot be
// sealed to creates nothing. The store's failures are
// already classified, and wrapping one here keeps that.
func (h *handlers) createInvitation(call *auth.Call, cmd createCommand) result.Result[Created] {
	return result.Of(h.newToken()).
		Then(func(token input.InvitationToken) (Created, error) {
			return auth.SealTo(h.seal, cmd.recipient, token.String()).
				Then(func(sealed string) (Created, error) { return h.write(call, cmd, token, sealed).Get() }).
				Get()
		})
}

// write writes the invitation and builds the response: the token in Code, or
// sealed in Sealed when it was sealed.
func (h *handlers) write(
	call *auth.Call, cmd createCommand, token input.InvitationToken, sealed string,
) result.Result[Created] {
	return result.Of(h.store.CreateInvitation(call.Request.Context, h.newInvitation(cmd, token))).
		MapErr(createRefused).
		Map(func(row store.Invitation) Created {
			created := Created{Invitation: present(row, cmd.now), Code: token.String(), Sealed: ""}
			if sealed != "" {
				created.Code, created.Sealed = "", sealed
			}

			return created
		})
}

// newInvitation is the invitation to store for a command: the token's hash and
// the id it is to have, and the organization when it names one.
func (h *handlers) newInvitation(cmd createCommand, token input.InvitationToken) store.NewInvitation {
	invitation := store.NewInvitation{
		ID: h.newID(), TokenHash: token.Hash(), Type: cmd.invitationType, Label: cmd.label,
		NumInvites: cmd.numInvites, ExpiresAt: cmd.expires, CreatedBy: cmd.createdBy, CreatedAt: cmd.now,
		Org: nil,
	}

	if cmd.org.Named() {
		invitation.Org = &store.NewInvitationOrg{OrgID: cmd.org.OrgID(), Role: cmd.org.Role()}
	}

	return invitation
}

// createRefused is the client's answer to a create the store refused: an
// organization that cannot be named is a 404, an admin who was revoked after
// the request was authenticated is a 401, and any other failure is kept as the
// store classified it.
func createRefused(err error) error {
	switch {
	case errors.Is(err, store.ErrInvitationOrgUnavailable):
		return orgNotFound(err)
	case errors.Is(err, store.ErrAccountRevoked):
		return auth.Unauthenticated(err) //nolint:wrapcheck // the boundary's own classified 401, with err as its cause
	default:
		return fmt.Errorf("create invitation: %w", err)
	}
}

// newToken returns a fresh invitation token: secret.Generate reads the entropy,
// and the result is parsed like any token a registration will present, so the
// hash that is stored and the hash a registration looks up come from one place.
// The entropy source failing, or giving too little, is the service's failure,
// as is a token that does not parse.
func (h *handlers) newToken() (input.InvitationToken, error) {
	raw, err := secret.Generate(h.entropy, secret.TagInvitation)
	if err != nil {
		return input.InvitationToken{}, tokenFailed(err)
	}

	token, err := input.ParseInvitationToken(raw)
	// coverage:ignore: Generate writes the prefix and 32 bytes as 43 canonical base64url characters, which always parse
	if err != nil {
		return input.InvitationToken{}, tokenFailed(err)
	}

	return token, nil
}

// tokenFailed is the internal error for a token that could not be generated. It
// is built with New and not Wrap: a parser's error is a classified 400, and Wrap
// would keep that, but a token the server generated that does not parse is the
// server's defect and not the client's.
func tokenFailed(cause error) *apierr.Error {
	return apierr.New(apierr.Internal, CodeCodeFailed, "internal error").
		WithCause(fmt.Errorf("generate invitation token: %w", cause))
}
