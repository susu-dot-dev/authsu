package registration

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

// finishBody is the body of POST /api/register/finish, as the client sent it.
// The invitation token (member invitationCode) and the name are sent again
// because the challenge is bound to them.
type finishBody struct {
	InvitationToken string         `json:"invitationCode"`
	Name            string         `json:"name"`
	Credential      credentialBody `json:"credential"`
}

// credentialBody is PublicKeyCredential.toJSON() for a registration
// (RegistrationResponseJSON, WebAuthn section 5.1), so a frontend can post
// what the browser produced without editing it.
type credentialBody struct {
	ID       string          `json:"id"`
	RawID    string          `json:"rawId"`
	Type     string          `json:"type"`
	Response attestationBody `json:"response"`
	// AuthenticatorAttachment is the client's description of the
	// authenticator. It is unverified and not used.
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
	// ClientExtensionResults are the client extension outputs. We request no
	// extensions, so any output is unsolicited and refused.
	ClientExtensionResults map[string]json.RawMessage `json:"clientExtensionResults"`
}

// attestationBody is AuthenticatorAttestationResponseJSON. authenticatorData,
// publicKey and publicKeyAlgorithm are copies of what attestationObject holds
// (section 5.2.1.1). They are accepted and ignored: everything is read from
// attestationObject alone, so a copy that disagrees cannot change what is
// verified or stored.
type attestationBody struct {
	// The member name is fixed by the WebAuthn specification.
	ClientDataJSON    string `json:"clientDataJSON"` //nolint:tagliatelle // WebAuthn names this member clientDataJSON
	AttestationObject string `json:"attestationObject"`
	// Transports is bounded while the body is still being checked, so an
	// oversized list is refused before it is allocated. The bound is the same
	// as the one webauthn.Verify enforces (webauthn.MaxTransports); a test
	// holds the two equal from the outside.
	Transports         []string `json:"transports"         maxitems:"100"`
	AuthenticatorData  string   `json:"authenticatorData"`
	PublicKey          string   `json:"publicKey"`
	PublicKeyAlgorithm int64    `json:"publicKeyAlgorithm"`
}

// FinishResponse is the body of a successful POST /api/register/finish.
type FinishResponse struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// finishCommand is a parsed finish request: the typed ceremony and the
// credential, whose members are checked by the webauthn verifier.
type finishCommand struct {
	ceremony

	credential credentialBody
}

func parseFinish(body finishBody) (finishCommand, error) {
	c, err := parseCeremony(body.InvitationToken, body.Name)

	return finishCommand{ceremony: c, credential: body.Credential}, err
}

// verified is a registration whose passkey and challenge have been checked.
type verified struct {
	// handle is the user handle the challenge carried.
	handle     []byte
	credential webauthn.Credential
}

// authorized adds what the invitation allows.
type authorized struct {
	verified

	invitationType string
	role           string
}

// descConflict is what a client is told when the write refuses the
// registration. It is the same text for a used-up invitation and a replay: the
// database reports one conflict, and the client could not act on the
// difference.
const descConflict = "registration could not be completed: " +
	"the invitation was already used or this registration was already submitted"

var (
	errCredentialType        = errors.New("credential type is not public-key")
	errUnsolicitedExtensions = errors.New("client extension results for extensions that were not requested")
	errUnknownRole           = errors.New("invitation type has no role")
)

// finish answers POST /api/register/finish. Order matters: everything that can
// be refused without touching the database is refused first (the envelope, the
// passkey and the challenge), then the invitation is read, and only then is
// anything written.
func (h *handlers) finish(call *auth.Call) result.Result[httpapi.Response] {
	now := h.now()

	return httpapi.Decode[finishBody](call.Request).
		Then(parseFinish).
		Then(func(cmd finishCommand) (FinishResponse, error) {
			return result.Of(call.Config()).
				Then(func(cfg config.Config) (verified, error) { return verifyCeremony(cfg, cmd, now) }).
				Then(func(ok verified) (authorized, error) { return h.authorize(call, cmd, ok, now) }).
				Then(func(ok authorized) (FinishResponse, error) { return h.createAccount(call, cmd, ok, now) }).
				Get()
		}).
		Map(func(out FinishResponse) httpapi.Response { return httpapi.JSON(http.StatusCreated, out) })
}

// verifyCeremony checks the credential's envelope, the passkey and the
// challenge, none of which needs the database.
func verifyCeremony(cfg config.Config, cmd finishCommand, now time.Time) (verified, error) {
	err := checkEnvelope(cmd.credential)
	if err != nil {
		return verified{}, invalidCredential(err)
	}

	passkey, err := webauthn.Verify(webauthn.Registration{
		ID:                cmd.credential.ID,
		RawID:             cmd.credential.RawID,
		ClientDataJSON:    cmd.credential.Response.ClientDataJSON,
		AttestationObject: cmd.credential.Response.AttestationObject,
		Transports:        cmd.credential.Response.Transports,
	}, cfg.RP)
	if err != nil {
		return verified{}, invalidCredential(err)
	}

	handle, err := challenge.Open(cfg.RegistrationKey, passkey.Challenge, now, ChallengeTTL, cmd.associatedData()...)
	// coverage:ignore: config.Load derives every key at challenge.KeyLen, so this cannot happen
	if errors.Is(err, challenge.ErrKey) {
		return verified{}, apierr.Wrap(err, apierr.Internal, CodeChallengeFailed, "could not finish registration")
	}

	if err != nil {
		return verified{}, apierr.Wrap(err, apierr.BadRequest, CodeInvalidChallenge,
			"the registration challenge is not valid or has expired")
	}

	return verified{handle: handle, credential: passkey.Credential}, nil
}

// checkEnvelope checks the members of the credential that are not part of the
// authenticator's response: the type, and the client extension outputs. We
// request no extensions, so any output is unsolicited, which section 7.1 lets
// the relying party refuse.
func checkEnvelope(c credentialBody) error {
	if c.Type != publicKeyCredentialType {
		return fmt.Errorf("%w: %q", errCredentialType, c.Type)
	}

	if len(c.ClientExtensionResults) != 0 {
		return errUnsolicitedExtensions
	}

	return nil
}

func invalidCredential(cause error) error {
	return apierr.Wrap(cause, apierr.BadRequest, CodeInvalidCredential,
		"the passkey registration response is not valid")
}

// authorize reads the invitation, which must still be redeemable, and the role
// its type grants. The read is advisory: createAccount's write re-checks every
// condition, so a request that went stale since this read gets a clean 403
// here and the race this read cannot close gets a 409 there.
func (h *handlers) authorize(call *auth.Call, cmd finishCommand, ok verified, now time.Time) (authorized, error) {
	invitationType, redeemable, err := h.store.RedeemableInvitationType(
		call.Request.Context, cmd.token, input.FirstRunSecret(call.Getenv), now)
	if err != nil {
		return authorized{}, err //nolint:wrapcheck // the store classifies its own failures
	}

	if !redeemable {
		return authorized{}, errNotRedeemable()
	}

	role, known := auth.RoleForInvitation(invitationType)
	if !known {
		return authorized{}, apierr.Wrap(fmt.Errorf("%w: %q", errUnknownRole, invitationType),
			apierr.Internal, CodeRegistrationFailed, "internal error")
	}

	return authorized{verified: ok, invitationType: invitationType, role: role}, nil
}

// createAccount writes the account and its first passkey. A conflict means the
// invitation was used up or this registration was already submitted.
func (h *handlers) createAccount(
	call *auth.Call, cmd finishCommand, ok authorized, now time.Time,
) (FinishResponse, error) {
	userID := h.newID()

	err := h.store.CreateAccount(call.Request.Context, store.NewAccount{
		UserID:         userID,
		UserHandle:     ok.handle,
		Role:           ok.role,
		Name:           cmd.name,
		Token:          cmd.token,
		InvitationType: ok.invitationType,
		// What the write needs to create the first-run invitation, if this
		// registration is the one that redeems the configured first-run secret.
		// Its id is taken after the account's own, so those do not depend on it.
		FirstRun:          input.FirstRunSecret(call.Getenv),
		CredentialRowID:   h.newID(),
		FirstRunID:        h.newID(),
		FirstRunLabel:     FirstRunLabel,
		FirstRunExpiresAt: now.Add(input.ExpiryHorizon),
		CredentialID:      ok.credential.ID,
		PublicKey:         ok.credential.PublicKey,
		Flags:             ok.credential.Flags.Stored(),
		AAGUID:            formatAAGUID(ok.credential.AAGUID),
		Transports:        ok.credential.Transports,
		CreatedAt:         now,
	})
	if errors.Is(err, store.ErrConflict) {
		return FinishResponse{}, apierr.Wrap(err, apierr.Conflict, CodeAcceptFailed, descConflict)
	}

	if err != nil {
		return FinishResponse{}, err //nolint:wrapcheck // the store classifies its own failures
	}

	return FinishResponse{UserID: userID, Role: ok.role}, nil
}

// canonicalUUIDLen is the length of a UUID in 8-4-4-4-12 form.
const canonicalUUIDLen = 36

// formatAAGUID renders an AAGUID in the canonical 8-4-4-4-12 form.
func formatAAGUID(id [16]byte) string {
	const hexDigits = "0123456789abcdef"

	out := make([]byte, 0, canonicalUUIDLen)

	for i, b := range id {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}

		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}

	return string(out)
}
