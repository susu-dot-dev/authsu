package registration

import (
	"encoding/base64"
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
)

// Error codes the handlers produce. Each failing step has its own, so a log
// line or an alert names the step. They are stable: clients and dashboards may
// match on them. The codes of malformed input are input's (invalid_invitation,
// invalid_name), those of a missing configuration are auth's (not_configured)
// and those of the database are the store's.
const (
	// CodeInvalidInvitation is also input.CodeInvalidInvitation: a token that
	// is malformed (400) and a token that is not redeemable (403) are told
	// apart by the status, and not by anything that reveals why.
	CodeInvalidInvitation  = input.CodeInvalidInvitation
	CodeChallengeFailed    = "registration_challenge_failed"
	CodeInvalidChallenge   = "invalid_challenge"
	CodeInvalidCredential  = "invalid_credential" //nolint:gosec // an error code, not a credential
	CodeRegistrationFailed = "registration_failed"
	CodeAcceptFailed       = store.CodeRegistrationAcceptFailed
)

// beginBody is the body of POST /api/register/begin, as the client sent it.
type beginBody struct {
	// InvitationToken is the invitation token. The member keeps its name,
	// invitationCode, as the clients know it.
	InvitationToken string `json:"invitationCode"`
	// Name is the account name. It is also the display name: one value, so
	// the user types it once.
	Name string `json:"name"`
}

// ceremony is what begin and finish both bind a challenge to: the invitation
// being redeemed and the name the account is to have.
type ceremony struct {
	token input.InvitationToken
	name  input.AccountName
}

// associatedData is what the challenge's tag commits to besides its own bytes.
func (c ceremony) associatedData() [][]byte {
	return [][]byte{[]byte(c.token.String()), []byte(c.name.String())}
}

// parseCeremony parses the two strings every request carries.
func parseCeremony(rawToken, rawName string) (ceremony, error) {
	token, err := input.ParseInvitationToken(rawToken)
	if err != nil {
		return ceremony{}, err //nolint:wrapcheck // the parser's error is already the classified client error
	}

	name, err := input.ParseAccountName(rawName)

	//nolint:wrapcheck // the parser's error is already the classified client error
	return ceremony{token: token, name: name}, err
}

func parseBegin(body beginBody) (ceremony, error) {
	return parseCeremony(body.InvitationToken, body.Name)
}

// creationOptions is PublicKeyCredentialCreationOptionsJSON, trimmed to what
// authsu asks for. Building it by hand keeps the request exactly what the
// verifier will accept: ES256 only, a discoverable credential, user
// verification required, and no attestation.
type creationOptions struct {
	PublicKey publicKeyOptions `json:"publicKey"`
}

type publicKeyOptions struct {
	RP                     rpEntity               `json:"rp"`
	User                   userEntity             `json:"user"`
	Challenge              string                 `json:"challenge"`
	PubKeyCredParams       []credParam            `json:"pubKeyCredParams"`
	Timeout                int64                  `json:"timeout"`
	Attestation            string                 `json:"attestation"`
	AuthenticatorSelection authenticatorSelection `json:"authenticatorSelection"`
}

type rpEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type credParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type authenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

// publicKeyCredentialType is the only credential type WebAuthn defines.
const publicKeyCredentialType = "public-key"

// algES256 is the COSE identifier of ES256, the only algorithm the verifier
// accepts.
const algES256 = -7

// begin answers POST /api/register/begin. It writes nothing.
func (h *handlers) begin(call *auth.Call) result.Result[httpapi.Response] {
	now := h.now()

	return httpapi.Decode[beginBody](call.Request).
		Then(parseBegin).
		Then(func(cmd ceremony) (creationOptions, error) {
			return result.Of(call.Config()).
				Check(func(config.Config) error { return h.checkInvitation(call, cmd.token, now) }).
				Then(func(cfg config.Config) (creationOptions, error) { return h.options(cfg, cmd, now) }).
				Get()
		}).
		Map(func(options creationOptions) httpapi.Response { return httpapi.JSON(http.StatusOK, options) })
}

// checkInvitation reports an unusable invitation as a client error. The cases
// a client could otherwise tell apart (unknown, exhausted, revoked, expired) are
// deliberately one answer. A failing lookup is the store's classified error.
func (h *handlers) checkInvitation(call *auth.Call, token input.InvitationToken, now time.Time) error {
	firstRun := input.FirstRunSecret(call.Getenv)

	_, redeemable, err := h.store.RedeemableInvitationType(call.Request.Context, token, firstRun, now)
	if err != nil {
		return err //nolint:wrapcheck // the store classifies its own failures
	}

	if !redeemable {
		return errNotRedeemable()
	}

	return nil
}

// errNotRedeemable is the one answer to a token that cannot be redeemed.
func errNotRedeemable() *apierr.Error {
	return apierr.New(apierr.Forbidden, CodeInvalidInvitation, "invitation token is not valid")
}

// options creates the challenge, whose nonce is the user handle, and returns the
// creation options that carry both.
func (h *handlers) options(cfg config.Config, cmd ceremony, now time.Time) (creationOptions, error) {
	issued, handle, err := challenge.Create(cfg.RegistrationKey, h.entropy, now.Add(ChallengeTTL), cmd.associatedData()...)
	if err != nil {
		return creationOptions{}, apierr.Wrap(err, apierr.Internal, CodeChallengeFailed, "could not start registration")
	}

	name := cmd.name.String()

	return creationOptions{PublicKey: publicKeyOptions{
		RP:        rpEntity{ID: cfg.RP.ID, Name: cfg.RPName},
		User:      userEntity{ID: b64(handle), Name: name, DisplayName: name},
		Challenge: b64(issued),
		// -7 is ES256, the only algorithm the verifier accepts.
		PubKeyCredParams: []credParam{{Type: publicKeyCredentialType, Alg: algES256}},
		Timeout:          ChallengeTTL.Milliseconds(),
		Attestation:      "none",
		AuthenticatorSelection: authenticatorSelection{
			ResidentKey:      "required",
			UserVerification: "required",
		},
	}}, nil
}

// b64 is unpadded base64url, the WebAuthn JSON encoding of binary values.
func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
