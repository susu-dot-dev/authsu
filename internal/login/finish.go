package login

import (
	"context"
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
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

// publicKeyCredentialType is the only credential type WebAuthn defines.
const publicKeyCredentialType = "public-key"

// finishBody is the body of POST /api/login/finish: what
// PublicKeyCredential.toJSON() returns for an assertion
// (AuthenticationResponseJSON, WebAuthn section 5.1), so a frontend can post
// what the browser produced without editing it.
type finishBody struct {
	ID       string        `json:"id"`
	RawID    string        `json:"rawId"`
	Type     string        `json:"type"`
	Response assertionBody `json:"response"`
	// AuthenticatorAttachment is the client's description of the authenticator.
	// It is unverified and not used.
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
	// ClientExtensionResults are the client extension outputs. We request no
	// extensions, so any output is unsolicited and refused.
	ClientExtensionResults map[string]json.RawMessage `json:"clientExtensionResults"`
}

// assertionBody is AuthenticatorAssertionResponseJSON.
type assertionBody struct {
	// The member names are fixed by the WebAuthn specification.
	ClientDataJSON    string `json:"clientDataJSON"` //nolint:tagliatelle // WebAuthn names this member clientDataJSON
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

// FinishResponse is the body of a successful POST /api/login/finish. The session
// itself is in the cookie, never in the body.
type FinishResponse struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
	// ExpiresAt is when the session ends, in Unix seconds.
	ExpiresAt int64 `json:"expiresAt"`
}

// The stages of a login, each carrying what the next needs.

// claimed is an assertion that passed every check that needs no stored
// credential, to a challenge this deployment issued.
type claimed struct {
	parsed webauthn.Parsed
}

// found adds the stored passkey the assertion names.
type found struct {
	claimed

	credential store.Credential
}

// proved adds the proof: the signature verified with the stored key.
type proved struct {
	found

	asserted webauthn.Asserted
}

// finished is a completed login.
type finished struct {
	userID  string
	role    string
	session auth.Issued
}

var (
	errCredentialType        = errors.New("credential type is not public-key")
	errUnsolicitedExtensions = errors.New("client extension results for extensions that were not requested")
	errUnknownCredential     = errors.New("no such credential")
)

// finish answers POST /api/login/finish. Order matters: everything that can be
// refused without touching the database is refused first (the envelope, the
// client and authenticator data, and the challenge), then the credential is
// read, then the assertion is verified against it, and only then is anything
// written. So a response that is malformed, from another origin, or answers a
// challenge we did not issue costs no read.
func (h *handlers) finish(call *auth.Call) result.Result[httpapi.Response] {
	now := h.now()
	ctx := call.Request.Context

	return httpapi.Decode[finishBody](call.Request).
		Then(func(body finishBody) (finished, error) {
			return result.Of(call.Config()).
				Then(func(cfg config.Config) (claimed, error) { return claim(cfg, body, now) }).
				Then(func(in claimed) (found, error) { return h.lookup(ctx, in) }).
				Then(prove).
				Then(func(in proved) (finished, error) { return h.accept(ctx, in, now) }).
				Get()
		}).
		Map(present)
}

// claim checks the envelope, the assertion's client and authenticator data and
// the challenge, none of which needs the database.
func claim(cfg config.Config, body finishBody, now time.Time) (claimed, error) {
	err := checkEnvelope(body)
	if err != nil {
		return claimed{}, invalid(err)
	}

	parsed, err := webauthn.ParseAssertion(webauthn.Assertion{
		ID:                body.ID,
		RawID:             body.RawID,
		ClientDataJSON:    body.Response.ClientDataJSON,
		AuthenticatorData: body.Response.AuthenticatorData,
		Signature:         body.Response.Signature,
		UserHandle:        body.Response.UserHandle,
	}, cfg.RP)
	if err != nil {
		return claimed{}, invalid(err)
	}

	_, err = challenge.Open(cfg.LoginKey, parsed.Challenge, now, ChallengeTTL)
	// coverage:ignore: config.Load derives every key at challenge.KeyLen, so this cannot happen
	if errors.Is(err, challenge.ErrKey) {
		return claimed{}, apierr.Wrap(err, apierr.Internal, CodeChallengeFailed, "could not finish login")
	}

	if err != nil {
		return claimed{}, invalid(err)
	}

	return claimed{parsed: parsed}, nil
}

// checkEnvelope checks the members of the credential that are not part of the
// authenticator's response: the type, and the client extension outputs. We
// request no extensions, so any output is unsolicited, which section 7.2 lets
// the relying party refuse.
func checkEnvelope(body finishBody) error {
	if body.Type != publicKeyCredentialType {
		return fmt.Errorf("%w: %q", errCredentialType, body.Type)
	}

	if len(body.ClientExtensionResults) != 0 {
		return errUnsolicitedExtensions
	}

	return nil
}

// invalid is the one answer to every assertion that fails to verify. The cause
// stays in the log; the client is told nothing about which check failed.
func invalid(cause error) error {
	return apierr.Wrap(cause, apierr.Unauthorized, CodeInvalidLogin, "the passkey login response is not valid")
}

// storedCredentialInvalid is the answer to a stored passkey whose public key
// does not parse. Registration refuses such a key before it is stored, so this
// is the database no longer holding what was written (corruption or an edit by
// hand), and it is the service's failure, not the caller's: 500, with the cause
// in the log so that it is noticed, where a 401 would pass for a bad signature.
// The client is told nothing but that an error occurred.
func storedCredentialInvalid(cause error) *apierr.Error {
	return apierr.New(apierr.Internal, CodeStoredCredentialInvalid, "internal error").
		WithCause(fmt.Errorf("stored credential: %w", cause))
}

// lookup reads the passkey the assertion names. A credential that does not
// exist, and one whose account is revoked, are the same absence.
func (h *handlers) lookup(ctx context.Context, in claimed) (found, error) {
	credential, exists, err := h.store.CredentialByID(ctx, in.parsed.CredentialID)
	if err != nil {
		return found{}, err //nolint:wrapcheck // the store classifies its own failures
	}

	if !exists {
		return found{}, invalid(errUnknownCredential)
	}

	return found{claimed: in, credential: credential}, nil
}

// prove checks the assertion against the stored passkey: the user handle is the
// account's, backup eligibility is unchanged and the signature verifies.
func prove(in found) (proved, error) {
	asserted, err := in.parsed.Verify(webauthn.Stored{
		PublicKey:  in.credential.PublicKey,
		Flags:      webauthn.Flags(in.credential.Flags),
		UserHandle: in.credential.UserHandle,
	})
	if errors.Is(err, webauthn.ErrPublicKey) {
		return proved{}, storedCredentialInvalid(err)
	}

	if err != nil {
		return proved{}, invalid(err)
	}

	return proved{found: in, asserted: asserted}, nil
}

// accept issues the session token and stores the session. The write records the challenge's hash in a unique
// column, so a replay of this response collides with the row the first login
// created; the flags update rides in the same operation, so a refused replay
// changes nothing. A conflict is reported as any other failed login, because
// telling a client that a response was already used is not something it can act
// on.
func (h *handlers) accept(ctx context.Context, in proved, now time.Time) (finished, error) {
	credential := in.credential

	issued, err := h.issueSession(h.entropy, h.newID, now)
	if err != nil {
		return finished{}, apierr.Wrap(err, apierr.Internal, CodeSessionCreateFailed, "internal error")
	}

	err = h.store.CreateSession(ctx, store.NewSession{
		ID:              issued.ID,
		Hash:            issued.Hash,
		CredentialRowID: credential.ID,
		GrantedFrom:     auth.LoginGrant(in.parsed.Challenge),
		Flags:           in.asserted.Flags.Stored(),
		ExpiresAt:       issued.ExpiresAt,
		CreatedAt:       now,
	})
	if errors.Is(err, store.ErrConflict) {
		return finished{}, invalid(err)
	}

	if err != nil {
		return finished{}, err //nolint:wrapcheck // the store classifies its own failures
	}

	return finished{userID: credential.UserID, role: credential.Role, session: issued}, nil
}

// present is the response of a completed login: the session is the cookie, not
// the body.
func present(done finished) httpapi.Response {
	return httpapi.JSON(http.StatusOK, FinishResponse{
		UserID:    done.userID,
		Role:      done.role,
		ExpiresAt: done.session.ExpiresAt.Unix(),
	}).WithCookies(auth.SessionCookie(done.session))
}
