package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/session"
	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

// Error codes. Each failing step has its own, so a log line or an alert names
// the step. They are stable: clients and dashboards may match on them.
const (
	CodeNotConfigured = "login_not_configured"
	CodeChallenge     = "login_challenge_failed"
	// CodeInvalidLogin is the one answer to every assertion that fails to
	// verify, so a failed login reveals nothing about which check failed: an
	// unknown credential, a handle that is not the account's, a bad signature,
	// a challenge that is forged, expired or already used.
	CodeInvalidLogin   = "invalid_login"
	CodeCredentialRead = "login_credential_lookup_failed" //nolint:gosec // an error code, not a credential
	CodeMintFailed     = "login_mint_failed"
	CodeAcceptFailed   = "login_accept_failed"
	// CodeAcceptRejected is a write the schema's own rules refused (a CHECK or
	// FOREIGN KEY): the code let through something the database would not.
	CodeAcceptRejected = "login_accept_rejected"
)

// publicKeyCredentialType is the only credential type WebAuthn defines.
const publicKeyCredentialType = "public-key"

// FinishRequest is the body of POST /api/login/finish: what
// PublicKeyCredential.toJSON() returns for an assertion
// (AuthenticationResponseJSON, WebAuthn section 5.1), so a frontend can post
// what the browser produced without editing it.
type FinishRequest struct {
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

// requestOptions is PublicKeyCredentialRequestOptionsJSON, trimmed to what
// authsu asks for. allowCredentials is empty, so the browser offers any
// discoverable passkey for the relying party: that is what makes login
// usernameless.
type requestOptions struct {
	PublicKey publicKeyOptions `json:"publicKey"`
}

type publicKeyOptions struct {
	Challenge        string   `json:"challenge"`
	RPID             string   `json:"rpId"`
	Timeout          int64    `json:"timeout"`
	UserVerification string   `json:"userVerification"`
	AllowCredentials []string `json:"allowCredentials"`
}

// Config is what login needs from the deployment.
type Config struct {
	// Deploy is the root secret and relying party.
	Deploy deploy.Config
	// Issuer is the session issuer, derived from the origin.
	Issuer session.Issuer
}

// LoadConfig reads the configuration login needs. Missing configuration is the
// deployment being broken, not the request being wrong, so it is Unavailable,
// with a code that names it for the log.
func LoadConfig(getenv func(string) string) (Config, error) {
	cfg, err := deploy.Load(getenv)
	if err != nil {
		return Config{}, notConfigured(err)
	}

	issuer, err := session.IssuerFor(cfg.RP.Origin)
	if err != nil {
		return Config{}, notConfigured(err)
	}

	return Config{Deploy: cfg, Issuer: issuer}, nil
}

func notConfigured(cause error) error {
	return fail(cause, apierr.Unavailable, CodeNotConfigured, "login is not available")
}

// BeginHandler returns POST /api/login/begin. getenv is called per request,
// because the Worker's environment only exists while a request is handled.
func (s *Service) BeginHandler(getenv func(string) string) httpapi.Handler {
	return func(httpapi.Request) result.Result[httpapi.Response] {
		return result.Of(s.begin(getenv)).
			Map(func(options requestOptions) httpapi.Response {
				return httpapi.JSON(http.StatusOK, options)
			})
	}
}

// FinishHandler returns POST /api/login/finish.
func (s *Service) FinishHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return httpapi.Decode[FinishRequest](req).
			Then(func(in FinishRequest) (finished, error) {
				return s.finish(req.Context, getenv, in)
			}).
			Map(func(out finished) httpapi.Response {
				return httpapi.JSON(http.StatusOK, FinishResponse{
					UserID:    out.userID,
					Role:      out.role,
					ExpiresAt: out.key.ExpiresAt.Unix(),
				}).WithCookies(session.Cookie(out.key))
			})
	}
}

// begin returns the request options. It writes nothing and reads nothing: the
// only things it holds are a clock and entropy.
func (s *Service) begin(getenv func(string) string) (requestOptions, error) {
	cfg, err := LoadConfig(getenv)
	if err != nil {
		return requestOptions{}, err
	}

	challenge, err := mint(deploy.DeriveKey(cfg.Deploy.Root, derivationContext), s.entropy, s.now().Add(ChallengeTTL))
	if err != nil {
		return requestOptions{}, apierr.Wrap(err, apierr.Internal, CodeChallenge, "could not start login")
	}

	return requestOptions{PublicKey: publicKeyOptions{
		Challenge:        b64(challenge),
		RPID:             cfg.Deploy.RP.ID,
		Timeout:          ChallengeTTL.Milliseconds(),
		UserVerification: "required",
		AllowCredentials: []string{},
	}}, nil
}

// b64 is unpadded base64url, the WebAuthn JSON encoding of binary values.
func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

var (
	errCredentialType        = errors.New("credential type is not public-key")
	errUnsolicitedExtensions = errors.New("client extension results for extensions that were not requested")
	errUnknownCredential     = errors.New("no such credential")
)

// finished is a completed login.
type finished struct {
	userID string
	role   string
	key    session.Key
}

// finish is the point of acceptance. Order matters: everything that can be
// refused without touching the database is refused first (the envelope, the
// client and authenticator data, and the challenge), then the credential is
// read, then the assertion is verified against it, and only then is anything
// written. So a response that is malformed, from another origin, or answers a
// challenge we did not issue costs no read, and a refusal's timing cannot tell
// whether a credential id exists.
func (s *Service) finish(ctx context.Context, getenv func(string) string, in FinishRequest) (finished, error) {
	cfg, err := LoadConfig(getenv)
	if err != nil {
		return finished{}, err
	}

	if s.reader == nil || s.batch == nil {
		return finished{}, notConfigured(errNoDatabase)
	}

	err = checkEnvelope(in)
	if err != nil {
		return finished{}, invalid(err)
	}

	parsed, err := webauthn.ParseAssertion(webauthn.Assertion{
		ID:                in.ID,
		RawID:             in.RawID,
		ClientDataJSON:    in.Response.ClientDataJSON,
		AuthenticatorData: in.Response.AuthenticatorData,
		Signature:         in.Response.Signature,
		UserHandle:        in.Response.UserHandle,
	}, cfg.Deploy.RP)
	if err != nil {
		return finished{}, invalid(err)
	}

	err = open(deploy.DeriveKey(cfg.Deploy.Root, derivationContext), parsed.Challenge, s.now())
	if err != nil {
		return finished{}, invalid(err)
	}

	stored, ok, err := s.reader.CredentialByID(ctx, parsed.CredentialID)
	if err != nil {
		return finished{}, apierr.Wrap(fmt.Errorf("look up credential: %w", err),
			apierr.Unavailable, CodeCredentialRead, "login is temporarily unavailable")
	}

	if !ok {
		return finished{}, invalid(errUnknownCredential)
	}

	asserted, err := parsed.Verify(webauthn.Stored{
		PublicKey:  stored.PublicKey,
		Flags:      webauthn.Flags(stored.Flags),
		UserHandle: stored.UserHandle,
	})
	if err != nil {
		return finished{}, invalid(err)
	}

	return s.accept(ctx, cfg, stored, asserted)
}

var errNoDatabase = errors.New("no database is configured")

// checkEnvelope checks the members of the credential that are not part of the
// authenticator's response: the type, and the client extension outputs. We
// request no extensions, so any output is unsolicited, which section 7.2 lets
// the relying party refuse.
func checkEnvelope(in FinishRequest) error {
	if in.Type != publicKeyCredentialType {
		return fmt.Errorf("%w: %q", errCredentialType, in.Type)
	}

	if len(in.ClientExtensionResults) != 0 {
		return errUnsolicitedExtensions
	}

	return nil
}

// invalid is the one answer to every assertion that fails to verify. The cause
// stays in the log; the client is told nothing about which check failed.
func invalid(cause error) error {
	return fail(cause, apierr.Unauthorized, CodeInvalidLogin, "the passkey login response is not valid")
}

// accept issues the session. The key insert records the challenge's hash in a
// unique column, so a replay of this response collides with the row the first
// login created and the batch fails; the flags update rides in the same batch,
// so a refused replay changes nothing. The insert takes the account from the
// credential's row, so a passkey deleted since it was read also fails the batch
// as a conflict (see session.InsertSessionQuery).
func (s *Service) accept(
	ctx context.Context, cfg Config, stored Credential, asserted webauthn.Asserted,
) (finished, error) {
	now := s.now()

	key, err := s.mint(cfg.Issuer, stored.UserID, now.Add(session.Lifetime))
	if err != nil {
		return finished{}, apierr.Wrap(err, apierr.Internal, CodeMintFailed, "internal error")
	}

	err = s.batch(ctx,
		atomic.Statement{Query: updateFlagsQuery, Args: []any{int64(asserted.Flags.Stored()), stored.ID}},
		atomic.Statement{Query: session.InsertSessionQuery, Args: []any{
			key.ID.String(), stored.ID, string(key.JWK), key.ExpiresAt.Unix(),
			session.LoginGrant(asserted.Challenge), stored.ID, now.Unix(),
		}},
	)
	if err != nil {
		return finished{}, acceptError(err)
	}

	return finished{userID: stored.UserID, role: stored.Role, key: key}, nil
}

// acceptError classifies a failed batch by why the database refused it:
//
//   - a conflict is a replay: this challenge already produced a session. It is
//     reported as any other failed login, because telling a client that a
//     response was already used is not something it can act on;
//   - a rejection (a CHECK or FOREIGN KEY, the schema's backstop for input the
//     code should have refused) is a defect on our side, so 500 under its own
//     code, which a log line or an alert can single out;
//   - anything else is the database being unavailable, so 503.
func acceptError(err error) error {
	switch {
	case errors.Is(err, atomic.ErrConflict):
		return invalid(err)
	case errors.Is(err, atomic.ErrRejected):
		return fail(err, apierr.Internal, CodeAcceptRejected, "internal error")
	default:
		return fail(err, apierr.Unavailable, CodeAcceptFailed, "login is temporarily unavailable")
	}
}

// fail builds a classified error. It goes through apierr.Wrap, which keeps the
// innermost classification, so a failure that already carries one is not
// reclassified.
func fail(cause error, kind apierr.Kind, code, description string) error {
	return apierr.Wrap(cause, kind, code, description)
}
