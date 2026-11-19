package login

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Error codes the handlers produce. Each failing step has its own, so a log
// line or an alert names the step. They are stable: clients and dashboards may
// match on them. The code of a missing configuration is auth's
// (not_configured) and those of the database are the store's.
const (
	// CodeChallengeFailed is a begin that could not read entropy.
	CodeChallengeFailed = "login_challenge_failed"

	// CodeInvalidLogin is the one answer to every assertion that fails to
	// verify, so a failed login reveals nothing about which check failed: an
	// unknown credential, a handle that is not the account's, a bad signature,
	// a challenge that is forged, expired or already used.
	CodeInvalidLogin = "invalid_login"

	// CodeStoredCredentialInvalid is a stored passkey whose public key does not
	// parse. Registration refuses such a key before it is stored, so this is
	// the database not holding what was written. It is the service's failure
	// (500, a bare internal error to the client) and is meant to be alerted on.
	CodeStoredCredentialInvalid = "stored_credential_invalid" //nolint:gosec // an error code, not a credential

	// CodeSessionCreateFailed is a session token that could not be issued.
	CodeSessionCreateFailed = "session_create_failed"
)

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

// begin answers POST /api/login/begin. It writes nothing and reads nothing from
// the request: login has no input before the ceremony.
func (h *handlers) begin(call *auth.Call) result.Result[httpapi.Response] {
	now := h.now()

	return result.Of(call.Config()).
		Then(func(cfg config.Config) (requestOptions, error) { return h.options(cfg, now) }).
		Map(func(options requestOptions) httpapi.Response { return httpapi.JSON(http.StatusOK, options) })
}

// options creates the challenge, with no associated data, and the request
// options that carry it. The challenge's nonce is the only entropy login needs
// and nothing uses it as a value, so it is dropped.
func (h *handlers) options(cfg config.Config, now time.Time) (requestOptions, error) {
	issued, _, err := challenge.Create(cfg.LoginKey, h.entropy, now.Add(ChallengeTTL))
	if err != nil {
		return requestOptions{}, apierr.Wrap(err, apierr.Internal, CodeChallengeFailed, "could not start login")
	}

	return requestOptions{PublicKey: publicKeyOptions{
		Challenge:        base64.RawURLEncoding.EncodeToString(issued),
		RPID:             cfg.RP.ID,
		Timeout:          ChallengeTTL.Milliseconds(),
		UserVerification: "required",
		AllowCredentials: []string{},
	}}, nil
}
