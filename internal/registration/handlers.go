package registration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

// Error codes. Each failing step has its own, so a log line or an alert names
// the step. They are stable: clients and dashboards may match on them.
const (
	CodeNotConfigured      = "registration_not_configured"
	CodeInvalidInvitation  = "invalid_invitation"
	CodeInvalidName        = "invalid_name"
	CodeInvitationCheck    = "registration_invitation_check_failed"
	CodeChallengeFailed    = "registration_challenge_failed"
	CodeInvalidChallenge   = "invalid_challenge"
	CodeInvalidCredential  = "invalid_credential" //nolint:gosec // an error code, not a credential
	CodeRegistrationFailed = "registration_failed"
	CodeAcceptFailed       = "registration_accept_failed"
	// CodeAcceptRejected is a write the schema's own rules refused (a CHECK or
	// FOREIGN KEY): the code let through something the database would not.
	CodeAcceptRejected = "registration_accept_rejected"
)

const (
	// maxNameBytes bounds the name. users.profile is limited to 1024 bytes of
	// JSON; the name is escaped inside it, so it is bounded well below that.
	maxNameBytes = 128
	// maxCodeBytes bounds the invitation code. Real codes are 43 characters.
	maxCodeBytes = 256
)

// BeginRequest is the body of POST /api/register/begin.
type BeginRequest struct {
	InvitationCode string `json:"invitationCode"`
	// Name is the account name. It is also the display name: one value, so
	// the user types it once.
	Name string `json:"name"`
}

// FinishRequest is the body of POST /api/register/finish. The code and name
// are sent again because the challenge is bound to them.
type FinishRequest struct {
	InvitationCode string     `json:"invitationCode"`
	Name           string     `json:"name"`
	Credential     credential `json:"credential"`
}

// credential is PublicKeyCredential.toJSON() for a registration
// (RegistrationResponseJSON, WebAuthn section 5.1), so a frontend can post
// what the browser produced without editing it.
type credential struct {
	ID       string           `json:"id"`
	RawID    string           `json:"rawId"`
	Type     string           `json:"type"`
	Response credentialResult `json:"response"`
	// AuthenticatorAttachment is the client's description of the
	// authenticator. It is unverified and not used.
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
	// ClientExtensionResults are the client extension outputs. We request no
	// extensions, so any output is unsolicited and refused.
	ClientExtensionResults map[string]json.RawMessage `json:"clientExtensionResults"`
}

// credentialResult is AuthenticatorAttestationResponseJSON. authenticatorData,
// publicKey and publicKeyAlgorithm are copies of what attestationObject holds
// (section 5.2.1.1). They are accepted and ignored: everything is read from
// attestationObject alone, so a copy that disagrees cannot change what is
// verified or stored.
type credentialResult struct {
	// The member name is fixed by the WebAuthn specification.
	ClientDataJSON     string   `json:"clientDataJSON"` //nolint:tagliatelle // WebAuthn names this member clientDataJSON
	AttestationObject  string   `json:"attestationObject"`
	Transports         []string `json:"transports"`
	AuthenticatorData  string   `json:"authenticatorData"`
	PublicKey          string   `json:"publicKey"`
	PublicKeyAlgorithm int64    `json:"publicKeyAlgorithm"`
}

// FinishResponse is the body of a successful POST /api/register/finish.
type FinishResponse struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// publicKeyCredentialType is the only credential type WebAuthn defines.
const publicKeyCredentialType = "public-key"

// BeginHandler returns POST /api/register/begin. getenv is called per request,
// because the Worker's environment only exists while a request is handled.
func (s *Service) BeginHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return httpapi.Decode[BeginRequest](req).
			Check(validateBegin).
			Then(func(in BeginRequest) (creationOptions, error) {
				return s.begin(req.Context, getenv, in)
			}).
			Map(func(options creationOptions) httpapi.Response {
				return httpapi.JSON(http.StatusOK, options)
			})
	}
}

// FinishHandler returns POST /api/register/finish.
func (s *Service) FinishHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return httpapi.Decode[FinishRequest](req).
			Check(validateFinish).
			Then(func(in FinishRequest) (FinishResponse, error) {
				return s.finish(req.Context, getenv, in)
			}).
			Map(func(out FinishResponse) httpapi.Response {
				return httpapi.JSON(http.StatusCreated, out)
			})
	}
}

// validateBegin bounds the client-supplied strings.
func validateBegin(in BeginRequest) error {
	return validateCodeAndName(in.InvitationCode, in.Name)
}

// validateFinish bounds the client-supplied strings.
func validateFinish(in FinishRequest) error {
	return validateCodeAndName(in.InvitationCode, in.Name)
}

func validateCodeAndName(code, name string) error {
	if code == "" || len(code) > maxCodeBytes {
		return fail(nil, apierr.BadRequest, CodeInvalidInvitation, "invitation code is missing or invalid")
	}

	if name == "" || len(name) > maxNameBytes || !displayable(name) {
		return fail(nil, apierr.BadRequest, CodeInvalidName, "name is missing or invalid")
	}

	return nil
}

// displayable reports whether name is fit to show as an account name. The
// name is shown by the browser's passkey prompt and stored as the display
// name, so it must not hide or reorder text. WebAuthn section 5.4.3 asks
// relying parties to enforce the PRECIS Nickname profile (RFC 8266); this
// enforces its core: valid UTF-8, no control (Cc) or format (Cf) code points
// (NUL, bidirectional overrides and isolates, zero-width characters, the byte
// order mark, soft hyphens), and Unicode Normalization Form C, so one visible
// name has one spelling.
func displayable(name string) bool {
	if !utf8.ValidString(name) || !norm.NFC.IsNormalString(name) {
		return false
	}

	for _, r := range name {
		if unicode.In(r, unicode.Cc, unicode.Cf) {
			return false
		}
	}

	return true
}

// config is the per-request configuration read from the environment.
type config struct {
	key []byte
	rp  webauthn.RelyingParty
	// rpName is shown by the browser.
	rpName string
}

// loadConfig reads and validates configuration. Missing configuration is the
// deployment being broken, not the request being wrong, so it is Unavailable,
// with a code that names it for the log.
func loadConfig(getenv func(string) string) (config, error) {
	cfg, err := deploy.Load(getenv)
	if err != nil {
		return config{}, notConfigured(err)
	}

	return config{key: deriveKey(cfg.Root), rp: cfg.RP, rpName: cfg.RPName}, nil
}

func notConfigured(cause error) error {
	return fail(cause, apierr.Unavailable, CodeNotConfigured, "registration is not available")
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

// begin checks the invitation as a courtesy and returns the creation options.
// It writes nothing: the only dependencies it holds are a Reader and entropy.
func (s *Service) begin(ctx context.Context, getenv func(string) string, in BeginRequest) (creationOptions, error) {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return creationOptions{}, err
	}

	if s.reader == nil {
		return creationOptions{}, notConfigured(errNoDatabase)
	}

	err = s.checkInvitation(ctx, in.InvitationCode)
	if err != nil {
		return creationOptions{}, err
	}

	expires := s.now().Add(ChallengeTTL)

	issued, err := mint(cfg.key, s.entropy, expires, in.InvitationCode, in.Name)
	if err != nil {
		return creationOptions{}, apierr.Wrap(err, apierr.Internal, CodeChallengeFailed, "could not start registration")
	}

	return creationOptions{PublicKey: publicKeyOptions{
		RP:        rpEntity{ID: cfg.rp.ID, Name: cfg.rpName},
		User:      userEntity{ID: b64(issued.UserHandle), Name: in.Name, DisplayName: in.Name},
		Challenge: b64(issued.Challenge),
		// -7 is ES256, the only algorithm the verifier accepts.
		PubKeyCredParams: []credParam{{Type: publicKeyCredentialType, Alg: -7}},
		Timeout:          ChallengeTTL.Milliseconds(),
		Attestation:      "none",
		AuthenticatorSelection: authenticatorSelection{
			ResidentKey:      "required",
			UserVerification: "required",
		},
	}}, nil
}

// checkInvitation reports an unusable invitation as a client error and a
// failing lookup as the service being unavailable. The two cases a client
// could otherwise tell apart (unknown, exhausted) are deliberately one answer.
func (s *Service) checkInvitation(ctx context.Context, code string) error {
	_, ok, err := s.reader.RedeemableInvitationType(ctx, codeHash(code), s.now())
	if err != nil {
		return apierr.Wrap(fmt.Errorf("look up invitation: %w", err),
			apierr.Unavailable, CodeInvitationCheck, "registration is temporarily unavailable")
	}

	if !ok {
		return errInvalidInvitation()
	}

	return nil
}

func errInvalidInvitation() error {
	return fail(nil, apierr.Forbidden, CodeInvalidInvitation, "invitation code is not valid")
}

// b64 is unpadded base64url, the WebAuthn JSON encoding of binary values.
func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

var (
	errUnknownRole           = errors.New("invitation type has no role")
	errCredentialType        = errors.New("credential type is not public-key")
	errUnsolicitedExtensions = errors.New("client extension results for extensions that were not requested")
)

// finish is the point of acceptance. Order matters: everything that can be
// refused without touching the database is refused first.
func (s *Service) finish(ctx context.Context, getenv func(string) string, in FinishRequest) (FinishResponse, error) {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return FinishResponse{}, err
	}

	if s.reader == nil || s.batch == nil {
		return FinishResponse{}, notConfigured(errNoDatabase)
	}

	err = checkCredentialEnvelope(in.Credential)
	if err != nil {
		return FinishResponse{}, invalidCredential(err)
	}

	verified, err := webauthn.Verify(webauthn.Registration{
		ID:                in.Credential.ID,
		RawID:             in.Credential.RawID,
		ClientDataJSON:    in.Credential.Response.ClientDataJSON,
		AttestationObject: in.Credential.Response.AttestationObject,
		Transports:        in.Credential.Response.Transports,
	}, cfg.rp)
	if err != nil {
		return FinishResponse{}, invalidCredential(err)
	}

	handle, err := open(cfg.key, verified.Challenge, s.now(), in.InvitationCode, in.Name)
	if err != nil {
		return FinishResponse{}, fail(err, apierr.BadRequest, CodeInvalidChallenge,
			"the registration challenge is not valid or has expired")
	}

	invitationType, ok, err := s.reader.RedeemableInvitationType(ctx, codeHash(in.InvitationCode), s.now())
	if err != nil {
		return FinishResponse{}, apierr.Wrap(fmt.Errorf("look up invitation: %w", err),
			apierr.Unavailable, CodeInvitationCheck, "registration is temporarily unavailable")
	}

	if !ok {
		return FinishResponse{}, errInvalidInvitation()
	}

	role, known := RoleFor(invitationType)
	if !known {
		return FinishResponse{}, fail(fmt.Errorf("%w: %q", errUnknownRole, invitationType),
			apierr.Internal, CodeRegistrationFailed, "internal error")
	}

	return s.accept(ctx, accepted{
		code:       in.InvitationCode,
		name:       in.Name,
		handle:     handle,
		role:       role,
		invType:    invitationType,
		credential: verified.Credential,
	})
}

// checkCredentialEnvelope checks the members of the credential that are not
// part of the authenticator's response: the type, and the client extension
// outputs. We request no extensions, so any output is unsolicited, which
// section 7.1 lets the relying party refuse.
func checkCredentialEnvelope(c credential) error {
	if c.Type != publicKeyCredentialType {
		return fmt.Errorf("%w: %q", errCredentialType, c.Type)
	}

	if len(c.ClientExtensionResults) != 0 {
		return errUnsolicitedExtensions
	}

	return nil
}

func invalidCredential(cause error) error {
	return fail(cause, apierr.BadRequest, CodeInvalidCredential,
		"the passkey registration response is not valid")
}

// accepted is everything finish has verified and is about to write.
type accepted struct {
	code       string
	name       string
	handle     []byte
	role       string
	invType    string
	credential webauthn.Credential
}

// profile is users.profile.
type profile struct {
	Name string `json:"name"`
}

// credentialMetadata is credentials.metadata: what is written once at
// registration and not needed to authenticate.
type credentialMetadata struct {
	Format     string   `json:"fmt"`
	AAGUID     string   `json:"aaguid"`
	Transports []string `json:"transports"`
}

// accept writes the account and its first passkey as one atomic batch. The
// user insert carries the invitation conditions; the credential insert fails
// when that matched nothing, rolling the batch back. See insertUserQuery.
func (s *Service) accept(ctx context.Context, in accepted) (FinishResponse, error) {
	profileJSON, err := s.marshal(profile{Name: in.name})
	if err != nil {
		return FinishResponse{}, apierr.Wrap(err, apierr.Internal, CodeRegistrationFailed, "internal error")
	}

	transports := in.credential.Transports
	if transports == nil {
		transports = []string{}
	}

	metadataJSON, err := s.marshal(credentialMetadata{
		Format:     "none",
		AAGUID:     formatAAGUID(in.credential.AAGUID),
		Transports: transports,
	})
	if err != nil {
		return FinishResponse{}, apierr.Wrap(err, apierr.Internal, CodeRegistrationFailed, "internal error")
	}

	now := s.now().Unix()
	userID := s.newID()

	err = s.batch(ctx,
		atomic.Statement{Query: insertUserQuery, Args: []any{
			userID, in.handle, in.role, string(profileJSON), now,
			codeHash(in.code), in.invType, now,
		}},
		atomic.Statement{Query: insertCredentialQuery, Args: []any{
			s.newID(), in.credential.ID, in.handle, in.credential.PublicKey,
			int64(in.credential.Flags.Stored()), string(metadataJSON), now,
		}},
	)
	if err != nil {
		return FinishResponse{}, acceptError(err)
	}

	return FinishResponse{UserID: userID, Role: in.role}, nil
}

// acceptError classifies a failed batch by why the database refused it:
//
//   - a conflict (a unique value already taken, or the required user row not
//     there) is the client's to resolve: the invitation was used up, or this
//     attempt was a replay, so 409;
//   - a rejection (a CHECK or FOREIGN KEY, the schema's backstop for input the
//     code should have refused) is a defect on our side, so 500 under its own
//     code, which a log line or an alert can single out;
//   - anything else is the database being unavailable, so 503.
func acceptError(err error) error {
	switch {
	case errors.Is(err, atomic.ErrConflict):
		return fail(err, apierr.Conflict, CodeAcceptFailed,
			"registration could not be completed: the invitation was already used or this registration was already submitted")
	case errors.Is(err, atomic.ErrRejected):
		return fail(err, apierr.Internal, CodeAcceptRejected, "internal error")
	default:
		return fail(err, apierr.Unavailable, CodeAcceptFailed, "registration is temporarily unavailable")
	}
}

// fail builds a classified error. It goes through apierr.Wrap, which keeps the
// innermost classification, so a failure that already carries one is not
// reclassified; cause may be nil for a failure with nothing underneath it.
func fail(cause error, kind apierr.Kind, code, description string) error {
	if cause == nil {
		return apierr.Wrap(errNoCause, kind, code, description)
	}

	return apierr.Wrap(cause, kind, code, description)
}

// errNoCause is the cause of a failure that has nothing underneath it, so Wrap
// (which is nil-in, nil-out) still produces an error.
var errNoCause = errors.New("rejected")

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
