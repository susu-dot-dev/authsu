package input

import (
	"encoding/base64"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/secret"
)

// Error codes of the token types. A session token or API key that fails to
// parse is a credential problem, not a malformed request, so the route
// boundary maps those two to an unauthenticated response; the invitation token
// is a field of a request body and is reported as the BadRequest it is.
const (
	CodeInvalidInvitation   = "invalid_invitation"
	CodeInvalidSessionToken = "invalid_session_token"
	CodeInvalidAPIKey       = "invalid_api_key"

	// CodeInvalidAuthorizationCode, CodeInvalidRefreshToken and
	// CodeInvalidAccessToken are the codes of the three OAuth tokens: the
	// credentials a client presents to the token endpoint (the code and the
	// refresh token) or to a resource server (the access token). A client sends
	// them in a request body, so a refusal is a BadRequest here; the OAuth
	// endpoints report it as invalid_grant, and introspection reports an unknown
	// token as inactive.
	CodeInvalidAuthorizationCode = "invalid_authorization_code"
	CodeInvalidRefreshToken      = "invalid_refresh_token"
	CodeInvalidAccessToken       = "invalid_access_token"
)

// The fixed descriptions of the token types. They name the rule, never the
// value, and must state the prefix and body length that internal/secret
// defines (TestTokenDescriptionsStateTheShape).
const (
	descInvalidInvitation   = "invitation token must be susu_inv_ followed by 43 base64url characters"
	descInvalidSessionToken = "session token must be susu_ses_ followed by 43 base64url characters"
	descInvalidKey          = "API key must be susu_key_ followed by 43 base64url characters"

	descInvalidAuthorizationCode = "authorization code must be susu_code_ followed by 43 base64url characters"
	descInvalidRefreshToken      = "refresh token must be susu_rt_ followed by 43 base64url characters"
	descInvalidAccessToken       = "access token must be susu_at_ followed by 43 base64url characters"
)

// The six token types are the bearer secrets a client presents. Each accepts
// exactly one kind: the prefix names it (internal/secret), so a token of
// another kind is refused here, before anything is read from the database. See
// internal/secret for the shape of a token and for what its hash covers.
//
// Each type's Hash is the value stored in secrets.hash
// (`typeof(hash) = 'blob' AND length(hash) = 32`, migration 0001). Hashing in
// one place, the type, means a lookup and an insert cannot disagree.

// InvitationToken is the secret an invitee presents to register.
type InvitationToken struct{ v string }

// ParseInvitationToken accepts exactly "susu_inv_" followed by a canonical
// 43-character base64url body, and refuses everything else with
// CodeInvalidInvitation.
func ParseInvitationToken(raw string) (InvitationToken, error) {
	v, err := parseToken(raw, secret.TagInvitation, CodeInvalidInvitation, descInvalidInvitation)

	return InvitationToken{v: v}, err
}

// FirstRunSecret returns the configured FIRST_RUN_SECRET as an invitation
// token, or nil when it is unset or is not exactly a token
// (ParseInvitationToken): "susu_inv_" and 43 canonical base64url characters. The
// value is never trimmed or corrected, and a rejected one is never described, so
// the secret cannot leak through an error or a log line.
//
// It is the one place that decides whether a deployment has a usable first-run
// secret, so that the status route and registration cannot disagree about it.
func FirstRunSecret(getenv func(string) string) *InvitationToken {
	token, err := ParseInvitationToken(config.FirstRunSecret(getenv))
	if err != nil {
		return nil
	}

	return &token
}

// String returns the token exactly as it was parsed.
func (t InvitationToken) String() string { return t.v }

// Hash returns the SHA-256 of the whole token, prefix included, as the 32
// bytes stored in secrets.hash. Each call returns a new slice.
func (t InvitationToken) Hash() []byte { return hashOf(t.v) }

// SessionToken is the secret a browser presents in the session cookie.
type SessionToken struct{ v string }

// ParseSessionToken accepts exactly "susu_ses_" followed by a canonical
// 43-character base64url body, and refuses everything else with
// CodeInvalidSessionToken.
func ParseSessionToken(raw string) (SessionToken, error) {
	v, err := parseToken(raw, secret.TagSession, CodeInvalidSessionToken, descInvalidSessionToken)

	return SessionToken{v: v}, err
}

// String returns the token exactly as it was parsed.
func (t SessionToken) String() string { return t.v }

// Hash returns the SHA-256 of the whole token, prefix included, as the 32
// bytes stored in secrets.hash. Each call returns a new slice.
func (t SessionToken) Hash() []byte { return hashOf(t.v) }

// APIKeyToken is the secret a caller presents as `Authorization: Bearer`.
type APIKeyToken struct{ v string }

// ParseAPIKeyToken accepts exactly "susu_key_" followed by a canonical
// 43-character base64url body, and refuses everything else with
// CodeInvalidAPIKey.
func ParseAPIKeyToken(raw string) (APIKeyToken, error) {
	v, err := parseToken(raw, secret.TagAPIKey, CodeInvalidAPIKey, descInvalidKey)

	return APIKeyToken{v: v}, err
}

// String returns the token exactly as it was parsed.
func (t APIKeyToken) String() string { return t.v }

// Hash returns the SHA-256 of the whole token, prefix included, as the 32
// bytes stored in secrets.hash. Each call returns a new slice.
func (t APIKeyToken) Hash() []byte { return hashOf(t.v) }

// AuthorizationCode is the one-time code a client exchanges at the token
// endpoint.
type AuthorizationCode struct{ v string }

// ParseAuthorizationCode accepts exactly "susu_code_" followed by a canonical
// 43-character base64url body, and refuses everything else with
// CodeInvalidAuthorizationCode.
func ParseAuthorizationCode(raw string) (AuthorizationCode, error) {
	v, err := parseToken(raw, secret.TagOAuthCode, CodeInvalidAuthorizationCode, descInvalidAuthorizationCode)

	return AuthorizationCode{v: v}, err
}

// String returns the code exactly as it was parsed.
func (t AuthorizationCode) String() string { return t.v }

// Hash returns the SHA-256 of the whole token, prefix included, as the 32
// bytes stored in secrets.hash. Each call returns a new slice.
func (t AuthorizationCode) Hash() []byte { return hashOf(t.v) }

// RefreshToken is the secret a client exchanges for a new access token.
type RefreshToken struct{ v string }

// ParseRefreshToken accepts exactly "susu_rt_" followed by a canonical
// 43-character base64url body, and refuses everything else with
// CodeInvalidRefreshToken.
func ParseRefreshToken(raw string) (RefreshToken, error) {
	v, err := parseToken(raw, secret.TagOAuthRefresh, CodeInvalidRefreshToken, descInvalidRefreshToken)

	return RefreshToken{v: v}, err
}

// String returns the token exactly as it was parsed.
func (t RefreshToken) String() string { return t.v }

// Hash returns the SHA-256 of the whole token, prefix included, as the 32
// bytes stored in secrets.hash. Each call returns a new slice.
func (t RefreshToken) Hash() []byte { return hashOf(t.v) }

// AccessToken is the secret a client presents to a resource server, and a
// resource server presents to introspection. authsu's own API accepts it as a
// bearer token only where the boundary tells it from an API key by its prefix
// (ParseAPIKeyToken refuses it), and then only for the first-party login
// resource.
type AccessToken struct{ v string }

// ParseAccessToken accepts exactly "susu_at_" followed by a canonical
// 43-character base64url body, and refuses everything else with
// CodeInvalidAccessToken.
func ParseAccessToken(raw string) (AccessToken, error) {
	v, err := parseToken(raw, secret.TagOAuthAccess, CodeInvalidAccessToken, descInvalidAccessToken)

	return AccessToken{v: v}, err
}

// String returns the token exactly as it was parsed.
func (t AccessToken) String() string { return t.v }

// Hash returns the SHA-256 of the whole token, prefix included, as the 32
// bytes stored in secrets.hash. Each call returns a new slice.
func (t AccessToken) Hash() []byte { return hashOf(t.v) }

// parseToken is the one parser behind the token types. raw must be the exact
// prefix of tag followed by exactly secret.BodyLen characters of the base64url
// alphabet, the last of which is canonical. It returns raw unchanged, or the
// refusal with the given code and description (and an empty string).
//
// The prefix is matched as a whole and never found by splitting on '_', since
// the body may hold '_' too. The length is tested before the body is scanned,
// so a huge input costs one comparison.
//
// Canonical means the encoding a generator would write: 32 bytes are 256 bits,
// 43 characters carry 258, so the last character's two low bits are unused and
// must be zero. Otherwise 4 distinct spellings would stand for one body, and
// one secret would have several hashes. The strict decoder refuses them. It
// would also skip '\r' and '\n', which is why the alphabet is checked first.
func parseToken(raw string, tag secret.Tag, code, description string) (string, error) {
	body, ok := strings.CutPrefix(raw, secret.Prefix(tag))
	if !ok || len(body) != secret.BodyLen || !base64URL(body) || !canonicalBody(body) {
		return "", refuse(code, description)
	}

	return raw, nil
}

// canonicalBody reports whether body decodes under the strict base64url rules,
// which refuse a last character with non-zero unused bits.
func canonicalBody(body string) bool {
	_, err := base64.RawURLEncoding.Strict().DecodeString(body)

	return err == nil
}

// hashOf is secret.Hash as a slice, the form every store argument takes.
func hashOf(token string) []byte {
	sum := secret.Hash(token)

	return sum[:]
}
