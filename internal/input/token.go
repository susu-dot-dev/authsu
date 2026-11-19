package input

import (
	"encoding/base64"
	"strings"

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
)

// The fixed descriptions of the token types. They name the rule, never the
// value, and must state the prefix and body length that internal/secret
// defines (TestTokenDescriptionsStateTheShape).
const (
	descInvalidInvitation   = "invitation token must be susu_inv_ followed by 43 base64url characters"
	descInvalidSessionToken = "session token must be susu_ses_ followed by 43 base64url characters"
	descInvalidKey          = "API key must be susu_key_ followed by 43 base64url characters"
)

// The three token types are the bearer secrets a client presents. Each accepts
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
