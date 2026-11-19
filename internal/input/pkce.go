package input

import (
	"crypto/sha256"
	"encoding/base64"
)

// PKCE (RFC 7636), with S256 as the only method.

// Bounds of the PKCE types.
const (
	// CodeChallengeLen is the length of a CodeChallenge: the base64url of a
	// SHA-256, 32 bytes, without padding. It is the schema CHECK
	// `length(code_challenge) = 43` on oauth_grants.code_challenge that the
	// migration must carry, and its share of the sealed pending request.
	CodeChallengeLen = 43

	// MinCodeVerifierLen and MaxCodeVerifierLen bound a CodeVerifier
	// (RFC 7636 section 4.1). A verifier is never stored: only its challenge
	// is, and the verifier is compared by hashing it.
	MinCodeVerifierLen = 43
	MaxCodeVerifierLen = 128
)

// Error codes of the PKCE types.
const (
	CodeInvalidCodeChallenge       = "invalid_code_challenge"
	CodeInvalidCodeChallengeMethod = "invalid_code_challenge_method"
	CodeInvalidCodeVerifier        = "invalid_code_verifier"
)

const (
	descInvalidCodeChallenge = "code_challenge must be exactly 43 base64url characters, the S256 challenge of a verifier"
	descInvalidMethod        = "code_challenge_method must be S256"
	descInvalidCodeVerifier  = "code_verifier must be 43 to 128 characters from A-Z, a-z, 0-9, '-', '.', '_' and '~'"
)

// methodS256 is the one challenge method.
const methodS256 = "S256"

// CodeChallenge is the S256 challenge of a client's code verifier.
type CodeChallenge struct{ v string }

// ParseCodeChallenge accepts exactly CodeChallengeLen characters of the
// base64url alphabet that are the canonical unpadded encoding of 32 bytes (the
// last character's two unused bits are zero, as for a token body), and refuses
// everything else. Padding, the standard alphabet and any other length are
// refused, so one SHA-256 has one challenge spelling and an equality test in the
// database (`code_challenge = ?`) is a test of the hash.
func ParseCodeChallenge(raw string) (CodeChallenge, error) {
	if len(raw) != CodeChallengeLen || !base64URL(raw) || !canonicalBody(raw) {
		return CodeChallenge{}, refuse(CodeInvalidCodeChallenge, descInvalidCodeChallenge)
	}

	return CodeChallenge{v: raw}, nil
}

// String returns the challenge exactly as it was parsed.
func (c CodeChallenge) String() string { return c.v }

// CodeChallengeMethod is the transformation a client says it applied to its
// verifier. There is only S256.
type CodeChallengeMethod struct{ v string }

// ParseCodeChallengeMethod accepts exactly "S256", compared case-sensitively.
// "plain", "s256" and every other value are refused: plain would make the
// challenge the verifier, and the whole point is that a stolen challenge is
// useless. A request that names no method is the caller's to refuse, because
// RFC 7636 would read it as plain.
func ParseCodeChallengeMethod(raw string) (CodeChallengeMethod, error) {
	if raw != methodS256 {
		return CodeChallengeMethod{}, refuse(CodeInvalidCodeChallengeMethod, descInvalidMethod)
	}

	return CodeChallengeMethod{v: raw}, nil
}

// String returns "S256".
func (m CodeChallengeMethod) String() string { return m.v }

// CodeVerifier is the secret a client proves it holds when it exchanges a
// code.
type CodeVerifier struct{ v string }

// ParseCodeVerifier accepts MinCodeVerifierLen to MaxCodeVerifierLen characters
// of the unreserved alphabet of RFC 3986, [A-Za-z0-9-._~]. The length is checked
// first, so a huge input costs one comparison.
func ParseCodeVerifier(raw string) (CodeVerifier, error) {
	if len(raw) < MinCodeVerifierLen || len(raw) > MaxCodeVerifierLen || !onlyBytes(raw, isUnreserved) {
		return CodeVerifier{}, refuse(CodeInvalidCodeVerifier, descInvalidCodeVerifier)
	}

	return CodeVerifier{v: raw}, nil
}

// isUnreserved reports whether c is in [A-Za-z0-9-._~].
func isUnreserved(c byte) bool {
	return isBase64URL(c) || c == '.' || c == '~'
}

// String returns the verifier exactly as it was parsed.
func (v CodeVerifier) String() string { return v.v }

// Challenge returns the S256 challenge of the verifier,
// base64url(sha256(verifier)) without padding. The token endpoint compares it
// with the stored challenge inside the write that spends the code, so the
// comparison and the spend are one statement.
func (v CodeVerifier) Challenge() CodeChallenge {
	sum := sha256.Sum256([]byte(v.v))

	return CodeChallenge{v: base64.RawURLEncoding.EncodeToString(sum[:])}
}
