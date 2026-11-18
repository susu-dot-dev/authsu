package input

// MaxTokenBytes bounds Token, in bytes. Tokens are never stored: it limits the
// work of decoding a credential and the size of a cookie or header a request can
// make the Worker parse. A signed session token is a few hundred bytes, and
// browsers cap a cookie at about 4096.
const MaxTokenBytes = 4096

// CodeInvalidToken is the error code of ParseToken.
const CodeInvalidToken = "invalid_token"

const descInvalidToken = "token must be 1 to 4096 characters from A-Z, a-z, 0-9, '.', '_' and '-'"

// Token is a bearer or cookie credential in JWT form: dot-separated base64url
// segments.
type Token struct{ v string }

// ParseToken accepts 1 to MaxTokenBytes bytes from [A-Za-z0-9_.-]. It checks
// only the alphabet and the size; whether the token is genuine is for the
// verifier. It does not require the three-segment structure either, for the
// same reason.
func ParseToken(raw string) (Token, error) {
	if raw == "" || len(raw) > MaxTokenBytes || !onlyBytes(raw, isTokenByte) {
		return Token{}, refuse(CodeInvalidToken, descInvalidToken)
	}

	return Token{v: raw}, nil
}

func isTokenByte(c byte) bool { return c == '.' || isBase64URL(c) }

// String returns the token exactly as it was parsed.
func (t Token) String() string { return t.v }
