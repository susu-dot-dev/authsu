package input

// The small values of an OAuth request: state, nonce, and the two enumerations
// response_type and grant_type.

// Bounds of State and Nonce.
const (
	// MaxStateBytes bounds State, in bytes. A state is not stored on the
	// grant: it travels in the sealed pending request and back to the client.
	// RFC 6749 sets no bound, so this is a Go policy, sized so that the sealed
	// request holds (TestPendingRequestFitsItsPayload).
	MaxStateBytes = 256

	// MaxNonceBytes bounds Nonce, in bytes. It is the schema CHECK
	// `length(cast(nonce AS BLOB)) BETWEEN 1 AND 128` on the nullable column
	// oauth_grants.nonce that the migration must carry. The bytes are ASCII, so
	// they are also characters.
	MaxNonceBytes = 128
)

// Error codes of the OAuth request values.
const (
	CodeInvalidState        = "invalid_state"
	CodeInvalidNonce        = "invalid_nonce"
	CodeInvalidResponseType = "invalid_response_type"
	CodeInvalidGrantType    = "invalid_grant_type"
)

const (
	descInvalidState        = "state must be 1 to 256 printable ASCII characters"
	descInvalidNonce        = "nonce must be 1 to 128 printable ASCII characters"
	descInvalidResponseType = "response_type must be code"
	descInvalidGrantType    = "grant_type must be authorization_code or refresh_token"
)

// isVSChar reports whether c is a VSCHAR (RFC 6749 appendix A): 0x20 to 0x7E,
// the printable ASCII characters including space.
func isVSChar(c byte) bool { return c >= 0x20 && c <= 0x7e }

// vsString reports whether s is 1 to max VSCHARs.
func vsString(s string, maxBytes int) bool {
	return s != "" && len(s) <= maxBytes && onlyBytes(s, isVSChar)
}

// State is the opaque value a client sends to be handed back unchanged.
type State struct{ v string }

// ParseState accepts 1 to MaxStateBytes VSCHARs (RFC 6749 appendix A:
// printable ASCII, space included). It is kept exactly, spaces and all, and
// never trimmed. An absent state is the caller's to allow; one that is present
// and empty is refused. The caller must put the value back in a URL by encoding
// it.
func ParseState(raw string) (State, error) {
	if !vsString(raw, MaxStateBytes) {
		return State{}, refuse(CodeInvalidState, descInvalidState)
	}

	return State{v: raw}, nil
}

// String returns the state exactly as it was parsed.
func (s State) String() string { return s.v }

// Nonce is the value an OpenID client sends to be echoed in its ID token.
type Nonce struct{ v string }

// ParseNonce accepts 1 to MaxNonceBytes VSCHARs, kept exactly: see ParseState.
func ParseNonce(raw string) (Nonce, error) {
	if !vsString(raw, MaxNonceBytes) {
		return Nonce{}, refuse(CodeInvalidNonce, descInvalidNonce)
	}

	return Nonce{v: raw}, nil
}

// String returns the nonce exactly as it was parsed.
func (n Nonce) String() string { return n.v }

// ResponseType is what an authorization request asks to be returned. There is
// only the code.
type ResponseType struct{ v string }

// ParseResponseType accepts exactly "code": no "token" (the implicit flow is
// gone from OAuth 2.1), no combination such as "code id_token", and no other
// case.
func ParseResponseType(raw string) (ResponseType, error) {
	if raw != "code" {
		return ResponseType{}, refuse(CodeInvalidResponseType, descInvalidResponseType)
	}

	return ResponseType{v: raw}, nil
}

// String returns "code".
func (r ResponseType) String() string { return r.v }

// The two grant types of the token endpoint.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
)

// GrantType is what a token request asks to be exchanged.
type GrantType struct{ v string }

// ParseGrantType accepts exactly "authorization_code" or "refresh_token".
// Client credentials, the password grant and every other value are refused.
func ParseGrantType(raw string) (GrantType, error) {
	if raw != GrantAuthorizationCode && raw != GrantRefreshToken {
		return GrantType{}, refuse(CodeInvalidGrantType, descInvalidGrantType)
	}

	return GrantType{v: raw}, nil
}

// String returns the grant type exactly as it was parsed.
func (g GrantType) String() string { return g.v }

// AuthorizationCode reports whether the grant type is authorization_code.
func (g GrantType) AuthorizationCode() bool { return g.v == GrantAuthorizationCode }

// RefreshToken reports whether the grant type is refresh_token.
func (g GrantType) RefreshToken() bool { return g.v == GrantRefreshToken }
