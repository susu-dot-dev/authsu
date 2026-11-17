// Package webauthn verifies the browser's response to a passkey registration
// ceremony (WebAuthn level 3, section 7.1) for exactly the configuration authsu
// asks for, and nothing else.
//
// It is deliberately narrow and fails closed. Anything outside the one shape
// authsu requests is rejected rather than interpreted:
//
//   - attestation format "none" with an empty statement (we request no
//     attestation, so there is no signature or certificate chain to parse);
//   - one algorithm, ES256 (COSE -7) over P-256;
//   - user presence and user verification both set;
//   - no extensions, and no cross-origin or top-origin use;
//   - every binary value in its one base64url spelling, and all CBOR in CTAP2
//     canonical form.
//
// Registration with attestation "none" verifies no signature: the response
// carries no attestation signature to check. What is verified is that the
// ceremony was for this relying party and origin, answers our challenge, and
// that the credential public key is a well-formed point on the curve.
// Signatures matter at login, which is a separate feature.
//
// The package does no I/O and reads no clock, so it is deterministic. The
// challenge is checked by the caller (see internal/registration): this package
// reports the challenge the browser echoed, and checks it equals the one the
// caller expects.
package webauthn

import (
	"errors"
)

// Sentinel failures. Callers classify them; the text is for logs only and may
// describe client input, so it must never be sent to a client.
var (
	// ErrClientData means clientDataJSON was malformed or did not describe a
	// registration for this relying party.
	ErrClientData = errors.New("invalid client data")
	// ErrAttestation means the attestation object was malformed or not the
	// "none" format.
	ErrAttestation = errors.New("invalid attestation object")
	// ErrAuthData means the authenticator data was malformed or failed a check.
	ErrAuthData = errors.New("invalid authenticator data")
	// ErrPublicKey means the credential public key was malformed, not ES256,
	// or not a point on the curve.
	ErrPublicKey = errors.New("invalid credential public key")
	// ErrTransports means the reported transports were not a short list of
	// printable-ASCII strings. Order and repeats are not errors.
	ErrTransports = errors.New("invalid transports")
)

// RelyingParty is the relying party configuration. These values come from
// deployment config and are fixed for a deployment: changing the ID
// invalidates every passkey.
type RelyingParty struct {
	// ID is the RP ID, a registrable domain suffix such as "example.com".
	ID string
	// Origin is the one origin ceremonies may come from, such as
	// "https://auth.example.com" (scheme, host and optional port; no path).
	Origin string
}

// Credential is a verified registration: what must be stored to authenticate
// the passkey later.
type Credential struct {
	// ID is the credential id, chosen by the authenticator.
	ID []byte
	// PublicKey is the credential public key as a canonical COSE_Key (CBOR).
	PublicKey []byte
	// Flags are the authenticator data flags (UP, UV, BE, BS).
	Flags Flags
	// AAGUID identifies the authenticator model. All zero when the
	// authenticator does not reveal it.
	AAGUID [16]byte
	// Transports are the transport hints the client reported, sorted and
	// without duplicates. They are unverified and informational only.
	Transports []string
}

// Flags are the authenticator data flag bits (WebAuthn section 6.1).
type Flags uint8

// The flag bits authsu inspects or stores.
const (
	// FlagUserPresent is UP: the user was present.
	FlagUserPresent Flags = 1 << 0
	// FlagUserVerified is UV: the user was verified (biometric or PIN).
	FlagUserVerified Flags = 1 << 2
	// FlagBackupEligible is BE: the credential can be backed up (synced).
	FlagBackupEligible Flags = 1 << 3
	// FlagBackupState is BS: the credential is currently backed up.
	FlagBackupState Flags = 1 << 4
	// flagAttestedCredentialData is AT: attested credential data follows.
	flagAttestedCredentialData Flags = 1 << 6
	// flagExtensionData is ED: extension data follows.
	flagExtensionData Flags = 1 << 7
	// flagReservedMask covers the reserved bits RFU1 (bit 1) and RFU2 (bit 5),
	// which must be zero.
	flagReservedMask Flags = 1<<1 | 1<<5
	// storedMask is what is kept: UP, UV, BE and BS. AT and ED describe the
	// shape of one response, not the credential.
	storedMask = FlagUserPresent | FlagUserVerified | FlagBackupEligible | FlagBackupState
)

// Stored returns the flags worth persisting (UP, UV, BE, BS).
func (f Flags) Stored() uint8 {
	return uint8(f & storedMask)
}
