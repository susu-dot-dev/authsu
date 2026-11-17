package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrAssertion means an assertion was malformed or failed a check. Its text is
// for logs only.
var ErrAssertion = errors.New("invalid assertion")

// MaxSignature caps the DER signature before it is parsed. An ES256 signature
// is at most 72 bytes.
const MaxSignature = 80

// MaxUserHandle is the WebAuthn limit on a user handle (section 5.4.3).
const MaxUserHandle = 64

// maxAuthenticatorData caps authenticator data before it is read. A login
// response's is exactly fixedAuthData bytes; the cap only bounds the decode.
const maxAuthenticatorData = 4096

var (
	errAssertionLength = errors.New("authenticator data is not exactly 37 bytes")
	errSignature       = errors.New("signature does not verify")
	errBackupChanged   = errors.New("backup eligibility changed")
	errUVNotCarried    = errors.New("user verification was not performed")
	errNoUserHandle    = errors.New("user handle is missing")
)

// Assertion is the browser's answer to a request ceremony, as sent by
// PublicKeyCredential.toJSON(): members are base64url without padding.
type Assertion struct {
	// ID and RawID are the credential id; they must agree.
	ID    string
	RawID string
	// ClientDataJSON, AuthenticatorData and Signature are the response members.
	ClientDataJSON    string
	AuthenticatorData string
	Signature         string
	// UserHandle is the response's userHandle member. A discoverable login
	// always carries one.
	UserHandle string
}

// Stored is what registration stored for the credential an assertion is
// checked against.
type Stored struct {
	// PublicKey is the canonical COSE_Key written at registration.
	PublicKey []byte
	// Flags are the stored flags (UP, UV, BE, BS).
	Flags Flags
	// UserHandle is the account's user handle.
	UserHandle []byte
}

// Asserted is an assertion that passed every check.
type Asserted struct {
	// CredentialID is the credential the user proved possession of.
	CredentialID []byte
	// Challenge is the challenge the browser echoed in clientDataJSON,
	// decoded. The caller must still check that it is one it issued.
	Challenge []byte
	// Flags are the flags the authenticator reported. They are covered by the
	// signature, so they are what to store when they have changed.
	Flags Flags
}

// Parsed is an assertion that passed every check that needs no stored
// credential. Nothing in it is trusted until Verify has checked the signature.
type Parsed struct {
	// CredentialID is the credential the assertion names: the caller looks
	// up the stored credential by it.
	CredentialID []byte
	// Challenge is the challenge the browser echoed in clientDataJSON,
	// decoded. The caller checks it is one it issued, which also needs no
	// stored credential, so it can be done before the lookup.
	Challenge []byte

	flags      Flags
	authData   []byte
	clientHash [sha256.Size]byte
	signature  []byte
	userHandle []byte
}

// ParseAssertion runs every check of an assertion that does not need the
// stored credential, so the caller can refuse a malformed or foreign response
// before reading its database: id and rawId agree; the client data is a
// webauthn.get ceremony from rp's origin, outside any cross-origin context;
// the authenticator data is exactly 37 bytes (rp id hash, flags, counter) for
// rp's id, with flags this deployment accepts; a user handle is present; and
// the signature is within bounds. It does not check the challenge; the caller
// owns it, as at registration.
//
// The signature counter is read and ignored: synced passkeys always report
// zero, so it cannot be a clone detector for the credentials this serves.
func ParseAssertion(a Assertion, rp RelyingParty) (Parsed, error) {
	id, err := checkAssertionID(a)
	if err != nil {
		return Parsed{}, err
	}

	clientData, err := decodeB64(a.ClientDataJSON, MaxClientDataJSON)
	if err != nil {
		return Parsed{}, fmt.Errorf("%w: clientDataJSON: %w", ErrClientData, err)
	}

	challenge, clientHash, err := ParseAssertionClientData(clientData, rp)
	if err != nil {
		return Parsed{}, err
	}

	authData, err := decodeB64(a.AuthenticatorData, maxAuthenticatorData)
	if err != nil {
		return Parsed{}, fmt.Errorf("%w: authenticatorData: %w", ErrAuthData, err)
	}

	flags, err := checkAssertionAuthData(authData, rp)
	if err != nil {
		return Parsed{}, err
	}

	handle, err := decodeUserHandle(a.UserHandle)
	if err != nil {
		return Parsed{}, err
	}

	signature, err := decodeB64(a.Signature, MaxSignature)
	if err != nil {
		return Parsed{}, fmt.Errorf("%w: signature: %w", ErrAssertion, err)
	}

	return Parsed{
		CredentialID: id,
		Challenge:    challenge,
		flags:        flags,
		authData:     authData,
		clientHash:   clientHash,
		signature:    signature,
		userHandle:   handle,
	}, nil
}

// Verify finishes checking a parsed assertion against the credential stored
// for its id: the user handle is the account's, the backup eligibility is
// unchanged since registration, and the ES256 signature over authenticator data
// and the hash of clientDataJSON was made with the stored key.
func (p Parsed) Verify(stored Stored) (Asserted, error) {
	if !bytes.Equal(p.userHandle, stored.UserHandle) {
		return Asserted{}, fmt.Errorf("%w: user handle is not the account's", ErrAssertion)
	}

	// Section 6.1.3 fixes backup eligibility for the life of the credential.
	// Backup state and the verified bit may legitimately differ from what was
	// stored.
	if p.flags&FlagBackupEligible != stored.Flags&FlagBackupEligible {
		return Asserted{}, fmt.Errorf("%w: %w", ErrAuthData, errBackupChanged)
	}

	key, err := storedKey(strictOptions(), stored.PublicKey)
	if err != nil {
		return Asserted{}, err
	}

	signed := append(bytes.Clone(p.authData), p.clientHash[:]...)

	err = verifyES256(key, signed, p.signature)
	if err != nil {
		return Asserted{}, err
	}

	return Asserted{CredentialID: p.CredentialID, Challenge: p.Challenge, Flags: p.flags}, nil
}

// checkAssertionID requires a non-empty rawId of at most the WebAuthn length,
// and id to be the same credential id.
func checkAssertionID(a Assertion) ([]byte, error) {
	id, err := decodeB64(a.RawID, maxCredentialIDLen)
	if err != nil || len(id) == 0 {
		return nil, fmt.Errorf("%w: rawId", ErrAssertion)
	}

	reported, err := decodeBase64URL(a.ID)
	if err != nil || !bytes.Equal(reported, id) {
		return nil, fmt.Errorf("%w: %w", ErrAssertion, errIDMismatch)
	}

	return id, nil
}

// checkAssertionAuthData checks the 37 bytes of authenticator data and returns
// its flags. Attested credential data and extension data are refused, which is
// what makes the length exact: we request no extensions, and an assertion has
// no attested credential data.
func checkAssertionAuthData(data []byte, rp RelyingParty) (Flags, error) {
	if len(data) != fixedAuthData {
		return 0, fmt.Errorf("%w: %w (%d)", ErrAuthData, errAssertionLength, len(data))
	}

	want := sha256.Sum256([]byte(rp.ID))
	if !bytes.Equal(data[:rpIDHashLen], want[:]) {
		return 0, fmt.Errorf("%w: %w", ErrAuthData, errRPIDHash)
	}

	flags := Flags(data[rpIDHashLen])

	err := checkAssertionFlags(flags)
	if err != nil {
		return 0, err
	}

	return flags, nil
}

// checkAssertionFlags enforces what we require of an assertion's flags: user
// presence and verification (we ask for both, and the flags are signed, so
// this is the one place user verification can be trusted), no attested
// credential data, no extension data, reserved bits clear, and consistent
// backup bits. Whether backup eligibility matches the stored credential is
// checked by Verify.
func checkAssertionFlags(flags Flags) error {
	switch {
	case flags&FlagUserPresent == 0:
		return fmt.Errorf("%w: user presence not set", ErrAuthData)
	case flags&FlagUserVerified == 0:
		return fmt.Errorf("%w: %w", ErrAuthData, errUVNotCarried)
	case flags&flagAttestedCredentialData != 0:
		return fmt.Errorf("%w: unexpected attested credential data", ErrAuthData)
	case flags&flagExtensionData != 0:
		return fmt.Errorf("%w: unexpected extension data", ErrAuthData)
	case flags&flagReservedMask != 0:
		return fmt.Errorf("%w: reserved flag bits set", ErrAuthData)
	case flags&FlagBackupState != 0 && flags&FlagBackupEligible == 0:
		return fmt.Errorf("%w: backup state set without backup eligibility", ErrAuthData)
	}

	return nil
}

// decodeUserHandle requires the response's user handle to be present. A
// discoverable login always returns one, and Verify compares it with the
// account's, which is how a credential that was moved between accounts is
// noticed.
func decodeUserHandle(reported string) ([]byte, error) {
	if reported == "" {
		return nil, fmt.Errorf("%w: %w", ErrAssertion, errNoUserHandle)
	}

	handle, err := decodeB64(reported, MaxUserHandle)
	if err != nil {
		return nil, fmt.Errorf("%w: userHandle: %w", ErrAssertion, err)
	}

	return handle, nil
}

// storedKey parses the canonical COSE_Key registration stored into an ECDSA
// public key. It was validated when it was written, and is validated again here
// because the database is not the code: a row that is not a P-256 point is
// refused, not trusted.
//
// The decoding options are a parameter so that the failure to build a decoder,
// which no valid option set causes, is reachable from a test.
func storedKey(opts cbor.DecOptions, cose []byte) (*ecdsa.PublicKey, error) {
	dec, err := newDecoder(opts, cbor.CTAP2EncOptions())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, err)
	}

	var key coseKey

	err = dec.unmarshal(cose, &key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, err)
	}

	err = key.validate()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, err)
	}

	point := make([]byte, 0, 1+2*coordinateLen)
	point = append(point, uncompressedByte)
	point = append(point, key.X...)
	point = append(point, key.Y...)

	// validate has proved the point is on the curve, so this parse cannot
	// fail; it is the conversion to the type ecdsa verifies with.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	// coverage:ignore: validate (ecdh.NewPublicKey) has already refused every point this would
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, err)
	}

	return pub, nil
}

// verifyES256 checks an ECDSA P-256 signature over SHA-256(signed). The
// standard library's ASN.1 verifier accepts only strict DER (it refuses
// trailing bytes, non-minimal lengths, indefinite lengths and padded integers),
// so a signature has exactly one accepted spelling and no second parser is
// needed here; a test pins that property.
//
// Low-S is not required: WebAuthn does not ask for it and authenticators do not
// promise it. The signature is not used as an identifier, so malleability is
// harmless; the challenge's single use is what stops a replay.
func verifyES256(key *ecdsa.PublicKey, signed, signature []byte) error {
	digest := sha256.Sum256(signed)

	if !ecdsa.VerifyASN1(key, digest[:], signature) {
		return fmt.Errorf("%w: %w", ErrAssertion, errSignature)
	}

	return nil
}
