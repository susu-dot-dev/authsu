package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const (
	// MaxAttestationObject caps the attestation object before it is parsed. A
	// "none" attestation for an ES256 key is about 130 bytes.
	MaxAttestationObject = 4096

	// maxCredentialIDLen is the WebAuthn limit on a credential id (section
	// 4, "Credential ID").
	maxCredentialIDLen = 1023

	// authenticator data layout (section 6.1): rpIdHash, flags, signCount.
	rpIDHashLen    = sha256.Size
	flagsLen       = 1
	signCountLen   = 4
	aaguidLen      = 16
	credIDLenBytes = 2
	fixedAuthData  = rpIDHashLen + flagsLen + signCountLen
	attestedHeader = aaguidLen + credIDLenBytes
)

// noneFormat is the only attestation statement format accepted.
const noneFormat = "none"

var (
	errNotNoneFormat = errors.New(`attestation format is not "none"`)
	errStatement     = errors.New("attestation statement is not empty")
	errIDMismatch    = errors.New("credential id does not match id and rawId")
	errRPIDHash      = errors.New("rp id hash does not match")
)

// Registration is the browser's answer to a creation ceremony, as sent by
// PublicKeyCredential.toJSON(): members are base64url without padding.
type Registration struct {
	// ID and RawID are the credential id; they must agree.
	ID    string
	RawID string
	// ClientDataJSON and AttestationObject are the response members.
	ClientDataJSON    string
	AttestationObject string
	// Transports are the client's transport hints, in any order and possibly
	// with repeats; Verify stores them sorted and unique.
	Transports []string
}

// Verified is a registration that passed every check.
type Verified struct {
	// Challenge is the challenge the browser echoed in clientDataJSON, decoded.
	// The caller must still check that it is one it issued.
	Challenge []byte
	// Credential is what to store.
	Credential Credential
}

// Verify checks a registration response against rp and returns the credential.
//
// It checks the client data (type, origin, no cross-origin), the attestation
// object (CBOR strictly decoded, format "none" with an empty statement) and
// the authenticator data (rp id hash, flags, attested credential data, no
// extensions, no trailing bytes), and that the credential public key is a
// valid ES256 key. It does not check the challenge; see ParseClientData.
func Verify(reg Registration, rp RelyingParty) (Verified, error) {
	return verifyWith(strictOptions(), reg, rp)
}

// verifyWith is Verify with the CBOR decoding options injected, so that the
// failure to build a decoder, which no valid option set causes, is reachable
// from a test.
func verifyWith(opts cbor.DecOptions, reg Registration, rp RelyingParty) (Verified, error) {
	dec, err := newDecoder(opts, cbor.CTAP2EncOptions())
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrAttestation, err)
	}

	clientData, err := decodeB64(reg.ClientDataJSON, MaxClientDataJSON)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: clientDataJSON: %w", ErrClientData, err)
	}

	challenge, _, err := ParseClientData(clientData, rp)
	if err != nil {
		return Verified{}, err
	}

	raw, err := decodeB64(reg.AttestationObject, MaxAttestationObject)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: attestationObject: %w", ErrAttestation, err)
	}

	authData, err := parseAttestationObject(dec, raw)
	if err != nil {
		return Verified{}, err
	}

	credential, err := parseAuthData(dec, authData, rp)
	if err != nil {
		return Verified{}, err
	}

	err = checkCredentialID(credential.ID, reg)
	if err != nil {
		return Verified{}, err
	}

	credential.Transports, err = canonicalTransports(reg.Transports)
	if err != nil {
		return Verified{}, err
	}

	return Verified{Challenge: challenge, Credential: credential}, nil
}

// decodeB64 decodes base64url (see decodeBase64URL), bounding the decoded size
// first so a huge string is not decoded just to be refused.
func decodeB64(encoded string, maxDecoded int) ([]byte, error) {
	if base64.RawURLEncoding.DecodedLen(len(encoded)) > maxDecoded {
		return nil, errTooLarge
	}

	return decodeBase64URL(encoded)
}

var (
	errTooLarge  = errors.New("too large")
	errLineBreak = errors.New("line break in base64url")
)

// decodeBase64URL decodes the base64url encoding as WebAuthn defines it
// (section 3): the URL-safe alphabet, no padding, and no line breaks or other
// characters. Go's decoder skips CR and LF even in strict mode, so they are
// refused first; strict mode then refuses non-zero unused bits in the last
// character. Each value therefore has exactly one accepted spelling.
func decodeBase64URL(encoded string) ([]byte, error) {
	if strings.ContainsAny(encoded, "\r\n") {
		return nil, errLineBreak
	}

	out, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode base64url: %w", err)
	}

	return out, nil
}

// attestationObject is the CBOR map of section 6.5. attStmt is decoded into an
// empty-struct-compatible map so that a non-empty statement is detectable.
type attestationObject struct {
	Fmt      string         `cbor:"fmt"`
	AttStmt  map[string]any `cbor:"attStmt"`
	AuthData []byte         `cbor:"authData"`
}

// parseAttestationObject decodes the attestation object, which must be in
// CTAP2 canonical form, and returns its authData, after requiring format
// "none" with an empty statement. A missing or null attStmt is read as the
// empty statement.
func parseAttestationObject(dec decoder, raw []byte) ([]byte, error) {
	err := dec.requireCanonical(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestation, err)
	}

	var object attestationObject

	err = dec.unmarshal(raw, &object)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestation, err)
	}

	if object.Fmt != noneFormat {
		return nil, fmt.Errorf("%w: %w: %q", ErrAttestation, errNotNoneFormat, object.Fmt)
	}

	if len(object.AttStmt) != 0 {
		return nil, fmt.Errorf("%w: %w", ErrAttestation, errStatement)
	}

	return object.AuthData, nil
}

// parseAuthData parses authenticator data for a registration (section 6.1 and
// 6.5.1) and verifies its rp id hash and flags.
func parseAuthData(dec decoder, data []byte, rp RelyingParty) (Credential, error) {
	if len(data) < fixedAuthData+attestedHeader {
		return Credential{}, fmt.Errorf("%w: too short (%d bytes)", ErrAuthData, len(data))
	}

	want := sha256.Sum256([]byte(rp.ID))
	if !bytes.Equal(data[:rpIDHashLen], want[:]) {
		return Credential{}, fmt.Errorf("%w: %w", ErrAuthData, errRPIDHash)
	}

	flags := Flags(data[rpIDHashLen])

	err := checkFlags(flags)
	if err != nil {
		return Credential{}, err
	}

	// signCount (4 bytes) is not kept: it is not meaningful at registration,
	// and many authenticators (all synced passkeys) always report zero.
	_ = binary.BigEndian.Uint32(data[rpIDHashLen+flagsLen:])

	rest := data[fixedAuthData:]

	var aaguid [aaguidLen]byte

	copy(aaguid[:], rest[:aaguidLen])

	idLen := int(binary.BigEndian.Uint16(rest[aaguidLen:]))
	rest = rest[attestedHeader:]

	if idLen == 0 || idLen > maxCredentialIDLen || idLen > len(rest) {
		return Credential{}, fmt.Errorf("%w: credential id length %d", ErrAuthData, idLen)
	}

	id := bytes.Clone(rest[:idLen])

	key, err := parseCOSEKey(dec, rest[idLen:])
	if err != nil {
		return Credential{}, err
	}

	return Credential{
		ID:         id,
		PublicKey:  key,
		Flags:      flags,
		AAGUID:     aaguid,
		Transports: nil,
	}, nil
}

// checkFlags enforces what we require of the authenticator's flags: user
// presence and verification (we ask for both), attested credential data
// present, no extension data (we send no extensions), reserved bits clear, and
// the backup bits consistent (BS without BE is invalid, section 6.1.3).
func checkFlags(flags Flags) error {
	switch {
	case flags&FlagUserPresent == 0:
		return fmt.Errorf("%w: user presence not set", ErrAuthData)
	case flags&FlagUserVerified == 0:
		return fmt.Errorf("%w: user verification not set", ErrAuthData)
	case flags&flagAttestedCredentialData == 0:
		return fmt.Errorf("%w: no attested credential data", ErrAuthData)
	case flags&flagExtensionData != 0:
		return fmt.Errorf("%w: unexpected extension data", ErrAuthData)
	case flags&flagReservedMask != 0:
		return fmt.Errorf("%w: reserved flag bits set", ErrAuthData)
	case flags&FlagBackupState != 0 && flags&FlagBackupEligible == 0:
		return fmt.Errorf("%w: backup state set without backup eligibility", ErrAuthData)
	}

	return nil
}

// checkCredentialID requires the id in the authenticator data to equal both
// the id and the rawId the client reported, so a client cannot label a
// credential with an id the authenticator did not issue.
func checkCredentialID(id []byte, reg Registration) error {
	for _, reported := range []string{reg.ID, reg.RawID} {
		decoded, err := decodeBase64URL(reported)
		if err != nil || !bytes.Equal(decoded, id) {
			return fmt.Errorf("%w: %w", ErrAuthData, errIDMismatch)
		}
	}

	return nil
}

// Transport bounds. Real lists are one or two of the six values section 5.8.4
// defines, each at most 10 bytes; these leave room for values defined later and
// are far more than any client sends. Over a bound is refused, never truncated.
const (
	// MaxTransports is the most transports a registration may report. The
	// request decoder enforces the same number with a maxitems tag on the
	// field, so an oversized list is refused before it is allocated; a test
	// keeps the two equal.
	MaxTransports   = 100
	maxTransportLen = 32
	minPrintable    = 0x20
	maxPrintable    = 0x7e
)

var errTransports = errors.New("transports are not a short list of printable-ASCII strings")

// canonicalTransports bounds and normalises the client's transport hints.
// Section 5.2.1 describes them as "zero or more unique DOMStrings in
// lexicographical order" and says relying parties SHOULD accept and store
// unknown values, so unknown values pass. Real providers do not always send
// them sorted or unique, and the hints are not security-relevant, so a harmless
// ordering difference or repeat is not an error: the list is returned sorted
// with duplicates removed, as a conforming client would have sent it.
//
// What is refused is a list too large to be a hint (counted as sent, so a
// flood of repeats is refused too) or an entry that is empty, too long or not
// printable ASCII. The input is not modified. A nil or empty list is returned
// as is.
func canonicalTransports(transports []string) ([]string, error) {
	if len(transports) > MaxTransports {
		return nil, fmt.Errorf("%w: %w: %d entries", ErrTransports, errTransports, len(transports))
	}

	for _, transport := range transports {
		if len(transport) == 0 || len(transport) > maxTransportLen || !printableASCII(transport) {
			return nil, fmt.Errorf("%w: %w: %q", ErrTransports, errTransports, transport)
		}
	}

	if len(transports) == 0 {
		return transports, nil
	}

	canonical := slices.Clone(transports)
	slices.Sort(canonical)

	return slices.Compact(canonical), nil
}

// printableASCII reports whether s holds only printable ASCII (0x20 to 0x7e).
func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < minPrintable || s[i] > maxPrintable {
			return false
		}
	}

	return true
}
