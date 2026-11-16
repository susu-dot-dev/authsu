package webauthn

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// COSE constants (RFC 9053) for the one key type authsu accepts: ES256, an
// ECDSA P-256 public key with SHA-256.
const (
	coseKeyTypeEC2   = 2  // kty: EC2
	coseAlgES256     = -7 // alg: ECDSA w/ SHA-256
	coseCurveP256    = 1  // crv: P-256
	coordinateLen    = 32 // bytes per P-256 coordinate
	uncompressedByte = 0x04
)

var (
	errKeyType      = errors.New("not an EC2 key")
	errKeyAlgorithm = errors.New("not ES256")
	errKeyCurve     = errors.New("not curve P-256")
	errCoordinate   = errors.New("coordinate is not 32 bytes")
	errTrailingKey  = errors.New("bytes after the public key")
)

// coseKey is a COSE_Key for ES256. The integer labels are fixed by RFC 9053
// (kty 1, alg 3, crv -1, x -2, y -3). A label not named here is an error under
// the strict profile, so a key carrying parameters we do not understand
// (key_ops, kid, a private key "d") is rejected, not trimmed.
//
// Every member is required. Pointers distinguish a missing member from the
// zero value, which is a valid-looking but meaningless integer.
type coseKey struct {
	KeyType   *int64 `cbor:"1,keyasint"`
	Algorithm *int64 `cbor:"3,keyasint"`
	Curve     *int64 `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}

// parseCOSEKey parses the credential public key that ends authenticator data.
// It must be a single COSE_Key in CTAP2 canonical form and the last thing in
// the data. It returns the key re-encoded canonically, which is what gets
// stored: the stored bytes are ones we produced from validated parts, and are
// equal to the client's.
func parseCOSEKey(dec decoder, data []byte) ([]byte, error) {
	var key coseKey

	rest, err := dec.unmarshalFirst(data, &key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, err)
	}

	// ED (extension data) is rejected by the flags check, so nothing may
	// follow the key.
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, errTrailingKey)
	}

	err = key.validate()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, err)
	}

	canonical, err := encodeCanonical(cbor.CTAP2EncOptions(), key)
	if err != nil {
		return nil, err
	}

	// The key is the whole of data (nothing may follow it), and every member
	// it may have is one we re-encoded, so the client's bytes are canonical
	// exactly when they equal ours (section 2.4).
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, errNotCanonical)
	}

	return canonical, nil
}

// validate checks the key is ES256 on P-256 with well-formed coordinates that
// form a point on the curve.
func (k coseKey) validate() error {
	if k.KeyType == nil || *k.KeyType != coseKeyTypeEC2 {
		return errKeyType
	}

	if k.Algorithm == nil || *k.Algorithm != coseAlgES256 {
		return errKeyAlgorithm
	}

	if k.Curve == nil || *k.Curve != coseCurveP256 {
		return errKeyCurve
	}

	if len(k.X) != coordinateLen || len(k.Y) != coordinateLen {
		return errCoordinate
	}

	// NewPublicKey rejects a point that is not on the curve and the point at
	// infinity, which is the invalid-curve attack's defence.
	point := make([]byte, 0, 1+2*coordinateLen)
	point = append(point, uncompressedByte)
	point = append(point, k.X...)
	point = append(point, k.Y...)

	_, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return fmt.Errorf("point is not on the curve: %w", err)
	}

	return nil
}

// encodeCanonical encodes value with opts, which are CTAP2 canonical in
// production. Taking both as parameters keeps the two failure modes (an invalid
// option set, an unencodable value) reachable from a test; for a coseKey and
// the production options neither can happen.
func encodeCanonical(opts cbor.EncOptions, value any) ([]byte, error) {
	mode, err := opts.EncMode()
	if err != nil {
		return nil, fmt.Errorf("%w: build encoder: %w", ErrPublicKey, err)
	}

	out, err := mode.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %w", ErrPublicKey, err)
	}

	return out, nil
}
