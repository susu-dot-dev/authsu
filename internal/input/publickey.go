package input

import (
	"encoding/base64"

	"github.com/susu-dot-dev/authsu/internal/seal"
)

// The public key a client sends so that a secret in the response can be sealed
// to it (internal/seal). It is never stored.

// PublicKeyLen is the length of a PublicKey as the client spells it: the
// base64url of seal.RecipientLen (33) bytes, which is exactly 44 characters with
// no padding and no spare bits, so one key has one spelling.
const PublicKeyLen = 44

// CodeInvalidPublicKey is the error code of a public key that is refused.
const CodeInvalidPublicKey = "invalid_public_key"

const descInvalidPublicKey = "publicKey must be exactly 44 base64url characters: " +
	"the suite byte 1 and a 32-byte X25519 public key"

// PublicKey is the recipient a response's secret is sealed to. The zero value is
// no key: Present reports false for it, and a handler that finds one knows the
// client sent none.
type PublicKey struct {
	raw [seal.RecipientLen]byte
	set bool
}

// ParsePublicKey accepts exactly PublicKeyLen characters of the base64url
// alphabet that decode to the suite byte seal.SuiteX25519 followed by 32 bytes,
// and refuses everything else. Padding, the standard alphabet, other lengths and
// any other suite are refused rather than corrected.
//
// It checks the shape and not the key: the 32 bytes of a point of low order
// parse, and seal.Seal refuses them. A handler therefore seals before it
// writes anything, so a key that cannot be sealed to creates nothing.
func ParsePublicKey(raw string) (PublicKey, error) {
	if len(raw) != PublicKeyLen || !base64URL(raw) {
		return PublicKey{}, refuse(CodeInvalidPublicKey, descInvalidPublicKey)
	}

	var decoded [seal.RecipientLen]byte

	// 44 base64url characters are 33 bytes with no spare bits, so the decode
	// cannot fail here; the error is part of the condition so that a decoder
	// change could never be taken for a key.
	_, err := base64.RawURLEncoding.Decode(decoded[:], []byte(raw))
	if err != nil || decoded[0] != seal.SuiteX25519 {
		return PublicKey{}, refuse(CodeInvalidPublicKey, descInvalidPublicKey)
	}

	return PublicKey{raw: decoded, set: true}, nil
}

// Present reports whether the client sent a key.
func (k PublicKey) Present() bool { return k.set }

// Recipient returns the suite byte and the key, which is what seal.Seal takes.
// It is nil for the zero value.
func (k PublicKey) Recipient() []byte {
	if !k.set {
		return nil
	}

	return k.raw[:]
}

// String returns the key exactly as it was parsed, and "" for the zero value.
func (k PublicKey) String() string {
	if !k.set {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(k.raw[:])
}
