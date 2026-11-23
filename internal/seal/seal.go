// Package seal encrypts a secret to a public key the client sent with its
// request, so that a response can carry the secret through a place that logs
// responses (a model's context, a provider's logs) without exposing it.
//
// The aim is narrow: the secret must not appear in plaintext in a response. The
// caller holds the matching private key and is the only one who can read the
// result. Sender authentication, replay and substitution of the value are not
// goals here: they would be as possible with the plaintext response.
//
// # The scheme
//
// HPKE (RFC 9180) in base mode, from the standard library: DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256 and AES-128-GCM, one message per call. Only the
// recipient's public key is needed, and every call makes a fresh ephemeral
// key, so the client may use a new key pair for every request.
//
// # The wire formats
//
// A recipient, as the client sends it, is a suite byte (SuiteX25519) followed
// by the 32-byte X25519 public key, 33 bytes, which is exactly 44 base64url
// characters with no padding and no spare bits, so every recipient has one
// spelling. The suite byte makes a later change of algorithm a new value
// instead of a guess.
//
// A sealed secret is base64url of the same suite byte, the 32-byte ephemeral
// public key and the ciphertext with its 16-byte tag.
package seal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"
)

// Sizes of the formats.
const (
	// SuiteX25519 is the suite byte of the one suite: DHKEM(X25519,
	// HKDF-SHA256), HKDF-SHA256 and AES-128-GCM.
	SuiteX25519 byte = 1

	// KeyLen is the length of an X25519 public key.
	KeyLen = 32

	// RecipientLen is the length of a recipient: the suite byte and the key.
	RecipientLen = 1 + KeyLen
)

// info binds a sealed secret to this use, so a blob made for another purpose
// with the same keys does not open here.
const info = "authsu secret v1"

// ErrRecipient is returned for a recipient that cannot be sealed to: one of the
// wrong length or suite, or a public key that is not a usable X25519 point (the
// all-zero key and the other low-order points among them). The recipient is the
// only input that decides whether a seal can fail, so a caller may treat this
// as the client's mistake.
var ErrRecipient = errors.New("seal: invalid recipient")

// Seal encrypts plaintext to recipient and returns the sealed secret as
// unpadded base64url.
//
// A recipient that cannot be sealed to is ErrRecipient, and nothing is
// returned. The randomness is the standard library's: crypto/hpke reads its
// own source and ignores any injected reader, so callers that need
// determinism in tests inject Seal itself, as a dependency, and not entropy.
func Seal(recipient []byte, plaintext string) (string, error) {
	if len(recipient) == 0 || recipient[0] != SuiteX25519 {
		return "", ErrRecipient
	}

	public, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(recipient[1:])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrRecipient, err)
	}

	sealed, err := hpke.Seal(public, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(info), []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrRecipient, err)
	}

	return base64.RawURLEncoding.EncodeToString(append([]byte{SuiteX25519}, sealed...)), nil
}
