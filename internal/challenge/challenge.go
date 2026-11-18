// Package challenge creates and opens the stateless, signed challenges that
// start a WebAuthn ceremony. Registration and login share it: both need a
// fresh, unforgeable, self-expiring challenge that the server can issue
// without writing anything, and the two copies of this code that used to exist
// had drifted apart.
//
// # Layout (version 1)
//
//	state     = version(1) || expires_unix_be(8) || nonce(32)
//	tag       = HMAC-SHA256(key, state || SHA256(ad_1) || SHA256(ad_2) || ...)
//	challenge = state || tag
//
// The challenge is Len bytes, whatever the associated data. It is opaque to
// the browser, which echoes it back inside clientDataJSON.
//
// # Why it is shaped this way
//
//   - Stateless. Issuing a challenge writes nothing, so anyone can ask for as
//     many as they like without filling a table that then needs expiry and
//     cleanup. The challenge itself carries the state, signed by the server.
//     Single use is not this package's job: each ceremony enforces it where it
//     writes (an account's unique user handle at registration, a unique grant
//     on the session row at login).
//   - The nonce is the entropy. WebAuthn asks for at least 16 random bytes per
//     challenge; nothing else in the layout is random (the version is a
//     constant, the expiry is a time, the tag is deterministic), so the nonce
//     is what makes every challenge unique. NonceLen is 32, as in the spec's
//     examples. A caller may also use the nonce for something that must be
//     random and fit in 64 bytes, such as a WebAuthn user handle.
//   - The expiry is inside the signed state, so a client cannot extend it. It
//     is read only after the tag verifies, so an attacker-chosen expiry is
//     never acted on, and a challenge that is both forged and expired is
//     reported as forged.
//   - Open also refuses an expiry further ahead than maxTTL from now. That is
//     the defence for a leaked key: no challenge Create made for this ceremony
//     could expire later, so a forged one with a distant expiry is refused even
//     though its tag is valid. Login depends on it, because a login challenge
//     must be shorter-lived than the session row that records its single use.
//   - The version byte lets the layout change later (to bind more data, say)
//     without ambiguity about how to parse challenges still in flight. It is
//     checked before the tag, so an unknown layout is never interpreted.
//   - A fixed binary layout, not a JWT or JSON, keeps the challenge small and
//     avoids parsing a general-purpose token format in a security-critical
//     place.
//
// # Associated data
//
// Associated data is mixed into the tag but is not part of the challenge: the
// verifier must supply it again, and a challenge created for different data
// does not open. Registration uses this to bind a ceremony to the invitation
// code and the account name it was started for; the raw code never travels in
// the challenge, only its influence on the tag does. Login binds nothing.
//
// Each item is replaced by its SHA-256 before it is mixed in. Plain
// concatenation would let ("ab", "c") and ("a", "bc") produce the same MAC
// input; hashed items are fixed-width, so item boundaries are unambiguous and
// the split cannot be moved. For the same reason the number of items matters:
// every item contributes exactly one 32-byte block, so a different count gives
// MAC input of a different length (() differs from ("") and ("a") from
// ("a", "")). Hashing also keeps raw secrets out of the MAC input.
//
// # Keys
//
// Callers pass a key derived for their own ceremony (see internal/config), so a
// challenge created for one ceremony can never open as another, even if a
// later check of the ceremony type were wrong.
//
// A key must be exactly KeyLen bytes, which is what the derivation produces.
// HMAC would accept any length (padding a short key with zeros, so that an
// empty key, a one-byte key and a key of zeros of any shorter length are
// weaker than they look), so a key of any other length is not trusted to have
// come from a sound derivation, and Create and Open refuse it with ErrKey
// rather than sign or verify with it.
package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// NonceLen is the length of the random nonce. WebAuthn asks for at least
	// 16 bytes of entropy; 32 matches the spec's examples.
	NonceLen = 32

	// KeyLen is the length of the key a challenge is signed with: the 32 bytes
	// of a derived key (see internal/config), the size of the HMAC's hash.
	KeyLen = sha256.Size

	// Len is the length of every challenge: the version, the expiry, the
	// nonce and the tag.
	Len = stateLen + tagLen

	version byte = 1

	versionLen = 1
	expiresLen = 8
	nonceStart = versionLen + expiresLen
	stateLen   = nonceStart + NonceLen
	tagLen     = sha256.Size
)

// ErrInvalid is wrapped by every error Open returns: the challenge is
// malformed, has an unknown version, was not signed by this key for exactly
// this associated data, has expired, or expires further ahead than allowed.
// It is a verdict on the caller's input. Callers treat every cause alike; the
// wrapped specific cause is for logs only.
var ErrInvalid = errors.New("challenge is invalid")

// ErrKey means the key is not KeyLen bytes. It is a server fault, not invalid
// input: the key comes from the deployment's derivation, never from a client.
// It does not wrap ErrInvalid.
var ErrKey = errors.New("challenge key is not 32 bytes")

// ErrEntropy means Create could not read its nonce. It is a server fault, not
// invalid input, and so does not wrap ErrInvalid.
var ErrEntropy = errors.New("read entropy for challenge")

// Specific causes, wrapped beside ErrInvalid so logs can tell them apart.
var (
	errLength  = errors.New("challenge has the wrong length")
	errVersion = errors.New("challenge has an unknown version")
	errTag     = errors.New("challenge signature does not match")
	errExpired = errors.New("challenge has expired")
	errFuture  = errors.New("challenge expires implausibly far ahead")
)

// Create makes a challenge that expires at expires, bound to ad, and returns
// it with the random nonce it carries. The nonce is read from entropy. The two
// returned slices do not share memory with each other or with anything the
// package keeps.
//
// The expiry is stored as whole seconds, rounded down. A time before the Unix
// epoch is stored as zero, which is already expired.
func Create(key []byte, entropy io.Reader, expires time.Time, ad ...[]byte) ([]byte, []byte, error) {
	if len(key) != KeyLen {
		return nil, nil, fmt.Errorf("%w: got %d", ErrKey, len(key))
	}

	buf := make([]byte, stateLen, Len)
	buf[0] = version

	putExpiry(buf, expires)

	_, err := io.ReadFull(entropy, buf[nonceStart:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrEntropy, err)
	}

	// buf has room for the tag, so this appends in place: one allocation, and
	// the nonce is copied out so the two results never share memory.
	buf = append(buf, sign(key, buf, ad)...)

	return buf, bytes.Clone(buf[nonceStart:stateLen]), nil
}

// Open verifies challenge at now against ad and returns the nonce it carries.
// A key that is not KeyLen bytes is ErrKey, not ErrInvalid. It checks, in
// order, the length, the version and the tag (in constant
// time); only then is the expiry read. It is refused when now is at or after
// the expiry, and when the expiry is more than maxTTL after now. Every
// failure about the challenge wraps ErrInvalid. The returned nonce is a copy.
func Open(key, challenge []byte, now time.Time, maxTTL time.Duration, ad ...[]byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("%w: got %d", ErrKey, len(key))
	}

	if len(challenge) != Len {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, errLength)
	}

	if challenge[0] != version {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, errVersion)
	}

	state, tag := challenge[:stateLen], challenge[stateLen:]

	if !hmac.Equal(tag, sign(key, state, ad)) {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, errTag)
	}

	// The tag matched, so these are bytes Create wrote.
	expires := expiry(state)

	if !now.Before(expires) {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, errExpired)
	}

	if expires.After(now.Add(maxTTL)) {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, errFuture)
	}

	return bytes.Clone(state[nonceStart:]), nil
}

// putExpiry writes expires into state as whole seconds since the epoch, held
// as a uint64 so no signed value is ever converted: a time before the epoch is
// written as zero, which is already expired.
func putExpiry(state []byte, expires time.Time) {
	var seconds uint64

	if expires.After(time.Unix(0, 0)) {
		//nolint:gosec // the After guard makes the duration positive, so the conversion is exact
		seconds = uint64(expires.Sub(time.Unix(0, 0)) / time.Second)
	}

	binary.BigEndian.PutUint64(state[versionLen:], seconds)
}

// expiry reads the expiry written by putExpiry. A Duration holds about 292
// years, so seconds beyond that are clamped to the latest time a Duration can
// express; Create never writes one, so only a forged value could reach the
// clamp, and a forged value fails its tag first. Clamping, rather than
// converting, keeps a huge value from wrapping to a negative duration.
func expiry(state []byte) time.Time {
	const maxSeconds = uint64(1<<63-1) / uint64(time.Second)

	seconds := min(binary.BigEndian.Uint64(state[versionLen:]), maxSeconds)

	return time.Unix(0, 0).Add(time.Duration(seconds) * time.Second)
}

// sign computes the tag over state and ad. Each item is hashed first, so items
// are fixed width and neither their boundaries nor their number can be moved
// without changing the MAC input (see the package documentation).
func sign(key, state []byte, ad [][]byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(state)

	for _, item := range ad {
		sum := sha256.Sum256(item)

		mac.Write(sum[:])
	}

	return mac.Sum(nil)
}
