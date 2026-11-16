package registration

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

// Challenge layout, version 1 (see docs/registration_design.md):
//
//	state     = version || expires_at || user_handle
//	signature = HMAC-SHA256(key, state || SHA-256(code) || SHA-256(name))
//	challenge = state || signature
//
// The invitation code and the name are inputs to the signature but are not in the
// challenge: they are associated data. The verifier must supply them again,
// and a challenge minted for a different code or name does not verify.
//
// The challenge is unique per begin because the user handle is 32 random
// bytes. That randomness is also what satisfies WebAuthn's requirement of at
// least 16 random bytes per challenge; nothing else in the challenge is random.
const (
	challengeVersion byte = 1

	// UserHandleLen is the length of the random user handle. WebAuthn allows
	// at most 64 bytes and recommends random ones.
	UserHandleLen = 32

	versionLen   = 1
	expiresLen   = 8
	stateLen     = versionLen + expiresLen + UserHandleLen
	tagLen       = sha256.Size
	challengeLen = stateLen + tagLen
)

var (
	errChallengeLength  = errors.New("challenge has the wrong length")
	errChallengeVersion = errors.New("challenge has an unknown version")
	errChallengeTag     = errors.New("challenge signature does not match")
	errChallengeExpired = errors.New("challenge has expired")
	errEntropy          = errors.New("read entropy")
)

// minted is a challenge and the user handle it commits to.
type minted struct {
	Challenge  []byte
	UserHandle []byte
}

// mint creates a challenge for code and name that expires at expires. The user
// handle is read from entropy.
func mint(key []byte, entropy io.Reader, expires time.Time, code, name string) (minted, error) {
	state := make([]byte, stateLen, challengeLen)
	state[0] = challengeVersion

	putExpiry(state, expires)

	handle := state[versionLen+expiresLen:]

	_, err := io.ReadFull(entropy, handle)
	if err != nil {
		return minted{}, fmt.Errorf("%w: %w", errEntropy, err)
	}

	userHandle := bytes.Clone(handle)
	challenge := append(bytes.Clone(state), sign(key, state, code, name)...)

	return minted{Challenge: challenge, UserHandle: userHandle}, nil
}

// open verifies challenge against code and name at now, and returns the user
// handle it commits to. It fails if the challenge is malformed, has an unknown
// version, was not signed by key for exactly this code and name, or has
// expired. The signature is checked before the expiry is read, so an
// attacker-chosen expiry is never acted on.
func open(key, challenge []byte, now time.Time, code, name string) ([]byte, error) {
	if len(challenge) != challengeLen {
		return nil, errChallengeLength
	}

	if challenge[0] != challengeVersion {
		return nil, errChallengeVersion
	}

	state, tag := challenge[:stateLen], challenge[stateLen:]

	if !hmac.Equal(tag, sign(key, state, code, name)) {
		return nil, errChallengeTag
	}

	// The tag matched, so these are the bytes mint wrote: a non-negative Unix
	// time. Reading it as unsigned and comparing in that domain avoids any
	// conversion.
	if !now.Before(expiry(state)) {
		return nil, errChallengeExpired
	}

	return bytes.Clone(state[versionLen+expiresLen:]), nil
}

// putExpiry writes expires into state as whole seconds since the epoch. The
// seconds are held as a uint64 so no signed value is ever converted: a time
// before the epoch is written as zero, which is already expired.
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
// express; mint never writes one, so only a forged value could reach the
// clamp, and a forged value fails its tag first.
func expiry(state []byte) time.Time {
	const maxSeconds = uint64(1<<63-1) / uint64(time.Second)

	seconds := min(binary.BigEndian.Uint64(state[versionLen:]), maxSeconds)

	return time.Unix(0, 0).Add(time.Duration(seconds) * time.Second)
}

// sign computes the tag. code and name are each replaced by their SHA-256
// before they are mixed in, so they are fixed width and two different (code,
// name) pairs can never produce the same byte string, which plain
// concatenation would allow ("ab"+"c" and "a"+"bc"). Hashing also keeps the
// raw invitation code out of the MAC input.
func sign(key, state []byte, code, name string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(state)
	codeSum := sha256.Sum256([]byte(code))
	nameSum := sha256.Sum256([]byte(name))

	mac.Write(codeSum[:])
	mac.Write(nameSum[:])

	return mac.Sum(nil)
}
