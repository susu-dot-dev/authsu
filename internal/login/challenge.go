package login

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

// Challenge layout, version 1 (see docs/login_design.md):
//
//	state     = version || expires_at || nonce
//	signature = HMAC-SHA256(key, state)
//	challenge = state || signature
//
// Unlike registration's challenge it binds nothing else: a login begin takes no
// input, so there is no associated data. And unlike registration's it carries
// its own nonce, because there is no user handle to supply the entropy: the
// nonce is what makes every challenge unique, and WebAuthn asks for at least 16
// random bytes.
//
// The challenge is stateless. Its single use is enforced at finish, by the
// unique grant recorded on the session row in the same write that issues it.
const (
	challengeVersion byte = 1

	// NonceLen is the length of the random nonce. WebAuthn asks for at least
	// 16 bytes of entropy; 32 matches the spec's examples.
	NonceLen = 32

	versionLen   = 1
	expiresLen   = 8
	stateLen     = versionLen + expiresLen + NonceLen
	tagLen       = sha256.Size
	challengeLen = stateLen + tagLen
)

var (
	errChallengeLength  = errors.New("challenge has the wrong length")
	errChallengeVersion = errors.New("challenge has an unknown version")
	errChallengeTag     = errors.New("challenge signature does not match")
	errChallengeExpired = errors.New("challenge has expired")
	errChallengeFuture  = errors.New("challenge expires implausibly far ahead")
	errEntropy          = errors.New("read entropy")
)

// mint creates a challenge that expires at expires. The nonce is read from
// entropy.
func mint(key []byte, entropy io.Reader, expires time.Time) ([]byte, error) {
	state := make([]byte, stateLen, challengeLen)
	state[0] = challengeVersion

	putExpiry(state, expires)

	_, err := io.ReadFull(entropy, state[versionLen+expiresLen:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errEntropy, err)
	}

	return append(bytes.Clone(state), sign(key, state)...), nil
}

// open verifies challenge at now. It fails if the challenge is malformed, has an
// unknown version, was not signed by key, has expired, or expires further ahead
// than a challenge minted now could. The signature is checked before the expiry
// is read, so an attacker-chosen expiry is never acted on.
//
// The far-ahead bound is the defence for a leaked key: a session must outlive
// its challenge for single use to hold (the challenge's record is the session
// row), and a forged challenge with a distant expiry would break that. Anything
// beyond ChallengeTTL from now cannot have been minted by begin.
func open(key, challenge []byte, now time.Time) error {
	if len(challenge) != challengeLen {
		return errChallengeLength
	}

	if challenge[0] != challengeVersion {
		return errChallengeVersion
	}

	state, tag := challenge[:stateLen], challenge[stateLen:]

	if !hmac.Equal(tag, sign(key, state)) {
		return errChallengeTag
	}

	expires := expiry(state)

	if !now.Before(expires) {
		return errChallengeExpired
	}

	if expires.After(now.Add(ChallengeTTL)) {
		return errChallengeFuture
	}

	return nil
}

// putExpiry writes expires into state as whole seconds since the epoch, held as
// a uint64 so no signed value is ever converted: a time before the epoch is
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
// express; mint never writes one, so only a forged value could reach the clamp,
// and a forged value fails its tag first.
func expiry(state []byte) time.Time {
	const maxSeconds = uint64(1<<63-1) / uint64(time.Second)

	seconds := min(binary.BigEndian.Uint64(state[versionLen:]), maxSeconds)

	return time.Unix(0, 0).Add(time.Duration(seconds) * time.Second)
}

// sign computes the tag over state.
func sign(key, state []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(state)

	return mac.Sum(nil)
}
