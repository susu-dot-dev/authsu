package login

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"
	"testing/iotest"
	"time"
)

var errNoEntropy = errors.New("no entropy")

func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// testNow is the fixed time the tests run at.
func testNow() time.Time { return time.Date(2026, time.November, 16, 12, 0, 0, 0, time.UTC) }

// counterEntropy is deterministic entropy: each byte is the previous plus one,
// starting at 1.
func counterEntropy() io.Reader {
	next := byte(1)

	return readerFunc(func(p []byte) (int, error) {
		for i := range p {
			p[i] = next
			next++
		}

		return len(p), nil
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func mustMint(t *testing.T) []byte {
	t.Helper()

	challenge, err := mint(testKey(), counterEntropy(), testNow().Add(ChallengeTTL))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	return challenge
}

func TestChallengeLayout(t *testing.T) {
	t.Parallel()

	challenge := mustMint(t)

	if len(challenge) != challengeLen {
		t.Errorf("challenge is %d bytes, want %d", len(challenge), challengeLen)
	}

	if challenge[0] != challengeVersion {
		t.Errorf("version = %d, want %d", challenge[0], challengeVersion)
	}

	// The nonce travels in the clear. It is not secret: it is what makes the
	// challenge unique.
	nonce := challenge[versionLen+expiresLen : stateLen]
	if len(nonce) != NonceLen {
		t.Errorf("nonce is %d bytes, want %d", len(nonce), NonceLen)
	}

	// WebAuthn asks for at least 16 random bytes per challenge.
	if NonceLen < 16 {
		t.Errorf("NonceLen = %d, want at least 16", NonceLen)
	}
}

func TestOpenAcceptsWhatMintMade(t *testing.T) {
	t.Parallel()

	err := open(testKey(), mustMint(t), testNow())
	if err != nil {
		t.Errorf("open: %v", err)
	}
}

func TestEveryChallengeIsUnique(t *testing.T) {
	t.Parallel()

	// Nothing in a challenge is random except the nonce, so uniqueness is only
	// as good as the entropy. Two begins must never produce the same bytes.
	entropy := counterEntropy()

	first, err := mint(testKey(), entropy, testNow().Add(ChallengeTTL))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	second, err := mint(testKey(), entropy, testNow().Add(ChallengeTTL))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Error("two challenges are identical")
	}
}

// openCase is a challenge, a key and a time, and the error open must give.
type openCase struct {
	challenge []byte
	key       []byte
	now       time.Time
	want      error
}

func runOpenCases(t *testing.T, tests map[string]openCase) {
	t.Helper()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := open(tt.key, tt.challenge, tt.now)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// tampered returns the minted challenge with edit applied.
func tampered(t *testing.T, edit func([]byte)) []byte {
	t.Helper()

	challenge := bytes.Clone(mustMint(t))
	edit(challenge)

	return challenge
}

func TestOpenRefusesAMalformedChallenge(t *testing.T) {
	t.Parallel()

	runOpenCases(t, map[string]openCase{
		"empty": {challenge: nil, key: testKey(), now: testNow(), want: errChallengeLength},
		"too short": {
			challenge: mustMint(t)[:challengeLen-1], key: testKey(), now: testNow(),
			want: errChallengeLength,
		},
		"too long": {
			challenge: slices.Concat(mustMint(t), []byte{0}), key: testKey(), now: testNow(),
			want: errChallengeLength,
		},
		"unknown version": {
			challenge: tampered(t, func(c []byte) { c[0] = 2 }), key: testKey(), now: testNow(),
			want: errChallengeVersion,
		},
	})
}

func TestOpenRefusesAChallengeWeDidNotSign(t *testing.T) {
	t.Parallel()

	runOpenCases(t, map[string]openCase{
		"wrong key": {
			challenge: mustMint(t), key: bytes.Repeat([]byte{0x43}, 32), now: testNow(),
			want: errChallengeTag,
		},
		"altered nonce": {
			challenge: tampered(t, func(c []byte) { c[versionLen+expiresLen] ^= 1 }), key: testKey(), now: testNow(),
			want: errChallengeTag,
		},
		"altered tag": {
			challenge: tampered(t, func(c []byte) { c[challengeLen-1] ^= 1 }), key: testKey(), now: testNow(),
			want: errChallengeTag,
		},
		// An attacker-chosen expiry must fail its tag, never be read: a
		// challenge that is both forged and expired is reported as forged.
		"altered expiry": {
			challenge: tampered(t, func(c []byte) { c[versionLen+expiresLen-1] ^= 0xff }), key: testKey(), now: testNow(),
			want: errChallengeTag,
		},
	})
}

func TestOpenRefusesAnExpiredChallenge(t *testing.T) {
	t.Parallel()

	runOpenCases(t, map[string]openCase{
		"expired": {
			challenge: mustMint(t), key: testKey(), now: testNow().Add(ChallengeTTL),
			want: errChallengeExpired,
		},
		"long after expiry": {
			challenge: mustMint(t), key: testKey(), now: testNow().Add(24 * time.Hour),
			want: errChallengeExpired,
		},
	})
}

// TestOpenRefusesAnExpiryBeyondTheTTL covers the defence for a leaked key: a
// challenge that is validly signed but expires further ahead than begin could
// have set. A session must outlive its challenge for single use to hold.
func TestOpenRefusesAnExpiryBeyondTheTTL(t *testing.T) {
	t.Parallel()

	far, err := mint(testKey(), counterEntropy(), testNow().Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	err = open(testKey(), far, testNow())
	if !errors.Is(err, errChallengeFuture) {
		t.Errorf("err = %v, want %v", err, errChallengeFuture)
	}

	// Exactly the TTL ahead is what begin itself writes, so it is accepted.
	edge, err := mint(testKey(), counterEntropy(), testNow().Add(ChallengeTTL))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	err = open(testKey(), edge, testNow())
	if err != nil {
		t.Errorf("a challenge expiring exactly one TTL ahead was refused: %v", err)
	}
}

func TestMintFailsWhenEntropyFails(t *testing.T) {
	t.Parallel()

	_, err := mint(testKey(), iotest.ErrReader(errNoEntropy), testNow().Add(ChallengeTTL))
	if !errors.Is(err, errEntropy) {
		t.Errorf("err = %v, want %v", err, errEntropy)
	}
}

func TestMintFailsOnShortEntropy(t *testing.T) {
	t.Parallel()

	_, err := mint(testKey(), bytes.NewReader(make([]byte, NonceLen-1)), testNow().Add(ChallengeTTL))
	if !errors.Is(err, errEntropy) {
		t.Errorf("err = %v, want %v", err, errEntropy)
	}
}

func TestExpiryRoundTripsAndClamps(t *testing.T) {
	t.Parallel()

	state := make([]byte, stateLen)

	putExpiry(state, testNow())

	if got := expiry(state); !got.Equal(testNow()) {
		t.Errorf("expiry = %v, want %v", got, testNow())
	}

	// A time before the epoch is written as zero, which is already expired.
	putExpiry(state, time.Unix(-5, 0))

	if got := expiry(state); !got.Equal(time.Unix(0, 0)) {
		t.Errorf("expiry before the epoch = %v, want the epoch", got)
	}

	// A seconds value beyond what a Duration can hold is clamped, not wrapped.
	for i := versionLen; i < versionLen+expiresLen; i++ {
		state[i] = 0xff
	}

	if got := expiry(state); got.Before(testNow()) {
		t.Errorf("a maximal expiry wrapped to %v", got)
	}
}

func TestLoginKeyIsNotRegistrationsKey(t *testing.T) {
	t.Parallel()

	// A challenge minted for one ceremony must never verify as the other, so
	// the two derive their keys from distinct contexts. Registration's context
	// is repeated here so a change to either is noticed.
	const registrationContext = "authsu/registration-challenge/v1"

	if derivationContext == registrationContext {
		t.Error("login and registration derive their challenge keys with the same context")
	}
}
