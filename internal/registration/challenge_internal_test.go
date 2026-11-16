package registration

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
	"time"
)

func mustMint(t *testing.T) minted {
	t.Helper()

	issued, err := mint(testKey(), counterEntropy(), testNow().Add(ChallengeTTL), testCode, testName)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	return issued
}

func TestChallengeLayout(t *testing.T) {
	t.Parallel()

	issued := mustMint(t)

	if len(issued.Challenge) != challengeLen {
		t.Errorf("challenge is %d bytes, want %d", len(issued.Challenge), challengeLen)
	}

	if len(issued.UserHandle) != UserHandleLen {
		t.Errorf("user handle is %d bytes, want %d", len(issued.UserHandle), UserHandleLen)
	}

	if issued.Challenge[0] != challengeVersion {
		t.Errorf("version = %d, want %d", issued.Challenge[0], challengeVersion)
	}

	// The handle travels inside the challenge, in the clear: it is not secret.
	if !bytes.Contains(issued.Challenge, issued.UserHandle) {
		t.Error("challenge does not carry the user handle")
	}

	// The invitation code and the name are associated data only. They must not
	// appear in the challenge.
	for _, secret := range []string{testCode, testName} {
		if bytes.Contains(issued.Challenge, []byte(secret)) {
			t.Errorf("challenge contains %q", secret)
		}
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	t.Parallel()

	issued := mustMint(t)

	handle, err := open(testKey(), issued.Challenge, testNow(), testCode, testName)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if !bytes.Equal(handle, issued.UserHandle) {
		t.Errorf("handle = %x, want %x", handle, issued.UserHandle)
	}
}

// TestChallengeIsUniquePerBegin pins where the challenge's required entropy
// comes from: the random user handle. Two begins for the same code and name
// must never produce the same challenge.
func TestChallengeIsUniquePerBegin(t *testing.T) {
	t.Parallel()

	entropy := counterEntropy()
	expires := testNow().Add(ChallengeTTL)

	first, err := mint(testKey(), entropy, expires, testCode, testName)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	second, err := mint(testKey(), entropy, expires, testCode, testName)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if bytes.Equal(first.Challenge, second.Challenge) {
		t.Error("two begins produced the same challenge")
	}

	if bytes.Equal(first.UserHandle, second.UserHandle) {
		t.Error("two begins produced the same user handle")
	}
}

func TestMintEntropyFailure(t *testing.T) {
	t.Parallel()

	tests := map[string]io.Reader{
		"error":      iotest.ErrReader(io.ErrClosedPipe),
		"too little": io.LimitReader(counterEntropy(), UserHandleLen-1),
	}

	for name, entropy := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := mint(testKey(), entropy, testNow(), testCode, testName)
			if !errors.Is(err, errEntropy) {
				t.Errorf("mint error = %v, want errEntropy", err)
			}
		})
	}
}

// openCase is one way a challenge can fail to verify: it starts from a valid
// challenge and breaks exactly one thing.
type openCase struct {
	mutate  func(challenge []byte) []byte
	now     time.Time
	code    string
	name    string
	key     []byte
	wantErr error
}

// validOpen is the open call that succeeds; a case overrides what it breaks.
func validOpen() openCase {
	return openCase{mutate: nil, now: testNow(), code: testCode, name: testName, key: testKey(), wantErr: nil}
}

func runOpenCases(t *testing.T, cases map[string]openCase) {
	t.Helper()

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			challenge := bytes.Clone(mustMint(t).Challenge)
			if tt.mutate != nil {
				challenge = tt.mutate(challenge)
			}

			handle, err := open(tt.key, challenge, tt.now, tt.code, tt.name)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("open error = %v, want %v", err, tt.wantErr)
			}

			if handle != nil {
				t.Errorf("open returned handle %x alongside an error", handle)
			}
		})
	}
}

func with(edit func(*openCase), wantErr error) openCase {
	c := validOpen()
	edit(&c)
	c.wantErr = wantErr

	return c
}

func TestOpenRejectsWrongInputs(t *testing.T) {
	t.Parallel()

	runOpenCases(t, map[string]openCase{
		"wrong code": with(func(c *openCase) { c.code = testCode + "x" }, errChallengeTag),
		"wrong name": with(func(c *openCase) { c.name = "Mallory" }, errChallengeTag),
		"wrong key":  with(func(c *openCase) { c.key = bytes.Repeat([]byte{0x43}, 32) }, errChallengeTag),
		"expired": with(func(c *openCase) {
			c.now = testNow().Add(ChallengeTTL)
		}, errChallengeExpired),
		"long expired": with(func(c *openCase) {
			c.now = testNow().Add(24 * time.Hour)
		}, errChallengeExpired),
	})
}

func TestOpenRejectsMalformedChallenges(t *testing.T) {
	t.Parallel()

	runOpenCases(t, map[string]openCase{
		"truncated": with(func(c *openCase) {
			c.mutate = func(b []byte) []byte { return b[:len(b)-1] }
		}, errChallengeLength),
		"extended": with(func(c *openCase) {
			c.mutate = func(b []byte) []byte { return append(b, 0) }
		}, errChallengeLength),
		emptyCase: with(func(c *openCase) {
			c.mutate = func([]byte) []byte { return nil }
		}, errChallengeLength),
		"unknown version": with(func(c *openCase) {
			c.mutate = func(b []byte) []byte { b[0] = 2; return b }
		}, errChallengeVersion),
		"version zero": with(func(c *openCase) {
			c.mutate = func(b []byte) []byte { b[0] = 0; return b }
		}, errChallengeVersion),
	})
}

// TestOpenRejectsTampering covers edits to each signed section. A client that
// tries to extend the lifetime changes the expiry bytes; the signature covers
// them, so that is a signature failure, not an extension.
func TestOpenRejectsTampering(t *testing.T) {
	t.Parallel()

	tamper := func(edit func([]byte)) openCase {
		return with(func(c *openCase) {
			c.mutate = func(b []byte) []byte { edit(b); return b }
		}, errChallengeTag)
	}

	runOpenCases(t, map[string]openCase{
		"expiry extended by the client": tamper(func(b []byte) { b[versionLen+expiresLen-1] += 0x7f }),
		"user handle replaced":          tamper(func(b []byte) { b[versionLen+expiresLen] ^= 0xff }),
		"signature zeroed":              tamper(func(b []byte) { clear(b[stateLen:]) }),
	})
}

// TestOpenFlipsEveryBit is the exhaustive form of the tamper tests: flipping
// any single bit of a valid challenge, in any section, must fail.
func TestOpenFlipsEveryBit(t *testing.T) {
	t.Parallel()

	valid := mustMint(t).Challenge

	for bit := range len(valid) * 8 {
		tampered := bytes.Clone(valid)
		tampered[bit/8] ^= 1 << (bit % 8)

		_, err := open(testKey(), tampered, testNow(), testCode, testName)
		if err == nil {
			t.Fatalf("flipping bit %d was accepted", bit)
		}
	}
}

// TestSignSeparatesCodeFromName guards the associated-data framing: moving a
// character between the code and the name must change the signature, which
// plain concatenation would not.
func TestSignSeparatesCodeFromName(t *testing.T) {
	t.Parallel()

	state := make([]byte, stateLen)

	first := sign(testKey(), state, "ab", "c")
	second := sign(testKey(), state, "a", "bc")

	if bytes.Equal(first, second) {
		t.Error(`("ab","c") and ("a","bc") produce the same signature`)
	}
}

func TestDeriveKeySeparatesPurposes(t *testing.T) {
	t.Parallel()

	root := "root-secret-0123456789abcdefghijklmnopqrstuv"

	derived := deriveKey(root)
	if len(derived) != 32 {
		t.Errorf("derived key is %d bytes, want 32", len(derived))
	}

	if bytes.Contains(derived, []byte(root)) || bytes.Equal(derived, []byte(root)) {
		t.Error("derived key is the root secret")
	}

	if !bytes.Equal(derived, deriveKey(root)) {
		t.Error("derivation is not deterministic")
	}

	if bytes.Equal(derived, deriveKey(root+"x")) {
		t.Error("different roots derived the same key")
	}
}

// TestForgedExpiryIsReportedAsForged proves the order in open: a challenge that
// is both forged and expired is reported as forged, so an attacker-chosen
// expiry is never what decides the outcome.
func TestForgedExpiryIsReportedAsForged(t *testing.T) {
	t.Parallel()

	challenge := bytes.Clone(mustMint(t).Challenge)
	clear(challenge[versionLen : versionLen+expiresLen]) // expiry = 1970

	_, err := open(testKey(), challenge, testNow(), testCode, testName)
	if !errors.Is(err, errChallengeTag) {
		t.Errorf("open error = %v, want errChallengeTag", err)
	}
}

// TestExpiryRoundTrips checks the seconds encoding at its edges: a time before
// the epoch is written as zero (already expired), and a forged-looking maximum
// is clamped without overflowing.
func TestExpiryRoundTrips(t *testing.T) {
	t.Parallel()

	state := make([]byte, stateLen)

	putExpiry(state, testNow())

	if got := expiry(state); !got.Equal(testNow()) {
		t.Errorf("expiry = %v, want %v", got, testNow())
	}

	putExpiry(state, time.Unix(-5, 0))

	if got := expiry(state); !got.Equal(time.Unix(0, 0)) {
		t.Errorf("a pre-epoch expiry = %v, want the epoch", got)
	}

	for i := range expiresLen {
		state[versionLen+i] = 0xff
	}

	if got := expiry(state); got.Before(testNow()) {
		t.Errorf("a maximal expiry = %v, want a time in the far future", got)
	}
}
