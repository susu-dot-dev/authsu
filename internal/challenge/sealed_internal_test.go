//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package challenge

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"
)

// sealedCase is one OpenSealed call. A case that wants success leaves cause nil
// and has the standard payload as its want.
type sealedCase struct {
	sealed []byte
	key    []byte
	now    time.Time
	maxTTL time.Duration
	cause  error
}

// goodSealed is a call that succeeds against validSealed: a case copies it and
// breaks one thing.
func goodSealed(t *testing.T) sealedCase {
	t.Helper()

	return sealedCase{sealed: validSealed(t), key: testKey(), now: testNow(), maxTTL: testMaxTTL, cause: nil}
}

func runSealedCases(t *testing.T, cases map[string]sealedCase) {
	t.Helper()

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			payload, err := OpenSealed(tt.key, tt.sealed, tt.now, tt.maxTTL)

			if tt.cause == nil {
				if err != nil {
					t.Fatalf("OpenSealed: %v", err)
				}

				if !bytes.Equal(payload, testPayload()) {
					t.Errorf("payload = %q, want %q", payload, testPayload())
				}

				return
			}

			if !errors.Is(err, ErrInvalid) || !errors.Is(err, tt.cause) {
				t.Fatalf("err = %v, want ErrInvalid wrapping %v", err, tt.cause)
			}

			if errors.Is(err, ErrKey) || errors.Is(err, ErrPayload) {
				t.Error("an invalid sealed payload is not a server fault")
			}

			if payload != nil {
				t.Errorf("a refused sealed payload returned %q", payload)
			}
		})
	}
}

// TestSealLayout pins the documented byte layout against an independent builder
// and one answer computed outside this package (Python hmac and hashlib).
func TestSealLayout(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		payload []byte
		want    string
	}{
		"payload": {
			payload: []byte("hello"),
			want:    "0200000000713fb42c68656c6c6f4ec31c1e74aac320759a52107ab45d84d09e4b0cc5ec1963d1a7d5a7750d4eef",
		},
		"empty": {payload: nil},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sealed, err := Seal(testKey(), time.Unix(expiresAt, 0), tt.payload)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			if !bytes.Equal(sealed, forgeSealed(testKey(), 2, expiresAt, tt.payload)) {
				t.Errorf("sealed %x differs from the documented layout", sealed)
			}

			if len(sealed) != MinSealedLen+len(tt.payload) {
				t.Errorf("sealed is %d bytes, want %d", len(sealed), MinSealedLen+len(tt.payload))
			}

			// The prefix is the clear state: version 2, then the expiry as 8
			// big-endian bytes (1900000300 = 0x713fb42c), then the payload.
			if prefix := hex.EncodeToString(sealed[:9]); prefix != "0200000000713fb42c" {
				t.Errorf("state prefix = %s", prefix)
			}

			if !bytes.Equal(sealed[9:len(sealed)-tagLen], tt.payload) {
				t.Errorf("payload is not in place after the expiry")
			}

			if tt.want != "" && hex.EncodeToString(sealed) != tt.want {
				t.Errorf("sealed = %x\nwant     %s", sealed, tt.want)
			}
		})
	}
}

func TestSealedSizes(t *testing.T) {
	t.Parallel()

	if MinSealedLen != 41 || MaxSealedLen != 41+4096 || MaxPayloadLen != 4096 {
		t.Errorf("sizes = %d, %d, %d, want 41, 4137, 4096", MinSealedLen, MaxSealedLen, MaxPayloadLen)
	}

	if version == sealedVersion {
		t.Error("a challenge and a sealed payload share a version byte")
	}
}

// TestSealIsDeterministic: nothing random is added, so equal inputs give equal
// bytes and any difference in a part gives different bytes.
func TestSealIsDeterministic(t *testing.T) {
	t.Parallel()

	base := validSealed(t)

	if !bytes.Equal(base, validSealed(t)) {
		t.Error("equal inputs gave different sealed bytes")
	}

	expires := testNow().Add(testMaxTTL)

	for name, other := range map[string]func() ([]byte, error){
		"payload": func() ([]byte, error) { return Seal(testKey(), expires, append(testPayload(), 'x')) },
		"expiry":  func() ([]byte, error) { return Seal(testKey(), expires.Add(time.Second), testPayload()) },
		"key":     func() ([]byte, error) { return Seal(otherKey(), expires, testPayload()) },
	} {
		got, err := other()
		if err != nil {
			t.Fatalf("%s: Seal: %v", name, err)
		}

		if bytes.Equal(got, base) {
			t.Errorf("changing the %s did not change the sealed bytes", name)
		}
	}
}

// TestSealExpiryEncoding: the expiry is stored as Create stores it.
func TestSealExpiryEncoding(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		expires time.Time
		want    uint64
	}{
		"whole second":               {expires: time.Unix(expiresAt, 0), want: expiresAt},
		"fraction rounds down":       {expires: time.Unix(expiresAt, 999_999_999), want: expiresAt},
		"the epoch":                  {expires: time.Unix(0, 0), want: 0},
		"just before the epoch":      {expires: time.Unix(0, -1), want: 0},
		"far before the epoch":       {expires: time.Unix(-(1 << 62), 0), want: 0},
		"the zero time":              {expires: time.Time{}, want: 0},
		"latest second a duration":   {expires: time.Unix(int64(maxSeconds), 0), want: maxSeconds},
		"beyond what a duration can": {expires: time.Unix(1<<62, 0), want: maxSeconds},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sealed, err := Seal(testKey(), tt.expires, testPayload())
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			if want := forgeSealed(testKey(), 2, tt.want, testPayload()); !bytes.Equal(sealed, want) {
				t.Errorf("sealed = %x\nwant   %x", sealed, want)
			}
		})
	}
}

// TestSealedRoundTrip: whatever bytes go in come out, unchanged, whatever they
// look like.
func TestSealedRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"empty":            {},
		"nil":              nil,
		"one byte":         {'x'},
		"a NUL":            {0},
		"NULs":             make([]byte, 100),
		"non-UTF-8":        {0xff, 0xfe, 0x00, 0xc0, 0x80},
		"json":             []byte(`{"client_id":"https://app.example/c","scopes":["a:read"]}`),
		"tag-like":         bytes.Repeat([]byte{0xab}, tagLen),
		"every byte value": allBytes(),
		"one under bound":  bytes.Repeat([]byte{'p'}, MaxPayloadLen-1),
		"at the bound":     bytes.Repeat([]byte{'p'}, MaxPayloadLen),
	}

	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sealed, err := Seal(testKey(), testNow().Add(testMaxTTL), payload)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			got, err := OpenSealed(testKey(), sealed, testNow(), testMaxTTL)
			if err != nil {
				t.Fatalf("OpenSealed: %v", err)
			}

			if !bytes.Equal(got, payload) {
				t.Errorf("payload = %x, want %x", got, payload)
			}

			if got == nil {
				t.Error("an opened payload is never nil, even when empty")
			}
		})
	}
}

func allBytes() []byte {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}

	return all
}

// TestSealPayloadBound: a payload over MaxPayloadLen is a server fault at Seal,
// and a value that carries one is invalid at OpenSealed, even when it is
// correctly signed (a leaked key must not widen what is accepted).
func TestSealPayloadBound(t *testing.T) {
	t.Parallel()

	cases := map[string]sealedCase{}

	for _, over := range []int{1, 2, 100, 1 << 20} {
		payload := make([]byte, MaxPayloadLen+over)

		t.Run(fmt.Sprintf("Seal refuses a payload over the bound by %d", over), func(t *testing.T) {
			t.Parallel()

			sealed, err := Seal(testKey(), testNow().Add(testMaxTTL), payload)
			if !errors.Is(err, ErrPayload) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrKey) || sealed != nil {
				t.Errorf("Seal of %d bytes = %x, %v, want ErrPayload only", len(payload), sealed, err)
			}
		})

		call := goodSealed(t)
		call.sealed = forgeSealed(testKey(), 2, expiresAt, payload)
		call.cause = errLength
		cases[fmt.Sprintf("OpenSealed refuses a signed payload over the bound by %d", over)] = call
	}

	runSealedCases(t, cases)

	// The bound is on the payload, not on the sealed value: the largest signed
	// value opens.
	atBound := bytes.Repeat([]byte{'p'}, MaxPayloadLen)

	if len(forgeSealed(testKey(), 2, expiresAt, atBound)) != MaxSealedLen {
		t.Fatal("MaxSealedLen is not the length of a payload at the bound")
	}

	got, err := OpenSealed(testKey(), forgeSealed(testKey(), 2, expiresAt, atBound), time.Unix(expiresAt-1, 0), testMaxTTL)
	if err != nil || !bytes.Equal(got, atBound) {
		t.Errorf("a payload at the bound = %d bytes, %v", len(got), err)
	}
}

func TestSealedKeys(t *testing.T) {
	t.Parallel()

	for name, key := range wrongSizeKeys() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sealed, err := Seal(key, testNow().Add(testMaxTTL), testPayload())
			if !errors.Is(err, ErrKey) || errors.Is(err, ErrInvalid) || sealed != nil {
				t.Errorf("Seal = %x, %v, want ErrKey only", sealed, err)
			}

			// OpenSealed refuses the key before it looks at the value, so even
			// a value signed by the zero-padded equivalent does not open.
			for _, value := range [][]byte{validSealed(t), nil, forgeSealed(key, 2, expiresAt, testPayload())} {
				payload, err := OpenSealed(key, value, testNow(), testMaxTTL)
				if !errors.Is(err, ErrKey) || errors.Is(err, ErrInvalid) || payload != nil {
					t.Errorf("OpenSealed = %x, %v, want ErrKey only", payload, err)
				}
			}
		})
	}
}

// TestOpenSealedKey: only the key that sealed it opens it, including a key
// derived for another purpose from the same root.
func TestOpenSealedKey(t *testing.T) {
	t.Parallel()

	const root = "0123456789abcdef0123456789abcdef"

	request := derivedKey(root, "authsu/oauth-request/v1")
	login := derivedKey(root, "authsu/login-challenge/v1")
	registration := derivedKey(root, "authsu/registration-challenge/v1")

	sealed, err := Seal(request, testNow().Add(testMaxTTL), testPayload())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tests := map[string]struct {
		key   []byte
		cause error
	}{
		"same key":                {key: request},
		"different key":           {key: otherKey(), cause: errTag},
		"one bit off":             {key: append(bytes.Clone(request[:31]), request[31]^1), cause: errTag},
		"login context":           {key: login, cause: errTag},
		"registration context":    {key: registration, cause: errTag},
		"all-zero key, full size": {key: make([]byte, KeyLen), cause: errTag},
		"the tag as a key":        {key: sealed[len(sealed)-tagLen:], cause: errTag},
		"another root":            {key: derivedKey(root+"x", "authsu/oauth-request/v1"), cause: errTag},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := OpenSealed(tt.key, sealed, testNow(), testMaxTTL)

			if tt.cause == nil {
				if err != nil || !bytes.Equal(got, testPayload()) {
					t.Errorf("OpenSealed = %q, %v", got, err)
				}

				return
			}

			if !errors.Is(err, ErrInvalid) || !errors.Is(err, tt.cause) || got != nil {
				t.Errorf("OpenSealed = %q, %v, want ErrInvalid wrapping %v", got, err, tt.cause)
			}
		})
	}
}

// TestOpenSealedRefusesEveryAlteredByte flips bits of every byte of a sealed
// payload. Every single alteration must be refused, whichever part it lands in.
func TestOpenSealedRefusesEveryAlteredByte(t *testing.T) {
	t.Parallel()

	cases := map[string]sealedCase{}

	for _, payload := range [][]byte{nil, testPayload()} {
		for index := range MinSealedLen + len(payload) {
			for _, mask := range []byte{0x01, 0x80, 0xff} {
				sealed, err := Seal(testKey(), testNow().Add(testMaxTTL), payload)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}

				sealed[index] ^= mask

				// Only the version is read before the tag; every other byte,
				// payload and expiry included, is refused by the tag.
				call := sealedCase{sealed: sealed, key: testKey(), now: testNow(), maxTTL: testMaxTTL, cause: errTag}
				if index == 0 {
					call.cause = errVersion
				}

				cases[fmt.Sprintf("payload %d bytes/byte %d xor %#02x", len(payload), index, mask)] = call
			}
		}
	}

	runSealedCases(t, cases)
}

// TestOpenSealedRefusesEveryTruncation: every proper prefix is refused, as is
// every extension, so no value is a shortened or lengthened form of another.
func TestOpenSealedRefusesEveryTruncation(t *testing.T) {
	t.Parallel()

	good := validSealed(t)
	cases := map[string]sealedCase{}

	for length := range good {
		call := goodSealed(t)
		call.sealed = bytes.Clone(good[:length])

		// A prefix that still has room for a tag is long enough to be read: it
		// is refused by the tag, the shorter ones by the length.
		call.cause = errLength
		if length >= MinSealedLen {
			call.cause = errTag
		}

		cases[fmt.Sprintf("truncated to %d", length)] = call
	}

	for _, extra := range [][]byte{{0}, {0xff}, good, make([]byte, MaxSealedLen)} {
		call := goodSealed(t)
		call.sealed = append(bytes.Clone(good), extra...)
		call.cause = errTag

		if len(call.sealed) > MaxSealedLen {
			call.cause = errLength
		}

		cases[fmt.Sprintf("extended by %d", len(extra))] = call
	}

	nilCall := goodSealed(t)
	nilCall.sealed = nil
	nilCall.cause = errLength
	cases["nil"] = nilCall

	runSealedCases(t, cases)
}

// TestOpenSealedVersion: only version 2 opens, even when the tag is correct
// for the bytes presented.
func TestOpenSealedVersion(t *testing.T) {
	t.Parallel()

	cases := map[string]sealedCase{}

	for _, ver := range []byte{0, 1, 3, 0x7f, 0x80, 0xff} {
		signed := goodSealed(t)
		signed.sealed = forgeSealed(testKey(), ver, expiresAt, testPayload())
		signed.cause = errVersion
		cases[fmt.Sprintf("signed version %d", ver)] = signed
	}

	good := goodSealed(t)
	good.sealed = forgeSealed(testKey(), 2, expiresAt, testPayload())
	cases["forged version 2 opens"] = good

	runSealedCases(t, cases)
}

// TestOpenSealedExpiry exercises every boundary of the validity window, with
// the semantics of Open: now before the expiry, and the expiry at most maxTTL
// after now.
func TestOpenSealedExpiry(t *testing.T) {
	t.Parallel()

	const ttl = testMaxTTL

	at := func(seconds uint64, now time.Time, maxTTL time.Duration) sealedCase {
		call := goodSealed(t)
		call.sealed = forgeSealed(testKey(), 2, seconds, testPayload())
		call.now = now
		call.maxTTL = maxTTL

		return call
	}

	expires := time.Unix(expiresAt, 0)

	expired := func(call sealedCase) sealedCase { call.cause = errExpired; return call }
	future := func(call sealedCase) sealedCase { call.cause = errFuture; return call }

	cases := map[string]sealedCase{
		"well before expiry":             at(expiresAt, expires.Add(-time.Minute), ttl),
		"one second before expiry":       at(expiresAt, expires.Add(-time.Second), ttl),
		"one nanosecond before expiry":   at(expiresAt, expires.Add(-time.Nanosecond), ttl),
		"exactly at expiry":              expired(at(expiresAt, expires, ttl)),
		"one nanosecond after expiry":    expired(at(expiresAt, expires.Add(time.Nanosecond), ttl)),
		"a day after expiry":             expired(at(expiresAt, expires.Add(24*time.Hour), ttl)),
		"exactly maxTTL ahead":           at(expiresAt, expires.Add(-ttl), ttl),
		"maxTTL ahead plus a nanosecond": future(at(expiresAt, expires.Add(-ttl-time.Nanosecond), ttl)),
		"a day ahead":                    future(at(expiresAt, expires.Add(-24*time.Hour), ttl)),
		"zero maxTTL, one second left":   future(at(expiresAt, expires.Add(-time.Second), 0)),
		"negative maxTTL":                future(at(expiresAt, expires.Add(-time.Second), -time.Second)),
		"huge maxTTL":                    at(expiresAt, expires.Add(-time.Second), math.MaxInt64),
		"stored as zero":                 expired(at(0, testNow(), ttl)),
		"stored as zero, clock at epoch": expired(at(0, time.Unix(0, 0), ttl)),
		"fractional clock before":        at(expiresAt, time.Unix(expiresAt-1, 999_999_999), ttl),
		"fractional clock after":         expired(at(expiresAt, time.Unix(expiresAt, 1), ttl)),
		"sign bit set is far ahead":      future(at(1<<63, testNow(), ttl)),
		"all ones is far ahead":          future(at(math.MaxUint64, testNow(), ttl)),
		"clamped value, one second before it": at(
			math.MaxUint64, time.Unix(int64(maxSeconds)-1, 0), 10*time.Second),
		"clamped value, at it": expired(at(
			math.MaxUint64, time.Unix(int64(maxSeconds), 0), 10*time.Second)),
	}

	runSealedCases(t, cases)
}

// TestSealOpenSealedAcrossTheWindow: what Seal writes opens for exactly the
// window its expiry defines, and a distant expiry is refused as a forged one
// would be.
func TestSealOpenSealedAcrossTheWindow(t *testing.T) {
	t.Parallel()

	type window struct {
		expires time.Time
		now     time.Time
		cause   error
	}

	minute := testNow().Add(time.Minute)

	tests := map[string]window{
		"the standard window":       {expires: testNow().Add(testMaxTTL), now: testNow()},
		"fraction of a second":      {expires: testNow().Add(testMaxTTL + 900*time.Millisecond), now: testNow()},
		"at the expiry":             {expires: minute, now: minute, cause: errExpired},
		"just before the expiry":    {expires: minute, now: minute.Add(-time.Second)},
		"after the expiry":          {expires: minute, now: testNow().Add(time.Hour), cause: errExpired},
		"far-future expiry":         {expires: testNow().Add(24 * time.Hour), now: testNow(), cause: errFuture},
		"ten years ahead":           {expires: testNow().Add(10 * 365 * 24 * time.Hour), now: testNow(), cause: errFuture},
		"the zero time":             {expires: time.Time{}, now: testNow(), cause: errExpired},
		"beyond a duration":         {expires: time.Unix(1<<62, 0), now: testNow(), cause: errFuture},
		"maxTTL plus a second":      {expires: testNow().Add(testMaxTTL + time.Second), now: testNow(), cause: errFuture},
		"maxTTL plus a fraction":    {expires: testNow().Add(testMaxTTL + time.Second), now: testNow(), cause: errFuture},
		"expiry is rounded down":    {expires: minute.Add(999 * time.Millisecond), now: minute, cause: errExpired},
		"now is before the epoch":   {expires: testNow(), now: time.Unix(-5, 0), cause: errFuture},
		"both at the epoch":         {expires: time.Unix(0, 0), now: time.Unix(0, 0), cause: errExpired},
		"one second after epoch":    {expires: time.Unix(1, 0), now: time.Unix(0, 0)},
		"expiry within a second":    {expires: testNow().Add(500 * time.Millisecond), now: testNow(), cause: errExpired},
		"expiry just over a second": {expires: testNow().Add(1500 * time.Millisecond), now: testNow()},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			call := goodSealed(t)

			sealed, err := Seal(testKey(), tt.expires, testPayload())
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			call.sealed, call.now, call.cause = sealed, tt.now, tt.cause

			runSealedCases(t, map[string]sealedCase{"call": call})
		})
	}
}

// TestOpenSealedChecksInOrder: the cheaper and safer checks come first, and an
// attacker-chosen expiry is never acted on. A value that fails several checks
// is reported by the first.
func TestOpenSealedChecksInOrder(t *testing.T) {
	t.Parallel()

	const (
		expiredAt = uint64(testNowSeconds - 1)
		farAt     = uint64(testNowSeconds + 10*365*24*3600)
	)

	forgedTag := func(sealed []byte) []byte {
		sealed[len(sealed)-1] ^= 1

		return sealed
	}

	p := testPayload()
	tooLong := make([]byte, MaxPayloadLen+1)

	tests := map[string]struct {
		sealed []byte
		cause  error
	}{
		"expired and forged is forged":        {forgedTag(forgeSealed(testKey(), 2, expiredAt, p)), errTag},
		"far ahead and forged is forged":      {forgedTag(forgeSealed(testKey(), 2, farAt, p)), errTag},
		"expired, signed by another key":      {forgeSealed(otherKey(), 2, expiredAt, p), errTag},
		"far ahead, signed by another key":    {forgeSealed(otherKey(), 2, farAt, p), errTag},
		"wrong version and forged":            {forgedTag(forgeSealed(testKey(), 1, expiredAt, p)), errVersion},
		"too long and wrong version":          {forgeSealed(testKey(), 1, expiredAt, tooLong), errLength},
		"too short and wrong version":         {[]byte{1, 2, 3}, errLength},
		"validly signed and expired":          {forgeSealed(testKey(), 2, expiredAt, p), errExpired},
		"validly signed and far ahead":        {forgeSealed(testKey(), 2, farAt, p), errFuture},
		"validly signed, over bound, expired": {forgeSealed(testKey(), 2, expiredAt, tooLong), errLength},
	}

	cases := map[string]sealedCase{}

	for name, tt := range tests {
		call := goodSealed(t)
		call.sealed = tt.sealed
		call.cause = tt.cause
		cases[name] = call
	}

	runSealedCases(t, cases)
}

// crossFixture is a challenge and a sealed payload of the same length, under one
// key: the only thing that tells them apart is the version and the tag.
type crossFixture struct {
	challenge  []byte
	bound      []byte
	sameLength []byte
}

func newCrossFixture(t *testing.T) crossFixture {
	t.Helper()

	expires := testNow().Add(testMaxTTL)

	challengeValue, nonce, err := Create(testKey(), counterEntropy(), expires)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	bound, _, err := Create(testKey(), counterEntropy(), expires, []byte("ad"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sameLength, err := Seal(testKey(), expires, nonce)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if len(sameLength) != Len {
		t.Fatalf("a %d-byte payload seals to %d bytes, want %d", len(nonce), len(sameLength), Len)
	}

	return crossFixture{challenge: challengeValue, bound: bound, sameLength: sameLength}
}

// TestAChallengeIsNotASealedPayload: a login or registration challenge never
// opens as a sealed payload, with the key that made it.
func TestAChallengeIsNotASealedPayload(t *testing.T) {
	t.Parallel()

	fx := newCrossFixture(t)

	for name, value := range map[string][]byte{"plain": fx.challenge, "with associated data": fx.bound} {
		payload, err := OpenSealed(testKey(), value, testNow(), testMaxTTL)
		if !errors.Is(err, ErrInvalid) || !errors.Is(err, errVersion) || payload != nil {
			t.Errorf("%s: OpenSealed = %x, %v, want ErrInvalid wrapping errVersion", name, payload, err)
		}
	}
}

// TestASealedPayloadIsNotAChallenge: the same length as a challenge, the same
// key, and still not one.
func TestASealedPayloadIsNotAChallenge(t *testing.T) {
	t.Parallel()

	got, err := Open(testKey(), newCrossFixture(t).sameLength, testNow(), testMaxTTL)
	if !errors.Is(err, ErrInvalid) || !errors.Is(err, errVersion) || got != nil {
		t.Errorf("Open = %x, %v, want ErrInvalid wrapping errVersion", got, err)
	}
}

// TestARewrittenVersionDoesNotCrossOver: relabelling does not help, because the
// version is in the MAC input. (Only a holder of the key could make the tag
// match, and a key holder is the signer.)
func TestARewrittenVersionDoesNotCrossOver(t *testing.T) {
	t.Parallel()

	fx := newCrossFixture(t)

	asSealed := bytes.Clone(fx.challenge)
	asSealed[0] = sealedVersion

	_, err := OpenSealed(testKey(), asSealed, testNow(), testMaxTTL)
	if !errors.Is(err, errTag) {
		t.Errorf("OpenSealed of a challenge relabelled as sealed = %v, want errTag", err)
	}

	asChallenge := bytes.Clone(fx.sameLength)
	asChallenge[0] = version

	_, err = Open(testKey(), asChallenge, testNow(), testMaxTTL)
	if !errors.Is(err, errTag) {
		t.Errorf("Open of a sealed payload relabelled as a challenge = %v, want errTag", err)
	}
}

// TestTheOtherFormsTagDoesNotCarryOver: a challenge's tag spliced under a
// sealed payload's state does not verify.
func TestTheOtherFormsTagDoesNotCarryOver(t *testing.T) {
	t.Parallel()

	fx := newCrossFixture(t)

	spliced := append(bytes.Clone(fx.sameLength[:stateLen]), fx.challenge[stateLen:]...)

	_, err := OpenSealed(testKey(), spliced, testNow(), testMaxTTL)
	if !errors.Is(err, errTag) {
		t.Errorf("OpenSealed of a spliced value = %v, want errTag", err)
	}
}

// TestSealedDoesNotAlias: the sealed value and the opened payload are copies.
func TestSealedDoesNotAlias(t *testing.T) {
	t.Parallel()

	payload := testPayload()

	sealed, err := Seal(testKey(), testNow().Add(testMaxTTL), payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	want := bytes.Clone(sealed)

	clear(payload)

	if !bytes.Equal(sealed, want) {
		t.Error("mutating the payload changed the sealed value")
	}

	first, err := OpenSealed(testKey(), sealed, testNow(), testMaxTTL)
	if err != nil {
		t.Fatalf("OpenSealed: %v", err)
	}

	second, err := OpenSealed(testKey(), sealed, testNow(), testMaxTTL)
	if err != nil {
		t.Fatalf("OpenSealed: %v", err)
	}

	clear(first)

	_ = append(first, 0xee)

	if !bytes.Equal(sealed, want) || !bytes.Equal(second, testPayload()) {
		t.Error("mutating an opened payload changed the sealed value or another payload")
	}
}

// FuzzOpenSealed: arbitrary bytes as the sealed value and the key never panic,
// fail only with ErrInvalid (or ErrKey for a key of the wrong size), and
// succeed only for a value the key really signed, which then round-trips.
func FuzzOpenSealed(f *testing.F) {
	good := forgeSealed(testKey(), 2, expiresAt, testPayload())

	f.Add(good, testKey())
	f.Add(good, otherKey())
	f.Add(good[:len(good)-1], testKey())
	f.Add(append(bytes.Clone(good), 0), testKey())
	f.Add([]byte{}, []byte{})
	f.Add(forgeSealed(testKey(), 2, expiresAt, nil), testKey())
	f.Add(forgeSealed(testKey(), 2, math.MaxUint64, nil), testKey())
	f.Add(forgeSealed(testKey(), 1, expiresAt, testPayload()), testKey())
	f.Add(forgeSealed(testKey(), 2, expiresAt, make([]byte, MaxPayloadLen+1)), testKey())
	f.Add(validChallenge(f), testKey())
	f.Add(make([]byte, MinSealedLen), testKey())

	f.Fuzz(func(t *testing.T, sealed, key []byte) {
		payload, err := OpenSealed(key, sealed, testNow(), testMaxTTL)
		if err != nil {
			requireSealedRefusal(t, key, payload, err)

			return
		}

		// Success is only possible for what the key really signed, and then
		// the payload is the bytes in place.
		if len(sealed) < MinSealedLen || len(sealed) > MaxSealedLen || payload == nil ||
			!bytes.Equal(payload, sealed[9:len(sealed)-tagLen]) {
			t.Fatalf("OpenSealed accepted %x with payload %x", sealed, payload)
		}

		if !bytes.Equal(sealed, forgeSealed(key, 2, binary.BigEndian.Uint64(sealed[1:9]), payload)) {
			t.Fatalf("OpenSealed accepted %x, which is not signed for this key", sealed)
		}
	})
}

// requireSealedRefusal checks the one shape a refusal may take: nothing
// returned, and ErrKey exactly when the key is the wrong size, else ErrInvalid.
func requireSealedRefusal(t *testing.T, key, payload []byte, err error) {
	t.Helper()

	wrongKey := len(key) != KeyLen
	if wrongKey != errors.Is(err, ErrKey) || (!wrongKey && !errors.Is(err, ErrInvalid)) ||
		errors.Is(err, ErrPayload) || payload != nil {
		t.Fatalf("OpenSealed = %x, %v", payload, err)
	}
}

// FuzzSealRoundTrip: whatever payload and expiry Seal accepts opens again to
// the same payload with the same key within its window, never with another key,
// and never when any single byte is changed.
func FuzzSealRoundTrip(f *testing.F) {
	f.Add([]byte{}, int64(60), uint(0))
	f.Add(testPayload(), int64(299), uint(5))
	f.Add(bytes.Repeat([]byte{'p'}, MaxPayloadLen), int64(1), uint(100))
	f.Add(bytes.Repeat([]byte{'p'}, MaxPayloadLen+1), int64(1), uint(0))
	f.Add([]byte{0, 0xff}, int64(-1), uint(1))
	f.Add([]byte("x"), int64(1<<40), uint(2))

	f.Fuzz(func(t *testing.T, payload []byte, ttlSeconds int64, flip uint) {
		expires := testNow().Add(time.Duration(ttlSeconds%1_000_000) * time.Second)

		sealed, err := Seal(testKey(), expires, payload)
		if len(payload) > MaxPayloadLen {
			if !errors.Is(err, ErrPayload) || sealed != nil {
				t.Fatalf("Seal of %d bytes = %x, %v", len(payload), sealed, err)
			}

			return
		}

		if err != nil {
			t.Fatalf("Seal: %v", err)
		}

		requireRoundTrip(t, sealed, payload, expires)

		// Never without the key, and never with a byte changed, whatever the
		// window: the tag is what refuses, so these hold inside it or out.
		_, err = OpenSealed(otherKey(), sealed, testNow(), testMaxTTL)
		if err == nil {
			t.Fatal("OpenSealed opened with another key")
		}

		altered := bytes.Clone(sealed)
		altered[flip%uint(len(altered))] ^= 0x01

		_, err = OpenSealed(testKey(), altered, testNow(), testMaxTTL)
		if err == nil {
			t.Fatalf("OpenSealed opened %x after a byte was changed", altered)
		}
	})
}

// requireRoundTrip checks that sealed opens to payload exactly when now falls
// in the window its expiry defines, and is refused as invalid otherwise.
func requireRoundTrip(t *testing.T, sealed, payload []byte, expires time.Time) {
	t.Helper()

	got, err := OpenSealed(testKey(), sealed, testNow(), testMaxTTL)
	// The expiry is stored in whole seconds, rounded down.
	stored := time.Unix(expires.Unix(), 0)
	inWindow := stored.After(testNow()) && !stored.After(testNow().Add(testMaxTTL))

	switch {
	case inWindow && (err != nil || !bytes.Equal(got, payload)):
		t.Fatalf("OpenSealed = %x, %v, want %x", got, err, payload)
	case !inWindow && (!errors.Is(err, ErrInvalid) || got != nil):
		t.Fatalf("OpenSealed outside the window = %x, %v", got, err)
	}
}

// validChallenge is a seed: a real challenge, which must not open as a sealed
// payload.
func validChallenge(f *testing.F) []byte {
	f.Helper()

	challenge, _, err := Create(testKey(), counterEntropy(), testNow().Add(testMaxTTL))
	if err != nil {
		f.Fatalf("Create: %v", err)
	}

	return challenge
}
