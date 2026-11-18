//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package challenge

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
	"testing/iotest"
	"time"
)

// maxSeconds is the latest whole second a time.Duration can span from the
// epoch: the point where expiry clamps.
const maxSeconds = uint64(math.MaxInt64) / uint64(time.Second)

// expiresAt is a forged challenge's expiry, as it sits in testNow's time frame.
const expiresAt = testNowSeconds + 300

// TestLayout pins the documented byte layout against an independent builder, so
// a change to the layout cannot pass unnoticed.
func TestLayout(t *testing.T) {
	t.Parallel()

	tests := map[string][][]byte{
		"no associated data": nil,
		"two items":          adOf("code", "name"),
		"empty item":         adOf(""),
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			challenge, nonce, err := Create(testKey(), counterEntropy(), time.Unix(expiresAt, 0), data...)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			if len(challenge) != Len || Len != 73 || NonceLen != 32 {
				t.Errorf("challenge is %d bytes (Len %d, NonceLen %d), want 73 and 32", len(challenge), Len, NonceLen)
			}

			if !bytes.Equal(challenge, forge(testKey(), 1, expiresAt, firstNonce(), data...)) {
				t.Errorf("challenge %x differs from the documented layout", challenge)
			}

			if !bytes.Equal(nonce, firstNonce()) || !bytes.Equal(challenge[9:41], nonce) {
				t.Errorf("nonce %x is not the entropy, in place at bytes 9..41", nonce)
			}

			// The prefix is the clear state: version 1, then the expiry as
			// 8 big-endian bytes (1900000300 = 0x713fb42c).
			if prefix := hex.EncodeToString(challenge[:9]); prefix != "0100000000713fb42c" {
				t.Errorf("state prefix = %s", prefix)
			}

			assertNotContained(t, challenge, data)
		})
	}
}

// assertNotContained checks that associated data influences the tag only: it
// is never in the challenge.
func assertNotContained(t *testing.T, challenge []byte, data [][]byte) {
	t.Helper()

	for _, item := range data {
		if len(item) > 0 && bytes.Contains(challenge, item) {
			t.Errorf("challenge contains associated data %q", item)
		}
	}
}

// TestKnownAnswer pins one complete challenge byte for byte, so the MAC
// construction (not just the layout of the clear state) cannot drift.
func TestKnownAnswer(t *testing.T) {
	t.Parallel()

	challenge, _, err := Create(testKey(), counterEntropy(), time.Unix(expiresAt, 0), []byte("code"), []byte("name"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := hex.EncodeToString(challenge); got != knownAnswer {
		t.Errorf("challenge = %s\nwant        %s", got, knownAnswer)
	}
}

// knownAnswer was computed independently of this package (Python hmac and hashlib).
const knownAnswer = "0100000000713fb42c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
	"b16b83799d928af80a97e15a068d603c424f81e7eacd11525ec11e086b8cdab0"

// TestAssociatedDataChangesOnlyTheTag: a challenge with and without data
// shares its state but not its tag.
func TestAssociatedDataChangesOnlyTheTag(t *testing.T) {
	t.Parallel()

	plain := valid(t)
	bound := valid(t, []byte("a"))

	if !bytes.Equal(plain[:41], bound[:41]) {
		t.Error("associated data changed the state")
	}

	if bytes.Equal(plain[41:], bound[41:]) {
		t.Error("associated data did not change the tag")
	}
}

// TestCreateExpiryEncoding: the expiry is a uint64 of whole seconds, rounded
// down, with times before the epoch stored as zero and nothing signed ever
// converted.
func TestCreateExpiryEncoding(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		expires time.Time
		want    uint64
	}{
		"whole second":               {expires: time.Unix(expiresAt, 0), want: expiresAt},
		"fraction rounds down":       {expires: time.Unix(expiresAt, 999_999_999), want: expiresAt},
		"just under a second":        {expires: time.Unix(0, 999_999_999), want: 0},
		"one second":                 {expires: time.Unix(1, 0), want: 1},
		"the epoch":                  {expires: time.Unix(0, 0), want: 0},
		"just before the epoch":      {expires: time.Unix(0, -1), want: 0},
		"before the epoch":           {expires: time.Unix(-100, 0), want: 0},
		"far before the epoch":       {expires: time.Unix(-(1 << 62), 0), want: 0},
		"the zero time":              {expires: time.Time{}, want: 0},
		"latest second a duration":   {expires: time.Unix(int64(maxSeconds), 0), want: maxSeconds},
		"beyond what a duration can": {expires: time.Unix(1<<62, 0), want: maxSeconds},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			challenge, _, err := Create(testKey(), counterEntropy(), tt.expires)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			if want := forge(testKey(), 1, tt.want, firstNonce()); !bytes.Equal(challenge, want) {
				t.Errorf("challenge = %x\nwant        %x", challenge, want)
			}
		})
	}
}

func TestCreateEntropyFailure(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entropy io.Reader
		cause   error
	}{
		"read error":     {entropy: iotest.ErrReader(io.ErrClosedPipe), cause: io.ErrClosedPipe},
		"empty":          {entropy: bytes.NewReader(nil), cause: io.EOF},
		"one byte short": {entropy: io.LimitReader(counterEntropy(), NonceLen-1), cause: io.ErrUnexpectedEOF},
		"short read then error": {
			entropy: io.MultiReader(io.LimitReader(counterEntropy(), 7), iotest.ErrReader(io.ErrNoProgress)),
			cause:   io.ErrNoProgress,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			challenge, nonce, err := Create(testKey(), tt.entropy, testNow())
			if !errors.Is(err, ErrEntropy) || !errors.Is(err, tt.cause) {
				t.Fatalf("err = %v, want ErrEntropy wrapping %v", err, tt.cause)
			}

			// A server fault is not a verdict on anyone's input.
			if errors.Is(err, ErrInvalid) {
				t.Error("an entropy failure must not wrap ErrInvalid")
			}

			if challenge != nil || nonce != nil {
				t.Errorf("a failed Create returned %x and %x", challenge, nonce)
			}
		})
	}
}

func TestCreateReadsExactlyTheNonce(t *testing.T) {
	t.Parallel()

	entropy := &countingReader{src: counterEntropy()}

	_, _, err := Create(testKey(), entropy, testNow())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if entropy.total != NonceLen {
		t.Errorf("read %d bytes of entropy, want %d", entropy.total, NonceLen)
	}
}

type countingReader struct {
	src   io.Reader
	total int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.total += n

	return n, err //nolint:wrapcheck // a test double passes the source's result through unchanged
}

// TestCreateIsUnique: the nonce is the challenge's only entropy, so two creates
// with identical inputs but fresh entropy must never produce the same
// challenge or nonce.
func TestCreateIsUnique(t *testing.T) {
	t.Parallel()

	entropy := counterEntropy()
	expires := testNow().Add(testMaxTTL)

	firstChallenge, firstNonce, err := Create(testKey(), entropy, expires, []byte("a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	secondChallenge, secondNonce, err := Create(testKey(), entropy, expires, []byte("a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if bytes.Equal(firstChallenge, secondChallenge) || bytes.Equal(firstNonce, secondNonce) {
		t.Error("two creates produced the same challenge or nonce")
	}
}

// The slices a caller gets back share no memory with each other, with the
// challenge they were taken from, or with the entropy.

func TestCreateNonceDoesNotAliasChallenge(t *testing.T) {
	t.Parallel()

	challenge, nonce, err := Create(testKey(), counterEntropy(), testNow().Add(testMaxTTL))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	want := bytes.Clone(challenge)

	for i := range nonce {
		nonce[i] = 0xff
	}

	_ = append(nonce, 0xee) // growing the nonce must not write into the challenge either

	if !bytes.Equal(challenge, want) {
		t.Error("mutating the returned nonce changed the challenge")
	}
}

func TestOpenNonceDoesNotAliasChallenge(t *testing.T) {
	t.Parallel()

	challenge := valid(t)
	want := bytes.Clone(challenge)

	nonce, err := Open(testKey(), challenge, testNow(), testMaxTTL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	clear(nonce)

	_ = append(nonce, 0xee)

	if !bytes.Equal(challenge, want) {
		t.Error("mutating the nonce Open returned changed the challenge")
	}

	// And the challenge still opens, to the original nonce.
	again, err := Open(testKey(), challenge, testNow(), testMaxTTL)
	if err != nil || !bytes.Equal(again, firstNonce()) {
		t.Errorf("second Open = %x, %v", again, err)
	}

	// Mutating the challenge afterwards leaves a returned nonce alone.
	clear(challenge)

	if !bytes.Equal(again, firstNonce()) {
		t.Error("mutating the challenge changed the nonce Open returned")
	}
}

func TestCreateChallengeDoesNotAliasNonce(t *testing.T) {
	t.Parallel()

	challenge, nonce, err := Create(testKey(), counterEntropy(), testNow().Add(testMaxTTL))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	clear(challenge)

	if !bytes.Equal(nonce, firstNonce()) {
		t.Error("mutating the returned challenge changed the nonce")
	}
}

func TestOpenCallsReturnDistinctMemory(t *testing.T) {
	t.Parallel()

	challenge := valid(t)

	first, err := Open(testKey(), challenge, testNow(), testMaxTTL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	second, err := Open(testKey(), challenge, testNow(), testMaxTTL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	first[0] ^= 0xff

	if second[0] != firstNonce()[0] {
		t.Error("two nonces from Open share memory")
	}
}

// openCase is one Open call. A case that wants success leaves cause nil.
type openCase struct {
	challenge []byte
	key       []byte
	now       time.Time
	maxTTL    time.Duration
	ad        [][]byte
	cause     error
}

// goodOpen is a call that succeeds against valid(t, ad...): a case copies it
// and breaks one thing.
func goodOpen(t *testing.T, ad ...[]byte) openCase {
	t.Helper()

	return openCase{challenge: valid(t, ad...), key: testKey(), now: testNow(), maxTTL: testMaxTTL, ad: ad, cause: nil}
}

func runOpenCases(t *testing.T, cases map[string]openCase) {
	t.Helper()

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			nonce, err := Open(tt.key, tt.challenge, tt.now, tt.maxTTL, tt.ad...)

			if tt.cause == nil {
				if err != nil {
					t.Fatalf("Open: %v", err)
				}

				if want := firstNonce(); !bytes.Equal(nonce, want) {
					t.Errorf("nonce = %x, want %x", nonce, want)
				}

				return
			}

			if !errors.Is(err, ErrInvalid) || !errors.Is(err, tt.cause) {
				t.Fatalf("err = %v, want ErrInvalid wrapping %v", err, tt.cause)
			}

			if errors.Is(err, ErrEntropy) {
				t.Error("an invalid challenge is not an entropy failure")
			}

			if nonce != nil {
				t.Errorf("a refused challenge returned nonce %x", nonce)
			}
		})
	}
}

func TestOpenRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string][][]byte{
		"no associated data":    nil,
		"one item":              adOf("code"),
		"two items":             adOf("code", "name"),
		"empty item":            adOf(""),
		"empty items":           adOf("", ""),
		"items with NUL":        adOf("a\x00b", "\x00"),
		"large item":            {bytes.Repeat([]byte{'x'}, 1<<16)},
		"many items":            adOf("1", "2", "3", "4", "5", "6", "7", "8"),
		"non-UTF-8 item":        {{0xff, 0xfe, 0x00}},
		"item equal to the tag": {valid(t)[41:]},
	}

	cases := map[string]openCase{}
	for name, data := range tests {
		cases[name] = goodOpen(t, data...)
	}

	runOpenCases(t, cases)
}

// TestOpenAssociatedData: the data supplied at Open must be exactly the data
// supplied at Create: same items, same order, same split, same count.
func TestOpenAssociatedData(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		create [][]byte
		open   [][]byte
		ok     bool
	}{
		"same":                        {create: adOf("code", "name"), open: adOf("code", "name"), ok: true},
		"none and none":               {create: nil, open: nil, ok: true},
		"swapped":                     {create: adOf("code", "name"), open: adOf("name", "code")},
		"first differs":               {create: adOf("code", "name"), open: adOf("Code", "name")},
		"second differs":              {create: adOf("code", "name"), open: adOf("code", "Name")},
		"missing entirely":            {create: adOf("code", "name"), open: nil},
		"missing last":                {create: adOf("code", "name"), open: adOf("code")},
		"missing first":               {create: adOf("code", "name"), open: adOf("name")},
		"extra at the end":            {create: adOf("code"), open: adOf("code", "name")},
		"extra at the start":          {create: adOf("code"), open: adOf("name", "code")},
		"supplied but none bound":     {create: nil, open: adOf("code")},
		"resplit later":               {create: adOf("ab", "c"), open: adOf("a", "bc")},
		"resplit earlier":             {create: adOf("a", "bc"), open: adOf("ab", "c")},
		"merged":                      {create: adOf("a", "b"), open: adOf("ab")},
		"split":                       {create: adOf("ab"), open: adOf("a", "b")},
		"trailing empty item":         {create: adOf("a"), open: adOf("a", "")},
		"leading empty item":          {create: adOf("a"), open: adOf("", "a")},
		"empty item vs none":          {create: adOf(""), open: nil},
		"none vs empty item":          {create: nil, open: adOf("")},
		"one empty vs two empties":    {create: adOf(""), open: adOf("", "")},
		"empty item moved":            {create: adOf("a", "", "b"), open: adOf("a", "b", "")},
		"case folded":                 {create: adOf("Code"), open: adOf("code")},
		"whitespace added":            {create: adOf("code"), open: adOf("code ")},
		"NUL appended":                {create: adOf("code"), open: adOf("code\x00")},
		"hash of the item instead":    {create: adOf("code"), open: [][]byte{sum256("code")}},
		"hashes concatenated":         {create: adOf("a", "b"), open: [][]byte{append(sum256("a"), sum256("b")...)}},
		"concatenation of two hashes": {create: [][]byte{append(sum256("a"), sum256("b")...)}, open: adOf("a", "b")},
	}

	cases := map[string]openCase{}

	for name, tt := range tests {
		call := goodOpen(t, tt.create...)
		call.ad = tt.open

		if !tt.ok {
			call.cause = errTag
		}

		cases[name] = call
	}

	runOpenCases(t, cases)
}

func TestOpenKey(t *testing.T) {
	t.Parallel()

	// Every key here is a full-size one: a key of any other length is ErrKey,
	// not a challenge verdict (TestWrongSizeKeysAreRefused).
	tests := map[string]struct {
		key   []byte
		cause error
	}{
		"same key":                {key: testKey()},
		"different key":           {key: otherKey(), cause: errTag},
		"one bit off":             {key: append(bytes.Clone(testKey()[:31]), testKey()[31]^1), cause: errTag},
		"the challenge's tag":     {key: valid(t)[stateLen:], cause: errTag},
		"all-zero key, full size": {key: make([]byte, KeyLen), cause: errTag},
	}

	cases := map[string]openCase{}

	for name, tt := range tests {
		call := goodOpen(t)
		call.key = tt.key
		call.cause = tt.cause
		cases[name] = call
	}

	runOpenCases(t, cases)
}

// wrongSizeKeys are keys that are not KeyLen bytes. HMAC would zero-pad a short
// one (making an empty key, a short key and the same key with trailing zeros
// one key) and hash a long one, so none is used.
func wrongSizeKeys() map[string][]byte {
	return map[string][]byte{
		"nil":                      nil,
		"empty":                    {},
		"one byte":                 {0x4b},
		"prefix of a good key":     testKey()[:KeyLen-1],
		"half the size":            testKey()[:KeyLen/2],
		"a good key and a suffix":  append(bytes.Clone(testKey()), 1),
		"a good key and a zero":    append(bytes.Clone(testKey()), 0),
		"a good key and zero pads": append(bytes.Clone(testKey()), make([]byte, 32)...),
		"the HMAC block minus one": bytes.Repeat([]byte{0x4b}, 63),
		"the HMAC block size":      bytes.Repeat([]byte{0x4b}, 64),
	}
}

// TestWrongSizeKeysAreRefused: a key that is not KeyLen bytes is the server's
// fault (ErrKey), never a verdict on the challenge (ErrInvalid), and neither
// Create nor Open signs or verifies with it. Open refuses it before it looks at
// the challenge, so even a challenge that was made by the zero-padded
// equivalent of the key does not open.
func TestWrongSizeKeysAreRefused(t *testing.T) {
	t.Parallel()

	for name, key := range wrongSizeKeys() {
		t.Run("create/"+name, func(t *testing.T) {
			t.Parallel()

			entropy := &countingEntropy{}
			issued, nonce, err := Create(key, entropy, testNow().Add(time.Minute))

			requireKeyRefusal(t, err)

			if issued != nil || nonce != nil || entropy.reads != 0 {
				t.Errorf("a refused key returned %x and %x after %d entropy reads", issued, nonce, entropy.reads)
			}
		})

		t.Run("open/"+name, func(t *testing.T) {
			t.Parallel()

			nonce, err := Open(key, valid(t), testNow(), testMaxTTL)

			requireKeyRefusal(t, err)

			if nonce != nil {
				t.Errorf("a refused key returned nonce %x", nonce)
			}
		})
	}
}

// requireKeyRefusal fails the test unless err is ErrKey and nothing else.
func requireKeyRefusal(t *testing.T, err error) {
	t.Helper()

	if !errors.Is(err, ErrKey) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrEntropy) {
		t.Fatalf("err = %v, want ErrKey only", err)
	}
}

// TestZeroPaddedKeyDoesNotOpen pins the property the size rule exists for: a
// challenge made with a short key does not open with the key a derivation would
// have to produce, and one made with a full-size key does not open with its
// short prefix or its zero-padded form (HMAC treats the padded form as the same
// key, so it is refused by size, not by the tag).
func TestZeroPaddedKeyDoesNotOpen(t *testing.T) {
	t.Parallel()

	short := []byte{0x4b, 0x4b}
	padded := append(bytes.Clone(short), make([]byte, KeyLen-len(short))...)

	made := forge(padded, 1, testNowSeconds+60, firstNonce())

	_, err := Open(short, made, testNow(), testMaxTTL)
	if !errors.Is(err, ErrKey) {
		t.Errorf("short key: err = %v, want ErrKey", err)
	}

	_, err = Open(padded, made, testNow(), testMaxTTL)
	if err != nil {
		t.Errorf("full-size zero-padded key: %v, want it to open (it is a full-size key)", err)
	}
}

// countingEntropy counts reads and supplies zero bytes.
type countingEntropy struct{ reads int }

func (c *countingEntropy) Read(p []byte) (int, error) {
	c.reads++

	return len(p), nil
}

// TestOpenRefusesEveryAlteredByte flips each bit position of each byte of a
// valid challenge. Every single alteration must be refused, whichever part it
// lands in: the version, the expiry, the nonce or the tag.
func TestOpenRefusesEveryAlteredByte(t *testing.T) {
	t.Parallel()

	masks := []byte{0x01, 0x80, 0xff}

	cases := map[string]openCase{}

	for _, withData := range []bool{false, true} {
		var data [][]byte
		if withData {
			data = adOf("code", "name")
		}

		for index := range Len {
			for _, mask := range masks {
				call := goodOpen(t, data...)
				call.challenge[index] ^= mask

				// The expiry bytes are the only ones whose alteration could
				// still verify if the tag were not checked; every alteration
				// must fail on the version or the tag, never reach the expiry.
				call.cause = errTag
				if index == 0 {
					call.cause = errVersion
				}

				cases[fmt.Sprintf("data=%t/byte %d xor %#02x", withData, index, mask)] = call
			}
		}
	}

	runOpenCases(t, cases)
}

func TestOpenLength(t *testing.T) {
	t.Parallel()

	good := valid(t)

	tests := map[string][]byte{
		"nil":                     nil,
		"empty":                   {},
		"one byte":                good[:1],
		"state only":              good[:41],
		"state without the nonce": good[:9],
		"one byte short":          good[:Len-1],
		"one byte long":           append(bytes.Clone(good), 0),
		"one byte long, tag-like": append(bytes.Clone(good), good[Len-1]),
		"two copies":              append(bytes.Clone(good), good...),
		"double length zeros":     make([]byte, 2*Len),
		"correct length zeros":    make([]byte, Len),
		"leading byte dropped":    good[1:],
	}

	cases := map[string]openCase{}

	for name, challenge := range tests {
		call := goodOpen(t)
		call.challenge = challenge
		call.cause = errLength

		if name == "correct length zeros" {
			call.cause = errVersion
		}

		cases[name] = call
	}

	runOpenCases(t, cases)
}

// TestOpenVersion: only version 1 opens, even when the tag is correct for the
// bytes presented (so a future layout is never read as this one).
func TestOpenVersion(t *testing.T) {
	t.Parallel()

	cases := map[string]openCase{}

	for _, ver := range []byte{0, 2, 3, 0x7f, 0x80, 0xff} {
		call := goodOpen(t)
		call.challenge = forge(testKey(), ver, expiresAt, firstNonce())
		call.cause = errVersion
		cases[fmt.Sprintf("signed version %d", ver)] = call

		unsigned := goodOpen(t)
		unsigned.challenge[0] = ver
		unsigned.cause = errVersion
		cases[fmt.Sprintf("altered version %d", ver)] = unsigned
	}

	good := goodOpen(t)
	good.challenge = forge(testKey(), 1, expiresAt, firstNonce())
	cases["forged version 1 opens"] = good

	runOpenCases(t, cases)
}

// TestOpenExpiry exercises every boundary of the validity window with
// challenges built by hand, so the expiry is exact. The window is
// (-inf, expires) for now, and expires - now <= maxTTL.
func TestOpenExpiry(t *testing.T) {
	t.Parallel()

	const ttl = testMaxTTL

	at := func(seconds uint64, now time.Time, maxTTL time.Duration) openCase {
		call := goodOpen(t)
		call.challenge = forge(testKey(), 1, seconds, firstNonce())
		call.now = now
		call.maxTTL = maxTTL

		return call
	}

	expires := time.Unix(expiresAt, 0)

	expired := func(call openCase) openCase { call.cause = errExpired; return call }
	future := func(call openCase) openCase { call.cause = errFuture; return call }

	cases := map[string]openCase{
		"well before expiry":             at(expiresAt, expires.Add(-time.Minute), ttl),
		"one second before expiry":       at(expiresAt, expires.Add(-time.Second), ttl),
		"one nanosecond before expiry":   at(expiresAt, expires.Add(-time.Nanosecond), ttl),
		"exactly at expiry":              expired(at(expiresAt, expires, ttl)),
		"one nanosecond after expiry":    expired(at(expiresAt, expires.Add(time.Nanosecond), ttl)),
		"one second after expiry":        expired(at(expiresAt, expires.Add(time.Second), ttl)),
		"a day after expiry":             expired(at(expiresAt, expires.Add(24*time.Hour), ttl)),
		"exactly maxTTL ahead":           at(expiresAt, expires.Add(-ttl), ttl),
		"maxTTL ahead less a nanosecond": at(expiresAt, expires.Add(-ttl+time.Nanosecond), ttl),
		"maxTTL ahead plus a nanosecond": future(at(expiresAt, expires.Add(-ttl-time.Nanosecond), ttl)),
		"maxTTL ahead plus a second":     future(at(expiresAt, expires.Add(-ttl-time.Second), ttl)),
		"a day ahead":                    future(at(expiresAt, expires.Add(-24*time.Hour), ttl)),
		"zero maxTTL, one second left":   future(at(expiresAt, expires.Add(-time.Second), 0)),
		"negative maxTTL":                future(at(expiresAt, expires.Add(-time.Second), -time.Second)),
		"huge maxTTL":                    at(expiresAt, expires.Add(-time.Second), math.MaxInt64),
		"stored as zero":                 expired(at(0, testNow(), ttl)),
		"stored as one":                  expired(at(1, testNow(), ttl)),
		"stored as zero, clock at epoch": expired(at(0, time.Unix(0, 0), ttl)),
		// Whole seconds only: a clock with a fraction is compared exactly.
		"fractional clock before": at(expiresAt, time.Unix(expiresAt-1, 999_999_999), ttl),
		"fractional clock after":  expired(at(expiresAt, time.Unix(expiresAt, 1), ttl)),
		// A huge stored value is unsigned seconds, never a negative number.
		"sign bit set is far ahead, not negative": future(at(1<<63, testNow(), ttl)),
		"all ones is far ahead":                   future(at(math.MaxUint64, testNow(), ttl)),
		"largest signed value is far ahead":       future(at(math.MaxInt64, testNow(), ttl)),
		// Beyond what a Duration holds the value clamps rather than wraps to a
		// negative duration, which would read as long expired.
		"clamped value, one second before it": at(math.MaxUint64, time.Unix(int64(maxSeconds)-1, 0), 10*time.Second),
		"clamped value, at it":                expired(at(math.MaxUint64, time.Unix(int64(maxSeconds), 0), 10*time.Second)),
		"clamped value, far ahead of now":     future(at(math.MaxUint64, testNow(), ttl)),
		"largest unclamped second":            at(maxSeconds, time.Unix(int64(maxSeconds)-1, 0), 10*time.Second),
	}

	runOpenCases(t, cases)
}

// orderingCase is a challenge that fails one or more checks, and the check
// that must be the one reported.
type orderingCase struct {
	challenge []byte
	cause     error
}

func orderingCases() map[string]orderingCase {
	const (
		expiredAt = uint64(testNowSeconds - 1)
		farAt     = uint64(testNowSeconds + 10*365*24*3600)
	)

	x := []byte("x")
	nonce := firstNonce()

	forgedTag := func(challenge []byte) []byte {
		challenge[Len-1] ^= 1

		return challenge
	}

	return map[string]orderingCase{
		"expired and forged is forged": {
			challenge: forgedTag(forge(testKey(), 1, expiredAt, nonce)), cause: errTag,
		},
		"far ahead and forged is forged": {
			challenge: forgedTag(forge(testKey(), 1, farAt, nonce)), cause: errTag,
		},
		"expired, signed by another key": {
			challenge: forge(otherKey(), 1, expiredAt, nonce), cause: errTag,
		},
		"far ahead, signed by another key": {
			challenge: forge(otherKey(), 1, farAt, nonce), cause: errTag,
		},
		"wrong version and forged is version": {
			challenge: forgedTag(forge(testKey(), 2, expiredAt, nonce)), cause: errVersion,
		},
		"wrong length and wrong version": {
			challenge: append(forge(testKey(), 2, expiredAt, nonce), 0), cause: errLength,
		},
		"validly signed and expired": {
			challenge: forge(testKey(), 1, expiredAt, nonce), cause: errExpired,
		},
		"validly signed and far ahead": {
			challenge: forge(testKey(), 1, farAt, nonce), cause: errFuture,
		},
		"bound to other data": {
			challenge: forge(testKey(), 1, expiresAt, nonce, x), cause: errTag,
		},
		"expired and bound to other data": {
			challenge: forge(testKey(), 1, expiredAt, nonce, x), cause: errTag,
		},
		"far ahead and bound to other data": {
			challenge: forge(testKey(), 1, farAt, nonce, x), cause: errTag,
		},
	}
}

// TestOpenChecksInOrder: the cheaper and safer checks come first, and an
// attacker-chosen expiry is never acted on. A challenge that fails several
// checks is reported by the first.
func TestOpenChecksInOrder(t *testing.T) {
	t.Parallel()

	cases := map[string]openCase{}

	for name, tt := range orderingCases() {
		call := goodOpen(t)
		call.challenge = tt.challenge
		call.cause = tt.cause
		cases[name] = call
	}

	runOpenCases(t, cases)
}

// TestCreateOpenAcrossTheWindow: what Create writes, Open accepts for exactly
// the window its expiry defines, including a time with a fraction of a second.
func TestCreateOpenAcrossTheWindow(t *testing.T) {
	t.Parallel()

	fractional := time.Unix(expiresAt, 750_000_000)

	tests := map[string]struct {
		expires time.Time
		now     time.Time
		cause   error
	}{
		"fraction truncates, now one second earlier":  {expires: fractional, now: time.Unix(expiresAt-1, 0)},
		"fraction truncates, now at the whole second": {expires: fractional, now: time.Unix(expiresAt, 0), cause: errExpired},
		"fraction truncates, now at the fraction":     {expires: fractional, now: fractional, cause: errExpired},
		"before the epoch is already expired":         {expires: time.Unix(-5, 0), now: time.Unix(0, 0), cause: errExpired},
		"an hour is too far for a five minute ttl":    {expires: testNow().Add(time.Hour), now: testNow(), cause: errFuture},
		"exactly the ttl":                             {expires: testNow().Add(testMaxTTL), now: testNow()},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			challenge, nonce, err := Create(testKey(), counterEntropy(), tt.expires)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			got, err := Open(testKey(), challenge, tt.now, testMaxTTL)

			if tt.cause == nil {
				if err != nil || !bytes.Equal(got, nonce) {
					t.Errorf("Open = %x, %v, want the nonce %x", got, err, nonce)
				}

				return
			}

			if !errors.Is(err, ErrInvalid) || !errors.Is(err, tt.cause) {
				t.Errorf("err = %v, want ErrInvalid wrapping %v", err, tt.cause)
			}
		})
	}
}

// TestAssociatedDataCountChangesMACInput is the structural claim behind the
// count sensitivity: hashing each item makes it one fixed 32-byte block, so a
// different item count is a MAC input of a different length. It is checked by
// building the MAC input independently and by observing that tags differ.
func TestAssociatedDataCountChangesMACInput(t *testing.T) {
	t.Parallel()

	state := forge(testKey(), 1, expiresAt, firstNonce())[:41]

	seen := map[string]string{}

	for count := range 6 {
		items := make([][]byte, count)
		for i := range items {
			items[i] = []byte{} // every item identical and empty
		}

		input := bytes.Clone(state)
		for _, item := range items {
			input = append(input, sum256(string(item))...)
		}

		if want := 41 + 32*count; len(input) != want {
			t.Errorf("%d items: MAC input is %d bytes, want %d", count, len(input), want)
		}

		tag := hex.EncodeToString(sign(testKey(), state, items))
		if previous, clash := seen[tag]; clash {
			t.Errorf("%d items and %s share a tag", count, previous)
		}

		seen[tag] = fmt.Sprintf("%d items", count)
	}
}

// FuzzOpen: arbitrary bytes as the challenge, the key and associated data
// never panic, never succeed without a valid tag, and fail only with
// ErrInvalid, or with ErrKey when the key is not KeyLen bytes.
func FuzzOpen(f *testing.F) {
	good := forge(testKey(), 1, expiresAt, firstNonce(), []byte("code"), []byte("name"))

	f.Add(good, testKey(), []byte("code"), []byte("name"))
	f.Add(good, testKey(), []byte("code"), []byte("other"))
	f.Add(good, otherKey(), []byte("code"), []byte("name"))
	f.Add(good[:Len-1], testKey(), []byte("code"), []byte("name"))
	f.Add(append(bytes.Clone(good), 0), testKey(), []byte("code"), []byte("name"))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Add(forge(testKey(), 1, math.MaxUint64, firstNonce()), testKey(), []byte{}, []byte{})
	f.Add(forge(testKey(), 2, expiresAt, firstNonce()), testKey(), []byte{}, []byte{})
	f.Add(make([]byte, Len), testKey(), []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, challenge, key, first, second []byte) {
		nonce, err := Open(key, challenge, testNow(), testMaxTTL, first, second)
		if err != nil {
			wrongKey := len(key) != KeyLen
			if wrongKey != errors.Is(err, ErrKey) || (!wrongKey && !errors.Is(err, ErrInvalid)) ||
				errors.Is(err, ErrEntropy) || nonce != nil {
				t.Fatalf("Open = %x, %v", nonce, err)
			}

			return
		}

		// Success is only possible for what the key and data really signed, and
		// then the nonce is the one in place.
		if len(challenge) != Len || !bytes.Equal(nonce, challenge[9:41]) {
			t.Fatalf("Open accepted %x with nonce %x", challenge, nonce)
		}

		if !bytes.Equal(challenge, forge(key, 1, binary.BigEndian.Uint64(challenge[1:9]), nonce, first, second)) {
			t.Fatalf("Open accepted %x, which is not signed for this key and data", challenge)
		}
	})
}
