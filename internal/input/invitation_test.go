//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

func parseInvitationCode(raw string) (string, error) {
	return strAdapter(input.ParseInvitationCode, input.InvitationCode.String)(raw)
}

func invitationCodeCases() []parseCase {
	limit := input.MaxInvitationCodeBytes

	return []parseCase{
		{"one character", "a", true},
		{"typical 32-byte code", "x7Qk2m_Zp-0AbCdEfGhIjKlMnOpQrStUvWxYz012345", true},
		{"whole alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", true},
		{"exactly max", strings.Repeat("A", limit), true},
		{"one over max", strings.Repeat("A", limit+1), false},
		{"far over max", strings.Repeat("A", limit*16), false},
		{"max with a refused character at the end", strings.Repeat("A", limit-1) + "=", false},
		{"empty", "", false},
		{"padding", "dGVzdA==", false},
		{"standard base64 plus", "a+b", false},
		{"standard base64 slash", "a/b", false},
		{"dot (allowed in a token, not in a code)", "a.b", false},
		{"space", "a b", false},
		{"leading space", " abc", false},
		{"trailing space", "abc ", false},
		{"trailing newline", "abc\n", false},
		{"NUL", "abc\x00", false},
		{"tab", "a\tb", false},
		{"multibyte letter", "caf\u00e9", false},
		{"fullwidth letter", "\uff21", false},
		{"zero width space", "ab\u200bcd", false},
		{"invalid utf8", "ab\xffcd", false},
		{"percent escape", "%41", false},
		{"sql quote", "a'b", false},
	}
}

func TestParseInvitationCode(t *testing.T) {
	t.Parallel()
	runStringTable(t, invitationCodeCases(), parseInvitationCode, input.CodeInvalidInvitation)
}

func TestInvitationCodeHash(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		code string
		want string // hex SHA-256 of the code's ASCII bytes (sha256sum)
	}{
		{"abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"one character", "a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
		{
			"typical code is hashed as text, not base64-decoded",
			"x7Qk2m_Zp-0AbCdEfGhIjKlMnOpQrStUvWxYz012345",
			"835be29d8503fe3624c2a21c68ee8874d13e4799074d64a11bd44aa14aa377aa",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			code, err := input.ParseInvitationCode(tc.code)
			if err != nil {
				t.Fatal(err)
			}

			got := code.Hash()
			if len(got) != 32 { // invitations.code_hash: length(code_hash) = 32
				t.Fatalf("len(Hash()) = %d, want 32", len(got))
			}

			if hex.EncodeToString(got) != tc.want {
				t.Errorf("Hash() = %x, want %s", got, tc.want)
			}
		})
	}
}

// TestInvitationCodeHashIsIndependentPerCall proves a caller that scribbles on
// the returned slice cannot change what the next lookup hashes to.
func TestInvitationCodeHashIsIndependentPerCall(t *testing.T) {
	t.Parallel()

	code, err := input.ParseInvitationCode("abc")
	if err != nil {
		t.Fatal(err)
	}

	first := code.Hash()
	want := bytes.Clone(first)

	for i := range first {
		first[i] = 0
	}

	if !bytes.Equal(code.Hash(), want) {
		t.Error("Hash() shares storage between calls")
	}
}

func TestInvitationCodeHashDistinguishesCodes(t *testing.T) {
	t.Parallel()

	a, errA := input.ParseInvitationCode("abc")
	b, errB := input.ParseInvitationCode("abd")

	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}

	if bytes.Equal(a.Hash(), b.Hash()) {
		t.Error("different codes hash alike")
	}
}

var codePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

func FuzzParseInvitationCode(f *testing.F) {
	fuzzString(f, seedsOf(invitationCodeCases()), input.ParseInvitationCode, input.InvitationCode.String,
		input.CodeInvalidInvitation, codePattern.MatchString)
}

func TestInvitationDescriptionsStateTheBounds(t *testing.T) {
	t.Parallel()

	_, err := parseInvitationCode("")
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidInvitation), input.MaxInvitationCodeBytes)

	_, err = input.ParseNumInvites(0)
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidNumInvites), input.MaxNumInvites)
}

//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestParseNumInvites(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   int64
		ok   bool
	}{
		{"one", 1, true},
		{"two", 2, true},
		{"mid", 500, true},
		{"max-1", input.MaxNumInvites - 1, true},
		{"max", input.MaxNumInvites, true},
		{"max+1", input.MaxNumInvites + 1, false},
		{"zero", 0, false},
		{"minus one", -1, false},
		{"int32 max", math.MaxInt32, false},
		{"int32 max + 1", math.MaxInt32 + 1, false},
		{"2^32 (zero when truncated to 32 bits)", 1 << 32, false},
		{"2^32 + 1 (one when truncated to 32 bits)", 1<<32 + 1, false},
		{"safe max", input.MaxSafeInteger, false},
		{"safe max + 1", input.MaxSafeInteger + 1, false},
		{"int64 max", math.MaxInt64, false},
		{"int64 min", math.MinInt64, false},
		{"int32 min", math.MinInt32, false},
	}

	var description string

	for _, tc := range cases {
		if !tc.ok {
			_, err := input.ParseNumInvites(tc.in)
			description = descriptionOf(t, err, input.CodeInvalidNumInvites)

			break
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseNumInvites(tc.in)
			if !tc.ok {
				requireFixedRefusal(t, err, input.CodeInvalidNumInvites, description)

				if got.Int64() != 0 {
					t.Errorf("refused input returned %d", got.Int64())
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			if got.Int64() != tc.in {
				t.Errorf("Int64() = %d, want %d", got.Int64(), tc.in)
			}
		})
	}
}

func FuzzParseNumInvites(f *testing.F) {
	for _, seed := range []int64{
		0, 1, 2, input.MaxNumInvites, input.MaxNumInvites + 1, -1, math.MaxInt32, 1 << 32,
		input.MaxSafeInteger, input.MaxSafeInteger + 1, math.MaxInt64, math.MinInt64,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw int64) {
		got, err := input.ParseNumInvites(raw)
		if !requireOutcome(t, raw, err, raw >= 1 && raw <= input.MaxNumInvites, input.CodeInvalidNumInvites) {
			return
		}

		if got.Int64() != raw || got.Int64() > input.MaxSafeInteger {
			t.Fatalf("Int64() = %d, want %d within the safe range", got.Int64(), raw)
		}

		again, err := input.ParseNumInvites(got.Int64())
		if err != nil || again != got {
			t.Fatalf("re-parse = %v, %v", again, err)
		}
	})
}

// expiryNowUnix is the clock of the Expiry tests: a whole second, so the table
// can be read in plain offsets.
const expiryNowUnix = 1_800_000_000

func expiryNow() time.Time { return time.Unix(expiryNowUnix, 0) }

//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestParseExpiry(t *testing.T) {
	t.Parallel()

	horizon := int64(input.ExpiryHorizon / time.Second)
	now := int64(expiryNowUnix)

	cases := []struct {
		name string
		now  time.Time
		in   int64
		ok   bool
	}{
		{"one second ahead", expiryNow(), now + 1, true},
		{"one day ahead", expiryNow(), now + 86400, true},
		{"one year ahead", expiryNow(), now + 365*86400, true},
		{"exactly the horizon", expiryNow(), now + horizon, true},
		{"horizon + 1s", expiryNow(), now + horizon + 1, false},
		{"horizon + 1 year", expiryNow(), now + horizon + 365*86400, false},
		{"exactly now", expiryNow(), now, false},
		{"one second ago", expiryNow(), now - 1, false},
		{"a day ago", expiryNow(), now - 86400, false},
		{"epoch", expiryNow(), 0, false},
		{"minus one", expiryNow(), -1, false},
		{"int64 min", expiryNow(), math.MinInt64, false},
		{"int64 max", expiryNow(), math.MaxInt64, false},
		{"safe max", expiryNow(), input.MaxSafeInteger, false},
		{"safe max + 1", expiryNow(), input.MaxSafeInteger + 1, false},
		{"int32 max (2038) when now is later", expiryNow(), math.MaxInt32, false},
		{"milliseconds mistaken for seconds", expiryNow(), now * 1000, false},
		{"microseconds mistaken for seconds", expiryNow(), now * 1_000_000, false},

		// A fractional clock: unix is whole seconds, now is not.
		{"fractional now: same second is in the past", time.Unix(now, 500_000_000), now, false},
		{"fractional now: next second", time.Unix(now, 500_000_000), now + 1, true},
		{"fractional now: horizon", time.Unix(now, 500_000_000), now + horizon, true},
		{"fractional now: horizon + 1s", time.Unix(now, 500_000_000), now + horizon + 1, false},
		{"fractional now just before the next second: next second", time.Unix(now, 999_999_999), now + 1, true},
		{"nanosecond past a second: the same second", time.Unix(now, 1), now, false},

		// Limits of the clock itself.
		{"clock near the safe max: in range", time.Unix(input.MaxSafeInteger-10, 0), input.MaxSafeInteger, true},
		{"clock near the safe max: past it", time.Unix(input.MaxSafeInteger-10, 0), input.MaxSafeInteger + 1, false},
		{"clock at the safe max: nothing is ahead", time.Unix(input.MaxSafeInteger, 0), input.MaxSafeInteger, false},
		{"clock before 1970: next second", time.Unix(-100, 0), -99, true},
		{"clock before 1970: the past", time.Unix(-100, 0), -101, false},
		{"clock before 1970: beyond the safe min", time.Unix(-input.MaxSafeInteger-5, 0), -input.MaxSafeInteger - 1, false},
		{"clock before 1970: int64 min", time.Unix(math.MinInt64/2, 0), math.MinInt64, false},
		{"zero time as the clock", time.Time{}, now, false},
		{"zero time as the clock: near", time.Time{}, -62135596800 + 1, true},
	}

	var description string

	for _, tc := range cases {
		if !tc.ok {
			_, err := input.ParseExpiry(tc.in, tc.now)
			description = descriptionOf(t, err, input.CodeInvalidExpiresAt)

			break
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseExpiry(tc.in, tc.now)
			if !tc.ok {
				requireFixedRefusal(t, err, input.CodeInvalidExpiresAt, description)

				if got.Unix() != 0 {
					t.Errorf("refused input returned %d", got.Unix())
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			if got.Unix() != tc.in {
				t.Errorf("Unix() = %d, want %d", got.Unix(), tc.in)
			}
		})
	}
}

// TestExpiryStaysWithinSafeIntegers: for any plausible clock the largest
// accepted value is far below 2^53-1, so D1 stores it exactly.
func TestExpiryStaysWithinSafeIntegers(t *testing.T) {
	t.Parallel()

	for _, year := range []int{2026, 2100, 3000, 9999} {
		now := time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC)
		latest := now.Add(input.ExpiryHorizon).Unix()

		got, err := input.ParseExpiry(latest, now)
		if err != nil {
			t.Fatalf("year %d: refused the horizon: %v", year, err)
		}

		if got.Unix() > input.MaxSafeInteger/1000 {
			t.Errorf("year %d: %d is not comfortably below 2^53-1", year, got.Unix())
		}
	}
}

// TestIntegerBoundsAreSafe: every integer bound is within 2^53-1.
func TestIntegerBoundsAreSafe(t *testing.T) {
	t.Parallel()

	bounds := map[string]int64{
		"MaxNumInvites":          input.MaxNumInvites,
		"MaxPageLimit":           input.MaxPageLimit,
		"DefaultPageLimit":       input.DefaultPageLimit,
		"MaxTokenBytes":          input.MaxTokenBytes,
		"MaxInvitationCodeBytes": input.MaxInvitationCodeBytes,
		"ExpiryHorizon seconds":  int64(input.ExpiryHorizon / time.Second),
	}

	for name, bound := range bounds {
		if bound > input.MaxSafeInteger || bound < 0 {
			t.Errorf("%s = %d is outside 0..2^53-1", name, bound)
		}
	}
}

func FuzzParseExpiry(f *testing.F) {
	now := int64(expiryNowUnix)
	horizon := int64(input.ExpiryHorizon / time.Second)

	for _, seed := range []struct{ unix, nowSec, nanos int64 }{
		{now + 1, now, 0},
		{now, now, 0},
		{now - 1, now, 0},
		{now + horizon, now, 0},
		{now + horizon + 1, now, 0},
		{now + 1, now, 999_999_999},
		{now + horizon, now, 999_999_999},
		{now + horizon + 1, now, 500_000_000},
		{input.MaxSafeInteger, input.MaxSafeInteger - 10, 0},
		{input.MaxSafeInteger + 1, input.MaxSafeInteger - 10, 0},
		{math.MaxInt64, now, 0},
		{math.MinInt64, now, 0},
		{math.MinInt64 + 1, math.MinInt64 / 2, 0},
		{0, now, 0},
		{-input.MaxSafeInteger, -input.MaxSafeInteger - 5, 0},
	} {
		f.Add(seed.unix, seed.nowSec, seed.nanos)
	}

	f.Fuzz(func(t *testing.T, unix, nowSec, nanos int64) {
		// Keep the clock a representable time.Time: far beyond this the
		// standard library itself wraps, which is not what is under test.
		nowSec %= 1 << 60
		now := time.Unix(nowSec, nanos%1_000_000_000)

		got, err := input.ParseExpiry(unix, now)
		if !requireOutcome(t, unix, err, expiryOracle(unix, now), input.CodeInvalidExpiresAt) {
			return
		}

		if got.Unix() != unix {
			t.Fatalf("Unix() = %d, want %d", got.Unix(), unix)
		}

		again, err := input.ParseExpiry(got.Unix(), now)
		if err != nil || again != got {
			t.Fatalf("re-parse = %v, %v", again, err)
		}
	})
}

// expiryOracle restates the Expiry rule in whole seconds with big integers, so
// it cannot overflow: after now's second, at most the horizon beyond it, and a
// safe integer. A fractional now agrees with this because unix is whole.
func expiryOracle(unix int64, now time.Time) bool {
	horizon := big.NewInt(int64(input.ExpiryHorizon / time.Second))
	diff := new(big.Int).Sub(big.NewInt(unix), big.NewInt(now.Unix()))

	return diff.Sign() > 0 && diff.Cmp(horizon) <= 0 &&
		unix <= input.MaxSafeInteger && unix >= -input.MaxSafeInteger
}
