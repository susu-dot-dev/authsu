//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

func TestMaxSafeInteger(t *testing.T) {
	t.Parallel()

	if input.MaxSafeInteger != 9007199254740991 {
		t.Fatalf("MaxSafeInteger = %d, want 2^53-1", input.MaxSafeInteger)
	}

	// 2^53-1 survives a trip through a float64 (a JS number) and 2^53+1 does
	// not, which is the reason for the limit.
	if int64(float64(input.MaxSafeInteger)) != input.MaxSafeInteger {
		t.Error("2^53-1 does not survive float64")
	}

	if int64(float64(input.MaxSafeInteger+2)) == input.MaxSafeInteger+2 {
		t.Error("2^53+1 unexpectedly survives float64")
	}
}

//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestDisplayText(t *testing.T) {
	t.Parallel()

	type rule struct {
		name        string
		runes       bool
		limit       int
		allowEmpty  bool
		identifying bool
	}

	// Wide enough for every sweep input, so only the content rules decide.
	sweeps := []rule{
		{"bytes", false, 64, false, true},
		{"runes", true, 64, false, false},
		{"runes allowing empty", true, 64, true, false},
		{"identifying runes", true, 64, false, true},
	}

	for _, rl := range sweeps {
		for _, tc := range slices.Concat(hostileText(), goodText(), joinerText(rl.identifying)) {
			t.Run(rl.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				if got := input.DisplayText(tc.in, rl.runes, rl.limit, rl.allowEmpty, rl.identifying); got != tc.ok {
					t.Errorf("DisplayText(%q) = %v, want %v", tc.in, got, tc.ok)
				}
			})
		}
	}

	bounds := []struct {
		name       string
		in         string
		runes      bool
		limit      int
		allowEmpty bool
		want       bool
	}{
		{"empty refused", "", false, 4, false, false},
		{"empty allowed", "", false, 4, true, true},
		{"empty allowed in runes", "", true, 4, true, true},
		{"blank is not empty even when empty is allowed", " ", true, 4, true, false},
		{"bytes: exactly max", "abcd", false, 4, false, true},
		{"bytes: max+1", "abcde", false, 4, false, false},
		{"bytes: two two-byte runes fill max", "\u00e9\u00e9", false, 4, false, true},
		{"bytes: three two-byte runes", "\u00e9\u00e9\u00e9", false, 4, false, false},
		{"bytes: rune straddles max", "abc\u00e9", false, 4, false, false},
		{"bytes: four-byte rune fills max", "\U0001F600", false, 4, false, true},
		{"bytes: four-byte rune plus one", "\U0001F600a", false, 4, false, false},
		{"bytes: max 1, one char", "a", false, 1, false, true},
		{"bytes: max 1, two-byte rune", "\u00e9", false, 1, false, false},
		{"runes: exactly max", "abcd", true, 4, false, true},
		{"runes: max+1", "abcde", true, 4, false, false},
		{"runes: max four-byte runes, the byte fast-path limit", strings.Repeat("\U0001F600", 4), true, 4, false, true},
		{"runes: max four-byte runes plus one", strings.Repeat("\U0001F600", 4) + "a", true, 4, false, false},
		{"runes: byte length within 4*max but more runes than max", "abcdefgh", true, 4, false, false},
		{"runes: five runes, within 4*max bytes", strings.Repeat("\u00e9", 5), true, 4, false, false},
		{"runes: one byte over 4*max is refused before scanning", strings.Repeat("a", 17), true, 4, false, false},
		{"runes: max 1, one four-byte rune", "\U0001F600", true, 1, false, true},
		{"runes: max 1, two runes", "ab", true, 1, false, false},
		{"hostile tail beyond the bound is still a refusal", "abcde\x00", true, 4, false, false},
		{"hostile inside the bound", "ab\x00d", true, 4, false, false},
		{"NFD pair counts as two runes and is refused as NFD", "e\u0301", true, 4, false, false},
		{"NFC form of the same text is accepted", "\u00e9", true, 4, false, true},
		{"max 0 admits only empty when allowed", "", true, 0, true, true},
		{"max 0 refuses anything else", "a", true, 0, true, false},
	}

	for _, tc := range bounds {
		t.Run("bounds/"+tc.name, func(t *testing.T) {
			t.Parallel()

			if got := input.DisplayText(tc.in, tc.runes, tc.limit, tc.allowEmpty, true); got != tc.want {
				t.Errorf("DisplayText(%q, runes=%v, max=%d, allowEmpty=%v) = %v, want %v",
					tc.in, tc.runes, tc.limit, tc.allowEmpty, got, tc.want)
			}
		})
	}
}

//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestDecimal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		in     string
		lo, hi int64
		want   int64
		ok     bool
	}{
		{"zero", "0", 0, 0, 0, true},
		{"zero below lo", "0", 1, 100, 0, false},
		{"lo", "1", 1, 100, 1, true},
		{"hi", "100", 1, 100, 100, true},
		{"hi+1 has the same digit count", "101", 1, 100, 0, false},
		{"hi+1 has more digits", "1000", 1, 100, 0, false},
		{"all nines of the same digit count", "999", 1, 100, 0, false},
		{"mid", "42", 1, 100, 42, true},
		{"single digit hi", "9", 0, 9, 9, true},
		{"single digit over hi", "10", 0, 9, 0, false},
		{"empty", "", 0, 100, 0, false},
		{"leading zero", "01", 0, 100, 0, false},
		{"leading zeros", "007", 0, 100, 0, false},
		{"double zero", "00", 0, 100, 0, false},
		{"plus sign", "+1", 0, 100, 0, false},
		{"minus sign", "-1", 0, 100, 0, false},
		{"minus zero", "-0", 0, 100, 0, false},
		{"leading space", " 1", 0, 100, 0, false},
		{"trailing space", "1 ", 0, 100, 0, false},
		{"trailing newline", "1\n", 0, 100, 0, false},
		{"embedded space", "1 0", 0, 100, 0, false},
		{"NUL", "1\x00", 0, 100, 0, false},
		{"decimal point", "1.0", 0, 100, 0, false},
		{"exponent", "1e1", 0, 100, 0, false},
		{"hex", "0x10", 0, 100, 0, false},
		{"separator", "1,0", 0, 100, 0, false},
		{"underscore", "1_0", 0, 100, 0, false},
		{"letter", "a", 0, 100, 0, false},
		{"arabic-indic digit", "\u0665", 0, 100, 0, false},
		{"fullwidth digits", "\uff11\uff10", 0, 100, 0, false},
		{"digit then multibyte", "1\u00e9", 0, 100, 0, false},
		{"invalid utf8", "\xff", 0, 100, 0, false},
		{"slash below the digits", "/", 0, 100, 0, false},
		{"colon above the digits", ":", 0, 100, 0, false},
		{"overflow length: int64 max plus one", "9223372036854775808", 0, 100, 0, false},
		{"overflow length: 20 digits", "99999999999999999999", 0, 100, 0, false},
		{"overflow length: uint64 max plus one", "18446744073709551616", 0, 100, 0, false},
		{"overflow length: 100 digits", strings.Repeat("9", 100), 0, 100, 0, false},
		{"overflow length with leading zeros", "000000000000000000000001", 0, 100, 0, false},
		{"safe max", "9007199254740991", 0, input.MaxSafeInteger, input.MaxSafeInteger, true},
		{"safe max + 1 (same digits)", "9007199254740992", 0, input.MaxSafeInteger, 0, false},
		{"all nines, same digit count as safe max", "9999999999999999", 0, input.MaxSafeInteger, 0, false},
		{"one more digit than safe max", "10000000000000000", 0, input.MaxSafeInteger, 0, false},
		{"2^32", "4294967296", 0, 10000, 0, false},
		{"2^31", "2147483648", 0, 10000, 0, false},
		{"10000 with hi 10000", "10000", 1, 10000, 10000, true},
		{"10001 with hi 10000", "10001", 1, 10000, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := input.Decimal(tc.in, tc.lo, tc.hi)
			if ok != tc.ok || got != tc.want {
				t.Errorf("Decimal(%q, %d, %d) = %d, %v; want %d, %v", tc.in, tc.lo, tc.hi, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestSingleValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		values      []string
		wantValue   string
		wantPresent bool
		wantOK      bool
	}{
		{"nil is absent", nil, "", false, true},
		{"empty slice is absent", []string{}, "", false, true},
		{"one value", []string{"x"}, "x", true, true},
		{"one empty value is present", []string{""}, "", true, true},
		{"two equal values are refused", []string{"x", "x"}, "", false, false},
		{"two different values are refused", []string{"x", "y"}, "", false, false},
		{"two empty values are refused", []string{"", ""}, "", false, false},
		{"three values are refused", []string{"x", "y", "z"}, "", false, false},
		{"absent first then present is still two", []string{"", "x"}, "", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			value, present, ok := input.SingleValue(tc.values)
			if value != tc.wantValue || present != tc.wantPresent || ok != tc.wantOK {
				t.Errorf("SingleValue(%q) = %q, %v, %v; want %q, %v, %v",
					tc.values, value, present, ok, tc.wantValue, tc.wantPresent, tc.wantOK)
			}
		})
	}
}

//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestCanonicalUUID(t *testing.T) {
	t.Parallel()

	const good = "0194f3a2-7b1c-7d3e-9a4b-123456789abc"

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"v7 sample", good, true},
		{"v4 sample", "f47ac10b-58cc-4372-a567-0e02b2c3d479", true},
		{"nil uuid", "00000000-0000-0000-0000-000000000000", true},
		{"max uuid", "ffffffff-ffff-ffff-ffff-ffffffffffff", true},
		{"all hex digits", "01234567-89ab-cdef-0123-456789abcdef", true},
		{"empty", "", false},
		{"upper-case", strings.ToUpper(good), false},
		{"one upper-case letter at the start", "A194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"one upper-case letter at the end", "0194f3a2-7b1c-7d3e-9a4b-123456789abC", false},
		{"35 characters", good[:35], false},
		{"37 characters", good + "0", false},
		{"no dashes", strings.ReplaceAll(good, "-", ""), false},
		{"dashes only", strings.Repeat("-", 36), false},
		{"dash moved earlier (7)", "0194f3a-27b1c-7d3e-9a4b-123456789abc", false},
		{"dash moved later (9)", "0194f3a27-b1c-7d3e-9a4b-123456789abc", false},
		{"second dash at 12", "0194f3a2-7b1-c7d3e-9a4b-123456789abc", false},
		{"second dash at 14", "0194f3a2-7b1c7-d3e-9a4b-123456789abc", false},
		{"third dash at 17", "0194f3a2-7b1c-7d3-e9a4b-123456789abc", false},
		{"third dash at 19", "0194f3a2-7b1c-7d3e9-a4b-123456789abc", false},
		{"fourth dash at 22", "0194f3a2-7b1c-7d3e-9a4-b123456789abc", false},
		{"fourth dash at 24", "0194f3a2-7b1c-7d3e-9a4b1-23456789abc", false},
		{"dash replaced by hex at 8", "0194f3a207b1c-7d3e-9a4b-123456789abc", false},
		{"dash replaced by hex at 23", "0194f3a2-7b1c-7d3e-9a4b0123456789abc", false},
		{"extra dash in the last group", "0194f3a2-7b1c-7d3e-9a4b-12345678-abc", false},
		{"non-hex g", "0194f3a2-7b1c-7d3e-9a4b-123456789abg", false},
		{"non-hex x at the start", "x194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"slash just below the digits", "/194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"colon just above the digits", ":194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"backtick just below a", "`194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"g just above f", "g194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"braces", "{" + good + "}", false},
		{"urn prefix", "urn:uuid:" + good, false},
		{"leading space", " " + good[:35], false},
		{"trailing space", good[:35] + " ", false},
		{"trailing newline", good[:35] + "\n", false},
		{"NUL", good[:35] + "\x00", false},
		{"NUL then a valid uuid", "\x00" + good, false},
		{"two uuids", good + good, false},
		{"hyphen look-alike U+2010 (3 bytes) for a dash", "0194f3a2\u20107b1c-7d3e-9a4b-123456789abc", false},
		{"arabic-indic digit, 36 bytes", "\u0660194f3a2-7b1c-7d3e-9a4b-123456789a", false},
		{"fullwidth digit", "\uff10194f3a2-7b1c-7d3e-9a4b-123456789a", false},
		{"invalid utf8 byte, 36 bytes", "\xff194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"sql quote", "' OR '1'='1' --", false},
		{"percent wildcard", "%194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"path traversal", "../../../../../../../etc/passwd/xxxx", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := input.CanonicalUUID(tc.in); got != tc.want {
				t.Errorf("CanonicalUUID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestBase64URL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty (callers bound the length)", "", true},
		{"lower-case", "abcdefghijklmnopqrstuvwxyz", true},
		{"upper-case", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", true},
		{"digits", "0123456789", true},
		{"underscore and dash", "_-", true},
		{"typical", "dGVzdC1jb2RlXzEyMw", true},
		{"padding", "dGVzdA==", false},
		{"standard plus", "a+b", false},
		{"standard slash", "a/b", false},
		{"dot", "a.b", false},
		{"space", "a b", false},
		{"leading space", " ab", false},
		{"trailing newline", "ab\n", false},
		{"NUL", "ab\x00", false},
		{"tab", "a\tb", false},
		{"DEL", "a\x7f", false},
		{"high byte", "a\x80", false},
		{"invalid utf8", "a\xff", false},
		{"multibyte letter", "caf\u00e9", false},
		{"fullwidth letter", "\uff21", false},
		{"percent escape", "%41", false},
		{"colon", "a:b", false},
		{"at", "a@b", false},
		{"bracket just above Z", "A[", false},
		{"backtick just above Z range end", "a`", false},
		{"brace just above z", "z{", false},
		{"slash just below 0", "0/", false},
		{"colon just above 9", "9:", false},
		{"at just below A", "@A", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := input.Base64URL(tc.in); got != tc.want {
				t.Errorf("Base64URL(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestBase64URLEveryByte checks all 256 byte values against the alphabet
// spelled out, so no byte is accepted or refused by accident.
func TestBase64URLEveryByte(t *testing.T) {
	t.Parallel()

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	for b := range 256 {
		in := string([]byte{byte(b)})
		want := strings.Contains(alphabet, in)

		t.Run(strconv.Itoa(b), func(t *testing.T) {
			t.Parallel()

			if got := input.Base64URL(in); got != want {
				t.Errorf("Base64URL(byte %#x) = %v, want %v", b, got, want)
			}
		})
	}
}
