//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// queryCase is one row of a query-parameter table.
type queryCase struct {
	name   string
	values []string
	want   int // PageLimit.Int() when ok
	ok     bool
}

func limitCases() []queryCase {
	return []queryCase{
		{"absent (nil)", nil, input.DefaultPageLimit, true},
		{"absent (empty slice)", []string{}, input.DefaultPageLimit, true},
		{"min", []string{"1"}, 1, true},
		{"the default spelled out", []string{"25"}, 25, true},
		{"max-1", []string{"99"}, 99, true},
		{"max", []string{"100"}, 100, true},
		{"max+1", []string{"101"}, 0, false},
		{"zero", []string{"0"}, 0, false},
		{"negative", []string{"-1"}, 0, false},
		{"minus zero", []string{"-0"}, 0, false},
		{"plus sign", []string{"+5"}, 0, false},
		{"leading space", []string{" 5"}, 0, false},
		{"trailing space", []string{"5 "}, 0, false},
		{"trailing newline", []string{"5\n"}, 0, false},
		{"leading zero", []string{"05"}, 0, false},
		{"leading zeros on max", []string{"0100"}, 0, false},
		{"double zero", []string{"00"}, 0, false},
		{"empty value present", []string{""}, 0, false},
		{"decimal point", []string{"5.0"}, 0, false},
		{"exponent", []string{"1e1"}, 0, false},
		{"hex", []string{"0x10"}, 0, false},
		{"binary", []string{"0b11"}, 0, false},
		{"separator", []string{"1,0"}, 0, false},
		{"underscore", []string{"1_0"}, 0, false},
		{"word", []string{"all"}, 0, false},
		{"nan", []string{"NaN"}, 0, false},
		{"infinity", []string{"Inf"}, 0, false},
		{"arabic-indic digit", []string{"\u0665"}, 0, false},
		{"fullwidth digits", []string{"\uff11\uff10"}, 0, false},
		{"NUL", []string{"5\x00"}, 0, false},
		{"invalid utf8", []string{"\xff"}, 0, false},
		{"int32 max", []string{"2147483647"}, 0, false},
		{"2^31", []string{"2147483648"}, 0, false},
		{"2^32", []string{"4294967296"}, 0, false},
		{"2^32 + 5 (five when truncated to 32 bits)", []string{"4294967301"}, 0, false},
		{"2^53 - 1", []string{"9007199254740991"}, 0, false},
		{"2^63 - 1", []string{"9223372036854775807"}, 0, false},
		{"2^63", []string{"9223372036854775808"}, 0, false},
		{"2^64 (zero when truncated to 64 bits)", []string{"18446744073709551616"}, 0, false},
		{"overflow length: 100 digits", []string{strings.Repeat("9", 100)}, 0, false},
		{"overflow length: a megabyte of zeros", []string{strings.Repeat("0", 1<<20)}, 0, false},
		{"repeated equal values", []string{"5", "5"}, 0, false},
		{"repeated different values", []string{"5", "6"}, 0, false},
		{"repeated, second invalid", []string{"5", "abc"}, 0, false},
		{"repeated, first empty", []string{"", "5"}, 0, false},
		{"repeated empty values", []string{"", ""}, 0, false},
		{"three values", []string{"1", "2", "3"}, 0, false},
	}
}

func TestParsePageLimit(t *testing.T) {
	t.Parallel()

	_, probe := input.ParsePageLimit([]string{"x"})
	description := descriptionOf(t, probe, input.CodeInvalidLimit)

	for _, tc := range limitCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParsePageLimit(tc.values)
			if !tc.ok {
				requireFixedRefusal(t, err, input.CodeInvalidLimit, description)

				if got.Int() != 0 {
					t.Errorf("refused input returned %d", got.Int())
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			if got.Int() != tc.want {
				t.Errorf("Int() = %d, want %d", got.Int(), tc.want)
			}
		})
	}

	requireMentions(t, description, input.MaxPageLimit)
}

func TestPageLimitDefaultIsInsideTheRange(t *testing.T) {
	t.Parallel()

	if input.DefaultPageLimit < 1 || input.DefaultPageLimit > input.MaxPageLimit {
		t.Fatalf("DefaultPageLimit = %d is outside 1..%d", input.DefaultPageLimit, input.MaxPageLimit)
	}

	got, err := input.ParsePageLimit(nil)
	if err != nil || got.Int() != input.DefaultPageLimit {
		t.Errorf("absent = %v, %v; want the default %d", got, err, input.DefaultPageLimit)
	}
}

var limitPattern = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)

func FuzzParsePageLimit(f *testing.F) {
	for _, tc := range limitCases() {
		if len(tc.values) == 1 && len(tc.values[0]) < 64 {
			f.Add(tc.values[0], uint8(1))
		}
	}

	f.Add("", uint8(0))
	f.Add("5", uint8(2))
	f.Add("", uint8(2))

	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		values := queryValues(raw, mode)
		got, err := input.ParsePageLimit(values)
		want, value := limitOracle(values)

		if !requireOutcome(t, values, err, want, input.CodeInvalidLimit) {
			return
		}

		if got.Int() != value {
			t.Fatalf("Int() = %d for %q, want %d", got.Int(), values, value)
		}

		if len(values) == 1 && strconv.Itoa(got.Int()) != raw {
			t.Fatalf("Int() = %d does not round-trip to %q", got.Int(), raw)
		}
	})
}

// limitOracle restates the PageLimit rule: whether the values are accepted and
// the resulting limit.
func limitOracle(values []string) (bool, int) {
	switch len(values) {
	case 0:
		return true, input.DefaultPageLimit
	case 1:
		if !limitPattern.MatchString(values[0]) {
			return false, 0
		}

		n, err := strconv.Atoi(values[0])

		return err == nil && n >= 1 && n <= input.MaxPageLimit, n
	default:
		return false, 0
	}
}

// queryValues builds the values of a parameter from a fuzz input: mode 0 is an
// absent parameter, 1 a single value, anything else a repeated parameter.
func queryValues(raw string, mode uint8) []string {
	switch mode % 3 {
	case 0:
		return nil
	case 1:
		return []string{raw}
	default:
		return []string{raw, raw}
	}
}

// cursorCase is one row of the cursor table.
type cursorCase struct {
	name   string
	values []string
	first  bool // the first page: ok, with no id
	id     string
	ok     bool
}

func cursorCases() []cursorCase {
	const id = "0194f3a2-7b1c-7d3e-9a4b-123456789abc"

	return []cursorCase{
		{"absent (nil) is the first page", nil, true, "", true},
		{"absent (empty slice) is the first page", []string{}, true, "", true},
		{"one id", []string{id}, false, id, true},
		{"nil uuid", []string{"00000000-0000-0000-0000-000000000000"}, false, "00000000-0000-0000-0000-000000000000", true},
		{"empty value is not the first page", []string{""}, false, "", false},
		{"upper-case", []string{strings.ToUpper(id)}, false, "", false},
		{"no dashes", []string{strings.ReplaceAll(id, "-", "")}, false, "", false},
		{"short", []string{id[:35]}, false, "", false},
		{"long", []string{id + "0"}, false, "", false},
		{"leading space", []string{" " + id[:35]}, false, "", false},
		{"trailing newline", []string{id[:35] + "\n"}, false, "", false},
		{"null", []string{"null"}, false, "", false},
		{"undefined", []string{"undefined"}, false, "", false},
		{"zero", []string{"0"}, false, "", false},
		{"sql quote", []string{"' OR 1=1 --"}, false, "", false},
		{"NUL", []string{id[:35] + "\x00"}, false, "", false},
		{"invalid utf8", []string{"\xff"}, false, "", false},
		{"repeated equal ids", []string{id, id}, false, "", false},
		{"repeated different ids", []string{id, "00000000-0000-0000-0000-000000000000"}, false, "", false},
		{"valid then invalid", []string{id, "x"}, false, "", false},
		{"empty then valid", []string{"", id}, false, "", false},
		{"repeated empty", []string{"", ""}, false, "", false},
	}
}

func TestParseCursor(t *testing.T) {
	t.Parallel()

	_, probe := input.ParseCursor([]string{"x"})
	description := descriptionOf(t, probe, input.CodeInvalidCursor)

	for _, tc := range cursorCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseCursor(tc.values)
			if !tc.ok {
				requireFixedRefusal(t, err, input.CodeInvalidCursor, description)

				if _, set := got.ID(); set {
					t.Error("refused input returned a cursor")
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			id, set := got.ID()
			if set == tc.first || id.String() != tc.id {
				t.Errorf("ID() = %q, %v; want %q, set=%v", id.String(), set, tc.id, !tc.first)
			}
		})
	}
}

// TestZeroCursorIsTheFirstPage: the zero Cursor means "no cursor", the same
// as an absent parameter.
func TestZeroCursorIsTheFirstPage(t *testing.T) {
	t.Parallel()

	var zero input.Cursor

	if id, set := zero.ID(); set || id.String() != "" {
		t.Errorf("zero Cursor = %q, %v", id.String(), set)
	}

	parsed, err := input.ParseCursor(nil)
	if err != nil || parsed != zero {
		t.Errorf("absent = %v, %v; want the zero Cursor", parsed, err)
	}
}

func seedCursors(f *testing.F) {
	f.Helper()

	for _, tc := range cursorCases() {
		if len(tc.values) == 1 {
			f.Add(tc.values[0], uint8(1))
		}
	}

	f.Add("", uint8(0))
	f.Add("0194f3a2-7b1c-7d3e-9a4b-123456789abc", uint8(2))
}

func FuzzParseCursor(f *testing.F) {
	seedCursors(f)

	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		values := queryValues(raw, mode)
		got, err := input.ParseCursor(values)
		want := len(values) == 0 || (len(values) == 1 && uuidPattern.MatchString(raw))

		if !requireOutcome(t, values, err, want, input.CodeInvalidCursor) {
			return
		}

		id, set := got.ID()
		if set != (len(values) == 1) || (set && id.String() != raw) {
			t.Fatalf("ID() = %q, %v for %q", id.String(), set, values)
		}

		again, err := input.ParseCursor(values)
		if err != nil || again != got {
			t.Fatalf("re-parse = %v, %v", again, err)
		}
	})
}
