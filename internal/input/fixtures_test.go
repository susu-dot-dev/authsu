//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/susu-dot-dev/authsu/internal/apierr"
)

// parseCase is one row of a string-parser table.
type parseCase struct {
	name string
	in   string
	ok   bool
}

// requireRefusal fails the test unless err is the BadRequest *apierr.Error a
// parser promises: the type's code, no data and no cause.
func requireRefusal(t *testing.T, err error, code string) {
	t.Helper()

	_ = refusalOf(t, err, code)
}

// refusalOf is requireRefusal that also returns the error, so a caller can
// compare descriptions.
func refusalOf(t *testing.T, err error, code string) *apierr.Error {
	t.Helper()

	got, ok := errors.AsType[*apierr.Error](err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *apierr.Error", err, err)
	}

	if got.Kind != apierr.BadRequest {
		t.Errorf("kind = %v, want BadRequest", got.Kind)
	}

	if got.Code != code {
		t.Errorf("code = %q, want %q", got.Code, code)
	}

	if got.Data != nil {
		t.Errorf("data = %v, want nil", got.Data)
	}

	cause := got.Unwrap()
	if cause != nil {
		t.Errorf("cause = %v, want nil", cause)
	}

	return got
}

// requireFixedRefusal is requireRefusal plus a check that the description is
// the type's one fixed text: a description that varied with the input could be
// echoing it.
func requireFixedRefusal(t *testing.T, err error, code, description string) {
	t.Helper()

	got := refusalOf(t, err, code)
	if got.Description != description {
		t.Errorf("description = %q, want the fixed %q", got.Description, description)
	}
}

// descriptionOf returns the description of the refusal err, failing the test if
// err is not one. Tests call it once, on a known-bad input, to learn the fixed
// text of a type.
func descriptionOf(t *testing.T, err error, code string) string {
	t.Helper()

	return refusalOf(t, err, code).Description
}

// hostileText is display text that every display-text type must refuse.
func hostileText() []parseCase {
	return []parseCase{
		{"NUL alone", "\x00", false},
		{"NUL inside", "a\x00b", false},
		{"NUL at the end", "name\x00", false},
		{"C0 control SOH", "a\x01b", false},
		{"tab", "a\tb", false},
		{"line feed", "a\nb", false},
		{"carriage return", "a\rb", false},
		{"escape", "a\x1bb", false},
		{"DEL", "a\x7fb", false},
		{"C1 control PAD", "a\u0080b", false},
		{"C1 control NEL", "a\u0085b", false},
		{"C1 control APC", "a\u009fb", false},
		{"bidi LRE", "a\u202ab", false},
		{"bidi RLE", "a\u202bb", false},
		{"bidi PDF", "a\u202cb", false},
		{"bidi LRO", "a\u202db", false},
		{"bidi RLO", "a\u202eb", false},
		{"bidi LRI", "a\u2066b", false},
		{"bidi RLI", "a\u2067b", false},
		{"bidi FSI", "a\u2068b", false},
		{"bidi PDI", "a\u2069b", false},
		{"LRM mark", "a\u200eb", false},
		{"RLM mark", "a\u200fb", false},
		{"arabic letter mark", "a\u061cb", false},
		{"zero width space", "a\u200bb", false},
		{"word joiner", "a\u2060b", false},
		{"byte order mark", "\ufeffname", false},
		{"soft hyphen", "a\u00adb", false},
		{"interlinear annotation", "a\ufff9b", false},
		{"tag character", "a\U000E0041b", false},
		{"replacement character", "a\ufffdb", false},
		{"replacement character alone", "\ufffd", false},
		{"invalid UTF-8 byte", "a\xffb", false},
		{"invalid UTF-8 lone continuation", "a\x80b", false},
		{"truncated multibyte", "a\xe2\x82", false},
		{"overlong slash", "a\xc0\xafb", false},
		{"encoded surrogate", "a\xed\xa0\x80b", false},
		{"above U+10FFFF", "a\xf4\x90\x80\x80b", false},
		{"decomposed e acute (NFD)", "caf" + "e\u0301", false},
		{"decomposed A ring (NFD)", "A\u030a", false},
		{"decomposed Hangul (NFD)", "\u1112\u1161\u11ab", false},
		{"empty-looking: space", " ", false},
		{"blank: spaces", "   ", false},
		{"blank: no-break space", "\u00a0", false},
		{"blank: em space", "\u2003", false},
		{"blank: ideographic space", "\u3000", false},
		{"blank: line separator", "\u2028", false},
		{"blank: paragraph separator", "\u2029", false},
		{"blank: mixed spaces", " \u00a0\u3000 ", false},
	}
}

// joinerText is text whose joiners (U+200C zero-width non-joiner, U+200D
// zero-width joiner) decide the outcome: refused for text that identifies
// someone (an account name), accepted for other display text. Text that has no
// character besides joiners is blank for both.
func joinerText(identifying bool) []parseCase {
	ok := !identifying

	return []parseCase{
		{"zero width non-joiner between letters", "a\u200cb", ok},
		{"zero width joiner between letters", "a\u200db", ok},
		{"emoji ZWJ sequence", "\U0001F468\u200d\U0001F469\u200d\U0001F467", ok},
		{"emoji with skin tone and ZWJ", "\U0001F9D1\U0001F3FD\u200d\U0001F4BB", ok},
		{"Persian word with a ZWNJ", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", ok},
		{"Devanagari conjunct with a ZWJ", "\u0915\u094d\u200d\u0937", ok},
		{"Sinhala with a ZWJ", "\u0d9a\u0dca\u200d\u0dbb", ok},
		{"joiner at the start", "\u200dabc", ok},
		{"joiner at the end", "abc\u200c", ok},
		{"only joiners is blank", "\u200c\u200d", false},
		{"one joiner alone is blank", "\u200d", false},
		{"joiners and spaces only are blank", " \u200d \u200c", false},
	}
}

// goodText is display text that every display-text type accepts (each is short
// enough for the smallest bound, 128 bytes).
func goodText() []parseCase {
	return []parseCase{
		{"one letter", "a", true},
		{"ascii word", "Alice", true},
		{"inner space", "Alice Smith", true},
		{"leading space is kept, never trimmed", " Alice", true},
		{"trailing space is kept, never trimmed", "Alice ", true},
		{"precomposed e acute (NFC)", "caf\u00e9", true},
		{"precomposed A ring (NFC)", "\u00c5", true},
		{"CJK", "\u65e5\u672c\u8a9e", true},
		{"Hangul syllables (NFC)", "\ud55c\uae00", true},
		{"emoji outside the BMP", "\U0001F600", true},
		{"emoji with variation selector", "\u2764\ufe0f", true},
		{"combining mark with no NFC composition", "q\u0301", true},
		{"right to left text without controls", "\u05e9\u05dc\u05d5\u05dd", true},
		{"punctuation", "O'Brien-Smith, Jr. <a&b> \"q\"", true},
		{"digits only", "12345", true},
		{"non-breaking space between letters", "a\u00a0b", true},
	}
}

// isJoiner reports whether r is U+200C or U+200D.
func isJoiner(r rune) bool { return r == '\u200c' || r == '\u200d' }

// hostileRunes reports whether s contains a rune a display-text type must
// never accept. Fuzz tests use it as the oracle. The joiners are hostile only
// to text that identifies someone.
func hostileRunes(s string, identifying bool) bool {
	if !utf8.ValidString(s) {
		return true
	}

	for _, r := range s {
		if isJoiner(r) && !identifying {
			continue
		}

		if r == utf8.RuneError || unicode.In(r, unicode.Cc, unicode.Cf) {
			return true
		}
	}

	return !norm.NFC.IsNormalString(s)
}

// blank reports whether s is empty, or only whitespace (and, for text that may
// hold them, joiners).
func blank(s string, identifying bool) bool {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (!identifying && isJoiner(r))
	}) == ""
}

// textSpec describes one display-text type for textCases.
type textSpec struct {
	max        int
	runes      bool // max counts runes, not bytes
	allowEmpty bool
	// identifying is text a person is recognised by: it refuses the joiners
	// that other display text accepts.
	identifying bool
}

// textCases is the table for one display-text type: the shared hostile and good
// inputs, then the type's own bound in its own unit.
func textCases(spec textSpec) []parseCase {
	cases := slices.Concat(hostileText(), goodText(), joinerText(spec.identifying))

	cases = append(cases,
		parseCase{"empty", "", spec.allowEmpty},
		parseCase{"exactly max of one-byte characters", strings.Repeat("a", spec.max), true},
		parseCase{"one over max of one-byte characters", strings.Repeat("a", spec.max+1), false},
		parseCase{"max spaces is blank, not a name", strings.Repeat(" ", spec.max), false},
		parseCase{"far over max", strings.Repeat("a", spec.max*8+1), false},
		parseCase{"far over max with hostile tail", strings.Repeat("a", spec.max*8) + "\x00", false},
		parseCase{"max with a NUL as the last character", strings.Repeat("a", spec.max-1) + "\x00", false},
		parseCase{"max with a ZWSP as the first character", "\u200b" + strings.Repeat("a", spec.max-3), false},
		parseCase{"max with a decomposed accent at the end", strings.Repeat("a", spec.max-2) + "e\u0301", false},
	)

	if spec.runes {
		return append(cases,
			parseCase{"max two-byte runes", strings.Repeat("\u00e9", spec.max), true},
			parseCase{"one over max two-byte runes", strings.Repeat("\u00e9", spec.max+1), false},
			parseCase{"max three-byte runes", strings.Repeat("\u65e5", spec.max), true},
			parseCase{"one over max three-byte runes", strings.Repeat("\u65e5", spec.max+1), false},
			parseCase{"max four-byte runes", strings.Repeat("\U0001F600", spec.max), true},
			parseCase{"max four-byte runes plus one ASCII", strings.Repeat("\U0001F600", spec.max) + "a", false},
			parseCase{"one over max four-byte runes", strings.Repeat("\U0001F600", spec.max+1), false},
			parseCase{"max-1 four-byte runes plus one ASCII", strings.Repeat("\U0001F600", spec.max-1) + "a", true},
		)
	}

	return append(cases,
		parseCase{"two-byte rune ends exactly at max", strings.Repeat("a", spec.max-2) + "\u00e9", true},
		parseCase{"two-byte rune straddles max", strings.Repeat("a", spec.max-1) + "\u00e9", false},
		parseCase{"three-byte rune ends exactly at max", strings.Repeat("a", spec.max-3) + "\u65e5", true},
		parseCase{"three-byte rune straddles max by one", strings.Repeat("a", spec.max-2) + "\u65e5", false},
		parseCase{"three-byte rune straddles max by two", strings.Repeat("a", spec.max-1) + "\u65e5", false},
		parseCase{"four-byte rune ends exactly at max", strings.Repeat("a", spec.max-4) + "\U0001F600", true},
		parseCase{"four-byte rune straddles max", strings.Repeat("a", spec.max-3) + "\U0001F600", false},
		parseCase{"max/2 two-byte runes", strings.Repeat("\u00e9", spec.max/2), true},
		parseCase{"max/2+1 two-byte runes", strings.Repeat("\u00e9", spec.max/2+1), false},
	)
}

// runStringTable runs a table against a parser. parse returns the parsed
// value's String() and the error.
func runStringTable(t *testing.T, cases []parseCase, parse func(string) (string, error), code string) {
	t.Helper()

	_, probe := parse("\x00\xff\x00")
	description := descriptionOf(t, probe, code)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parse(tc.in)
			if !tc.ok {
				requireFixedRefusal(t, err, code, description)

				if got != "" {
					t.Errorf("a refused input returned the value %q", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			if got != tc.in {
				t.Errorf("String() = %q, want the input unchanged", got)
			}
		})
	}
}

// fuzzString checks one string parser against an independent oracle: the
// parser accepts exactly the inputs the oracle accepts; an accepted value
// returns the input unchanged from String and parses again to an equal value;
// a refused value carries the type's code and the fixed description.
func fuzzString[T comparable](
	f *testing.F, seeds []string, parse func(string) (T, error), str func(T) string, code string, oracle func(string) bool,
) {
	f.Helper()

	for _, seed := range seeds {
		f.Add(seed)
	}

	_, probe := parse("\x00\xff\x00")
	if probe == nil {
		f.Fatal("the probe input was accepted")
	}

	description := probeDescription(probe)

	f.Fuzz(func(t *testing.T, raw string) {
		value, err := parse(raw)

		if !requireOutcome(t, raw, err, oracle(raw), code) {
			requireFixedRefusal(t, err, code, description)

			return
		}

		if str(value) != raw {
			t.Fatalf("String() = %q, want %q", str(value), raw)
		}

		again, err := parse(str(value))
		if err != nil || again != value {
			t.Fatalf("re-parse of %q = %v, %v; want the same value", raw, again, err)
		}
	})
}

// requireOutcome checks a parser result against what an oracle says: refused
// exactly when the oracle refuses, and a refusal carries the type's code. It
// reports whether the input was accepted.
func requireOutcome(t *testing.T, input any, err error, want bool, code string) bool {
	t.Helper()

	if err != nil {
		if want {
			t.Fatalf("refused %v, oracle accepts it: %v", input, err)
		}

		requireRefusal(t, err, code)

		return false
	}

	if !want {
		t.Fatalf("accepted %v, oracle refuses it", input)
	}

	return true
}

// probeDescription returns the description of a refusal without a *testing.T,
// for use while a fuzz test is being registered.
func probeDescription(err error) string {
	if got, ok := errors.AsType[*apierr.Error](err); ok {
		return got.Description
	}

	return ""
}

// requireMentions fails the test unless the description states the bound n, so
// the fixed client-facing text cannot drift from the exported constant.
func requireMentions(t *testing.T, description string, n int) {
	t.Helper()

	if !strings.Contains(description, strconv.Itoa(n)) {
		t.Errorf("description %q does not state the bound %d", description, n)
	}
}

// seedsOf returns the inputs of a case table, for seeding a fuzz corpus.
func seedsOf(cases []parseCase) []string {
	seeds := make([]string, 0, len(cases))

	for _, tc := range cases {
		seeds = append(seeds, tc.in)
	}

	return seeds
}

// strAdapter adapts a typed parser to the (string, error) shape of
// runStringTable.
func strAdapter[T any](parse func(string) (T, error), str func(T) string) func(string) (string, error) {
	return func(raw string) (string, error) {
		value, err := parse(raw)
		if err != nil {
			return "", err
		}

		return str(value), nil
	}
}

// textOracle is an independent statement of the display-text rules, for fuzz
// tests: valid, no U+FFFD/Cc/Cf, NFC, not blank (empty only if allowed), and
// within the bound in its unit.
func textOracle(spec textSpec) func(string) bool {
	return func(s string) bool {
		if s == "" {
			return spec.allowEmpty
		}

		length := len(s)
		if spec.runes {
			length = utf8.RuneCountInString(s)
		}

		return length <= spec.max && !hostileRunes(s, spec.identifying) && !blank(s, spec.identifying)
	}
}
