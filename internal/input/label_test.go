//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
)

// acceptedLabels are labels of the alphabet, at and below the bound.
func acceptedLabels() []parseCase {
	return []parseCase{
		{"one letter", "a", true},
		{"one digit", "0", true},
		{"a dot", ".", true},
		{"an underscore", "_", true},
		{"a dash", "-", true},
		{"a word", "production", true},
		{"with a dash", "ci-runner", true},
		{"with an underscore", "ci_runner", true},
		{"with a dot", "team.alpha", true},
		{"digits only", "12345", true},
		{"a version", "v1.2.3-rc.1", true},
		{"every allowed class", "az09._-", true},
		{"a SQL underscore is allowed and literal", "a_b", true},
		{"exactly the maximum", strings.Repeat("a", input.MaxLabelBytes), true},
		{"the maximum of every class", strings.Repeat("a0._-", 12) + "a0.", true},
	}
}

// oversizedLabels are labels over the bound, however they are made.
func oversizedLabels() []parseCase {
	return []parseCase{
		{"one over the maximum", strings.Repeat("a", input.MaxLabelBytes+1), false},
		{"far over the maximum", strings.Repeat("a", 4096), false},
		{"far over the maximum, hostile tail", strings.Repeat("a", 4096) + "\x00", false},
		{"NUL after the maximum minus one", strings.Repeat("a", input.MaxLabelBytes-1) + "\x00", false},
		{"empty", "", false},
	}
}

// punctuationLabels are ASCII outside the alphabet.
func punctuationLabels() []parseCase {
	return []parseCase{
		{"upper case is not an alias", "Prod", false},
		{"all upper case", "PROD", false},
		{"mixed case", "pRod", false},
		{"a space", "a b", false},
		{"a leading space", " a", false},
		{"a trailing space", "a ", false},
		{"only a space", " ", false},
		{"a tab", "a\tb", false},
		{"a newline", "a\nb", false},
		{"a trailing newline", "a\n", false},
		{"a carriage return", "a\rb", false},
		{"NUL", "\x00", false},
		{"NUL inside", "a\x00b", false},
		{"DEL", "a\x7fb", false},
		{"a colon", "env:prod", false},
		{"a slash", "a/b", false},
		{"a backslash", `a\b`, false},
		{"a comma (a list is not one label)", "a,b", false},
		{"a semicolon", "a;b", false},
		{"an equals sign", "k=v", false},
		{"an ampersand", "a&b", false},
		{"a percent sign", "a%20b", false},
		{"a plus sign", "a+b", false},
		{"a quote", `a"b`, false},
		{"an apostrophe", "a'b", false},
		{"a wildcard", "a*", false},
		{"a SQL wildcard", "a%", false},
		{"a SQL injection", "' OR '1'='1", false},
		{"a path traversal", "../x", false},
		{"an at sign", "a@b", false},
		{"a hash", "#a", false},
		{"brackets", "a[0]", false},
	}
}

// unicodeLabels are text outside ASCII: look-alikes, invisibles and bad UTF-8.
func unicodeLabels() []parseCase {
	return []parseCase{
		{"e acute (NFC)", "caf\u00e9", false},
		{"e with a combining acute (NFD)", "cafe\u0301", false},
		{"a fullwidth letter", "\uff41", false},
		{"a fullwidth digit", "\uff11", false},
		{"an arabic-indic digit", "\u0665", false},
		{"a cyrillic a that looks latin", "\u0430", false},
		{"a greek omicron among latin", "pr\u03bfd", false},
		{"Kelvin sign that folds to k", "\u212a", false},
		{"dotless i", "\u0131", false},
		{"long s", "\u017f", false},
		{"an emoji", "\U0001F600", false},
		{"a zero-width space", "a\u200bb", false},
		{"a zero-width joiner", "a\u200db", false},
		{"a zero-width non-joiner", "a\u200cb", false},
		{"a bidi override", "a\u202eb", false},
		{"a byte order mark", "\ufeffa", false},
		{"a soft hyphen", "a\u00adb", false},
		{"a tag character", "a\U000E0041b", false},
		{"a non-breaking space", "a\u00a0b", false},
		{"the replacement character", "a\ufffdb", false},
		{"an invalid UTF-8 byte", "a\xffb", false},
		{"a truncated multibyte sequence", "a\xe2\x82", false},
		{"an overlong NUL", "a\xc0\x80b", false},
		{"an encoded surrogate", "a\xed\xa0\x80b", false},
	}
}

// labelCases is the table of single labels. The alphabet is [a-z0-9._-], so
// every case of another script, case, normalisation form or invisible
// character is a refusal, and the bound is in bytes.
func labelCases() []parseCase {
	return slices.Concat(acceptedLabels(), oversizedLabels(), punctuationLabels(), unicodeLabels())
}

func parseLabelText(raw string) (string, error) {
	return strAdapter(input.ParseLabel, input.Label.String)(raw)
}

func TestParseLabel(t *testing.T) {
	t.Parallel()
	runStringTable(t, labelCases(), parseLabelText, input.CodeInvalidLabelName)
}

// labelPattern restates the rule independently of the parser.
var labelPattern = regexp.MustCompile(`^[a-z0-9._-]{1,63}$`)

func FuzzParseLabel(f *testing.F) {
	fuzzString(f, seedsOf(labelCases()), input.ParseLabel, input.Label.String, input.CodeInvalidLabelName,
		labelOracle)
}

// TestLabelBoundsFitTheSchema pins the arithmetic the constants rely on. The
// alphabet is ASCII, so a label's bytes are its characters, and the largest
// label is exactly the schema's 63 bytes.
func TestLabelBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	const schemaMaxBytes = 63 // agent_labels.label CHECK, migration 0001

	if input.MaxLabelBytes != schemaMaxBytes {
		t.Errorf("MaxLabelBytes = %d, want the schema's %d", input.MaxLabelBytes, schemaMaxBytes)
	}

	largest, err := input.ParseLabel(strings.Repeat("z", input.MaxLabelBytes))
	if err != nil || len(largest.String()) != schemaMaxBytes {
		t.Errorf("the largest label = %q, %v; want %d bytes", largest.String(), err, schemaMaxBytes)
	}

	if input.MaxLabelsPerPatch > input.MaxLabelsPerAgent {
		t.Errorf("a request may add %d labels but an agent holds %d", input.MaxLabelsPerPatch, input.MaxLabelsPerAgent)
	}
}

func TestLabelDescriptionsStateTheBound(t *testing.T) {
	t.Parallel()

	_, nameErr := input.ParseLabel("")
	requireMentions(t, descriptionOf(t, nameErr, input.CodeInvalidLabelName), input.MaxLabelBytes)

	_, filterErr := input.ParseLabelFilter([]string{""})
	requireMentions(t, descriptionOf(t, filterErr, input.CodeInvalidLabelFilter), input.MaxLabelBytes)
}

// filterCase is one row of the label filter table.
type filterCase struct {
	name   string
	values []string
	want   string // the label when set
	set    bool
	ok     bool
}

// longestLabel is the longest label there is.
//
//nolint:gochecknoglobals // a fixed value shared by the tables
var longestLabel = strings.Repeat("a", input.MaxLabelBytes)

func filterCases() []filterCase {
	cases := []filterCase{
		{"absent (nil) is no filter", nil, "", false, true},
		{"absent (empty slice) is no filter", []string{}, "", false, true},
		{"one label", []string{"abc"}, "abc", true, true},
		{"the maximum", []string{longestLabel}, longestLabel, true, true},
		{"present but empty is refused, not read as absent", []string{""}, "", false, false},
		{"repeated, the same", []string{"a", "a"}, "", false, false},
		{"repeated, different", []string{"a", "b"}, "", false, false},
		{"repeated, the second invalid", []string{"a", "B"}, "", false, false},
		{"repeated, the first empty", []string{"", "a"}, "", false, false},
		{"three values", []string{"a", "b", "c"}, "", false, false},
		{"over the maximum", []string{strings.Repeat("a", input.MaxLabelBytes+1)}, "", false, false},
		{"upper case", []string{"ABC"}, "", false, false},
		{"a comma list is one invalid label", []string{"a,b"}, "", false, false},
		{"a space", []string{"a b"}, "", false, false},
		{"NUL", []string{"a\x00"}, "", false, false},
		{"a SQL injection", []string{"' OR '1'='1"}, "", false, false},
		{"invalid UTF-8", []string{"\xff"}, "", false, false},
	}

	return cases
}

func TestParseLabelFilter(t *testing.T) {
	t.Parallel()

	_, probe := input.ParseLabelFilter([]string{"A"})
	description := descriptionOf(t, probe, input.CodeInvalidLabelFilter)

	for _, tc := range filterCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseLabelFilter(tc.values)
			if !tc.ok {
				requireFixedRefusal(t, err, input.CodeInvalidLabelFilter, description)

				if _, set := got.Label(); set {
					t.Error("a refused filter is set")
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			label, set := got.Label()
			if set != tc.set || label.String() != tc.want {
				t.Errorf("Label() = %q, %v; want %q, %v", label.String(), set, tc.want, tc.set)
			}
		})
	}
}

func FuzzParseLabelFilter(f *testing.F) {
	for _, tc := range filterCases() {
		if len(tc.values) == 1 && len(tc.values[0]) < 80 {
			f.Add(tc.values[0], uint8(1))
		}
	}

	f.Add("", uint8(0))
	f.Add("abc", uint8(2))

	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		values := queryValues(raw, mode)
		got, err := input.ParseLabelFilter(values)

		if !requireOutcome(t, values, err, filterOracle(values), input.CodeInvalidLabelFilter) {
			return
		}

		label, set := got.Label()
		if set != (len(values) == 1) || (set && label.String() != raw) {
			t.Fatalf("Label() = %q, %v for %q", label.String(), set, values)
		}
	})
}

// filterOracle restates the filter rule independently of the parser: no value,
// or exactly one that is a label.
func filterOracle(values []string) bool {
	switch len(values) {
	case 0:
		return true
	case 1:
		return labelOracle(values[0])
	default:
		return false
	}
}

// labelOracle restates the label rule independently of the parser. The regexp's
// $ also matches before a final newline, which a label must not hold.
func labelOracle(s string) bool { return labelPattern.MatchString(s) && !strings.Contains(s, "\n") }

// patchCase is one row of the label patch table.
type patchCase struct {
	name   string
	add    []string
	remove []string
	ok     bool
	empty  bool
}

func manyLabels(n int, prefix string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}

	return out
}

// maxLabelsX is the most labels a request may add or remove at once.
//
//nolint:gochecknoglobals // a fixed value shared by the tables
var maxLabelsX = manyLabels(input.MaxLabelsPerPatch, "x")

func patchCases() []patchCase {
	return []patchCase{
		{"nothing at all", nil, nil, true, true},
		{"empty lists", []string{}, []string{}, true, true},
		{"add one", []string{"a"}, nil, true, false},
		{"remove one", nil, []string{"a"}, true, false},
		{"add and remove different labels", []string{"a", "b"}, []string{"c"}, true, false},
		{"the maximum added", manyLabels(input.MaxLabelsPerPatch, "x"), nil, true, false},
		{"the maximum removed", nil, manyLabels(input.MaxLabelsPerPatch, "x"), true, false},
		{"the maximum of both", maxLabelsX, manyLabels(input.MaxLabelsPerPatch, "y"), true, false},
		{"one over the maximum added", manyLabels(input.MaxLabelsPerPatch+1, "x"), nil, false, false},
		{"one over the maximum removed", nil, manyLabels(input.MaxLabelsPerPatch+1, "x"), false, false},
		{"the same label added twice", []string{"a", "a"}, nil, false, false},
		{"the same label removed twice", nil, []string{"a", "a"}, false, false},
		{"a label in both lists", []string{"a"}, []string{"a"}, false, false},
		{"a label in both lists among others", []string{"a", "b"}, []string{"c", "b"}, false, false},
		{"an invalid label added", []string{"A"}, nil, false, false},
		{"an invalid label removed", nil, []string{"A"}, false, false},
		{"an empty label added", []string{""}, nil, false, false},
		{"an empty label removed", nil, []string{""}, false, false},
		{"a valid label then an invalid one", []string{"a", "b c"}, nil, false, false},
		{"an over-long label", []string{strings.Repeat("a", input.MaxLabelBytes+1)}, nil, false, false},
	}
}

func TestParseLabelPatch(t *testing.T) {
	t.Parallel()

	for _, tc := range patchCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseLabelPatch(tc.add, tc.remove)
			if !tc.ok {
				requireEmptyRefusal(t, got, err)

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			if got.Empty() != tc.empty {
				t.Errorf("Empty() = %v, want %v", got.Empty(), tc.empty)
			}

			// The order sent is the order kept, and nothing is dropped or added.
			if !sameLabels(got.Add(), tc.add) || !sameLabels(got.Remove(), tc.remove) {
				t.Errorf("patch = add %v remove %v, want add %v remove %v", got.Add(), got.Remove(), tc.add, tc.remove)
			}
		})
	}
}

// requireEmptyRefusal fails the test unless a refused patch is an error and an
// empty patch.
func requireEmptyRefusal(t *testing.T, got input.LabelPatch, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("accepted")
	}

	if !got.Empty() || len(got.Add()) != 0 || len(got.Remove()) != 0 {
		t.Error("a refused patch is not empty")
	}
}

// TestParseLabelPatchRefusalsCarryTheirCode: an invalid label is the label's
// code, a bad combination is the patch's, and neither echoes the input.
func TestParseLabelPatchRefusalsCarryTheirCode(t *testing.T) {
	t.Parallel()

	_, invalid := input.ParseLabelPatch([]string{"A"}, nil)
	requireRefusal(t, invalid, input.CodeInvalidLabelName)

	_, both := input.ParseLabelPatch([]string{"a"}, []string{"a"})
	requireRefusal(t, both, input.CodeInvalidLabelPatch)

	_, twice := input.ParseLabelPatch([]string{"a", "a"}, nil)
	requireRefusal(t, twice, input.CodeInvalidLabelPatch)

	_, tooMany := input.ParseLabelPatch(manyLabels(input.MaxLabelsPerPatch+1, "x"), nil)
	requireRefusal(t, tooMany, input.CodeInvalidLabelPatch)

	_, tooManyRemoved := input.ParseLabelPatch(nil, manyLabels(input.MaxLabelsPerPatch+1, "x"))
	requireRefusal(t, tooManyRemoved, input.CodeInvalidLabelPatch)
}

// TestLabelPatchIsNotAliased: the slices a patch hands out are copies, so a
// caller cannot change what a parsed patch holds.
func TestLabelPatchIsNotAliased(t *testing.T) {
	t.Parallel()

	patch, err := input.ParseLabelPatch([]string{"a"}, []string{"b"})
	if err != nil {
		t.Fatal(err)
	}

	patch.Add()[0], _ = input.ParseLabel("z")
	patch.Remove()[0], _ = input.ParseLabel("z")

	if patch.Add()[0].String() != "a" || patch.Remove()[0].String() != "b" {
		t.Errorf("a caller changed the patch: add %v remove %v", patch.Add(), patch.Remove())
	}

	// The input slices are not retained either.
	add := []string{"a"}

	kept, err := input.ParseLabelPatch(add, nil)
	if err != nil {
		t.Fatal(err)
	}

	add[0] = "changed"

	if kept.Add()[0].String() != "a" {
		t.Errorf("the patch kept the caller's slice: %v", kept.Add())
	}
}

func FuzzParseLabelPatch(f *testing.F) {
	f.Add("a", "b", "c", "d")
	f.Add("a", "a", "", "")
	f.Add("a", "b", "b", "c")
	f.Add("A", "", "", "")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, a1, a2, r1, r2 string) {
		add, remove := []string{a1, a2}, []string{r1, r2}
		got, err := input.ParseLabelPatch(add, remove)

		// A refusal carries one of the two codes of the patch parser.
		if err != nil {
			failure, ok := errors.AsType[*apierr.Error](err)
			if !ok || (failure.Code != input.CodeInvalidLabelName && failure.Code != input.CodeInvalidLabelPatch) {
				t.Fatalf("refusal %v is not a label error", err)
			}
		}

		if want := patchOracle(add, remove); (err == nil) != want {
			t.Fatalf("patch %v %v: accepted=%v, oracle says %v", add, remove, err == nil, want)
		}

		if err != nil {
			return
		}

		if !sameLabels(got.Add(), add) || !sameLabels(got.Remove(), remove) {
			t.Fatalf("patch = %v %v, want %v %v", got.Add(), got.Remove(), add, remove)
		}
	})
}

// patchOracle restates the patch rule independently of the parser: every label
// valid, none repeated, none in both lists.
func patchOracle(add, remove []string) bool {
	seen := map[string]bool{}

	for _, label := range append(append([]string{}, add...), remove...) {
		if !labelOracle(label) || seen[label] {
			return false
		}

		seen[label] = true
	}

	return true
}

func sameLabels(got []input.Label, want []string) bool {
	text := make([]string, len(got))
	for i, label := range got {
		text[i] = label.String()
	}

	if len(text) == 0 && len(want) == 0 {
		return true
	}

	return reflect.DeepEqual(text, want)
}

// setCase is one row of the label set table.
type setCase struct {
	name string
	raw  []string
	ok   bool
	// code is the refusal's code when ok is false.
	code string
}

func setCases() []setCase {
	return []setCase{
		{"nothing at all", nil, true, ""},
		{"an empty list", []string{}, true, ""},
		{"one label", []string{"a"}, true, ""},
		{"several, in no particular order", []string{"zeta", "alpha", "mid"}, true, ""},
		{"the longest label", []string{longestLabel}, true, ""},
		{"the maximum number of labels", manyLabels(input.MaxLabelsPerCreate, "x"), true, ""},
		{"one over the maximum number", manyLabels(input.MaxLabelsPerCreate+1, "x"), false, input.CodeInvalidLabelSet},
		{"far over the maximum number", manyLabels(1000, "x"), false, input.CodeInvalidLabelSet},
		{"the same label twice", []string{"a", "a"}, false, input.CodeInvalidLabelSet},
		{"the same label twice, apart", []string{"a", "b", "c", "a"}, false, input.CodeInvalidLabelSet},
		{"an upper-case label", []string{"A"}, false, input.CodeInvalidLabelName},
		{"an empty label", []string{""}, false, input.CodeInvalidLabelName},
		{"an over-long label", []string{strings.Repeat("a", input.MaxLabelBytes+1)}, false, input.CodeInvalidLabelName},
		{"a NUL", []string{"a\x00b"}, false, input.CodeInvalidLabelName},
		{"a valid label then an invalid one", []string{"a", "b c"}, false, input.CodeInvalidLabelName},
		{"an invalid label before a repeat", []string{"A", "a", "a"}, false, input.CodeInvalidLabelName},
	}
}

func TestParseLabelSet(t *testing.T) {
	t.Parallel()

	for _, tc := range setCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseLabelSet(tc.raw)
			if !tc.ok {
				requireRefusal(t, err, tc.code)

				if !got.Empty() || len(got.Labels()) != 0 {
					t.Error("a refused set is not empty")
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			if got.Empty() != (len(tc.raw) == 0) {
				t.Errorf("Empty() = %v for %d labels", got.Empty(), len(tc.raw))
			}

			// The order sent is the order kept, and nothing is dropped or added.
			if !sameLabels(got.Labels(), tc.raw) {
				t.Errorf("set = %v, want %v", got.Labels(), tc.raw)
			}
		})
	}
}

// TestLabelSetBoundIsTheAgentsBound: a create may give an agent every label it
// may hold and no more, so the first PATCH after it has the same room as any.
func TestLabelSetBoundIsTheAgentsBound(t *testing.T) {
	t.Parallel()

	if input.MaxLabelsPerCreate != input.MaxLabelsPerAgent {
		t.Errorf("a create may give %d labels but an agent holds %d", input.MaxLabelsPerCreate, input.MaxLabelsPerAgent)
	}

	_, err := input.ParseLabelSet([]string{"a", "a"})
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidLabelSet), input.MaxLabelsPerCreate)
}

// TestParseLabelSetRefusalsDoNotEchoTheInput: the description is fixed, so a
// hostile label is never reflected into a response or a log line.
func TestParseLabelSetRefusalsDoNotEchoTheInput(t *testing.T) {
	t.Parallel()

	_, probe := input.ParseLabelSet([]string{"a", "a"})
	description := descriptionOf(t, probe, input.CodeInvalidLabelSet)

	for _, raw := range [][]string{{"x", "x"}, manyLabels(input.MaxLabelsPerCreate+1, "secret")} {
		_, err := input.ParseLabelSet(raw)
		requireFixedRefusal(t, err, input.CodeInvalidLabelSet, description)
	}
}

// TestLabelSetIsNotAliased: the slices a set hands out are copies, so a caller
// cannot change what was parsed, and the set keeps nothing of the caller's slice.
func TestLabelSetIsNotAliased(t *testing.T) {
	t.Parallel()

	raw := []string{"a", "b"}

	set, err := input.ParseLabelSet(raw)
	if err != nil {
		t.Fatal(err)
	}

	raw[0] = "changed"
	set.Labels()[1], _ = input.ParseLabel("z")

	if !sameLabels(set.Labels(), []string{"a", "b"}) {
		t.Errorf("the set changed under its caller: %v", set.Labels())
	}
}

func FuzzParseLabelSet(f *testing.F) {
	f.Add("a", "b", "c")
	f.Add("a", "a", "")
	f.Add("A", "", "")
	f.Add("", "", "")
	f.Add("a", "b", "a")

	f.Fuzz(func(t *testing.T, a, b, c string) {
		raw := []string{a, b, c}
		got, err := input.ParseLabelSet(raw)

		// A refusal carries one of the two codes of the set parser.
		if err != nil {
			failure, ok := errors.AsType[*apierr.Error](err)
			if !ok || (failure.Code != input.CodeInvalidLabelName && failure.Code != input.CodeInvalidLabelSet) {
				t.Fatalf("refusal %v is not a label error", err)
			}
		}

		// The rule, restated independently: every label valid, none repeated.
		if want := patchOracle(raw, nil); (err == nil) != want {
			t.Fatalf("set %v: accepted=%v, oracle says %v", raw, err == nil, want)
		}

		if err == nil && !sameLabels(got.Labels(), raw) {
			t.Fatalf("set = %v, want %v", got.Labels(), raw)
		}
	})
}
