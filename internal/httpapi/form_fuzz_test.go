package httpapi_test

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

// FuzzParseParams holds the properties of ParseParams for every input, whatever
// it is. The model is the standard library's own decoding of each pair, which is
// what the rules (see ParseParams) are built from, so the property is that no
// input makes the parser disagree with it:
//
//   - it never panics, and a refusal is a 400 with one of the four codes the rules
//     name and nothing else;
//   - a declared name that two pairs decode to is always refused, however the pairs
//     spell it (percent-encoded, empty-valued, with no "="), and wherever the other
//     pairs are;
//   - a pair with a broken escape, in a name or a value, and a pair with no name,
//     are always refused, recognised or not;
//   - when the input is accepted, each declared name reads as exactly the decoded
//     value of its one pair (absent when empty, or when there is no pair), and
//     that value is valid UTF-8 with no NUL.
func FuzzParseParams(f *testing.F) {
	for _, tt := range acceptedParams() {
		f.Add(tt.raw)
	}

	for _, tt := range absentParams() {
		f.Add(tt.raw)
	}

	for _, tt := range refusedParams() {
		f.Add(tt.raw)
	}

	for _, raw := range []string{"a=1&%61=2", "%61=1&a=2&b=3", "a=%2&b=1", "x%=1", "a=1&&&a", "a=a=a&b=%26", "\xff=\x00"} {
		f.Add(raw)
	}

	names := recognisedNames()

	f.Fuzz(func(t *testing.T, raw string) {
		params, err := httpapi.ParseParams(raw, names...).Get()
		if err != nil {
			checkRefusal(t, raw, err)

			return
		}

		checkAccepted(t, raw, params, names)
	})
}

// checkAccepted holds the properties of an input that was accepted.
func checkAccepted(t *testing.T, raw string, params httpapi.Params, names []string) {
	t.Helper()

	model := modelOf(raw)

	if model.refused {
		t.Fatalf("accepted %q, which has a pair that must be refused", raw)
	}

	for _, name := range names {
		pairs := model.values[name]
		if len(pairs) > 1 {
			t.Fatalf("accepted %q, which names %q %d times", raw, name, len(pairs))
		}

		got, present := params.Get(name)

		want := ""
		if len(pairs) == 1 {
			want = pairs[0]
		}

		if got != want || present != (want != "") {
			t.Fatalf("Get(%q) of %q = %q, %t; want %q, %t", name, raw, got, present, want, want != "")
		}

		if refusedAsText(got) {
			t.Fatalf("Get(%q) of %q = %q, which is not valid text", name, raw, got)
		}
	}
}

// model is what the standard library's decoding says of an input.
type model struct {
	// refused is whether some pair has a broken escape or no name.
	refused bool

	// values are the decoded values of the declared names, one per pair that
	// names them, in order.
	values map[string][]string
}

// modelOf decodes every pair of raw with url.QueryUnescape, as the rules say.
func modelOf(raw string) model {
	out := model{refused: false, values: map[string][]string{}}
	declared := map[string]bool{}

	for _, name := range recognisedNames() {
		declared[name] = true
	}

	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}

		rawName, rawValue, _ := strings.Cut(pair, "=")
		name, nameErr := url.QueryUnescape(rawName)
		value, valueErr := url.QueryUnescape(rawValue)

		if nameErr != nil || valueErr != nil || name == "" {
			out.refused = true

			continue
		}

		if declared[name] {
			out.values[name] = append(out.values[name], value)
		}
	}

	return out
}

// checkRefusal holds that a refusal is one of the parser's four, and that the
// input really has what it is refused for, so a valid one is never refused.
func checkRefusal(t *testing.T, raw string, err error) {
	t.Helper()

	failure, classified := errors.AsType[*apierr.Error](err)
	if !classified || failure.Kind != apierr.BadRequest || failure.Kind.Status() != http.StatusBadRequest {
		t.Fatalf("refusal of %q = %v, want a classified 400", raw, err)
	}

	reasons := map[string]func(model) bool{
		codeEncoding:  func(m model) bool { return m.refused },
		codeParamName: func(m model) bool { return m.refused },
		codeDuplicate: func(m model) bool { return anyValues(m, func(pairs []string) bool { return len(pairs) > 1 }) },
		codeText: func(m model) bool {
			return anyValues(m, func(pairs []string) bool { return slices.ContainsFunc(pairs, refusedAsText) })
		},
	}

	reason, known := reasons[failure.Code]
	if !known {
		t.Fatalf("refused %q with the unknown code %q", raw, failure.Code)
	}

	if !reason(modelOf(raw)) {
		t.Fatalf("refused %q as %s, which it has no reason for", raw, failure.Code)
	}
}

// anyValues reports whether some declared name's values satisfy test.
func anyValues(m model, test func([]string) bool) bool {
	for _, pairs := range m.values {
		if test(pairs) {
			return true
		}
	}

	return false
}

// refusedAsText reports whether a decoded value is refused as text.
func refusedAsText(value string) bool {
	return !utf8.ValidString(value) || strings.ContainsRune(value, 0)
}
