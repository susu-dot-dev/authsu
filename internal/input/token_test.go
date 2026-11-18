//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

func parseToken(raw string) (string, error) {
	return strAdapter(input.ParseToken, input.Token.String)(raw)
}

func tokenCases() []parseCase {
	const jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IngifQ.eyJzdWIiOiJ1In0.c2lnLV8"

	limit := input.MaxTokenBytes

	return []parseCase{
		{"jwt shape", jwt, true},
		{"one character", "a", true},
		{"whole alphabet and dot", "ABCXYZabcxyz0189-_.", true},
		{"dots only (structure is the verifier's)", "...", true},
		{"no dots", "abcdef", true},
		{"exactly max", strings.Repeat("a", limit), true},
		{"max with dots", strings.Repeat("a.", limit/2), true},
		{"one over max", strings.Repeat("a", limit+1), false},
		{"far over max", strings.Repeat("a", limit*4), false},
		{"over max with a refused character at the end", strings.Repeat("a", limit) + "!", false},
		{"max with a refused character at the end", strings.Repeat("a", limit-1) + "!", false},
		{"empty", "", false},
		{"bearer prefix", "Bearer " + jwt, false},
		{"space", "a b", false},
		{"leading space", " " + jwt, false},
		{"trailing space", jwt + " ", false},
		{"trailing newline", jwt + "\n", false},
		{"carriage return and line feed", jwt + "\r\n", false},
		{"tab", "a\tb", false},
		{"NUL", "a\x00b", false},
		{"padding", "abc=", false},
		{"standard base64 plus", "a+b", false},
		{"standard base64 slash", "a/b", false},
		{"semicolon (cookie separator)", "a;b", false},
		{"comma", "a,b", false},
		{"equals (cookie name separator)", "session=" + jwt, false},
		{"double quote", "\"" + jwt + "\"", false},
		{"colon", "a:b", false},
		{"percent escape", "%41", false},
		{"multibyte letter", "caf\u00e9", false},
		{"fullwidth dot", "a\uff0eb", false},
		{"high byte", "a\x80", false},
		{"invalid utf8", "a\xffb", false},
		{"two tokens", jwt + " " + jwt, false},
	}
}

func TestParseToken(t *testing.T) {
	t.Parallel()
	runStringTable(t, tokenCases(), parseToken, input.CodeInvalidToken)
}

func TestTokenDescriptionStatesTheBound(t *testing.T) {
	t.Parallel()

	_, err := parseToken("")
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidToken), input.MaxTokenBytes)
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// tokenOracle is the Token rule restated: the alphabet, and 1..4096 bytes (the
// regexp engine's repeat limit is 1000, so the length is checked separately).
func tokenOracle(s string) bool {
	return len(s) <= input.MaxTokenBytes && tokenPattern.MatchString(s)
}

func FuzzParseToken(f *testing.F) {
	fuzzString(f, seedsOf(tokenCases()), input.ParseToken, input.Token.String, input.CodeInvalidToken, tokenOracle)
}
