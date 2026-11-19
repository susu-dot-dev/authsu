//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// allVSChars is every VSCHAR, 0x20 to 0x7E.
func allVSChars() string {
	var b strings.Builder

	for c := byte(0x20); c <= 0x7e; c++ {
		b.WriteByte(c)
	}

	return b.String()
}

// vsCases is the table of State and Nonce, which differ only in their bound.
func vsCases(maxBytes int) []parseCase {
	cases := []parseCase{
		{"one character", "x", true},
		{"one space", " ", true},
		{"a random-looking value", "k3-Jq_9xT.7~wZ", true},
		{"a base64 value with padding", "dGVzdA==", true},
		{"a UUID", "123e4567-e89b-12d3-a456-426614174000", true},
		{"words and spaces", "abc 123", true},
		{"a leading space, kept", " abc", true},
		{"a trailing space, kept", "abc ", true},
		{"quotes and backslashes", `"a\b"`, true},
		{"markup characters", "<a href='x'>&amp;</a>", true},
		{"a URL", "https://example.com/a?b=c&d=e#f", true},
		{"JSON", `{"a":[1,2,{"b":null}]}`, true},
		{"percent signs, which are the client's own", "100%25", true},
		{"every VSCHAR", allVSChars(), true},
		{"the first VSCHAR", "\x20", true},
		{"the last VSCHAR", "~", true},
		{"exactly the bound", strings.Repeat("a", maxBytes), true},
		{"exactly the bound of quotes", strings.Repeat(`"`, maxBytes), true},

		{"empty", "", false},
		{"one over the bound", strings.Repeat("a", maxBytes+1), false},
		{"far over the bound", strings.Repeat("a", maxBytes*100), false},
		{"a megabyte", strings.Repeat("a", 1<<20), false},
		{"the bound with a NUL last", strings.Repeat("a", maxBytes-1) + "\x00", false},
		{"NUL", "\x00", false},
		{"NUL inside", "a\x00b", false},
		{"NUL at the end", "abc\x00", false},
		{"SOH", "a\x01b", false},
		{"US, the last C0 control", "a\x1fb", false},
		{"tab", "a\tb", false},
		{"line feed", "a\nb", false},
		{"carriage return", "a\rb", false},
		{"a CRLF that would split a header", "a\r\nSet-Cookie: x=y", false},
		{"escape", "a\x1bb", false},
		{"DEL", "a\x7fb", false},
		{"a C1 control", "a\u0085b", false},
		{"e acute", "caf\u00e9", false},
		{"decomposed e acute", "cafe\u0301", false},
		{"an emoji", "a\U0001F600", false},
		{"CJK", "\u65e5\u672c", false},
		{"a fullwidth letter", "\uff21", false},
		{"no-break space", "a\u00a0b", false},
		{"zero width space", "a\u200bb", false},
		{"a bidi override", "a\u202eb", false},
		{"a byte order mark", "\ufeffabc", false},
		{"U+FFFD", "a\ufffdb", false},
		{"an invalid UTF-8 byte", "a\xffb", false},
		{"a lone continuation byte", "a\x80b", false},
	}

	return cases
}

func TestParseState(t *testing.T) {
	t.Parallel()

	parse := strAdapter(input.ParseState, input.State.String)

	runStringTable(t, vsCases(input.MaxStateBytes), parse, input.CodeInvalidState)
}

func TestParseNonce(t *testing.T) {
	t.Parallel()

	parse := strAdapter(input.ParseNonce, input.Nonce.String)

	runStringTable(t, vsCases(input.MaxNonceBytes), parse, input.CodeInvalidNonce)
}

func TestStateAndNonceDescriptionsStateTheBounds(t *testing.T) {
	t.Parallel()

	_, err := input.ParseState("")
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidState), input.MaxStateBytes)

	_, err = input.ParseNonce("")
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidNonce), input.MaxNonceBytes)
}

func TestParseResponseType(t *testing.T) {
	t.Parallel()

	runStringTable(t, []parseCase{
		{"code", "code", true},
		{"token, the implicit flow", "token", false},
		{"id_token", "id_token", false},
		{"code id_token", "code id_token", false},
		{"code token", "code token", false},
		{"id_token token", "id_token token", false},
		{"none", "none", false},
		{"upper case", "CODE", false},
		{"capitalised", "Code", false},
		{"a leading space", " code", false},
		{"a trailing space", "code ", false},
		{"a trailing newline", "code\n", false},
		{"NUL", "code\x00", false},
		{"a repeated value", "code" + " " + "code", false},
		{"a comma list", "code,token", false},
		{"empty", "", false},
		{"a prefix", "cod", false},
		{"a longer word", "codes", false},
		{"a Cyrillic o", "c\u043ede", false},
		{"percent-encoded", "%63ode", false},
		{"a megabyte", strings.Repeat("code", 1<<18), false},
	}, strAdapter(input.ParseResponseType, input.ResponseType.String), input.CodeInvalidResponseType)
}

func TestParseGrantType(t *testing.T) {
	t.Parallel()

	runStringTable(t, []parseCase{
		{"authorization_code", "authorization_code", true},
		{"refresh_token", "refresh_token", true},
		{"client_credentials", "client_credentials", false},
		{"password", "password", false},
		{"implicit", "implicit", false},
		{"the token exchange URN", "urn:ietf:params:oauth:grant-type:token-exchange", false},
		{"the device code URN", "urn:ietf:params:oauth:grant-type:device_code", false},
		{"the JWT bearer URN", "urn:ietf:params:oauth:grant-type:jwt-bearer", false},
		{"upper case", "AUTHORIZATION_CODE", false},
		{"capitalised", "Authorization_Code", false},
		{"upper case refresh", "Refresh_Token", false},
		{"hyphens", "authorization-code", false},
		{"no separator", "authorizationcode", false},
		{"a short form", "refresh", false},
		{"a short code form", "code", false},
		{"a leading space", " authorization_code", false},
		{"a trailing space", "refresh_token ", false},
		{"a trailing newline", "refresh_token\n", false},
		{"NUL", "authorization_code\x00", false},
		{"both", "authorization_code refresh_token", false},
		{"both, comma separated", "refresh_token,authorization_code", false},
		{"a repeated value", "refresh_tokenrefresh_token", false},
		{"empty", "", false},
		{"a Cyrillic e", "r\u0435fresh_token", false},
		{"percent-encoded", "refresh%5Ftoken", false},
		{"a megabyte", strings.Repeat("a", 1<<20), false},
	}, strAdapter(input.ParseGrantType, input.GrantType.String), input.CodeInvalidGrantType)
}

func TestGrantTypePredicates(t *testing.T) {
	t.Parallel()

	code, err := input.ParseGrantType("authorization_code")
	if err != nil || !code.AuthorizationCode() || code.RefreshToken() {
		t.Errorf("authorization_code: %v, %v, %v", code, code.AuthorizationCode(), code.RefreshToken())
	}

	refresh, err := input.ParseGrantType("refresh_token")
	if err != nil || refresh.AuthorizationCode() || !refresh.RefreshToken() {
		t.Errorf("refresh_token: %v, %v, %v", refresh, refresh.AuthorizationCode(), refresh.RefreshToken())
	}

	var zero input.GrantType
	if zero.AuthorizationCode() || zero.RefreshToken() {
		t.Error("the zero GrantType is a grant type")
	}
}

func FuzzParseState(f *testing.F) {
	fuzzString(f, seedsOf(vsCases(input.MaxStateBytes)), input.ParseState, input.State.String, input.CodeInvalidState,
		vsOracle(input.MaxStateBytes))
}

func FuzzParseNonce(f *testing.F) {
	fuzzString(f, seedsOf(vsCases(input.MaxNonceBytes)), input.ParseNonce, input.Nonce.String, input.CodeInvalidNonce,
		vsOracle(input.MaxNonceBytes))
}

func FuzzParseResponseType(f *testing.F) {
	fuzzString(f, []string{"code", "token", "", "Code", "code "}, input.ParseResponseType, input.ResponseType.String,
		input.CodeInvalidResponseType, func(s string) bool { return s == "code" })
}

func FuzzParseGrantType(f *testing.F) {
	fuzzString(f, []string{"authorization_code", "refresh_token", "", "password", "refresh_token "}, input.ParseGrantType,
		input.GrantType.String, input.CodeInvalidGrantType,
		func(s string) bool { return s == "authorization_code" || s == "refresh_token" })
}

// vsOracle states the rule independently: 1 to max bytes, all of 0x20 to 0x7E.
func vsOracle(maxBytes int) func(string) bool {
	return func(s string) bool {
		if s == "" || len(s) > maxBytes {
			return false
		}

		for _, r := range s {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}

		return true
	}
}
