//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/secret"
)

// base64urlAlphabet is the alphabet in value order: the index of a character
// is its 6-bit value.
const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// tokenSpec describes one token type to the shared tests.
type tokenSpec struct {
	name string
	tag  secret.Tag
	code string
	// parse returns the String() of the parsed value.
	parse func(string) (string, error)
	// hash returns the Hash() of the parsed value.
	hash func(string) ([]byte, error)
}

func tokenSpecs() []tokenSpec {
	return []tokenSpec{
		{
			name: "InvitationToken", tag: secret.TagInvitation, code: input.CodeInvalidInvitation,
			parse: strAdapter(input.ParseInvitationToken, input.InvitationToken.String),
			hash: func(raw string) ([]byte, error) {
				v, err := input.ParseInvitationToken(raw)

				return v.Hash(), err
			},
		},
		{
			name: "SessionToken", tag: secret.TagSession, code: input.CodeInvalidSessionToken,
			parse: strAdapter(input.ParseSessionToken, input.SessionToken.String),
			hash: func(raw string) ([]byte, error) {
				v, err := input.ParseSessionToken(raw)

				return v.Hash(), err
			},
		},
		{
			name: "APIKeyToken", tag: secret.TagAPIKey, code: input.CodeInvalidAPIKey,
			parse: strAdapter(input.ParseAPIKeyToken, input.APIKeyToken.String),
			hash: func(raw string) ([]byte, error) {
				v, err := input.ParseAPIKeyToken(raw)

				return v.Hash(), err
			},
		},
	}
}

// otherTags returns the tags of the two other token types.
func otherTags(tag secret.Tag) []secret.Tag {
	var others []secret.Tag

	for _, spec := range tokenSpecs() {
		if spec.tag != tag {
			others = append(others, spec.tag)
		}
	}

	return others
}

// replaceAt returns s with the byte at i replaced by r, which may be longer.
func replaceAt(s string, i int, r string) string { return s[:i] + r + s[i+1:] }

// tokenCases is the table for the type whose tag is given. The body is always
// 43 characters, ending in 'A' (value 0, canonical) unless the case says
// otherwise.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func tokenCases(tag secret.Tag) []parseCase {
	prefix := secret.Prefix(tag)
	body := strings.Repeat("A", secret.BodyLen)
	token := prefix + body
	huge := 1 << 20

	fixed := []parseCase{
		{"valid", token, true},
		{"valid, body with _ and -", prefix + strings.Repeat("-_", 21) + "A", true},
		{"valid, body that starts with _", prefix + "_" + strings.Repeat("A", 42), true},
		{"valid, body that starts with -", prefix + "-" + strings.Repeat("A", 42), true},
		{"valid, body that spells another prefix", prefix + "susu_inv_" + strings.Repeat("A", 34), true},
		{"valid, mixed case body", prefix + strings.Repeat("aB", 21) + "E", true},
		{"valid, all digits ending in 4", prefix + strings.Repeat("0123456789", 4) + "014", true},
		{"valid, all ones body", secret.Prefix(tag) + strings.Repeat("_", 42) + "8", true},

		// The prefix.
		{"prefix only", prefix, false},
		{"unknown tag", "susu_xyz_" + body, false},
		{"empty tag", "susu__" + body, false},
		{"tag is a prefix of the right one", "susu_" + string(tag)[:2] + "_" + body, false},
		{"tag with a suffix", "susu_" + string(tag) + "x_" + body, false},
		{"missing _ after the tag", "susu_" + string(tag) + body, false},
		{"missing _ after susu", "susu" + string(tag) + "_" + body, false},
		{"missing brand", string(tag) + "_" + body, false},
		{"extra _ after susu", "susu__" + string(tag) + "_" + body, false},
		{"extra _ after the tag, 43 more characters", "susu_" + string(tag) + "__" + body, false},
		// The second _ is the body's first character.
		{"extra _ after the tag, 42 more characters", "susu_" + string(tag) + "__" + body[1:], true},
		{"leading _", "_" + token, false},
		{"hyphen for underscore", "susu-" + string(tag) + "-" + body, false},
		{"dot for underscore", "susu." + string(tag) + "." + body, false},
		{"uppercase prefix", "SUSU_" + strings.ToUpper(string(tag)) + "_" + body, false},
		{"uppercase brand", "SUSU_" + string(tag) + "_" + body, false},
		{"uppercase tag", "susu_" + strings.ToUpper(string(tag)) + "_" + body, false},
		{"capitalised brand", "Susu_" + string(tag) + "_" + body, false},
		{"prefix twice", prefix + token, false},
		{"token twice", token + token, false},
		{"two tokens separated by a space", token + " " + token, false},
		{"two tokens separated by a comma", token + "," + token, false},

		// The length of the body.
		{"empty", "", false},
		{"body of 0", prefix, false},
		{"body of 1", prefix + "A", false},
		{"body of 42", prefix + body[:42], false},
		{"body of 44", prefix + body + "A", false},
		{"body of 44, extra at the front", prefix + "A" + body, false},
		{"body of 86", prefix + body + body, false},
		{"body of 64 (a 48-byte token)", prefix + strings.Repeat("A", 64), false},
		{"body of 42, last character not canonical", prefix + body[:41] + "B", false},
		{"huge body", prefix + strings.Repeat("A", huge), false},
		{"huge input with no prefix", strings.Repeat("A", huge), false},
		{"huge input of the prefix", strings.Repeat(prefix, huge/len(prefix)), false},
		{"valid token and then a huge tail", token + strings.Repeat("A", huge), false},
		{"huge input of NULs", strings.Repeat("\x00", huge), false},

		// Padding and the standard alphabet.
		{"padding replacing the last character", prefix + body[:42] + "=", false},
		{"padding after the body", prefix + body + "=", false},
		{"two paddings, as a 42 character body would carry", prefix + body[:41] + "==", false},
		{"padding in the middle", replaceAt(token, len(prefix)+10, "="), false},
		{"plus in the middle", replaceAt(token, len(prefix)+10, "+"), false},
		{"slash in the middle", replaceAt(token, len(prefix)+10, "/"), false},
		{"plus as the last character (value 62, standard alphabet)", prefix + body[:42] + "+", false},
		{"slash as the last character (value 63, standard alphabet)", prefix + body[:42] + "/", false},
		{"plus as the first character", prefix + "+" + body[1:], false},
		{"dot", replaceAt(token, len(prefix)+10, "."), false},
		{"percent escape", prefix + "%41" + body[3:], false},
		{"percent encoded underscore", "susu%5F" + string(tag) + "_" + body, false},
		{"colon", replaceAt(token, len(prefix)+10, ":"), false},
		{"semicolon (cookie separator)", replaceAt(token, len(prefix)+10, ";"), false},
		{"equals (cookie name separator)", "session=" + token, false},
		{"double quote", "\"" + token + "\"", false},
		{"single quote inside", replaceAt(token, len(prefix)+10, "'"), false},
		{"bracket just above Z", replaceAt(token, len(prefix)+10, "["), false},
		{"backtick just above Z", replaceAt(token, len(prefix)+10, "`"), false},
		{"brace just above z", replaceAt(token, len(prefix)+10, "{"), false},
		{"at just below A", replaceAt(token, len(prefix)+10, "@"), false},

		// Whitespace and control characters, which are never trimmed.
		{"leading space", " " + token, false},
		{"trailing space", token + " ", false},
		{"leading tab", "\t" + token, false},
		{"trailing tab", token + "\t", false},
		{"leading newline", "\n" + token, false},
		{"trailing newline", token + "\n", false},
		{"trailing carriage return and line feed", token + "\r\n", false},
		{"space inside the body", replaceAt(token, len(prefix)+10, " "), false},
		{"tab inside the body", replaceAt(token, len(prefix)+10, "\t"), false},
		{"newline inside the body (a base64 decoder skips it)", replaceAt(token, len(prefix)+10, "\n"), false},
		{"carriage return inside the body (a base64 decoder skips it)", replaceAt(token, len(prefix)+10, "\r"), false},
		{"newline inside a 44 character body", prefix + body[:20] + "\n" + body[20:], false},
		{"bearer prefix", "Bearer " + token, false},
		{"cookie form", "__Host-session=" + token, false},
		{"DEL", replaceAt(token, len(prefix)+10, "\x7f"), false},
		{"form feed", token + "\f", false},
		{"vertical tab", token + "\v", false},
		{"no-break space", token + "\u00a0", false},
		{"ideographic space", "\u3000" + token, false},

		// NUL and non-ASCII.
		{"NUL at the end", token + "\x00", false},
		{"NUL at the start", "\x00" + token, false},
		{"NUL inside the body", replaceAt(token, len(prefix)+10, "\x00"), false},
		{"NUL inside the prefix", replaceAt(token, 2, "\x00"), false},
		{"NUL ends the token early", token[:len(prefix)+10] + "\x00" + token[len(prefix)+10:], false},
		{"e acute replacing a character, 43 bytes", prefix + body[:20] + "\u00e9" + body[22:], false},
		{"e acute replacing a character, 43 characters", prefix + body[:20] + "\u00e9" + body[21:], false},
		{"fullwidth A replacing a character", prefix + body[:19] + "\uff21" + body[22:], false},
		{"fullwidth A as well as a full body", prefix + body + "\uff21", false},
		{"fullwidth underscore in the prefix", "susu\uff3f" + string(tag) + "_" + body, false},
		{"fullwidth brand", "\uff53\uff55\uff53\uff55_" + string(tag) + "_" + body, false},
		{"zero width space inside", prefix + body[:20] + "\u200b" + body[21:], false},
		{"zero width space before", "\u200b" + token, false},
		{"byte order mark before", "\ufeff" + token, false},
		{"Cyrillic s for the first letter of the tag", "susu_" + "\u0455" + string(tag)[1:] + "_" + body, false},
		{"invalid UTF-8 byte", prefix + body[:20] + "\xff" + body[21:], false},
		{"high byte", prefix + body[:20] + "\x80" + body[21:], false},
		{"lone high byte after the body", token + "\x80", false},
	}

	cases := make([]parseCase, 0, len(fixed)+len(base64urlAlphabet)+2*len(otherTags(tag)))
	cases = append(cases, fixed...)

	// The last character: its 6-bit value must have its two low bits zero. All
	// 64 characters of the alphabet are tried in that position.
	for i := range len(base64urlAlphabet) {
		last := string(base64urlAlphabet[i])
		name := "last character " + last + " (value " + strconv.Itoa(i) + ")"

		cases = append(cases, parseCase{name, prefix + body[:42] + last, i%4 == 0})
	}

	// Another type's valid token, with the same body, is refused, and so is a
	// valid token of this type's with a foreign prefix swapped in.
	dashes := strings.Repeat("-_", 21) + "A"

	for _, other := range otherTags(tag) {
		cases = append(cases,
			parseCase{"another type's valid token: " + string(other), secret.Prefix(other) + body, false},
			parseCase{"another type's valid token, body with _ and -: " + string(other), secret.Prefix(other) + dashes, false},
		)
	}

	return cases
}

func TestParseTokens(t *testing.T) {
	t.Parallel()

	for _, spec := range tokenSpecs() {
		t.Run(spec.name, func(t *testing.T) {
			t.Parallel()
			runStringTable(t, tokenCases(spec.tag), spec.parse, spec.code)
		})
	}
}

func TestTokenCodes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ got, want string }{
		{input.CodeInvalidInvitation, "invalid_invitation"},
		{input.CodeInvalidSessionToken, "invalid_session_token"},
		{input.CodeInvalidAPIKey, "invalid_api_key"},
	} {
		if tc.got != tc.want {
			t.Errorf("code = %q, want %q", tc.got, tc.want)
		}
	}
}

// TestTokenDescriptionsStateTheShape keeps the fixed client-facing text in
// step with internal/secret, and checks that each type has its own text and
// that none of them contains the input.
func TestTokenDescriptionsStateTheShape(t *testing.T) {
	t.Parallel()

	seen := map[string]string{}

	for _, spec := range tokenSpecs() {
		t.Run(spec.name, func(t *testing.T) {
			t.Parallel()

			_, err := spec.parse("")
			description := descriptionOf(t, err, spec.code)

			if !strings.Contains(description, secret.Prefix(spec.tag)) {
				t.Errorf("description %q does not state the prefix %q", description, secret.Prefix(spec.tag))
			}

			requireMentions(t, description, secret.BodyLen)

			if !strings.Contains(description, "base64url") {
				t.Errorf("description %q does not name the alphabet", description)
			}

			// A refusal never varies with the input.
			secretish := secret.Prefix(spec.tag) + "SENSITIVE"
			_, err = spec.parse(secretish)
			requireFixedRefusal(t, err, spec.code, description)
		})

		_, err := spec.parse("")
		description := probeDescription(err)

		if other, dup := seen[description]; dup {
			t.Errorf("%s and %s share the description %q", spec.name, other, description)
		}

		seen[description] = spec.name
	}
}

// TestTokenHash: the hash is the SHA-256 of the whole token string, prefix
// included, as 32 bytes, and it is the same value internal/secret computes.
func TestTokenHash(t *testing.T) {
	t.Parallel()

	known := map[secret.Tag]string{ // sha256sum of the token with an all-'A' body
		secret.TagInvitation: "deea0b66bbe6ae2fc63809b6da5b8609b545d2ea1ea89f1711b098f91301371f",
		secret.TagSession:    "2301fbf509e56daaa1975f1f2070d1e780085d46eb2218610165ef75aef440eb",
		secret.TagAPIKey:     "60ae433c89f4b65105cd713a3e69e9754de9d5cb13aa7e1b3eb15cda5a433c3d",
	}

	for _, spec := range tokenSpecs() {
		t.Run(spec.name, func(t *testing.T) {
			t.Parallel()

			token := secret.Prefix(spec.tag) + strings.Repeat("A", secret.BodyLen)

			got, err := spec.hash(token)
			if err != nil {
				t.Fatal(err)
			}

			if len(got) != sha256.Size { // secrets.hash: length(hash) = 32
				t.Fatalf("len(Hash()) = %d, want %d", len(got), sha256.Size)
			}

			want := sha256.Sum256([]byte(token))
			if !bytes.Equal(got, want[:]) {
				t.Errorf("Hash() = %x, want sha256 of the whole token %x", got, want)
			}

			if hex.EncodeToString(got) != known[spec.tag] {
				t.Errorf("Hash() = %x, want %s", got, known[spec.tag])
			}

			if secretHash := secret.Hash(token); !bytes.Equal(got, secretHash[:]) {
				t.Errorf("Hash() = %x differs from secret.Hash %x", got, secretHash)
			}
		})
	}
}

// TestTokenHashIsPerCall proves a caller that scribbles on the returned slice
// cannot change what the next lookup hashes to.
func TestTokenHashIsPerCall(t *testing.T) {
	t.Parallel()

	token, err := input.ParseSessionToken(secret.Prefix(secret.TagSession) + strings.Repeat("A", secret.BodyLen))
	if err != nil {
		t.Fatal(err)
	}

	first := token.Hash()
	want := bytes.Clone(first)

	for i := range first {
		first[i] = 0
	}

	if !bytes.Equal(token.Hash(), want) {
		t.Error("Hash() shares storage between calls")
	}
}

// TestTokenHashDistinguishesTypesAndBodies: one body under the three tags, and
// two bodies under one tag, are all different lookups.
func TestTokenHashDistinguishesTypesAndBodies(t *testing.T) {
	t.Parallel()

	seen := map[string]string{}

	for _, spec := range tokenSpecs() {
		for _, last := range []string{"A", "E"} {
			token := secret.Prefix(spec.tag) + strings.Repeat("A", secret.BodyLen-1) + last

			got, err := spec.hash(token)
			if err != nil {
				t.Fatal(err)
			}

			if other, dup := seen[string(got)]; dup {
				t.Errorf("%q and %s hash alike", token, other)
			}

			seen[string(got)] = token
		}
	}
}

// TestGeneratedTokensParseAsTheirOwnType: what internal/secret generates for a
// tag is accepted by that type's parser and refused by the other two, with each
// parser's own code. The readers cover the extremes of the last character.
func TestGeneratedTokensParseAsTheirOwnType(t *testing.T) {
	t.Parallel()

	ramp := make([]byte, secret.BodyBytes)
	for i := range ramp {
		ramp[i] = byte(i)
	}

	readers := map[string][]byte{
		"zeros":  make([]byte, secret.BodyBytes),
		"ones":   bytes.Repeat([]byte{0xff}, secret.BodyBytes),
		"ramp":   ramp,
		"last 1": append(make([]byte, secret.BodyBytes-1), 1),
		"last f": append(make([]byte, secret.BodyBytes-1), 0xf0),
	}

	for name, entropy := range readers {
		for _, spec := range tokenSpecs() {
			t.Run(name+"/"+spec.name, func(t *testing.T) {
				t.Parallel()

				checkGenerated(t, bytes.NewReader(entropy), spec)
			})
		}
	}

	for _, spec := range tokenSpecs() {
		t.Run("random/"+spec.name, func(t *testing.T) {
			t.Parallel()

			for range 50 {
				checkGenerated(t, rand.Reader, spec)
			}
		})
	}
}

func checkGenerated(t *testing.T, entropy io.Reader, spec tokenSpec) {
	t.Helper()

	token, err := secret.Generate(entropy, spec.tag)
	if err != nil {
		t.Fatal(err)
	}

	got, err := spec.parse(token)
	if err != nil || got != token {
		t.Fatalf("%s refused the %q token it should accept: %q, %v", spec.name, spec.tag, got, err)
	}

	for _, other := range tokenSpecs() {
		if other.tag == spec.tag {
			continue
		}

		_, err := other.parse(token)
		requireRefusal(t, err, other.code)
	}
}

// TestTokenBodyDecodesToTheBodySize: the longest and shortest accepted bodies
// decode to exactly BodyBytes, so a 43-character body is never a different
// size of secret.
func TestTokenBodyDecodesToTheBodySize(t *testing.T) {
	t.Parallel()

	for i := range len(base64urlAlphabet) {
		body := strings.Repeat("A", secret.BodyLen-1) + string(base64urlAlphabet[i])
		_, err := base64.RawURLEncoding.Strict().DecodeString(body)

		if canonical := err == nil; canonical != (i%4 == 0) {
			t.Errorf("last character %q: strict decode canonical = %v, want %v", base64urlAlphabet[i], canonical, i%4 == 0)
		}
	}
}

// tokenOracle restates the rule for one tag without the parser's code: the
// exact prefix, and a body that is 43 characters long and is the unpadded,
// strict encoding of 32 bytes (so decoding and re-encoding gives it back).
func tokenOracle(tag secret.Tag) func(string) bool {
	return func(s string) bool {
		body, ok := strings.CutPrefix(s, secret.Prefix(tag))
		if !ok {
			return false
		}

		raw, err := base64.RawURLEncoding.Strict().DecodeString(body)

		return err == nil && len(raw) == secret.BodyBytes && base64.RawURLEncoding.EncodeToString(raw) == body
	}
}

// fuzzToken is the fuzz target of one token type. Anything accepted has the
// exact prefix, parses again to the same value, and its body decodes under the
// strict rules to 32 bytes that encode back to the same body; Hash is the
// SHA-256 of the token. Anything refused carries the type's code and fixed
// text.
func fuzzToken[T comparable](
	f *testing.F, tag secret.Tag, code string, parse func(string) (T, error), str func(T) string, hash func(T) []byte,
) {
	f.Helper()

	for _, seed := range seedsOf(tokenCases(tag)) {
		f.Add(seed)
	}

	_, probe := parse("\x00\xff\x00")
	if probe == nil {
		f.Fatal("the probe input was accepted")
	}

	description := probeDescription(probe)
	oracle := tokenOracle(tag)

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

		sum := sha256.Sum256([]byte(raw))
		if !bytes.Equal(hash(value), sum[:]) {
			t.Fatalf("Hash() of %q = %x, want %x", raw, hash(value), sum)
		}
	})
}

func FuzzParseInvitationToken(f *testing.F) {
	fuzzToken(f, secret.TagInvitation, input.CodeInvalidInvitation, input.ParseInvitationToken,
		input.InvitationToken.String, input.InvitationToken.Hash)
}

func FuzzParseSessionToken(f *testing.F) {
	fuzzToken(f, secret.TagSession, input.CodeInvalidSessionToken, input.ParseSessionToken,
		input.SessionToken.String, input.SessionToken.Hash)
}

func FuzzParseAPIKeyToken(f *testing.F) {
	fuzzToken(f, secret.TagAPIKey, input.CodeInvalidAPIKey, input.ParseAPIKeyToken,
		input.APIKeyToken.String, input.APIKeyToken.Hash)
}
