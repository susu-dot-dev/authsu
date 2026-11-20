//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// RFC 7636 appendix B: a verifier and its S256 challenge.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// challengeCases is the table of ParseCodeChallenge.
func challengeCases() []parseCase {
	body := strings.Repeat("A", input.CodeChallengeLen)

	fixed := []parseCase{
		{"the RFC 7636 challenge", rfcChallenge, true},
		{"all zero bits", body, true},
		{"with _ and -", strings.Repeat("-_", 21) + "A", true},
		{"starting with _", "_" + strings.Repeat("A", 42), true},
		{"mixed case", strings.Repeat("aB", 21) + "E", true},
		{"all digits", strings.Repeat("0123456789", 4) + "014", true},

		{"empty", "", false},
		{"one character", "A", false},
		{"42 characters", body[:42], false},
		{"44 characters", body + "A", false},
		{"a 128 character verifier", strings.Repeat("A", 128), false},
		{"padding replacing the last character", body[:42] + "=", false},
		{"padding after the body", body + "=", false},
		{"a 42 character body with padding", body[:41] + "==", false},
		{"plus", body[:10] + "+" + body[11:], false},
		{"slash", body[:10] + "/" + body[11:], false},
		{"dot", body[:10] + "." + body[11:], false},
		{"tilde", body[:10] + "~" + body[11:], false},
		{"percent escape", "%41" + body[3:], false},
		{"a leading space", " " + body[1:], false},
		{"a trailing space", body + " ", false},
		{"a leading newline", "\n" + body, false},
		{"a trailing newline", body + "\n", false},
		{"a newline inside, which a decoder skips", body[:20] + "\n" + body[20:], false},
		{"a carriage return inside", body[:20] + "\r" + body[20:], false},
		{"NUL", body[:20] + "\x00" + body[21:], false},
		{"NUL at the end", body + "\x00", false},
		{"e acute, 43 bytes", body[:20] + "\u00e9" + body[22:], false},
		{"e acute, 43 characters", body[:20] + "\u00e9" + body[21:], false},
		{"a fullwidth letter", body[:19] + "\uff21" + body[22:], false},
		{"invalid UTF-8", body[:20] + "\xff" + body[21:], false},
		{"two challenges", body + body, false},
		{"a megabyte", strings.Repeat("A", 1<<20), false},
	}

	// The last character of 43 carries two unused bits, which must be zero:
	// 16 of the 64 characters are canonical.
	cases := make([]parseCase, 0, len(fixed)+len(base64urlAlphabet))
	cases = append(cases, fixed...)

	for i := range len(base64urlAlphabet) {
		last := string(base64urlAlphabet[i])
		cases = append(cases, parseCase{"last character " + last, body[:42] + last, i%4 == 0})
	}

	return cases
}

func TestParseCodeChallenge(t *testing.T) {
	t.Parallel()

	parse := strAdapter(input.ParseCodeChallenge, input.CodeChallenge.String)

	runStringTable(t, challengeCases(), parse, input.CodeInvalidCodeChallenge)
}

func TestCodeChallengeDescriptionStatesTheLength(t *testing.T) {
	t.Parallel()

	_, err := input.ParseCodeChallenge("")
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidCodeChallenge), input.CodeChallengeLen)
}

// TestCodeChallengeMethod: S256 only, compared exactly. The others, plain
// above all, are refused whatever their case.
func TestParseCodeChallengeMethod(t *testing.T) {
	t.Parallel()

	runStringTable(t, []parseCase{
		{"S256", "S256", true},
		{"plain", "plain", false},
		{"PLAIN", "PLAIN", false},
		{"Plain", "Plain", false},
		{"lower-case s256", "s256", false},
		{"mixed case", "S256a", false},
		{"S384", "S384", false},
		{"S512", "S512", false},
		{"SHA256", "SHA256", false},
		{"sha-256", "sha-256", false},
		{"S-256", "S-256", false},
		{"the empty method", "", false},
		{"a leading space", " S256", false},
		{"a trailing space", "S256 ", false},
		{"a trailing newline", "S256\n", false},
		{"a trailing tab", "S256\t", false},
		{"NUL", "S256\x00", false},
		{"S256 twice", "S256,S256", false},
		{"S256 and plain", "S256 plain", false},
		{"a fullwidth digit", "S25\uff16", false},
		{"a Cyrillic S", "\u0405256", false},
		{"percent-encoded", "S%32%35%36", false},
		{"a megabyte", strings.Repeat("S", 1<<20), false},
	}, strAdapter(input.ParseCodeChallengeMethod, input.CodeChallengeMethod.String), input.CodeInvalidCodeChallengeMethod)
}

// verifierCases is the table of ParseCodeVerifier.
func verifierCases() []parseCase {
	forty3 := strings.Repeat("a", input.MinCodeVerifierLen)

	cases := []parseCase{
		{"the RFC 7636 verifier", rfcVerifier, true},
		{"the shortest", forty3, true},
		{"the longest", strings.Repeat("a", input.MaxCodeVerifierLen), true},
		{"one over the longest", strings.Repeat("a", input.MaxCodeVerifierLen+1), false},
		{"one under the shortest", forty3[:input.MinCodeVerifierLen-1], false},
		{"42 characters", strings.Repeat("a", 42), false},
		{"129 characters", strings.Repeat("a", 129), false},
		{"the whole alphabet", unreserved, true},
		{"dots", strings.Repeat(".", 43), true},
		{"tildes", strings.Repeat("~", 43), true},
		{"underscores", strings.Repeat("_", 43), true},
		{"hyphens", strings.Repeat("-", 43), true},
		{"digits", strings.Repeat("7", 43), true},
		{"upper case", strings.Repeat("Z", 43), true},
		{"an ending that is not a base64 canonical one", forty3[:42] + "B", true},
		{"empty", "", false},
		{"a megabyte", strings.Repeat("a", 1<<20), false},
		{"a megabyte of NULs", strings.Repeat("\x00", 1<<20), false},
	}

	// Every byte outside the alphabet is refused in the first, middle and last position.
	for b := range 256 {
		c := byte(b)
		if strings.IndexByte(unreserved, c) >= 0 {
			continue
		}

		name := "byte " + string(rune('0'+b/100)) + string(rune('0'+b/10%10)) + string(rune('0'+b%10))
		cases = append(cases,
			parseCase{name + " first", string([]byte{c}) + forty3[1:], false},
			parseCase{name + " middle", forty3[:20] + string([]byte{c}) + forty3[21:], false},
			parseCase{name + " last", forty3[:42] + string([]byte{c}), false},
		)
	}

	return append(cases,
		parseCase{"padding", forty3[:42] + "=", false},
		parseCase{"plus", forty3[:42] + "+", false},
		parseCase{"slash", forty3[:42] + "/", false},
		parseCase{"a space", forty3[:20] + " " + forty3[21:], false},
		parseCase{"a percent escape", "%41" + forty3[3:], false},
		parseCase{"e acute", forty3[:20] + "\u00e9" + forty3[22:], false},
		parseCase{"a 43 character verifier with a multibyte character", forty3[:20] + "\u00e9" + forty3[21:], false},
		parseCase{"a fullwidth letter", forty3[:20] + "\uff21" + forty3[23:], false},
		parseCase{"a trailing newline", forty3[:42] + "\n", false},
	)
}

func TestParseCodeVerifier(t *testing.T) {
	t.Parallel()

	parse := strAdapter(input.ParseCodeVerifier, input.CodeVerifier.String)

	runStringTable(t, verifierCases(), parse, input.CodeInvalidCodeVerifier)
}

func TestCodeVerifierDescriptionStatesTheBounds(t *testing.T) {
	t.Parallel()

	_, err := input.ParseCodeVerifier("")
	description := descriptionOf(t, err, input.CodeInvalidCodeVerifier)

	requireMentions(t, description, input.MinCodeVerifierLen)
	requireMentions(t, description, input.MaxCodeVerifierLen)
}

// TestVerifierChallenge: the challenge is base64url(sha256(verifier)), the one
// of the RFC for its example, a value ParseCodeChallenge accepts for every
// verifier, and different for different verifiers.
func TestVerifierChallenge(t *testing.T) {
	t.Parallel()

	verifier, err := input.ParseCodeVerifier(rfcVerifier)
	if err != nil {
		t.Fatal(err)
	}

	if got := verifier.Challenge().String(); got != rfcChallenge {
		t.Errorf("Challenge() = %q, want the RFC's %q", got, rfcChallenge)
	}

	seen := map[string]string{}

	for _, raw := range []string{
		rfcVerifier, strings.Repeat("a", 43), strings.Repeat("a", 44), strings.Repeat("a", 128),
		strings.Repeat("A", 43), strings.Repeat("~", 43), rfcVerifier[:42] + "A", "a" + rfcVerifier[1:],
		strings.ToUpper(rfcVerifier),
	} {
		verifier, err := input.ParseCodeVerifier(raw)
		if err != nil {
			t.Fatal(err)
		}

		challenge := verifier.Challenge().String()

		sum := sha256.Sum256([]byte(raw))
		if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
			t.Errorf("Challenge() of %q = %q, want %q", raw, challenge, want)
		}

		_, err = input.ParseCodeChallenge(challenge)
		if err != nil {
			t.Errorf("the challenge of %q is refused: %v", raw, err)
		}

		if other, dup := seen[challenge]; dup {
			t.Errorf("%q and %q have one challenge", raw, other)
		}

		seen[challenge] = raw
	}
}

// TestVerifierChallengeOfRandomVerifiers: whatever a client generates, its
// challenge is a challenge, and a verifier that is not the one does not
// produce it.
func TestVerifierChallengeOfRandomVerifiers(t *testing.T) {
	t.Parallel()

	for range 200 {
		raw := make([]byte, 32)
		_, err := rand.Read(raw)
		if err != nil {
			t.Fatal(err)
		}

		verifier, err := input.ParseCodeVerifier(base64.RawURLEncoding.EncodeToString(raw))
		if err != nil {
			t.Fatal(err)
		}

		challenge, err := input.ParseCodeChallenge(verifier.Challenge().String())
		if err != nil || challenge != verifier.Challenge() {
			t.Fatalf("challenge %q: %v", verifier.Challenge(), err)
		}

		raw[0] ^= 1

		other, err := input.ParseCodeVerifier(base64.RawURLEncoding.EncodeToString(raw))
		if err != nil {
			t.Fatal(err)
		}

		if other.Challenge() == verifier.Challenge() {
			t.Fatal("two verifiers have one challenge")
		}
	}
}

func FuzzParseCodeChallenge(f *testing.F) {
	fuzzInvariants(f, seedsOf(challengeCases()), input.ParseCodeChallenge, input.CodeChallenge.String,
		input.CodeInvalidCodeChallenge, func(t *testing.T, raw string) {
			t.Helper()

			decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
			if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != raw {
				t.Fatalf("%q is not the canonical base64url of a SHA-256: %v", raw, err)
			}
		})
}

func FuzzParseCodeChallengeMethod(f *testing.F) {
	fuzzInvariants(f, []string{"S256", "plain", "", "s256"}, input.ParseCodeChallengeMethod,
		input.CodeChallengeMethod.String, input.CodeInvalidCodeChallengeMethod, func(t *testing.T, raw string) {
			t.Helper()

			if raw != "S256" {
				t.Fatalf("accepted %q", raw)
			}
		})
}

const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

func FuzzParseCodeVerifier(f *testing.F) {
	fuzzInvariants(f, seedsOf(verifierCases()), input.ParseCodeVerifier, input.CodeVerifier.String,
		input.CodeInvalidCodeVerifier, func(t *testing.T, raw string) {
			t.Helper()

			if len(raw) < 43 || len(raw) > 128 || strings.Trim(raw, unreserved) != "" {
				t.Fatalf("accepted %q", raw)
			}

			verifier, _ := input.ParseCodeVerifier(raw)

			_, err := input.ParseCodeChallenge(verifier.Challenge().String())
			if err != nil {
				t.Fatalf("the challenge of %q is refused: %v", raw, err)
			}
		})
}
