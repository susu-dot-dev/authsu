//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

func parseEmail(raw string) (string, error) {
	return strAdapter(input.ParseEmail, input.Email.String)(raw)
}

// domainOf returns a domain of exactly n bytes (n of at least 3) made of labels
// of the longest length the parser allows, so a test can reach MaxEmailBytes.
func domainOf(n int) string {
	var labels []string

	for remaining := n; remaining > 0; {
		size := min(remaining, input.MaxEmailLabelBytes)

		// Leave at least one byte for a label after the dot, never an empty one.
		if remaining-size == 1 {
			size--
		}

		labels = append(labels, strings.Repeat("a", size))
		remaining -= size + 1
	}

	return strings.Join(labels, ".")
}

func emailCases() []parseCase {
	return slices.Concat(acceptedEmails(), malformedEmails(), hostileEmails())
}

// acceptedEmails are the addresses the parser accepts, up to its limits.
func acceptedEmails() []parseCase {
	label63 := strings.Repeat("a", input.MaxEmailLabelBytes)
	local64 := strings.Repeat("a", input.MaxEmailLocalBytes)
	// An address of exactly MaxEmailBytes: a short local part and a long domain.
	longest := "a@" + domainOf(input.MaxEmailBytes-len("a@"))
	if len(longest) != input.MaxEmailBytes {
		panic("the longest address is not MaxEmailBytes long")
	}

	return []parseCase{
		// Accepted.
		{"a plain address", "alice@example.com", true},
		{"case is kept", "Alice@Example.COM", true},
		{"a subdomain", "alice@mail.example.co.uk", true},
		{"dots inside the local part", "first.last@example.com", true},
		{"a plus tag", "alice+tag@example.com", true},
		{"an apostrophe", "o'brien@example.com", true},
		{"every special character of the local part", "!#$%'*+-/=?^_`{|}~@example.com", true},
		{"digits everywhere", "123@456.example", true},
		{"a hyphen inside a label", "a@my-host.example.com", true},
		{"a one-character local part and labels", "a@b.cc", true},
		{"a local part of 64 bytes", local64 + "@example.com", true},
		{"a label of 63 bytes", "a@" + label63 + ".com", true},
		{"a punycode label", "a@xn--bcher-kva.example", true},
		{"a top-level label with a digit", "a@example.c0m", true},
		{"exactly MaxEmailBytes", longest, true},
		{"a percent sign in the local part", "alice%b@example.com", true},
	}
}

// malformedEmails are the addresses that break the grammar or a size limit.
func malformedEmails() []parseCase {
	label63 := strings.Repeat("a", input.MaxEmailLabelBytes)
	local64 := strings.Repeat("a", input.MaxEmailLocalBytes)
	longest := "a@" + domainOf(input.MaxEmailBytes-len("a@"))

	return []parseCase{
		// Shape.
		{"empty", "", false},
		{"only an @", "@", false},
		{"no @", "alice.example.com", false},
		{"two @", "a@b@example.com", false},
		{"@ in the domain", "a@exa@mple.com", false},
		{"no local part", "@example.com", false},
		{"no domain", "alice@", false},
		{"a single-label domain", "alice@localhost", false},
		{"an address literal", "alice@[127.0.0.1]", false},
		{"an IPv4 domain", "alice@127.0.0.1", false},
		{"an all-digit top-level label", "alice@example.123", false},
		{"IPv6 literal", "alice@[IPv6:::1]", false},

		// The local part.
		{"a local part of 65 bytes", local64 + "a@example.com", false},
		{"a leading dot", ".alice@example.com", false},
		{"a trailing dot", "alice.@example.com", false},
		{"two dots in a row", "al..ice@example.com", false},
		{"a quoted local part", `"alice"@example.com`, false},
		{"a quoted local part with a space", `"al ice"@example.com`, false},
		{"an escaped character", `al\ice@example.com`, false},
		{"a comment", "alice(comment)@example.com", false},
		{"angle brackets", "<alice@example.com>", false},
		{"a display name", "Alice <alice@example.com>", false},
		{"a space in the local part", "al ice@example.com", false},
		{"a comma", "alice,bob@example.com", false},
		{"a semicolon", "alice;bob@example.com", false},
		{"a colon", "alice:bob@example.com", false},
		{"an ampersand, which JSON would expand six-fold", "r&d@example.com", false},
		{"a double quote", `al"ice@example.com`, false},
		{"a backslash", `a\@example.com`, false},
		{"a source route", "@a.com:alice@example.com", false},

		// The domain.
		{"a leading dot in the domain", "alice@.example.com", false},
		{"a trailing dot in the domain", "alice@example.com.", false},
		{"two dots in the domain", "alice@example..com", false},
		{"a label of 64 bytes", "a@" + label63 + "a.com", false},
		{"a label starting with a hyphen", "a@-example.com", false},
		{"a label ending with a hyphen", "a@example-.com", false},
		{"an underscore in the domain", "a@exa_mple.com", false},
		{"a space in the domain", "a@exa mple.com", false},
		{"a plus in the domain", "a@exa+mple.com", false},

		// Size.
		{"one over MaxEmailBytes", longest + "a", false},
		{"far over MaxEmailBytes", "a@" + strings.Repeat("a.", input.MaxEmailBytes) + "com", false},
		{"far over with a hostile tail", longest + strings.Repeat("a", input.MaxEmailBytes*8) + "\x00", false},
	}
}

// hostileEmails are addresses made of what no address may hold: the parser
// refuses them and never rewrites them.
func hostileEmails() []parseCase {
	return []parseCase{
		// Hostile bytes and text: the parser refuses and never rewrites.
		{"surrounding space", " alice@example.com", false},
		{"trailing space", "alice@example.com ", false},
		{"trailing newline", "alice@example.com\n", false},
		{"embedded newline", "alice@exam\nple.com", false},
		{"carriage return and line feed", "alice@example.com\r\nBcc: eve@example.com", false},
		{"a tab", "alice@example.com\t", false},
		{"NUL at the end", "alice@example.com\x00", false},
		{"NUL in the local part", "al\x00ice@example.com", false},
		{"DEL", "al\x7fice@example.com", false},
		{"a non-ASCII letter in the local part", "alic\u00e9@example.com", false},
		{"a non-ASCII letter in the domain", "alice@exampl\u00e9.com", false},
		{"an internationalised domain", "alice@\u4f8b\u3048.jp", false},
		{"a fullwidth @", "alice\uff20example.com", false},
		{"a fullwidth dot", "alice@example\uff0ecom", false},
		{"a zero-width space", "ali\u200bce@example.com", false},
		{"a bidi override", "alice@example\u202e.com", false},
		{"a decomposed accent", "alice\u0301@example.com", false},
		{"an invalid UTF-8 byte", "alice@exam\xffple.com", false},
		{"U+FFFD", "alice@exam\ufffdple.com", false},
		{"an emoji", "alice@example.com\U0001f600", false},
	}
}

func TestParseEmail(t *testing.T) {
	t.Parallel()
	runStringTable(t, emailCases(), parseEmail, input.CodeInvalidEmail)
}

// TestEmailDescriptionStatesTheBound keeps the fixed client-facing text in step
// with the exported constant.
func TestEmailDescriptionStatesTheBound(t *testing.T) {
	t.Parallel()

	_, err := input.ParseEmail("")
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidEmail), input.MaxEmailBytes)
}

func TestZeroEmailIsEmpty(t *testing.T) {
	t.Parallel()

	var email input.Email

	if email.String() != "" {
		t.Error("the zero value is not empty")
	}
}

// TestEmailFitsTheProfileBesideTheName proves the arithmetic MaxEmailBytes rests
// on: the longest account name, all of it escaped, and the longest email, in
// the object registration stores, fit users.profile's CHECK.
func TestEmailFitsTheProfileBesideTheName(t *testing.T) {
	t.Parallel()

	const maxJSONExpansion = 6 // "<" becomes \u003c in encoding/json

	limits := migrationNumbers(t, `length\(profile\) <= (\d+)`)
	limit := limits[len(limits)-1]

	worst := struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}{
		Name:  strings.Repeat("<", input.MaxAccountNameBytes),
		Email: "a@" + domainOf(input.MaxEmailBytes-len("a@")),
	}

	encoded, err := json.Marshal(worst)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want := len(`{"name":"","email":""}`) + input.MaxAccountNameBytes*maxJSONExpansion + input.MaxEmailBytes
	if len(encoded) != want {
		t.Errorf("worst-case profile is %d bytes, want %d: an email character is escaped", len(encoded), want)
	}

	if len(encoded) > limit {
		t.Errorf("worst-case profile is %d bytes, over the %d-byte CHECK", len(encoded), limit)
	}
}

// TestEmailCharactersAreNotEscapedByJSON holds that no byte the parser accepts
// is expanded by encoding/json, which is what makes the bound above exact: every
// accepted byte is tried alone in both parts of an address.
func TestEmailCharactersAreNotEscapedByJSON(t *testing.T) {
	t.Parallel()

	accepted := 0

	for c := range 256 {
		raw := string([]byte{byte(c)}) + "@example.com"

		_, err := input.ParseEmail(raw)
		if err != nil {
			continue
		}

		accepted++

		encoded, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("marshal %q: %v", raw, err)
		}

		if len(encoded) != len(raw)+2 {
			t.Errorf("%q is %d bytes in JSON, want %d", raw, len(encoded), len(raw)+2)
		}
	}

	if accepted == 0 {
		t.Fatal("no byte was accepted, so nothing was checked")
	}
}

// emailOracle is an independent statement of the rules, for the fuzz test.
func emailOracle() func(string) bool {
	const (
		atext = "[A-Za-z0-9!#$%'*+/=?^_`{|}~-]+"
		label = "[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
	)

	pattern := regexp.MustCompile(`^` + atext + `(?:\.` + atext + `)*@(?:` + label + `\.)+` + label + `$`)
	allDigits := regexp.MustCompile(`^[0-9]+$`)

	return func(s string) bool {
		if len(s) > input.MaxEmailBytes || !pattern.MatchString(s) {
			return false
		}

		local, domain, _ := strings.Cut(s, "@")
		if len(local) > input.MaxEmailLocalBytes {
			return false
		}

		labels := strings.Split(domain, ".")
		for _, l := range labels {
			if len(l) > input.MaxEmailLabelBytes {
				return false
			}
		}

		return !allDigits.MatchString(labels[len(labels)-1])
	}
}

func FuzzParseEmail(f *testing.F) {
	fuzzString(f, seedsOf(emailCases()), input.ParseEmail, input.Email.String, input.CodeInvalidEmail, emailOracle())
}
