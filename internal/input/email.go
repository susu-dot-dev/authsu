package input

import "strings"

// Bounds of Email.
const (
	// MaxEmailBytes bounds Email, in bytes. The address is stored in
	// users.profile beside the name, as the JSON {"name": "...", "email":
	// "..."}, which the CHECK `length(profile) <= 1024` (migration 0001)
	// limits to 1024 bytes. The name's worst case is 768 bytes (128 bytes, each
	// escaped to six) and the object syntax of the two members is 22 more, which
	// leaves 234 for the address. Every character an Email may hold is one that
	// JSON does not escape, so it takes exactly one byte there. 200 is below that
	// with room for a further profile field, and above every address in common
	// use; RFC 5321's 254 does not fit beside a maximal name.
	MaxEmailBytes = 200

	// MaxEmailLocalBytes is the longest local part (RFC 5321, section 4.5.3.1.1).
	MaxEmailLocalBytes = 64

	// MaxEmailLabelBytes is the longest label of the domain (RFC 1035, section
	// 2.3.4).
	MaxEmailLabelBytes = 63
)

// CodeInvalidEmail is the code of a refused Email.
const CodeInvalidEmail = "invalid_email"

const descInvalidEmail = "email must be an address of the form local@domain, 5 to 200 bytes, " +
	"in ASCII, with a dotted domain name"

// Email is the address a person registers with. It is a conservative subset of
// RFC 5322's addr-spec, chosen so that one address has one spelling and the
// stored JSON is never longer than the address:
//
//   - the local part is a dot-atom: 1 to 64 letters, digits and the characters
//     in emailLocalSpecials, in runs separated by single dots, never starting or
//     ending with a dot. Quoted strings, comments and escapes are refused;
//   - the domain is a host name of at least two dot-separated labels of 1 to 63
//     letters, digits and hyphens, none starting or ending with a hyphen, the
//     last not all digits (so an address literal such as [127.0.0.1] or
//     1.2.3.4 is no domain);
//   - everything is ASCII. An internationalised address is refused rather than
//     converted, and case is kept: "Ann@x.org" and "ann@x.org" are two
//     spellings, as with every other parsed value.
//
// The ampersand is valid in RFC 5322 and refused here: encoding/json writes it
// as \u0026, six bytes, which no bound that fits the profile CHECK could allow.
type Email struct{ v string }

// emailLocalSpecials are the non-alphanumeric characters of RFC 5322's atext,
// less the ampersand (see Email), the dot being handled apart.
const emailLocalSpecials = "!#$%'*+-/=?^_`{|}~"

// ParseEmail accepts an address of at most MaxEmailBytes bytes, as Email
// describes, and refuses everything else, never rewriting it.
func ParseEmail(raw string) (Email, error) {
	if !validEmail(raw) {
		return Email{}, refuse(CodeInvalidEmail, descInvalidEmail)
	}

	return Email{v: raw}, nil
}

// String returns the address exactly as it was parsed.
func (e Email) String() string { return e.v }

// validEmail reports whether s is an address ParseEmail accepts.
func validEmail(s string) bool {
	if len(s) > MaxEmailBytes {
		return false
	}

	// Neither part may hold an @, so there is exactly one.
	local, domain, found := strings.Cut(s, "@")
	if !found || strings.Contains(domain, "@") {
		return false
	}

	return validEmailLocal(local) && validEmailDomain(domain)
}

// validEmailLocal reports whether s is a dot-atom of at most
// MaxEmailLocalBytes bytes.
func validEmailLocal(s string) bool {
	if s == "" || len(s) > MaxEmailLocalBytes {
		return false
	}

	for atom := range strings.SplitSeq(s, ".") {
		if atom == "" || !allBytes(atom, func(c byte) bool {
			return alphanumeric(c) || strings.IndexByte(emailLocalSpecials, c) >= 0
		}) {
			return false
		}
	}

	return true
}

// minDomainLabels is the fewest labels of a domain: a name and a top level.
const minDomainLabels = 2

// validEmailDomain reports whether s is a host name of at least two labels.
func validEmailDomain(s string) bool {
	labels := strings.Split(s, ".")
	if len(labels) < minDomainLabels {
		return false
	}

	for _, label := range labels {
		if !validEmailLabel(label) {
			return false
		}
	}

	return !allBytes(labels[len(labels)-1], digit)
}

// validEmailLabel reports whether s is one label of a host name.
func validEmailLabel(s string) bool {
	if s == "" || len(s) > MaxEmailLabelBytes || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}

	return allBytes(s, func(c byte) bool { return alphanumeric(c) || c == '-' })
}

func digit(c byte) bool { return c >= '0' && c <= '9' }

func alphanumeric(c byte) bool {
	return digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// allBytes reports whether every byte of s satisfies ok. A byte of a multi-byte
// character is above 0x7f, which no predicate here accepts, so non-ASCII text
// is refused.
func allBytes(s string, ok func(byte) bool) bool {
	for i := range len(s) {
		if !ok(s[i]) {
			return false
		}
	}

	return true
}
