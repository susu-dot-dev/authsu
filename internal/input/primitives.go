package input

import (
	"strconv"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/susu-dot-dev/authsu/internal/apierr"
)

// MaxSafeInteger is 2^53-1, the largest integer a JavaScript number (a
// float64) represents exactly. D1 moves numbers through JavaScript, so any
// integer above this loses precision between Go and the database. Every
// integer type in this package stays at or below it.
const MaxSafeInteger int64 = 1<<53 - 1

// refuse builds the error every parser returns. Each call returns a fresh
// value so a caller that adds data to it cannot affect another request.
func refuse(code, description string) *apierr.Error {
	return apierr.New(apierr.BadRequest, code, description)
}

// unit is what a text bound counts.
type unit uint8

const (
	unitBytes unit = iota
	unitRunes
)

// maxRuneBytes is the longest UTF-8 encoding of one rune.
const maxRuneBytes = 4

// textRule is the bound and policy for one kind of display text.
type textRule struct {
	// unit is what max counts.
	unit unit
	// max is the largest accepted length, in unit.
	max int
	// allowEmpty accepts the empty string. Text that is not empty but only
	// whitespace is always refused, since it displays as nothing.
	allowEmpty bool
	// identifying is text a person is recognised by (an account's name). It
	// admits no format character at all. Other display text (a label, an
	// agent's name) may also hold the zero-width joiner and non-joiner,
	// because emoji sequences and several scripts (Persian, Indic, Sinhala)
	// cannot be written without them, and nothing is identified by it.
	identifying bool
}

// displayText reports whether s may be shown to a person and stored as-is. It
// holds when s:
//   - is valid UTF-8 containing no U+FFFD (an invalid byte decodes to U+FFFD,
//     so one test covers both);
//   - contains no control (Cc: NUL, C0, DEL, C1) and no format (Cf: bidi
//     overrides and isolates, zero-width space, BOM, soft hyphen, tag
//     characters) code points, which can hide or reorder text. The two joiners,
//     U+200C and U+200D, are the one exception, and only for text that does not
//     identify anyone (rule.identifying is false);
//   - is already in Unicode Normalization Form C, so one visible name has one
//     spelling;
//   - is not blank (empty, or only whitespace) unless rule.allowEmpty permits
//     the empty string;
//   - is no longer than rule.max in rule.unit.
//
// WebAuthn section 5.4.3 asks relying parties to enforce the PRECIS Nickname
// profile (RFC 8266); this is its core, without the rewriting steps.
func displayText(s string, rule textRule) bool {
	// Cheap refusal before scanning: a valid string of max runes has at most
	// max*4 bytes, and a string of max bytes has at most max.
	byteLimit := rule.max
	if rule.unit == unitRunes {
		byteLimit = rule.max * maxRuneBytes
	}

	if len(s) > byteLimit {
		return false
	}

	if s == "" {
		return rule.allowEmpty
	}

	if !showable(s, rule.identifying) || !norm.NFC.IsNormalString(s) {
		return false
	}

	return rule.unit == unitBytes || utf8.RuneCountInString(s) <= rule.max
}

// Joiners are the format characters that text with no identifying role may
// hold: the zero-width non-joiner and joiner. They have no effect on direction
// or on what else is shown; they only change how neighbouring characters join.
const (
	zeroWidthNonJoiner = '\u200c'
	zeroWidthJoiner    = '\u200d'
)

// showable reports whether s has no U+FFFD (or invalid UTF-8), no Cc and no Cf
// code point (apart from the joiners, unless identifying), and at least one
// character that is neither whitespace nor a joiner, so a string of nothing but
// invisible characters is not a name.
func showable(s string, identifying bool) bool {
	visible := false

	for _, r := range s {
		joiner := !identifying && (r == zeroWidthNonJoiner || r == zeroWidthJoiner)

		if r == utf8.RuneError || (!joiner && unicode.In(r, unicode.Cc, unicode.Cf)) {
			return false
		}

		visible = visible || (!joiner && !unicode.IsSpace(r))
	}

	return visible
}

// decimalBase is the radix of decimal.
const decimalBase = 10

// decimal parses s as a canonical non-negative decimal integer in [lo, hi].
// Canonical means digits only: no sign, no space, no separators, no exponent
// and no leading zeros (so "0" is zero and "007" is refused). The digit count
// is capped at the digit count of hi before any arithmetic, so an overlong
// string is refused without being converted and the accumulation below cannot
// overflow. hi must not exceed MaxSafeInteger.
func decimal(s string, lo, hi int64) (int64, bool) {
	maxDigits := len(strconv.FormatInt(hi, 10))

	if s == "" || len(s) > maxDigits || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}

	var n int64

	for i := range len(s) {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}

		n = n*decimalBase + int64(c-'0')
	}

	if n < lo || n > hi {
		return 0, false
	}

	return n, true
}

// singleValue reads a query parameter that may appear at most once. It returns
// the value, whether the parameter was present, and whether the repetition
// rule held. An absent parameter (no values) is present=false so the caller
// can apply its default. Several values are refused rather than choosing one,
// because "first wins" and "last wins" differ between proxies and a request
// that means two things to two layers is a smuggling vector.
func singleValue(values []string) (string, bool, bool) {
	switch len(values) {
	case 0:
		return "", false, true
	case 1:
		return values[0], true, true
	default:
		return "", false, false
	}
}

// Layout of the canonical 8-4-4-4-12 text form: its length and the offsets of
// its four dashes.
const (
	uuidLen   = 36
	uuidDash1 = 8
	uuidDash2 = 13
	uuidDash3 = 18
	uuidDash4 = 23
)

// canonicalUUID reports whether s is a UUID in canonical text form: 36
// characters, lower-case hexadecimal, dashes exactly at offsets 8, 13, 18 and
// 23. It does not look at the version or variant nibbles.
func canonicalUUID(s string) bool {
	if len(s) != uuidLen {
		return false
	}

	for i := range len(s) {
		c := s[i]

		switch i {
		case uuidDash1, uuidDash2, uuidDash3, uuidDash4:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}

	return true
}

// isBase64URL reports whether c is in the base64url alphabet [A-Za-z0-9_-].
func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// base64URL reports whether every byte of s is in the base64url alphabet. It
// accepts the empty string; callers bound the length. Padding ('=') is not in
// the alphabet and is refused.
func base64URL(s string) bool {
	return onlyBytes(s, isBase64URL)
}

// onlyBytes reports whether every byte of s satisfies ok.
func onlyBytes(s string, ok func(byte) bool) bool {
	for i := range len(s) {
		if !ok(s[i]) {
			return false
		}
	}

	return true
}
