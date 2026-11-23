//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/seal"
)

// publicKeyCases is the table of ParsePublicKey.
func publicKeyCases() []parseCase {
	body := bytes.Repeat([]byte{0x2a}, seal.KeyLen)
	good := base64.RawURLEncoding.EncodeToString(append([]byte{seal.SuiteX25519}, body...))
	zero := base64.RawURLEncoding.EncodeToString(append([]byte{seal.SuiteX25519}, make([]byte, seal.KeyLen)...))
	wrongSuite := func(suite byte) string {
		return base64.RawURLEncoding.EncodeToString(append([]byte{suite}, bytes.Repeat([]byte{0x2a}, seal.KeyLen)...))
	}

	return []parseCase{
		{"a key", good, true},
		{"the all-zero key, whose shape is fine", zero, true},
		{"a key of characters from both ends of the alphabet", "AQ" + strings.Repeat("-_", 21), true},

		{"empty", "", false},
		{"one character", "A", false},
		{"43 characters", good[:43], false},
		{"45 characters", good + "A", false},
		{"two keys", good + good, false},
		{"suite 0", wrongSuite(0), false},
		{"suite 2", wrongSuite(2), false},
		{"suite 255", wrongSuite(255), false},
		{"a bare 32-byte key", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, seal.KeyLen)), false},
		{"padding replacing the last character", good[:43] + "=", false},
		{"the standard alphabet, +", good[:10] + "+" + good[11:], false},
		{"the standard alphabet, /", good[:10] + "/" + good[11:], false},
		{"a leading space", " " + good[1:], false},
		{"a trailing space", good + " ", false},
		{"a trailing newline", good + "\n", false},
		{"a newline inside, which a decoder skips", good[:20] + "\n" + good[20:], false},
		{"a carriage return inside", good[:20] + "\r" + good[21:], false},
		{"NUL", good[:20] + "\x00" + good[21:], false},
		{"e acute, 44 bytes", good[:20] + "\u00e9" + good[22:], false},
		{"e acute, 44 characters", good[:20] + "\u00e9" + good[21:], false},
		{"invalid UTF-8", good[:20] + "\xff" + good[21:], false},
		{"a megabyte", strings.Repeat("A", 1<<20), false},
	}
}

func TestParsePublicKey(t *testing.T) {
	t.Parallel()

	parse := strAdapter(input.ParsePublicKey, input.PublicKey.String)

	runStringTable(t, publicKeyCases(), parse, input.CodeInvalidPublicKey)
}

// TestPublicKeyEncodingIsFixed pins that the wire length is exactly what 33
// bytes encode to, so no key has a padded or non-canonical spelling.
func TestPublicKeyEncodingIsFixed(t *testing.T) {
	t.Parallel()

	if got := base64.RawURLEncoding.EncodedLen(seal.RecipientLen); got != input.PublicKeyLen {
		t.Errorf("EncodedLen(%d) = %d, want %d", seal.RecipientLen, got, input.PublicKeyLen)
	}
}

func TestPublicKeyRecipient(t *testing.T) {
	t.Parallel()

	var none input.PublicKey

	if none.Present() || none.Recipient() != nil || none.String() != "" {
		t.Errorf("the zero value is %v %v %q, want no key", none.Present(), none.Recipient(), none.String())
	}

	wire := append([]byte{seal.SuiteX25519}, bytes.Repeat([]byte{7}, seal.KeyLen)...)

	key, err := input.ParsePublicKey(base64.RawURLEncoding.EncodeToString(wire))
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}

	if !key.Present() || !bytes.Equal(key.Recipient(), wire) {
		t.Errorf("Present = %v, Recipient = %x, want %x", key.Present(), key.Recipient(), wire)
	}
}

func FuzzParsePublicKey(f *testing.F) {
	fuzzInvariants(f, seedsOf(publicKeyCases()), input.ParsePublicKey, input.PublicKey.String,
		input.CodeInvalidPublicKey, func(t *testing.T, raw string) {
			t.Helper()

			decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
			if err != nil || len(decoded) != seal.RecipientLen || decoded[0] != seal.SuiteX25519 ||
				base64.RawURLEncoding.EncodeToString(decoded) != raw {
				t.Fatalf("%q is not the canonical base64url of a suite byte and a key: %v", raw, err)
			}
		})
}
