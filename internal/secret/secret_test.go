//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package secret_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/secret"
)

type taggedPrefix struct {
	tag    secret.Tag
	prefix string
}

func allTags() []taggedPrefix {
	return []taggedPrefix{
		{secret.TagInvitation, "susu_inv_"},
		{secret.TagSession, "susu_ses_"},
		{secret.TagAPIKey, "susu_key_"},
		{secret.TagOAuthCode, "susu_code_"},
		{secret.TagOAuthRefresh, "susu_rt_"},
		{secret.TagOAuthAccess, "susu_at_"},
	}
}

func TestPrefix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		tag  secret.Tag
		want string
	}{
		{secret.TagInvitation, "susu_inv_"},
		{secret.TagSession, "susu_ses_"},
		{secret.TagAPIKey, "susu_key_"},
		{secret.TagOAuthCode, "susu_code_"},
		{secret.TagOAuthRefresh, "susu_rt_"},
		{secret.TagOAuthAccess, "susu_at_"},
		{"x", "susu_x_"},
		{"", "susu__"},
	}

	for _, tc := range cases {
		t.Run(string(tc.tag), func(t *testing.T) {
			t.Parallel()

			if got := secret.Prefix(tc.tag); got != tc.want {
				t.Errorf("Prefix(%q) = %q, want %q", tc.tag, got, tc.want)
			}
		})
	}
}

func TestSizes(t *testing.T) {
	t.Parallel()

	if secret.BodyBytes != 32 {
		t.Errorf("BodyBytes = %d, want 32", secret.BodyBytes)
	}

	if got := base64.RawURLEncoding.EncodedLen(secret.BodyBytes); got != secret.BodyLen {
		t.Errorf("BodyLen = %d, but %d bytes encode to %d characters", secret.BodyLen, secret.BodyBytes, got)
	}
}

func TestGenerateShape(t *testing.T) {
	t.Parallel()

	for _, tc := range allTags() {
		t.Run(string(tc.tag), func(t *testing.T) {
			t.Parallel()

			token, err := secret.Generate(&countingReader{}, tc.tag)
			if err != nil {
				t.Fatal(err)
			}

			body, ok := strings.CutPrefix(token, tc.prefix)
			if !ok {
				t.Fatalf("token %q does not start with %q", token, tc.prefix)
			}

			if len(body) != secret.BodyLen {
				t.Errorf("body length = %d, want %d", len(body), secret.BodyLen)
			}

			for i := range len(body) {
				c := body[i]
				if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", rune(c)) {
					t.Errorf("body byte %d = %q is outside the base64url alphabet", i, c)
				}
			}

			decoded, err := base64.RawURLEncoding.Strict().DecodeString(body)
			if err != nil {
				t.Fatalf("body is not canonical base64url: %v", err)
			}

			want := make([]byte, secret.BodyBytes)
			for i := range want {
				want[i] = byte(i)
			}

			if !bytes.Equal(decoded, want) {
				t.Errorf("body decodes to %x, want the reader's first %d bytes %x", decoded, secret.BodyBytes, want)
			}
		})
	}
}

func TestGenerateReadsExactlyBodyBytes(t *testing.T) {
	t.Parallel()

	reader := &countingReader{}

	_, err := secret.Generate(reader, secret.TagSession)
	if err != nil {
		t.Fatal(err)
	}

	if got := reader.total(); got != secret.BodyBytes {
		t.Errorf("read %d bytes, want exactly %d", got, secret.BodyBytes)
	}
}

func TestGenerateReaderFailures(t *testing.T) {
	t.Parallel()

	full := bytes.Repeat([]byte{7}, secret.BodyBytes)

	cases := []struct {
		name    string
		reader  io.Reader
		wantErr error
	}{
		{"empty reader", &failingReader{}, io.EOF},
		{"failing from the start", &failingReader{err: errBoom}, errBoom},
		{"one byte short", &failingReader{data: full[:secret.BodyBytes-1]}, io.ErrUnexpectedEOF},
		{"one byte then end", &failingReader{data: full[:1]}, io.ErrUnexpectedEOF},
		{"one byte short then failing", &failingReader{data: full[:secret.BodyBytes-1], err: errBoom}, errBoom},
		{"short slice reader", bytes.NewReader(full[:10]), io.ErrUnexpectedEOF},
		{"empty slice reader", bytes.NewReader(nil), io.EOF},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token, err := secret.Generate(tc.reader, secret.TagAPIKey)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want one wrapping %v", err, tc.wantErr)
			}

			if token != "" {
				t.Errorf("a failed Generate returned the token %q", token)
			}
		})
	}
}

// TestGenerateAcceptsAnExactReader: a reader holding exactly BodyBytes bytes,
// delivered a byte at a time, is enough. All-ones input encodes to 42 "_"
// characters and a last one of 0b111100 ("8"): 4 data bits, 2 zero bits.
func TestGenerateAcceptsAnExactReader(t *testing.T) {
	t.Parallel()

	token, err := secret.Generate(&failingReader{data: bytes.Repeat([]byte{0xff}, secret.BodyBytes)}, secret.TagInvitation)
	if err != nil {
		t.Fatal(err)
	}

	if want := "susu_inv_" + strings.Repeat("_", secret.BodyLen-1) + "8"; token != want {
		t.Errorf("token = %q, want %q", token, want)
	}
}

func TestGenerateDiffers(t *testing.T) {
	t.Parallel()

	for _, tc := range allTags() {
		t.Run(string(tc.tag), func(t *testing.T) {
			t.Parallel()

			first, err := secret.Generate(rand.Reader, tc.tag)
			if err != nil {
				t.Fatal(err)
			}

			second, err := secret.Generate(rand.Reader, tc.tag)
			if err != nil {
				t.Fatal(err)
			}

			if first == second {
				t.Errorf("two tokens are equal: %q", first)
			}
		})
	}
}

func TestHash(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"prefix only", "susu_inv_"},
		{"a token", "susu_ses_" + strings.Repeat("A", secret.BodyLen)},
		{"not a token at all", "abc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := sha256.Sum256([]byte(tc.token))
			if got := secret.Hash(tc.token); got != want {
				t.Errorf("Hash(%q) = %x, want %x", tc.token, got, want)
			}
		})
	}
}

func TestHashCoversThePrefix(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("A", secret.BodyLen)
	seen := map[[sha256.Size]byte]secret.Tag{}

	for _, tc := range allTags() {
		hash := secret.Hash(secret.Prefix(tc.tag) + body)

		if other, dup := seen[hash]; dup {
			t.Errorf("tags %q and %q give the same hash for one body", other, tc.tag)
		}

		seen[hash] = tc.tag

		if hash == secret.Hash(body) {
			t.Errorf("tag %q: the hash ignores the prefix", tc.tag)
		}
	}
}

// TestNoPrefixStartsAnother: a reader that expects one kind refuses every other
// by its prefix, which only holds if no kind's prefix begins with another's.
func TestNoPrefixStartsAnother(t *testing.T) {
	t.Parallel()

	for _, first := range allTags() {
		for _, second := range allTags() {
			if first.tag != second.tag && strings.HasPrefix(first.prefix, second.prefix) {
				t.Errorf("%q starts with %q", first.prefix, second.prefix)
			}
		}
	}
}
