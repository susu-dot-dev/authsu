//nolint:cyclop // one test of the sealer holds a subtest per outcome
package auth_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/seal"
)

var errSeal = errors.New("the sealer failed")

// wireKey is a public key as a client spells it.
func wireKey() string {
	return base64.RawURLEncoding.EncodeToString(append([]byte{seal.SuiteX25519}, bytes.Repeat([]byte{9}, seal.KeyLen)...))
}

func TestRecipient(t *testing.T) {
	t.Parallel()

	key := wireKey()
	bad := "not a key"

	cases := []struct {
		name string
		kind string
		raw  *string
		// code is the refusal's code, or "" when a recipient is returned.
		code    string
		present bool
	}{
		{"a session without a key is sent plaintext", auth.KindSession, nil, "", false},
		{"a session with a key is sealed", auth.KindSession, &key, "", true},
		{"an API key with a key is sealed", auth.KindAPIKey, &key, "", true},
		{"an API key without a key is refused", auth.KindAPIKey, nil, auth.CodePublicKeyRequired, false},
		{"a session with a bad key is refused", auth.KindSession, &bad, input.CodeInvalidPublicKey, false},
		{"an API key with a bad key is refused", auth.KindAPIKey, &bad, input.CodeInvalidPublicKey, false},
		{"a credential of no kind is treated as a key", "", nil, auth.CodePublicKeyRequired, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := auth.Recipient(auth.Principal{Kind: tc.kind}, tc.raw).Get()

			if tc.code != "" {
				failure, ok := errors.AsType[*apierr.Error](err)
				if !ok || failure.Code != tc.code || failure.Kind != apierr.BadRequest {
					t.Fatalf("error = %v, want a 400 with code %q", err, tc.code)
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			if got.Present() != tc.present {
				t.Errorf("Present = %v, want %v", got.Present(), tc.present)
			}
		})
	}
}

func TestSealTo(t *testing.T) {
	t.Parallel()

	key, err := input.ParsePublicKey(wireKey())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}

	t.Run("no recipient sends the secret as it is", func(t *testing.T) {
		t.Parallel()

		calls := 0
		fake := func([]byte, string) (string, error) { calls++; return "", errSeal }

		got, err := auth.SealTo(fake, input.PublicKey{}, "secret").Get()
		if err != nil || got != "" || calls != 0 {
			t.Errorf("got %q, %v after %d calls, want \"\" and no call", got, err, calls)
		}
	})

	t.Run("a recipient is sealed to", func(t *testing.T) {
		t.Parallel()

		var gotRecipient []byte

		var gotPlain string

		fake := func(recipient []byte, plain string) (string, error) {
			gotRecipient, gotPlain = recipient, plain

			return "sealed!", nil
		}

		got, err := auth.SealTo(fake, key, "secret").Get()
		if err != nil || got != "sealed!" {
			t.Fatalf("got %q, %v, want sealed!", got, err)
		}

		if !bytes.Equal(gotRecipient, key.Recipient()) || gotPlain != "secret" {
			t.Errorf("sealer got %x and %q", gotRecipient, gotPlain)
		}
	})

	t.Run("a sealer that fails is the client's 400 and keeps its cause", func(t *testing.T) {
		t.Parallel()

		fake := func([]byte, string) (string, error) { return "", errSeal }

		_, err := auth.SealTo(fake, key, "secret").Get()

		failure, ok := errors.AsType[*apierr.Error](err)
		if !ok || failure.Kind != apierr.BadRequest || failure.Code != input.CodeInvalidPublicKey {
			t.Fatalf("error = %v, want a 400 invalid_public_key", err)
		}

		if !errors.Is(err, errSeal) {
			t.Errorf("the cause was lost: %v", err)
		}
	})
}
