package seal_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/seal"
)

// openInfo is the info the package binds a sealed secret to. It is repeated
// here on purpose: a change to it breaks every client that holds a key, so the
// test must fail when it changes.
const openInfo = "authsu secret v1"

// keyPair is a recipient as a client makes one.
type keyPair struct {
	private   hpke.PrivateKey
	recipient []byte
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()

	private, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return keyPair{private: private, recipient: append([]byte{seal.SuiteX25519}, private.PublicKey().Bytes()...)}
}

// open is what a client does with a sealed secret.
func open(t *testing.T, private hpke.PrivateKey, sealed string) string {
	t.Helper()

	raw, err := base64.RawURLEncoding.Strict().DecodeString(sealed)
	if err != nil {
		t.Fatalf("sealed %q is not canonical base64url: %v", sealed, err)
	}

	if raw[0] != seal.SuiteX25519 {
		t.Fatalf("suite byte = %d, want %d", raw[0], seal.SuiteX25519)
	}

	plain, err := hpke.Open(private, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(openInfo), raw[1:])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	return string(plain)
}

func TestSealRoundTrips(t *testing.T) {
	t.Parallel()

	for name, secret := range map[string]string{
		"an API key": "susu_key_" + string(bytes.Repeat([]byte("A"), 43)),
		"empty":      "",
		"non ASCII":  "h\u00e9llo \u4e16\u754c",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pair := newKeyPair(t)

			sealed, err := seal.Seal(pair.recipient, secret)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			if got := open(t, pair.private, sealed); got != secret {
				t.Errorf("opened %q, want %q", got, secret)
			}

			// suite byte, ephemeral key, the secret and the 16-byte tag.
			raw, _ := base64.RawURLEncoding.DecodeString(sealed)
			if want := 1 + seal.KeyLen + len(secret) + 16; len(raw) != want {
				t.Errorf("sealed is %d bytes, want %d", len(raw), want)
			}
		})
	}
}

// TestSealIsFreshAndPrivate pins what makes a sealed secret safe to log: it
// differs on every call, never contains the secret, and is not opened by a key
// it was not sealed to.
func TestSealIsFreshAndPrivate(t *testing.T) {
	t.Parallel()

	pair := newKeyPair(t)
	other := newKeyPair(t)

	first, err := seal.Seal(pair.recipient, "the-secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	second, err := seal.Seal(pair.recipient, "the-secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if first == second {
		t.Error("two seals of one secret to one key are equal")
	}

	raw, _ := base64.RawURLEncoding.DecodeString(first)
	if bytes.Contains(raw, []byte("the-secret")) {
		t.Error("the sealed bytes contain the secret")
	}

	_, err = hpke.Open(other.private, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(openInfo), raw[1:])
	if err == nil {
		t.Error("another key opened the secret")
	}

	_, err = hpke.Open(pair.private, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte("another use"), raw[1:])
	if err == nil {
		t.Error("the secret opened under a different info")
	}
}

func TestSealRefusesARecipientItCannotSealTo(t *testing.T) {
	t.Parallel()

	good := newKeyPair(t).recipient

	cases := map[string][]byte{
		"nil":                    nil,
		"empty":                  {},
		"only the suite byte":    {seal.SuiteX25519},
		"a short key":            good[:seal.RecipientLen-1],
		"a long key":             append(bytes.Clone(good), 0),
		"no suite byte":          good[1:],
		"suite zero":             append([]byte{0}, good[1:]...),
		"an unknown suite":       append([]byte{2}, good[1:]...),
		"the all-zero key":       append([]byte{seal.SuiteX25519}, make([]byte, seal.KeyLen)...),
		"the low-order point 1":  append([]byte{seal.SuiteX25519, 1}, make([]byte, seal.KeyLen-1)...),
		"the low-order point 2":  lowOrderTwo(),
		"a key of the wrong len": append([]byte{seal.SuiteX25519}, make([]byte, 31)...),
	}

	for name, recipient := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sealed, err := seal.Seal(recipient, "secret")
			if !errors.Is(err, seal.ErrRecipient) {
				t.Errorf("error = %v, want seal.ErrRecipient", err)
			}

			if sealed != "" {
				t.Errorf("sealed = %q, want nothing", sealed)
			}
		})
	}
}

// lowOrderTwo is the point of order 2 of Curve25519 (u = 32560625091655743179598362635611063129400811572784880556002338
// 7167927233504), with a suite byte.
func lowOrderTwo() []byte {
	key := []byte{
		0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
	}

	return append([]byte{seal.SuiteX25519}, key...)
}
