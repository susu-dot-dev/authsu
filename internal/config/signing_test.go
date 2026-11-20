package config_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/config"
)

// TestLoadSigningKeyAccepts: the keys that are accepted, at both ends of the
// size range.
func TestLoadSigningKeyAccepts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		value    string
		wantBits int
	}{
		"2048 bits, the smallest": {value: fixtureKey2048, wantBits: config.MinSigningKeyBits},
		"4096 bits, the largest":  {value: fixtureKey4096, wantBits: config.MaxSigningKeyBits},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := config.LoadSigningKey(signingEnv(tt.value))
			if err != nil {
				t.Fatalf("LoadSigningKey: %v", err)
			}

			private := key.Private()
			if private == nil || private.N.BitLen() != tt.wantBits || private.E != config.SigningKeyExponent {
				t.Fatalf("key = %+v", private)
			}

			// It is usable: it signs, and the public half verifies.
			digest := sha256.Sum256([]byte("message"))

			signature, err := rsa.SignPKCS1v15(nil, private, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			err = rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, digest[:], signature)
			if err != nil {
				t.Errorf("verify: %v", err)
			}

			// ParseSigningKey is the same parse for a value already read.
			again, err := config.ParseSigningKey(tt.value)
			if err != nil || again.KeyID() != key.KeyID() {
				t.Errorf("ParseSigningKey = %v, %v", again.KeyID(), err)
			}
		})
	}
}

// TestLoadSigningKeyReadsTheNamedSecret: only OAUTH_SIGNING_KEY is read, so the
// root secret can never be taken for a key.
func TestLoadSigningKeyReadsTheNamedSecret(t *testing.T) {
	t.Parallel()

	if config.SecretOAuthSigningKey != "OAUTH_SIGNING_KEY" {
		t.Errorf("SecretOAuthSigningKey = %q", config.SecretOAuthSigningKey)
	}

	var asked []string

	_, err := config.LoadSigningKey(func(name string) string {
		asked = append(asked, name)

		return fixtureKey2048
	})
	if err != nil || len(asked) != 1 || asked[0] != "OAUTH_SIGNING_KEY" {
		t.Errorf("err = %v, asked = %v, want one read of OAUTH_SIGNING_KEY", err, asked)
	}
}

// TestSigningKeyIsNotDerivedFromTheRootSecret: the key is only what its own
// secret says. A deployment with every other setting, the root secret included,
// has no signing key until it is given one.
func TestSigningKeyIsNotDerivedFromTheRootSecret(t *testing.T) {
	t.Parallel()

	_, err := config.Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	_, err = config.LoadSigningKey(env(nil))
	if !errors.Is(err, config.ErrSigningKey) {
		t.Errorf("err = %v, want ErrSigningKey with only the root secret set", err)
	}
}

// TestLoadSigningKeyRefuses: every way a value can be wrong is ErrSigningKey,
// for the reason that check gives, and returns no key and none of the value.
func TestLoadSigningKeyRefuses(t *testing.T) {
	t.Parallel()

	for name, tt := range refusedSigningKeys(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := config.LoadSigningKey(signingEnv(tt.value))
			if !errors.Is(err, config.ErrSigningKey) {
				t.Fatalf("err = %v, want ErrSigningKey", err)
			}

			if !strings.Contains(err.Error(), tt.reason) {
				t.Errorf("err = %q, want the reason %q", err, tt.reason)
			}

			if key.Private() != nil || key.KeyID() != "" {
				t.Errorf("a refused value returned a key: %+v", key)
			}

			// The reason never carries the value, however much of it there was.
			if len(tt.value) > 20 && strings.Contains(err.Error(), tt.value[:20]) {
				t.Errorf("error %q includes the value", err)
			}
		})
	}
}

// TestSigningKeyKeyID: the key ID is base64url of the first eight bytes of the
// SHA-256 of the modulus.
func TestSigningKeyKeyID(t *testing.T) {
	t.Parallel()

	key, err := config.ParseSigningKey(fixtureKey2048)
	if err != nil {
		t.Fatalf("ParseSigningKey: %v", err)
	}

	// Independently of the package: parse the DER here, and hash the modulus.
	digest := sha256.Sum256(fixtureRSA(t, fixtureKey2048).N.Bytes())

	wantKID := base64.RawURLEncoding.EncodeToString(digest[:8])
	if key.KeyID() != wantKID || key.KeyID() != fixtureKey2048KeyID {
		t.Errorf("KeyID = %q, want %q (and %q)", key.KeyID(), wantKID, fixtureKey2048KeyID)
	}
}

// TestSigningKeyJWK: n and e are the unsigned big-endian values, and the wire
// form has exactly the public members.
func TestSigningKeyJWK(t *testing.T) {
	t.Parallel()

	key, err := config.ParseSigningKey(fixtureKey2048)
	if err != nil {
		t.Fatalf("ParseSigningKey: %v", err)
	}

	jwk := key.JWK()

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("n is not base64url: %v", err)
	}

	// n is the modulus with no leading zero byte, so it is exactly 256 bytes for
	// 2048 bits with the top bit set.
	modulus := fixtureRSA(t, fixtureKey2048).N
	if len(nBytes) != 256 || nBytes[0] < 0x80 || new(big.Int).SetBytes(nBytes).Cmp(modulus) != 0 {
		t.Errorf("n = %x, want the modulus", nBytes)
	}

	want := config.JWK{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: fixtureKey2048KeyID, N: jwk.N, E: "AQAB"}
	if jwk != want {
		t.Errorf("JWK = %+v, want %+v", jwk, want)
	}
}

// TestSigningKeyJWKWireForm: the JSON has exactly the public members.
func TestSigningKeyJWKWireForm(t *testing.T) {
	t.Parallel()

	key, err := config.ParseSigningKey(fixtureKey2048)
	if err != nil {
		t.Fatalf("ParseSigningKey: %v", err)
	}

	jwk := key.JWK()

	encoded, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var members map[string]string

	err = json.Unmarshal(encoded, &members)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	wantMembers := map[string]string{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": fixtureKey2048KeyID, "n": jwk.N, "e": "AQAB",
	}

	if len(members) != len(wantMembers) {
		t.Errorf("members = %v, want %v", members, wantMembers)
	}

	for member, value := range wantMembers {
		if members[member] != value {
			t.Errorf("member %q = %q, want %q", member, members[member], value)
		}
	}
}

// TestSigningKeyIdentityIsPerKey: a different key has a different ID and
// modulus, and the same key loaded twice has the same ones.
func TestSigningKeyIdentityIsPerKey(t *testing.T) {
	t.Parallel()

	first, err := config.ParseSigningKey(fixtureKey2048)
	if err != nil {
		t.Fatalf("ParseSigningKey: %v", err)
	}

	second, err := config.ParseSigningKey(fixtureKey4096)
	if err != nil {
		t.Fatalf("ParseSigningKey: %v", err)
	}

	again, err := config.ParseSigningKey(fixtureKey2048)
	if err != nil {
		t.Fatalf("ParseSigningKey: %v", err)
	}

	if first.KeyID() == second.KeyID() || first.JWK().N == second.JWK().N {
		t.Error("two keys share an identity")
	}

	if first.KeyID() != again.KeyID() || first.JWK() != again.JWK() {
		t.Error("one key has two identities")
	}
}
