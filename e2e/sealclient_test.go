//go:build e2e

package e2e_test

// sealclient_test.go is the client half of sealed secrets. A credential that is
// not a session must send a publicKey with a create that returns a secret, and
// gets the secret back sealed to it. The tests of those routes were written
// when the response carried the token, so send plays the CLI: it adds a fresh
// publicKey to such a request, opens the sealed member of the response with its
// private key, and puts the plain token back where the test reads it. A test of
// the sealing itself sets request.noSeal and sees the wire.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"net/http"
	"regexp"
	"testing"
)

// sealedMembers are the routes that return a secret and the response member
// that carries it unsealed.
var sealedMembers = map[string]string{ //nolint:gochecknoglobals // a constant table
	pathAgent:      "token", //nolint:goconst // a JSON member, not the OAuth parameter
	pathInvitation: "code",  //nolint:goconst // a JSON member, not the OAuth parameter
}

// clientPair is the key pair a client makes for one request.
type clientPair struct {
	private hpke.PrivateKey
	public  string
}

func newClientPair(t *testing.T) clientPair {
	t.Helper()

	private, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	wire := append([]byte{1}, private.PublicKey().Bytes()...)

	return clientPair{private: private, public: base64.RawURLEncoding.EncodeToString(wire)}
}

// open is what a client does with the sealed member of a response.
func (c clientPair) open(t *testing.T, sealed string) string {
	t.Helper()

	raw, err := base64.RawURLEncoding.Strict().DecodeString(sealed)
	if err != nil || len(raw) < 1 || raw[0] != 1 {
		t.Fatalf("sealed %q is not a suite byte and a canonical base64url: %v", sealed, err)
	}

	plain, err := hpke.Open(c.private, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte("authsu secret v1"), raw[1:])
	if err != nil {
		t.Fatalf("open %q: %v", sealed, err)
	}

	return string(plain)
}

// sealsFor reports whether send must act as the CLI for r: a create on a route
// that returns a secret, made by a key, with a JSON object body that names no
// publicKey, and not one a test wants to see unsealed.
func (r request) sealsFor() (string, bool) {
	member, ok := sealedMembers[r.path]

	return member, ok && !r.noSeal && r.bearer != "" && r.method == http.MethodPost &&
		bytes.HasPrefix(r.body, []byte("{")) && !bytes.Contains(r.body, []byte(`"publicKey"`))
}

// withPublicKey adds the publicKey member to the front of a JSON object body.
func (r request) withPublicKey(key string) request {
	member := []byte(`"publicKey":"` + key + `"`)

	if bytes.Equal(r.body, []byte("{}")) {
		r.body = append(append([]byte("{"), member...), '}')

		return r
	}

	r.body = append(append([]byte("{"), member...), append([]byte(","), r.body[1:]...)...)

	return r
}

var sealedMember = regexp.MustCompile(`"sealed":"([A-Za-z0-9_-]+)"`)

// opened is the reply with its sealed member replaced by the plain one, so a
// test reads it as it did before secrets were sealed.
func (c clientPair) opened(t *testing.T, member string, got reply) reply {
	t.Helper()

	got.body = sealedMember.ReplaceAllStringFunc(got.body, func(found string) string {
		return `"` + member + `":"` + c.open(t, sealedMember.FindStringSubmatch(found)[1]) + `"`
	})

	return got
}
