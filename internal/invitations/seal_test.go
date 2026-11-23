//nolint:cyclop // one test per credential holds a subtest per outcome
package invitations_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/seal"
	"github.com/susu-dot-dev/authsu/internal/secret"
)

var errSealer = errors.New("the sealer is broken")

// clientPair is the key pair a client makes for one request.
type clientPair struct {
	private hpke.PrivateKey
	// public is the publicKey member's value.
	public string
}

func newClientPair(t *testing.T) clientPair {
	t.Helper()

	private, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	wire := append([]byte{seal.SuiteX25519}, private.PublicKey().Bytes()...)

	return clientPair{private: private, public: base64.RawURLEncoding.EncodeToString(wire)}
}

// open is what a client does with the sealed member of a response.
func (c clientPair) open(t *testing.T, sealed string) string {
	t.Helper()

	raw, err := base64.RawURLEncoding.Strict().DecodeString(sealed)
	if err != nil {
		t.Fatalf("sealed %q: %v", sealed, err)
	}

	plain, err := hpke.Open(c.private, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte("authsu secret v1"), raw[1:])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	return string(plain)
}

// sealBody is a member create carrying publicKey as JSON.
func sealBody(publicKey string) string {
	return `{"type":"member","numInvites":1,"publicKey":` + strconv.Quote(publicKey) + `}`
}

const plainBody = `{"type":"member","numInvites":1}`

// callers send a create with body as an admin session or as an admin's key.
func callers() map[string]func(h *harness, body string) *httptest.ResponseRecorder {
	return map[string]func(h *harness, body string) *httptest.ResponseRecorder{
		"a session": func(h *harness, body string) *httptest.ResponseRecorder {
			return h.asAdmin(http.MethodPost, collectionPath, body)
		},
		"a key": func(h *harness, body string) *httptest.ResponseRecorder {
			return h.do(request{
				method: http.MethodPost, target: collectionPath, body: body,
				authorization: h.adminKey(scope.List{string(scope.InvitationCreate)}),
			})
		},
	}
}

// TestCreateSealsTheTokenToThePublicKey: the response carries the token sealed
// to the request's key and nowhere else. The client opens it and gets the token
// whose hash was stored, and the response holds no trace of it in plaintext.
func TestCreateSealsTheTokenToThePublicKey(t *testing.T) {
	t.Parallel()

	for name, send := range callers() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			pair := newClientPair(t)
			rec := send(h, sealBody(pair.public))

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body)
			}

			// The token the routes generated from the harness's entropy.
			token := codeOf(sequence(0, secret.BodyBytes))
			if strings.Contains(rec.Body.String(), token) || strings.Contains(rec.Body.String(), `"code"`) {
				t.Errorf("the response holds the token or a code member: %s", rec.Body)
			}

			got := decode[wireCreated](t, rec)
			if got.Code != "" || got.Sealed == "" {
				t.Fatalf("code %q and sealed %q, want a sealed token only", got.Code, got.Sealed)
			}

			if opened := pair.open(t, got.Sealed); opened != token {
				t.Errorf("opened %q, want %q", opened, token)
			}

			sum := sha256.Sum256([]byte(token))
			if stored := h.store.calls[len(h.store.calls)-1]; !bytes.Equal(stored.created.TokenHash, sum[:]) {
				t.Errorf("the stored hash is not the sealed token's")
			}

			if len(h.sealCalls) != 1 || !bytes.Equal(h.sealCalls[0].recipient[1:], pair.private.PublicKey().Bytes()) {
				t.Errorf("sealCalls = %+v, want one to the request's key", h.sealCalls)
			}
		})
	}
}

// TestCreateNeedsAPublicKeyExceptForASession: only a session may be sent the
// token as it is. A key that sends none, or null, is refused before a token is
// generated or anything is written.
func TestCreateNeedsAPublicKeyExceptForASession(t *testing.T) {
	t.Parallel()

	want := `{"error":{"code":"public_key_required","message":` +
		`"publicKey is required: a secret is only sent to this credential sealed to a key"}}` + "\n"

	for name, send := range callers() {
		for _, body := range []string{plainBody, `{"type":"member","numInvites":1,"publicKey":null}`} {
			t.Run(name+" "+body, func(t *testing.T) {
				t.Parallel()

				h := newHarness(t)
				rec := send(h, body)

				if name == "a session" {
					got := decode[wireCreated](t, rec)
					if rec.Code != http.StatusCreated || got.Code != codeOf(sequence(0, secret.BodyBytes)) || got.Sealed != "" ||
						len(h.sealCalls) != 0 {
						t.Errorf("status %d, %s: want the plain code and no sealing", rec.Code, rec.Body)
					}

					return
				}

				if rec.Code != http.StatusBadRequest || rec.Body.String() != want {
					t.Errorf("status %d, body %q, want 400 %q", rec.Code, rec.Body, want)
				}

				if len(h.store.calls) != 0 || len(h.sealCalls) != 0 || h.entropy.taken != 0 {
					t.Errorf("store %v, seals %d, entropy reads %d, want none", h.opsCalled(), len(h.sealCalls), h.entropy.taken)
				}
			})
		}
	}
}

// TestCreateRefusesAPublicKeyThatIsNotOne: a key of the wrong shape is refused
// at the parse, whatever the credential, before a token is generated.
func TestCreateRefusesAPublicKeyThatIsNotOne(t *testing.T) {
	t.Parallel()

	want := `{"error":{"code":"invalid_public_key","message":"publicKey must be exactly 44 base64url characters: ` +
		`the suite byte 1 and a 32-byte X25519 public key"}}` + "\n"
	good := newClientPair(t).public

	for name, send := range callers() {
		for key, bad := range map[string]string{
			"empty":         "",
			"short":         good[:43],
			"long":          good + "A",
			"another suite": base64.RawURLEncoding.EncodeToString(append([]byte{2}, bytes.Repeat([]byte{1}, 32)...)),
			"text":          "not a key",
		} {
			t.Run(name+" "+key, func(t *testing.T) {
				t.Parallel()

				h := newHarness(t)
				rec := send(h, sealBody(bad))

				if rec.Code != http.StatusBadRequest || rec.Body.String() != want {
					t.Errorf("status %d, body %q, want 400 %q", rec.Code, rec.Body, want)
				}

				if len(h.store.calls) != 0 || len(h.sealCalls) != 0 || h.entropy.taken != 0 {
					t.Errorf("store %v, seals %d, entropy reads %d, want none", h.opsCalled(), len(h.sealCalls), h.entropy.taken)
				}
			})
		}
	}
}

// TestCreateWritesNothingForAKeyItCannotSealTo: a point of low order has the
// shape of a key and fails in the sealer, as does a sealer that is broken. The
// seal comes before the write, so nothing was written.
func TestCreateWritesNothingForAKeyItCannotSealTo(t *testing.T) {
	t.Parallel()

	want := `{"error":{"code":"invalid_public_key","message":"publicKey cannot be sealed to"}}` + "\n"
	zero := base64.RawURLEncoding.EncodeToString(append([]byte{seal.SuiteX25519}, make([]byte, seal.KeyLen)...))

	for name, send := range callers() {
		for what, setup := range map[string]struct {
			key string
			err error
		}{
			"a low-order key":  {key: zero, err: nil},
			"a failing sealer": {key: newClientPair(t).public, err: errSealer},
		} {
			t.Run(name+" "+what, func(t *testing.T) {
				t.Parallel()

				h := newHarness(t)
				h.sealErr = setup.err
				rec := send(h, sealBody(setup.key))

				if rec.Code != http.StatusBadRequest || rec.Body.String() != want {
					t.Errorf("status %d, body %q, want 400 %q", rec.Code, rec.Body, want)
				}

				if len(h.store.calls) != 0 || len(h.sealCalls) != 1 {
					t.Errorf("store %v, seals %d, want no write after one seal", h.opsCalled(), len(h.sealCalls))
				}

				if setup.err != nil && (len(h.logged) != 1 || !errors.Is(h.logged[0], setup.err)) {
					t.Errorf("logged %v, want one failure caused by %v", h.logged, setup.err)
				}
			})
		}
	}
}
