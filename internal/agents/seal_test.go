//nolint:cyclop,goconst // one test per credential holds a subtest per outcome, and case names repeat on purpose
package agents_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/seal"
)

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

func publicKeyBody(public string) string {
	return `{"name":"assistant","publicKey":` + marshalString(public) + `}`
}

func marshalString(s string) string { return strconv.Quote(s) }

// creators are the callers of a create, each sending body and returning the
// response. An agent's key is the creator seeded as agentA1, which holds
// agent:create.
func creators() map[string]func(rg *rig, body string) *httptest.ResponseRecorder {
	creator := scope.List{bundleAgent, agentCreate}

	return map[string]func(rg *rig, body string) *httptest.ResponseRecorder{
		"a session": func(rg *rig, body string) *httptest.ResponseRecorder {
			return rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, body)
		},
		"a user's key": func(rg *rig, body string) *httptest.ResponseRecorder {
			header := rg.signInKey(keySpec{owner: userA, role: roleMember, scope: scope.List{bundleUser}})

			return rg.serve(request{method: http.MethodPost, target: collection, body: body, authorization: header})
		},
		"an agent's key": func(rg *rig, body string) *httptest.ResponseRecorder {
			rg.seed(userA, stored(agentA1, "creator", 1, nil))
			rg.store.rows[0].agent.Scopes = creator.JSON()

			return rg.serve(request{
				method: http.MethodPost, target: collection, body: body, authorization: agentCaller(rg, creator, creator),
			})
		},
	}
}

// TestCreateSealsTheFirstKeyToThePublicKey is the point of the member: the
// response carries the token sealed to the request's key and nowhere else, for
// every kind of credential. The client opens it and gets the token whose hash
// was written, and the response holds no trace of the token in plaintext.
func TestCreateSealsTheFirstKeyToThePublicKey(t *testing.T) {
	t.Parallel()

	for name, send := range creators() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			pair := newClientPair(t)
			rec := send(rg, publicKeyBody(pair.public))

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}

			var response agents.CreateResponse

			err := json.Unmarshal(rec.Body.Bytes(), &response)
			if err != nil {
				t.Fatalf("body %q: %v", rec.Body, err)
			}

			if response.Key.Token != "" || response.Key.Sealed == "" {
				t.Fatalf("key = %+v, want a sealed token and no plain one", response.Key)
			}

			token := rg.issueCalls[0].issued.Token
			if strings.Contains(rec.Body.String(), token) {
				t.Errorf("the response holds the token in plaintext: %s", rec.Body)
			}

			if strings.Contains(rec.Body.String(), `"token"`) {
				t.Errorf("the response has a token member: %s", rec.Body)
			}

			if got := pair.open(t, response.Key.Sealed); got != token {
				t.Errorf("opened %q, want the issued token %q", got, token)
			}

			written := rg.store.calls[len(rg.store.calls)-1].agent
			if sum := sha256.Sum256([]byte(token)); !bytes.Equal(written.KeyHash, sum[:]) {
				t.Errorf("the key written is not the one that was sealed")
			}

			if len(rg.sealCalls) != 1 || !bytes.Equal(rg.sealCalls[0].recipient[1:], pair.private.PublicKey().Bytes()) {
				t.Errorf("sealCalls = %+v, want one to the request's key", rg.sealCalls)
			}
		})
	}
}

// wantPublicKeyRequired is the exact refusal of a credential that sent no key.
const wantPublicKeyRequired = `{"error":{"code":"public_key_required","message":` +
	`"publicKey is required: a secret is only sent to this credential sealed to a key"}}` + "\n"

// TestCreateNeedsAPublicKeyExceptForASession: only a session may be sent the
// token as it is. Every other credential that sends no key, or null, is refused
// before a key is issued or anything is written.
func TestCreateNeedsAPublicKeyExceptForASession(t *testing.T) {
	t.Parallel()

	for name, send := range creators() {
		for _, body := range []string{bodyAssistant, `{"name":"assistant","publicKey":null}`} {
			t.Run(name+" "+body, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rec := send(rg, body)

				if name == "a session" {
					var response agents.CreateResponse

					err := json.Unmarshal(rec.Body.Bytes(), &response)
					if rec.Code != http.StatusCreated || err != nil || response.Key.Sealed != "" ||
						response.Key.Token != rg.issueCalls[0].issued.Token || len(rg.sealCalls) != 0 {
						t.Errorf("status %d, %s: want the plain token and no sealing", rec.Code, rec.Body)
					}

					return
				}

				if rec.Code != http.StatusBadRequest || rec.Body.String() != wantPublicKeyRequired {
					t.Errorf("status %d, body %q, want 400 %q", rec.Code, rec.Body, wantPublicKeyRequired)
				}

				// An agent creator is seeded, so only the writes and issues count.
				if rg.writes() != 0 || len(rg.issueCalls) != 0 || len(rg.sealCalls) != 0 {
					t.Errorf("writes %d, issues %d, seals %d, want none", rg.writes(), len(rg.issueCalls), len(rg.sealCalls))
				}
			})
		}
	}
}

// bodyBadPublicKey is the exact refusal of a key that is not a public key.
const bodyBadPublicKey = `{"error":{"code":"invalid_public_key","message":` +
	`"publicKey must be exactly 44 base64url characters: the suite byte 1 and a 32-byte X25519 public key"}}` + "\n"

// TestCreateRefusesAPublicKeyThatIsNotOne: a key of the wrong shape is refused
// at the parse, for every credential, before a key is issued.
func TestCreateRefusesAPublicKeyThatIsNotOne(t *testing.T) {
	t.Parallel()

	good := newClientPair(t).public

	for name, send := range creators() {
		for key, bad := range map[string]string{
			"an empty string": "",
			"short":           good[:43],
			"long":            good + "A",
			"padded":          good[:43] + "=",
			"another suite":   base64.RawURLEncoding.EncodeToString(append([]byte{2}, bytes.Repeat([]byte{1}, 32)...)),
			"text":            "not a key",
		} {
			t.Run(name+" "+key, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rec := send(rg, publicKeyBody(bad))

				if rec.Code != http.StatusBadRequest || rec.Body.String() != bodyBadPublicKey {
					t.Errorf("status %d, body %q, want 400 %q", rec.Code, rec.Body, bodyBadPublicKey)
				}

				if rg.writes() != 0 || len(rg.issueCalls) != 0 || len(rg.sealCalls) != 0 {
					t.Errorf("writes %d, issues %d, seals %d, want none", rg.writes(), len(rg.issueCalls), len(rg.sealCalls))
				}
			})
		}
	}
}

// bodyUnsealable is the exact refusal of a key that parses and cannot be sealed
// to.
const bodyUnsealable = `{"error":{"code":"invalid_public_key","message":"publicKey cannot be sealed to"}}` + "\n"

// TestCreateWritesNothingForAKeyItCannotSealTo: a point of low order has the
// shape of a key and fails in the sealer. The key was issued and the seal tried,
// and since the seal comes before the write, nothing was written.
func TestCreateWritesNothingForAKeyItCannotSealTo(t *testing.T) {
	t.Parallel()

	zero := base64.RawURLEncoding.EncodeToString(append([]byte{seal.SuiteX25519}, make([]byte, seal.KeyLen)...))

	for name, send := range creators() {
		t.Run(name+" low order", func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := send(rg, publicKeyBody(zero))

			if rec.Code != http.StatusBadRequest || rec.Body.String() != bodyUnsealable {
				t.Errorf("status %d, body %q, want 400 %q", rec.Code, rec.Body, bodyUnsealable)
			}

			if rg.writes() != 0 || len(rg.sealCalls) != 1 {
				t.Errorf("writes %d, seals %d, want no write after one seal", rg.writes(), len(rg.sealCalls))
			}
		})

		t.Run(name+" failing sealer", func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.sealErr = errSealer
			rec := send(rg, publicKeyBody(clientKey()))

			if rec.Code != http.StatusBadRequest || rec.Body.String() != bodyUnsealable {
				t.Errorf("status %d, body %q, want 400 %q", rec.Code, rec.Body, bodyUnsealable)
			}

			if rg.writes() != 0 {
				t.Errorf("writes = %d, want none", rg.writes())
			}

			if len(rg.logged) != 1 || !errors.Is(rg.logged[0], errSealer) {
				t.Errorf("logged %v, want one failure caused by %v", rg.logged, errSealer)
			}
		})
	}
}

var errSealer = errors.New("the sealer is broken")
