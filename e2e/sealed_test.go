//go:build e2e

package e2e_test

// sealed_test.go drives the sealed responses of POST /api/agent and POST
// /api/invitation against the real Worker. The unit tests run Go's crypto/hpke
// on the host; this file proves what only the real build can: that the TinyGo
// wasm seals (X25519, its randomness, the AEAD), that a client's key opens the
// result, that the token inside is the real one, and that a refused key leaves
// nothing behind.
//
// REVIEW.md categories covered: permission confusion (a key without a
// publicKey is refused, a session is not), input edge cases (the shape and the
// low-order key) and type/bound confusion (the key through JSON and base64url).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// lowOrderKey is the suite byte and 32 zero bytes: the shape of a key, and a
// point the sealer refuses.
func lowOrderKey() string {
	return base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 32)...))
}

// sealedBodyOf is a create body carrying publicKey.
func sealedBodyOf(name, publicKey string) []byte {
	return []byte(`{"name":"` + name + `","publicKey":"` + publicKey + `"}`)
}

// TestACreateByAKeyIsSealedToTheRequestsPublicKey: a key creates an agent with a
// publicKey and gets the agent's first key sealed to it. The response holds no
// token; the client opens it, and the token it gets is the agent's real key.
//
//nolint:paralleltest // shares one database
func TestACreateByAKeyIsSealedToTheRequestsPublicKey(t *testing.T) {
	admin := newAdmin(t)
	userKey := sbSeedKey(t, idN(sbKeyFam, 70), admin.userID, "", `["default:user"]`)
	pair := newClientPair(t)

	got := send(t, request{
		method: http.MethodPost, path: pathAgent, body: sealedBodyOf("sealed", pair.public), bearer: userKey, noSeal: true,
	})
	got.expect(t, "create with a key and a publicKey", http.StatusCreated, "")

	var response struct {
		Key map[string]any `json:"key"`
	}

	err := json.Unmarshal([]byte(got.body), &response)
	if err != nil {
		t.Fatalf("body %s: %v", got.body, err)
	}

	sealed, _ := response.Key["sealed"].(string)
	if _, plain := response.Key["token"]; plain || sealed == "" {
		t.Fatalf("key = %v, want a sealed member and no token", response.Key)
	}

	token := pair.open(t, sealed)
	if !strings.HasPrefix(token, "susu_key_") || strings.Contains(got.body, token) {
		t.Errorf("opened %q from %s, want an API key that is not in the body", token, got.body)
	}

	// The token that was sealed is the one that was stored: it is the agent's key.
	send(t, request{path: pathAgent, bearer: token}).expect(t, "the opened token as a bearer", http.StatusOK, "")
}

// TestACreateByAKeyNeedsAPublicKey: a key that sends none is refused with
// nothing written, and a key that sends one that cannot be sealed to is refused
// after the key was issued and sealed and before the write, so no row is left.
//
//nolint:paralleltest,goconst // shares one database; the table repeats codes and bodies on purpose
func TestACreateByAKeyNeedsAPublicKey(t *testing.T) {
	admin := newAdmin(t)
	userKey := sbSeedKey(t, idN(sbKeyFam, 71), admin.userID, "", `["default:user"]`)

	before := count(t, "agents")

	for _, tc := range []struct {
		name, code string
		body       string
	}{
		{"no publicKey", "public_key_required", `{"name":"x"}`},
		{"a null publicKey", "public_key_required", `{"name":"x","publicKey":null}`},
		{"an empty publicKey", "invalid_public_key", `{"name":"x","publicKey":""}`},
		{"a bare 32-byte key", "invalid_public_key",
			`{"name":"x","publicKey":"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `"}`},
		{"the low-order key", "invalid_public_key", `{"name":"x","publicKey":"` + lowOrderKey() + `"}`},
	} {
		got := send(t, request{
			method: http.MethodPost, path: pathAgent, body: []byte(tc.body), bearer: userKey, noSeal: true,
		})
		got.expect(t, tc.name, http.StatusBadRequest, tc.code)

		if strings.Contains(got.body, "susu_key_") {
			t.Errorf("%s: the refusal holds a token: %s", tc.name, got.body)
		}
	}

	if after := count(t, "agents"); after != before {
		t.Errorf("refused creates left agents behind: %s -> %s", before, after)
	}
}

// TestASessionMayOmitThePublicKey: a session is a browser's and is sent the
// token as it is, and it may also ask for a sealed one.
//
//nolint:paralleltest // shares one database
func TestASessionMayOmitThePublicKey(t *testing.T) {
	admin := newAdmin(t)
	session := login(t, admin)

	plain := post(t, pathAgent, []byte(`{"name":"plain"}`), session)
	plain.expect(t, "a session without a key", http.StatusCreated, "")

	if !strings.Contains(plain.body, `"token":"susu_key_`) || strings.Contains(plain.body, `"sealed"`) {
		t.Errorf("body %s, want the token and no sealed member", plain.body)
	}

	pair := newClientPair(t)

	sealed := post(t, pathAgent, sealedBodyOf("sealed", pair.public), session)
	sealed.expect(t, "a session with a key", http.StatusCreated, "")

	if strings.Contains(sealed.body, `"token"`) || !strings.Contains(sealed.body, `"sealed":"`) {
		t.Errorf("body %s, want a sealed member and no token", sealed.body)
	}
}

// TestAnInvitationByAKeyIsSealed: an admin's key creates an invitation sealed to
// its publicKey, and without one is refused.
//
//nolint:paralleltest // shares one database
func TestAnInvitationByAKeyIsSealed(t *testing.T) {
	admin := newAdmin(t)
	key := sbSeedKey(t, idN(sbKeyFam, 72), admin.userID, "", `["invitation:create"]`)
	pair := newClientPair(t)

	body := []byte(`{"type":"member","numInvites":1,"publicKey":"` + pair.public + `"}`)

	got := send(t, request{method: http.MethodPost, path: pathInvitation, body: body, bearer: key, noSeal: true})
	got.expect(t, "create with a publicKey", http.StatusCreated, "")

	var response struct {
		ID     string  `json:"id"`
		Code   *string `json:"code"`
		Sealed string  `json:"sealed"`
	}

	err := json.Unmarshal([]byte(got.body), &response)
	if err != nil || response.Code != nil || response.Sealed == "" {
		t.Fatalf("body %s (%v), want a sealed member and no code", got.body, err)
	}

	code := pair.open(t, response.Sealed)
	if !strings.HasPrefix(code, "susu_inv_") || strings.Contains(got.body, code) {
		t.Errorf("opened %q from %s, want an invitation token that is not in the body", code, got.body)
	}

	// What was sealed is what was stored: the hash of the opened token.
	expectCount(t, "secrets WHERE hash = ?", "1", tokenHash(code))

	refused := send(t, request{
		method: http.MethodPost, path: pathInvitation, body: []byte(`{"type":"member","numInvites":1}`), bearer: key,
		noSeal: true,
	})
	refused.expect(t, "create without a publicKey", http.StatusBadRequest, "public_key_required")
}
