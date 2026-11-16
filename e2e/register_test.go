//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// This file drives passkey registration against the real Worker. The unit tests
// fake the database, so these are what prove the SQL: the conditional user
// insert, the credential's reference to it, and the rollback.
//
// The test plays the browser and authenticator: it takes the creation options
// the Worker returned, generates a real ES256 key and builds a real "none"
// attestation over them. Nothing about the Worker is mocked.
//
// The invitation is the first-run one, minted by GET /api/first-run from
// FIRST_RUN_SECRET, so the whole path from bootstrap to first administrator is
// exercised.

const (
	registerPath = "/api/register"

	codeInvalidChallenge  = "invalid_challenge"
	codeInvalidCredential = "invalid_credential"
)

type creationOptions struct {
	PublicKey struct {
		RP struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"user"`
		Challenge        string `json:"challenge"`
		PubKeyCredParams []struct {
			Alg int `json:"alg"`
		} `json:"pubKeyCredParams"`
		Attestation string `json:"attestation"`
	} `json:"publicKey"`
}

// authenticator builds registration responses the way a passkey would.
type authenticator struct {
	rpID   string
	origin string
	credID []byte
	flags  byte

	// The overrides below let a test send what no honest authenticator would.
	// cose replaces the generated credential public key.
	cose []byte
	// object builds the attestation object from authData instead of the
	// canonical {"fmt":"none","attStmt":{},"authData":...}.
	object func(authData []byte) []byte
	// clientData builds clientDataJSON from the challenge instead of the
	// browser's serialization.
	clientData func(challenge string) []byte
}

func newAuthenticator() authenticator {
	return authenticator{
		rpID:   rpID,
		origin: target.origin,
		credID: mustRandom(32),
		// UP | UV | AT
		flags: 0x01 | 0x04 | 0x40,
	}
}

func mustRandom(n int) []byte {
	out := make([]byte, n)

	_, err := rand.Read(out)
	if err != nil {
		panic(err)
	}

	return out
}

// finishBody builds the POST /api/register/finish body answering options.
func (a authenticator) finishBody(t *testing.T, options creationOptions, code, name string) []byte {
	t.Helper()

	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   options.PublicKey.Challenge,
		"origin":      a.origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	if a.clientData != nil {
		clientData = a.clientData(options.PublicKey.Challenge)
	}

	id := base64.RawURLEncoding.EncodeToString(a.credID)

	body, err := json.Marshal(map[string]any{
		"invitationCode": code,
		"name":           name,
		"credential": map[string]any{
			"id": id, "rawId": id, "type": "public-key",
			"response": map[string]any{
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
				"attestationObject": base64.RawURLEncoding.EncodeToString(a.attestationObject(t)),
				"transports":        []string{"internal"},
			},
		},
	})
	if err != nil {
		t.Fatalf("finish body: %v", err)
	}

	return body
}

// attestationObject is a "none" attestation over a fresh ES256 key.
func (a authenticator) attestationObject(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	cose, err := encoder.Marshal(map[int64]any{
		1: 2, 3: -7, -1: 1,
		-2: key.X.FillBytes(make([]byte, 32)),
		-3: key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("cose: %v", err)
	}

	if a.cose != nil {
		cose = a.cose
	}

	hash := sha256.Sum256([]byte(a.rpID))

	authData := make([]byte, 0, len(hash)+1+4+16+2+len(a.credID)+len(cose))
	authData = append(authData, hash[:]...)
	authData = append(authData, a.flags)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(min(len(a.credID), 1023)))
	authData = append(authData, a.credID...)
	authData = append(authData, cose...)

	if a.object != nil {
		return a.object(authData)
	}

	object, err := encoder.Marshal(map[string]any{
		fmtMember: noneFormat, attStmtMember: map[string]any{}, "authData": authData,
	})
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}

	return object
}

// postJSON POSTs body to path and returns the status and response body.
func postJSON(t *testing.T, path string, body []byte) (int, string) {
	t.Helper()

	url := target.baseURL + path

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	return resp.StatusCode, string(data)
}

func beginRegistration(t *testing.T, code, name string) (int, string) {
	t.Helper()

	body, err := json.Marshal(map[string]string{"invitationCode": code, "name": name})
	if err != nil {
		t.Fatalf("begin body: %v", err)
	}

	return postJSON(t, registerPath+"/begin", body)
}

func mustBegin(t *testing.T, name string) creationOptions {
	t.Helper()

	status, body := beginRegistration(t, firstRunSecret, name)
	if status != http.StatusOK {
		t.Fatalf("begin = %d %s, want 200", status, body)
	}

	var options creationOptions

	err := json.Unmarshal([]byte(body), &options)
	if err != nil {
		t.Fatalf("parse begin response: %v\n%s", err, body)
	}

	return options
}

// TestRegistration walks the whole feature against the real Worker, TinyGo
// build and D1: bootstrap, begin, refusals that must leave nothing behind, the
// accepted registration, and the replays that must be refused afterwards.
//
// It shares the one database with the first-run tests, and registers the first
// user, so it must run after them; the first-run tests finish by closing first
// run themselves, which is why this one clears that state first.
//
//nolint:paralleltest // shares one database with the first-run tests; the steps are ordered
func TestRegistration(t *testing.T) {
	// First-run tests leave a user and an invitation behind. Start from the
	// state a fresh deployment has, so the first-run invitation is minted here
	// by the real endpoint and redeemed by the real registration.
	query(t, "DELETE FROM credentials")
	query(t, "DELETE FROM users")
	query(t, "DELETE FROM invitations")

	expectFirstRun(t, pendingBody)

	t.Run("begin is stateless", beginIsStateless)
	t.Run("begin refuses a wrong code", beginRefusesWrongCode)
	t.Run("finish refusals leave nothing behind", finishRefusalsLeaveNothing)
	t.Run("finish creates the first administrator", finishCreatesAdmin)
	t.Run("a spent invitation is refused", replaysAreRefused)
	t.Run("the Worker build parses like the host", workerParsesLikeTheHost)
}

func beginIsStateless(t *testing.T) {
	options := mustBegin(t, "Alice")

	if options.PublicKey.RP.ID != rpID || options.PublicKey.User.Name != "Alice" {
		t.Errorf("options = %+v", options.PublicKey)
	}

	if len(options.PublicKey.PubKeyCredParams) != 1 || options.PublicKey.PubKeyCredParams[0].Alg != -7 {
		t.Errorf("pubKeyCredParams = %+v, want only ES256", options.PublicKey.PubKeyCredParams)
	}

	if options.PublicKey.Attestation != noneFormat {
		t.Errorf("attestation = %q, want none", options.PublicKey.Attestation)
	}

	// Two begins differ, and neither wrote anything.
	again := mustBegin(t, "Alice")
	if again.PublicKey.Challenge == options.PublicKey.Challenge || again.PublicKey.User.ID == options.PublicKey.User.ID {
		t.Error("two begins returned the same challenge or user handle")
	}

	expectCount(t, "users", "0")
	expectCount(t, "credentials", "0")
}

func beginRefusesWrongCode(t *testing.T) {
	status, body := beginRegistration(t, "not-a-real-invitation-code", "Alice")
	if status != http.StatusForbidden || !strings.Contains(body, `"invalid_invitation"`) {
		t.Errorf("begin with a wrong code = %d %s, want 403 invalid_invitation", status, body)
	}
}

// refusal is a finish request the Worker must refuse without writing anything.
type refusal struct {
	body       func() []byte
	wantStatus int
	wantCode   string
}

func finishRefusalsLeaveNothing(t *testing.T) {
	options := mustBegin(t, "Alice")

	tests := map[string]refusal{}

	maps.Copy(tests, tamperedChallenges(t, options))
	maps.Copy(tests, badPasskeys(t, options))

	tests["unknown member in the request"] = refusal{
		body:       func() []byte { return []byte(`{"invitationCode":"x","name":"y","role":"admin"}`) },
		wantStatus: http.StatusBadRequest, wantCode: "unknown_field",
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			status, body := postJSON(t, registerPath+"/finish", tt.body())
			if status != tt.wantStatus || !strings.Contains(body, `"`+tt.wantCode+`"`) {
				t.Errorf("finish = %d %s, want %d %s", status, body, tt.wantStatus, tt.wantCode)
			}

			expectCount(t, "users", "0")
			expectCount(t, "credentials", "0")
		})
	}
}

// tamperedChallenges are finishes whose challenge does not match the begin.
func tamperedChallenges(t *testing.T, options creationOptions) map[string]refusal {
	t.Helper()

	return map[string]refusal{
		"challenge signed for another name": {
			body: func() []byte {
				return newAuthenticator().finishBody(t, options, firstRunSecret, "Mallory")
			},
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidChallenge,
		},
		"challenge signed for another code": {
			body: func() []byte {
				return newAuthenticator().finishBody(t, options, "another-code-0123456789abcdefghijklmnop", "Alice")
			},
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidChallenge,
		},
		"challenge that was never issued": {
			body: func() []byte {
				forged := options
				forged.PublicKey.Challenge = base64.RawURLEncoding.EncodeToString(mustRandom(73))

				return newAuthenticator().finishBody(t, forged, firstRunSecret, "Alice")
			},
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidChallenge,
		},
	}
}

// badPasskeys are finishes whose passkey response fails verification.
func badPasskeys(t *testing.T, options creationOptions) map[string]refusal {
	t.Helper()

	from := func(edit func(*authenticator)) func() []byte {
		return func() []byte {
			a := newAuthenticator()
			edit(&a)

			return a.finishBody(t, options, firstRunSecret, "Alice")
		}
	}

	return map[string]refusal{
		"wrong origin": {
			body:       from(func(a *authenticator) { a.origin = "https://evil.example.com" }),
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidCredential,
		},
		"wrong relying party": {
			body:       from(func(a *authenticator) { a.rpID = "evil.example.com" }),
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidCredential,
		},
		"user verification missing": {
			body:       from(func(a *authenticator) { a.flags = 0x01 | 0x40 }),
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidCredential,
		},
	}
}

// racers are two registrations that both began while the invitation was open.
// Both challenges are validly signed, so nothing but the write can tell them
// apart: exactly one may win.
type racer struct {
	options creationOptions
	auth    authenticator
	name    string
}

func finishCreatesAdmin(t *testing.T) {
	// Both begin before either finishes, so each one's advisory check passes
	// and each holds a challenge the server will accept.
	first := racer{options: mustBegin(t, "Alice"), auth: newAuthenticator(), name: "Alice"}
	second := racer{options: mustBegin(t, "Bob"), auth: newAuthenticator(), name: "Bob"}

	status, body := postJSON(t, registerPath+"/finish",
		first.auth.finishBody(t, first.options, firstRunSecret, first.name))
	if status != http.StatusCreated || !strings.Contains(body, `"role":"admin"`) {
		t.Fatalf("finish = %d %s, want 201 with role admin", status, body)
	}

	expectCount(t, "users", "1")
	expectCount(t, "credentials", "1")

	// The role came from the invitation, the handle from the signed challenge,
	// and the profile from the name that challenge was bound to.
	wantHandle := base64ToHex(t, first.options.PublicKey.User.ID)

	got := query(t, "SELECT role || '|' || hex(user_handle) || '|' || profile AS v FROM users")
	if want := "admin|" + wantHandle + `|{"name":"Alice"}`; got != want {
		t.Errorf("stored user = %q, want %q", got, want)
	}

	// The credential belongs to that user and records what was verified.
	expectCount(t, "credentials c JOIN users u ON u.id = c.user_id WHERE u.role = 'admin' AND c.flags = 5", "1")
	expectCount(t, "credentials WHERE json_extract(metadata, '$.fmt') = 'none'", "1")

	// First run is over.
	expectFirstRun(t, acceptedBody)

	// The second racer's challenge is still validly signed and its passkey is
	// valid. Only the write's conditions refuse it: the invitation is spent and
	// first run needs an empty system. The conflict must leave no partial state.
	status, body = postJSON(t, registerPath+"/finish",
		second.auth.finishBody(t, second.options, firstRunSecret, second.name))
	if status != http.StatusForbidden || !strings.Contains(body, `"invalid_invitation"`) {
		t.Errorf("second finish = %d %s, want 403 invalid_invitation", status, body)
	}

	expectCount(t, "users", "1")
	expectCount(t, "credentials", "1")
}

func replaysAreRefused(t *testing.T) {
	// begin refuses outright now that the invitation is spent.
	status, body := beginRegistration(t, firstRunSecret, "Alice")
	if status != http.StatusForbidden || !strings.Contains(body, `"invalid_invitation"`) {
		t.Errorf("begin after first run = %d %s, want 403 invalid_invitation", status, body)
	}

	expectCount(t, "users", "1")
	expectCount(t, "credentials", "1")
}

func base64ToHex(t *testing.T, encoded string) string {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode %q: %v", encoded, err)
	}

	return strings.ToUpper(hex.EncodeToString(raw))
}
