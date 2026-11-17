package login

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

var errDB = errors.New("database is on fire")

const (
	testSecret = "login-secret-0123456789ABCDEFGHIJKLMNOP"
	testRPID   = "example.com"
	testOrigin = "https://example.com"
	testAPI    = "https://auth.example.com"

	testCredRowID = "00000000-0000-7000-8000-000000000001"
	testUserID    = "00000000-0000-7000-8000-000000000002"
	testRole      = "admin"
)

// testCredID is the passkey's credential id and testHandle the account's user
// handle. They are functions, not variables, so nothing can change them.
func testCredID() []byte { return []byte("credential-id-0123456789") }
func testHandle() []byte { return []byte("user-handle-0123456789abcdef0123") }

// fakeReader answers CredentialByID from a fixed credential.
type fakeReader struct {
	cred Credential
	ok   bool
	err  error
	// asked records the credential ids it was asked for.
	asked [][]byte
}

func (f *fakeReader) CredentialByID(_ context.Context, id []byte) (Credential, bool, error) {
	f.asked = append(f.asked, id)

	if f.err != nil {
		return Credential{}, false, f.err
	}

	if !f.ok || !bytes.Equal(id, testCredID()) {
		return Credential{}, false, nil
	}

	return f.cred, true, nil
}

// fakeBatch records the batches it receives and returns a configured error.
type fakeBatch struct {
	err     error
	batches [][]atomic.Statement
}

func (f *fakeBatch) run(_ context.Context, statements ...atomic.Statement) error {
	f.batches = append(f.batches, statements)

	return f.err
}

func getenv(overrides map[string]string) func(string) string {
	values := map[string]string{
		deploy.SecretHMAC:   testSecret,
		deploy.VarAPIOrigin: testAPI,
		deploy.VarUIOrigin:  testOrigin,
	}

	maps.Copy(values, overrides)

	return func(name string) string { return values[name] }
}

// fixture is a service wired to fakes, with a clock we control.
type fixture struct {
	svc     *Service
	reader  *fakeReader
	batcher *fakeBatch
	// priv is the passkey's private key.
	priv *ecdsa.PrivateKey
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cose, err := coseKey(priv)
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}

	fix := &fixture{
		reader: &fakeReader{
			cred: Credential{
				ID: testCredRowID, UserID: testUserID, PublicKey: cose,
				Flags: 0x01 | 0x04, UserHandle: testHandle(), Role: testRole,
			},
			ok: true, err: nil, asked: nil,
		},
		batcher: &fakeBatch{err: nil, batches: nil},
		priv:    priv,
		now:     testNow(),
		svc:     nil,
	}

	fix.svc = NewService(Deps{
		Reader:  fix.reader,
		Batch:   fix.batcher.run,
		Now:     func() time.Time { return fix.now },
		Entropy: counterEntropy(),
	})

	return fix
}

// coseKey is the canonical COSE_Key registration stores for priv.
func coseKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("encoder: %w", err)
	}

	out, err := mode.Marshal(map[int64]any{
		1: 2, 3: -7, -1: 1,
		-2: priv.X.FillBytes(make([]byte, 32)),
		-3: priv.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	return out, nil
}

func request(t *testing.T, body any) httpapi.Request {
	t.Helper()

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	return httpapi.Request{Method: http.MethodPost, Path: "/", Context: t.Context(), Query: nil, Body: data, Cookies: nil}
}

// failureOf returns the classified error of a handler result.
func failureOf(t *testing.T, err error) *apierr.Error {
	t.Helper()

	if err == nil {
		t.Fatal("handler succeeded, want an error")
	}

	return apierr.As(err)
}

// wantFailure checks the kind and code of a handler failure.
func wantFailure(t *testing.T, err error, kind apierr.Kind, code string) {
	t.Helper()

	failure := failureOf(t, err)
	if failure.Kind != kind || failure.Code != code {
		t.Errorf("error = (%d, %q), want (%d, %q)", failure.Kind, failure.Code, kind, code)
	}
}

// begin runs the begin handler.
func begin(t *testing.T, fix *fixture, env func(string) string) (requestOptions, error) {
	t.Helper()

	resp, err := fix.svc.BeginHandler(env)(httpapi.Request{Context: t.Context()}).Get()
	if err != nil {
		return requestOptions{}, err //nolint:wrapcheck // test helper
	}

	if resp.Status != http.StatusOK {
		t.Fatalf("begin status = %d, want %d", resp.Status, http.StatusOK)
	}

	options, ok := resp.Body.(requestOptions)
	if !ok {
		t.Fatalf("begin body is %T", resp.Body)
	}

	return options, nil
}

// finish runs the finish handler and returns the whole response.
func finish(t *testing.T, fix *fixture, env func(string) string, body FinishRequest) (httpapi.Response, error) {
	t.Helper()

	return fix.svc.FinishHandler(env)(request(t, body)).Get() //nolint:wrapcheck // test helper
}

// authenticator is a software authenticator for tests: it turns the request
// options begin returned into the assertion a browser would send.
type authenticator struct {
	rpID   string
	origin string
	flags  byte
	credID []byte
	handle []byte
	// clientDataType is the clientData type; "webauthn.get" when empty.
	clientDataType string
	// challenge overrides the challenge echoed in clientDataJSON.
	challenge []byte
	// key signs the assertion; the fixture's passkey when nil.
	key *ecdsa.PrivateKey
}

func newAuthenticator() authenticator {
	return authenticator{
		rpID:   testRPID,
		origin: testOrigin,
		// UP | UV
		flags:          0x01 | 0x04,
		credID:         testCredID(),
		handle:         testHandle(),
		clientDataType: "",
		challenge:      nil,
		key:            nil,
	}
}

// respond builds the request a browser would post for options.
func (a authenticator) respond(t *testing.T, fix *fixture, options requestOptions) FinishRequest {
	t.Helper()

	challenge := a.challenge
	if challenge == nil {
		var err error

		challenge, err = base64.RawURLEncoding.DecodeString(options.PublicKey.Challenge)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
	}

	typ := a.clientDataType
	if typ == "" {
		typ = "webauthn.get"
	}

	client, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      a.origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	hash := sha256.Sum256([]byte(a.rpID))

	authData := append([]byte(nil), hash[:]...)
	authData = append(authData, a.flags)
	authData = binary.BigEndian.AppendUint32(authData, 0)

	key := a.key
	if key == nil {
		key = fix.priv
	}

	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))

	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	id := base64.RawURLEncoding.EncodeToString(a.credID)

	return FinishRequest{
		ID: id, RawID: id, Type: "public-key",
		Response: assertionBody{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(client),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
			Signature:         base64.RawURLEncoding.EncodeToString(signature),
			UserHandle:        base64.RawURLEncoding.EncodeToString(a.handle),
		},
		AuthenticatorAttachment: "",
		ClientExtensionResults:  nil,
	}
}

// beginThenRespond runs begin and answers it with a.
func beginThenRespond(t *testing.T, fix *fixture, a authenticator) FinishRequest {
	t.Helper()

	options, err := begin(t, fix, getenv(nil))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	return a.respond(t, fix, options)
}

// otherKey is a passkey that is not the fixture's.
func otherKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return priv
}
