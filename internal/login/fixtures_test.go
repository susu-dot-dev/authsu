package login_test

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
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/login"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface
// login reads and writes through.
var _ login.Store = (*store.Store)(nil)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB      = errors.New("INSERT INTO japikeys: database is on fire")
	errEntropy = errors.New("entropy source is broken")
	errCreate  = errors.New("key generation is broken")
)

const (
	testSecret = "login-secret-0123456789ABCDEFGHIJKLMNOP"
	testRPID   = "example.com"
	testUI     = "https://example.com"
	testAPI    = "https://auth.example.com"

	testCredRowID = "00000000-0000-7000-8000-000000000001"
	testUserID    = "00000000-0000-7000-8000-000000000002"
	testRole      = "admin"

	jsonType     = "application/json"
	cacheNoStore = "no-store"
)

// Flag bits of authenticator data (WebAuthn section 6.1).
const (
	flagUP byte = 1 << 0
	flagUV byte = 1 << 2
	flagBE byte = 1 << 3
	flagBS byte = 1 << 4
	flagAT byte = 1 << 6
	flagED byte = 1 << 7
)

// Error codes the tests expect, spelled out so that renaming one in the code
// is a visible change here.
const (
	codeInvalidLogin  = "invalid_login"
	codeInternal      = "internal"
	codeNotConfigured = "not_configured"
)

// Messages clients see. They are fixed text: a cause never reaches a client.
const (
	msgInvalidLogin  = "the passkey login response is not valid"
	msgNotConfigured = "the service is not configured"
	msgUnavailable   = "login is temporarily unavailable"
	msgBodyTooLarge  = "request body is too large"
)

// The answers a client is given.
const (
	bodyInternal = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
)

// bodyInvalidLogin is the one answer to every assertion that does not verify.
func bodyInvalidLogin() string { return errorBody(codeInvalidLogin, msgInvalidLogin) }

// errorBody is the exact body of a failure with this code and message.
func errorBody(code, message string) string {
	return `{"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n"
}

// testNow is the fixed time the tests run at, on a whole second so a
// challenge's expiry (stored in whole seconds) is exact.
func testNow() time.Time { return time.Date(2026, time.November, 16, 12, 0, 0, 0, time.UTC) }

// testCredID is the passkey's credential id and testHandle the account's user
// handle. They are functions, not variables, so nothing can change them.
func testCredID() []byte { return []byte("credential-id-0123456789") }
func testHandle() []byte { return []byte("user-handle-0123456789abcdef0123") }

// counterEntropy is deterministic entropy: each byte is the previous plus one,
// starting at 1.
func counterEntropy() io.Reader {
	next := byte(1)

	return readerFunc(func(p []byte) (int, error) {
		for i := range p {
			p[i] = next
			next++
		}

		return len(p), nil
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// brokenEntropy fails every read.
func brokenEntropy() io.Reader {
	return readerFunc(func([]byte) (int, error) { return 0, errEntropy })
}

// fakeStore is the database as login sees it. It records every call and can be
// programmed to return any outcome.
type fakeStore struct {
	// credentials are the passkeys by credential id.
	credentials map[string]store.Credential
	// lookupErr, when set, is returned by every CredentialByID.
	lookupErr error
	// createErrs are the outcomes of successive CreateSession calls; a call
	// past the end succeeds.
	createErrs []error

	looked  [][]byte
	created []store.NewSession
}

func (f *fakeStore) CredentialByID(_ context.Context, id []byte) (store.Credential, bool, error) {
	f.looked = append(f.looked, bytes.Clone(id))

	if f.lookupErr != nil {
		return store.Credential{}, false, f.lookupErr
	}

	credential, ok := f.credentials[string(id)]

	return credential, ok, nil
}

func (f *fakeStore) CreateSession(_ context.Context, session store.NewSession) error {
	f.created = append(f.created, session)

	if len(f.created) <= len(f.createErrs) {
		return f.createErrs[len(f.created)-1]
	}

	return nil
}

// noKeys is the key store of a deployment under a route that needs no session:
// reading it at all is a defect.
type noKeys struct{ t *testing.T }

func (k noKeys) ActiveKey(context.Context, string, string, time.Time) (store.ActiveKey, bool, error) {
	k.t.Error("an open route read the key store")

	return store.ActiveKey{}, false, nil
}

// sessionCall is one call of the injected session creation.
type sessionCall struct {
	issuer  auth.Issuer
	userID  string
	expires time.Time
}

// rig is one deployment under test: the real boundary and routes over a fake
// store, with a clock, entropy and key creation the test controls.
type rig struct {
	t       *testing.T
	store   *fakeStore
	env     map[string]string
	now     time.Time
	entropy io.Reader
	// priv is the passkey's private key, the one the store has the public half of.
	priv *ecdsa.PrivateKey
	// createErr, when set, is what the injected session creation fails with.
	createErr error
	// sessions records every session creation, and keys the keys it made.
	sessions []sessionCall
	keys     []auth.Key
	// logged records every error the boundary turned into a response.
	logged []*apierr.Error
}

func newRig(t *testing.T) *rig {
	t.Helper()

	priv := newPrivateKey(t)

	return &rig{
		t: t,
		store: &fakeStore{
			credentials: map[string]store.Credential{string(testCredID()): {
				ID: testCredRowID, UserID: testUserID, PublicKey: coseKey(t, priv),
				Flags: flagUP | flagUV, UserHandle: testHandle(), Role: testRole,
			}},
			lookupErr: nil, createErrs: nil, looked: nil, created: nil,
		},
		env: map[string]string{
			config.SecretHMAC: testSecret, config.VarAPIOrigin: testAPI, config.VarUIOrigin: testUI,
		},
		now:       testNow(),
		entropy:   counterEntropy(),
		priv:      priv,
		createErr: nil, sessions: nil, keys: nil, logged: nil,
	}
}

func newPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return priv
}

// coseKey is the canonical COSE_Key registration stores for priv.
func coseKey(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()

	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	out, err := mode.Marshal(map[int64]any{
		1: 2, 3: -7, -1: 1,
		-2: priv.X.FillBytes(make([]byte, 32)),
		-3: priv.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	return out
}

// with sets, or with "" removes, deployment settings.
func (r *rig) with(settings map[string]string) *rig {
	maps.Copy(r.env, settings)

	return r
}

func (r *rig) getenv(name string) string { return r.env[name] }

// config is the deployment configuration the handlers load.
func (r *rig) config() config.Config {
	r.t.Helper()

	cfg, err := config.Load(r.getenv)
	if err != nil {
		r.t.Fatalf("config: %v", err)
	}

	return cfg
}

// credential is the stored passkey, for a test to change.
func (r *rig) credential() store.Credential { return r.store.credentials[string(testCredID())] }

// setCredential replaces the stored passkey.
func (r *rig) setCredential(change func(*store.Credential)) {
	credential := r.credential()

	change(&credential)
	r.store.credentials[string(testCredID())] = credential
}

// createSession is the injected session creation: the real one, recorded, unless
// the test made it fail.
func (r *rig) createSession(issuer auth.Issuer, userID string, expires time.Time) (auth.Key, error) {
	r.sessions = append(r.sessions, sessionCall{issuer: issuer, userID: userID, expires: expires})

	if r.createErr != nil {
		return auth.Key{}, r.createErr
	}

	key, err := auth.CreateSession(issuer, userID, expires)
	if err == nil {
		r.keys = append(r.keys, key)
	}

	return key, err //nolint:wrapcheck // a test double passes the real function's result through
}

func (r *rig) deps() login.Deps {
	return login.Deps{
		Store:         r.store,
		Now:           func() time.Time { return r.now },
		Entropy:       readerFunc(func(p []byte) (int, error) { return r.entropy.Read(p) }),
		CreateSession: r.createSession,
	}
}

// handler is the real boundary over the real routes.
func (r *rig) handler() http.Handler {
	return auth.Handler(login.Routes(r.deps()), auth.Deps{
		Keys:   noKeys{t: r.t},
		Now:    func() time.Time { return r.now },
		Getenv: r.getenv,
		Log:    func(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) },
	})
}

// request is one request to send.
type request struct {
	method, target, body string
	// contentType defaults to application/json; "-" sends none.
	contentType string
	cookies     []*http.Cookie
}

func (r *rig) serve(req request) *httptest.ResponseRecorder {
	r.t.Helper()

	method := req.method
	if method == "" {
		method = http.MethodPost
	}

	httpReq := httptest.NewRequestWithContext(r.t.Context(), method, req.target, strings.NewReader(req.body))

	switch req.contentType {
	case "":
		httpReq.Header.Set("Content-Type", jsonType)
	case "-":
	default:
		httpReq.Header.Set("Content-Type", req.contentType)
	}

	for _, cookie := range req.cookies {
		httpReq.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	r.handler().ServeHTTP(rec, httpReq)

	return rec
}

// post sends body to path.
func (r *rig) post(path, body string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{target: path, body: body})
}

// requestOptions is the part of the begin response a browser uses.
type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
}

// beginOK runs a begin that must succeed and returns its options.
func (r *rig) beginOK() requestOptions {
	r.t.Helper()

	rec := r.post(login.PathBegin, "{}")
	if rec.Code != http.StatusOK {
		r.t.Fatalf("begin = %d %s, want 200", rec.Code, rec.Body)
	}

	var options requestOptions

	err := json.Unmarshal(rec.Body.Bytes(), &options)
	if err != nil {
		r.t.Fatalf("begin body: %v", err)
	}

	return options
}

// jsonBody is a JSON object a test builds and edits.
type jsonBody map[string]any

// set puts value at a dotted path, creating objects on the way.
func (b jsonBody) set(path string, value any) {
	head, rest, nested := strings.Cut(path, ".")
	if !nested {
		b[head] = value

		return
	}

	child, ok := b[head].(jsonBody)
	if !ok {
		child = jsonBody{}
		b[head] = child
	}

	child.set(rest, value)
}

// remove deletes the member at a dotted path.
func (b jsonBody) remove(path string) {
	head, rest, nested := strings.Cut(path, ".")
	if !nested {
		delete(b, head)

		return
	}

	if child, ok := b[head].(jsonBody); ok {
		child.remove(rest)
	}
}

func mustJSON(value any) string {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	return string(out)
}

// b64 is unpadded base64url.
func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func unb64(t *testing.T, text string) []byte {
	t.Helper()

	out, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("base64url %q: %v", text, err)
	}

	return out
}

// authenticator is a software authenticator: it turns the request options begin
// returned into the assertion a browser would send, and can be told to
// misbehave in one way at a time.
type authenticator struct {
	rpID   string
	origin string
	// flags are the authenticator data flags: UP | UV by default.
	flags  byte
	credID []byte
	handle []byte
	// clientDataType is the clientData type; "webauthn.get" when empty.
	clientDataType string
	// challenge replaces the challenge echoed in clientDataJSON.
	challenge []byte
	// key signs the assertion.
	key *ecdsa.PrivateKey
	// trailing is appended to the authenticator data, which must be exactly
	// 37 bytes.
	trailing []byte
}

func (r *rig) newAuthenticator() authenticator {
	return authenticator{
		rpID: testRPID, origin: testUI, flags: flagUP | flagUV, credID: testCredID(), handle: testHandle(),
		clientDataType: "", challenge: nil, key: r.priv, trailing: nil,
	}
}

// respond builds the finish request a browser would post for options.
func (a authenticator) respond(t *testing.T, options requestOptions) jsonBody {
	t.Helper()

	echoed := a.challenge
	if echoed == nil {
		echoed = unb64(t, options.PublicKey.Challenge)
	}

	typ := a.clientDataType
	if typ == "" {
		typ = "webauthn.get"
	}

	client := []byte(mustJSON(map[string]any{
		"type": typ, "challenge": b64(echoed), "origin": a.origin, "crossOrigin": false,
	}))

	hash := sha256.Sum256([]byte(a.rpID))

	authData := append([]byte(nil), hash[:]...)
	authData = append(authData, a.flags)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, a.trailing...)

	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))

	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	id := b64(a.credID)

	return jsonBody{
		"id": id, "rawId": id, "type": "public-key",
		"response": jsonBody{
			"clientDataJSON":    b64(client),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64(a.handle),
		},
		"clientExtensionResults": jsonBody{},
	}
}

// finish posts a finish body.
func (r *rig) finish(body jsonBody) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.post(login.PathFinish, mustJSON(body))
}

// ceremony is a full login: begin, then the authenticator's answer.
func (r *rig) ceremony() jsonBody {
	r.t.Helper()

	return r.newAuthenticator().respond(r.t, r.beginOK())
}

// forgeChallenge creates a challenge the way begin would, with whatever key and
// expiry the test chooses.
func forgeChallenge(t *testing.T, key []byte, expires time.Time) []byte {
	t.Helper()

	made, _, err := challenge.Create(key, counterEntropy(), expires)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	return made
}

// requestCookie is a cookie as a browser returns it: only a name and a value.
func requestCookie(name, value string) *http.Cookie {
	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: name, Value: value}
}

// classified is an error as the store returns it for a failed operation.
func classified(kind apierr.Kind, code string) error {
	return apierr.Wrap(errDB, kind, code, msgUnavailable)
}

// wantFailure checks the status and the exact body of a failure response, and
// that it was logged once under code with no cookies set.
func wantFailure(t *testing.T, r *rig, rec *httptest.ResponseRecorder, status int, body, code string) {
	t.Helper()

	if rec.Code != status || rec.Body.String() != body {
		t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), status, body)
	}

	if got := rec.Header().Get("Cache-Control"); got != cacheNoStore {
		t.Errorf("Cache-Control = %q, want %s", got, cacheNoStore)
	}

	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("a failure set cookies: %v", rec.Result().Cookies())
	}

	if len(r.logged) != 1 {
		t.Fatalf("logged %d errors, want 1: %v", len(r.logged), r.logged)
	}

	if r.logged[0].Code != code {
		t.Errorf("logged code = %q, want %q", r.logged[0].Code, code)
	}
}
