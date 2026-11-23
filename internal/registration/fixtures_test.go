package registration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface
// registration reads and writes through.
var _ registration.Store = (*store.Store)(nil)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB      = errors.New("INSERT INTO users: database is on fire")
	errEntropy = errors.New("entropy source is broken")
)

const (
	testSecret = "registration-secret-0123456789ABCDEFGHIJ"
	testRPID   = "example.com"
	testUI     = "https://example.com"
	testAPI    = "https://auth.example.com"
	// testCode and otherCode are canonical invitation tokens: the prefix, 42
	// body characters and a last character whose two unused low bits are zero.
	testCode  = "susu_inv_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefA"
	otherCode = "susu_inv_zyxwvutsrqponmlkjihgfedcba9876543210-_-_-_E"
	// unknownCode is well formed, and no invitation has it.
	unknownCode = "susu_inv_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testName    = "Alice"
	testEmail   = "alice@example.com"

	jsonType = "application/json"

	firstRun = "first_run"

	cacheNoStore = "no-store"
	zeroAAGUID   = "00000000-0000-0000-0000-000000000000"

	transportInternal = "internal"
	transportUSB      = "usb"
)

// Error codes the tests expect, spelled out so that renaming one in the code
// is a visible change here.
const (
	codeInvalidInvitation = "invalid_invitation"
	codeInvalidName       = "invalid_name"
	codeInvalidEmail      = "invalid_email"
	codeInvalidCredential = "invalid_credential" //nolint:gosec // an error code, not a credential
	codeInvalidChallenge  = "invalid_challenge"
	codeInternal          = "internal"
	codeNotConfigured     = "not_configured"
	codeAcceptFailed      = "registration_accept_failed"
)

// Messages clients see. They are fixed text: a cause never reaches a client.
const (
	msgInvalidInvitation = "invitation token must be susu_inv_ followed by 43 base64url characters"
	msgInvalidName       = "name must be 1 to 128 bytes of normalised text without control or formatting characters"
	msgInvalidEmail      = "email must be an address of the form local@domain, 5 to 200 bytes, " +
		"in ASCII, with a dotted domain name"
	msgNotRedeemable     = "invitation token is not valid"
	msgNotConfigured     = "the service is not configured"
	msgUnavailable       = "registration is temporarily unavailable"
	msgBodyTooLarge      = "request body is too large"
	msgInvalidCredential = "the passkey registration response is not valid"
	msgInvalidChallenge  = "the registration challenge is not valid or has expired"
	msgConflict          = "registration could not be completed: " +
		"the invitation was already used or this registration was already submitted"
)

// The answers a client is given. A response carries a code and a fixed message,
// and never a cause.
const (
	bodyInternal = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
)

// errorBody is the exact body of a failure with this code and message.
func errorBody(code, message string) string {
	return `{"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n"
}

// testNow is the fixed time the tests run at, on a whole second so a
// challenge's expiry (stored in whole seconds) is exact.
func testNow() time.Time { return time.Date(2026, time.November, 16, 12, 0, 0, 0, time.UTC) }

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

// redeemCall is one RedeemableInvitationType call: the token as the store
// received it, the hash the store would look it up by, the configured first-run
// token it was given ("" for none) and the time.
type redeemCall struct {
	token    string
	hash     [sha256.Size]byte
	firstRun string
	now      time.Time
}

// wantRedeem is the call a store receives for token at now when the deployment
// has no first-run secret configured.
func wantRedeem(token string, now time.Time) redeemCall {
	return wantRedeemWith(token, "", now)
}

// wantRedeemWith is the call a store receives for token at now when firstRun is
// the configured first-run secret.
func wantRedeemWith(token, firstRun string, now time.Time) redeemCall {
	return redeemCall{token: token, hash: secret.Hash(token), firstRun: firstRun, now: now}
}

// fakeStore is the database as registration sees it. It records every call and
// can be programmed to return any outcome.
type fakeStore struct {
	// invitations maps the token of each redeemable invitation to its type.
	invitations map[string]string
	// redeemErr, when set, is returned by every RedeemableInvitationType.
	redeemErr error
	// createErrs are the outcomes of successive CreateAccount calls; a call
	// past the end succeeds.
	createErrs []error

	redeemed []redeemCall
	created  []store.NewAccount
}

func (f *fakeStore) RedeemableInvitationType(
	_ context.Context, token input.InvitationToken, firstRunToken *input.InvitationToken, now time.Time,
) (string, bool, error) {
	call := redeemCall{token: token.String(), hash: [sha256.Size]byte(token.Hash()), now: now}
	if firstRunToken != nil {
		call.firstRun = firstRunToken.String()
	}

	f.redeemed = append(f.redeemed, call)

	if f.redeemErr != nil {
		return "", false, f.redeemErr
	}

	invitationType, ok := f.invitations[token.String()]

	return invitationType, ok, nil
}

func (f *fakeStore) CreateAccount(_ context.Context, account store.NewAccount) error {
	f.created = append(f.created, account)

	if len(f.created) <= len(f.createErrs) {
		return f.createErrs[len(f.created)-1]
	}

	return nil
}

// noCredentials is the credential store of a deployment under a route that
// needs no session: reading it at all is a defect.
type noCredentials struct{ t *testing.T }

func (c noCredentials) ResolveSession(
	context.Context, input.SessionToken, time.Time,
) (store.ActiveSession, bool, error) {
	c.t.Error("an open route resolved a session")

	return store.ActiveSession{}, false, nil
}

func (c noCredentials) ResolveAPIKey(
	context.Context, input.APIKeyToken, time.Time,
) (store.ActiveAPIKey, bool, error) {
	c.t.Error("an open route resolved an API key")

	return store.ActiveAPIKey{}, false, nil
}

// rig is one deployment under test: the real boundary and routes over a fake
// store, with a clock, entropy and ids the test controls.
type rig struct {
	t       *testing.T
	store   *fakeStore
	env     map[string]string
	now     time.Time
	entropy io.Reader
	ids     int
	// logged records every error the boundary turned into a response.
	logged []*apierr.Error
}

func newRig(t *testing.T) *rig {
	t.Helper()

	return &rig{
		t: t,
		store: &fakeStore{
			invitations: map[string]string{testCode: firstRun, otherCode: firstRun},
			redeemErr:   nil, createErrs: nil, redeemed: nil, created: nil,
		},
		env: map[string]string{
			config.SecretHMAC: testSecret, config.VarAPIOrigin: testAPI, config.VarUIOrigin: testUI,
		},
		now:     testNow(),
		entropy: counterEntropy(),
		ids:     0,
		logged:  nil,
	}
}

// with sets, or with "" removes, deployment settings.
func (r *rig) with(settings map[string]string) *rig {
	maps.Copy(r.env, settings)

	return r
}

// newID is the id source: ids are numbered from 1 in the order they are asked.
func (r *rig) newID() string {
	r.ids++

	return fmt.Sprintf("00000000-0000-7000-8000-%012d", r.ids)
}

func (r *rig) getenv(name string) string { return r.env[name] }

// config is the deployment configuration the handlers load, for tests that
// build a challenge the way begin would.
func (r *rig) config() config.Config {
	r.t.Helper()

	cfg, err := config.Load(r.getenv)
	if err != nil {
		r.t.Fatalf("config: %v", err)
	}

	return cfg
}

func (r *rig) deps() registration.Deps {
	return registration.Deps{
		Store:   r.store,
		Now:     func() time.Time { return r.now },
		Entropy: readerFunc(func(p []byte) (int, error) { return r.entropy.Read(p) }),
		NewID:   r.newID,
	}
}

// handler is the real boundary over the real routes.
func (r *rig) handler() http.Handler {
	return auth.Handler(registration.Routes(r.deps()), auth.Deps{
		Credentials: noCredentials{t: r.t},
		Now:         func() time.Time { return r.now },
		Getenv:      r.getenv,
		Log:         func(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) },
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

// beginJSON is the body of a begin request.
func beginJSON(code, name string) string {
	return beginJSONWithEmail(code, name, testEmail)
}

// beginJSONWithEmail is beginJSON with an email address of the test's choosing.
func beginJSONWithEmail(code, name, email string) string {
	return mustJSON(jsonBody{"invitationCode": code, "name": name, "email": email})
}

// begin runs a begin and returns the response.
func (r *rig) begin(name string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.post(registration.PathBegin, beginJSON(testCode, name))
}

// creationOptions is the part of the begin response a browser uses.
type creationOptions struct {
	PublicKey struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
}

// beginOK runs a begin that must succeed and returns its options.
func (r *rig) beginOK() creationOptions {
	r.t.Helper()

	rec := r.begin(testName)
	if rec.Code != http.StatusOK {
		r.t.Fatalf("begin = %d %s, want 200", rec.Code, rec.Body)
	}

	var options creationOptions

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

// authenticator is a software authenticator: it turns the creation options
// begin returned into the response a browser would send, and can be told to
// misbehave in one way at a time.
type authenticator struct {
	rpID   string
	origin string
	// flags are the authenticator data flags: UP | UV | AT by default.
	flags  byte
	credID []byte
	aaguid [16]byte
	// transports are what the client reports.
	transports []string
	// clientDataType is the clientData type; "webauthn.create" when empty.
	clientDataType string
	// challenge replaces the challenge echoed in clientDataJSON.
	challenge []byte
	// format replaces the attestation format; "none" when empty.
	format string
	// cose is the credential's public key, as the COSE_Key the verifier stores,
	// and spki the same key in the DER form toJSON() reports as publicKey.
	cose []byte
	spki []byte
}

func newAuthenticator(t *testing.T) authenticator {
	t.Helper()

	return authenticator{
		rpID:           testRPID,
		origin:         testUI,
		flags:          0x01 | 0x04 | 0x40,
		credID:         []byte("credential-id-0123456789"),
		aaguid:         [16]byte{},
		transports:     []string{transportInternal},
		clientDataType: "",
		challenge:      nil,
		format:         "",
		cose:           nil,
		spki:           nil,
	}.withNewKey(t)
}

// withNewKey gives the authenticator a fresh ES256 credential key.
func (a authenticator) withNewKey(t *testing.T) authenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	a.cose, err = ctap2().Marshal(map[int64]any{
		1: 2, 3: -7, -1: 1,
		-2: key.X.FillBytes(make([]byte, 32)),
		-3: key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("cose: %v", err)
	}

	a.spki, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("spki: %v", err)
	}

	return a
}

func ctap2() cbor.EncMode {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}

	return mode
}

// authData is the authenticator data with attested credential data.
func (a authenticator) authData() []byte {
	hash := sha256.Sum256([]byte(a.rpID))

	authData := make([]byte, 0, len(hash)+1+4+16+2+len(a.credID))
	authData = append(authData, hash[:]...)
	authData = append(authData, a.flags)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, a.aaguid[:]...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(min(len(a.credID), 1023)))
	authData = append(authData, a.credID...)
	authData = append(authData, a.cose...)

	return authData
}

// attestationObject is an attestation over the credential's key.
func (a authenticator) attestationObject(t *testing.T) []byte {
	t.Helper()

	format := a.format
	if format == "" {
		format = "none"
	}

	object, err := ctap2().Marshal(map[string]any{"fmt": format, "attStmt": map[string]any{}, "authData": a.authData()})
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}

	return object
}

// clientData is the clientDataJSON the browser would write for options.
func (a authenticator) clientData(t *testing.T, options creationOptions) []byte {
	t.Helper()

	echoed := a.challenge
	if echoed == nil {
		echoed = unb64(t, options.PublicKey.Challenge)
	}

	typ := a.clientDataType
	if typ == "" {
		typ = "webauthn.create"
	}

	return []byte(mustJSON(map[string]any{
		"type": typ, "challenge": b64(echoed), "origin": a.origin,
	}))
}

// respond builds the finish request a browser would post for options, for the
// invitation token and name it was begun with.
func (a authenticator) respond(t *testing.T, options creationOptions) jsonBody {
	t.Helper()

	id := b64(a.credID)

	return jsonBody{
		"invitationCode": testCode,
		"name":           testName,
		"email":          testEmail,
		"credential": jsonBody{
			"id": id, "rawId": id, "type": "public-key",
			"response": jsonBody{
				"clientDataJSON":    b64(a.clientData(t, options)),
				"attestationObject": b64(a.attestationObject(t)),
				"transports":        a.transports,
			},
			"clientExtensionResults": jsonBody{},
		},
	}
}

// finish posts a finish body.
func (r *rig) finish(body jsonBody) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.post(registration.PathFinish, mustJSON(body))
}

// ceremony is a full registration: begin, then the authenticator's answer.
func (r *rig) ceremony(a authenticator) jsonBody {
	r.t.Helper()

	return a.respond(r.t, r.beginOK())
}

// forgeChallenge creates a challenge the way begin would, with whatever key,
// expiry and associated data the test chooses.
func forgeChallenge(t *testing.T, key []byte, expires time.Time, ad ...[]byte) []byte {
	t.Helper()

	made, _, err := challenge.Create(key, counterEntropy(), expires, ad...)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	return made
}

// registrationAD is the associated data a registration challenge is bound to.
func registrationAD(code, name, email string) [][]byte {
	return [][]byte{[]byte(code), []byte(name), []byte(email)}
}

// wantFailure checks the status and the exact body of a failure response, and
// that it was logged once under code with no cookies set.
func wantFailure(t *testing.T, r *rig, rec *httptest.ResponseRecorder, status int, body, code string) {
	t.Helper()

	if rec.Code != status || rec.Body.String() != body {
		t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), status, body)
	}

	if got := rec.Header().Get("Cache-Control"); got != cacheNoStore {
		t.Errorf("Cache-Control = %q, want no-store", got)
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

// invalidToken is a value of the invitationCode member that is not an
// invitation token.
type invalidToken struct{ name, value string }

// invalidInvitationTokens are values that must be refused as malformed (400
// invalid_invitation) before the store is touched, whatever the route. Each is
// derived from testCode, so a case differs from a valid token in one respect.
func invalidInvitationTokens() []invalidToken {
	prefix := secret.Prefix(secret.TagInvitation)
	body := strings.TrimPrefix(testCode, prefix)
	last := len(testCode) - 1

	// A token whose last body character is not zero in its two low bits is one
	// of four spellings of the same 256 bits.
	noncanonical := func(c string) string { return testCode[:last] + c }

	return []invalidToken{
		{"empty", ""},
		{"a session token", secret.Prefix(secret.TagSession) + body},
		{"an API key", secret.Prefix(secret.TagAPIKey) + body},
		{"an unknown tag", "susu_xyz_" + body},
		{"uppercase prefix", strings.ToUpper(prefix) + body},
		{"capitalised prefix", "Susu_inv_" + body},
		{"another brand", "xusu_inv_" + body},
		{"no prefix", body},
		{"the tag only", "inv_" + body},
		{"prefix without a body", prefix},
		{"prefix twice", prefix + testCode},
		{"body one character short", testCode[:last]},
		{"body one character long", testCode + "A"},
		{"body doubled", testCode + body},
		{"padding after the body", testCode + "="},
		{"padding in place of the last character", testCode[:last] + "="},
		{"two padding characters", testCode[:last-1] + "=="},
		{"leading space", " " + testCode},
		{"trailing space", testCode + " "},
		{"trailing newline", testCode + "\n"},
		{"trailing carriage return and newline", testCode + "\r\n"},
		{"embedded newline", testCode[:20] + "\n" + testCode[21:]},
		{"leading tab", "\t" + testCode},
		{"NUL at the end", testCode + "\x00"},
		{"NUL in the body", testCode[:20] + "\x00" + testCode[21:]},
		{"non-ASCII in place of two characters", testCode[:20] + "\u00e9" + testCode[22:]},
		{"non-ASCII appended", testCode + "\u00e9"},
		{"full-width letter in the body", testCode[:20] + "\uff21" + testCode[23:]},
		{"standard base64 plus", testCode[:20] + "+" + testCode[21:]},
		{"standard base64 slash", testCode[:20] + "/" + testCode[21:]},
		{"a dot in the body", testCode[:20] + "." + testCode[21:]},
		{"last character with bit 0 set", noncanonical("B")},
		{"last character with bit 1 set", noncanonical("C")},
		{"last character with both low bits set", noncanonical("D")},
		{"last character 9", noncanonical("9")},
		{"last character _", noncanonical("_")},
		{"huge", strings.Repeat("A", 3000)},
		{"huge with the right prefix", prefix + strings.Repeat("A", 3000)},
	}
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

// mustName parses an account name the test knows is valid.
func mustOrgName(t *testing.T, raw string) input.OrgName {
	t.Helper()

	name, err := input.ParseOrgName(raw)
	if err != nil {
		t.Fatalf("organization name: %v", err)
	}

	return name
}

func mustName(t *testing.T, raw string) input.AccountName {
	t.Helper()

	name, err := input.ParseAccountName(raw)
	if err != nil {
		t.Fatalf("name: %v", err)
	}

	return name
}

// mustEmail parses an email address the test knows is valid.
func mustEmail(t *testing.T, raw string) input.Email {
	t.Helper()

	email, err := input.ParseEmail(raw)
	if err != nil {
		t.Fatalf("email: %v", err)
	}

	return email
}

// mustToken parses an invitation token the test knows is valid.
func mustToken(t *testing.T, raw string) input.InvitationToken {
	t.Helper()

	token, err := input.ParseInvitationToken(raw)
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	return token
}

// asToJSONWrites sets the members PublicKeyCredential.toJSON() adds to a
// registration response, derived from the authenticator: the attachment, a copy
// of the authenticator data, the public key as DER and its algorithm.
func (a authenticator) asToJSONWrites(body jsonBody) {
	body.set("credential.authenticatorAttachment", "platform")
	body.set("credential.response.authenticatorData", b64(a.authData()))
	body.set("credential.response.publicKey", b64(a.spki))
	body.set("credential.response.publicKeyAlgorithm", -7)
}

// wantQuietSuccess checks what every successful response has in common: JSON,
// not cacheable, no cookie, and nothing logged.
func wantQuietSuccess(t *testing.T, r *rig, rec *httptest.ResponseRecorder) {
	t.Helper()

	if got := rec.Header().Get("Content-Type"); got != jsonType {
		t.Errorf("Content-Type = %q, want %q", got, jsonType)
	}

	if got := rec.Header().Get("Cache-Control"); got != cacheNoStore {
		t.Errorf("Cache-Control = %q, want %s", got, cacheNoStore)
	}

	if len(rec.Result().Cookies()) != 0 || len(r.logged) != 0 {
		t.Errorf("cookies %v, logged %v: registering issues no session and logs nothing",
			rec.Result().Cookies(), r.logged)
	}
}

// migrationLimits reads the numbers a CHECK of the migrations states, by a
// pattern whose capture groups are the numbers, over the migrations' text with
// whitespace collapsed. A pattern that matches nothing fails the test, so a
// reworded migration is noticed.
func migrationLimits(t *testing.T, pattern string) []int {
	t.Helper()

	paths, err := filepath.Glob("../../migrations/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}

	var text strings.Builder

	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // the paths are a glob of the repository's own migrations
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		text.Write(raw)
		text.WriteString("\n")
	}

	match := regexp.MustCompile(pattern).FindStringSubmatch(strings.Join(strings.Fields(text.String()), " "))
	if match == nil {
		t.Fatalf("no CHECK matches %s; was the migration text changed?", pattern)
	}

	limits := make([]int, 0, len(match)-1)

	for _, captured := range match[1:] {
		number, err := strconv.Atoi(captured)
		if err != nil {
			t.Fatalf("limit %q: %v", captured, err)
		}

		limits = append(limits, number)
	}

	return limits
}
