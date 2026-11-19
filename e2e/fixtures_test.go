//go:build e2e

package e2e_test

// fixtures_test.go is the one fixtures file of this package (docs/TESTING.md,
// "Unit tests"): the HTTP client, the software passkey that plays the browser and
// authenticator, and the builders that put the database into a known state.
//
// Principles every test file follows:
//
//   - A test states the state it needs by calling reset (empty deployment) and
//     the builders below, never by relying on what an earlier test left.
//   - Behaviour under test is always an HTTP request to the Worker. The
//     database side channel (db_test.go) only prepares state and reads it back.
//   - Requests carry the session as a raw Cookie header: the cookie is Secure
//     and the Worker is served over plain http, so a cookie jar would not send it.

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
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Routes and names the tests share.
const (
	pathHealth        = "/healthz"
	pathFirstRun      = "/api/first-run"
	pathRegisterBegin = "/api/register/begin"
	pathRegisterEnd   = "/api/register/finish"
	pathLoginBegin    = "/api/login/begin"
	pathLoginEnd      = "/api/login/finish"
	pathSession       = "/api/session"
	pathLogout        = "/api/logout"
	pathAgent         = "/api/agent"
	pathInvitation    = "/api/invitation"
	pathUser          = "/api/user"

	cookieName = "__Host-session"
	jsonType   = "application/json"

	roleAdmin  = "admin"
	roleMember = "e2e_member" // a role no route treats as an administrator
)

// Error codes the tests assert on. They are part of the API's contract.
const (
	codeUnauthenticated = "unauthenticated"
	codeForbidden       = "forbidden"
	codeInvalidID       = "invalid_id"
	codeInvalidLogin    = "invalid_login"
	codeBodyTooLarge    = "body_too_large"
	codeUnsupportedType = "unsupported_media_type"
	codeNotFound        = "not_found"
	codeMethodNotAllow  = "method_not_allowed"
	codeUnknownField    = "unknown_field"
)

// transportInternal is the transport a platform authenticator reports.
const transportInternal = "internal"

// Member names of the WebAuthn JSON bodies.
const (
	memberChallenge      = "challenge"
	memberInvitationCode = "invitationCode"
	memberName           = "name"
	memberClientData     = "clientDataJSON"
	memberAttStmt        = "attStmt"
	memberFmt            = "fmt"
	memberType           = "type"
	formatNone           = "none"
	typeCreate           = "webauthn.create"
	typeGet              = "webauthn.get"
	memberCrossOrigin    = "crossOrigin"
	memberOrigin         = "origin"
	memberAuthDataBytes  = "authData"
	memberAuthData       = "authenticatorData"
	memberSignature      = "signature"
	memberUserHandle     = "userHandle"
)

// ---- HTTP ------------------------------------------------------------------

// reply is a response with its Set-Cookie lines kept raw.
type reply struct {
	status     int
	body       string
	header     http.Header
	setCookies []string
}

// request describes one HTTP request to the Worker. The zero value is a GET
// with no body, no cookie and no extra headers.
type request struct {
	method string
	path   string
	body   []byte
	// token is the session token, sent as the session cookie.
	token string
	// bearer is an API key, sent as "Authorization: Bearer <bearer>".
	bearer string
	// headers are set after the defaults, so they can replace Content-Type or
	// Cookie. A header set to "" is removed.
	headers map[string]string
	// noType omits the default Content-Type of an unsafe method.
	noType bool
}

// build turns r into an http.Request against the Worker.
func (r request) build(t *testing.T) *http.Request {
	t.Helper()

	method := r.method
	if method == "" {
		method = http.MethodGet
	}

	var reader io.Reader = http.NoBody
	if r.body != nil {
		reader = bytes.NewReader(r.body)
	}

	// Not t.Context(): that is cancelled before t.Cleanup callbacks run.
	req, err := http.NewRequestWithContext(context.Background(), method, target.baseURL+r.path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	safe := method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
	if !safe && !r.noType {
		req.Header.Set("Content-Type", jsonType)
	}

	r.applyHeaders(req)

	return req
}

// applyHeaders sets the session cookie and then the explicit headers, which win.
func (r request) applyHeaders(req *http.Request) {
	if r.token != "" {
		req.Header.Set("Cookie", cookieName+"="+r.token)
	}

	if r.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearer)
	}

	for name, value := range r.headers {
		if value == "" {
			req.Header.Del(name)

			continue
		}

		req.Header.Set(name, value)
	}
}

// send performs the request against the Worker.
func send(t *testing.T, r request) reply {
	t.Helper()

	req := r.build(t)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, r.path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	return reply{
		status: resp.StatusCode, body: string(data), header: resp.Header,
		setCookies: resp.Header.Values("Set-Cookie"),
	}
}

// get, post, patch and del are the common shapes of send.
func get(t *testing.T, path, token string) reply {
	t.Helper()

	return send(t, request{method: http.MethodGet, path: path, token: token})
}

func post(t *testing.T, path string, body []byte, token string) reply {
	t.Helper()

	return send(t, request{method: http.MethodPost, path: path, body: body, token: token})
}

func patch(t *testing.T, path string, body []byte, token string) reply {
	t.Helper()

	return send(t, request{method: http.MethodPatch, path: path, body: body, token: token})
}

func del(t *testing.T, path, token string) reply {
	t.Helper()

	return send(t, request{method: http.MethodDelete, path: path, token: token})
}

// session returns the session token the response set, or "".
func (r reply) session() string {
	for _, line := range r.setCookies {
		if value, ok := strings.CutPrefix(line, cookieName+"="); ok {
			token, _, _ := strings.Cut(value, ";")

			return token
		}
	}

	return ""
}

// errorCode returns the error code of an error response, or "" when the body is
// not one.
func (r reply) errorCode() string {
	var parsed struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}

	err := json.Unmarshal([]byte(r.body), &parsed)
	if err != nil {
		return ""
	}

	return parsed.Error.Code
}

// expect fails the test unless the reply has the status and, when code is not
// "", the error code. what names the request in the failure.
func (r reply) expect(t *testing.T, what string, status int, code string) {
	t.Helper()

	if r.status != status || (code != "" && r.errorCode() != code) {
		t.Errorf("%s = %d %s, want %d %s", what, r.status, r.body, status, code)
	}
}

// ---- the software passkey ---------------------------------------------------

// passkey is a software passkey: it plays the browser and the authenticator.
// It registers through the real endpoints and signs real assertions.
type passkey struct {
	priv   *ecdsa.PrivateKey
	credID []byte
	// handle is the WebAuthn user handle the Worker issued at registration.
	handle []byte
	// userID is the id of the account the registration created.
	userID string
}

// creationOptions is the part of the begin response a test reads.
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

// requestOptions is the part of the login begin response a test reads.
type requestOptions struct {
	PublicKey struct {
		Challenge        string   `json:"challenge"`
		RPID             string   `json:"rpId"`
		UserVerification string   `json:"userVerification"`
		Timeout          int64    `json:"timeout"`
		AllowCredentials []string `json:"allowCredentials"`
	} `json:"publicKey"`
}

// authenticator builds registration responses the way a passkey would. The
// override fields let a test send what no honest authenticator would.
type authenticator struct {
	rpID   string
	origin string
	credID []byte
	// flags are the authenticator-data flags: UP | UV | AT by default.
	flags byte
	// transports are reported in the response.
	transports []string

	// priv is the credential's key, generated when nil so a later assertion can
	// be signed with the key supplied here.
	priv *ecdsa.PrivateKey
	// cose replaces the credential public key.
	cose []byte
	// object builds the attestation object from authData instead of the
	// canonical {"fmt":"none","attStmt":{},"authData":...}.
	object func(authData []byte) []byte
	// clientData builds clientDataJSON from the challenge instead of the
	// browser's serialization.
	clientData func(challenge string) []byte
	// credIDLen overrides the credential id length written into authData.
	credIDLen *uint16
}

func newAuthenticator() authenticator {
	return authenticator{
		rpID: rpID, origin: target.origin, credID: randomBytes(32),
		flags: flagUP | flagUV | flagAT, transports: []string{transportInternal},
	}
}

// Authenticator-data flag bits.
const (
	flagUP byte = 0x01
	flagUV byte = 0x04
	flagAT byte = 0x40
)

func randomBytes(n int) []byte {
	out := make([]byte, n)

	_, err := rand.Read(out)
	if err != nil {
		panic(err) // crypto/rand does not fail
	}

	return out
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	return key
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return out
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()

	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("cbor mode: %v", err)
	}

	out, err := enc.Marshal(v)
	if err != nil {
		t.Fatalf("cbor: %v", err)
	}

	return out
}

// coseES256 is the canonical COSE_Key of an ES256 public key.
func coseES256(t *testing.T, x, y []byte) []byte {
	t.Helper()

	return mustCBOR(t, map[int64]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
}

// finishBody builds the POST /api/register/finish body answering options.
func (a authenticator) finishBody(t *testing.T, options creationOptions, code, name string) []byte {
	t.Helper()

	clientData := mustJSON(t, map[string]any{
		memberType: typeCreate, memberChallenge: options.PublicKey.Challenge,
		memberOrigin: a.origin, memberCrossOrigin: false,
	})
	if a.clientData != nil {
		clientData = a.clientData(options.PublicKey.Challenge)
	}

	id := b64(a.credID)

	return mustJSON(t, map[string]any{
		memberInvitationCode: code,
		memberName:           name,
		"credential": map[string]any{
			"id": id, "rawId": id, memberType: "public-key",
			"response": map[string]any{
				memberClientData:    b64(clientData),
				"attestationObject": b64(a.attestationObject(t)),
				"transports":        a.transports,
			},
		},
	})
}

// attestationObject is a "none" attestation over the authenticator's key.
func (a authenticator) attestationObject(t *testing.T) []byte {
	t.Helper()

	key := a.priv
	if key == nil {
		key = newKey(t)
	}

	cose := coseES256(t, key.X.FillBytes(make([]byte, 32)), key.Y.FillBytes(make([]byte, 32)))
	if a.cose != nil {
		cose = a.cose
	}

	hash := sha256.Sum256([]byte(a.rpID))

	idLen := uint16(min(len(a.credID), 1023))
	if a.credIDLen != nil {
		idLen = *a.credIDLen
	}

	authData := append([]byte(nil), hash[:]...)
	authData = append(authData, a.flags)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, idLen)
	authData = append(authData, a.credID...)
	authData = append(authData, cose...)

	if a.object != nil {
		return a.object(authData)
	}

	return mustCBOR(t, map[string]any{
		memberFmt: formatNone, memberAttStmt: map[string]any{}, memberAuthDataBytes: authData,
	})
}

// beginRegistration posts a register begin for code and name.
func beginRegistration(t *testing.T, code, name string) reply {
	t.Helper()

	return post(t, pathRegisterBegin, mustJSON(t, map[string]string{memberInvitationCode: code, memberName: name}), "")
}

// mustBeginRegistration begins a registration and decodes the options.
func mustBeginRegistration(t *testing.T, code, name string) creationOptions {
	t.Helper()

	got := beginRegistration(t, code, name)
	if got.status != http.StatusOK {
		t.Fatalf("register begin = %d %s, want 200", got.status, got.body)
	}

	var options creationOptions

	err := json.Unmarshal([]byte(got.body), &options)
	if err != nil {
		t.Fatalf("parse register begin: %v\n%s", err, got.body)
	}

	return options
}

// registered is the response of a successful registration.
type registered struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// registerWith registers a passkey for name with the first-run invitation code
// through the real endpoints, and returns it.
func registerWith(t *testing.T, name string) passkey {
	t.Helper()

	return registerWithCode(t, firstRunSecret, name)
}

// registerWithCode registers a passkey for name with an invitation code
// through the real endpoints, and returns it.
func registerWithCode(t *testing.T, code, name string) passkey {
	t.Helper()

	options := mustBeginRegistration(t, code, name)
	auth := newAuthenticator()
	auth.priv = newKey(t)

	got := post(t, pathRegisterEnd, auth.finishBody(t, options, code, name), "")
	if got.status != http.StatusCreated {
		t.Fatalf("register finish = %d %s, want 201", got.status, got.body)
	}

	var out registered

	err := json.Unmarshal([]byte(got.body), &out)
	if err != nil {
		t.Fatalf("parse register finish: %v\n%s", err, got.body)
	}

	handle, err := base64.RawURLEncoding.DecodeString(options.PublicKey.User.ID)
	if err != nil {
		t.Fatalf("user handle: %v", err)
	}

	return passkey{priv: auth.priv, credID: auth.credID, handle: handle, userID: out.UserID}
}

// newAdmin starts a fresh deployment and registers its first administrator
// through the real first-run and registration endpoints.
func newAdmin(t *testing.T) passkey {
	t.Helper()

	reset(t)

	got := get(t, pathFirstRun, "")
	if got.status != http.StatusOK || !strings.Contains(got.body, "invitation_pending") {
		t.Fatalf("first run = %d %s, want pending", got.status, got.body)
	}

	return registerWith(t, "Admin")
}

// ---- assertions ------------------------------------------------------------

// assertion is what an authenticator signs for a request ceremony. The fields
// let a test send what no honest authenticator would.
type assertion struct {
	pk     passkey
	rpID   string
	origin string
	flags  byte
	handle []byte
	// challenge replaces the challenge the browser echoes in clientDataJSON.
	challenge []byte
	// key signs the assertion: the passkey's own when nil.
	key *ecdsa.PrivateKey
	// typ is the clientData type: webauthn.get when empty.
	typ string
}

func (pk passkey) assertion() assertion {
	return assertion{pk: pk, rpID: rpID, origin: target.origin, flags: flagUP | flagUV, handle: pk.handle}
}

// signedLogin is a signed answer to one set of options, kept in parts so a test
// can change any of them after signing.
type signedLogin struct {
	pk       passkey
	client   []byte
	authData []byte
	sig      []byte
}

// authDataPrefix is the 37 bytes of authenticator data: RP ID hash, flags and a
// zero counter.
func (a assertion) authDataPrefix() []byte {
	hash := sha256.Sum256([]byte(a.rpID))

	out := append([]byte(nil), hash[:]...)
	out = append(out, a.flags)

	return binary.BigEndian.AppendUint32(out, 0)
}

// clientDataFor is the clientDataJSON the browser would write for options.
func (a assertion) clientDataFor(t *testing.T, options requestOptions) []byte {
	t.Helper()

	challenge := a.challenge
	if challenge == nil {
		var err error

		challenge, err = base64.RawURLEncoding.DecodeString(options.PublicKey.Challenge)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
	}

	typ := a.typ
	if typ == "" {
		typ = typeGet
	}

	return mustJSON(t, map[string]any{
		memberType: typ, memberChallenge: b64(challenge), memberOrigin: a.origin, memberCrossOrigin: false,
	})
}

// sign answers options, signing over client (the default clientDataJSON when
// nil).
func (a assertion) sign(t *testing.T, options requestOptions, client []byte) signedLogin {
	t.Helper()

	if client == nil {
		client = a.clientDataFor(t, options)
	}

	authData := a.authDataPrefix()
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))

	key := a.key
	if key == nil {
		key = a.pk.priv
	}

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signedLogin{pk: a.pk, client: client, authData: authData, sig: sig}
}

// body is the finish request for s, with extra top-level members merged in. The
// handle is the passkey's unless s.pk.handle was changed by the test.
func (s signedLogin) body(t *testing.T, extra map[string]any) []byte {
	t.Helper()

	id := b64(s.pk.credID)
	members := map[string]any{
		"id": id, "rawId": id, memberType: "public-key",
		"response": map[string]any{
			memberClientData: b64(s.client),
			memberAuthData:   b64(s.authData),
			memberSignature:  b64(s.sig),
			memberUserHandle: b64(s.pk.handle),
		},
	}

	maps.Copy(members, extra)

	return mustJSON(t, members)
}

// withSig returns s with its signature replaced.
func (s signedLogin) withSig(sig []byte) signedLogin {
	s.sig = sig

	return s
}

// beginLogin runs login begin and decodes the options.
func beginLogin(t *testing.T) requestOptions {
	t.Helper()

	got := post(t, pathLoginBegin, nil, "")
	if got.status != http.StatusOK {
		t.Fatalf("login begin = %d %s, want 200", got.status, got.body)
	}

	var options requestOptions

	err := json.Unmarshal([]byte(got.body), &options)
	if err != nil {
		t.Fatalf("parse login begin: %v\n%s", err, got.body)
	}

	return options
}

// login runs a complete, honest login and returns the session token.
func login(t *testing.T, pk passkey) string {
	t.Helper()

	got := post(t, pathLoginEnd, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil), "")
	if got.status != http.StatusOK {
		t.Fatalf("login finish = %d %s, want 200", got.status, got.body)
	}

	token := got.session()
	if token == "" {
		t.Fatalf("login set no session cookie: %v", got.setCookies)
	}

	return token
}

// ---- secrets ----------------------------------------------------------------

// Tokens are "susu_<tag>_" and 43 base64url characters (docs/secrets_design.md).
// The tests build them here, independently of the Worker's code, so a token the
// Worker issues is checked against this definition and not against itself.
const (
	tokenBodyBytes = 32
	tokenBodyLen   = 43

	tagInvitation = "inv"
	tagSession    = "ses"
	tagAPIKey     = "key"

	// The kind each secret has in secrets.kind and the table of its own that
	// holds the rest of it.
	kindInvitation = "invitation"
	kindSession    = "session"
	kindAPIKey     = "api_key"
)

// tokenPrefix is what every token of a tag starts with.
func tokenPrefix(tag string) string { return "susu_" + tag + "_" }

// newToken returns a fresh random token of the tag.
func newToken(tag string) string {
	return tokenPrefix(tag) + b64(randomBytes(tokenBodyBytes))
}

// tokenHash is what the Worker stores for a token: SHA-256 of the whole string,
// prefix included.
func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))

	return sum[:]
}

// kindTable is the table that holds a kind's own rows.
func kindTable(kind string) string {
	switch kind {
	case kindInvitation:
		return tableInvitations
	case kindSession:
		return tableSessions
	case kindAPIKey:
		return tableKeys
	default:
		panic("unknown secret kind " + kind)
	}
}

// secretRow is a row of the secrets table, found by the token that hashes to it.
type secretRow struct {
	// found is false when no secret has the token's hash; nothing else is set.
	found bool
	id    string
	kind  string
	// expiresAt, createdAt are Unix seconds.
	expiresAt int64
	createdAt int64
	// revoked is whether revoked_at is set at all, and revokedAt its value.
	revoked   bool
	revokedAt int64
	// kindRow is whether the kind's own table has a row under the same id.
	kindRow bool
}

// secretOf finds a token's secret row by hashing the whole token string, the
// way the Worker finds it, and reads the row back.
func secretOf(t *testing.T, token string) secretRow {
	t.Helper()

	cells, ok := firstRow(t,
		"SELECT id, kind, expires_at, ifnull(revoked_at, 'NULL'), created_at FROM secrets WHERE hash = ?",
		tokenHash(token))
	if !ok {
		return secretRow{}
	}

	out := secretRow{
		found: true, id: cells[0], kind: cells[1], expiresAt: parseInt(t, cells[2]), createdAt: parseInt(t, cells[4]),
	}

	if cells[3] != "NULL" {
		out.revoked, out.revokedAt = true, parseInt(t, cells[3])
	}

	out.kindRow = count(t, kindTable(out.kind)+" WHERE id = ?", out.id) == "1"

	return out
}

// mustSecretOf is secretOf for a token that must be stored.
func mustSecretOf(t *testing.T, token string) secretRow {
	t.Helper()

	got := secretOf(t, token)
	if !got.found {
		t.Fatalf("no secret is stored under the hash of %.16s...", token)
	}

	return got
}

// idOfToken returns the secret id of a token the Worker issued.
func idOfToken(t *testing.T, token string) string {
	t.Helper()

	return mustSecretOf(t, token).id
}

// expectToken fails the test unless token is exactly "susu_<tag>_" and 43
// canonical base64url characters: 32 bytes with no stray bits in the last one.
func expectToken(t *testing.T, token, tag string) {
	t.Helper()

	body, ok := strings.CutPrefix(token, tokenPrefix(tag))
	if !ok || len(body) != tokenBodyLen {
		t.Errorf("token %.20q... is not %s and %d characters", token, tokenPrefix(tag), tokenBodyLen)

		return
	}

	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(raw) != tokenBodyBytes {
		t.Errorf("token body %q is not canonical base64url of %d bytes: %v", body, tokenBodyBytes, err)
	}
}

// expectStoredNowhere fails the test if any column of any table holds a token,
// or its body, or the 32 random bytes the body encodes, as text or as bytes.
// What is stored is the hash; the token itself must not be recoverable.
func expectStoredNowhere(t *testing.T, tokens ...string) {
	t.Helper()

	needles := make([]string, 0, 3*len(tokens))

	for _, token := range tokens {
		_, body, _ := strings.Cut(strings.TrimPrefix(token, "susu_"), "_")
		raw, _ := base64.RawURLEncoding.DecodeString(body)

		needles = append(needles, token, body, string(raw))
	}

	for _, column := range columnsHolding(t, needles...) {
		t.Errorf("%s holds a token in the clear", column)
	}
}

// expectNoOrphanSecrets fails the test if a secret has no row in its kind's own
// table, which is how a batch that wrote the secret and lost the rest would
// show.
func expectNoOrphanSecrets(t *testing.T) {
	t.Helper()

	for _, kind := range []string{kindInvitation, kindSession, kindAPIKey} {
		expectCount(t, "secrets WHERE kind = ? AND id NOT IN (SELECT id FROM "+kindTable(kind)+")", "0", kind)
	}

	expectCount(t, "secrets WHERE kind NOT IN (?, ?, ?)", "0", kindInvitation, kindSession, kindAPIKey)
}

func parseInt(t *testing.T, text string) int64 {
	t.Helper()

	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		t.Fatalf("not an integer: %q", text)
	}

	return n
}

// ---- state builders (seeds) -------------------------------------------------

// Deterministic ids for seeded rows. Ids are UUIDv7-shaped and lower case, as
// the schema's CHECK and the Worker's parser require. Tests that need many use
// idN.
const (
	idInvitationA = "00000000-0000-7000-8000-00000000a001"
	idInvitationB = "00000000-0000-7000-8000-00000000a002"
	idUserB       = "00000000-0000-7000-8000-00000000b001"
	idUserC       = "00000000-0000-7000-8000-00000000b002"
	idAgentA      = "00000000-0000-7000-8000-00000000d001"
	idAgentB      = "00000000-0000-7000-8000-00000000d002"

	// idMissing is a well-formed id no builder ever uses.
	idMissing = "00000000-0000-7000-8000-00000000ffff"
)

// idN returns the n-th id of a family: prefix is the family's 4 hex digits.
func idN(prefix string, n int) string {
	const digits = "0123456789abcdef"

	suffix := []byte("000000000000")

	for pos := len(suffix) - 1; n > 0 && pos >= 0; pos-- {
		suffix[pos] = digits[n%16]
		n /= 16
	}

	return "00000000-0000-7000-8000-" + prefix + string(suffix[4:])
}

// Joins that let a condition name a key's or an owner's columns together with
// its secret's, for the tests that count rows by state. revoked_at and
// expires_at are the secret's; user_id, agent_id and scope are the key's, and
// user_id the session's. Qualify id and kind (k.id, s.id).
const (
	// keyRows is every API key with its secret.
	keyRows = "api_keys k JOIN secrets s ON s.id = k.id"

	// ownedSecrets is every session and API key secret with its owner's id as
	// user_id, so a condition can cover "everything this user holds".
	ownedSecrets = "secrets s JOIN " +
		"(SELECT id, user_id FROM sessions UNION ALL SELECT id, user_id FROM api_keys) o ON o.id = s.id"
)

// seedLifetime is how long a seeded secret lasts: long enough that no test
// outlives it, short enough to read as "valid for a while" in a failure.
const seedLifetime = 24 * 60 * 60

// seedSecret inserts a secret of kind for token, valid for seedLifetime seconds
// from the database's now. The kind's own row is the caller's. Only the token's
// hash is stored, as the Worker does.
func seedSecret(t *testing.T, id, kind, token string) {
	t.Helper()

	seed(t, "INSERT INTO secrets (id, kind, hash, expires_at, created_at) "+
		"VALUES (?, ?, ?, strftime('%s','now') + ?, strftime('%s','now'))", id, kind, tokenHash(token), seedLifetime)
}

// seedInvitation inserts an invitation of type 'e2e_invite' (no role, never
// redeemable through registration) with a token of its own, and returns the
// token. It lasts seedLifetime.
func seedInvitation(t *testing.T, id string, numInvites int) string {
	t.Helper()

	token := newToken(tagInvitation)

	seedSecret(t, id, kindInvitation, token)
	seed(t, "INSERT INTO invitations (id, type, label, num_invites) VALUES (?, 'e2e_invite', 'seeded', ?)", id, numInvites)

	return token
}

// seedUsers makes n accounts of role e2e_none that came from the invitation.
func seedUsers(t *testing.T, invitation string, n int) {
	t.Helper()

	for i := range n {
		seed(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) "+
			"VALUES (?, randomblob(16), 'e2e_none', ?, strftime('%s','now'))", idN("0b00", i+1), invitation)
	}
}

// seedUser inserts an account with role, redeemed from any existing invitation
// so its foreign key holds. Its profile is {"name":"seeded"}.
func seedUser(t *testing.T, id, role string) {
	t.Helper()

	seed(t, "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) "+
		"VALUES (?, randomblob(16), ?, (SELECT id FROM invitations LIMIT 1), '{\"name\":\"seeded\"}', strftime('%s','now'))",
		id, role)
}

// seedAgent inserts an agent for owner with no key.
func seedAgent(t *testing.T, id, owner, name string) {
	t.Helper()

	seed(t, "INSERT INTO agents (id, user_id, name, scopes, created_at) "+
		"VALUES (?, ?, ?, '[\"default:agent\"]', strftime('%s','now'))", id, owner, name)
}

// agentScope is the scope list of seeded agents and of their seeded keys.
const agentScope = `["default:agent"]`

// seedAPIKey inserts an API key for owner with a token of its own, and returns
// the token. agent is the agent it belongs to, or "" for the user's own key. It
// lasts seedLifetime and carries agentScope.
func seedAPIKey(t *testing.T, id, owner, agent string) string {
	t.Helper()

	token := newToken(tagAPIKey)

	seedSecret(t, id, kindAPIKey, token)

	var agentID any
	if agent != "" {
		agentID = agent
	}

	seed(t, "INSERT INTO api_keys (id, user_id, agent_id, scope) VALUES (?, ?, ?, ?)", id, owner, agentID, agentScope)

	return token
}

// seedSession inserts a session for a user, on a passkey of its own that the
// seed adds, and returns its token. The login it records is random, so it never
// collides with a real one.
func seedSession(t *testing.T, id, user string) string {
	t.Helper()

	token := newToken(tagSession)

	seed(t, "INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at) "+
		"VALUES (?, randomblob(32), ?, randomblob(77), 0, '{}', strftime('%s','now'))", id, user)
	seedSecret(t, id, kindSession, token)
	seed(t, "INSERT INTO sessions (id, user_id, credential_id, granted_from) "+
		"VALUES (?, ?, ?, randomblob(32))", id, user, id)

	return token
}

// setRole changes an account's role behind the Worker's back.
func setRole(t *testing.T, id, role string) {
	t.Helper()

	seed(t, "UPDATE users SET role = ? WHERE id = ?", role, id)
}
