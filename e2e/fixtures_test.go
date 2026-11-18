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

// kidOf returns the key id in a token's header: how the session row is found
// without parsing the whole JWT.
func kidOf(t *testing.T, token string) string {
	t.Helper()

	header, _, _ := strings.Cut(token, ".")

	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("token header: %v", err)
	}

	var parsed struct {
		Kid string `json:"kid"`
	}

	err = json.Unmarshal(raw, &parsed)
	if err != nil || parsed.Kid == "" {
		t.Fatalf("token header %s: %v", raw, err)
	}

	return parsed.Kid
}

// claimsOf decodes a JWT's claims without verifying it.
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q has %d parts, want 3", token, len(parts))
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims map[string]any

	err = json.Unmarshal(raw, &claims)
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	return claims
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

// seedInvitation inserts an invitation of type 'e2e_invite' (no role, never
// redeemable through registration) with its own distinct code hash.
func seedInvitation(t *testing.T, id string, numInvites int) {
	t.Helper()

	seed(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at) "+
		"VALUES (?, randomblob(32), 'e2e_invite', 'seeded', ?, strftime('%s','now'))", id, numInvites)
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
		"VALUES (?, ?, ?, 'default:agent', strftime('%s','now'))", id, owner, name)
}

// seedAgentKey inserts an API key row for an agent, so a test can see
// revocation reach it. It is a row only: it never verifies.
func seedAgentKey(t *testing.T, kid, owner, agent string) {
	t.Helper()

	seed(t, "INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, agent_id, scope, created_at) "+
		"VALUES (?, ?, 'api_key', '{}', strftime('%s','now') + 3600, ?, 'default:agent', strftime('%s','now'))",
		kid, owner, agent)
}

// seedSession inserts a session key row for a user, so a test can see
// revocation reach it. It is a row only: it never verifies.
func seedSession(t *testing.T, kid, user string) {
	t.Helper()

	seed(t, "INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, created_at) "+
		"VALUES (?, ?, 'session', '{}', strftime('%s','now') + 3600, strftime('%s','now'))", kid, user)
}

// setRole changes an account's role behind the Worker's back.
func setRole(t *testing.T, id, role string) {
	t.Helper()

	seed(t, "UPDATE users SET role = ? WHERE id = ?", role, id)
}
