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
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// This file drives passkey login against the real Worker. The unit tests fake
// the database, so these are what prove the SQL: the credential lookup, the
// session insert and the unique grant that makes a login single use.
//
// The test plays the browser and authenticator. It registers a real passkey
// through the real registration endpoints (so the stored credential is exactly
// what registration writes), then signs real assertions with it. Nothing about
// the Worker is mocked.
//
// The session cookie is Secure and the e2e origin is plain http on localhost,
// so a cookie jar would refuse to send it back. The tests therefore read
// Set-Cookie themselves, which also lets them check the raw attributes, and
// send the Cookie header by hand.

const (
	typeMember   = "type"
	garbageToken = "garbage"
	loginPath    = "/api/login"
	sessionPath  = "/api/session"
	logoutPath   = "/api/logout"
	cookieName   = "__Host-session"
	codeInvalid  = "invalid_login"
	codeNoAuth   = "unauthenticated"
	// jsonContentType is what the frontend sends on every unsafe request, and
	// what the Worker requires of one.
	jsonContentType = "application/json"
)

// passkey is a software passkey registered with the Worker.
type passkey struct {
	priv   *ecdsa.PrivateKey
	credID []byte
	handle []byte
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string   `json:"challenge"`
		RPID             string   `json:"rpId"`
		UserVerification string   `json:"userVerification"`
		Timeout          int64    `json:"timeout"`
		AllowCredentials []string `json:"allowCredentials"`
	} `json:"publicKey"`
}

// registerPasskey creates the first administrator through the real
// registration endpoints and returns the passkey it registered. It clears the
// users, credentials, invitations and keys first, so it can be called more than
// once.
func registerPasskey(t *testing.T) passkey {
	t.Helper()

	query(t, "DELETE FROM japikeys")
	query(t, "DELETE FROM credentials")
	query(t, "DELETE FROM users")
	query(t, "DELETE FROM invitations")

	expectFirstRun(t, pendingBody)

	options := mustBegin(t, "Login Tester")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	auth := newAuthenticator()
	auth.priv = priv

	status, body := postJSON(t, registerPath+"/finish", auth.finishBody(t, options, firstRunSecret, "Login Tester"))
	if status != http.StatusCreated {
		t.Fatalf("register = %d %s, want 201", status, body)
	}

	handle, err := base64.RawURLEncoding.DecodeString(options.PublicKey.User.ID)
	if err != nil {
		t.Fatalf("user handle: %v", err)
	}

	return passkey{priv: priv, credID: auth.credID, handle: handle}
}

func beginLogin(t *testing.T) requestOptions {
	t.Helper()

	status, body := postJSON(t, loginPath+"/begin", nil)
	if status != http.StatusOK {
		t.Fatalf("login begin = %d %s, want 200", status, body)
	}

	var options requestOptions

	err := json.Unmarshal([]byte(body), &options)
	if err != nil {
		t.Fatalf("parse login begin: %v\n%s", err, body)
	}

	return options
}

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
	// key signs the assertion; the passkey's own when nil.
	key *ecdsa.PrivateKey
	// typ is the clientData type; webauthn.get when empty.
	typ string
}

func (pk passkey) assertion() assertion {
	return assertion{
		pk: pk, rpID: rpID, origin: target.origin,
		// UP | UV
		flags: 0x01 | 0x04, handle: pk.handle,
	}
}

// body builds the POST /api/login/finish body answering options.
func (a assertion) body(t *testing.T, options requestOptions) []byte {
	t.Helper()

	client := a.clientData(t, options)

	authData := append([]byte(nil), a.authDataPrefix()...)

	key := a.key
	if key == nil {
		key = a.pk.priv
	}

	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))

	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	id := base64.RawURLEncoding.EncodeToString(a.pk.credID)

	body, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, typeMember: "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(client),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(a.handle),
		},
	})
	if err != nil {
		t.Fatalf("finish body: %v", err)
	}

	return body
}

// clientData is the clientDataJSON the browser would write for options.
func (a assertion) clientData(t *testing.T, options requestOptions) []byte {
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
		typ = "webauthn.get"
	}

	client, err := json.Marshal(map[string]any{
		typeMember:    typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      a.origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	return client
}

// authDataPrefix is the 37 bytes of authenticator data: the RP ID hash, the
// flags and a zero counter.
func (a assertion) authDataPrefix() []byte {
	hash := sha256.Sum256([]byte(a.rpID))

	out := append([]byte(nil), hash[:]...)
	out = append(out, a.flags)

	return binary.BigEndian.AppendUint32(out, 0)
}

// reply is an HTTP response with its Set-Cookie headers kept raw.
type reply struct {
	status     int
	body       string
	setCookies []string
	header     http.Header
}

// session returns the session token the response set, or "".
func (r reply) session() string {
	prefix := cookieName + "="

	for _, line := range r.setCookies {
		if value, ok := strings.CutPrefix(line, prefix); ok {
			token, _, _ := strings.Cut(value, ";")

			return token
		}
	}

	return ""
}

// call sends a request with an optional session cookie.
func call(t *testing.T, method, path string, body []byte, token string) reply {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, target.baseURL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	if method != http.MethodGet {
		req.Header.Set("Content-Type", jsonContentType)
	}

	if token != "" {
		req.Header.Set("Cookie", cookieName+"="+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	return reply{
		status: resp.StatusCode, body: string(data),
		setCookies: resp.Header.Values("Set-Cookie"), header: resp.Header,
	}
}

// login runs a complete, honest login and returns the session token.
func login(t *testing.T, pk passkey) string {
	t.Helper()

	options := beginLogin(t)

	got := call(t, http.MethodPost, loginPath+"/finish", pk.assertion().body(t, options), "")
	if got.status != http.StatusOK {
		t.Fatalf("login finish = %d %s, want 200", got.status, got.body)
	}

	token := got.session()
	if token == "" {
		t.Fatalf("login set no session cookie: %v", got.setCookies)
	}

	return token
}

// kidOf returns the key id in a token's header, which is how the session row is
// found without parsing the whole JWT.
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

// TestLogin walks passkey login against the real Worker, TinyGo build and D1:
// begin, every refusal (which must write nothing), the accepted login, and the
// replay that must be refused. It registers a passkey first, through the real
// registration endpoints, so it must run after the registration tests; it
// resets the users, credentials, invitations and keys itself.
//
//nolint:paralleltest // shares one database with the other tests; the steps are ordered
func TestLogin(t *testing.T) {
	pk := registerPasskey(t)

	t.Run("begin is stateless and usernameless", func(t *testing.T) { beginIsStatelessAndUsernameless(t) })
	t.Run("refusals write nothing", func(t *testing.T) { loginRefusalsWriteNothing(t, pk) })
	t.Run("login issues a session", loginIssuesASession(pk))
	t.Run("a captured login cannot be replayed", replayIsRefused(pk))
	t.Run("two honest logins both work", twoLoginsBothWork(pk))
}

func beginIsStatelessAndUsernameless(t *testing.T) {
	t.Helper()

	options := beginLogin(t)
	pk := options.PublicKey

	if pk.RPID != rpID || pk.UserVerification != "required" {
		t.Errorf("options = %+v", pk)
	}

	// An empty list is what makes login usernameless.
	if pk.AllowCredentials == nil || len(pk.AllowCredentials) != 0 {
		t.Errorf("allowCredentials = %#v, want an empty list", pk.AllowCredentials)
	}

	if beginLogin(t).PublicKey.Challenge == pk.Challenge {
		t.Error("two begins returned the same challenge")
	}

	expectCount(t, "japikeys", "0")
}

// loginRefusal is a finish request the Worker must refuse without writing.
type loginRefusal struct {
	edit func(*assertion)
}

func loginRefusalsWriteNothing(t *testing.T, pk passkey) {
	t.Helper()

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	tests := map[string]loginRefusal{
		"wrong origin":             {edit: func(a *assertion) { a.origin = "https://evil.example.com" }},
		"wrong relying party":      {edit: func(a *assertion) { a.rpID = "evil.example.com" }},
		"no user verification":     {edit: func(a *assertion) { a.flags = 0x01 }},
		"registration ceremony":    {edit: func(a *assertion) { a.typ = "webauthn.create" }},
		"another account's handle": {edit: func(a *assertion) { a.handle = []byte("someone-else") }},
		"signed by another key":    {edit: func(a *assertion) { a.key = other }},
		"forged challenge":         {edit: func(a *assertion) { a.challenge = mustRandom(73) }},
		"unknown credential": {edit: func(a *assertion) {
			a.pk.credID = mustRandom(32)
		}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := pk.assertion()
			tt.edit(&a)

			got := call(t, http.MethodPost, loginPath+"/finish", a.body(t, beginLogin(t)), "")
			if got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"`+codeInvalid+`"`) {
				t.Errorf("finish = %d %s, want 401 %s", got.status, got.body, codeInvalid)
			}

			// A refused login must not set a cookie or write a key.
			if got.session() != "" {
				t.Error("a refused login set a session cookie")
			}

			expectCount(t, "japikeys", "0")
		})
	}

	t.Run("a response to someone else's challenge", func(t *testing.T) {
		// A challenge signed with another purpose's key is not ours.
		options := requestOptionsFromRegistration(t)

		got := call(t, http.MethodPost, loginPath+"/finish", pk.assertion().body(t, options), "")
		if got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"`+codeInvalid+`"`) {
			t.Errorf("finish = %d %s, want 401 %s", got.status, got.body, codeInvalid)
		}

		expectCount(t, "japikeys", "0")
	})
}

// requestOptionsFromRegistration returns request options whose challenge was
// minted by registration begin, not login begin. Registration signs its
// challenges with a different derived key, so login must refuse it.
func requestOptionsFromRegistration(t *testing.T) requestOptions {
	t.Helper()

	// The first-run invitation is spent, so use a begin that still works: any
	// registration challenge will do, and a refused begin has none. Build one
	// from the registration begin's shape by asking while an invitation exists.
	const crossCode = "e2e-cross-ceremony-0123456789ABCDEFGHI"

	query(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at) "+
		"VALUES ('00000000-0000-7000-8000-0000000e2e90', X'"+hexOf(sha256.Sum256([]byte(crossCode)))+
		"', 'e2e_no_role', 'cross ceremony', 1, 0)")

	t.Cleanup(func() { query(t, "DELETE FROM invitations WHERE id = '00000000-0000-7000-8000-0000000e2e90'") })

	status, body := beginRegistration(t, crossCode, "Cross")
	if status != http.StatusOK {
		t.Fatalf("registration begin = %d %s, want 200", status, body)
	}

	var reg creationOptions

	err := json.Unmarshal([]byte(body), &reg)
	if err != nil {
		t.Fatalf("parse registration begin: %v", err)
	}

	var options requestOptions

	options.PublicKey.Challenge = reg.PublicKey.Challenge

	return options
}

func hexOf(sum [sha256.Size]byte) string {
	const digits = "0123456789ABCDEF"

	out := make([]byte, 0, len(sum)*2)
	for _, b := range sum {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}

	return string(out)
}

func loginIssuesASession(pk passkey) func(*testing.T) {
	return func(t *testing.T) {
		token := login(t, pk)

		// The row: one session key for this account and passkey, granted from a
		// login (so it has a grant), expiring in the future, not revoked.
		expectCount(t, "japikeys", "1")
		expectCount(t, "japikeys j JOIN users u ON u.id = j.user_id JOIN credentials c ON c.id = j.credential_id "+
			"WHERE j.kind = 'session' AND j.revoked_at IS NULL AND length(j.granted_from) = 32 "+
			"AND j.expires_at > strftime('%s','now') AND u.role = 'admin' AND c.user_id = u.id", "1")

		// The stored key is the public half, in the document japikey defines.
		expectCount(t, "japikeys WHERE json_extract(jwk, '$.keys[0].kid') = kid "+
			"AND json_extract(jwk, '$.keys[0].alg') = 'ES256' AND json_extract(jwk, '$.keys[0].d') IS NULL", "1")

		if got := query(t, "SELECT kid AS v FROM japikeys"); got != kidOf(t, token) {
			t.Errorf("stored kid = %q, token kid = %q", got, kidOf(t, token))
		}

		whoami := call(t, http.MethodGet, sessionPath, nil, token)
		if whoami.status != http.StatusOK || !strings.Contains(whoami.body, `"role":"admin"`) {
			t.Errorf("GET /api/session = %d %s, want 200 as admin", whoami.status, whoami.body)
		}

		if strings.Contains(whoami.body, token) {
			t.Error("the session response carries the token")
		}
	}
}

func replayIsRefused(pk passkey) func(*testing.T) {
	return func(t *testing.T) {
		options := beginLogin(t)
		body := pk.assertion().body(t, options)

		first := call(t, http.MethodPost, loginPath+"/finish", body, "")
		if first.status != http.StatusOK || first.session() == "" {
			t.Fatalf("first finish = %d %s, want 200 with a cookie", first.status, first.body)
		}

		before := query(t, "SELECT count(*) AS v FROM japikeys")

		// The same bytes again: a captured response. The unique grant refuses it.
		for range 3 {
			again := call(t, http.MethodPost, loginPath+"/finish", body, "")
			if again.status != http.StatusUnauthorized || !strings.Contains(again.body, `"`+codeInvalid+`"`) {
				t.Errorf("replay = %d %s, want 401 %s", again.status, again.body, codeInvalid)
			}

			if again.session() != "" {
				t.Error("a replay was given a session cookie")
			}
		}

		if after := query(t, "SELECT count(*) AS v FROM japikeys"); after != before {
			t.Errorf("replays changed the key count from %s to %s", before, after)
		}
	}
}

func twoLoginsBothWork(pk passkey) func(*testing.T) {
	return func(t *testing.T) {
		// Single use is per challenge, not per account: a second honest login is a
		// new challenge and must work.
		first, second := login(t, pk), login(t, pk)

		if first == second || kidOf(t, first) == kidOf(t, second) {
			t.Error("two logins produced the same session")
		}

		for _, token := range []string{first, second} {
			if got := call(t, http.MethodGet, sessionPath, nil, token); got.status != http.StatusOK {
				t.Errorf("GET /api/session = %d %s, want 200", got.status, got.body)
			}
		}
	}
}

// TestLoginCookie checks the attributes of the raw Set-Cookie header, which a
// browser acts on and a cookie jar would hide.
//
//nolint:paralleltest // shares one database with the other tests
func TestLoginCookie(t *testing.T) {
	pk := registerPasskey(t)

	got := call(t, http.MethodPost, loginPath+"/finish", pk.assertion().body(t, beginLogin(t)), "")
	if got.status != http.StatusOK || len(got.setCookies) != 1 {
		t.Fatalf("finish = %d, Set-Cookie = %v, want 200 and exactly one", got.status, got.setCookies)
	}

	line := got.setCookies[0]

	for _, want := range []string{cookieName + "=", "Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Expires="} {
		if !strings.Contains(line, want) {
			t.Errorf("Set-Cookie %q lacks %q", line, want)
		}
	}

	// __Host- forbids a Domain attribute, and a Max-Age we do not set.
	if strings.Contains(line, "Domain=") {
		t.Errorf("Set-Cookie %q has a Domain, which __Host- forbids", line)
	}

	// The token is only in the cookie.
	token := got.session()
	if token == "" || strings.Contains(got.body, token) {
		t.Errorf("the token is missing from the cookie or present in the body: %s", got.body)
	}

	if cc := got.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// TestSessionVerificationRunsInTheWorker is the TinyGo-specific check: the
// japikey library's JWK parsing and ES256 verification run reflection-driven
// code under TinyGo that the host tests exercise under Go. A login followed by a
// verified session read proves them end to end, and a tampered token proves
// verification really runs.
//
//nolint:paralleltest // shares one database with the other tests
func TestSessionVerificationRunsInTheWorker(t *testing.T) {
	pk := registerPasskey(t)
	token := login(t, pk)

	if got := call(t, http.MethodGet, sessionPath, nil, token); got.status != http.StatusOK {
		t.Fatalf("GET /api/session = %d %s, want 200", got.status, got.body)
	}

	header, payload, signature := splitToken(t, token)

	tampered := map[string]string{
		"no cookie":         "",
		garbageToken:        garbageToken,
		"truncated":         token[:len(token)-4],
		"signature flipped": header + "." + payload + "." + flip(signature),
		"payload altered":   header + "." + flip(payload) + "." + signature,
		"not a jwt":         header,
	}

	for name, bad := range tampered {
		t.Run(name, func(t *testing.T) {
			got := call(t, http.MethodGet, sessionPath, nil, bad)
			if got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"`+codeNoAuth+`"`) {
				t.Errorf("GET /api/session = %d %s, want 401 %s", got.status, got.body, codeNoAuth)
			}
		})
	}

	// A well-formed token for a key that was never stored: japikey passes its
	// own checks and the lookup finds nothing.
	other := login(t, pk)
	query(t, "DELETE FROM japikeys WHERE kid = '"+kidOf(t, other)+"'")

	if got := call(t, http.MethodGet, sessionPath, nil, other); got.status != http.StatusUnauthorized {
		t.Errorf("a token whose key is gone = %d %s, want 401", got.status, got.body)
	}
}

func splitToken(t *testing.T, token string) (string, string, string) {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}

	return parts[0], parts[1], parts[2]
}

// flip changes the first character of a base64url segment, so the segment is
// still well-formed but means something else.
func flip(segment string) string {
	if segment == "" {
		return "A"
	}

	if segment[0] == 'A' {
		return "B" + segment[1:]
	}

	return "A" + segment[1:]
}
