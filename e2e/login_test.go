//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it, and a test that walks one scenario step by step reads best as one function
package e2e_test

// login_test.go drives POST /api/login/begin and /api/login/finish against the
// real Worker: the TinyGo wasm, the real D1 driver and the real SQLite. Unit
// tests fake the database, so what only these tests prove is the SQL (the
// credential lookup, the one batch that updates the flags and inserts the
// session, the UNIQUE granted_from that makes a login single use), the strict
// JSON readers as TinyGo built them, and what the Worker really writes to the
// database and to the Set-Cookie header.
//
// REVIEW.md categories covered:
//
//   - input edge cases: every way a begin or a finish body can be malformed,
//     every member of an assertion that can be wrong, in a table;
//   - interleaving: a captured finish replayed sequentially and by 16
//     concurrent requests against one SQLite database, and many honest logins
//     at once, always asserting the invariant on the stored rows;
//   - payload size: the 16 KiB cap and every per-member bound, one byte under,
//     at and over;
//   - permission confusion: a login for a revoked account, a deleted passkey,
//     a challenge of another ceremony, a response signed by another key;
//   - type and bound confusion: JSON number/null/array/string where a string or
//     object is expected, padded base64, a 1024-byte credential id.
//
// Every refusal of an assertion must be the one answer (401 invalid_login) with
// a byte-identical body whatever the cause (no oracle), set no cookie, and
// leave japikeys and credentials exactly as they were.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// invalidLoginBody is the exact body of every refused assertion. The tests
// compare against this constant, so a cause that leaks into the body (an
// oracle) fails every case at once.
const invalidLoginBody = `{"error":{"code":"invalid_login","message":"the passkey login response is not valid"}}` + "\n"

// lgSessionLifetime is auth.SessionLifetime, restated because e2e imports
// nothing from internal: a change of the product constant must be a conscious
// change of this test.
const lgSessionLifetime = 14 * 24 * time.Hour

// lgClockSlack is how far the Worker's clock and the test's may differ for a
// "now"-relative assertion. Both run on one machine, so a few seconds is slack
// for a slow request, not for skew.
const lgClockSlack = 10 * time.Second

// lgState is everything a refused login must leave unchanged: the sessions and
// the passkeys' flags.
type lgState struct {
	keys  string
	flags string
	rows  string
}

// lgSnapshot reads the state a login may write. rows is the whole japikeys
// table, so a refusal that touched an existing row (a revocation, say) is seen
// too, not only an insert.
func lgSnapshot(t *testing.T) lgState {
	t.Helper()

	return lgState{
		keys:  count(t, "japikeys"),
		flags: scalar(t, "SELECT group_concat(id || ':' || flags, ',') FROM (SELECT id, flags FROM credentials ORDER BY id)"),
		rows: scalar(t, "SELECT group_concat(kid || ':' || ifnull(revoked_at, 'N') || ':' || expires_at, ',') "+
			"FROM (SELECT kid, revoked_at, expires_at FROM japikeys ORDER BY kid)"),
	}
}

// lgExpectRefused posts body to finish and requires the one refusal: 401, the
// exact invalid_login body, no cookie, and nothing changed in the database.
func lgExpectRefused(t *testing.T, body []byte) {
	t.Helper()

	before := lgSnapshot(t)
	got := post(t, pathLoginEnd, body, "")

	lgRequireRefusal(t, got)

	if after := lgSnapshot(t); after != before {
		t.Errorf("a refused login changed the database:\nbefore %+v\nafter  %+v", before, after)
	}
}

// lgRequireRefusal checks a reply is the one refusal.
func lgRequireRefusal(t *testing.T, got reply) {
	t.Helper()

	if got.status != http.StatusUnauthorized || got.body != invalidLoginBody {
		t.Errorf("finish = %d %q, want 401 %q", got.status, got.body, invalidLoginBody)
	}

	if len(got.setCookies) != 0 {
		t.Errorf("a refused login set cookies: %q", got.setCookies)
	}

	if got.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got.header.Get("Cache-Control"))
	}
}

// lgExpectAccepted posts body to finish and requires a session. It returns the
// reply.
func lgExpectAccepted(t *testing.T, body []byte) reply {
	t.Helper()

	got := post(t, pathLoginEnd, body, "")
	if got.status != http.StatusOK || got.session() == "" {
		t.Fatalf("finish = %d %s, want 200 with a session cookie", got.status, got.body)
	}

	return got
}

// lgLogin begins and finishes an honest login and returns the finish reply.
func lgLogin(t *testing.T, pk passkey) reply {
	t.Helper()

	return lgExpectAccepted(t, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))
}

// lgOptionsFrom builds request options whose challenge is the given raw bytes.
func lgOptionsFrom(challenge []byte) requestOptions {
	var options requestOptions

	options.PublicKey.Challenge = b64(challenge)

	return options
}

// lgChallenge decodes the challenge of begin options.
func lgChallenge(t *testing.T, options requestOptions) []byte {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(options.PublicKey.Challenge)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	return raw
}

// ---- begin -----------------------------------------------------------------

// TestLoginBegin holds what begin promises: stateless, usernameless, unique
// challenges, no write, and it ignores whatever the body holds.
//
//nolint:paralleltest // shares one database
func TestLoginBegin(t *testing.T) {
	newAdmin(t)

	t.Run("options", func(t *testing.T) {
		got := post(t, pathLoginBegin, nil, "")
		if got.status != http.StatusOK {
			t.Fatalf("begin = %d %s, want 200", got.status, got.body)
		}

		if got.header.Get("Cache-Control") != "no-store" || got.header.Get("Content-Type") != jsonType {
			t.Errorf("headers = %v, want no-store and application/json", got.header)
		}

		if len(got.setCookies) != 0 {
			t.Errorf("begin set cookies %q", got.setCookies)
		}

		// Exact members: a browser-facing shape, nothing extra.
		var members map[string]json.RawMessage

		err := json.Unmarshal([]byte(got.body), &members)
		if err != nil || len(members) != 1 {
			t.Fatalf("body = %s, want exactly {publicKey}", got.body)
		}

		var inner map[string]json.RawMessage

		err = json.Unmarshal(members["publicKey"], &inner)
		if err != nil {
			t.Fatalf("publicKey: %v", err)
		}

		for _, name := range []string{"challenge", "rpId", "timeout", "userVerification", "allowCredentials"} {
			if _, ok := inner[name]; !ok {
				t.Errorf("publicKey lacks %q: %s", name, members["publicKey"])
			}
		}

		if len(inner) != 5 {
			t.Errorf("publicKey has %d members, want 5: %s", len(inner), members["publicKey"])
		}

		var options requestOptions

		err = json.Unmarshal([]byte(got.body), &options)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		pub := options.PublicKey
		if pub.RPID != rpID || pub.UserVerification != "required" || pub.Timeout != 300_000 {
			t.Errorf("options = %+v, want rpId %s, userVerification required, timeout 300000", pub, rpID)
		}

		// An empty list (not null, not absent) is what makes login usernameless.
		if string(inner["allowCredentials"]) != "[]" {
			t.Errorf("allowCredentials = %s, want []", inner["allowCredentials"])
		}

		// 1 version + 8 expiry + 32 nonce + 32 tag, in base64url without padding.
		raw := lgChallenge(t, options)
		if len(raw) != 73 || raw[0] != 1 || strings.Contains(pub.Challenge, "=") {
			t.Errorf("challenge = %d bytes, version %d, want 73 bytes of version 1 and no padding", len(raw), raw[0])
		}
	})

	t.Run("the challenge expires in five minutes", func(t *testing.T) {
		raw := lgChallenge(t, beginLogin(t))

		expires := time.Unix(lgSeconds(raw[1:9]), 0)
		if left := time.Until(expires); left < 5*time.Minute-lgClockSlack || left > 5*time.Minute+lgClockSlack {
			t.Errorf("challenge expires in %s, want about 5m", left)
		}
	})

	t.Run("challenges are unique and begin writes nothing", func(t *testing.T) {
		before := lgSnapshot(t)
		users, creds := count(t, "users"), count(t, "credentials")
		seen := map[string]bool{}

		for range 25 {
			challenge := beginLogin(t).PublicKey.Challenge
			if seen[challenge] {
				t.Fatalf("challenge %s was issued twice", challenge)
			}

			seen[challenge] = true
		}

		if after := lgSnapshot(t); after != before {
			t.Errorf("begin changed the database: %+v -> %+v", before, after)
		}

		expectCount(t, "users", users)
		expectCount(t, "credentials", creds)
		expectCount(t, "japikeys", "0")
	})

	// The body is not read by the handler, so whatever the client sends is
	// accepted, up to the route's 1 KiB cap.
	bodies := []struct {
		name string
		body []byte
		want int
		code string
	}{
		{"empty", nil, http.StatusOK, ""},
		{"empty object", []byte(`{}`), http.StatusOK, ""},
		{"garbage", []byte(`not json at all`), http.StatusOK, ""},
		{"array", []byte(`[1,2,3]`), http.StatusOK, ""},
		{"unknown members", []byte(`{"username":"admin","allowCredentials":["x"]}`), http.StatusOK, ""},
		{"NUL bytes", []byte("\x00\x00\x00"), http.StatusOK, ""},
		{"invalid UTF-8", []byte("\xff\xfe\xfd"), http.StatusOK, ""},
		{"1024 bytes", bytes.Repeat([]byte("x"), 1024), http.StatusOK, ""},
		{"1025 bytes", bytes.Repeat([]byte("x"), 1025), http.StatusRequestEntityTooLarge, codeBodyTooLarge},
		{"1 MiB", bytes.Repeat([]byte("x"), 1<<20), http.StatusRequestEntityTooLarge, codeBodyTooLarge},
	}

	for _, tt := range bodies {
		t.Run("body "+tt.name, func(t *testing.T) {
			got := post(t, pathLoginBegin, tt.body, "")
			got.expect(t, "begin", tt.want, tt.code)

			if tt.want == http.StatusOK && !strings.Contains(got.body, `"challenge"`) {
				t.Errorf("begin body = %s, want options", got.body)
			}
		})
	}

	wrong := []struct {
		name string
		req  request
		want int
		code string
	}{
		{"GET", request{method: http.MethodGet, path: pathLoginBegin}, http.StatusMethodNotAllowed, codeMethodNotAllow},
		{"PUT", request{method: http.MethodPut, path: pathLoginBegin}, http.StatusMethodNotAllowed, codeMethodNotAllow},
		{"DELETE", request{method: http.MethodDelete, path: pathLoginBegin}, http.StatusMethodNotAllowed, codeMethodNotAllow},
		{"no content type", request{method: http.MethodPost, path: pathLoginBegin, noType: true}, http.StatusUnsupportedMediaType, codeUnsupportedType},
		{
			"text/plain",
			request{method: http.MethodPost, path: pathLoginBegin, headers: map[string]string{"Content-Type": "text/plain"}},
			http.StatusUnsupportedMediaType, codeUnsupportedType,
		},
		{
			"form encoded",
			request{
				method: http.MethodPost, path: pathLoginBegin,
				headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			},
			http.StatusUnsupportedMediaType, codeUnsupportedType,
		},
	}

	for _, tt := range wrong {
		t.Run("request "+tt.name, func(t *testing.T) {
			send(t, tt.req).expect(t, "begin", tt.want, tt.code)
		})
	}

	// A session on begin is ignored: login is open and a signed-in caller may
	// begin another.
	t.Run("a session cookie is ignored", func(t *testing.T) {
		got := post(t, pathLoginBegin, nil, "garbage")
		got.expect(t, "begin with a garbage cookie", http.StatusOK, "")
	})

	expectCount(t, "japikeys", "0")
}

// lgSeconds reads 8 big-endian bytes of a challenge's expiry as Unix seconds.
func lgSeconds(raw []byte) int64 {
	return int64(binary.BigEndian.Uint64(raw[:8]))
}

// ---- finish: the accepted login --------------------------------------------

// lgAccepted is one accepted login and what it was begun with, for the checks
// of TestLoginFinishStoresExactly.
type lgAccepted struct {
	pk        passkey
	got       reply
	token     string
	kid       string
	challenge []byte
	started   time.Time
}

// TestLoginFinishStoresExactly holds what an accepted login writes and sends:
// the session row field by field, the credential's flags, the cookie line, the
// JWT's claims and the response body.
//
//nolint:paralleltest // shares one database
func TestLoginFinishStoresExactly(t *testing.T) {
	pk := newAdmin(t)

	options := beginLogin(t)
	started := time.Now()
	got := lgExpectAccepted(t, pk.assertion().sign(t, options, nil).body(t, nil))

	login := lgAccepted{
		pk: pk, got: got, token: got.session(), kid: kidOf(t, got.session()),
		challenge: lgChallenge(t, options), started: started,
	}

	t.Run("response body", login.checkBody)
	t.Run("session row", login.checkRow)
	t.Run("stored key is public only", login.checkKey)
	t.Run("flags", login.checkFlags)
	t.Run("cookie", login.checkCookie)
	t.Run("jwt", login.checkJWT)
	t.Run("the session works", func(t *testing.T) {
		get(t, pathSession, login.token).expect(t, "GET /api/session", http.StatusOK, "")
	})
}

// checkBody checks the response body: who, the role and expiry, and no token.
func (l lgAccepted) checkBody(t *testing.T) {
	var body struct {
		UserID    string `json:"userId"`
		Role      string `json:"role"`
		ExpiresAt int64  `json:"expiresAt"`
	}

	err := json.Unmarshal([]byte(l.got.body), &body)
	if err != nil {
		t.Fatalf("body %s: %v", l.got.body, err)
	}

	if body.UserID != l.pk.userID || body.Role != roleAdmin {
		t.Errorf("body = %+v, want user %s role admin", body, l.pk.userID)
	}

	stored := scalar(t, "SELECT expires_at FROM japikeys WHERE kid = ?", l.kid)
	if strconv.FormatInt(body.ExpiresAt, 10) != stored {
		t.Errorf("body expiresAt = %d, stored expires_at = %s", body.ExpiresAt, stored)
	}

	var members map[string]json.RawMessage

	_ = json.Unmarshal([]byte(l.got.body), &members)
	if len(members) != 3 {
		t.Errorf("body has %d members, want exactly userId, role, expiresAt: %s", len(members), l.got.body)
	}

	if strings.Contains(l.got.body, l.token) || strings.Contains(l.got.body, strings.Split(l.token, ".")[2]) {
		t.Errorf("the token is in the body: %s", l.got.body)
	}

	if l.got.header.Get("Cache-Control") != "no-store" || l.got.header.Get("Content-Type") != jsonType {
		t.Errorf("headers = %v", l.got.header)
	}
}

// checkRow checks the japikeys row field by field.
func (l lgAccepted) checkRow(t *testing.T) {
	expectCount(t, "japikeys", "1")

	if got := scalar(t, "SELECT kind FROM japikeys WHERE kid = ?", l.kid); got != "session" {
		t.Errorf("kind = %q, want session", got)
	}

	if got := scalar(t, "SELECT user_id FROM japikeys WHERE kid = ?", l.kid); got != l.pk.userID {
		t.Errorf("user_id = %q, want %q", got, l.pk.userID)
	}

	credRow := scalar(t, "SELECT id FROM credentials WHERE hex(credential_id) = ?", strings.ToUpper(hexOf(l.pk.credID)))
	if got := scalar(t, "SELECT credential_id FROM japikeys WHERE kid = ?", l.kid); got != credRow || credRow == "" {
		t.Errorf("credential_id = %q, want the passkey's row %q", got, credRow)
	}

	want := sha256.Sum256(l.challenge)
	if got := scalar(t, "SELECT hex(granted_from) FROM japikeys WHERE kid = ?", l.kid); got != strings.ToUpper(hexOf(want[:])) {
		t.Errorf("granted_from = %s, want sha256(challenge) = %X", got, want)
	}

	if got := scalar(t, "SELECT length(granted_from) || typeof(granted_from) FROM japikeys WHERE kid = ?", l.kid); got != "32blob" {
		t.Errorf("granted_from is %s, want 32blob", got)
	}

	if got := scalar(t, "SELECT metadata FROM japikeys WHERE kid = ?", l.kid); got != "{}" {
		t.Errorf("metadata = %q, want {}", got)
	}

	if got := scalar(t, "SELECT ifnull(revoked_at, 'NULL') FROM japikeys WHERE kid = ?", l.kid); got != "NULL" {
		t.Errorf("revoked_at = %q, want NULL", got)
	}

	if got := scalar(t, "SELECT typeof(expires_at) || typeof(created_at) FROM japikeys WHERE kid = ?", l.kid); got != "integerinteger" {
		t.Errorf("expires_at and created_at are %s, want integers", got)
	}

	expires := lgUnix(t, scalar(t, "SELECT expires_at FROM japikeys WHERE kid = ?", l.kid))
	if d := expires.Sub(l.started.Add(lgSessionLifetime)); d < -lgClockSlack || d > lgClockSlack {
		t.Errorf("expires_at = %s, want about now + 14d (%s off)", expires, d)
	}

	created := lgUnix(t, scalar(t, "SELECT created_at FROM japikeys WHERE kid = ?", l.kid))
	if d := created.Sub(l.started); d < -lgClockSlack || d > lgClockSlack {
		t.Errorf("created_at = %s, want about now (%s off)", created, d)
	}

	if created.After(expires) {
		t.Errorf("created_at %s is after expires_at %s", created, expires)
	}
}

// checkKey checks that the stored JWK is the public half only.
func (l lgAccepted) checkKey(t *testing.T) {
	jwk := scalar(t, "SELECT jwk FROM japikeys WHERE kid = ?", l.kid)

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}

	err := json.Unmarshal([]byte(jwk), &doc)
	if err != nil || len(doc.Keys) != 1 {
		t.Fatalf("jwk = %s, want {keys:[one]}: %v", jwk, err)
	}

	key := doc.Keys[0]
	if key["kid"] != l.kid || key["alg"] != "ES256" || key["kty"] != "EC" || key["crv"] != "P-256" {
		t.Errorf("key = %v, want EC P-256 ES256 with kid %s", key, l.kid)
	}

	// RFC 7517 / 7518 private members: the private half must be gone.
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"} {
		if _, ok := key[private]; ok {
			t.Errorf("stored JWK has private member %q: %s", private, jwk)
		}
	}

	var top map[string]json.RawMessage

	_ = json.Unmarshal([]byte(jwk), &top)
	if len(top) != 1 {
		t.Errorf("JWKS has members %v, want only keys", top)
	}
}

// checkFlags checks the credential flags after the login.
func (l lgAccepted) checkFlags(t *testing.T) {
	// Registration stored UP|UV (AT is not kept); the assertion reported UP|UV.
	if got := scalar(t, "SELECT flags FROM credentials WHERE user_id = ?", l.pk.userID); got != "5" {
		t.Errorf("credential flags = %s, want 5 (UP|UV)", got)
	}
}

// checkCookie checks the exact Set-Cookie line.
func (l lgAccepted) checkCookie(t *testing.T) {
	if len(l.got.setCookies) != 1 {
		t.Fatalf("Set-Cookie = %q, want exactly one", l.got.setCookies)
	}

	parts := strings.Split(l.got.setCookies[0], "; ")
	if parts[0] != cookieName+"="+l.token {
		t.Errorf("cookie starts %q", parts[0])
	}

	attrs := map[string]string{}

	for _, part := range parts[1:] {
		name, value, _ := strings.Cut(part, "=")
		attrs[strings.ToLower(name)] = value
	}

	for _, name := range []string{"path", "httponly", "secure", "samesite", "expires"} {
		if _, ok := attrs[name]; !ok {
			t.Errorf("cookie %q lacks %s", l.got.setCookies[0], name)
		}
	}

	if attrs["path"] != "/" || attrs["samesite"] != "Lax" {
		t.Errorf("cookie attributes = %v, want Path=/ and SameSite=Lax", attrs)
	}

	// __Host- forbids Domain; the lifetime is an absolute Expires, never a
	// Max-Age that would restart on every response.
	for _, forbidden := range []string{"domain", "max-age"} {
		if _, ok := attrs[forbidden]; ok {
			t.Errorf("cookie %q has %s", l.got.setCookies[0], forbidden)
		}
	}

	if len(attrs) != 5 {
		t.Errorf("cookie has attributes %v, want exactly Path, Expires, HttpOnly, Secure, SameSite", attrs)
	}

	expires, err := http.ParseTime(attrs["expires"])
	if err != nil {
		t.Fatalf("Expires %q: %v", attrs["expires"], err)
	}

	stored := lgUnix(t, scalar(t, "SELECT expires_at FROM japikeys WHERE kid = ?", l.kid))
	if !expires.Equal(stored) {
		t.Errorf("cookie Expires = %s, stored expires_at = %s", expires, stored)
	}
}

// checkJWT checks the token header and claims.
func (l lgAccepted) checkJWT(t *testing.T) {
	parts := strings.Split(l.token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}

	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])

	var header map[string]any

	_ = json.Unmarshal(raw, &header)
	if header["alg"] != "ES256" || header["kid"] != l.kid || header["typ"] != "JWT" || len(header) != 3 {
		t.Errorf("header = %v, want alg ES256, kid %s, typ JWT", header, l.kid)
	}

	claims := claimsOf(t, l.token)
	if claims["sub"] != l.pk.userID {
		t.Errorf("sub = %v, want %s", claims["sub"], l.pk.userID)
	}

	if claims["iss"] != target.apiOrigin+"/keys/"+l.kid {
		t.Errorf("iss = %v, want %s/keys/%s", claims["iss"], target.apiOrigin, l.kid)
	}

	if claims["aud"] != "authsu/session" {
		t.Errorf("aud = %v, want authsu/session", claims["aud"])
	}

	stored := lgUnix(t, scalar(t, "SELECT expires_at FROM japikeys WHERE kid = ?", l.kid))
	if exp, _ := claims["exp"].(float64); int64(exp) != stored.Unix() {
		t.Errorf("exp = %v, stored expires_at = %d", claims["exp"], stored.Unix())
	}

	iat, _ := claims["iat"].(float64)
	if d := time.Unix(int64(iat), 0).Sub(l.started); d < -lgClockSlack || d > lgClockSlack {
		t.Errorf("iat = %v, want about now", claims["iat"])
	}

	// The role is read per request and never signed into the token.
	for _, forbidden := range []string{"role", "roles", "act", "admin"} {
		if _, ok := claims[forbidden]; ok {
			t.Errorf("claims carry %q: %v", forbidden, claims)
		}
	}

	// A session is signed with every scope, as the default:session bundle: the
	// one thing besides the registered claims that a token carries.
	if list, _ := claims["scope"].([]any); len(list) != 1 || list[0] != "default:session" {
		t.Errorf("scope claim = %v, want [default:session]", claims["scope"])
	}
}

// lgUnix parses a Unix-seconds column.
func lgUnix(t *testing.T, text string) time.Time {
	t.Helper()

	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		t.Fatalf("unix seconds %q: %v", text, err)
	}

	return time.Unix(seconds, 0)
}

// hexOf is the lower-case hex of raw.
func hexOf(raw []byte) string {
	const digits = "0123456789abcdef"

	out := make([]byte, 0, len(raw)*2)
	for _, b := range raw {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}

	return string(out)
}

// ---- flags -----------------------------------------------------------------

// TestLoginFlagsUpdate holds what happens to credentials.flags: backup state
// and the verified bit may change and are stored on login; backup eligibility
// may not change; a refused login (including a refused replay) changes nothing.
//
//nolint:paralleltest // shares one database
func TestLoginFlagsUpdate(t *testing.T) {
	const (
		up     = flagUP
		uv     = flagUV
		be     = byte(0x08)
		bs     = byte(0x10)
		stored = "SELECT flags FROM credentials WHERE user_id = ?"
	)

	cases := []struct {
		name      string
		seeded    int // credentials.flags before the login
		reported  byte
		want      string // flags after; "" for refused
		wantLogin bool
	}{
		{"UP|UV stays", 5, up | uv, "5", true},
		{"backup state gained", 13, up | uv | be | bs, "29", true},
		{"backup state lost", 29, up | uv | be, "13", true},
		{"eligible and unchanged", 13, up | uv | be, "13", true},
		{"UV stored as 0 is rewritten from the signed flags", 1, up | uv, "5", true},
		{"BE appears where registration stored none", 5, up | uv | be, "5", false},
		{"BE disappears", 13, up | uv, "13", false},
		{"BS without BE", 5, up | uv | bs, "5", false},
		{"UV missing", 5, up, "5", false},
		{"UP missing", 5, uv, "5", false},
		{"neither UP nor UV", 5, 0, "5", false},
		{"AT set", 5, up | uv | flagAT, "5", false},
		{"ED set", 5, up | uv | 0x80, "5", false},
		{"RFU1 set", 5, up | uv | 0x02, "5", false},
		{"RFU2 set", 5, up | uv | 0x20, "5", false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			pk := newAdmin(t)
			seed(t, "UPDATE credentials SET flags = ? WHERE user_id = ?", tt.seeded, pk.userID)

			a := pk.assertion()
			a.flags = tt.reported
			body := a.sign(t, beginLogin(t), nil).body(t, nil)

			if tt.wantLogin {
				lgExpectAccepted(t, body)
			} else {
				lgExpectRefused(t, body)
			}

			if got := scalar(t, stored, pk.userID); got != tt.want {
				t.Errorf("flags after = %s, want %s", got, tt.want)
			}

			// The same body again is a replay (or still refused): it changes nothing.
			before := lgSnapshot(t)

			lgRequireRefusal(t, post(t, pathLoginEnd, body, ""))

			if after := lgSnapshot(t); after != before {
				t.Errorf("a refused replay changed the database: %+v -> %+v", before, after)
			}
		})
	}

	// A refused replay must not roll the flags back or forward: the second
	// login of a pair, with other flags, is refused as a replay of the first
	// challenge and leaves the first one's flags in place.
	t.Run("a refused replay with other flags changes nothing", func(t *testing.T) {
		pk := newAdmin(t)
		seed(t, "UPDATE credentials SET flags = 13 WHERE user_id = ?", pk.userID)

		options := beginLogin(t)

		first := pk.assertion()
		first.flags = up | uv | be | bs
		lgExpectAccepted(t, first.sign(t, options, nil).body(t, nil))

		if got := scalar(t, stored, pk.userID); got != "29" {
			t.Fatalf("flags after the first login = %s, want 29", got)
		}

		// Same challenge, different (valid) flags: the grant collides, so the
		// flags statement in the same batch must be rolled back.
		second := pk.assertion()
		second.flags = up | uv | be
		lgExpectRefused(t, second.sign(t, options, nil).body(t, nil))

		if got := scalar(t, stored, pk.userID); got != "29" {
			t.Errorf("flags after a refused replay = %s, want 29: the batch must be atomic", got)
		}
	})
}

// ---- finish: refusals ------------------------------------------------------

// TestLoginFinishRefusals sends every assertion that must fail to verify. Each
// is the one 401 invalid_login with the same bytes, sets no cookie and writes
// nothing.
//
//nolint:paralleltest // shares one database
func TestLoginFinishRefusals(t *testing.T) {
	pk := newAdmin(t)
	other := newKey(t)

	// A second account's passkey for the confusion cases: registered for real
	// by seeding the account and moving a registered credential's identity.
	//
	// The passkey is registered through the API for a throwaway deployment, so
	// the row is exactly what registration writes.
	//
	// Cases are applied to a fresh honest assertion over fresh options.
	cases := []struct {
		name string
		edit func(t *testing.T, a *assertion, options *requestOptions)
	}{
		{"wrong origin", func(_ *testing.T, a *assertion, _ *requestOptions) { a.origin = "https://evil.example.com" }},
		{"origin of the API instead of the UI", func(_ *testing.T, a *assertion, _ *requestOptions) { a.origin = target.apiOrigin }},
		{"origin with a trailing slash", func(_ *testing.T, a *assertion, _ *requestOptions) { a.origin = target.origin + "/" }},
		{"origin in upper case", func(_ *testing.T, a *assertion, _ *requestOptions) { a.origin = strings.ToUpper(target.origin) }},
		{"origin with another port", func(_ *testing.T, a *assertion, _ *requestOptions) { a.origin = "http://localhost:3001" }},
		{"origin with another scheme", func(_ *testing.T, a *assertion, _ *requestOptions) { a.origin = "https://localhost:3000" }},
		{"empty origin", func(_ *testing.T, a *assertion, _ *requestOptions) { a.origin = "" }},
		{"wrong relying party", func(_ *testing.T, a *assertion, _ *requestOptions) { a.rpID = "evil.example.com" }},
		{"relying party with a port", func(_ *testing.T, a *assertion, _ *requestOptions) { a.rpID = "localhost:3000" }},
		{"relying party in upper case", func(_ *testing.T, a *assertion, _ *requestOptions) { a.rpID = "LOCALHOST" }},
		{"user presence missing", func(_ *testing.T, a *assertion, _ *requestOptions) { a.flags = flagUV }},
		{"user verification missing", func(_ *testing.T, a *assertion, _ *requestOptions) { a.flags = flagUP }},
		{"no flags", func(_ *testing.T, a *assertion, _ *requestOptions) { a.flags = 0 }},
		{"every flag", func(_ *testing.T, a *assertion, _ *requestOptions) { a.flags = 0xff }},
		{"type webauthn.create", func(_ *testing.T, a *assertion, _ *requestOptions) { a.typ = "webauthn.create" }},
		{"type empty is webauthn.get so this is the control", nil},
		{"type in upper case", func(_ *testing.T, a *assertion, _ *requestOptions) { a.typ = "WEBAUTHN.GET" }},
		{"type with a trailing space", func(_ *testing.T, a *assertion, _ *requestOptions) { a.typ = "webauthn.get " }},
		{"user handle of nothing", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.handle = []byte{} }},
		{"user handle of someone else", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.handle = randomBytes(len(pk.handle)) }},
		{"user handle one byte short", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.handle = pk.handle[:len(pk.handle)-1] }},
		{"user handle one byte long", func(_ *testing.T, a *assertion, _ *requestOptions) {
			a.pk.handle = append(append([]byte(nil), pk.handle...), 0)
		}},
		{"user handle of 64 bytes (the maximum) that is not ours", func(_ *testing.T, a *assertion, _ *requestOptions) {
			a.pk.handle = randomBytes(64)
		}},
		{"user handle of 65 bytes", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.handle = randomBytes(65) }},
		{"signed by another key", func(_ *testing.T, a *assertion, _ *requestOptions) { a.key = other }},
		{"forged challenge", func(_ *testing.T, a *assertion, _ *requestOptions) { a.challenge = randomBytes(73) }},
		{"challenge of zeros", func(_ *testing.T, a *assertion, _ *requestOptions) { a.challenge = make([]byte, 73) }},
		{"empty challenge", func(_ *testing.T, a *assertion, _ *requestOptions) { a.challenge = []byte{} }},
		{"unknown credential", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.credID = randomBytes(32) }},
		{"credential id of 1 byte", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.credID = []byte{1} }},
		{"credential id of 1023 bytes", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.credID = randomBytes(1023) }},
		{"credential id of 1024 bytes", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.credID = randomBytes(1024) }},
		{"credential id of 5000 bytes", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.credID = randomBytes(5000) }},
		{"credential id empty", func(_ *testing.T, a *assertion, _ *requestOptions) { a.pk.credID = []byte{} }},
		{"credential id is the stored one with a byte appended", func(_ *testing.T, a *assertion, _ *requestOptions) {
			a.pk.credID = append(append([]byte(nil), pk.credID...), 0)
		}},
		{"credential id is the stored one with a byte dropped", func(_ *testing.T, a *assertion, _ *requestOptions) {
			a.pk.credID = pk.credID[:len(pk.credID)-1]
		}},
	}

	for _, tt := range cases {
		if tt.edit == nil {
			continue
		}

		t.Run(tt.name, func(t *testing.T) {
			a := pk.assertion()
			options := beginLogin(t)

			tt.edit(t, &a, &options)

			lgExpectRefused(t, a.sign(t, options, nil).body(t, nil))
		})
	}

	// The control: the same machinery with no edit logs in, so every refusal
	// above is the edit's doing and not the harness'.
	t.Run("control: no edit is accepted", func(t *testing.T) {
		lgExpectAccepted(t, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))
	})
}

// TestLoginRefusalsAreIndistinguishable holds the no-oracle property across
// causes: the bodies, status, headers that vary by cause, and the absence of a
// cookie are identical whether the credential is unknown, the signature bad,
// the account revoked or the challenge forged.
//
//nolint:paralleltest // shares one database
func TestLoginRefusalsAreIndistinguishable(t *testing.T) {
	pk := newAdmin(t)
	other := newKey(t)

	causes := []struct {
		name string
		edit func(a *assertion)
		body map[string]any // extra top-level members
	}{
		{"unknown credential", func(a *assertion) { a.pk.credID = randomBytes(32) }, nil},
		{"bad signature", func(a *assertion) { a.key = other }, nil},
		{"wrong handle", func(a *assertion) { a.pk.handle = randomBytes(32) }, nil},
		{"forged challenge", func(a *assertion) { a.challenge = randomBytes(73) }, nil},
		{"wrong origin", func(a *assertion) { a.origin = "https://evil.example" }, nil},
		{"missing user verification", func(a *assertion) { a.flags = flagUP }, nil},
		{"wrong type", func(a *assertion) { a.typ = "webauthn.create" }, nil},
		{"client extension results", func(*assertion) {}, map[string]any{"clientExtensionResults": map[string]any{"x": 1}}},
		{"credential type", func(*assertion) {}, map[string]any{"type": "password"}},
	}

	var reference *reply

	check := func(name string, got reply) {
		t.Helper()

		if reference == nil {
			reference = &got
		}

		if got.status != reference.status || got.body != reference.body {
			t.Errorf("%s: %d %q differs from %d %q", name, got.status, got.body, reference.status, reference.body)
		}

		lgRequireRefusal(t, got)

		if got.header.Get("Content-Type") != reference.header.Get("Content-Type") {
			t.Errorf("%s: Content-Type %q differs", name, got.header.Get("Content-Type"))
		}
	}

	for _, tt := range causes {
		a := pk.assertion()
		tt.edit(&a)

		check(tt.name, post(t, pathLoginEnd, a.sign(t, beginLogin(t), nil).body(t, tt.body), ""))
	}

	check("empty envelope", post(t, pathLoginEnd, []byte(`{"id":"","rawId":"","type":"public-key","response":{}}`), ""))
	check("null body", post(t, pathLoginEnd, []byte(`null`), ""))

	// The account states: a revoked account and a deleted credential are the
	// same absence as an unknown credential.
	seed(t, "UPDATE users SET revoked_at = strftime('%s','now') WHERE id = ?", pk.userID)
	check("revoked account", post(t, pathLoginEnd, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil), ""))
	seed(t, "UPDATE users SET revoked_at = NULL WHERE id = ?", pk.userID)

	body := pk.assertion().sign(t, beginLogin(t), nil).body(t, nil)

	seed(t, "DELETE FROM credentials WHERE user_id = ?", pk.userID)
	check("deleted credential", post(t, pathLoginEnd, body, ""))

	expectCount(t, "japikeys", "0")
}

// TestLoginFinishChallengeTampering flips, truncates and extends the challenge
// at every byte region of its 73-byte layout (version, expiry, nonce, tag).
//
//nolint:paralleltest // shares one database
func TestLoginFinishChallengeTampering(t *testing.T) {
	pk := newAdmin(t)

	type edit func(challenge []byte) []byte

	flip := func(at int) edit {
		return func(c []byte) []byte {
			out := bytes.Clone(c)
			out[at] ^= 0x01

			return out
		}
	}

	cases := []struct {
		name string
		edit edit
	}{
		{"version byte", flip(0)},
		{"version 2", func(c []byte) []byte { out := bytes.Clone(c); out[0] = 2; return out }},
		{"version 0", func(c []byte) []byte { out := bytes.Clone(c); out[0] = 0; return out }},
		{"expiry first byte", flip(1)},
		{"expiry last byte (one second)", flip(8)},
		{"expiry pushed a day ahead", func(c []byte) []byte {
			out := bytes.Clone(c)
			out[7] += 0x02 // +512 seconds: still a valid layout, with a stale tag

			return out
		}},
		{"nonce first byte", flip(9)},
		{"nonce middle byte", flip(25)},
		{"nonce last byte", flip(40)},
		{"tag first byte", flip(41)},
		{"tag middle byte", flip(57)},
		{"tag last byte", flip(72)},
		{"truncated by one", func(c []byte) []byte { return c[:len(c)-1] }},
		{"truncated to the state", func(c []byte) []byte { return c[:41] }},
		{"truncated to one byte", func(c []byte) []byte { return c[:1] }},
		{"extended by one zero", func(c []byte) []byte { return append(bytes.Clone(c), 0) }},
		{"extended with the tag again", func(c []byte) []byte { return append(bytes.Clone(c), c[41:]...) }},
		{"doubled", func(c []byte) []byte { return append(bytes.Clone(c), c...) }},
		{"tag zeroed", func(c []byte) []byte {
			out := bytes.Clone(c)
			clear(out[41:])

			return out
		}},
		{"all ones", func(c []byte) []byte { return bytes.Repeat([]byte{0xff}, len(c)) }},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			options := beginLogin(t)
			a := pk.assertion()
			a.challenge = tt.edit(lgChallenge(t, options))

			lgExpectRefused(t, a.sign(t, options, nil).body(t, nil))
		})
	}

	t.Run("the untouched challenge is accepted", func(t *testing.T) {
		lgExpectAccepted(t, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))
	})
}

// TestLoginFinishChallengeOfAnotherCeremony holds that a challenge issued by
// registration begin does not open at login (it is signed with another derived
// key), even though it is a validly signed challenge of the same layout.
//
//nolint:paralleltest // shares one database
func TestLoginFinishChallengeOfAnotherCeremony(t *testing.T) {
	// The first-run invitation is redeemable only while no account exists, so
	// the registration challenge is taken from a deployment that is still empty,
	// and the passkey is registered with it afterwards.
	reset(t)
	get(t, pathFirstRun, "").expect(t, "first run", http.StatusOK, "")

	registration := mustBeginRegistration(t, firstRunSecret, "Admin")
	pk := registerWith(t, "Admin")

	// The challenge is a well-formed, validly signed one of the same layout, but
	// signed with registration's derived key.
	raw, err := base64.RawURLEncoding.DecodeString(registration.PublicKey.Challenge)
	if err != nil || len(raw) != 73 {
		t.Fatalf("registration challenge: %d bytes, %v; want the same 73-byte layout as login's", len(raw), err)
	}

	lgExpectRefused(t, pk.assertion().sign(t, lgOptionsFrom(raw), nil).body(t, nil))

	// And the control: the passkey logs in with a login challenge.
	lgExpectAccepted(t, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))
}

// sha256sum is the SHA-256 of raw as a slice.
func sha256sum(raw []byte) []byte {
	sum := sha256.Sum256(raw)

	return sum[:]
}

// ---- finish: state of the account and passkey ------------------------------

// TestLoginFinishAccountState holds the ordering semantics of a login against
// the state of the passkey and account, both ways. A seed changes the state
// while the Worker is idle, so each case is sequential: the login that is
// refused, and then (where it applies) the state restored and the login that is
// accepted.
//
//nolint:paralleltest // shares one database
func TestLoginFinishAccountState(t *testing.T) {
	t.Run("revoked account is refused, and restored account logs in", func(t *testing.T) {
		pk := newAdmin(t)

		seed(t, "UPDATE users SET revoked_at = strftime('%s','now') WHERE id = ?", pk.userID)
		lgExpectRefused(t, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))

		seed(t, "UPDATE users SET revoked_at = NULL WHERE id = ?", pk.userID)
		lgExpectAccepted(t, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))
	})

	t.Run("revoked_at in the future still revokes the account", func(t *testing.T) {
		// users.revoked_at: any value revokes; there is no scheduled revocation.
		pk := newAdmin(t)

		seed(t, "UPDATE users SET revoked_at = strftime('%s','now') + 3600 WHERE id = ?", pk.userID)
		lgExpectRefused(t, pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))
	})

	t.Run("deleted credential is refused", func(t *testing.T) {
		pk := newAdmin(t)

		options := beginLogin(t)
		body := pk.assertion().sign(t, options, nil).body(t, nil)

		seed(t, "DELETE FROM credentials WHERE user_id = ?", pk.userID)
		lgExpectRefused(t, body)
	})

	t.Run("a session of a deleted credential dies, and its login cannot be replayed", func(t *testing.T) {
		pk := newAdmin(t)

		options := beginLogin(t)
		body := pk.assertion().sign(t, options, nil).body(t, nil)
		token := lgExpectAccepted(t, body).session()

		seed(t, "DELETE FROM credentials WHERE user_id = ?", pk.userID)
		// The row cascaded with the passkey: the grant went with it, but the
		// credential is gone, so the replay still cannot log in.
		expectCount(t, "japikeys", "0")
		get(t, pathSession, token).expect(t, "session of a deleted passkey", http.StatusUnauthorized, codeUnauthenticated)
		lgExpectRefused(t, body)
	})

	t.Run("a login whose credential is another account's handle is refused", func(t *testing.T) {
		// Two accounts: the passkey of the second presents the first's handle.
		pk := newAdmin(t)

		seedInvitation(t, idInvitationA, 2)
		seedUser(t, idUserB, roleMember)

		other := lgSeedCredential(t, idUserB, 1)
		other.handle = pk.handle // the first account's handle on the second account's passkey

		lgExpectRefused(t, other.assertion().sign(t, beginLogin(t), nil).body(t, nil))
	})

	t.Run("two accounts log in as themselves", func(t *testing.T) {
		pk := newAdmin(t)

		seedUser(t, idUserB, roleMember)

		other := lgSeedCredential(t, idUserB, 2)

		for _, tt := range []struct {
			who  passkey
			user string
			role string
		}{{pk, pk.userID, roleAdmin}, {other, idUserB, roleMember}} {
			got := lgExpectAccepted(t, tt.who.assertion().sign(t, beginLogin(t), nil).body(t, nil))
			if !strings.Contains(got.body, `"userId":"`+tt.user+`"`) || !strings.Contains(got.body, `"role":"`+tt.role+`"`) {
				t.Errorf("login as %s = %s", tt.user, got.body)
			}

			who := get(t, pathSession, got.session())
			if !strings.Contains(who.body, `"userId":"`+tt.user+`"`) {
				t.Errorf("session of %s = %s", tt.user, who.body)
			}
		}
	})

	t.Run("the same public key under two credential ids is refused by the schema", func(t *testing.T) {
		// migration 0003: one public key belongs to one credential, so a response
		// cannot verify against two rows.
		pk := newAdmin(t)

		seedUser(t, idUserB, roleMember)

		if !refused(t, "INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at) "+
			"SELECT ?, randomblob(32), ?, public_key, flags, metadata, created_at FROM credentials WHERE user_id = ?",
			idN("0c00", 9), idUserB, pk.userID) {
			t.Error("the database accepted a second credential with the same public key")
		}
	})
}

// lgSeedCredential inserts a credential for user whose key the test holds, and
// returns the passkey. The public key is the canonical COSE ES256 encoding
// registration writes, so the Worker verifies against it as it would a real one.
// handle must be the account's user_handle, which the seed reads back.
func lgSeedCredential(t *testing.T, user string, n int) passkey {
	t.Helper()

	key := newKey(t)
	cose := coseES256(t, key.X.FillBytes(make([]byte, 32)), key.Y.FillBytes(make([]byte, 32)))
	credID := randomBytes(32)

	seed(t, "INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at) "+
		"VALUES (?, ?, ?, ?, 5, '{}', strftime('%s','now'))", idN("0c00", n), credID, user, cose)

	handle := []byte(scalarBlob(t, "SELECT hex(user_handle) FROM users WHERE id = ?", user))

	return passkey{priv: key, credID: credID, handle: handle, userID: user}
}

// scalarBlob returns the bytes a hex() query yields.
func scalarBlob(t *testing.T, query string, args ...any) string {
	t.Helper()

	hexed := scalar(t, query, args...)

	out := make([]byte, 0, len(hexed)/2)

	for i := 0; i+1 < len(hexed); i += 2 {
		v, err := strconv.ParseUint(hexed[i:i+2], 16, 8)
		if err != nil {
			t.Fatalf("hex %q: %v", hexed, err)
		}

		out = append(out, byte(v))
	}

	return string(out)
}

// ---- finish: body shape ----------------------------------------------------

// lgMembers decodes an honest body into its members, so a case can replace one.
func lgMembers(t *testing.T, body string) map[string]any {
	t.Helper()

	var members map[string]any

	err := json.Unmarshal([]byte(body), &members)
	if err != nil {
		t.Fatalf("honest body: %v", err)
	}

	return members
}

// lgSetResponse returns body with one response member replaced.
func lgSetResponse(t *testing.T, body, member string, value any) string {
	t.Helper()

	members := lgMembers(t, body)

	response, _ := members["response"].(map[string]any)
	response[member] = value

	return string(mustJSON(t, members))
}

// lgSetMember returns body with one top-level member replaced.
func lgSetMember(t *testing.T, body, member string, value any) string {
	t.Helper()

	members := lgMembers(t, body)
	members[member] = value

	return string(mustJSON(t, members))
}

// lgWithMember is an edit that sets a top-level member of the honest body.
func lgWithMember(member string, value any) func(*testing.T, string) string {
	return func(t *testing.T, honest string) string {
		t.Helper()

		return lgSetMember(t, honest, member, value)
	}
}

// lgWithResponse is an edit that sets a member of the honest body's response.
func lgWithResponse(member string, value any) func(*testing.T, string) string {
	return func(t *testing.T, honest string) string {
		t.Helper()

		return lgSetResponse(t, honest, member, value)
	}
}

// lgBodyCase is one malformed (or unusual) finish body, as an edit of an
// honest one.
type lgBodyCase struct {
	name string
	// edit builds the request body from the honest one.
	edit   func(t *testing.T, honest string) string
	status int
	code   string
}

// lgReplace is an edit that replaces the first occurrence of old.
func lgReplace(old, replacement string) func(*testing.T, string) string {
	return func(_ *testing.T, honest string) string { return strings.Replace(honest, old, replacement, 1) }
}

// lgLiteral is an edit that ignores the honest body.
func lgLiteral(body string) func(*testing.T, string) string {
	return func(*testing.T, string) string { return body }
}

// lgBodyShapeCases are the envelopes of TestLoginFinishBodyShape. idMember is
// the `"id":"..."` member of the honest body for the registered passkey.
func lgBodyShapeCases(idMember string) []lgBodyCase {
	const (
		badType  = "invalid_field_type"
		badJSON  = "invalid_json"
		dupField = "duplicate_field"
		badText  = "invalid_text"
		bad      = http.StatusBadRequest
		refused  = http.StatusUnauthorized
	)

	return []lgBodyCase{
		{"empty body", lgLiteral(""), bad, "empty_body"},
		{"whitespace only", lgLiteral("   \n"), bad, "empty_body"},
		{"null", lgLiteral("null"), refused, codeInvalidLogin},
		{"array", lgLiteral("[]"), bad, badType},
		{"number", lgLiteral("1"), bad, badType},
		{"string", lgLiteral(`"x"`), bad, badType},
		{"true", lgLiteral("true"), bad, badType},
		{"empty object", lgLiteral("{}"), refused, codeInvalidLogin},
		{"truncated JSON", func(_ *testing.T, h string) string { return h[:len(h)-5] }, bad, badJSON},
		{"not JSON", lgLiteral("id=1&rawId=2"), bad, badJSON},
		{"trailing garbage", func(_ *testing.T, h string) string { return h + "x" }, bad, "trailing_data"},
		{"two documents", func(_ *testing.T, h string) string { return h + h }, bad, "trailing_data"},
		{"trailing whitespace is fine", func(_ *testing.T, h string) string { return h + " \n" }, http.StatusOK, ""},
		{"UTF-8 BOM", func(_ *testing.T, h string) string { return "\xef\xbb\xbf" + h }, bad, badJSON},

		{"unknown member", lgReplace(`{`, `{"extra":1,`), bad, codeUnknownField},
		{"unknown member in response", lgReplace(`"response":{`, `"response":{"extra":1,`), bad, codeUnknownField},
		{"top-level member in another case", lgReplace(`"rawId"`, `"RawId"`), bad, codeUnknownField},
		{"type member in upper case", lgReplace(`"type"`, `"TYPE"`), bad, codeUnknownField},
		{"response member in another case", lgReplace(`"signature"`, `"Signature"`), bad, codeUnknownField},
		{"clientDataJSON member in lower case", lgReplace(`"clientDataJSON"`, `"clientdatajson"`), bad, codeUnknownField},
		{"response in upper case", lgReplace(`"response"`, `"RESPONSE"`), bad, codeUnknownField},
		{"unicode escaped member name that spells an unknown one", lgReplace(`"signature"`, `"signatur\u0065x"`), bad, codeUnknownField},

		{"duplicate id", lgReplace(`{`, `{"id":"x",`), bad, dupField},
		{"duplicate response member", lgReplace(`"response":{`, `"response":{"signature":"AA",`), bad, dupField},
		{"duplicate with an escaped name", lgReplace(`{`, `{"\u0069d":"x",`), bad, dupField},
		{"duplicate response object", lgReplace(`{`, `{"response":{},`), bad, dupField},

		{"id is a number", lgReplace(idMember, `"id":1`), bad, badType},
		{"id is null", lgReplace(idMember, `"id":null`), refused, codeInvalidLogin},
		{"id is an array", lgReplace(idMember, `"id":["a"]`), bad, badType},
		{"id is an object", lgReplace(idMember, `"id":{}`), bad, badType},
		{"id is true", lgReplace(idMember, `"id":true`), bad, badType},
		{"id is a float", lgReplace(idMember, `"id":1.5`), bad, badType},
		{"id is 2^53+1", lgReplace(idMember, `"id":9007199254740993`), bad, badType},
		{"id is 1e3", lgReplace(idMember, `"id":1e3`), bad, badType},
		{"response is null", lgWithMember("response", nil), refused, codeInvalidLogin},
		{"response is an array", lgWithMember("response", []any{}), bad, badType},
		{"response is a string", lgWithMember("response", "x"), bad, badType},
		{"clientDataJSON is a number", lgWithResponse("clientDataJSON", 7), bad, badType},
		{"signature is null", lgWithResponse("signature", nil), refused, codeInvalidLogin},
		{"userHandle is null", lgWithResponse("userHandle", nil), refused, codeInvalidLogin},
		{"userHandle is a number", lgWithResponse("userHandle", 1), bad, badType},
		{"type is a number", lgReplace(`"type":"public-key"`, `"type":1`), bad, badType},
		{"type is another credential type", lgReplace(`"public-key"`, `"password"`), refused, codeInvalidLogin},
		{"type is empty", lgReplace(`"public-key"`, `""`), refused, codeInvalidLogin},
		{"type in upper case", lgReplace(`"public-key"`, `"PUBLIC-KEY"`), refused, codeInvalidLogin},

		{"invalid UTF-8 in a value", lgReplace(`"public-key"`, "\"public-\xffkey\""), bad, badText},
		{"lone surrogate escape in a value", lgReplace(`"public-key"`, `"public-\ud800key"`), bad, badText},
		{"NUL escape in a value", lgReplace(`"public-key"`, `"public-\u0000key"`), refused, codeInvalidLogin},
		{"raw control character in a string", lgReplace(`"public-key"`, "\"public\nkey\""), bad, badJSON},

		{"client extension results non-empty", lgReplace(`{`, `{"clientExtensionResults":{"credProps":{"rk":true}},`), refused, codeInvalidLogin},
		{"client extension results is an array", lgReplace(`{`, `{"clientExtensionResults":[],`), bad, badType},
		{"client extension results is a string", lgReplace(`{`, `{"clientExtensionResults":"x",`), bad, badType},
		{"client extension results is a number", lgReplace(`{`, `{"clientExtensionResults":0,`), bad, badType},
		{"client extension results empty object is what browsers send", lgReplace(`{`, `{"clientExtensionResults":{},`), http.StatusOK, ""},
		{"client extension results null is read as none", lgReplace(`{`, `{"clientExtensionResults":null,`), http.StatusOK, ""},
		{"authenticatorAttachment platform is accepted and unused", lgReplace(`{`, `{"authenticatorAttachment":"platform",`), http.StatusOK, ""},
		{"authenticatorAttachment is a number", lgReplace(`{`, `{"authenticatorAttachment":3,`), bad, badType},
		{"authenticatorAttachment is free text", lgReplace(`{`, `{"authenticatorAttachment":"<script>alert(1)</script>",`), http.StatusOK, ""},
	}
}

// TestLoginFinishBodyShape sends malformed envelopes. A body that is not the
// documented JSON shape is a 400 with a code that says what was wrong (the body
// is read before the assertion); a body that is the shape but whose values do
// not verify is the one 401.
//
//nolint:paralleltest // shares one database
func TestLoginFinishBodyShape(t *testing.T) {
	pk := newAdmin(t)
	id := b64(pk.credID)

	for _, tt := range lgBodyShapeCases(`"id":"` + id + `"`) {
		t.Run(tt.name, func(t *testing.T) {
			honest := string(pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))
			body := tt.edit(t, honest)

			before := count(t, "japikeys")
			got := post(t, pathLoginEnd, []byte(body), "")
			got.expect(t, "finish", tt.status, tt.code)

			switch tt.status {
			case http.StatusOK:
				if got.session() == "" {
					t.Errorf("an accepted login set no cookie")
				}
			case http.StatusUnauthorized:
				lgRequireRefusal(t, got)
				expectCount(t, "japikeys", before)
			default:
				if len(got.setCookies) != 0 {
					t.Errorf("a malformed request set cookies %q", got.setCookies)
				}

				expectCount(t, "japikeys", before)

				// A 400 never echoes the input back.
				if strings.Contains(got.body, "public-") || strings.Contains(got.body, id) {
					t.Errorf("error body echoes client input: %s", got.body)
				}
			}
		})
	}
}

// TestLoginFinishBounds sends each bounded member at, one under and one over
// its bound. The bounds are the Worker's: id and rawId 1023 bytes,
// clientDataJSON 2048, signature 80, user handle 64, the body 16 KiB.
//
//nolint:paralleltest // shares one database
func TestLoginFinishBounds(t *testing.T) {
	pk := newAdmin(t)

	// build is an honest body with one response member replaced.
	build := func(t *testing.T, member string, value string) []byte {
		t.Helper()

		var members map[string]any

		err := json.Unmarshal(pk.assertion().sign(t, beginLogin(t), nil).body(t, nil), &members)
		if err != nil {
			t.Fatalf("honest body: %v", err)
		}

		members["response"].(map[string]any)[member] = value //nolint:forcetypeassert // built by body()

		return mustJSON(t, members)
	}

	cases := []struct {
		name   string
		member string
		size   int // decoded bytes of the member
	}{
		{"clientDataJSON 2048", "clientDataJSON", 2048},
		{"clientDataJSON 2049", "clientDataJSON", 2049},
		{"clientDataJSON 4096", "clientDataJSON", 4096},
		{"clientDataJSON 10000", "clientDataJSON", 10000},
		{"signature 80", "signature", 80},
		{"signature 81", "signature", 81},
		{"signature 1000", "signature", 1000},
		{"userHandle 64", "userHandle", 64},
		{"userHandle 65", "userHandle", 65},
		{"userHandle 1000", "userHandle", 1000},
		{"authenticatorData 36", "authenticatorData", 36},
		{"authenticatorData 38", "authenticatorData", 38},
		{"authenticatorData 4096", "authenticatorData", 4096},
		{"authenticatorData 4097", "authenticatorData", 4097},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Every one of these members is wrong for another reason as well
			// (random bytes), so the point is that none is anything but the one
			// answer, and none reaches the database.
			lgExpectRefused(t, build(t, tt.member, b64(randomBytes(tt.size))))
		})
	}

	t.Run("credential id bounds", func(t *testing.T) {
		for _, size := range []int{0, 1, 1022, 1023, 1024, 1025, 4000} {
			id := b64(randomBytes(size))

			var members map[string]any

			_ = json.Unmarshal(pk.assertion().sign(t, beginLogin(t), nil).body(t, nil), &members)
			members["id"], members["rawId"] = id, id

			t.Run(strconv.Itoa(size), func(t *testing.T) {
				lgExpectRefused(t, mustJSON(t, members))
			})
		}
	})

	t.Run("the body cap", func(t *testing.T) {
		honest := string(pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))

		// Whitespace after the document is legal JSON, so the body is exactly
		// the cap, one under and one over, around an otherwise valid request.
		const limit = 16 << 10

		under := honest + strings.Repeat(" ", limit-len(honest))
		if len(under) != limit {
			t.Fatalf("test body is %d bytes, want %d", len(under), limit)
		}

		lgExpectAccepted(t, []byte(under))

		over := pk.assertion().sign(t, beginLogin(t), nil).body(t, nil)
		over = append(over, bytes.Repeat([]byte(" "), limit+1-len(over))...)

		before := lgSnapshot(t)
		post(t, pathLoginEnd, over, "").expect(t, "finish over the cap", http.StatusRequestEntityTooLarge, codeBodyTooLarge)

		if after := lgSnapshot(t); after != before {
			t.Errorf("an oversized body changed the database")
		}

		post(t, pathLoginEnd, bytes.Repeat([]byte("x"), 1<<20+1), "").
			expect(t, "finish of 1 MiB + 1", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
	})

	t.Run("base64 spellings", func(t *testing.T) {
		honest := string(pk.assertion().sign(t, beginLogin(t), nil).body(t, nil))

		var members map[string]any

		_ = json.Unmarshal([]byte(honest), &members)

		response, _ := members["response"].(map[string]any)

		for _, member := range []string{"clientDataJSON", "authenticatorData", "signature", "userHandle"} {
			value, _ := response[member].(string)

			for name, spelling := range map[string]string{
				"padded":        value + strings.Repeat("=", (4-len(value)%4)%4+4),
				"standard":      strings.NewReplacer("-", "+", "_", "/").Replace(value) + "+",
				"whitespace":    value + " ",
				"newline":       value[:4] + "\n" + value[4:],
				"invalid alpha": value + "!",
				"empty":         "",
			} {
				t.Run(member+" "+name, func(t *testing.T) {
					body := bytes.Clone([]byte(honest))
					body = bytes.Replace(body, []byte(`"`+member+`":"`+value+`"`), []byte(`"`+member+`":`+string(mustJSON(t, spelling))), 1)

					lgExpectRefused(t, body)
				})
			}
		}
	})
}

// ---- replay and interleaving -----------------------------------------------

// TestLoginReplayIsSingleUse holds that a captured finish body produces exactly
// one session, however it is replayed.
//
//nolint:paralleltest // shares one database
func TestLoginReplayIsSingleUse(t *testing.T) {
	pk := newAdmin(t)

	t.Run("sequential replays", func(t *testing.T) {
		body := pk.assertion().sign(t, beginLogin(t), nil).body(t, nil)
		first := lgExpectAccepted(t, body)

		before := lgSnapshot(t)

		for i := range 3 {
			got := post(t, pathLoginEnd, body, "")
			lgRequireRefusal(t, got)

			if after := lgSnapshot(t); after != before {
				t.Fatalf("replay %d changed the database: %+v -> %+v", i, before, after)
			}
		}

		// The first session is untouched and still works.
		get(t, pathSession, first.session()).expect(t, "the first session", http.StatusOK, "")
		expectCount(t, "japikeys", "1")
	})

	t.Run("a replay with the signature re-encoded is still a replay", func(t *testing.T) {
		// The grant is the challenge, not the signature.
		s := pk.assertion().sign(t, beginLogin(t), nil)
		lgExpectAccepted(t, s.body(t, nil))

		resigned := pk.assertion()
		lgExpectRefused(t, resigned.sign(t, lgOptionsFrom(s.challengeBytes(t)), s.client).body(t, nil))
	})

	// 16 concurrent submissions of one captured body: exactly one 200.
	t.Run("concurrent submissions of one body", func(t *testing.T) {
		const (
			rounds  = 4
			workers = 16
		)

		for round := range rounds {
			reset(t)
			pk := lgReregister(t)

			body := pk.assertion().sign(t, beginLogin(t), nil).body(t, nil)
			statuses := lgRace(t, workers, func(int) reply { return post(t, pathLoginEnd, body, "") })

			t.Logf("round %d: %v", round, lgTally(statuses))

			won, refused := 0, 0

			for _, got := range statuses {
				switch got.status {
				case http.StatusOK:
					won++

					if got.session() == "" {
						t.Errorf("the winner set no cookie")
					}
				case http.StatusUnauthorized:
					refused++

					lgRequireRefusal(t, got)
				default:
					t.Errorf("status %d %s: want only 200 and 401", got.status, got.body)
				}
			}

			if won != 1 || refused != workers-1 {
				t.Errorf("round %d: %d x 200 and %d x 401, want 1 and %d", round, won, refused, workers-1)
			}

			expectCount(t, "japikeys", "1")
			expectCount(t, "japikeys WHERE kind = 'session' AND revoked_at IS NULL", "1")
		}
	})

	t.Run("concurrent honest logins with distinct challenges all succeed", func(t *testing.T) {
		const workers = 12

		for round := range 3 {
			pk := lgReregister(t)

			// The challenges are begun first, so the only concurrency is finish.
			bodies := make([][]byte, workers)
			for i := range bodies {
				bodies[i] = pk.assertion().sign(t, beginLogin(t), nil).body(t, nil)
			}

			replies := lgRace(t, workers, func(i int) reply { return post(t, pathLoginEnd, bodies[i], "") })
			tokens := map[string]bool{}
			kids := map[string]bool{}

			for _, got := range replies {
				if got.status != http.StatusOK || got.session() == "" {
					t.Errorf("round %d: concurrent honest login = %d %s", round, got.status, got.body)

					continue
				}

				tokens[got.session()] = true
				kids[kidOf(t, got.session())] = true
			}

			if len(tokens) != workers || len(kids) != workers {
				t.Errorf("round %d: %d tokens and %d kids from %d logins, want all distinct", round, len(tokens), len(kids), workers)
			}

			expectCount(t, "japikeys", strconv.Itoa(workers))
			expectCount(t, "(SELECT DISTINCT granted_from FROM japikeys)", strconv.Itoa(workers))
		}
	})

	t.Run("a mix of replays and fresh logins", func(t *testing.T) {
		// 6 distinct challenges, each submitted 4 times: exactly 6 winners.
		pk := lgReregister(t)

		const distinct, copies = 6, 4

		bodies := make([][]byte, distinct)
		for i := range bodies {
			bodies[i] = pk.assertion().sign(t, beginLogin(t), nil).body(t, nil)
		}

		replies := lgRace(t, distinct*copies, func(i int) reply { return post(t, pathLoginEnd, bodies[i%distinct], "") })

		wins := 0

		for _, got := range replies {
			switch got.status {
			case http.StatusOK:
				wins++
			case http.StatusUnauthorized:
				lgRequireRefusal(t, got)
			default:
				t.Errorf("status %d %s", got.status, got.body)
			}
		}

		if wins != distinct {
			t.Errorf("%d winners, want %d", wins, distinct)
		}

		expectCount(t, "japikeys", strconv.Itoa(distinct))
	})
}

// challengeBytes is the challenge echoed in s's clientDataJSON.
func (s signedLogin) challengeBytes(t *testing.T) []byte {
	t.Helper()

	var parsed struct {
		Challenge string `json:"challenge"`
	}

	err := json.Unmarshal(s.client, &parsed)
	if err != nil {
		t.Fatalf("clientDataJSON: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(parsed.Challenge)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	return raw
}

// lgReregister empties the deployment and registers the first administrator.
func lgReregister(t *testing.T) passkey {
	t.Helper()

	return newAdmin(t)
}

// lgRace runs fn(i) for i in [0, n) at once, released together, and returns the
// replies in index order.
func lgRace(t *testing.T, n int, fn func(i int) reply) []reply {
	t.Helper()

	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		replies = make([]reply, n)
	)

	for i := range n {
		wg.Go(func() {
			<-start

			replies[i] = fn(i)
		})
	}

	close(start)
	wg.Wait()

	return replies
}

// lgTally counts replies by status.
func lgTally(replies []reply) map[int]int {
	out := map[int]int{}
	for _, r := range replies {
		out[r.status]++
	}

	return out
}

// TestLoginMalleatedSignature holds that the grant is the challenge and not the
// signature: the high-S spelling (r, n-s) of a valid signature verifies and
// spends the challenge once, and then neither spelling replays.
//
//nolint:paralleltest // shares one database
func TestLoginMalleatedSignature(t *testing.T) {
	pk := newAdmin(t)

	for _, first := range []string{"original first", "malleated first"} {
		t.Run(first, func(t *testing.T) {
			s := pk.assertion().sign(t, beginLogin(t), nil)
			malleated := s.withSig(lgMalleate(s.sig))

			a, b := s, malleated
			if first == "malleated first" {
				a, b = malleated, s
			}

			before := count(t, "japikeys")

			lgExpectAccepted(t, a.body(t, nil))
			lgExpectRefused(t, b.body(t, nil))
			lgExpectRefused(t, a.body(t, nil))
			lgExpectRefused(t, b.body(t, nil))

			if got := count(t, "japikeys"); got == before {
				t.Errorf("no session was created")
			}
		})
	}

	t.Run("both spellings racing create one session", func(t *testing.T) {
		for range 3 {
			pk := newAdmin(t)

			s := pk.assertion().sign(t, beginLogin(t), nil)
			bodies := [][]byte{s.body(t, nil), s.withSig(lgMalleate(s.sig)).body(t, nil)}

			replies := lgRace(t, 16, func(i int) reply { return post(t, pathLoginEnd, bodies[i%2], "") })

			if got := lgTally(replies); got[http.StatusOK] != 1 || got[http.StatusUnauthorized] != 15 {
				t.Errorf("statuses = %v, want one 200 and fifteen 401", got)
			}

			expectCount(t, "japikeys", "1")
		}
	})
}

// ---- login after logout ----------------------------------------------------

// TestLoginAfterSessionEnds holds that ending a session does not reopen its
// login: the row (and with it the grant) stays, so the captured finish cannot be
// replayed, and a fresh challenge still works.
//
//nolint:paralleltest // shares one database
func TestLoginAfterSessionEnds(t *testing.T) {
	pk := newAdmin(t)

	body := pk.assertion().sign(t, beginLogin(t), nil).body(t, nil)
	token := lgExpectAccepted(t, body).session()

	post(t, pathLogout, nil, token).expect(t, "logout", http.StatusNoContent, "")

	before := lgSnapshot(t)

	lgRequireRefusal(t, post(t, pathLoginEnd, body, ""))

	if after := lgSnapshot(t); after != before {
		t.Errorf("the replay after logout changed the database: %+v -> %+v", before, after)
	}

	expectCount(t, "japikeys", "1")

	fresh := lgLogin(t, pk)
	get(t, pathSession, fresh.session()).expect(t, "a fresh login after logout", http.StatusOK, "")
	expectCount(t, "japikeys", "2")
}

// ---- a login racing a change of state ---------------------------------------

// TestLoginRacingAStateChange holds that a login whose passkey is deleted, or
// whose account is revoked, after finish looked it up and before the session is
// written is an ordinary failed login (401 invalid_login), not a server fault
// (500 or 503 that would page someone for a user deleting their own passkey).
//
// finish reads the credential, verifies, then writes, and a seed cannot be timed
// into that gap from outside (seeds are only allowed while the Worker is idle).
// A trigger does it at the one point that is inside the write instead: the
// batch's first statement updates the credential's flags, and the trigger reacts
// to it as a concurrent change committed just ahead of the session insert would.
// The trigger is installed while the Worker is idle and fires inside the
// Worker's own transaction, so no seed lands during a request.
//
//nolint:paralleltest // shares one database
func TestLoginRacingAStateChange(t *testing.T) {
	cases := []struct {
		name    string
		trigger string // the body of the trigger: what happens "in the gap"
	}{
		{"passkey deleted in the gap", "DELETE FROM credentials WHERE id = NEW.id;"},
		{"account revoked in the gap", "UPDATE users SET revoked_at = strftime('%s','now') WHERE id = NEW.user_id;"},
		{"account deleted in the gap", "DELETE FROM users WHERE id = NEW.user_id;"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			pk := newAdmin(t)

			body := pk.assertion().sign(t, beginLogin(t), nil).body(t, nil)

			// The trigger is dropped right after the one request, not in a
			// t.Cleanup (whose context is already cancelled), so a failing
			// assertion below cannot leave it behind for the next test.
			seed(t, "CREATE TRIGGER e2e_login_race AFTER UPDATE OF flags ON credentials BEGIN "+tt.trigger+" END")

			got := post(t, pathLoginEnd, body, "")

			seed(t, "DROP TRIGGER e2e_login_race")

			lgRequireRefusal(t, got)

			// The whole batch rolled back: no session row, and nothing the
			// trigger did survives either.
			expectCount(t, "japikeys", "0")
			expectCount(t, "credentials", "1")
			expectCount(t, "users WHERE revoked_at IS NULL", "1")

			if flags := scalar(t, "SELECT flags FROM credentials WHERE user_id = ?", pk.userID); flags != "5" {
				t.Errorf("flags = %s after a failed login, want the stored 5: the batch must be atomic", flags)
			}

			// The failed attempt rolled back whole, including what the trigger did
			// (it ran inside the batch), and recorded nothing of its grant: with
			// the trigger gone the very same body is a first use and logs in.
			lgExpectAccepted(t, body)
		})
	}
}
