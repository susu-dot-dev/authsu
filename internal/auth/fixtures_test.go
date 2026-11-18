package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/susu-dot-dev/japikey_go"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// boundary reads keys through. KeyReader has no write method, which is how the
// tests know the boundary cannot write.
var _ auth.KeyReader = (*store.Store)(nil)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB      = errors.New("SELECT jwk FROM japikeys: database is on fire")
	errEncode  = errors.New("encoder is broken")
	errPlain   = errors.New("a requirement that forgot to classify")
	errRevoked = errors.New("the session was revoked by another request")
)

const (
	testSecret   = "auth-test-secret-0123456789ABCDEFGHIJKLMNOPQ"
	apiOrigin    = "https://auth.example.com"
	uiOrigin     = "https://example.com"
	localOrigin  = "http://localhost:8787"
	localIssuer  = localOrigin + "/keys"
	userID       = "00000000-0000-7000-8000-000000000002"
	otherUserID  = "00000000-0000-7000-8000-0000000000ff"
	credentialID = "00000000-0000-7000-8000-000000000001"
	itemID       = "00000000-0000-7000-8000-0000000000aa"
	otherItemID  = "00000000-0000-7000-8000-0000000000bb"
	roleMember   = "member"
	adminText    = "admin" // how the role is stored, spelled out

	jsonType = "application/json"

	// Names of situations that several tables share.
	nameNoCookie = "no cookie"
	nameEmpty    = "empty"
	nameUpper    = "upper case"
)

// The routes of the standard table (see standardRoutes).
const (
	pathPublic  = "/public"
	pathMe      = "/me"
	pathAdmin   = "/admin"
	pathItems   = "/items/"
	patternItem = "/items/{id}"
)

// Claim names and values of a token.
const (
	claimSub   = "sub"
	claimIss   = "iss"
	claimAud   = "aud"
	claimExp   = "exp"
	claimIat   = "iat"
	claimVer   = "ver"
	claimScope = "scope"
	versionV2  = "japikey-v2"
	audSession = "authsu/session"
	audForAPI  = "authsu/api_key"
)

// The answers a client is given: the status text is part of the contract. A
// response carries a code and the fixed message, and never a cause.
const (
	bodyUnauthenticated = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bodyForbidden       = `{"error":{"code":"forbidden","message":"administrator access is required"}}` + "\n"
	bodyNotConfigured   = `{"error":{"code":"not_configured","message":"the service is not configured"}}` + "\n"
	bodyUnavailable     = `{"error":{"code":"session_verify_failed",` +
		`"message":"sessions are temporarily unavailable"}}` + "\n"
	bodyInvalidID = `{"error":{"code":"invalid_id","message":` +
		`"id must be a lower-case UUID such as 01234567-89ab-cdef-0123-456789abcdef"}}` + "\n"
	bodyNotFound = `{"error":{"code":"not_found","message":"no such route"}}` + "\n"
	bodyInternal = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
	bodyOK       = `{"ok":true}` + "\n"
)

// errorBody is the exact body of a failure with this code and message.
func errorBody(code, message string) string {
	return `{"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n"
}

// keyCall is one read of the key store.
type keyCall struct {
	kid, kind string
	now       time.Time
}

type rowKey struct{ kid, kind string }

// fakeKeys is the key store: rows by kid and kind, as the database holds them,
// with a programmable failure. It records every call.
type fakeKeys struct {
	rows map[rowKey]store.ActiveKey
	// err, when set, is returned by every read.
	err error
	// ignoreKind makes the fake answer for a kid whatever its kind, as a
	// store that forgot its kind condition would.
	ignoreKind bool
	calls      []keyCall
}

func (f *fakeKeys) ActiveKey(_ context.Context, kid, kind string, now time.Time) (store.ActiveKey, bool, error) {
	f.calls = append(f.calls, keyCall{kid: kid, kind: kind, now: now})

	if f.err != nil {
		return store.ActiveKey{}, false, f.err
	}

	if row, ok := f.rows[rowKey{kid: kid, kind: kind}]; ok {
		return row, true, nil
	}

	if f.ignoreKind {
		for key, row := range f.rows {
			if key.kid == kid {
				return row, true, nil
			}
		}
	}

	return store.ActiveKey{}, false, nil
}

// rig is one deployment under test: the real boundary over a fake key store, a
// route that records whether and how it ran, and the errors the boundary logged.
type rig struct {
	t      *testing.T
	keys   *fakeKeys
	env    map[string]string
	now    time.Time
	issuer auth.Issuer

	// handled records every call a route's Handle received.
	handled []*auth.Call
	// ran records the name of each route that ran, for routes built with named.
	ran []string
	// logged records every error the boundary turned into a response.
	logged []*apierr.Error
	// envReads counts how often the configuration was read.
	envReads int
}

func newRig(t *testing.T) *rig {
	t.Helper()

	return &rig{
		t:    t,
		keys: &fakeKeys{rows: map[rowKey]store.ActiveKey{}, err: nil, ignoreKind: false, calls: nil},
		env: map[string]string{
			config.SecretHMAC: testSecret, config.VarAPIOrigin: apiOrigin, config.VarUIOrigin: uiOrigin,
		},
		now:    time.Now(),
		issuer: auth.IssuerFor(origin(t, apiOrigin)),
	}
}

// with sets or, with "", removes deployment settings.
func (r *rig) with(settings map[string]string) *rig {
	maps.Copy(r.env, settings)

	return r
}

func (r *rig) deps() auth.Deps {
	return auth.Deps{
		Keys: r.keys,
		Now:  func() time.Time { return r.now },
		Getenv: func(name string) string {
			r.envReads++

			return r.env[name]
		},
		Log: func(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) },
	}
}

// capture is a route body that records the call and answers 200.
func (r *rig) capture(call *auth.Call) result.Result[httpapi.Response] {
	r.handled = append(r.handled, call)

	return result.Ok(httpapi.JSON(http.StatusOK, map[string]bool{"ok": true}))
}

// getRoute builds a GET route that records its calls.
func (r *rig) getRoute(path string, credential auth.Credential, require func(auth.Principal) error) auth.Route {
	return auth.Route{
		Method: http.MethodGet, Path: path, MaxBody: 0, Credential: credential, Require: require, Handle: r.capture,
	}
}

// standardRoutes is the route table the boundary tests drive.
func (r *rig) standardRoutes() []auth.Route {
	return []auth.Route{
		r.getRoute(pathPublic, auth.None, nil),
		r.getRoute(pathPublic+"/{id}", auth.None, nil),
		r.getRoute(pathMe, auth.Session, nil),
		r.getRoute(pathAdmin, auth.Session, auth.Admin),
		r.getRoute(patternItem, auth.Session, nil),
	}
}

// request is one request to send.
type request struct {
	method, target, body string
	// contentType defaults to application/json; "-" sends none.
	contentType string
	cookies     []*http.Cookie
	// cancelled sends a request whose client has already gone away.
	cancelled bool
}

// serve sends req to the boundary built over routes and returns the response.
func (r *rig) serve(routes []auth.Route, req request) *httptest.ResponseRecorder {
	r.t.Helper()

	var reader io.Reader

	if req.body != "" {
		reader = strings.NewReader(req.body)
	}

	ctx := r.t.Context()

	if req.cancelled {
		var cancel context.CancelFunc

		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}

	method := req.method
	if method == "" {
		method = http.MethodGet
	}

	httpReq := httptest.NewRequestWithContext(ctx, method, req.target, reader)

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
	auth.Handler(routes, r.deps()).ServeHTTP(rec, httpReq)

	return rec
}

// get is a GET of target carrying cookies, against the standard routes.
func (r *rig) get(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(r.standardRoutes(), request{method: http.MethodGet, target: target, cookies: cookies})
}

// requestCookie is a cookie as a browser returns it: only a name and a value.
func requestCookie(name, value string) *http.Cookie {
	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: name, Value: value}
}

// sessionCookie is the session cookie of key as the browser sends it back.
func sessionCookie(key auth.Key) *http.Cookie {
	return requestCookie(auth.CookieName, key.JWT)
}

// row is the stored row for key, owned by userID with role.
func (r *rig) row(key auth.Key, owner, role string) store.ActiveKey {
	return store.ActiveKey{
		JWK: []byte(key.JWK), UserID: owner, CredentialID: credentialID, Role: role, ExpiresAt: key.ExpiresAt,
	}
}

// sessionFor creates a session for owner and stores its row, as login would,
// with the given role.
func (r *rig) sessionFor(owner, role string) auth.Key {
	r.t.Helper()

	key, err := auth.CreateSession(r.issuer, owner, r.now.Add(auth.SessionLifetime))
	if err != nil {
		r.t.Fatalf("CreateSession: %v", err)
	}

	r.keys.rows[rowKey{kid: key.ID.String(), kind: auth.KindSession}] = r.row(key, owner, role)

	return key
}

// session is a stored session of the standard user, an administrator.
func (r *rig) session() auth.Key { return r.sessionFor(userID, auth.RoleAdmin) }

// unstore removes key's row, as a revocation, an expiry or a revoked account
// does: the store reports nothing active.
func (r *rig) unstore(key auth.Key) {
	delete(r.keys.rows, rowKey{kid: key.ID.String(), kind: auth.KindSession})
}

// setRow replaces the stored row of a session.
func (r *rig) setRow(key auth.Key, change func(*store.ActiveKey)) {
	rk := rowKey{kid: key.ID.String(), kind: auth.KindSession}
	row := r.keys.rows[rk]

	change(&row)
	r.keys.rows[rk] = row
}

// forged is a token that this test signed itself, so that it can carry claims
// the creation code never writes. It is correctly signed, and its public key
// is a valid stored JWK for its kid.
type forged struct {
	ID  uuid.UUID
	JWT string
	JWK string
}

// forge signs a session token for subject under issuer, with claims that mutate
// may change or delete.
func forge(t *testing.T, issuer auth.Issuer, subject string, now time.Time, mutate func(claims map[string]any)) forged {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	kid := uuid.NewV7()
	claims := map[string]any{
		claimSub: subject,
		claimIss: issuer.Base + "/" + kid.String(),
		claimAud: auth.Audience(auth.KindSession),
		claimExp: now.Add(time.Hour).Unix(),
		claimIat: now.Unix(),
		claimVer: versionV2,
	}

	if mutate != nil {
		mutate(claims)
	}

	jwt := signJWT(t, priv, kid, claims)

	document, err := japikey.NewJWKS(&priv.PublicKey, kid)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}

	jwk, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("jwk: %v", err)
	}

	return forged{ID: kid, JWT: jwt, JWK: string(jwk)}
}

// signJWT signs claims as an ES256 JWT with priv, under the key id kid.
func signJWT(t *testing.T, priv *ecdsa.PrivateKey, kid uuid.UUID, claims map[string]any) string {
	t.Helper()

	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid.String()})
	if err != nil {
		t.Fatalf("header: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("claims: %v", err)
	}

	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))

	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	var sig struct{ R, S *big.Int }

	_, err = asn1.Unmarshal(der, &sig)
	if err != nil {
		t.Fatalf("signature: %v", err)
	}

	// A JWS ES256 signature is R and S as two fixed-width 32-byte integers.
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])

	return signing + "." + enc.EncodeToString(raw)
}

// storeForged puts the forged key's row in the fake store.
func (r *rig) storeForged(f forged, owner, role string) {
	r.keys.rows[rowKey{kid: f.ID.String(), kind: auth.KindSession}] = store.ActiveKey{
		JWK: []byte(f.JWK), UserID: owner, CredentialID: credentialID, Role: role, ExpiresAt: r.now.Add(time.Hour),
	}
}

// wantFailure checks the status and the exact body of a failure response, that
// the failure was logged once under code, and that the cause (when given) is in
// the log and so not in the body.
func wantFailure(t *testing.T, r *rig, rec *httptest.ResponseRecorder, status int, body, code string, cause error) {
	t.Helper()

	if rec.Code != status || rec.Body.String() != body {
		t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), status, body)
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
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

	if cause != nil && !errors.Is(r.logged[0], cause) {
		t.Errorf("logged error %v does not wrap the cause %v", r.logged[0], cause)
	}
}

// createKey creates a key of kind under issuer for the standard user, valid for
// an hour. Nothing is stored.
func (r *rig) createKey(issuer auth.Issuer, kind string) auth.Key {
	r.t.Helper()

	key, err := auth.CreateKey(issuer, auth.KeySpec{
		Kind: kind, Subject: userID, Expires: r.now.Add(time.Hour), Claims: nil,
	})
	if err != nil {
		r.t.Fatalf("CreateKey: %v", err)
	}

	return key
}

// put stores key's row under kind, as the database would hold it, owned by the
// standard user, an administrator.
func (r *rig) put(key auth.Key, kind string) {
	r.keys.rows[rowKey{kid: key.ID.String(), kind: kind}] = r.row(key, userID, auth.RoleAdmin)
}

// origin parses an origin, which the test knows is valid.
func origin(t *testing.T, value string) config.Origin {
	t.Helper()

	parsed, err := config.ParseOrigin(value)
	if err != nil {
		t.Fatalf("origin: %v", err)
	}

	return parsed
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
