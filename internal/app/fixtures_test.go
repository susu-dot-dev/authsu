package app_test

import (
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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/app"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Deployment configuration the tests run under. The API origin is https, so
// the session cookie the tests create is the one a deployment issues.
const (
	testSecret = "app-test-secret-0123456789ABCDEFGHIJKLMNOPQRS"
	apiOrigin  = "https://auth.example.com"
	uiOrigin   = "https://example.com"

	// someID is a canonical id for the {id} wildcard of a route.
	someID = "01234567-89ab-7def-8123-456789abcdef"
	// adminID and memberID are the accounts the tests sign in as.
	adminID  = "00000000-0000-7000-8000-0000000000a1"
	memberID = "00000000-0000-7000-8000-0000000000b2"
	// someCode is a well-formed invitation token: the prefix, and 43
	// characters whose last one is canonical.
	someCode = "susu_inv_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	// sessionRowID and keyRowID are the ids of the secrets the tests issue.
	sessionRowID = "00000000-0000-7000-8000-0000000000d1"
	keyRowID     = "00000000-0000-7000-8000-0000000000d2"

	roleAdmin  = "admin"
	roleMember = "member"

	jsonType = "application/json"
)

// Error bodies the client sees. The status text is part of the contract.
const (
	bodyUnauthenticated = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bodyNotFound        = `{"error":{"code":"not_found","message":"no such route"}}` + "\n"
	bodyInternal        = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
)

// Fragments of the statements the credential reads and writes run, which the
// fake Exec matches the first statement of a call against.
const (
	readSession = "JOIN sessions x"
	readAPIKey  = "JOIN api_keys k" //nolint:gosec // SQL naming the api_keys table, not a credential
	revokeToken = "UPDATE secrets"
)

// errDB is a cause the fakes inject. It must only ever reach the log.
var errDB = errors.New("D1_ERROR: database is on fire")

// errUnscripted is what the fake Exec answers a statement the test did not
// expect, after it has failed the test.
var errUnscripted = errors.New("unscripted Exec call")

// fullEnv is a complete, valid deployment configuration.
func fullEnv() map[string]string {
	return map[string]string{
		config.SecretHMAC:   testSecret,
		config.VarAPIOrigin: apiOrigin,
		config.VarUIOrigin:  uiOrigin,
	}
}

// getenv reads from env, as the Worker's environment is read: "" for unset.
func getenv(env map[string]string) func(string) string {
	return func(name string) string { return env[name] }
}

// step is one scripted answer of the fake Exec.
type step struct {
	// match is a fragment the first statement of the call must contain. It
	// is how a test notices that the app asked something other than it
	// expected, and not only that it asked.
	match string
	// results and err are the answer.
	results []store.Result
	err     error
}

// fakeExec is the database port: it answers each call from the script, in
// order, and records every call. A call beyond the script, or one whose first
// statement does not contain the scripted fragment, fails the test.
type fakeExec struct {
	t      *testing.T
	script []step

	mu    sync.Mutex
	calls [][]store.Statement
}

func (f *fakeExec) exec(_ context.Context, statements ...store.Statement) ([]store.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.t.Helper()

	f.calls = append(f.calls, statements)
	at := len(f.calls) - 1

	if at >= len(f.script) {
		f.t.Errorf("unscripted Exec call %d: %s", at, describe(statements))

		return nil, errUnscripted
	}

	want := f.script[at]
	if !strings.Contains(statements[0].Query, want.match) {
		f.t.Errorf("Exec call %d is %s, want a statement containing %q", at, describe(statements), want.match)

		return nil, errUnscripted
	}

	return want.results, want.err
}

// describe names a call for a failure message.
func describe(statements []store.Statement) string {
	parts := make([]string, len(statements))
	for i, statement := range statements {
		parts[i] = strings.Join(strings.Fields(statement.Query), " ")
	}

	return fmt.Sprintf("%d statement(s): %s", len(statements), strings.Join(parts, " | "))
}

// callCount is how many times the app has called Exec.
func (f *fakeExec) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.calls)
}

// harness is the app under test with its fake database and its log.
type harness struct {
	t       *testing.T
	exec    *fakeExec
	handler http.Handler

	mu     sync.Mutex
	logged []*apierr.Error
}

// newHarness builds the real handler over a fake Exec that answers from script.
func newHarness(t *testing.T, env map[string]string, script ...step) *harness {
	t.Helper()

	harness := &harness{t: t, exec: &fakeExec{t: t, script: script}}
	harness.handler = app.NewHandler(app.Platform{
		Exec:   harness.exec.exec,
		Getenv: getenv(env),
		Log: func(_ httpapi.Request, failure *apierr.Error) {
			harness.mu.Lock()
			defer harness.mu.Unlock()

			harness.logged = append(harness.logged, failure)
		},
	})

	return harness
}

// request describes one request to the app.
type request struct {
	method  string
	path    string
	body    string
	headers map[string]string
	cookies []*http.Cookie
	// noContentType leaves out the JSON Content-Type the same-origin frontend
	// sends with every unsafe request.
	noContentType bool
}

// do sends req through the handler.
func (h *harness) do(req request) *httptest.ResponseRecorder {
	h.t.Helper()

	httpReq := httptest.NewRequestWithContext(h.t.Context(), req.method, req.path, strings.NewReader(req.body))
	if !req.noContentType {
		httpReq.Header.Set("Content-Type", jsonType)
	}

	for name, value := range req.headers {
		httpReq.Header.Set(name, value)
	}

	for _, cookie := range req.cookies {
		httpReq.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httpReq)

	return rec
}

// loggedCodes are the codes of the failures the app logged, in order. A
// client sees a bare "internal" for a defect; the log has the real code.
func (h *harness) loggedCodes() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	codes := make([]string, len(h.logged))
	for i, failure := range h.logged {
		codes[i] = failure.Code
	}

	return codes
}

// session is a signed-in caller: the session a login would have issued.
type session struct {
	issued auth.Issued
	userID string
	cookie *http.Cookie
}

// newSession issues a real session token for userID, as login does, with the
// real entropy and the fixed id sessionRowID.
func newSession(t *testing.T, userID string) session {
	t.Helper()

	issued, err := auth.IssueSession(rand.Reader, func() string { return sessionRowID }, time.Now().Truncate(time.Second))
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	return session{issued: issued, userID: userID, cookie: requestCookie(auth.CookieName, issued.Token)}
}

// agentRowID is an agent id for rows that name one.
const agentRowID = "00000000-0000-7000-8000-0000000000a1"

// activeSessionStep is the answer to the session lookup of the auth boundary,
// with the row exactly as D1 returns it: text as string, integers as int64.
func (s session) activeSessionStep(role string) step {
	return s.activeSessionRow([]any{s.issued.ID, s.userID, role, s.issued.ExpiresAt.Unix()})
}

// activeSessionRow is activeSessionStep with a row of the test's own making, to
// feed the boundary values D1 could produce but should not.
func (s session) activeSessionRow(row []any) step {
	return step{match: readSession, results: []store.Result{{Changes: 0, Rows: [][]any{row}}}, err: nil}
}

// apiKey is an API key a test holds: what IssueAPIKey made and the headers
// that present it.
type apiKey struct {
	issued  auth.Issued
	headers map[string]string
}

// newAPIKey issues a real API key with the fixed id keyRowID.
func newAPIKey(t *testing.T) apiKey {
	t.Helper()

	issued, err := auth.IssueAPIKey(rand.Reader, func() string { return keyRowID },
		time.Now().Truncate(time.Second), auth.AgentKeyLifetime)
	if err != nil {
		t.Fatalf("issue API key: %v", err)
	}

	return apiKey{issued: issued, headers: bearer(issued.Token)}
}

// authorization is the headers of a request with that Authorization header.
func authorization(value string) map[string]string {
	return map[string]string{"Authorization": value}
}

// bearer is the headers of a request that presents token as an API key.
func bearer(token string) map[string]string { return authorization("Bearer " + token) }

// keyStep is the answer to the API key lookup of the auth boundary: the key's
// own user, role and expiry, the agent it belongs to (or "" for none) with
// that agent's stored scopes, and the key's own scope.
func (k apiKey) keyStep(userID, role, agentID, agentScopes, keyScope string) step {
	return k.keyRow([]any{k.issued.ID, userID, role, k.issued.ExpiresAt.Unix(), agentID, agentScopes, keyScope})
}

// keyRow is keyStep with a row of the test's own making.
func (k apiKey) keyRow(row []any) step {
	return step{match: readAPIKey, results: []store.Result{{Changes: 0, Rows: [][]any{row}}}, err: nil}
}

// rows is a one-statement answer with the given rows.
func rows(rows ...[]any) []store.Result {
	return []store.Result{{Changes: 0, Rows: rows}}
}

// changes is a one-statement answer of a write that changed n rows.
func changes(n int64) []store.Result {
	return []store.Result{{Changes: n, Rows: nil}}
}

// requestCookie is a cookie as a browser sends it back: name and value. It
// carries the attributes the app sets, which a request never reads.
func requestCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

// expect appends answers to the database script, for a test whose later
// answers depend on what the app wrote earlier in the same test.
func (h *harness) expect(steps ...step) {
	h.exec.mu.Lock()
	defer h.exec.mu.Unlock()

	h.exec.script = append(h.exec.script, steps...)
}

// lastCall is the batch of the most recent Exec call.
func (h *harness) lastCall() []store.Statement {
	h.exec.mu.Lock()
	defer h.exec.mu.Unlock()

	return h.exec.calls[len(h.exec.calls)-1]
}

// batchOf is the answer of a batch of n statements that all took effect.
func batchOf(n int) []store.Result { return make([]store.Result, n) }

// createdAgentBatch is the answer of an agent create's batch: the agent insert
// returns the scope list it stored (RETURNING scopes, as D1 sends text), and the
// key's secret and the key's own row return nothing.
func createdAgentBatch(scopes string) []store.Result {
	return []store.Result{{Changes: 1, Rows: [][]any{{scopes}}}, {Changes: 1, Rows: nil}, {Changes: 1, Rows: nil}}
}

// passkey is a software authenticator: a fresh ES256 key and the credential id
// it registers under. It builds the requests a browser would send, so a test
// can run a whole ceremony through the real stack.
type passkey struct {
	priv   *ecdsa.PrivateKey
	credID []byte
	// handle is the user handle an assertion echoes: the one begin issued.
	handle []byte
}

// newPasskey makes a passkey with a random credential id.
func newPasskey(t *testing.T) passkey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	credID := make([]byte, 32)

	_, err = rand.Read(credID)
	if err != nil {
		t.Fatalf("credential id: %v", err)
	}

	return passkey{priv: priv, credID: credID, handle: nil}
}

// typeMember is the name of the member that tells what a WebAuthn object is.
const typeMember = "type"

// b64 is the base64url encoding WebAuthn uses.
func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// unb64 decodes b64.
func unb64(t *testing.T, text string) []byte {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("base64url %q: %v", text, err)
	}

	return raw
}

// optionsOf reads the challenge, and the user handle when there is one, out of
// the options a begin answered.
func optionsOf(t *testing.T, body []byte) (string, []byte) {
	t.Helper()

	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}

	err := json.Unmarshal(body, &options)
	if err != nil {
		t.Fatalf("options %q: %v", body, err)
	}

	handle := []byte(nil)
	if options.PublicKey.User.ID != "" {
		handle = unb64(t, options.PublicKey.User.ID)
	}

	return options.PublicKey.Challenge, handle
}

// coseKey is the canonical COSE_Key registration stores for the passkey.
func (p passkey) coseKey(t *testing.T) []byte {
	t.Helper()

	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	cose, err := encoder.Marshal(map[int64]any{
		1: 2, 3: -7, -1: 1,
		-2: p.priv.X.FillBytes(make([]byte, 32)),
		-3: p.priv.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("cose: %v", err)
	}

	return cose
}

// registrationBody is the finish request a browser sends for challenge, with a
// "none" attestation.
func (p passkey) registrationBody(t *testing.T, challenge, code, name string) string {
	t.Helper()

	clientData, err := json.Marshal(map[string]any{
		typeMember: "webauthn.create", "challenge": challenge, "origin": uiOrigin,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	hash := sha256.Sum256([]byte("example.com"))
	cose := p.coseKey(t)

	authData := slices.Concat(hash[:], []byte{0x01 | 0x04 | 0x40}, []byte{0, 0, 0, 0}, make([]byte, 16),
		binary.BigEndian.AppendUint16(nil, uint16(min(len(p.credID), 1023))), p.credID, cose)

	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	attestation, err := encoder.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}

	id := b64(p.credID)

	body, err := json.Marshal(map[string]any{
		"invitationCode": code, "name": name,
		"credential": map[string]any{
			"id": id, "rawId": id, typeMember: "public-key",
			"response": map[string]any{
				"clientDataJSON":    b64(clientData),
				"attestationObject": b64(attestation),
			},
		},
	})
	if err != nil {
		t.Fatalf("body: %v", err)
	}

	return string(body)
}

// assertionBody is the login finish request a browser sends for challenge,
// signed by the passkey, with user presence and verification.
func (p passkey) assertionBody(t *testing.T, challenge string) string {
	t.Helper()

	clientData, err := json.Marshal(map[string]any{
		typeMember: "webauthn.get", "challenge": challenge, "origin": uiOrigin,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	hash := sha256.Sum256([]byte("example.com"))
	authData := slices.Concat(hash[:], []byte{0x01 | 0x04}, []byte{0, 0, 0, 0})

	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(slices.Concat(authData, clientHash[:]))

	signature, err := ecdsa.SignASN1(rand.Reader, p.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	id := b64(p.credID)

	body, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, typeMember: "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64(p.handle),
		},
	})
	if err != nil {
		t.Fatalf("body: %v", err)
	}

	return string(body)
}

// migrationLimit reads the one number a CHECK of the migrations states, by a
// pattern with a single capture group over their whitespace-collapsed text.
func migrationLimit(t *testing.T, pattern string) int {
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

	limit, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("limit %q: %v", match[1], err)
	}

	return limit
}
