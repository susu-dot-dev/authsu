package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// boundary resolves credentials through. CredentialReader has no write method,
// which is how the tests know the boundary cannot write.
var _ auth.CredentialReader = (*store.Store)(nil)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB      = errors.New("SELECT hash FROM secrets: database is on fire")
	errRevoked = errors.New("the session was revoked by another request")
)

const (
	testSecret  = "auth-test-secret-0123456789ABCDEFGHIJKLMNOPQ"
	apiOrigin   = "https://auth.example.com"
	uiOrigin    = "https://example.com"
	userID      = "00000000-0000-7000-8000-000000000002"
	otherUserID = "00000000-0000-7000-8000-0000000000ff"
	itemID      = "00000000-0000-7000-8000-0000000000aa"
	otherItemID = "00000000-0000-7000-8000-0000000000bb"
	roleMember  = "member"
	adminText   = "admin" // how the role is stored, spelled out

	jsonType = "application/json"

	// Names of situations that several tables share.
	nameNoCookie = "no cookie"
	nameEmpty    = "empty"
	nameUpper    = "upper case"
)

// The routes of the standard table (see standardRoutes).
const (
	pathPublic = "/public"
	pathMe     = "/me"
	// pathMeInSandbox is pathMe for a route that has opted in to sandboxed agents.
	pathMeInSandbox = "/me-in-sandbox"
	pathAdmin       = "/admin"
	pathItems       = "/items/"
	patternItem     = "/items/{id}"
)

// The answers a client is given: the status text is part of the contract. A
// response carries a code and the fixed message, and never a cause.
const (
	bodyUnauthenticated = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bodyForbidden       = `{"error":{"code":"forbidden","message":"administrator access is required"}}` + "\n"
	bodyNoScope         = `{"error":{"code":"insufficient_scope",` +
		`"message":"this credential lacks the scope user:read"}}` + "\n"
	bodyNotConfigured = `{"error":{"code":"not_configured","message":"the service is not configured"}}` + "\n"
	bodyUnavailable   = `{"error":{"code":"session_verify_failed",` +
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

// credentialCall is one read of the credential store: which kind was asked for,
// the token's text, and the time the boundary passed.
type credentialCall struct {
	kind  string
	token string
	now   time.Time
}

// fakeCredentials is the credential store: active sessions and keys by the
// token that names them, as the store reports them after applying its own
// active predicate (the SQL runs only in e2e), with a programmable failure. It
// records every call, so a test can assert that a refused request cost no read.
type fakeCredentials struct {
	sessions map[string]store.ActiveSession
	keys     map[string]store.ActiveAPIKey
	// err, when set, is returned by every read.
	err error
	// calls is every read, in order.
	calls []credentialCall
}

func newFakeCredentials() *fakeCredentials {
	return &fakeCredentials{
		sessions: map[string]store.ActiveSession{}, keys: map[string]store.ActiveAPIKey{}, err: nil, calls: nil,
	}
}

// ResolveSession answers for an active session, honouring a cancelled request
// as the real store does.
func (f *fakeCredentials) ResolveSession(
	ctx context.Context, token input.SessionToken, now time.Time,
) (store.ActiveSession, bool, error) {
	f.calls = append(f.calls, credentialCall{kind: auth.KindSession, token: token.String(), now: now})

	err := f.failure(ctx)
	if err != nil {
		return store.ActiveSession{}, false, err
	}

	row, found := f.sessions[token.String()]

	return row, found, nil
}

// ResolveAPIKey answers for an active API key, as ResolveSession does.
func (f *fakeCredentials) ResolveAPIKey(
	ctx context.Context, token input.APIKeyToken, now time.Time,
) (store.ActiveAPIKey, bool, error) {
	f.calls = append(f.calls, credentialCall{kind: auth.KindAPIKey, token: token.String(), now: now})

	err := f.failure(ctx)
	if err != nil {
		return store.ActiveAPIKey{}, false, err
	}

	row, found := f.keys[token.String()]

	return row, found, nil
}

// failure is why every read fails, or nil.
func (f *fakeCredentials) failure(ctx context.Context) error {
	if f.err != nil {
		return f.err
	}

	err := ctx.Err()
	if err != nil {
		return fmt.Errorf("the request ended: %w", err)
	}

	return nil
}

// sequence is a deterministic source of entropy: each read returns bytes that
// differ from every other read's, so issued tokens are distinct.
type sequence struct{ reads uint64 }

func (s *sequence) Read(p []byte) (int, error) {
	s.reads++

	sum := sha256.Sum256(binary.BigEndian.AppendUint64(nil, s.reads))

	return copy(p, sum[:]), nil
}

// rig is one deployment under test: the real boundary over a fake credential
// store, a route that records whether and how it ran, and the errors the
// boundary logged.
type rig struct {
	t       *testing.T
	creds   *fakeCredentials
	env     map[string]string
	now     time.Time
	entropy *sequence
	ids     int

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
		t:     t,
		creds: newFakeCredentials(),
		env: map[string]string{
			config.SecretHMAC: testSecret, config.VarAPIOrigin: apiOrigin, config.VarUIOrigin: uiOrigin,
		},
		now:     time.Date(2030, time.March, 4, 5, 6, 7, 0, time.UTC),
		entropy: &sequence{reads: 0},
		ids:     0,
	}
}

// with sets or, with "", removes deployment settings.
func (r *rig) with(settings map[string]string) *rig {
	maps.Copy(r.env, settings)

	return r
}

func (r *rig) deps() auth.Deps {
	return auth.Deps{
		Credentials: r.creds,
		Now:         func() time.Time { return r.now },
		Getenv: func(name string) string {
			r.envReads++

			return r.env[name]
		},
		Log: func(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) },
	}
}

// newID is the id source the rig issues secrets with: distinct UUID-shaped
// values.
func (r *rig) newID() string {
	r.ids++

	return fmt.Sprintf("00000000-0000-7000-8000-%012x", 0x1000+r.ids)
}

// capture is a route body that records the call and answers 200.
func (r *rig) capture(call *auth.Call) result.Result[httpapi.Response] {
	r.handled = append(r.handled, call)

	return result.Ok(httpapi.JSON(http.StatusOK, map[string]bool{"ok": true}))
}

// accessFor is the access a test route declares by default for a credential:
// none for a None route (which has no caller to ask about) and Open() for an
// Authenticated one.
func accessFor(credential auth.Credential) auth.Access {
	if credential == auth.Authenticated {
		return auth.Open()
	}

	return auth.Access{}
}

// getRoute builds a GET route that records its calls. A None route has no
// access, and an Authenticated one declares access.
func (r *rig) getRoute(path string, credential auth.Credential, access auth.Access) auth.Route {
	return auth.Route{
		Method: http.MethodGet, Path: path, MaxBody: 0, Credential: credential, Access: access, Handle: r.capture,
	}
}

// standardRoutes is the route table the boundary tests drive.
func (r *rig) standardRoutes() []auth.Route {
	return []auth.Route{
		r.getRoute(pathPublic, auth.None, auth.Access{}),
		r.getRoute(pathPublic+"/{id}", auth.None, auth.Access{}),
		r.getRoute(pathMe, auth.Authenticated, auth.Open()),
		r.getRoute(pathMeInSandbox, auth.Authenticated, auth.Open().InSandbox()),
		r.getRoute(pathAdmin, auth.Authenticated, auth.Needs(scope.UserRead)),
		r.getRoute(patternItem, auth.Authenticated, auth.Open()),
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

// sessionCookie is the session cookie of an issued session as the browser
// sends it back.
func sessionCookie(issued auth.Issued) *http.Cookie {
	return requestCookie(auth.CookieName, issued.Token)
}

// bearer is the Authorization header value for an issued key.
func bearer(issued auth.Issued) string { return "Bearer " + issued.Token }

// issueSession issues a session as login would, from the rig's entropy.
func (r *rig) issueSession() auth.Issued {
	r.t.Helper()

	issued, err := auth.IssueSession(r.entropy, r.newID, r.now)
	if err != nil {
		r.t.Fatalf("IssueSession: %v", err)
	}

	return issued
}

// issueKey issues an API key that lives an hour, from the rig's entropy.
func (r *rig) issueKey() auth.Issued {
	r.t.Helper()

	issued, err := auth.IssueAPIKey(r.entropy, r.newID, r.now, time.Hour)
	if err != nil {
		r.t.Fatalf("IssueAPIKey: %v", err)
	}

	return issued
}

// foreign is a token of another kind than session or key, as an invitation is.
func (r *rig) foreign(tag secret.Tag) string {
	r.t.Helper()

	token, err := secret.Generate(r.entropy, tag)
	if err != nil {
		r.t.Fatalf("Generate: %v", err)
	}

	return token
}

// sessionFor issues a session for the standard user and stores its row as
// active, as login and the store would, with the given role.
func (r *rig) sessionFor(role string) auth.Issued {
	r.t.Helper()

	issued := r.issueSession()

	r.creds.sessions[issued.Token] = store.ActiveSession{
		ID: issued.ID, UserID: userID, Role: role, ExpiresAt: issued.ExpiresAt,
	}

	return issued
}

// session is a stored session of the standard user, an administrator.
func (r *rig) session() auth.Issued { return r.sessionFor(auth.RoleAdmin) }

// unstore makes a session or key inactive, as a revocation, an expiry or a
// revoked account or agent does: the store reports nothing active, and that is
// all the boundary learns.
func (r *rig) unstore(issued auth.Issued) {
	delete(r.creds.sessions, issued.Token)
	delete(r.creds.keys, issued.Token)
}

// setSession replaces the stored row of a session.
func (r *rig) setSession(issued auth.Issued, change func(*store.ActiveSession)) {
	row := r.creds.sessions[issued.Token]

	change(&row)
	r.creds.sessions[issued.Token] = row
}

// bearerSpec describes an API key to issue and store, for the tests of the
// bearer credential and of scopes.
type bearerSpec struct {
	// scope is the key's own scope list, stored as its JSON.
	scope scope.List
	// stored, when set, is the key's stored scope text as it is, whatever scope
	// says: how a damaged value is put in the row.
	stored *string
	// role is the owner's role in the stored row.
	role string
	// agent is the agent the key belongs to, or "" for a user's own key.
	agent string
	// agentScopes is the agent's stored scope list (JSON), read now.
	agentScopes string
	// org is the owner's organization in the stored row, "" for none.
	org string
	// sandbox is the sandbox of the key's agent in the stored row, "" for none.
	sandbox string
}

// withStoredScope returns a copy of s whose stored scope text is text.
func (s bearerSpec) withStoredScope(text string) bearerSpec {
	s.stored = &text

	return s
}

// apiKey issues an API key as spec describes, stores its row as the store would
// return it, and returns it.
func (r *rig) apiKey(spec bearerSpec) auth.Issued {
	r.t.Helper()

	issued := r.issueKey()

	stored := spec.scope.JSON()
	if spec.stored != nil {
		stored = *spec.stored
	}

	role := spec.role
	if role == "" {
		role = roleMember
	}

	r.creds.keys[issued.Token] = store.ActiveAPIKey{
		ID: issued.ID, UserID: userID, Role: role, ExpiresAt: issued.ExpiresAt,
		AgentID: spec.agent, AgentScopes: spec.agentScopes, Scope: stored,
		OrgID: spec.org, SandboxID: spec.sandbox,
	}

	return issued
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

// serveWith is serve with Authorization header values.
func (r *rig) serveWith(
	routes []auth.Route, target string, authorization []string, cookies []*http.Cookie,
) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serveCtx(routes, target, carried{headers: authorization, cookies: cookies}, false)
}

// serveCtx sends a GET of target presenting what a request carries, from a
// client that has already gone away when cancelled.
func (r *rig) serveCtx(
	routes []auth.Route, target string, presented carried, cancelled bool,
) *httptest.ResponseRecorder {
	r.t.Helper()

	ctx := r.t.Context()

	if cancelled {
		var cancel context.CancelFunc

		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}

	httpReq := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	httpReq.Header.Set("Content-Type", jsonType)

	for _, value := range presented.headers {
		httpReq.Header.Add("Authorization", value)
	}

	for _, cookie := range presented.cookies {
		httpReq.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	auth.Handler(routes, r.deps()).ServeHTTP(rec, httpReq)

	return rec
}
