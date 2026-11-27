package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/mcp"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	adminID = "00000000-0000-7000-8000-000000000002"
	// itemID is a valid invitation id.
	itemID = "00000000-0000-7000-8000-0000000000aa"

	testKey   = "mcp-test-secret-0123456789ABCDEFGHIJKLMNOP"
	apiOrigin = "https://auth.example.com"
	uiOrigin  = "https://example.com"

	jsonType = "application/json"

	// A key a client may send: the suite byte 1 and 32 bytes, as 44 characters.
	someKey = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// restCall is one request the fake REST routes received.
type restCall struct {
	method, path  string
	body          string
	authorization []string
	ctxValue      any
}

// ctxKey keys the value the tests put on a request's context.
type ctxKey struct{}

// fakeREST stands in for the REST route table: it records each request and
// answers with what the test programmed, as the real routes would have.
type fakeREST struct {
	calls  []restCall
	status int
	body   string
	err    error
}

func (f *fakeREST) do(
	ctx context.Context, method, path string, body []byte, authorization []string,
) (httpapi.LocalResponse, error) {
	f.calls = append(f.calls, restCall{
		method: method, path: path, body: string(body), authorization: authorization, ctxValue: ctx.Value(ctxKey{}),
	})

	if f.err != nil {
		return httpapi.LocalResponse{}, f.err
	}

	return httpapi.LocalResponse{Status: f.status, Body: []byte(f.body)}, nil
}

// fakeCredentials is the credential store the boundary reads from.
type fakeCredentials struct {
	sessions map[string]store.ActiveSession
	keys     map[string]store.ActiveAPIKey
}

func (f *fakeCredentials) ResolveSession(
	_ context.Context, token input.SessionToken, _ time.Time,
) (store.ActiveSession, bool, error) {
	row, ok := f.sessions[token.String()]

	return row, ok, nil
}

func (f *fakeCredentials) ResolveAPIKey(
	_ context.Context, token input.APIKeyToken, _ time.Time,
) (store.ActiveAPIKey, bool, error) {
	row, found := f.keys[string(token.Hash())]

	return row, found, nil
}

// ResolveGrant finds no grant: these routes are exercised through sessions and
// keys, and an access token presented to them is unknown.
func (f *fakeCredentials) ResolveGrant(
	context.Context, input.AccessToken, input.ResourceID, time.Time,
) (store.ActiveGrant, bool, error) {
	return store.ActiveGrant{}, false, nil
}

// harness is the route under test behind the real auth boundary.
type harness struct {
	t      *testing.T
	rest   *fakeREST
	creds  *fakeCredentials
	logged []*apierr.Error

	handler http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	harn := &harness{
		t: t, rest: &fakeREST{status: http.StatusOK, body: `{"ok":true}` + "\n"},
		creds: &fakeCredentials{sessions: map[string]store.ActiveSession{}, keys: map[string]store.ActiveAPIKey{}},
	}

	env := map[string]string{config.SecretHMAC: testKey, config.VarAPIOrigin: apiOrigin, config.VarUIOrigin: uiOrigin}

	harn.handler = auth.Handler(mcp.Routes(mcp.Deps{Do: harn.rest.do}), auth.Deps{
		Credentials: harn.creds, Resources: resource.Select, Now: time.Now,
		Getenv: func(name string) string { return env[name] },
		Log:    func(_ httpapi.Request, failure *apierr.Error) { harn.logged = append(harn.logged, failure) },
	})

	return harn
}

// sequence returns n bytes counting up from start.
func sequence(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}

	return out
}

// key issues an API key that holds no scopes, registers it as active and returns
// the Authorization header a client sends. Scopes are the routes' business, not
// this endpoint's, so no test here needs any.
func (h *harness) key() string {
	h.t.Helper()

	issued, err := auth.IssueAPIKey(bytes.NewReader(sequence(100, 8*secret.BodyBytes)), func() string { return adminID },
		time.Now(), time.Hour)
	if err != nil {
		h.t.Fatalf("IssueAPIKey: %v", err)
	}

	h.creds.keys[string(issued.Hash)] = store.ActiveAPIKey{
		ID: issued.ID, UserID: adminID, Role: auth.RoleAdmin, ExpiresAt: issued.ExpiresAt, Scope: scope.List{}.JSON(),
	}

	return "Bearer " + issued.Token
}

// session issues a login session and returns the cookie a browser sends.
func (h *harness) session() *http.Cookie {
	h.t.Helper()

	issued, err := auth.IssueSession(
		bytes.NewReader(sequence(1, 8*secret.BodyBytes)), func() string { return adminID }, time.Now())
	if err != nil {
		h.t.Fatalf("IssueSession: %v", err)
	}

	h.creds.sessions[issued.Token] = store.ActiveSession{
		ID: issued.ID, UserID: adminID, Role: auth.RoleAdmin, ExpiresAt: issued.ExpiresAt,
	}

	return auth.SessionCookie(issued)
}

// request is one request to /mcp.
type request struct {
	method        string
	body          string
	contentType   string
	authorization string
	cookie        *http.Cookie
}

// post sends body to /mcp as an API key with the usual headers.
func (h *harness) post(body string) *httptest.ResponseRecorder {
	h.t.Helper()

	return h.do(request{method: http.MethodPost, body: body, contentType: jsonType, authorization: h.key(), cookie: nil})
}

// do sends req through the boundary.
func (h *harness) do(req request) *httptest.ResponseRecorder {
	h.t.Helper()

	var body io.Reader
	if req.body != "" {
		body = strings.NewReader(req.body)
	}

	ctx := context.WithValue(h.t.Context(), ctxKey{}, "marker")
	httpReq := httptest.NewRequestWithContext(ctx, req.method, mcp.Path, body)

	if req.contentType != "" {
		httpReq.Header.Set("Content-Type", req.contentType)
	}

	if req.authorization != "" {
		httpReq.Header.Set("Authorization", req.authorization)
	}

	if req.cookie != nil {
		httpReq.AddCookie(req.cookie)
	}

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httpReq)

	return rec
}

// decode reads body as a generic JSON value.
func decode(t *testing.T, body string) any {
	t.Helper()

	var out any

	err := json.Unmarshal([]byte(body), &out)
	if err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}

	return out
}
