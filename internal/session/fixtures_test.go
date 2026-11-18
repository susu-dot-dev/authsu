package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/session"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// routes write through and the boundary reads keys through.
var (
	_ session.Store  = (*store.Store)(nil)
	_ auth.KeyReader = (*store.Store)(nil)
)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB    = errors.New("UPDATE japikeys: database is on fire")
	errPlain = errors.New("an error the store forgot to classify")
)

const (
	testSecret  = "session-test-secret-0123456789ABCDEFGHIJKLMNOP"
	apiOrigin   = "https://auth.example.com"
	uiOrigin    = "https://example.com"
	userID      = "00000000-0000-7000-8000-000000000002"
	otherUserID = "00000000-0000-7000-8000-0000000000ff"
	credential  = "00000000-0000-7000-8000-000000000001"
	jsonType    = "application/json"

	unavailableText = "sessions are temporarily unavailable"

	roleAdmin  = "admin"
	roleMember = "member"
)

// The exact bodies a client gets: the code and the fixed message are the
// contract, and a cause never appears.
const (
	bodyUnauthenticated = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bodyNotConfigured   = `{"error":{"code":"not_configured","message":"the service is not configured"}}` + "\n"
	bodyVerifyFailed    = `{"error":{"code":"session_verify_failed",` +
		`"message":"sessions are temporarily unavailable"}}` + "\n"
	bodyLogoutFailed = `{"error":{"code":"session_logout_failed",` +
		`"message":"sessions are temporarily unavailable"}}` + "\n"
	bodyInternal = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
)

// revokeCall is one call of RevokeKey.
type revokeCall struct {
	userID string
	kid    string
	now    time.Time
}

// fakeStore is the session store: it records every revocation and answers as it
// is programmed to.
type fakeStore struct {
	// revoked is what RevokeKey reports; false is a session another
	// request revoked first.
	revoked bool
	// err, when set, is returned by RevokeKey.
	err error
	// onRevoked runs when a revocation took effect, so the rest of the
	// fake database can follow: a revoked session is no longer active.
	onRevoked func(kid string)

	calls []revokeCall
}

func (f *fakeStore) RevokeKey(_ context.Context, userID, kid string, now time.Time) (bool, error) {
	f.calls = append(f.calls, revokeCall{userID: userID, kid: kid, now: now})

	if f.err != nil {
		return false, f.err
	}

	if f.revoked && f.onRevoked != nil {
		f.onRevoked(kid)
	}

	return f.revoked, nil
}

// keyCall is one read of the key store.
type keyCall struct {
	kid, kind string
	now       time.Time
}

// fakeKeys is the key store: rows by kid, as the database holds active
// sessions, with a programmable failure.
type fakeKeys struct {
	rows  map[string]store.ActiveKey
	err   error
	calls []keyCall
}

func (f *fakeKeys) ActiveKey(_ context.Context, kid, kind string, now time.Time) (store.ActiveKey, bool, error) {
	f.calls = append(f.calls, keyCall{kid: kid, kind: kind, now: now})

	if f.err != nil {
		return store.ActiveKey{}, false, f.err
	}

	row, ok := f.rows[kid]

	return row, ok, nil
}

// rig is one deployment under test: the real boundary and the real routes over
// a fake key store and a fake session store.
type rig struct {
	t     *testing.T
	store *fakeStore
	keys  *fakeKeys
	env   map[string]string

	// authNow is the boundary's clock and logoutNow the session routes'. They
	// differ, so a test can tell which one a call used.
	authNow, logoutNow time.Time

	// logged records every error the boundary turned into a response.
	logged []*apierr.Error
}

func newRig(t *testing.T) *rig {
	t.Helper()

	keys := &fakeKeys{rows: map[string]store.ActiveKey{}, err: nil, calls: nil}

	return &rig{
		t: t,
		store: &fakeStore{
			revoked: true, err: nil, calls: nil,
			onRevoked: func(kid string) { delete(keys.rows, kid) },
		},
		keys: keys,
		env: map[string]string{
			config.SecretHMAC: testSecret, config.VarAPIOrigin: apiOrigin, config.VarUIOrigin: uiOrigin,
		},
		authNow:   time.Now(),
		logoutNow: time.Date(2026, time.November, 17, 12, 30, 45, 987654321, time.UTC),
		logged:    nil,
	}
}

// routes are the session routes over the rig's fakes.
func (r *rig) routes() []auth.Route {
	return session.Routes(session.Deps{Store: r.store, Now: func() time.Time { return r.logoutNow }})
}

// handler is the real boundary over the real routes.
func (r *rig) handler() http.Handler {
	return auth.Handler(r.routes(), auth.Deps{
		Keys:   r.keys,
		Now:    func() time.Time { return r.authNow },
		Getenv: func(name string) string { return r.env[name] },
		Log:    func(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) },
	})
}

// request is one request to send.
type request struct {
	method, target string
	// contentType defaults to application/json; "-" sends none.
	contentType string
	cookies     []*http.Cookie
	body        string
}

// serve sends req to the boundary and returns the response.
func (r *rig) serve(req request) *httptest.ResponseRecorder {
	r.t.Helper()

	httpReq := httptest.NewRequestWithContext(r.t.Context(), req.method, req.target, strings.NewReader(req.body))

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

// requestCookie is a cookie as a browser returns it: only a name and a value.
func requestCookie(name, value string) *http.Cookie {
	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: name, Value: value}
}

// activeSession creates a real session of owner with role that expires at
// expiresAt according to its stored row, stores its row as the database would
// hold an active session, and returns the cookie a browser would send and the
// kid.
func (r *rig) activeSession(owner, role string, expiresAt time.Time) (*http.Cookie, string) {
	r.t.Helper()

	issuer := auth.IssuerFor(origin(r.t, apiOrigin))

	key, err := auth.CreateSession(issuer, owner, r.authNow.Add(auth.SessionLifetime))
	if err != nil {
		r.t.Fatalf("CreateSession: %v", err)
	}

	r.keys.rows[key.ID.String()] = store.ActiveKey{
		JWK: []byte(key.JWK), UserID: owner, CredentialID: credential, Role: role, ExpiresAt: expiresAt,
	}

	return requestCookie(auth.CookieName, key.JWT), key.ID.String()
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
