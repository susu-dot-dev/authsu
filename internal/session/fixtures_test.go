package session_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/session"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// routes write through and the boundary resolves credentials through.
var (
	_ session.Store         = (*store.Store)(nil)
	_ auth.CredentialReader = (*store.Store)(nil)
)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB    = errors.New("UPDATE secrets: database is on fire")
	errPlain = errors.New("an error the store forgot to classify")
)

const (
	userID      = "00000000-0000-7000-8000-000000000002"
	otherUserID = "00000000-0000-7000-8000-0000000000ff"
	jsonType    = "application/json"

	unavailableText = "sessions are temporarily unavailable"

	roleAdmin  = "admin"
	roleMember = "member"
)

// The exact bodies a client gets: the code and the fixed message are the
// contract, and a cause never appears.
const (
	bodyUnauthenticated = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bodyVerifyFailed    = `{"error":{"code":"session_verify_failed",` +
		`"message":"sessions are temporarily unavailable"}}` + "\n"
	bodyLogoutFailed = `{"error":{"code":"session_logout_failed",` +
		`"message":"sessions are temporarily unavailable"}}` + "\n"
	bodyInternal = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
)

// revokeCall is one call of RevokeSecret.
type revokeCall struct {
	userID string
	id     string
	now    time.Time
}

// fakeStore is the session store: it records every revocation and answers as it
// is programmed to.
type fakeStore struct {
	// revoked is what RevokeSecret reports; false is a secret another
	// request revoked first.
	revoked bool
	// err, when set, is returned by RevokeSecret.
	err error
	// onRevoked runs when a revocation took effect, so the rest of the
	// fake database can follow: a revoked secret is no longer active.
	onRevoked func(id string)

	calls []revokeCall
}

func (f *fakeStore) RevokeSecret(_ context.Context, userID, id string, now time.Time) (bool, error) {
	f.calls = append(f.calls, revokeCall{userID: userID, id: id, now: now})

	if f.err != nil {
		return false, f.err
	}

	if f.revoked && f.onRevoked != nil {
		f.onRevoked(id)
	}

	return f.revoked, nil
}

// resolveCall is one read of the credential store: what kind of token was
// resolved, by its hash, and when.
type resolveCall struct {
	kind string
	hash string
	now  time.Time
}

// held is a secret the fake database holds as active: exactly one of its
// session and key is set.
type held struct {
	session store.ActiveSession
	key     store.ActiveAPIKey
	kind    string
}

// id is the secret id of the row.
func (h held) id() string {
	if h.kind == auth.KindSession {
		return h.session.ID
	}

	return h.key.ID
}

// fakeCredentials is the credential store: the active secrets by the hash of
// their token, as the database holds them, with a programmable failure. Each
// resolution only finds a secret of its own kind, as the real ones do.
type fakeCredentials struct {
	rows  map[string]held
	err   error
	calls []resolveCall
}

func (f *fakeCredentials) ResolveSession(
	_ context.Context, token input.SessionToken, now time.Time,
) (store.ActiveSession, bool, error) {
	f.calls = append(f.calls, resolveCall{kind: auth.KindSession, hash: string(token.Hash()), now: now})

	if f.err != nil {
		return store.ActiveSession{}, false, f.err
	}

	row, ok := f.rows[string(token.Hash())]
	if !ok || row.kind != auth.KindSession {
		return store.ActiveSession{}, false, nil
	}

	return row.session, true, nil
}

func (f *fakeCredentials) ResolveAPIKey(
	_ context.Context, token input.APIKeyToken, now time.Time,
) (store.ActiveAPIKey, bool, error) {
	f.calls = append(f.calls, resolveCall{kind: auth.KindAPIKey, hash: string(token.Hash()), now: now})

	if f.err != nil {
		return store.ActiveAPIKey{}, false, f.err
	}

	row, ok := f.rows[string(token.Hash())]
	if !ok || row.kind != auth.KindAPIKey {
		return store.ActiveAPIKey{}, false, nil
	}

	return row.key, true, nil
}

// forget removes the active secret with this id, which is what revoking it does.
func (f *fakeCredentials) forget(id string) {
	for hash, row := range f.rows {
		if row.id() == id {
			delete(f.rows, hash)
		}
	}
}

// rig is one deployment under test: the real boundary and the real routes over
// a fake credential store and a fake session store.
type rig struct {
	t     *testing.T
	store *fakeStore
	creds *fakeCredentials

	// authNow is the boundary's clock and logoutNow the session routes'. They
	// differ, so a test can tell which one a call used.
	authNow, logoutNow time.Time

	// entropy supplies the random bytes of every secret the rig issues, so
	// each has its own token.
	entropy io.Reader
	// ids counts the ids the rig has handed out.
	ids int

	// logged records every error the boundary turned into a response.
	logged []*apierr.Error

	// org is the organization of the account of every secret the rig stores
	// from now on.
	org string
}

// rigOrg is the organization of the accounts of a new rig.
const rigOrg = "00000000-0000-7000-8000-0000000000b1"

func newRig(t *testing.T) *rig {
	t.Helper()

	creds := &fakeCredentials{rows: map[string]held{}, err: nil, calls: nil}

	return &rig{
		t: t,
		store: &fakeStore{
			revoked: true, err: nil, calls: nil,
			onRevoked: creds.forget,
		},
		creds:     creds,
		authNow:   time.Now(),
		logoutNow: time.Date(2026, time.November, 17, 12, 30, 45, 987654321, time.UTC),
		entropy:   counterEntropy(),
		ids:       0,
		logged:    nil,
		org:       rigOrg,
	}
}

// counterEntropy is deterministic entropy: each byte is the previous plus one.
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

// newID is the rig's id source: UUID-shaped ids that count up.
func (r *rig) newID() string {
	r.ids++

	return fmt.Sprintf("00000000-0000-7000-8000-%012d", r.ids)
}

// routes are the session routes over the rig's fakes.
func (r *rig) routes() []auth.Route {
	return session.Routes(session.Deps{Store: r.store, Now: func() time.Time { return r.logoutNow }})
}

// handler is the real boundary over the real routes.
func (r *rig) handler() http.Handler {
	return auth.Handler(r.routes(), auth.Deps{
		Credentials: r.creds,
		Now:         func() time.Time { return r.authNow },
		Getenv:      func(string) string { return "" },
		Log:         func(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) },
	})
}

// request is one request to send.
type request struct {
	method, target string
	// contentType defaults to application/json; "-" sends none.
	contentType string
	cookies     []*http.Cookie
	// authorization values are sent as Authorization headers.
	authorization []string
	body          string
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

	for _, value := range req.authorization {
		httpReq.Header.Add("Authorization", value)
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

// bearer is the Authorization header value that presents token.
func bearer(token string) string { return "Bearer " + token }

// activeSession issues a real session of owner with role, stores its row as the
// database would hold an active session that expires at expiresAt, and returns
// the cookie a browser would send and the session's id.
func (r *rig) activeSession(owner, role string, expiresAt time.Time) (*http.Cookie, string) {
	r.t.Helper()

	issued, err := auth.IssueSession(r.entropy, r.newID, r.authNow)
	if err != nil {
		r.t.Fatalf("IssueSession: %v", err)
	}

	r.creds.rows[string(issued.Hash)] = held{
		kind: auth.KindSession,
		session: store.ActiveSession{
			ID: issued.ID, UserID: owner, Role: role, ExpiresAt: expiresAt, OrgID: r.org,
		},
		key: store.ActiveAPIKey{},
	}

	return requestCookie(auth.CookieName, issued.Token), issued.ID
}

// liveKey issues a real API key of owner with role, stores its row as the
// database would hold an active key that expires at expiresAt, and returns the
// token a client would present and the key's id. agentID is "" for a user's own
// key.
func (r *rig) liveKey(owner, role, agentID string, expiresAt time.Time) (string, string) {
	r.t.Helper()

	issued, err := auth.IssueAPIKey(r.entropy, r.newID, r.authNow, auth.AgentKeyLifetime)
	if err != nil {
		r.t.Fatalf("IssueAPIKey: %v", err)
	}

	r.creds.rows[string(issued.Hash)] = held{
		kind:    auth.KindAPIKey,
		session: store.ActiveSession{},
		key: store.ActiveAPIKey{
			ID: issued.ID, UserID: owner, Role: role, ExpiresAt: expiresAt,
			AgentID: agentID, AgentScopes: "", Scope: `["default:session"]`, OrgID: r.org,
		},
	}

	return issued.Token, issued.ID
}

// tokenHash is the hash the credential store resolves token by.
func tokenHash(token string) string {
	hash := secret.Hash(token)

	return string(hash[:])
}
