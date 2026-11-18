package invitations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// routes are built over.
var _ invitations.Store = (*store.Store)(nil)

const (
	adminID  = "00000000-0000-7000-8000-000000000002"
	memberID = "00000000-0000-7000-8000-000000000003"
	// invID is the invitation the item routes are aimed at; newInvID is the id
	// NewID hands out for a create.
	invID    = "00000000-0000-7000-8000-0000000000aa"
	newInvID = "00000000-0000-7000-8000-0000000000bb"

	roleMember = "member"
	typeCustom = auth.InvitationMember

	jsonType = "application/json"

	apiOrigin = "https://auth.example.com"
	uiOrigin  = "https://example.com"
	testKey   = "invitations-test-secret-0123456789ABCDEFGHIJ"

	itemPath       = "/api/invitation/" + invID
	collectionPath = "/api/invitation"

	// The statuses and codes a client sees, spelled out here and not taken from
	// the package, so that renaming one is noticed.
	statusActive    = "active"
	statusExhausted = "exhausted"
	statusExpired   = "expired"
	statusRevoked   = "revoked"

	codeInvalidFieldType = "invalid_field_type"
	codeUnknownField     = "unknown_field"
	codeInternal         = "internal"

	// garbage is a body that is not JSON.
	garbage = "nope"

	// typeOther is a type a store row may have that is not the creatable one.
	typeOther = "other"

	// The operations of the fake store, as recorded in its calls.
	opList   = "list"
	opCreate = "create"
	opUpdate = "update"
	opRevoke = "revoke"
)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB    = errors.New("INSERT INTO invitations: database is on fire")
	errEntro = errors.New("entropy source is on fire")
)

// fixedNow is the time the clock every route reads is set to. It is a whole
// second, so that a boundary is exactly one second either side of it.
func fixedNow() time.Time { return time.Date(2026, time.November, 17, 12, 0, 0, 0, time.UTC) }

// clock is the injected clock. It counts its readings, because a request must
// read it once.
type clock struct {
	now   time.Time
	calls int
}

func (c *clock) read() time.Time {
	c.calls++

	return c.now
}

// countingReader is entropy that records how many bytes were taken from it, so
// a test can show a refused request consumed none.
type countingReader struct {
	reader io.Reader
	taken  int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.taken += n

	return n, err //nolint:wrapcheck // a test reader passes the wrapped reader's answer through
}

// failingReader is entropy that fails.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errEntro }

// sequence returns n bytes counting up from start, as entropy with a known
// output.
func sequence(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}

	return out
}

// codeOf is the code a create returns for entropy bytes raw: base64url of the
// bytes with no padding, computed here independently of the package.
func codeOf(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// hashOf is the SHA-256 of a code, which is what is stored.
func hashOf(code string) []byte {
	sum := sha256.Sum256([]byte(code))

	return sum[:]
}

// storeCall is one call the fake store received.
type storeCall struct {
	op      string
	id      string
	n       int64
	now     time.Time
	created store.NewInvitation
}

// fakeStore is the invitation store: it records every call and returns what the
// test programmed, as the database would have answered.
type fakeStore struct {
	calls []storeCall

	// err, when set, is returned by every operation.
	err error

	// list is what ListInvitations returns.
	list []store.Invitation
	// created, when set, is what CreateInvitation returns instead of echoing
	// what it was given as the database would.
	created *store.Invitation
	// updated and applied are what UpdateNumInvites returns.
	updated store.Invitation
	applied bool
	// revoked is what RevokeInvitation returns.
	revoked store.Invitation
}

func (f *fakeStore) ListInvitations(context.Context) ([]store.Invitation, error) {
	f.calls = append(f.calls, storeCall{op: opList})

	return f.list, f.err
}

func (f *fakeStore) CreateInvitation(_ context.Context, in store.NewInvitation) (store.Invitation, error) {
	f.calls = append(f.calls, storeCall{op: opCreate, created: in})

	if f.err != nil {
		return store.Invitation{}, f.err
	}

	if f.created != nil {
		return *f.created, nil
	}

	row := store.Invitation{
		ID: in.ID, Type: in.Type, Label: in.Label.String(), NumInvites: in.NumInvites.Int64(), Uses: 0,
		ExpiresAt: nil, RevokedAt: nil, CreatedBy: &in.CreatedBy, CreatedAt: in.CreatedAt.Unix(),
	}

	if in.ExpiresAt != nil {
		expires := in.ExpiresAt.Unix()
		row.ExpiresAt = &expires
	}

	return row, nil
}

func (f *fakeStore) UpdateNumInvites(
	_ context.Context, id input.ID, n input.NumInvites,
) (store.Invitation, bool, error) {
	f.calls = append(f.calls, storeCall{op: opUpdate, id: id.String(), n: n.Int64()})

	if f.err != nil {
		return store.Invitation{}, false, f.err
	}

	return f.updated, f.applied, nil
}

func (f *fakeStore) RevokeInvitation(_ context.Context, id input.ID, now time.Time) (store.Invitation, error) {
	f.calls = append(f.calls, storeCall{op: opRevoke, id: id.String(), now: now})

	return f.revoked, f.err
}

// fakeKeys is the key store the auth boundary reads sessions from.
type fakeKeys struct {
	rows map[string]store.ActiveKey
}

func (f *fakeKeys) ActiveKey(_ context.Context, kid, kind string, _ time.Time) (store.ActiveKey, bool, error) {
	row, ok := f.rows[kid]

	return row, ok && kind == store.KindSession, nil
}

// harness is one deployment under test: the real auth boundary over the routes,
// with a fake store, fake keys and a fixed clock.
type harness struct {
	t      *testing.T
	store  *fakeStore
	keys   *fakeKeys
	clock  *clock
	logged []*apierr.Error

	// deps are the routes' dependencies. A test may change them before the
	// first request, which builds the handler.
	deps    invitations.Deps
	entropy *countingReader
	idCalls int

	handler http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	harn := &harness{
		t: t, store: &fakeStore{}, keys: &fakeKeys{rows: map[string]store.ActiveKey{}},
		clock:   &clock{now: fixedNow()},
		entropy: &countingReader{reader: bytes.NewReader(sequence(0, 8*invitations.CodeBytes))},
	}

	harn.deps = invitations.Deps{
		Store: harn.store, Now: harn.clock.read, Entropy: harn.entropy,
		NewID: func() string {
			harn.idCalls++

			return newInvID
		},
	}

	return harn
}

// build constructs the handler over the current deps.
func (h *harness) build() http.Handler {
	h.t.Helper()

	env := map[string]string{
		config.SecretHMAC: testKey, config.VarAPIOrigin: apiOrigin, config.VarUIOrigin: uiOrigin,
	}

	return auth.Handler(invitations.Routes(h.deps), auth.Deps{
		Keys:   h.keys,
		Now:    time.Now,
		Getenv: func(name string) string { return env[name] },
		Log:    func(_ httpapi.Request, failure *apierr.Error) { h.logged = append(h.logged, failure) },
	})
}

// session creates a real session for owner with role and stores its row, as a
// login would, and returns the cookie a browser sends back. The token's own
// lifetime is measured against the wall clock by the verifier, so it is created
// from the wall clock and not from the fixed test clock.
func (h *harness) session(owner, role string) *http.Cookie {
	h.t.Helper()

	origin, err := config.ParseOrigin(apiOrigin)
	if err != nil {
		h.t.Fatalf("origin: %v", err)
	}

	key, err := auth.CreateSession(auth.IssuerFor(origin), owner, time.Now().Add(time.Hour))
	if err != nil {
		h.t.Fatalf("CreateSession: %v", err)
	}

	h.keys.rows[key.ID.String()] = store.ActiveKey{
		JWK: []byte(key.JWK), UserID: owner, CredentialID: "", Role: role, ExpiresAt: key.ExpiresAt,
	}

	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: auth.CookieName, Value: key.JWT}
}

// admin and member are the two callers: a session of an admin and of a member.
func (h *harness) admin() *http.Cookie  { return h.session(adminID, auth.RoleAdmin) }
func (h *harness) member() *http.Cookie { return h.session(memberID, roleMember) }

// request is one request to send.
type request struct {
	method, target, body string
	cookie               *http.Cookie
	// contentType defaults to application/json.
	contentType string
}

// do sends req through the boundary and returns the response.
func (h *harness) do(req request) *httptest.ResponseRecorder {
	h.t.Helper()

	if h.handler == nil {
		h.handler = h.build()
	}

	var body io.Reader
	if req.body != "" {
		body = strings.NewReader(req.body)
	}

	httpReq := httptest.NewRequestWithContext(h.t.Context(), req.method, req.target, body)

	if req.contentType == "" {
		req.contentType = jsonType
	}

	httpReq.Header.Set("Content-Type", req.contentType)

	if req.cookie != nil {
		httpReq.AddCookie(req.cookie)
	}

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httpReq)

	return rec
}

// asAdmin sends method target body with an admin's session.
func (h *harness) asAdmin(method, target, body string) *httptest.ResponseRecorder {
	h.t.Helper()

	return h.do(request{method: method, target: target, body: body, cookie: h.admin(), contentType: ""})
}

// opsCalled lists the operations the store received, in order.
func (h *harness) opsCalled() []string {
	ops := make([]string, 0, len(h.store.calls))
	for _, call := range h.store.calls {
		ops = append(ops, call.op)
	}

	return ops
}

// wireInvitation is an invitation as a client decodes it, written here
// independently of the package's types so a renamed field is caught.
type wireInvitation struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Label      string  `json:"label"`
	NumInvites int64   `json:"numInvites"`
	Uses       int64   `json:"uses"`
	Status     string  `json:"status"`
	ExpiresAt  *int64  `json:"expiresAt"`
	RevokedAt  *int64  `json:"revokedAt"`
	CreatedBy  *string `json:"createdBy"`
	CreatedAt  int64   `json:"createdAt"`
}

// wireCreated is the body of a created invitation.
type wireCreated struct {
	wireInvitation

	Code string `json:"code"`
}

// wireList is the body of the list.
type wireList struct {
	Invitations []wireInvitation `json:"invitations"`
}

// wireError is the body of a failure.
type wireError struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	} `json:"error"`
}

// decode reads the response body as T and refuses a member T does not name, so
// a field the server added or renamed fails the test.
func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()

	var out T

	decoder := json.NewDecoder(rec.Body)
	decoder.DisallowUnknownFields()

	err := decoder.Decode(&out)
	if err != nil {
		t.Fatalf("response %d %q is not the expected JSON: %v", rec.Code, rec.Body.String(), err)
	}

	return out
}

// wantError checks that rec is a failure with this status and wire code, that it
// was logged once under logCode (which differs from code for an internal
// error, whose code the client never sees), and that no cause leaked into the
// body.
func wantError(
	t *testing.T, harn *harness, rec *httptest.ResponseRecorder, status int, code, logCode string,
) wireError {
	t.Helper()

	body := rec.Body.String()

	var got wireError

	err := json.Unmarshal([]byte(body), &got)
	if err != nil {
		t.Fatalf("failure body %q is not JSON: %v", body, err)
	}

	if rec.Code != status || got.Error.Code != code {
		t.Errorf("response = %d %q, want %d %q (%s)", rec.Code, got.Error.Code, status, code, body)
	}

	if len(harn.logged) != 1 || harn.logged[0].Code != logCode {
		t.Errorf("logged %v, want one error with code %q", harn.logged, logCode)
	}

	for _, leak := range []string{errDB.Error(), errEntro.Error(), "INSERT", "SELECT"} {
		if strings.Contains(body, leak) {
			t.Errorf("failure body leaks %q: %s", leak, body)
		}
	}

	return got
}

// storedRow is an invitation row as the store returns it: five accounts allowed,
// two used, no expiry, not revoked.
func storedRow(mutate func(*store.Invitation)) store.Invitation {
	row := store.Invitation{
		ID: invID, Type: typeCustom, Label: "November workshop", NumInvites: 5, Uses: 2,
		ExpiresAt: nil, RevokedAt: nil, CreatedBy: nil, CreatedAt: fixedNow().Unix() - 100,
	}

	if mutate != nil {
		mutate(&row)
	}

	return row
}

// storeFailure is a way the store can fail and what the client is told. The
// store classifies its own failures, and a route sends them unchanged.
type storeFailure struct {
	name string
	err  error
	// status and wireCode are the response; logCode is what the log records,
	// which differs for an internal error, whose code the client never sees.
	status   int
	wireCode string
	logCode  string
}

// storeFailures are the three failures of an operation with these codes: the
// database failing (503), the schema refusing (500), and an error nobody
// classified (500, which must not leak).
func storeFailures(failed, rejected string) []storeFailure {
	return []storeFailure{
		{
			"database unavailable",
			apierr.Wrap(errDB, apierr.Unavailable, failed, "invitations are temporarily unavailable"),
			http.StatusServiceUnavailable, failed, failed,
		},
		{
			"schema rejects it",
			apierr.Wrap(errDB, apierr.Internal, rejected, "internal error"),
			http.StatusInternalServerError, codeInternal, rejected,
		},
		{"unclassified error", errDB, http.StatusInternalServerError, codeInternal, codeInternal},
	}
}
