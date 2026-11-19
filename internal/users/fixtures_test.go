package users_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
	"github.com/susu-dot-dev/authsu/internal/users"
)

// This file is the package's one fixtures file: the fakes of the account store
// and of the credential store, and the rig that builds the real boundary around
// the routes under test.

// The real *store.Store is what runs in production, so it must satisfy the
// interfaces the routes and the boundary use.
var (
	_ users.Store           = (*store.Store)(nil)
	_ auth.CredentialReader = (*store.Store)(nil)
)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB = errors.New("the database is on fire")
	errIO = errors.New("something nobody classified")
)

const (
	roleMember = "member"
	roleAdmin  = auth.RoleAdmin

	// adminID is the account that signs in. targetID is the account acted on.
	adminID  = "01890000-0000-7000-8000-000000000001"
	targetID = "01890000-0000-7000-8000-0000000000aa"
	// invitationID is the invitation every account came from.
	invitationID = "01890000-0000-7000-8000-0000000000bb"

	profileAda = `{"name":"Ada"}`

	// sessionBody is a canonical token body (43 base64url characters, the last
	// with its two unused low bits zero) that no issued session has.
	sessionBody = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefA"

	collection = "/api/user"
	itemPrefix = "/api/user/"

	jsonType = "application/json"

	unavailableText = "users are temporarily unavailable"
	internalBody    = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
)

// errorBody is the exact body of a failure with this code and message.
func errorBody(code, message string) string {
	return `{"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n"
}

// Exact bodies of the failures the boundary and the routes produce.
const (
	bodyUnauthenticated = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bodyForbidden       = `{"error":{"code":"forbidden","message":"administrator access is required"}}` + "\n"
	bodyNotFound        = `{"error":{"code":"user_not_found","message":"no such user"}}` + "\n"
	bodyLastAdmin       = `{"error":{"code":"user_last_admin",` +
		`"message":"the last active administrator cannot be revoked"}}` + "\n"
	bodyInvalidID = `{"error":{"code":"invalid_id","message":` +
		`"id must be a lower-case UUID such as 01234567-89ab-cdef-0123-456789abcdef"}}` + "\n"
	bodyUnavailableSession = `{"error":{"code":"session_verify_failed",` +
		`"message":"sessions are temporarily unavailable"}}` + "\n"
	bodyNoRoute  = `{"error":{"code":"not_found","message":"no such route"}}` + "\n"
	bodyTooLarge = `{"error":{"code":"body_too_large","message":"request body is too large"}}` + "\n"
)

// The operations the fake store records.
const (
	opList   = "list"
	opGet    = "get"
	opRevoke = "revoke"
)

// unavailable is the failure the store reports for a database that is down: 503
// under the operation's code, with the driver error as the cause.
func unavailable(code string) *apierr.Error {
	return apierr.New(apierr.Unavailable, code, unavailableText).WithCause(errDB)
}

// rejected is the failure the store reports for a defect: 500 under the
// operation's code.
func rejected(code string) *apierr.Error {
	return apierr.New(apierr.Internal, code, "internal error").WithCause(errDB)
}

// bodyUnavailable is the exact body of unavailable(code).
func bodyUnavailable(code string) string { return errorBody(code, unavailableText) }

// storeCall is one call to the account store.
type storeCall struct {
	op   string
	id   string
	role string
	now  time.Time
}

// fakeStore is the account store with a programmable outcome per operation. It
// records every call.
type fakeStore struct {
	users   []store.User
	listErr error

	got    store.User
	getErr error

	revoked   store.User
	revokeErr error

	calls []storeCall
}

func (f *fakeStore) ListUsers(context.Context) ([]store.User, error) {
	f.calls = append(f.calls, storeCall{op: opList, id: "", role: "", now: time.Time{}})

	return f.users, f.listErr
}

func (f *fakeStore) GetUser(_ context.Context, id input.ID) (store.User, error) {
	f.calls = append(f.calls, storeCall{op: opGet, id: id.String(), role: "", now: time.Time{}})

	return f.got, f.getErr
}

func (f *fakeStore) RevokeUser(_ context.Context, id input.ID, adminRole string, now time.Time) (store.User, error) {
	f.calls = append(f.calls, storeCall{op: opRevoke, id: id.String(), role: adminRole, now: now})

	return f.revoked, f.revokeErr
}

// fakeCredentials is the credential store the boundary verifies sessions
// against: the active sessions the database would hold, by token, as the store
// reports them after applying its own active predicate (the SQL runs only in
// e2e). It records every read, so a test can assert that a refused request cost
// none.
type fakeCredentials struct {
	rows map[string]store.ActiveSession
	// err, when set, is what every read fails with.
	err error
	// reads is how many times the store was asked to resolve a credential.
	reads int
}

func (f *fakeCredentials) ResolveSession(
	_ context.Context, token input.SessionToken, _ time.Time,
) (store.ActiveSession, bool, error) {
	f.reads++

	if f.err != nil {
		return store.ActiveSession{}, false, f.err
	}

	row, ok := f.rows[token.String()]

	return row, ok, nil
}

// ResolveAPIKey finds no key: these routes are exercised through sessions, and
// a key presented to them is unknown.
func (f *fakeCredentials) ResolveAPIKey(
	context.Context, input.APIKeyToken, time.Time,
) (store.ActiveAPIKey, bool, error) {
	f.reads++

	return store.ActiveAPIKey{}, false, f.err
}

// sequence is deterministic entropy: each read returns bytes that differ from
// every other read's, so each issued token is distinct.
type sequence struct{ reads uint64 }

func (s *sequence) Read(p []byte) (int, error) {
	s.reads++

	sum := sha256.Sum256(binary.BigEndian.AppendUint64(nil, s.reads))

	return copy(p, sum[:]), nil
}

// rig is one deployment under test: the real boundary over the account routes
// and the fakes.
type rig struct {
	t     *testing.T
	store *fakeStore
	creds *fakeCredentials
	// now is the clock of both the boundary and the routes.
	now     time.Time
	entropy *sequence
	ids     int
	// logged records every error the boundary turned into a response.
	logged  []*apierr.Error
	handler http.Handler
}

// log records an error the boundary or a handler logged.
func (r *rig) log(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) }

// newID is the id source sessions are issued with: distinct UUID-shaped values.
func (r *rig) newID() string {
	r.ids++

	return fmt.Sprintf("01890000-0000-7000-8000-%012x", 0x1000+r.ids)
}

func newRig(t *testing.T) *rig {
	t.Helper()

	env := map[string]string{
		config.SecretHMAC:   "users-test-secret-0123456789ABCDEFGHIJKLMNOPQ",
		config.VarAPIOrigin: "https://auth.example.com",
		config.VarUIOrigin:  "https://example.com",
	}

	rg := &rig{
		t:       t,
		store:   &fakeStore{},
		creds:   &fakeCredentials{rows: map[string]store.ActiveSession{}},
		now:     time.Now(),
		entropy: &sequence{reads: 0},
		ids:     0,
		logged:  nil,
		handler: nil,
	}

	clock := func() time.Time { return rg.now }

	rg.handler = auth.Handler(users.Routes(users.Deps{Store: rg.store, Now: clock, Log: rg.log}), auth.Deps{
		Credentials: rg.creds,
		Now:         clock,
		Getenv:      func(name string) string { return env[name] },
		Log:         rg.log,
	})

	return rg
}

// signIn issues a real session token for owner, whose account has role, stores
// its row as the credential store would report it, and returns the cookie a
// browser sends back.
func (r *rig) signIn(owner, role string) *http.Cookie {
	r.t.Helper()

	issued, err := auth.IssueSession(r.entropy, r.newID, r.now)
	if err != nil {
		r.t.Fatalf("IssueSession: %v", err)
	}

	r.creds.rows[issued.Token] = store.ActiveSession{
		ID: issued.ID, UserID: owner, Role: role, ExpiresAt: issued.ExpiresAt,
	}

	return sessionCookie(issued.Token)
}

// sessionCookie is the session cookie as a browser returns it: only a name and a
// value.
func sessionCookie(value string) *http.Cookie {
	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: auth.CookieName, Value: value}
}

// as sends method and target as the account the cookie signs in, or with no
// cookie when it is nil.
func (r *rig) as(cookie *http.Cookie, method, target string) *httptest.ResponseRecorder {
	r.t.Helper()

	req := request{method: method, target: target, body: "", contentType: "", cookies: nil}
	if cookie != nil {
		req.cookies = []*http.Cookie{cookie}
	}

	return r.do(req)
}

// request is one request to send.
type request struct {
	method, target, body string
	// contentType defaults to application/json; "-" sends none.
	contentType string
	cookies     []*http.Cookie
}

// do sends req through the boundary.
func (r *rig) do(req request) *httptest.ResponseRecorder {
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
	r.handler.ServeHTTP(rec, httpReq)

	return rec
}

// route is one of the three routes, as a client calls it.
type route struct {
	name   string
	method string
	// target is the request target; item routes are called for targetID.
	target string
	// op is the store operation the route calls.
	op string
}

// routes are the three routes, called for targetID.
func routes() []route {
	return []route{
		{name: opList, method: http.MethodGet, target: collection, op: "list"},
		{name: "get", method: http.MethodGet, target: itemPrefix + targetID, op: opGet},
		{name: "revoke", method: http.MethodDelete, target: itemPrefix + targetID, op: opRevoke},
	}
}

// userRow is the stored account id, as an active member with a profile.
func userRow(id string) store.User {
	return store.User{
		ID: id, Role: roleMember, InvitationID: invitationID, Profile: profileAda,
		RevokedAt: nil, CreatedAt: 1_700_000_000,
	}
}

// userJSON is the exact JSON of an account as an admin sees it.
func userJSON(id, role, profile, status string, revoked *int64, created string) string {
	out := `{"id":"` + id + `","role":"` + role + `","invitationId":"` + invitationID + `","profile":` + profile +
		`,"status":"` + status + `"`

	if revoked != nil {
		out += `,"revokedAt":` + itoa(*revoked)
	}

	return out + `,"createdAt":` + created + `}`
}

// itoa formats an integer the way JSON writes it.
func itoa(n int64) string {
	data, err := json.Marshal(n)
	if err != nil {
		panic(err)
	}

	return string(data)
}

// wantCalls checks the store calls the fake recorded, by value.
func wantCalls(t *testing.T, got, want []storeCall) {
	t.Helper()

	if len(got) == 0 && len(want) == 0 {
		return
	}

	if len(got) != len(want) {
		t.Fatalf("store calls = %+v, want %+v", got, want)
	}

	for i := range want {
		if got[i].op != want[i].op || got[i].id != want[i].id || got[i].role != want[i].role ||
			!got[i].now.Equal(want[i].now) {
			t.Errorf("store call %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// wantResponse checks the status, the exact body and the headers every
// response carries, that nothing was set as a cookie, and the code that was
// logged (none for a success).
func wantResponse(t *testing.T, r *rig, rec *httptest.ResponseRecorder, status int, body, logged string) {
	t.Helper()

	if rec.Code != status || rec.Body.String() != body {
		t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), status, body)
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("the response set cookies: %v", rec.Result().Cookies())
	}

	wantLogged(t, r, logged)
}

// wantLogged checks that the boundary logged exactly one error, with this code,
// or none when code is "".
func wantLogged(t *testing.T, r *rig, code string) {
	t.Helper()

	switch {
	case code == "" && len(r.logged) != 0:
		t.Errorf("a success logged %v", r.logged)
	case code != "" && len(r.logged) != 1:
		t.Errorf("logged %d errors, want one %q: %v", len(r.logged), code, r.logged)
	case code != "" && r.logged[0].Code != code:
		t.Errorf("logged code = %q, want %q", r.logged[0].Code, code)
	}
}

// wantNoHandle fails when a success body carries the user handle under any
// spelling, or any member beyond the account's view. body is a list response
// or one account.
func wantNoHandle(t *testing.T, body string) {
	t.Helper()

	if strings.Contains(strings.ToLower(body), "handle") {
		t.Errorf("body mentions a user handle: %s", body)
	}

	var decoded map[string]json.RawMessage

	err := json.Unmarshal([]byte(body), &decoded)
	if err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}

	views := []json.RawMessage{json.RawMessage(body)}

	if list, isList := decoded["users"]; isList {
		err = json.Unmarshal(list, &views)
		if err != nil {
			t.Fatalf("users is not a list: %v", err)
		}
	}

	allowed := []string{"id", "role", "invitationId", "profile", "status", "revokedAt", "createdAt"}

	for _, view := range views {
		var members map[string]json.RawMessage

		err = json.Unmarshal(view, &members)
		if err != nil {
			t.Fatalf("view is not an object: %v", err)
		}

		for name := range members {
			if !slices.Contains(allowed, name) {
				t.Errorf("view has an unexpected member %q: %s", name, view)
			}
		}
	}
}

// clockAt is the time the revoke tests run at: it has nanoseconds and is not in
// UTC, so a store that is handed anything but this instant is visible.
//
//nolint:gochecknoglobals // a fixed clock shared by the table tests
var clockAt = time.Date(2026, time.November, 17, 12, 30, 45, 123_456_789, time.FixedZone("test", 5*60*60))

// readCall is the call of a read: it has no role and no time.
func readCall(op, id string) storeCall { return storeCall{op: op, id: id, role: "", now: time.Time{}} }

// revokeCall is the call a revocation of id makes at clockAt.
func revokeCall(id string) storeCall {
	return storeCall{op: opRevoke, id: id, role: auth.RoleAdmin, now: clockAt}
}

// outcomeCase is one request to a route, with the store programmed to answer it
// and what the client and the store must see.
type outcomeCase struct {
	name string
	// program sets the store's outcomes; the clock is clockAt.
	program func(*fakeStore)
	status  int
	// body is the exact response body.
	body string
	// logged is the code of the error the boundary logged, "" for a success.
	logged string
	// calls are the store calls that must have been made, in order.
	calls []storeCall
}

// runOutcomes signs in as an administrator and sends the route's request once
// per case.
func runOutcomes(t *testing.T, rt route, cases []outcomeCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			cookie := rg.signIn(adminID, roleAdmin)
			rg.now = clockAt

			tc.program(rg.store)

			rec := rg.as(cookie, rt.method, rt.target)

			wantResponse(t, rg, rec, tc.status, tc.body, tc.logged)
			wantCalls(t, rg.store.calls, tc.calls)

			if tc.status == http.StatusOK {
				wantNoHandle(t, rec.Body.String())
			}
		})
	}
}
