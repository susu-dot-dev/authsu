package orgs_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	"github.com/susu-dot-dev/authsu/internal/orgs"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file is the package's one fixtures file: the fake of the store, the fake
// of the credential store, and the rig that builds the real boundary around the
// routes under test.

// The real *store.Store is what runs in production, so it must satisfy the
// interfaces the routes and the boundary use.
var (
	_ orgs.Store            = (*store.Store)(nil)
	_ auth.CredentialReader = (*store.Store)(nil)
)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB = errors.New("the database is on fire")
	errIO = errors.New("something nobody classified")
)

const (
	roleMember = auth.RoleMember
	roleAdmin  = auth.RoleAdmin

	// userID signs in. otherID is another user. orgID, sandboxID, offerID and
	// newID are the ids of the things acted on.
	userID    = "01890000-0000-7000-8000-000000000001"
	otherID   = "01890000-0000-7000-8000-0000000000aa"
	orgID     = "01890000-0000-7000-8000-0000000000b1"
	sandboxID = "01890000-0000-7000-8000-0000000000b2"
	offerID   = "01890000-0000-7000-8000-0000000000c1"
	cursorID  = "01890000-0000-7000-8000-0000000000d1"
	invID     = "01890000-0000-7000-8000-0000000000e1"
	newID     = "01890000-0000-7000-8000-0000000000f1"

	jsonType = "application/json"

	unavailableText = "organizations are temporarily unavailable"
)

// The instants the cases are about, in Unix seconds, around the clock every test
// runs at (2030-03-04 05:06:07 UTC): it has no fraction, so the Unix seconds in a
// response are exact.
const (
	now        int64 = 1_898_831_167
	inAWeek          = now + 7*24*60*60
	past             = now - 1
	future           = now + 1
	exactlyNow       = now
)

// clockAt is the clock every test runs at.
//
//nolint:gochecknoglobals // a fixed clock shared by the table tests
var clockAt = time.Unix(now, 0).UTC()

// errorBody is the exact body of a failure with this code and message.
func errorBody(code, message string) string {
	return `{"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n"
}

// Exact bodies of the failures the boundary and the routes produce.
const (
	bodyUnauthenticated = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bodyInternal        = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
	bodyOrgNotFound     = `{"error":{"code":"org_not_found","message":"no such organization"}}` + "\n"
	bodyMemberNotFound  = `{"error":{"code":"member_not_found","message":"no such member"}}` + "\n"
	bodyOfferNotFound   = `{"error":{"code":"offer_not_found","message":"no such offer"}}` + "\n"
)

// unavailable is the failure the store reports for a database that is down: 503
// under the operation's code, with the driver error as the cause.
func unavailable(code string) *apierr.Error {
	return apierr.New(apierr.Unavailable, code, unavailableText).WithCause(errDB)
}

// bodyUnavailable is the exact body of unavailable(code).
func bodyUnavailable(code string) string { return errorBody(code, unavailableText) }

// reply is what one operation of the fake returns.
type reply[T any] struct {
	value T
	err   error
}

// fakeStore is the store with a programmable outcome per operation. It records
// every call as one line naming the operation and every argument it received, so
// a test compares what the route asked for as text.
type fakeStore struct {
	create       reply[store.Org]
	get          reply[store.Org]
	list         reply[store.OrgPage]
	rename       reply[store.Org]
	revoke       reply[store.OrgEnd]
	members      reply[store.MemberPage]
	setAdmin     reply[store.Member]
	removeMember reply[store.Member]
	createOffer  reply[store.Offer]
	orgOffers    reply[store.OfferPage]
	myOffers     reply[store.OfferPage]
	accept       reply[store.Offer]
	revokeOffer  reply[store.Offer]

	calls []string
}

// cursorText is a cursor as the fake records it: its id, or "-" for the first
// page.
func cursorText(cursor input.Cursor) string {
	if id, ok := cursor.ID(); ok {
		return id.String()
	}

	return "-"
}

func (f *fakeStore) CreateOrg(_ context.Context, org store.NewOrg) (store.Org, error) {
	f.recordf("CreateOrg id=%s kind=%s name=%s creator=%s expires=%d limit=%d at=%d",
		org.ID, org.Kind, org.Name, org.Creator, org.ExpiresAt.Unix(), org.Limit, org.CreatedAt.Unix())

	return f.create.value, f.create.err
}

func (f *fakeStore) GetOrg(_ context.Context, id input.ID, caller, adminRole string) (store.Org, error) {
	f.recordf("GetOrg id=%s caller=%s role=%s", id, caller, adminRole)

	return f.get.value, f.get.err
}

func (f *fakeStore) ListOrgs(
	_ context.Context, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
) (store.OrgPage, error) {
	f.recordf("ListOrgs caller=%s role=%s cursor=%s limit=%d", caller, adminRole, cursorText(cursor), limit.Int())

	return f.list.value, f.list.err
}

func (f *fakeStore) RenameOrg(
	_ context.Context, id input.ID, name input.OrgName, caller, adminRole string, now time.Time,
) (store.Org, error) {
	f.recordf("RenameOrg id=%s name=%s caller=%s role=%s at=%d", id, name, caller, adminRole, now.Unix())

	return f.rename.value, f.rename.err
}

func (f *fakeStore) RevokeOrg(
	_ context.Context, id input.ID, caller, adminRole string, now time.Time,
) (store.OrgEnd, error) {
	f.recordf("RevokeOrg id=%s caller=%s role=%s at=%d", id, caller, adminRole, now.Unix())

	return f.revoke.value, f.revoke.err
}

func (f *fakeStore) ListMembers(
	_ context.Context, id input.ID, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
) (store.MemberPage, error) {
	f.recordf("ListMembers id=%s caller=%s role=%s cursor=%s limit=%d",
		id, caller, adminRole, cursorText(cursor), limit.Int())

	return f.members.value, f.members.err
}

func (f *fakeStore) SetMemberAdmin(
	_ context.Context, id input.ID, admin bool, caller, adminRole string, now time.Time,
) (store.Member, error) {
	f.recordf("SetMemberAdmin id=%s admin=%t caller=%s role=%s at=%d", id, admin, caller, adminRole, now.Unix())

	return f.setAdmin.value, f.setAdmin.err
}

func (f *fakeStore) RemoveMember(_ context.Context, id input.ID, caller, adminRole string) (store.Member, error) {
	f.recordf("RemoveMember id=%s caller=%s role=%s", id, caller, adminRole)

	return f.removeMember.value, f.removeMember.err
}

func (f *fakeStore) CreateOffer(_ context.Context, offer store.NewOffer) (store.Offer, error) {
	f.recordf("CreateOffer id=%s org=%s user=%s role=%s caller=%s adminRole=%s at=%d",
		offer.ID, offer.OrgID, offer.UserID, offer.Role, offer.Caller, offer.AdminRole, offer.CreatedAt.Unix())

	return f.createOffer.value, f.createOffer.err
}

func (f *fakeStore) ListOrgOffers(
	_ context.Context, id input.ID, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
) (store.OfferPage, error) {
	f.recordf("ListOrgOffers id=%s caller=%s role=%s cursor=%s limit=%d",
		id, caller, adminRole, cursorText(cursor), limit.Int())

	return f.orgOffers.value, f.orgOffers.err
}

func (f *fakeStore) ListMyOffers(
	_ context.Context, caller string, cursor input.Cursor, limit input.PageLimit,
) (store.OfferPage, error) {
	f.recordf("ListMyOffers caller=%s cursor=%s limit=%d", caller, cursorText(cursor), limit.Int())

	return f.myOffers.value, f.myOffers.err
}

func (f *fakeStore) AcceptOffer(_ context.Context, id input.ID, caller string, now time.Time) (store.Offer, error) {
	f.recordf("AcceptOffer id=%s caller=%s at=%d", id, caller, now.Unix())

	return f.accept.value, f.accept.err
}

func (f *fakeStore) RevokeOffer(_ context.Context, id input.ID, caller, adminRole string) (store.Offer, error) {
	f.recordf("RevokeOffer id=%s caller=%s role=%s", id, caller, adminRole)

	return f.revokeOffer.value, f.revokeOffer.err
}

// recordf notes a call.
func (f *fakeStore) recordf(format string, args ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

// fakeCredentials is the credential store the boundary resolves tokens with: the
// active sessions and API keys by the hash their token has, as the real store
// holds them (the SQL runs only in e2e).
type fakeCredentials struct {
	sessions map[string]store.ActiveSession
	keys     map[string]store.ActiveAPIKey
}

func (f *fakeCredentials) ResolveSession(
	_ context.Context, token input.SessionToken, _ time.Time,
) (store.ActiveSession, bool, error) {
	row, found := f.sessions[string(token.Hash())]

	return row, found, nil
}

func (f *fakeCredentials) ResolveAPIKey(
	_ context.Context, token input.APIKeyToken, _ time.Time,
) (store.ActiveAPIKey, bool, error) {
	row, found := f.keys[string(token.Hash())]

	return row, found, nil
}

// sequence is deterministic entropy: each read returns bytes that differ from
// every other read's, so each issued token is distinct.
type sequence struct{ reads uint64 }

func (s *sequence) Read(p []byte) (int, error) {
	s.reads++

	sum := sha256.Sum256(binary.BigEndian.AppendUint64(nil, s.reads))

	return copy(p, sum[:]), nil
}

// rig is one deployment under test: the real boundary over the organization
// routes and the fakes.
type rig struct {
	t     *testing.T
	store *fakeStore
	creds *fakeCredentials
	// signer is the entropy credentials are issued with, and signs the ids.
	signer *sequence
	signs  int
	// logged records every error the boundary turned into a response.
	logged  []*apierr.Error
	handler http.Handler
}

func newRig(t *testing.T) *rig {
	t.Helper()

	rg := &rig{
		t:      t,
		store:  &fakeStore{},
		creds:  &fakeCredentials{sessions: map[string]store.ActiveSession{}, keys: map[string]store.ActiveAPIKey{}},
		signer: &sequence{},
	}

	rg.handler = auth.Handler(orgs.Routes(orgs.Deps{
		Store: rg.store, Now: func() time.Time { return clockAt }, NewID: func() string { return newID },
	}), auth.Deps{
		Credentials: rg.creds,
		Now:         func() time.Time { return clockAt },
		Getenv:      func(string) string { return "" },
		Log:         func(_ httpapi.Request, failure *apierr.Error) { rg.logged = append(rg.logged, failure) },
	})

	return rg
}

// signID is an id for the rig's own sign-ins, apart from the routes' ids.
func (r *rig) signID() string {
	r.signs++

	return fmt.Sprintf("00000000-0000-7000-8000-%012x", 0x5000+r.signs)
}

// signIn issues a session for owner, with role, stores it as active and returns
// the cookie a browser would send.
func (r *rig) signIn(owner, role string) *http.Cookie {
	r.t.Helper()

	issued, err := auth.IssueSession(r.signer, r.signID, clockAt)
	if err != nil {
		r.t.Fatalf("IssueSession: %v", err)
	}

	r.creds.sessions[string(issued.Hash)] = store.ActiveSession{
		ID: issued.ID, UserID: owner, Role: role, ExpiresAt: issued.ExpiresAt, OrgID: "",
	}

	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: auth.CookieName, Value: issued.Token}
}

// keySpec describes an API key of a user, or of one of their agents.
type keySpec struct {
	// scope is the key's own list, as stored with it.
	scope scope.List
	// agent is the agent the key acts for, or "" for the user's own key; and
	// agentScopes is that agent's stored list, read now.
	agent       string
	agentScopes scope.List
	// sandbox is the sandbox that agent is confined to, or "" for none.
	sandbox string
}

// signInKey issues an API key as spec describes for the account userID, stores
// its row as active, and returns the Authorization header value.
func (r *rig) signInKey(spec keySpec) string {
	r.t.Helper()

	issued, err := auth.IssueAPIKey(r.signer, r.signID, clockAt, time.Hour)
	if err != nil {
		r.t.Fatalf("IssueAPIKey: %v", err)
	}

	r.creds.keys[string(issued.Hash)] = store.ActiveAPIKey{
		ID: issued.ID, UserID: userID, Role: roleMember, ExpiresAt: issued.ExpiresAt,
		AgentID: spec.agent, AgentScopes: spec.agentScopes.JSON(), Scope: spec.scope.JSON(),
		OrgID: "", SandboxID: spec.sandbox,
	}

	return "Bearer " + issued.Token
}

// request is one request to send.
type request struct {
	method, target, body string
	// contentType defaults to application/json; "-" sends none.
	contentType string
	cookies     []*http.Cookie
	// authorization is sent as the Authorization header when set.
	authorization string
}

// serve sends req and returns the response.
func (r *rig) serve(req request) *httptest.ResponseRecorder {
	r.t.Helper()

	var reader io.Reader

	if req.body != "" {
		reader = strings.NewReader(req.body)
	}

	httpReq := httptest.NewRequestWithContext(r.t.Context(), req.method, req.target, reader)

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

	if req.authorization != "" {
		httpReq.Header.Set("Authorization", req.authorization)
	}

	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, httpReq)

	return rec
}

// as sends method target with body, signed in as cookie.
func (r *rig) as(cookie *http.Cookie, method, target, body string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{method: method, target: target, body: body, cookies: []*http.Cookie{cookie}})
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

// wantResponse checks the status, the exact body and the headers every response
// carries, that nothing was set as a cookie, and the code that was logged (none
// for a success).
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

// wantCalls checks the calls the fake recorded, in order.
func wantCalls(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("store calls = %q, want %q", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("store call %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// Stored rows the tests program the fake with.

// storedOrg is a standard organization: active unless the test changes it.
func storedOrg(id string) store.Org {
	return store.Org{
		ID: id, Kind: store.OrgKindStandard, Name: "Acme", CreatedBy: userID, ExpiresAt: nil, RevokedAt: nil,
		CreatedAt: 1_700_000_000,
	}
}

// storedSandbox is a sandbox that expires at expires.
func storedSandbox(id string, expires int64) store.Org {
	org := storedOrg(id)
	org.Kind, org.Name, org.ExpiresAt = store.OrgKindSandbox, "Scratch", &expires

	return org
}

// storedMember is a member of orgID.
func storedMember(id string, admin bool) store.Member {
	return store.Member{ID: id, OrgID: orgID, Admin: admin, RevokedAt: nil, CreatedAt: 1_700_000_001}
}

// storedOffer is an offer to userID.
func storedOffer(id string) store.Offer {
	return store.Offer{
		ID: id, OrgID: orgID, OrgName: "Acme", UserID: new(userID), InvitationID: nil, Role: store.OfferRoleMember,
		CreatedBy: otherID, CreatedAt: 1_700_000_002,
	}
}

// wantRefusal checks a failure whose message is the parser's: the status, the
// code in the body's envelope and in the log, and the headers every response
// carries.
func wantRefusal(t *testing.T, r *rig, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()

	if rec.Code != status || !strings.HasPrefix(rec.Body.String(), `{"error":{"code":"`+code+`","message":"`) {
		t.Errorf("response = %d %q, want %d with code %q", rec.Code, rec.Body.String(), status, code)
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	wantLogged(t, r, code)
}
