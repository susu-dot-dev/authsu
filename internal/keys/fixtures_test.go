package keys_test

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/keys"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// routes are written against.
var _ keys.Store = (*store.Store)(nil)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB      = errors.New("INSERT INTO api_keys: database is on fire")
	errEntropy = errors.New("the entropy source is broken")
	errNotNull = errors.New("D1_ERROR: SQLITE_CONSTRAINT_NOTNULL: NOT NULL")
)

// Users, keys and names the tables share.
const (
	userA = "00000000-0000-7000-8000-00000000000a"
	userB = "00000000-0000-7000-8000-00000000000b"

	// Keys of user A, user B, and one nobody has. keyB0 sorts below every other
	// key, so a cursor at a key of user A still has one of user B's below it.
	keyA1  = "00000000-0000-7000-8000-0000000000a1"
	keyA2  = "00000000-0000-7000-8000-0000000000a2"
	keyA3  = "00000000-0000-7000-8000-0000000000a3"
	keyB1  = "00000000-0000-7000-8000-0000000000b1"
	keyB0  = "00000000-0000-7000-8000-000000000001"
	nobody = "00000000-0000-7000-8000-0000000000ee"

	// agentKey is the id of a key that belongs to an agent of user A: it is in
	// the store with an owner, and is never one of the user's own.
	agentKey = "00000000-0000-7000-8000-0000000000f1"
	agentA1  = "00000000-0000-7000-8000-0000000000c1"

	// newKeyID is the id NewID hands out first, for the new key.
	newKeyID = "00000000-0000-7000-8000-0000000000dd"

	roleMember = "member"
	roleAdmin  = auth.RoleAdmin

	jsonType = "application/json"

	// Names of the routes, and of cases several tables share.
	routeList   = "list"
	routeCreate = "create"
	routeGet    = "get"
	routePatch  = "patch"
	routeRevoke = "revoke"
	nameCI      = "ci"

	caseUpper = "upper case"

	// Codes that several tables name.
	codeInvalidName = "invalid_key_name"
	codeInvalidID   = "invalid_id"
	codeLimit       = "invalid_limit"
	codeCursor      = "invalid_cursor"
	codeNoRoute     = "not_found"
	codeNotAllowed  = "method_not_allowed"

	codeLifetime  = "invalid_key_lifetime"
	codeFieldType = "invalid_field_type"
	codeUnknown   = "unknown_field"
	codeBadJSON   = "invalid_json"
	valueNope     = "nope"

	defaultUserJSON = `["default:user"]`

	// Bodies several tables send.
	bodyCI      = `{"name":"ci"}`
	bodyRenamed = `{"name":"renamed"}`
	itemPattern = "/api/key/{id}"

	collection = "/api/key"
	itemPrefix = "/api/key/"
)

// Names of the methods of fakeStore, for its call log and its programmed
// failures.
const (
	methodList   = "ListKeys"
	methodGet    = "GetKey"
	methodCreate = "CreateKey"
	methodRename = "RenameKey"
	methodRevoke = "RevokeKey"
)

// unavailableErr is how the store reports a database that failed: 503 under the
// operation's code.
func unavailableErr(code string) *apierr.Error {
	return apierr.New(apierr.Unavailable, code, "keys are temporarily unavailable").WithCause(errDB)
}

// internalErr is how the store reports a write the schema rejected, or a result
// that is not the shape promised: 500 under the operation's code.
func internalErr(code string) *apierr.Error {
	return apierr.New(apierr.Internal, code, "internal error").WithCause(errDB)
}

// storeCall is one call to the fake store, with everything it was given.
type storeCall struct {
	method string
	owner  string
	id     string
	// cursor is the cursor's id, "" for the first page.
	cursor string
	limit  int
	now    time.Time
	// except is the presented secret's id of a revoke.
	except string
	// key is the NewKey of a create, name the KeyName of a rename.
	key  store.NewKey
	name string
}

// ownedKey is a key as the fake database holds it: with its owner, and the
// agent it belongs to, if any.
type ownedKey struct {
	owner, agent string
	key          store.Key
}

// fakeStore is the key store: the rows of every user, scoped by owner and to keys
// with no agent as the real one is, with a programmable failure per method. It
// records every call.
type fakeStore struct {
	rows []ownedKey
	// failures are returned by the named method instead of its normal outcome.
	failures map[string]error
	calls    []storeCall
}

// ListKeys is the contract of store.ListKeys: the owner's own keys with an id
// below the cursor, newest first, at most limit, and Next set when more remain.
func (f *fakeStore) ListKeys(
	_ context.Context, owner string, cursor input.Cursor, limit input.PageLimit,
) (store.KeyPage, error) {
	before := ""
	if id, ok := cursor.ID(); ok {
		before = id.String()
	}

	f.calls = append(f.calls, storeCall{method: methodList, owner: owner, cursor: before, limit: limit.Int()})

	err := f.fail(methodList)
	if err != nil {
		return store.KeyPage{}, err
	}

	mine := []store.Key{}

	for _, row := range f.rows {
		if row.owner == owner && row.agent == "" && (before == "" || row.key.ID < before) {
			mine = append(mine, row.key)
		}
	}

	slices.SortFunc(mine, func(a, b store.Key) int { return cmp.Compare(b.ID, a.ID) })

	if len(mine) <= limit.Int() {
		return store.KeyPage{Keys: mine, Next: ""}, nil
	}

	mine = mine[:limit.Int()]

	return store.KeyPage{Keys: mine, Next: mine[len(mine)-1].ID}, nil
}

// GetKey is the contract of store.GetKey.
func (f *fakeStore) GetKey(_ context.Context, owner string, id input.ID) (store.Key, error) {
	f.calls = append(f.calls, storeCall{method: methodGet, owner: owner, id: id.String()})

	err := f.fail(methodGet)
	if err != nil {
		return store.Key{}, err
	}

	at, ok := f.find(owner, id.String())
	if !ok {
		return store.Key{}, store.ErrNotFound
	}

	return f.rows[at].key, nil
}

// CreateKey is the contract of store.CreateKey. A programmed failure is returned
// before anything is written.
func (f *fakeStore) CreateKey(_ context.Context, key store.NewKey) error {
	f.calls = append(f.calls, storeCall{method: methodCreate, owner: key.Owner, key: key})

	err := f.fail(methodCreate)
	if err != nil {
		return err
	}

	f.rows = append(f.rows, ownedKey{owner: key.Owner, agent: "", key: store.Key{
		ID: key.ID, Name: key.Name.String(), Scope: key.Scope, ExpiresAt: key.ExpiresAt.Unix(), RevokedAt: nil,
		CreatedAt: key.CreatedAt.Unix(),
	}})

	return nil
}

// active reports whether key is neither revoked nor expired at now.
func active(key store.Key, now time.Time) bool {
	return (key.RevokedAt == nil || *key.RevokedAt > now.Unix()) && key.ExpiresAt > now.Unix()
}

// RenameKey is the contract of store.RenameKey: a key that is no longer active
// is returned as it is.
func (f *fakeStore) RenameKey(
	_ context.Context, owner string, id input.ID, name input.KeyName, now time.Time,
) (store.Key, error) {
	f.calls = append(f.calls,
		storeCall{method: methodRename, owner: owner, id: id.String(), name: name.String(), now: now})

	err := f.fail(methodRename)
	if err != nil {
		return store.Key{}, err
	}

	at, ok := f.find(owner, id.String())
	if !ok {
		return store.Key{}, store.ErrNotFound
	}

	if active(f.rows[at].key, now) {
		f.rows[at].key.Name = name.String()
	}

	return f.rows[at].key, nil
}

// RevokeKey is the contract of store.RevokeKey: the presented secret is never
// revoked and is not found, and a key already revoked keeps its earlier time.
func (f *fakeStore) RevokeKey(
	_ context.Context, owner string, id input.ID, except string, now time.Time,
) (store.Key, error) {
	f.calls = append(f.calls,
		storeCall{method: methodRevoke, owner: owner, id: id.String(), except: except, now: now})

	err := f.fail(methodRevoke)
	if err != nil {
		return store.Key{}, err
	}

	at, ok := f.find(owner, id.String())
	if !ok || id.String() == except {
		return store.Key{}, store.ErrNotFound
	}

	if f.rows[at].key.RevokedAt == nil || *f.rows[at].key.RevokedAt > now.Unix() {
		unix := now.Unix()
		f.rows[at].key.RevokedAt = &unix
	}

	return f.rows[at].key, nil
}

// find returns the position of the own key of owner with id: a key with no agent.
func (f *fakeStore) find(owner, id string) (int, bool) {
	at := slices.IndexFunc(f.rows, func(row ownedKey) bool {
		return row.owner == owner && row.agent == "" && row.key.ID == id
	})

	return at, at >= 0
}

// fail is the failure programmed for method, if any.
func (f *fakeStore) fail(method string) error { return f.failures[method] }

// key returns the stored key with id, whoever owns it.
func (f *fakeStore) key(t *testing.T, id string) store.Key {
	t.Helper()

	at := slices.IndexFunc(f.rows, func(row ownedKey) bool { return row.key.ID == id })
	if at < 0 {
		t.Fatalf("the store has no key %s", id)
	}

	return f.rows[at].key
}

// stored is a stored key that expires far in the future, so it is active at the
// rig's clock, with the fixture's scopes.
func stored(id, name string, createdAt int64, revokedAt *int64) store.Key {
	return store.Key{
		ID: id, Name: name, Scope: keys.DefaultScopes().JSON(), ExpiresAt: farFuture, RevokedAt: revokedAt,
		CreatedAt: createdAt,
	}
}

// farFuture is a Unix time long after the rig's clock (2030).
const farFuture = int64(4_102_444_800)

// fakeCredentials is the credential store the boundary resolves tokens with: the
// active sessions and API keys by the hash their token has, as the real store
// holds them.
type fakeCredentials struct {
	sessions map[string]store.ActiveSession
	keys     map[string]store.ActiveAPIKey
}

// ResolveSession answers for an active session.
func (f *fakeCredentials) ResolveSession(
	_ context.Context, token input.SessionToken, _ time.Time,
) (store.ActiveSession, bool, error) {
	row, found := f.sessions[string(token.Hash())]

	return row, found, nil
}

// ResolveAPIKey answers for an active API key.
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

// sequence is a deterministic source of entropy: each read returns bytes that
// differ from every other read's, so issued tokens are distinct.
type sequence struct{ reads uint64 }

func (s *sequence) Read(p []byte) (int, error) {
	s.reads++

	sum := sha256.Sum256(binary.BigEndian.AppendUint64(nil, s.reads))

	return copy(p, sum[:]), nil
}

// brokenReader is an entropy source that always fails.
type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errEntropy }

// issueCall is one call to the IssueUserAPIKey the routes were given.
type issueCall struct {
	now      time.Time
	lifetime time.Duration
	issued   auth.Issued
	err      error
}

// rig is one deployment under test: the real boundary and the real key routes
// over a fake store, a fake credential store and a clock the test controls.
type rig struct {
	t     *testing.T
	store *fakeStore
	creds *fakeCredentials
	// now is the clock the routes run on.
	now time.Time
	// entropy is what the routes issue keys from. signer is the separate source
	// the rig's own sign-ins use, so the two never produce the same token.
	entropy io.Reader
	signer  *sequence
	// ids is how many ids NewID has handed out, and signs how many the rig's own
	// sign-ins have used.
	ids, signs int
	// issueCalls records every key the routes issued, and issueErr, when set,
	// makes issuing fail without calling auth.IssueUserAPIKey.
	issueCalls []issueCall
	issueErr   error
	// logged records every error the boundary turned into a response.
	logged  []*apierr.Error
	handler http.Handler
}

func newRig(t *testing.T) *rig {
	t.Helper()

	rg := &rig{
		t:     t,
		store: &fakeStore{rows: nil, failures: map[string]error{}, calls: nil},
		creds: &fakeCredentials{sessions: map[string]store.ActiveSession{}, keys: map[string]store.ActiveAPIKey{}},
		// A fixed instant, in whole seconds: the response carries Unix seconds.
		now:     time.Date(2030, time.March, 4, 5, 6, 7, 0, time.UTC),
		entropy: &sequence{reads: 1 << 32},
		signer:  &sequence{reads: 0},
	}

	rg.handler = auth.Handler(keys.Routes(rg.deps()), auth.Deps{
		Credentials: rg.creds,
		Resources:   resource.Select,
		Now:         func() time.Time { return rg.now },
		Getenv:      func(string) string { return "" },
		Log:         func(_ httpapi.Request, failure *apierr.Error) { rg.logged = append(rg.logged, failure) },
	})

	return rg
}

// newID is the routes' id source: the new key's id first, and distinct ones
// after that.
func (r *rig) newID() string {
	r.ids++

	if r.ids == 1 {
		return newKeyID
	}

	return fmt.Sprintf("00000000-0000-7000-8000-%012x", 0x1000+r.ids)
}

// deps are the key routes' dependencies, over the rig's fakes. The entropy is
// read through the rig, so a test may replace it before a request.
func (r *rig) deps() keys.Deps {
	return keys.Deps{
		Store:           r.store,
		Now:             func() time.Time { return r.now },
		NewID:           r.newID,
		Entropy:         readerFunc(func(p []byte) (int, error) { return r.entropy.Read(p) }),
		IssueUserAPIKey: r.issueUserAPIKey,
	}
}

// issueUserAPIKey is the routes' IssueUserAPIKey: auth.IssueUserAPIKey, recorded,
// unless a test programmed a failure, which is returned without calling it.
func (r *rig) issueUserAPIKey(
	entropy io.Reader, newID func() string, now time.Time, lifetime time.Duration,
) (auth.Issued, error) {
	call := issueCall{now: now, lifetime: lifetime, issued: auth.Issued{}, err: r.issueErr}

	if r.issueErr == nil {
		call.issued, call.err = auth.IssueUserAPIKey(entropy, newID, now, lifetime)
	}

	r.issueCalls = append(r.issueCalls, call)

	return call.issued, call.err
}

// readerFunc is an io.Reader made of a function.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// seed puts the user's own keys in the store for owner.
func (r *rig) seed(owner string, key ...store.Key) {
	for _, one := range key {
		r.store.rows = append(r.store.rows, ownedKey{owner: owner, agent: "", key: one})
	}
}

// seedAgentKey puts a key of an agent of owner in the store: it is never one of
// the user's own.
func (r *rig) seedAgentKey(owner, agent string, key store.Key) {
	r.store.rows = append(r.store.rows, ownedKey{owner: owner, agent: agent, key: key})
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

	issued, err := auth.IssueSession(r.signer, r.signID, r.now)
	if err != nil {
		r.t.Fatalf("IssueSession: %v", err)
	}

	r.creds.sessions[string(issued.Hash)] = store.ActiveSession{
		ID: issued.ID, UserID: owner, Role: role, ExpiresAt: issued.ExpiresAt,
	}

	return sessionCookie(issued.Token)
}

// sessionCookie is the session cookie with value as a browser returns it: only a
// name and a value.
func sessionCookie(value string) *http.Cookie {
	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: auth.CookieName, Value: value}
}

// keySpec describes an API key of a user, or of one of their agents.
type keySpec struct {
	// owner and role are the account's, as the row holds them.
	owner, role string
	// scope is the key's own list, as stored with it.
	scope scope.List
	// agent is the agent the key acts for, or "" for the user's own key; and
	// agentScopes is that agent's stored list (JSON), read now.
	agent, agentScopes string
}

// signInKey issues an API key as spec describes, stores its row as active, and
// returns the Authorization header value a client would send, and the id of the
// key's secret (the one the boundary reports as the presented credential).
func (r *rig) signInKey(spec keySpec) (string, string) {
	r.t.Helper()

	issued, err := auth.IssueUserAPIKey(r.signer, r.signID, r.now, time.Hour)
	if err != nil {
		r.t.Fatalf("IssueUserAPIKey: %v", err)
	}

	r.creds.keys[string(issued.Hash)] = store.ActiveAPIKey{
		ID: issued.ID, UserID: spec.owner, Role: spec.role, ExpiresAt: issued.ExpiresAt,
		AgentID: spec.agent, AgentScopes: spec.agentScopes, Scope: spec.scope.JSON(),
	}

	return "Bearer " + issued.Token, issued.ID
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

// withKey sends method target with body, authorized by header (an API key).
func (r *rig) withKey(header, method, target, body string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{method: method, target: target, body: body, authorization: header})
}

// writes counts the calls to the store that change something.
func (r *rig) writes() int {
	count := 0

	for _, call := range r.store.calls {
		if call.method == methodCreate || call.method == methodRename || call.method == methodRevoke {
			count++
		}
	}

	return count
}

// untouched asserts that no request reached the store or issued a key.
func (r *rig) untouched() {
	r.t.Helper()

	if len(r.store.calls) != 0 || len(r.issueCalls) != 0 {
		r.t.Errorf("the request reached the store (%+v) or issued %d keys", r.store.calls, len(r.issueCalls))
	}
}

// errorBody is the exact body of a failure with this code and message.
func errorBody(code, message string) string {
	return `{"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n"
}

// bodyInternal is what a client is told for any Internal failure, whatever its
// code in the log.
const bodyInternal = `{"error":{"code":"internal","message":"internal error"}}` + "\n"

// Exact bodies of the failures several tables share.
const (
	bodyNotFound  = `{"error":{"code":"key_not_found","message":"no such key"}}` + "\n"
	bodyUnauth    = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bodyInvalidID = `{"error":{"code":"invalid_id","message":` +
		`"id must be a lower-case UUID such as 01234567-89ab-cdef-0123-456789abcdef"}}` + "\n"
)

// wantFailure asserts the status and exact body of a failure, and that the
// failure was logged once under code.
func wantFailure(t *testing.T, r *rig, rec *httptest.ResponseRecorder, status int, body, code string) {
	t.Helper()

	if rec.Code != status || rec.Body.String() != body {
		t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), status, body)
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
}

// wantOK asserts a 200 and its exact body, with the JSON content type.
func wantOK(t *testing.T, r *rig, rec *httptest.ResponseRecorder, body string) {
	t.Helper()

	if rec.Code != http.StatusOK || rec.Body.String() != body {
		t.Errorf("response = %d %q, want 200 %q", rec.Code, rec.Body.String(), body)
	}

	if got := rec.Header().Get("Content-Type"); got != jsonType {
		t.Errorf("Content-Type = %q, want %q", got, jsonType)
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	if len(r.logged) != 0 {
		t.Errorf("a success logged %v", r.logged)
	}
}

// wantCode asserts a failure's status and the code in its body, for a table whose
// messages are not what it pins, and that it was logged once under that code.
func wantCode(t *testing.T, r *rig, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	err := json.Unmarshal(rec.Body.Bytes(), &body)
	if err != nil {
		t.Fatalf("the failure's body %q is not the error envelope: %v", rec.Body.String(), err)
	}

	if rec.Code != status || body.Error.Code != code || body.Error.Message == "" {
		t.Errorf("response = %d %q, want %d with code %q and a message", rec.Code, rec.Body.String(), status, code)
	}

	if len(r.logged) != 1 || r.logged[0].Code != code {
		t.Errorf("logged %v, want one %q", r.logged, code)
	}
}

// wantBadRequest is wantCode for the common case, a 400.
func wantBadRequest(t *testing.T, r *rig, rec *httptest.ResponseRecorder, code string) {
	t.Helper()

	wantCode(t, r, rec, http.StatusBadRequest, code)
}

// keyJSON is the exact JSON of an active key in a response that expires at
// farFuture.
func keyJSON(id, name string, createdAt int64, revokedAt *int64) string {
	return keyJSONAt(id, name, createdAt, farFuture, revokedAt, statusOf(revokedAt))
}

// statusOf is the status of a key that has not expired: revoked or active.
func statusOf(revokedAt *int64) string {
	if revokedAt != nil {
		return "revoked"
	}

	return "active"
}

// keyJSONAt is keyJSON with the expiry and the status named.
func keyJSONAt(id, name string, createdAt, expiresAt int64, revokedAt *int64, status string) string {
	if revokedAt != nil {
		return fmt.Sprintf(
			`{"id":%q,"name":%q,"scopes":["default:user"],"status":%q,"expiresAt":%d,"revokedAt":%d,"createdAt":%d}`,
			id, name, status, expiresAt, *revokedAt, createdAt)
	}

	return fmt.Sprintf(`{"id":%q,"name":%q,"scopes":["default:user"],"status":%q,"expiresAt":%d,"createdAt":%d}`,
		id, name, status, expiresAt, createdAt)
}
