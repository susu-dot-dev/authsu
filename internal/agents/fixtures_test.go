package agents_test

import (
	"cmp"
	"context"
	"crypto"
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
	"uuid"

	"github.com/susu-dot-dev/japikey_go"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// routes are written against.
var _ agents.Store = (*store.Store)(nil)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB      = errors.New("INSERT INTO agents: database is on fire")
	errKeyPair = errors.New("the entropy source is broken")
	errNotNull = errors.New("D1_ERROR: SQLITE_CONSTRAINT_NOTNULL: NOT NULL")
)

// Users, agents and deployment settings.
const (
	userA = "00000000-0000-7000-8000-00000000000a"
	userB = "00000000-0000-7000-8000-00000000000b"

	// Agents of user A, user B, and one nobody has.
	agentA1 = "00000000-0000-7000-8000-0000000000a1"
	agentA2 = "00000000-0000-7000-8000-0000000000a2"
	agentA3 = "00000000-0000-7000-8000-0000000000a3"
	agentB1 = "00000000-0000-7000-8000-0000000000b1"
	// agentB0 sorts below every other agent, so a cursor at an agent of user A
	// still has one of user B's below it.
	agentB0 = "00000000-0000-7000-8000-000000000001"
	nobody  = "00000000-0000-7000-8000-0000000000ee"

	// newAgentID is the id NewID hands out.
	newAgentID = "00000000-0000-7000-8000-0000000000cc"

	roleMember = "member"
	roleAdmin  = auth.RoleAdmin

	apiOrigin = "https://auth.example.com"
	uiOrigin  = "https://example.com"
	secret    = "agents-test-secret-0123456789ABCDEFGHIJKLM"

	jsonType = "application/json"

	// Names of the routes, and of cases several tables share.
	routeList   = "list"
	routeCreate = "create"
	routeGet    = "get"
	routeRename = "rename"
	routeRevoke = "revoke"
	nameAlpha   = "alpha"

	// Codes that several tables name.
	codeUnknownField = "unknown_field"
	codeInvalidName  = "invalid_agent_name"
	codeInvalidJSON  = "invalid_json"
	codeFieldType    = "invalid_field_type"
	codeNotFound     = "agent_not_found"
	codeInvalidID    = "invalid_id"
	codeInvalidText  = "invalid_text"
	codeLimit        = "invalid_limit"
	codeCursor       = "invalid_cursor"
	codeNoRoute      = "not_found"
	codeNotAllowed   = "method_not_allowed"

	// Claims of an agent's key, and bodies several tables send.
	claimSub      = "sub"
	claimAct      = "act"
	claimScope    = "scope"
	bodyX         = `{"name":"x"}`
	bodyAssistant = `{"name":"assistant"}`
	bodyRenamed   = `{"name":"renamed"}`
	itemPattern   = "/api/agent/{id}"

	collection = "/api/agent"
	itemPrefix = "/api/agent/"
)

// Names of the methods of fakeStore, for its call log and its programmed
// failures.
const (
	methodList   = "ListAgents"
	methodGet    = "GetAgent"
	methodCreate = "CreateAgent"
	methodRename = "RenameAgent"
	methodRevoke = "RevokeAgent"
)

// unavailableErr is how the store reports a database that failed: 503 under
// the operation's code.
func unavailableErr(code string) *apierr.Error {
	return apierr.New(apierr.Unavailable, code, "agents are temporarily unavailable").WithCause(errDB)
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
	name   string
	now    time.Time
	// agent is the NewAgent of a create.
	agent store.NewAgent
}

// ownedAgent is an agent as the fake database holds it: with its owner.
type ownedAgent struct {
	owner string
	agent store.Agent
}

// fakeStore is the agent store: the rows of every user, scoped by owner as the
// real one is, with a programmable failure per method. It records every call.
type fakeStore struct {
	rows []ownedAgent
	// failures are returned by the named method instead of its normal outcome.
	failures map[string]error
	calls    []storeCall
}

// ListAgents is the contract of store.ListAgents: the owner's agents with an id
// below the cursor, newest first, at most limit, and Next set when more remain.
func (f *fakeStore) ListAgents(
	_ context.Context, owner string, cursor input.Cursor, limit input.PageLimit,
) (store.AgentPage, error) {
	before := ""
	if id, ok := cursor.ID(); ok {
		before = id.String()
	}

	f.calls = append(f.calls, storeCall{method: methodList, owner: owner, cursor: before, limit: limit.Int()})

	err := f.fail(methodList)
	if err != nil {
		return store.AgentPage{}, err
	}

	var mine []store.Agent

	for _, row := range f.rows {
		if row.owner == owner && (before == "" || row.agent.ID < before) {
			mine = append(mine, row.agent)
		}
	}

	slices.SortFunc(mine, func(a, b store.Agent) int { return cmp.Compare(b.ID, a.ID) })

	if len(mine) <= limit.Int() {
		return store.AgentPage{Agents: mine, Next: ""}, nil
	}

	mine = mine[:limit.Int()]

	return store.AgentPage{Agents: mine, Next: mine[len(mine)-1].ID}, nil
}

// GetAgent is the contract of store.GetAgent.
func (f *fakeStore) GetAgent(_ context.Context, owner string, id input.ID) (store.Agent, error) {
	f.calls = append(f.calls, storeCall{method: methodGet, owner: owner, id: id.String()})

	err := f.fail(methodGet)
	if err != nil {
		return store.Agent{}, err
	}

	at, ok := f.find(owner, id.String())
	if !ok {
		return store.Agent{}, store.ErrNotFound
	}

	return f.rows[at].agent, nil
}

// CreateAgent is the contract of store.CreateAgent. A programmed failure is
// returned before anything is written.
func (f *fakeStore) CreateAgent(_ context.Context, agent store.NewAgent) error {
	f.calls = append(f.calls, storeCall{method: methodCreate, owner: agent.Owner, agent: agent})

	err := f.fail(methodCreate)
	if err != nil {
		return err
	}

	f.rows = append(f.rows, ownedAgent{owner: agent.Owner, agent: store.Agent{
		ID: agent.ID, Name: agent.Name.String(), Scopes: agent.Scopes, RevokedAt: nil, CreatedAt: agent.CreatedAt.Unix(),
	}})

	return nil
}

// RenameAgent is the contract of store.RenameAgent: a revoked agent keeps its
// name and is returned as it is.
func (f *fakeStore) RenameAgent(
	_ context.Context, owner string, id input.ID, name input.AgentName,
) (store.Agent, error) {
	f.calls = append(f.calls, storeCall{method: methodRename, owner: owner, id: id.String(), name: name.String()})

	err := f.fail(methodRename)
	if err != nil {
		return store.Agent{}, err
	}

	at, ok := f.find(owner, id.String())
	if !ok {
		return store.Agent{}, store.ErrNotFound
	}

	if f.rows[at].agent.RevokedAt == nil {
		f.rows[at].agent.Name = name.String()
	}

	return f.rows[at].agent, nil
}

// RevokeAgent is the contract of store.RevokeAgent: an agent already revoked
// keeps its earlier time.
func (f *fakeStore) RevokeAgent(_ context.Context, owner string, id input.ID, now time.Time) (store.Agent, error) {
	f.calls = append(f.calls, storeCall{method: methodRevoke, owner: owner, id: id.String(), now: now})

	err := f.fail(methodRevoke)
	if err != nil {
		return store.Agent{}, err
	}

	at, ok := f.find(owner, id.String())
	if !ok {
		return store.Agent{}, store.ErrNotFound
	}

	if f.rows[at].agent.RevokedAt == nil {
		unix := now.Unix()
		f.rows[at].agent.RevokedAt = &unix
	}

	return f.rows[at].agent, nil
}

// fail is the failure programmed for method, if any.
func (f *fakeStore) fail(method string) error { return f.failures[method] }

// find returns the position of the agent of owner with id.
func (f *fakeStore) find(owner, id string) (int, bool) {
	at := slices.IndexFunc(f.rows, func(row ownedAgent) bool { return row.owner == owner && row.agent.ID == id })

	return at, at >= 0
}

// agent returns the stored agent with id, whoever owns it.
func (f *fakeStore) agent(t *testing.T, id string) store.Agent {
	t.Helper()

	at := slices.IndexFunc(f.rows, func(row ownedAgent) bool { return row.agent.ID == id })
	if at < 0 {
		t.Fatalf("the store has no agent %s", id)
	}

	return f.rows[at].agent
}

// stored is a stored agent with the fixture's name and scopes.
func stored(id, name string, createdAt int64, revokedAt *int64) store.Agent {
	return store.Agent{ID: id, Name: name, Scopes: agents.DefaultScopes, RevokedAt: revokedAt, CreatedAt: createdAt}
}

// fakeKeys is the key store the boundary reads sessions from: rows by kid, as
// the database holds them for the kind session.
type fakeKeys struct {
	rows map[string]store.ActiveKey
}

func (f *fakeKeys) ActiveKey(_ context.Context, kid, kind string, _ time.Time) (store.ActiveKey, bool, error) {
	if kind != auth.KindSession {
		return store.ActiveKey{}, false, nil
	}

	row, ok := f.rows[kid]

	return row, ok, nil
}

// keyCall is one call to the CreateKey the routes were given.
type keyCall struct {
	issuer auth.Issuer
	spec   auth.KeySpec
	key    auth.Key
}

// rig is one deployment under test: the real boundary and the real agent routes
// over a fake store, a fake key store and a clock the test controls.
type rig struct {
	t     *testing.T
	store *fakeStore
	keys  *fakeKeys
	env   map[string]string
	// now is the clock the routes run on.
	now time.Time
	// keyCalls records every key the routes created, and keyErr, when set, makes
	// the creation fail.
	keyCalls []keyCall
	keyErr   error
	// logged records every error the boundary turned into a response.
	logged  []*apierr.Error
	handler http.Handler
}

func newRig(t *testing.T) *rig {
	t.Helper()

	rg := &rig{
		t:     t,
		store: &fakeStore{rows: nil, failures: map[string]error{}, calls: nil},
		keys:  &fakeKeys{rows: map[string]store.ActiveKey{}},
		env: map[string]string{
			config.SecretHMAC: secret, config.VarAPIOrigin: apiOrigin, config.VarUIOrigin: uiOrigin,
		},
		// Whole seconds: the response carries Unix seconds.
		now: time.Now().Truncate(time.Second),
	}

	rg.handler = auth.Handler(agents.Routes(rg.deps()), auth.Deps{
		Keys:   rg.keys,
		Now:    func() time.Time { return rg.now },
		Getenv: func(name string) string { return rg.env[name] },
		Log:    func(_ httpapi.Request, failure *apierr.Error) { rg.logged = append(rg.logged, failure) },
	})

	return rg
}

// deps are the agent routes' dependencies, over the rig's fakes.
func (r *rig) deps() agents.Deps {
	return agents.Deps{
		Store: r.store,
		Now:   func() time.Time { return r.now },
		NewID: func() string { return newAgentID },
		CreateKey: func(issuer auth.Issuer, spec auth.KeySpec) (auth.Key, error) {
			if r.keyErr != nil {
				r.keyCalls = append(r.keyCalls, keyCall{issuer: issuer, spec: spec, key: auth.Key{}})

				return auth.Key{}, r.keyErr
			}

			key, err := auth.CreateKey(issuer, spec)
			r.keyCalls = append(r.keyCalls, keyCall{issuer: issuer, spec: spec, key: key})

			if err != nil {
				return key, fmt.Errorf("create key: %w", err)
			}

			return key, nil
		},
	}
}

// seed puts agents in the store for owner.
func (r *rig) seed(owner string, agent ...store.Agent) {
	for _, one := range agent {
		r.store.rows = append(r.store.rows, ownedAgent{owner: owner, agent: one})
	}
}

// signIn creates a session for owner, with role, and returns the cookie a
// browser would send. The key lives in real time: japikey checks a token's own
// claims against the wall clock.
func (r *rig) signIn(owner, role string) *http.Cookie {
	r.t.Helper()

	origin, err := config.ParseOrigin(apiOrigin)
	if err != nil {
		r.t.Fatalf("origin: %v", err)
	}

	key, err := auth.CreateSession(auth.IssuerFor(origin), owner, time.Now().Add(auth.SessionLifetime))
	if err != nil {
		r.t.Fatalf("CreateSession: %v", err)
	}

	r.keys.rows[key.ID.String()] = store.ActiveKey{
		JWK: []byte(key.JWK), UserID: owner, CredentialID: "", Role: role, ExpiresAt: key.ExpiresAt,
	}

	return sessionCookie(key.JWT)
}

// sessionCookie is the session cookie with value as a browser returns it: only
// a name and a value.
func sessionCookie(value string) *http.Cookie {
	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: auth.CookieName, Value: value}
}

// request is one request to send.
type request struct {
	method, target, body string
	// contentType defaults to application/json; "-" sends none.
	contentType string
	cookies     []*http.Cookie
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

	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, httpReq)

	return rec
}

// as sends method target with body, signed in as cookie.
func (r *rig) as(cookie *http.Cookie, method, target, body string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{method: method, target: target, body: body, cookies: []*http.Cookie{cookie}})
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

// untouched asserts that no request reached the store or created a key.
func (r *rig) untouched() {
	r.t.Helper()

	if len(r.store.calls) != 0 || len(r.keyCalls) != 0 {
		r.t.Errorf("the request reached the store (%+v) or created %d keys", r.store.calls, len(r.keyCalls))
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
	bodyNotFound  = `{"error":{"code":"agent_not_found","message":"no such agent"}}` + "\n"
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

// wantOK asserts a success: status, exact body and the JSON content type.
func wantOK(t *testing.T, r *rig, rec *httptest.ResponseRecorder, status int, body string) {
	t.Helper()

	if rec.Code != status || rec.Body.String() != body {
		t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), status, body)
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

// agentJSON is the exact JSON of an agent in a response.
func agentJSON(id, name string, createdAt int64, revokedAt *int64) string {
	if revokedAt != nil {
		return fmt.Sprintf(`{"id":%q,"name":%q,"scopes":"default:agent","status":"revoked","revokedAt":%d,"createdAt":%d}`,
			id, name, *revokedAt, createdAt)
	}

	return fmt.Sprintf(`{"id":%q,"name":%q,"scopes":"default:agent","status":"active","createdAt":%d}`,
		id, name, createdAt)
}

// verifiedKey is a key token that japikey accepted.
type verifiedKey struct {
	kid    uuid.UUID
	claims map[string]any
}

// verifyToken verifies token the way a verifier of authsu keys would: with the
// issuer of the API origin, the audience of kind, and the public key out of
// jwk, the document that reached the store.
func verifyToken(t *testing.T, token, jwk, kind string) (verifiedKey, error) {
	t.Helper()

	origin, err := config.ParseOrigin(apiOrigin)
	if err != nil {
		t.Fatalf("origin: %v", err)
	}

	issuer := auth.IssuerFor(origin)

	lookup := func(_ context.Context, kid uuid.UUID) (crypto.PublicKey, error) {
		var document japikey.JWKS

		err := json.Unmarshal([]byte(jwk), &document)
		if err != nil {
			return nil, fmt.Errorf("stored jwk: %w", err)
		}

		return document.GetPublicKey(kid)
	}

	verified, err := japikey.Verify(t.Context(), token, japikey.VerifyConfig{
		BaseIssuerURL: issuer.Base, AllowInsecureHTTP: issuer.Insecure, Timeout: 0, Audience: auth.Audience(kind),
	}, lookup)
	if err != nil {
		return verifiedKey{}, fmt.Errorf("verify: %w", err)
	}

	return verifiedKey{kid: verified.KeyID, claims: verified.Claims}, nil
}

// wantCode asserts a failure's status and the code in its body, for a table
// whose messages are not what it pins, and that it was logged once under that
// code. It is for failures a client sees: an Internal one has the code
// "internal" in its body whatever it was logged as.
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
