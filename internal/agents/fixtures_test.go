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
	"reflect"
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
	"github.com/susu-dot-dev/authsu/internal/scope"
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
	routePatch  = "patch"
	routeRevoke = "revoke"
	nameAlpha   = "alpha"

	// Names of the malformed-input cases that the id, label and scope tables
	// share.
	caseUpper    = "upper case"
	caseNUL      = "a NUL"
	caseWildcard = "a wildcard"

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
	codeDuplicate    = "duplicate_field"
	codeNotAllowed   = "method_not_allowed"

	// fieldName is the member of a body that names an agent.
	fieldName = "name"

	// defaultAgentJSON is the stored form of the default agent bundle.
	defaultAgentJSON = `["default:agent"]`

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
	methodPatch  = "PatchAgent"
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
	now    time.Time
	// agent is the NewAgent of a create.
	agent store.NewAgent
	// patch is the AgentPatch of a patch.
	patch store.AgentPatch
	// label is the label filter of a list, "" for none.
	label string
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
// below the cursor, newest first, at most limit, only those with the filter's
// label when it is set, and Next set when more remain.
func (f *fakeStore) ListAgents(
	_ context.Context, owner string, cursor input.Cursor, limit input.PageLimit, filter input.LabelFilter,
) (store.AgentPage, error) {
	before := ""
	if id, ok := cursor.ID(); ok {
		before = id.String()
	}

	want := ""
	if label, ok := filter.Label(); ok {
		want = label.String()
	}

	f.calls = append(f.calls,
		storeCall{method: methodList, owner: owner, cursor: before, limit: limit.Int(), label: want})

	err := f.fail(methodList)
	if err != nil {
		return store.AgentPage{}, err
	}

	mine := f.matching(owner, before, want)

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

	return normalised(f.rows[at].agent), nil
}

// normalised returns agent with a non-nil, sorted label list, as the store
// returns it.
func normalised(agent store.Agent) store.Agent {
	agent.Labels = slices.Sorted(slices.Values(agent.Labels))
	if agent.Labels == nil {
		agent.Labels = []string{}
	}

	return agent
}

// CreateAgent is the contract of store.CreateAgent. A programmed failure is
// returned before anything is written.
func (f *fakeStore) CreateAgent(_ context.Context, agent store.NewAgent) (string, error) {
	f.calls = append(f.calls, storeCall{method: methodCreate, owner: agent.Owner, agent: agent})

	err := f.fail(methodCreate)
	if err != nil {
		return "", err
	}

	scopes := agent.Scopes

	// The contract of store.CreateAgent for an agent's create: the new agent's
	// scopes are the creating agent's, read from its row, and the list the
	// caller offered is not used. A creating agent that is not the owner's, or
	// is revoked, makes the write fail as a conflict.
	if agent.CreatedBy != "" {
		at, ok := f.find(agent.Owner, agent.CreatedBy)
		if !ok || f.rows[at].agent.RevokedAt != nil {
			return "", store.ErrConflict
		}

		scopes = f.rows[at].agent.Scopes
	}

	// The contract: the labels are written with the agent, in the same batch.
	labels := make([]string, 0, len(agent.Labels.Labels()))
	for _, label := range agent.Labels.Labels() {
		labels = append(labels, label.String())
	}

	f.rows = append(f.rows, ownedAgent{owner: agent.Owner, agent: store.Agent{
		ID: agent.ID, Name: agent.Name.String(), Scopes: scopes, RevokedAt: nil, CreatedAt: agent.CreatedAt.Unix(),
		Labels: labels,
	}})

	// The contract: what the row holds is what is returned.
	return scopes, nil
}

// PatchAgent is the contract of store.PatchAgent: the whole patch takes effect
// or none of it does. A revoked agent is returned as it is. The removals are
// applied before the additions, an added label the agent has is a no-op, and a
// patch that would leave the agent over patch.MaxLabels is ErrConflict.
func (f *fakeStore) PatchAgent(
	_ context.Context, owner string, id input.ID, patch store.AgentPatch,
) (store.Agent, error) {
	f.calls = append(f.calls, storeCall{method: methodPatch, owner: owner, id: id.String(), patch: patch})

	err := f.fail(methodPatch)
	if err != nil {
		return store.Agent{}, err
	}

	at, ok := f.find(owner, id.String())
	if !ok {
		return store.Agent{}, store.ErrNotFound
	}

	if f.rows[at].agent.RevokedAt != nil {
		return normalised(f.rows[at].agent), nil
	}

	updated := f.rows[at].agent
	updated.Labels = slices.Clone(updated.Labels)

	for _, label := range patch.Labels.Remove() {
		updated.Labels = slices.DeleteFunc(updated.Labels, func(have string) bool { return have == label.String() })
	}

	for _, label := range patch.Labels.Add() {
		if slices.Contains(updated.Labels, label.String()) {
			continue
		}

		if len(updated.Labels) >= patch.MaxLabels {
			return store.Agent{}, store.ErrConflict
		}

		updated.Labels = append(updated.Labels, label.String())
	}

	if patch.Name != nil {
		updated.Name = patch.Name.String()
	}

	f.rows[at].agent = updated

	return normalised(updated), nil
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

	return normalised(f.rows[at].agent), nil
}

// matching is the owner's agents with an id below before (any, when it is ""),
// and with the label (any, when it is "").
func (f *fakeStore) matching(owner, before, label string) []store.Agent {
	var mine []store.Agent

	for _, row := range f.rows {
		below := before == "" || row.agent.ID < before
		labelled := label == "" || slices.Contains(row.agent.Labels, label)

		if row.owner == owner && below && labelled {
			mine = append(mine, normalised(row.agent))
		}
	}

	return mine
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

// stored is a stored agent with the fixture's name and scopes, and no labels.
func stored(id, name string, createdAt int64, revokedAt *int64) store.Agent {
	return store.Agent{
		ID: id, Name: name, Scopes: agents.DefaultScopes().JSON(), RevokedAt: revokedAt, CreatedAt: createdAt,
		Labels: []string{},
	}
}

// labelled is stored with labels.
func labelled(agent store.Agent, labels ...string) store.Agent {
	agent.Labels = labels

	return agent
}

// sameAgent reports whether two stored agents are equal: Agent holds a slice,
// so it cannot be compared with ==.
func sameAgent(a, b store.Agent) bool {
	return reflect.DeepEqual(normalised(a), normalised(b))
}

// fakeKeys is the key store the boundary reads keys from: rows by kid and kind,
// as the database holds them.
type fakeKeys struct {
	rows map[string]store.ActiveKey
	// apiRows are the rows of API keys.
	apiRows map[string]store.ActiveKey
}

func (f *fakeKeys) ActiveKey(_ context.Context, kid, kind string, _ time.Time) (store.ActiveKey, bool, error) {
	rows := f.rows
	if kind == auth.KindAPIKey {
		rows = f.apiRows
	} else if kind != auth.KindSession {
		return store.ActiveKey{}, false, nil
	}

	row, ok := rows[kid]

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
		keys:  &fakeKeys{rows: map[string]store.ActiveKey{}, apiRows: map[string]store.ActiveKey{}},
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

// writes counts the calls to the store that change something.
func (r *rig) writes() int {
	count := 0

	for _, call := range r.store.calls {
		if call.method == methodCreate || call.method == methodPatch || call.method == methodRevoke {
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

// agentJSON is the exact JSON of an agent in a response, with no labels.
func agentJSON(id, name string, createdAt int64, revokedAt *int64) string {
	return agentJSONWith(id, name, createdAt, revokedAt, "[]")
}

// agentJSONWith is agentJSON with the JSON text of the labels, such as `["a","b"]`.
func agentJSONWith(id, name string, createdAt int64, revokedAt *int64, labels string) string {
	if revokedAt != nil {
		return fmt.Sprintf(
			`{"id":%q,"name":%q,"scopes":["default:agent"],"status":"revoked","revokedAt":%d,"createdAt":%d,"labels":%s}`,
			id, name, *revokedAt, createdAt, labels)
	}

	return fmt.Sprintf(`{"id":%q,"name":%q,"scopes":["default:agent"],"status":"active","createdAt":%d,"labels":%s}`,
		id, name, createdAt, labels)
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

// wantBadRequest is wantCode for the common case, a 400.
func wantBadRequest(t *testing.T, r *rig, rec *httptest.ResponseRecorder, code string) {
	t.Helper()

	wantCode(t, r, rec, http.StatusBadRequest, code)
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

// keySpec describes an API key of a user, or of one of their agents.
type keySpec struct {
	// owner and role are the account's, as the row holds them.
	owner, role string
	// scope is the key's own list, signed into its token.
	scope scope.List
	// agent is the agent the key acts for, or "" for the user's own key; and
	// agentScopes is that agent's stored list (JSON), read now.
	agent, agentScopes string
}

// signInKey creates an API key as spec describes, stores its row, and returns
// the Authorization header value a client would send. The key lives in real
// time, as signIn's does.
func (r *rig) signInKey(spec keySpec) string {
	r.t.Helper()

	origin, err := config.ParseOrigin(apiOrigin)
	if err != nil {
		r.t.Fatalf("origin: %v", err)
	}

	claims := map[string]any{}
	if spec.agent != "" {
		claims["act"] = map[string]any{"sub": spec.agent}
	}

	key, err := auth.CreateKey(auth.IssuerFor(origin), auth.KeySpec{
		Kind: auth.KindAPIKey, Subject: spec.owner, Expires: time.Now().Add(time.Hour), Scope: spec.scope, Claims: claims,
	})
	if err != nil {
		r.t.Fatalf("CreateKey: %v", err)
	}

	r.keys.apiRows[key.ID.String()] = store.ActiveKey{
		JWK: []byte(key.JWK), UserID: spec.owner, CredentialID: "", Role: spec.role, ExpiresAt: key.ExpiresAt,
		AgentID: spec.agent, AgentScopes: spec.agentScopes,
	}

	return "Bearer " + key.JWT
}

// withKey sends method target with body, authorized by header (an API key).
func (r *rig) withKey(header, method, target, body string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{method: method, target: target, body: body, authorization: header})
}

// storeKeyRow is the row the database would hold for the key a create wrote: the
// owner's, the agent's id, and that agent's stored scopes, read from its row.
func storeKeyRow(written store.NewAgent, rg *rig) store.ActiveKey {
	return store.ActiveKey{
		JWK: []byte(written.KeyJWK), UserID: written.Owner, CredentialID: "", Role: roleMember,
		ExpiresAt: written.KeyExpiresAt, AgentID: written.ID, AgentScopes: rg.store.agent2(written.ID).Scopes,
	}
}

// agent2 returns the stored agent with id, or the zero agent.
func (f *fakeStore) agent2(id string) store.Agent {
	for _, row := range f.rows {
		if row.agent.ID == id {
			return row.agent
		}
	}

	return store.Agent{ID: "", Name: "", Scopes: "", RevokedAt: nil, CreatedAt: 0}
}
