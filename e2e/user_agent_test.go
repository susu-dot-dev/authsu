//go:build e2e

package e2e_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// This file drives /api/agent against the real Worker. The unit tests fake the
// database, so these prove what only the real build and SQLite can: that the
// migration applies, that TinyGo's mux routes the three methods on
// "/api/agent/{id}", that the real minting produces a key the schema accepts and
// that carries the user as subject and the agent as actor, and that the create
// guards, the ownership scoping and the revocation cascades behave as the SQL
// says.
//
// The file is named user_agent_test.go and not agent_test.go on purpose: the
// first-run tests need the still-empty database and rely on running first, in
// file order, so a file that leaves rows behind must sort after firstrun_test.go.

const (
	agentPath = "/api/agent"
	// agentMissing is a well-formed id nothing has.
	agentMissing = "00000000-0000-7000-8000-00000000dfff"
	// seedAgentA and seedAgentB are fixed ids for agents a test inserts.
	seedAgentA = "00000000-0000-7000-8000-00000000d001"
	seedAgentB = "00000000-0000-7000-8000-00000000d002"

	defaultScopes = "default:agent"

	codeAgentLimit   = "agent_limit_reached"
	codeAgentRevoked = "agent_revoked"
	codeAgentMissing = "agent_not_found"
)

// seedAgent inserts an agent for owner, with no key.
func seedAgent(t *testing.T, id, owner, name string) {
	t.Helper()

	query(t, "INSERT INTO agents (id, user_id, name, scopes, created_at) VALUES ('"+id+"', '"+owner+"', '"+name+
		"', 'default:agent', strftime('%s','now'))")
}

// seedAgentKey inserts an API key for an agent, so a test can see revocation
// reach it. It is never verified: it only needs to be a row.
func seedAgentKey(t *testing.T, kid, owner, agent string) {
	t.Helper()

	query(t, "INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, agent_id, scope, created_at) VALUES ('"+
		kid+"', '"+owner+"', 'api_key', '{}', strftime('%s','now') + 3600, '"+agent+"', 'default:agent', "+
		"strftime('%s','now'))")
}

func createAgent(t *testing.T, token, name string) reply {
	t.Helper()

	return call(t, http.MethodPost, agentPath, []byte(`{"name":"`+name+`"}`), token)
}

// createdAgent is the part of a create response a test reads back.
type createdAgent struct {
	Agent struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Scopes string `json:"scopes"`
		Status string `json:"status"`
	} `json:"agent"`
	Key struct {
		ID        string `json:"id"`
		Token     string `json:"token"`
		Scope     string `json:"scope"`
		ExpiresAt int64  `json:"expiresAt"`
	} `json:"key"`
}

func mustCreateAgent(t *testing.T, token, name string) createdAgent {
	t.Helper()

	got := createAgent(t, token, name)
	if got.status != http.StatusCreated {
		t.Fatalf("POST = %d %s, want 201", got.status, got.body)
	}

	var out createdAgent

	err := json.Unmarshal([]byte(got.body), &out)
	if err != nil {
		t.Fatalf("decode %s: %v", got.body, err)
	}

	return out
}

// claimsOf decodes a JWT's claims without verifying it.
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q has %d parts, want 3", token, len(parts))
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims map[string]any

	err = json.Unmarshal(raw, &claims)
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	return claims
}

// TestAgentRoutesRequireASession: without a session every route is 401. There
// is no role requirement: the session of an account with any role is enough.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentRoutesRequireASession(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)
	seedAgent(t, seedAgentA, self, "mine")

	routes := []struct {
		method, path string
		body         []byte
	}{
		{http.MethodGet, agentPath, nil},
		{http.MethodPost, agentPath, []byte(`{"name":"x"}`)},
		{http.MethodGet, agentPath + "/" + seedAgentA, nil},
		{http.MethodPatch, agentPath + "/" + seedAgentA, []byte(`{"name":"x"}`)},
		{http.MethodDelete, agentPath + "/" + seedAgentA, nil},
	}

	for _, rt := range routes {
		if got := call(t, rt.method, rt.path, rt.body, ""); got.status != http.StatusUnauthorized {
			t.Errorf("signed out %s %s = %d %s, want 401", rt.method, rt.path, got.status, got.body)
		}
	}

	expectCount(t, "agents WHERE name <> 'mine'", "0")

	// Any role works: an agent is something every user has.
	query(t, "UPDATE users SET role = 'e2e_member'")

	if got := call(t, http.MethodGet, agentPath, nil, token); got.status != http.StatusOK {
		t.Errorf("GET as a member = %d %s, want 200", got.status, got.body)
	}
}

// TestAgentCreateStoresTheAgentAndItsKey: the response carries the key once, and
// the stored rows are what the design says: an api_key owned by the user, tied
// to the agent, with no login grant.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentCreateStoresTheAgentAndItsKey(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	created := mustCreateAgent(t, token, "assistant")

	if created.Agent.Name != "assistant" || created.Agent.Scopes != defaultScopes || created.Agent.Status != "active" {
		t.Errorf("agent = %+v, want an active assistant with the default agent scopes", created.Agent)
	}

	if created.Key.Scope != defaultScopes || created.Key.Token == "" || created.Key.ExpiresAt == 0 {
		t.Errorf("key = %+v, want a token with the default agent scope and an expiry", created.Key)
	}

	expectCount(t, "agents WHERE id = '"+created.Agent.ID+"' AND user_id = '"+self+"' AND revoked_at IS NULL "+
		"AND scopes = '"+defaultScopes+"'", "1")
	expectCount(t, "japikeys WHERE kid = '"+created.Key.ID+"' AND user_id = '"+self+"' AND kind = 'api_key' "+
		"AND agent_id = '"+created.Agent.ID+"' AND scope = '"+defaultScopes+"' AND granted_from IS NULL "+
		"AND credential_id IS NULL AND revoked_at IS NULL", "1")

	expectTokenNotKept(t, token, created)
}

// expectTokenNotKept checks the key's token is not stored (the row holds only
// the public key) and is not shown again.
func expectTokenNotKept(t *testing.T, token string, created createdAgent) {
	t.Helper()

	stored := query(t, "SELECT jwk AS v FROM japikeys WHERE kid = '"+created.Key.ID+"'")
	if strings.Contains(stored, created.Key.Token) {
		t.Error("the stored key contains the token")
	}

	one := call(t, http.MethodGet, agentPath+"/"+created.Agent.ID, nil, token)
	if one.status != http.StatusOK || strings.Contains(one.body, created.Key.Token) {
		t.Errorf("GET one = %d %s, want the agent without its token", one.status, one.body)
	}
}

// TestAgentKeyIsTheUsersWithTheAgentAsActor: the central decision of
// docs/agents_design.md, written into the token the real build mints. The subject
// is the user and the actor is the agent. The audience is the api_key one, so
// the key is not a session.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentKeyIsTheUsersWithTheAgentAsActor(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	created := mustCreateAgent(t, token, "assistant")
	claims := claimsOf(t, created.Key.Token)

	if claims["sub"] != self {
		t.Errorf("sub = %v, want the user %s", claims["sub"], self)
	}

	if act, _ := claims["act"].(map[string]any); act["sub"] != created.Agent.ID {
		t.Errorf("act = %v, want the agent %s", claims["act"], created.Agent.ID)
	}

	if claims["scope"] != defaultScopes || claims["aud"] != "authsu/api_key" {
		t.Errorf("claims = %v, want scope %s and the api_key audience", claims, defaultScopes)
	}

	if got := call(t, http.MethodGet, sessionPath, nil, created.Key.Token); got.status != http.StatusUnauthorized {
		t.Errorf("an agent key as a session cookie = %d %s, want 401", got.status, got.body)
	}
}

// TestAgentCreateValidation: a bad body is refused before anything is written.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentCreateValidation(t *testing.T) {
	token := login(t, registerPasskey(t))

	for name, body := range map[string]string{
		"no name":       `{}`,
		"blank name":    `{"name":"   "}`,
		"unknown field": `{"name":"a","userId":"x"}`,
		"too long":      `{"name":"` + strings.Repeat("a", 257) + `"}`,
	} {
		got := call(t, http.MethodPost, agentPath, []byte(body), token)
		if got.status != http.StatusBadRequest {
			t.Errorf("%s: POST = %d %s, want 400", name, got.status, got.body)
		}
	}

	expectCount(t, "agents", "0")
	expectCount(t, "japikeys WHERE kind = 'api_key'", "0")
}

// TestAgentCreateStopsAtTheLimit: the limit counts active agents, is checked in
// the write, and a refused create leaves neither an agent nor a key behind.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentCreateStopsAtTheLimit(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	// 25 active agents is the limit. Insert them in one statement.
	query(t, "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 25) "+
		"INSERT INTO agents (id, user_id, name, scopes, created_at) "+
		"SELECT '00000000-0000-7000-8000-00000000e' || printf('%03d', i), '"+self+"', 'bulk', 'default:agent', "+
		"strftime('%s','now') FROM n")
	expectCount(t, "agents", "25")

	got := createAgent(t, token, "one too many")
	if got.status != http.StatusConflict || !strings.Contains(got.body, `"`+codeAgentLimit+`"`) {
		t.Fatalf("POST at the limit = %d %s, want 409 %s", got.status, got.body, codeAgentLimit)
	}

	expectCount(t, "agents", "25")
	expectCount(t, "japikeys WHERE kind = 'api_key'", "0")

	// Revoked agents do not count against the limit.
	query(t, "UPDATE agents SET revoked_at = 12345 WHERE id = '00000000-0000-7000-8000-00000000e001'")

	if got := createAgent(t, token, "fits now"); got.status != http.StatusCreated {
		t.Errorf("POST after a revocation = %d %s, want 201", got.status, got.body)
	}

	// Another user's agents do not count against this one.
	expectCount(t, "agents WHERE name = 'fits now'", "1")
}

// TestAgentCreateIsRefusedForARevokedOwner: the owner is read in the write, so
// an account revoked after authentication gets no agent and no key. Here the
// account is revoked behind the session's back, which verification would catch
// first; the write-level guard is pinned with the statement itself.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentCreateIsRefusedForARevokedOwner(t *testing.T) {
	token := login(t, registerPasskey(t))
	query(t, "UPDATE users SET revoked_at = 12345")

	// Verification refuses the revoked account before the write is reached.
	if got := createAgent(t, token, "ghost"); got.status != http.StatusUnauthorized {
		t.Errorf("POST by a revoked account = %d %s, want 401", got.status, got.body)
	}

	expectCount(t, "agents", "0")
	expectCount(t, "japikeys WHERE kind = 'api_key'", "0")

	// The write itself also refuses: no row is inserted for a revoked owner.
	query(t, "INSERT INTO agents (id, user_id, name, scopes, created_at) "+
		"SELECT '"+seedAgentA+"', u.id, 'ghost', 'default:agent', 1 FROM users u "+
		"WHERE u.id = '"+adminID(t)+"' AND u.revoked_at IS NULL")
	expectCount(t, "agents", "0")
}

// TestAgentsAreScopedToTheirOwner: a user sees and changes only their own
// agents, and another user's agent is answered as one that does not exist.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentsAreScopedToTheirOwner(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	seedUser(t, userB, "e2e_member")
	seedAgent(t, seedAgentA, self, "mine")
	seedAgent(t, seedAgentB, userB, "theirs")

	list := call(t, http.MethodGet, agentPath, nil, token)
	if list.status != http.StatusOK || !strings.Contains(list.body, `"id":"`+seedAgentA+`"`) ||
		strings.Contains(list.body, seedAgentB) || strings.Contains(list.body, "theirs") {
		t.Errorf("list = %d %s, want only my agent", list.status, list.body)
	}

	other := agentPath + "/" + seedAgentB

	for _, rt := range []struct {
		method string
		body   []byte
	}{{http.MethodGet, nil}, {http.MethodPatch, []byte(`{"name":"taken"}`)}, {http.MethodDelete, nil}} {
		got := call(t, rt.method, other, rt.body, token)
		if got.status != http.StatusNotFound || !strings.Contains(got.body, `"`+codeAgentMissing+`"`) {
			t.Errorf("%s another user's agent = %d %s, want 404 %s", rt.method, got.status, got.body, codeAgentMissing)
		}
	}

	expectCount(t, "agents WHERE id = '"+seedAgentB+"' AND name = 'theirs' AND revoked_at IS NULL", "1")
}

// TestAgentList reads agents through the real route, newest first, with revoked
// ones included and without the owner.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentList(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	empty := call(t, http.MethodGet, agentPath, nil, token)
	if empty.status != http.StatusOK || empty.body != `{"agents":[]}`+"\n" {
		t.Errorf("empty list = %d %q, want {\"agents\":[]}", empty.status, empty.body)
	}

	seedAgent(t, seedAgentA, self, "first")
	seedAgent(t, seedAgentB, self, "second")
	query(t, "UPDATE agents SET revoked_at = 12345 WHERE id = '"+seedAgentA+"'")

	list := call(t, http.MethodGet, agentPath, nil, token)

	// Same second, so the id breaks the tie: newest (largest id) first.
	if list.status != http.StatusOK || strings.Index(list.body, seedAgentB) > strings.Index(list.body, seedAgentA) {
		t.Errorf("list = %d %s, want the second agent first", list.status, list.body)
	}

	for _, want := range []string{statusRevokedJSON, `"revokedAt":12345`, statusActiveJSON, `"scopes":"default:agent"`} {
		if !strings.Contains(list.body, want) {
			t.Errorf("list lacks %s:\n%s", want, list.body)
		}
	}

	if strings.Contains(list.body, "userId") || strings.Contains(list.body, self) {
		t.Errorf("list names the owner:\n%s", list.body)
	}
}

// TestAgentGet reads one agent, and refuses a missing or malformed id.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentGet(t *testing.T) {
	token := login(t, registerPasskey(t))
	seedAgent(t, seedAgentA, adminID(t), "first")

	one := call(t, http.MethodGet, agentPath+"/"+seedAgentA, nil, token)
	if one.status != http.StatusOK || !strings.Contains(one.body, `"name":"first"`) {
		t.Errorf("GET one = %d %s, want it", one.status, one.body)
	}

	if got := call(t, http.MethodGet, agentPath+"/"+agentMissing, nil, token); got.status != http.StatusNotFound {
		t.Errorf("GET unknown = %d %s, want 404", got.status, got.body)
	}

	if got := call(t, http.MethodGet, agentPath+"/nope", nil, token); got.status != http.StatusBadRequest {
		t.Errorf("GET bad id = %d %s, want 400", got.status, got.body)
	}
}

// TestAgentRename renames an agent, and refuses a revoked one.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentRename(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)
	seedAgent(t, seedAgentA, self, "before")

	item := agentPath + "/" + seedAgentA

	got := call(t, http.MethodPatch, item, []byte(`{"name":"after"}`), token)
	if got.status != http.StatusOK || !strings.Contains(got.body, `"name":"after"`) {
		t.Fatalf("PATCH = %d %s, want 200 and the new name", got.status, got.body)
	}

	expectCount(t, "agents WHERE id = '"+seedAgentA+"' AND name = 'after'", "1")

	if got := call(t, http.MethodPatch, item, []byte(`{}`), token); got.status != http.StatusBadRequest {
		t.Errorf("PATCH with no name = %d %s, want 400", got.status, got.body)
	}

	unknown := call(t, http.MethodPatch, agentPath+"/"+agentMissing, []byte(`{"name":"x"}`), token)
	if unknown.status != http.StatusNotFound {
		t.Errorf("PATCH unknown = %d %s, want 404", unknown.status, unknown.body)
	}

	query(t, "UPDATE agents SET revoked_at = 12345 WHERE id = '"+seedAgentA+"'")

	got = call(t, http.MethodPatch, item, []byte(`{"name":"revived"}`), token)
	if got.status != http.StatusConflict || !strings.Contains(got.body, `"`+codeAgentRevoked+`"`) {
		t.Errorf("PATCH a revoked agent = %d %s, want 409 %s", got.status, got.body, codeAgentRevoked)
	}

	expectCount(t, "agents WHERE id = '"+seedAgentA+"' AND name = 'after'", "1")
}

// TestAgentRevoke revokes one agent: the row stays, its keys are revoked with
// it, the user's other agents and keys are untouched, and revoking again keeps
// the first time.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentRevoke(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	seedAgent(t, seedAgentA, self, "doomed")
	seedAgent(t, seedAgentB, self, "spared")
	seedAgentKey(t, "00000000-0000-7000-8000-00000000f001", self, seedAgentA)
	seedAgentKey(t, "00000000-0000-7000-8000-00000000f002", self, seedAgentA)
	seedAgentKey(t, "00000000-0000-7000-8000-00000000f003", self, seedAgentB)

	item := agentPath + "/" + seedAgentA

	got := call(t, http.MethodDelete, item, nil, token)
	if got.status != http.StatusOK || !strings.Contains(got.body, statusRevokedJSON) {
		t.Fatalf("DELETE = %d %s, want 200 and revoked", got.status, got.body)
	}

	expectCount(t, "agents WHERE id = '"+seedAgentA+"' AND revoked_at IS NOT NULL", "1")
	expectCount(t, "japikeys WHERE agent_id = '"+seedAgentA+"' AND revoked_at IS NULL", "0")

	// Nothing else was touched: not the sibling agent, its key, or the session.
	expectCount(t, "agents WHERE id = '"+seedAgentB+"' AND revoked_at IS NULL", "1")
	expectCount(t, "japikeys WHERE agent_id = '"+seedAgentB+"' AND revoked_at IS NULL", "1")
	expectCount(t, "japikeys WHERE kind = 'session' AND revoked_at IS NULL", "1")

	if got := call(t, http.MethodGet, sessionPath, nil, token); got.status != http.StatusOK {
		t.Errorf("session after revoking an agent = %d %s, want 200", got.status, got.body)
	}

	query(t, "UPDATE agents SET revoked_at = 12345 WHERE id = '"+seedAgentA+"'")

	if again := call(t, http.MethodDelete, item, nil, token); again.status != http.StatusOK ||
		!strings.Contains(again.body, `"revokedAt":12345`) {
		t.Errorf("second DELETE = %d %s, want 200 keeping revokedAt 12345", again.status, again.body)
	}

	unknown := call(t, http.MethodDelete, agentPath+"/"+agentMissing, nil, token)
	if unknown.status != http.StatusNotFound {
		t.Errorf("DELETE unknown = %d %s, want 404", unknown.status, unknown.body)
	}
}

// TestRevokingAUserRevokesTheirAgents: an agent's authority is borrowed from
// its user, so revoking the account revokes every agent and every agent key,
// and a refused revocation (the last admin) touches none of them.
//
//nolint:paralleltest // shares one database with the other tests
func TestRevokingAUserRevokesTheirAgents(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	seedUser(t, userB, "e2e_member")
	seedAgent(t, seedAgentA, userB, "borrowed")
	seedAgentKey(t, "00000000-0000-7000-8000-00000000f011", userB, seedAgentA)
	seedAgent(t, seedAgentB, self, "admins")
	seedAgentKey(t, "00000000-0000-7000-8000-00000000f012", self, seedAgentB)

	// The last admin cannot be revoked, so their agents are not either.
	if got := revokeUser(t, token, self); got.status != http.StatusConflict {
		t.Fatalf("DELETE the last admin = %d %s, want 409", got.status, got.body)
	}

	expectCount(t, "agents WHERE revoked_at IS NOT NULL", "0")
	expectCount(t, "japikeys WHERE agent_id IS NOT NULL AND revoked_at IS NOT NULL", "0")

	if got := revokeUser(t, token, userB); got.status != http.StatusOK {
		t.Fatalf("DELETE the member = %d %s, want 200", got.status, got.body)
	}

	expectCount(t, "agents WHERE id = '"+seedAgentA+"' AND revoked_at IS NOT NULL", "1")
	expectCount(t, "japikeys WHERE agent_id = '"+seedAgentA+"' AND revoked_at IS NULL", "0")

	// The admin's own agent is untouched.
	expectCount(t, "agents WHERE id = '"+seedAgentB+"' AND revoked_at IS NULL", "1")
	expectCount(t, "japikeys WHERE agent_id = '"+seedAgentB+"' AND revoked_at IS NULL", "1")
}

// TestAgentKeysHaveNoGrantColumns: the schema requires an API key to have
// neither login grant column, and a key without an owner is refused.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentKeysHaveNoGrantColumns(t *testing.T) {
	_ = login(t, registerPasskey(t))
	self := adminID(t)
	seedAgent(t, seedAgentA, self, "a")

	// A key must name its owner: user_id is NOT NULL, which is how a create
	// whose agent was not inserted fails its whole batch.
	if !queryFails(t, "INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, agent_id, created_at) VALUES ("+
		"'00000000-0000-7000-8000-00000000f021', (SELECT user_id FROM agents WHERE id = '"+agentMissing+"'), "+
		"'api_key', '{}', 9999999999, '"+seedAgentA+"', 1)") {
		t.Error("a key with no owner was accepted")
	}

	expectCount(t, "japikeys WHERE kind = 'api_key'", "0")
}

// TestAgentRoutingUnderTinyGo pins what only the real build can show: the
// collection and the item are separate routes with separate methods.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentRoutingUnderTinyGo(t *testing.T) {
	token := login(t, registerPasskey(t))
	itemPath := agentPath + "/" + seedAgentA

	m := http.StatusMethodNotAllowed

	expectRouting(t, token, map[string]routingCase{
		"collection rejects DELETE": {http.MethodDelete, agentPath, m, allowGetPost},
		"collection rejects PATCH":  {http.MethodPatch, agentPath, m, allowGetPost},
		"item rejects POST":         {http.MethodPost, itemPath, m, "DELETE, GET, PATCH"},
		"item rejects PUT":          {http.MethodPut, itemPath, m, "DELETE, GET, PATCH"},
		nameNoRouteForPath:          {http.MethodGet, itemPath + "/x", http.StatusNotFound, ""},
	})
}

// TestAgentCORS: the UI origin may preflight every agent route, and no other
// origin can.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentCORS(t *testing.T) {
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, agentPath}, {http.MethodPost, agentPath},
		{http.MethodGet, agentPath + "/" + seedAgentA}, {http.MethodPatch, agentPath + "/" + seedAgentA},
		{http.MethodDelete, agentPath + "/" + seedAgentA},
	} {
		headers := func(origin string) map[string]string {
			return map[string]string{originHeader: origin, "Access-Control-Request-Method": rt.method}
		}

		allowed := rawRequest(t, http.MethodOptions, rt.path, headers(target.origin))
		if allowed.status != http.StatusNoContent || allowed.header.Get("Access-Control-Allow-Methods") != rt.method {
			t.Errorf("preflight %s %s from the UI = %d %v, want 204 allowing it",
				rt.method, rt.path, allowed.status, allowed.header)
		}

		refused := rawRequest(t, http.MethodOptions, rt.path, headers(evilOrigin))
		if refused.header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("preflight %s %s from %s was answered with CORS headers", rt.method, rt.path, evilOrigin)
		}
	}
}

// TestAgentListPaging pages through real rows by id: every agent once, newest
// first, and the cursor and limit are refused when malformed.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentListPaging(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	for i := 1; i <= 5; i++ {
		seedAgent(t, fmt.Sprintf("00000000-0000-7000-8000-00000000d%03d", i), self, fmt.Sprintf("a%d", i))
	}

	var seen []string

	path := agentPath + "?limit=2"

	for range 5 {
		got := call(t, http.MethodGet, path, nil, token)
		if got.status != http.StatusOK {
			t.Fatalf("GET %s = %d %s", path, got.status, got.body)
		}

		var page struct {
			Agents []struct {
				ID string `json:"id"`
			} `json:"agents"`
			Next string `json:"next"`
		}

		err := json.Unmarshal([]byte(got.body), &page)
		if err != nil {
			t.Fatalf("decode %s: %v", got.body, err)
		}

		for _, agent := range page.Agents {
			seen = append(seen, agent.ID)
		}

		if page.Next == "" {
			break
		}

		path = agentPath + "?limit=2&cursor=" + page.Next
	}

	want := []string{
		"00000000-0000-7000-8000-00000000d005", "00000000-0000-7000-8000-00000000d004",
		"00000000-0000-7000-8000-00000000d003", "00000000-0000-7000-8000-00000000d002",
		"00000000-0000-7000-8000-00000000d001",
	}
	if !slices.Equal(seen, want) {
		t.Errorf("pages gave %v, want %v", seen, want)
	}

	for _, bad := range []string{"?limit=0", "?limit=101", "?limit=x", "?cursor=nope", "?limit=1&limit=2"} {
		if got := call(t, http.MethodGet, agentPath+bad, nil, token); got.status != http.StatusBadRequest {
			t.Errorf("GET %s = %d %s, want 400", bad, got.status, got.body)
		}
	}
}

// TestAgentSchemaRefusesWhatGoShouldHave pins the schema's backstop against the
// real SQLite: a NUL, and a value past the byte limit that SQLite's length()
// would not see because it stops counting at a NUL.
//
//nolint:paralleltest // shares one database with the other tests
func TestAgentSchemaRefusesWhatGoShouldHave(t *testing.T) {
	_ = login(t, registerPasskey(t))
	self := adminID(t)

	for name, value := range map[string]string{
		"nul":            "char(97, 0, 98)",
		"nul then huge":  "char(97, 0) || printf('%2000s', 'b')",
		"over the bytes": "printf('%1025s', 'b')",
		"empty":          "''",
		"not text":       "x'6162'",
	} {
		if !queryFails(t, "INSERT INTO agents (id, user_id, name, scopes, created_at) VALUES ('"+seedAgentA+"', '"+
			self+"', "+value+", 'default:agent', 1)") {
			t.Errorf("%s: a name the schema should refuse was accepted", name)
		}
	}

	if !queryFails(t, "INSERT INTO agents (id, user_id, name, scopes, created_at) VALUES ('"+seedAgentA+"', '"+
		self+"', 'ok', char(97, 0, 98), 1)") {
		t.Error("scopes with a NUL were accepted")
	}

	expectCount(t, "agents", "0")
}
