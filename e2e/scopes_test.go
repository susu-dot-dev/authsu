//go:build e2e

//nolint:goconst,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// scopes_test.go drives permissions (docs/permissions_design.md) against the
// real Worker: the TinyGo wasm, the real D1 driver and the real SQLite. The unit
// tests fake the database, so this file proves what only the real build can:
//
//   - a key created by the API is accepted as an "Authorization: Bearer" token
//     (TinyGo's net/http, header parsing, the join of the agent's row in the one
//     key read, and the JSON scope text through real SQLite);
//   - the scope a key carries bounds what it may call, and the agent's own scopes
//     narrow it further, with the role gating admin scopes whatever any token says;
//   - an agent that holds agent:create creates agents only within itself: the
//     new agent's scopes are read from the creating agent's row inside the write;
//   - a revoked agent's keys stop working at once, and a session and an API key
//     are not interchangeable between the cookie and the header.
//
// REVIEW.md categories covered: permission confusion (every route of the matrix
// by every kind of credential), interleaving (an agent create against that
// agent's revocation), and type/bound confusion (JSON arrays through JSON,
// Go and SQLite).

import (
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	scBundleAgent   = "default:agent"
	scBundleUser    = "default:user"
	scBundleSession = "default:session"
)

// scBearer sends a request authorized by an API key.
func scBearer(t *testing.T, method, path string, body []byte, key string) reply {
	t.Helper()

	return send(t, request{method: method, path: path, body: body, bearer: key})
}

// scCreateBody is {"name":..., "scopes":..., "keyScopes":...}; a nil list is left out.
func scCreateBody(t *testing.T, name string, agent, key []string) []byte {
	t.Helper()

	body := map[string]any{"name": name}

	if agent != nil {
		body["scopes"] = agent
	}

	if key != nil {
		body["keyScopes"] = key
	}

	return mustJSON(t, body)
}

// scMakeAgent creates an agent as the signed-in user and returns what came back.
func scMakeAgent(t *testing.T, token, name string, agent, key []string) agCreated {
	t.Helper()

	got := post(t, pathAgent, scCreateBody(t, name, agent, key), token)
	if got.status != http.StatusCreated {
		t.Fatalf("create %q = %d %s, want 201", name, got.status, got.body)
	}

	return agDecode[agCreated](t, got)
}

// TestAKeyAndItsAgentBoundWhatARequestMayDo: an agent's key is verified as a
// bearer through the real build and may do exactly the intersection of its own
// scopes and its agent's, and the routes that refuse agents refuse it whatever
// it holds.
//
//nolint:paralleltest // shares one database
func TestAKeyAndItsAgentBoundWhatARequestMayDo(t *testing.T) {
	world := agNewPair(t, roleMember)

	own := scMakeAgent(t, world.tokenB, "reader", []string{"agent:read"}, []string{scBundleUser})
	victim := scMakeAgent(t, world.tokenB, "victim", nil, nil)

	tests := []struct {
		name           string
		method, path   string
		body           []byte
		wantStatus     int
		wantCode       string
		wantNoMutation bool
	}{
		{"read: the agent and the key both name it", http.MethodGet, pathAgent, nil, http.StatusOK, "", false},
		{"read one", http.MethodGet, agItem(victim.Agent.ID), nil, http.StatusOK, "", false},
		{"create: the key's bundle has it, the agent's list does not", http.MethodPost, pathAgent,
			scCreateBody(t, "x", nil, nil), http.StatusForbidden, "insufficient_scope", true},
		{"rename: refused to agents whatever they hold", http.MethodPatch, agItem(victim.Agent.ID),
			[]byte(`{"name":"renamed"}`), http.StatusForbidden, "insufficient_scope", true},
		{"revoke: the same", http.MethodDelete, agItem(victim.Agent.ID), nil, http.StatusForbidden, "insufficient_scope", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := scBearer(t, test.method, test.path, test.body, own.Key.Token)
			got.expect(t, test.name, test.wantStatus, test.wantCode)

			if test.wantNoMutation {
				if name := scalar(t, "SELECT name FROM agents WHERE id = ?", victim.Agent.ID); name != "victim" {
					t.Errorf("a refused request changed the sibling: name = %q", name)
				}

				expectCount(t, "agents WHERE user_id = ?", "2", world.b.userID)
			}
		})
	}

	// An agent that is given agent:update and agent:revoke on both sides is still
	// refused: agents are peers under their user.
	powerful := scMakeAgent(t, world.tokenB, "powerful",
		[]string{scBundleUser}, []string{scBundleUser})

	for _, call := range []struct {
		method string
		body   []byte
	}{{http.MethodPatch, []byte(`{"name":"renamed"}`)}, {http.MethodDelete, nil}} {
		got := scBearer(t, call.method, agItem(victim.Agent.ID), call.body, powerful.Key.Token)
		got.expect(t, call.method+" by an agent holding the scope", http.StatusForbidden, "forbidden")
	}

	if name := scalar(t, "SELECT name FROM agents WHERE id = ?", victim.Agent.ID); name != "victim" {
		t.Errorf("a sibling was renamed by an agent: %q", name)
	}

	expectCount(t, "agents WHERE id = ? AND revoked_at IS NULL", "1", victim.Agent.ID)
}

// TestAUserKeyIsALimitedUser: a user's own key, with no agent, is the user
// narrowed to what it names. Presented as a bearer to the real build it reads
// and writes agents exactly as far as its scopes go, and never as a session.
//
//nolint:paralleltest // shares one database
func TestAUserKeyIsALimitedUser(t *testing.T) {
	world := agNewPair(t, roleMember)

	// A user's own key has no create route yet, so make one the way a later
	// feature will: an agent's key is the only API key the API creates, so use
	// it as the limited credential and check its scope is what is enforced.
	readOnly := scMakeAgent(t, world.tokenB, "ro", []string{scBundleSession}, []string{"agent:read"})

	scBearer(t, http.MethodGet, pathAgent, nil, readOnly.Key.Token).expect(t, "read", http.StatusOK, "")
	scBearer(t, http.MethodPost, pathAgent, scCreateBody(t, "x", nil, nil), readOnly.Key.Token).
		expect(t, "create without the scope", http.StatusForbidden, "insufficient_scope")

	// The same token as the session cookie is not a session: the cookie and the
	// header are different carriers, and the audience pins each.
	send(t, request{method: http.MethodGet, path: pathAgent, token: readOnly.Key.Token}).
		expect(t, "an api key as the cookie", http.StatusUnauthorized, "unauthenticated")

	// And a session token as a bearer is not an API key.
	scBearer(t, http.MethodGet, pathAgent, nil, world.tokenB).
		expect(t, "a session as a bearer", http.StatusUnauthorized, "unauthenticated")

	// Both carriers at once are refused, whichever is valid.
	send(t, request{method: http.MethodGet, path: pathAgent, token: world.tokenB, bearer: readOnly.Key.Token}).
		expect(t, "a cookie and a bearer", http.StatusUnauthorized, "unauthenticated")
}

// TestAdminScopesNeedTheRoleWhateverATokenSays: a member's agent whose lists
// name every scope, admin scopes included, is still refused an admin route, and
// an administrator's agent needs both lists to name it.
//
//nolint:paralleltest // shares one database
func TestAdminScopesNeedTheRoleWhateverATokenSays(t *testing.T) {
	world := agNewPair(t, roleMember)

	// The members' own session is every scope, and the role still decides.
	got := get(t, "/api/user", world.tokenB)
	got.expect(t, "member session on an admin route", http.StatusForbidden, "forbidden")

	everything := []string{scBundleSession}
	memberAgent := scMakeAgent(t, world.tokenB, "wants-admin", everything, everything)

	scBearer(t, http.MethodGet, "/api/user", nil, memberAgent.Key.Token).
		expect(t, "a member's agent naming every scope", http.StatusForbidden, "forbidden")

	adminBoth := scMakeAgent(t, world.tokenA, "admin-both", everything, everything)
	adminOnlyKey := scMakeAgent(t, world.tokenA, "admin-key-only", []string{scBundleAgent}, everything)
	adminOnlyAgent := scMakeAgent(t, world.tokenA, "admin-agent-only", everything, []string{scBundleAgent})

	scBearer(t, http.MethodGet, "/api/user", nil, adminBoth.Key.Token).
		expect(t, "an admin's agent whose lists both name it", http.StatusOK, "")
	scBearer(t, http.MethodGet, "/api/user", nil, adminOnlyKey.Key.Token).
		expect(t, "an admin's agent whose own list lacks it", http.StatusForbidden, "insufficient_scope")
	scBearer(t, http.MethodGet, "/api/user", nil, adminOnlyAgent.Key.Token).
		expect(t, "an admin's key whose bundle lacks it", http.StatusForbidden, "insufficient_scope")

	// Demoting the admin narrows their agent at once, without a new token: the
	// role is read on every request and is not in the token.
	setRole(t, world.a.userID, roleMember)

	scBearer(t, http.MethodGet, "/api/user", nil, adminBoth.Key.Token).
		expect(t, "after the admin is demoted", http.StatusForbidden, "forbidden")
}

// TestAnAgentCreatesAgentsOnlyWithinItself is the delegation rule through the
// real database: the new agent's scopes are read from the creating agent's row
// in the write, the new key may hold only entries of the creating key's list,
// and everything beyond that is refused with nothing written.
//
//nolint:paralleltest // shares one database
func TestAnAgentCreatesAgentsOnlyWithinItself(t *testing.T) {
	world := agNewPair(t, roleMember)

	creatorKey := []string{scBundleAgent, "agent:create"}
	creator := scMakeAgent(t, world.tokenB, "creator", []string{scBundleAgent, "agent:create"}, creatorKey)
	token := creator.Key.Token

	// Allowed: inherit everything, then a smaller key list.
	child := post2(t, token, scCreateBody(t, "child", nil, nil))
	child.expect(t, "inherit", http.StatusCreated, "")

	got := agDecode[agCreated](t, child)
	if !slices.Equal(got.Agent.Scopes, creatorKey) || !slices.Equal(got.Key.Scopes, creatorKey) {
		t.Errorf("an inheriting create = agent %v key %v, want a copy of %v", got.Agent.Scopes, got.Key.Scopes, creatorKey)
	}

	// The stored text is what was returned, and is the creator's row text.
	if stored := scalar(t, "SELECT scopes FROM agents WHERE id = ?", got.Agent.ID); stored != `["default:agent","agent:create"]` {
		t.Errorf("stored scopes = %s", stored)
	}

	// The key row's copy is the claim that was signed.
	if row := scalar(t, "SELECT scope FROM japikeys WHERE kid = ?", got.Key.ID); row != `["default:agent","agent:create"]` {
		t.Errorf("stored key scope = %s", row)
	}

	narrower := post2(t, token, scCreateBody(t, "narrow", nil, []string{scBundleAgent}))
	narrower.expect(t, "a key list that is an entry of the creating key", http.StatusCreated, "")

	empty := post2(t, token, scCreateBody(t, "empty", nil, []string{}))
	empty.expect(t, "an empty key list", http.StatusCreated, "")

	before := scalar(t, "SELECT count(*) FROM agents")

	for _, refused := range []struct {
		name, code string
		agent, key []string
	}{
		{"a bigger bundle for the key", "key_scopes_exceeded", nil, []string{scBundleUser}},
		{"the session bundle for the key", "key_scopes_exceeded", nil, []string{scBundleSession}},
		{"an admin scope for the key", "key_scopes_exceeded", nil, []string{"user:read"}},
		{"an entry the creating key lacks", "key_scopes_exceeded", nil, []string{"agent:update"}},
		{"choosing the new agent's scopes", "agent_scopes_inherited", []string{scBundleAgent}, nil},
		{"choosing the new agent's scopes as empty", "agent_scopes_inherited", []string{}, nil},
	} {
		post2(t, token, scCreateBody(t, "x", refused.agent, refused.key)).
			expect(t, refused.name, http.StatusForbidden, refused.code)
	}

	if after := scalar(t, "SELECT count(*) FROM agents"); after != before {
		t.Errorf("refused creates left agents behind: %s -> %s", before, after)
	}

	// The new agent is an ordinary agent of the same user: nothing records who
	// created it, and its own key works within what it was given.
	scBearer(t, http.MethodGet, pathAgent, nil, got.Key.Token).expect(t, "the new agent reads", http.StatusOK, "")

	// The creator, "child", "narrow" and "empty": four agents, and no more.
	expectCount(t, "agents WHERE user_id = ?", "4", world.b.userID)
}

// post2 creates an agent as an API key. It is post with a bearer.
func post2(t *testing.T, key string, body []byte) reply {
	t.Helper()

	return scBearer(t, http.MethodPost, pathAgent, body, key)
}

// TestAnAgentWithoutAgentCreateCannotCreate: the default agent bundle has no
// agent:create, so a default agent's key cannot make agents, and nothing is
// written.
//
//nolint:paralleltest // shares one database
func TestAnAgentWithoutAgentCreateCannotCreate(t *testing.T) {
	world := agNewPair(t, roleMember)

	plain := scMakeAgent(t, world.tokenB, "plain", nil, nil)

	post2(t, plain.Key.Token, scCreateBody(t, "x", nil, nil)).
		expect(t, "default agent creating", http.StatusForbidden, "insufficient_scope")

	expectCount(t, "agents WHERE user_id = ?", "1", world.b.userID)
}

// TestARevokedAgentsKeyStopsWorking: revoking the agent ends its keys at once,
// and a create that is racing the revocation either completes before it or is
// refused as a conflict, never leaving an agent the revoked one made after.
//
//nolint:paralleltest // shares one database
func TestARevokedAgentsKeyStopsWorking(t *testing.T) {
	world := agNewPair(t, roleMember)

	creator := scMakeAgent(t, world.tokenB, "creator", []string{scBundleAgent, "agent:create"},
		[]string{scBundleAgent, "agent:create"})

	scBearer(t, http.MethodGet, pathAgent, nil, creator.Key.Token).expect(t, "before", http.StatusOK, "")

	del(t, agItem(creator.Agent.ID), world.tokenB).expect(t, "revoke", http.StatusOK, "")

	scBearer(t, http.MethodGet, pathAgent, nil, creator.Key.Token).
		expect(t, "after the agent is revoked", http.StatusUnauthorized, "unauthenticated")
	post2(t, creator.Key.Token, scCreateBody(t, "late", nil, nil)).
		expect(t, "a create after the agent is revoked", http.StatusUnauthorized, "unauthenticated")

	// A key whose own row was left active while its agent is revoked is still not
	// active: the read joins the agent.
	if rows := scalar(t, "SELECT count(*) FROM japikeys WHERE agent_id = ? AND revoked_at IS NOT NULL", creator.Agent.ID); rows != "1" {
		t.Errorf("revoked key rows = %s, want the agent's one key revoked with it", rows)
	}

	seed(t, "UPDATE japikeys SET revoked_at = NULL WHERE agent_id = ?", creator.Agent.ID)

	scBearer(t, http.MethodGet, pathAgent, nil, creator.Key.Token).
		expect(t, "a key row left active under a revoked agent", http.StatusUnauthorized, "unauthenticated")
}

// TestCreatesRacingTheCreatorsRevocation: a create by an agent and the revocation
// of that agent are sent together. Every create either succeeded before the
// revocation or was refused, and no agent exists whose key a revoked agent
// made after the revocation took effect. The new agents that exist are all
// copies of the creator, and the batch is atomic: an agent has its key.
//
//nolint:paralleltest // shares one database
func TestCreatesRacingTheCreatorsRevocation(t *testing.T) {
	world := agNewPair(t, roleMember)

	list := []string{scBundleAgent, "agent:create"}
	creator := scMakeAgent(t, world.tokenB, "creator", list, list)

	const creates = 8

	var wg sync.WaitGroup

	statuses := make([]int, creates)
	start := make(chan struct{})

	for i := range creates {
		wg.Go(func() {
			<-start

			statuses[i] = post2(t, creator.Key.Token, scCreateBody(t, "racer", nil, nil)).status
		})
	}

	wg.Go(func() {
		<-start

		del(t, agItem(creator.Agent.ID), world.tokenB)
	})

	close(start)
	wg.Wait()

	for _, status := range statuses {
		switch status {
		case http.StatusCreated, http.StatusConflict, http.StatusUnauthorized:
		default:
			t.Errorf("a racing create answered %d, want 201, 409 or 401", status)
		}
	}

	// Every active agent that was not the creator has exactly one key, and every
	// key has its agent: the batch is atomic.
	expectCount(t, "agents a WHERE a.user_id = ? AND a.id <> ? AND NOT EXISTS "+
		"(SELECT 1 FROM japikeys k WHERE k.agent_id = a.id)", "0", world.b.userID, creator.Agent.ID)
	expectCount(t, "japikeys WHERE agent_id IS NOT NULL AND agent_id NOT IN (SELECT id FROM agents)", "0")

	// Every agent the race made is a copy of the creator's scopes.
	expectCount(t, "agents WHERE user_id = ? AND id <> ? AND scopes <> ?", "0",
		world.b.userID, creator.Agent.ID, `["default:agent","agent:create"]`)

	// And once the dust settles the creator's key is dead.
	scBearer(t, http.MethodGet, pathAgent, nil, creator.Key.Token).
		expect(t, "after the race", http.StatusUnauthorized, "unauthenticated")

	if strings.TrimSpace(scalar(t, "SELECT count(*) FROM agents WHERE id = ? AND revoked_at IS NOT NULL", creator.Agent.ID)) != "1" {
		t.Error("the creator was not revoked")
	}
}

// TestSessionsCarryEveryScope: a login signs default:session into the session
// and stores the same text, so a session is limited only by the role.
//
//nolint:paralleltest // shares one database
func TestSessionsCarryEveryScope(t *testing.T) {
	world := agNewPair(t, roleMember)

	for _, token := range []string{world.tokenA, world.tokenB} {
		claims := claimsOf(t, token)

		list, _ := claims["scope"].([]any)
		if len(list) != 1 || list[0] != scBundleSession {
			t.Errorf("session scope claim = %v, want [%s]", claims["scope"], scBundleSession)
		}
	}

	issuer, _ := claimsOf(t, world.tokenB)["iss"].(string)
	kid := issuer[strings.LastIndex(issuer, "/")+1:]

	if stored := scalar(t, "SELECT scope FROM japikeys WHERE kid = ?", kid); stored != `["`+scBundleSession+`"]` {
		t.Errorf("the session row's scope = %s, want the signed claim", stored)
	}
}

// TestCreateRefusesBadScopeLists: lists the code does not accept are refused by
// the real build with a fixed message, and nothing is written. (Rename takes no
// scopes at all: that is pinned with the other rename shapes.)
//
//nolint:paralleltest // shares one database
func TestCreateRefusesBadScopeLists(t *testing.T) {
	world := agNewPair(t, roleMember)

	for _, c := range []struct{ label, raw, code string }{
		{"scopes as a string", `{"name":"a","scopes":"admin:all"}`, "invalid_field_type"},
		{"keyScopes as a string", `{"name":"a","keyScopes":"agent:read"}`, "invalid_field_type"},
		{"an unknown scope", `{"name":"a","scopes":["admin:all"]}`, "invalid_scopes"},
		{"an unknown key scope", `{"name":"a","keyScopes":["agent:reed"]}`, "invalid_scopes"},
		{"all is not a name", `{"name":"a","scopes":["all"]}`, "invalid_scopes"},
		{"a repeated name", `{"name":"a","keyScopes":["agent:read","agent:read"]}`, "invalid_scopes"},
		{"two names in one string", `{"name":"a","scopes":["agent:read agent:create"]}`, "invalid_scopes"},
		{"an empty name", `{"name":"a","scopes":[""]}`, "invalid_scopes"},
		{"a number in the list", `{"name":"a","scopes":[1]}`, "invalid_field_type"},
	} {
		post(t, pathAgent, []byte(c.raw), world.tokenB).expect(t, c.label, http.StatusBadRequest, c.code)
	}

	expectCount(t, "agents WHERE user_id = ?", "0", world.b.userID)

	// The empty lists are accepted and stored as "[]", which fits the schema's
	// CHECK, so a credential that can use only the routes that need no scope can
	// exist.
	made := scMakeAgent(t, world.tokenB, "nothing", []string{}, []string{})

	if len(made.Agent.Scopes) != 0 || len(made.Key.Scopes) != 0 {
		t.Errorf("empty lists came back as %v and %v", made.Agent.Scopes, made.Key.Scopes)
	}

	if stored := scalar(t, "SELECT scopes FROM agents WHERE id = ?", made.Agent.ID); stored != "[]" {
		t.Errorf("stored agent scopes = %q, want []", stored)
	}

	if stored := scalar(t, "SELECT scope FROM japikeys WHERE kid = ?", made.Key.ID); stored != "[]" {
		t.Errorf("stored key scope = %q, want []", stored)
	}

	// A key with no scopes still verifies, and uses only the routes that need none.
	scBearer(t, http.MethodGet, pathSession, nil, made.Key.Token).expect(t, "an open route", http.StatusOK, "")
	scBearer(t, http.MethodGet, pathAgent, nil, made.Key.Token).
		expect(t, "a scoped route", http.StatusForbidden, "insufficient_scope")
}
