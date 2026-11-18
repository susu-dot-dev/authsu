//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package agents_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// Scope names the tables below repeat.
const (
	agentRead   = "agent:read"
	agentCreate = "agent:create"
	keyRead     = "key:read"
	userRead    = "user:read"
	bundleAgent = scope.DefaultAgent
	bundleUser  = scope.DefaultUser
	bundleAll   = scope.DefaultSession

	fieldScopes    = "scopes"
	fieldKeyScopes = "keyScopes"
)

// strs is a list of strings, for the expected lists of a response. It is never
// nil, so strs() is the empty list and a nil slice stays "not given".
func strs(names ...string) []string { return append([]string{}, names...) }

// created is the parsed body of a successful create.
func created(t *testing.T, body []byte) agents.CreateResponse {
	t.Helper()

	var response agents.CreateResponse

	err := json.Unmarshal(body, &response)
	if err != nil {
		t.Fatalf("body %q: %v", body, err)
	}

	return response
}

// createBodyOf is a create body for an agent named "a" with the lists that are
// given: nil leaves a list out, and an empty slice sends an empty list.
func createBodyOf(t *testing.T, agent, key []string) string {
	t.Helper()

	body := map[string]any{fieldName: "a"}

	if agent != nil {
		body[fieldScopes] = agent
	}

	if key != nil {
		body[fieldKeyScopes] = key
	}

	return marshal(t, body)
}

// marshal encodes v as JSON, failing the test if it cannot be.
func marshal(t *testing.T, v any) string {
	t.Helper()

	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return string(encoded)
}

// TestUserChoosesTheScopesOfTheAgentAndItsKey: a user (here with a session) sets
// both lists freely; an absent list is the default bundle written out in full;
// and a list that is present, even empty, is exactly what was asked for. The
// agent's row, the key's row and the signed claim all carry the same list.
func TestUserChoosesTheScopesOfTheAgentAndItsKey(t *testing.T) {
	t.Parallel()

	def := strs(bundleAgent)

	tests := []struct {
		name         string
		ask          [2][]string
		wantAgent    []string
		wantKey      []string
		sendNullList bool
	}{
		{"neither list: both default", [2][]string{nil, nil}, def, def, false},
		{"both lists", [2][]string{strs(agentRead), strs(keyRead)}, strs(agentRead), strs(keyRead), false},
		{"only the agent's list", [2][]string{strs(agentRead), nil}, strs(agentRead), def, false},
		{"only the key's list", [2][]string{nil, strs(agentRead)}, def, strs(agentRead), false},
		{"empty lists stay empty", [2][]string{strs(), strs()}, strs(), strs(), false},
		{"empty agent list, populated key list", [2][]string{strs(), strs(agentRead)}, strs(), strs(agentRead), false},
		{
			"bundles and scopes together", [2][]string{strs(bundleUser, agentRead), strs(bundleAgent, agentCreate)},
			strs(bundleUser, agentRead), strs(bundleAgent, agentCreate), false,
		},
		{
			"admin scopes are accepted: the role gates them", [2][]string{strs(userRead), strs(bundleAll)},
			strs(userRead), strs(bundleAll), false,
		},
		{
			"order is kept", [2][]string{strs(keyRead, agentRead), strs(keyRead, agentRead)},
			strs(keyRead, agentRead), strs(keyRead, agentRead), false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection,
				createBodyOf(t, test.ask[0], test.ask[1]))

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}

			response := created(t, rec.Body.Bytes())

			if !slices.Equal(response.Agent.Scopes, test.wantAgent) || !slices.Equal(response.Key.Scopes, test.wantKey) {
				t.Errorf("response scopes = agent %v key %v, want %v and %v",
					response.Agent.Scopes, response.Key.Scopes, test.wantAgent, test.wantKey)
			}

			// Responses always carry arrays, never null.
			if !strings.Contains(rec.Body.String(), `"scopes":[`) {
				t.Errorf("the body has no scopes array: %s", rec.Body)
			}

			checkWrittenLists(t, rg, response, test.wantAgent, test.wantKey)
		})
	}
}

// checkWrittenLists checks that what was written is the lists returned, as JSON,
// that the signed claim is the key's list and the row's copy the same text, and
// that a user's create names no creating agent.
func checkWrittenLists(t *testing.T, rg *rig, response agents.CreateResponse, wantAgent, wantKey []string) {
	t.Helper()

	written := rg.store.calls[0].agent
	if written.Scopes != scope.List(wantAgent).JSON() || written.KeyScope != scope.List(wantKey).JSON() {
		t.Errorf("written scopes = %s and %s, want %s and %s",
			written.Scopes, written.KeyScope, scope.List(wantAgent).JSON(), scope.List(wantKey).JSON())
	}

	verified, err := verifyToken(t, response.Key.Token, written.KeyJWK, "api_key")
	if err != nil {
		t.Fatalf("the token does not verify: %v", err)
	}

	claim := marshal(t, verified.claims[claimScope])
	if claim != written.KeyScope {
		t.Errorf("signed scope claim = %s, the row's copy = %s: they must be the same", claim, written.KeyScope)
	}

	if written.CreatedBy != "" {
		t.Errorf("a user's create was written as created by agent %q", written.CreatedBy)
	}
}

// badScopeLists are JSON lists that name anything but known scopes and bundles.
func badScopeLists() map[string]string {
	repeated := strings.Repeat(`"agent:read",`, 32) + `"agent:read"`

	return map[string]string{
		"an unknown scope":              `["agent:reed"]`,
		"an unknown resource":           `["nope:read"]`,
		"an unknown bundle":             `["default:admin"]`,
		"all is not a name":             `["all"]`,
		"a wildcard":                    `["*"]`,
		"an empty name":                 `[""]`,
		"the same scope twice":          `["agent:read","agent:read"]`,
		"two names in one string":       `["agent:read agent:create"]`,
		"upper case":                    `["AGENT:READ"]`,
		"padding":                       `[" agent:read"]`,
		"a NUL":                         `["agent:read\u0000"]`,
		"a number":                      `[1]`,
		"null in the list":              `[null]`,
		"an object":                     `[{"agent":"read"}]`,
		"a nested list":                 `[["agent:read"]]`,
		"one name over the entry bound": `[` + repeated + `]`,
		"a name a kilobyte long":        `["` + strings.Repeat("a", 1<<10) + `"]`,
		"a lone surrogate":              `["agent:\ud800"]`,
		"an invalid unicode escape":     `["agent:\u00zz"]`,
	}
}

// TestCreateRefusesBadScopes: a list that names anything but known scopes and
// bundles is refused whole, before a key is created or anything is written.
func TestCreateRefusesBadScopes(t *testing.T) {
	t.Parallel()

	for name, list := range badScopeLists() {
		for _, field := range []string{fieldScopes, fieldKeyScopes} {
			t.Run(field+"/"+name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection,
					`{"name":"a","`+field+`":`+list+`}`)

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d (%s), want 400", rec.Code, rec.Body.String())
				}

				rg.untouched()
			})
		}
	}
}

// TestBadScopesRefusalIsFixed: the message is the same whatever was sent and
// never echoes it.
func TestBadScopesRefusalIsFixed(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection,
		`{"name":"a","scopes":["secret-typo-zzz"]}`)

	wantFailure(t, rg, rec, http.StatusBadRequest,
		errorBody("invalid_scopes", "scopes must be a list of at most 32 distinct, known scope or bundle names"),
		"invalid_scopes")

	if strings.Contains(rec.Body.String(), "typo") {
		t.Error("the refusal echoed the input")
	}
}

// TestScopesOfTheWrongJSONType: a list that is not a JSON array is refused by
// the decoder, before the scope parser sees it.
func TestScopesOfTheWrongJSONType(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"name":"a","scopes":"agent:read"}`, `{"name":"a","scopes":{}}`, `{"name":"a","scopes":1}`,
		`{"name":"a","keyScopes":"agent:read"}`, `{"name":"a","keyScopes":true}`,
	} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, body)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}

			rg.untouched()
		})
	}
}

// TestNullScopesAreAbsent: JSON null is how a client says "not given", which is
// the default and not the empty list.
func TestNullScopesAreAbsent(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection,
		`{"name":"a","scopes":null,"keyScopes":null}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	response := created(t, rec.Body.Bytes())
	if !slices.Equal(response.Agent.Scopes, []string{scope.DefaultAgent}) ||
		!slices.Equal(response.Key.Scopes, []string{scope.DefaultAgent}) {
		t.Errorf("null scopes = %v and %v, want the defaults", response.Agent.Scopes, response.Key.Scopes)
	}
}

// TestAUsersKeyCreatesAgentsLikeAUser: a user's own API key with agent:create is
// the same caller as their session for the purpose of creating, and sets the
// lists freely. Programmatic creation of agents is a use case.
func TestAUsersKeyCreatesAgentsLikeAUser(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	header := rg.signInKey(keySpec{owner: userA, role: roleMember, scope: scope.List{bundleUser}})

	rec := rg.withKey(header, http.MethodPost, collection,
		createBodyOf(t, strs(bundleUser), strs(agentCreate, bundleAll)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	response := created(t, rec.Body.Bytes())
	if !slices.Equal(response.Agent.Scopes, strs(bundleUser)) ||
		!slices.Equal(response.Key.Scopes, strs(agentCreate, bundleAll)) {
		t.Errorf("scopes = %v and %v: a user's key chooses freely", response.Agent.Scopes, response.Key.Scopes)
	}

	if got := rg.store.calls[0].agent; got.CreatedBy != "" || got.Owner != userA {
		t.Errorf("written = %+v, want an agent of A created by no agent", got)
	}
}

// agentCaller is an agent of user A that holds the given lists.
func agentCaller(rg *rig, key, agent scope.List) string {
	return rg.signInKey(keySpec{
		owner: userA, role: roleMember, scope: key, agent: agentA1, agentScopes: agent.JSON(),
	})
}

// delegation is one create by an agent and what must come of it.
type delegation struct {
	name string
	// agent and key are the lists asked for; nil leaves the member out.
	agent, key []string
	// want is the status. On success wantKey is the list the new key must hold
	// (the new agent always holds a copy of the creator's); on a refusal
	// wantCode is the code that is logged.
	want     int
	wantCode string
	wantKey  []string
}

// delegations are the creates an agent holding creatorKey and creatorAgent may
// attempt. The creator's key lists bundle:agent, agent:create and agent:read as
// entries, so a new key may hold any subset of those three entries and nothing
// else, however the bundles expand.
func delegations() []delegation {
	const created, forbidden, malformed = http.StatusCreated, http.StatusForbidden, http.StatusBadRequest

	exceeded, inherited := agents.CodeKeyScopesExceeded, agents.CodeScopesInherited

	return []delegation{
		{"no lists: inherits the key's list", nil, nil, created, "", strs(bundleAgent, agentCreate, agentRead)},
		{"one entry of the creating key", nil, strs(agentRead), created, "", strs(agentRead)},
		{"the bundle entry alone", nil, strs(bundleAgent), created, "", strs(bundleAgent)},
		{
			"both entries, another order", nil, strs(agentCreate, bundleAgent), created, "",
			strs(agentCreate, bundleAgent),
		},
		{"an empty key list", nil, strs(), created, "", strs()},
		{"a scope the creating key did not list as an entry", nil, strs("agent:update"), forbidden, exceeded, nil},
		{"a bigger bundle", nil, strs(bundleUser), forbidden, exceeded, nil},
		{"the session bundle", nil, strs(bundleAll), forbidden, exceeded, nil},
		{"one allowed entry and one that is not", nil, strs(agentRead, "key:create"), forbidden, exceeded, nil},
		{"an admin scope", nil, strs(userRead), forbidden, exceeded, nil},
		{
			"choosing the agent's scopes: the same list", strs(bundleAgent, agentCreate, agentRead), nil,
			forbidden, inherited, nil,
		},
		{"choosing the agent's scopes: a smaller list", strs(agentRead), nil, forbidden, inherited, nil},
		{"choosing the agent's scopes: empty", strs(), nil, forbidden, inherited, nil},
		{"an unknown key name is a 400, not a 403", nil, strs("nope:read"), malformed, "invalid_scopes", nil},
		{"an unknown agent name is a 400 too", strs("nope:read"), nil, malformed, "invalid_scopes", nil},
	}
}

// TestAnAgentCreatesAgentsWithinItself is the delegation rule of
// docs/permissions_design.md: the new agent is a copy of the creating agent, and
// its key may hold only entries of the creating key's own list, compared as
// written. Everything else is refused before anything is created or written.
func TestAnAgentCreatesAgentsWithinItself(t *testing.T) {
	t.Parallel()

	creator := scope.List{bundleAgent, agentCreate, agentRead}

	for _, test := range delegations() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, "creator", 1, nil))
			rg.store.rows[0].agent.Scopes = creator.JSON()

			rec := rg.withKey(agentCaller(rg, creator, creator), http.MethodPost, collection,
				createBodyOf(t, test.agent, test.key))
			if rec.Code != test.want {
				t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, test.want)
			}

			if test.want == http.StatusCreated {
				checkDelegated(t, rg, created(t, rec.Body.Bytes()), creator, test.wantKey)

				return
			}

			if len(rg.logged) != 1 || rg.logged[0].Code != test.wantCode {
				t.Errorf("logged = %v, want one %s", rg.logged, test.wantCode)
			}

			if len(rg.keyCalls) != 0 || rg.writes() != 0 {
				t.Errorf("a refused create made %d keys and %d writes", len(rg.keyCalls), rg.writes())
			}
		})
	}
}

// checkDelegated checks a create by an agent that was allowed: the new agent is a
// copy of the creator's, the key holds the list asked for, the write names the
// creating agent so the store reads its scopes in the write, and the signed
// claim is the list that was stored and returned.
func checkDelegated(t *testing.T, rg *rig, response agents.CreateResponse, creator scope.List, wantKey []string) {
	t.Helper()

	if !slices.Equal(response.Agent.Scopes, []string(creator)) || !slices.Equal(response.Key.Scopes, wantKey) {
		t.Errorf("scopes = agent %v key %v, want %v and %v", response.Agent.Scopes, response.Key.Scopes, creator, wantKey)
	}

	written := rg.store.calls[0].agent

	// The new agent is an ordinary agent of the same user, and nothing records
	// who created it: CreatedBy only chooses where the scopes are read from.
	if written.CreatedBy != agentA1 || written.Owner != userA {
		t.Errorf("written = created by %q for %q, want %q for %q", written.CreatedBy, written.Owner, agentA1, userA)
	}

	if made := rg.store.agent(t, newAgentID); made.Scopes != creator.JSON() {
		t.Errorf("the new agent's stored scopes = %s, want a copy of the creator's %s", made.Scopes, creator.JSON())
	}

	if written.KeyScope != scope.List(wantKey).JSON() {
		t.Errorf("key scope written = %s, want %s", written.KeyScope, scope.List(wantKey).JSON())
	}
}

// TestAnAgentCannotCreateMoreCapableAgents is the property of the delegation
// rule: whatever lists an agent supplies and the server accepts, the new agent's
// effective scopes are within the creating agent's.
func TestAnAgentCannotCreateMoreCapableAgents(t *testing.T) {
	t.Parallel()

	creatorKey := scope.List{bundleAgent, agentCreate}
	creatorAgent := scope.List{bundleAgent, agentCreate}
	ceiling := creatorKey.Expand().Intersect(creatorAgent.Expand())

	pool := []string{bundleAgent, bundleUser, bundleAll, agentCreate, agentRead, keyRead, userRead}

	for mask := range 1 << len(pool) {
		var requested []string

		for i, name := range pool {
			if mask&(1<<i) != 0 {
				requested = append(requested, name)
			}
		}

		rg := newRig(t)
		rg.seed(userA, stored(agentA1, "creator", 1, nil))
		rg.store.rows[0].agent.Scopes = creatorAgent.JSON()

		body := marshal(t, map[string]any{fieldName: "c", fieldKeyScopes: requested})

		rec := rg.withKey(agentCaller(rg, creatorKey, creatorAgent), http.MethodPost, collection, body)
		if rec.Code != http.StatusCreated {
			continue
		}

		response := created(t, rec.Body.Bytes())
		child := scope.List(response.Key.Scopes).Expand().Intersect(scope.List(response.Agent.Scopes).Expand())

		for _, s := range child.Sorted() {
			if !ceiling.Has(s) {
				t.Fatalf("requested %v: the new agent holds %s, which its creator does not", requested, s)
			}
		}
	}
}

// TestTheResponseReportsTheScopesTheWriteStored: an agent's create copies the
// creating agent's scopes from its row in the write, which can differ from the
// list the request was verified with if the row changed in between. The
// response reports what the write stored, not what was verified, so a client is
// never told an agent holds scopes its row does not.
func TestTheResponseReportsTheScopesTheWriteStored(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		verified scope.List
		row      scope.List
	}{
		{"the row was narrowed after verification", scope.List{bundleAgent, agentCreate}, scope.List{agentCreate}},
		{"the row was widened after verification", scope.List{agentCreate}, scope.List{bundleAgent, agentCreate}},
		{"the row was emptied after verification", scope.List{agentCreate}, scope.List{}},
		{"the row did not change", scope.List{bundleAgent, agentCreate}, scope.List{bundleAgent, agentCreate}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, "creator", 1, nil))
			rg.store.rows[0].agent.Scopes = test.row.JSON()

			creatorKey := scope.List{bundleAgent, agentCreate}

			rec := rg.withKey(agentCaller(rg, creatorKey, test.verified), http.MethodPost, collection, bodyX)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d (%s), want 201", rec.Code, rec.Body)
			}

			response := created(t, rec.Body.Bytes())

			if !slices.Equal(response.Agent.Scopes, test.row.Claim()) {
				t.Errorf("response scopes = %v, want the stored %v (verified with %v)",
					response.Agent.Scopes, test.row.Claim(), test.verified)
			}

			if made := rg.store.agent(t, newAgentID); made.Scopes != test.row.JSON() {
				t.Errorf("stored scopes = %s, want %s", made.Scopes, test.row.JSON())
			}
		})
	}
}

// TestAStoredScopeListThatIsNotAListReportsAsEmpty: the response never reports
// more than the stored text says. A list the store returns that is not a JSON
// array of strings reads as the empty list, as it does everywhere it is read.
func TestAStoredScopeListThatIsNotAListReportsAsEmpty(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(agentA1, "creator", 1, nil))
	rg.store.rows[0].agent.Scopes = "[unterminated"

	rec := rg.withKey(agentCaller(rg, scope.List{agentCreate}, scope.List{agentCreate}),
		http.MethodPost, collection, bodyX)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s), want 201", rec.Code, rec.Body)
	}

	if got := created(t, rec.Body.Bytes()).Agent.Scopes; len(got) != 0 {
		t.Errorf("response scopes = %v, want none", got)
	}
}

// TestAnAgentThatWasRevokedCreatesNothing: the creating agent is checked in the
// write, and a revoked one (or one that is not the owner's) fails it as a
// conflict, so a request authenticated just before a revocation cannot create an
// agent. Nothing is left behind.
func TestAnAgentThatWasRevokedCreatesNothing(t *testing.T) {
	t.Parallel()

	revoked := int64(5)

	tests := []struct {
		name string
		seed func(*rig)
	}{
		{"revoked after the key was verified", func(rg *rig) { rg.seed(userA, stored(agentA1, "creator", 1, &revoked)) }},
		{"the agent is another user's", func(rg *rig) { rg.seed(userB, stored(agentA1, "creator", 1, nil)) }},
		{"the agent is gone", func(*rig) {}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			test.seed(rg)

			rec := rg.withKey(agentCaller(rg, scope.List{"agent:create"}, scope.List{"agent:create"}),
				http.MethodPost, collection, `{"name":"c"}`)

			wantFailure(t, rg, rec, http.StatusConflict,
				errorBody("agent_limit_reached", "an account may have at most 25 active agents"), agents.CodeLimit)

			for _, row := range rg.store.rows {
				if row.agent.ID == newAgentID {
					t.Error("a refused create left an agent behind")
				}
			}
		})
	}
}

// TestAgentsMayNotRenameOrRevokeWhateverTheyHold: agents are peers under their
// user, so even an agent that holds the scopes is refused before the handler.
func TestAgentsMayNotRenameOrRevokeWhateverTheyHold(t *testing.T) {
	t.Parallel()

	everything := scope.List{scope.DefaultSession}

	routes := []agentRoute{
		{name: routeRename, method: http.MethodPatch, target: itemPrefix + agentA2, body: bodyRenamed},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + agentA2, body: ""},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, "creator", 1, nil), stored(agentA2, "sibling", 2, nil))

			rec := rg.withKey(agentCaller(rg, everything, everything), route.method, route.target, route.body)

			wantFailure(t, rg, rec, http.StatusForbidden,
				errorBody("forbidden", "an agent may not do this"), "forbidden")

			if rg.writes() != 0 {
				t.Errorf("a refused request made %d writes", rg.writes())
			}

			if got := rg.store.agent(t, agentA2); got.Name != "sibling" || got.RevokedAt != nil {
				t.Errorf("the sibling became %+v", got)
			}
		})
	}
}

// routeNamed is the route of everyRoute called name.
func routeNamed(t *testing.T, name string) agentRoute {
	t.Helper()

	at := slices.IndexFunc(everyRoute(), func(route agentRoute) bool { return route.name == name })
	if at < 0 {
		t.Fatalf("no route named %q", name)
	}

	return everyRoute()[at]
}

// TestKeysScopeBoundsEveryRoute: a key can use only the routes its scopes allow,
// and a user's key without agent:create cannot create.
func TestKeysScopeBoundsEveryRoute(t *testing.T) {
	t.Parallel()

	const ok, no = http.StatusOK, http.StatusForbidden

	tests := []struct {
		name   string
		scopes scope.List
		route  string
		want   int
	}{
		{"list needs agent:read", scope.List{agentRead}, routeList, ok},
		{"list without it", scope.List{agentCreate}, routeList, no},
		{"get needs agent:read", scope.List{agentRead}, routeGet, ok},
		{"get without it", scope.List{}, routeGet, no},
		{"create needs agent:create", scope.List{agentCreate}, routeCreate, http.StatusCreated},
		{"create without it", scope.List{agentRead, "agent:update"}, routeCreate, no},
		{"rename needs agent:update", scope.List{"agent:update"}, routeRename, ok},
		{"rename without it", scope.List{"agent:revoke"}, routeRename, no},
		{"revoke needs agent:revoke", scope.List{"agent:revoke"}, routeRevoke, ok},
		{"revoke without it", scope.List{"agent:update"}, routeRevoke, no},
		{"the user bundle does all of them", scope.List{bundleUser}, routeRevoke, ok},
		{"the agent bundle only reads", scope.List{bundleAgent}, routeCreate, no},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			route := routeNamed(t, test.route)

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))

			header := rg.signInKey(keySpec{owner: userA, role: roleMember, scope: test.scopes})

			rec := rg.withKey(header, route.method, route.target, route.body)
			if rec.Code != test.want {
				t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, test.want)
			}

			if test.want == no && (rg.writes() != 0 || len(rg.keyCalls) != 0) {
				t.Errorf("a refused request made %d writes and %d keys", rg.writes(), len(rg.keyCalls))
			}
		})
	}
}

// TestACreatedKeyReadsBackAsTheScopesItWasGiven closes the loop: the key an
// agent's create returns is accepted by the boundary and has exactly the scopes
// it was given, so what is signed is what is enforced.
func TestACreatedKeyReadsBackAsTheScopesItWasGiven(t *testing.T) {
	t.Parallel()

	rg := newRig(t)

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection,
		`{"name":"a","scopes":["default:user"],"keyScopes":["agent:read"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	response := created(t, rec.Body.Bytes())
	written := rg.store.calls[0].agent

	// Store the row the way the database would, and present the returned token.
	rg.keys.apiRows[written.KeyID] = storeKeyRow(written, rg)

	header := "Bearer " + response.Key.Token

	if got := rg.withKey(header, http.MethodGet, collection, ""); got.Code != http.StatusOK {
		t.Errorf("the key's own scope was refused: %d %s", got.Code, got.Body)
	}

	if got := rg.withKey(header, http.MethodPost, collection, bodyX); got.Code != http.StatusForbidden {
		t.Errorf("a scope the key was not given was allowed: %d %s", got.Code, got.Body)
	}

	if !reflect.DeepEqual(response.Key.Scopes, []string{"agent:read"}) {
		t.Errorf("returned key scopes = %v", response.Key.Scopes)
	}
}
