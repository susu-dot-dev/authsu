//go:build e2e

//nolint:goconst,funlen,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// agents_sandbox_test.go drives the sandbox half of /api/agent against the real
// Worker (docs/orgs_design.md): creating an agent in a sandbox, what an agent
// of a sandbox may reach, and the boundary that refuses it everywhere else.
// The unit tests fake the store, so what only the real build and the real
// SQLite can show is here:
//
//   - the create's write: the sandbox must be a sandbox, unexpired as of the
//     write, and the caller its administrator, and a refusal says "sandbox"
//     and not "limit" by the column D1 names in its error;
//   - an agent's create takes the creating agent's sandbox from its row, and
//     no request value can move it;
//   - the confinement of the list and the read (IS equality, so ordinary agents
//     see only ordinary ones and a sandbox's agents only their sandbox), through
//     paging and the sandbox filter;
//   - the key of an agent in a sandbox that has expired, or been deleted, is
//     refused as any dead key is;
//   - an agent of a sandbox is refused on every route that has not opted in,
//     whatever scopes it holds, and the consent that attaches an agent to an
//     OAuth grant cannot attach one.
//
// The sandboxes are seeded through the side channel, because the organization
// routes are another file's: the behaviour under test here is always a request
// to the Worker.
//
// REVIEW.md categories covered: permission confusion (another user's sandbox,
// a standard organization, an administrator of nothing, a platform
// administrator, an agent choosing a sandbox, an agent on routes it has no
// business with), interleaving (creates racing at the agent limit, a sandbox
// expiring under a live key), input edge cases (every spelling of a sandbox id
// in a body and a query), and type/bound confusion (an id where a sandbox is
// wanted).

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	sbCodeNotFound    = "sandbox_not_found"
	sbCodeInherited   = "agent_sandbox_inherited"
	sbCodeConfined    = "sandbox_confined"
	sbCodeInvalidBody = "invalid_sandbox_id"
	sbCodeInvalidQ    = "invalid_sandbox_filter"
	sbCodeScopes      = "agent_scopes_inherited"

	// sbWeek is how long a seeded sandbox stands, in seconds.
	sbWeek = 7 * 24 * 3600

	// Families of the ids this file seeds.
	sbSandboxFam = "0c10"
	sbOrgFam     = "0c11"
	sbAgentFam   = "0c12"
	sbKeyFam     = "0c13"

	// sbAgentScope is the scope list of the agents and keys this file seeds: the
	// two an agent needs to read and to create agents.
	sbAgentScope = `["agent:read","agent:create"]`
	// sbEverything is the widest list there is, so that no refusal of a route
	// can be put down to a missing scope.
	sbEverything = `["default:session"]`
)

// sbView is the JSON view of an agent with its sandbox.
type sbView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	Status    string   `json:"status"`
	SandboxID *string  `json:"sandboxId"`
}

// sbCreated is the body of a successful create.
type sbCreated struct {
	Agent sbView `json:"agent"`
	Key   agKey  `json:"key"`
}

// sbPage is the body of a list.
type sbPage struct {
	Agents []sbView `json:"agents"`
	Next   string   `json:"next"`
}

// sbSandboxOf is the sandbox of a view, or "".
func sbSandboxOf(v sbView) string {
	if v.SandboxID == nil {
		return ""
	}

	return *v.SandboxID
}

// sbIDs are the ids of a page's agents, in order.
func sbIDs(page sbPage) []string {
	ids := make([]string, 0, len(page.Agents))
	for _, agent := range page.Agents {
		ids = append(ids, agent.ID)
	}

	return ids
}

// sbSeedSandbox inserts a sandbox that expires in lifetime seconds from the
// database's now (negative: it already has) with admin as its one administrator.
func sbSeedSandbox(t *testing.T, id, admin string, lifetime int) {
	t.Helper()

	seed(t, "INSERT INTO orgs (id, kind, name, created_by, expires_at, created_at) "+
		"VALUES (?, 'sandbox', 'Scratch', ?, strftime('%s','now') + ?, strftime('%s','now'))", id, admin, lifetime)
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, strftime('%s','now'))", id, admin)
}

// sbSeedAgent inserts an active agent of owner holding sbAgentScope, in sandbox
// ("" for none).
func sbSeedAgent(t *testing.T, id, owner, name, sandbox string) {
	t.Helper()

	var inSandbox any
	if sandbox != "" {
		inSandbox = sandbox
	}

	seed(t, "INSERT INTO agents (id, user_id, name, scopes, created_at, sandbox_id) "+
		"VALUES (?, ?, ?, ?, strftime('%s','now'), ?)", id, owner, name, sbAgentScope, inSandbox)
}

// sbSeedKey inserts an API key holding scope for owner, of agent ("" for the
// user's own), and returns its token.
func sbSeedKey(t *testing.T, id, owner, agent, scope string) string {
	t.Helper()

	token := newToken(tagAPIKey)

	seedSecret(t, id, kindAPIKey, token)

	var agentID any
	if agent != "" {
		agentID = agent
	}

	seed(t, "INSERT INTO api_keys (id, user_id, agent_id, name, scope) VALUES (?, ?, ?, 'seeded', ?)",
		id, owner, agentID, scope)

	return token
}

// sbSeedAgentWithKey inserts an agent and a key of its own, both holding
// sbAgentScope, and returns the key's token.
func sbSeedAgentWithKey(t *testing.T, n int, owner, sandbox string) (string, string) {
	t.Helper()

	id := idN(sbAgentFam, n)

	sbSeedAgent(t, id, owner, "agent "+id[len(id)-3:], sandbox)

	return id, sbSeedKey(t, idN(sbKeyFam, n), owner, id, sbAgentScope)
}

// sbAs sends a request authorized by an API key.
func sbAs(t *testing.T, key, method, path string, body []byte) reply {
	t.Helper()

	return send(t, request{method: method, path: path, body: body, bearer: key})
}

// sbCreate posts a create naming a sandbox (raw JSON, or "" to leave it out).
func sbCreate(t *testing.T, as func(body []byte) reply, name, sandboxJSON string) reply {
	t.Helper()

	body := `{"name":"` + name + `"`
	if sandboxJSON != "" {
		body += `,"sandboxId":` + sandboxJSON
	}

	return as([]byte(body + `}`))
}

// sbQuoted is s as a JSON string.
func sbQuoted(s string) string { return `"` + s + `"` }

// sbWorld is two users, an administrator A and a member B, both signed in by
// real logins, with the sandboxes the tests share:
//
//	mine      B's, standing        others    A's, standing
//	expired   B's, run out         adminless B created it but no longer administers it
//	standard  a standard organization B administers, and its id
type sbWorld struct {
	agPair

	mine, others, expired, adminless, standard, second string
}

func sbNewWorld(t *testing.T) sbWorld {
	t.Helper()

	world := sbWorld{
		agPair:    agNewPair(t, roleMember),
		mine:      idN(sbSandboxFam, 1),
		others:    idN(sbSandboxFam, 2),
		expired:   idN(sbSandboxFam, 3),
		adminless: idN(sbSandboxFam, 4),
		second:    idN(sbSandboxFam, 5),
		standard:  idN(sbOrgFam, 1),
	}

	sbSeedSandbox(t, world.mine, world.b.userID, sbWeek)
	sbSeedSandbox(t, world.second, world.b.userID, sbWeek)
	sbSeedSandbox(t, world.others, world.a.userID, sbWeek)
	sbSeedSandbox(t, world.expired, world.b.userID, -10)
	sbSeedSandbox(t, world.adminless, world.b.userID, sbWeek)
	seed(t, "DELETE FROM org_admins WHERE org_id = ?", world.adminless)

	seedOrg(t, world.standard)
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, strftime('%s','now'))",
		world.standard, world.b.userID)

	return world
}

// sbCheckCreatedIn checks a create that succeeded in sandbox for owner: the
// response and the stored row say so, the agent's one key belongs to it and its
// user, and that key resolves and sees only the sandbox.
func sbCheckCreatedIn(t *testing.T, got reply, owner, sandbox string) {
	t.Helper()

	created := agDecode[sbCreated](t, got)
	made := created.Agent

	if sbSandboxOf(made) != sandbox || made.Status != "active" {
		t.Errorf("created agent = %+v, want active in %s", made, sandbox)
	}

	if stored := scalar(t, "SELECT sandbox_id FROM agents WHERE id = ?", made.ID); stored != sandbox {
		t.Errorf("stored sandbox = %q, want %q", stored, sandbox)
	}

	keyRow := scalar(t, "SELECT user_id||'|'||agent_id FROM api_keys WHERE agent_id = ?", made.ID)
	if keyRow != owner+"|"+made.ID {
		t.Errorf("key row = %q, want the user and the agent", keyRow)
	}

	// It reads its sandbox, which holds every agent created in it so far.
	listed := agDecode[sbPage](t, sbAs(t, created.Key.Token, http.MethodGet, pathAgent, nil))
	if !slices.Contains(sbIDs(listed), made.ID) {
		t.Errorf("the new agent's own list = %v, want it to hold itself", sbIDs(listed))
	}

	for _, seen := range listed.Agents {
		if sbSandboxOf(seen) != sandbox {
			t.Errorf("the new agent sees %s in %q, want only %q", seen.ID, sbSandboxOf(seen), sandbox)
		}
	}
}

// ---- a user creates an agent in a sandbox ----------------------------------

// TestSandboxCreateByAUser: a user creates an agent in a sandbox they
// administer, by session or by their own key, and it is stored there, shown
// there and given a key that works. Every other sandbox is the same 404 and
// writes nothing: someone else's, one that has run out, one the caller no
// longer administers, a standard organization (even one the caller
// administers), an id that is not a sandbox, one that does not exist, and a
// platform administrator's own reach does not include a user's sandbox.
//
//nolint:paralleltest // shares one database
func TestSandboxCreateByAUser(t *testing.T) {
	world := sbNewWorld(t)
	userKey := sbSeedKey(t, idN(sbKeyFam, 90), world.b.userID, "", `["default:user"]`)

	asSession := func(token string) func([]byte) reply {
		return func(body []byte) reply { return post(t, pathAgent, body, token) }
	}
	asKey := func(key string) func([]byte) reply {
		return func(body []byte) reply { return sbAs(t, key, http.MethodPost, pathAgent, body) }
	}

	refusals := []struct {
		name    string
		as      func([]byte) reply
		sandbox string
	}{
		{"someone else's sandbox", asSession(world.tokenB), world.others},
		{"someone else's sandbox, by key", asKey(userKey), world.others},
		{"an expired sandbox", asSession(world.tokenB), world.expired},
		{"a sandbox the caller no longer administers", asSession(world.tokenB), world.adminless},
		{"a standard organization the caller administers", asSession(world.tokenB), world.standard},
		{"a sandbox that does not exist", asSession(world.tokenB), idMissing},
		{"an agent's id", asSession(world.tokenB), idAgentA},
		{"the user's own id", asSession(world.tokenB), world.b.userID},
		{"a platform administrator in a user's sandbox", asSession(world.tokenA), world.mine},
	}

	for _, test := range refusals {
		t.Run(test.name, func(t *testing.T) {
			got := sbCreate(t, test.as, "refused", sbQuoted(test.sandbox))

			got.expect(t, "create in "+test.name, http.StatusNotFound, sbCodeNotFound)
		})
	}

	expectCount(t, tableAgents, "0")
	expectCount(t, tableKeys, "1")
	expectNoOrphanSecrets(t)

	for _, as := range []struct {
		name string
		send func([]byte) reply
	}{
		{"by session", asSession(world.tokenB)},
		{"by key", asKey(userKey)},
	} {
		t.Run("a sandbox of their own "+as.name, func(t *testing.T) {
			got := sbCreate(t, as.send, "scratch "+as.name[3:], sbQuoted(world.mine))
			got.expect(t, "create", http.StatusCreated, "")

			sbCheckCreatedIn(t, got, world.b.userID, world.mine)
		})
	}

	// Without a sandbox, and with null: an ordinary agent, with no sandboxId.
	for _, body := range []string{`{"name":"plain"}`, `{"name":"plain","sandboxId":null}`} {
		got := post(t, pathAgent, []byte(body), world.tokenB)
		got.expect(t, "create "+body, http.StatusCreated, "")

		if strings.Contains(got.body, "sandboxId") {
			t.Errorf("an ordinary agent reports a sandbox: %s", got.body)
		}

		made := agDecode[sbCreated](t, got).Agent
		expectCount(t, "agents WHERE id = ? AND sandbox_id IS NULL", "1", made.ID)
	}

	expectNoOrphanSecrets(t)
}

// TestSandboxCreateRefusesABadSandboxId: a sandboxId that is not exactly a
// canonical lower-case id, or not a string, is a 400 before anything is
// written, and nothing about it is corrected.
//
//nolint:paralleltest // shares one database
func TestSandboxCreateRefusesABadSandboxId(t *testing.T) {
	world := sbNewWorld(t)

	tests := []struct {
		name string
		raw  string
		code string
	}{
		{"empty", `""`, sbCodeInvalidBody},
		{"upper case", sbQuoted(strings.ToUpper(world.mine)), sbCodeInvalidBody},
		{"no dashes", sbQuoted(strings.ReplaceAll(world.mine, "-", "")), sbCodeInvalidBody},
		{"a space after it", sbQuoted(world.mine + " "), sbCodeInvalidBody},
		{"a newline after it", sbQuoted(world.mine + `\n`), sbCodeInvalidBody},
		{"a NUL after it", sbQuoted(world.mine + `\u0000`), sbCodeInvalidBody},
		{"a SQL injection", sbQuoted(`' OR '1'='1`), sbCodeInvalidBody},
		{"two ids", sbQuoted(world.mine + "," + world.second), sbCodeInvalidBody},
		{"a number", `5`, "invalid_field_type"},
		{"true", `true`, "invalid_field_type"},
		{"an object", `{"id":"` + world.mine + `"}`, "invalid_field_type"},
		{"an array", `["` + world.mine + `"]`, "invalid_field_type"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := post(t, pathAgent, []byte(`{"name":"x","sandboxId":`+test.raw+`}`), world.tokenB)

			got.expect(t, "create", http.StatusBadRequest, test.code)
		})
	}

	// Given twice, the decoder refuses the repetition before the id is read.
	got := post(t, pathAgent, []byte(`{"name":"x","sandboxId":"`+world.mine+`","sandboxId":"`+world.second+`"}`), world.tokenB)
	got.expect(t, "a repeated member", http.StatusBadRequest, "duplicate_field")

	expectCount(t, tableAgents, "0")
	expectCount(t, tableKeys, "0")
	expectNoOrphanSecrets(t)
}

// TestSandboxAgentsCountAgainstTheLimit: an agent in a sandbox is one of the
// user's active agents, so it takes a place and the 26th, in a sandbox or not,
// is refused as the limit and not as a missing sandbox, and a revoked agent
// frees its place. Concurrent creates at the limit cannot both succeed.
//
//nolint:paralleltest // shares one database
func TestSandboxAgentsCountAgainstTheLimit(t *testing.T) {
	world := sbNewWorld(t)
	owner := world.b.userID

	agSeedMany(t, owner, 1, agMaxAgents-2)

	first := agDecode[sbCreated](t, sbCreate(t, func(b []byte) reply { return post(t, pathAgent, b, world.tokenB) }, "24th", sbQuoted(world.mine)))
	if first.Agent.ID == "" {
		t.Fatal("the 24th agent was not created in the sandbox")
	}

	// One place is left: eight creates in a sandbox race for it.
	replies := agRelease(8, func(int) reply {
		return sbCreate(t, func(b []byte) reply { return post(t, pathAgent, b, world.tokenB) }, "racer", sbQuoted(world.mine))
	})

	agNo5xx(t, "creates at the limit", replies)

	tally := agTally(replies)
	if tally["201"] != 1 || tally["409 "+agCodeLimit] != 7 {
		t.Errorf("replies = %v, want one 201 and seven 409 %s", tally, agCodeLimit)
	}

	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", owner)
	expectCount(t, "agents WHERE sandbox_id = ?", "2", world.mine)
	expectNoOrphanSecrets(t)

	// At the limit, every create is the limit's 409, whatever it names.
	for _, sandbox := range []string{world.mine, world.second} {
		got := sbCreate(t, func(b []byte) reply { return post(t, pathAgent, b, world.tokenB) }, "over", sbQuoted(sandbox))
		got.expect(t, "create over the limit in "+sandbox, http.StatusConflict, agCodeLimit)
	}

	got := post(t, pathAgent, []byte(`{"name":"over"}`), world.tokenB)
	got.expect(t, "ordinary create over the limit", http.StatusConflict, agCodeLimit)

	// A sandbox that is not usable is still the sandbox's answer at the limit:
	// the guard is first, and it does not depend on the count.
	got = sbCreate(t, func(b []byte) reply { return post(t, pathAgent, b, world.tokenB) }, "over", sbQuoted(world.others))
	got.expect(t, "create in someone else's sandbox at the limit", http.StatusNotFound, sbCodeNotFound)

	// Revoking the sandbox agent frees its place.
	del(t, agItem(first.Agent.ID), world.tokenB).expect(t, "revoke", http.StatusOK, "")
	sbCreate(t, func(b []byte) reply { return post(t, pathAgent, b, world.tokenB) }, "after", sbQuoted(world.mine)).
		expect(t, "create after a revocation", http.StatusCreated, "")
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", owner)
}

// TestSandboxExpiryFreesTheAgentLimit: the agents of a sandbox that has expired
// stop counting against their user's limit, though nothing has deleted them
// (docs/orgs_design.md, principle 6). The user's 25 agents are one ordinary one
// and 24 in a sandbox: at the limit, a create by the user and a create by the
// ordinary agent are both refused. Once the sandbox expires, behind the
// Worker's back, both succeed, a create in the expired sandbox itself is still
// refused as a missing sandbox, and the agents in it are still there. There is
// no cap of a sandbox's own: only the user's total counts.
//
//nolint:paralleltest // shares one database
func TestSandboxExpiryFreesTheAgentLimit(t *testing.T) {
	world := sbNewWorld(t)
	owner := world.b.userID

	_, ordinaryKey := sbSeedAgentWithKey(t, 1, owner, "")

	for i := range agMaxAgents - 1 {
		sbSeedAgent(t, idN(sbAgentFam, 100+i), owner, "boxed", world.mine)
	}

	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", owner)

	byUser := func(sandboxJSON string) reply {
		return sbCreate(t, func(b []byte) reply { return post(t, pathAgent, b, world.tokenB) }, "extra", sandboxJSON)
	}
	byAgent := func() reply { return sbAs(t, ordinaryKey, http.MethodPost, pathAgent, []byte(`{"name":"extra"}`)) }

	// A standing sandbox's agents count, so the user is at the limit.
	byUser("").expect(t, "a user at the limit", http.StatusConflict, agCodeLimit)
	byUser(sbQuoted(world.second)).expect(t, "a user at the limit, in another sandbox", http.StatusConflict, agCodeLimit)
	byAgent().expect(t, "an agent at the limit", http.StatusConflict, agCodeLimit)

	// The last second of the sandbox: it still stands, so it still counts.
	seed(t, "UPDATE orgs SET expires_at = strftime('%s','now') + 3600 WHERE id = ?", world.mine)
	byUser("").expect(t, "a user at the limit, the sandbox standing", http.StatusConflict, agCodeLimit)

	// Expired, and not deleted: the 24 agents stop counting.
	seed(t, "UPDATE orgs SET expires_at = strftime('%s','now') - 1 WHERE id = ?", world.mine)

	byUser("").expect(t, "a user whose sandbox expired", http.StatusCreated, "")
	byAgent().expect(t, "an agent of a user whose sandbox expired", http.StatusCreated, "")
	byUser(sbQuoted(world.mine)).expect(t, "a create in the expired sandbox", http.StatusNotFound, sbCodeNotFound)
	byUser(sbQuoted(world.second)).expect(t, "a create in another sandbox", http.StatusCreated, "")

	expectCount(t, "agents WHERE sandbox_id = ?", strconv.Itoa(agMaxAgents-1), world.mine)
	expectCount(t, "agents WHERE user_id = ?", strconv.Itoa(agMaxAgents+3), owner)

	// The limit is the user's total of agents that count, so the user can fill
	// the rest and is then refused again: the expired sandbox's agents are not
	// a place held.
	for i := range agMaxAgents - 4 {
		byUser("").expect(t, "filling the freed places, create "+strconv.Itoa(i), http.StatusCreated, "")
	}

	byUser("").expect(t, "a user at the limit again", http.StatusConflict, agCodeLimit)
	expectNoOrphanSecrets(t)
}

// ---- an agent creates an agent ----------------------------------------------

// TestSandboxAgentCreatesIntoItsOwnSandbox: the new agent of an agent is in the
// creating agent's sandbox (or in none), read from its row in the write. The
// agent may leave the sandbox out or repeat its own; it may not choose another,
// its user's own sandbox or not, and a refused request writes nothing.
//
//nolint:paralleltest // shares one database
func TestSandboxAgentCreatesIntoItsOwnSandbox(t *testing.T) {
	world := sbNewWorld(t)
	owner := world.b.userID

	_, inMine := sbSeedAgentWithKey(t, 1, owner, world.mine)
	_, ordinary := sbSeedAgentWithKey(t, 2, owner, "")

	tests := []struct {
		name    string
		key     string
		sandbox string // raw JSON, or "" to leave the member out
		want    string // the new agent's sandbox, "" for none
		status  int
		code    string
	}{
		{"a sandbox agent names nothing", inMine, "", world.mine, http.StatusCreated, ""},
		{"a sandbox agent names null", inMine, "null", world.mine, http.StatusCreated, ""},
		{"a sandbox agent names its own", inMine, sbQuoted(world.mine), world.mine, http.StatusCreated, ""},
		{"an ordinary agent names nothing", ordinary, "", "", http.StatusCreated, ""},
		{"a sandbox agent names its user's other sandbox", inMine, sbQuoted(world.second), "", http.StatusForbidden, sbCodeInherited},
		{"a sandbox agent names someone else's sandbox", inMine, sbQuoted(world.others), "", http.StatusForbidden, sbCodeInherited},
		{"a sandbox agent names a standard organization", inMine, sbQuoted(world.standard), "", http.StatusForbidden, sbCodeInherited},
		{"a sandbox agent names one that does not exist", inMine, sbQuoted(idMissing), "", http.StatusForbidden, sbCodeInherited},
		{"an ordinary agent names a sandbox of its user", ordinary, sbQuoted(world.mine), "", http.StatusForbidden, sbCodeInherited},
		{"an ordinary agent names an expired sandbox", ordinary, sbQuoted(world.expired), "", http.StatusForbidden, sbCodeInherited},
		{"a sandbox agent names a malformed id", inMine, sbQuoted("nope"), "", http.StatusBadRequest, sbCodeInvalidBody},
		{"a sandbox agent names an empty id", inMine, `""`, "", http.StatusBadRequest, sbCodeInvalidBody},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := count(t, tableAgents)

			got := sbCreate(t, func(b []byte) reply { return sbAs(t, test.key, http.MethodPost, pathAgent, b) }, "child", test.sandbox)

			if test.status != http.StatusCreated {
				got.expect(t, test.name, test.status, test.code)

				if after := count(t, tableAgents); after != before {
					t.Errorf("a refused create changed the agents from %s to %s", before, after)
				}

				return
			}

			got.expect(t, test.name, http.StatusCreated, "")

			made := agDecode[sbCreated](t, got).Agent
			if sbSandboxOf(made) != test.want {
				t.Errorf("response sandbox = %q, want %q (%s)", sbSandboxOf(made), test.want, got.body)
			}

			if stored := scalar(t, "SELECT ifnull(sandbox_id, '') FROM agents WHERE id = ?", made.ID); stored != test.want {
				t.Errorf("stored sandbox = %q, want %q", stored, test.want)
			}

			// The new agent is its creator's copy and its user's.
			if row := scalar(t, "SELECT user_id||'|'||scopes FROM agents WHERE id = ?", made.ID); row != owner+"|"+sbAgentScope {
				t.Errorf("stored agent = %q, want the owner's and the creator's scopes", row)
			}

			// Its key resolves, and sees what its sandbox sees and no more.
			token := agDecode[sbCreated](t, got).Key.Token
			listed := agDecode[sbPage](t, sbAs(t, token, http.MethodGet, pathAgent, nil))

			for _, seen := range listed.Agents {
				if sbSandboxOf(seen) != test.want {
					t.Errorf("the new agent sees %s in %q, want only %q", seen.ID, sbSandboxOf(seen), test.want)
				}
			}
		})
	}

	// Choosing the scopes is refused first, whatever the sandbox says.
	got := sbAs(t, inMine, http.MethodPost, pathAgent,
		[]byte(`{"name":"x","scopes":["agent:read"],"sandboxId":"`+world.second+`"}`))
	got.expect(t, "scopes and another sandbox", http.StatusForbidden, sbCodeScopes)

	expectNoOrphanSecrets(t)
}

// ---- what an agent reaches ---------------------------------------------------

// sbReach is user B's agents in and out of sandboxes, and the keys that read
// them: three ordinary agents, two in one sandbox (one revoked), one in another,
// and an agent of user A in A's sandbox.
type sbReach struct {
	sbWorld

	ordinary                []string
	inMine, inMineRevoked   string
	inSecond                string
	foreign                 string
	keyOrdinary, keyInMine  string
	keyInSecond, keyForeign string
}

func sbNewReach(t *testing.T) sbReach {
	t.Helper()

	reach := sbReach{sbWorld: sbNewWorld(t)}
	owner := reach.b.userID

	// Ids rise with n, so the agents read newest first as n falls.
	reach.ordinary = make([]string, 2)
	reach.ordinary[0], reach.keyOrdinary = sbSeedAgentWithKey(t, 1, owner, "")
	reach.ordinary[1], _ = sbSeedAgentWithKey(t, 2, owner, "")
	reach.inMine, reach.keyInMine = sbSeedAgentWithKey(t, 3, owner, reach.mine)
	reach.inMineRevoked, _ = sbSeedAgentWithKey(t, 4, owner, reach.mine)
	seed(t, "UPDATE agents SET revoked_at = strftime('%s','now') WHERE id = ?", reach.inMineRevoked)
	reach.inSecond, reach.keyInSecond = sbSeedAgentWithKey(t, 5, owner, reach.second)
	reach.foreign, reach.keyForeign = sbSeedAgentWithKey(t, 6, reach.a.userID, reach.others)

	return reach
}

// TestSandboxAgentListsOnlyItsSandbox: the list of an agent holds exactly the
// agents of its own sandbox, an ordinary agent's exactly the ordinary ones, and
// the user's everything of theirs, through the sandbox filter and the paging.
//
//nolint:paralleltest // shares one database
func TestSandboxAgentListsOnlyItsSandbox(t *testing.T) {
	reach := sbNewReach(t)

	// Newest first, as the list is.
	all := []string{reach.inSecond, reach.inMineRevoked, reach.inMine, reach.ordinary[1], reach.ordinary[0]}

	tests := []struct {
		name  string
		as    func(path string) reply
		query string
		want  []string
	}{
		{"the user, by session", func(p string) reply { return get(t, p, reach.tokenB) }, "", all},
		{"the user filtering to a sandbox", func(p string) reply { return get(t, p, reach.tokenB) }, "?sandbox=" + reach.mine,
			[]string{reach.inMineRevoked, reach.inMine}},
		{"the user filtering to another", func(p string) reply { return get(t, p, reach.tokenB) }, "?sandbox=" + reach.second,
			[]string{reach.inSecond}},
		{"the user filtering to someone else's", func(p string) reply { return get(t, p, reach.tokenB) }, "?sandbox=" + reach.others, []string{}},
		{"the user filtering to an expired one with none", func(p string) reply { return get(t, p, reach.tokenB) }, "?sandbox=" + reach.expired, []string{}},
		{"the administrator sees none of the user's", func(p string) reply { return get(t, p, reach.tokenA) }, "", []string{reach.foreign}},
		{"an agent of a sandbox", func(p string) reply { return sbAs(t, reach.keyInMine, http.MethodGet, p, nil) }, "",
			[]string{reach.inMineRevoked, reach.inMine}},
		{"an agent of a sandbox, paged", func(p string) reply { return sbAs(t, reach.keyInMine, http.MethodGet, p, nil) }, "?limit=1",
			[]string{reach.inMineRevoked}},
		{"an agent of a sandbox, after a cursor", func(p string) reply { return sbAs(t, reach.keyInMine, http.MethodGet, p, nil) },
			"?cursor=" + reach.inMineRevoked, []string{reach.inMine}},
		{"an agent of a sandbox, past what it may see", func(p string) reply { return sbAs(t, reach.keyInMine, http.MethodGet, p, nil) },
			"?cursor=" + reach.inMine, []string{}},
		{"an agent of a sandbox filtering to its own", func(p string) reply { return sbAs(t, reach.keyInMine, http.MethodGet, p, nil) },
			"?sandbox=" + reach.mine, []string{reach.inMineRevoked, reach.inMine}},
		{"an agent of a sandbox filtering to another", func(p string) reply { return sbAs(t, reach.keyInMine, http.MethodGet, p, nil) },
			"?sandbox=" + reach.second, []string{}},
		{"an agent of another sandbox", func(p string) reply { return sbAs(t, reach.keyInSecond, http.MethodGet, p, nil) }, "",
			[]string{reach.inSecond}},
		{"an ordinary agent", func(p string) reply { return sbAs(t, reach.keyOrdinary, http.MethodGet, p, nil) }, "",
			[]string{reach.ordinary[1], reach.ordinary[0]}},
		{"an ordinary agent filtering to a sandbox", func(p string) reply { return sbAs(t, reach.keyOrdinary, http.MethodGet, p, nil) },
			"?sandbox=" + reach.mine, []string{}},
		{"an agent of another user's sandbox", func(p string) reply { return sbAs(t, reach.keyForeign, http.MethodGet, p, nil) }, "",
			[]string{reach.foreign}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.as(pathAgent + test.query)
			got.expect(t, test.name, http.StatusOK, "")

			if ids := sbIDs(agDecode[sbPage](t, got)); !slices.Equal(ids, test.want) {
				t.Errorf("agents = %v, want %v", ids, test.want)
			}
		})
	}

	// Paging an agent's list to its end never leaves the sandbox: the next
	// cursor of a confined page is an agent it may see.
	var seen []string

	query := "?limit=1"

	for range 5 {
		page := agDecode[sbPage](t, sbAs(t, reach.keyInMine, http.MethodGet, pathAgent+query, nil))
		seen = append(seen, sbIDs(page)...)

		if page.Next == "" {
			break
		}

		query = "?limit=1&cursor=" + url.QueryEscape(page.Next)
	}

	if want := []string{reach.inMineRevoked, reach.inMine}; !slices.Equal(seen, want) {
		t.Errorf("paging a sandbox agent's list saw %v, want %v", seen, want)
	}

	// The filter is parsed, not corrected, and at most once.
	for _, query := range []string{
		"?sandbox=", "?sandbox=nope", "?sandbox=" + strings.ToUpper(reach.mine),
		"?sandbox=" + reach.mine + "&sandbox=" + reach.mine, "?sandbox=" + reach.mine + "&sandbox=" + reach.second,
		"?sandbox=" + url.QueryEscape(reach.mine+","+reach.second), "?sandbox=" + reach.mine + "%00",
	} {
		get(t, pathAgent+query, reach.tokenB).expect(t, "list "+query, http.StatusBadRequest, sbCodeInvalidQ)
		sbAs(t, reach.keyInMine, http.MethodGet, pathAgent+query, nil).
			expect(t, "agent list "+query, http.StatusBadRequest, sbCodeInvalidQ)
	}
}

// TestSandboxAgentReadsOnlyItsSandbox: the read of one agent is the same
// confinement, and an agent outside the caller's reach is the 404 of one that
// does not exist, so the answer teaches nothing about it.
//
//nolint:paralleltest // shares one database
func TestSandboxAgentReadsOnlyItsSandbox(t *testing.T) {
	reach := sbNewReach(t)

	targets := []string{
		reach.ordinary[0], reach.inMine, reach.inMineRevoked, reach.inSecond, reach.foreign, idMissing,
	}

	callers := []struct {
		name  string
		send  func(path string) reply
		reads []string
	}{
		{"the user", func(p string) reply { return get(t, p, reach.tokenB) },
			[]string{reach.ordinary[0], reach.inMine, reach.inMineRevoked, reach.inSecond}},
		{"an agent of a sandbox", func(p string) reply { return sbAs(t, reach.keyInMine, http.MethodGet, p, nil) },
			[]string{reach.inMine, reach.inMineRevoked}},
		{"an agent of another sandbox", func(p string) reply { return sbAs(t, reach.keyInSecond, http.MethodGet, p, nil) },
			[]string{reach.inSecond}},
		{"an ordinary agent", func(p string) reply { return sbAs(t, reach.keyOrdinary, http.MethodGet, p, nil) },
			[]string{reach.ordinary[0]}},
		{"the other user's agent of a sandbox", func(p string) reply { return sbAs(t, reach.keyForeign, http.MethodGet, p, nil) },
			[]string{reach.foreign}},
	}

	for _, caller := range callers {
		for _, target := range targets {
			t.Run(caller.name+" reading "+target[len(target)-4:], func(t *testing.T) {
				got := caller.send(agItem(target))

				if !slices.Contains(caller.reads, target) {
					got.expect(t, "read", http.StatusNotFound, agCodeMissing)

					return
				}

				got.expect(t, "read", http.StatusOK, "")

				if view := agDecode[sbView](t, got); view.ID != target {
					t.Errorf("read %s, want %s", view.ID, target)
				}
			})
		}
	}

	// The read shows where an agent is.
	inSandbox := agDecode[sbView](t, get(t, agItem(reach.inSecond), reach.tokenB))
	if sbSandboxOf(inSandbox) != reach.second {
		t.Errorf("sandboxId = %q, want %q", sbSandboxOf(inSandbox), reach.second)
	}

	ordinary := get(t, agItem(reach.ordinary[0]), reach.tokenB)
	if strings.Contains(ordinary.body, "sandboxId") {
		t.Errorf("an ordinary agent reports a sandbox: %s", ordinary.body)
	}
}

// TestSandboxAgentsStayTheOwnersToChange: renaming and revoking stay with the
// owner, who reaches an agent of their sandbox with them; nobody else does, and
// no agent does, the agent of the sandbox included. Revoking the agent ends its
// key.
//
//nolint:paralleltest // shares one database
func TestSandboxAgentsStayTheOwnersToChange(t *testing.T) {
	reach := sbNewReach(t)

	renamed := patch(t, agItem(reach.inSecond), []byte(`{"name":"renamed"}`), reach.tokenB)
	renamed.expect(t, "rename", http.StatusOK, "")

	if view := agDecode[sbView](t, renamed); view.Name != "renamed" || sbSandboxOf(view) != reach.second {
		t.Errorf("renamed = %+v, want the new name and the same sandbox", view)
	}

	// Another user: the 404 of an agent that does not exist, for both.
	patch(t, agItem(reach.inSecond), []byte(`{"name":"mine now"}`), reach.tokenA).
		expect(t, "another user renames", http.StatusNotFound, agCodeMissing)
	del(t, agItem(reach.inSecond), reach.tokenA).expect(t, "another user revokes", http.StatusNotFound, agCodeMissing)

	// An agent of a sandbox, of its own sandbox or not: the boundary.
	sbAs(t, reach.keyInMine, http.MethodPatch, agItem(reach.inMine), []byte(`{"name":"me"}`)).
		expect(t, "an agent renames itself", http.StatusForbidden, sbCodeConfined)
	sbAs(t, reach.keyInMine, http.MethodDelete, agItem(reach.inMine), nil).
		expect(t, "an agent revokes itself", http.StatusForbidden, sbCodeConfined)
	sbAs(t, reach.keyInMine, http.MethodDelete, agItem(reach.inSecond), nil).
		expect(t, "an agent revokes another sandbox's", http.StatusForbidden, sbCodeConfined)

	if got := scalar(t, "SELECT name||'|'||ifnull(revoked_at, '') FROM agents WHERE id = ?", reach.inSecond); got != "renamed|" {
		t.Errorf("agent row = %q, want renamed and not revoked", got)
	}

	// The owner revokes one: its key is dead from then on.
	sbAs(t, reach.keyInMine, http.MethodGet, pathAgent, nil).expect(t, "key before", http.StatusOK, "")
	del(t, agItem(reach.inMine), reach.tokenB).expect(t, "owner revokes", http.StatusOK, "")
	sbAs(t, reach.keyInMine, http.MethodGet, pathAgent, nil).expect(t, "key after", http.StatusUnauthorized, codeUnauthenticated)
}

// ---- the boundary -------------------------------------------------------------

// TestSandboxAgentIsRefusedWhereItMayNotGo: a sandbox's agent may use only the
// list, the read and the create. Every other route refuses it before the
// handler, whatever scopes its key and the agent hold (the widest list there
// is here), with a code of its own, and nothing is written. An ordinary agent
// with the same scopes is not refused for it.
//
//nolint:paralleltest // shares one database
func TestSandboxAgentIsRefusedWhereItMayNotGo(t *testing.T) {
	world := sbNewWorld(t)
	owner := world.b.userID

	sandboxed := idN(sbAgentFam, 1)
	plain := idN(sbAgentFam, 2)

	sbSeedAgent(t, sandboxed, owner, "sandboxed", world.mine)
	sbSeedAgent(t, plain, owner, "plain", "")
	seed(t, "UPDATE agents SET scopes = ? WHERE id IN (?, ?)", sbEverything, sandboxed, plain)

	keyInSandbox := sbSeedKey(t, idN(sbKeyFam, 1), owner, sandboxed, sbEverything)
	keyPlain := sbSeedKey(t, idN(sbKeyFam, 2), owner, plain, sbEverything)

	// A key of the user's own for the key routes to name.
	sbSeedKey(t, idN(sbKeyFam, 9), owner, "", `["default:user"]`)

	routes := []struct {
		name, method, path string
		body               string
	}{
		{"who am i", http.MethodGet, pathSession, ""},
		{"log out", http.MethodPost, pathLogout, ""},
		{"list keys", http.MethodGet, "/api/key", ""},
		{"create a key", http.MethodPost, "/api/key", `{"name":"k"}`},
		{"read a key", http.MethodGet, "/api/key/" + idN(sbKeyFam, 9), ""},
		{"rename a key", http.MethodPatch, "/api/key/" + idN(sbKeyFam, 9), `{"name":"k"}`},
		{"revoke a key", http.MethodDelete, "/api/key/" + idN(sbKeyFam, 9), ""},
		{"list grants", http.MethodGet, pathGrant, ""},
		{"revoke a grant", http.MethodDelete, pathGrant + "/" + idMissing, ""},
		{"consent", http.MethodPost, "/api/oauth/consent", `{"pending":"x","approve":false}`},
		{"list organizations", http.MethodGet, "/api/org", ""},
		{"create an organization", http.MethodPost, "/api/org", `{"name":"x"}`},
		{"read an organization", http.MethodGet, "/api/org/" + world.mine, ""},
		{"delete an organization", http.MethodDelete, "/api/org/" + world.mine, ""},
		{"rename an agent", http.MethodPatch, agItem(sandboxed), `{"name":"x"}`},
		{"revoke an agent", http.MethodDelete, agItem(sandboxed), ""},
		{"list users", http.MethodGet, pathUser, ""},
		{"read a user", http.MethodGet, pathUser + "/" + owner, ""},
		{"revoke a user", http.MethodDelete, pathUser + "/" + owner, ""},
		{"create an invitation", http.MethodPost, pathInvitation, `{"type":"x"}`},
		{"list invitations", http.MethodGet, pathInvitation, ""},
	}

	before := map[string]string{tableAgents: count(t, tableAgents), tableKeys: count(t, tableKeys), tableOrgs: count(t, tableOrgs)}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			var body []byte
			if route.body != "" {
				body = []byte(route.body)
			}

			got := sbAs(t, keyInSandbox, route.method, route.path, body)
			got.expect(t, route.name+" as a sandbox's agent", http.StatusForbidden, sbCodeConfined)
		})
	}

	for table, was := range before {
		if now := count(t, table); now != was {
			t.Errorf("%s went from %s to %s: a refused request wrote", table, was, now)
		}
	}

	// The refusal is the sandbox's own and not a missing scope or role: an
	// ordinary agent holding the same lists is not refused as confined on any
	// route that only reads.
	for _, route := range routes {
		if route.method != http.MethodGet {
			continue
		}

		t.Run(route.name+" as an ordinary agent", func(t *testing.T) {
			other := sbAs(t, keyPlain, route.method, route.path, nil)
			if other.errorCode() == sbCodeConfined {
				t.Errorf("%s: an ordinary agent is refused as confined: %d %s", route.name, other.status, other.body)
			}
		})
	}

	// The three routes it may use work.
	sbAs(t, keyInSandbox, http.MethodGet, pathAgent, nil).expect(t, "list", http.StatusOK, "")
	sbAs(t, keyInSandbox, http.MethodGet, agItem(sandboxed), nil).expect(t, "read", http.StatusOK, "")
	sbAs(t, keyInSandbox, http.MethodPost, pathAgent, []byte(`{"name":"child"}`)).expect(t, "create", http.StatusCreated, "")
}

// ---- a sandbox that stops standing -------------------------------------------

// TestSandboxKeysDieWithTheirSandbox: the key of an agent in a sandbox works
// while the sandbox stands, is the 401 of any dead key once it has expired
// (checked when the key is used, not by anything that deletes on time) and works
// again if the expiry moves out, because nothing was removed. Deleting the
// sandbox deletes its agents and their keys, and the keys are the same 401.
// Other sandboxes' and ordinary agents' keys are never touched by either.
//
//nolint:paralleltest // shares one database
func TestSandboxKeysDieWithTheirSandbox(t *testing.T) {
	world := sbNewWorld(t)
	owner := world.b.userID

	agentMine, keyMine := sbSeedAgentWithKey(t, 1, owner, world.mine)
	agentSecond, keySecond := sbSeedAgentWithKey(t, 2, owner, world.second)
	_, keyOrdinary := sbSeedAgentWithKey(t, 3, owner, "")

	check := func(what string, key string, status int, code string) {
		t.Helper()

		sbAs(t, key, http.MethodGet, pathAgent, nil).expect(t, what, status, code)
	}

	check("a standing sandbox's key", keyMine, http.StatusOK, "")

	// It has expired: dead on every route it could reach, create included.
	seed(t, "UPDATE orgs SET expires_at = strftime('%s','now') - 1 WHERE id = ?", world.mine)

	check("an expired sandbox's key", keyMine, http.StatusUnauthorized, codeUnauthenticated)
	sbAs(t, keyMine, http.MethodGet, agItem(agentMine), nil).
		expect(t, "an expired sandbox's key, a read", http.StatusUnauthorized, codeUnauthenticated)
	sbAs(t, keyMine, http.MethodPost, pathAgent, []byte(`{"name":"late"}`)).
		expect(t, "an expired sandbox's key, a create", http.StatusUnauthorized, codeUnauthenticated)
	sbAs(t, keyMine, http.MethodGet, pathSession, nil).
		expect(t, "an expired sandbox's key on a route it never had", http.StatusUnauthorized, codeUnauthenticated)
	expectCount(t, "agents WHERE name = 'late'", "0")

	// The others do not notice, and the user still sees the agent: expired is
	// inert, not gone.
	check("another sandbox's key", keySecond, http.StatusOK, "")
	check("an ordinary agent's key", keyOrdinary, http.StatusOK, "")

	seen := agDecode[sbPage](t, get(t, pathAgent+"?sandbox="+world.mine, world.tokenB))
	if !slices.Equal(sbIDs(seen), []string{agentMine}) {
		t.Errorf("the user's list of the expired sandbox = %v, want its agent", sbIDs(seen))
	}

	// Creating in an expired sandbox is refused to its own administrator.
	sbCreate(t, func(b []byte) reply { return post(t, pathAgent, b, world.tokenB) }, "late", sbQuoted(world.mine)).
		expect(t, "a create in an expired sandbox", http.StatusNotFound, sbCodeNotFound)

	// The expiry exactly now is expired: the sandbox stands only while now is
	// before it.
	seed(t, "UPDATE orgs SET expires_at = strftime('%s','now') WHERE id = ?", world.mine)
	check("a sandbox that expires this second", keyMine, http.StatusUnauthorized, codeUnauthenticated)

	// Moved out, it stands again.
	seed(t, "UPDATE orgs SET expires_at = strftime('%s','now') + 3600 WHERE id = ?", world.mine)
	check("a sandbox that stands again", keyMine, http.StatusOK, "")

	// Deleted: the agents go with it, and so do their keys.
	seed(t, "DELETE FROM orgs WHERE id = ?", world.mine)

	check("a deleted sandbox's key", keyMine, http.StatusUnauthorized, codeUnauthenticated)
	expectCount(t, "agents WHERE id = ?", "0", agentMine)
	expectCount(t, "api_keys WHERE agent_id = ?", "0", agentMine)
	get(t, agItem(agentMine), world.tokenB).expect(t, "the deleted sandbox's agent", http.StatusNotFound, agCodeMissing)
	expectNoOrphanSecrets(t)

	check("another sandbox's key after the delete", keySecond, http.StatusOK, "")
	check("an ordinary agent's key after the delete", keyOrdinary, http.StatusOK, "")
	expectCount(t, "agents WHERE id = ?", "1", agentSecond)
}

// ---- consent ------------------------------------------------------------------

// TestSandboxAgentCannotHoldAnOAuthGrant: consent can attach an ordinary agent
// to a grant and cannot attach an agent of a sandbox, which the write answers
// as it does an agent that is not the user's. Nothing is written for the
// refusal, and the agent a consent creates is never in a sandbox.
//
//nolint:paralleltest // shares one database
func TestSandboxAgentCannotHoldAnOAuthGrant(t *testing.T) {
	holder := newOAuthHolder(t)
	inSandbox, ordinary := idN(sbAgentFam, 1), idN(sbAgentFam, 2)

	sbSeedSandbox(t, idN(sbSandboxFam, 1), holder.userID, sbWeek)
	sbSeedAgent(t, inSandbox, holder.userID, "in a sandbox", idN(sbSandboxFam, 1))
	sbSeedAgent(t, ordinary, holder.userID, "ordinary", "")

	_, refusedPending := oaPending(t)
	consent(t, holder.session, refusedPending, true, agentChoiceID(inSandbox)).
		expect(t, "a sandbox agent", http.StatusNotFound, codeAgentNotFound)
	oaNothingWritten(t, "a sandbox agent", 2)

	// The same consent, still open, goes through with an ordinary agent.
	consent(t, holder.session, refusedPending, true, agentChoiceID(ordinary)).
		expect(t, "an ordinary agent", http.StatusOK, "")
	expectCount(t, tableOAuthGrants, "1")
	expectCount(t, "oauth_grants WHERE agent_id = ?", "0", inSandbox)

	// A consent that creates the agent makes an ordinary one.
	_, createPending := oaPending(t)
	consent(t, holder.session, createPending, true, newAgentChoice("made by consent")).
		expect(t, "a new agent", http.StatusOK, "")
	expectCount(t, "agents WHERE name = 'made by consent' AND sandbox_id IS NULL", "1")
	expectCount(t, "agents WHERE sandbox_id IS NOT NULL", "1")
	expectNoOrphanSecrets(t)
}

// TestSandboxAgentsAreRefusedAnOAuthGrantAfterTheFact: consent never attaches an
// agent of a sandbox to a grant (TestSandboxAgentCannotHoldAnOAuthGrant), and
// the token routes hold the same line themselves, as defence in depth. A grant
// on an agent that is in a sandbox, however it came to be (here the agent is
// moved into one behind the Worker's back after the consent and again after the
// tokens were issued), can be neither exchanged, nor refreshed, nor
// introspected as active. Moving the agent out again is all it takes to work,
// which shows the sandbox is the whole reason for each refusal.
//
//nolint:paralleltest // shares one database
func TestSandboxAgentsAreRefusedAnOAuthGrantAfterTheFact(t *testing.T) {
	holder := newOAuthHolder(t)
	sandbox := idN(sbSandboxFam, 1)

	sbSeedSandbox(t, sandbox, holder.userID, sbWeek)

	enter := func(agent string) {
		seed(t, "UPDATE agents SET sandbox_id = ? WHERE id = ?", sandbox, agent)
	}
	leave := func(agent string) {
		seed(t, "UPDATE agents SET sandbox_id = NULL WHERE id = ?", agent)
	}

	t.Run("exchange", func(t *testing.T) {
		a := approve(t, newOAuthClient(t), holder.session, newAgentChoice("exchanged in a sandbox"))
		agent := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", idOfToken(t, a.code))

		enter(agent)
		a.exchange(t).expectOAuth(t, "the exchange of a sandbox agent's code", http.StatusBadRequest, "invalid_grant")
		expectCount(t, "secrets WHERE kind = ?", "0", kindOAuthAccess)

		// The refusal spent nothing: the same code works once the agent is out.
		leave(agent)
		a.exchange(t).expect(t, "the same code, the agent out of the sandbox", http.StatusOK, "")
	})

	t.Run("refresh and introspection", func(t *testing.T) {
		issued := oaIssue(t, holder.session, newAgentChoice("refreshed in a sandbox"))
		agent := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", issued.grant)

		if got, _ := introspect(t, issued.tokens.AccessToken, oauthResource); !got.Active {
			t.Fatal("the access token of an ordinary agent is not active")
		}

		enter(agent)
		expectInactive(t, "the access token of a sandbox agent", issued.tokens.AccessToken, oauthResource)
		issued.a.refresh(t, issued.tokens.RefreshToken).
			expectOAuth(t, "the refresh of a sandbox agent's grant", http.StatusBadRequest, "invalid_grant")

		leave(agent)

		if got, _ := introspect(t, issued.tokens.AccessToken, oauthResource); !got.Active {
			t.Error("the access token is not active again once the agent is out of the sandbox")
		}

		issued.a.refresh(t, issued.tokens.RefreshToken).
			expect(t, "the refresh, the agent out of the sandbox", http.StatusOK, "")
	})

	expectNoOrphanSecrets(t)
}
