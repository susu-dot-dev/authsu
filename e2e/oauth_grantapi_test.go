//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_grantapi_test.go: an OAuth grant of the first-party login used as a
// credential at authsu's own API (docs/oauth_design.md), through the real Worker
// and database. A first-party sign-in that asks for the sandbox scopes
// is exchanged for a token, and that one token manages the user's sandboxes: it
// creates one, creates an agent in it (only in it, with the key sealed), lists
// and reads, and deletes the sandbox with everything in it. The same token is
// refused everywhere else, with its own code, and an agent's API key is still
// refused where it always was.

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// grantScopesAsked is every authsu scope the login resource defines, asked for at
// sign-in.
const grantScopesAsked = "openid profile sandbox:create sandbox:revoke org:read agent:create agent:read"

// codeGrantRefused is what the boundary says to a grant on a route that has not
// opted in to it.
const codeGrantRefused = "grant_not_accepted"

// grantToken signs the holder in to the first-party client asking for scope, and
// exchanges the code, returning the access token a first-party app would hold.
func grantToken(t *testing.T, client *oauthClient, session, scope string) string {
	t.Helper()

	pair := newPKCE()
	query := loginQuery(client, pair)
	query.Set("scope", scope)

	pending := loginPage(t, authorize(t, query))
	redirect := consentRedirect(t, consent(t, session, pending, true, nil))
	code := redirect.Query().Get("code")
	expectToken(t, code, tagOAuthCode)

	issued := mustTokens(t, (approved{client: client, pkce: pair, query: query, code: code}).exchange(t))
	expectToken(t, issued.AccessToken, tagOAuthAccess)

	return issued.AccessToken
}

// asGrant sends method path with body, authorized by the access token as a bearer.
func asGrant(t *testing.T, token, method, path string, body []byte) reply {
	t.Helper()

	return send(t, request{method: method, path: path, body: body, bearer: token})
}

// TestGrantManagesSandboxes is the Pages story end to end: sign in, create a
// sandbox, create an agent in it, list, read, delete the sandbox. Every step is
// the one token.
//
//nolint:paralleltest // shares one database
func TestGrantManagesSandboxes(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)
	token := grantToken(t, client, holder.session, grantScopesAsked)

	// Create a sandbox: a grant is let through the refusal of agents here, and the
	// sandbox is the user's.
	made := asGrant(t, token, http.MethodPost, pathOrg, orgCreateBody(t, "Scratch"))
	made.expect(t, "create sandbox", http.StatusCreated, "")

	sandbox := orgDecode[orgView](t, made)
	if sandbox.Kind != "sandbox" || sandbox.CreatedBy != holder.userID || sandbox.Status != "active" {
		t.Errorf("sandbox = %+v, want an active sandbox created by the user", sandbox)
	}

	if got := count(t, "org_admins WHERE org_id = ? AND user_id = ?", sandbox.ID, holder.userID); got != "1" {
		t.Errorf("the user administers the new sandbox %s times, want once", got)
	}

	// Read it, and list: the list is the user's own organizations.
	asGrant(t, token, http.MethodGet, orgItem(sandbox.ID), nil).expect(t, "get sandbox", http.StatusOK, "")

	listed := asGrant(t, token, http.MethodGet, pathOrg, nil)
	listed.expect(t, "list orgs", http.StatusOK, "")

	if !strings.Contains(listed.body, sandbox.ID) || !strings.Contains(listed.body, orgMembership(t, holder.userID)) {
		t.Errorf("list = %s, want the sandbox and the user's own organization", listed.body)
	}

	// Create an agent in it. The key comes back sealed (a grant is not a session);
	// send opens it as a client does, so the plain token is read from the reply.
	body := mustJSON(t, map[string]any{
		"name": "box", "sandboxId": sandbox.ID, "scopes": []string{"agent:read"}, "keyScopes": []string{"agent:read"},
	})

	madeAgent := asGrant(t, token, http.MethodPost, pathAgent, body)
	madeAgent.expect(t, "create agent in the sandbox", http.StatusCreated, "")

	agent := orgDecode[sbCreated](t, madeAgent)
	if sbSandboxOf(agent.Agent) != sandbox.ID || strings.Join(agent.Agent.Scopes, ",") != "agent:read" ||
		strings.Join(agent.Key.Scopes, ",") != "agent:read" {
		t.Errorf("agent = %+v, want it in the sandbox holding agent:read", agent)
	}

	expectToken(t, agent.Key.Token, tagAPIKey)

	// The key was returned sealed: asked for as the wire, the response has no token.
	raw := sendRaw(t, request{method: http.MethodPost, path: pathAgent, bearer: token,
		body: mustJSON(t, map[string]any{"name": "unsealed", "sandboxId": sandbox.ID})})
	raw.expect(t, "create agent without a public key", http.StatusBadRequest, "public_key_required")

	// The agent is the user's own and is created in the sandbox, not as a copy of
	// the first-party agent.
	if got := scalar(t, "SELECT sandbox_id || '|' || user_id || '|' || first_party FROM agents WHERE id = ?", agent.Agent.ID); got != sandbox.ID+"|"+holder.userID+"|0" {
		t.Errorf("the agent row = %q, want the sandbox, the user, not first-party", got)
	}

	// List and read agents: the user's own, the sandbox's included.
	page := orgDecode[sbPage](t, asGrant(t, token, http.MethodGet, pathAgent, nil))
	if !slices.Contains(sbIDs(page), agent.Agent.ID) {
		t.Errorf("agents = %v, want the sandbox agent among them", sbIDs(page))
	}

	asGrant(t, token, http.MethodGet, pathAgent+"/"+agent.Agent.ID, nil).expect(t, "get sandbox agent", http.StatusOK, "")

	// Delete the sandbox: it and the agent in it go, with the agent's key.
	asGrant(t, token, http.MethodDelete, orgItem(sandbox.ID), nil).expect(t, "delete sandbox", http.StatusOK, "")

	if got := count(t, "orgs WHERE id = ?", sandbox.ID); got != "0" {
		t.Errorf("the sandbox remains (%s rows)", got)
	}

	if got := count(t, "agents WHERE id = ?", agent.Agent.ID); got != "0" {
		t.Errorf("the sandbox's agent remains (%s rows)", got)
	}

	expectNoOrphanSecrets(t)
}

// TestGrantRefusedWhereItIsNotAccepted: the same token that manages sandboxes is
// refused, with the grant's own code and nothing done, on every other route: the
// session-only POST /api/key, and PATCH and DELETE of an agent among them.
//
//nolint:paralleltest // shares one database
func TestGrantRefusedWhereItIsNotAccepted(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)
	token := grantToken(t, client, holder.session, grantScopesAsked)

	seedAgent(t, idN("d500", 1), holder.userID, "mine")

	member := idN("d501", 1)
	seedUserIn(t, member, roleMember, orgMembership(t, holder.userID))

	made := asGrant(t, token, http.MethodPost, pathOrg, orgCreateBody(t, "Scratch"))
	sandbox := orgDecode[orgView](t, made).ID

	tests := []struct {
		name         string
		method, path string
		body         []byte
	}{
		{"issue a key", http.MethodPost, pathKey, mustJSON(t, map[string]any{"name": "k"})},
		{"list keys", http.MethodGet, pathKey, nil},
		{"rename an agent", http.MethodPatch, pathAgent + "/" + idN("d500", 1), mustJSON(t, map[string]any{"name": "x"})},
		{"revoke an agent", http.MethodDelete, pathAgent + "/" + idN("d500", 1), nil},
		{"rename an organization", http.MethodPatch, orgItem(sandbox), mustJSON(t, map[string]any{"name": "x"})},
		{"list members", http.MethodGet, orgItem(orgMembership(t, holder.userID)) + "/member", nil},
		{"promote a member", http.MethodPatch, pathMember + "/" + member, mustJSON(t, map[string]any{"admin": true})},
		{"revoke a member", http.MethodDelete, pathMember + "/" + member, nil},
		{"the grants", http.MethodGet, "/api/grant", nil},
		{"the users", http.MethodGet, pathUser, nil},
		{"the invitations", http.MethodGet, pathInvitation, nil},
		{"the session", http.MethodGet, pathSession, nil},
		{"logout", http.MethodPost, pathLogout, nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := asGrant(t, token, test.method, test.path, test.body)
			if got.status != http.StatusForbidden || got.errorCode() != codeGrantRefused {
				t.Errorf("%s %s = %d %s, want 403 %s", test.method, test.path, got.status, got.body, codeGrantRefused)
			}
		})
	}

	// Nothing was done: the agent, the member and the sandbox are as they were.
	if got := scalar(t, "SELECT name || '|' || ifnull(revoked_at, 'NULL') FROM agents WHERE id = ?", idN("d500", 1)); got != "mine|NULL" {
		t.Errorf("the agent = %q, want it unchanged", got)
	}

	if got := count(t, "api_keys WHERE user_id = ? AND agent_id IS NULL", holder.userID); got != "0" {
		t.Errorf("the user has %s keys of their own, want none issued", got)
	}
}

// TestGrantCreateAgentBounds: through the real write, a grant creates agents only
// in a sandbox the user administers, with lists inside the grant's own.
//
//nolint:paralleltest // shares one database
func TestGrantCreateAgentBounds(t *testing.T) {
	holder := newOAuthHolder(t)
	other, _ := secondUser(t)
	client := firstPartyClient(t)
	token := grantToken(t, client, holder.session, "openid profile sandbox:create agent:create agent:read")

	sandbox := orgDecode[orgView](t, asGrant(t, token, http.MethodPost, pathOrg, orgCreateBody(t, "Mine"))).ID

	const foreign = "d5f0"

	sbSeedSandbox(t, idN(foreign, 1), other, 3600)

	create := func(members map[string]any) reply {
		return asGrant(t, token, http.MethodPost, pathAgent, mustJSON(t, members))
	}

	create(map[string]any{"name": "ordinary"}).
		expect(t, "an ordinary agent", http.StatusForbidden, "grant_requires_sandbox")
	create(map[string]any{"name": "other", "sandboxId": idN(foreign, 1)}).
		expect(t, "another user's sandbox", http.StatusNotFound, "sandbox_not_found")
	create(map[string]any{"name": "wide", "sandboxId": sandbox, "scopes": []string{"org:read"}}).
		expect(t, "an agent list beyond the grant's", http.StatusForbidden, "grant_scopes_exceeded")
	create(map[string]any{"name": "wide key", "sandboxId": sandbox, "keyScopes": []string{"default:session"}}).
		expect(t, "a key list beyond the grant's", http.StatusForbidden, "grant_scopes_exceeded")
	create(map[string]any{"name": "ok", "sandboxId": sandbox}).
		expect(t, "the default lists, the grant's own", http.StatusCreated, "")

	if got := count(t, "agents WHERE sandbox_id IS NULL AND first_party = 0 AND user_id = ?", holder.userID); got != "0" {
		t.Errorf("an ordinary agent was created through the grant (%s)", got)
	}

	// The agent's list is the primary ceiling and is read live: cut behind the
	// Worker's back to two names (the token still holds every one it asked for),
	// a create asks for lists inside it only.
	seed(t, "UPDATE agents SET scopes = ? WHERE user_id = ? AND first_party = 1", `["agent:create","agent:read"]`, holder.userID)

	create(map[string]any{"name": "beyond the agent", "sandboxId": sandbox, "scopes": []string{"sandbox:create"}}).
		expect(t, "an agent list the token holds and the agent does not", http.StatusForbidden, "grant_scopes_exceeded")
	create(map[string]any{"name": "key beyond the agent", "sandboxId": sandbox, "keyScopes": []string{"sandbox:create"}}).
		expect(t, "a key list the token holds and the agent does not", http.StatusForbidden, "grant_scopes_exceeded")

	narrow := orgDecode[sbCreated](t, create(map[string]any{"name": "default", "sandboxId": sandbox}))
	if strings.Join(narrow.Agent.Scopes, ",") != "agent:create,agent:read" || strings.Join(narrow.Key.Scopes, ",") != "agent:create,agent:read" {
		t.Errorf("the default lists = %v and %v, want the intersection of the token and the agent", narrow.Agent.Scopes, narrow.Key.Scopes)
	}

	// An agent with nothing allows only nothing: not even the route's own scope,
	// which the boundary refuses first.
	seed(t, "UPDATE agents SET scopes = '[]' WHERE user_id = ? AND first_party = 1", holder.userID)
	create(map[string]any{"name": "empty agent", "sandboxId": sandbox}).
		expect(t, "an agent whose list is empty", http.StatusForbidden, "insufficient_scope")
}

// TestGrantNeedsTheScopes: the token holds only what the sign-in asked for, and
// each route needs its own: a sign-in without a scope is told it lacks it.
//
//nolint:paralleltest // shares one database
func TestGrantNeedsTheScopes(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)
	narrow := grantToken(t, client, holder.session, "openid profile org:read")

	asGrant(t, narrow, http.MethodGet, pathOrg, nil).expect(t, "list with org:read", http.StatusOK, "")
	asGrant(t, narrow, http.MethodPost, pathOrg, orgCreateBody(t, "Scratch")).
		expect(t, "create without sandbox:create", http.StatusForbidden, "insufficient_scope")
	asGrant(t, narrow, http.MethodGet, pathAgent, nil).
		expect(t, "list agents without agent:read", http.StatusForbidden, "insufficient_scope")
}

// TestAgentKeyStillRefusedWhereAGrantIsLetIn: an agent's API key, with every scope
// the grant has, is refused at creating and deleting a sandbox as it was, because
// the grant's way past the refusal of agents is the grant's alone.
//
//nolint:paralleltest // shares one database
func TestAgentKeyStillRefusedWhereAGrantIsLetIn(t *testing.T) {
	holder := newOAuthHolder(t)

	const family = "d5a0"

	seedAgent(t, idN(family, 1), holder.userID, "keyed")
	seed(t, "UPDATE agents SET scopes = ? WHERE id = ?", `["default:session"]`, idN(family, 1))

	key := sbSeedKey(t, idN(family, 2), holder.userID, idN(family, 1), `["default:session"]`)

	sbSeedSandbox(t, idN(family, 3), holder.userID, 3600)

	send(t, request{method: http.MethodPost, path: pathOrg, body: orgCreateBody(t, "Scratch"), bearer: key}).
		expect(t, "an agent key creating a sandbox", http.StatusForbidden, "forbidden")
	send(t, request{method: http.MethodDelete, path: orgItem(idN(family, 3)), bearer: key}).
		expect(t, "an agent key deleting a sandbox", http.StatusForbidden, "forbidden")

	if got := count(t, "orgs WHERE id = ?", idN(family, 3)); got != "1" {
		t.Errorf("the sandbox = %s rows, want it still there", got)
	}
}

// TestGrantOfAPlatformAdministratorManagesOnlyTheirOwnSandboxes: the platform
// administrator's override is a power of a person's session, and a grant of the
// same user does not have it. Through the real write, the admin user's grant
// lists, reads and deletes the sandboxes the user administers, and for another
// user's sandbox every one of them is a 404 and changes nothing, while the same
// user's session, which has the override, still reaches it.
//
//nolint:paralleltest // shares one database
func TestGrantOfAPlatformAdministratorManagesOnlyTheirOwnSandboxes(t *testing.T) {
	holder := newOAuthHolder(t)
	other, _ := secondUser(t)
	client := firstPartyClient(t)
	token := grantToken(t, client, holder.session, grantScopesAsked)

	if got := scalar(t, "SELECT role FROM users WHERE id = ?", holder.userID); got != roleAdmin {
		t.Fatalf("the holder's role = %q, want a platform administrator", got)
	}

	const family = "d5c0"

	mine, theirs := idN(family, 1), idN(family, 2)

	sbSeedSandbox(t, mine, holder.userID, 3600)
	sbSeedSandbox(t, theirs, other, 3600)

	agentOfTheirs := idN(family, 3)
	sbSeedAgent(t, agentOfTheirs, other, "theirs", theirs)

	digest := func() string {
		return scalar(t, "SELECT (SELECT group_concat(id, ',') FROM (SELECT id FROM orgs ORDER BY id)) || '|' || "+
			"(SELECT group_concat(id, ',') FROM (SELECT id FROM agents ORDER BY id))")
	}
	before := digest()

	// The list holds the user's own sandbox and organization, and never the other
	// user's sandbox or organization, which a platform administrator's session lists.
	listed := asGrant(t, token, http.MethodGet, pathOrg, nil)
	listed.expect(t, "list orgs", http.StatusOK, "")

	if !strings.Contains(listed.body, mine) || !strings.Contains(listed.body, orgMembership(t, holder.userID)) {
		t.Errorf("list = %s, want the user's own sandbox and organization", listed.body)
	}

	for _, foreign := range []string{theirs, orgMembership(t, other)} {
		if strings.Contains(listed.body, foreign) {
			t.Errorf("list = %s, holds %s, which the user does not administer", listed.body, foreign)
		}
	}

	// Another user's sandbox and organization: not found, read and delete alike.
	for _, foreign := range []string{theirs, orgMembership(t, other)} {
		asGrant(t, token, http.MethodGet, orgItem(foreign), nil).
			expect(t, "get a foreign org through the grant", http.StatusNotFound, "org_not_found")
		asGrant(t, token, http.MethodDelete, orgItem(foreign), nil).
			expect(t, "delete a foreign org through the grant", http.StatusNotFound, "org_not_found")
	}

	if after := digest(); after != before {
		t.Errorf("the grant changed what was not its user's:\n before %s\n after  %s", before, after)
	}

	// The same user's session is a platform administrator's and does reach it.
	get(t, orgItem(theirs), holder.session).expect(t, "get it by session", http.StatusOK, "")

	// And the user's own sandbox still works through the grant, with what it holds.
	asGrant(t, token, http.MethodGet, orgItem(mine), nil).expect(t, "get own sandbox", http.StatusOK, "")
	asGrant(t, token, http.MethodDelete, orgItem(mine), nil).expect(t, "delete own sandbox", http.StatusOK, "")

	if got := count(t, "orgs WHERE id = ?", mine); got != "0" {
		t.Errorf("the user's own sandbox remains (%s rows)", got)
	}

	if got := count(t, "orgs WHERE id = ?", theirs); got != "1" {
		t.Errorf("the other user's sandbox = %s rows, want it untouched", got)
	}

	expectNoOrphanSecrets(t)
}

// TestGrantReachesOnlyAgentsOfSandboxesTheUserAdministers: a grant manages the
// user's sandboxes, so through the real statements it lists and reads the agents
// of the sandboxes the user administers and nothing else of the user's: not an
// ordinary agent (with its name, labels and scopes), not the first-party agent,
// and not an agent of a sandbox the user no longer administers.
//
//nolint:paralleltest // shares one database
func TestGrantReachesOnlyAgentsOfSandboxesTheUserAdministers(t *testing.T) {
	holder := newOAuthHolder(t)
	other, _ := secondUser(t)
	client := firstPartyClient(t)
	token := grantToken(t, client, holder.session, grantScopesAsked)

	const family = "d5d0"

	mine, demoted := idN(family, 1), idN(family, 2)
	ordinary, inMine, inDemoted := idN(family, 3), idN(family, 4), idN(family, 5)

	sbSeedSandbox(t, mine, holder.userID, 3600)
	sbSeedSandbox(t, demoted, holder.userID, 3600)
	sbSeedAgent(t, ordinary, holder.userID, "ordinary", "")
	sbSeedAgent(t, inMine, holder.userID, "in mine", mine)
	sbSeedAgent(t, inDemoted, holder.userID, "in demoted", demoted)

	// The administration of one sandbox passes to another user: the agent stays the
	// user's, in a sandbox they do not administer.
	seed(t, "UPDATE org_admins SET user_id = ? WHERE org_id = ?", other, demoted)

	firstParty := scalar(t, "SELECT id FROM agents WHERE first_party = 1 AND user_id = ?", holder.userID)

	listed := orgDecode[sbPage](t, asGrant(t, token, http.MethodGet, pathAgent+"?limit=100", nil))
	if got := sbIDs(listed); !slices.Equal(got, []string{inMine}) {
		t.Errorf("the grant lists %v, want only %s", got, inMine)
	}

	asGrant(t, token, http.MethodGet, pathAgent+"/"+inMine, nil).expect(t, "an agent of a sandbox the user administers", http.StatusOK, "")

	for name, id := range map[string]string{"an ordinary agent": ordinary, "the first-party agent": firstParty, "an agent of a sandbox no longer administered": inDemoted} {
		asGrant(t, token, http.MethodGet, pathAgent+"/"+id, nil).expect(t, name, http.StatusNotFound, "agent_not_found")
	}

	// The user's own session still sees them all.
	if got := sbIDs(orgDecode[sbPage](t, get(t, pathAgent+"?limit=100", holder.session))); !slices.Contains(got, ordinary) || !slices.Contains(got, inDemoted) {
		t.Errorf("the session lists %v, want every agent of the user", got)
	}
}

// grantLiveness is one way an access token is, or stops being, good at authsu's
// own API: a change made behind the Worker's back after the token was issued (an
// UPDATE, whose arguments are named by what they stand for), and the answer to GET
// /api/org and GET /api/agent it must then get. The token is the first-party
// login's, held by an administrator user, unless the case brings its own.
type grantLiveness struct {
	name string
	// update is the statement run after the token was issued, with "?" where an id
	// of the world goes: each of args is "grant", "access" (the access token's
	// secret), "agent", "user" or "sandbox". Empty is no change.
	update string
	args   []string
	// mcp makes the token one of the MCP resource's, live at its own resource.
	mcp bool
	// status and code are the answer at both routes.
	status int
	code   string
}

// grantLivenessCases are the states the resolver reads live, each tested through
// the real statement: the token is refused, with the same 401, whichever way it
// is dead, and a grant whose user is no longer an administrator is no more than a
// member's.
func grantLivenessCases() []grantLiveness {
	const (
		expireAccess = "UPDATE secrets SET expires_at = strftime('%s','now') + ? WHERE id = ?"
		expireGrant  = "UPDATE secrets SET expires_at = strftime('%s','now') + ? WHERE id = ?"
		revoke       = "UPDATE secrets SET revoked_at = 5 WHERE id = ?"
	)

	dead := func(name, update string, args ...string) grantLiveness {
		return grantLiveness{name: name, update: update, args: args, status: http.StatusUnauthorized, code: "unauthenticated"}
	}

	return []grantLiveness{
		{name: "a live token", status: http.StatusOK},
		dead("the access token's secret is revoked", revoke, "access"),
		dead("the grant's secret is revoked", revoke, "grant"),
		// The expiry compares strictly, on the access token's secret and the grant's:
		// a token that expires this very second is over, and one 30 seconds on is live.
		dead("the access token has expired", expireAccess, "-1", "access"),
		dead("the access token expires this second", expireAccess, "0", "access"),
		{name: "the access token expires in 30 seconds", update: expireAccess, args: []string{"30", "access"}, status: http.StatusOK},
		dead("the grant has expired", expireGrant, "-1", "grant"),
		dead("the grant expires this second", expireGrant, "0", "grant"),
		{name: "the grant expires in 30 seconds", update: expireGrant, args: []string{"30", "grant"}, status: http.StatusOK},
		dead("the user is revoked", "UPDATE users SET revoked_at = 5 WHERE id = ?", "user"),
		dead("the agent is revoked", "UPDATE agents SET revoked_at = 5 WHERE id = ?", "agent"),
		dead("the agent is in a sandbox", "UPDATE agents SET sandbox_id = ? WHERE id = ?", "sandbox", "agent"),
		dead("the grant is for another resource", "UPDATE oauth_grants SET resource = '"+oauthResource+"' WHERE id = ?", "grant"),
		// The role is read now: a demoted administrator is a member from the next request on.
		{name: "the user was demoted from administrator", update: "UPDATE users SET role = '" + roleMember + "' WHERE id = ?",
			args: []string{"user"}, status: http.StatusOK},
		{name: "the token of an MCP resource, live at its own resource", mcp: true,
			status: http.StatusUnauthorized, code: "unauthenticated"},
	}
}

// TestGrantLivenessAtTheAPI: every way an access token can stop being good is read
// from the database on the request, through the real statement, and answered as
// any bad credential is, at a route that takes a grant and at one that lists.
//
//nolint:paralleltest // shares one database
func TestGrantLivenessAtTheAPI(t *testing.T) {
	client := firstPartyClient(t)

	for _, test := range grantLivenessCases() {
		t.Run(test.name, func(t *testing.T) {
			holder := newOAuthHolder(t)
			token := grantToken(t, client, holder.session, grantScopesAsked)

			grant := scalar(t, "SELECT id FROM oauth_grants WHERE user_id = ? ORDER BY id DESC LIMIT 1", holder.userID)
			world := map[string]string{
				"grant": grant, "user": holder.userID, "agent": scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", grant),
				"access": scalar(t, "SELECT id FROM oauth_access_tokens WHERE grant_id = ?", grant),
			}

			if test.mcp {
				token = approve(t, newOAuthClient(t), holder.session, newAgentChoice("mcp")).mustExchange(t).AccessToken
			}

			if test.update != "" {
				args := make([]any, 0, len(test.args))

				for _, arg := range test.args {
					if id, named := world[arg]; named {
						args = append(args, id)
					} else if arg == "sandbox" {
						sbSeedSandbox(t, idN("d5e0", 1), holder.userID, 3600)

						args = append(args, idN("d5e0", 1))
					} else {
						args = append(args, arg)
					}
				}

				seed(t, test.update, args...)
			}

			for _, path := range []string{pathOrg, pathAgent} {
				asGrant(t, token, http.MethodGet, path, nil).expect(t, test.name+" at "+path, test.status, test.code)
			}
		})
	}
}

// TestGrantRoleIsReadLive: a user demoted from administrator is a member to the
// next request of a grant they already hold, and a member promoted is no
// administrator through one either: nothing about the role is in the token, and
// the grant never carries the administrator's override in any case.
//
//nolint:paralleltest // shares one database
func TestGrantRoleIsReadLive(t *testing.T) {
	holder := newOAuthHolder(t)
	other, _ := secondUser(t)
	client := firstPartyClient(t)
	token := grantToken(t, client, holder.session, grantScopesAsked)

	sbSeedSandbox(t, idN("d5e1", 1), other, 3600)

	for _, role := range []string{roleAdmin, roleMember, roleAdmin} {
		setRole(t, holder.userID, role)

		asGrant(t, token, http.MethodGet, orgItem(idN("d5e1", 1)), nil).
			expect(t, "another user's sandbox as "+role, http.StatusNotFound, "org_not_found")
	}
}

// TestGrantAtTheAgentLimitRacesASignIn: a user with exactly one place left has a
// grant create an agent in a sandbox, and the same user's session create an
// ordinary agent, together, for the last place. Exactly one gets it, the other is
// told the limit as a conflict and not an error, the user is never over the
// limit, and no secret is left without its row.
//
//nolint:paralleltest // shares one database
func TestGrantAtTheAgentLimitRacesASignIn(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)

	for round := range oaRaceRounds {
		// Each round signs in afresh: the reset below removes the login's agent and
		// with it the grant.
		token := grantToken(t, client, holder.session, grantScopesAsked)
		sandbox := orgDecode[orgView](t, asGrant(t, token, http.MethodPost, pathOrg, orgCreateBody(t, "Full "+strconv.Itoa(round)))).ID

		// Every place but one is taken: the login's own agent is one of the active
		// ones, so the others are seeded.
		active := atoiOf(t, count(t, "agents WHERE revoked_at IS NULL AND user_id = ?", holder.userID))
		for i := range maxAgents - 1 - active {
			seedAgent(t, idN("d5f1", round*100+i+1), holder.userID, "bulk")
		}

		replies := oaRace(2, func(i int) reply {
			if i == 0 {
				return asGrant(t, token, http.MethodPost, pathAgent, mustJSON(t, map[string]any{
					"name": "grant racer", "sandboxId": sandbox, "scopes": []string{"agent:read"}, "keyScopes": []string{"agent:read"},
				}))
			}

			return post(t, pathAgent, mustJSON(t, map[string]any{"name": "session racer"}), holder.session)
		})

		oaNo5xx(t, "the two creates", replies)

		if got := count(t, "agents WHERE revoked_at IS NULL AND user_id = ?", holder.userID); got != strconv.Itoa(maxAgents) {
			t.Fatalf("round %d: %s active agents, want exactly the limit %d (one create wins, one is refused)", round, got, maxAgents)
		}

		tally := oaTally(replies)
		if tally["201"] != 1 || tally["409 "+codeAgentLimit] != 1 {
			t.Errorf("round %d: replies = %v, want one 201 and one 409 %s", round, tally, codeAgentLimit)
		}

		expectNoOrphanSecrets(t)

		// Reset for the next round: the user's agents go, with their keys and grants
		// (the cascades and the delete triggers remove the secrets behind them).
		seed(t, "DELETE FROM agents WHERE user_id = ?", holder.userID)
	}
}

// TestFirstPartySignInRacesTheLastPlace: a first-party sign-in that needs a new
// agent (the login's was revoked) races an ordinary create of the user's own for
// the last place at the limit. Exactly one wins; the loser is the limit's conflict
// and never an error; no consent is left half-written.
//
//nolint:paralleltest // shares one database
func TestFirstPartySignInRacesTheLastPlace(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)

	for round := range oaRaceRounds {
		signInAsking(t, client, holder.session, "profile agent:read")

		login := scalar(t, "SELECT id FROM agents WHERE first_party = 1 AND revoked_at IS NULL AND user_id = ?", holder.userID)
		del(t, pathAgent+"/"+login, holder.session).expect(t, "revoke the login's agent", http.StatusOK, "")

		active := atoiOf(t, count(t, "agents WHERE revoked_at IS NULL AND user_id = ?", holder.userID))
		for i := range maxAgents - 1 - active {
			seedAgent(t, idN("d5f2", round*100+i+1), holder.userID, "bulk")
		}

		// The sign-in's authorize page is fetched first, so the race is the consent.
		pending := loginPage(t, authorize(t, loginQuery(client, newPKCE())))

		replies := oaRace(2, func(i int) reply {
			if i == 0 {
				return consent(t, holder.session, pending, true, nil)
			}

			return post(t, pathAgent, mustJSON(t, map[string]any{"name": "session racer"}), holder.session)
		})

		oaNo5xx(t, "the sign-in and the create", replies)

		if got := count(t, "agents WHERE revoked_at IS NULL AND user_id = ?", holder.userID); got != strconv.Itoa(maxAgents) {
			t.Fatalf("round %d: %s active agents, want exactly the limit %d", round, got, maxAgents)
		}

		tally := oaTally(replies)
		if tally["200"]+tally["201"] != 1 || tally["409 "+codeAgentLimit] != 1 {
			t.Errorf("round %d: replies = %v, want one winner and one 409 %s", round, tally, codeAgentLimit)
		}

		expectNoOrphanSecrets(t)

		seed(t, "DELETE FROM agents WHERE user_id = ?", holder.userID)
	}
}

// atoiOf is a count read from the database, as a number.
func atoiOf(t *testing.T, text string) int {
	t.Helper()

	n, err := strconv.Atoi(text)
	if err != nil {
		t.Fatalf("%q is not a number: %v", text, err)
	}

	return n
}

// TestGrantSupersededWhileRefreshing: the first-party client signs in again (the
// newer consent is exchanged, which ends the older grant) while the older grant's
// refresh token is being used, together. Whichever wins, the older grant ends up
// ended (its refresh token and access token both dead afterwards), the newer one
// is untouched and works at the API, and nothing is a 5xx or an orphan.
//
//nolint:paralleltest // shares one database
func TestGrantSupersededWhileRefreshing(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)

	for round := range oaRaceRounds {
		pair := newPKCE()
		query := loginQuery(client, pair)
		query.Set("scope", "profile agent:read")

		older := approved{client: client, pkce: pair, query: query,
			code: consentRedirect(t, consent(t, holder.session, loginPage(t, authorize(t, query)), true, nil)).Query().Get("code")}
		olderTokens := older.mustExchange(t)

		pair2 := newPKCE()
		query2 := loginQuery(client, pair2)
		query2.Set("scope", "profile agent:read")

		newer := approved{client: client, pkce: pair2, query: query2,
			code: consentRedirect(t, consent(t, holder.session, loginPage(t, authorize(t, query2)), true, nil)).Query().Get("code")}

		olderID := idOfToken(t, olderTokens.RefreshToken)
		newerID := idOfToken(t, newer.code)

		replies := oaRace(2, func(i int) reply {
			if i == 0 {
				return older.refresh(t, olderTokens.RefreshToken)
			}

			return newer.exchange(t)
		})

		oaNo5xx(t, "the refresh and the exchange", replies)

		if replies[1].status != http.StatusOK {
			t.Fatalf("round %d: the newer consent's exchange = %d %s, want 200", round, replies[1].status, replies[1].body)
		}

		newerTokens := mustTokens(t, replies[1])

		// The older grant is ended whichever came first: nothing the refresh handed out lives on.
		if got := revokedAtOf(t, olderID); got == supersedeNull {
			t.Errorf("round %d: the older grant was not ended", round)
		}

		if replies[0].status == http.StatusOK {
			rotated := mustTokens(t, replies[0])

			send(t, request{method: http.MethodGet, path: pathAgent, bearer: rotated.AccessToken}).
				expect(t, "the access token the refresh raced to hand out", http.StatusUnauthorized, codeUnauthenticated)
			older.refresh(t, rotated.RefreshToken).
				expectOAuth(t, "the refresh token it rotated to", http.StatusBadRequest, "invalid_grant")
		} else {
			replies[0].expectOAuth(t, "the refresh that lost", http.StatusBadRequest, "invalid_grant")
		}

		send(t, request{method: http.MethodGet, path: pathAgent, bearer: olderTokens.AccessToken}).
			expect(t, "the older access token", http.StatusUnauthorized, codeUnauthenticated)

		if got := revokedAtOf(t, newerID); got != supersedeNull {
			t.Errorf("round %d: the newer grant has revoked_at %s", round, got)
		}

		send(t, request{method: http.MethodGet, path: pathAgent, bearer: newerTokens.AccessToken}).
			expect(t, "the newer access token", http.StatusOK, "")

		expectNoOrphanSecrets(t)
	}
}
