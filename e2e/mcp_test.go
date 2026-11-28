//go:build e2e

//nolint:goconst,cyclop,funlen,lll // the tests spell JSON-RPC bodies and codes inline on purpose, and the flow is the test
package e2e_test

// mcp_test.go drives POST /mcp, the admin MCP endpoint, against the real TinyGo
// Worker and the real D1/SQLite. What it proves that the host tests cannot:
// that the in-process call to the REST routes works under TinyGo's net/http
// (a request built with http.NewRequestWithContext, answered by the real route
// table), that encoding/json handles the JSON-RPC messages and results under
// TinyGo, that the sealed invitation code opens with the client's key, and that
// the route's own role and scope rules are what a tool is held to.
//
// REVIEW.md categories covered: permission confusion (a member's key, a key
// without the scope, a session and no credential), input edge cases (an id that
// is not an id, arguments the tool does not take) and type/bound confusion (the
// JSON-RPC id and the tool result through the real encoder).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const (
	pathMCP = "/mcp"

	mcpKeyFam = "0c77"
)

// rpc is a JSON-RPC response as a client decodes it.
type rpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// toolOutcome is the result of tools/call.
type toolOutcome struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StructuredContent map[string]any `json:"structuredContent"`
	IsError           bool           `json:"isError"`
}

// mcpPost sends one JSON-RPC message to /mcp with an API key.
func mcpPost(t *testing.T, key, message string) reply {
	t.Helper()

	return send(t, request{method: http.MethodPost, path: pathMCP, body: []byte(message), bearer: key, noSeal: true})
}

// mcpRPC sends message and decodes the JSON-RPC response, which must be 200.
func mcpRPC(t *testing.T, key, message string) rpc {
	t.Helper()

	got := mcpPost(t, key, message)
	got.expect(t, "mcp "+message, http.StatusOK, "")

	var out rpc

	err := json.Unmarshal([]byte(got.body), &out)
	if err != nil || out.JSONRPC != "2.0" {
		t.Fatalf("body %s (%v), want a JSON-RPC 2.0 response", got.body, err)
	}

	return out
}

// mcpTool calls a tool and decodes its result.
func mcpTool(t *testing.T, key, tool, arguments string) toolOutcome {
	t.Helper()

	out := mcpRPC(t, key, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+arguments+`}}`)
	if out.Error != nil || string(out.ID) != "7" {
		t.Fatalf("tool %s = %+v, want a result for id 7", tool, out)
	}

	var result toolOutcome

	err := json.Unmarshal(out.Result, &result)
	if err != nil || len(result.Content) != 1 {
		t.Fatalf("tool %s result %s (%v)", tool, out.Result, err)
	}

	return result
}

// TestMCPHandshakeAndTheToolList: a client opens with initialize, says it is
// initialized, and lists the tools, in the legacy handshake every current
// harness opens with.
//
//nolint:paralleltest // shares one database
func TestMCPHandshakeAndTheToolList(t *testing.T) {
	admin := newAdmin(t)
	key := sbSeedKey(t, idN(mcpKeyFam, 1), admin.userID, "", `["invitation:read"]`)

	opened := mcpRPC(t, key, `{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2025-06-18",`+
		`"capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}`)
	if opened.Error != nil || string(opened.ID) != `"a"` ||
		!strings.Contains(string(opened.Result), `"protocolVersion":"2025-06-18"`) ||
		!strings.Contains(string(opened.Result), `"serverInfo":{"name":"authsu","version":"2"}`) {
		t.Errorf("initialize = %+v %s", opened, opened.Result)
	}

	notified := mcpPost(t, key, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if notified.status != http.StatusAccepted || notified.body != "" {
		t.Errorf("initialized notification = %d %q, want 202 and no body", notified.status, notified.body)
	}

	list := mcpRPC(t, key, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)

	var tools struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}

	want := []string{
		"list_invitations", "get_invitation", "create_invitation", "revoke_invitation",
		"list_users", "get_user", "revoke_user",
		"list_orgs", "get_org", "rename_org", "delete_sandbox",
		"list_org_members", "set_member_admin", "revoke_member",
	}

	err := json.Unmarshal(list.Result, &tools)
	if err != nil || len(tools.Tools) != len(want) {
		t.Fatalf("tools/list = %s (%v), want %d tools", list.Result, err, len(want))
	}

	for i, name := range want {
		if tools.Tools[i].Name != name {
			t.Errorf("tool %d = %q, want %q", i, tools.Tools[i].Name, name)
		}
	}
}

// TestMCPInvitationLifecycle: an admin's key creates an invitation through the
// tool and gets the code sealed to its key, reads it, sees it in the list and
// revokes it, each through the real route and the real database. The code is
// never in a tool result in the clear, and what was sealed is what was stored.
//
//nolint:paralleltest // shares one database
func TestMCPInvitationLifecycle(t *testing.T) {
	admin := newAdmin(t)
	key := sbSeedKey(t, idN(mcpKeyFam, 2), admin.userID, "",
		`["invitation:create","invitation:read","invitation:revoke"]`)
	pair := newClientPair(t)

	created := mcpTool(t, key, "create_invitation",
		`{"type":"member","numInvites":2,"label":"mcp e2e","publicKey":"`+pair.public+`"}`)
	if created.IsError {
		t.Fatalf("create_invitation = %+v", created)
	}

	id, _ := created.StructuredContent["id"].(string)
	sealed, _ := created.StructuredContent["sealed"].(string)

	if _, plain := created.StructuredContent["code"]; plain || id == "" || sealed == "" ||
		!strings.Contains(created.Content[0].Text, sealed) {
		t.Fatalf("create result = %+v, want an id and a sealed member and no code", created)
	}

	code := pair.open(t, sealed)
	if !strings.HasPrefix(code, "susu_inv_") || strings.Contains(created.Content[0].Text, code) {
		t.Errorf("opened %q, want an invitation token that is not in the result", code)
	}

	expectCount(t, "secrets WHERE hash = ?", "1", tokenHash(code))

	fetched := mcpTool(t, key, "get_invitation", `{"id":"`+id+`"}`)
	if fetched.IsError || fetched.StructuredContent["status"] != "active" || fetched.StructuredContent["uses"] != float64(0) ||
		fetched.StructuredContent["numInvites"] != float64(2) || fetched.StructuredContent["label"] != "mcp e2e" {
		t.Errorf("get_invitation = %+v", fetched)
	}

	listed := mcpTool(t, key, "list_invitations", `{}`)
	if listed.IsError || !strings.Contains(listed.Content[0].Text, id) {
		t.Errorf("list_invitations = %+v, want the invitation in it", listed)
	}

	revoked := mcpTool(t, key, "revoke_invitation", `{"id":"`+id+`"}`)
	if revoked.IsError || revoked.StructuredContent["status"] != "revoked" {
		t.Errorf("revoke_invitation = %+v", revoked)
	}

	again := mcpTool(t, key, "get_invitation", `{"id":"`+id+`"}`)
	if again.IsError || again.StructuredContent["status"] != "revoked" {
		t.Errorf("get_invitation after the revoke = %+v", again)
	}

	// The same answers over REST: the tool added nothing to what a route says.
	rest := send(t, request{path: pathInvitation + "/" + id, bearer: key})
	rest.expect(t, "GET the invitation", http.StatusOK, "")

	if strings.TrimSpace(rest.body) != again.Content[0].Text {
		t.Errorf("REST body %q differs from the tool's text %q", rest.body, again.Content[0].Text)
	}

	send(t, request{path: pathInvitation + "/" + idN("0c78", 9), bearer: key}).
		expect(t, "GET an invitation that does not exist", http.StatusNotFound, "invitation_not_found")
}

// TestMCPToolErrorsAreResultsTheModelCanRead: a route's refusal and a tool's own
// refusal of its arguments are results with isError, in the REST error shape.
//
//nolint:paralleltest // shares one database
func TestMCPToolErrorsAreResultsTheModelCanRead(t *testing.T) {
	admin := newAdmin(t)
	key := sbSeedKey(t, idN(mcpKeyFam, 3), admin.userID, "", `["invitation:create","invitation:read","invitation:revoke"]`)

	tests := []struct {
		name, tool, arguments, code string
	}{
		{"an invitation that does not exist", "get_invitation", `{"id":"` + idN("0c78", 1) + `"}`, "invitation_not_found"},
		{"a revoke of one that does not exist", "revoke_invitation", `{"id":"` + idN("0c78", 2) + `"}`, "invitation_not_found"},
		{"an id that is not an id", "get_invitation", `{"id":"../x"}`, "invalid_id"},
		{"another argument beside the id", "revoke_invitation", `{"id":"` + idN("0c78", 3) + `","x":1}`, "unknown_field"},
		{"a create with no public key", "create_invitation", `{"type":"member","numInvites":1}`, "public_key_required"},
		{"a create with a key that cannot be sealed to", "create_invitation",
			`{"type":"member","numInvites":1,"publicKey":"` + lowOrderKey() + `"}`, "invalid_public_key"},
		{"a create of a type that does not exist", "create_invitation",
			`{"type":"owner","numInvites":1,"publicKey":"` + newClientPair(t).public + `"}`, "invalid_invitation_type"},
		{"arguments for a tool that takes none", "list_invitations", `{"x":1}`, "unknown_field"},
	}

	for _, tt := range tests {
		got := mcpTool(t, key, tt.tool, tt.arguments)

		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}

		err := json.Unmarshal([]byte(got.Content[0].Text), &body)
		if !got.IsError || err != nil || body.Error.Code != tt.code || len(got.StructuredContent) != 0 {
			t.Errorf("%s: result = %+v (%v), want an error with code %s", tt.name, got, err, tt.code)
		}
	}

	// Nothing was created by the refused creates.
	expectCount(t, "invitations WHERE type = 'member' AND label = ''", "0")
}

// TestMCPHoldsAToolToTheRoutesRules: the endpoint lets any API key in, so the
// route a tool reaches is what refuses. A key that names an admin scope but
// belongs to a member is refused for the role, a key without the scope is
// refused for the scope, a session is refused at the endpoint, and a request
// with no credential is the one 401.
//
//nolint:paralleltest // shares one database
func TestMCPHoldsAToolToTheRoutesRules(t *testing.T) {
	admin := newAdmin(t)
	session := login(t, admin)

	noScope := sbSeedKey(t, idN(mcpKeyFam, 4), admin.userID, "", `["agent:read"]`)
	named := sbSeedKey(t, idN(mcpKeyFam, 5), admin.userID, "", `["invitation:read"]`)

	for _, tool := range []struct{ name, arguments string }{
		{"list_invitations", `{}`},
		{"get_invitation", `{"id":"` + idN("0c78", 4) + `"}`},
		{"revoke_invitation", `{"id":"` + idN("0c78", 5) + `"}`},
		{"create_invitation", `{"type":"member","numInvites":1,"publicKey":"` + newClientPair(t).public + `"}`},
	} {
		got := mcpTool(t, noScope, tool.name, tool.arguments)
		if !got.IsError || !strings.Contains(got.Content[0].Text, "insufficient_scope") {
			t.Errorf("%s without its scope = %+v, want insufficient_scope", tool.name, got)
		}
	}

	// The role is read live: demoted, the same key that listed before is refused.
	before := mcpTool(t, named, "list_invitations", `{}`)
	if before.IsError {
		t.Fatalf("list as an admin = %+v", before)
	}

	setRole(t, admin.userID, "member")

	after := mcpTool(t, named, "list_invitations", `{}`)
	if !after.IsError || !strings.Contains(after.Content[0].Text, `"code":"forbidden"`) {
		t.Errorf("list as a member who names the scope = %+v, want forbidden", after)
	}

	setRole(t, admin.userID, "admin")

	sessionCall := send(t, request{
		method: http.MethodPost, path: pathMCP, body: []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`), token: session,
	})
	sessionCall.expect(t, "a session at /mcp", http.StatusForbidden, "api_key_required")

	anonymous := send(t, request{method: http.MethodPost, path: pathMCP, body: []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)})
	anonymous.expect(t, "no credential at /mcp", http.StatusUnauthorized, "unauthenticated")

	stream := send(t, request{method: http.MethodGet, path: pathMCP, bearer: named})
	stream.expect(t, "GET /mcp", http.StatusMethodNotAllowed, "method_not_allowed")
}

// mcpErrorCode is the code of the REST error a tool result carries as text.
func mcpErrorCode(t *testing.T, got toolOutcome) string {
	t.Helper()

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}

	err := json.Unmarshal([]byte(got.Content[0].Text), &body)
	if err != nil {
		t.Fatalf("result text %q is not a REST error: %v", got.Content[0].Text, err)
	}

	return body.Error.Code
}

// TestMCPManagesUsers: an admin's key reads its own profile with "me", lists
// accounts a page at a time, reads one, and revokes it, each through the real
// route and database, and the tool's text is the REST body byte for byte. A
// revoked account is final and is shown as such, and the last active
// administrator cannot be revoked.
//
//nolint:paralleltest // shares one database
func TestMCPManagesUsers(t *testing.T) {
	admin := newAdmin(t)
	key := sbSeedKey(t, idN(mcpKeyFam, 6), admin.userID, "", `["user:read","user:revoke"]`)

	seedUser(t, idUserB, roleMember)
	seedUser(t, idUserC, roleMember)

	me := mcpTool(t, key, "get_user", `{"id":"me"}`)
	if me.IsError || me.StructuredContent["id"] != admin.userID || me.StructuredContent["role"] != roleAdmin ||
		me.StructuredContent["status"] != "active" {
		t.Fatalf("get_user me = %+v, want the admin's own account", me)
	}

	rest := send(t, request{path: pathUser + "/me", bearer: key})
	rest.expect(t, "GET the caller's own account", http.StatusOK, "")

	if strings.TrimSpace(rest.body) != me.Content[0].Text {
		t.Errorf("REST body %q differs from the tool's text %q", rest.body, me.Content[0].Text)
	}

	byID := mcpTool(t, key, "get_user", `{"id":"`+admin.userID+`"}`)
	if byID.Content[0].Text != me.Content[0].Text {
		t.Errorf("get_user by id = %s, want the same as me: %s", byID.Content[0].Text, me.Content[0].Text)
	}

	first := mcpTool(t, key, "list_users", `{"limit":2}`)

	users, _ := first.StructuredContent["users"].([]any)
	next, _ := first.StructuredContent["next"].(string)

	if first.IsError || len(users) != 2 || next == "" {
		t.Fatalf("list_users limit 2 = %+v, want two accounts and a next", first)
	}

	second := mcpTool(t, key, "list_users", `{"limit":2,"cursor":"`+next+`"}`)

	rest = send(t, request{path: pathUser + "?limit=2&cursor=" + next, bearer: key})
	if second.IsError || strings.TrimSpace(rest.body) != second.Content[0].Text {
		t.Errorf("second page = %+v, REST body %q, want the same text", second, rest.body)
	}

	if rest := mcpTool(t, key, "get_user", `{"id":"`+idUserB+`"}`); rest.IsError || rest.StructuredContent["status"] != "active" {
		t.Errorf("get_user = %+v", rest)
	}

	revoked := mcpTool(t, key, "revoke_user", `{"id":"`+idUserB+`"}`)
	if revoked.IsError || revoked.StructuredContent["status"] != "revoked" || usrStoredRevoked(t, idUserB) == "" {
		t.Fatalf("revoke_user = %+v, stored revoked_at %q", revoked, usrStoredRevoked(t, idUserB))
	}

	again := mcpTool(t, key, "revoke_user", `{"id":"`+idUserB+`"}`)
	if again.IsError || again.StructuredContent["revokedAt"] != revoked.StructuredContent["revokedAt"] {
		t.Errorf("revoking again = %+v, want the first time kept", again)
	}

	last := mcpTool(t, key, "revoke_user", `{"id":"`+admin.userID+`"}`)
	if !last.IsError || mcpErrorCode(t, last) != usrCodeLastAdmin || usrStoredRevoked(t, admin.userID) != "" {
		t.Errorf("revoking the last admin = %+v, want %s", last, usrCodeLastAdmin)
	}

	missing := mcpTool(t, key, "get_user", `{"id":"`+idMissing+`"}`)
	if !missing.IsError || mcpErrorCode(t, missing) != usrCodeNotFound {
		t.Errorf("get_user of a missing account = %+v", missing)
	}

	for _, tt := range []struct{ name, tool, arguments, code string }{
		{"me is not an id for a revoke", "revoke_user", `{"id":"me"}`, "invalid_id"},
		{"me is only the exact word", "get_user", `{"id":"Me"}`, "invalid_id"},
		{"a limit over the maximum", "list_users", `{"limit":101}`, "invalid_limit"},
		{"a cursor that is not an id", "list_users", `{"cursor":"x"}`, "invalid_cursor"},
		{"an argument the tool does not take", "list_users", `{"filter":"x"}`, "unknown_field"},
	} {
		got := mcpTool(t, key, tt.tool, tt.arguments)
		if !got.IsError || mcpErrorCode(t, got) != tt.code {
			t.Errorf("%s: %+v, want an error with code %s", tt.name, got, tt.code)
		}
	}
}

// TestMCPManagesOrganizations: an admin's key lists every organization, reads
// one, renames it, lists its members, promotes and demotes a member and revokes
// one, and deletes a sandbox, each through the real route and database. The
// organization's own rules (the last administrator, a standard organization is
// never deleted) are the route's answers, as the tool's results.
//
//nolint:paralleltest // shares one database
func TestMCPManagesOrganizations(t *testing.T) {
	admin := newAdmin(t)
	key := sbSeedKey(t, idN(mcpKeyFam, 7), admin.userID, "",
		`["org:read","org:update","sandbox:revoke","member:read","member:update","member:revoke"]`)

	org := scalar(t, "SELECT org_id FROM users WHERE id = ?", admin.userID)

	// A second member of the admin's organization, who is not an administrator of
	// it, and the second administrator that demoting the first needs.
	seedUserIn(t, idUserB, roleMember, org)
	seedUserIn(t, idUserC, roleMember, org)
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, strftime('%s','now'))", org, idUserC)

	listed := mcpTool(t, key, "list_orgs", `{}`)
	if listed.IsError || !strings.Contains(listed.Content[0].Text, org) {
		t.Fatalf("list_orgs = %+v, want the admin's organization", listed)
	}

	one := mcpTool(t, key, "get_org", `{"id":"`+org+`"}`)
	if one.IsError || one.StructuredContent["kind"] != "standard" || one.StructuredContent["status"] != "active" {
		t.Fatalf("get_org = %+v", one)
	}

	renamed := mcpTool(t, key, "rename_org", `{"id":"`+org+`","name":"Renamed by MCP"}`)
	if renamed.IsError || renamed.StructuredContent["name"] != "Renamed by MCP" ||
		scalar(t, "SELECT name FROM orgs WHERE id = ?", org) != "Renamed by MCP" {
		t.Errorf("rename_org = %+v, stored name %q", renamed, scalar(t, "SELECT name FROM orgs WHERE id = ?", org))
	}

	members := mcpTool(t, key, "list_org_members", `{"id":"`+org+`"}`)
	if members.IsError || !strings.Contains(members.Content[0].Text, admin.userID) {
		t.Errorf("list_org_members = %+v, want the admin among them", members)
	}

	for _, tt := range []struct {
		name, tool, arguments, code string
	}{
		{"a rename to nothing", "rename_org", `{"id":"` + org + `","name":""}`, "invalid_org_name"},
		{"a rename with no name", "rename_org", `{"id":"` + org + `"}`, "invalid_org_name"},
		{"an organization that does not exist", "get_org", `{"id":"` + idMissing + `"}`, "org_not_found"},
		{"a standard organization is never deleted", "delete_sandbox", `{"id":"` + org + `"}`, "org_not_sandbox"},
		{"an administrator flag left out", "set_member_admin", `{"id":"` + idUserB + `"}`, "missing_admin"},
		{"an administrator flag that is null", "set_member_admin", `{"id":"` + idUserB + `","admin":null}`, "missing_admin"},
		{"a member that does not exist", "revoke_member", `{"id":"` + idMissing + `"}`, "member_not_found"},
	} {
		got := mcpTool(t, key, tt.tool, tt.arguments)
		if !got.IsError || mcpErrorCode(t, got) != tt.code {
			t.Errorf("%s: %+v, want an error with code %s", tt.name, got, tt.code)
		}
	}

	if got := mcpTool(t, key, "rename_org", `{"id":"`+org+`","name":""}`); scalar(t, "SELECT name FROM orgs WHERE id = ?", org) != "Renamed by MCP" {
		t.Errorf("a refused rename changed the name: %+v", got)
	}

	promoted := mcpTool(t, key, "set_member_admin", `{"id":"`+idUserB+`","admin":true}`)
	if promoted.IsError || promoted.StructuredContent["admin"] != true {
		t.Fatalf("set_member_admin true = %+v", promoted)
	}

	demoted := mcpTool(t, key, "set_member_admin", `{"id":"`+idUserB+`","admin":false}`)
	if demoted.IsError || demoted.StructuredContent["admin"] != false {
		t.Errorf("set_member_admin false = %+v", demoted)
	}

	revoked := mcpTool(t, key, "revoke_member", `{"id":"`+idUserB+`"}`)
	if revoked.IsError || revoked.StructuredContent["status"] != "revoked" || usrStoredRevoked(t, idUserB) == "" {
		t.Errorf("revoke_member = %+v, stored revoked_at %q", revoked, usrStoredRevoked(t, idUserB))
	}

	promotedAgain := mcpTool(t, key, "set_member_admin", `{"id":"`+idUserB+`","admin":true}`)
	if !promotedAgain.IsError || mcpErrorCode(t, promotedAgain) != "member_revoked" {
		t.Errorf("promoting a revoked member = %+v, want member_revoked", promotedAgain)
	}

	// The same answers over REST: the tool added nothing to what a route says.
	rest := send(t, request{path: "/api/org/" + org, bearer: key})
	rest.expect(t, "GET the organization", http.StatusOK, "")

	if got := mcpTool(t, key, "get_org", `{"id":"`+org+`"}`); strings.TrimSpace(rest.body) != got.Content[0].Text {
		t.Errorf("REST body %q differs from the tool's text %q", rest.body, got.Content[0].Text)
	}
}

// TestMCPHoldsUserAndOrgToolsToTheRoutesRules: a key without a tool's scope is
// refused for the scope, and a member's key that names an admin tool's scope is
// refused for the role, through the real boundary, for every new tool. The
// organization tools are not admin tools: a member's key reaches the route and
// sees only what the member may, so it is told an organization it does not
// administer is not found.
//
//nolint:paralleltest // shares one database
func TestMCPHoldsUserAndOrgToolsToTheRoutesRules(t *testing.T) {
	admin := newAdmin(t)

	noScope := sbSeedKey(t, idN(mcpKeyFam, 8), admin.userID, "", `["agent:read"]`)
	org := scalar(t, "SELECT org_id FROM users WHERE id = ?", admin.userID)

	tools := []struct{ name, arguments string }{
		{"list_users", `{}`}, {"get_user", `{"id":"me"}`}, {"revoke_user", `{"id":"` + idMissing + `"}`},
		{"list_orgs", `{}`}, {"get_org", `{"id":"` + org + `"}`},
		{"rename_org", `{"id":"` + org + `","name":"x"}`}, {"delete_sandbox", `{"id":"` + idMissing + `"}`},
		{"list_org_members", `{"id":"` + org + `"}`}, {"set_member_admin", `{"id":"` + idUserB + `","admin":true}`},
		{"revoke_member", `{"id":"` + idUserB + `"}`},
	}

	for _, tool := range tools {
		got := mcpTool(t, noScope, tool.name, tool.arguments)
		if !got.IsError || !strings.Contains(got.Content[0].Text, "insufficient_scope") {
			t.Errorf("%s without its scope = %+v, want insufficient_scope", tool.name, got)
		}
	}

	// A member of the admin's organization who does not administer it, holding the
	// scopes that name every tool. The role is read live, so the same key as an
	// admin is refused the admin tools once the account is a member.
	seedUserIn(t, idUserB, roleMember, org)

	memberKey := sbSeedKey(t, idN(mcpKeyFam, 9), idUserB, "",
		`["user:read","user:revoke","org:read","org:update","member:read"]`)

	named := memberKey

	for _, tool := range []struct{ name, arguments string }{
		{"list_users", `{}`}, {"get_user", `{"id":"me"}`}, {"revoke_user", `{"id":"` + idMissing + `"}`},
	} {
		got := mcpTool(t, named, tool.name, tool.arguments)
		if !got.IsError || !strings.Contains(got.Content[0].Text, `"code":"forbidden"`) {
			t.Errorf("%s as a member naming the scope = %+v, want forbidden", tool.name, got)
		}
	}

	orgKey := memberKey

	own := mcpTool(t, orgKey, "get_org", `{"id":"`+org+`"}`)
	if own.IsError || own.StructuredContent["id"] != org {
		t.Errorf("a member reading their own organization = %+v", own)
	}

	renamed := mcpTool(t, orgKey, "rename_org", `{"id":"`+org+`","name":"nope"}`)
	if !renamed.IsError || mcpErrorCode(t, renamed) != "org_admin_required" {
		t.Errorf("a member renaming their organization = %+v, want org_admin_required", renamed)
	}

	other := mcpTool(t, orgKey, "get_org", `{"id":"`+idMissing+`"}`)
	if !other.IsError || mcpErrorCode(t, other) != "org_not_found" {
		t.Errorf("a member reading an organization that is not theirs = %+v, want org_not_found", other)
	}
}
