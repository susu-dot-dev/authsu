//go:build e2e

//nolint:goconst,cyclop,lll // the tests spell JSON-RPC bodies and codes inline on purpose, and the flow is the test
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
		!strings.Contains(string(opened.Result), `"serverInfo":{"name":"authsu","version":"1"}`) {
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

	err := json.Unmarshal(list.Result, &tools)
	if err != nil || len(tools.Tools) != 4 {
		t.Fatalf("tools/list = %s (%v), want 4 tools", list.Result, err)
	}

	for i, name := range []string{"list_invitations", "get_invitation", "create_invitation", "revoke_invitation"} {
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
