//nolint:goconst // table-driven tests repeat case inputs on purpose; a constant per row would hide the table
package mcp_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

// errBoom is a cause that must never reach a client.
var errBoom = errors.New("boom")

// toolCall is the body of a tools/call for tool with raw arguments, or none.
func toolCall(tool, arguments string) string {
	args := ""
	if arguments != "" {
		args = `,"arguments":` + arguments
	}

	return `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"` + tool + `"` + args + `}}`
}

// wireResult is a response to tools/call, as a client decodes it.
type wireResult struct {
	Result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		IsError           bool            `json:"isError"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// decodeResult reads a response to tools/call.
func decodeResult(t *testing.T, body string) wireResult {
	t.Helper()

	var out wireResult

	err := json.Unmarshal([]byte(body), &out)
	if err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, body)
	}

	return out
}

// listedTool is a tool as a client decodes it from "tools/list".
type listedTool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations"`
}

// toolWant is what a listed tool must say.
type toolWant struct {
	name                  string
	readOnly, destructive bool
	idempotent            bool
	required              []any
}

// check compares a listed tool with what it must say: its name, a title and a
// description, a schema that is an object schema forbidding other arguments and
// requiring what it must, and the hints a harness may use to ask before calling.
func (w toolWant) check(t *testing.T, tool listedTool) {
	t.Helper()

	if tool.Name != w.name || tool.Title == "" || tool.Description == "" {
		t.Errorf("tool = %q %q, want %q with a title and a description", tool.Name, tool.Title, w.name)
	}

	if tool.InputSchema["type"] != "object" || tool.InputSchema["additionalProperties"] != false {
		t.Errorf("%s schema = %v, want an object schema that forbids other arguments", w.name, tool.InputSchema)
	}

	if required, _ := tool.InputSchema["required"].([]any); !slices.Equal(required, w.required) {
		t.Errorf("%s requires %v, want %v", w.name, tool.InputSchema["required"], w.required)
	}

	hints := map[string]any{
		"title": tool.Title, "readOnlyHint": w.readOnly, "destructiveHint": w.destructive,
		"idempotentHint": w.idempotent, "openWorldHint": false,
	}
	if !reflect.DeepEqual(tool.Annotations, hints) {
		t.Errorf("%s annotations = %v, want %v", w.name, tool.Annotations, hints)
	}
}

// TestToolsAreListed pins the tools a client is told about, in order.
func TestToolsAreListed(t *testing.T) {
	t.Parallel()

	rec := newHarness(t).post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)

	var got struct {
		Result struct {
			Tools []listedTool `json:"tools"`
		} `json:"result"`
	}

	err := json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || err != nil {
		t.Fatalf("response = %d %s (%v)", rec.Code, rec.Body.String(), err)
	}

	want := []toolWant{
		{"list_invitations", true, false, true, nil},
		{"get_invitation", true, false, true, []any{"id"}},
		{"create_invitation", false, false, false, []any{"type", "numInvites", "publicKey"}},
		{"revoke_invitation", false, true, true, []any{"id"}},
		{"list_users", true, false, true, nil},
		{"get_user", true, false, true, []any{"id"}},
		{"revoke_user", false, true, true, []any{"id"}},
		{"list_orgs", true, false, true, nil},
		{"get_org", true, false, true, []any{"id"}},
		{"rename_org", false, false, true, []any{"id", "name"}},
		{"delete_sandbox", false, true, false, []any{"id"}},
		{"list_org_members", true, false, true, []any{"id"}},
		{"set_member_admin", false, false, true, []any{"id", "admin"}},
		{"revoke_member", false, true, true, []any{"id"}},
	}

	if len(got.Result.Tools) != len(want) {
		t.Fatalf("%d tools, want %d: %s", len(got.Result.Tools), len(want), rec.Body.String())
	}

	for i, tool := range got.Result.Tools {
		want[i].check(t, tool)
	}
}

// TestToolCallsBecomeTheRoutesRequest: for every tool, the arguments become
// the method, path and body of the route's request, and the caller's own
// Authorization header is what goes with it. This table is the record of which
// route each tool reaches.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestToolCallsBecomeTheRoutesRequest(t *testing.T) {
	t.Parallel()

	create := `{"type":"member","numInvites":1,"label":"x","expiresAt":1900000000,"publicKey":"` + someKey + `"}`

	tests := []struct {
		name         string
		call         string
		method, path string
		body         string
	}{
		{"list", toolCall("list_invitations", ""), http.MethodGet, "/api/invitation", ""},
		{"list with empty arguments", toolCall("list_invitations", "{}"), http.MethodGet, "/api/invitation", ""},
		{"get", toolCall("get_invitation", `{"id":"`+itemID+`"}`), http.MethodGet, "/api/invitation/" + itemID, ""},
		{"create", toolCall("create_invitation", create), http.MethodPost, "/api/invitation", create},
		{"create sends the arguments as they came, spelling and all",
			toolCall("create_invitation", `{ "type" : "admin" ,"numInvites":2}`), http.MethodPost, "/api/invitation",
			`{ "type" : "admin" ,"numInvites":2}`},
		{"create with no arguments sends an empty object so the route says what is missing",
			toolCall("create_invitation", ""), http.MethodPost, "/api/invitation", `{}`},
		{"revoke", toolCall("revoke_invitation", `{"id":"`+itemID+`"}`), http.MethodDelete, "/api/invitation/" + itemID, ""},

		{"list users", toolCall("list_users", ""), http.MethodGet, "/api/user", ""},
		{"list users with empty arguments", toolCall("list_users", "{}"), http.MethodGet, "/api/user", ""},
		{"list users with a limit", toolCall("list_users", `{"limit":5}`), http.MethodGet, "/api/user?limit=5", ""},
		{"list users with a cursor", toolCall("list_users", `{"cursor":"`+itemID+`"}`), http.MethodGet,
			"/api/user?cursor=" + itemID, ""},
		{"list users with both", toolCall("list_users", `{"limit":100,"cursor":"`+itemID+`"}`), http.MethodGet,
			"/api/user?cursor=" + itemID + "&limit=100", ""},
		{"get a user", toolCall("get_user", `{"id":"`+itemID+`"}`), http.MethodGet, "/api/user/" + itemID, ""},
		{"get the caller's own user", toolCall("get_user", `{"id":"me"}`), http.MethodGet, "/api/user/me", ""},
		{"revoke a user", toolCall("revoke_user", `{"id":"`+itemID+`"}`), http.MethodDelete, "/api/user/" + itemID, ""},

		{"list orgs", toolCall("list_orgs", ""), http.MethodGet, "/api/org", ""},
		{"list orgs with a limit", toolCall("list_orgs", `{"limit":1}`), http.MethodGet, "/api/org?limit=1", ""},
		{"get an org", toolCall("get_org", `{"id":"`+itemID+`"}`), http.MethodGet, "/api/org/" + itemID, ""},
		{"rename an org", toolCall("rename_org", `{"id":"`+itemID+`","name":"Acme"}`), http.MethodPatch,
			"/api/org/" + itemID, `{"name":"Acme"}`},
		{"rename sends the name as it came, spelling and all",
			toolCall("rename_org", `{ "name" : " A\u00e9 ","id":"`+itemID+`"}`), http.MethodPatch,
			"/api/org/" + itemID, `{"name":" A\u00e9 "}`},
		{"rename with no name sends an empty body so the route says what is missing",
			toolCall("rename_org", `{"id":"`+itemID+`"}`), http.MethodPatch, "/api/org/" + itemID, `{}`},
		{"delete a sandbox", toolCall("delete_sandbox", `{"id":"`+itemID+`"}`), http.MethodDelete,
			"/api/org/" + itemID, ""},
		{"list the members of an org", toolCall("list_org_members", `{"id":"`+itemID+`"}`), http.MethodGet,
			"/api/org/" + itemID + "/member", ""},
		{"list the members with a page", toolCall("list_org_members", `{"id":"`+itemID+`","limit":2,"cursor":"`+itemID+`"}`),
			http.MethodGet, "/api/org/" + itemID + "/member?cursor=" + itemID + "&limit=2", ""},
		{"make a member an administrator", toolCall("set_member_admin", `{"id":"`+itemID+`","admin":true}`),
			http.MethodPatch, "/api/member/" + itemID, `{"admin":true}`},
		{"stop a member administering", toolCall("set_member_admin", `{"admin":false,"id":"`+itemID+`"}`),
			http.MethodPatch, "/api/member/" + itemID, `{"admin":false}`},
		{"a null admin is sent as null, for the route to refuse",
			toolCall("set_member_admin", `{"id":"`+itemID+`","admin":null}`),
			http.MethodPatch, "/api/member/" + itemID, `{"admin":null}`},
		{"revoke a member", toolCall("revoke_member", `{"id":"`+itemID+`"}`), http.MethodDelete,
			"/api/member/" + itemID, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			auth := harn.key()

			rec := harn.do(request{method: http.MethodPost, body: tt.call, contentType: jsonType, authorization: auth})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			want := restCall{
				method: tt.method, path: tt.path, body: tt.body, authorization: []string{auth}, ctxValue: "marker",
			}
			if len(harn.rest.calls) != 1 || !reflect.DeepEqual(harn.rest.calls[0], want) {
				t.Errorf("routes got %+v, want one %+v", harn.rest.calls, want)
			}
		})
	}
}

// TestTheCallersAuthorizationIsForwardedAsSent: the route is reached with the
// header values of the request and no more, so the route sees exactly the
// credential the caller presented.
func TestTheCallersAuthorizationIsForwardedAsSent(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	auth := harn.key()

	rec := harn.do(request{
		method: http.MethodPost, body: toolCall("list_invitations", ""), contentType: jsonType, authorization: auth,
	})

	if rec.Code != http.StatusOK || len(harn.rest.calls) != 1 ||
		!reflect.DeepEqual(harn.rest.calls[0].authorization, []string{auth}) {
		t.Errorf("response = %d, routes got %+v", rec.Code, harn.rest.calls)
	}
}

// TestAToolResultIsWhatTheRouteAnswered: a success carries the body as text and
// as structured content; a refusal carries the body as text and is an error of
// the tool; a body that is not JSON is text only. Nothing is rewritten but the
// newline the REST boundary ends a body with.
func TestAToolResultIsWhatTheRouteAnswered(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		status     int
		body       string
		wantText   string
		structured string
		isError    bool
	}{
		{"a read", http.StatusOK, `{"invitations":[]}` + "\n", `{"invitations":[]}`, `{"invitations":[]}`, false},
		{"a create", http.StatusCreated, `{"id":"a","sealed":"s"}` + "\n",
			`{"id":"a","sealed":"s"}`, `{"id":"a","sealed":"s"}`, false},
		{"a body that is not JSON", http.StatusOK, "plain\n", "plain", "", false},
		{"no body", http.StatusOK, "", "", "", false},
		{"not found", http.StatusNotFound, `{"error":{"code":"invitation_not_found","message":"no such invitation"}}` + "\n",
			`{"error":{"code":"invitation_not_found","message":"no such invitation"}}`, "", true},
		{"forbidden", http.StatusForbidden, `{"error":{"code":"forbidden","message":"x"}}` + "\n",
			`{"error":{"code":"forbidden","message":"x"}}`, "", true},
		{"a failure of the service", http.StatusInternalServerError,
			`{"error":{"code":"internal","message":"internal error"}}` + "\n",
			`{"error":{"code":"internal","message":"internal error"}}`, "", true},
		{"the first error status", http.StatusBadRequest, `{"error":{"code":"x","message":"y"}}`,
			`{"error":{"code":"x","message":"y"}}`, "", true},
		{"the last non-error status", 399, `{"a":1}`, `{"a":1}`, `{"a":1}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.rest.status, harn.rest.body = tt.status, tt.body

			rec := harn.post(toolCall("get_invitation", `{"id":"`+itemID+`"}`))
			got := decodeResult(t, rec.Body.String())

			if rec.Code != http.StatusOK || got.Error != nil || len(got.Result.Content) != 1 ||
				got.Result.Content[0].Type != "text" || got.Result.Content[0].Text != tt.wantText ||
				got.Result.IsError != tt.isError || string(got.Result.StructuredContent) != tt.structured {
				t.Errorf("response = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestArgumentsTheToolDoesNotTakeAreRefusedAsAToolError: the model can read the
// refusal and correct the call, and the route is never reached. The text is the
// REST error's shape, with the parser's own code.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestArgumentsTheToolDoesNotTakeAreRefusedAsAToolError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call string
		code string
	}{
		{"an id that is not an id", toolCall("get_invitation", `{"id":"abc"}`), "invalid_id"},
		{"an upper-case id", toolCall("get_invitation", `{"id":"`+strings.ToUpper(itemID)+`"}`), "invalid_id"},
		{"an id with a path in it", toolCall("revoke_invitation", `{"id":"`+itemID+`/../x"}`), "invalid_id"},
		{"an id with a query", toolCall("revoke_invitation", `{"id":"`+itemID+`?x=1"}`), "invalid_id"},
		{"no id", toolCall("get_invitation", `{}`), "invalid_id"},
		{"no arguments for a tool that needs an id", toolCall("revoke_invitation", ""), "invalid_id"},
		{"an id that is a number", toolCall("get_invitation", `{"id":1}`), "invalid_field_type"},
		{"another argument beside the id", toolCall("get_invitation", `{"id":"`+itemID+`","x":1}`), "unknown_field"},
		{"arguments that are not an object", toolCall("revoke_invitation", `[]`), "invalid_field_type"},
		{"arguments for a tool that takes none", toolCall("list_invitations", `{"id":"`+itemID+`"}`), "unknown_field"},

		{"me is only ever the exact word", toolCall("get_user", `{"id":"ME"}`), "invalid_id"},
		{"me with a space", toolCall("get_user", `{"id":"me "}`), "invalid_id"},
		{"a user lookup with another argument", toolCall("get_user", `{"id":"me","x":1}`), "unknown_field"},
		{"a user lookup whose arguments are not an object", toolCall("get_user", `[]`), "invalid_field_type"},
		{"me for a tool that does not take it", toolCall("revoke_user", `{"id":"me"}`), "invalid_id"},
		{"me for an org", toolCall("get_org", `{"id":"me"}`), "invalid_id"},
		{"a path for a user", toolCall("get_user", `{"id":"me/../x"}`), "invalid_id"},
		{"a limit of zero", toolCall("list_users", `{"limit":0}`), "invalid_limit"},
		{"a limit over the maximum", toolCall("list_orgs", `{"limit":101}`), "invalid_limit"},
		{"a negative limit", toolCall("list_users", `{"limit":-1}`), "invalid_limit"},
		{"a limit beyond an int64", toolCall("list_users", `{"limit":99999999999999999999}`), "invalid_field_type"},
		{"a limit that is not a number", toolCall("list_users", `{"limit":"5"}`), "invalid_field_type"},
		{"a fractional limit", toolCall("list_users", `{"limit":1.5}`), "invalid_field_type"},
		{"a cursor that is not an id", toolCall("list_users", `{"cursor":"abc"}`), "invalid_cursor"},
		{"an empty cursor", toolCall("list_orgs", `{"cursor":""}`), "invalid_cursor"},
		{"a cursor with a query in it", toolCall("list_users", `{"cursor":"`+itemID+`&limit=1"}`), "invalid_cursor"},
		{"a cursor that is a number", toolCall("list_users", `{"cursor":1}`), "invalid_field_type"},
		{"another argument beside the page", toolCall("list_users", `{"limit":1,"x":1}`), "unknown_field"},
		{"a members list with no id", toolCall("list_org_members", `{"limit":1}`), "invalid_id"},
		{"a members list with a bad id", toolCall("list_org_members", `{"id":"x"}`), "invalid_id"},
		{"a members list with another argument", toolCall("list_org_members", `{"id":"`+itemID+`","x":1}`), "unknown_field"},
		{"a rename with a bad id", toolCall("rename_org", `{"id":"x","name":"A"}`), "invalid_id"},
		{"a rename with no id", toolCall("rename_org", `{"name":"A"}`), "invalid_id"},
		{"a rename with an id that is a number", toolCall("rename_org", `{"id":1,"name":"A"}`), "invalid_field_type"},
		{"a rename with another argument", toolCall("rename_org", `{"id":"`+itemID+`","name":"A","x":1}`), "unknown_field"},
		{"a rename that names admin", toolCall("rename_org", `{"id":"`+itemID+`","admin":true}`), "unknown_field"},
		{"a rename whose arguments are not an object", toolCall("rename_org", `[]`), "invalid_field_type"},
		{"an admin change with a bad id", toolCall("set_member_admin", `{"id":"x","admin":true}`), "invalid_id"},
		{"an admin change that names name", toolCall("set_member_admin", `{"id":"`+itemID+`","name":"A"}`), "unknown_field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			rec := harn.post(tt.call)
			got := decodeResult(t, rec.Body.String())

			if rec.Code != http.StatusOK || got.Error != nil || !got.Result.IsError || len(got.Result.Content) != 1 {
				t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
			}

			wantToolErrorCode(t, got.Result.Content[0].Text, tt.code)

			if len(harn.rest.calls) != 0 || len(got.Result.StructuredContent) != 0 {
				t.Errorf("reached the routes: %+v", harn.rest.calls)
			}
		})
	}
}

// TestRepeatedArgumentsAreRefusedBeforeTheTool: a member given twice anywhere in
// the message is refused as an invalid request by the endpoint's strict reader,
// so no tool ever sees two spellings of one argument.
func TestRepeatedArgumentsAreRefusedBeforeTheTool(t *testing.T) {
	t.Parallel()

	calls := []string{
		toolCall("list_users", `{"limit":1,"limit":2}`),
		toolCall("rename_org", `{"id":"`+itemID+`","name":"A","name":"B"}`),
		toolCall("rename_org", `{"id":"`+itemID+`","id":"`+itemID+`","name":"A"}`),
		toolCall("set_member_admin", `{"id":"`+itemID+`","admin":true,"admin":false}`),
	}

	for _, call := range calls {
		harn := newHarness(t)
		rec := harn.post(call)

		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":-32600`) ||
			len(harn.rest.calls) != 0 {
			t.Errorf("%s: response = %d %s, routes got %+v", call, rec.Code, rec.Body.String(), harn.rest.calls)
		}
	}
}

// wantToolErrorCode checks that text is the REST error body with code.
func wantToolErrorCode(t *testing.T, text, code string) {
	t.Helper()

	var shape struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	err := json.Unmarshal([]byte(text), &shape)
	if err != nil || shape.Error.Code != code || shape.Error.Message == "" {
		t.Errorf("text = %s (%v), want code %s", text, err, code)
	}
}

// TestNullArgumentsAreNoArgumentsForAToolThatTakesNone: a client may send null
// where it has nothing to say, and a tool that takes nothing is reached.
func TestNullArgumentsAreNoArgumentsForAToolThatTakesNone(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	rec := harn.post(toolCall("list_invitations", `null`))
	got := decodeResult(t, rec.Body.String())

	if len(harn.rest.calls) != 1 || got.Result.IsError {
		t.Errorf("response = %s, routes got %+v", rec.Body.String(), harn.rest.calls)
	}
}

// TestCallsTheProtocolRefuses: an unknown tool, a call with no name, or params
// that are not a call are errors of the protocol, not of a tool.
func TestCallsTheProtocolRefuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params string
	}{
		{"an unknown tool", `{"name":"drop_everything"}`},
		{"a tool name in the wrong case", `{"name":"LIST_INVITATIONS"}`},
		{"no name", `{"arguments":{}}`},
		{"no params", ``},
		{"an empty object", `{}`},
		{"a member it does not know", `{"name":"list_invitations","extra":1}`},
		{"a name that is not a string", `{"name":1}`},
		{"params that are not an object", `[]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			params := ""
			if tt.params != "" {
				params = `,"params":` + tt.params
			}

			harn := newHarness(t)
			rec := harn.post(`{"jsonrpc":"2.0","id":9,"method":"tools/call"` + params + `}`)
			got := decodeResult(t, rec.Body.String())

			if rec.Code != http.StatusOK || got.Error == nil || got.Error.Code != -32602 || len(harn.rest.calls) != 0 {
				t.Errorf("response = %d %s, routes got %+v", rec.Code, rec.Body.String(), harn.rest.calls)
			}
		})
	}
}

// TestAFailureToReachTheRoutesIsInternal: a request that could not be built is
// a bug of ours, so it is a logged 500 with the bare "internal" and not a tool
// result that could carry what went wrong.
func TestAFailureToReachTheRoutesIsInternal(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	harn.rest.err = apierr.Wrap(errBoom, apierr.Internal, httpapi.CodeLocalRequestFailed, "internal error")

	rec := harn.post(toolCall("list_invitations", ""))

	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "boom") ||
		!strings.Contains(rec.Body.String(), `"code":"internal"`) {
		t.Errorf("response = %d %s", rec.Code, rec.Body.String())
	}

	if len(harn.logged) != 1 || harn.logged[0].Code != httpapi.CodeLocalRequestFailed {
		t.Errorf("logged = %v", harn.logged)
	}
}
