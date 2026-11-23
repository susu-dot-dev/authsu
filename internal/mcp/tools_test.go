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
