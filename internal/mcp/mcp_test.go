package mcp_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/mcp"
)

// TestRouteIsDeclaredAsAnyValidCredentialToOneEndpoint pins what the boundary is
// told: one POST route that needs a credential and nothing more. The route's own
// declaration is not the access rule (each tool's REST route is), so this table
// is also the record that the looseness is deliberate.
func TestRouteIsDeclaredAsAnyValidCredentialToOneEndpoint(t *testing.T) {
	t.Parallel()

	routes := mcp.Routes(mcp.Deps{Do: newHarness(t).rest.do})

	if len(routes) != 1 {
		t.Fatalf("%d routes, want 1", len(routes))
	}

	route := routes[0]
	if route.Method != http.MethodPost || route.Path != "/mcp" || route.Credential != auth.Authenticated ||
		route.Access != auth.Open() || route.MaxBody != mcp.MaxBody || route.Media != httpapi.MediaJSON ||
		route.Errors != httpapi.ErrorsAPI || route.Handle == nil {
		t.Errorf("route = %+v", route)
	}
}

// TestRoutesRefuseAMissingDependency: a deployment without Do is not an MCP
// server with a degraded mode, it fails when it is built.
func TestRoutesRefuseAMissingDependency(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("Routes did not panic")
		}
	}()

	mcp.Routes(mcp.Deps{Do: nil})
}

// TestOnlyAnAPIKeyMayCall: no credential is the boundary's 401; a session is
// refused here, because the REST routes are reached with the Authorization
// header alone and a cookie would pass this route and fail inside; and a key is
// let through whatever scopes it holds, since the route a tool reaches decides.
func TestOnlyAnAPIKeyMayCall(t *testing.T) {
	t.Parallel()

	const ping = `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	tests := []struct {
		name       string
		request    func(*harness) request
		status     int
		code       string
		wantReaded bool
	}{
		{"no credential", func(*harness) request {
			return request{method: http.MethodPost, body: ping, contentType: jsonType}
		}, http.StatusUnauthorized, "unauthenticated", false},
		{"a session", func(h *harness) request {
			return request{method: http.MethodPost, body: ping, contentType: jsonType, cookie: h.session()}
		}, http.StatusForbidden, mcp.CodeAPIKeyRequired, false},
		{"a session with a bogus key header", func(h *harness) request {
			return request{
				method: http.MethodPost, body: ping, contentType: jsonType, cookie: h.session(),
				authorization: "Bearer susu_key_" + strings.Repeat("A", 43),
			}
		}, http.StatusUnauthorized, "unauthenticated", false},
		{"an API key with no scopes", func(h *harness) request {
			return request{method: http.MethodPost, body: ping, contentType: jsonType, authorization: h.key()}
		}, http.StatusOK, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			rec := harn.do(tt.request(harn))

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body.String())
			}

			if tt.code != "" && !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
				t.Errorf("body = %s, want code %s", rec.Body.String(), tt.code)
			}
		})
	}
}

// TestRequestsTheBoundaryRefuses: the method, the media type and the size are
// the boundary's, in the API's own error format.
func TestRequestsTheBoundaryRefuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		req    func(*harness) request
		status int
		code   string
	}{
		{"GET (there is no stream)", func(h *harness) request {
			return request{method: http.MethodGet, authorization: h.key()}
		}, http.StatusMethodNotAllowed, "method_not_allowed"},
		{"another media type", func(h *harness) request {
			return request{method: http.MethodPost, body: "{}", contentType: "text/plain", authorization: h.key()}
		}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"a body over the limit", func(h *harness) request {
			return request{
				method: http.MethodPost, body: strings.Repeat(" ", mcp.MaxBody+1), contentType: jsonType,
				authorization: h.key(),
			}
		}, http.StatusRequestEntityTooLarge, "body_too_large"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			rec := harn.do(tt.req(harn))

			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
				t.Errorf("response = %d %s, want %d %s", rec.Code, rec.Body.String(), tt.status, tt.code)
			}

			if len(harn.rest.calls) != 0 {
				t.Errorf("reached the routes: %+v", harn.rest.calls)
			}
		})
	}
}

// protocolCase is a message in, and the status and JSON body out.
type protocolCase struct {
	name   string
	body   string
	status int
	want   string
}

// Answers the protocol tests repeat.
const (
	invalidParams = `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}`
	invalidFrame  = `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid request"}}`
	parseFailure  = `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`
)

// runProtocol sends each case's body and compares the status and the JSON body,
// as JSON so spelling and member order do not matter. The REST routes are never
// reached by a message of the protocol.
func runProtocol(t *testing.T, tests []protocolCase) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			rec := harn.post(tt.body)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body.String())
			}

			if !reflect.DeepEqual(decode(t, rec.Body.String()), decode(t, tt.want)) {
				t.Errorf("body = %s\nwant %s", rec.Body.String(), tt.want)
			}

			if len(harn.rest.calls) != 0 {
				t.Errorf("reached the routes: %+v", harn.rest.calls)
			}
		})
	}
}

// TestInitialize: the version the client asks for is answered when the server
// speaks it, and the newest the server speaks when it does not.
func TestInitialize(t *testing.T) {
	t.Parallel()

	initialized := func(version string) string {
		return `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"` + version + `",` +
			`"capabilities":{"tools":{}},"serverInfo":{"name":"authsu","version":"2"}}}`
	}

	initial := func(params string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` + params + `}`
	}

	full := func(version string) string {
		return initial(`{"protocolVersion":"` + version + `","capabilities":{},"clientInfo":{"name":"c","version":"1"}}`)
	}

	runProtocol(t, []protocolCase{
		{"the newest version", full("2025-11-25"), 200, initialized("2025-11-25")},
		{"the middle version", full("2025-06-18"), 200, initialized("2025-06-18")},
		{"the oldest version", full("2025-03-26"), 200, initialized("2025-03-26")},
		{"a version it does not speak gets the newest", full("2024-11-05"), 200, initialized("2025-11-25")},
		{"a version from the future gets the newest", full("2099-01-01"), 200, initialized("2025-11-25")},
		{"_meta is accepted", initial(`{"protocolVersion":"2025-06-18","_meta":{"a":1}}`), 200, initialized("2025-06-18")},
		{"no version", initial(`{}`), 200, invalidParams},
		{"no params", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, 200, invalidParams},
		{"a member it does not know", initial(`{"protocolVersion":"2025-06-18","x":1}`), 200, invalidParams},
	})
}

// TestMethods: the other methods a client may send with an id.
func TestMethods(t *testing.T) {
	t.Parallel()

	runProtocol(t, []protocolCase{
		{"ping", `{"jsonrpc":"2.0","id":"abc","method":"ping"}`, 200, `{"jsonrpc":"2.0","id":"abc","result":{}}`},
		{"a negative number id is an id", `{"jsonrpc":"2.0","id":-3,"method":"ping"}`, 200,
			`{"jsonrpc":"2.0","id":-3,"result":{}}`},
		{"a method it does not have", `{"jsonrpc":"2.0","id":7,"method":"resources/list"}`, 200,
			`{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"method not found"}}`},
	})
}

// TestFraming: what is not a request or notification of the protocol is refused
// with 400 and a null id, and text that is not JSON at all is a parse error.
func TestFraming(t *testing.T) {
	t.Parallel()

	const call = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`

	runProtocol(t, []protocolCase{
		{"not JSON", `nope`, 400, parseFailure},
		{"an empty body", ``, 400, parseFailure},
		{"trailing data", `{"jsonrpc":"2.0","id":1,"method":"ping"} {}`, 400, parseFailure},
		{"a batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, 400, invalidFrame},
		{"another version of the framing", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, 400, invalidFrame},
		{"no version of the framing", `{"id":1,"method":"ping"}`, 400, invalidFrame},
		{"no method", `{"jsonrpc":"2.0","id":1}`, 400, invalidFrame},
		{"an empty method", `{"jsonrpc":"2.0","id":1,"method":""}`, 400, invalidFrame},
		{"a null id", `{"jsonrpc":"2.0","id":null,"method":"ping"}`, 400, invalidFrame},
		{"an object id", `{"jsonrpc":"2.0","id":{},"method":"ping"}`, 400, invalidFrame},
		{"a boolean id", `{"jsonrpc":"2.0","id":true,"method":"ping"}`, 400, invalidFrame},
		{"an unknown member", `{"jsonrpc":"2.0","id":1,"method":"ping","extra":1}`, 400, invalidFrame},
		{"a response, not a request", `{"jsonrpc":"2.0","id":1,"result":{}}`, 400, invalidFrame},
		{"a repeated member", `{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`, 400, invalidFrame},
		{"a member repeated inside the arguments",
			call + `{"name":"get_invitation","arguments":{"id":"a","id":"b"}}}`, 400, invalidFrame},
		{"a member that is not the right type", `{"jsonrpc":2,"id":1,"method":"ping"}`, 400, invalidFrame},
	})
}

// TestNotificationsAreAcceptedAndNeverAnswered: a message without an id is 202
// with no body, whatever it names, including the one a client sends after
// "initialize".
func TestNotificationsAreAcceptedAndNeverAnswered(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"initialized":           `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		"cancelled with params": `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		"a method it lacks":     `{"jsonrpc":"2.0","method":"nope"}`,
		"a call with no id":     `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_invitations"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			rec := harn.post(body)

			if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
				t.Errorf("response = %d %q, want 202 with no body", rec.Code, rec.Body.String())
			}

			if len(harn.rest.calls) != 0 {
				t.Errorf("a notification reached the routes: %+v", harn.rest.calls)
			}
		})
	}
}
