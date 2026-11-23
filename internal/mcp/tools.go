package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// arguments says how a tool's arguments become the request to its route.
type arguments uint8

const (
	// noArguments is a tool that takes none: an empty object, or none at all.
	noArguments arguments = iota
	// idArgument is a tool that takes only the id of the item the route's path
	// names. The id is parsed (input.ParseID) before it is written into the path,
	// so a value that is not an id never changes which route is reached.
	idArgument
	// bodyArguments is a tool whose arguments are the route's JSON body, sent
	// as they came. The route parses them, with its own strictness and its own
	// error codes.
	bodyArguments
)

// idPlaceholder is where the id goes in the path of a tool that takes one.
const idPlaceholder = "{id}"

// tool is one tool: the route it reaches and what a client is told about it.
type tool struct {
	name, title, description string
	// schema is the JSON Schema of the arguments.
	schema json.RawMessage
	// method and path are the route, as declared in its feature.
	method, path string
	args         arguments
	// readOnly and destructive are the hints a harness may use to decide whether
	// to ask before calling: a read changes nothing; a revoke cannot be undone.
	readOnly, destructive bool
}

// tools are the tools, in the order they are listed. Each names the route it
// reaches: the route's own declaration, not this table, decides who may call
// it, and the app package's seam tests send every tool to that route as an
// admin, a member and a key without its scope.
func tools() []tool {
	return []tool{
		{
			name: "list_invitations", title: "List invitations",
			description: "List every invitation, newest first, with how many accounts each has created, its status " +
				"and its expiry. Revoked invitations are included.",
			schema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			method: http.MethodGet, path: "/api/invitation", args: noArguments, readOnly: true, destructive: false,
		},
		{
			name: "get_invitation", title: "Get an invitation",
			description: "Read one invitation: how many accounts have registered with it (uses), how many it allows " +
				"(numInvites), whether it can still be used (status is active, exhausted, expired or revoked) and " +
				"when it expires.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The invitation's id, as create_invitation and list_invitations return it."}},` +
				`"required":["id"],"additionalProperties":false}`),
			method: http.MethodGet, path: "/api/invitation/" + idPlaceholder, args: idArgument,
			readOnly: true, destructive: false,
		},
		{
			name: "create_invitation", title: "Create an invitation",
			description: "Create an invitation. The invitation code is never returned in the clear: it comes back " +
				"sealed (the sealed field) to the public key you pass, and only the holder of that key's private " +
				"half can open it. An invitation with no orgId gives each person who registers with it an " +
				"organization of their own, which they name and administer. Type admin makes platform " +
				"administrators, so use the smallest numInvites and a short expiresAt.",
			schema: json.RawMessage(`{"type":"object","properties":{` +
				`"type":{"type":"string","enum":["member","admin"],` +
				`"description":"member creates a regular account; admin creates a platform administrator."},` +
				`"numInvites":{"type":"integer","minimum":1,"maximum":10000,` +
				`"description":"How many accounts the invitation may create."},` +
				`"label":{"type":"string","description":"A note for administrators, shown in the list."},` +
				`"expiresAt":{"type":"integer",` +
				`"description":"When it stops working, in Unix seconds, at most 10 years ahead. Defaults to 10 years."},` +
				`"orgId":{"type":"string",` +
				`"description":"A standard organization to join instead of getting one; needs orgRole."},` +
				`"orgRole":{"type":"string","enum":["member","admin"],"description":"The role in orgId; needs orgId."},` +
				`"publicKey":{"type":"string",` +
				`"description":"The recipient of the sealed code: 44 base64url characters, ` +
				`the suite byte 1 followed by a 32-byte X25519 public key."}` +
				`},"required":["type","numInvites","publicKey"],"additionalProperties":false}`),
			method: http.MethodPost, path: "/api/invitation", args: bodyArguments, readOnly: false, destructive: false,
		},
		{
			name: "revoke_invitation", title: "Revoke an invitation",
			description: "Revoke an invitation so that nobody can register with it from now on. Accounts it already " +
				"created are not affected. Revoking one that is already revoked succeeds and changes nothing.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The invitation's id."}},"required":["id"],"additionalProperties":false}`),
			method: http.MethodDelete, path: "/api/invitation/" + idPlaceholder, args: idArgument,
			readOnly: false, destructive: true,
		},
	}
}

// listedTool is a tool as "tools/list" shows it.
type listedTool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations annotations     `json:"annotations"`
}

// annotations are the hints a tool carries. They are advice to a harness and
// not a control: the route is the control.
type annotations struct {
	Title           string `json:"title"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

// toolList is the result of "tools/list".
func toolList() map[string][]listedTool {
	all := tools()
	listed := make([]listedTool, 0, len(all))

	for _, t := range all {
		listed = append(listed, listedTool{
			Name: t.name, Title: t.title, Description: t.description, InputSchema: t.schema,
			Annotations: annotations{
				Title: t.title, ReadOnlyHint: t.readOnly, DestructiveHint: t.destructive,
				// A read and a revoke (which keeps the first revocation) have the same
				// effect when repeated; a create makes another invitation each time.
				IdempotentHint: t.readOnly || t.destructive, OpenWorldHint: false,
			},
		})
	}

	return map[string][]listedTool{"tools": listed}
}

// callParams are the params of "tools/call".
type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Meta      json.RawMessage `json:"_meta"` //nolint:tagliatelle // the protocol names it _meta
}

// idArguments are the arguments of a tool that takes only an id.
type idArguments struct {
	ID string `json:"id"`
}

// noArgumentsBody is what a tool is read as when it is sent no arguments at all.
func noArgumentsBody() []byte { return []byte("{}") }

// callTool answers "tools/call": an unknown tool or params that are not a call
// are errors of the protocol; arguments the tool refuses are an error of the
// tool, in a result the model can read and correct.
func (h *handlers) callTool(call *auth.Call, msg message) result.Result[httpapi.Response] {
	params, err := httpapi.DecodeBody[callParams](msg.Params).Get()
	if err != nil {
		return result.Ok(protocolFailure(http.StatusOK, msg.ID, codeInvalidParams, "invalid params"))
	}

	var chosen *tool

	for _, t := range tools() {
		if t.name == params.Name {
			chosen = &t

			break
		}
	}

	if chosen == nil {
		return result.Ok(protocolFailure(http.StatusOK, msg.ID, codeInvalidParams, "unknown tool"))
	}

	path, body, err := chosen.request(params.Arguments)
	if err != nil {
		return result.Ok(answer(msg.ID, refused(err)))
	}

	local, err := h.do(call.Request.Context, chosen.method, path, body, call.Request.Authorization)
	if err != nil {
		return result.Fail[httpapi.Response](err)
	}

	return result.Ok(answer(msg.ID, outcome(local)))
}

// request is the path and body of the request to the tool's route for the
// given arguments, or the refusal of arguments the tool does not take.
func (t tool) request(raw json.RawMessage) (string, []byte, error) {
	if raw == nil {
		raw = noArgumentsBody()
	}

	switch t.args {
	case bodyArguments:
		return t.path, raw, nil
	case idArgument:
		id, err := httpapi.DecodeBody[idArguments](raw).Then(func(a idArguments) (input.ID, error) {
			return input.ParseID(a.ID)
		}).Get()
		if err != nil {
			return "", nil, err //nolint:wrapcheck // the classified client error is the tool's refusal
		}

		return strings.Replace(t.path, idPlaceholder, id.String(), 1), nil, nil
	case noArguments:
	}

	_, err := httpapi.DecodeBody[struct{}](raw).Get()

	return t.path, nil, err //nolint:wrapcheck // the classified client error is the tool's refusal
}

// content is one piece of a tool's result.
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolResult is the result of "tools/call": what the route answered, as text a
// model reads and, for a success, as the structured content a harness may
// parse. isError is true for any status of 400 or more, so a refusal (a missing
// scope, an id no invitation has) is read as a failed call and not a result.
type toolResult struct {
	Content           []content       `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError"`
}

// outcome is the tool result for what the route answered.
func outcome(local httpapi.LocalResponse) toolResult {
	text := bytes.TrimRight(local.Body, "\n")
	out := toolResult{
		Content: []content{{Type: "text", Text: string(text)}}, StructuredContent: nil,
		IsError: local.Status >= http.StatusBadRequest,
	}

	if !out.IsError && json.Valid(text) {
		out.StructuredContent = text
	}

	return out
}

// refused is the tool result for arguments the tool does not take. The text is
// the REST error's body, so a client reads one format whether the tool or the
// route refused.
func refused(err error) toolResult {
	text := bytes.TrimRight(httpapi.FailureBody(apierr.As(err)), "\n")

	return toolResult{Content: []content{{Type: "text", Text: string(text)}}, StructuredContent: nil, IsError: true}
}
