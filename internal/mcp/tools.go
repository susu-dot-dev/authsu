package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
	// idBodyArguments is a tool that takes the id of the item the route's path
	// names (parsed as for idArgument) and, beside it, the route's JSON body: the
	// arguments without the id, sent as they came. The route parses the body.
	idBodyArguments
	// pageArguments is a tool that takes an optional limit and cursor, which
	// are the query of a list route. Each is parsed (input.ParsePageLimit,
	// input.ParseCursor) before it is written, so what reaches the route is
	// exactly what its own parsers accept.
	pageArguments
	// idPageArguments is pageArguments for a list that belongs to the item the
	// route's path names: the id is parsed as for idArgument.
	idPageArguments
	// userArgument is a tool that takes the id of an account or the word "me":
	// "me" reaches the route that answers for the caller's own account (the
	// tool's selfPath), and anything else must be an id, as for idArgument.
	userArgument
)

// mePlaceholder is the one argument of userArgument that is not an id: the
// caller's own account.
const mePlaceholder = "me"

// idPlaceholder is where the id goes in the path of a tool that takes one.
const idPlaceholder = "{id}"

// The schemas of the paging arguments, shared by every list tool. The bounds are
// the ones of the parsers the route applies (input.MaxPageLimit), which refuse
// anything outside them again.
const (
	limitProperty = `"limit":{"type":"integer","minimum":1,"maximum":100,` +
		`"description":"How many to return, from 1 to 100. Defaults to 25."}`
	cursorProperty = `"cursor":{"type":"string",` +
		`"description":"Where to resume: the next member of the previous page. Leave out for the first page."}`
)

// tool is one tool: the route it reaches and what a client is told about it.
type tool struct {
	name, title, description string
	// schema is the JSON Schema of the arguments.
	schema json.RawMessage
	// method and path are the route, as declared in its feature.
	method, path string
	// selfPath is the route of a userArgument tool for "me".
	selfPath string
	// bodyMember is the one member of the JSON body of an idBodyArguments tool,
	// beside its id: what is being set on the item the path names.
	bodyMember string
	args       arguments
	// readOnly and destructive are the hints a harness may use to decide whether
	// to ask before calling: a read changes nothing; a revoke cannot be undone.
	readOnly, destructive bool
	// repeatable is whether calling again with the same arguments has no further
	// effect: true of a read, of a revoke (which keeps the first revocation) and
	// of setting a value (a rename, an administrator flag), and false of a create,
	// which makes another each time.
	repeatable bool
}

// tools are the tools, in the order they are listed: invitations, then accounts,
// then organizations, then their members. Each names the route it reaches: the
// route's own declaration, not this table, decides who may call it, and the app
// package's seam tests send every tool to that route as an admin, as a member and
// as a key without its scope.
func tools() []tool {
	return slices.Concat(invitationTools(), userTools(), orgTools(), memberTools())
}

// invitationTools are the tools of the invitation routes (docs/invitations_design.md).
func invitationTools() []tool {
	return []tool{
		{
			name: "list_invitations", title: "List invitations",
			description: "List every invitation, newest first, with how many accounts each has created, its status " +
				"and its expiry. Revoked invitations are included.",
			schema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			method: http.MethodGet, path: "/api/invitation", args: noArguments,
			readOnly: true, destructive: false, repeatable: true,
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
			readOnly: true, destructive: false, repeatable: true,
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
			method: http.MethodPost, path: "/api/invitation", args: bodyArguments,
			readOnly: false, destructive: false, repeatable: false,
		},
		{
			name: "revoke_invitation", title: "Revoke an invitation",
			description: "Revoke an invitation so that nobody can register with it from now on. Accounts it already " +
				"created are not affected. Revoking one that is already revoked succeeds and changes nothing.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The invitation's id."}},"required":["id"],"additionalProperties":false}`),
			method: http.MethodDelete, path: "/api/invitation/" + idPlaceholder, args: idArgument,
			readOnly: false, destructive: true, repeatable: true,
		},
	}
}

// userTools are the tools of the account routes (docs/users_design.md).
func userTools() []tool {
	return []tool{
		{
			name: "list_users", title: "List users",
			description: "List accounts, newest first, one page at a time, revoked ones included. Each has its " +
				"role, the invitation it came from, its profile and whether it is active or revoked. When the " +
				"answer has a next member, pass it as cursor to read the following page.",
			schema: json.RawMessage(`{"type":"object","properties":{` + limitProperty + `,` + cursorProperty +
				`},"additionalProperties":false}`),
			method: http.MethodGet, path: "/api/user", args: pageArguments,
			readOnly: true, destructive: false, repeatable: true,
		},
		{
			name: "get_user", title: "Get a user",
			description: "Read one account: its role, the invitation it came from, its profile and whether it is " +
				"active or revoked. Pass the id \"me\" for the account of the credential making the call, which " +
				"is how an administrator reads their own profile.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The account's id, as list_users returns it, or \"me\" for the caller's own."}},` +
				`"required":["id"],"additionalProperties":false}`),
			method: http.MethodGet, path: "/api/user/" + idPlaceholder, selfPath: "/api/user/me", args: userArgument,
			readOnly: true, destructive: false, repeatable: true,
		},
		{
			name: "revoke_user", title: "Revoke a user",
			description: "Revoke an account. This is final and cannot be undone: the account can no longer sign " +
				"in and its sessions, keys and agents stop working at once, and a person let back in is a new " +
				"account. It stays listed, as revoked. The last active administrator cannot be revoked. Revoking " +
				"one that is already revoked succeeds and keeps the first time.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The account's id."}},"required":["id"],"additionalProperties":false}`),
			method: http.MethodDelete, path: "/api/user/" + idPlaceholder, args: idArgument,
			readOnly: false, destructive: true, repeatable: true,
		},
	}
}

// orgTools are the tools of the organization routes (docs/orgs_design.md). Who
// may act on an organization is decided by the route, in the write, and not by
// the administrator role alone.
func orgTools() []tool {
	return []tool{
		{
			name: "list_orgs", title: "List organizations",
			description: "List organizations and sandboxes, newest first, one page at a time. An administrator " +
				"sees every one. Each has its kind (standard or sandbox), name, who created it and its status " +
				"(active or expired). When the answer has a next member, pass it as cursor to read the " +
				"following page.",
			schema: json.RawMessage(`{"type":"object","properties":{` + limitProperty + `,` + cursorProperty +
				`},"additionalProperties":false}`),
			method: http.MethodGet, path: "/api/org", args: pageArguments,
			readOnly: true, destructive: false, repeatable: true,
		},
		{
			name: "get_org", title: "Get an organization",
			description: "Read one organization or sandbox: its kind, name, who created it, when it expires " +
				"(sandboxes only) and its status.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The organization's id, as list_orgs returns it."}},` +
				`"required":["id"],"additionalProperties":false}`),
			method: http.MethodGet, path: "/api/org/" + idPlaceholder, args: idArgument,
			readOnly: true, destructive: false, repeatable: true,
		},
		{
			name: "rename_org", title: "Rename an organization",
			description: "Rename an organization or a sandbox. An expired sandbox cannot be renamed.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The organization's id."},"name":{"type":"string",` +
				`"description":"The new name."}},"required":["id","name"],"additionalProperties":false}`),
			method: http.MethodPatch, path: "/api/org/" + idPlaceholder, args: idBodyArguments,
			bodyMember: "name", readOnly: false, destructive: false, repeatable: true,
		},
		{
			name: "delete_sandbox", title: "Delete a sandbox",
			description: "Delete a sandbox and everything in it, its agents included. This cannot be undone. A " +
				"standard organization is never deleted and is refused.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The sandbox's id."}},"required":["id"],"additionalProperties":false}`),
			method: http.MethodDelete, path: "/api/org/" + idPlaceholder, args: idArgument,
			readOnly: false, destructive: true, repeatable: false,
		},
	}
}

// memberTools are the tools of the member routes: who belongs to an organization,
// who administers it, and revoking an account through it.
func memberTools() []tool {
	return []tool{
		{
			name: "list_org_members", title: "List the members of an organization",
			description: "List the members of a standard organization, newest first, one page at a time, revoked " +
				"ones included. Each says whether it administers the organization. A sandbox has no members. " +
				"When the answer has a next member, pass it as cursor to read the following page.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The organization's id, as list_orgs returns it."},` + limitProperty + `,` +
				cursorProperty + `},"required":["id"],"additionalProperties":false}`),
			method: http.MethodGet, path: "/api/org/" + idPlaceholder + "/member", args: idPageArguments,
			readOnly: true, destructive: false, repeatable: true,
		},
		{
			name: "set_member_admin", title: "Make a member an administrator, or not",
			description: "Make a member an administrator of their organization, or stop them being one. " +
				"Promoting an administrator and demoting a member change nothing. A revoked member cannot be " +
				"promoted, and an organization's last unrevoked administrator cannot be demoted.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The member's user id, as list_org_members returns it."},` +
				`"admin":{"type":"boolean","description":"true to make them an administrator, false to stop."}},` +
				`"required":["id","admin"],"additionalProperties":false}`),
			method: http.MethodPatch, path: "/api/member/" + idPlaceholder, args: idBodyArguments,
			bodyMember: "admin", readOnly: false, destructive: false, repeatable: true,
		},
		{
			name: "revoke_member", title: "Revoke a member",
			description: "Revoke the account of a member of an organization. This is final and cannot be " +
				"undone, as for revoke_user: the account can no longer sign in and everything it holds stops " +
				"working at once. The last active platform administrator cannot be revoked.",
			schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string",` +
				`"description":"The member's user id, as list_org_members returns it."}},` +
				`"required":["id"],"additionalProperties":false}`),
			method: http.MethodDelete, path: "/api/member/" + idPlaceholder, args: idArgument,
			readOnly: false, destructive: true, repeatable: true,
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
				IdempotentHint: t.repeatable, OpenWorldHint: false,
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

// pageArguments are the arguments of a tool that lists a page. Both are
// optional, and are strings as the REST query parameters are, so that what a
// client sends is parsed by the same parsers whichever way it asks.
type pageParams struct {
	Limit  *int64  `json:"limit"`
	Cursor *string `json:"cursor"`
}

// idPageParams are pageParams for a list that belongs to an item.
type idPageParams struct {
	ID     string  `json:"id"`
	Limit  *int64  `json:"limit"`
	Cursor *string `json:"cursor"`
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
		return t.withID(raw)
	case idBodyArguments:
		return t.withIDAndBody(raw)
	case pageArguments:
		return t.paged(raw)
	case idPageArguments:
		return t.pagedWithID(raw)
	case userArgument:
		return t.forUser(raw)
	case noArguments:
	}

	_, err := httpapi.DecodeBody[struct{}](raw).Get()

	return t.path, nil, err //nolint:wrapcheck // the classified client error is the tool's refusal
}

// withID is the request of a tool that takes only an id.
func (t tool) withID(raw json.RawMessage) (string, []byte, error) {
	id, err := httpapi.DecodeBody[idArguments](raw).Then(func(a idArguments) (input.ID, error) {
		return input.ParseID(a.ID)
	}).Get()
	if err != nil {
		return "", nil, err //nolint:wrapcheck // the classified client error is the tool's refusal
	}

	return strings.Replace(t.path, idPlaceholder, id.String(), 1), nil, nil
}

// forUser is the request of a tool that takes an account's id, or "me".
func (t tool) forUser(raw json.RawMessage) (string, []byte, error) {
	arg, err := httpapi.DecodeBody[idArguments](raw).Get()
	if err != nil {
		return "", nil, err //nolint:wrapcheck // the classified client error is the tool's refusal
	}

	// Only the exact word: "ME" or " me" is not an id and is refused as one.
	if arg.ID == mePlaceholder {
		return t.selfPath, nil, nil
	}

	return t.withID(raw)
}

// withIDAndBody is the request of a tool that takes an id and the one member of
// the route's body. The arguments are read strictly (an unknown or repeated
// member is refused, as it is for a route) and may hold only the id and the
// tool's bodyMember. The id goes in the path, parsed. The member, when sent, is
// written into the body exactly as it came, and when not sent the body is empty,
// so the route says what is missing, in its own code.
func (t tool) withIDAndBody(raw json.RawMessage) (string, []byte, error) {
	members, err := httpapi.DecodeBody[map[string]json.RawMessage](raw).Get()
	if err != nil {
		return "", nil, err //nolint:wrapcheck // the classified client error is the tool's refusal
	}

	for name := range members {
		if name != "id" && name != t.bodyMember {
			return "", nil, unknownArgument()
		}
	}

	idText, hasID := members["id"]
	if !hasID {
		idText = json.RawMessage(`""`)
	}

	path, _, err := t.withID(append(append([]byte(`{"id":`), idText...), '}'))
	if err != nil {
		return "", nil, err
	}

	value, sent := members[t.bodyMember]
	if !sent {
		return path, []byte("{}"), nil
	}

	return path, []byte("{" + strconv.Quote(t.bodyMember) + ":" + string(value) + "}"), nil
}

// unknownArgument is the refusal of an argument the tool does not take, in the
// code the strict decoder gives for an unknown member of a body.
func unknownArgument() *apierr.Error {
	return apierr.New(apierr.BadRequest, "unknown_field", "request body has an unknown field")
}

// paged is the request of a tool that lists a page.
func (t tool) paged(raw json.RawMessage) (string, []byte, error) {
	query, err := httpapi.DecodeBody[pageParams](raw).Then(func(p pageParams) (string, error) {
		return pageQuery(p.Limit, p.Cursor)
	}).Get()
	if err != nil {
		return "", nil, err //nolint:wrapcheck // the classified client error is the tool's refusal
	}

	return t.path + query, nil, nil
}

// pagedWithID is the request of a tool that lists a page of an item's.
func (t tool) pagedWithID(raw json.RawMessage) (string, []byte, error) {
	path, err := httpapi.DecodeBody[idPageParams](raw).Then(func(p idPageParams) (string, error) {
		id, idErr := input.ParseID(p.ID)
		if idErr != nil {
			return "", idErr //nolint:wrapcheck // the parser's error is the classified client error
		}

		query, queryErr := pageQuery(p.Limit, p.Cursor)

		return strings.Replace(t.path, idPlaceholder, id.String(), 1) + query, queryErr
	}).Get()
	if err != nil {
		return "", nil, err //nolint:wrapcheck // the classified client error is the tool's refusal
	}

	return path, nil, nil
}

// pageQuery is the query string of a list for the limit and cursor a tool was
// given, or "" for neither. Each is parsed by the parser the route uses, so a
// value the route would refuse is refused here with the same code, and each is
// written back as the parser read it, escaped, so what is sent cannot add or
// change a parameter.
func pageQuery(limit *int64, cursor *string) (string, error) {
	values := url.Values{}

	if limit != nil {
		text := strconv.FormatInt(*limit, 10)

		parsed, err := input.ParsePageLimit([]string{text})
		if err != nil {
			return "", err //nolint:wrapcheck // the parser's error is the classified client error
		}

		values.Set("limit", strconv.Itoa(parsed.Int()))
	}

	if cursor != nil {
		parsed, err := input.ParseCursor([]string{*cursor})
		if err != nil {
			return "", err //nolint:wrapcheck // the parser's error is the classified client error
		}

		if id, set := parsed.ID(); set {
			values.Set("cursor", id.String())
		}
	}

	if len(values) == 0 {
		return "", nil
	}

	return "?" + values.Encode(), nil
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
