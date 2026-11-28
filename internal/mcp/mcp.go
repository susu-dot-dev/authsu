// Package mcp is the admin MCP endpoint (docs/mcp_design.md): one POST route,
// /mcp, that speaks JSON-RPC 2.0 to a coding harness and offers tools to manage
// invitations, accounts, organizations and their members, each of which is one
// of authsu's own REST routes under a name and a schema.
//
// # A tool is a request to a route
//
// A tool call is not handled here. It is turned into the request the REST route
// takes (a method, a path, a JSON body) and sent through the same route table,
// in process, with the caller's own Authorization header (httpapi.Local). The
// route then does everything it does for any caller: it resolves the
// credential, requires the administrator role and the route's scope, parses the
// body into its own types and answers in its own format. This package parses
// nothing a route parses, and decides nothing about who may do what: the only
// access rule is the route's declaration, so a tool can never do more than the
// caller's key could do over REST.
//
// /mcp itself declares auth.Open(): a valid credential and nothing more. That is
// the one place a route's declaration is not its whole access rule, and it is
// why every tool is in a table the route-table tests range over (see the app
// package's seam tests): a tool that did not name a route that refuses a member
// would be a hole.
//
// A tool's arguments become the request in one of a few ways (the arguments
// type of tools.go): none, an id, the route's JSON body as it came, an id with
// one body member, a page (limit and cursor, parsed by the route's own parsers
// before they are written into the query), and an account's id or the word "me",
// which reaches the route of the caller's own account. In every way a value the
// route parses is parsed by the route's parser, so a tool and a route refuse the
// same input with the same code.
//
// Only an API key is accepted. The REST routes are reached with the
// Authorization header alone, so a browser session (a cookie) would pass this
// route and fail inside, and a request that carries one is refused up front.
//
// # What it speaks
//
// The tools-only subset of MCP over Streamable HTTP, as a stateless server: one
// JSON object in, one JSON object out, no session id, no stream. A request that
// has an id is answered with 200 and a JSON-RPC response (an error of the
// protocol is a JSON-RPC error; an error of a tool is a result with isError, so
// the model can read it). A notification is answered 202 with no body. Batches
// are not supported (the 2025-06-18 revision removed them). GET answers 405,
// which tells a client there is no server-to-server stream.
//
// The protocol versions served are the ones that open with "initialize"
// (2025-03-26 to 2025-11-25). The newest revision replaces that handshake and
// is not served: a client that tries it first gets a JSON-RPC error and falls
// back.
//
// # Secrets
//
// Invitation codes pass through a model, whose provider keeps its inputs and
// outputs, so the create tool never returns one: the REST route answers an API
// key only with a code sealed to the publicKey the call carries (auth.Recipient),
// and the tool forwards publicKey as an argument and returns what the route
// returned.
package mcp

import (
	"context"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Path is the endpoint.
const Path = "/mcp"

// MaxBody is the largest JSON-RPC message the route reads, in bytes. A tool's
// arguments are a few short fields, so this is generous and no more.
const MaxBody = 16 << 10

// ServerName and ServerVersion identify the server to a client. The version is
// the version of the tool surface, raised when a tool is added, removed or
// changes what it takes.
const (
	ServerName    = "authsu"
	ServerVersion = "2"
)

// CodeAPIKeyRequired is a request to /mcp made with a credential that is not an
// API key.
const CodeAPIKeyRequired = "api_key_required"

// Do sends a request through the REST routes and returns the answer
// (httpapi.Local in production). It is a dependency so a test can answer for
// the routes, and make the call fail, which a valid request never does.
type Do func(
	ctx context.Context, method, path string, body []byte, authorization []string,
) (httpapi.LocalResponse, error)

// Deps are the collaborators of the route. Do is required, and Routes panics
// when it is missing.
type Deps struct {
	Do Do
}

// Routes returns the one route of the endpoint. It panics when a dependency is
// missing, a programming error.
func Routes(deps Deps) []auth.Route {
	if deps.Do == nil {
		panic("mcp: Deps.Do is required")
	}

	h := &handlers{do: deps.Do}

	return []auth.Route{{
		Method: http.MethodPost, Path: Path, MaxBody: MaxBody, Media: httpapi.MediaJSON, Errors: httpapi.ErrorsAPI,
		Credential: auth.Authenticated, Access: auth.Open(), Handle: h.serve,
	}}
}

// handlers carries the dependencies of the route handler.
type handlers struct {
	do Do
}

// serve answers POST /mcp: an API key's JSON-RPC message.
func (h *handlers) serve(call *auth.Call) result.Result[httpapi.Response] {
	if call.Principal.Kind != auth.KindAPIKey {
		return result.Fail[httpapi.Response](
			apierr.New(apierr.Forbidden, CodeAPIKeyRequired, "the MCP endpoint is called with an API key"))
	}

	msg, err := httpapi.Decode[message](call.Request).Get()
	if err != nil {
		return result.Ok(undecodable(err))
	}

	if refused := msg.refusal(); refused != nil {
		return result.Ok(*refused)
	}

	// A notification is never answered, whatever it names.
	if msg.ID == nil {
		return result.Ok(httpapi.Response{Status: http.StatusAccepted, Body: nil, Location: "", Cookies: nil})
	}

	switch msg.Method {
	case "initialize":
		return result.Ok(initialize(msg))
	case "ping":
		return result.Ok(answer(msg.ID, struct{}{}))
	case "tools/list":
		return result.Ok(answer(msg.ID, toolList()))
	case "tools/call":
		return h.callTool(call, msg)
	default:
		return result.Ok(protocolFailure(http.StatusOK, msg.ID, codeMethodNotFound, "method not found"))
	}
}

// undecodable is the answer to a body that could not be decoded as a message:
// text that is not JSON is a parse error, and JSON that is not a message of the
// protocol is an invalid request. The id is null, as JSON-RPC says when it
// could not be read.
func undecodable(err error) httpapi.Response {
	switch apierr.As(err).Code {
	case "invalid_json", "empty_body", "trailing_data":
		return protocolFailure(http.StatusBadRequest, nil, codeParseError, "parse error")
	default:
		return protocolFailure(http.StatusBadRequest, nil, codeInvalidRequest, "invalid request")
	}
}
