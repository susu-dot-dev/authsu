package mcp

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

// JSON-RPC 2.0 error codes the endpoint answers with.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// jsonRPC is the only version of the framing there is.
const jsonRPC = "2.0"

// message is a JSON-RPC request or notification as a client sent it. A member
// the protocol does not name is refused, as every body this service reads is.
// Params stays JSON: each method reads its own (see Decode in httpapi).
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// refusal is the answer to a message that is not a request or notification of
// the protocol, or nil when it is one: the version must be "2.0", the method
// present, and an id, when there is one, a string or a number (never null,
// which MCP forbids).
func (m message) refusal() *httpapi.Response {
	if m.JSONRPC == jsonRPC && m.Method != "" && (m.ID == nil || validID(m.ID)) {
		return nil
	}

	refused := protocolFailure(http.StatusBadRequest, nil, codeInvalidRequest, "invalid request")

	return &refused
}

// validID reports whether raw, the text of an id, is a JSON string or number.
func validID(raw json.RawMessage) bool {
	switch first := raw[0]; {
	case first == '"', first == '-', first >= '0' && first <= '9':
		return true
	default:
		return false
	}
}

// success is a response that carries a result.
type success struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

// failure is a response that carries an error of the protocol.
type failure struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcError        `json:"error"`
}

// rpcError is the error of a failure.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// answer is the 200 response to request id, carrying result.
func answer(id json.RawMessage, result any) httpapi.Response {
	return httpapi.JSON(http.StatusOK, success{JSONRPC: jsonRPC, ID: id, Result: result})
}

// protocolFailure is a response that carries an error of the protocol. A
// request whose id could not be read is answered with a null id, as JSON-RPC
// says.
func protocolFailure(status int, id json.RawMessage, code int, text string) httpapi.Response {
	if id == nil {
		id = json.RawMessage("null")
	}

	return httpapi.JSON(status, failure{JSONRPC: jsonRPC, ID: id, Error: rpcError{Code: code, Message: text}})
}

// versions are the protocol versions the endpoint speaks, newest first. All of
// them open with "initialize".
func versions() []string { return []string{"2025-11-25", "2025-06-18", "2025-03-26"} }

// initializeParams are the params of "initialize" that the endpoint reads. The
// client's capabilities and info are accepted and not used: the server offers
// tools whatever the client can do.
type initializeParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities"`
	ClientInfo      json.RawMessage `json:"clientInfo"`
	Meta            json.RawMessage `json:"_meta"` //nolint:tagliatelle // the protocol names it _meta
}

// initialize answers the opening of a session: the version the client asked
// for when it is one of the server's, or the server's newest when it is not
// (the client then decides whether it can speak that), the one capability, and
// who the server is.
func initialize(msg message) httpapi.Response {
	params, err := httpapi.DecodeBody[initializeParams](msg.Params).Get()
	if err != nil || params.ProtocolVersion == "" {
		return protocolFailure(http.StatusOK, msg.ID, codeInvalidParams, "invalid params")
	}

	spoken := versions()

	version := spoken[0]
	if slices.Contains(spoken, params.ProtocolVersion) {
		version = params.ProtocolVersion
	}

	return answer(msg.ID, map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]string{"name": ServerName, "version": ServerVersion},
	})
}
