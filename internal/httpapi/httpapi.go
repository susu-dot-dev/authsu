// Package httpapi is the boundary between net/http and the rest of the code.
//
// Handlers are pure functions from a Request to a Result[Response]: they never
// see an http.ResponseWriter and never choose a status for a failure. Serve
// wraps a handler as an http.Handler and does everything that touches HTTP,
// once: method check, reading the request, converting a failure into a status
// and JSON body, logging it, and writing headers.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// maxBodyBytes caps how much of a request body is read.
const maxBodyBytes = 1 << 20

// Request is the part of an HTTP request a handler may use.
type Request struct {
	// Method and Path identify the request in logs.
	Method string
	Path   string
	// Context is cancelled when the client goes away.
	Context context.Context //nolint:containedctx // a request value is the unit that carries its context
	// Query holds the URL query parameters.
	Query map[string][]string
	// Body is the raw request body, read up to a fixed limit.
	Body []byte
}

// Response is what a successful handler returns.
type Response struct {
	// Status is the HTTP status code.
	Status int
	// Body is marshalled to JSON. Nil means no body.
	Body any
}

// Handler is a pure request handler.
type Handler func(Request) result.Result[Response]

// Logger records an error that the boundary is about to turn into a response.
// It receives the request, so the entry can be tied to a route, and the full
// error detail, including the cause. The request's Body is not populated when
// the failure happened before the body was read.
type Logger func(Request, *apierr.Error)

// JSON returns a successful Response carrying body.
func JSON(status int, body any) Response {
	return Response{Status: status, Body: body}
}

// Decode parses the request body as a T. Malformed input is a BadRequest with
// a code that says what was wrong. Unknown fields are rejected so a typo in a
// client is not silently ignored.
func Decode[T any](req Request) result.Result[T] {
	var out T

	decoder := json.NewDecoder(bytes.NewReader(req.Body))
	decoder.DisallowUnknownFields()

	err := decoder.Decode(&out)
	if err != nil {
		return result.Fail[T](decodeError(err))
	}

	if decoder.More() {
		return result.Fail[T](apierr.New(apierr.BadRequest, "trailing_data", "request body has trailing data"))
	}

	return result.Ok(out)
}

// decodeError classifies a json decoding failure. The descriptions are fixed
// text: the raw json error can quote client input back, so it stays in the
// cause.
func decodeError(err error) *apierr.Error {
	if errors.Is(err, io.EOF) {
		return apierr.New(apierr.BadRequest, "empty_body", "request body is empty").WithCause(err)
	}

	if _, isType := errors.AsType[*json.UnmarshalTypeError](err); isType {
		return apierr.New(apierr.BadRequest, "invalid_field_type", "a field has the wrong type").WithCause(err)
	}

	if strings.HasPrefix(err.Error(), "json: unknown field") {
		return apierr.New(apierr.BadRequest, "unknown_field", "request body has an unknown field").WithCause(err)
	}

	return apierr.New(apierr.BadRequest, "invalid_json", "request body is not valid JSON").WithCause(err)
}

// Serve returns an http.Handler that runs handler for requests using method,
// and answers every other method with 405 and an Allow header. A panic in the
// handler is recovered and reported as an Internal error.
func Serve(method string, logger Logger, handler Handler) http.Handler {
	return serve(method, logger, handler)
}

// ServeAny is Serve for a handler that accepts every method.
func ServeAny(logger Logger, handler Handler) http.Handler {
	return serve("", logger, handler)
}

// serve implements Serve. An empty method accepts every method.
func serve(method string, logger Logger, handler Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")

		request := Request{
			Method:  req.Method,
			Path:    req.URL.Path,
			Context: req.Context(),
			Query:   req.URL.Query(),
			Body:    nil,
		}

		if method != "" && req.Method != method {
			writer.Header().Set("Allow", method)
			write(writer, logger, request, result.Fail[Response](
				apierr.New(apierr.MethodNotAllowed, "method_not_allowed", "method not allowed")))

			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(writer, req.Body, maxBodyBytes))
		if err != nil {
			write(writer, logger, request, result.Fail[Response](bodyReadError(err)))

			return
		}

		request.Body = body

		write(writer, logger, request, safely(handler, request))
	})
}

// bodyReadError classifies a failure to read the request body. Only the size
// cap is the client's doing; any other failure (a dropped connection, a
// transport fault) is not something the client can fix by changing the
// request, so it is an Internal error with its own code for the logs.
func bodyReadError(err error) *apierr.Error {
	if _, tooBig := errors.AsType[*http.MaxBytesError](err); tooBig {
		return apierr.New(apierr.PayloadTooLarge, "body_too_large", "request body is too large").WithCause(err)
	}

	return apierr.New(apierr.Internal, "body_read_failed", "request body could not be read").WithCause(err)
}

// safely runs handler and converts a panic into a failed Result, so the
// boundary's error contract (classified, logged, redacted JSON) holds even for
// a bug such as a nil step in a Result chain.
//
//nolint:nonamedreturns // recover can only change the result through a named return
func safely(handler Handler, req Request) (res result.Result[Response]) {
	defer func() {
		if recovered := recover(); recovered != nil {
			res = result.Fail[Response](panicError(recovered))
		}
	}()

	return handler(req)
}

// errInvalidStatus is the cause when a handler returns a status outside 200-599.
var errInvalidStatus = errors.New("handler returned an invalid status")

// errPanic is the cause of an Internal error that came from a recovered panic.
var errPanic = errors.New("handler panicked")

// panicError describes a recovered panic value.
func panicError(recovered any) *apierr.Error {
	return apierr.New(apierr.Internal, "handler_panic", "handler panicked").
		WithCause(fmt.Errorf("%w: %v", errPanic, recovered))
}

// write sends res, converting a failure into its error response.
func write(writer http.ResponseWriter, logger Logger, req Request, res result.Result[Response]) {
	resp, err := res.Get()
	if err == nil {
		err = send(writer, resp)
		if err == nil {
			return
		}
	}

	failure := apierr.As(err)
	logger(req, failure)

	// A failure while encoding the success body can only be reported as an
	// Internal error, and nothing has been written yet because send encodes
	// before it writes.
	data, marshalErr := marshalError(failure)
	if marshalErr != nil {
		// Unreachable for real values; keep the contract that something valid
		// is always written.
		data = []byte(`{"error":{"code":"internal","message":"internal error"}}` + "\n")
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(failure.Kind.Status())
	_, _ = writer.Write(data)
}

// send encodes and writes a successful response. It writes nothing when
// encoding fails, so the caller can still send an error response.
func send(writer http.ResponseWriter, resp Response) error {
	if resp.Status < http.StatusOK || resp.Status > 599 {
		return apierr.Wrap(fmt.Errorf("%w: %d", errInvalidStatus, resp.Status),
			apierr.Internal, "invalid_status", "internal error")
	}

	var data []byte

	if resp.Body != nil {
		var err error

		data, err = json.Marshal(resp.Body)
		if err != nil {
			return apierr.Wrap(err, apierr.Internal, "marshal_failed", "internal error")
		}

		data = append(data, '\n')
		writer.Header().Set("Content-Type", "application/json")
	}

	writer.WriteHeader(resp.Status)
	_, _ = writer.Write(data)

	return nil
}

// errorBody is the JSON shape of every error response.
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// marshalError builds the error body. Internal errors expose neither their
// description nor their data: both may mention internals.
func marshalError(failure *apierr.Error) ([]byte, error) {
	detail := errorDetail{Code: failure.Code, Message: failure.Description, Data: failure.Data}
	if failure.Kind == apierr.Internal {
		detail = errorDetail{Code: "internal", Message: "internal error", Data: nil}
	}

	data, err := json.Marshal(errorBody{Error: detail})
	if err != nil {
		return nil, err //nolint:wrapcheck // single call site; the caller replaces the body on any error
	}

	return append(data, '\n'), nil
}

// NotFound is a Handler that fails with a structured not_found error. Register
// it for "/" so an unknown path gets the same JSON error shape as every other
// failure.
func NotFound(Request) result.Result[Response] {
	return result.Fail[Response](apierr.New(apierr.NotFound, "not_found", "no such route"))
}
