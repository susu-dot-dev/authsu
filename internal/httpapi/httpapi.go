// Package httpapi is the boundary between net/http and the rest of the code.
//
// Handlers are pure functions from a Request to a Result[Response]: they never
// see an http.ResponseWriter and never choose a status for a failure. Serve
// wraps a handler as an http.Handler and does everything that touches HTTP,
// once: method check, reading the request, converting a failure into a status
// and JSON body, logging it, and writing headers.
//
// Serve is the only place that does this, so the contract holds for every route:
//
//   - A route whose method is not GET or HEAD requires the request's
//     Content-Type to be application/json, even when the body is empty (415
//     unsupported_media_type, checked after the method and before the body is
//     read). That type forces a CORS preflight, which fails for every origin
//     but the one CORS allows, so another site cannot make a browser deliver
//     such a request: this is the CSRF defence for every unsafe route (see
//     isJSON and CORS).
//   - A request body is capped at 1 MiB (413 body_too_large), or at a smaller
//     limit a route asks for with ServeLimited.
//   - A handler runs inside a recover, so a panic still gets the JSON error
//     contract and a log line, as Internal handler_panic.
//   - Responses carry Content-Type and Cache-Control: no-store, and the status
//     is written once. A Status outside 200-599 is an Internal invalid_status
//     error rather than a panic in net/http.
//   - A failure is sent as {"error":{"code","message","data?"}}. The logger gets
//     the request and the full error, cause included. An error that was never
//     classified, or is Internal, is sent as a bare "internal" with no data, so
//     causes, SQL and table names never reach a client.
//   - Unknown paths are answered by NotFound registered on "/", so they too use
//     the JSON envelope.
//
// Routes are registered as plain paths, optionally with {name} wildcards
// (see Request.PathValues): TinyGo's http.ServeMux ignores method-qualified
// patterns, so Serve does the method check instead, and ServeMethods lets one
// path answer several methods.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// maxBodyBytes caps how much of a request body is read.
const maxBodyBytes = 1 << 20

// DefaultMaxBody is the cap on a request body for a route that does not ask for
// a smaller one.
const DefaultMaxBody = maxBodyBytes

// Request is the part of an HTTP request a handler may use.
type Request struct {
	// Method and Path identify the request in logs.
	Method string
	Path   string
	// Context is cancelled when the client goes away.
	Context context.Context //nolint:containedctx // a request value is the unit that carries its context
	// Query holds the URL query parameters.
	Query map[string][]string
	// PathValues holds the values of the route's path wildcards, by name: for
	// a route registered as "/x/{id}", PathValues["id"]. It is empty for a route
	// with none.
	PathValues map[string]string
	// Body is the raw request body, read up to a fixed limit.
	Body []byte
	// Cookies are the request's cookies.
	Cookies []*http.Cookie
}

// Response is what a successful handler returns.
type Response struct {
	// Status is the HTTP status code.
	Status int
	// Body is marshalled to JSON. Nil means no body.
	Body any
	// Cookies are sent as Set-Cookie headers. A handler builds each one in
	// full (name, attributes, expiry), so what a cookie allows is decided in
	// one place, beside the code that issues it.
	Cookies []*http.Cookie
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
	return Response{Status: status, Body: body, Cookies: nil}
}

// WithCookies returns r that also sets cookies.
func (r Response) WithCookies(cookies ...*http.Cookie) Response {
	r.Cookies = cookies

	return r
}

// Decode parses the request body as a T. Malformed input is a BadRequest with
// a code that says what was wrong. Member names must match exactly and appear
// once, and text must be valid UTF-8 (see checkStrict), so the body means the
// same thing to every parser. Unknown members are rejected so a typo in a
// client is not silently ignored.
func Decode[T any](req Request) result.Result[T] {
	var out T

	strict := json.NewDecoder(bytes.NewReader(req.Body))
	strict.UseNumber() // a number is checked, not converted, so none can overflow here

	err := checkStrict(strict, reflect.TypeFor[T]())
	if err != nil {
		return result.Fail[T](decodeError(err))
	}

	decoder := json.NewDecoder(bytes.NewReader(req.Body))
	// checkStrict has already refused unknown members; this is a backstop.
	decoder.DisallowUnknownFields()

	err = decoder.Decode(&out)
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

	switch {
	case errors.Is(err, errUnknownMember):
		return apierr.New(apierr.BadRequest, "unknown_field", "request body has an unknown field").WithCause(err)
	case errors.Is(err, errTooManyItems):
		return apierr.New(apierr.BadRequest, "too_many_items", "request body has an array with too many items").WithCause(err)
	case errors.Is(err, errDuplicateMember):
		return apierr.New(apierr.BadRequest, "duplicate_field", "request body repeats a field").WithCause(err)
	case errors.Is(err, errInvalidText):
		return apierr.New(apierr.BadRequest, "invalid_text", "request body has text that is not valid UTF-8").WithCause(err)
	}

	return apierr.New(apierr.BadRequest, "invalid_json", "request body is not valid JSON").WithCause(err)
}

// Serve returns an http.Handler that runs handler for requests using method,
// and answers every other method with 405 and an Allow header. A panic in the
// handler is recovered and reported as an Internal error.
func Serve(method string, logger Logger, handler Handler) http.Handler {
	return serve([]string{method}, maxBodyBytes, logger, handler)
}

// ServeLimited is Serve for a route whose legitimate bodies are small: a body
// over maxBody bytes is refused with 413 body_too_large, and never read past
// that, so a client cannot make the route spend time on a megabyte it could
// never use. maxBody is clamped to DefaultMaxBody, so a route can only tighten
// the cap, never raise it.
func ServeLimited(method string, maxBody int64, logger Logger, handler Handler) http.Handler {
	return serve([]string{method}, min(maxBody, maxBodyBytes), logger, handler)
}

// ServeMethods is Serve for one path that answers several methods, each with
// its own handler. The routes map is keyed by method; any other method gets 405
// with an Allow header listing the keys, sorted. Every rule in the package doc
// applies per method, so a method that is not GET or HEAD still requires
// Content-Type: application/json.
//
// wildcards names the {name} wildcards in the path the handler is registered
// for. net/http can only look a wildcard up by name, not list them, so the
// caller says which to copy into Request.PathValues.
//
// It exists because TinyGo's http.ServeMux cannot route by method: a path is
// registered once, and the method is chosen here.
func ServeMethods(logger Logger, wildcards []string, routes map[string]Handler) http.Handler {
	methods := slices.Sorted(maps.Keys(routes))

	return serveWith(methods, wildcards, maxBodyBytes, logger, func(req Request) result.Result[Response] {
		return routes[req.Method](req)
	})
}

// ServeAny is Serve for a handler that accepts every method.
func ServeAny(logger Logger, handler Handler) http.Handler {
	return serve(nil, maxBodyBytes, logger, handler)
}

// serve implements Serve. No methods accepts every method.
func serve(methods []string, maxBody int64, logger Logger, handler Handler) http.Handler {
	return serveWith(methods, nil, maxBody, logger, handler)
}

// serveWith is serve for a route whose path has the named wildcards.
func serveWith(methods, wildcards []string, maxBody int64, logger Logger, handler Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")

		request := Request{
			Method:     req.Method,
			Path:       req.URL.Path,
			Context:    req.Context(),
			Query:      req.URL.Query(),
			PathValues: pathValues(req, wildcards),
			Body:       nil,
			Cookies:    req.Cookies(),
		}

		if len(methods) > 0 && !slices.Contains(methods, req.Method) {
			writer.Header().Set("Allow", strings.Join(methods, ", "))
			write(writer, logger, request, result.Fail[Response](
				apierr.New(apierr.MethodNotAllowed, "method_not_allowed", "method not allowed")))

			return
		}

		if len(methods) > 0 && !safeMethod(req.Method) && !isJSON(req.Header.Values("Content-Type")) {
			write(writer, logger, request, result.Fail[Response](
				apierr.New(apierr.UnsupportedMediaType, "unsupported_media_type",
					"request Content-Type must be application/json")))

			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(writer, req.Body, maxBody))
		if err != nil {
			write(writer, logger, request, result.Fail[Response](bodyReadError(err)))

			return
		}

		request.Body = body

		write(writer, logger, request, safely(handler, request))
	})
}

// pathValues returns the value the mux matched for each named wildcard.
// A wildcard that matched nothing is absent; the map itself is never nil.
func pathValues(req *http.Request, wildcards []string) map[string]string {
	values := make(map[string]string, len(wildcards))

	for _, name := range wildcards {
		if value := req.PathValue(name); value != "" {
			values[name] = value
		}
	}

	return values
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

	for _, cookie := range resp.Cookies {
		http.SetCookie(writer, cookie)
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

// safeMethod reports whether method is GET or HEAD, which change nothing and
// so need no Content-Type.
func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// jsonMediaType is the only Content-Type an unsafe request may carry.
const jsonMediaType = "application/json"

// isJSON reports whether values, a request's Content-Type header lines, are
// exactly one application/json, optionally with charset=utf-8 (JSON is UTF-8,
// RFC 8259). Anything else is refused: a missing header, a second line, any
// other type, any other parameter.
//
// This is the CSRF defence. application/json is not a CORS-safelisted type, so
// a browser cannot send it cross-origin without a preflight, and the
// preflight fails because CORS answers it only for the one allowed origin
// (the UI), never for another site. HTML forms
// cannot send it at all. Requiring it on every unsafe request, even one with
// an empty body, means no other site can make a browser deliver a request this
// boundary will hand to a handler, whatever the handler does with the body.
func isJSON(values []string) bool {
	if len(values) != 1 {
		return false
	}

	media, params, hasParams := strings.Cut(values[0], ";")
	if !strings.EqualFold(strings.TrimSpace(media), jsonMediaType) {
		return false
	}

	if !hasParams {
		return true
	}

	for param := range strings.SplitSeq(params, ";") {
		if !strings.EqualFold(strings.TrimSpace(param), "charset=utf-8") {
			return false
		}
	}

	return true
}
