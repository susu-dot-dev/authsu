// Package httpapi is the boundary between net/http and the rest of the code.
//
// Handlers are pure functions from a Request to a Result[Response]: they never
// see an http.ResponseWriter and never choose a status for a failure.
// ServeRoutes wraps the handlers of one path as an http.Handler and does
// everything that touches HTTP, once: method check, reading the request,
// converting a failure into a status and JSON body, logging it, and writing
// headers. ServeAny does the same for the catch-all that answers every method.
//
// They are the only places that do this, so the contract holds for every route:
//
//   - A route whose method is not GET or HEAD requires the request's
//     Content-Type to be its declared media type (MethodRoute.Media), even when
//     the body is empty (415 unsupported_media_type, checked after the method
//     and before the body is read). The default is application/json. That type
//     forces a CORS preflight, which fails for every origin but the one CORS
//     allows, so another site cannot make a browser deliver such a request:
//     this is the CSRF defence for every unsafe route (see hasMediaType and
//     CORS).
//   - The one other media type is application/x-www-form-urlencoded
//     (MediaForm), for the standard OAuth endpoints. It is CORS-safelisted, so
//     it gives no CSRF defence: a route may declare it only because a
//     browser's ambient credentials do not authenticate it (auth.Handler
//     refuses it on an Authenticated route). Parameters are read with
//     Request.FormParams, whose rules are in ParseParams.
//   - A request body is capped at 1 MiB (413 body_too_large), or at a smaller
//     limit a route asks for (MethodRoute.MaxBody). The same limit bounds the
//     request's query string (413 query_too_large), so a route that parses it
//     (Request.QueryParams) reads no more than it does a body.
//   - A handler runs inside a recover, so a panic still gets the JSON error
//     contract and a log line, as Internal handler_panic.
//   - Responses carry Content-Type and Cache-Control: no-store, and the status
//     is written once. A Status outside 200-599 is an Internal invalid_status
//     error rather than a panic in net/http.
//   - A failure is sent as {"error":{"code","message","data?"}}. The logger gets
//     the request and the full error, cause included. An error that was never
//     classified, or is Internal, is sent as a bare "internal" with no data, so
//     causes, SQL and table names never reach a client. A route may declare
//     the RFC 6749 section 5.2 format instead (MethodRoute.Errors,
//     ErrorsOAuth): see OAuthError for how a failure maps to it. Failures of
//     the boundary itself (405, 415, 413) are rendered in the route's format.
//   - A response is a status and an optional JSON body, or a redirect: a 302 or
//     303 with a Location and no other 3xx (Response.Location).
//   - Unknown paths are answered by NotFound registered on "/", so they too use
//     the JSON envelope.
//
// Routes are registered as plain paths, optionally with {name} wildcards
// (see Request.PathValues): TinyGo's http.ServeMux ignores method-qualified
// patterns, so ServeRoutes does the method check instead, and lets one path
// answer several methods, each with its own handler and body limit.
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
	// Query holds the URL query parameters, as net/http parses them: leniently,
	// dropping what it cannot decode. A handler that must be strict reads
	// RawQuery through QueryParams instead.
	Query map[string][]string
	// RawQuery is the URL's query string exactly as it was sent, still
	// encoded and without the leading "?". It is at most the route's body
	// limit long.
	RawQuery string
	// PathValues holds the values of the route's path wildcards, by name: for
	// a route registered as "/x/{id}", PathValues["id"]. It is empty for a route
	// with none.
	PathValues map[string]string
	// Body is the raw request body, read up to a fixed limit.
	Body []byte
	// Cookies are the request's cookies.
	Cookies []*http.Cookie
	// Authorization holds every value of the Authorization header, in order. It
	// is the one header a handler's boundary reads, so it is the only one
	// carried: a request that sent the header twice is visible as two values,
	// which a single string could not show.
	Authorization []string
}

// Response is what a successful handler returns.
type Response struct {
	// Status is the HTTP status code.
	Status int
	// Body is marshalled to JSON. Nil means no body.
	Body any
	// Location is where a redirect points. It is set exactly when Status is
	// 302 or 303: any other 3xx, a 302 or 303 without a Location and a
	// Location on any other status are programming errors, answered as an
	// Internal invalid_status. It must be printable ASCII with no spaces
	// (Internal invalid_redirect otherwise), so a value that came from a
	// client cannot split the header. The handler builds the whole URL: the
	// boundary neither parses nor rewrites it.
	Location string
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
	return Response{Status: status, Body: body, Cookies: nil, Location: ""}
}

// Redirect returns a redirect Response. status must be 302 (Found) or 303 (See
// Other), which is what an authorization server answers with: the client
// follows it with a GET whatever it sent. It is checked when the response is
// sent, not here.
func Redirect(status int, location string) Response {
	return Response{Status: status, Body: nil, Cookies: nil, Location: location}
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
	return DecodeBody[T](req.Body)
}

// DecodeBody is Decode for a JSON document that is not a request's body: the
// same strictness and the same errors. It is for a value a request carries
// inside its body, such as the params of a JSON-RPC message.
func DecodeBody[T any](body []byte) result.Result[T] {
	var out T

	strict := json.NewDecoder(bytes.NewReader(body))
	strict.UseNumber() // a number is checked, not converted, so none can overflow here

	err := checkStrict(strict, reflect.TypeFor[T]())
	if err != nil {
		return result.Fail[T](decodeError(err))
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
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

// Media is the Content-Type an unsafe request to a route must carry.
type Media uint8

// The media types a route may declare. The zero value is JSON, so a route that
// says nothing keeps the CSRF defence in the package doc.
const (
	// MediaJSON is application/json, optionally with charset=utf-8.
	MediaJSON Media = iota
	// MediaForm is application/x-www-form-urlencoded, optionally with
	// charset=utf-8 and with no other parameter. It is for the standard OAuth
	// endpoints and carries no CSRF defence of its own (see the package doc).
	MediaForm
)

// mediaType is the Content-Type value a route of media requires.
func (m Media) mediaType() string {
	if m == MediaForm {
		return formMediaType
	}

	return jsonMediaType
}

// ErrorFormat is how a route's failures are written.
type ErrorFormat uint8

// The error formats a route may declare. The zero value is the API's own, so a
// route that says nothing keeps {"error":{"code","message"}}.
const (
	// ErrorsAPI is {"error":{"code","message","data?"}}.
	ErrorsAPI ErrorFormat = iota
	// ErrorsOAuth is RFC 6749 section 5.2: {"error","error_description"},
	// with the standard status. See OAuthError.
	ErrorsOAuth
)

// MethodRoute is how ServeRoutes answers one method of a path.
type MethodRoute struct {
	// Handler answers the method.
	Handler Handler
	// MaxBody caps this method's request body, in bytes. Zero or less means
	// DefaultMaxBody, and a larger value is clamped to it: a route can only
	// tighten the cap, never raise it. It also caps the query string.
	MaxBody int64
	// Media is the Content-Type an unsafe request must carry. The zero value
	// is MediaJSON. A GET or HEAD route has no body type, so it is ignored
	// there.
	Media Media
	// Errors is the format of this method's failures. The zero value is
	// ErrorsAPI.
	Errors ErrorFormat
}

// policy is what the boundary enforces for one method of a path.
type policy struct {
	limit  int64
	media  Media
	errors ErrorFormat
	// checkMedia is whether an unsafe request must carry media: true for a
	// route, false for the catch-all, which accepts every method as it comes.
	checkMedia bool
}

// defaultPolicy is the policy of a request no route declared anything for.
func defaultPolicy(format ErrorFormat) policy {
	return policy{limit: maxBodyBytes, media: MediaJSON, errors: format, checkMedia: false}
}

// ServeRoutes returns the http.Handler for one path that answers several
// methods, each with its own handler, body limit, media type and error format.
// The routes map is keyed by method; any other method gets 405 with an Allow
// header listing the keys, sorted. Every rule in the package doc applies per
// method, so a method that is not GET or HEAD still requires its route's
// Content-Type (application/json unless the route declares a form). A request
// is measured against the body limit of the method it used, so a tight limit
// on one method does not constrain another. A panic in a handler is recovered
// and reported as an Internal error.
//
// A failure that belongs to the path and not to a method (405, which is
// answered for a method no route has) is written in the format every method of
// the path declares, and in the API's format when they differ.
//
// wildcards names the {name} wildcards in the path the handler is registered
// for. net/http can only look a wildcard up by name, not list them, so the
// caller says which to copy into Request.PathValues.
//
// It panics when a route declares a Media or ErrorFormat that does not exist:
// a route table is fixed in code, so the mistake is found at construction.
//
// It exists because TinyGo's http.ServeMux cannot route by method: a path is
// registered once, and the method is chosen here.
func ServeRoutes(logger Logger, wildcards []string, routes map[string]MethodRoute) http.Handler {
	methods := slices.Sorted(maps.Keys(routes))
	policies := make(map[string]policy, len(routes))
	pathFormat, agreed := ErrorsAPI, false

	for _, method := range methods {
		route := routes[method]
		if route.Media > MediaForm || route.Errors > ErrorsOAuth {
			panic(fmt.Sprintf("httpapi: route %s has an unknown Media or ErrorFormat", method))
		}

		limit := int64(maxBodyBytes)
		if route.MaxBody > 0 {
			limit = min(route.MaxBody, maxBodyBytes)
		}

		policies[method] = policy{limit: limit, media: route.Media, errors: route.Errors, checkMedia: true}

		if !agreed {
			pathFormat, agreed = route.Errors, true
		} else if pathFormat != route.Errors {
			pathFormat = ErrorsAPI
		}
	}

	return serveWith(methods, wildcards, pathFormat, func(method string) policy { return policies[method] }, logger,
		func(req Request) result.Result[Response] { return routes[req.Method].Handler(req) })
}

// ServeAny is ServeRoutes for a handler that accepts every method: the
// catch-all, whose answer to an unknown path does not depend on how it was
// asked. It has no wildcards, and so no method check and no Content-Type rule.
func ServeAny(logger Logger, handler Handler) http.Handler {
	return serveWith(nil, nil, ErrorsAPI, func(string) policy { return defaultPolicy(ErrorsAPI) }, logger, handler)
}

// serveWith implements ServeRoutes and ServeAny for a route whose path has the
// named wildcards: policyOf returns what is enforced for a method, and
// pathFormat is the error format of a failure that no method owns. No methods
// accepts every method.
func serveWith(
	methods, wildcards []string, pathFormat ErrorFormat, policyOf func(method string) policy, logger Logger,
	handler Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")

		request := Request{
			Method:        req.Method,
			Path:          req.URL.Path,
			Context:       req.Context(),
			Query:         req.URL.Query(),
			RawQuery:      req.URL.RawQuery,
			PathValues:    pathValues(req, wildcards),
			Body:          nil,
			Cookies:       req.Cookies(),
			Authorization: req.Header.Values("Authorization"),
		}

		known := len(methods) == 0 || slices.Contains(methods, req.Method)

		rule := defaultPolicy(pathFormat)
		if known {
			rule = policyOf(req.Method)
		}

		if rule.errors == ErrorsOAuth {
			// RFC 6749 section 5.1: a response that carries a token must not be
			// cached. no-store is already set; Pragma is for HTTP/1.0 caches.
			writer.Header().Set("Pragma", "no-cache")
		}

		failure := precheck(request, req.Header.Values("Content-Type"), rule, known)
		if failure != nil {
			if !known {
				writer.Header().Set("Allow", strings.Join(methods, ", "))
			}

			refuse(writer, logger, request, rule.errors, failure)

			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(writer, req.Body, rule.limit))
		if err != nil {
			refuse(writer, logger, request, rule.errors, bodyReadError(err))

			return
		}

		request.Body = body

		write(writer, logger, request, rule.errors, safely(handler, request))
	})
}

// precheck is what the boundary refuses before it reads the body: a method no
// route answers (405), an unsafe request whose Content-Type is not the route's
// (415) and a query string over the route's limit (413). It returns nil when
// the request may go on. The catch-all (ServeAny) has no Content-Type rule,
// which rule.checkMedia says.
func precheck(request Request, contentType []string, rule policy, known bool) *apierr.Error {
	switch {
	case !known:
		return apierr.New(apierr.MethodNotAllowed, "method_not_allowed", "method not allowed")
	case rule.checkMedia && !safeMethod(request.Method) && !hasMediaType(contentType, rule.media):
		return apierr.New(apierr.UnsupportedMediaType, "unsupported_media_type",
			"request Content-Type must be "+rule.media.mediaType())
	case int64(len(request.RawQuery)) > rule.limit:
		return apierr.New(apierr.PayloadTooLarge, "query_too_large", "request query string is too large")
	}

	return nil
}

// refuse answers the request with failure, in format.
func refuse(writer http.ResponseWriter, logger Logger, req Request, format ErrorFormat, failure *apierr.Error) {
	write(writer, logger, req, format, result.Fail[Response](failure))
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

// write sends res, converting a failure into its error response in format.
func write(writer http.ResponseWriter, logger Logger, req Request, format ErrorFormat, res result.Result[Response]) {
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
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(failure.Kind.Status())
	_, _ = writer.Write(failureBody(failure, format))
}

// FailureBody is the body the API answers a failure with, in its own format:
// {"error":{"code","message","data?"}} and a newline, an Internal failure
// reduced to the bare "internal". It is how a feature that carries a refusal
// somewhere other than a response (an MCP tool's result) says it in the one
// shape a client already reads.
func FailureBody(failure *apierr.Error) []byte { return failureBody(failure, ErrorsAPI) }

// failureBody is the body of an error response in format. Something valid is
// always returned.
func failureBody(failure *apierr.Error, format ErrorFormat) []byte {
	data, err := marshalFailure(failure, format)
	if err != nil {
		// Unreachable for real values; keep the contract that something valid
		// is always written.
		return []byte(`{"error":{"code":"internal","message":"internal error"}}` + "\n")
	}

	return data
}

// marshalFailure builds the body of an error response in format.
func marshalFailure(failure *apierr.Error, format ErrorFormat) ([]byte, error) {
	if format == ErrorsOAuth {
		return marshalOAuthError(failure), nil
	}

	return marshalError(failure)
}

// send encodes and writes a successful response. It writes nothing when
// encoding fails, so the caller can still send an error response.
func send(writer http.ResponseWriter, resp Response) error {
	err := checkStatus(resp)
	if err != nil {
		return err
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

	if resp.Location != "" {
		writer.Header().Set("Location", resp.Location)
	}

	for _, cookie := range resp.Cookies {
		http.SetCookie(writer, cookie)
	}

	writer.WriteHeader(resp.Status)
	_, _ = writer.Write(data)

	return nil
}

// errInvalidRedirect is the cause when a handler returns a Location that is not
// printable ASCII without spaces.
var errInvalidRedirect = errors.New("handler returned an invalid redirect location")

// checkStatus refuses a response whose status and Location do not agree: a
// status outside 200-599, a 3xx other than a 302 or 303, a 302 or 303 without a
// Location, a Location on any other status, and a Location that is not
// printable ASCII without spaces. A handler's mistake is Internal, not a panic
// in net/http.
func checkStatus(resp Response) error {
	redirect := resp.Status == http.StatusFound || resp.Status == http.StatusSeeOther
	threeXX := resp.Status >= http.StatusMultipleChoices && resp.Status < http.StatusBadRequest

	switch {
	case resp.Status < http.StatusOK || resp.Status > 599 || (threeXX && !redirect) || redirect != (resp.Location != ""):
		return apierr.Wrap(fmt.Errorf("%w: %d, has Location %t", errInvalidStatus, resp.Status, resp.Location != ""),
			apierr.Internal, "invalid_status", "internal error")
	case strings.ContainsFunc(resp.Location, func(r rune) bool { return r <= ' ' || r >= 0x7f }):
		return apierr.Wrap(errInvalidRedirect, apierr.Internal, "invalid_redirect", "internal error")
	}

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

// The Content-Types a route may require of an unsafe request.
const (
	jsonMediaType = "application/json"
	formMediaType = "application/x-www-form-urlencoded"
)

// hasMediaType reports whether values, a request's Content-Type header lines,
// are exactly one line naming media's type, optionally with charset=utf-8
// (JSON is UTF-8, RFC 8259, and a form body is UTF-8 by RFC 6749 appendix B).
// Anything else is refused: a missing header, a second line, any other type,
// any other parameter. The two types share this one rule, so a charset another
// parser would read differently is never accepted for either.
//
// For JSON this is the CSRF defence. application/json is not a CORS-safelisted
// type, so a browser cannot send it cross-origin without a preflight, and the
// preflight fails because CORS answers it only for the one allowed origin
// (the UI), never for another site. HTML forms
// cannot send it at all. Requiring it on every unsafe request, even one with
// an empty body, means no other site can make a browser deliver a request this
// boundary will hand to a handler, whatever the handler does with the body.
// The form type gives none of that, which is why a route that declares it must
// not rely on a cookie.
func hasMediaType(values []string, media Media) bool {
	if len(values) != 1 {
		return false
	}

	mediaType, params, hasParams := strings.Cut(values[0], ";")
	if !strings.EqualFold(strings.TrimSpace(mediaType), media.mediaType()) {
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
