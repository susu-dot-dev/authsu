// Package apierr defines the structured error that HTTP handlers return.
//
// A handler reports failure by returning an *Error (or any error that wraps
// one). The boundary in internal/httpapi turns it into a status code and a JSON
// body, logs the detail, and never sends the cause to the client. Code is
// therefore free to build, wrap and return errors without deciding how they are
// shown.
//
// Every failure should be classified, with a Code of its own: Internal (500) is
// the fail-closed fallback for the genuinely unknown, not a default to reach
// for. The Code is what a log search or an alert keys on, so each failing step
// gets its own. A database that errors is Unavailable (503) with a code naming
// the step, a fixed client-safe description, and the driver error as the cause.
//
// Errors carry no stack: TinyGo's runtime.Callers returns no frames on wasm.
// Add context by wrapping with fmt.Errorf("verb noun: %w", err) instead.
package apierr

import (
	"errors"
	"net/http"
)

// Kind classifies an error and selects its HTTP status.
type Kind uint8

// Kinds. The zero value, Internal, is the safe default for anything that was
// never classified: it is a 500 and its detail is hidden from the client.
const (
	Internal Kind = iota
	BadRequest
	Unauthorized
	Forbidden
	NotFound
	MethodNotAllowed
	Conflict
	PayloadTooLarge
	RateLimited
	Unavailable
	UnsupportedMediaType
)

// Status returns the HTTP status for the kind. Internal and any unknown kind
// fail closed to 500.
func (k Kind) Status() int {
	statuses := [...]int{
		Internal:             http.StatusInternalServerError,
		BadRequest:           http.StatusBadRequest,
		Unauthorized:         http.StatusUnauthorized,
		Forbidden:            http.StatusForbidden,
		NotFound:             http.StatusNotFound,
		MethodNotAllowed:     http.StatusMethodNotAllowed,
		Conflict:             http.StatusConflict,
		PayloadTooLarge:      http.StatusRequestEntityTooLarge,
		RateLimited:          http.StatusTooManyRequests,
		Unavailable:          http.StatusServiceUnavailable,
		UnsupportedMediaType: http.StatusUnsupportedMediaType,
	}

	if int(k) < len(statuses) {
		return statuses[k]
	}

	return http.StatusInternalServerError
}

// Error is a classified error.
type Error struct {
	// Kind selects the HTTP status.
	Kind Kind
	// Code is a stable, machine-readable identifier clients can switch on.
	Code string
	// Description is human-readable. It is shown to clients for every Kind
	// except Internal, so it must never contain secrets or internals. Use fixed
	// text, never err.Error(): put the underlying error in the cause with
	// WithCause, which only the log sees.
	Description string
	// Data is optional structured detail for the client, marshalled to JSON
	// under "data". It is never sent for Internal errors.
	Data any

	cause error
}

// New returns an Error with no cause.
func New(kind Kind, code, description string) *Error {
	return &Error{Kind: kind, Code: code, Description: description, Data: nil, cause: nil}
}

// Error implements error. It includes the cause, so logs carry the detail.
func (e *Error) Error() string {
	if e.cause == nil {
		return e.Code + ": " + e.Description
	}

	return e.Code + ": " + e.Description + ": " + e.cause.Error()
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error {
	return e.cause
}

// WithData returns a copy of e carrying data for the client.
func (e *Error) WithData(data any) *Error {
	clone := *e
	clone.Data = data

	return &clone
}

// WithCause returns a copy of e that wraps cause. The cause is for logs only.
func (e *Error) WithCause(cause error) *Error {
	clone := *e
	clone.cause = cause

	return &clone
}

// Wrap classifies err as kind, unless an *Error is already in its chain, in
// which case that one is returned untouched: the innermost classification
// wins. Wrap(nil, ...) is nil, so `return apierr.Wrap(err, ...)` is safe on
// the success path.
func Wrap(err error, kind Kind, code, description string) error {
	if err == nil {
		return nil
	}

	if _, found := errors.AsType[*Error](err); found {
		return err
	}

	return New(kind, code, description).WithCause(err)
}

// As returns the *Error in err's chain. An error that was never classified
// becomes an Internal one that wraps it, so callers always get an *Error.
func As(err error) *Error {
	if found, ok := errors.AsType[*Error](err); ok {
		return found
	}

	return New(Internal, "internal", "internal error").WithCause(err)
}
