// Package fetch is the outbound HTTP port and the one client built on it: a
// GET of a small JSON document from a URL a stranger chose.
//
// The port is Doer, a function from one request to one response. cmd/worker
// adapts the platform's fetch to it, and nothing else touches the platform, so
// everything here runs, and is tested, on the host against a fake.
//
// # What GetJSON enforces
//
// The URL names a server the caller does not control, so the client assumes
// nothing of it and bounds everything it can:
//
//   - The method is GET and the request carries no body, cookie or credential,
//     only Accept: application/json.
//   - A redirect is a failure and is never followed, whatever the Doer does:
//     the client refuses every 3xx itself, so a Doer that follows redirects
//     cannot be tricked into leaving the URL that was validated.
//   - The status must be exactly 200. 201, 204 and every other code are refused.
//   - Content-Type must be application/json, optionally with charset=utf-8 and
//     no other parameter, in exactly one header line. This is the rule
//     internal/httpapi applies to JSON request bodies; it is repeated here
//     because httpapi keeps its rule unexported, and importing the whole of the
//     inbound HTTP boundary into the outbound client for four lines would tie
//     the two together (fetch imports only result, of the foundation).
//   - The whole exchange, the wait for headers and the read of the body, ends
//     at Limits.Timeout. The platform sets no time limit of its own on a
//     subrequest, so the client puts the deadline on the request's context and
//     the Doer ends the exchange when it is done: the platform's fetch aborts
//     the subrequest and fails a pending body read with the context's error.
//     Nothing is left running afterwards.
//   - The body is read through a limit of Limits.MaxBytes+1 bytes, and one byte
//     over is a refusal, not a truncation, so a document is either whole or
//     rejected. A Content-Length that already exceeds the cap is refused before
//     any byte is read; a header that lies low is caught by the read limit.
//   - The body is always closed.
//
// The URL is not checked here. It is parsed once into an input type
// (input.ClientID) that decides which hosts and schemes are acceptable, and the
// platform's own refusal to reach private addresses is not relied on.
//
// # Errors
//
// Every failure wraps ErrFailed, so a caller that only needs "this URL could
// not be fetched" tests errors.Is(err, ErrFailed) and answers one generic error.
// The specific sentinels exist for logs and tests, and a wrapped detail (a
// status code, the platform's error text) can name the other server's
// behaviour, so an error is for the log and is never shown to a client.
//
// The bytes returned are not parsed. Whether they are valid JSON, whether a key
// is repeated, and what the document means is for the caller's parser.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/susu-dot-dev/authsu/internal/result"
)

// The limits GetJSON is meant to be called with for a client metadata document.
const (
	// DefaultTimeout bounds the whole exchange.
	DefaultTimeout = 5 * time.Second
	// DefaultMaxBytes is the largest document accepted: 5 KiB.
	DefaultMaxBytes = 5 * 1024
)

// Doer sends one request and returns its response. It is the port the platform
// implements.
//
// An implementation must not follow redirects (GetJSON refuses a 3xx either
// way, but one that was followed has already sent the request to its target),
// must return a non-nil response with a non-nil Body when the error is nil,
// and must end when the request's context does: a wait for the response
// returns the context's error, and so does a read of the Body begun or pending
// when it ends. GetJSON starts no goroutine of its own and so depends on this
// for the timeout. The caller closes the Body.
type Doer func(*http.Request) (*http.Response, error)

// Limits bound one GetJSON call. A zero Timeout ends the call at once and a
// zero MaxBytes accepts only an empty body, so neither is silently unlimited.
type Limits struct {
	// Timeout bounds the whole exchange, from sending the request to the last
	// byte of the body.
	Timeout time.Duration
	// MaxBytes is the largest body accepted, in bytes.
	MaxBytes int64
}

// DefaultLimits are the limits for a client metadata document.
func DefaultLimits() Limits {
	return Limits{Timeout: DefaultTimeout, MaxBytes: DefaultMaxBytes}
}

// The failures. Each wraps ErrFailed.
var (
	// ErrFailed is the root of every error GetJSON returns.
	ErrFailed = errors.New("fetch failed")
	// ErrRequest means the request could not be built, which is a URL the
	// platform cannot send.
	ErrRequest = fmt.Errorf("%w: the request could not be built", ErrFailed)
	// ErrTransport means the Doer failed, or the body could not be read: a
	// refused connection, a reset, a failed TLS handshake, a broken stream.
	ErrTransport = fmt.Errorf("%w: the request could not be completed", ErrFailed)
	// ErrAborted means the context ended before the exchange finished: the
	// timeout, or the caller's cancellation. It wraps the context's error.
	ErrAborted = fmt.Errorf("%w: the request did not finish in time", ErrFailed)
	// ErrRedirect means the server answered with a 3xx.
	ErrRedirect = fmt.Errorf("%w: the server redirected", ErrFailed)
	// ErrStatus means the status was not 200.
	ErrStatus = fmt.Errorf("%w: the status is not 200", ErrFailed)
	// ErrContentType means Content-Type was not application/json.
	ErrContentType = fmt.Errorf("%w: the content type is not application/json", ErrFailed)
	// ErrTooLarge means the body was over Limits.MaxBytes.
	ErrTooLarge = fmt.Errorf("%w: the body is too large", ErrFailed)
)

// jsonMediaType is the only content type accepted.
const jsonMediaType = "application/json"

// GetJSON fetches rawURL with GET through do and returns the body, under the
// rules in the package documentation. The Result carries an error that wraps
// ErrFailed and is for the log.
func GetJSON(ctx context.Context, do Doer, limits Limits, rawURL string) result.Result[[]byte] {
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()

	return result.Of(newRequest(ctx, rawURL)).
		Then(func(req *http.Request) ([]byte, error) {
			body, err := exchange(do, req, limits.MaxBytes)

			return body, aborted(ctx, err)
		})
}

// newRequest builds the one request GetJSON sends.
func newRequest(ctx context.Context, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRequest, err)
	}

	req.Header.Set("Accept", jsonMediaType)

	return req, nil
}

// aborted reclassifies a failure that happened once ctx had ended as
// ErrAborted, keeping the context's error beside the Doer's. The Doer reports
// the end of the context in its own words (the platform's abort error, or the
// context's), and a caller tests errors.Is(err, ErrAborted), not the wording. A
// failure before ctx ended, and a success, are returned as they are.
func aborted(ctx context.Context, err error) error {
	if err == nil || ctx.Err() == nil || errors.Is(err, ErrAborted) {
		return err
	}

	return fmt.Errorf("%w: %w: %w", ErrAborted, ctx.Err(), err)
}

// exchange sends req through do, checks the response and reads its body. It
// closes the body on every path.
func exchange(do Doer, req *http.Request, maxBytes int64) ([]byte, error) {
	resp, err := do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTransport, err)
	}

	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("%w: the Doer returned no response body", ErrTransport)
	}

	defer func() { _ = resp.Body.Close() }()

	err = checkResponse(resp, maxBytes)
	if err != nil {
		return nil, err
	}

	return readCapped(resp.Body, maxBytes)
}

// checkResponse refuses a response by its status and headers, before any of
// its body is read.
func checkResponse(resp *http.Response, maxBytes int64) error {
	switch {
	case resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest:
		return fmt.Errorf("%w: status %d", ErrRedirect, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%w: status %d", ErrStatus, resp.StatusCode)
	case !isJSON(resp.Header.Values("Content-Type")):
		return fmt.Errorf("%w: %q", ErrContentType, resp.Header.Values("Content-Type"))
	case resp.ContentLength > maxBytes:
		return fmt.Errorf("%w: Content-Length %d, limit %d", ErrTooLarge, resp.ContentLength, maxBytes)
	}

	return nil
}

// readCapped reads body whole, or refuses it when it is longer than maxBytes.
// It reads one byte past the cap so an oversized body is told apart from one
// that is exactly the cap, and never keeps more than that.
func readCapped(body io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrTransport, err)
	}

	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, maxBytes)
	}

	return data, nil
}

// isJSON reports whether values, a response's Content-Type header lines, are
// exactly one line naming application/json, optionally with charset=utf-8.
// A missing header, a second line, another type or another parameter is
// refused. It is the rule of internal/httpapi's media type check.
func isJSON(values []string) bool {
	if len(values) != 1 {
		return false
	}

	mediaType, params, hasParams := strings.Cut(values[0], ";")
	if !strings.EqualFold(strings.TrimSpace(mediaType), jsonMediaType) {
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
