package fetch_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/fetch"
)

// testLimits are small so the tests are fast and the cap is easy to cross.
// jsonType is the media type the client accepts.
const jsonType = "application/json"

func testLimits() fetch.Limits { return fetch.Limits{Timeout: 2 * time.Second, MaxBytes: 16} }

func TestDefaultLimits(t *testing.T) {
	t.Parallel()

	got := fetch.DefaultLimits()
	if got.Timeout != 5*time.Second || got.MaxBytes != 5*1024 {
		t.Errorf("DefaultLimits() = %+v, want 5s and 5 KiB", got)
	}
}

// TestGetJSONSucceeds: what is accepted, byte for byte.
func TestGetJSONSucceeds(t *testing.T) {
	t.Parallel()

	atCap := strings.Repeat("a", 16)
	mixedCase := "Application/JSON;Charset=UTF-8"

	tests := map[string]struct {
		contentTypes  []string
		contentLength int64
		payload       string
	}{
		"plain":                    {contentTypes: []string{jsonType}, contentLength: 7, payload: `{"a":1}`},
		"empty body":               {contentTypes: []string{jsonType}, contentLength: 0, payload: ""},
		"exactly at the cap":       {contentTypes: []string{jsonType}, contentLength: 16, payload: atCap},
		"charset utf-8":            {contentTypes: []string{jsonType + "; charset=utf-8"}, contentLength: 2, payload: "{}"},
		"mixed case":               {contentTypes: []string{mixedCase}, contentLength: 2, payload: "{}"},
		"unknown length":           {contentTypes: []string{jsonType}, contentLength: -1, payload: "{}"},
		"length zero, body behind": {contentTypes: []string{jsonType}, contentLength: 0, payload: "{}"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			doer := &fakeDoer{reply: reply{
				status: 200, contentTypes: tt.contentTypes, contentLength: tt.contentLength,
				source: strings.NewReader(tt.payload),
			}}

			got, err := fetch.GetJSON(background(), doer.do, testLimits(), testURL).Get()
			if err != nil {
				t.Fatalf("GetJSON() error = %v", err)
			}

			if string(got) != tt.payload {
				t.Errorf("GetJSON() = %q, want %q", got, tt.payload)
			}

			if !doer.lastBody().isClosed() {
				t.Error("the body was not closed")
			}
		})
	}
}

// answer is a scripted response. An empty contentType sends no header, and the
// body is payload.
func answer(status int, contentType string, length int64, payload io.Reader) reply {
	var types []string
	if contentType != "" {
		types = []string{contentType}
	}

	return reply{status: status, contentTypes: types, contentLength: length, source: payload}
}

// TestGetJSONRefuses: every way a response is refused, with the sentinel that
// names it and the root every one shares. The body is closed in each case.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestGetJSONRefuses(t *testing.T) {
	t.Parallel()

	small := func() io.Reader { return strings.NewReader("{}") }
	typed := func(status int) reply { return answer(status, jsonType, 2, small()) }
	withType := func(contentType string) reply { return answer(http.StatusOK, contentType, 2, small()) }
	lines := func(types ...string) reply {
		return reply{status: http.StatusOK, contentTypes: types, contentLength: 2, source: small()}
	}

	tests := map[string]struct {
		answer reply
		want   error
	}{
		"redirect 300":                  {answer: typed(300), want: fetch.ErrRedirect},
		"redirect 301":                  {answer: typed(301), want: fetch.ErrRedirect},
		"redirect 302":                  {answer: typed(302), want: fetch.ErrRedirect},
		"redirect 303":                  {answer: typed(303), want: fetch.ErrRedirect},
		"redirect 304":                  {answer: typed(304), want: fetch.ErrRedirect},
		"redirect 307":                  {answer: typed(307), want: fetch.ErrRedirect},
		"redirect 308":                  {answer: typed(308), want: fetch.ErrRedirect},
		"redirect 399":                  {answer: typed(399), want: fetch.ErrRedirect},
		"redirect with no content type": {answer: answer(302, "", 2, small()), want: fetch.ErrRedirect},
		"status 0":                      {answer: typed(0), want: fetch.ErrStatus},
		"status 100":                    {answer: typed(100), want: fetch.ErrStatus},
		"status 201":                    {answer: typed(201), want: fetch.ErrStatus},
		"status 202":                    {answer: typed(202), want: fetch.ErrStatus},
		"status 204":                    {answer: answer(204, jsonType, 0, strings.NewReader("")), want: fetch.ErrStatus},
		"status 206":                    {answer: typed(206), want: fetch.ErrStatus},
		"status 400":                    {answer: typed(400), want: fetch.ErrStatus},
		"status 404":                    {answer: typed(404), want: fetch.ErrStatus},
		"status 410":                    {answer: typed(410), want: fetch.ErrStatus},
		"status 500":                    {answer: typed(500), want: fetch.ErrStatus},
		"status 503":                    {answer: typed(503), want: fetch.ErrStatus},
		"no content type":               {answer: withType(""), want: fetch.ErrContentType},
		"empty content type":            {answer: lines(""), want: fetch.ErrContentType},
		"text/json":                     {answer: withType("text/json"), want: fetch.ErrContentType},
		"text/html":                     {answer: withType("text/html"), want: fetch.ErrContentType},
		"application/ld+json":           {answer: withType("application/ld+json"), want: fetch.ErrContentType},
		"application/jsonx":             {answer: withType("application/jsonx"), want: fetch.ErrContentType},
		"another charset":               {answer: withType(jsonType + "; charset=latin1"), want: fetch.ErrContentType},
		"another parameter":             {answer: withType(jsonType + "; version=2"), want: fetch.ErrContentType},
		"charset and another parameter": {answer: withType(jsonType + "; charset=utf-8; x=1"), want: fetch.ErrContentType},
		"empty parameter":               {answer: withType("application/json;"), want: fetch.ErrContentType},
		"two lines":                     {answer: lines(jsonType, jsonType), want: fetch.ErrContentType},
		"two lines, the second is not":  {answer: lines(jsonType, "text/html"), want: fetch.ErrContentType},
		"one byte over the cap": {
			answer: answer(200, jsonType, -1, strings.NewReader(strings.Repeat("a", 17))), want: fetch.ErrTooLarge,
		},
		"far over the cap, no length":     {answer: answer(200, jsonType, -1, endless{}), want: fetch.ErrTooLarge},
		"content length over the cap":     {answer: answer(200, jsonType, 17, small()), want: fetch.ErrTooLarge},
		"content length lies low":         {answer: answer(200, jsonType, 2, endless{}), want: fetch.ErrTooLarge},
		"content length far over the cap": {answer: answer(200, jsonType, 1<<40, small()), want: fetch.ErrTooLarge},
		"body fails midway": {
			answer: answer(200, jsonType, -1, &brokenAfter{data: "{"}), want: fetch.ErrTransport,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			doer := &fakeDoer{reply: tt.answer}

			got, err := fetch.GetJSON(background(), doer.do, testLimits(), testURL).Get()

			if !errors.Is(err, tt.want) {
				t.Fatalf("GetJSON() error = %v, want %v", err, tt.want)
			}

			if !errors.Is(err, fetch.ErrFailed) {
				t.Errorf("error %v does not wrap ErrFailed", err)
			}

			if got != nil {
				t.Errorf("GetJSON() = %q, want no body with an error", got)
			}

			if !doer.lastBody().isClosed() {
				t.Error("the body was not closed")
			}

			// An oversized body is never read past one byte over the cap.
			if read := doer.lastBody().bytesRead(); read > 17 {
				t.Errorf("read %d bytes, want at most the cap plus one (17)", read)
			}
		})
	}
}

// TestGetJSONRequest: what is sent, which is all the client says to a
// stranger's server.
func TestGetJSONRequest(t *testing.T) {
	t.Parallel()

	doer := &fakeDoer{reply: jsonReply("{}")}

	before := time.Now()

	err := fetch.GetJSON(background(), doer.do, testLimits(), testURL).Err()
	if err != nil {
		t.Fatalf("GetJSON() error = %v", err)
	}

	requests := doer.seen()
	if len(requests) != 1 {
		t.Fatalf("the Doer saw %d requests, want 1", len(requests))
	}

	req := requests[0]

	deadline, hasDeadline := req.Context().Deadline()

	checks := map[string]struct{ got, want any }{
		"method":       {got: req.Method, want: http.MethodGet},
		"URL":          {got: req.URL.String(), want: testURL},
		"has no body":  {got: req.Body == nil || req.Body == http.NoBody, want: true},
		"header count": {got: len(req.Header), want: 1},
		"Accept":       {got: req.Header.Get("Accept"), want: jsonType},
		"Cookie":       {got: req.Header.Get("Cookie"), want: ""},
		"Authorization": {
			got: req.Header.Get("Authorization"), want: "",
		},
		"has a deadline": {got: hasDeadline, want: true},
		"deadline is within the timeout": {
			got: deadline.Sub(before) > 0 && deadline.Sub(before) <= testLimits().Timeout+time.Second, want: true,
		},
	}

	for name, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %v, want %v", name, check.got, check.want)
		}
	}
}

// TestGetJSONRequestFailures: a Doer that fails, or answers with nothing.
func TestGetJSONRequestFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		url     string
		respond func(*http.Request) (*http.Response, error)
		want    error
		cause   error
	}{
		"doer error": {
			url: testURL, want: fetch.ErrTransport, cause: errNetwork,
			respond: func(*http.Request) (*http.Response, error) { return nil, errNetwork },
		},
		"doer returns nothing": {
			url: testURL, want: fetch.ErrTransport,
			//nolint:nilnil // the case under test is a Doer that breaks its contract
			respond: func(*http.Request) (*http.Response, error) { return nil, nil },
		},
		"doer returns no body": {
			url: testURL, want: fetch.ErrTransport,
			respond: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {jsonType}}}, nil
			},
		},
		"url the platform cannot send": {
			url: "https://client.example/\x7f", want: fetch.ErrRequest,
			respond: func(*http.Request) (*http.Response, error) { return nil, errNetwork },
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			doer := &fakeDoer{respond: tt.respond}

			err := fetch.GetJSON(background(), doer.do, testLimits(), tt.url).Err()

			if !errors.Is(err, tt.want) || !errors.Is(err, fetch.ErrFailed) {
				t.Errorf("GetJSON() error = %v, want %v", err, tt.want)
			}

			if errors.Is(tt.want, fetch.ErrRequest) && len(doer.seen()) != 0 {
				t.Error("a request that could not be built was sent")
			}

			if tt.cause != nil && !errors.Is(err, tt.cause) {
				t.Errorf("error %v lost the Doer's cause %v", err, tt.cause)
			}
		})
	}
}

// TestGetJSONTimeout: a server that never answers ends the call at the
// deadline, because the deadline is on the request's context and the Doer ends
// the exchange when it is done. A zero timeout ends the call at once.
func TestGetJSONTimeout(t *testing.T) {
	t.Parallel()

	timedOut, cancelled := context.DeadlineExceeded, context.Canceled

	tests := map[string]struct {
		timeout time.Duration
		cancel  bool
		cause   error
	}{
		"a deadline":         {timeout: 20 * time.Millisecond, cause: timedOut},
		"a cancelled caller": {timeout: time.Hour, cancel: true, cause: cancelled},
		"a zero timeout":     {timeout: 0, cause: timedOut},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			slow := newBlocked(jsonReply("{}"))
			doer := &fakeDoer{respond: slow.respond}

			ctx, cancel := context.WithCancel(background())
			defer cancel()

			if tt.cancel {
				cancel()
			}

			started := time.Now()
			err := fetch.GetJSON(ctx, doer.do, fetch.Limits{Timeout: tt.timeout, MaxBytes: 16}, testURL).Err()

			if !errors.Is(err, fetch.ErrFailed) || !errors.Is(err, fetch.ErrAborted) || !errors.Is(err, tt.cause) {
				t.Fatalf("GetJSON() error = %v, want an ErrAborted caused by %v", err, tt.cause)
			}

			if elapsed := time.Since(started); elapsed > time.Second {
				t.Errorf("GetJSON took %v, want it to end at the deadline", elapsed)
			}
		})
	}
}

// errPlatformAbort is how the platform's fetch reports an aborted request.
var errPlatformAbort = errors.New("failed on promise: AbortError: The operation was aborted")

// TestGetJSONFailureAfterTheDeadline: a failure is ErrAborted when the context
// had ended by the time it was reported, whatever words the Doer used, and is
// what the Doer said when it had not.
func TestGetJSONFailureAfterTheDeadline(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		respond     func(*http.Request) (*http.Response, error)
		wantAborted bool
		cause       error
	}{
		"the platform's own abort error": {
			respond: func(req *http.Request) (*http.Response, error) {
				<-req.Context().Done()

				return nil, errPlatformAbort
			},
			wantAborted: true, cause: errPlatformAbort,
		},
		"an error from before the deadline": {
			respond: func(*http.Request) (*http.Response, error) { return nil, errNetwork },
			cause:   errNetwork,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			doer := &fakeDoer{respond: tt.respond}
			limits := fetch.Limits{Timeout: 20 * time.Millisecond, MaxBytes: 16}

			err := fetch.GetJSON(background(), doer.do, limits, testURL).Err()

			if !errors.Is(err, fetch.ErrFailed) || !errors.Is(err, tt.cause) {
				t.Fatalf("GetJSON() error = %v, want a fetch failure caused by %v", err, tt.cause)
			}

			if got := errors.Is(err, fetch.ErrAborted); got != tt.wantAborted {
				t.Errorf("errors.Is(ErrAborted) = %v, want %v (%v)", got, tt.wantAborted, err)
			}

			if !tt.wantAborted && !errors.Is(err, fetch.ErrTransport) {
				t.Errorf("error %v is not ErrTransport", err)
			}
		})
	}
}

// TestGetJSONSlowBody: headers arrive and the body then stalls. The deadline
// covers the body read too, not only the wait for headers, and the body is
// closed when the call ends.
func TestGetJSONSlowBody(t *testing.T) {
	t.Parallel()

	doer := &fakeDoer{reply: reply{
		status: 200, contentTypes: []string{jsonType}, contentLength: -1, source: blockedSource{},
	}}

	err := fetch.GetJSON(background(), doer.do, fetch.Limits{Timeout: 20 * time.Millisecond, MaxBytes: 16}, testURL).Err()

	if !errors.Is(err, fetch.ErrAborted) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetJSON() error = %v, want ErrAborted wrapping the deadline", err)
	}

	if !doer.lastBody().isClosed() {
		t.Error("the body was not closed")
	}
}
