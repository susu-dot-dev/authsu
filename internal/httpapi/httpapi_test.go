package httpapi_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

var errCause = errors.New("SELECT secret FROM hidden_table failed")

type call struct {
	method string
	target string
	body   string
}

type outcome struct {
	rec       *httptest.ResponseRecorder
	logged    []*apierr.Error
	loggedReq []httpapi.Request
}

func run(t *testing.T, in call, handler httpapi.Handler) outcome {
	t.Helper()

	var out outcome

	out.rec = httptest.NewRecorder()
	logger := func(r httpapi.Request, e *apierr.Error) {
		out.logged = append(out.logged, e)
		out.loggedReq = append(out.loggedReq, r)
	}

	req := httptest.NewRequestWithContext(t.Context(), in.method, in.target, strings.NewReader(in.body))
	httpapi.Serve(http.MethodPost, logger, handler).ServeHTTP(out.rec, req)

	return out
}

func respond(resp httpapi.Response) httpapi.Handler {
	return func(httpapi.Request) result.Result[httpapi.Response] { return result.Ok(resp) }
}

func failWith(err error) httpapi.Handler {
	return func(httpapi.Request) result.Result[httpapi.Response] { return result.Fail[httpapi.Response](err) }
}

type want struct {
	status  int
	body    string
	allow   string
	nLogged int
}

func check(t *testing.T, in call, handler httpapi.Handler, want want) {
	t.Helper()

	out := run(t, in, handler)

	if out.rec.Code != want.status {
		t.Errorf("status = %d, want %d", out.rec.Code, want.status)
	}

	if got := out.rec.Body.String(); got != want.body {
		t.Errorf("body = %q, want %q", got, want.body)
	}

	if got := out.rec.Header().Get("Allow"); got != want.allow {
		t.Errorf("Allow = %q, want %q", got, want.allow)
	}

	if got := out.rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	if len(out.logged) != want.nLogged {
		t.Errorf("logged %d errors, want %d", len(out.logged), want.nLogged)
	}
}

const (
	queryValue   = "abc"
	jsonType     = "application/json"
	helloBody    = "hello"
	internalBody = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
	invalidJSON  = "invalid_json"
	notFoundBody = `{"error":{"code":"not_found","message":"no such route"}}` + "\n"
)

func post() call {
	return call{method: http.MethodPost, target: "/x", body: ""}
}

func TestServeSuccess(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		handler httpapi.Handler
		want    want
	}{
		"json body": {
			handler: respond(httpapi.JSON(http.StatusOK, map[string]string{"status": "ok"})),
			want:    want{status: http.StatusOK, body: `{"status":"ok"}` + "\n"},
		},
		"created": {
			handler: respond(httpapi.JSON(http.StatusCreated, map[string]int{"n": 1})),
			want:    want{status: http.StatusCreated, body: `{"n":1}` + "\n"},
		},
		"no body": {
			handler: respond(httpapi.Response{Status: http.StatusNoContent, Body: nil}),
			want:    want{status: http.StatusNoContent},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			check(t, post(), tt.handler, tt.want)
		})
	}
}

func TestServeErrors(t *testing.T) {
	t.Parallel()

	tests := serveErrorCases()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			check(t, post(), tt.handler, tt.want)
		})
	}
}

type serveErrorCase struct {
	handler httpapi.Handler
	want    want
}

func serveErrorCases() map[string]serveErrorCase {
	return map[string]serveErrorCase{
		"classified error shows code and message": {
			handler: failWith(apierr.New(apierr.Conflict, "invitation_full", "invitation already used")),
			want: want{
				status: http.StatusConflict, nLogged: 1,
				body: `{"error":{"code":"invitation_full","message":"invitation already used"}}` + "\n",
			},
		},
		"classified error carries data": {
			handler: failWith(apierr.New(apierr.BadRequest, "invalid", "bad field").
				WithData(map[string]string{"field": "code"})),
			want: want{
				status: http.StatusBadRequest, nLogged: 1,
				body: `{"error":{"code":"invalid","message":"bad field","data":{"field":"code"}}}` + "\n",
			},
		},
		"classified error found through wrapping": {
			handler: failWith(fmt.Errorf("ctx: %w", apierr.New(apierr.NotFound, "gone", "it is gone"))),
			want: want{
				status: http.StatusNotFound, nLogged: 1,
				body: `{"error":{"code":"gone","message":"it is gone"}}` + "\n",
			},
		},
		"unclassified error hides its cause": {
			handler: failWith(errCause),
			want:    want{status: http.StatusInternalServerError, nLogged: 1, body: internalBody},
		},
		"internal error hides description and data": {
			handler: failWith(apierr.New(apierr.Internal, "oops", "table users is corrupt").
				WithData("secret").WithCause(errCause)),
			want: want{status: http.StatusInternalServerError, nLogged: 1, body: internalBody},
		},
		"unencodable success body becomes internal error": {
			handler: respond(httpapi.JSON(http.StatusOK, make(chan int))),
			want:    want{status: http.StatusInternalServerError, nLogged: 1, body: internalBody},
		},
		"invalid status becomes internal error": {
			handler: respond(httpapi.Response{Status: 0, Body: nil}),
			want:    want{status: http.StatusInternalServerError, nLogged: 1, body: internalBody},
		},
		"panic becomes internal error": {
			handler: func(httpapi.Request) result.Result[httpapi.Response] { panic("nil step") },
			want:    want{status: http.StatusInternalServerError, nLogged: 1, body: internalBody},
		},
		"unencodable error data falls back to a fixed body": {
			handler: failWith(apierr.New(apierr.BadRequest, "bad", "bad").WithData(make(chan int))),
			want:    want{status: http.StatusBadRequest, nLogged: 1, body: internalBody},
		},
	}
}

func TestServeWrongMethod(t *testing.T) {
	t.Parallel()

	handled := false

	check(t, call{method: http.MethodGet, target: "/x", body: ""},
		func(httpapi.Request) result.Result[httpapi.Response] {
			handled = true

			return result.Ok(httpapi.Response{Status: http.StatusOK, Body: nil})
		},
		want{
			status: http.StatusMethodNotAllowed, allow: http.MethodPost, nLogged: 1,
			body: `{"error":{"code":"method_not_allowed","message":"method not allowed"}}` + "\n",
		})

	if handled {
		t.Error("handler ran for the wrong method")
	}
}

func TestServeContentType(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		handler httpapi.Handler
		want    string
	}{
		"body":    {handler: respond(httpapi.JSON(http.StatusOK, 1)), want: jsonType},
		"no body": {handler: respond(httpapi.Response{Status: http.StatusNoContent, Body: nil}), want: ""},
		"error":   {handler: failWith(errCause), want: jsonType},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := run(t, post(), tt.handler).rec.Header().Get("Content-Type"); got != tt.want {
				t.Errorf("Content-Type = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServeLogsFullDetail(t *testing.T) {
	t.Parallel()

	out := run(t, post(), failWith(errCause))

	if len(out.logged) != 1 || !errors.Is(out.logged[0], errCause) {
		t.Fatalf("logged = %v, want one error wrapping the cause", out.logged)
	}
}

func TestServePassesRequestToHandler(t *testing.T) {
	t.Parallel()

	var got httpapi.Request

	run(t, call{method: http.MethodPost, target: "/x?code=" + queryValue + "&code=def", body: helloBody},
		func(req httpapi.Request) result.Result[httpapi.Response] {
			got = req

			return result.Ok(httpapi.Response{Status: http.StatusNoContent, Body: nil})
		})

	if string(got.Body) != helloBody {
		t.Errorf("Body = %q, want hello", got.Body)
	}

	if len(got.Query["code"]) != 2 || got.Query["code"][0] != queryValue {
		t.Errorf("Query = %v", got.Query)
	}

	if got.Context == nil {
		t.Error("Context is nil")
	}
}

func TestServeBodyReadErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body       io.Reader
		wantStatus int
		wantCode   string
	}{
		"too large": {
			body:       strings.NewReader(strings.Repeat("a", 2<<20)),
			wantStatus: http.StatusRequestEntityTooLarge, wantCode: "body_too_large",
		},
		"read failed": {
			body:       iotest.ErrReader(errCause),
			wantStatus: http.StatusInternalServerError, wantCode: "body_read_failed",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handled := false

			var logged []*apierr.Error

			logger := func(_ httpapi.Request, e *apierr.Error) { logged = append(logged, e) }
			handler := func(httpapi.Request) result.Result[httpapi.Response] {
				handled = true

				return result.Ok(httpapi.Response{Status: http.StatusOK, Body: nil})
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", tt.body)
			httpapi.Serve(http.MethodPost, logger, handler).ServeHTTP(rec, req)

			if handled {
				t.Error("handler ran although the body could not be read")
			}

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if len(logged) != 1 || logged[0].Code != tt.wantCode {
				t.Errorf("logged = %v, want one error with code %q", logged, tt.wantCode)
			}

			if strings.Contains(rec.Body.String(), errCause.Error()) {
				t.Errorf("body leaks the cause: %q", rec.Body.String())
			}
		})
	}
}

func TestServeLogsRequest(t *testing.T) {
	t.Parallel()

	out := run(t, call{method: http.MethodPost, target: "/x?a=b", body: helloBody}, failWith(errCause))

	if len(out.loggedReq) != 1 {
		t.Fatalf("logged %d requests, want 1", len(out.loggedReq))
	}

	got := out.loggedReq[0]
	if got.Method != http.MethodPost || got.Path != "/x" || string(got.Body) != helloBody || got.Query["a"][0] != "b" {
		t.Errorf("logged request = %+v", got)
	}
}

func TestServeAnyAndNotFound(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), method, "/nope", nil)
		httpapi.ServeAny(func(httpapi.Request, *apierr.Error) {}, httpapi.NotFound).ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound || rec.Body.String() != notFoundBody {
			t.Errorf("%s: (%d, %q), want (404, %q)", method, rec.Code, rec.Body.String(), notFoundBody)
		}

		if got := rec.Header().Get("Content-Type"); got != jsonType {
			t.Errorf("%s: Content-Type = %q, want %s", method, got, jsonType)
		}
	}
}

type input struct {
	Code string `json:"code"`
}

func TestDecode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body     string
		want     input
		wantCode string
	}{
		"valid":           {body: `{"code":"abc"}`, want: input{Code: queryValue}},
		"valid with nl":   {body: `{"code":"abc"}` + "\n", want: input{Code: queryValue}},
		"malformed":       {body: `{`, wantCode: invalidJSON},
		"empty":           {body: ``, wantCode: "empty_body"},
		"unknown field":   {body: `{"code":"a","extra":1}`, wantCode: "unknown_field"},
		"wrong type":      {body: `{"code":1}`, wantCode: "invalid_field_type"},
		"trailing object": {body: `{"code":"a"}{"code":"b"}`, wantCode: "trailing_data"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := httpapi.Decode[input](httpapi.Request{
				Context: t.Context(), Query: nil, Body: []byte(tt.body),
			}).Get()

			if tt.wantCode == "" {
				if err != nil || got != tt.want {
					t.Errorf("Decode = (%+v, %v), want (%+v, nil)", got, err, tt.want)
				}

				return
			}

			failure := apierr.As(err)
			if failure.Kind != apierr.BadRequest || failure.Code != tt.wantCode {
				t.Errorf("Decode error = (%d, %q), want (BadRequest, %q)", failure.Kind, failure.Code, tt.wantCode)
			}
		})
	}
}
