package httpapi_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
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
	// contentType are the Content-Type header lines sent. Nil sends
	// application/json; an empty, non-nil slice sends none.
	contentType []string
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
	setContentType(req, in.contentType)
	serve(http.MethodPost, logger, handler).ServeHTTP(out.rec, req)

	return out
}

// setContentType sets the Content-Type lines of req: application/json when
// lines is nil, none when it is empty.
func setContentType(req *http.Request, lines []string) {
	if lines == nil {
		lines = []string{jsonType}
	}

	for _, line := range lines {
		req.Header.Add("Content-Type", line)
	}
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

	if got := out.rec.Header().Get("Cache-Control"); got != noStore {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	if len(out.logged) != want.nLogged {
		t.Errorf("logged %d errors, want %d", len(out.logged), want.nLogged)
	}
}

const (
	queryValue   = "abc"
	jsonType     = "application/json"
	plainType    = "text/plain"
	helloBody    = "hello"
	internalBody = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
	invalidJSON  = "invalid_json"
	unknownField = "unknown_field"
	invalidType  = "invalid_field_type"
	invalidText  = "invalid_text"
	tooManyItems = "too_many_items"
	notFoundBody = `{"error":{"code":"not_found","message":"no such route"}}` + "\n"
)

func post() call {
	return call{method: http.MethodPost, target: "/x", body: "", contentType: nil}
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

	check(t, call{method: http.MethodGet, target: "/x", body: "", contentType: nil},
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

	run(t, call{method: http.MethodPost, target: "/x?code=" + queryValue + "&code=def", body: helloBody, contentType: nil},
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
			wantStatus: http.StatusRequestEntityTooLarge, wantCode: codeTooBig,
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
			setContentType(req, nil)
			serve(http.MethodPost, logger, handler).ServeHTTP(rec, req)

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

	out := run(t, call{method: http.MethodPost, target: "/x?a=b", body: helloBody, contentType: nil}, failWith(errCause))

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
		"unknown field":   {body: `{"code":"a","extra":1}`, wantCode: unknownField},
		"wrong type":      {body: `{"code":1}`, wantCode: invalidType},
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

type nested struct {
	Inner input `json:"inner"`
}

// TestDecodeIsStrict covers request bodies that encoding/json reads leniently:
// it matches member names case-insensitively, keeps the last of a repeated
// name, and replaces invalid UTF-8 with U+FFFD. Each means a body can say one
// thing to another parser (a proxy, a log pipeline, a WAF) and another to us,
// so each is refused. Member names are matched exactly.
func TestDecodeIsStrict(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"name in another case":         `{"inner":{"CODE":"abc"}}`,
		"name in mixed case":           `{"inner":{"Code":"abc"}}`,
		"outer name in another case":   `{"INNER":{"code":"abc"}}`,
		"repeated name":                `{"inner":{"code":"abc","code":"def"}}`,
		"repeated name, same value":    `{"inner":{"code":"abc","code":"abc"}}`,
		"repeated outer name":          `{"inner":{"code":"abc"},"inner":{"code":"def"}}`,
		"repeated name through escape": `{"inner":{"code":"abc","\u0063ode":"def"}}`,
		"invalid UTF-8 in a value":     "{\"inner\":{\"code\":\"ab\xffc\"}}",
		"invalid UTF-8 in a name":      "{\"inner\":{\"code\xff\":\"abc\"}}",
		"lone surrogate in a value":    `{"inner":{"code":"ab\ud800c"}}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := httpapi.Decode[nested](httpapi.Request{
				Context: t.Context(), Query: nil, Body: []byte(body),
			}).Get()
			if err == nil {
				t.Fatalf("Decode accepted %q as %+v", body, got)
			}

			if kind := apierr.As(err).Kind; kind != apierr.BadRequest {
				t.Errorf("kind = %d, want BadRequest", kind)
			}
		})
	}
}

// shapes has a member of every kind checkStrict walks into.
type shapes struct {
	List  []input            `json:"list"`
	Map   map[string]input   `json:"map"`
	Ptr   *input             `json:"ptr"`
	Any   json.RawMessage    `json:"any"`
	Plain string             // untagged, so matched by its Go name
	Words map[string][]input `json:"words"`
	// Few is an array bounded to three items.
	Few []string `json:"few" maxitems:"3"`
	// None is bounded to zero items: always empty.
	None []string `json:"none" maxitems:"0"`
}

// TestDecodeChecksEveryValue covers checkStrict's walk: the exact-name and
// repeat rules hold inside arrays, maps and pointers, and inside values whose
// Go type gives no structure.
func TestDecodeChecksEveryValue(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body     string
		wantCode string
	}{
		"every kind": {
			body: `{"list":[{"code":"a"}],"map":{"k":{"code":"b"}},"ptr":{"code":"c"},` +
				`"any":{"X":[1,{"y":true}],"z":null},"Plain":"p","words":{"w":[{"code":"d"}]}}`,
		},
		"a number too large for float64": {body: `{"any":1e999999}`},
		"name in another case in an array": {
			body: `{"list":[{"CODE":"a"}]}`, wantCode: unknownField,
		},
		"name in another case in a map": {
			body: `{"map":{"k":{"CODE":"a"}}}`, wantCode: unknownField,
		},
		"name in another case behind a pointer": {
			body: `{"ptr":{"CODE":"a"}}`, wantCode: unknownField,
		},
		"untagged field in another case": {body: `{"plain":"p"}`, wantCode: unknownField},
		"repeat inside an unstructured value": {
			body: `{"any":{"x":{"y":1,"y":2}}}`, wantCode: "duplicate_field",
		},
		"repeat inside an array in an unstructured value": {
			body: `{"any":[{"y":1,"y":2}]}`, wantCode: "duplicate_field",
		},
		"invalid UTF-8 in a name":          {body: "{\"map\":{\"k\xff\":{}}}", wantCode: invalidText},
		"an escaped replacement character": {body: `{"Plain":"\ufffd"}`, wantCode: invalidText},
		"a lone surrogate":                 {body: `{"Plain":"\udc00"}`, wantCode: invalidText},
		"non-string key":                   {body: `{1:2}`, wantCode: invalidJSON},
		"unclosed array":                   {body: `{"list":[`, wantCode: invalidJSON},
		"value missing at the end":         {body: `{"Plain":`, wantCode: invalidJSON},
		"object for a string":              {body: `{"Plain":{"x":1}}`, wantCode: invalidType},
		"array for a string":               {body: `{"Plain":[1]}`, wantCode: invalidType},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := httpapi.Decode[shapes](httpapi.Request{
				Context: t.Context(), Query: nil, Body: []byte(tt.body),
			}).Get()

			if tt.wantCode == "" {
				if err != nil {
					t.Errorf("Decode error = %v, want success", err)
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

func TestServeReadsRequestCookies(t *testing.T) {
	t.Parallel()

	var got []*http.Cookie

	handler := func(req httpapi.Request) result.Result[httpapi.Response] {
		got = req.Cookies

		return result.Ok(httpapi.JSON(http.StatusOK, 1))
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(""))
	setContentType(req, nil)
	// A browser returns only a cookie's name and value, so that is all a test
	// request carries; the attributes belong to Set-Cookie.
	req.Header.Add("Cookie", "a=1; b=2")

	serve(http.MethodPost, nil, handler).ServeHTTP(rec, req)

	if len(got) != 2 || got[0].Name != "a" || got[1].Value != "2" {
		t.Errorf("cookies = %v, want a=1 and b=2", got)
	}
}

func TestServeSetsResponseCookies(t *testing.T) {
	t.Parallel()

	cookie := &http.Cookie{
		Name: "session", Value: "token", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}

	out := run(t, post(), respond(httpapi.JSON(http.StatusOK, 1).WithCookies(cookie)))

	set := out.rec.Result().Cookies()
	if len(set) != 1 || set[0].Name != "session" || set[0].Value != "token" || !set[0].HttpOnly || !set[0].Secure {
		t.Errorf("Set-Cookie = %v, want one HttpOnly Secure session cookie", set)
	}
}

func TestServeSetsNoCookiesOnFailure(t *testing.T) {
	t.Parallel()

	// A handler that failed must not have its cookies sent, whatever it
	// built before failing: the cookies are part of a Response, and a failure
	// has none.
	out := run(t, post(), failWith(errCause))

	if got := out.rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie = %v, want none", got)
	}
}

const unsupportedBody = `{"error":{"code":"unsupported_media_type",` +
	`"message":"request Content-Type must be application/json"}}` + "\n"

// TestServeRefusesAnUnsafeRequestThatIsNotJSON is the CSRF defence. A request
// another site can make a browser send without a CORS preflight (a form post,
// or fetch with a CORS-safelisted Content-Type: text/plain,
// application/x-www-form-urlencoded, multipart/form-data, or none) must never
// reach a handler. Every case sends an empty body: the check is on the
// request, not on what the body holds, so routes that read no body (login
// begin, logout) are covered the same as those that do.
func TestServeRefusesAnUnsafeRequestThatIsNotJSON(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		// The CORS-safelisted types, and no header at all: what a cross-site
		// form or a no-cors fetch sends.
		"no Content-Type":       {},
		"text/plain":            {plainType},
		"text/plain with UTF-8": {"text/plain;charset=UTF-8"},
		"form-urlencoded":       {"application/x-www-form-urlencoded"},
		"multipart":             {"multipart/form-data; boundary=x"},
		// Near misses, which must not be read as JSON.
		emptyValue:               {""},
		"json as a suffix":       {"text/plain; application/json"},
		"two types in one line":  {"application/json, text/plain"},
		"two lines":              {jsonType, plainType},
		"json twice":             {jsonType, jsonType},
		"another subtype":        {"application/jsonx"},
		"structured suffix":      {"application/merge-patch+json"},
		"another charset":        {"application/json; charset=latin1"},
		"another parameter":      {"application/json; boundary=x"},
		"empty parameter":        {"application/json;"},
		"charset then junk":      {"application/json; charset=utf-8; x=y"},
		"type with no subtype":   {"application"},
		"wildcard":               {"*/*"},
		"padded with a NUL byte": {"application/json\x00"},
	}

	for name, lines := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handled := false
			handler := func(httpapi.Request) result.Result[httpapi.Response] {
				handled = true

				return result.Ok(httpapi.JSON(http.StatusOK, 1))
			}

			check(t, call{method: http.MethodPost, target: "/x", body: "", contentType: lines}, handler,
				want{status: http.StatusUnsupportedMediaType, body: unsupportedBody, nLogged: 1})

			if handled {
				t.Error("the handler ran for a request that is not application/json")
			}
		})
	}
}

// TestServeAcceptsJSON pins the spellings of application/json that pass:
// media types are case-insensitive, and charset=utf-8 is the one parameter
// JSON allows.
func TestServeAcceptsJSON(t *testing.T) {
	t.Parallel()

	for _, line := range []string{
		jsonType, "Application/JSON", " application/json ",
		"application/json; charset=utf-8", "application/json;charset=UTF-8",
	} {
		t.Run(line, func(t *testing.T) {
			t.Parallel()

			check(t, call{method: http.MethodPost, target: "/x", body: "", contentType: []string{line}},
				respond(httpapi.JSON(http.StatusOK, 1)), want{status: http.StatusOK, body: "1\n"})
		})
	}
}

// TestServeReadsNoBodyBeforeTheContentTypeCheck requires the refusal before
// the body is read, so an oversized non-JSON body is answered 415, not 413.
func TestServeReadsNoBodyBeforeTheContentTypeCheck(t *testing.T) {
	t.Parallel()

	in := call{
		method: http.MethodPost, target: "/x", body: strings.Repeat("a", 2<<20), contentType: []string{plainType},
	}

	if got := run(t, in, respond(httpapi.JSON(http.StatusOK, 1))).rec.Code; got != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", got)
	}
}

// TestServeSafeMethodsNeedNoContentType: a GET or HEAD changes nothing and has
// no body, so it is not held to the JSON rule. A browser sends none on a GET.
func TestServeSafeMethodsNeedNoContentType(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), method, "/x", nil)
		serve(method, nil, respond(httpapi.JSON(http.StatusOK, 1))).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s with no Content-Type = %d, want 200", method, rec.Code)
		}
	}
}

// TestDecodeBoundsArrays covers the maxitems tag: an array over its limit is
// refused (never truncated), at the first item past the limit.
func TestDecodeBoundsArrays(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body     string
		wantFew  []string
		wantCode string
	}{
		"empty":                  {body: `{"few":[]}`, wantFew: []string{}},
		"under the limit":        {body: `{"few":["a","b"]}`, wantFew: []string{"a", "b"}},
		"at the limit":           {body: `{"few":["a","b","c"]}`, wantFew: []string{"a", "b", "c"}},
		"one over the limit":     {body: `{"few":["a","b","c","d"]}`, wantCode: tooManyItems},
		"far over the limit":     {body: `{"few":[` + strings.Repeat(`"a",`, 5000) + `"a"]}`, wantCode: tooManyItems},
		"repeats count as items": {body: `{"few":["a","a","a","a"]}`, wantCode: tooManyItems},
		"zero limit, empty":      {body: `{"none":[]}`},
		"zero limit, one item":   {body: `{"none":["a"]}`, wantCode: tooManyItems},
		"null is no array":       {body: `{"few":null}`},
		"unbounded array":        {body: `{"list":[` + strings.Repeat(`{},`, 50) + `{}]}`},
		"limit is per array":     {body: `{"few":["a"],"words":{"w":[{},{},{},{},{}]}}`, wantFew: []string{"a"}},
		"too many then bad json": {body: `{"few":["a","b","c","d"`, wantCode: tooManyItems},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := httpapi.Decode[shapes](httpapi.Request{
				Context: t.Context(), Query: nil, Body: []byte(tt.body),
			}).Get()

			if tt.wantCode != "" {
				failure := apierr.As(err)
				if failure.Kind != apierr.BadRequest || failure.Code != tt.wantCode {
					t.Errorf("Decode error = (%d, %q), want (BadRequest, %q)", failure.Kind, failure.Code, tt.wantCode)
				}

				return
			}

			if err != nil {
				t.Fatalf("Decode error = %v, want success", err)
			}

			if tt.wantFew != nil && !slices.Equal(got.Few, tt.wantFew) {
				t.Errorf("Few = %q, want %q (an array is never truncated)", got.Few, tt.wantFew)
			}
		})
	}
}

// badLimit has a maxitems tag that is not a non-negative integer.
type badLimit struct {
	Items []string `json:"items" maxitems:"many"`
}

type negativeLimit struct {
	Items []string `json:"items" maxitems:"-1"`
}

// TestDecodeRefusesAMalformedLimit: a bad tag is a bug in the code, not in the
// request, so it must not silently leave the array unbounded. Decode panics,
// which ServeRoutes turns into an Internal error.
func TestDecodeRefusesAMalformedLimit(t *testing.T) {
	t.Parallel()

	body := httpapi.Request{Context: t.Context(), Query: nil, Body: []byte(`{"items":["a"]}`)}

	tests := map[string]func() any{
		"not a number": func() any { return httpapi.Decode[badLimit](body) },
		"negative":     func() any { return httpapi.Decode[negativeLimit](body) },
	}

	for name, decode := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("Decode did not panic on a malformed maxitems tag")
				}
			}()

			decode()
		})
	}
}

// echoMethod answers with the method the handler saw, so a test can tell which
// of several handlers ran.
func echoMethod(req httpapi.Request) result.Result[httpapi.Response] {
	return result.Ok(httpapi.JSON(http.StatusOK, req.Method))
}

func methodsHandler(logger httpapi.Logger, wildcards []string) http.Handler {
	return serveMethods(logger, wildcards, map[string]httpapi.Handler{
		http.MethodGet:    echoMethod,
		http.MethodPatch:  echoMethod,
		http.MethodDelete: echoMethod,
	})
}

func TestServeRoutesDispatchesByMethod(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), method, "/x", nil)
			req.Header.Set("Content-Type", jsonType)

			methodsHandler(func(httpapi.Request, *apierr.Error) {}, nil).ServeHTTP(rec, req)

			if rec.Code != http.StatusOK || rec.Body.String() != `"`+method+`"`+"\n" {
				t.Errorf("%s = %d %q, want 200 and the method echoed", method, rec.Code, rec.Body)
			}
		})
	}
}

func TestServeRoutesRefusesOtherMethods(t *testing.T) {
	t.Parallel()

	var logged []*apierr.Error

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/x", nil)
	req.Header.Set("Content-Type", jsonType)

	methodsHandler(func(_ httpapi.Request, e *apierr.Error) { logged = append(logged, e) }, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}

	if got := rec.Header().Get("Allow"); got != "DELETE, GET, PATCH" {
		t.Errorf("Allow = %q, want the methods, sorted", got)
	}

	if len(logged) != 1 {
		t.Errorf("logged %d errors, want 1", len(logged))
	}
}

// TestServeRoutesRequiresJSONForUnsafeMethods holds the CSRF rule per method:
// GET needs no Content-Type, PATCH and DELETE need application/json, and the
// refusal comes before the handler.
func TestServeRoutesRequiresJSONForUnsafeMethods(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method, contentType string
		want                int
	}{
		"get without a type":     {method: http.MethodGet, contentType: "", want: http.StatusOK},
		"patch without a type":   {method: http.MethodPatch, contentType: "", want: http.StatusUnsupportedMediaType},
		"patch as text":          {method: http.MethodPatch, contentType: plainType, want: http.StatusUnsupportedMediaType},
		"delete without a type":  {method: http.MethodDelete, contentType: "", want: http.StatusUnsupportedMediaType},
		"delete as json":         {method: http.MethodDelete, contentType: jsonType, want: http.StatusOK},
		"delete as json+charset": {method: http.MethodDelete, contentType: jsonType + "; charset=utf-8", want: http.StatusOK},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/x", nil)

			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			methodsHandler(func(httpapi.Request, *apierr.Error) {}, nil).ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Errorf("%s = %d %q, want %d", name, rec.Code, rec.Body, tt.want)
			}
		})
	}
}

// TestPathValues checks that the wildcards a route names reach the handler, and
// that one the route does not name, or that matched nothing, does not.
func TestPathValues(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		wildcards []string
		want      map[string]string
	}{
		"named":     {wildcards: []string{"id"}, want: map[string]string{"id": "abc"}},
		"not named": {wildcards: nil, want: map[string]string{}},
		"unknown":   {wildcards: []string{"other"}, want: map[string]string{}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var got map[string]string

			handler := serveMethods(func(httpapi.Request, *apierr.Error) {}, tt.wildcards,
				map[string]httpapi.Handler{http.MethodGet: func(req httpapi.Request) result.Result[httpapi.Response] {
					got = req.PathValues

					return result.Ok(httpapi.JSON(http.StatusOK, nil))
				}})

			mux := http.NewServeMux()
			mux.Handle("/x/{id}", handler)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x/abc", nil))

			if rec.Code != http.StatusOK || !maps.Equal(got, tt.want) {
				t.Errorf("PathValues = %v (status %d), want %v", got, rec.Code, tt.want)
			}
		})
	}
}

// routeLimits are the caps the ServeRoutes tests give each method of one path:
// two tight ones, the default three ways (zero, negative and an absurd value,
// which is clamped) and nothing in between.
func routeLimits() map[string]int64 {
	return map[string]int64{
		http.MethodPatch:  10,
		http.MethodPost:   64,
		http.MethodPut:    0,
		http.MethodDelete: -5,
		http.MethodGet:    1 << 40,
	}
}

// recordingRoutes gives every method of limits a handler that records how much
// body it received.
func recordingRoutes(limits map[string]int64, delivered *int) map[string]httpapi.MethodRoute {
	routes := map[string]httpapi.MethodRoute{}

	for method, limit := range limits {
		handler := func(req httpapi.Request) result.Result[httpapi.Response] {
			*delivered = len(req.Body)

			return result.Ok(httpapi.JSON(http.StatusOK, req.Method))
		}

		routes[method] = httpapi.MethodRoute{MaxBody: limit, Handler: handler}
	}

	return routes
}

// TestServeRoutesLimitsBodiesPerMethod: each method of one path is measured
// against its own cap. A tight cap on one method does not constrain another,
// a body exactly at the cap is delivered whole and one byte more is refused
// before the handler, and a cap of zero, below or above the default means the
// default (a route can only tighten it).
func TestServeRoutesLimitsBodiesPerMethod(t *testing.T) {
	t.Parallel()

	const (
		oneMiB  = 1 << 20
		overMiB = oneMiB + 1
		tooBig  = http.StatusRequestEntityTooLarge
	)

	tests := map[string]struct {
		method     string
		bodyLen    int
		wantStatus int
	}{
		"patch at its cap":              {http.MethodPatch, 10, http.StatusOK},
		"patch one over its cap":        {http.MethodPatch, 11, tooBig},
		"post keeps its own cap":        {http.MethodPost, 64, http.StatusOK},
		"post one over its cap":         {http.MethodPost, 65, tooBig},
		"post far over its cap":         {http.MethodPost, 512 << 10, tooBig},
		"post is not held to patch cap": {http.MethodPost, 11, http.StatusOK},
		"zero means the default":        {http.MethodPut, oneMiB, http.StatusOK},
		"zero default one over":         {http.MethodPut, overMiB, tooBig},
		"negative means the default":    {http.MethodDelete, oneMiB, http.StatusOK},
		"negative default one over":     {http.MethodDelete, overMiB, tooBig},
		"cannot be raised":              {http.MethodGet, overMiB, tooBig},
		"huge cap is the default":       {http.MethodGet, oneMiB, http.StatusOK},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			delivered := -1
			routes := recordingRoutes(routeLimits(), &delivered)

			rec := httptest.NewRecorder()
			body := strings.NewReader(strings.Repeat("a", tt.bodyLen))
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/x", body)
			req.Header.Set("Content-Type", jsonType)

			httpapi.ServeRoutes(func(httpapi.Request, *apierr.Error) {}, nil, routes).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tt.wantStatus, rec.Body)
			}

			if tt.wantStatus == http.StatusOK && delivered != tt.bodyLen {
				t.Errorf("handler got %d bytes, want %d", delivered, tt.bodyLen)
			}

			if tt.wantStatus != http.StatusOK && (delivered != -1 || !strings.Contains(rec.Body.String(), codeTooBig)) {
				t.Errorf("handler ran (%d bytes) or body = %q, want body_too_large without the handler", delivered, rec.Body)
			}
		})
	}
}

// TestServeRoutesAnswersOtherMethodsWithAllow: a method the path does not have
// is 405 with the others listed, sorted, whatever the limits are.
func TestServeRoutesAnswersOtherMethodsWithAllow(t *testing.T) {
	t.Parallel()

	routes := map[string]httpapi.MethodRoute{
		http.MethodPost:   {Handler: echoMethod, MaxBody: 8},
		http.MethodDelete: {Handler: echoMethod, MaxBody: 0},
		http.MethodGet:    {Handler: echoMethod, MaxBody: 0},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/x", nil)
	req.Header.Set("Content-Type", jsonType)

	httpapi.ServeRoutes(func(httpapi.Request, *apierr.Error) {}, nil, routes).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "DELETE, GET, POST" {
		t.Errorf("status = %d, Allow = %q, want 405 and the sorted methods", rec.Code, rec.Header().Get("Allow"))
	}
}

// TestServeRoutesKeepsTheContentTypeAndWildcardRules: ServeRoutes is the same
// boundary for every method, so an unsafe method still needs application/json
// (checked before the body is read) and named wildcards reach the handler.
func TestServeRoutesKeepsTheContentTypeAndWildcardRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		contentType string
		want        int
	}{
		"json":    {contentType: jsonType, want: http.StatusOK},
		"missing": {contentType: "", want: http.StatusUnsupportedMediaType},
		"text":    {contentType: plainType, want: http.StatusUnsupportedMediaType},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var got map[string]string

			handler := func(req httpapi.Request) result.Result[httpapi.Response] {
				got = req.PathValues

				return result.Ok(httpapi.JSON(http.StatusOK, nil))
			}

			routes := map[string]httpapi.MethodRoute{http.MethodPatch: {MaxBody: 4, Handler: handler}}

			mux := http.NewServeMux()
			mux.Handle("/x/{id}", httpapi.ServeRoutes(func(httpapi.Request, *apierr.Error) {}, []string{"id"}, routes))

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/x/abc", nil)

			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			mux.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}

			if tt.want == http.StatusOK && !maps.Equal(got, map[string]string{"id": "abc"}) {
				t.Errorf("PathValues = %v", got)
			}
		})
	}
}

// TestServeAnyHasNoContentTypeRule: the catch-all answers every method as it
// comes, so an unsafe request with any Content-Type, or none, reaches it.
func TestServeAnyHasNoContentTypeRule(t *testing.T) {
	t.Parallel()

	for _, lines := range [][]string{{}, {plainType}, {formType}, {jsonType}} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/anything", strings.NewReader("x"))
		setContentType(req, lines)
		httpapi.ServeAny(func(httpapi.Request, *apierr.Error) {}, httpapi.NotFound).ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound || rec.Body.String() != notFoundBody {
			t.Errorf("POST with %v = %d %q, want the 404 envelope", lines, rec.Code, rec.Body)
		}
	}
}
