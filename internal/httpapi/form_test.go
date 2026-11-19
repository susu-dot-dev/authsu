package httpapi_test

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// recognisedNames are the names the parsing tests declare.
func recognisedNames() []string { return []string{"a", "b", scopeName, "state"} }

// values is what the parsing tests expect of the recognised parameters.
type values = map[string]string

// accepted is a body or query string that parses, and the recognised values it
// gives (an empty one is absent).
type accepted struct {
	raw  string
	want values
}

// acceptedParams are the strings ParseParams accepts.
func acceptedParams() map[string]accepted {
	long := strings.Repeat("x", 100_000)

	return map[string]accepted{
		"nothing":                      {"", values{}},
		"one pair":                     {oneParam, values{"a": "1"}},
		"two pairs":                    {"a=1&b=2", values{"a": "1", "b": "2"}},
		"order does not matter":        {"b=2&a=1", values{"a": "1", "b": "2"}},
		"a value with an equals sign":  {"a=x=y=", values{"a": "x=y="}},
		"a value with a question mark": {"a=?x", values{"a": "?x"}},
		"percent-encoding":             {"a=%41%62%2f", values{"a": "Ab/"}},
		"lower-case hex":               {"a=%2f", values{"a": "/"}},
		"upper-case hex":               {"a=%2F", values{"a": "/"}},
		"plus is a space":              {"scope=openid+mcp%3Aread", values{scopeName: "openid mcp:read"}},
		"%20 is a space":               {"scope=openid%20mcp%3Aread", values{scopeName: "openid mcp:read"}},
		"%2B is a plus":                {"a=1%2B1", values{"a": "1+1"}},
		"plus in a name":               {"a+b=1", values{}},
		"UTF-8":                        {"a=%C3%A9", values{"a": "é"}},
		"raw UTF-8":                    {"a=é", values{"a": "é"}},
		"a semicolon is not a pair":    {"a=1;b=2", values{"a": "1;b=2"}},
		"a hash is not special":        {"a=1#b=2", values{"a": "1#b=2"}},
		"a leading ampersand":          {"&a=1", values{"a": "1"}},
		"a trailing ampersand":         {"a=1&", values{"a": "1"}},
		"empty pairs":                  {"a=1&&&b=2", values{"a": "1", "b": "2"}},
		"only ampersands":              {"&&&", values{}},
		"names are case sensitive":     {"A=1&a=2", values{"a": "2"}},
		"names are decoded":            {"%73cope=x", values{scopeName: "x"}},
		"a value that is a space":      {"a=+", values{"a": " "}},
		"a value that is spaces":       {"a=%20%20", values{"a": "  "}},
		"a long value":                 {"a=" + long, values{"a": long}},
	}
}

// absentParams are the strings that parse and read as absent (RFC 6749
// section 3.1), or are ignored because the parameter is not recognised.
func absentParams() map[string]accepted {
	return map[string]accepted{
		emptyValue:                      {"a=", values{}},
		"empty among others":            {"a=&b=2", values{"b": "2"}},
		"no equals sign":                {"a", values{}},
		"no equals among":               {"a&b=2", values{"b": "2"}},
		"encoded name, empty":           {"%61=", values{}},
		"unknown":                       {"x=1&a=1", values{"a": "1"}},
		"unknown only":                  {"x=1&y=2", values{}},
		"unknown repeated":              {"x=1&x=2&a=1", values{"a": "1"}},
		"unknown with an empty value":   {"x=&a=1", values{"a": "1"}},
		"unknown with a NUL":            {"x=%00&a=1", values{"a": "1"}},
		"unknown with invalid UTF-8":    {"x=%FF&a=1", values{"a": "1"}},
		"unknown with a long value":     {"x=" + strings.Repeat("y", 10_000) + "&a=1", values{"a": "1"}},
		"unknown that looks recognised": {"aa=1&sscope=2&A=3", values{}},
	}
}

// refusedParams are the strings ParseParams refuses, with the code it gives.
func refusedParams() map[string]struct{ raw, code string } {
	type refused = struct{ raw, code string }

	return map[string]refused{
		"duplicate":                    {"a=1&a=2", codeDuplicate},
		"duplicate, same value":        {"a=1&a=1", codeDuplicate},
		"duplicate, first empty":       {"a=&a=1", codeDuplicate},
		"duplicate, both empty":        {"a=&a=", codeDuplicate},
		"duplicate, no equals":         {"a&a=1", codeDuplicate},
		"duplicate, encoded name":      {"a=1&%61=2", codeDuplicate},
		"duplicate, plus-encoded name": {"scope=1&scope=2", codeDuplicate},
		"duplicate among others":       {"a=1&b=2&x=3&a=4", codeDuplicate},
		"truncated escape in a value":  {"a=%4", codeEncoding},
		"lone percent":                 {"a=%", codeEncoding},
		"non-hex escape":               {"a=%zz", codeEncoding},
		"half non-hex escape":          {"a=%4g", codeEncoding},
		"bad escape in a name":         {"%zz=1", codeEncoding},
		"bad escape, unknown value":    {"x=%zz&a=1", codeEncoding},
		"bad escape, unknown name":     {"x%=1&a=1", codeEncoding},
		"bad escape, no equals":        {"x%", codeEncoding},
		"NUL":                          {"a=%00", codeText},
		"NUL inside":                   {"a=x%00y", codeText},
		"a raw NUL":                    {"a=x\x00y", codeText},
		"invalid UTF-8":                {"a=%FF", codeText},
		"truncated UTF-8":              {"a=%C3", codeText},
		"overlong UTF-8":               {"a=%C0%AF", codeText},
		"a surrogate":                  {"a=%ED%A0%80", codeText},
		"a raw invalid byte":           {"a=\xff", codeText},
		"no name":                      {"=1", codeParamName},
		"equals alone":                 {"=", codeParamName},
		"no name among others":         {"a=1&=2", codeParamName},
		"a name that decodes to empty": {"=%41", codeParamName},
	}
}

// TestParseParams pins every decision in the rules of ParseParams: the
// recognised values that come out (an empty one is absent), or the error code
// that comes out. Each case is a body or a query string, which are parsed
// alike.
func TestParseParams(t *testing.T) {
	t.Parallel()

	good := acceptedParams()
	maps.Copy(good, absentParams())

	for name, tt := range good {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			params, err := httpapi.ParseParams(tt.raw, recognisedNames()...).Get()
			if err != nil {
				t.Fatalf("error = %v", err)
			}

			got := values{}

			for _, key := range recognisedNames() {
				if value, present := params.Get(key); present {
					got[key] = value
				}
			}

			if !maps.Equal(got, tt.want) {
				t.Errorf("values = %v, want %v", got, tt.want)
			}
		})
	}

	for name, tt := range refusedParams() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := httpapi.ParseParams(tt.raw, recognisedNames()...).Get()

			failure := apierr.As(err)
			if failure.Kind != apierr.BadRequest || failure.Code != tt.code {
				t.Fatalf("error = %v, want a BadRequest %s", err, tt.code)
			}
		})
	}
}

// TestParamsErrorsDoNotEchoInput: a description is fixed text plus, at most, the
// name of a parameter the handler declared. What a client sent never comes back.
func TestParamsErrorsDoNotEchoInput(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"a=%zzSECRET", "SECRET%=1", "SECRET=1&=x", "a=SECRET%00", "a=1&a=SECRET"} {
		_, err := httpapi.ParseParams(raw, "a").Get()
		if err == nil {
			t.Fatalf("%q was accepted", raw)
		}

		if strings.Contains(apierr.As(err).Description, "SECRET") {
			t.Errorf("%q: description %q echoes the input", raw, apierr.As(err).Description)
		}
	}
}

// TestParamsGetRefusesAnUndeclaredName: asking for a name that was not declared
// is a bug in the handler, not an absent parameter.
func TestParamsGetRefusesAnUndeclaredName(t *testing.T) {
	t.Parallel()

	params, err := httpapi.ParseParams("a=1&x=2", "a").Get()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if recover() == nil {
			t.Error("Get of an undeclared name did not panic")
		}
	}()

	params.Get("x")
}

// paramsCase is a request to a route that reads parameter a, and the answer.
type paramsCase struct {
	method, target, body string
	fromBody             bool
	wantStatus           int
	wantBody             string
}

const (
	dupBody   = `{"error":"invalid_request","error_description":"a parameter was sent more than once"}` + "\n"
	escapeMsg = `{"error":"invalid_request","error_description":"a parameter value is not validly percent-encoded"}` + "\n"
)

// found is the answer of a handler that read a.
func found(value string, present bool) string {
	return fmt.Sprintf(`{"a":%q,"present":%t}`, value, present) + "\n"
}

func paramsCases() map[string]paramsCase {
	post, get := http.MethodPost, http.MethodGet

	return map[string]paramsCase{
		"form body":                   {post, "/x", "a=1%2B1&x=2", true, http.StatusOK, found("1+1", true)},
		"form body, duplicate":        {post, "/x", "a=1&a=2", true, http.StatusBadRequest, dupBody},
		"form body ignores the query": {post, "/x?a=9", oneParam, true, http.StatusOK, found("1", true)},
		"form body with no a":         {post, "/x?a=9", "", true, http.StatusOK, found("", false)},
		"query":                       {get, "/x?a=hello+world&x=1", "", false, http.StatusOK, found("hello world", true)},
		"query ignores the body":      {get, "/x", "a=9", false, http.StatusOK, found("", false)},
		"query, duplicate":            {get, "/x?a=1&a=2", "", false, http.StatusBadRequest, dupBody},
		"query, a bad escape that net/http would drop": {
			get, "/x?a=1&b=%zz", "", false, http.StatusBadRequest, escapeMsg,
		},
		"query, a semicolon is not a separator": {get, "/x?a=1;a=2", "", false, http.StatusOK, found("1;a=2", true)},
	}
}

// TestRequestParams reads the body and the query string through the boundary:
// a form route's body, and a GET's query string, each with the same rules.
func TestRequestParams(t *testing.T) {
	t.Parallel()

	for name, tt := range paramsCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := func(req httpapi.Request) result.Result[httpapi.Response] {
				parse := req.QueryParams
				if tt.fromBody {
					parse = req.FormParams
				}

				return parse("a").Map(func(p httpapi.Params) httpapi.Response {
					a, present := p.Get("a")

					return httpapi.JSON(http.StatusOK, map[string]any{"a": a, "present": present})
				})
			}

			media := httpapi.MediaJSON
			if tt.fromBody {
				media = httpapi.MediaForm
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.target, strings.NewReader(tt.body))

			if tt.method != http.MethodGet {
				req.Header.Set("Content-Type", formType)
			}

			serveRoute(tt.method, httpapi.MethodRoute{
				Handler: handler, MaxBody: 0, Media: media, Errors: httpapi.ErrorsOAuth,
			}).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("status = %d, body = %q, want %d, %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}
		})
	}
}

// TestRequestRawQuery: the handler is given the query exactly as sent.
func TestRequestRawQuery(t *testing.T) {
	t.Parallel()

	var got httpapi.Request

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x?a=%41+b&%zz", nil)
	serveRoute(http.MethodGet, httpapi.MethodRoute{
		Handler: func(r httpapi.Request) result.Result[httpapi.Response] {
			got = r

			return result.Ok(httpapi.Response{Status: http.StatusNoContent})
		},
	}).ServeHTTP(rec, req)

	if got.RawQuery != "a=%41+b&%zz" {
		t.Errorf("RawQuery = %q", got.RawQuery)
	}
}

// limitCase is a request to a route whose limit is limitBytes.
type limitCase struct {
	method, target, body string
	wantStatus           int
	wantCode             string
}

const limitBytes = 64

// padded is the parameter a with a value that makes it size bytes long.
func padded(size int) string { return "a=" + strings.Repeat("x", size-len("a=")) }

func limitCases() map[string]limitCase {
	post, get := http.MethodPost, http.MethodGet
	noContent, tooLarge := http.StatusNoContent, http.StatusRequestEntityTooLarge

	return map[string]limitCase{
		"body at the limit":       {post, "/x", padded(limitBytes), noContent, ""},
		"body over the limit":     {post, "/x", padded(limitBytes + 1), tooLarge, codeTooBig},
		"body far over":           {post, "/x", strings.Repeat("a=1&", 100_000), tooLarge, codeTooBig},
		"query at the limit":      {get, "/x?" + padded(limitBytes), "", noContent, ""},
		"query over the limit":    {get, "/x?" + padded(limitBytes+1), "", tooLarge, "query_too_large"},
		"query far over":          {get, "/x?a=" + strings.Repeat("x", 2<<20), "", tooLarge, "query_too_large"},
		"body is not the query":   {post, "/x?" + padded(limitBytes), oneParam, noContent, ""},
		"query is not the body":   {get, "/x?a=1", "", noContent, ""},
		"the empty query is fine": {get, "/x", "", noContent, ""},
	}
}

// TestFormAndQueryAreBoundedByTheRouteLimit: a body or a query string over the
// route's MaxBody is 413 before the handler runs, in the route's format, and one
// at the limit is read. Writes happen only in handlers, so nothing was written.
func TestFormAndQueryAreBoundedByTheRouteLimit(t *testing.T) {
	t.Parallel()

	for name, tt := range limitCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var (
				handled bool
				logged  []*apierr.Error
			)

			handler := func(httpapi.Request) result.Result[httpapi.Response] {
				handled = true

				return result.Ok(httpapi.Response{Status: http.StatusNoContent})
			}

			media := httpapi.MediaForm
			if tt.method == http.MethodGet {
				media = httpapi.MediaJSON
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.target, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", formType)
			httpapi.ServeRoutes(func(_ httpapi.Request, e *apierr.Error) { logged = append(logged, e) }, nil,
				map[string]httpapi.MethodRoute{tt.method: {
					Handler: handler, MaxBody: limitBytes, Media: media, Errors: httpapi.ErrorsOAuth,
				}}).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus || handled != (tt.wantCode == "") {
				t.Errorf("status = %d, handled = %t, want %d, %t", rec.Code, handled, tt.wantStatus, tt.wantCode == "")
			}

			if tt.wantCode == "" {
				return
			}

			if len(logged) != 1 || logged[0].Code != tt.wantCode {
				t.Errorf("logged %v, want one %s", logged, tt.wantCode)
			}

			if !strings.HasPrefix(rec.Body.String(), `{"error":"invalid_request","error_description":"`) {
				t.Errorf("body = %q, want an OAuth invalid_request", rec.Body)
			}
		})
	}
}
