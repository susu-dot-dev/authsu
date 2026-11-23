//nolint:goconst // table-driven tests repeat case inputs on purpose; a constant per row would hide the table
package httpapi_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// seen is what a handler behind Local was handed.
type seen struct {
	method, path, contentType string
	authorization             []string
	hasCookie                 bool
	origin                    string
}

// equal reports whether two requests carried the same things.
func (s seen) equal(other seen) bool {
	return s.method == other.method && s.path == other.path && s.contentType == other.contentType &&
		slices.Equal(s.authorization, other.authorization) && s.hasCookie == other.hasCookie && s.origin == other.origin
}

// wasSeen reads what the request carried.
func wasSeen(r *http.Request) seen {
	_, err := r.Cookie("any")

	return seen{
		method: r.Method, path: r.URL.Path, contentType: r.Header.Get("Content-Type"),
		authorization: r.Header.Values("Authorization"), hasCookie: err == nil, origin: r.Header.Get("Origin"),
	}
}

// TestLocalCarriesExactlyWhatTheCallerPassed: the method, path and
// Authorization values reach the handler, the Content-Type is JSON, and nothing
// else is on the request. Its answer is the status and body the handler wrote.
func TestLocalCarriesExactlyWhatTheCallerPassed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		method        string
		authorization []string
		status        int
	}{
		{"a read", http.MethodGet, []string{"Bearer a"}, http.StatusOK},
		{"a write", http.MethodPost, []string{"Bearer a"}, http.StatusCreated},
		{"two Authorization lines are both carried", http.MethodDelete, []string{"Bearer a", "Bearer b"}, http.StatusOK},
		{"no Authorization", http.MethodGet, nil, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got seen

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = wasSeen(r)

				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte("answer"))
			})

			resp, err := httpapi.Local(handler)(context.Background(), tt.method, "/x", []byte("{}"), tt.authorization)
			if err != nil {
				t.Fatalf("Local: %v", err)
			}

			want := seen{
				method: tt.method, path: "/x", contentType: "application/json", authorization: tt.authorization,
				hasCookie: false, origin: "",
			}

			if resp.Status != tt.status || string(resp.Body) != "answer" || !got.equal(want) {
				t.Errorf("response = %d %q, handler saw %+v, want %d and %+v", resp.Status, resp.Body, got, tt.status, want)
			}
		})
	}
}

// TestLocalRunsTheRealBoundary: a route behind ServeRoutes gets the same
// checks as one reached over the network, so a wrong method is refused in its
// own format and the body the route reads is the one passed.
func TestLocalRunsTheRealBoundary(t *testing.T) {
	t.Parallel()

	logger := func(httpapi.Request, *apierr.Error) {}
	local := httpapi.Local(serve(http.MethodPost, logger, func(req httpapi.Request) result.Result[httpapi.Response] {
		return result.Ok(httpapi.JSON(http.StatusOK, map[string]string{"body": string(req.Body)}))
	}))

	resp, err := local(context.Background(), http.MethodPost, "/", []byte("{}"), nil)
	if err != nil || resp.Status != http.StatusOK || string(resp.Body) != `{"body":"{}"}`+"\n" {
		t.Errorf("a POST = %d %q, %v", resp.Status, resp.Body, err)
	}

	resp, err = local(context.Background(), http.MethodGet, "/", nil, nil)
	if err != nil || resp.Status != http.StatusMethodNotAllowed {
		t.Errorf("a GET = %d %q, %v, want 405", resp.Status, resp.Body, err)
	}
}

// TestLocalDefaultsToOKAndRefusesAnUnbuildableRequest: a handler that writes
// nothing is a 200 with no body, and a method that is not a request is a
// classified Internal error, not a panic.
func TestLocalDefaultsToOKAndRefusesAnUnbuildableRequest(t *testing.T) {
	t.Parallel()

	local := httpapi.Local(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	resp, err := local(context.Background(), http.MethodGet, "/x", nil, nil)
	if err != nil || resp.Status != http.StatusOK || len(resp.Body) != 0 {
		t.Errorf("a silent handler = %d %q, %v", resp.Status, resp.Body, err)
	}

	_, err = local(context.Background(), "BAD METHOD", "/x", nil, nil)

	failure := apierr.As(err)
	if failure.Code != httpapi.CodeLocalRequestFailed || failure.Kind != apierr.Internal {
		t.Errorf("error = %v, want Internal %s", err, httpapi.CodeLocalRequestFailed)
	}
}

// TestFailureBody: the body of a refusal is the API's own error body, an
// Internal failure is the bare "internal", and the cause is never in it.
func TestFailureBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		failure *apierr.Error
		want    string
	}{
		{"a client error", apierr.New(apierr.BadRequest, "invalid_id", "id is not valid"),
			`{"error":{"code":"invalid_id","message":"id is not valid"}}` + "\n"},
		{"with data", apierr.New(apierr.Conflict, "x", "y").WithData(map[string]int64{"uses": 3}),
			`{"error":{"code":"x","message":"y","data":{"uses":3}}}` + "\n"},
		{"an internal failure", apierr.New(apierr.Internal, "boom", "detail").WithCause(errCause),
			`{"error":{"code":"internal","message":"internal error"}}` + "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := string(httpapi.FailureBody(tt.failure))
			if got != tt.want || strings.Contains(got, "hidden_table") {
				t.Errorf("FailureBody = %q, want %q", got, tt.want)
			}
		})
	}
}
