package httpapi

import (
	"bytes"
	"context"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
)

// CodeLocalRequestFailed is the error code of a request Local could not build.
// It is a programming error (a method or path that is not a request), so it is
// Internal and the client sees a bare "internal".
const CodeLocalRequestFailed = "local_request_failed"

// LocalResponse is what a handler answered a request made with Local.
type LocalResponse struct {
	// Status is the HTTP status the handler wrote, 200 when it wrote none.
	Status int
	// Body is what it wrote.
	Body []byte
}

// Local returns a function that sends a request to handler in the same process,
// as if it had arrived over the network, and returns the answer. It is how one
// endpoint runs another endpoint's route, so that everything the route does
// before its handler (credential, access, parsing) happens exactly as for a
// request from outside, and nothing is copied.
//
// Only what the caller passes is on the request: the method, the path, the
// body, and the Authorization header values. The Content-Type is always JSON.
// No cookie, no Origin and no other header is carried, so a credential the
// caller did not present on purpose is never forwarded.
//
// The function returns an error only for a request that cannot be built, which
// is a method or path that is not a request: a programming error and Internal.
func Local(handler http.Handler) func(
	ctx context.Context, method, path string, body []byte, authorization []string,
) (LocalResponse, error) {
	return func(ctx context.Context, method, path string, body []byte, authorization []string) (LocalResponse, error) {
		req, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
		if err != nil {
			return LocalResponse{}, apierr.Wrap(err, apierr.Internal, CodeLocalRequestFailed, "internal error")
		}

		req.Header.Set("Content-Type", jsonMediaType)

		for _, value := range authorization {
			req.Header.Add("Authorization", value)
		}

		rec := &recorder{header: http.Header{}, status: http.StatusOK, body: bytes.Buffer{}}
		handler.ServeHTTP(rec, req)

		return LocalResponse{Status: rec.status, Body: rec.body.Bytes()}, nil
	}
}

// recorder is the in-memory http.ResponseWriter Local gives a handler.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) { r.status = status }

func (r *recorder) Write(data []byte) (int, error) {
	// A bytes.Buffer's Write never fails.
	_, _ = r.body.Write(data)

	return len(data), nil
}
