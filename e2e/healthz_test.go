//go:build e2e

package e2e_test

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// get issues a request against the Worker under test and returns the status
// and body.
func get(t *testing.T, method, path string) (int, string) {
	t.Helper()

	// Not t.Context(): that is cancelled before t.Cleanup callbacks run.
	req, err := http.NewRequestWithContext(context.Background(), method, target.baseURL+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return resp.StatusCode, string(body)
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method     string
		path       string
		wantStatus int
		wantBody   string
	}{
		"get":          {method: http.MethodGet, path: "/healthz", wantStatus: http.StatusOK, wantBody: "ok\n"},
		"wrong method": {method: http.MethodPost, path: "/healthz", wantStatus: http.StatusMethodNotAllowed},
		"unknown path": {method: http.MethodGet, path: "/nope", wantStatus: http.StatusNotFound},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			status, body := get(t, tt.method, tt.path)
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}

			if tt.wantBody != "" && body != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}
