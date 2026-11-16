package diag_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/diag"
)

const infoPath = "/debug/info"

func serve(t *testing.T, impl diag.Diagnostics, method, path string) *httptest.ResponseRecorder {
	t.Helper()

	mux := http.NewServeMux()
	impl.Register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))

	return rec
}

func TestOffRegistersNothing(t *testing.T) {
	t.Parallel()

	if rec := serve(t, diag.Off{}, http.MethodGet, infoPath); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestOnInfo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method     string
		wantStatus int
		wantBody   string
		wantAllow  string
	}{
		"get":  {method: http.MethodGet, wantStatus: http.StatusOK, wantBody: "debug_routes=on"},
		"head": {method: http.MethodHead, wantStatus: http.StatusOK},
		"post": {method: http.MethodPost, wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, HEAD"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := serve(t, diag.On{}, tt.method, infoPath)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
			if got := rec.Header().Get("Allow"); got != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tt.wantAllow)
			}
		})
	}
}
