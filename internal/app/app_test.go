package app_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/app"
)

func TestHealthz(t *testing.T) {
	t.Parallel()

	const path = "/healthz"

	tests := map[string]struct {
		method     string
		path       string
		wantStatus int
		wantBody   string
		wantAllow  string
	}{
		"get": {
			method: http.MethodGet, path: path,
			wantStatus: http.StatusOK, wantBody: "ok\n",
		},
		"head": {
			method: http.MethodHead, path: path,
			wantStatus: http.StatusOK,
		},
		"post": {
			method: http.MethodPost, path: path,
			wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, HEAD",
		},
		"unknown path": {
			method: http.MethodGet, path: "/nope",
			wantStatus: http.StatusNotFound,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			app.NewHandler(app.Deps{}, app.Platform{}).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusOK && rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
			if got := rec.Header().Get("Allow"); got != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tt.wantAllow)
			}
		})
	}
}

type fakeDiagnostics struct{ registered bool }

func (f *fakeDiagnostics) Register(mux *http.ServeMux) {
	f.registered = true

	mux.HandleFunc("/fake", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
}

func TestDiagnosticsWiring(t *testing.T) {
	t.Parallel()

	fake := &fakeDiagnostics{}
	handler := app.NewHandler(app.Deps{Diagnostics: fake}, app.Platform{})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fake", nil))

	if !fake.registered {
		t.Error("Diagnostics.Register was not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestNilDiagnosticsRegistersNothing(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/debug/info", nil)
	app.NewHandler(app.Deps{}, app.Platform{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
