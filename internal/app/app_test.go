package app_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/app"
	"github.com/susu-dot-dev/authsu/internal/diag"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
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
			wantStatus: http.StatusOK, wantBody: `{"status":"ok"}` + "\n",
		},
		"post": {
			method: http.MethodPost, path: path,
			wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodGet,
			wantBody: `{"error":{"code":"method_not_allowed","message":"method not allowed"}}` + "\n",
		},
		"unknown path": {
			method: http.MethodGet, path: "/nope",
			wantStatus: http.StatusNotFound,
			wantBody:   `{"error":{"code":"not_found","message":"no such route"}}` + "\n",
		},
		"unknown path any method": {
			method: http.MethodPost, path: "/nope",
			wantStatus: http.StatusNotFound,
			wantBody:   `{"error":{"code":"not_found","message":"no such route"}}` + "\n",
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

func (f *fakeDiagnostics) Register(router diag.Router) {
	f.registered = true

	router.Handle(http.MethodGet, "/fake", func(httpapi.Request) result.Result[httpapi.Response] {
		return result.Ok(httpapi.Response{Status: http.StatusTeapot, Body: nil})
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

var errDB = errors.New("database is on fire")

// failingConnector makes every database operation fail, to drive a handler
// error through the whole app.
type failingConnector struct{}

func (failingConnector) Connect(context.Context) (driver.Conn, error) { return nil, errDB }
func (failingConnector) Driver() driver.Driver                        { return nil }

func failingDB(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(failingConnector{})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func TestFailureIsLoggedAndHidden(t *testing.T) {
	t.Parallel()

	var logged []*apierr.Error

	var loggedReq httpapi.Request

	platform := app.Platform{
		DB:     failingDB(t),
		Getenv: func(string) string { return "" },
		Log: func(req httpapi.Request, failure *apierr.Error) {
			loggedReq = req
			logged = append(logged, failure)
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/first-run", nil)
	app.NewHandler(app.Deps{}, platform).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	if strings.Contains(rec.Body.String(), errDB.Error()) {
		t.Errorf("body leaks the cause: %q", rec.Body.String())
	}

	if !strings.Contains(rec.Body.String(), "first-run status is temporarily unavailable") {
		t.Errorf("body = %q, want the client-safe description", rec.Body.String())
	}

	if len(logged) != 1 || !errors.Is(logged[0], errDB) || logged[0].Code != firstrun.CodeUsersCheckFailed {
		t.Errorf("logged = %v, want one classified error wrapping the cause", logged)
	}

	if loggedReq.Method != http.MethodGet || loggedReq.Path != "/api/first-run" {
		t.Errorf("logged request = %s %s, want GET /api/first-run", loggedReq.Method, loggedReq.Path)
	}
}

func TestNilLogDiscards(t *testing.T) {
	t.Parallel()

	platform := app.Platform{DB: failingDB(t), Getenv: func(string) string { return "" }}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/first-run", nil)
	app.NewHandler(app.Deps{}, platform).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}
