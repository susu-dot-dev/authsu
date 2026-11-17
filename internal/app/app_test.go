package app_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/app"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
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

			req := newRequest(t, tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			app.NewHandler(app.Platform{}).ServeHTTP(rec, req)

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
	req := newRequest(t, http.MethodGet, "/api/first-run", nil)
	app.NewHandler(platform).ServeHTTP(rec, req)

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
	req := newRequest(t, http.MethodGet, "/api/first-run", nil)
	app.NewHandler(platform).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// newRequest builds a request as the same-origin frontend sends it: with
// Content-Type: application/json, which every unsafe route requires.
func newRequest(t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, body)
	req.Header.Set("Content-Type", "application/json")

	return req
}

// TestUnsafeRoutesRequireJSON checks the CSRF defence is wired to every route
// that changes something: a POST another site could make a browser send (no
// Content-Type, or a CORS-safelisted one) is refused with 415 before any
// handler runs, even with an empty body and with the deployment fully
// configured. See httpapi's package doc.
func TestUnsafeRoutesRequireJSON(t *testing.T) {
	t.Parallel()

	paths := []string{beginPath, finishPath, loginBeginPath, loginFinishPath, logoutPath}

	for _, path := range paths {
		for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
			t.Run(path+" "+contentType, func(t *testing.T) {
				t.Parallel()

				rec := httptest.NewRecorder()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)

				if contentType != "" {
					req.Header.Set("Content-Type", contentType)
				}

				app.NewHandler(app.Platform{Getenv: loginEnv}).ServeHTTP(rec, req)

				if rec.Code != http.StatusUnsupportedMediaType ||
					!strings.Contains(rec.Body.String(), `"unsupported_media_type"`) {
					t.Errorf("POST %s (%q) = %d %s, want 415 unsupported_media_type",
						path, contentType, rec.Code, rec.Body)
				}
			})
		}
	}
}
