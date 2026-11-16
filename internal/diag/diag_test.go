package diag_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/diag"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

const infoPath = "/debug/info"

// fakeRouter records registrations, and can serve them without a mux.
type fakeRouter struct {
	method   string
	path     string
	handlers int
	handler  httpapi.Handler
}

func (f *fakeRouter) Handle(method, path string, handler httpapi.Handler) {
	f.method, f.path, f.handler = method, path, handler
	f.handlers++
}

func TestOffRegistersNothing(t *testing.T) {
	t.Parallel()

	router := &fakeRouter{}
	diag.Off{}.Register(router)

	if router.handlers != 0 {
		t.Errorf("Off registered %d handlers, want 0", router.handlers)
	}
}

func TestOnRegistersInfo(t *testing.T) {
	t.Parallel()

	router := &fakeRouter{}
	diag.On{}.Register(router)

	if router.handlers != 1 || router.method != http.MethodGet || router.path != infoPath {
		t.Fatalf("registered %d handlers, first = %s %s", router.handlers, router.method, router.path)
	}

	resp, err := router.handler(httpapi.Request{Context: t.Context(), Query: nil, Body: nil}).Get()
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.Status, http.StatusOK)
	}

	// Serve the response the way the app would, to check the JSON shape.
	rec := httptest.NewRecorder()
	httpapi.Serve(http.MethodGet, func(httpapi.Request, *apierr.Error) {}, router.handler).
		ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, infoPath, nil))

	if !strings.Contains(rec.Body.String(), `"debugRoutes":"on"`) {
		t.Errorf("body = %q, want it to report debug_routes on", rec.Body.String())
	}
}
