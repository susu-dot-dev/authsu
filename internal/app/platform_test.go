package app_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/app"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// completePlatform is a Platform with every resource.
func completePlatform() app.Platform {
	return app.Platform{
		Exec: func(context.Context, ...store.Statement) ([]store.Result, error) {
			return nil, errUnscripted
		},
		Getenv: func(string) string { return "" },
		Log:    func(httpapi.Request, *apierr.Error) {},
		Fetch:  func(*http.Request) (*http.Response, error) { return nil, errUnscripted },
	}
}

// TestNewHandlerRequiresEveryResource: there is no degraded mode. A Platform
// missing a resource is a wiring mistake found when the Worker starts, not a
// 503 on a request.
func TestNewHandlerRequiresEveryResource(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		without func(*app.Platform)
		field   string
	}{
		"Exec":   {without: func(p *app.Platform) { p.Exec = nil }, field: "Exec"},
		"Getenv": {without: func(p *app.Platform) { p.Getenv = nil }, field: "Getenv"},
		"Log":    {without: func(p *app.Platform) { p.Log = nil }, field: "Log"},
		"Fetch":  {without: func(p *app.Platform) { p.Fetch = nil }, field: "Fetch"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			platform := completePlatform()
			tt.without(&platform)

			defer func() {
				message := fmt.Sprint(recover())
				if !strings.Contains(message, "Platform."+tt.field+" is required") {
					t.Errorf("panic = %q, want it to name Platform.%s", message, tt.field)
				}
			}()

			app.NewHandler(platform)

			t.Error("NewHandler did not panic")
		})
	}

	t.Run("the zero value", func(t *testing.T) {
		t.Parallel()

		defer func() {
			if recover() == nil {
				t.Error("NewHandler(Platform{}) did not panic")
			}
		}()

		app.NewHandler(app.Platform{})
	})

	t.Run("a complete platform", func(t *testing.T) {
		t.Parallel()

		if app.NewHandler(completePlatform()) == nil {
			t.Error("NewHandler returned nil")
		}
	})
}
