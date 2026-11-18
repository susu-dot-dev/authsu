//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"bytes"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// TestCallIDOfARouteWithoutAnIDIsAProgrammingError: asking for the id of a route
// whose path has none panics, which the boundary reports as an internal error
// instead of handing back an empty id for a query to treat as "no such row".
func TestCallIDOfARouteWithoutAnIDIsAProgrammingError(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ path, target string }{
		"a route without wildcards": {path: "/x", target: "/x"},
		"an exact root":             {path: "/{$}", target: "/"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			routes := []auth.Route{{
				Method: http.MethodGet, Path: tt.path, MaxBody: 0, Credential: auth.None, Access: accessFor(auth.None),
				Handle: func(call *auth.Call) result.Result[httpapi.Response] {
					_ = call.ID()

					return result.Ok(httpapi.JSON(http.StatusOK, nil))
				},
			}}

			rec := r.serve(routes, request{target: tt.target})
			wantFailure(t, r, rec, http.StatusInternalServerError, bodyInternal, "handler_panic", nil)
		})
	}
}

// configAnswers is what a route saw when it asked for the configuration twice.
type configAnswers struct {
	first, second       config.Config
	firstErr, secondErr error
}

// asksTwice is a route body that asks for the configuration twice.
func asksTwice(out *configAnswers) func(*auth.Call) result.Result[httpapi.Response] {
	return func(call *auth.Call) result.Result[httpapi.Response] {
		out.first, out.firstErr = call.Config()
		out.second, out.secondErr = call.Config()

		return result.Ok(httpapi.JSON(http.StatusOK, nil))
	}
}

// loadCost is how many times a successful config.Load reads the environment.
func (r *rig) loadCost() int {
	reads := 0

	_, err := config.Load(func(name string) string {
		reads++

		return r.env[name]
	})
	if err != nil {
		r.t.Fatalf("Load: %v", err)
	}

	return reads
}

// TestCallConfigIsLoadedOncePerRequest: the pipeline and the handler share one
// load, so asking more than once costs nothing, and a route that never asks,
// and does not need a session, never loads.
func TestCallConfigIsLoadedOncePerRequest(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		credential auth.Credential
		asks       bool
		cookies    cookieFn
		wantLoads  int
	}{
		"a none route that asks twice":    {credential: auth.None, asks: true, cookies: nil, wantLoads: 1},
		"a none route that never asks":    {credential: auth.None, asks: false, cookies: nil, wantLoads: 0},
		"a session route that asks twice": {credential: auth.Authenticated, asks: true, cookies: valid, wantLoads: 1},
		"a session route that never asks": {credential: auth.Authenticated, asks: false, cookies: valid, wantLoads: 1},
		"a session route that is refused": {
			credential: auth.Authenticated, asks: true, cookies: sessionValue("garbage"), wantLoads: 1,
		},
		"a session route without a session": {credential: auth.Authenticated, asks: true, cookies: nil, wantLoads: 1},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			var answers configAnswers

			handle := r.capture
			if tt.asks {
				handle = asksTwice(&answers)
			}

			routes := []auth.Route{{
				Method: http.MethodGet, Path: "/c", MaxBody: 0,
				Credential: tt.credential, Access: accessFor(tt.credential), Handle: handle,
			}}

			var cookies []*http.Cookie
			if tt.cookies != nil {
				cookies = tt.cookies(r)
			}

			r.serve(routes, request{target: "/c", cookies: cookies})

			if want := tt.wantLoads * r.loadCost(); r.envReads != want {
				t.Errorf("read the environment %d times, want %d (%d load(s))", r.envReads, want, tt.wantLoads)
			}
		})
	}
}

// TestCallConfigValues: the configuration is the deployment's, derived keys
// included.
func TestCallConfigValues(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	var answers configAnswers

	routes := []auth.Route{{
		Method: http.MethodGet, Path: "/c", MaxBody: 0,
		Credential: auth.None, Access: accessFor(auth.None), Handle: asksTwice(&answers),
	}}

	r.serve(routes, request{target: "/c"})

	if answers.firstErr != nil || answers.secondErr != nil {
		t.Fatalf("Config: %v, %v", answers.firstErr, answers.secondErr)
	}

	cfg := answers.first

	if cfg.API.String != apiOrigin || cfg.UI.String != uiOrigin || cfg.RP.ID != "example.com" {
		t.Errorf("config = %+v", cfg)
	}

	if !bytes.Equal(cfg.RegistrationKey, answers.second.RegistrationKey) || len(cfg.RegistrationKey) == 0 ||
		bytes.Equal(cfg.RegistrationKey, cfg.LoginKey) {
		t.Errorf("keys = %x, %x", cfg.RegistrationKey, cfg.LoginKey)
	}
}

// TestCallConfigFailureIsRemembered: missing configuration is the same 503 each
// time it is asked for, loaded once, with the reason kept for the log.
func TestCallConfigFailureIsRemembered(t *testing.T) {
	t.Parallel()

	r := newRig(t).with(noSecret())

	var answers configAnswers

	routes := []auth.Route{{
		Method: http.MethodGet, Path: "/c", MaxBody: 0,
		Credential: auth.None, Access: accessFor(auth.None), Handle: asksTwice(&answers),
	}}

	r.serve(routes, request{target: "/c"})

	if answers.firstErr == nil || !errors.Is(answers.secondErr, answers.firstErr) {
		t.Fatalf("errors = %v, %v: want the one failure twice", answers.firstErr, answers.secondErr)
	}

	failure := apierr.As(answers.firstErr)
	if failure.Kind != apierr.Unavailable || failure.Code != auth.CodeNotConfigured ||
		failure.Description != "the service is not configured" {
		t.Errorf("error = %+v, want Unavailable not_configured", failure)
	}

	if !errors.Is(failure, config.ErrSecret) {
		t.Error("the reason is not kept for the log")
	}

	// One load: it stopped at the first missing setting.
	if r.envReads != 1 {
		t.Errorf("read the environment %d times, want 1", r.envReads)
	}
}

// problemsWith lists what is wrong with the call a route saw.
func problemsWith(call *auth.Call, key auth.Key) []string {
	var problems []string

	req := call.Request

	checks := map[string]bool{
		"method":     req.Method == http.MethodPost,
		"path":       req.Path == "/things/"+itemID,
		"body":       string(req.Body) == `{"k":"v"}`,
		"path value": req.PathValues["id"] == itemID,
		"context":    req.Context != nil,
		"cookies":    len(req.Cookies) == 2,
		"query a":    slices.Equal(req.Query["a"], []string{"1", "2"}),
		"query b":    slices.Equal(req.Query["b"], []string{"x"}),
		"id":         call.ID().String() == itemID,
		"principal":  call.Principal.KeyID == key.ID.String(),
		"getenv":     call.Getenv(config.VarAPIOrigin) == apiOrigin,
	}

	for name, good := range checks {
		if !good {
			problems = append(problems, name)
		}
	}

	return problems
}

// TestCallCarriesTheRequest: the handler sees the request as httpapi read it,
// the raw wildcard text beside the parsed ids, and the deployment's Getenv.
func TestCallCarriesTheRequest(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	routes := []auth.Route{{
		Method: http.MethodPost, Path: "/things/{id}", MaxBody: 0, Credential: auth.Authenticated,
		Access: accessFor(auth.Authenticated), Handle: r.capture,
	}}

	key := r.session()
	rec := r.serve(routes, request{
		method: http.MethodPost, target: "/things/" + itemID + "?a=1&a=2&b=x", body: `{"k":"v"}`,
		cookies: []*http.Cookie{sessionCookie(key), requestCookie("theme", "dark")},
	})

	if rec.Code != http.StatusOK || len(r.handled) != 1 {
		t.Fatalf("status = %d, ran %d times", rec.Code, len(r.handled))
	}

	if problems := problemsWith(r.handled[0], key); len(problems) != 0 {
		t.Errorf("the call is wrong in: %v", problems)
	}
}
