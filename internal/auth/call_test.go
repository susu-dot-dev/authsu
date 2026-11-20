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

// TestCallConfigIsLoadedOncePerRequest: the handler's asks share one load, so
// asking more than once costs nothing, and a route that never asks never loads,
// whatever its credential: verifying a credential reads no configuration.
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
		"a session route that never asks": {credential: auth.Authenticated, asks: false, cookies: valid, wantLoads: 0},
		// The handler never runs for a refused request, so nothing asks.
		"a session route that is refused": {
			credential: auth.Authenticated, asks: true, cookies: sessionValue("garbage"), wantLoads: 0,
		},
		"a session route without a session": {credential: auth.Authenticated, asks: true, cookies: nil, wantLoads: 0},
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
func problemsWith(call *auth.Call, key auth.Issued) []string {
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
		"principal":  call.Principal.SecretID == key.ID,
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

// TestAuthenticatedRoutesAnswerNotConfiguredThemselves: a credential is
// verified without the deployment's configuration, so a deployment that lacks
// it still resolves the session and runs the handler. A handler that needs the
// configuration asks for it and returns its failure, which is the same 503
// not_configured a None route gives. A caller with no valid credential is 401
// whatever the deployment lacks, and never learns it is misconfigured.
func TestAuthenticatedRoutesAnswerNotConfiguredThemselves(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cookies    cookieFn
		wantStatus int
		wantBody   string
		wantCode   string
		wantReads  int
	}{
		"a valid session": {
			cookies: valid, wantStatus: http.StatusServiceUnavailable, wantBody: bodyNotConfigured,
			wantCode: auth.CodeNotConfigured, wantReads: 1,
		},
		nameNoCookie: {
			cookies: nil, wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
			wantCode: auth.CodeUnauthenticated, wantReads: 0,
		},
		"a revoked session": {
			cookies: afterStoring(revoked), wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
			wantCode: auth.CodeUnauthenticated, wantReads: 1,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t).with(noSecret())

			routes := []auth.Route{{
				Method: http.MethodGet, Path: "/c", MaxBody: 0, Credential: auth.Authenticated, Access: auth.Open(),
				Handle: func(call *auth.Call) result.Result[httpapi.Response] {
					_, err := call.Config()

					return result.Fail[httpapi.Response](err)
				},
			}}

			var cookies []*http.Cookie
			if tt.cookies != nil {
				cookies = tt.cookies(r)
			}

			rec := r.serve(routes, request{target: "/c", cookies: cookies})

			wantFailure(t, r, rec, tt.wantStatus, tt.wantBody, tt.wantCode, nil)

			if len(r.creds.calls) != tt.wantReads {
				t.Errorf("store read %d times, want %d", len(r.creds.calls), tt.wantReads)
			}
		})
	}
}

// testSigningKey is a throwaway RSA 2048 private key in the form
// OAUTH_SIGNING_KEY holds: PKCS#8 DER, base64url without padding, one line.
const testSigningKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6ahvNJu31g6Bs" +
	"JC2aVJBrcyCubvwgl8wYMHW0yV__jUIzhjaDK4h5HDuUPkJV3pF842ynmC0XIawe" +
	"FiivW6uI-kpesoc2DUWHCoUte81nKEKOjFeu2TvbR7dLZlVt3F4fTsyn2sXfUsHm" +
	"UXiTvuWNV2mQVrfmnaCMihLkGCoCNP7wJ2jAkeTAbgcL61foSxhAdygXDIgLUxzR" +
	"47N0nv4G02Z0eWIFPb8rar3ppSt3UX1Cl569iFb6wk3_7QVYNCodhjYm5IPioW6B" +
	"FJsts6-FbGkC_7RIATwNeGiJezxb_ClO_6ZxEMeVcadhy0FWL8wp4iO15zELJ1o-" +
	"tX0i-FmBAgMBAAECggEABIJBFVHITV2ghNiET5GVMTr9WahzRUjUWlhIktW1Nv7d" +
	"9VWmR1FZqosZ_KrJaRpKLNn8fsysCoad-NfAXU-7cvptGO1D8RmaOFaFX9MdnLtr" +
	"adc9cNU3INfKE7w5VwkzL-M9v_q-FVVMPZuYknEfAx1P2p8HeokOoQ5xUfVRYRVj" +
	"VfpBBrJbbqUvqN_q8VQImWZTNkmcE1Y1LE0XZIevj9im9ZjwbDnwhPv3ST0jmPoH" +
	"K97oxEAF36bT71uNeizgcPCtJaV6L3HXayNIo-IxFMtjOW9wcXHtTQDSh8FEsx_G" +
	"aVYNqdbwCL3FtDFauA3GBNTDw6HBBXXxo-4VDFQHoQKBgQDN5bFE2YVPdlWb1kMj" +
	"C3zGrZrFZ59n-hoPxU9iaM-8oobPsTy7Zr9UzSSawhfIPOHTJr69SQfiIV23iBJo" +
	"6k_X1BKAti1oFZ0_Ir-oiskMyH39LEyFoR4OxzzCtCxz03MOY0CQYofF3tCF-Glp" +
	"bz1d6r06J5Xjw7atNaC-AJJjfwKBgQDnxr536dM0907Fl-rGGm70CqL6Nh9oiwpF" +
	"rSjaeWi2HcIrQX_4ScNqugUIShc4KIwQhBIWSS9Fd4ydOKD7eyuDLoI6yXBx8Ft8" +
	"dAs_Xir8ya7s_23Za_7hZ2PGaLhgdtUVwgzzvm0z9_PihlPOoXgAj1ooPvvVEMon" +
	"SbnHmr_C_wKBgGFR_V0-t51coJBdUTSCXIMIUcyW8yjRdXoY2DH6up498BzBeKRX" +
	"p34szO19aoJSDKeie6u6lkhTXxm97n26quyoJ-rAsWuuM7pA8Xh3yRoKtkpxouXS" +
	"xwNTNywMv6oruwmE7mKQv_5OGCAKz8BvPQFkT_bp-RZETtdGLulAGfF_AoGBAJMT" +
	"T7wiGY9Lu6WxQB6TmYKs2TyzaXzadhs-xWTVk_e0rIjsWHtCu4mXHyhic5eES1UT" +
	"qbKQoDmRoh4GWEkcoMDum18Ygo0au8MelCCS7e5ZQPJNJ_THDgcUp4C45P75iT_0" +
	"Umm9lehbWFyPZtEBL3gTf194kC9lJxKFOymJblQbAoGAZYVraT4JOj1G400k9UFw" +
	"1lJRMpjKZ8NWMOLNHIE60GRAxm49exY0hVip4gOrHOZjLqxor6sdU5OS_G3O1UE0" +
	"dEqAmP3FiJcYqf-8W9qUPc1KulMqnuGndE6ZFpXHlVkhRwWD1ZebATTXh9EzmuDS" +
	"SVOw37zoh_COkszjZ24btDs"

// asksForTheKeyTwice is a route body that asks for the signing key twice.
func asksForTheKeyTwice(first, second *keyAnswer) func(*auth.Call) result.Result[httpapi.Response] {
	return func(call *auth.Call) result.Result[httpapi.Response] {
		first.key, first.err = call.SigningKey()
		second.key, second.err = call.SigningKey()

		return result.Ok(httpapi.JSON(http.StatusOK, nil))
	}
}

// keyAnswer is what a route saw when it asked for the signing key.
type keyAnswer struct {
	key config.SigningKey
	err error
}

// TestCallSigningKey: the key is loaded on first use, once per request, and a
// route that never asks never parses it. A missing or invalid key is the one
// 503 not_configured, remembered for the rest of the request, with the reason
// kept for the log; it does not depend on the rest of the configuration.
func TestCallSigningKey(t *testing.T) {
	t.Parallel()

	valid := map[string]string{config.SecretOAuthSigningKey: testSigningKey}

	tests := map[string]struct {
		env       map[string]string
		asks      bool
		wantReads int
		wantErr   bool
	}{
		"a valid key, asked twice": {env: valid, asks: true, wantReads: 1, wantErr: false},
		"a valid key, never asked": {env: valid, asks: false, wantReads: 0, wantErr: false},
		"no key":                   {env: map[string]string{}, asks: true, wantReads: 1, wantErr: true},
		"not a key": {
			env: map[string]string{config.SecretOAuthSigningKey: "AAAA"}, asks: true, wantReads: 1, wantErr: true,
		},
		"a key with the rest of the configuration missing": {
			env:  map[string]string{config.SecretOAuthSigningKey: testSigningKey, config.SecretHMAC: ""},
			asks: true, wantReads: 1, wantErr: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t).with(tt.env)

			var first, second keyAnswer

			handle := r.capture
			if tt.asks {
				handle = asksForTheKeyTwice(&first, &second)
			}

			routes := []auth.Route{{
				Method: http.MethodGet, Path: "/k", MaxBody: 0,
				Credential: auth.None, Access: accessFor(auth.None), Handle: handle,
			}}

			r.serve(routes, request{target: "/k"})

			if r.envReads != tt.wantReads {
				t.Errorf("read the environment %d times, want %d", r.envReads, tt.wantReads)
			}

			if tt.asks {
				wantKeyAnswers(t, first, second, tt.wantErr)
			}
		})
	}
}

// wantKeyAnswers asserts that both asks got the one outcome: a loaded key, or
// the classified 503.
func wantKeyAnswers(t *testing.T, first, second keyAnswer, wantErr bool) {
	t.Helper()

	if wantErr {
		wantNotConfigured(t, first, second)

		return
	}

	if first.err != nil || second.err != nil || first.key.KeyID() == "" || first.key.KeyID() != second.key.KeyID() {
		t.Errorf("key = %q, %q (%v, %v), want one loaded key", first.key.KeyID(), second.key.KeyID(), first.err, second.err)
	}
}

// wantNotConfigured asserts that both asks got the one classified 503.
func wantNotConfigured(t *testing.T, first, second keyAnswer) {
	t.Helper()

	failure := apierr.As(first.err)
	if !errors.Is(second.err, first.err) || failure.Kind != apierr.Unavailable || failure.Code != auth.CodeNotConfigured ||
		failure.Description != "the service is not configured" || !errors.Is(failure, config.ErrSigningKey) {
		t.Errorf("errors = %v, %v, want one Unavailable not_configured wrapping ErrSigningKey", first.err, second.err)
	}
}
