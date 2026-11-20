//nolint:gosec // the secrets in these tests are fixtures, not credentials
package firstrun_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestRouteDeclaration pins the route: it is public by design (a person with no
// account is who reads it), so the declaration is where a requirement added by
// mistake, or a credential taken away, would show.
func TestRouteDeclaration(t *testing.T) {
	t.Parallel()

	routes := newRig(t).routes()

	if len(routes) != 1 {
		t.Fatalf("Routes returned %d routes, want 1", len(routes))
	}

	route := routes[0]

	if route.Method != http.MethodGet || route.Path != "/api/first-run" {
		t.Errorf("route = %s %s, want GET /api/first-run", route.Method, route.Path)
	}

	if route.Credential != auth.None {
		t.Errorf("Credential = %v, want None", route.Credential)
	}

	if route.Access != (auth.Access{}) || route.MaxBody != 0 || route.Handle == nil {
		t.Errorf("Access = %+v, MaxBody = %d, Handle set = %t, want none, 0, set",
			route.Access, route.MaxBody, route.Handle != nil)
	}
}

// TestRoutesRequireEveryDependency checks that a missing dependency is found
// when the routes are built, not by a request.
func TestRoutesRequireEveryDependency(t *testing.T) {
	t.Parallel()

	complete := newRig(t)
	deps := firstrun.Deps{Store: complete.store}

	tests := []struct {
		name   string
		mutate func(*firstrun.Deps)
	}{
		{name: "no store", mutate: func(d *firstrun.Deps) { d.Store = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			broken := deps
			tt.mutate(&broken)

			defer func() {
				if recover() == nil {
					t.Error("Routes did not panic")
				}
			}()

			firstrun.Routes(broken)
		})
	}
}

// TestStatus covers every state the database can be in with every state of the
// secret, and what each leads to: the exact response, whether the secret was
// consulted, and that the route reads the database exactly once and writes
// nothing (the store has no write to call).
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		state  store.FirstRunState
		secret string

		wantStatus int
		wantBody   string
		// wantSecretRead is whether FIRST_RUN_SECRET may be read at all.
		wantSecretRead bool
	}{
		// Once an account exists, setup is over: the secret is not consulted, so
		// one left in the deployment forever is inert.
		{
			name: "users, no invitation, secret set", state: usersOnly(), secret: validSecret,
			wantStatus: http.StatusOK, wantBody: bodyAccepted,
		},
		{
			name: "users and first-run invitation, secret set", state: usersAndInvitation(), secret: validSecret,
			wantStatus: http.StatusOK, wantBody: bodyAccepted,
		},
		{
			name: "users and another invitation, secret set", state: usersAndOtherInvitation(), secret: validSecret,
			wantStatus: http.StatusOK, wantBody: bodyAccepted,
		},
		{
			name: "users, secret not set", state: usersOnly(), secret: "",
			wantStatus: http.StatusOK, wantBody: bodyAccepted,
		},
		// A first-run invitation is waiting: the secret is not consulted, and
		// changing it later does nothing.
		{
			name: "first-run invitation exists, secret set", state: invited(), secret: validSecret,
			wantStatus: http.StatusOK, wantBody: bodyPending,
		},
		{
			name: "first-run invitation exists, secret since changed to garbage", state: invited(), secret: "x",
			wantStatus: http.StatusOK, wantBody: bodyPending,
		},
		{
			name: "first-run invitation exists, secret since removed", state: invited(), secret: "",
			wantStatus: http.StatusOK, wantBody: bodyPending,
		},
		// Nothing exists, so the status depends on the secret: with a valid one,
		// registering with it creates the invitation, so setup is pending.
		{
			name: "empty, no secret", state: empty(), secret: "",
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantSecretRead: true,
		},
		{
			name: "empty, invalid secret", state: empty(), secret: "x",
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantSecretRead: true,
		},
		{
			name: "empty, valid secret", state: empty(), secret: validSecret,
			wantStatus: http.StatusOK, wantBody: bodyPending, wantSecretRead: true,
		},
		// An invitation of another type and no account: no first-run invitation
		// can ever be created, so no secret helps. It is told apart from
		// "missing secret", which would send the owner to set it again forever.
		{
			name: "another invitation and no account, secret set", state: otherInvited(), secret: validSecret,
			wantStatus: http.StatusConflict, wantBody: bodyBlocked,
		},
		{
			name: "another invitation and no account, no secret", state: otherInvited(), secret: "",
			wantStatus: http.StatusConflict, wantBody: bodyBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t, reading(tt.state))
			rig.env[config.SecretFirstRun] = tt.secret

			rec := rig.serve(request{method: http.MethodGet, cookies: nil, body: "", contentType: ""})

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
			}

			if rig.store.calls != 1 {
				t.Errorf("FirstRunState called %d times, want once", rig.store.calls)
			}

			if got := rig.reads[config.SecretFirstRun]; (got != 0) != tt.wantSecretRead {
				t.Errorf("FIRST_RUN_SECRET read %d times, want a read: %t", got, tt.wantSecretRead)
			}

			wantBlockedLogged(t, rig, tt.wantStatus == http.StatusConflict)
			wantSecretStays(t, rec.Header(), rec.Body.String(), tt.secret)

			if rig.creds.calls != 0 {
				t.Error("the credential store was read for a route with no credential")
			}
		})
	}
}

// wantBlockedLogged checks that the one failure the boundary logged is the
// blocked database's when blocked, and that nothing was logged otherwise.
func wantBlockedLogged(t *testing.T, rig *rig, blocked bool) {
	t.Helper()

	if !blocked {
		if len(rig.logged) != 0 {
			t.Errorf("logged = %v, want nothing", rig.logged)
		}

		return
	}

	if len(rig.logged) != 1 || rig.logged[0].Code != firstrun.CodeBlocked {
		t.Errorf("logged = %v, want one %q", rig.logged, firstrun.CodeBlocked)
	}
}

// TestStoreFailures holds that a failed read passes through as the store
// classified it, with its fixed message, and never as a status.
func TestStoreFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
		wantCode   string
	}{
		{
			name: "the read fails", err: unavailable(store.CodeFirstRunCheckFailed),
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   errorBody(store.CodeFirstRunCheckFailed, unavailableText), wantCode: store.CodeFirstRunCheckFailed,
		},
		{
			name:       "the read is malformed",
			err:        apierr.Wrap(errDB, apierr.Internal, store.CodeFirstRunCheckRejected, "internal error"),
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantCode: store.CodeFirstRunCheckRejected,
		},
		{
			// A store error that quoted its arguments: the boundary still sends
			// only the fixed message.
			name:       "the failure quotes the secret in its cause",
			err:        apierr.Wrap(errLeaky, apierr.Unavailable, store.CodeFirstRunCheckFailed, unavailableText),
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   errorBody(store.CodeFirstRunCheckFailed, unavailableText), wantCode: store.CodeFirstRunCheckFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t, stateAnswer{state: empty(), err: tt.err})
			rig.env[config.SecretFirstRun] = validSecret

			rec := rig.serve(request{method: http.MethodGet, cookies: nil, body: "", contentType: ""})

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
			}

			if len(rig.logged) != 1 || rig.logged[0].Code != tt.wantCode {
				t.Errorf("logged = %v, want one %q", rig.logged, tt.wantCode)
			}

			wantSecretStays(t, rec.Header(), rec.Body.String(), validSecret)
		})
	}
}

// wantSecretStays fails when secret, or a piece of it, is anywhere in a
// response: the token is an admin credential until the owner registers.
func wantSecretStays(t *testing.T, headers http.Header, body, secret string) {
	t.Helper()

	if secret == "" || len(secret) < 8 {
		return
	}

	var everything strings.Builder

	everything.WriteString(body)

	for name, values := range headers {
		everything.WriteString(name + ": " + strings.Join(values, ",") + "\n")
	}

	for start := 0; start+8 <= len(secret); start += 4 {
		if strings.Contains(everything.String(), secret[start:start+8]) {
			t.Errorf("the response contains part of the secret: %q", everything.String())

			return
		}
	}
}

// TestSecretMustBeAnInvitationToken: only a complete invitation token is a
// usable FIRST_RUN_SECRET. Every other value is "missing secret", and the secret
// is never described in the response.
func TestSecretMustBeAnInvitationToken(t *testing.T) {
	t.Parallel()

	wholeBody := strings.TrimPrefix(validSecret, "susu_inv_")

	tests := map[string]struct {
		secret string
		valid  bool
	}{
		"a token":                         {secret: validSecret, valid: true},
		"another canonical token":         {secret: "susu_inv_" + strings.Repeat("A", 43), valid: true},
		"unset":                           {secret: ""},
		"random body without the prefix":  {secret: wholeBody},
		"old-style 32 random characters":  {secret: "k3Jx9Qp-Zr2_LmN8vB5tYcD1fGhWaX0e"},
		"a session token":                 {secret: "susu_ses_" + wholeBody},
		"an API key":                      {secret: "susu_key_" + wholeBody},
		"prefix only":                     {secret: "susu_inv_"},
		"prefix without the underscore":   {secret: "susu_inv" + wholeBody},
		"upper-case prefix":               {secret: "SUSU_INV_" + wholeBody},
		"body of 42 characters":           {secret: validSecret[:len(validSecret)-1]},
		"body of 44 characters":           {secret: validSecret + "A"},
		"leading space":                   {secret: " " + validSecret},
		"trailing space":                  {secret: validSecret + " "},
		"trailing newline":                {secret: validSecret + "\n"},
		"leading tab":                     {secret: "\t" + validSecret},
		"carriage return":                 {secret: validSecret + "\r\n"},
		"non-canonical last character":    {secret: validSecret[:len(validSecret)-1] + "F"},
		"character outside base64url":     {secret: "susu_inv_" + wholeBody[:42] + "+"},
		"padding":                         {secret: validSecret[:len(validSecret)-1] + "="},
		"multibyte character in the body": {secret: "susu_inv_" + wholeBody[:41] + "\u00e9"},
		"two tokens":                      {secret: validSecret + validSecret},
		"a very long value":               {secret: strings.Repeat("k", 1<<16)},
		"the prefix in the middle":        {secret: "x" + validSecret},
		"NUL byte":                        {secret: validSecret + "\x00"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t, reading(empty()))
			rig.env[config.SecretFirstRun] = tt.secret

			rec := rig.serve(request{method: http.MethodGet, cookies: nil, body: "", contentType: ""})

			wantBody := bodyMissing
			if tt.valid {
				wantBody = bodyPending
			}

			if rec.Code != http.StatusOK || rec.Body.String() != wantBody {
				t.Errorf("response = %d %q, want 200 %q", rec.Code, rec.Body.String(), wantBody)
			}

			if len(rig.logged) != 0 {
				t.Errorf("logged = %v, want nothing: a bad secret is a status, not a failure", rig.logged)
			}

			wantSecretStays(t, rec.Header(), rec.Body.String(), tt.secret)
		})
	}
}

// TestNeedsNoCredentialAndNoConfiguration checks that the route answers without
// a session and without anything but the one secret it reads: it is what a
// deployment reads before it has finished being configured.
func TestNeedsNoCredentialAndNoConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  request
	}{
		{name: "no cookie", req: request{method: http.MethodGet, cookies: nil, body: "", contentType: ""}},
		{
			name: "a session cookie that is not valid",
			req: request{
				method: http.MethodGet, body: "", contentType: "",
				cookies: []*http.Cookie{requestCookie(auth.CookieName, "not a token")},
			},
		},
		{
			name: "two session cookies",
			req: request{
				method: http.MethodGet, body: "", contentType: "",
				cookies: []*http.Cookie{requestCookie(auth.CookieName, "a"), requestCookie(auth.CookieName, "b")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t, reading(empty()))

			rec := rig.serve(tt.req)

			if rec.Code != http.StatusOK || rec.Body.String() != bodyMissing {
				t.Errorf("response = %d %q, want 200 %q", rec.Code, rec.Body.String(), bodyMissing)
			}

			if rig.creds.calls != 0 {
				t.Error("the credential store was read")
			}

			if len(rig.reads) != 1 || rig.reads[config.SecretFirstRun] != 1 {
				t.Errorf("environment reads = %v, want only %s once", rig.reads, config.SecretFirstRun)
			}
		})
	}
}

// TestHTTPContract checks what the boundary decides before the route runs.
func TestHTTPContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		wantStatus int
		wantAllow  string
	}{
		{name: "POST", method: http.MethodPost, wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodGet},
		{name: "PUT", method: http.MethodPut, wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodGet},
		{name: "DELETE", method: http.MethodDelete, wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodGet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t)
			rig.env[config.SecretFirstRun] = validSecret

			rec := rig.serve(request{method: tt.method, cookies: nil, body: "", contentType: jsonType})

			if rec.Code != tt.wantStatus || rec.Header().Get("Allow") != tt.wantAllow {
				t.Errorf("response = %d Allow %q, want %d Allow %q",
					rec.Code, rec.Header().Get("Allow"), tt.wantStatus, tt.wantAllow)
			}

			if rig.store.calls != 0 || len(rig.reads) != 0 {
				t.Errorf("a refused request did work: store calls %d, env %v", rig.store.calls, rig.reads)
			}
		})
	}
}
