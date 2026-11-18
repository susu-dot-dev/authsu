//nolint:gosec // the secrets in these tests are fixtures, not credentials
package firstrun_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/input"
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

	if route.Require != nil || route.MaxBody != 0 || route.Handle == nil {
		t.Errorf("Require set = %t, MaxBody = %d, Handle set = %t, want nil, 0, set",
			route.Require != nil, route.MaxBody, route.Handle != nil)
	}
}

// TestRoutesRequireEveryDependency checks that a missing dependency is found
// when the routes are built, not by a request.
func TestRoutesRequireEveryDependency(t *testing.T) {
	t.Parallel()

	complete := newRig(t)
	deps := firstrun.Deps{
		Store: complete.store,
		Now:   func() time.Time { return complete.now },
		NewID: func() string { return generatedID },
	}

	tests := []struct {
		name   string
		mutate func(*firstrun.Deps)
	}{
		{name: "no store", mutate: func(d *firstrun.Deps) { d.Store = nil }},
		{name: "no clock", mutate: func(d *firstrun.Deps) { d.Now = nil }},
		{name: "no id source", mutate: func(d *firstrun.Deps) { d.NewID = nil }},
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
// secret, and what each leads to: the exact store calls, the exact response,
// and whether the secret was consulted.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestStatus(t *testing.T) {
	t.Parallel()

	longest := strings.Repeat("k", input.MaxInvitationCodeBytes)

	const (
		short    = "k3Jx9Qp-Zr2_LmN8vB5tYcD1fGhWaX0"  // 31 characters, one short
		shortest = "k3Jx9Qp-Zr2_LmN8vB5tYcD1fGhWaX0e" // 32 characters, the least
	)

	tests := []struct {
		name string
		// states are the answers of FirstRunState, in order.
		states []stateAnswer
		secret string
		create createAnswer

		wantStatus int
		wantBody   string
		// wantCalls are the store calls, in order.
		wantCalls []string
		// wantSecretRead is whether FIRST_RUN_SECRET may be read at all.
		wantSecretRead bool
		// wantCode is the code of the error the boundary logs, "" for none.
		wantCode string
	}{
		// Once an account exists, setup is over: the secret is not consulted, so
		// one left in the deployment forever is inert.
		{
			name: "users, no invitation, secret set", states: []stateAnswer{reading(usersOnly())}, secret: validSecret,
			wantStatus: http.StatusOK, wantBody: bodyAccepted, wantCalls: []string{callState},
		},
		{
			name: "users and invitation, secret set", states: []stateAnswer{reading(usersAndInvitation())}, secret: validSecret,
			wantStatus: http.StatusOK, wantBody: bodyAccepted, wantCalls: []string{callState},
		},
		{
			name: "users, secret not set", states: []stateAnswer{reading(usersOnly())}, secret: "",
			wantStatus: http.StatusOK, wantBody: bodyAccepted, wantCalls: []string{callState},
		},
		// An invitation is waiting: nothing to create, so the secret is not
		// consulted either, and changing it later does nothing.
		{
			name: "invitation exists, secret set", states: []stateAnswer{reading(invited())}, secret: validSecret,
			wantStatus: http.StatusOK, wantBody: bodyPending, wantCalls: []string{callState},
		},
		{
			name: "invitation exists, secret since changed to garbage", states: []stateAnswer{reading(invited())}, secret: "x",
			wantStatus: http.StatusOK, wantBody: bodyPending, wantCalls: []string{callState},
		},
		// Nothing exists, so the status depends on the secret.
		{
			name: "empty, no secret", states: []stateAnswer{reading(empty())}, secret: "",
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantCalls: []string{callState}, wantSecretRead: true,
		},
		{
			name: "empty, secret one character short", states: []stateAnswer{reading(empty())}, secret: short,
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantCalls: []string{callState}, wantSecretRead: true,
		},
		{
			name: "empty, secret with a character outside base64url", states: []stateAnswer{reading(empty())},
			secret:     "k3Jx9Qp+Zr2/LmN8vB5tYcD1fGhWaXeUoIiS7dTqA0E=",
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantCalls: []string{callState}, wantSecretRead: true,
		},
		{
			name: "empty, secret with a space inside", states: []stateAnswer{reading(empty())},
			secret:     "k3Jx9Qp-Zr2_LmN8vB5tYcD1 fGhWaXeUoIiS7dTqA0E",
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantCalls: []string{callState}, wantSecretRead: true,
		},
		{
			name: "empty, secret with a newline", states: []stateAnswer{reading(empty())},
			secret:     shortest[:31] + "\n",
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantCalls: []string{callState}, wantSecretRead: true,
		},
		{
			name: "empty, multibyte secret of 32 bytes", states: []stateAnswer{reading(empty())},
			secret:     strings.Repeat("\u00e9", 16),
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantCalls: []string{callState}, wantSecretRead: true,
		},
		{
			name: "empty, secret longer than an invitation code", states: []stateAnswer{reading(empty())},
			secret:     longest + "k",
			wantStatus: http.StatusOK, wantBody: bodyMissing, wantCalls: []string{callState}, wantSecretRead: true,
		},
		{
			name: "empty, secret of the least length creates", states: []stateAnswer{reading(empty())}, secret: shortest,
			create:     createAnswer{created: true, err: nil},
			wantStatus: http.StatusOK, wantBody: bodyPending, wantCalls: []string{callState, callCreate}, wantSecretRead: true,
		},
		{
			name: "empty, secret of the greatest length creates", states: []stateAnswer{reading(empty())}, secret: longest,
			create:     createAnswer{created: true, err: nil},
			wantStatus: http.StatusOK, wantBody: bodyPending, wantCalls: []string{callState, callCreate}, wantSecretRead: true,
		},
		{
			name: "empty, valid secret creates", states: []stateAnswer{reading(empty())}, secret: validSecret,
			create:     createAnswer{created: true, err: nil},
			wantStatus: http.StatusOK, wantBody: bodyPending, wantCalls: []string{callState, callCreate}, wantSecretRead: true,
		},
		// The insert is refused: someone else got there between the read and
		// the write. The state is read again to say what happened, and the
		// answer is never "missing secret", because the secret is fine.
		{
			name: "refused, a concurrent request created the invitation", secret: validSecret,
			states:     []stateAnswer{reading(empty()), reading(invited())},
			create:     createAnswer{created: false, err: nil},
			wantStatus: http.StatusOK, wantBody: bodyPending, wantCalls: []string{callState, callCreate, callState},
			wantSecretRead: true,
		},
		{
			name: "refused, an account appeared", secret: validSecret,
			states:     []stateAnswer{reading(empty()), reading(usersOnly())},
			create:     createAnswer{created: false, err: nil},
			wantStatus: http.StatusOK, wantBody: bodyAccepted, wantCalls: []string{callState, callCreate, callState},
			wantSecretRead: true,
		},
		{
			name: "refused, the invitation was created and redeemed", secret: validSecret,
			states:     []stateAnswer{reading(empty()), reading(usersAndInvitation())},
			create:     createAnswer{created: false, err: nil},
			wantStatus: http.StatusOK, wantBody: bodyAccepted, wantCalls: []string{callState, callCreate, callState},
			wantSecretRead: true,
		},
		// Refused, and nothing first-run exists: an invitation of another type
		// is in a database with no account, so no first-run invitation can ever
		// be created. Setting the secret again would not help, so the status is
		// not "missing secret".
		{
			name: "refused, blocked by an invitation of another type", secret: validSecret,
			states:     []stateAnswer{reading(empty()), reading(empty())},
			create:     createAnswer{created: false, err: nil},
			wantStatus: http.StatusConflict, wantBody: bodyBlocked, wantCalls: []string{callState, callCreate, callState},
			wantSecretRead: true, wantCode: firstrun.CodeBlocked,
		},
		// Failures of the store pass through as the store classified them.
		{
			name: "the first read fails", secret: validSecret,
			states:     []stateAnswer{{state: empty(), err: unavailable(store.CodeFirstRunCheckFailed)}},
			wantStatus: http.StatusServiceUnavailable, wantBody: errorBody(store.CodeFirstRunCheckFailed, unavailableText),
			wantCalls: []string{callState}, wantCode: store.CodeFirstRunCheckFailed,
		},
		{
			name: "the first read is malformed", secret: validSecret,
			states: []stateAnswer{{
				state: empty(),
				err:   apierr.Wrap(errDB, apierr.Internal, store.CodeFirstRunCheckRejected, "internal error"),
			}},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantCalls: []string{callState}, wantCode: store.CodeFirstRunCheckRejected,
		},
		{
			name: "the insert fails", secret: validSecret, states: []stateAnswer{reading(empty())},
			create:     createAnswer{created: false, err: unavailable(store.CodeFirstRunCreateFailed)},
			wantStatus: http.StatusServiceUnavailable, wantBody: errorBody(store.CodeFirstRunCreateFailed, unavailableText),
			wantCalls: []string{callState, callCreate}, wantSecretRead: true, wantCode: store.CodeFirstRunCreateFailed,
		},
		{
			name: "the insert is rejected by the schema", secret: validSecret, states: []stateAnswer{reading(empty())},
			create: createAnswer{
				created: false, err: apierr.Wrap(errDB, apierr.Internal, store.CodeFirstRunCreateRejected, "internal error"),
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantCalls: []string{callState, callCreate}, wantSecretRead: true, wantCode: store.CodeFirstRunCreateRejected,
		},
		{
			name: "the read after a refusal fails", secret: validSecret,
			states:     []stateAnswer{reading(empty()), {state: empty(), err: unavailable(store.CodeFirstRunCheckFailed)}},
			create:     createAnswer{created: false, err: nil},
			wantStatus: http.StatusServiceUnavailable, wantBody: errorBody(store.CodeFirstRunCheckFailed, unavailableText),
			wantCalls: []string{callState, callCreate, callState}, wantSecretRead: true, wantCode: store.CodeFirstRunCheckFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t, tt.states...)
			rig.store.create = tt.create
			rig.env[config.SecretFirstRun] = tt.secret

			rec := rig.serve(request{method: http.MethodGet, cookies: nil, body: "", contentType: ""})

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
			}

			if !slices.Equal(rig.store.calls, tt.wantCalls) {
				t.Errorf("store calls = %v, want %v", rig.store.calls, tt.wantCalls)
			}

			if got := rig.reads[config.SecretFirstRun]; (got != 0) != tt.wantSecretRead {
				t.Errorf("FIRST_RUN_SECRET read %d times, want a read: %t", got, tt.wantSecretRead)
			}

			wantCode := tt.wantCode
			if len(rig.logged) != boolToInt(wantCode != "") || (wantCode != "" && rig.logged[0].Code != wantCode) {
				t.Errorf("logged = %v, want one %q", rig.logged, wantCode)
			}

			wantSecretStays(t, rec.Header(), rec.Body.String(), tt.secret)

			if rig.keys.calls != 0 {
				t.Error("the key store was read for a route with no credential")
			}
		})
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

// wantSecretStays fails when secret, or a piece of it, is anywhere in a
// response: the code is an admin credential until the owner registers.
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

// TestCreatesTheInvitation checks what the insert is given: a fresh id, the
// code, the label and the injected clock, and that each is taken from the
// injected source exactly once.
func TestCreatesTheInvitation(t *testing.T) {
	t.Parallel()

	rig := newRig(t, reading(empty()))
	rig.env[config.SecretFirstRun] = validSecret
	rig.store.create = createAnswer{created: true, err: nil}

	rec := rig.serve(request{method: http.MethodGet, cookies: nil, body: "", contentType: ""})
	if rec.Code != http.StatusOK || rec.Body.String() != bodyPending {
		t.Fatalf("response = %d %q, want 200 %q", rec.Code, rec.Body.String(), bodyPending)
	}

	want := createCall{id: generatedID, code: validSecret, label: "First run: initial administrator", now: rig.now}

	if len(rig.store.creates) != 1 || rig.store.creates[0] != want {
		t.Errorf("created %v, want %v", rig.store.creates, want)
	}

	if rig.ids != 1 || rig.clockReads != 1 {
		t.Errorf("NewID called %d times and Now %d times, want once each", rig.ids, rig.clockReads)
	}
}

// TestNothingIsGeneratedUnlessCreating checks that the id and the clock are used
// only for an insert that is attempted.
func TestNothingIsGeneratedUnlessCreating(t *testing.T) {
	t.Parallel()

	for _, state := range []store.FirstRunState{usersOnly(), usersAndInvitation(), invited(), empty()} {
		rig := newRig(t, reading(state))

		rec := rig.serve(request{method: http.MethodGet, cookies: nil, body: "", contentType: ""})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}

		if rig.ids != 0 || rig.clockReads != 0 || len(rig.store.creates) != 0 {
			t.Errorf("state %+v: ids %d, clock reads %d, inserts %v, want none",
				state, rig.ids, rig.clockReads, rig.store.creates)
		}
	}
}

// TestRefusedInsertIsNotRetried checks that a refusal is
// final: the route does not retry, so a deployment cannot be made to insert
// twice.
func TestRefusedInsertIsNotRetried(t *testing.T) {
	t.Parallel()

	rig := newRig(t, reading(empty()), reading(empty()))
	rig.env[config.SecretFirstRun] = validSecret

	rig.serve(request{method: http.MethodGet, cookies: nil, body: "", contentType: ""})

	if len(rig.store.creates) != 1 {
		t.Errorf("inserts = %d, want 1", len(rig.store.creates))
	}
}

// TestSecretIsNotInAnyResponse checks the one rule of the route with a secret
// that is a live admin credential: it is in no body and no header, on success
// and failure, even when the store's own failure mentions it.
func TestSecretIsNotInAnyResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		states []stateAnswer
		create createAnswer
	}{
		{name: "created", states: []stateAnswer{reading(empty())}, create: createAnswer{created: true, err: nil}},
		{
			name: "refused", states: []stateAnswer{reading(empty()), reading(invited())},
			create: createAnswer{created: false, err: nil},
		},
		{
			name: "blocked", states: []stateAnswer{reading(empty()), reading(empty())},
			create: createAnswer{created: false, err: nil},
		},
		{
			// A store error that quoted its arguments: the boundary still sends
			// only the fixed message.
			name: "the insert fails with the secret in its cause", states: []stateAnswer{reading(empty())},
			create: createAnswer{
				created: false,
				err: apierr.Wrap(errLeaky, apierr.Unavailable,
					store.CodeFirstRunCreateFailed, unavailableText),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t, tt.states...)
			rig.store.create = tt.create
			rig.env[config.SecretFirstRun] = validSecret

			rec := rig.serve(request{method: http.MethodGet, cookies: nil, body: "", contentType: ""})

			wantSecretStays(t, rec.Header(), rec.Body.String(), validSecret)
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

			if rig.keys.calls != 0 {
				t.Error("the key store was read")
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

			if len(rig.store.calls) != 0 || len(rig.reads) != 0 {
				t.Errorf("a refused request did work: store %v, env %v", rig.store.calls, rig.reads)
			}
		})
	}
}

// TestInvitationLabelIsOneTheSchemaAndTheParserAccept: the first-run label is
// written straight to invitations.label and shown in the admin's list, so it
// must fit the column's CHECK (read from the migrations' text) and be a label
// the invitation parser would accept from a person, which is what the rest of
// the system assumes every label is.
func TestInvitationLabelIsOneTheSchemaAndTheParserAccept(t *testing.T) {
	t.Parallel()

	limit := migrationLimits(t, `length\(label\) <= (\d+)`)[0]

	if runes := utf8.RuneCountInString(firstrun.InvitationLabel); runes == 0 || runes > limit {
		t.Errorf("the label is %d characters; the schema allows up to %d", runes, limit)
	}

	parsed, err := input.ParseInvitationLabel(firstrun.InvitationLabel)
	if err != nil || parsed.String() != firstrun.InvitationLabel {
		t.Errorf("the parser does not accept the first-run label as it is: %v", err)
	}
}
