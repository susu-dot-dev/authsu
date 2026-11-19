//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// firstrun_test.go drives GET /api/first-run against the real Worker (TinyGo
// wasm, workerd, the real D1 driver and SQLite). The unit tests fake the
// database, so they re-implement the guards that live in the SQL; only the real
// database can prove them:
//
//   - the conditional INSERT ... WHERE NOT EXISTS ... RETURNING that admits one
//     first-run invitation however many checks race (interleaving);
//   - the one-statement snapshot of "any user / any first-run invitation";
//   - that nothing secret (the FIRST_RUN_SECRET or its hash) ever reaches a
//     response (permission confusion / information disclosure);
//   - that a wrong method or a stray body can neither create nor change state.
//
// REVIEW.md categories covered: input edge cases (method, query, body on GET),
// interleaving (concurrent checks from an empty database, a check racing a
// registration), permission confusion (the route is open and must stay inert).
//
// missing_secret is not reachable here: the Worker under test always has a
// valid FIRST_RUN_SECRET, a complete "susu_inv_" invitation token
// (harness_test.go), and it is read per request from the environment, which a
// test cannot change. That a value that is not a token of that exact shape
// (too short, another tag, not canonical, a bare random string) is reported as
// "missing secret" and never creates an invitation is therefore covered by the
// unit tests of internal/firstrun and of the invitation token parser, and not
// here.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const (
	frPending  = `{"status":"invitation_pending"}` + "\n"
	frAccepted = `{"status":"invitation_accepted"}` + "\n"
	frBlocked  = `{"error":{"code":"first_run_blocked","message":` +
		`"first-run setup cannot finish with this database: wipe it and redeploy"}}` + "\n"

	frLabel = "First run: initial administrator"
)

// frSecretHashHex is the hex of sha256(FIRST_RUN_SECRET), the whole token
// string with its prefix: the hash the Worker must store in secrets.hash.
func frSecretHashHex() string {
	sum := sha256.Sum256([]byte(firstRunSecret))

	return hex.EncodeToString(sum[:])
}

// frExpectStatus asks GET /api/first-run and requires a 200 with body.
func frExpectStatus(t *testing.T, what, want string) {
	t.Helper()

	got := get(t, pathFirstRun, "")
	if got.status != http.StatusOK || got.body != want {
		t.Errorf("%s: GET %s = %d %q, want 200 %q", what, pathFirstRun, got.status, got.body, want)
	}
}

// frSeedFirstRunInvitation inserts a first_run invitation whose token is the
// configured secret, as the Worker would have, with an extra column of its
// secret set (revoked_at or expires_at) to value, or none when extraColumn is "".
func frSeedFirstRunInvitation(t *testing.T, id, extraColumn string, extraValue any) {
	t.Helper()

	seedSecret(t, id, kindInvitation, firstRunSecret)

	if extraColumn != "" {
		seed(t, "UPDATE secrets SET "+extraColumn+" = ? WHERE id = ?", extraValue, id)
	}

	seed(t, "INSERT INTO invitations (id, type, label, num_invites) VALUES (?, 'first_run', ?, 1)", id, frLabel)
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}

	return out
}

// TestFirstRunCreatesTheInvitation proves the empty -> pending transition and
// the exact row the Worker stores, and that repeats create nothing more.
//
//nolint:paralleltest // shares one database
func TestFirstRunCreatesTheInvitation(t *testing.T) {
	reset(t)

	expectCount(t, "invitations", "0")
	frExpectStatus(t, "first check on an empty database", frPending)
	expectCount(t, "invitations", "1")

	// The stored rows, column by column: the invitation, and its secret, which
	// holds the hash of the token, the expiry, the revocation and the creation time.
	row := func(column string) string { return scalar(t, "SELECT "+column+" FROM invitations") }
	secret := func(column string) string { return scalar(t, "SELECT "+column+" FROM secrets") }

	expectCount(t, "secrets", "1")

	if got := secret("lower(hex(hash))"); got != frSecretHashHex() {
		t.Errorf("secrets.hash = %s, want sha256 of the whole token %s", got, frSecretHashHex())
	}

	for column, want := range map[string]string{
		"typeof(hash)":                      "blob",
		"length(hash)":                      "32",
		"kind":                              kindInvitation,
		"id = (SELECT id FROM invitations)": "1",
		"revoked_at IS NULL":                "1",
		"typeof(expires_at)":                "integer",
		"typeof(created_at)":                "integer",
		// Every secret expires: ten years of 365 days after it was created.
		"expires_at - created_at = 10 * 365 * 24 * 3600": "1",
		// created_at is "now": within a minute of the database clock.
		"abs(created_at - strftime('%s','now')) < 60": "1",
	} {
		if got := secret(column); got != want {
			t.Errorf("secrets.%s = %q, want %q", column, got, want)
		}
	}

	for column, want := range map[string]string{
		"type":                "first_run",
		"kind":                kindInvitation,
		"label":               frLabel,
		"num_invites":         "1",
		"typeof(num_invites)": "integer",
		"created_by IS NULL":  "1",
		"length(id)":          "36",
	} {
		if got := row(column); got != want {
			t.Errorf("invitations.%s = %q, want %q", column, got, want)
		}
	}

	expectStoredNowhere(t, firstRunSecret)
	expectNoOrphanSecrets(t)

	// The id is a UUIDv7: version nibble 7.
	if got := scalar(t, "SELECT substr(id, 15, 1) FROM invitations"); got != "7" {
		t.Errorf("invitation id %s is not a UUIDv7", scalar(t, "SELECT id FROM invitations"))
	}

	id := row("id")

	for range 5 {
		frExpectStatus(t, "repeat check", frPending)
	}

	expectCount(t, "invitations", "1")
	expectCount(t, "users", "0")

	if got := row("id"); got != id {
		t.Errorf("a repeat check replaced the invitation: id %s -> %s", id, got)
	}
}

// TestFirstRunStateMachine walks the database states first-run reads, against
// the real SQL. Each row seeds one state and states what GET /api/first-run
// must answer and what it must leave in the invitations table.
//
// The revoked / exhausted / expired first_run rows document a real property:
// FirstRunState asks only whether a first_run row EXISTS, so a dead first-run
// invitation still reads as pending even though registration refuses its code.
// The design's answer is "recovery is a wipe" (docs/first_run_design.md).
//
//nolint:paralleltest // shares one database
func TestFirstRunStateMachine(t *testing.T) {
	const (
		idFirstRun = "00000000-0000-7000-8000-00000000f001"
		idOther    = "00000000-0000-7000-8000-00000000f002"
	)

	tests := []struct {
		name  string
		setup func(t *testing.T)
		// wantStatus and wantBody are the response.
		wantStatus int
		wantBody   string
		// wantInvitations is the invitation count afterwards, wantFirstRun
		// how many of them are first_run.
		wantInvitations string
		wantFirstRun    string
	}{
		{
			name:       "empty database creates the invitation",
			setup:      func(*testing.T) {},
			wantStatus: http.StatusOK, wantBody: frPending, wantInvitations: "1", wantFirstRun: "1",
		},
		{
			name:       "a first_run invitation exists: pending, nothing created",
			setup:      func(t *testing.T) { t.Helper(); frSeedFirstRunInvitation(t, idFirstRun, "", nil) },
			wantStatus: http.StatusOK, wantBody: frPending, wantInvitations: "1", wantFirstRun: "1",
		},
		{
			name: "a first_run invitation with a DIFFERENT code hash is still pending (the secret is not consulted)",
			setup: func(t *testing.T) {
				t.Helper()
				seedSecret(t, idFirstRun, kindInvitation, newToken(tagInvitation))
				seed(t, "INSERT INTO invitations (id, type, label, num_invites) VALUES (?, 'first_run', 'older secret', 1)", idFirstRun)
			},
			wantStatus: http.StatusOK, wantBody: frPending, wantInvitations: "1", wantFirstRun: "1",
		},
		{
			name: "a revoked first_run invitation and no account reads pending (dead end: wipe)",
			setup: func(t *testing.T) {
				t.Helper()
				frSeedFirstRunInvitation(t, idFirstRun, "revoked_at", 1)
			},
			wantStatus: http.StatusOK, wantBody: frPending, wantInvitations: "1", wantFirstRun: "1",
		},
		{
			name: "an expired first_run invitation and no account reads pending (dead end: wipe)",
			setup: func(t *testing.T) {
				t.Helper()
				frSeedFirstRunInvitation(t, idFirstRun, "expires_at", 1)
			},
			wantStatus: http.StatusOK, wantBody: frPending, wantInvitations: "1", wantFirstRun: "1",
		},
		{
			name: "an invitation of another type and no account is blocked, nothing created",
			setup: func(t *testing.T) {
				t.Helper()
				seedInvitation(t, idOther, 1)
			},
			wantStatus: http.StatusConflict, wantBody: frBlocked, wantInvitations: "1", wantFirstRun: "0",
		},
		{
			name: "another type plus an account reads accepted: the secret is never consulted",
			setup: func(t *testing.T) {
				t.Helper()
				seedInvitation(t, idOther, 1)
				seedUser(t, idUserB, "e2e_member")
			},
			wantStatus: http.StatusOK, wantBody: frAccepted, wantInvitations: "1", wantFirstRun: "0",
		},
		{
			name: "a first_run invitation plus an account reads accepted",
			setup: func(t *testing.T) {
				t.Helper()
				frSeedFirstRunInvitation(t, idFirstRun, "", nil)
				seedUser(t, idUserB, roleAdmin)
			},
			wantStatus: http.StatusOK, wantBody: frAccepted, wantInvitations: "1", wantFirstRun: "1",
		},
		{
			name: "an account whose invitation was revoked still reads accepted",
			setup: func(t *testing.T) {
				t.Helper()
				frSeedFirstRunInvitation(t, idFirstRun, "", nil)
				seedUser(t, idUserB, roleAdmin)
				seed(t, "UPDATE secrets SET revoked_at = 1 WHERE kind = 'invitation'")
			},
			wantStatus: http.StatusOK, wantBody: frAccepted, wantInvitations: "1", wantFirstRun: "1",
		},
		{
			name: "a revoked account does not reopen first run",
			setup: func(t *testing.T) {
				t.Helper()
				frSeedFirstRunInvitation(t, idFirstRun, "", nil)
				seedUser(t, idUserB, roleAdmin)
				seed(t, "UPDATE users SET revoked_at = 1")
			},
			wantStatus: http.StatusOK, wantBody: frAccepted, wantInvitations: "1", wantFirstRun: "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset(t)
			tt.setup(t)

			usersBefore := count(t, "users")

			got := get(t, pathFirstRun, "")
			if got.status != tt.wantStatus || got.body != tt.wantBody {
				t.Errorf("GET %s = %d %q, want %d %q", pathFirstRun, got.status, got.body, tt.wantStatus, tt.wantBody)
			}

			expectCount(t, "invitations", tt.wantInvitations)
			expectCount(t, "invitations WHERE type = 'first_run'", tt.wantFirstRun)
			expectCount(t, "users", usersBefore)

			// Idempotent: the same question gets the same answer.
			again := get(t, pathFirstRun, "")
			if again.status != tt.wantStatus || again.body != tt.wantBody {
				t.Errorf("second GET = %d %q, want %d %q", again.status, again.body, tt.wantStatus, tt.wantBody)
			}

			expectCount(t, "invitations", tt.wantInvitations)
		})
	}
}

// TestFirstRunDeadInvitationCannotRegister is the other half of the dead-end
// rows above: a first_run invitation that reads "pending" but is revoked or
// expired is refused by registration, so the owner is told to continue to a
// page that cannot succeed. The design accepts this ("recovery is a wipe"); the
// test pins it so a change is a conscious one.
//
//nolint:paralleltest // shares one database
func TestFirstRunDeadInvitationCannotRegister(t *testing.T) {
	for _, column := range []string{"revoked_at", "expires_at"} {
		t.Run(column, func(t *testing.T) {
			reset(t)
			frSeedFirstRunInvitation(t, "00000000-0000-7000-8000-00000000f001", column, 1)

			frExpectStatus(t, "dead invitation", frPending)
			beginRegistration(t, firstRunSecret, "Admin").
				expect(t, "begin with a dead first-run code", http.StatusForbidden, "invalid_invitation")
			expectCount(t, "users", "0")
		})
	}

	t.Run("an exhausted first_run invitation (num_invites reached by another account) reads accepted", func(t *testing.T) {
		reset(t)
		frSeedFirstRunInvitation(t, "00000000-0000-7000-8000-00000000f001", "", nil)
		seedUser(t, idUserB, roleAdmin)

		frExpectStatus(t, "exhausted", frAccepted)
		beginRegistration(t, firstRunSecret, "Admin").
			expect(t, "begin after exhaustion", http.StatusForbidden, "invalid_invitation")
	})
}

// TestFirstRunRequestShapes sends the route things it must ignore or refuse and
// proves that none of them creates or changes anything.
//
//nolint:paralleltest // shares one database
func TestFirstRunRequestShapes(t *testing.T) {
	tests := []struct {
		name string
		req  request
		// wantStatus is the response status; wantBody (when set) the exact
		// body; wantCode the error code of a refusal.
		wantStatus int
		wantCode   string
		wantBody   string
		// wantCreated says whether the request may have created the
		// invitation (only a GET may).
		wantCreated bool
	}{
		{name: "plain GET", req: request{path: pathFirstRun}, wantStatus: http.StatusOK, wantBody: frPending, wantCreated: true},
		{
			name:       "GET with a query string is harmless",
			req:        request{path: pathFirstRun + "?status=invitation_accepted&secret=x&code=y"},
			wantStatus: http.StatusOK, wantBody: frPending, wantCreated: true,
		},
		{
			name:       "GET with a body is harmless",
			req:        request{path: pathFirstRun, body: []byte(`{"secret":"x"}`)},
			wantStatus: http.StatusOK, wantBody: frPending, wantCreated: true,
		},
		{
			name:       "GET with a huge body is harmless",
			req:        request{path: pathFirstRun, body: []byte(strings.Repeat("x", 4096))},
			wantStatus: http.StatusOK, wantBody: frPending, wantCreated: true,
		},
		{
			name:       "GET with a session cookie of nobody is harmless",
			req:        request{path: pathFirstRun, token: "not.a.token"},
			wantStatus: http.StatusOK, wantBody: frPending, wantCreated: true,
		},
		{
			name:       "GET with a foreign Origin header does not echo CORS",
			req:        request{path: pathFirstRun, headers: map[string]string{"Origin": "https://evil.example"}},
			wantStatus: http.StatusOK, wantBody: frPending, wantCreated: true,
		},
		{
			name:       "POST is refused and creates nothing",
			req:        request{method: http.MethodPost, path: pathFirstRun, body: []byte("{}")},
			wantStatus: http.StatusMethodNotAllowed, wantCode: codeMethodNotAllow,
		},
		{
			name:       "PUT is refused and creates nothing",
			req:        request{method: http.MethodPut, path: pathFirstRun, body: []byte("{}")},
			wantStatus: http.StatusMethodNotAllowed, wantCode: codeMethodNotAllow,
		},
		{
			name:       "PATCH is refused and creates nothing",
			req:        request{method: http.MethodPatch, path: pathFirstRun, body: []byte("{}")},
			wantStatus: http.StatusMethodNotAllowed, wantCode: codeMethodNotAllow,
		},
		{
			name:       "DELETE is refused and creates nothing",
			req:        request{method: http.MethodDelete, path: pathFirstRun},
			wantStatus: http.StatusMethodNotAllowed, wantCode: codeMethodNotAllow,
		},
		{
			name:       "HEAD is refused and creates nothing (only GET may create)",
			req:        request{method: http.MethodHead, path: pathFirstRun},
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "OPTIONS is refused and creates nothing",
			req:        request{method: http.MethodOptions, path: pathFirstRun},
			wantStatus: http.StatusMethodNotAllowed, wantCode: codeMethodNotAllow,
		},
		{
			name:       "TRACE is refused and creates nothing",
			req:        request{method: http.MethodTrace, path: pathFirstRun},
			wantStatus: http.StatusMethodNotAllowed, wantCode: codeMethodNotAllow,
		},
		{
			name:       "a path that only looks like it is not found and creates nothing",
			req:        request{path: pathFirstRun + "/"},
			wantStatus: http.StatusNotFound, wantCode: codeNotFound,
		},
		{
			name:       "a longer path is not found and creates nothing",
			req:        request{path: pathFirstRun + "/x"},
			wantStatus: http.StatusNotFound, wantCode: codeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset(t)

			got := send(t, tt.req)
			if got.status != tt.wantStatus {
				t.Errorf("%s %s = %d %q, want %d", tt.req.method, tt.req.path, got.status, got.body, tt.wantStatus)
			}

			if tt.wantCode != "" && got.errorCode() != tt.wantCode {
				t.Errorf("error code = %q, want %q (body %q)", got.errorCode(), tt.wantCode, got.body)
			}

			if tt.wantBody != "" && got.body != tt.wantBody {
				t.Errorf("body = %q, want %q", got.body, tt.wantBody)
			}

			want := "0"
			if tt.wantCreated {
				want = "1"
			}

			expectCount(t, "invitations", want)
			expectCount(t, "users", "0")

			if got.header.Get("Access-Control-Allow-Origin") == "https://evil.example" || got.header.Get("Access-Control-Allow-Origin") == "*" {
				t.Errorf("a foreign origin was allowed: %v", got.header)
			}

			if got.header.Get("Cache-Control") != "no-store" && got.status == http.StatusOK {
				t.Errorf("Cache-Control = %q, want no-store", got.header.Get("Cache-Control"))
			}
		})
	}
}

// TestFirstRunNeverDisclosesTheSecret checks every response of the route, in
// every state it can be in, for the secret, its hash and the invitation's id.
// The route is open to the world, so anything it said would be public.
//
//nolint:paralleltest // shares one database
func TestFirstRunNeverDisclosesTheSecret(t *testing.T) {
	reset(t)

	forbidden := func(extra ...string) []string {
		return append([]string{
			firstRunSecret, b64([]byte(firstRunSecret)), frSecretHashHex(), strings.ToUpper(frSecretHashHex()),
			b64(mustDecodeHex(t, frSecretHashHex())), "susu_inv_", "invitation_id",
		}, extra...)
	}

	check := func(what string, got reply, extra ...string) {
		t.Helper()

		var builder strings.Builder

		builder.WriteString(got.body)

		for name, values := range got.header {
			builder.WriteString("\n" + name + ": " + strings.Join(values, ","))
		}

		blob := builder.String()

		for _, bad := range forbidden(extra...) {
			if strings.Contains(blob, bad) {
				t.Errorf("%s leaks %q: %s", what, bad, blob)
			}
		}
	}

	// Pending (the first check creates the invitation).
	check("first check", get(t, pathFirstRun, ""), scalar(t, "SELECT 'no-such-id'"))
	id := scalar(t, "SELECT id FROM invitations")
	check("pending", get(t, pathFirstRun, ""), id)

	// Accepted.
	registerWith(t, "Admin")
	check("accepted", get(t, pathFirstRun, ""), id, scalar(t, "SELECT id FROM users"))

	// Blocked.
	reset(t)
	seedInvitation(t, idInvitationA, 1)
	check("blocked", get(t, pathFirstRun, ""), idInvitationA)
}

// TestFirstRunConcurrentChecksCreateOneInvitation releases many checks at once
// against an empty database. The conditional INSERT admits exactly one row;
// every request must answer 200 pending (the losers re-read and see the
// winner's row), and none may fail.
//
//nolint:paralleltest // shares one database
func TestFirstRunConcurrentChecksCreateOneInvitation(t *testing.T) {
	const (
		rounds  = 4
		callers = 32
	)

	for round := range rounds {
		reset(t)

		type outcome struct {
			status int
			body   string
		}

		outcomes := make([]outcome, callers)
		start := make(chan struct{})

		var wg sync.WaitGroup

		for i := range callers {
			wg.Go(func() {
				<-start

				got := get(t, pathFirstRun, "")
				outcomes[i] = outcome{status: got.status, body: got.body}
			})
		}

		close(start)
		wg.Wait()

		mix := map[string]int{}

		for _, o := range outcomes {
			mix[o.body]++

			if o.status != http.StatusOK || o.body != frPending {
				t.Errorf("round %d: concurrent check = %d %q, want 200 pending", round, o.status, o.body)
			}
		}

		t.Logf("round %d: %v", round, mix)

		expectCount(t, "invitations", "1")
		expectCount(t, "invitations WHERE type = 'first_run' AND num_invites = 1", "1")
		expectCount(t, "users", "0")

		expectCount(t, "secrets", "1")

		if got := scalar(t, "SELECT lower(hex(hash)) FROM secrets"); got != frSecretHashHex() {
			t.Errorf("round %d: hash = %s, want %s", round, got, frSecretHashHex())
		}

		expectNoOrphanSecrets(t)
	}
}

// TestFirstRunRacesARegistration interleaves GET /api/first-run with the
// registration that closes first run. Whatever the order, the registration
// succeeds exactly once, every check answers 200 with pending or accepted
// (never an error, never a second invitation), and afterwards the state is
// accepted.
//
//nolint:paralleltest // shares one database
func TestFirstRunRacesARegistration(t *testing.T) {
	const (
		rounds   = 3
		checkers = 16
	)

	for round := range rounds {
		reset(t)
		frExpectStatus(t, "setup", frPending)

		options := mustBeginRegistration(t, firstRunSecret, "Racer")
		auth := newAuthenticator()
		body := auth.finishBody(t, options, firstRunSecret, "Racer")

		start := make(chan struct{})
		statuses := make([]reply, checkers)

		var (
			wg     sync.WaitGroup
			finish reply
		)

		wg.Go(func() {
			<-start

			finish = post(t, pathRegisterEnd, body, "")
		})

		for i := range checkers {
			wg.Go(func() {
				<-start

				statuses[i] = get(t, pathFirstRun, "")
			})
		}

		close(start)
		wg.Wait()

		finish.expect(t, "racing finish", http.StatusCreated, "")

		mix := map[string]int{}

		for _, got := range statuses {
			mix[got.body]++

			if got.status != http.StatusOK || (got.body != frPending && got.body != frAccepted) {
				t.Errorf("round %d: racing check = %d %q, want 200 pending|accepted", round, got.status, got.body)
			}
		}

		t.Logf("round %d: %v", round, mix)

		expectCount(t, "invitations", "1")
		expectCount(t, "users", "1")
		expectCount(t, "credentials", "1")
		frExpectStatus(t, "after the race", frAccepted)
	}
}

// TestFirstRunSingleUseThroughRegistration proves the first-run invitation
// closes the hole: after the first account exists the same code cannot create a
// second one, and the status stays accepted whatever is then done.
//
//nolint:paralleltest // shares one database
func TestFirstRunSingleUseThroughRegistration(t *testing.T) {
	reset(t)
	frExpectStatus(t, "setup", frPending)

	// Two ceremonies begin while the invitation is open.
	first := mustBeginRegistration(t, firstRunSecret, "First")
	second := mustBeginRegistration(t, firstRunSecret, "Second")

	post(t, pathRegisterEnd, newAuthenticator().finishBody(t, first, firstRunSecret, "First"), "").
		expect(t, "first finish", http.StatusCreated, "")
	frExpectStatus(t, "after the first account", frAccepted)

	// The second ceremony's challenge is validly signed, but the invitation is
	// spent and first run needs an empty system: refused, nothing written.
	post(t, pathRegisterEnd, newAuthenticator().finishBody(t, second, firstRunSecret, "Second"), "").
		expect(t, "second finish", http.StatusForbidden, "invalid_invitation")
	beginRegistration(t, firstRunSecret, "Third").
		expect(t, "begin after first run", http.StatusForbidden, "invalid_invitation")

	expectCount(t, "users", "1")
	expectCount(t, "credentials", "1")
	expectCount(t, "invitations", "1")
	frExpectStatus(t, "still accepted", frAccepted)
	expectCount(t, "invitations", "1")
}
