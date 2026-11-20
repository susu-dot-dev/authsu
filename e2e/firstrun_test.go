//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// firstrun_test.go drives GET /api/first-run, and the registration that creates
// the first-run invitation, against the real Worker (TinyGo wasm, workerd, the
// real D1 driver and SQLite). The unit tests fake the database, so they
// re-implement the guards that live in the SQL; only the real database can
// prove them:
//
//   - that the status route only reads: whatever it is asked, in whatever state,
//     it writes nothing (no invitation, no secret);
//   - that the first admin registers with the configured secret on an empty
//     database, with nothing stored beforehand: the invitation is created by the
//     registration's own write, in the same batch as the account, and exactly
//     once however many registrations race (interleaving);
//   - that the conditions of that creation are the database's: no other token,
//     no database with an invitation or an account, and no failed registration
//     leaves an invitation or a secret behind;
//   - the one-statement snapshot of "any user / any invitation / any first-run
//     invitation";
//   - that nothing secret (the FIRST_RUN_SECRET or its hash) ever reaches a
//     response (permission confusion / information disclosure);
//   - that a wrong method or a stray body can neither create nor change state.
//
// REVIEW.md categories covered: input edge cases (method, query, body on GET,
// tokens that are not the secret), interleaving (concurrent first registrations,
// a status check racing a registration), permission confusion (the route is open
// and must stay inert; only the exact secret creates the invitation).
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
	"strconv"
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

// TestFirstRunStatusWritesNothing proves the route only reads: from an empty
// database, any number of checks leave no invitation and no secret behind, and
// say pending because the secret is configured and registering with it will work.
//
//nolint:paralleltest // shares one database
func TestFirstRunStatusWritesNothing(t *testing.T) {
	reset(t)

	for range 5 {
		frExpectStatus(t, "check on an empty database", frPending)
	}

	expectCount(t, "invitations", "0")
	expectCount(t, "secrets", "0")
	expectCount(t, "users", "0")
}

// TestFirstRunRegistrationCreatesTheInvitation proves the empty -> accepted
// transition and the exact rows the Worker stores: the first admin registers with
// the configured secret, nothing having been stored beforehand, and the one
// write creates the invitation (its secret and its row) beside the account that
// redeems it.
//
//nolint:paralleltest // shares one database
func TestFirstRunRegistrationCreatesTheInvitation(t *testing.T) {
	reset(t)
	expectCount(t, "invitations", "0")
	expectCount(t, "secrets", "0")

	// Begin is a read: it accepts the secret with no invitation stored, and
	// writes nothing.
	options := mustBeginRegistration(t, firstRunSecret, "Admin")

	expectCount(t, "invitations", "0")
	expectCount(t, "secrets", "0")

	post(t, pathRegisterEnd, newAuthenticator().finishBody(t, options, firstRunSecret, "Admin"), "").
		expect(t, "the first registration", http.StatusCreated, "")

	// The stored rows, column by column: the invitation, and its secret, which
	// holds the hash of the token, the expiry, the revocation and the creation time.
	row := func(column string) string { return scalar(t, "SELECT "+column+" FROM invitations") }
	secret := func(column string) string { return scalar(t, "SELECT "+column+" FROM secrets") }

	expectCount(t, "invitations", "1")
	expectCount(t, "secrets", "1")
	expectCount(t, "users", "1")

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

	// The account is the invitation's redemption, and is the administrator.
	if got := scalar(t, "SELECT invitation_id = (SELECT id FROM invitations) FROM users"); got != "1" {
		t.Error("the account does not refer to the first-run invitation")
	}

	if got := scalar(t, "SELECT role FROM users"); got != roleAdmin {
		t.Errorf("role = %q, want admin", got)
	}

	expectStoredNowhere(t, firstRunSecret)
	expectNoOrphanSecrets(t)

	// The id is a UUIDv7: version nibble 7. It is the invitation's own, not the
	// account's or the passkey's.
	if got := scalar(t, "SELECT substr(id, 15, 1) FROM invitations"); got != "7" {
		t.Errorf("invitation id %s is not a UUIDv7", scalar(t, "SELECT id FROM invitations"))
	}

	if got := scalar(t, "SELECT (SELECT id FROM invitations) IN (SELECT id FROM users UNION SELECT id FROM credentials)"); got != "0" {
		t.Error("the invitation shares an id with the account or the passkey")
	}

	frExpectStatus(t, "after the first registration", frAccepted)
	expectCount(t, "invitations", "1")
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
// No row creates anything: the route only reads, so "invitations afterwards" is
// always "invitations before".
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
			name:       "an empty database is pending and nothing is created",
			setup:      func(*testing.T) {},
			wantStatus: http.StatusOK, wantBody: frPending, wantInvitations: "0", wantFirstRun: "0",
		},
		{
			name:       "a first_run invitation exists: pending",
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
			name: "an invitation of another type and no account is blocked",
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
			secretsBefore := count(t, "secrets")

			got := get(t, pathFirstRun, "")
			if got.status != tt.wantStatus || got.body != tt.wantBody {
				t.Errorf("GET %s = %d %q, want %d %q", pathFirstRun, got.status, got.body, tt.wantStatus, tt.wantBody)
			}

			expectCount(t, "invitations", tt.wantInvitations)
			expectCount(t, "invitations WHERE type = 'first_run'", tt.wantFirstRun)
			expectCount(t, "users", usersBefore)
			expectCount(t, "secrets", secretsBefore)

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
	const idStored = "00000000-0000-7000-8000-00000000f001"

	// frSeedDifferentHash stores a live first_run invitation under a token that
	// is not the configured secret, as an older deployment with another secret
	// would have left it.
	frSeedDifferentHash := func(t *testing.T) {
		t.Helper()

		seedSecret(t, idStored, kindInvitation, regUnknownCode)
		seed(t, "INSERT INTO invitations (id, type, label, num_invites) VALUES (?, 'first_run', ?, 1)", idStored, frLabel)
	}

	tests := []struct {
		name  string
		setup func(t *testing.T)
		// status is what GET /api/first-run reads once the invitation is stored.
		status string
	}{
		{"revoked", func(t *testing.T) { t.Helper(); frSeedFirstRunInvitation(t, idStored, "revoked_at", 1) }, frPending},
		{"expired", func(t *testing.T) { t.Helper(); frSeedFirstRunInvitation(t, idStored, "expires_at", 1) }, frPending},
		{"stored under a different secret than the configured one", frSeedDifferentHash, frPending},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset(t)

			// A ceremony begun while the database is empty, to be finished after
			// the invitation is stored: begin's advisory check is then not what
			// refuses it, the write is.
			options := mustBeginRegistration(t, firstRunSecret, "Admin")

			tt.setup(t)

			frExpectStatus(t, "dead invitation", tt.status)
			beginRegistration(t, firstRunSecret, "Admin").
				expect(t, "begin with a dead first-run code", http.StatusForbidden, "invalid_invitation")

			post(t, pathRegisterEnd, newAuthenticator().finishBody(t, options, firstRunSecret, "Admin"), "").
				expect(t, "finish with a dead first-run code", http.StatusForbidden, "invalid_invitation")

			// The configured secret created nothing: only the seeded rows exist.
			expectCount(t, "users", "0")
			expectCount(t, "credentials", "0")
			expectCount(t, "invitations", "1")
			expectCount(t, "invitations WHERE type = 'first_run'", "1")
			expectCount(t, "secrets", "1")
			expectNoOrphanSecrets(t)
		})
	}

	t.Run("an exhausted first_run invitation (num_invites reached by another account) reads accepted", func(t *testing.T) {
		reset(t)
		frSeedFirstRunInvitation(t, idStored, "", nil)
		seedUser(t, idUserB, roleAdmin)

		frExpectStatus(t, "exhausted", frAccepted)
		beginRegistration(t, firstRunSecret, "Admin").
			expect(t, "begin after exhaustion", http.StatusForbidden, "invalid_invitation")
	})
}

// TestFirstRunRequestShapes sends the route things it must ignore or refuse and
// proves that none of them creates or changes anything: not even a plain GET
// writes.
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
	}{
		{name: "plain GET", req: request{path: pathFirstRun}, wantStatus: http.StatusOK, wantBody: frPending},
		{
			name:       "GET with a query string is harmless",
			req:        request{path: pathFirstRun + "?status=invitation_accepted&secret=x&code=y"},
			wantStatus: http.StatusOK, wantBody: frPending,
		},
		{
			name:       "GET with a body is harmless",
			req:        request{path: pathFirstRun, body: []byte(`{"secret":"x"}`)},
			wantStatus: http.StatusOK, wantBody: frPending,
		},
		{
			name:       "GET with a huge body is harmless",
			req:        request{path: pathFirstRun, body: []byte(strings.Repeat("x", 4096))},
			wantStatus: http.StatusOK, wantBody: frPending,
		},
		{
			name:       "GET with a session cookie of nobody is harmless",
			req:        request{path: pathFirstRun, token: "not.a.token"},
			wantStatus: http.StatusOK, wantBody: frPending,
		},
		{
			name:       "GET with a foreign Origin header does not echo CORS",
			req:        request{path: pathFirstRun, headers: map[string]string{"Origin": "https://evil.example"}},
			wantStatus: http.StatusOK, wantBody: frPending,
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
			name:       "HEAD is refused and creates nothing",
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

			expectCount(t, "invitations", "0")
			expectCount(t, "secrets", "0")
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

	// Pending: the secret is configured and the database is empty.
	check("pending", get(t, pathFirstRun, ""))

	// Accepted: the registration created the invitation and the account. The
	// invitation's id is as private as the secret, so no response may carry it.
	registerWith(t, "Admin")

	id := scalar(t, "SELECT id FROM invitations")
	check("accepted", get(t, pathFirstRun, ""), id, scalar(t, "SELECT id FROM users"))

	// Blocked.
	reset(t)
	seedInvitation(t, idInvitationA, 1)
	check("blocked", get(t, pathFirstRun, ""), idInvitationA)
}

// TestFirstRunConcurrentChecksWriteNothing releases many status checks at once
// against an empty database. Every one answers 200 pending, and none writes: the
// route has no write to race.
//
//nolint:paralleltest // shares one database
func TestFirstRunConcurrentChecksWriteNothing(t *testing.T) {
	const (
		rounds  = 2
		callers = 32
	)

	for round := range rounds {
		reset(t)

		outcomes := make([]reply, callers)
		start := make(chan struct{})

		var wg sync.WaitGroup

		for i := range callers {
			wg.Go(func() {
				<-start

				outcomes[i] = get(t, pathFirstRun, "")
			})
		}

		close(start)
		wg.Wait()

		for _, got := range outcomes {
			if got.status != http.StatusOK || got.body != frPending {
				t.Errorf("round %d: concurrent check = %d %q, want 200 pending", round, got.status, got.body)
			}
		}

		expectCount(t, "invitations", "0")
		expectCount(t, "secrets", "0")
	}
}

// TestFirstRunConcurrentRegistrationsCreateOneInvitation releases many finishes
// with the first-run secret at once against an empty database, none of which
// finds an invitation stored. Each one's write offers to create it; the database
// admits exactly one registration and so exactly one invitation, the losers are
// refused cleanly (never a 5xx), and no secret is left without its invitation.
//
//nolint:paralleltest // shares one database
func TestFirstRunConcurrentRegistrationsCreateOneInvitation(t *testing.T) {
	const (
		rounds  = 4
		callers = 16
	)

	for round := range rounds {
		reset(t)

		bodies := make([][]byte, callers)

		for i := range callers {
			name := "Racer " + strconv.Itoa(i)
			options := mustBeginRegistration(t, firstRunSecret, name)
			bodies[i] = newAuthenticator().finishBody(t, options, firstRunSecret, name)
		}

		replies := make([]reply, callers)
		start := make(chan struct{})

		var wg sync.WaitGroup

		for i := range callers {
			wg.Go(func() {
				<-start

				replies[i] = post(t, pathRegisterEnd, bodies[i], "")
			})
		}

		close(start)
		wg.Wait()

		winners := 0

		for _, got := range replies {
			switch {
			case got.status == http.StatusCreated:
				winners++
			case got.status == http.StatusForbidden && got.errorCode() == "invalid_invitation":
			case got.status == http.StatusConflict && got.errorCode() == "registration_accept_failed":
			default:
				t.Errorf("round %d: loser = %d %s, want a clean 403 or 409", round, got.status, got.body)
			}
		}

		if winners != 1 {
			t.Errorf("round %d: %d winners, want exactly 1", round, winners)
		}

		expectCount(t, "invitations", "1")
		expectCount(t, "invitations WHERE type = 'first_run' AND num_invites = 1", "1")
		expectCount(t, "secrets", "1")
		expectCount(t, "users", "1")
		expectCount(t, "credentials", "1")

		if got := scalar(t, "SELECT lower(hex(hash)) FROM secrets"); got != frSecretHashHex() {
			t.Errorf("round %d: hash = %s, want %s", round, got, frSecretHashHex())
		}

		expectNoOrphanSecrets(t)
		frExpectStatus(t, "after the race", frAccepted)
	}
}

// TestFirstRunOnlyTheSecretCreatesTheInvitation proves the creation's
// conditions are the database's. A registration whose token is not the
// configured secret, whether or not it is well formed, creates no invitation and
// no account on an empty database; and neither does the secret once the database
// is no longer empty. Nothing is left behind in any case.
//
//nolint:paralleltest // shares one database
func TestFirstRunOnlyTheSecretCreatesTheInvitation(t *testing.T) {
	const idOther = "00000000-0000-7000-8000-00000000f002"

	tests := []struct {
		name  string
		setup func(t *testing.T)
		code  string
		// empty is whether the database is still empty, in which case a
		// ceremony can begin with the real secret, and finishing it with the
		// token under test is refused as a challenge of another token.
		empty bool
	}{
		{name: "a well-formed token that is not the secret", setup: func(*testing.T) {}, code: regUnknownCode, empty: true},
		{
			name: "the secret with its last character changed", setup: func(*testing.T) {},
			code: firstRunSecret[:len(firstRunSecret)-1] + "M", empty: true,
		},
		{
			name: "the secret's body in lower case", setup: func(*testing.T) {},
			code: strings.ToLower(firstRunSecret), empty: true,
		},
		{
			name: "the secret once an invitation of another type exists",
			setup: func(t *testing.T) {
				t.Helper()
				seedInvitation(t, idOther, 1)
			},
			code: firstRunSecret, empty: false,
		},
		{
			name: "the secret once an account exists",
			setup: func(t *testing.T) {
				t.Helper()
				seedInvitation(t, idOther, 1)
				seedUser(t, idUserB, roleAdmin)
			},
			code: firstRunSecret, empty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset(t)
			tt.setup(t)

			invitations, secrets, users := count(t, "invitations"), count(t, "secrets"), count(t, "users")

			beginRegistration(t, tt.code, "Mallory").expect(t, "begin", http.StatusForbidden, "invalid_invitation")

			if tt.empty {
				options := mustBeginRegistration(t, firstRunSecret, "Mallory")

				post(t, pathRegisterEnd, newAuthenticator().finishBody(t, options, tt.code, "Mallory"), "").
					expect(t, "finish with another token", http.StatusBadRequest, "invalid_challenge")
			}

			expectCount(t, "invitations", invitations)
			expectCount(t, "secrets", secrets)
			expectCount(t, "users", users)
			expectCount(t, "credentials", "0")
		})
	}
}

// TestFirstRunRacesARegistration interleaves GET /api/first-run with the
// registration that closes first run, which also creates the invitation. Whatever
// the order, the registration succeeds exactly once, every check answers 200 with
// pending or accepted (never an error, never a second invitation), and afterwards
// the state is accepted.
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
		expectCount(t, "invitations", "0")

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
// second one, neither by redeeming the invitation again nor by creating another,
// and the status stays accepted whatever is then done.
//
//nolint:paralleltest // shares one database
func TestFirstRunSingleUseThroughRegistration(t *testing.T) {
	reset(t)
	frExpectStatus(t, "setup", frPending)

	// Two ceremonies begin while the system is empty, with no invitation stored.
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

// TestFirstRunWriteGuardsAreTheDatabases proves, at finish and against the real
// database, that the conditions of the first-run creation are part of the write
// and not only of begin's advisory check. Each ceremony is begun while the
// system is empty and the configured secret is valid, so begin accepts it; the
// state then changes, and finishing with the configured secret must be refused
// with nothing created: no account, no credential, no second invitation, no
// stray secret. This is what stops a FIRST_RUN_SECRET left in the deployment from
// creating an administrator once the database is no longer empty.
//
//nolint:paralleltest // shares one database
func TestFirstRunWriteGuardsAreTheDatabases(t *testing.T) {
	const idOther = "00000000-0000-7000-8000-00000000f002"

	tests := []struct {
		name  string
		setup func(t *testing.T)
		// users, invitations and secrets are what is left after the attempt.
		users, invitations, secrets string
	}{
		{
			name:  "an invitation of another type appears: no account, so first run is blocked",
			setup: func(t *testing.T) { t.Helper(); seedInvitation(t, idOther, 1) },
			users: "0", invitations: "1", secrets: "1",
		},
		{
			name: "an account appears",
			setup: func(t *testing.T) {
				t.Helper()
				seedInvitation(t, idOther, 1)
				seedUser(t, idUserB, roleAdmin)
			},
			users: "1", invitations: "1", secrets: "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset(t)

			options := mustBeginRegistration(t, firstRunSecret, "Mallory")

			tt.setup(t)

			reply := post(t, pathRegisterEnd, newAuthenticator().finishBody(t, options, firstRunSecret, "Mallory"), "")
			if reply.status != http.StatusForbidden || reply.errorCode() != "invalid_invitation" {
				t.Errorf("finish = %d %s, want 403 invalid_invitation", reply.status, reply.body)
			}

			expectCount(t, "users", tt.users)
			expectCount(t, "credentials", "0")
			expectCount(t, "invitations", tt.invitations)
			expectCount(t, "invitations WHERE type = 'first_run'", "0")
			expectCount(t, "secrets", tt.secrets)
			expectNoOrphanSecrets(t)
		})
	}
}

// TestFirstRunFailedRegistrationLeavesNothingBehind proves the batch rolls the
// first-run invitation back with the account. The failure is provoked after the
// invitation's two inserts and the user insert have run, by a trigger on the
// credential insert, so what is checked is the database's rollback and not a
// refusal made earlier. A concurrent loser cannot show this: it sees the
// winner's rows and inserts nothing, so it would pass without any rollback.
//
// Afterwards the empty database is still empty, and with the trigger gone the
// very same request registers the first administrator, so nothing the failed
// attempt wrote made first run unavailable.
//
//nolint:paralleltest // shares one database
func TestFirstRunFailedRegistrationLeavesNothingBehind(t *testing.T) {
	reset(t)

	options := mustBeginRegistration(t, firstRunSecret, "Admin")
	body := newAuthenticator().finishBody(t, options, firstRunSecret, "Admin")

	// The trigger is dropped right after the one request, not in a t.Cleanup
	// (whose context is already cancelled), so a failing assertion below cannot
	// leave it behind for the next test.
	seed(t, "CREATE TRIGGER e2e_first_run_fail BEFORE INSERT ON credentials "+
		"BEGIN SELECT RAISE(ABORT, 'e2e: forced failure after the first-run inserts'); END")

	got := post(t, pathRegisterEnd, body, "")

	seed(t, "DROP TRIGGER e2e_first_run_fail")

	if got.status < http.StatusBadRequest {
		t.Fatalf("finish = %d %s, want a refusal", got.status, got.body)
	}

	expectCount(t, "users", "0")
	expectCount(t, "credentials", "0")
	expectCount(t, "invitations", "0")
	expectCount(t, "secrets", "0")
	expectNoOrphanSecrets(t)
	frExpectStatus(t, "after the failed attempt", frPending)

	post(t, pathRegisterEnd, body, "").expect(t, "retry without the trigger", http.StatusCreated, "")

	expectCount(t, "users WHERE role = ?", "1", roleAdmin)
	expectCount(t, "invitations WHERE type = 'first_run'", "1")
	expectCount(t, "secrets", "1")
}

// TestFirstRunCreationConditionsInTheDatabase runs the two first-run inserts
// directly, against the real database, as CreateAccount's batch does, to prove
// what the end-to-end tests cannot reach: that the creation requires the
// presented hash to equal the configured one, that an unconfigured secret (NULL)
// equals nothing, and that it needs an empty database. The Worker under test
// always has a valid secret and a token that differs from it is stopped earlier
// as a challenge of another token, so a regression that dropped the comparison
// would pass every other test.
//
//nolint:paralleltest // shares one database
func TestFirstRunCreationConditionsInTheDatabase(t *testing.T) {
	const (
		idNew   = "00000000-0000-7000-8000-00000000f101"
		idOther = "00000000-0000-7000-8000-00000000f102"

		insertSecret = "INSERT INTO secrets (id, kind, hash, expires_at, created_at) SELECT ?, ?, ?, ?, ? " +
			"WHERE ? = ? AND NOT EXISTS (SELECT 1 FROM invitations) AND NOT EXISTS (SELECT 1 FROM users)"
		insertInvitation = "INSERT INTO invitations (id, kind, type, label, num_invites) SELECT ?, ?, 'first_run', ?, 1 " +
			"WHERE EXISTS (SELECT 1 FROM secrets WHERE id = ? AND kind = ?)"
	)

	presented := tokenHash(regUnknownCode)

	tests := []struct {
		name       string
		setup      func(t *testing.T)
		configured any
		want       string // secrets and invitations afterwards (the same number)
	}{
		{"the presented token is the configured secret, empty database", func(*testing.T) {}, presented, "1"},
		{"a different token is configured", func(*testing.T) {}, tokenHash(firstRunSecret), "0"},
		{"no secret is configured (NULL)", func(*testing.T) {}, nil, "0"},
		{"the configured secret, an invitation exists",
			func(t *testing.T) { t.Helper(); seedInvitation(t, idOther, 1) }, presented, "1"},
		{"the configured secret, an account exists",
			func(t *testing.T) { t.Helper(); seedInvitation(t, idOther, 1); seedUser(t, idUserB, roleAdmin) }, presented, "1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset(t)
			tt.setup(t)

			seed(t, insertSecret, idNew, kindInvitation, presented, 4_000_000_000, 1, presented, tt.configured)
			seed(t, insertInvitation, idNew, kindInvitation, frLabel, idNew, kindInvitation)

			expectCount(t, "secrets", tt.want)
			expectCount(t, "invitations", tt.want)
			expectNoOrphanSecrets(t)
		})
	}
}

// TestFirstRunSecretHashCollisionIsAConflict proves that a secret of another
// kind already holding the configured secret's hash makes the registration a
// clean conflict, with nothing left behind: the first-run secret insert then
// violates the unique hash in the middle of the batch, and the batch rolls back.
//
//nolint:paralleltest // shares one database
func TestFirstRunSecretHashCollisionIsAConflict(t *testing.T) {
	reset(t)

	options := mustBeginRegistration(t, firstRunSecret, "Admin")

	seedSecret(t, "00000000-0000-7000-8000-00000000f201", kindSession, firstRunSecret)

	post(t, pathRegisterEnd, newAuthenticator().finishBody(t, options, firstRunSecret, "Admin"), "").
		expect(t, "finish with a colliding hash", http.StatusConflict, "registration_accept_failed")

	expectCount(t, "users", "0")
	expectCount(t, "credentials", "0")
	expectCount(t, "invitations", "0")
	expectCount(t, "secrets", "1")
}
