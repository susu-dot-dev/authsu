//go:build e2e

package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
)

const (
	missingSecretBody = `{"status":"missing_secret"}` + "\n"
	pendingBody       = `{"status":"invitation_pending"}` + "\n"
	acceptedBody      = `{"status":"invitation_accepted"}` + "\n"
)

// TestFirstRunRefusesWhenOtherInvitationExists checks the guard that lives in
// the insert's SQL: first run is minted only when there are no invitations at
// all. The unit tests cannot prove this, because their fake database
// re-implements the rule; only the real SQLite does.
//
// The Worker and its database are shared by every e2e test and the first-run
// tests change it, so they depend on source order and must not run in
// parallel. This one runs first, against the still-empty database, and removes
// what it adds so TestFirstRun starts from empty too.
//
//nolint:paralleltest // shares one database with TestFirstRun and depends on running before it
func TestFirstRunRefusesWhenOtherInvitationExists(t *testing.T) {
	const otherID = "01a1e2db-3124-7000-9746-a3e074c3b350"

	query(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at) "+
		"VALUES ('"+otherID+"', zeroblob(32), 'admin_invite', 'someone else', 1, 1)")

	t.Cleanup(func() { query(t, "DELETE FROM invitations WHERE id = '"+otherID+"'") })

	// A valid secret is configured, so a missing guard would mint here. The
	// status stays missing_secret because no invitation was minted from it.
	expectFirstRun(t, missingSecretBody)
	expectCount(t, "invitations", "1")
	expectCount(t, "invitations WHERE type = 'first_run'", "0")
}

// TestFirstRun walks GET /api/first-run through the bootstrap states against
// the real Worker, TinyGo build and D1, in order: a wrong method, the first
// check that mints, repeat checks, and finally a user closing first run.
//
// It changes the shared database (see TestFirstRunRefusesWhenOtherInvitationExists)
// and ends with a user in it, so no other e2e test may depend on the
// invitations or users tables being empty, and it must not be split into
// parallel subtests.
//
//nolint:paralleltest // shares one database with the other first-run test; the steps are ordered
func TestFirstRun(t *testing.T) {
	t.Run("wrong method does not mint", wrongMethodDoesNotMint)
	t.Run("first check mints and reports pending", firstCheckMints)
	t.Run("repeat check does not mint again", repeatCheckDoesNotMint)
	t.Run("a user closes first run", userClosesFirstRun)
}

func wrongMethodDoesNotMint(t *testing.T) {
	status, _ := get(t, http.MethodPost, "/api/first-run")
	if status != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", status, http.StatusMethodNotAllowed)
	}

	// A valid secret is configured and the system is empty, so a handler that
	// let a POST through to the service would mint here.
	expectCount(t, "invitations", "0")
}

func firstCheckMints(t *testing.T) {
	expectFirstRun(t, pendingBody)

	sum := sha256.Sum256([]byte(firstRunSecret))
	wantRow := strings.ToUpper(hex.EncodeToString(sum[:])) + "|first_run|First run: initial administrator|1"

	got := query(t, "SELECT hex(code_hash) || '|' || type || '|' || label || '|' || num_invites AS v FROM invitations")
	if got != wantRow {
		t.Errorf("stored invitation = %q, want %q", got, wantRow)
	}

	expectCount(t, "invitations WHERE created_by IS NULL", "1")
}

func repeatCheckDoesNotMint(t *testing.T) {
	for range 3 {
		expectFirstRun(t, pendingBody)
	}

	expectCount(t, "invitations", "1")
}

func userClosesFirstRun(t *testing.T) {
	query(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) "+
		"SELECT '01a1e2db-3124-7000-9746-a3e074c3b34f', x'0102', 'admin', id, 1 FROM invitations")

	expectFirstRun(t, acceptedBody)
}

// expectFirstRun issues GET /api/first-run and checks that it answers 200 with
// wantBody.
func expectFirstRun(t *testing.T, wantBody string) {
	t.Helper()

	status, body := get(t, http.MethodGet, "/api/first-run")
	if status != http.StatusOK || body != wantBody {
		t.Errorf("GET /api/first-run = %d %q, want %d %q", status, body, http.StatusOK, wantBody)
	}
}

// expectCount checks the number of rows in a table, optionally filtered:
// pass "invitations" or "invitations WHERE type = 'first_run'".
func expectCount(t *testing.T, from, want string) {
	t.Helper()

	if got := query(t, "SELECT count(*) AS v FROM "+from); got != want {
		t.Errorf("count of %s = %s, want %s", from, got, want)
	}
}

// query runs one SQL statement against the Worker's local D1 database and
// returns column "v" of its first row as text, or "" if there is no row.
// Statements that return nothing (INSERT) need no alias.
func query(t *testing.T, sql string) string {
	t.Helper()

	// `wrangler d1 execute` is the only way to reach the simulated D1 from
	// outside the Worker. --json keeps the output machine-readable.
	cmd := exec.CommandContext(context.Background(), "npx", "wrangler", "d1", "execute", "DB",
		"--local", "--persist-to", target.state, "--json", "--command", sql)
	cmd.Dir = target.root

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("d1 execute %q: %v\n%s", sql, err, out)
	}

	var parsed []struct {
		Results []map[string]any `json:"results"`
	}

	err = json.Unmarshal(out, &parsed)
	if err != nil {
		t.Fatalf("parse d1 output for %q: %v\n%s", sql, err, out)
	}

	if len(parsed) != 1 || len(parsed[0].Results) == 0 {
		return ""
	}

	return fmt.Sprint(parsed[0].Results[0]["v"])
}

// queryFails runs one SQL statement against the Worker's local D1 database and
// reports whether the database refused it. A refusal is an outcome here, not a
// test failure: the caller is asserting that a constraint held.
func queryFails(t *testing.T, sql string) bool {
	t.Helper()

	cmd := exec.CommandContext(context.Background(), "npx", "wrangler", "d1", "execute", "DB",
		"--local", "--persist-to", target.state, "--json", "--command", sql)
	cmd.Dir = target.root

	_, err := cmd.Output()

	return err != nil
}
