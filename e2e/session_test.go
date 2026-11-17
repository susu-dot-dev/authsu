//go:build e2e

package e2e_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// This file drives what happens to a session after login against the real
// Worker: reading it, ending it with logout, and the ways a stored key stops
// being usable. The key lookup and the revocation are SQL, so only the real
// SQLite can prove them.
//
// A session lasts two weeks and is never extended. Real time cannot be waited
// out, so a test ages a session by rewriting its stored expiry. The token's own
// signed exp is not changed, which is what makes this a test of the stored copy:
// the token stays valid for verification either way.

// setExpiry rewrites a session's stored expiry to be secondsLeft from now.
func setExpiry(t *testing.T, token string, secondsLeft int) {
	t.Helper()

	query(t, "UPDATE japikeys SET expires_at = strftime('%s','now') + "+strconv.Itoa(secondsLeft)+
		" WHERE kid = '"+kidOf(t, token)+"'")
}

// TestSessionStopsWorkingWhenItsKeyIsNotUsable proves the lookup refuses a key
// the database says is not usable, even though the token itself still verifies.
//
//nolint:paralleltest // shares one database with the other tests
func TestSessionStopsWorkingWhenItsKeyIsNotUsable(t *testing.T) {
	pk := registerPasskey(t)

	tests := map[string]string{
		"revoked":                 "UPDATE japikeys SET revoked_at = strftime('%s','now') - 1 WHERE kid = '{KID}'",
		"expired in the database": "UPDATE japikeys SET expires_at = strftime('%s','now') - 1 WHERE kid = '{KID}'",
		"deleted":                 "DELETE FROM japikeys WHERE kid = '{KID}'",
		// A session's key is bound to the passkey that made it, so removing the
		// passkey ends its sessions.
		"its passkey deleted": "DELETE FROM credentials WHERE id = (SELECT credential_id FROM japikeys WHERE kid = '{KID}')",
	}

	for name, update := range tests {
		t.Run(name, func(t *testing.T) {
			token := login(t, pk)

			if got := call(t, http.MethodGet, sessionPath, nil, token); got.status != http.StatusOK {
				t.Fatalf("GET /api/session before = %d %s, want 200", got.status, got.body)
			}

			query(t, strings.ReplaceAll(update, "{KID}", kidOf(t, token)))

			got := call(t, http.MethodGet, sessionPath, nil, token)
			if got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"`+codeNoAuth+`"`) {
				t.Errorf("GET /api/session = %d %s, want 401 %s", got.status, got.body, codeNoAuth)
			}
		})
	}
}

// TestSessionIsNotExtended proves nothing lengthens a session: using it does not
// move its expiry, and there is no route that mints a replacement.
//
//nolint:paralleltest // shares one database with the other tests
func TestSessionIsNotExtended(t *testing.T) {
	pk := registerPasskey(t)
	token := login(t, pk)

	setExpiry(t, token, 3600)

	before := query(t, "SELECT CAST(expires_at AS TEXT) AS v FROM japikeys WHERE kid = '"+kidOf(t, token)+"'")

	for range 3 {
		if got := call(t, http.MethodGet, sessionPath, nil, token); got.status != http.StatusOK {
			t.Fatalf("GET /api/session = %d %s, want 200", got.status, got.body)
		}
	}

	after := query(t, "SELECT CAST(expires_at AS TEXT) AS v FROM japikeys WHERE kid = '"+kidOf(t, token)+"'")
	if after != before {
		t.Errorf("using a session moved its expiry from %s to %s", before, after)
	}

	expectCount(t, "japikeys", "1")

	// There is no refresh: the user signs in again.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if got := call(t, method, "/api/refresh", nil, token); got.status != http.StatusNotFound {
			t.Errorf("%s /api/refresh = %d %s, want 404", method, got.status, got.body)
		}
	}

	expectCount(t, "japikeys", "1")
}

// TestLogout walks POST /api/logout against the real Worker.
//
//nolint:paralleltest // shares one database with the other tests; the steps are ordered
func TestLogout(t *testing.T) {
	pk := registerPasskey(t)

	t.Run("requires a session", func(t *testing.T) {
		got := call(t, http.MethodPost, logoutPath, nil, "")
		if got.status != http.StatusUnauthorized {
			t.Errorf("logout = %d %s, want 401", got.status, got.body)
		}
	})

	t.Run("revokes now and clears the cookie", logoutRevokesNow(pk))
	t.Run("only ends the session it was given", logoutEndsOnlyThatSession(pk))
}

func logoutRevokesNow(pk passkey) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()

		token := login(t, pk)

		got := call(t, http.MethodPost, logoutPath, nil, token)
		if got.status != http.StatusNoContent || got.body != "" {
			t.Fatalf("logout = %d %q, want 204 with no body", got.status, got.body)
		}

		// The browser is told to drop the cookie: an empty value that is already
		// expired, with the same attributes the session cookie had.
		if len(got.setCookies) != 1 {
			t.Fatalf("Set-Cookie = %v, want exactly one", got.setCookies)
		}

		line := got.setCookies[0]

		for _, want := range []string{cookieName + "=;", "Path=/", "HttpOnly", "Secure", "Max-Age=0"} {
			if !strings.Contains(line, want) {
				t.Errorf("Set-Cookie %q lacks %q", line, want)
			}
		}

		// Revoked now, and the row stays: deleting it would reopen replay of the
		// login that created it.
		expectCount(t, "japikeys WHERE kid = '"+kidOf(t, token)+"' AND revoked_at <= strftime('%s','now')", "1")

		if whoami := call(t, http.MethodGet, sessionPath, nil, token); whoami.status != http.StatusUnauthorized {
			t.Errorf("GET /api/session after logout = %d, want 401", whoami.status)
		}

		// Logging out twice is a 401, like any request without a valid session.
		if again := call(t, http.MethodPost, logoutPath, nil, token); again.status != http.StatusUnauthorized {
			t.Errorf("second logout = %d, want 401", again.status)
		}
	}
}

func logoutEndsOnlyThatSession(pk passkey) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()

		first, second := login(t, pk), login(t, pk)

		if got := call(t, http.MethodPost, logoutPath, nil, first); got.status != http.StatusNoContent {
			t.Fatalf("logout = %d %s, want 204", got.status, got.body)
		}

		if got := call(t, http.MethodGet, sessionPath, nil, second); got.status != http.StatusOK {
			t.Errorf("another session after logout = %d %s, want 200", got.status, got.body)
		}
	}
}

// TestLoginRowsSurviveLogout holds the rule the design depends on: a revoked
// session's row stays until it expires, because the unique grant on it is what
// stops its login being replayed.
//
//nolint:paralleltest // shares one database with the other tests
func TestLoginRowsSurviveLogout(t *testing.T) {
	pk := registerPasskey(t)

	options := beginLogin(t)
	body := pk.assertion().body(t, options)

	first := call(t, http.MethodPost, loginPath+"/finish", body, "")
	if first.status != http.StatusOK {
		t.Fatalf("login = %d %s, want 200", first.status, first.body)
	}

	if got := call(t, http.MethodPost, logoutPath, nil, first.session()); got.status != http.StatusNoContent {
		t.Fatalf("logout = %d %s, want 204", got.status, got.body)
	}

	// The captured response, replayed after logout and within the challenge
	// window: if logout had deleted the row, this would mint a fresh session.
	again := call(t, http.MethodPost, loginPath+"/finish", body, "")
	if again.status != http.StatusUnauthorized || again.session() != "" {
		t.Errorf("replay after logout = %d %s, want 401 and no cookie", again.status, again.body)
	}
}

// TestLoginRacingAPasskeyDeletion holds that a login whose passkey is deleted
// after it was looked up and before the session is written is an ordinary
// failed login (401 invalid_login), not a server fault.
//
// finish reads the credential, verifies, then writes. Deleting the passkey in
// that gap cannot be timed from outside, so a trigger does it at the one point
// that is inside the write: the batch's first statement updates the credential's
// flags, and the trigger deletes the credential in response, as a concurrent
// delete committed just ahead of the session insert would. The session insert
// then has no passkey to attach to. That is the user's passkey going away, not a
// defect in the code, so it must not be reported (and alerted on) as one.
//
//nolint:paralleltest // shares one database with the other tests
func TestLoginRacingAPasskeyDeletion(t *testing.T) {
	pk := registerPasskey(t)

	query(t, "CREATE TRIGGER e2e_race_delete AFTER UPDATE OF flags ON credentials "+
		"BEGIN DELETE FROM credentials WHERE id = NEW.id; END")

	t.Cleanup(func() { query(t, "DROP TRIGGER IF EXISTS e2e_race_delete") })

	got := call(t, http.MethodPost, loginPath+"/finish", pk.assertion().body(t, beginLogin(t)), "")

	if got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"`+codeInvalid+`"`) {
		t.Errorf("finish = %d %s, want 401 %s", got.status, got.body, codeInvalid)
	}

	if got.session() != "" {
		t.Error("a login whose passkey was deleted set a session cookie")
	}

	expectCount(t, "japikeys", "0")
}
