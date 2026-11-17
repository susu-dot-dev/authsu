//go:build e2e

package e2e_test

import (
	"net/http"
	"strings"
	"testing"
)

// This file drives /api/user against the real Worker. The unit tests fake the
// database, so these prove what only the real build and SQLite can: that
// TinyGo's mux routes GET and DELETE on "/api/user/{id}", and that the revoke
// statement's last-admin guard, its idempotence, and the keys it revokes behave
// as the SQL says. They also prove the effect of revocation outside this API:
// a revoked account's sessions stop verifying and it cannot log in again.

const (
	userPath = "/api/user"
	// userB and userC are fixed ids for accounts a test inserts.
	userB = "00000000-0000-7000-8000-00000000b001"
	userC = "00000000-0000-7000-8000-00000000b002"
	// userMissing is a well-formed id nothing has.
	userMissing = "00000000-0000-7000-8000-00000000bfff"

	codeLastAdmin = "user_last_admin"
)

// seedUser inserts an account with role, from the invitation registerPasskey
// redeemed, so its foreign key is satisfied.
func seedUser(t *testing.T, id, role string) {
	t.Helper()

	query(t, "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) VALUES ('"+id+
		"', randomblob(16), '"+role+"', (SELECT id FROM invitations LIMIT 1), '{\"name\":\"seeded\"}', "+
		"strftime('%s','now'))")
}

// seedSession inserts a session key for id, so a test can see revocation reach
// it. It is never verified: it only needs to be a row.
func seedSession(t *testing.T, kid, id string) {
	t.Helper()

	query(t, "INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, created_at) VALUES ('"+kid+"', '"+id+
		"', 'session', '{}', strftime('%s','now') + 3600, strftime('%s','now'))")
}

// adminID is the id of the account registerPasskey created. Call it before
// seeding another admin.
func adminID(t *testing.T) string {
	t.Helper()

	return query(t, "SELECT id AS v FROM users WHERE role = 'admin' LIMIT 1")
}

func revokeUser(t *testing.T, token, id string) reply {
	t.Helper()

	return call(t, http.MethodDelete, userPath+"/"+id, nil, token)
}

// TestUserRoutesRequireAnAdmin: without a session every route is 401, and with
// the session of an account that is not an admin every route is 403.
//
//nolint:paralleltest // shares one database with the other tests
func TestUserRoutesRequireAnAdmin(t *testing.T) {
	token := login(t, registerPasskey(t))
	seedUser(t, userB, "e2e_member")

	routes := []struct{ method, path string }{
		{http.MethodGet, userPath}, {http.MethodGet, userPath + "/" + userB}, {http.MethodDelete, userPath + "/" + userB},
	}

	for _, rt := range routes {
		if got := call(t, rt.method, rt.path, nil, ""); got.status != http.StatusUnauthorized {
			t.Errorf("signed out %s %s = %d %s, want 401", rt.method, rt.path, got.status, got.body)
		}
	}

	query(t, "UPDATE users SET role = 'e2e_member'")

	for _, rt := range routes {
		got := call(t, rt.method, rt.path, nil, token)
		if got.status != http.StatusForbidden || !strings.Contains(got.body, `"users_forbidden"`) {
			t.Errorf("member %s %s = %d %s, want 403 users_forbidden", rt.method, rt.path, got.status, got.body)
		}
	}

	expectCount(t, "users WHERE revoked_at IS NOT NULL", "0")
}

// TestUserListAndGet reads accounts through the real routes.
//
//nolint:paralleltest // shares one database with the other tests
func TestUserListAndGet(t *testing.T) {
	token := login(t, registerPasskey(t))
	seedUser(t, userB, "e2e_member")
	query(t, "UPDATE users SET revoked_at = 12345 WHERE id = '"+userB+"'")

	list := call(t, http.MethodGet, userPath, nil, token)
	if list.status != http.StatusOK {
		t.Fatalf("GET = %d %s, want 200", list.status, list.body)
	}

	for _, want := range []string{
		`"id":"` + adminID(t) + `"`, `"role":"admin"`, `"profile":{"name":"Login Tester"}`, `"status":"active"`,
		`"id":"` + userB + `"`, `"status":"revoked"`, `"revokedAt":12345`,
	} {
		if !strings.Contains(list.body, want) {
			t.Errorf("list lacks %s:\n%s", want, list.body)
		}
	}

	if strings.Contains(strings.ToLower(list.body), "handle") {
		t.Errorf("list mentions the user handle:\n%s", list.body)
	}

	one := call(t, http.MethodGet, userPath+"/"+userB, nil, token)
	if one.status != http.StatusOK || !strings.Contains(one.body, `"profile":{"name":"seeded"}`) {
		t.Errorf("GET one = %d %s, want 200 with its profile", one.status, one.body)
	}

	if got := call(t, http.MethodGet, userPath+"/"+userMissing, nil, token); got.status != http.StatusNotFound {
		t.Errorf("GET unknown = %d %s, want 404", got.status, got.body)
	}

	if got := call(t, http.MethodGet, userPath+"/nope", nil, token); got.status != http.StatusBadRequest {
		t.Errorf("GET bad id = %d %s, want 400", got.status, got.body)
	}
}

// TestUserRevoke revokes a member: the row stays, its keys are revoked with it,
// and revoking again keeps the first time.
//
//nolint:paralleltest // shares one database with the other tests
func TestUserRevoke(t *testing.T) {
	token := login(t, registerPasskey(t))
	seedUser(t, userB, "e2e_member")
	seedSession(t, "00000000-0000-7000-8000-00000000c001", userB)

	got := revokeUser(t, token, userB)
	if got.status != http.StatusOK || !strings.Contains(got.body, `"status":"revoked"`) {
		t.Fatalf("DELETE = %d %s, want 200 and revoked", got.status, got.body)
	}

	expectCount(t, "users WHERE id = '"+userB+"' AND revoked_at IS NOT NULL", "1")
	expectCount(t, "japikeys WHERE user_id = '"+userB+"' AND revoked_at IS NULL", "0")
	// Nobody else's keys were touched.
	expectCount(t, "japikeys WHERE user_id <> '"+userB+"' AND revoked_at IS NULL", "1")

	query(t, "UPDATE users SET revoked_at = 12345 WHERE id = '"+userB+"'")

	if again := revokeUser(t, token, userB); again.status != http.StatusOK ||
		!strings.Contains(again.body, `"revokedAt":12345`) {
		t.Errorf("second DELETE = %d %s, want 200 keeping revokedAt 12345", again.status, again.body)
	}

	if missing := revokeUser(t, token, userMissing); missing.status != http.StatusNotFound {
		t.Errorf("DELETE unknown = %d %s, want 404", missing.status, missing.body)
	}
}

// TestUserRevokeSparesTheLastAdmin: the only active admin cannot be revoked,
// and the guard counts only active admins, so two admins can never revoke
// each other down to none.
//
//nolint:paralleltest // shares one database with the other tests
func TestUserRevokeSparesTheLastAdmin(t *testing.T) {
	token := login(t, registerPasskey(t))
	self := adminID(t)

	got := revokeUser(t, token, self)
	if got.status != http.StatusConflict || !strings.Contains(got.body, `"`+codeLastAdmin+`"`) {
		t.Fatalf("DELETE the only admin = %d %s, want 409 %s", got.status, got.body, codeLastAdmin)
	}

	expectCount(t, "users WHERE revoked_at IS NOT NULL", "0")
	expectCount(t, "japikeys WHERE revoked_at IS NULL", "1")

	// A second admin may be revoked while this one is active...
	seedUser(t, userB, "admin")

	if got := revokeUser(t, token, userB); got.status != http.StatusOK {
		t.Fatalf("DELETE the other admin = %d %s, want 200", got.status, got.body)
	}

	// ...after which this one is the last again. A revoked admin does not
	// count, and neither does an active account that is not an admin.
	seedUser(t, userC, "e2e_member")

	if got := revokeUser(t, token, self); got.status != http.StatusConflict {
		t.Errorf("DELETE the last active admin = %d %s, want 409", got.status, got.body)
	}

	if got := call(t, http.MethodGet, sessionPath, nil, token); got.status != http.StatusOK {
		t.Errorf("GET /api/session after a refused revoke = %d %s, want 200", got.status, got.body)
	}
}

// TestRevokedAccountIsSignedOutAndLockedOut: an admin revokes their own account
// while another admin exists. The session they used stops verifying at once,
// and the passkey can no longer log in.
//
//nolint:paralleltest // shares one database with the other tests
func TestRevokedAccountIsSignedOutAndLockedOut(t *testing.T) {
	pk := registerPasskey(t)
	token := login(t, pk)
	self := adminID(t)
	seedUser(t, userB, "admin")

	if got := revokeUser(t, token, self); got.status != http.StatusOK {
		t.Fatalf("DELETE self = %d %s, want 200", got.status, got.body)
	}

	got := call(t, http.MethodGet, sessionPath, nil, token)
	if got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"`+codeNoAuth+`"`) {
		t.Errorf("GET /api/session = %d %s, want 401 %s", got.status, got.body, codeNoAuth)
	}

	before := query(t, "SELECT count(*) AS v FROM japikeys")

	again := call(t, http.MethodPost, loginPath+"/finish", pk.assertion().body(t, beginLogin(t)), "")
	if again.status != http.StatusUnauthorized || again.session() != "" {
		t.Errorf("login of a revoked account = %d %s, want 401 and no session", again.status, again.body)
	}

	expectCount(t, "japikeys", before)

	// The session check reads the account, not only the key: clearing the
	// key's revocation does not bring a revoked account's session back.
	query(t, "UPDATE japikeys SET revoked_at = NULL")

	if got := call(t, http.MethodGet, sessionPath, nil, token); got.status != http.StatusUnauthorized {
		t.Errorf("GET /api/session with the key restored = %d %s, want 401", got.status, got.body)
	}
}

// TestUserRoutingUnderTinyGo pins what only the real build can show: the
// collection and the item are separate routes with separate methods.
//
//nolint:paralleltest // shares one database with the other tests
func TestUserRoutingUnderTinyGo(t *testing.T) {
	token := login(t, registerPasskey(t))
	itemPath := userPath + "/" + userB

	tests := map[string]struct {
		method, path string
		want         int
		allow        string
	}{
		"collection rejects DELETE": {http.MethodDelete, userPath, http.StatusMethodNotAllowed, "GET"},
		"collection rejects POST":   {http.MethodPost, userPath, http.StatusMethodNotAllowed, "GET"},
		"item rejects PATCH":        {http.MethodPatch, itemPath, http.StatusMethodNotAllowed, "DELETE, GET"},
		"two segments are no route": {http.MethodGet, itemPath + "/x", http.StatusNotFound, ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := call(t, tt.method, tt.path, nil, token)
			if got.status != tt.want || got.header.Get("Allow") != tt.allow {
				t.Errorf("%s %s = %d (Allow %q) %s, want %d (Allow %q)",
					tt.method, tt.path, got.status, got.header.Get("Allow"), got.body, tt.want, tt.allow)
			}
		})
	}
}
