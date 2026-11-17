//go:build e2e

package e2e_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// This file drives /api/invitation against the real Worker. The unit tests fake
// the database, so these prove what only the real build and SQLite can: that
// TinyGo's mux routes a method on "/api/invitation/{id}" and hands the handler
// the id, the conditional writes (cap below uses, revoked), and the use count.
//
// POST cannot create anything yet (no invitation type is creatable), so the
// invitations here are inserted with SQL, as the registration tests do.

const (
	invitationPath = "/api/invitation"
	// invA and invB are fixed ids for invitations a test inserts.
	invA = "00000000-0000-7000-8000-00000000a001"
	invB = "00000000-0000-7000-8000-00000000a002"
	// invMissing is a well-formed id nothing has.
	invMissing = "00000000-0000-7000-8000-00000000ffff"

	routeCreate = "create"
	body9       = `{"numInvites":9}`
)

// seedInvitation inserts an invitation that is not first run. Its code hash is
// distinct per id, so the UNIQUE column is satisfied.
func seedInvitation(t *testing.T, id string, numInvites int) {
	t.Helper()

	query(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at) VALUES ('"+id+
		"', randomblob(32), 'e2e_invite', 'seeded', "+itoa(numInvites)+", strftime('%s','now'))")
}

func itoa(n int) string { return strconv.Itoa(n) }

// seedUsers makes n accounts that came from the invitation.
func seedUsers(t *testing.T, invitation string, n int) {
	t.Helper()

	for i := range n {
		query(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) VALUES ('"+
			"00000000-0000-7000-8000-0000000b000"+itoa(i)+"', randomblob(16), 'e2e_none', '"+invitation+
			"', strftime('%s','now'))")
	}
}

func cleanInvitations(t *testing.T) {
	t.Helper()

	query(t, "DELETE FROM users WHERE role = 'e2e_none'")
	query(t, "DELETE FROM invitations WHERE type = 'e2e_invite'")
}

// TestInvitationRoutesRequireAnAdmin: without a session every route is 401, and
// with the session of an account that is not an admin every route is 403.
//
//nolint:paralleltest // shares one database with the other tests
func TestInvitationRoutesRequireAnAdmin(t *testing.T) {
	token := login(t, registerPasskey(t))
	itemPath := invitationPath + "/" + invA

	routes := map[string]struct {
		method, path string
		body         []byte
	}{
		"list":      {http.MethodGet, invitationPath, nil},
		routeCreate: {http.MethodPost, invitationPath, []byte(`{"type":"first_run","numInvites":1}`)},
		"update":    {http.MethodPatch, itemPath, []byte(`{"numInvites":2}`)},
		"revoke":    {http.MethodDelete, itemPath, nil},
	}

	for name, rt := range routes {
		t.Run(name+" signed out", func(t *testing.T) {
			got := call(t, rt.method, rt.path, rt.body, "")
			// Create is refused for its body first, before anyone is asked who they are.
			want := http.StatusUnauthorized
			if name == routeCreate {
				want = http.StatusBadRequest
			}

			if got.status != want {
				t.Errorf("%s %s = %d %s, want %d", rt.method, rt.path, got.status, got.body, want)
			}
		})
	}

	query(t, "UPDATE users SET role = 'e2e_member'")
	t.Cleanup(func() { query(t, "UPDATE users SET role = 'admin'") })

	for name, rt := range routes {
		if name == routeCreate {
			continue // refused for its body before the role is looked at
		}

		t.Run(name+" not an admin", func(t *testing.T) {
			got := call(t, rt.method, rt.path, rt.body, token)
			if got.status != http.StatusForbidden || !strings.Contains(got.body, `"invitations_forbidden"`) {
				t.Errorf("%s %s = %d %s, want 403 invitations_forbidden", rt.method, rt.path, got.status, got.body)
			}
		})
	}
}

// TestInvitationList lists invitations through the real route, including a
// revoked one, with their derived status and use counts.
//
//nolint:paralleltest // shares one database with the other tests
func TestInvitationList(t *testing.T) {
	token := login(t, registerPasskey(t))

	t.Cleanup(func() { cleanInvitations(t) })
	cleanInvitations(t)
	seedInvitation(t, invA, 2)
	seedUsers(t, invA, 1)
	seedInvitation(t, invB, 1)
	query(t, "UPDATE invitations SET revoked_at = strftime('%s','now') WHERE id = '"+invB+"'")

	got := call(t, http.MethodGet, invitationPath, nil, token)
	if got.status != http.StatusOK {
		t.Fatalf("GET = %d %s, want 200", got.status, got.body)
	}

	for _, want := range []string{
		`"id":"` + invA + `"`, `"uses":1`, `"numInvites":2`, `"status":"active"`,
		`"id":"` + invB + `"`, `"status":"revoked"`, `"revokedAt":`,
		`"type":"first_run"`, // the first-run invitation registerPasskey made is listed too
	} {
		if !strings.Contains(got.body, want) {
			t.Errorf("list lacks %s:\n%s", want, got.body)
		}
	}

	for _, banned := range []string{"code", "hash"} {
		if strings.Contains(strings.ToLower(got.body), banned) {
			t.Errorf("list mentions %q:\n%s", banned, got.body)
		}
	}
}

// TestInvitationCreateIsRefusedForEveryType: no type is creatable yet, and first
// run in particular says to use /api/first-run. Nothing is written.
//
//nolint:paralleltest // shares one database with the other tests
func TestInvitationCreateIsRefusedForEveryType(t *testing.T) {
	token := login(t, registerPasskey(t))
	before := query(t, "SELECT count(*) AS v FROM invitations")

	for _, invitationType := range []string{"first_run", "e2e_invite"} {
		got := call(t, http.MethodPost, invitationPath, []byte(`{"type":"`+invitationType+`","numInvites":1}`), token)
		if got.status != http.StatusBadRequest || !strings.Contains(got.body, `"invalid_invitation_type"`) {
			t.Errorf("POST type %s = %d %s, want 400 invalid_invitation_type", invitationType, got.status, got.body)
		}
	}

	expectCount(t, "invitations", before)
}

// patcher sends PATCH /api/invitation/{id} as the admin.
func patcher(t *testing.T, token string) func(id, body string) reply {
	t.Helper()

	return func(id, body string) reply {
		return call(t, http.MethodPatch, invitationPath+"/"+id, []byte(body), token)
	}
}

// TestInvitationUpdate changes the cap through PATCH /api/invitation/{id}, and
// checks what the conditional write refuses: a cap below the accounts made, and
// a revoked invitation.
//
//nolint:paralleltest // shares one database with the other tests
func TestInvitationUpdate(t *testing.T) {
	token := login(t, registerPasskey(t))

	t.Cleanup(func() { cleanInvitations(t) })
	cleanInvitations(t)
	seedInvitation(t, invA, 3)
	seedUsers(t, invA, 2)
	seedInvitation(t, invB, 3)
	query(t, "UPDATE invitations SET revoked_at = strftime('%s','now') WHERE id = '"+invB+"'")

	patch := patcher(t, token)

	t.Run("raises the cap", func(t *testing.T) {
		got := patch(invA, `{"numInvites":10}`)
		if got.status != http.StatusOK || !strings.Contains(got.body, `"numInvites":10`) ||
			!strings.Contains(got.body, `"uses":2`) {
			t.Errorf("PATCH = %d %s, want 200 with the new cap", got.status, got.body)
		}

		expectCount(t, "invitations WHERE id = '"+invA+"' AND num_invites = 10", "1")
	})

	t.Run("may lower it to exactly the accounts made", func(t *testing.T) {
		got := patch(invA, `{"numInvites":2}`)
		if got.status != http.StatusOK || !strings.Contains(got.body, `"status":"exhausted"`) {
			t.Errorf("PATCH = %d %s, want 200 and exhausted", got.status, got.body)
		}
	})

	t.Run("refusals", func(t *testing.T) { updateRefusals(t, patch) })
}

func updateRefusals(t *testing.T, patch func(id, body string) reply) {
	t.Helper()

	tests := map[string]struct {
		id, body string
		status   int
		code     string
		extra    string
	}{
		"not below the accounts made": {invA, `{"numInvites":1}`, http.StatusConflict, "num_invites_below_uses", `"uses":2`},
		"not once revoked":            {invB, body9, http.StatusConflict, "invitation_revoked", ""},
		"unknown invitation":          {invMissing, body9, http.StatusNotFound, "invitation_not_found", ""},
		"malformed id":                {"not-a-uuid", body9, http.StatusBadRequest, "invalid_invitation_id", ""},
		"zero":                        {invA, `{"numInvites":0}`, http.StatusBadRequest, "invalid_num_invites", ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := patch(tt.id, tt.body)
			if got.status != tt.status || !strings.Contains(got.body, `"`+tt.code+`"`) ||
				!strings.Contains(got.body, tt.extra) {
				t.Errorf("PATCH = %d %s, want %d %s %s", got.status, got.body, tt.status, tt.code, tt.extra)
			}
		})
	}

	// None of them changed a stored cap.
	expectCount(t, "invitations WHERE id = '"+invA+"' AND num_invites = 2", "1")
	expectCount(t, "invitations WHERE id = '"+invB+"' AND num_invites = 3", "1")
}

// TestInvitationRevoke revokes through DELETE /api/invitation/{id}: the row
// stays, revocation is idempotent and keeps the first time, and a revoked
// invitation can no longer be redeemed.
//
//nolint:paralleltest // shares one database with the other tests
func TestInvitationRevoke(t *testing.T) {
	token := login(t, registerPasskey(t))

	t.Cleanup(func() { cleanInvitations(t) })
	cleanInvitations(t)
	seedInvitation(t, invA, 1)
	seedUsers(t, invA, 1)

	revoke := func(id string) reply { return call(t, http.MethodDelete, invitationPath+"/"+id, nil, token) }

	got := revoke(invA)
	if got.status != http.StatusOK || !strings.Contains(got.body, `"status":"revoked"`) {
		t.Fatalf("DELETE = %d %s, want 200 and revoked", got.status, got.body)
	}

	// Deleting a revoked invitation's row is impossible once accounts came from
	// it, so it is kept; the audit trail stays.
	expectCount(t, "invitations WHERE id = '"+invA+"' AND revoked_at IS NOT NULL", "1")
	expectCount(t, "users WHERE invitation_id = '"+invA+"'", "1")

	// Idempotent, and the first revocation time is the one that stays.
	query(t, "UPDATE invitations SET revoked_at = 12345 WHERE id = '"+invA+"'")

	if again := revoke(invA); again.status != http.StatusOK || !strings.Contains(again.body, `"revokedAt":12345`) {
		t.Errorf("second DELETE = %d %s, want 200 keeping revokedAt 12345", again.status, again.body)
	}

	if missing := revoke(invMissing); missing.status != http.StatusNotFound {
		t.Errorf("DELETE unknown = %d %s, want 404", missing.status, missing.body)
	}

	if bad := revoke("nope"); bad.status != http.StatusBadRequest {
		t.Errorf("DELETE bad id = %d %s, want 400", bad.status, bad.body)
	}
}

// TestInvitationRoutingUnderTinyGo pins what only the real build can show: the
// wildcard path matches exactly one segment, the collection and the item are
// separate routes with separate methods, and a wrong method is a 405.
//
//nolint:paralleltest // shares one database with the other tests
func TestInvitationRoutingUnderTinyGo(t *testing.T) {
	token := login(t, registerPasskey(t))
	itemPath := invitationPath + "/" + invA

	tests := map[string]struct {
		method, path string
		want         int
		allow        string
	}{
		"collection rejects PATCH":  {http.MethodPatch, invitationPath, http.StatusMethodNotAllowed, "GET, POST"},
		"collection rejects PUT":    {http.MethodPut, invitationPath, http.StatusMethodNotAllowed, "GET, POST"},
		"item rejects GET":          {http.MethodGet, itemPath, http.StatusMethodNotAllowed, "DELETE, PATCH"},
		"item rejects POST":         {http.MethodPost, itemPath, http.StatusMethodNotAllowed, "DELETE, PATCH"},
		"two segments are no route": {http.MethodDelete, itemPath + "/x", http.StatusNotFound, ""},
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

// TestInvitationCORS: the UI's origin may preflight PATCH and DELETE, which are
// not CORS-safelisted, so they always need it; another origin may not.
//
//nolint:paralleltest // shares one database with the other tests
func TestInvitationCORS(t *testing.T) {
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		path := invitationPath + "/" + invA

		allowed := rawRequest(t, http.MethodOptions, path, map[string]string{
			originHeader:         target.origin,
			requestMethodHeader:  method,
			requestHeadersHeader: contentTypeOnly,
		})

		if allowed.status != http.StatusNoContent || allowed.header.Get("Access-Control-Allow-Methods") != method {
			t.Errorf("UI preflight for %s = %d %v, want 204 allowing it", method, allowed.status, allowed.header)
		}

		foreign := rawRequest(t, http.MethodOptions, path, map[string]string{
			originHeader:        evilOrigin,
			requestMethodHeader: method,
		})

		if foreign.status < 400 || foreign.header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("foreign preflight for %s = %d %v, want a refusal", method, foreign.status, foreign.header)
		}

		unsafe := rawRequest(t, method, path, map[string]string{originHeader: evilOrigin, "Content-Type": plainText})
		if unsafe.status != http.StatusUnsupportedMediaType {
			t.Errorf("%s as text/plain = %d, want 415", method, unsafe.status)
		}
	}
}
