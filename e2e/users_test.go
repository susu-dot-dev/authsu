//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// users_test.go drives /api/user (admin only) against the real TinyGo Worker
// and the real D1/SQLite. What it proves that the host unit tests cannot:
//
//   - the GET/DELETE routing of "/api/user/{id}" under TinyGo's ServeMux;
//   - that a stored profile reaches the client as a JSON OBJECT (not an escaped
//     string) through TinyGo's encoding/json, including 6x-escaped names, and
//     which stored profiles SQLite's json_valid lets in that the handler then
//     refuses;
//   - the revoke batch (user, keys, agents) and its last-admin guard against
//     real SQLite, including the effect on logins and sessions;
//   - interleavings: admins revoking each other concurrently must never leave
//     the deployment without an active admin.
//
// REVIEW.md categories covered: input edge cases (ids, profiles, roles),
// interleaving (mutual and self revocation, repeated revoke), permission
// confusion (role spellings that must not be admin, a revoked admin, a session
// that dies on revoke), and type/bound confusion (revoked_at of 0 or far
// future, JSON profile vs string, JS-number-sized timestamps).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	usrCodeNotFound  = "user_not_found"
	usrCodeLastAdmin = "user_last_admin"
	// usrCodeProfile is the code in the Worker's log; an Internal error is served as
	// the bare "internal" (httpapi.marshalError), so a client can never see it.
	usrCodeInternal = "internal"
	usrActive       = "active"
	usrRevoked      = "revoked"
)

// usrView is the JSON an account is served as. Profile is raw so a test can see
// whether it is an object or an escaped string.
type usrView struct {
	ID           string          `json:"id"`
	Role         string          `json:"role"`
	InvitationID string          `json:"invitationId"`
	Profile      json.RawMessage `json:"profile"`
	Status       string          `json:"status"`
	RevokedAt    *int64          `json:"revokedAt"`
	CreatedAt    int64           `json:"createdAt"`
}

// usrDecode strictly decodes body into out: an unknown member fails.
func usrDecode(t *testing.T, body string, out any) {
	t.Helper()

	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()

	err := dec.Decode(out)
	if err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

// usrList reads GET /api/user.
func usrList(t *testing.T, token string) []usrView {
	t.Helper()

	got := get(t, pathUser, token)
	if got.status != http.StatusOK {
		t.Fatalf("GET %s = %d %s, want 200", pathUser, got.status, got.body)
	}

	var out struct {
		Users []usrView `json:"users"`
	}

	usrDecode(t, got.body, &out)

	return out.Users
}

// usrOne reads GET /api/user/{id}.
func usrOne(t *testing.T, token, id string) usrView {
	t.Helper()

	got := get(t, usrItem(id), token)
	if got.status != http.StatusOK {
		t.Fatalf("GET user %s = %d %s, want 200", id, got.status, got.body)
	}

	var view usrView

	usrDecode(t, got.body, &view)

	return view
}

func usrItem(id string) string { return pathUser + "/" + id }

// usrRevoke is DELETE /api/user/{id}.
func usrRevoke(t *testing.T, token, id string) reply { t.Helper(); return del(t, usrItem(id), token) }

// usrStoredRevoked is users.revoked_at of id ("" when NULL).
func usrStoredRevoked(t *testing.T, id string) string {
	t.Helper()

	return scalar(t, "SELECT revoked_at FROM users WHERE id = ?", id)
}

// usrAssertNoHandle fails when a response names the user handle in any spelling or
// encoding.
func usrAssertNoHandle(t *testing.T, what, body string, handles ...[]byte) {
	t.Helper()

	lower := strings.ToLower(body)
	for _, banned := range []string{"handle", "user_handle", "userhandle"} {
		if strings.Contains(lower, banned) {
			t.Errorf("%s mentions %q:\n%s", what, banned, body)
		}
	}

	for _, handle := range handles {
		for _, form := range []string{
			b64(handle), hex.EncodeToString(handle), strings.ToUpper(hex.EncodeToString(handle)), string(handle),
		} {
			if form != "" && strings.Contains(body, form) {
				t.Errorf("%s leaks the user handle as %q:\n%s", what, form, body)
			}
		}
	}
}

// ---- access ---------------------------------------------------------------------

// TestUserRoutesSpotCheckAccess: each route is 401 without a session and 403 for
// a non-admin (the full matrix is owned elsewhere). Nothing is revoked.
//
//nolint:paralleltest // shares one database
func TestUserRoutesSpotCheckAccess(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	seedUser(t, idUserB, roleMember)
	setRole(t, admin.userID, roleMember)

	routes := []struct {
		name         string
		method, path string
	}{
		{"list", http.MethodGet, pathUser},
		{"get", http.MethodGet, usrItem(idUserB)},
		{"revoke", http.MethodDelete, usrItem(idUserB)},
	}

	for _, rt := range routes {
		t.Run(rt.name+" signed out", func(t *testing.T) {
			send(t, request{method: rt.method, path: rt.path}).
				expect(t, rt.method+" "+rt.path, http.StatusUnauthorized, codeUnauthenticated)
		})

		t.Run(rt.name+" member", func(t *testing.T) {
			send(t, request{method: rt.method, path: rt.path, token: token}).
				expect(t, rt.method+" "+rt.path, http.StatusForbidden, codeForbidden)
		})
	}

	expectCount(t, "users WHERE revoked_at IS NOT NULL", "0")
}

// TestUserRoleSpellingsAreNotAdmin: only the exact role "admin" administers. The
// session of an account whose stored role differs in case, by whitespace or by a
// look-alike is a 403 on every route, and so is the removed e2e_member role.
//
//nolint:paralleltest // shares one database
func TestUserRoleSpellingsAreNotAdmin(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	roles := []string{
		"Admin", "ADMIN", "admin ", " admin", "admin\n", "admin\x00", "admin\u200b", "аdmin", // Cyrillic a
		"administrator", "root", "e2e_member", "member", "user", "e2e_none", "adm", "admin:admin", "default:admin",
	}

	for _, role := range roles {
		t.Run(fmt.Sprintf("%q", role), func(t *testing.T) {
			setRole(t, admin.userID, role)

			for _, rt := range []struct{ method, path string }{
				{http.MethodGet, pathUser}, {http.MethodGet, usrItem(admin.userID)},
				{http.MethodDelete, usrItem(admin.userID)}, {http.MethodGet, pathInvitation},
			} {
				send(t, request{method: rt.method, path: rt.path, token: token}).
					expect(t, rt.method+" "+rt.path+" as "+role, http.StatusForbidden, codeForbidden)
			}

			expectCount(t, "users WHERE revoked_at IS NOT NULL", "0")
		})
	}

	// Control: the exact spelling is an admin.
	setRole(t, admin.userID, roleAdmin)
	get(t, pathUser, token).expect(t, "GET /api/user as admin", http.StatusOK, "")
}

// ---- list and get --------------------------------------------------------------------

// TestUserListShape: the exact JSON an account is served as, in the exact order
// the store says (created_at DESC, id DESC), with the user handle nowhere, and
// the profile a JSON object.
//
//nolint:paralleltest // shares one database
func TestUserListShape(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	invitation := scalar(t, "SELECT id FROM invitations")

	handles := map[string][]byte{}

	rows := []struct {
		id      string
		created int64
		revoked any
	}{
		{idN("0c00", 1), 1000, nil}, {idN("0c00", 2), 1000, 5}, {idN("0c00", 3), 1000, nil},
		{idN("0c00", 0x10), 999, nil}, {idN("0c00", 0xf), 999, 0}, {idN("0c00", 4), 5, nil},
	}

	for _, r := range rows {
		handle := randomBytes(16)
		handles[r.id] = handle

		seedAccount(t, "INSERT INTO users (id, user_handle, role, invitation_id, profile, revoked_at, created_at) "+
			"VALUES (?, ?, 'e2e_none', ?, '{\"name\":\"seeded\"}', ?, ?)", r.id, handle, invitation, r.revoked, r.created)
	}

	got := get(t, pathUser, token)
	if got.status != http.StatusOK {
		t.Fatalf("GET = %d %s", got.status, got.body)
	}

	if ct := got.header.Get("Content-Type"); !strings.HasPrefix(ct, jsonType) {
		t.Errorf("Content-Type = %q, want %s", ct, jsonType)
	}

	allHandles := make([][]byte, 0, 1+len(handles))
	allHandles = append(allHandles, admin.handle)

	for _, h := range handles {
		allHandles = append(allHandles, h)
	}

	usrAssertNoHandle(t, "list", got.body, allHandles...)

	var top map[string]json.RawMessage

	usrDecode(t, got.body, &top)

	if len(top) != 1 || top["users"] == nil {
		t.Fatalf("members = %v, want only users", top)
	}

	var items []map[string]json.RawMessage

	usrDecode(t, string(top["users"]), &items)

	for _, item := range items {
		keys := make([]string, 0, len(item))
		for k := range item {
			keys = append(keys, k)
		}

		slices.Sort(keys)

		var id string

		usrDecode(t, string(item["id"]), &id)

		want := "createdAt,id,invitationId,profile,revokedAt,role,status"
		if string(item["revokedAt"]) == "" {
			want = "createdAt,id,invitationId,profile,role,status"
		}

		if strings.Join(keys, ",") != want {
			t.Errorf("%s members = %v, want %s", id, keys, want)
		}

		if !strings.HasPrefix(string(item["profile"]), "{") {
			t.Errorf("%s profile = %s, want a JSON object and not a string", id, item["profile"])
		}
	}

	// Order: created_at DESC then id DESC; the admin's own account is newest
	// (created now), then the seeded ones.
	var ids []string

	for _, view := range usrList(t, token) {
		if strings.HasPrefix(view.ID, "00000000-0000-7000-8000-0c00") {
			ids = append(ids, view.ID)
		}
	}

	want := []string{idN("0c00", 3), idN("0c00", 2), idN("0c00", 1), idN("0c00", 0x10), idN("0c00", 0xf), idN("0c00", 4)}
	if !slices.Equal(ids, want) {
		t.Errorf("order = %v\nwant    %v", ids, want)
	}

	if first := usrList(t, token)[0]; first.ID != admin.userID {
		t.Errorf("first = %s, want the admin %s (created now)", first.ID, admin.userID)
	}

	// Status is derived from revoked_at being set at all, including 0 and 5.
	byID := map[string]usrView{}
	for _, view := range usrList(t, token) {
		byID[view.ID] = view
	}

	for _, r := range rows {
		view := byID[r.id]
		wantStatus := usrActive

		if r.revoked != nil {
			wantStatus = usrRevoked

			if view.RevokedAt == nil || *view.RevokedAt != int64(r.revoked.(int)) { //nolint:forcetypeassert // seeded as int
				t.Errorf("%s revokedAt = %v, want %v", r.id, view.RevokedAt, r.revoked)
			}
		}

		if view.Status != wantStatus {
			t.Errorf("%s status = %s, want %s (revoked_at %v)", r.id, view.Status, wantStatus, r.revoked)
		}

		if view.InvitationID != invitation || view.Role != "e2e_none" || view.CreatedAt != r.created {
			t.Errorf("%s = %+v", r.id, view)
		}
	}
}

// TestUserGet: one account, its exact shape, 404 for an unknown id, a revoked
// account is still readable, and a malformed id is 400 before the session is read.
//
//nolint:paralleltest // shares one database
func TestUserGet(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	seedUser(t, idUserB, roleMember)
	seed(t, "UPDATE users SET revoked_at = 12345 WHERE id = ?", idUserB)

	t.Run("active admin", func(t *testing.T) {
		view := usrOne(t, token, admin.userID)
		if view.Role != roleAdmin || view.Status != usrActive || view.RevokedAt != nil ||
			string(view.Profile) != `{"name":"Admin","email":"`+testEmail+`"}` || view.InvitationID == "" {
			t.Errorf("view = %+v profile %s", view, view.Profile)
		}
	})

	t.Run("revoked account is readable", func(t *testing.T) {
		view := usrOne(t, token, idUserB)
		if view.Status != usrRevoked || view.RevokedAt == nil || *view.RevokedAt != 12345 ||
			string(view.Profile) != `{"name":"seeded"}` {
			t.Errorf("view = %+v profile %s", view, view.Profile)
		}
	})

	t.Run("one account matches the list entry", func(t *testing.T) {
		for _, listed := range usrList(t, token) {
			one := usrOne(t, token, listed.ID)
			if one.ID != listed.ID || one.Role != listed.Role || one.Status != listed.Status ||
				string(one.Profile) != string(listed.Profile) || one.CreatedAt != listed.CreatedAt {
				t.Errorf("get %+v differs from list %+v", one, listed)
			}
		}
	})

	t.Run("no route answers with the user handle", func(t *testing.T) {
		seedAgent(t, idAgentA, idUserB, "bot")

		replies := map[string]reply{
			"get":            get(t, usrItem(admin.userID), token),
			"get revoked":    get(t, usrItem(idUserB), token),
			"list":           get(t, pathUser, token),
			"get unknown":    get(t, usrItem(idMissing), token),
			"revoke":         usrRevoke(t, token, idUserB),
			"revoke again":   usrRevoke(t, token, idUserB),
			"revoke last":    usrRevoke(t, token, admin.userID),
			"revoke unknown": usrRevoke(t, token, idMissing),
			"bad id":         get(t, usrItem("nope"), token),
			"signed out":     get(t, pathUser, ""),
		}

		seedHandle, err := hex.DecodeString(scalar(t, "SELECT hex(user_handle) FROM users WHERE id = ?", idUserB))
		if err != nil {
			t.Fatalf("handle: %v", err)
		}

		for what, got := range replies {
			usrAssertNoHandle(t, what, got.body, admin.handle, seedHandle)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		get(t, usrItem(idMissing), token).expect(t, "GET unknown", http.StatusNotFound, usrCodeNotFound)
	})

	for _, id := range []string{"nope", "0", strings.ToUpper(idUserB), idUserB + "x", idUserB[:35], "%20", strings.Repeat("a", 3000)} {
		t.Run("bad id "+id[:min(len(id), 12)], func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodDelete} {
				send(t, request{method: method, path: usrItem(id), token: token}).
					expect(t, method+" bad id", http.StatusBadRequest, codeInvalidID)
				send(t, request{method: method, path: usrItem(id)}).
					expect(t, method+" bad id signed out", http.StatusUnauthorized, codeUnauthenticated)
			}
		})
	}

	t.Run("routing", func(t *testing.T) {
		send(t, request{method: http.MethodPatch, path: usrItem(idUserB), body: []byte(`{}`), token: token}).
			expect(t, "PATCH item", http.StatusMethodNotAllowed, codeMethodNotAllow)
		send(t, request{method: http.MethodPost, path: pathUser, body: []byte(`{}`), token: token}).
			expect(t, "POST collection", http.StatusMethodNotAllowed, codeMethodNotAllow)
		send(t, request{method: http.MethodDelete, path: pathUser, token: token}).
			expect(t, "DELETE collection", http.StatusMethodNotAllowed, codeMethodNotAllow)
		get(t, usrItem(idUserB)+"/x", token).expect(t, "GET extra segment", http.StatusNotFound, "")
	})

	t.Run("a body on a bodiless route is bounded", func(t *testing.T) {
		got := send(t, request{method: http.MethodDelete, path: usrItem(idMissing), token: token,
			body: []byte(strings.Repeat(" ", 2000))})
		got.expect(t, "DELETE 2000 byte body", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
		expectCount(t, "users WHERE revoked_at IS NOT NULL", "1")
	})
}

// TestUserProfileServedAsObject: a profile registered through the Worker is
// served as a JSON object equal to {"name": ..., "email": ...}, for normal names and for the
// worst case a name can reach: 128 bytes of '<', which JSON-escapes six-fold.
//
//nolint:paralleltest // shares one database
func TestUserProfileServedAsObject(t *testing.T) {
	names := map[string]string{
		"plain":         "Ada",
		"unicode":       "Ada \u00e9\u4e16\u754c",
		"emoji":         "\U0001f600\U0001f468\U0001f469",
		"quote":         `He said "hi"`,
		"backslash":     `a\b`,
		"html":          `<b>&</b>`,
		"128 lt":        strings.Repeat("<", 128),
		"128 amp":       strings.Repeat("&", 128),
		"128 quote":     strings.Repeat(`"`, 128),
		"128 backslash": strings.Repeat(`\`, 128),
		"u2028":         "a\u2028b",
		"128 bytes":     strings.Repeat("a", 128),
	}

	for name, value := range names {
		t.Run(name, func(t *testing.T) {
			reset(t)
			get(t, pathFirstRun, "").expect(t, "first run", http.StatusOK, "")

			pk := registerWith(t, value)
			token := login(t, pk)

			stored := scalar(t, "SELECT profile FROM users WHERE id = ?", pk.userID)

			// The stored text, and what the Worker serves, both decode to the name.
			var want, fromDB struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			}

			usrDecode(t, stored, &fromDB)

			if fromDB.Name != value || fromDB.Email != testEmail {
				t.Fatalf("stored profile %s does not hold the name %q and the email %q", stored, value, testEmail)
			}

			for what, body := range map[string]string{
				"list": get(t, pathUser, token).body, "get": get(t, usrItem(pk.userID), token).body,
			} {
				var raw struct {
					Profile json.RawMessage `json:"profile"`
					Users   []struct {
						Profile json.RawMessage `json:"profile"`
					} `json:"users"`
				}

				err := json.Unmarshal([]byte(body), &raw)
				if err != nil {
					t.Fatalf("%s: response is not valid JSON: %v\n%s", what, err, body)
				}

				profile := raw.Profile
				if what == "list" {
					profile = raw.Users[0].Profile
				}

				if len(profile) == 0 || profile[0] != '{' {
					t.Fatalf("%s: profile = %s, want a JSON object and not an escaped string", what, profile)
				}

				usrDecode(t, string(profile), &want)

				if want.Name != value || want.Email != testEmail {
					t.Errorf("%s: profile = %q, %q, want %q, %q (profile %s)", what, want.Name, want.Email, value, testEmail, profile)
				}
			}
		})
	}
}

// TestUserProfileDefects: stored profiles that SQLite's json_valid accepts but are
// not the JSON object the response promises. The handler logs
// user_profile_invalid and serves the account with {}: the request succeeds, the
// list still shows every account, and a revoke that was applied is still
// reported as done. Profiles that are valid objects (whitespace, nesting,
// duplicate keys) are served as stored.
//
// Invalid UTF-8 is a different case: the D1 driver goes through JS strings, so
// the bytes are already replaced by U+FFFD when Go sees them. The profile that
// reaches the client is then valid text, and is served with the replacement
// character rather than refused. The Go check cannot see that, and does not need
// to: what is served is valid JSON.
//
//nolint:paralleltest // shares one database
func TestUserProfileDefects(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	invitation := scalar(t, "SELECT id FROM invitations")

	cases := []struct {
		name    string
		profile any
		ok      bool
		// served is the profile expected in a 200. ok is false when the stored
		// profile is not an object: it is then served as {}.
		served string
	}{
		{"empty object", `{}`, true, `{}`},
		{"whitespace around is dropped", " \n{ \"a\" : 1 }\t\n", true, `{"a":1}`},
		{"nested", `{"a":[1,{"b":null}],"c":{"d":"e"}}`, true, `{"a":[1,{"b":null}],"c":{"d":"e"}}`},
		{"duplicate keys are valid JSON", `{"a":1,"a":2}`, true, `{"a":1,"a":2}`},
		{"lone surrogate escape", `{"name":"\ud800"}`, true, `{"name":"\ud800"}`},
		{"escaped NUL", `{"name":"\u0000"}`, true, `{"name":"\u0000"}`},
		{"array", `[1]`, false, ""},
		{"string", `"x"`, false, ""},
		{"number", `1`, false, ""},
		{"null", `null`, false, ""},
		{"true", `true`, false, ""},
		{"leading whitespace then array", ` [1]`, false, ""},
		{"invalid UTF-8 inside a string", "{\"name\":\"\xff\"}", true, "{\"name\":\"\ufffd\"}"},
		{"2 byte overlong", "{\"name\":\"\xc0\xaf\"}", true, "{\"name\":\"\ufffd\ufffd\"}"},
		{"BOM", "\ufeff{}", false, ""},
		{"trailing text", `{} x`, false, ""},
	}

	for i, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			id := idN("0c20", i+1)

			// A Go string with invalid UTF-8 is bound as TEXT with those bytes.
			deleteAccount(t, id)

			refusedBySchema := refused(t, "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at, org_id) "+
				"VALUES (?, randomblob(16), 'e2e_none', ?, ?, 1, (SELECT id FROM orgs LIMIT 1))", id, invitation, tt.profile)
			if refusedBySchema {
				t.Skipf("the schema's json_valid CHECK refuses %q already; the handler's check is unreachable for it", tt.profile)
			}

			usrSeedProfileFor(t, id, invitation, tt.profile)

			one := get(t, usrItem(id), token)
			list := get(t, pathUser, token)

			if tt.ok {
				one.expect(t, "GET "+tt.name, http.StatusOK, "")
				list.expect(t, "list with "+tt.name, http.StatusOK, "")

				var view usrView

				usrDecode(t, one.body, &view)

				if string(view.Profile) != tt.served {
					t.Errorf("profile served = %s, want %s", view.Profile, tt.served)
				}

				return
			}

			// Not an object: logged, and served as {} without failing the request.
			one.expect(t, "GET "+tt.name, http.StatusOK, "")
			list.expect(t, "list with "+tt.name, http.StatusOK, "")

			var view usrView

			usrDecode(t, one.body, &view)

			if string(view.Profile) != "{}" {
				t.Errorf("profile served = %s, want {}", view.Profile)
			}

			// The list still holds this account (with {}) and every other one.
			if !strings.Contains(list.body, id) || !strings.Contains(list.body, admin.userID) {
				t.Errorf("the list lost an account: %s", list.body)
			}

			get(t, usrItem(admin.userID), token).expect(t, "GET the admin", http.StatusOK, "")
			deleteAccount(t, id)
		})
	}

	get(t, pathUser, token).expect(t, "list after cleanup", http.StatusOK, "")
}

func usrSeedProfileFor(t *testing.T, id, invitation string, profile any) {
	t.Helper()

	seedAccount(t, "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) "+
		"VALUES (?, randomblob(16), 'e2e_none', ?, ?, 1)", id, invitation, profile)
}

// TestUserListLarge: 300 accounts are listed in full in a sane time. The list is
// unpaged (documented).
//
//nolint:paralleltest // shares one database
func TestUserListLarge(t *testing.T) {
	token := login(t, newAdmin(t))

	const n = 300

	invitation := scalar(t, "SELECT id FROM invitations")

	for i := range n {
		seedAccount(t, "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) "+
			"VALUES (?, randomblob(16), 'e2e_none', ?, ?, ?)", idN("0c30", i+1), invitation,
			`{"name":"`+strings.Repeat("<", 128)+`"}`, 1000+i)
	}

	started := time.Now()
	got := get(t, pathUser, token)
	elapsed := time.Since(started)

	got.expect(t, "GET large list", http.StatusOK, "")

	var out struct {
		Users []usrView `json:"users"`
	}

	usrDecode(t, got.body, &out)

	if len(out.Users) != n+1 {
		t.Errorf("listed %d, want %d", len(out.Users), n+1)
	}

	t.Logf("list of %d accounts: %d bytes in %s (unpaged)", n+1, len(got.body), elapsed)

	if elapsed > 5*time.Second {
		t.Errorf("list took %s, want under 5s", elapsed)
	}
}

// ---- revoke --------------------------------------------------------------------------

// usrKeys are the secrets and the agent usrSeedKeys gives a user: a session and
// two keys of one agent, with the agent, all with fresh ids from one family.
type usrKeys struct {
	session, key, otherKey string
	agent                  string
}

func usrSeedKeys(t *testing.T, family, user string) usrKeys {
	t.Helper()

	out := usrKeys{
		session: idN(family, 1), key: idN(family, 2), otherKey: idN(family, 3), agent: idN(family, 4),
	}

	seedSession(t, out.session, user)
	seedAgent(t, out.agent, user, "bot")
	seedAPIKey(t, out.key, user, out.agent)
	seedAPIKey(t, out.otherKey, user, out.agent)

	return out
}

// usrRevokedKeys is the number of revoked secrets (sessions and keys) of user.
func usrRevokedKeys(t *testing.T, user string) string {
	t.Helper()

	return count(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NOT NULL", user)
}

// TestUserRevoke: revoking a member answers 200 with the revoked view, revokes the
// account, every key it has (sessions and agent keys) and every agent in the same
// write and touches nobody else, never deletes a row, and a second revoke keeps
// the first time even after seconds pass.
//
//nolint:paralleltest // shares one database
func TestUserRevoke(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	seedUser(t, idUserB, roleMember)
	seedUser(t, idUserC, roleMember)

	victim := usrSeedKeys(t, "0c40", idUserB)
	bystander := usrSeedKeys(t, "0c41", idUserC)

	// Expired and pre-revoked keys: a revoke keeps an earlier revocation and an
	// already-due time, and brings a later one forward.
	seed(t, "UPDATE secrets SET revoked_at = 100 WHERE id = ?", victim.otherKey)
	seed(t, "UPDATE secrets SET revoked_at = ? WHERE id = ?", invUnixFar, victim.key)

	adminKeysBefore := count(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NULL", admin.userID)
	usersBefore, credsBefore := count(t, "users"), count(t, "credentials")

	before := time.Now().Unix()
	first := usrRevoke(t, token, idUserB)
	after := time.Now().Unix()

	first.expect(t, "DELETE", http.StatusOK, "")

	var view usrView

	usrDecode(t, first.body, &view)

	if view.ID != idUserB || view.Status != usrRevoked || view.RevokedAt == nil || *view.RevokedAt < before ||
		*view.RevokedAt > after || view.Role != roleMember || string(view.Profile) != `{"name":"seeded"}` {
		t.Fatalf("revoke body = %+v, want revoked at now (%d..%d)", view, before, after)
	}

	revokedAt := strconv.FormatInt(*view.RevokedAt, 10)

	if stored := usrStoredRevoked(t, idUserB); stored != revokedAt {
		t.Errorf("stored revoked_at = %s, response %s", stored, revokedAt)
	}

	// Keys: all of the victim's are revoked; the pre-revoked one keeps 100, the
	// far-future one is brought forward to now.
	expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NULL", "0", idUserB)

	if got := scalar(t, "SELECT revoked_at FROM secrets WHERE id = ?", victim.otherKey); got != "100" {
		t.Errorf("earlier key revocation = %s, want 100 kept", got)
	}

	if got := scalar(t, "SELECT revoked_at FROM secrets WHERE id = ?", victim.key); got != revokedAt {
		t.Errorf("far-future key revocation = %s, want brought forward to %s", got, revokedAt)
	}

	if got := scalar(t, "SELECT revoked_at FROM secrets WHERE id = ?", victim.session); got != revokedAt {
		t.Errorf("session revoked_at = %s, want %s", got, revokedAt)
	}

	expectCount(t, "agents WHERE user_id = ? AND revoked_at = ?", "1", idUserB, revokedAt)

	// Nobody else is touched.
	expectCount(t, "users WHERE revoked_at IS NOT NULL", "1")
	expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NULL", "3", idUserC)
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "1", idUserC)
	expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NULL", adminKeysBefore, admin.userID)

	if usrRevokedKeys(t, idUserC) != "0" || bystander.agent == "" {
		t.Errorf("a bystander's keys were revoked")
	}

	// Never deletes.
	expectCount(t, "users", usersBefore)
	expectCount(t, "credentials", credsBefore)

	// Idempotent, keeping the first time after seconds pass.
	time.Sleep(2100 * time.Millisecond)

	second := usrRevoke(t, token, idUserB)
	second.expect(t, "second DELETE", http.StatusOK, "")

	var again usrView

	usrDecode(t, second.body, &again)

	if again.RevokedAt == nil || *again.RevokedAt != *view.RevokedAt || again.Status != usrRevoked {
		t.Errorf("second revoke = %+v, want the original time %s", again, revokedAt)
	}

	if stored := usrStoredRevoked(t, idUserB); stored != revokedAt {
		t.Errorf("stored revoked_at moved to %s, want %s", stored, revokedAt)
	}

	// The second revoke does not touch keys or agents again.
	if got := scalar(t, "SELECT revoked_at FROM secrets WHERE id = ?", victim.session); got != revokedAt {
		t.Errorf("session revoked_at moved to %s, want %s", got, revokedAt)
	}

	// A revoked account is still readable and listed, as revoked.
	if one := usrOne(t, token, idUserB); one.Status != usrRevoked || *one.RevokedAt != *view.RevokedAt {
		t.Errorf("get after revoke = %+v", one)
	}

	usrRevoke(t, token, idMissing).expect(t, "DELETE unknown", http.StatusNotFound, usrCodeNotFound)
}

// TestUserRevokeLastAdminGuard: the only active admin cannot be revoked (409,
// nothing changed, including their keys and agents), a second admin can, revoked
// admins and active non-admins do not count as "another admin", and the removed
// e2e_member role is not an admin.
//
//nolint:paralleltest // shares one database
func TestUserRevokeLastAdminGuard(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	seedSession(t, idN("0c60", 1), admin.userID)
	seedAgent(t, idN("0c60", 2), admin.userID, "bot")
	seedAPIKey(t, idN("0c60", 3), admin.userID, idN("0c60", 2))

	unchanged := func(t *testing.T, step string) {
		t.Helper()

		expectCount(t, "users WHERE id = ? AND revoked_at IS NOT NULL", "0", admin.userID)
		expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NOT NULL", "0", admin.userID)
		expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NOT NULL", "0", admin.userID)

		if got := get(t, pathSession, token); got.status != http.StatusOK {
			t.Errorf("%s: session = %d %s, want it alive", step, got.status, got.body)
		}
	}

	steps := []struct {
		name  string
		setup func()
	}{
		{"the only admin", func() {}},
		{"with an active member beside", func() { seedUser(t, idUserB, roleMember) }},
		{"with the removed e2e_member role beside", func() { seedUser(t, idUserC, "e2e_member") }},
		{"with look-alike admin roles beside", func() {
			for i, role := range []string{"Admin", "ADMIN", "admin ", " admin", "administrator", "e2e_none"} {
				seedUser(t, idN("0c61", i+1), role)
			}
		}},
		{"with a revoked admin beside", func() {
			seedUser(t, idN("0c62", 1), roleAdmin)
			seed(t, "UPDATE users SET revoked_at = 1 WHERE id = ?", idN("0c62", 1))
		}},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			step.setup()

			usrRevoke(t, token, admin.userID).expect(t, "DELETE the only active admin", http.StatusConflict, usrCodeLastAdmin)
			unchanged(t, step.name)
		})
	}

	// The refusal body carries no account detail.
	got := usrRevoke(t, token, admin.userID)
	if strings.Contains(got.body, admin.userID) {
		t.Errorf("refusal names the account: %s", got.body)
	}

	t.Run("a second active admin may be revoked", func(t *testing.T) {
		seedUser(t, idN("0c63", 1), roleAdmin)
		seedSession(t, idN("0c63", 2), idN("0c63", 1))

		usrRevoke(t, token, idN("0c63", 1)).expect(t, "DELETE the second admin", http.StatusOK, "")
		expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NOT NULL", "1", idN("0c63", 1))

		// After which the first is the last again.
		usrRevoke(t, token, admin.userID).expect(t, "DELETE the last admin again", http.StatusConflict, usrCodeLastAdmin)
		unchanged(t, "after revoking the second admin")
	})

	t.Run("a second admin makes self revoke possible", func(t *testing.T) {
		other := idN("0c64", 1)

		seedUser(t, other, roleAdmin)

		usrRevoke(t, token, admin.userID).expect(t, "DELETE self with another admin", http.StatusOK, "")
		expectCount(t, "users WHERE id = ? AND revoked_at IS NOT NULL", "1", admin.userID)
		expectCount(t, "users WHERE id = ? AND revoked_at IS NULL", "1", other)

		// The other admin is now the last active admin.
		expectCount(t, "users WHERE role = 'admin' AND revoked_at IS NULL", "1")
	})
}

// ---- interleavings ----------------------------------------------------------------------

// usrRace runs n calls together, released by one channel.
func usrRace(n int, call func(i int) reply) []reply {
	replies := make([]reply, n)
	start := make(chan struct{})

	var wg sync.WaitGroup

	for i := range n {
		wg.Go(func() {
			<-start

			replies[i] = call(i)
		})
	}

	close(start)
	wg.Wait()

	return replies
}

// usrStatuses summarises replies for t.Logf.
func usrStatuses(replies []reply) map[string]int {
	out := map[string]int{}

	for _, r := range replies {
		key := strconv.Itoa(r.status)
		if c := r.errorCode(); c != "" {
			key += " " + c
		}

		out[key]++
	}

	return out
}

// TestUserConcurrentRevokesOfOneMember: 16 DELETEs of one member at once are all
// 200, report one revokedAt (the stored one), and revoke the member's keys and
// agent exactly once.
//
//nolint:paralleltest // shares one database
func TestUserConcurrentRevokesOfOneMember(t *testing.T) {
	token := login(t, newAdmin(t))

	for round := range 4 {
		seed(t, "DELETE FROM api_keys WHERE user_id = ?", idUserB)
		seed(t, "DELETE FROM sessions WHERE user_id = ?", idUserB)
		seed(t, "DELETE FROM agents WHERE user_id = ?", idUserB)
		deleteAccount(t, idUserB)
		seedUser(t, idUserB, roleMember)
		usrSeedKeys(t, "0c80", idUserB)

		replies := usrRace(16, func(int) reply { return usrRevoke(t, token, idUserB) })

		t.Logf("round %d: %v", round, usrStatuses(replies))

		stored := usrStoredRevoked(t, idUserB)

		for _, r := range replies {
			if r.status != http.StatusOK {
				t.Errorf("DELETE = %d %s, want 200", r.status, r.body)

				continue
			}

			if !strings.Contains(r.body, `"revokedAt":`+stored) {
				t.Errorf("response %s reports a time other than the stored %s", r.body, stored)
			}
		}

		expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at = ?", "3", idUserB, stored)
		expectCount(t, "agents WHERE user_id = ? AND revoked_at = ?", "1", idUserB, stored)
	}
}

// TestUserRevokeKeepsTheInvitationUseCount: revoking an account does not give its
// invitation a use back: the account is the redemption, and a revoked account
// still is one (docs/invitations_design.md). The invitation's list entry shows
// the same uses before and after, and a cap equal to the uses stays exhausted.
//
//nolint:paralleltest // shares one database
func TestUserRevokeKeepsTheInvitationUseCount(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	invSeedAt(t, idInvitationA, 2, 1000, nil, nil)
	seedAccount(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) "+
		"VALUES (?, randomblob(16), 'e2e_none', ?, 1000)", idUserB, idInvitationA)
	seedAccount(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) "+
		"VALUES (?, randomblob(16), 'e2e_none', ?, 1000)", idUserC, idInvitationA)

	before := invFind(t, token, idInvitationA)
	if before.Uses != 2 || before.Status != invStatusExhausted {
		t.Fatalf("before = %+v, want 2 uses, exhausted", before)
	}

	usrRevoke(t, token, idUserB).expect(t, "revoke an account of the invitation", http.StatusOK, "")

	after := invFind(t, token, idInvitationA)
	if after.Uses != 2 || after.Status != invStatusExhausted {
		t.Errorf("after revoking an account = %+v, want the same 2 uses, still exhausted", after)
	}

	// The cap cannot be lowered below the accounts made, revoked ones included.
	patch(t, invItem(idInvitationA), []byte(`{"numInvites":1}`), token).
		expect(t, "PATCH below uses", http.StatusConflict, invCodeBelowUses)
}
