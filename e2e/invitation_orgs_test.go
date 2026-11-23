//go:build e2e

//nolint:goconst,funlen,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// invitation_orgs_test.go holds what the organization of an account does against
// the real TinyGo Worker and the real D1/SQLite (docs/orgs_design.md, principle
// 2; docs/invitations_design.md): an admin's create may name an organization
// with orgId and orgRole, which is written in the invitation's own batch only if
// the organization is standard at that write; every registration through such
// an invitation joins that organization, as an administrator of it too when the
// role says so; and one through an invitation that names none gets an
// organization of its own, which it administers. Registration never fails
// because of the organization, and everything it writes (the account, its
// organization, its administrator row, its passkey) stands or falls together.
//
// What only the real database can show, and so is here and not in the unit
// tests: that a refused organization rolls the invitation's secret back with it
// (the NOT NULL subselect of the organization), that the registration batch
// joins or creates the organization, and makes an administrator, in the one
// write that creates the account, and that a failure at any statement of that
// batch (a trigger plays it at each, as TestLoginRacingAStateChange does for
// login) leaves nothing behind: no account, no organization, no administrator
// row, and the invitation still redeemable.
//
// REVIEW.md categories covered: permission confusion (a non-admin, an
// organization's own administrator, no session), input edge cases and
// type/bound confusion (every value of the two fields), too large payloads,
// interleaving (multi-use registrations racing each other), and atomicity.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Families of ids of this file's tests.
const (
	famInvOrg = "0fc0"

	invOrgCodeNotFound  = "org_not_found"
	invOrgCodeNoID      = "missing_org_id"
	invOrgCodeNoRole    = "missing_org_role"
	invOrgCodeInvalidID = "invalid_id"
	invOrgCodeRole      = "invalid_org_role"

	invOrgRaceTrigger = "e2e_inv_org_race"
)

// invOrgView is an invitation as it is served with the organization it names,
// which is absent when it names none.
type invOrgView struct {
	invView

	OrgID   *string `json:"orgId"`
	OrgRole *string `json:"orgRole"`
}

// invOrgCreated is the response of a create.
type invOrgCreated struct {
	invOrgView

	Code string `json:"code"`
}

// invOrgWorld is a fresh deployment with its first administrator, a second
// account (idUserB, who creates the organizations), and the administrator's
// session token.
func invOrgWorld(t *testing.T) string {
	t.Helper()

	token := login(t, newAdmin(t))

	seedUser(t, idUserB, roleMember)

	return token
}

// invOrgBody is a create body of numInvites accounts of the given type, with
// the organization fields when they are not "".
func invOrgBody(t *testing.T, invitationType string, numInvites int, org, role string) []byte {
	t.Helper()

	body := map[string]any{"type": invitationType, "numInvites": numInvites}

	if org != "" {
		body["orgId"] = org
	}

	if role != "" {
		body["orgRole"] = role
	}

	return mustJSON(t, body)
}

// invOrgCreate creates an invitation and requires it to succeed.
func invOrgCreate(t *testing.T, token, invitationType string, numInvites int, org, role string) invOrgCreated {
	t.Helper()

	got := post(t, pathInvitation, invOrgBody(t, invitationType, numInvites, org, role), token)
	got.expect(t, "create naming an organization", http.StatusCreated, "")

	var created invOrgCreated

	invDecode(t, got.body, &created)

	return created
}

// invOrgList reads the list with the organizations the invitations name.
func invOrgList(t *testing.T, token string) []invOrgView {
	t.Helper()

	got := get(t, pathInvitation, token)
	got.expect(t, "list", http.StatusOK, "")

	var out struct {
		Invitations []invOrgView `json:"invitations"`
	}

	invDecode(t, got.body, &out)

	return out.Invitations
}

// invOrgFind returns the listed invitation with id.
func invOrgFind(t *testing.T, token, id string) invOrgView {
	t.Helper()

	for _, view := range invOrgList(t, token) {
		if view.ID == id {
			return view
		}
	}

	t.Fatalf("invitation %s is not listed", id)

	return invOrgView{}
}

// expectOrg fails the test unless the invitation shows exactly this
// organization and role, and none when org is "".
func (v invOrgView) expectOrg(t *testing.T, what, org, role string) {
	t.Helper()

	switch {
	case org == "":
		if v.OrgID != nil || v.OrgRole != nil {
			t.Errorf("%s shows the organization %v %v, want none", what, v.OrgID, v.OrgRole)
		}
	case v.OrgID == nil || *v.OrgID != org || v.OrgRole == nil || *v.OrgRole != role:
		t.Errorf("%s shows the organization %v %v, want %s %s", what, v.OrgID, v.OrgRole, org, role)
	}
}

// invOrgExpectConsistent holds the invariants of organizations that no
// registration may break: whoever administers an organization belongs to it, and
// every organization that its creator belongs to has the creator among its
// administrators (which is what an account's own organization is).
func invOrgExpectConsistent(t *testing.T) {
	t.Helper()

	expectCount(t, "org_admins WHERE user_id NOT IN (SELECT id FROM users WHERE org_id = org_admins.org_id)", "0")
	expectCount(t, "orgs WHERE kind = 'standard' AND id <> created_by "+
		"AND created_by IN (SELECT id FROM users WHERE org_id = orgs.id) "+
		"AND NOT EXISTS (SELECT 1 FROM org_admins a WHERE a.org_id = orgs.id AND a.user_id = orgs.created_by)", "0")
	expectNoOrphanSecrets(t)
}

// invOrgMember is the id of the organization a user belongs to.
func invOrgMember(t *testing.T, user string) string {
	t.Helper()

	return scalar(t, "SELECT org_id FROM users WHERE id = ?", user)
}

// ---- creating an invitation that names an organization ------------------------

// TestInvitationOrgIsStoredAndShown: an organization of each role is written
// with the invitation, shown by the create and by every later response that
// shows the invitation (the list, an update and a revoke). An invitation that
// names none shows neither field.
//
//nolint:paralleltest // shares one database
func TestInvitationOrgIsStoredAndShown(t *testing.T) {
	for _, role := range []string{"member", "admin"} {
		t.Run(role, func(t *testing.T) {
			token := invOrgWorld(t)
			org := idN(famInvOrg, 1)

			seedOrg(t, org)

			plain := invOrgCreate(t, token, "member", 2, "", "")
			created := invOrgCreate(t, token, "member", 2, org, role)

			created.expectOrg(t, "create", org, role)
			plain.expectOrg(t, "create naming none", "", "")

			expectCount(t, "invitation_orgs", "1")
			expectCount(t, "invitation_orgs WHERE invitation_id = ? AND org_id = ? AND role = ? AND kind = 'standard'",
				"1", created.ID, org, role)
			expectCount(t, "invitations", "3") // the first run's, and these two

			// It is shown by the list, beside an invitation that names none.
			invOrgFind(t, token, created.ID).expectOrg(t, "list", org, role)
			invOrgFind(t, token, plain.ID).expectOrg(t, "list of one naming none", "", "")

			// An update and a revoke show it too, and neither touches it.
			upd := patch(t, invItem(created.ID), []byte(`{"numInvites":5}`), token)
			upd.expect(t, "update", http.StatusOK, "")

			var updated invOrgView

			invDecode(t, upd.body, &updated)
			updated.expectOrg(t, "update", org, role)

			rev := del(t, invItem(created.ID), token)
			rev.expect(t, "revoke", http.StatusOK, "")

			var revoked invOrgView

			invDecode(t, rev.body, &revoked)
			revoked.expectOrg(t, "revoke", org, role)

			invOrgFind(t, token, created.ID).expectOrg(t, "list after the revoke", org, role)
			expectCount(t, "invitation_orgs", "1")
		})
	}
}

// TestInvitationOrgTwoInvitationsOneOrg: several invitations may name the same
// organization, each with a row of its own (the key is the invitation).
//
//nolint:paralleltest // shares one database
func TestInvitationOrgTwoInvitationsOneOrg(t *testing.T) {
	token := invOrgWorld(t)
	org := idN(famInvOrg, 1)

	seedOrg(t, org)

	first := invOrgCreate(t, token, "member", 1, org, "member")
	second := invOrgCreate(t, token, "member", 1, org, "admin")

	expectCount(t, "invitation_orgs WHERE org_id = ?", "2", org)

	invOrgFind(t, token, first.ID).expectOrg(t, "first", org, "member")
	invOrgFind(t, token, second.ID).expectOrg(t, "second", org, "admin")
}

// TestInvitationOrgRefusals: every refusal writes nothing at all. An
// organization that cannot be named (none, a sandbox) is a 404 that rolls the
// whole batch back, the invitation's secret included, which is what the NOT NULL
// organization is for; a value that is not valid is a 400 from its parser; an
// oversized body is refused before it is read. Each 404 is the same whatever the
// cause, and shows no code.
//
//nolint:paralleltest // shares one database
func TestInvitationOrgRefusals(t *testing.T) {
	token := invOrgWorld(t)

	active, sandbox := idN(famInvOrg, 1), idN(famInvOrg, 4)

	seedOrg(t, active)
	seedSandbox(t, sandbox, idUserB)

	named := func(org, role string) string {
		return `{"type":"member","numInvites":1,"orgId":` + org + `,"orgRole":` + role + `}`
	}

	tests := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		// What cannot be named.
		{"an organization that does not exist", named(`"`+idMissing+`"`, `"member"`), http.StatusNotFound, invOrgCodeNotFound},
		{"an organization that does not exist, as an admin", named(`"`+idMissing+`"`, `"admin"`), http.StatusNotFound, invOrgCodeNotFound},
		{"a sandbox", named(`"`+sandbox+`"`, `"member"`), http.StatusNotFound, invOrgCodeNotFound},
		{"a sandbox, as an admin", named(`"`+sandbox+`"`, `"admin"`), http.StatusNotFound, invOrgCodeNotFound},

		// One field without the other.
		{"a role with no organization", `{"type":"member","numInvites":1,"orgRole":"member"}`, http.StatusBadRequest, invOrgCodeNoID},
		{"a role with a null organization", named(`null`, `"member"`), http.StatusBadRequest, invOrgCodeNoID},
		{"an organization with no role", `{"type":"member","numInvites":1,"orgId":"` + active + `"}`, http.StatusBadRequest, invOrgCodeNoRole},
		{"an organization with a null role", named(`"`+active+`"`, `null`), http.StatusBadRequest, invOrgCodeNoRole},

		// The organization's id.
		{"an empty organization", named(`""`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id in upper case", named(`"`+strings.ToUpper(active)+`"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id with a trailing space", named(`"`+active+` "`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id of 35 characters", named(`"`+active[1:]+`"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id of 37 characters", named(`"`+active+`0"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id with a NUL", named(`"`+active[:35]+`\u0000"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id of 3000 characters", named(`"`+strings.Repeat("a", 3000)+`"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id that is a number", named(`1`, `"member"`), http.StatusBadRequest, "invalid_field_type"},
		{"an id that is an object", named(`{"id":"`+active+`"}`, `"member"`), http.StatusBadRequest, "invalid_field_type"},

		// The role.
		{"an empty role", named(`"`+active+`"`, `""`), http.StatusBadRequest, invOrgCodeRole},
		{"a role in another case", named(`"`+active+`"`, `"Admin"`), http.StatusBadRequest, invOrgCodeRole},
		{"a role with a trailing space", named(`"`+active+`"`, `"admin "`), http.StatusBadRequest, invOrgCodeRole},
		{"a role with a NUL", named(`"`+active+`"`, `"admin\u0000"`), http.StatusBadRequest, invOrgCodeRole},
		{"a role nobody has", named(`"`+active+`"`, `"owner"`), http.StatusBadRequest, invOrgCodeRole},
		{"a role of 3000 characters", named(`"`+active+`"`, `"`+strings.Repeat("a", 3000)+`"`), http.StatusBadRequest, invOrgCodeRole},
		{"a role that is a number", named(`"`+active+`"`, `1`), http.StatusBadRequest, "invalid_field_type"},

		// Shapes.
		{"the organization as an object", `{"type":"member","numInvites":1,"org":{"id":"` + active + `","role":"member"}}`, http.StatusBadRequest, codeUnknownField},
		{"the organization twice", `{"type":"member","numInvites":1,"orgId":"` + active + `","orgId":"` + active + `","orgRole":"member"}`, http.StatusBadRequest, "duplicate_field"},

		// Too large: refused before anything is read.
		{"an organization over the body limit", named(`"`+strings.Repeat("a", 5000)+`"`, `"member"`), http.StatusRequestEntityTooLarge, codeBodyTooLarge},
		{"a role over the body limit", named(`"`+active+`"`, `"`+strings.Repeat("a", 5000)+`"`), http.StatusRequestEntityTooLarge, codeBodyTooLarge},
	}

	// The first run's invitation and its secret are all there is.
	invitations, secrets := count(t, "invitations"), count(t, "secrets")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := post(t, pathInvitation, []byte(tt.body), token)
			got.expect(t, "create", tt.status, tt.code)

			if strings.Contains(got.body, "susu_inv_") {
				t.Errorf("a refused create shows a code: %s", got.body)
			}

			// Nothing at all was written: not the organization, not the
			// invitation, and not the secret that was written before the
			// organization was refused.
			expectCount(t, "invitations", invitations)
			expectCount(t, "secrets", secrets)
			expectCount(t, "invitation_orgs", "0")
		})
	}

	t.Run("the 404 is the same body for every cause", func(t *testing.T) {
		var first string

		for _, org := range []string{idMissing, sandbox} {
			got := post(t, pathInvitation, invOrgBody(t, "member", 1, org, "member"), token)
			got.expect(t, "create", http.StatusNotFound, invOrgCodeNotFound)

			if first == "" {
				first = got.body
			}

			if got.body != first {
				t.Errorf("the refusal differs by cause: %s vs %s", got.body, first)
			}
		}
	})

	t.Run("a control: the standard organization is named", func(t *testing.T) {
		invOrgCreate(t, token, "member", 1, active, "member").expectOrg(t, "create", active, "member")
		expectCount(t, "invitation_orgs", "1")
		expectCount(t, "invitations", strconv.FormatInt(parseInt(t, invitations)+1, 10))
	})
}

// TestInvitationOrgPermissions: only a platform administrator creates
// invitations, so an organization cannot be named by anyone else: not by a
// member, not by an organization's own administrator (who may not delegate
// admission, docs/orgs_design.md), and not without a session. Nothing is
// written, and the organization's existence is not told to a caller who may not
// create.
//
//nolint:paralleltest // shares one database
func TestInvitationOrgPermissions(t *testing.T) {
	adminToken := invOrgWorld(t)
	org := idN(famInvOrg, 1)

	seedOrg(t, org)
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, strftime('%s','now'))", org, idUserB)
	seed(t, "UPDATE users SET org_id = ? WHERE id = ?", org, idUserB)

	orgAdminToken := seedSession(t, idN(famInvOrg, 90), idUserB)

	seedUser(t, idUserC, roleMember)

	memberToken := seedSession(t, idN(famInvOrg, 91), idUserC)

	bodies := map[string][]byte{
		"an organization that exists":         invOrgBody(t, "member", 1, org, "admin"),
		"an organization that does not exist": invOrgBody(t, "member", 1, idMissing, "admin"),
		"a body that would be refused":        []byte(`{"orgId":1`),
	}

	tokens := []struct {
		name   string
		token  string
		status int
		code   string
	}{
		{"no session", "", http.StatusUnauthorized, codeUnauthenticated},
		{"a member", memberToken, http.StatusForbidden, codeForbidden},
		{"an administrator of the organization", orgAdminToken, http.StatusForbidden, codeForbidden},
	}

	rows := count(t, "invitations")

	for _, who := range tokens {
		for what, body := range bodies {
			t.Run(who.name+"/"+what, func(t *testing.T) {
				post(t, pathInvitation, body, who.token).expect(t, "create", who.status, who.code)

				expectCount(t, "invitations", rows)
				expectCount(t, "invitation_orgs", "0")
			})
		}
	}

	t.Run("the platform administrator may", func(t *testing.T) {
		invOrgCreate(t, adminToken, "member", 1, org, "admin").expectOrg(t, "create", org, "admin")
	})
}

// ---- registering ---------------------------------------------------------------

// invOrgRegisterAll registers n accounts with code and returns them.
func invOrgRegisterAll(t *testing.T, code string, n int) []passkey {
	t.Helper()

	users := make([]passkey, 0, n)

	for i := range n {
		users = append(users, registerWithCode(t, code, fmt.Sprintf("Invited %d", i)))
	}

	return users
}

// TestRegistrationJoinsTheNamedOrg: every account created through an invitation
// that names an organization lands in that organization in the write that
// creates it, as an administrator of it too when the role is admin, and only
// then, and no organization is created for it; the role of the account itself
// (the invitation's type) is independent of it. The organization is not
// consumed: a multi-use invitation admits each registrant to it, and it is still
// shown when the invitation is used up.
//
//nolint:paralleltest // shares one database
func TestRegistrationJoinsTheNamedOrg(t *testing.T) {
	tests := []struct {
		invitationType string
		role           string
	}{
		{"member", "member"}, {"member", "admin"}, {"admin", "member"}, {"admin", "admin"},
	}

	for _, tt := range tests {
		t.Run("an account of type "+tt.invitationType+" joining as "+tt.role, func(t *testing.T) {
			token := invOrgWorld(t)
			org, other := idN(famInvOrg, 1), idN(famInvOrg, 2)

			seedOrg(t, org)
			seedOrg(t, other)

			// The first administrator, registered by first run, has its own
			// organization and administers it.
			orgs := count(t, "orgs")

			created := invOrgCreate(t, token, tt.invitationType, 3, org, tt.role)

			users := invOrgRegisterAll(t, created.Code, 3)

			wantAdmins := map[string]int{"member": 0, "admin": 3}[tt.role]

			for i, user := range users {
				if got := invOrgMember(t, user.userID); got != org {
					t.Errorf("registrant %d belongs to %q, want %q", i, got, org)
				}

				expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", strconv.Itoa(wantAdmins/3), org, user.userID)

				if role := scalar(t, "SELECT role FROM users WHERE id = ?", user.userID); role != tt.invitationType {
					t.Errorf("registrant %d has the role %q, want %q: the organization is not the account's role", i, role, tt.invitationType)
				}
			}

			// Exactly the three joined, no organization was created for any of
			// them, and the administrators are exactly them when the role says so.
			expectCount(t, "users WHERE org_id = ?", "3", org)
			expectCount(t, "users WHERE org_id = ?", "0", other)
			expectCount(t, "orgs", orgs)
			expectCount(t, "org_admins WHERE org_id = ?", strconv.Itoa(wantAdmins), org)

			// It persists through every registration, and is shown on an
			// invitation that is used up.
			expectCount(t, "invitation_orgs WHERE invitation_id = ?", "1", created.ID)

			view := invOrgFind(t, token, created.ID)
			view.expectOrg(t, "the exhausted invitation", org, tt.role)

			if view.Status != invStatusExhausted || view.Uses != 3 {
				t.Errorf("invitation = %s with %d uses, want exhausted with 3", view.Status, view.Uses)
			}

			// A fourth is refused, and joins nothing.
			beginRegistration(t, created.Code, "Too many").expect(t, "begin after exhaustion", http.StatusForbidden, invCodeInvalidReg)
			expectCount(t, "users WHERE org_id = ?", "3", org)
			invOrgExpectConsistent(t)
		})
	}
}

// TestRegistrationNamedOrgIsTheInvitationsOwn: an account joins the organization
// its own invitation names and no other: two invitations naming two
// organizations send their registrants to their own.
//
//nolint:paralleltest // shares one database
func TestRegistrationNamedOrgIsTheInvitationsOwn(t *testing.T) {
	token := invOrgWorld(t)
	left, right := idN(famInvOrg, 1), idN(famInvOrg, 2)

	seedOrg(t, left)
	seedOrg(t, right)

	toLeft := invOrgCreate(t, token, "member", 1, left, "admin")
	toRight := invOrgCreate(t, token, "member", 1, right, "member")

	// Registered in the opposite order to the creation.
	r := registerWithCode(t, toRight.Code, "Right")
	l := registerWithCode(t, toLeft.Code, "Left")

	if got := invOrgMember(t, l.userID); got != left {
		t.Errorf("left belongs to %q, want %q", got, left)
	}

	if got := invOrgMember(t, r.userID); got != right {
		t.Errorf("right belongs to %q, want %q", got, right)
	}

	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", left, l.userID)
	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "0", right, r.userID)
	invOrgExpectConsistent(t)
}

// TestRegistrationWithoutAnOrgCreatesOne: an account created through an
// invitation that names none (and the first administrator, through first run) is
// given a new standard organization in the write that creates it: created by the
// account, at the time of the account, named "<name>'s org" after it, with the account as its
// one administrator and its only member. Each account of a multi-use invitation
// gets one of its own.
//
//nolint:paralleltest // shares one database
func TestRegistrationWithoutAnOrgCreatesOne(t *testing.T) {
	for _, invitationType := range []string{"member", "admin"} {
		t.Run(invitationType, func(t *testing.T) {
			token := invOrgWorld(t)

			// The first administrator, from first run.
			first := scalar(t, "SELECT id FROM users WHERE role = 'admin'")
			expectCount(t, "orgs WHERE created_by = ? AND kind = 'standard' AND name = 'Admin''s org' AND expires_at IS NULL", "1", first)
			expectCount(t, "users WHERE id = ? AND org_id = (SELECT id FROM orgs WHERE created_by = ?)", "1", first, first)
			expectCount(t, "org_admins WHERE user_id = ? AND org_id = (SELECT org_id FROM users WHERE id = ?)", "1", first, first)

			created := invOrgCreate(t, token, invitationType, 2, "", "")
			users := invOrgRegisterAll(t, created.Code, 2)

			seen := map[string]bool{}

			for i, user := range users {
				org := invOrgMember(t, user.userID)
				if org == "" || seen[org] {
					t.Fatalf("registrant %d belongs to %q, want an organization of its own (seen %v)", i, org, seen)
				}

				seen[org] = true

				name := fmt.Sprintf("Invited %d's org", i)

				expectCount(t, "orgs WHERE id = ? AND kind = 'standard' AND name = ? AND created_by = ? "+
					"AND created_at = (SELECT created_at FROM users WHERE id = ?) AND expires_at IS NULL",
					"1", org, name, user.userID, user.userID)
				expectCount(t, "org_admins WHERE org_id = ?", "1", org)
				expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", org, user.userID)
				expectCount(t, "users WHERE org_id = ?", "1", org)
			}

			// The first administrator's, the seeded account's and these two.
			expectCount(t, "orgs", "4")
			expectCount(t, "invitation_orgs", "0")
			invOrgExpectConsistent(t)
		})
	}
}

// TestRegistrationFailureRollsBackEverything: a failure at any statement of the
// account's write leaves nothing behind. A trigger refuses the insert of one
// table (as a concurrent write that broke a constraint would), and the response
// is a failure, no account, no organization of its own, no administrator row and
// no passkey stands, and the invitation is still redeemable: the same finish
// succeeds once the trigger is gone.
//
// The trigger is installed while the Worker is idle and dropped right after the
// one request, not in a Cleanup, so a failing assertion cannot leave it behind.
//
//nolint:paralleltest // shares one database
func TestRegistrationFailureRollsBackEverything(t *testing.T) {
	tests := []struct {
		name  string
		role  string // the role of the named organization, "" to name none
		table string // the table whose insert fails
	}{
		{"the account, with an organization of its own", "", "users"},
		{"the organization of its own", "", "orgs"},
		{"the administrator of its own organization", "", "org_admins"},
		{"the passkey, with an organization of its own", "", "credentials"},
		{"the account, joining as a member", "member", "users"},
		{"the passkey, joining as a member", "member", "credentials"},
		{"the account, joining as an administrator", "admin", "users"},
		{"the administrator of the organization joined", "admin", "org_admins"},
		{"the passkey, joining as an administrator", "admin", "credentials"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := invOrgWorld(t)
			org := idN(famInvOrg, 1)

			seedOrg(t, org)

			named, role := "", ""
			if tt.role != "" {
				named, role = org, tt.role
			}

			created := invOrgCreate(t, token, "member", 1, named, role)

			// The ceremony is begun first: begin writes nothing, so the trigger
			// can be installed afterwards, and fires only for finish's batch.
			options := mustBeginRegistration(t, created.Code, "Racer")
			auth := newAuthenticator()
			auth.priv = newKey(t)
			finish := auth.finishBody(t, options, created.Code, "Racer")

			users, orgs, admins, credentials := count(t, "users"), count(t, "orgs"), count(t, "org_admins"), count(t, "credentials")

			seed(t, "CREATE TRIGGER "+invOrgRaceTrigger+" AFTER INSERT ON "+tt.table+
				" BEGIN SELECT RAISE(ABORT, 'e2e: refused'); END")

			got := post(t, pathRegisterEnd, finish, "")

			seed(t, "DROP TRIGGER "+invOrgRaceTrigger)

			if got.status/100 == 2 {
				t.Fatalf("register finish = %d %s, want a failure", got.status, got.body)
			}

			expectCount(t, "users", users)
			expectCount(t, "orgs", orgs)
			expectCount(t, "org_admins", admins)
			expectCount(t, "credentials", credentials)
			expectCount(t, "users WHERE invitation_id = ?", "0", created.ID)
			invOrgExpectConsistent(t)

			// Nothing was spent: the same request succeeds now.
			post(t, pathRegisterEnd, finish, "").expect(t, "register finish again", http.StatusCreated, "")
			expectCount(t, "users WHERE invitation_id = ?", "1", created.ID)
			invOrgExpectConsistent(t)
		})
	}
}

// TestRegistrationsRacingEachOther: registrations finished together through a
// multi-use invitation, with and without a named organization. Exactly as many
// succeed as the invitation allows, each of them gets its organization (joined,
// as an administrator of it too for the administrator role, or its own) in its
// own write, and each loser is refused as any registration over the cap is,
// leaving no organization behind.
//
//nolint:paralleltest // shares one database
func TestRegistrationsRacingEachOther(t *testing.T) {
	const allowed = 4

	// For each role ("" names no organization): how many accounts end in the
	// seeded organization, how many administer it, and how many organizations
	// exist (the first administrator's, the seeded account's and the seeded one,
	// and one for each account that won when the invitation names none).
	tests := []struct {
		role                      string
		joined, administrators, n int
	}{
		{"admin", allowed, allowed, 3},
		{"member", allowed, 0, 3},
		{"", 0, 0, allowed + 3},
	}

	for _, tt := range tests {
		for round := range 3 {
			org := idN(famInvOrg, 1)
			created := invOrgRaceRound(t, org, tt.role, allowed, round)

			expectCount(t, "users WHERE invitation_id = ?", strconv.Itoa(allowed), created.ID)
			expectCount(t, "users WHERE invitation_id = ? AND org_id = ?", strconv.Itoa(tt.joined), created.ID, org)
			expectCount(t, "org_admins WHERE org_id = ?", strconv.Itoa(tt.administrators), org)
			expectCount(t, "orgs", strconv.Itoa(tt.n))
			expectCount(t, "invitation_orgs", strconv.Itoa(min(len(tt.role), 1)))
			invOrgExpectConsistent(t)
		}
	}
}

// invOrgRaceRound runs one round of the race above in a fresh world: a seeded
// organization, an invitation for allowed accounts that names it with role (or
// none when role is ""), and more finishes than it allows, released together. It
// holds that exactly allowed of them succeed and the others are refused as any
// registration over the cap is, and returns the invitation.
func invOrgRaceRound(t *testing.T, org, role string, allowed, round int) invOrgCreated {
	t.Helper()

	const attempts = 7

	token := invOrgWorld(t)

	seedOrg(t, org)

	named := ""
	if role != "" {
		named = org
	}

	created := invOrgCreate(t, token, "member", allowed, named, role)
	bodies := invFirstRunFinishes(t, created.Code, attempts)

	replies := invRace(len(bodies), func(i int) reply { return post(t, pathRegisterEnd, bodies[i], "") })

	t.Logf("role %q round %d: %v", role, round, invStatuses(replies))

	won := 0

	for _, r := range replies {
		switch {
		case r.status == http.StatusCreated:
			won++
		case r.status == http.StatusForbidden && r.errorCode() == invCodeInvalidReg:
		case r.status == http.StatusConflict && r.errorCode() == "registration_accept_failed":
		default:
			t.Errorf("finish = %d %s, want 201, 403 invalid_invitation or 409 registration_accept_failed", r.status, r.body)
		}
	}

	if won != allowed {
		t.Fatalf("role %q round %d: %d accounts created, want exactly %d", role, round, won, allowed)
	}

	return created
}
