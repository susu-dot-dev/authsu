//go:build e2e

//nolint:goconst,funlen,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// invitation_orgs_test.go holds what an invitation's offer to join an
// organization does against the real TinyGo Worker and the real D1/SQLite
// (docs/orgs_design.md, principle 2; docs/invitations_design.md): an admin's
// create may carry orgId and orgRole, the offer is written in the invitation's
// own batch only if the organization is standard and unrevoked at that write,
// and every registration through the invitation joins that organization, as an
// administrator of it too when the role says so, without ever failing because
// of the organization.
//
// What only the real database can show, and so is here and not in the unit
// tests: that a refused offer rolls the invitation's secret back with it (the
// NOT NULL subselect of the offer's organization), that the registration batch
// joins, and makes an administrator, in the one write that creates the account,
// and that an organization revoked INSIDE that batch (a trigger plays the
// concurrent revoke at three points of it, as TestLoginRacingAStateChange does
// for login) leaves the account registered, released, and never an
// administrator of or a member of a revoked organization.
//
// REVIEW.md categories covered: permission confusion (a non-admin, an
// organization's own administrator, no session), input edge cases and
// type/bound confusion (every value of the two fields), too large payloads,
// interleaving (multi-use registrations racing each other, and racing the
// revocation of the organization through its route).

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

// invOrgView is an invitation as it is served with its offer, which is absent
// when it has none.
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
// the offer fields when they are not "".
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
	got.expect(t, "create with an offer", http.StatusCreated, "")

	var created invOrgCreated

	invDecode(t, got.body, &created)

	return created
}

// invOrgList reads the list with its offers.
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

// expectOffer fails the test unless the invitation shows exactly this offer, and
// none when org is "".
func (v invOrgView) expectOffer(t *testing.T, what, org, role string) {
	t.Helper()

	switch {
	case org == "":
		if v.OrgID != nil || v.OrgRole != nil {
			t.Errorf("%s shows the offer %v %v, want none", what, v.OrgID, v.OrgRole)
		}
	case v.OrgID == nil || *v.OrgID != org || v.OrgRole == nil || *v.OrgRole != role:
		t.Errorf("%s shows the offer %v %v, want %s %s", what, v.OrgID, v.OrgRole, org, role)
	}
}

// invOrgRevoke revokes an organization the way the Worker's revoke does: it is
// marked revoked, its members are released, and its offers and administrators
// are deleted, all together.
func invOrgRevoke(t *testing.T, org string) {
	t.Helper()

	seed(t, "UPDATE orgs SET revoked_at = strftime('%s','now') WHERE id = ?", org)
	seed(t, "UPDATE users SET org_id = NULL WHERE org_id = ?", org)
	seed(t, "DELETE FROM org_admins WHERE org_id = ?", org)
	seed(t, "DELETE FROM org_offers WHERE org_id = ?", org)
}

// invOrgRevokeSQL is invOrgRevoke as the body of a trigger, for the org.
func invOrgRevokeSQL(org string) string {
	return fmt.Sprintf("UPDATE orgs SET revoked_at = strftime('%%s','now') WHERE id = '%[1]s'; "+
		"UPDATE users SET org_id = NULL WHERE org_id = '%[1]s'; "+
		"DELETE FROM org_admins WHERE org_id = '%[1]s'; "+
		"DELETE FROM org_offers WHERE org_id = '%[1]s';", org)
}

// invOrgExpectConsistent holds the invariants of a revoked organization, which
// no registration may break: nobody belongs to it and nobody administers it, and
// whoever administers one is a member of it.
func invOrgExpectConsistent(t *testing.T) {
	t.Helper()

	expectCount(t, "users WHERE org_id IN (SELECT id FROM orgs WHERE revoked_at IS NOT NULL)", "0")
	expectCount(t, "org_admins WHERE org_id IN (SELECT id FROM orgs WHERE revoked_at IS NOT NULL)", "0")
	expectCount(t, "org_admins WHERE user_id NOT IN (SELECT id FROM users WHERE org_id = org_admins.org_id)", "0")
	expectNoOrphanSecrets(t)
}

// invOrgMember is the id of the organization a user belongs to, "" for none.
func invOrgMember(t *testing.T, user string) string {
	t.Helper()

	return scalar(t, "SELECT COALESCE(org_id, '') FROM users WHERE id = ?", user)
}

// ---- creating an invitation with an offer -------------------------------------

// TestInvitationOrgOfferIsStoredAndShown: an offer of each role is written with
// the invitation, addressed to the invitation and to no user, made by the
// creator, and shown by the create and by every later response that shows the
// invitation while it exists (the list, an update and a revoke). An invitation
// without one shows neither field.
//
//nolint:paralleltest // shares one database
func TestInvitationOrgOfferIsStoredAndShown(t *testing.T) {
	for _, role := range []string{"member", "admin"} {
		t.Run(role, func(t *testing.T) {
			token := invOrgWorld(t)
			org := idN(famInvOrg, 1)

			seedOrg(t, org)

			plain := invOrgCreate(t, token, "member", 2, "", "")
			created := invOrgCreate(t, token, "member", 2, org, role)

			created.expectOffer(t, "create", org, role)
			plain.expectOffer(t, "create without one", "", "")

			expectCount(t, "org_offers", "1")
			expectCount(t, "org_offers WHERE invitation_id = ? AND org_id = ? AND role = ? AND kind = 'standard' "+
				"AND user_id IS NULL AND created_by = (SELECT id FROM users WHERE role = 'admin')",
				"1", created.ID, org, role)
			expectCount(t, "invitations", "3") // the first run's, and these two

			// The offer is shown by the list, beside an invitation without one.
			invOrgFind(t, token, created.ID).expectOffer(t, "list", org, role)
			invOrgFind(t, token, plain.ID).expectOffer(t, "list of one without", "", "")

			// An update and a revoke show it too, and neither touches it.
			upd := patch(t, invItem(created.ID), []byte(`{"numInvites":5}`), token)
			upd.expect(t, "update", http.StatusOK, "")

			var updated invOrgView

			invDecode(t, upd.body, &updated)
			updated.expectOffer(t, "update", org, role)

			rev := del(t, invItem(created.ID), token)
			rev.expect(t, "revoke", http.StatusOK, "")

			var revoked invOrgView

			invDecode(t, rev.body, &revoked)
			revoked.expectOffer(t, "revoke", org, role)

			invOrgFind(t, token, created.ID).expectOffer(t, "list after the revoke", org, role)
			expectCount(t, "org_offers", "1")
		})
	}
}

// TestInvitationOrgOfferTwoInvitationsOneOrg: several invitations may offer the
// same organization, each with an offer of its own (UNIQUE is on the invitation,
// and NULL users are distinct in the key on the organization and the user).
//
//nolint:paralleltest // shares one database
func TestInvitationOrgOfferTwoInvitationsOneOrg(t *testing.T) {
	token := invOrgWorld(t)
	org := idN(famInvOrg, 1)

	seedOrg(t, org)

	first := invOrgCreate(t, token, "member", 1, org, "member")
	second := invOrgCreate(t, token, "member", 1, org, "admin")

	expectCount(t, "org_offers WHERE org_id = ?", "2", org)

	invOrgFind(t, token, first.ID).expectOffer(t, "first", org, "member")
	invOrgFind(t, token, second.ID).expectOffer(t, "second", org, "admin")
}

// TestInvitationOrgOfferRefusals: every refusal writes nothing at all. The
// organization that cannot be offered (none, a sandbox, a revoked one) is a 404
// that rolls the whole batch back, the invitation's secret included, which is
// what the offer's NOT NULL organization is for; a value that is not valid is a
// 400 from its parser; an oversized body is refused before it is read. Each
// refusal is the same whatever the cause, and shows no code.
//
//nolint:paralleltest // shares one database
func TestInvitationOrgOfferRefusals(t *testing.T) {
	token := invOrgWorld(t)

	active, revoked, epoch, sandbox := idN(famInvOrg, 1), idN(famInvOrg, 2), idN(famInvOrg, 3), idN(famInvOrg, 4)

	seedOrg(t, active)
	seedOrg(t, revoked)
	seedOrg(t, epoch)
	seedSandbox(t, sandbox, idUserB)
	seed(t, "UPDATE orgs SET revoked_at = strftime('%s','now') WHERE id = ?", revoked)
	seed(t, "UPDATE orgs SET revoked_at = 0 WHERE id = ?", epoch)

	offer := func(org, role string) string {
		return `{"type":"member","numInvites":1,"orgId":` + org + `,"orgRole":` + role + `}`
	}

	tests := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		// What cannot be offered.
		{"an organization that does not exist", offer(`"`+idMissing+`"`, `"member"`), http.StatusNotFound, invOrgCodeNotFound},
		{"an organization that does not exist, as an admin", offer(`"`+idMissing+`"`, `"admin"`), http.StatusNotFound, invOrgCodeNotFound},
		{"a revoked organization", offer(`"`+revoked+`"`, `"member"`), http.StatusNotFound, invOrgCodeNotFound},
		{"an organization revoked at the epoch", offer(`"`+epoch+`"`, `"member"`), http.StatusNotFound, invOrgCodeNotFound},
		{"a sandbox", offer(`"`+sandbox+`"`, `"member"`), http.StatusNotFound, invOrgCodeNotFound},
		{"a sandbox, as an admin", offer(`"`+sandbox+`"`, `"admin"`), http.StatusNotFound, invOrgCodeNotFound},

		// One field without the other.
		{"a role with no organization", `{"type":"member","numInvites":1,"orgRole":"member"}`, http.StatusBadRequest, invOrgCodeNoID},
		{"a role with a null organization", offer(`null`, `"member"`), http.StatusBadRequest, invOrgCodeNoID},
		{"an organization with no role", `{"type":"member","numInvites":1,"orgId":"` + active + `"}`, http.StatusBadRequest, invOrgCodeNoRole},
		{"an organization with a null role", offer(`"`+active+`"`, `null`), http.StatusBadRequest, invOrgCodeNoRole},

		// The organization's id.
		{"an empty organization", offer(`""`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id in upper case", offer(`"`+strings.ToUpper(active)+`"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id with a trailing space", offer(`"`+active+` "`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id of 35 characters", offer(`"`+active[1:]+`"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id of 37 characters", offer(`"`+active+`0"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id with a NUL", offer(`"`+active[:35]+`\u0000"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id of 3000 characters", offer(`"`+strings.Repeat("a", 3000)+`"`, `"member"`), http.StatusBadRequest, invOrgCodeInvalidID},
		{"an id that is a number", offer(`1`, `"member"`), http.StatusBadRequest, "invalid_field_type"},
		{"an id that is an object", offer(`{"id":"`+active+`"}`, `"member"`), http.StatusBadRequest, "invalid_field_type"},

		// The role.
		{"an empty role", offer(`"`+active+`"`, `""`), http.StatusBadRequest, invOrgCodeRole},
		{"a role in another case", offer(`"`+active+`"`, `"Admin"`), http.StatusBadRequest, invOrgCodeRole},
		{"a role with a trailing space", offer(`"`+active+`"`, `"admin "`), http.StatusBadRequest, invOrgCodeRole},
		{"a role with a NUL", offer(`"`+active+`"`, `"admin\u0000"`), http.StatusBadRequest, invOrgCodeRole},
		{"a role nobody has", offer(`"`+active+`"`, `"owner"`), http.StatusBadRequest, invOrgCodeRole},
		{"a role of 3000 characters", offer(`"`+active+`"`, `"`+strings.Repeat("a", 3000)+`"`), http.StatusBadRequest, invOrgCodeRole},
		{"a role that is a number", offer(`"`+active+`"`, `1`), http.StatusBadRequest, "invalid_field_type"},

		// Shapes.
		{"the offer as an object", `{"type":"member","numInvites":1,"org":{"id":"` + active + `","role":"member"}}`, http.StatusBadRequest, codeUnknownField},
		{"the organization twice", `{"type":"member","numInvites":1,"orgId":"` + active + `","orgId":"` + active + `","orgRole":"member"}`, http.StatusBadRequest, "duplicate_field"},

		// Too large: refused before anything is read.
		{"an organization over the body limit", offer(`"`+strings.Repeat("a", 5000)+`"`, `"member"`), http.StatusRequestEntityTooLarge, codeBodyTooLarge},
		{"a role over the body limit", offer(`"`+active+`"`, `"`+strings.Repeat("a", 5000)+`"`), http.StatusRequestEntityTooLarge, codeBodyTooLarge},
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

			// Nothing at all was written: not the offer, not the invitation, and
			// not the secret that was written before the offer was refused.
			expectCount(t, "invitations", invitations)
			expectCount(t, "secrets", secrets)
			expectCount(t, "org_offers", "0")
		})
	}

	t.Run("the 404 is the same body for every cause", func(t *testing.T) {
		var first string

		for _, org := range []string{idMissing, revoked, epoch, sandbox} {
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

	t.Run("a control: the active organization is offered", func(t *testing.T) {
		invOrgCreate(t, token, "member", 1, active, "member").expectOffer(t, "create", active, "member")
		expectCount(t, "org_offers", "1")
		expectCount(t, "invitations", strconv.FormatInt(parseInt(t, invitations)+1, 10))
	})
}

// TestInvitationOrgOfferPermissions: only a platform administrator creates
// invitations, so an offer cannot be made by anyone else: not by a member, not
// by an organization's own administrator (who may not delegate admission,
// docs/orgs_design.md), and not without a session. Nothing is written, and the
// organization's existence is not told to a caller who may not create.
//
//nolint:paralleltest // shares one database
func TestInvitationOrgOfferPermissions(t *testing.T) {
	adminToken := invOrgWorld(t)
	org := idN(famInvOrg, 1)

	seedOrg(t, org)
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, strftime('%s','now'))", org, idUserB)
	seed(t, "UPDATE users SET org_id = ? WHERE id = ?", org, idUserB)

	orgAdminToken := seedSession(t, idN(famInvOrg, 90), idUserB)

	seedUser(t, idUserC, roleMember)

	memberToken := seedSession(t, idN(famInvOrg, 91), idUserC)

	bodies := map[string][]byte{
		"an offer of an organization that exists":         invOrgBody(t, "member", 1, org, "admin"),
		"an offer of an organization that does not exist": invOrgBody(t, "member", 1, idMissing, "admin"),
		"a body that would be refused":                    []byte(`{"orgId":1`),
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
				expectCount(t, "org_offers", "0")
			})
		}
	}

	t.Run("the platform administrator may", func(t *testing.T) {
		invOrgCreate(t, adminToken, "member", 1, org, "admin").expectOffer(t, "create", org, "admin")
	})
}

// ---- registering through an offer ----------------------------------------------

// invOrgRegisterAll registers n accounts with code and returns them.
func invOrgRegisterAll(t *testing.T, code string, n int) []passkey {
	t.Helper()

	users := make([]passkey, 0, n)

	for i := range n {
		users = append(users, registerWithCode(t, code, fmt.Sprintf("Invited %d", i)))
	}

	return users
}

// TestRegistrationJoinsTheOfferedOrg: every account created through an
// invitation that carries an offer lands in that organization in the write that
// creates it, as an administrator of it too when the offer's role is admin, and
// only then; the role of the account itself (the invitation's type) is
// independent of it. The offer is not consumed: a multi-use invitation admits
// each registrant to the organization, it still shows the offer when it is used
// up, and an invitation without an offer, even to the same organization's
// registrants, puts nobody anywhere.
//
//nolint:paralleltest // shares one database
func TestRegistrationJoinsTheOfferedOrg(t *testing.T) {
	tests := []struct {
		invitationType string
		role           string
	}{
		{"member", "member"}, {"member", "admin"}, {"admin", "member"}, {"admin", "admin"},
	}

	for _, tt := range tests {
		t.Run("an account of type "+tt.invitationType+" offered the role "+tt.role, func(t *testing.T) {
			token := invOrgWorld(t)
			org, other := idN(famInvOrg, 1), idN(famInvOrg, 2)

			seedOrg(t, org)
			seedOrg(t, other)

			// The first administrator belongs to nothing: first run is unaffected.
			expectCount(t, "users WHERE org_id IS NOT NULL", "0")

			offered := invOrgCreate(t, token, tt.invitationType, 3, org, tt.role)
			plain := invOrgCreate(t, token, "member", 1, "", "")

			users := invOrgRegisterAll(t, offered.Code, 3)

			for i, user := range users {
				if got := invOrgMember(t, user.userID); got != org {
					t.Errorf("registrant %d belongs to %q, want %q", i, got, org)
				}

				wantAdmin := "0"
				if tt.role == "admin" {
					wantAdmin = "1"
				}

				expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", wantAdmin, org, user.userID)

				if role := scalar(t, "SELECT role FROM users WHERE id = ?", user.userID); role != tt.invitationType {
					t.Errorf("registrant %d has the role %q, want %q: the offer is not the account's role", i, role, tt.invitationType)
				}
			}

			// Exactly the three joined, and the administrators are exactly them
			// when the role says so.
			expectCount(t, "users WHERE org_id = ?", "3", org)
			expectCount(t, "users WHERE org_id = ?", "0", other)
			expectCount(t, "org_admins WHERE org_id = ?", strconv.Itoa(map[string]int{"member": 0, "admin": 3}[tt.role]), org)
			expectCount(t, "org_admins", strconv.Itoa(map[string]int{"member": 0, "admin": 3}[tt.role]))

			// The offer persists through every registration, and is shown on an
			// invitation that is used up.
			expectCount(t, "org_offers WHERE invitation_id = ?", "1", offered.ID)

			view := invOrgFind(t, token, offered.ID)
			view.expectOffer(t, "the exhausted invitation", org, tt.role)

			if view.Status != invStatusExhausted || view.Uses != 3 {
				t.Errorf("invitation = %s with %d uses, want exhausted with 3", view.Status, view.Uses)
			}

			// A fourth is refused, and joins nothing.
			beginRegistration(t, offered.Code, "Too many").expect(t, "begin after exhaustion", http.StatusForbidden, invCodeInvalidReg)
			expectCount(t, "users WHERE org_id = ?", "3", org)

			// An invitation with no offer puts its registrant nowhere, though the
			// organization exists and others joined it.
			loner := registerWithCode(t, plain.Code, "Loner")
			if got := invOrgMember(t, loner.userID); got != "" {
				t.Errorf("registrant without an offer belongs to %q, want nothing", got)
			}

			expectCount(t, "users WHERE org_id IS NOT NULL", "3")
			invOrgExpectConsistent(t)
		})
	}
}

// TestRegistrationOfferOfAnotherInvitation: an account joins the organization of
// its own invitation's offer and no other: two invitations offering two
// organizations send their registrants to their own.
//
//nolint:paralleltest // shares one database
func TestRegistrationOfferOfAnotherInvitation(t *testing.T) {
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
	expectCount(t, "org_admins", "1")
}

// TestRegistrationWhenTheOrgWasRevoked: an organization revoked between the
// invitation and the registration never fails the registration: the account is
// created with no organization, and is never an administrator of one. The same
// holds when only revoked_at is set (the offer is still there), when it is
// revoked as the Worker revokes it (the offer is deleted too), and for a
// revocation at the epoch, since any value revokes.
//
//nolint:paralleltest // shares one database
func TestRegistrationWhenTheOrgWasRevoked(t *testing.T) {
	tests := []struct {
		name   string
		revoke func(*testing.T, string)
		// offerStays is whether the invitation still carries its offer: only a
		// revoke that deletes offers, as the Worker's does, removes it.
		offerStays bool
	}{
		{"only marked revoked", func(t *testing.T, org string) {
			t.Helper()
			seed(t, "UPDATE orgs SET revoked_at = strftime('%s','now') WHERE id = ?", org)
		}, true},
		{"revoked at the epoch", func(t *testing.T, org string) {
			t.Helper()
			seed(t, "UPDATE orgs SET revoked_at = 0 WHERE id = ?", org)
		}, true},
		{"revoked as the Worker revokes it", invOrgRevoke, false},
	}

	for _, tt := range tests {
		for _, role := range []string{"member", "admin"} {
			t.Run(tt.name+"/"+role, func(t *testing.T) {
				token := invOrgWorld(t)
				org := idN(famInvOrg, 1)

				seedOrg(t, org)

				offered := invOrgCreate(t, token, "member", 2, org, role)

				tt.revoke(t, org)

				// Both registrants are admitted: the organization is not a
				// condition of registration.
				for i, user := range invOrgRegisterAll(t, offered.Code, 2) {
					if got := invOrgMember(t, user.userID); got != "" {
						t.Errorf("registrant %d belongs to the revoked organization %q", i, got)
					}

					expectCount(t, "org_admins WHERE user_id = ?", "0", user.userID)
				}

				expectCount(t, "users WHERE invitation_id = ?", "2", offered.ID)
				expectCount(t, "credentials", "3") // the first admin's and these two

				if tt.offerStays {
					invOrgFind(t, token, offered.ID).expectOffer(t, "the invitation", org, role)
				} else {
					invOrgFind(t, token, offered.ID).expectOffer(t, "the invitation", "", "")
				}

				// Registering does not consume or revive anything.
				expectCount(t, "orgs WHERE id = ? AND revoked_at IS NOT NULL", "1", org)
				invOrgExpectConsistent(t)
			})
		}
	}
}

// TestRegistrationRacingAnOrgRevoke: an organization revoked INSIDE the
// registration batch is the interleaving the write's own conditions exist for. A
// trigger plays a concurrent revoke at one point of the batch, doing what a
// revoke does (mark the organization revoked, release its members, delete its
// offers and administrators), at the user insert, at the administrator insert
// and at the last statement. Each way the registration still succeeds, and the
// account is never stranded: it ends in no organization, with no administrator
// row, and nothing refers to the revoked organization.
//
// The trigger is installed while the Worker is idle and dropped right after the
// one request, not in a Cleanup, so a failing assertion cannot leave it behind.
//
//nolint:paralleltest // shares one database
func TestRegistrationRacingAnOrgRevoke(t *testing.T) {
	tests := []struct {
		name  string
		role  string
		table string // the table whose insert fires the trigger
	}{
		{"revoked as the account is inserted, joining as a member", "member", "users"},
		{"revoked as the account is inserted, joining as an administrator", "admin", "users"},
		{"revoked as the administrator row is inserted", "admin", "org_admins"},
		{"revoked as the passkey is stored, joining as a member", "member", "credentials"},
		{"revoked as the passkey is stored, joining as an administrator", "admin", "credentials"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := invOrgWorld(t)
			org := idN(famInvOrg, 1)

			seedOrg(t, org)

			offered := invOrgCreate(t, token, "member", 1, org, tt.role)

			// The ceremony is begun first: begin writes nothing, so the trigger
			// can be installed afterwards, and fires only for finish's batch.
			options := mustBeginRegistration(t, offered.Code, "Racer")
			auth := newAuthenticator()
			auth.priv = newKey(t)
			finish := auth.finishBody(t, options, offered.Code, "Racer")

			seed(t, "CREATE TRIGGER "+invOrgRaceTrigger+" AFTER INSERT ON "+tt.table+" BEGIN "+invOrgRevokeSQL(org)+" END")

			got := post(t, pathRegisterEnd, finish, "")

			seed(t, "DROP TRIGGER "+invOrgRaceTrigger)

			// The organization is not a condition of registration.
			got.expect(t, "register finish", http.StatusCreated, "")

			expectCount(t, "users WHERE invitation_id = ?", "1", offered.ID)
			expectCount(t, "credentials", "2") // the first admin's and this one
			expectCount(t, "orgs WHERE id = ? AND revoked_at IS NOT NULL", "1", org)

			// Never stranded: in no organization, administrating none.
			expectCount(t, "users WHERE invitation_id = ? AND org_id IS NULL", "1", offered.ID)
			expectCount(t, "org_admins", "0")
			expectCount(t, "org_offers", "0")
			invOrgExpectConsistent(t)
		})
	}
}

// TestRegistrationsRacingEachOther: registrations finished together through a
// multi-use invitation with an administrator offer. Exactly as many succeed as
// the invitation allows, each of them joins the organization and is made an
// administrator in its own write, and each loser is refused as any registration
// over the cap is, joining nothing.
//
//nolint:paralleltest // shares one database
func TestRegistrationsRacingEachOther(t *testing.T) {
	const allowed, attempts = 4, 7

	for round := range 3 {
		token := invOrgWorld(t)
		org := idN(famInvOrg, 1)

		seedOrg(t, org)

		offered := invOrgCreate(t, token, "member", allowed, org, "admin")
		bodies := invFirstRunFinishes(t, offered.Code, attempts)

		replies := invRace(len(bodies), func(i int) reply { return post(t, pathRegisterEnd, bodies[i], "") })

		t.Logf("round %d: %v", round, invStatuses(replies))

		created := 0

		for _, r := range replies {
			switch {
			case r.status == http.StatusCreated:
				created++
			case r.status == http.StatusForbidden && r.errorCode() == invCodeInvalidReg:
			case r.status == http.StatusConflict && r.errorCode() == "registration_accept_failed":
			default:
				t.Errorf("finish = %d %s, want 201, 403 invalid_invitation or 409 registration_accept_failed", r.status, r.body)
			}
		}

		if created != allowed {
			t.Fatalf("round %d: %d accounts created, want exactly %d", round, created, allowed)
		}

		expectCount(t, "users WHERE invitation_id = ? AND org_id = ?", strconv.Itoa(allowed), offered.ID, org)
		expectCount(t, "org_admins WHERE org_id = ?", strconv.Itoa(allowed), org)
		expectCount(t, "users WHERE org_id IS NOT NULL", strconv.Itoa(allowed))
		expectCount(t, "org_offers WHERE invitation_id = ?", "1", offered.ID)
		invOrgExpectConsistent(t)
	}
}

// TestRegistrationsRacingTheOrgRevoke: registrations finished together with the
// organization's revocation through the API (a platform administrator may revoke
// any organization). Whichever order each lands in, every registration succeeds,
// and the end state is consistent: nobody is left in the revoked organization or
// administering it, however the writes interleaved. This is the test that runs
// the real revoke of the organization against the real registration write.
//
//nolint:paralleltest // shares one database
func TestRegistrationsRacingTheOrgRevoke(t *testing.T) {
	const registrants = 4

	for round := range 3 {
		token := invOrgWorld(t)
		org := idN(famInvOrg, 1)

		seedOrg(t, org)

		offered := invOrgCreate(t, token, "member", registrants+2, org, "admin")
		bodies := invFirstRunFinishes(t, offered.Code, registrants)

		replies := invRace(registrants+1, func(i int) reply {
			if i == registrants {
				return del(t, "/api/org/"+org, token)
			}

			return post(t, pathRegisterEnd, bodies[i], "")
		})

		t.Logf("round %d: %v", round, invStatuses(replies))

		for i, r := range replies {
			if i == registrants {
				if r.status/100 != 2 {
					t.Errorf("revoke = %d %s, want a success", r.status, r.body)
				}

				continue
			}

			if r.status != http.StatusCreated {
				t.Errorf("finish %d = %d %s, want 201: the organization is never a condition of registration", i, r.status, r.body)
			}
		}

		expectCount(t, "users WHERE invitation_id = ?", strconv.Itoa(registrants), offered.ID)
		expectCount(t, "orgs WHERE id = ? AND revoked_at IS NOT NULL", "1", org)
		invOrgExpectConsistent(t)
	}
}
