//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// orgs_authority_test.go is who may do what to whom, through the real Worker and
// the real database, as tables of actor x target x expected answer, each row run
// from a fresh world with the database read back afterwards: a refused request
// changed nothing, an accepted one changed exactly its target. It also holds
// the interleavings of the requests that change who may act (revocations and
// promotions racing each other), the ids of one kind passed where another is
// wanted, the credentials that may not revoke other people, and the seat that a
// revoked account keeps in its invitation (docs/orgs_design.md, principle 1).

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// orgAuth is the world of orgNewWorld with the accounts an authority table
// needs beside it:
//
//   - foreign administers a second standard organization, orgB, which also holds
//     the second platform administrator, platform2 (who does not belong to org);
//   - the platform administrator platform belongs to org without administering it;
//   - sandbox is a sandbox of outsider, who administers it and does not belong to it.
//
// Every account holds a session, an agent and an API key of the agent, so that a
// revocation's reach is visible.
type orgAuth struct {
	orgWorld

	foreign, platform2           string
	foreignToken, platform2Token string

	orgB, sandbox string
}

// users are the accounts of the world, keyed as the tables name them.
func (w orgAuth) users() map[string]string {
	return map[string]string{
		"admin": w.admin, "member": w.member, "second": w.second, "outsider": w.outsider,
		"platform": w.platform, "platform2": w.platform2, "foreign": w.foreign,
	}
}

// id resolves a name of a table: an account, an organization, or an id that
// names nothing (or a literal id).
func (w orgAuth) id(key string) string {
	if id, ok := w.users()[key]; ok {
		return id
	}

	switch key {
	case "missing":
		return idMissing
	case "org":
		return w.org
	case "orgB":
		return w.orgB
	case "sandbox":
		return w.sandbox
	case "outsiderOrg":
		return w.outsiderOrg
	case "platformOrg":
		return w.platformOrg
	}

	return key
}

// token is the session of the account a table names.
func (w orgAuth) token(key string) string {
	return map[string]string{
		"admin": w.adminToken, "member": w.memberToken, "second": w.secondToken, "outsider": w.outsiderToken,
		"platform": w.platformToken, "platform2": w.platform2Token, "foreign": w.foreignToken,
		"none": "",
	}[key]
}

// orgAuthNewWorld builds the world.
func orgAuthNewWorld(t *testing.T) orgAuth {
	t.Helper()

	world := orgAuth{
		orgWorld: orgNewWorld(t), foreign: orgUser(7), platform2: orgUser(8),
		orgB: idN(orgFamOrg, 2), sandbox: idN(orgFamSandbox, 1),
	}

	seedUserWithOrg(t, world.foreign, roleMember, world.orgB, "Other")
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", world.orgB, world.foreign)
	seedUserIn(t, world.platform2, roleAdmin, world.orgB)

	world.foreignToken = seedSession(t, idN(orgFamSession, 7), world.foreign)
	world.platform2Token = seedSession(t, idN(orgFamSession, 8), world.platform2)

	orgJoin(t, world.org, world.platform, false)
	sbSeedSandbox(t, world.sandbox, world.outsider, sbWeek)

	// A session each is there already; an agent with a key of its own each.
	for i, user := range []string{
		world.admin, world.member, world.second, world.outsider, world.platform, world.platform2, world.foreign,
	} {
		seedAgent(t, idN(orgFamAgent, 10+i), user, "agent")
		seedAPIKey(t, idN(orgFamKey, 10+i), user, idN(orgFamAgent, 10+i))
	}

	return world
}

// orgRevokedSet is the ids of the accounts that are revoked.
func orgRevokedSet(t *testing.T) []string {
	t.Helper()

	return rowsOf(t, "SELECT id FROM users WHERE revoked_at IS NOT NULL ORDER BY id")
}

// orgDigest is everything an authority request may change, in one string: every
// account (its organization and when it was revoked), every organization (kind
// and name), every administrator, every secret and agent with when it was revoked,
// and how many invitations and invitation organizations there are.
func orgDigest(t *testing.T) string {
	t.Helper()

	return scalar(t, "SELECT "+
		"ifnull((SELECT group_concat(id || ':' || ifnull(org_id, '-') || ':' || ifnull(revoked_at, '-'), ',') "+
		"FROM (SELECT id, org_id, revoked_at FROM users ORDER BY id)), '') || '|' || "+
		"ifnull((SELECT group_concat(id || ':' || kind || ':' || name, ',') "+
		"FROM (SELECT id, kind, name FROM orgs ORDER BY id)), '') || '|' || "+
		"ifnull((SELECT group_concat(org_id || ':' || user_id, ',') "+
		"FROM (SELECT org_id, user_id FROM org_admins ORDER BY org_id, user_id)), '') || '|' || "+
		"ifnull((SELECT group_concat(id || ':' || ifnull(revoked_at, '-'), ',') "+
		"FROM (SELECT id, revoked_at FROM secrets ORDER BY id)), '') || '|' || "+
		"ifnull((SELECT group_concat(id || ':' || ifnull(revoked_at, '-'), ',') "+
		"FROM (SELECT id, revoked_at FROM agents ORDER BY id)), '') || '|' || "+
		"(SELECT count(*) FROM invitations) || '|' || (SELECT count(*) FROM invitation_orgs)")
}

// orgSetRevoked marks an account revoked behind the Worker's back, as a revocation
// that is older than the request does, and leaves its session as it was: the
// boundary, and not the session's own revocation, is what is under test.
func orgSetRevoked(key string) func(t *testing.T, w orgAuth) {
	return func(t *testing.T, w orgAuth) {
		t.Helper()

		seed(t, "UPDATE users SET revoked_at = 5 WHERE id = ?", w.id(key))
	}
}

// orgDemoted removes an administrator row behind the Worker's back.
func orgDemoted(key string) func(t *testing.T, w orgAuth) {
	return func(t *testing.T, w orgAuth) {
		t.Helper()

		seed(t, "DELETE FROM org_admins WHERE org_id = ? AND user_id = ?", w.org, w.id(key))
	}
}

// orgMemberPromoted makes the member an administrator behind the Worker's back.
func orgMemberPromoted(t *testing.T, w orgAuth) {
	t.Helper()

	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", w.org, w.member)
}

// orgNotPlatform makes platform2 an ordinary account, so that platform is the
// only platform administrator.
func orgNotPlatform(t *testing.T, w orgAuth) {
	t.Helper()

	setRole(t, w.platform2, roleMember)
}

// orgAll runs several setups in order.
func orgAll(steps ...func(t *testing.T, w orgAuth)) func(t *testing.T, w orgAuth) {
	return func(t *testing.T, w orgAuth) {
		t.Helper()

		for _, step := range steps {
			step(t, w)
		}
	}
}

// ---- revoking an account through /api/member ---------------------------------

// orgAuthCase is one row of an authority table: who asks, about whom, and the
// answer. A setup runs on the fresh world first.
type orgAuthCase struct {
	name          string
	actor, target string
	setup         func(t *testing.T, w orgAuth)
	status        int
	code          string
}

// orgRevokeCases are the rows of TestOrgRevokeMemberAuthority: a platform
// administrator revokes anyone, an administrator of the organization revokes its
// accounts and never a platform administrator, even a revoked one and one who
// belongs to the organization, and never themself, and nobody else revokes anyone.
func orgRevokeCases() []orgAuthCase {
	const (
		ok     = http.StatusOK
		denied = http.StatusForbidden
		absent = http.StatusNotFound
	)

	return []orgAuthCase{
		// Who is not an administrator.
		{"a member revokes an administrator", "member", "admin", nil, denied, orgCodeNotAdmin},
		{"a member revokes another member", "member", "second", nil, denied, orgCodeNotAdmin},
		{"a member revokes themself", "member", "member", nil, denied, orgCodeNotAdmin},
		{"a member revokes a platform administrator", "member", "platform", nil, denied, orgCodeNotAdmin},
		{"an account that administers nothing revokes themself", "outsider", "outsider", nil, denied, orgCodeNotAdmin},
		{"an outsider revokes a member", "outsider", "member", nil, absent, orgCodeMemberMissing},
		{"the administrator of a sandbox revokes a member of an organization", "outsider", "member", nil, absent, orgCodeMemberMissing},
		{"the administrator of another organization revokes a member", "foreign", "member", nil, absent, orgCodeMemberMissing},
		{"the administrator of another organization revokes an administrator", "foreign", "admin", nil, absent, orgCodeMemberMissing},
		{"the administrator of another organization revokes a platform administrator", "foreign", "platform", nil, absent, orgCodeMemberMissing},

		// What an administrator may not do.
		{"an administrator revokes a platform administrator of the organization", "admin", "platform", nil, denied, orgCodePlatformAdmin},
		{"an administrator revokes a revoked platform administrator of the organization", "admin", "platform",
			orgSetRevoked("platform"), denied, orgCodePlatformAdmin},
		{"an administrator revokes themself", "admin", "admin", nil, denied, orgCodeSelfRevoke},
		{"the last administrator revokes themself", "admin", "admin", orgDemoted("second"), denied, orgCodeSelfRevoke},
		{"an administrator revokes someone who does not exist", "admin", "missing", nil, absent, orgCodeMemberMissing},
		{"an administrator revokes an account of another organization", "admin", "outsider", nil, absent, orgCodeMemberMissing},
		{"an administrator revokes the administrator of another organization", "admin", "foreign", nil, absent, orgCodeMemberMissing},
		{"an administrator revokes a platform administrator of another organization", "admin", "platform2", nil, absent, orgCodeMemberMissing},
		{"an administrator revokes an organization (its id is no account's)", "admin", "org", nil, absent, orgCodeMemberMissing},
		{"an administrator revokes a sandbox (its id is no account's)", "admin", "sandbox", nil, absent, orgCodeMemberMissing},

		// What a platform administrator may not do: leave none.
		{"the only platform administrator revokes themself", "platform", "platform", orgNotPlatform, http.StatusConflict, orgCodeLastPlatform},
		{"the only platform administrator revokes themself, with a revoked one beside", "platform", "platform",
			orgAll(orgSetRevoked("platform2")), http.StatusConflict, orgCodeLastPlatform},
		{"a platform administrator revokes someone who does not exist", "platform", "missing", nil, absent, orgCodeMemberMissing},
		{"a platform administrator revokes an organization", "platform", "org", nil, absent, orgCodeMemberMissing},
		{"a platform administrator revokes a sandbox", "platform", "sandbox", nil, absent, orgCodeMemberMissing},
		{"a platform administrator revokes the id of an organization of their own", "platform", "platformOrg", nil, absent, orgCodeMemberMissing},

		// A caller who is revoked is not signed in, whatever they ask: their
		// session is presented and refused at the boundary (the account is
		// revoked at once, and their secrets only by what revokes them).
		{"a revoked administrator revokes a member", "admin", "member", orgSetRevoked("admin"), http.StatusUnauthorized, codeUnauthenticated},
		{"a revoked administrator revokes a missing account", "admin", "missing", orgSetRevoked("admin"), http.StatusUnauthorized, codeUnauthenticated},
		{"a revoked administrator revokes themself", "admin", "admin", orgSetRevoked("admin"), http.StatusUnauthorized, codeUnauthenticated},
		{"a revoked platform administrator revokes a member", "platform", "member", orgSetRevoked("platform"), http.StatusUnauthorized, codeUnauthenticated},
		{"a revoked platform administrator revokes the other", "platform", "platform2", orgSetRevoked("platform"), http.StatusUnauthorized, codeUnauthenticated},
		{"a revoked member revokes an administrator", "member", "admin", orgSetRevoked("member"), http.StatusUnauthorized, codeUnauthenticated},
		{"no session revokes a member", "none", "member", nil, http.StatusUnauthorized, codeUnauthenticated},

		// What each may do.
		{"an administrator revokes a member", "admin", "member", nil, ok, ""},
		{"an administrator revokes the other administrator", "admin", "second", nil, ok, ""},
		{"the other administrator revokes the first", "second", "admin", nil, ok, ""},
		{"an administrator revokes a member who is revoked already", "admin", "member", orgSetRevoked("member"), ok, ""},
		{"an administrator revokes a revoked administrator", "admin", "second", orgSetRevoked("second"), ok, ""},
		{"a platform administrator revokes a member", "platform", "member", nil, ok, ""},
		{"a platform administrator revokes a member who is revoked already", "platform", "member", orgSetRevoked("member"), ok, ""},
		{"a platform administrator revokes an administrator", "platform", "admin", nil, ok, ""},
		{"a platform administrator revokes the last administrator", "platform", "admin", orgDemoted("second"), ok, ""},
		{"a platform administrator revokes an account of another organization", "platform", "outsider", nil, ok, ""},
		{"a platform administrator revokes the administrator of another organization", "platform", "foreign", nil, ok, ""},
		{"a platform administrator revokes another platform administrator, of another organization", "platform", "platform2", nil, ok, ""},
		{"a platform administrator who belongs to no organization of the target's revokes a member", "platform2", "member", nil, ok, ""},
		{"a platform administrator who belongs to no organization of the target's revokes an administrator", "platform2", "admin", nil, ok, ""},
		{"a platform administrator revokes themself while another remains", "platform", "platform", nil, ok, ""},
	}
}

// TestOrgRevokeMemberAuthority is the authority of DELETE /api/member/{id}
// (docs/users_design.md) as a table: for each actor and target, the answer, and
// then the database. A refusal changed nothing at all. An acceptance revoked the
// target's account and all of its sessions, keys and agents, and no other
// account, secret or agent; the target stays in its organization, and is served
// as revoked and no longer as an administrator.
//
//nolint:paralleltest // shares one database
func TestOrgRevokeMemberAuthority(t *testing.T) {
	for _, tc := range orgRevokeCases() {
		t.Run(tc.name, func(t *testing.T) {
			world := orgAuthNewWorld(t)

			if tc.setup != nil {
				tc.setup(t, world)
			}

			target := world.id(tc.target)
			revokedBefore := orgRevokedSet(t)
			digestBefore := orgDigest(t)
			othersBefore := count(t, ownedSecrets+" WHERE o.user_id <> ? AND s.revoked_at IS NULL", target)
			orgBefore := orgMembership(t, target)

			got := del(t, pathMember+"/"+target, world.token(tc.actor))
			got.expect(t, tc.name, tc.status, tc.code)

			if tc.status != http.StatusOK {
				if after := orgDigest(t); after != digestBefore {
					t.Errorf("a refused revocation changed the state:\n%s\n%s", digestBefore, after)
				}

				return
			}

			orgRevoked(t, tc.name, got, target)

			want := revokedBefore
			if !slices.Contains(want, target) {
				want = append(slices.Clone(want), target)
				slices.Sort(want)
			}

			if after := orgRevokedSet(t); !slices.Equal(after, want) {
				t.Errorf("revoked accounts = %v, want %v", after, want)
			}

			if slices.Contains(revokedBefore, target) {
				expectCount(t, "users WHERE id = ? AND revoked_at = 5", "1", target)
			} else {
				expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NULL", "0", target)
				expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "0", target)
			}

			// Nobody else's sessions, keys or agents were touched, and the target
			// is where it was.
			expectCount(t, ownedSecrets+" WHERE o.user_id <> ? AND s.revoked_at IS NULL", othersBefore, target)
			expectCount(t, "agents WHERE user_id <> ? AND revoked_at IS NOT NULL", "0", target)

			if after := orgMembership(t, target); after != orgBefore {
				t.Errorf("the revoked account belongs to %s, want it still in %s", after, orgBefore)
			}
		})
	}
}

// ---- promoting and demoting --------------------------------------------------

// orgPromoteCase is a row of the table of PATCH /api/member/{id}: admin is what
// the body asks for, and administers is whether the target administers the
// organization afterwards (known only when the answer is 200).
type orgPromoteCase struct {
	orgAuthCase

	admin      bool
	administer bool
}

// orgPromoteCases are the rows of TestOrgMemberAuthority.
func orgPromoteCases() []orgPromoteCase {
	const (
		ok     = http.StatusOK
		denied = http.StatusForbidden
		absent = http.StatusNotFound
	)

	row := func(name, actor, target string, setup func(t *testing.T, w orgAuth), admin bool, status int, code string, administers bool) orgPromoteCase {
		return orgPromoteCase{orgAuthCase{name, actor, target, setup, status, code}, admin, administers}
	}

	return []orgPromoteCase{
		// What an administrator may do, and that it is idempotent.
		row("an administrator promotes a member", "admin", "member", nil, true, ok, "", true),
		row("a promoted member is promoted again", "admin", "member", orgMemberPromoted, true, ok, "", true),
		row("the other administrator promotes a member", "second", "member", nil, true, ok, "", true),
		row("an administrator demotes a member who is no administrator", "admin", "member", nil, false, ok, "", false),
		row("the other administrator demotes a promoted member", "second", "member", orgMemberPromoted, false, ok, "", false),
		row("an administrator demotes the other administrator", "admin", "second", nil, false, ok, "", false),
		row("an administrator demotes themself while another administers", "admin", "admin", nil, false, ok, "", false),
		row("an administrator promotes themself again", "admin", "admin", nil, true, ok, "", true),

		// What a platform administrator may do, whether they belong to it or not.
		row("a platform administrator who is a member promotes a member", "platform", "member", nil, true, ok, "", true),
		row("a platform administrator who is not a member promotes a member", "platform2", "member", nil, true, ok, "", true),
		row("a platform administrator demotes an administrator", "platform2", "second", nil, false, ok, "", false),
		row("a platform administrator promotes a member of an organization with no administrator left", "platform2", "member",
			orgAll(orgDemoted("admin"), orgDemoted("second")), true, ok, "", true),

		// The last administrator is never demoted, by anyone.
		row("an administrator demotes the last administrator", "admin", "admin", orgDemoted("second"), false, http.StatusConflict, orgCodeLastAdmin, true),
		row("a member who was an administrator demotes the last administrator", "second", "admin", orgDemoted("second"), false, denied, orgCodeNotAdmin, true),
		row("a platform administrator demotes the last administrator", "platform2", "admin", orgDemoted("second"), false, http.StatusConflict, orgCodeLastAdmin, true),
		row("a platform administrator demotes the last unrevoked administrator, a revoked one beside", "platform2", "admin",
			orgSetRevoked("second"), false, http.StatusConflict, orgCodeLastAdmin, true),
		row("an administrator demotes the last unrevoked administrator, a revoked one beside", "admin", "admin",
			orgSetRevoked("second"), false, http.StatusConflict, orgCodeLastAdmin, true),

		// A revoked member is never promoted, an administrator who is revoked
		// included; demoting one is allowed, which is how a revoked administrator's
		// row is removed.
		row("an administrator promotes a revoked member", "admin", "member", orgSetRevoked("member"), true,
			http.StatusConflict, orgCodeMemberRevoked, false),
		row("a platform administrator promotes a revoked member", "platform2", "member", orgSetRevoked("member"), true,
			http.StatusConflict, orgCodeMemberRevoked, false),
		row("an administrator promotes a revoked administrator, who stays one", "admin", "second", orgSetRevoked("second"), true,
			http.StatusConflict, orgCodeMemberRevoked, true),
		row("an administrator demotes a revoked member who was never promoted", "admin", "member", orgSetRevoked("member"), false, ok, "", false),
		row("an administrator demotes a revoked administrator", "admin", "second", orgSetRevoked("second"), false, ok, "", false),
		row("a platform administrator demotes a revoked administrator", "platform2", "second", orgSetRevoked("second"), false, ok, "", false),
		row("a promoted member who is revoked is demoted", "admin", "member",
			orgAll(orgMemberPromoted, orgSetRevoked("member")), false, ok, "", false),

		// Who may not.
		row("a member promotes themself", "member", "member", nil, true, denied, orgCodeNotAdmin, false),
		row("a member promotes an account of another organization", "member", "outsider", nil, true, absent, orgCodeMemberMissing, false),
		row("a member demotes an administrator", "member", "admin", nil, false, denied, orgCodeNotAdmin, true),
		row("an administrator who was a member demotes themself", "member", "member", orgMemberPromoted, false, ok, "", false),
		row("an outsider promotes a member", "outsider", "member", nil, true, absent, orgCodeMemberMissing, false),
		row("the administrator of a sandbox promotes a member", "outsider", "member", nil, true, absent, orgCodeMemberMissing, false),
		row("the administrator of another organization promotes a member", "foreign", "member", nil, true, absent, orgCodeMemberMissing, false),
		row("the administrator of another organization demotes an administrator", "foreign", "admin", nil, false, absent, orgCodeMemberMissing, true),

		// Whom.
		row("an administrator promotes an account of another organization", "admin", "outsider", nil, true, absent, orgCodeMemberMissing, false),
		row("an administrator promotes the administrator of another organization", "admin", "foreign", nil, true, absent, orgCodeMemberMissing, false),
		row("an administrator promotes a platform administrator of another organization", "admin", "platform2", nil, true, absent, orgCodeMemberMissing, false),
		row("an administrator promotes someone who does not exist", "admin", "missing", nil, true, absent, orgCodeMemberMissing, false),
		row("an administrator promotes an organization (its id is no account's)", "admin", "org", nil, true, absent, orgCodeMemberMissing, false),
		row("an administrator promotes a sandbox (its id is no account's)", "admin", "sandbox", nil, true, absent, orgCodeMemberMissing, false),
		row("a platform administrator promotes an organization", "platform2", "org", nil, true, absent, orgCodeMemberMissing, false),
		row("a platform administrator promotes a sandbox", "platform2", "sandbox", nil, true, absent, orgCodeMemberMissing, false),
		row("a platform administrator promotes someone who does not exist", "platform2", "missing", nil, true, absent, orgCodeMemberMissing, false),

		// A caller who is revoked is not signed in.
		row("a revoked administrator promotes a member", "admin", "member", orgSetRevoked("admin"), true,
			http.StatusUnauthorized, codeUnauthenticated, false),
		row("a revoked administrator demotes the other", "admin", "second", orgSetRevoked("admin"), false,
			http.StatusUnauthorized, codeUnauthenticated, true),
		row("a revoked administrator promotes someone who does not exist", "admin", "missing", orgSetRevoked("admin"), true,
			http.StatusUnauthorized, codeUnauthenticated, false),
		row("a revoked platform administrator promotes a member", "platform2", "member", orgSetRevoked("platform2"), true,
			http.StatusUnauthorized, codeUnauthenticated, false),
		row("no session promotes a member", "none", "member", nil, true, http.StatusUnauthorized, codeUnauthenticated, false),
	}
}

// orgBody is the body of a promotion or a demotion.
func orgBody(admin bool) []byte {
	return []byte(`{"admin":` + strconv.FormatBool(admin) + `}`)
}

// TestOrgMemberAuthority is the authority of PATCH /api/member/{id} as a table.
// Every refusal changed no row, and an acceptance changed the target's
// administrator row and no other. It answers with the target as it now is.
//
//nolint:paralleltest // shares one database
func TestOrgMemberAuthority(t *testing.T) {
	for _, tc := range orgPromoteCases() {
		t.Run(tc.name, func(t *testing.T) {
			world := orgAuthNewWorld(t)

			if tc.setup != nil {
				tc.setup(t, world)
			}

			target := world.id(tc.target)
			digestBefore := orgDigest(t)
			revokedBefore := orgRevokedSet(t)
			othersBefore := scalar(t, "SELECT ifnull(group_concat(org_id || ':' || user_id, ','), '') FROM "+
				"(SELECT org_id, user_id FROM org_admins WHERE user_id <> ? ORDER BY org_id, user_id)", target)
			membersBefore := orgMembership(t, target)

			got := patch(t, pathMember+"/"+target, orgBody(tc.admin), world.token(tc.actor))
			got.expect(t, tc.name, tc.status, tc.code)

			// What the answer is told on the way, whatever it was.
			if after := orgMembership(t, target); after != membersBefore {
				t.Errorf("the target moved from %s to %s", membersBefore, after)
			}

			if tc.status != http.StatusOK {
				if after := orgDigest(t); after != digestBefore {
					t.Errorf("a refused change changed the state:\n%s\n%s", digestBefore, after)
				}

				return
			}

			member := orgDecode[orgMemberView](t, got)
			if member.ID != target || member.OrgID != world.org || member.Admin != tc.administer {
				t.Errorf("answer = %+v, want %s of %s with administrator %t", member, target, world.org, tc.administer)
			}

			wantRows := "0"
			if tc.administer {
				wantRows = "1"
			}

			expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", wantRows, world.org, target)

			if after := scalar(t, "SELECT ifnull(group_concat(org_id || ':' || user_id, ','), '') FROM "+
				"(SELECT org_id, user_id FROM org_admins WHERE user_id <> ? ORDER BY org_id, user_id)", target); after != othersBefore {
				t.Errorf("another administrator's row changed:\n%s\n%s", othersBefore, after)
			}

			// A promotion or a demotion never revokes anyone.
			if after := orgRevokedSet(t); !slices.Equal(after, revokedBefore) {
				t.Errorf("revoked accounts = %v, want %v", after, revokedBefore)
			}
		})
	}
}

// ---- an id of one kind where another is wanted -------------------------------

// TestOrgIDConfusion: the id of an account where an organization is wanted, the
// id of an organization or a sandbox where an account is wanted, and a sandbox
// where a standard organization is wanted. In the world no account has the id of
// an organization (an account's own organization has an id of its own), so each
// is an id that names nothing of the kind asked for, and is answered as one that
// names nothing: 404 with the code of the kind, from every caller, and not a row
// changes.
//
//nolint:paralleltest // shares one database
func TestOrgIDConfusion(t *testing.T) {
	type call struct {
		method, path string
		body         []byte
	}

	// users are the ids of accounts: an administrator, a member, an account with
	// an organization of its own, and a platform administrator of another.
	users := []string{"admin", "member", "outsider", "platform2"}
	// orgs are the ids of organizations and of the sandbox.
	orgs := []string{"org", "orgB", "outsiderOrg", "platformOrg", "sandbox"}

	orgRoutes := func(id string) []call {
		return []call{
			{http.MethodGet, orgItem(id), nil},
			{http.MethodPatch, orgItem(id), []byte(`{"name":"Renamed"}`)},
			{http.MethodDelete, orgItem(id), nil},
			{http.MethodGet, orgItem(id) + "/member", nil},
		}
	}

	memberRoutes := func(id string) []call {
		return []call{
			{http.MethodPatch, pathMember + "/" + id, orgBody(true)},
			{http.MethodPatch, pathMember + "/" + id, orgBody(false)},
			{http.MethodDelete, pathMember + "/" + id, nil},
		}
	}

	userRoutes := func(id string) []call {
		return []call{
			{http.MethodGet, usrItem(id), nil},
			{http.MethodDelete, usrItem(id), nil},
		}
	}

	t.Run("an account's id as an organization's", func(t *testing.T) {
		world := orgAuthNewWorld(t)
		before := orgDigest(t)

		for _, actor := range []string{"platform", "platform2", "admin", "second", "member", "outsider", "foreign"} {
			for _, user := range users {
				for _, c := range orgRoutes(world.id(user)) {
					got := send(t, request{method: c.method, path: c.path, body: c.body, token: world.token(actor)})
					got.expect(t, actor+" "+c.method+" "+c.path+" ("+user+")", http.StatusNotFound, orgCodeNotFound)
				}
			}
		}

		if after := orgDigest(t); after != before {
			t.Errorf("refusals changed the state:\n%s\n%s", before, after)
		}
	})

	t.Run("an organization's id as an account's", func(t *testing.T) {
		world := orgAuthNewWorld(t)
		before := orgDigest(t)

		// The caller who may most: a platform administrator, and the administrators
		// of the organizations whose ids are used, and one of no authority.
		for _, actor := range []string{"platform", "platform2", "admin", "second", "outsider", "foreign"} {
			for _, org := range orgs {
				for _, c := range memberRoutes(world.id(org)) {
					got := send(t, request{method: c.method, path: c.path, body: c.body, token: world.token(actor)})
					got.expect(t, actor+" "+c.method+" "+c.path+" ("+org+")", http.StatusNotFound, orgCodeMemberMissing)
				}
			}
		}

		for _, org := range orgs {
			for _, c := range userRoutes(world.id(org)) {
				got := send(t, request{method: c.method, path: c.path, body: c.body, token: world.platformToken})
				got.expect(t, "platform "+c.method+" "+c.path+" ("+org+")", http.StatusNotFound, usrCodeNotFound)
			}
		}

		if after := orgDigest(t); after != before {
			t.Errorf("refusals changed the state:\n%s\n%s", before, after)
		}
	})

	t.Run("a sandbox where a standard organization is wanted", func(t *testing.T) {
		world := orgAuthNewWorld(t)
		before := orgDigest(t)

		for _, tc := range []struct {
			actor  string
			status int
			code   string
		}{
			{"outsider", http.StatusConflict, orgCodeNotStandard}, // its administrator
			{"platform", http.StatusConflict, orgCodeNotStandard},
			{"platform2", http.StatusConflict, orgCodeNotStandard},
			{"admin", http.StatusNotFound, orgCodeNotFound}, // an administrator of another
			{"member", http.StatusNotFound, orgCodeNotFound},
			{"foreign", http.StatusNotFound, orgCodeNotFound},
		} {
			got := get(t, orgItem(world.sandbox)+"/member", world.token(tc.actor))
			got.expect(t, tc.actor+" lists the members of a sandbox", tc.status, tc.code)
		}

		// Control: the sandbox is there, for its administrator.
		get(t, orgItem(world.sandbox), world.outsiderToken).expect(t, "the sandbox itself", http.StatusOK, "")

		if after := orgDigest(t); after != before {
			t.Errorf("refusals changed the state:\n%s\n%s", before, after)
		}
	})

	t.Run("an invitation naming an account or a sandbox as its organization", func(t *testing.T) {
		world := orgAuthNewWorld(t)
		before := orgDigest(t)
		secrets := count(t, "secrets")

		for _, id := range []string{"admin", "member", "outsider", "platform", "sandbox", "missing"} {
			for _, role := range []string{"member", "admin"} {
				got := post(t, pathInvitation, invOrgBody(t, "member", 1, world.id(id), role), world.platformToken)
				got.expect(t, "an invitation naming "+id+" as "+role, http.StatusNotFound, invOrgCodeNotFound)

				if strings.Contains(got.body, "susu_inv_") {
					t.Errorf("a refused create shows a code: %s", got.body)
				}
			}
		}

		if after := orgDigest(t); after != before {
			t.Errorf("refusals changed the state:\n%s\n%s", before, after)
		}

		expectCount(t, "secrets", secrets)

		// Control: the standard organization's id is named, once the account's
		// own organization is told apart from the account.
		post(t, pathInvitation, invOrgBody(t, "member", 1, world.outsiderOrg, "member"), world.platformToken).
			expect(t, "an invitation naming a standard organization", http.StatusCreated, "")
		expectCount(t, "invitation_orgs WHERE org_id = ?", "1", world.outsiderOrg)
	})
}

// ---- credentials that may not revoke people ------------------------------------

// orgScopeNames are every scope there is and every bundle, as the API names them.
func orgScopeNames() []string {
	return []string{
		"agent:read", "agent:create", "agent:update", "agent:revoke",
		"key:read", "key:create", "key:update", "key:revoke",
		"grant:read", "grant:revoke",
		"org:read", "sandbox:create", "org:update", "sandbox:revoke",
		"member:read", "member:update", "member:revoke",
		"invitation:read", "invitation:create", "invitation:update", "invitation:revoke",
		"user:read", "user:revoke",
		"default:session", "default:user", "default:agent",
	}
}

// orgScopeList is the JSON list of the names.
func orgScopeList(names ...string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = `"` + name + `"`
	}

	return "[" + strings.Join(quoted, ",") + "]"
}

// TestOrgAgentsNeverRevokePeople: an agent is refused DELETE /api/user/{id} and
// PATCH and DELETE /api/member/{id} whatever it was given: each scope alone, a
// bundle, and every scope at once, the agent of a platform administrator and of
// an organization's administrator alike. The refusal is 403 and changes nothing.
//
//nolint:paralleltest // shares one database
func TestOrgAgentsNeverRevokePeople(t *testing.T) {
	world := orgAuthNewWorld(t)
	target := world.member

	everything := orgScopeNames()
	sets := make([]string, 0, len(everything)+2)

	for _, name := range everything {
		sets = append(sets, orgScopeList(name))
	}

	sets = append(sets, orgScopeList(everything...), orgScopeList(everything[:23]...))

	for _, owner := range []string{"platform", "admin"} {
		agent, key := idN(orgFamAgent, 40), idN(orgFamKey, 40)

		seedAgent(t, agent, world.id(owner), "holder")

		token := seedAPIKey(t, key, world.id(owner), agent)
		before := orgDigest(t)

		for _, scopes := range sets {
			seed(t, "UPDATE agents SET scopes = ? WHERE id = ?", scopes, agent)
			seed(t, "UPDATE api_keys SET scope = ? WHERE id = ?", scopes, key)

			for _, c := range []struct{ method, path, body string }{
				{http.MethodDelete, usrItem(target), ""},
				{http.MethodDelete, pathMember + "/" + target, ""},
				{http.MethodPatch, pathMember + "/" + target, `{"admin":true}`},
				{http.MethodPatch, pathMember + "/" + world.second, `{"admin":false}`},
			} {
				var body []byte
				if c.body != "" {
					body = []byte(c.body)
				}

				got := send(t, request{method: c.method, path: c.path, body: body, bearer: token})
				got.expect(t, owner+"'s agent with "+scopes+": "+c.method+" "+c.path, http.StatusForbidden, "")
			}
		}

		seed(t, "DELETE FROM api_keys WHERE id = ?", key)
		seed(t, "DELETE FROM agents WHERE id = ?", agent)

		// Accounts, organizations and administrators are as they were (the
		// secrets are not: the key was added and removed).
		if after := orgDigest(t); strings.Join(strings.Split(after, "|")[:3], "|") != strings.Join(strings.Split(before, "|")[:3], "|") {
			t.Errorf("a refusal changed the state:\n%s\n%s", before, after)
		}
	}

	expectCount(t, "users WHERE revoked_at IS NOT NULL", "0")
	expectCount(t, "org_admins WHERE org_id = ?", "2", world.org)
}

// TestOrgKeysRevokePeopleOnlyWhenTheyNameIt: the default scopes of a user's own
// key (default:user) do not revoke other people: a key must name member:revoke
// for DELETE /api/member/{id}, and a platform administrator's key user:revoke
// for DELETE /api/user/{id}. They promote and demote, and a session, which holds
// every scope, revokes.
//
//nolint:paralleltest // shares one database
func TestOrgKeysRevokePeopleOnlyWhenTheyNameIt(t *testing.T) {
	const (
		revokeMember = "DELETE member"
		revokeUser   = "DELETE user"
		promote      = "PATCH member"
	)

	rows := []struct {
		name        string
		owner       string // "admin" or "platform"
		scopes      string // "" is the session itself
		route       string
		status      int
		code        string
		wantRevoked bool
	}{
		// An organization's administrator.
		{"an administrator's session revokes a member", "admin", "", revokeMember, http.StatusOK, "", true},
		{"an administrator's default key does not revoke a member", "admin", orgScopeList("default:user"), revokeMember,
			http.StatusForbidden, "insufficient_scope", false},
		{"an administrator's key of no scopes does not revoke a member", "admin", orgScopeList(), revokeMember,
			http.StatusForbidden, "insufficient_scope", false},
		{"an administrator's key of the other revoke scopes does not revoke a member", "admin", orgScopeList("agent:revoke", "key:revoke", "sandbox:revoke", "grant:revoke", "member:update"),
			revokeMember, http.StatusForbidden, "insufficient_scope", false},
		{"an administrator's key naming member:revoke revokes a member", "admin", orgScopeList("member:revoke"), revokeMember,
			http.StatusOK, "", true},
		{"an administrator's key naming the default and member:revoke revokes a member", "admin", orgScopeList("default:user", "member:revoke"),
			revokeMember, http.StatusOK, "", true},
		{"an administrator's key of the session bundle revokes a member", "admin", orgScopeList("default:session"), revokeMember,
			http.StatusOK, "", true},
		{"an administrator's default key promotes a member", "admin", orgScopeList("default:user"), promote,
			http.StatusOK, "", false},
		{"an administrator's key without member:update does not promote", "admin", orgScopeList("member:revoke", "member:read"), promote,
			http.StatusForbidden, "insufficient_scope", false},
		{"an administrator's key naming user:revoke does not revoke an account", "admin", orgScopeList("user:revoke", "member:revoke"), revokeUser,
			http.StatusForbidden, codeForbidden, false},

		// A platform administrator.
		{"a platform administrator's session revokes a member", "platform", "", revokeMember, http.StatusOK, "", true},
		{"a platform administrator's session revokes an account", "platform", "", revokeUser, http.StatusOK, "", true},
		{"a platform administrator's default key does not revoke a member", "platform", orgScopeList("default:user"), revokeMember,
			http.StatusForbidden, "insufficient_scope", false},
		{"a platform administrator's default key does not revoke an account", "platform", orgScopeList("default:user"), revokeUser,
			http.StatusForbidden, "insufficient_scope", false},
		{"a platform administrator's key naming member:revoke revokes a member", "platform", orgScopeList("member:revoke"), revokeMember,
			http.StatusOK, "", true},
		{"a platform administrator's key naming member:revoke does not revoke an account", "platform", orgScopeList("member:revoke"), revokeUser,
			http.StatusForbidden, "insufficient_scope", false},
		{"a platform administrator's key naming user:revoke revokes an account", "platform", orgScopeList("user:revoke"), revokeUser,
			http.StatusOK, "", true},
		{"a platform administrator's key naming user:revoke does not revoke a member", "platform", orgScopeList("user:revoke"), revokeMember,
			http.StatusForbidden, "insufficient_scope", false},
		{"a platform administrator's key of the session bundle revokes an account", "platform", orgScopeList("default:session"), revokeUser,
			http.StatusOK, "", true},
		{"a platform administrator's default key promotes a member", "platform", orgScopeList("default:user"), promote,
			http.StatusOK, "", false},
	}

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			world := orgAuthNewWorld(t)
			owner := world.id(tc.owner)

			var as request

			if tc.scopes == "" {
				as.token = world.token(tc.owner)
			} else {
				as.bearer = sbSeedKey(t, idN(orgFamKey, 41), owner, "", tc.scopes)
			}

			target := world.member

			switch tc.route {
			case revokeMember:
				as.method, as.path = http.MethodDelete, pathMember+"/"+target
			case revokeUser:
				as.method, as.path = http.MethodDelete, usrItem(target)
			default:
				as.method, as.path, as.body = http.MethodPatch, pathMember+"/"+target, orgBody(true)
			}

			digest := orgDigest(t)
			got := send(t, as)
			got.expect(t, tc.name, tc.status, tc.code)

			revoked := count(t, "users WHERE id = ? AND revoked_at IS NOT NULL", target)
			if (revoked == "1") != tc.wantRevoked {
				t.Errorf("the member's revocation = %s, want %t", revoked, tc.wantRevoked)
			}

			if tc.status != http.StatusOK && orgDigest(t) != digest {
				t.Errorf("a refusal changed the state")
			}

			if tc.wantRevoked {
				expectCount(t, "users WHERE revoked_at IS NOT NULL", "1")
			}
		})
	}
}

// ---- the seat of a revoked account ---------------------------------------------

// TestInvitationSeatOfARevokedAccount: an account holds its invitation's seat
// for good (docs/orgs_design.md, principle 1). An invitation of a cap N that has
// made N accounts admits no other when some of them are revoked, as the one
// who revoked them (an administrator of the organization it names, or a platform
// administrator, by either route), and a cap of 3 with one account revoked
// admits two more and not a fourth. The refusal is the one a spent invitation
// gives, a cap cannot be lowered below the accounts made (revoked ones included),
// and raising it by one admits exactly one.
//
// The ceremonies are all begun first, while the invitation has room, and
// finished one after another, so a registration that would pass the check at its
// begin is still refused at its finish.
//
//nolint:paralleltest // shares one database
func TestInvitationSeatOfARevokedAccount(t *testing.T) {
	type seatCase struct {
		name string
		// cap is the invitation's cap, and registered how many accounts it has
		// made when the revocations are done.
		cap, registered int
		// revoke are the indices of the accounts revoked, and by whom: "user" and
		// "member" are the platform administrator through each route, "org" the
		// administrator of the organization the invitation names.
		revoke []int
		by     string
	}

	cases := []seatCase{
		{"a cap of three, none revoked", 3, 3, nil, "user"},
		{"a cap of one, its account revoked by a platform administrator", 1, 1, []int{0}, "user"},
		{"a cap of one, its account revoked by a platform administrator through the member route", 1, 1, []int{0}, "member"},
		{"a cap of one, its account revoked by an administrator of its organization", 1, 1, []int{0}, "org"},
		{"a cap of three, one of three revoked by an administrator", 3, 3, []int{1}, "org"},
		{"a cap of three, all three revoked by a platform administrator", 3, 3, []int{0, 1, 2}, "user"},
		{"a cap of three, all three revoked by an administrator", 3, 3, []int{0, 1, 2}, "org"},
		{"a cap of five, two of five revoked through the member route", 5, 5, []int{0, 4}, "member"},
		{"a cap of three, one of one revoked: two seats remain, and not a third", 3, 1, []int{0}, "org"},
		{"a cap of three, two of two revoked: one seat remains", 3, 2, []int{0, 1}, "user"},
	}

	// refusal is what a spent invitation answers at the finish, found from the
	// first row, where nothing is revoked, and held by the rest.
	refusal := ""

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admin := newAdmin(t)
			platformToken := login(t, admin)

			// The organization the invitation names, with an administrator of its own.
			org, orgAdmin := idN(famInvOrg, 1), idN(famInvOrg, 2)

			seedUser(t, idUserB, roleMember)
			seedOrg(t, org)
			seedUserIn(t, orgAdmin, roleMember, org)
			seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", org, orgAdmin)

			orgAdminToken := seedSession(t, idN(famInvOrg, 90), orgAdmin)
			created := invOrgCreate(t, platformToken, "member", tc.cap, org, "member")

			// Every ceremony is begun now: the one past the cap too.
			bodies := invFirstRunFinishes(t, created.Code, tc.cap+2)

			var accounts []string

			finish := func(i int) reply {
				t.Helper()

				return post(t, pathRegisterEnd, bodies[i], "")
			}

			for i := range tc.registered {
				got := finish(i)
				got.expect(t, "register "+strconv.Itoa(i), http.StatusCreated, "")

				var out registered

				err := json.Unmarshal([]byte(got.body), &out)
				if err != nil {
					t.Fatalf("parse register finish: %v\n%s", err, got.body)
				}

				accounts = append(accounts, out.UserID)
			}

			for _, i := range tc.revoke {
				var got reply

				switch tc.by {
				case "user":
					got = usrRevoke(t, platformToken, accounts[i])
				case "member":
					got = del(t, pathMember+"/"+accounts[i], platformToken)
				default:
					got = del(t, pathMember+"/"+accounts[i], orgAdminToken)
				}

				got.expect(t, "revoke account "+strconv.Itoa(i), http.StatusOK, "")
			}

			expectCount(t, "users WHERE invitation_id = ? AND revoked_at IS NOT NULL", strconv.Itoa(len(tc.revoke)), created.ID)

			// The seats left are the cap's less every account made, revoked or not.
			left := tc.cap - tc.registered

			next := tc.registered

			for range left {
				finish(next).expect(t, "a seat that is left", http.StatusCreated, "")

				next++
			}

			// No seat remains: a finish begun before is refused as for a spent
			// invitation, and so is a begin.
			spent := finish(next)
			spent.expect(t, "the finish past the cap", http.StatusForbidden, invCodeInvalidReg)

			if refusal == "" {
				refusal = strconv.Itoa(spent.status) + " " + spent.errorCode()
			}

			if got := strconv.Itoa(spent.status) + " " + spent.errorCode(); got != refusal {
				t.Errorf("past the cap: %s, want what a spent invitation answers, %s", got, refusal)
			}

			beginRegistration(t, created.Code, "One more").expect(t, "the begin past the cap", http.StatusForbidden, invCodeInvalidReg)

			expectCount(t, "users WHERE invitation_id = ?", strconv.Itoa(tc.cap), created.ID)

			view := invOrgFind(t, platformToken, created.ID)
			if view.Uses != int64(tc.cap) || view.Status != invStatusExhausted {
				t.Errorf("invitation = %s with %d uses, want exhausted with %d", view.Status, view.Uses, tc.cap)
			}

			// A cap cannot be lowered below the accounts made, the revoked included.
			if tc.cap > 1 {
				patch(t, invItem(created.ID), []byte(`{"numInvites":`+strconv.Itoa(tc.cap-1)+`}`), platformToken).
					expect(t, "a cap below the accounts made", http.StatusConflict, invCodeBelowUses)
			}

			// Raising it by one makes one seat, and exactly one.
			patch(t, invItem(created.ID), []byte(`{"numInvites":`+strconv.Itoa(tc.cap+1)+`}`), platformToken).
				expect(t, "a cap raised by one", http.StatusOK, "")
			finish(next+1).expect(t, "the seat the raised cap makes", http.StatusCreated, "")
			beginRegistration(t, created.Code, "Over").expect(t, "past the raised cap", http.StatusForbidden, invCodeInvalidReg)

			expectCount(t, "users WHERE invitation_id = ?", strconv.Itoa(tc.cap+1), created.ID)
			invOrgExpectConsistent(t)
		})
	}
}

// ---- races that change who may act ---------------------------------------------

// orgAuthRace is orgRace for the world of this file: a state it builds, the
// requests that run against it released together, and what holds whatever their
// order.
type orgAuthRace struct {
	name   string
	rounds int
	build  func(t *testing.T, world orgAuth) orgRound
}

// orgPlatformAdmins is how many platform administrators are not revoked.
func orgPlatformAdmins(t *testing.T) string {
	t.Helper()

	return count(t, "users WHERE role = 'admin' AND revoked_at IS NULL")
}

// orgSecretsOfInvitationsAreSound holds that no invitation's secret is without
// its invitation, and no invitation without its secret, and that an invitation
// names an organization only through a row that has both.
func orgSecretsOfInvitationsAreSound(t *testing.T) {
	t.Helper()

	expectCount(t, "secrets WHERE kind = 'invitation' AND id NOT IN (SELECT id FROM invitations)", "0")
	expectCount(t, "invitations WHERE id NOT IN (SELECT id FROM secrets)", "0")
	expectCount(t, "invitation_orgs WHERE invitation_id NOT IN (SELECT id FROM invitations)", "0")
}

// orgRaceRevokePlatform is two platform administrators revoking each other, or
// themselves, or both, through one route or the other. However the requests
// fall, one platform administrator is left: with only the two, the second
// revocation of any kind is refused, one as a caller who is signed out and the
// other as the last.
func orgRaceRevokePlatform(name string, revoke func(t *testing.T, token, id string) reply, selfToo bool) orgAuthRace {
	return orgAuthRace{
		name: name, rounds: 10,
		build: func(t *testing.T, world orgAuth) orgRound {
			t.Helper()

			racers := []func() reply{
				func() reply { return revoke(t, world.platformToken, world.platform2) },
				func() reply { return revoke(t, world.platform2Token, world.platform) },
			}

			if selfToo {
				racers = append(racers,
					func() reply { return revoke(t, world.platformToken, world.platform) },
					func() reply { return revoke(t, world.platform2Token, world.platform2) })
			}

			return orgRound{
				racers: racers,
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					tally := orgTally(replies)

					// Whichever revoked the other first is the one left, and the
					// rest are refused as signed out, as the last one or, for one
					// already revoked, answered as the revocation it is.
					for i, got := range replies {
						if got.status != http.StatusOK {
							orgOneOf(t, "request "+strconv.Itoa(i), got, http.StatusUnauthorized, http.StatusConflict)

							if got.status == http.StatusConflict && got.errorCode() != usrCodeLastAdmin {
								t.Errorf("request %d = %d %s, want %s", i, got.status, got.body, usrCodeLastAdmin)
							}
						}
					}

					if !selfToo && tally["OK"] != 1 {
						t.Errorf("tally = %v, want exactly one OK", tally)
					}

					if selfToo && tally["OK"] < 1 {
						t.Errorf("tally = %v, want at least one OK", tally)
					}

					if got := orgPlatformAdmins(t); got != "1" {
						t.Errorf("%s platform administrators are left (%v), want exactly 1", got, tally)
					}
				},
			}
		},
	}
}

// orgRaceThemselves is two platform administrators each revoking themself: the
// first to be written is allowed, as another remains, and the second is then the last.
func orgRaceThemselves(name string, revoke func(t *testing.T, token, id string) reply) orgAuthRace {
	return orgAuthRace{
		name: name, rounds: 10,
		build: func(t *testing.T, world orgAuth) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply { return revoke(t, world.platformToken, world.platform) },
					func() reply { return revoke(t, world.platform2Token, world.platform2) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					if tally := orgTally(replies); tally["OK"] != 1 || tally["Conflict "+usrCodeLastAdmin] != 1 {
						t.Errorf("tally = %v, want one OK and one Conflict %s", tally, usrCodeLastAdmin)
					}

					if got := orgPlatformAdmins(t); got != "1" {
						t.Errorf("%s platform administrators are left, want exactly 1", got)
					}
				},
			}
		},
	}
}

// orgRevokeByUser and orgRevokeByMember are the two routes that revoke an account.
func orgRevokeByUser(t *testing.T, token, id string) reply {
	t.Helper()
	return del(t, usrItem(id), token)
}

func orgRevokeByMember(t *testing.T, token, id string) reply {
	t.Helper()

	return del(t, pathMember+"/"+id, token)
}

// orgAuthRaces are the interleavings of requests that change who may act. Each
// states what holds in terms of the outcome, never of the order.
func orgAuthRaces() []orgAuthRace {
	return []orgAuthRace{
		orgRaceRevokePlatform("platform administrators revoke each other by account", orgRevokeByUser, false),
		orgRaceRevokePlatform("platform administrators revoke each other by member", orgRevokeByMember, false),
		orgRaceRevokePlatform("platform administrators revoke each other and themselves by account", orgRevokeByUser, true),
		orgRaceRevokePlatform("platform administrators revoke each other and themselves by member", orgRevokeByMember, true),
		orgRaceThemselves("platform administrators revoke themselves by account", orgRevokeByUser),
		orgRaceThemselves("platform administrators revoke themselves by member", orgRevokeByMember),
		orgRaceAdminRevokesWhileRevoked("an administrator revokes a member while a platform administrator revokes them, by account", orgRevokeByUser),
		orgRaceAdminRevokesWhileRevoked("an administrator revokes a member while a platform administrator revokes them, by member", orgRevokeByMember),
		orgRacePromoteRevoke("a member is promoted while the other administrator revokes them", "admin", "second", orgRevokeByMember),
		orgRacePromoteRevoke("a member is promoted while a platform administrator revokes them by account", "admin", "platform2", orgRevokeByUser),
		orgRacePromoteRevoke("a member is promoted by a platform administrator while an administrator revokes them", "platform2", "admin", orgRevokeByMember),
		orgRacePromoterRevoked(),
		orgRaceInvitationCreatorRevoked("invitations are created while their creator is revoked", false),
		orgRaceInvitationCreatorRevoked("invitations naming an organization are created while their creator is revoked", true),
	}
}

// orgRaceAdminRevokesWhileRevoked: an organization's administrator revokes a member
// while a platform administrator revokes that administrator. The administrator's
// request is either made before their own revocation, and revokes the member and
// all of their secrets, or after it, and is refused as signed out and changes
// nothing: never a member revoked with their keys left, nor an administrator who
// revoked after they were revoked.
func orgRaceAdminRevokesWhileRevoked(name string, platformRevokes func(t *testing.T, token, id string) reply) orgAuthRace {
	return orgAuthRace{
		name: name, rounds: 10,
		build: func(t *testing.T, world orgAuth) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply { return del(t, pathMember+"/"+world.member, world.adminToken) },
					func() reply { return platformRevokes(t, world.platformToken, world.admin) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					replies[1].expect(t, "the platform administrator's revocation", http.StatusOK, "")
					orgOneOf(t, "the administrator's revocation", replies[0], http.StatusOK, http.StatusUnauthorized)

					expectCount(t, "users WHERE id = ? AND revoked_at IS NOT NULL", "1", world.admin)

					want := "0"
					if replies[0].status == http.StatusOK {
						want = "1"
					} else if replies[0].errorCode() != codeUnauthenticated {
						t.Errorf("the refused revocation = %s, want %s", replies[0].body, codeUnauthenticated)
					}

					expectCount(t, "users WHERE id = ? AND revoked_at IS NOT NULL", want, world.member)
					expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NOT NULL", want, world.member)
					secrets := count(t, ownedSecrets+" WHERE o.user_id = ?", world.member)
					if want == "0" {
						expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NOT NULL", "0", world.member)
					} else {
						expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NOT NULL", secrets, world.member)
					}

					// The other administrator is untouched and keeps the organization.
					expectCount(t, "users WHERE id = ? AND revoked_at IS NULL", "1", world.second)
					expectCount(t, "users WHERE revoked_at IS NOT NULL", strconv.Itoa(1+parseIntCount(want)))
				},
			}
		},
	}
}

// parseIntCount is a "0" or a "1" as a number.
func parseIntCount(text string) int {
	if text == "1" {
		return 1
	}

	return 0
}

// orgRacePromoteRevoke: the member is promoted by one account while another
// revokes them. A promotion is either first, and the member is then an
// administrator who is revoked (and listed as revoked and never as an
// administrator), or after, and is refused as 409 member_revoked and writes no
// row: no interleaving leaves a revoked account promoted by a request that saw
// them revoked. promoter is the account that promotes, and revoker is
// "second" (the other administrator, by member route) or "platform2" (by either
// route); the promoted account is the plain member.
func orgRacePromoteRevoke(name, promoter, revoker string, revoke func(t *testing.T, token, id string) reply) orgAuthRace {
	return orgAuthRace{
		name: name, rounds: 10,
		build: func(t *testing.T, world orgAuth) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply {
						return patch(t, pathMember+"/"+world.member, orgBody(true), world.token(promoter))
					},
					func() reply { return revoke(t, world.token(revoker), world.member) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					replies[1].expect(t, "the revocation", http.StatusOK, "")
					expectCount(t, "users WHERE id = ? AND revoked_at IS NOT NULL", "1", world.member)

					want := "1"

					switch {
					case replies[0].status == http.StatusOK:
					case replies[0].status == http.StatusConflict && replies[0].errorCode() == orgCodeMemberRevoked:
						want = "0"
					default:
						t.Errorf("the promotion = %d %s, want 200 or 409 %s", replies[0].status, replies[0].body, orgCodeMemberRevoked)
					}

					expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", want, world.org, world.member)

					// Listed as revoked, and never as an administrator.
					for _, m := range orgMembers(t, world.org, world.adminToken, "").Members {
						if m.ID == world.member && (m.Status != "revoked" || m.Admin) {
							t.Errorf("the member is listed as %+v, want revoked and no administrator", m)
						}
					}

					// The organization keeps its unrevoked administrators.
					expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id "+
						"WHERE a.org_id = ? AND u.revoked_at IS NULL AND a.user_id <> ?", "2", world.org, world.member)
				},
			}
		},
	}
}

// orgRacePromoterRevoked: an administrator promotes a member while a platform
// administrator revokes that administrator. The promotion is first and
// stands, or is refused as signed out and writes no row.
func orgRacePromoterRevoked() orgAuthRace {
	return orgAuthRace{
		name: "an administrator promotes a member while they are revoked", rounds: 10,
		build: func(t *testing.T, world orgAuth) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply { return patch(t, pathMember+"/"+world.member, orgBody(true), world.adminToken) },
					func() reply { return del(t, usrItem(world.admin), world.platformToken) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					replies[1].expect(t, "the revocation", http.StatusOK, "")

					want := "1"

					switch {
					case replies[0].status == http.StatusOK:
					case replies[0].status == http.StatusUnauthorized && replies[0].errorCode() == codeUnauthenticated:
						want = "0"
					default:
						t.Errorf("the promotion = %d %s, want 200 or 401", replies[0].status, replies[0].body)
					}

					expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", want, world.org, world.member)
					expectCount(t, "users WHERE revoked_at IS NOT NULL", "1")
				},
			}
		},
	}
}

// orgRaceInvitationCreatorRevoked: a platform administrator creates invitations
// (naming an organization or not) while another platform administrator revokes
// them. Each create is a 201 or a 401, a 201 has left its secret, its
// invitation and its organization row, a 401 has left none of the three, and
// the database never holds a secret of an invitation without the invitation (the
// batch is rolled back whole, as one write).
func orgRaceInvitationCreatorRevoked(name string, named bool) orgAuthRace {
	return orgAuthRace{
		name: name, rounds: 10,
		build: func(t *testing.T, world orgAuth) orgRound {
			t.Helper()

			org, role := "", ""
			if named {
				org, role = world.org, "member"
			}

			before := count(t, "invitations")

			create := func() reply {
				return post(t, pathInvitation, invOrgBody(t, "member", 1, org, role), world.platform2Token)
			}

			return orgRound{
				racers: []func() reply{
					create, create, create, create,
					func() reply { return del(t, usrItem(world.platform2), world.platformToken) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					created := 0

					for i, got := range replies[:4] {
						switch {
						case got.status == http.StatusCreated:
							created++
						case got.status == http.StatusUnauthorized && got.errorCode() == codeUnauthenticated:
						default:
							t.Errorf("create %d = %d %s, want 201 or 401", i, got.status, got.body)
						}
					}

					replies[4].expect(t, "the revocation", http.StatusOK, "")

					expectCount(t, "invitations", strconv.FormatInt(parseInt(t, before)+int64(created), 10))
					expectCount(t, "invitations WHERE created_by = ?", strconv.Itoa(created), world.platform2)
					expectCount(t, "invitation_orgs", strconv.Itoa(created*min(len(org), 1)))
					orgSecretsOfInvitationsAreSound(t)

					// Once revoked, a create is refused for good, and writes nothing.
					post(t, pathInvitation, invOrgBody(t, "member", 1, org, role), world.platform2Token).
						expect(t, "a create after the revocation", http.StatusUnauthorized, codeUnauthenticated)
					expectCount(t, "invitations", strconv.FormatInt(parseInt(t, before)+int64(created), 10))
				},
			}
		},
	}
}

// TestOrgAuthorityRaces runs each interleaving of orgAuthRaces, over and over,
// each round from a fresh world, and holds what no interleaving may produce.
//
//nolint:paralleltest // shares one database
func TestOrgAuthorityRaces(t *testing.T) {
	for _, race := range orgAuthRaces() {
		t.Run(race.name, func(t *testing.T) {
			for round := range race.rounds {
				t.Run("round "+strconv.Itoa(round), func(t *testing.T) {
					world := orgAuthNewWorld(t)
					run := race.build(t, world)

					replies := orgRelease(len(run.racers), func(i int) reply { return run.racers[i]() })
					t.Logf("%v", orgTally(replies))
					orgNo5xx(t, race.name, replies)
					run.judge(t, replies)
					orgExpectSound(t)
					orgSecretsOfInvitationsAreSound(t)
				})
			}
		})
	}
}
