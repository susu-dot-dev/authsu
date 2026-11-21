//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// orgs_test.go drives the organization routes (/api/org, /api/member and
// /api/offer) against the real Worker: the TinyGo wasm, the real D1 driver and
// the real SQLite the migrations created. The unit tests fake the database, so
// this file proves what only the real build can:
//
//   - that every conditional write of internal/store/orgs.go, members.go and
//     offers.go does what its SQL text says, for each caller standing;
//   - that races between requests (revoking against accepting, two creates at a
//     limit, two administrators demoting or leaving at once, accepting two
//     offers at once) end in a state no sequential order could not have
//     produced, and never leave a user in a revoked organization or an
//     organization without an administrator;
//   - and, through the Worker, the depth test of the design: deleting a sandbox
//     that holds agents with keys, labels and OAuth grants with access tokens
//     leaves none of them and no secret without its row.
//
// REVIEW.md categories covered: permission confusion (an outsider, a member, an
// administrator, a former administrator, a platform administrator, an agent and
// an agent of a sandbox, on every route), interleaving (above), payload size
// (the body caps, a name at its bounds in runes) and type and bound confusion
// (limits at their boundaries, an expiry that is this very second).

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Routes of the organization API.
const (
	pathOrg    = "/api/org"
	pathMember = "/api/member"
	pathOffer  = "/api/offer"
)

// Error codes of the organization API, as internal/orgs documents them.
const (
	orgCodeNotFound      = "org_not_found"
	orgCodeMemberMissing = "member_not_found"
	orgCodeOfferMissing  = "offer_not_found"
	orgCodeUserMissing   = "offer_user_not_found"
	orgCodeNotAdmin      = "org_admin_required"
	orgCodeInactive      = "org_inactive"
	orgCodeNotStandard   = "org_not_standard"
	orgCodeAlready       = "org_already_member"
	orgCodeOrgLimit      = "org_limit_reached"
	orgCodeSandboxLimit  = "sandbox_limit_reached"
	orgCodeLastAdmin     = "org_last_admin"
	orgCodeOfferExists   = "offer_exists"
	orgCodeMissingAdmin  = "missing_admin"
	orgCodeTooLarge      = "body_too_large"
	orgCodeInvalidID     = "invalid_id"

	orgMaxSandboxes = 25
	orgMaxStandard  = 5
	orgSandboxLife  = 7 * 24 * 3600
	orgNameRunes    = 256
	orgBodyCap      = 8 << 10

	// orgNone is how orgMembership reads a user who belongs to no organization.
	orgNone     = "NULL"
	orgSmallCap = 1 << 10
)

// Families of ids of this file.
const (
	orgFamUser     = "0e50"
	orgFamSession  = "0e51"
	orgFamOrg      = "0e52"
	orgFamOffer    = "0e53"
	orgFamInvite   = "0e54"
	orgFamSandbox  = "0e55"
	orgFamAgent    = "0e56"
	orgFamKey      = "0e57"
	orgFamRevoked  = "0e58"
	orgFamExpired  = "0e59"
	orgFamCreation = "0e5a"
)

// orgView, orgMember, orgOfferView and their pages are the JSON the routes serve.
type orgView struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	CreatedBy string `json:"createdBy"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt *int64 `json:"expiresAt"`
	RevokedAt *int64 `json:"revokedAt"`
	Status    string `json:"status"`
}

type orgMemberView struct {
	ID        string `json:"id"`
	OrgID     string `json:"orgId"`
	Admin     bool   `json:"admin"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"createdAt"`
	RevokedAt *int64 `json:"revokedAt"`
}

type orgOfferView struct {
	ID           string  `json:"id"`
	OrgID        string  `json:"orgId"`
	OrgName      string  `json:"orgName"`
	UserID       *string `json:"userId"`
	InvitationID *string `json:"invitationId"`
	Role         string  `json:"role"`
	CreatedBy    string  `json:"createdBy"`
	CreatedAt    int64   `json:"createdAt"`
}

type orgPage struct {
	Orgs    []orgView       `json:"orgs"`
	Members []orgMemberView `json:"members"`
	Offers  []orgOfferView  `json:"offers"`
	Next    string          `json:"next"`
}

// orgDecode strictly decodes a reply's body into a T: an unknown member fails.
func orgDecode[T any](t *testing.T, r reply) T {
	t.Helper()

	var out T

	dec := json.NewDecoder(strings.NewReader(r.body))
	dec.DisallowUnknownFields()

	err := dec.Decode(&out)
	if err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}

	return out
}

// orgWorld is a deployment with five accounts, each signed in: an administrator
// and a member of the organization org (who both belong to it), a second
// administrator of it, an outsider who belongs to nothing, and a platform
// administrator. Its sessions are seeded, so a test spends its requests on the
// routes under test.
type orgWorld struct {
	admin, member, second, outsider, platform string
	adminToken, memberToken, secondToken      string
	outsiderToken, platformToken              string

	// org is a standard organization of admin, member and second.
	org string
}

// orgUser is the n-th account of the file.
func orgUser(n int) string { return idN(orgFamUser, n) }

// orgNewWorld resets the deployment and builds the world above.
func orgNewWorld(t *testing.T) orgWorld {
	t.Helper()

	reset(t)
	seedInvitation(t, idInvitationA, 500)

	world := orgWorld{
		admin: orgUser(1), member: orgUser(2), second: orgUser(3), outsider: orgUser(4), platform: orgUser(5),
		org: idN(orgFamOrg, 1),
	}

	for i, id := range []string{world.admin, world.member, world.second, world.outsider, world.platform} {
		role := roleMember
		if id == world.platform {
			role = roleAdmin
		}

		seedUser(t, id, role)

		token := seedSession(t, idN(orgFamSession, i+1), id)

		switch id {
		case world.admin:
			world.adminToken = token
		case world.member:
			world.memberToken = token
		case world.second:
			world.secondToken = token
		case world.outsider:
			world.outsiderToken = token
		default:
			world.platformToken = token
		}
	}

	orgSeedStandard(t, world.org, world.admin)
	orgJoin(t, world.org, world.admin, true)
	orgJoin(t, world.org, world.member, false)
	orgJoin(t, world.org, world.second, true)

	return world
}

// orgSeedStandard inserts an active standard organization made by creator.
func orgSeedStandard(t *testing.T, id, creator string) {
	t.Helper()

	seed(t, insertOrg, id, schemaKindStandard, "Acme", creator, nil, nil, int64(1_700_000_000))
}

// orgJoin makes user a member of org, and an administrator of it when admin.
func orgJoin(t *testing.T, org, user string, admin bool) {
	t.Helper()

	seed(t, "UPDATE users SET org_id = ? WHERE id = ?", org, user)

	if admin {
		seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", org, user)
	}
}

// orgOfferSeed inserts an offer of org to user with role.
func orgOfferSeed(t *testing.T, id, org, user, role, creator string) {
	t.Helper()

	seed(t, "INSERT INTO org_offers (id, org_id, user_id, role, created_by, created_at) VALUES (?, ?, ?, ?, ?, 1)",
		id, org, user, role, creator)
}

// orgRelease starts n goroutines at once, each running fn(i), and returns their
// replies in order.
func orgRelease(n int, fn func(i int) reply) []reply {
	out := make([]reply, n)
	start := make(chan struct{})

	var group sync.WaitGroup

	for i := range n {
		group.Go(func() {
			<-start

			out[i] = fn(i)
		})
	}

	close(start)
	group.Wait()

	return out
}

// orgTally counts replies by "status code".
func orgTally(replies []reply) map[string]int {
	out := map[string]int{}

	for _, r := range replies {
		key := http.StatusText(r.status)
		if code := r.errorCode(); code != "" {
			key += " " + code
		}

		out[key]++
	}

	return out
}

// orgNo5xx fails the test on any 5xx reply.
func orgNo5xx(t *testing.T, what string, replies []reply) {
	t.Helper()

	for _, r := range replies {
		if r.status >= http.StatusInternalServerError {
			t.Errorf("%s: %d %s, want no 5xx", what, r.status, r.body)
		}
	}
}

// orgJSON is a JSON object body of the given members.
func orgJSON(t *testing.T, members map[string]any) []byte {
	t.Helper()

	return mustJSON(t, members)
}

func orgCreateBody(t *testing.T, kind, name string) []byte {
	t.Helper()

	return orgJSON(t, map[string]any{"kind": kind, "name": name})
}

func orgCreate(t *testing.T, token, kind, name string) reply {
	t.Helper()

	return post(t, pathOrg, orgCreateBody(t, kind, name), token)
}

func orgOfferBody(t *testing.T, user, role string) []byte {
	t.Helper()

	return orgJSON(t, map[string]any{"userId": user, "role": role})
}

func orgItem(id string) string { return pathOrg + "/" + id }

// orgIsMember reports whether the user belongs to the organization, as a number.
func orgMembership(t *testing.T, user string) string {
	t.Helper()

	return scalar(t, "SELECT ifnull(org_id, '"+orgNone+"') FROM users WHERE id = ?", user)
}

// orgAdminCount is how many administrator rows the organization has.
func orgAdminCount(t *testing.T, org string) string {
	t.Helper()

	return count(t, "org_admins WHERE org_id = ?", org)
}

// ---- access ----------------------------------------------------------------

// TestOrgRoutesNeedASession: signed out is 401 on every route and writes
// nothing; a revoked account's session is 401 as well.
//
//nolint:paralleltest // shares one database
func TestOrgRoutesNeedASession(t *testing.T) {
	world := orgNewWorld(t)
	orgOfferSeed(t, idN(orgFamOffer, 1), world.org, world.outsider, "member", world.admin)

	routes := []struct {
		name, method, path string
		body               []byte
	}{
		{"create", http.MethodPost, pathOrg, orgCreateBody(t, "sandbox", "x")},
		{"list", http.MethodGet, pathOrg, nil},
		{"get", http.MethodGet, orgItem(world.org), nil},
		{"rename", http.MethodPatch, orgItem(world.org), []byte(`{"name":"x"}`)},
		{"revoke", http.MethodDelete, orgItem(world.org), nil},
		{"members", http.MethodGet, orgItem(world.org) + "/member", nil},
		{"promote", http.MethodPatch, pathMember + "/" + world.member, []byte(`{"admin":true}`)},
		{"remove", http.MethodDelete, pathMember + "/" + world.member, nil},
		{"offer", http.MethodPost, orgItem(world.org) + "/offer", orgOfferBody(t, world.outsider, "member")},
		{"org offers", http.MethodGet, orgItem(world.org) + "/offer", nil},
		{"my offers", http.MethodGet, pathOffer, nil},
		{"accept", http.MethodPost, pathOffer + "/" + idN(orgFamOffer, 1) + "/accept", nil},
		{"decline", http.MethodDelete, pathOffer + "/" + idN(orgFamOffer, 1), nil},
	}

	for _, rt := range routes {
		t.Run("signed out "+rt.name, func(t *testing.T) {
			got := send(t, request{method: rt.method, path: rt.path, body: rt.body})
			got.expect(t, rt.name, http.StatusUnauthorized, codeUnauthenticated)
		})
	}

	expectCount(t, "orgs", "1")
	expectCount(t, "org_offers", "1")
	expectCount(t, "org_admins", "2")
	expectCount(t, "users WHERE org_id IS NOT NULL", "3")

	// A revoked account is told it is not signed in, on a read and on a write.
	seed(t, "UPDATE users SET revoked_at = strftime('%s','now') WHERE id = ?", world.member)
	get(t, pathOrg, world.memberToken).expect(t, "revoked, list", http.StatusUnauthorized, codeUnauthenticated)
	orgCreate(t, world.memberToken, "sandbox", "x").expect(t, "revoked, create", http.StatusUnauthorized, codeUnauthenticated)
}

// ---- create ----------------------------------------------------------------

// TestOrgCreateStandard: the creator becomes a member and an administrator in
// one write, the response is exactly the stored row, and the account then
// belongs to the organization it made.
//
//nolint:paralleltest // shares one database
func TestOrgCreateStandard(t *testing.T) {
	world := orgNewWorld(t)

	before := time.Now().Unix()
	got := orgCreate(t, world.outsiderToken, "standard", "Mine")
	after := time.Now().Unix()

	got.expect(t, "create", http.StatusCreated, "")

	if got.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got.header.Get("Cache-Control"))
	}

	view := orgDecode[orgView](t, got)

	if view.Kind != "standard" || view.Name != "Mine" || view.CreatedBy != world.outsider || view.Status != "active" ||
		view.ExpiresAt != nil || view.RevokedAt != nil || view.CreatedAt < before || view.CreatedAt > after {
		t.Errorf("created = %+v, want an active standard organization of the outsider made in [%d, %d]", view, before, after)
	}

	expectCount(t, "orgs WHERE id = ? AND kind = 'standard' AND name = 'Mine' AND created_by = ?", "1", view.ID, world.outsider)
	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", view.ID, world.outsider)

	if got := orgMembership(t, world.outsider); got != view.ID {
		t.Errorf("the creator's org_id = %s, want %s", got, view.ID)
	}

	// Already a member of one: no second, and nothing written.
	orgCreate(t, world.outsiderToken, "standard", "Again").expect(t, "second standard", http.StatusConflict, orgCodeAlready)
	orgCreate(t, world.adminToken, "standard", "Again").expect(t, "member of another", http.StatusConflict, orgCodeAlready)
	expectCount(t, "orgs", "2")

	// A sandbox is not refused for belonging to an organization.
	orgCreate(t, world.adminToken, "sandbox", "Scratch").expect(t, "sandbox of a member", http.StatusCreated, "")
}

// TestOrgCreateSandbox: a sandbox expires a week after it is made, its creator
// administers it and does not belong to it, and the response is the stored row.
//
//nolint:paralleltest // shares one database
func TestOrgCreateSandbox(t *testing.T) {
	world := orgNewWorld(t)

	before := time.Now().Unix()
	got := orgCreate(t, world.outsiderToken, "sandbox", "Scratch")
	after := time.Now().Unix()

	got.expect(t, "create", http.StatusCreated, "")

	view := orgDecode[orgView](t, got)

	if view.Kind != "sandbox" || view.Status != "active" || view.RevokedAt != nil || view.ExpiresAt == nil ||
		*view.ExpiresAt < before+orgSandboxLife || *view.ExpiresAt > after+orgSandboxLife {
		t.Errorf("created = %+v, want an active sandbox expiring a week after [%d, %d]", view, before, after)
	}

	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", view.ID, world.outsider)

	if got := orgMembership(t, world.outsider); got != orgNone {
		t.Errorf("the sandbox's creator belongs to %s, want no organization", got)
	}

	// Its administrator reads it, and a member of no organization has it listed.
	get(t, orgItem(view.ID), world.outsiderToken).expect(t, "read", http.StatusOK, "")

	page := orgDecode[orgPage](t, get(t, pathOrg, world.outsiderToken))
	if len(page.Orgs) != 1 || page.Orgs[0].ID != view.ID {
		t.Errorf("list = %+v, want the sandbox", page.Orgs)
	}

	// A sandbox has no members and receives no offers.
	get(t, orgItem(view.ID)+"/member", world.outsiderToken).expect(t, "members", http.StatusConflict, orgCodeNotStandard)
	get(t, orgItem(view.ID)+"/offer", world.outsiderToken).expect(t, "offers", http.StatusConflict, orgCodeNotStandard)
	post(t, orgItem(view.ID)+"/offer", orgOfferBody(t, world.member, "member"), world.outsiderToken).
		expect(t, "offer", http.StatusConflict, orgCodeNotStandard)
	expectCount(t, "org_offers", "0")
}

// TestOrgCreateInput: what a create refuses before anything is written, and the
// bounds of a name in runes, not bytes.
//
//nolint:paralleltest // shares one database
func TestOrgCreateInput(t *testing.T) {
	world := orgNewWorld(t)

	bad := []struct {
		name string
		body string
		code string
	}{
		{"no body", ``, "empty_body"},
		{"not JSON", `{`, "invalid_json"},
		{"no kind", `{"name":"x"}`, "invalid_org_kind"},
		{"an unknown kind", `{"kind":"enterprise","name":"x"}`, "invalid_org_kind"},
		{"a kind in another case", `{"kind":"Sandbox","name":"x"}`, "invalid_org_kind"},
		{"a kind with a space", `{"kind":" sandbox","name":"x"}`, "invalid_org_kind"},
		{"no name", `{"kind":"sandbox"}`, "invalid_org_name"},
		{"an empty name", `{"kind":"sandbox","name":""}`, "invalid_org_name"},
		{"a name with NUL", `{"kind":"sandbox","name":"a\u0000b"}`, "invalid_org_name"},
		{"a name of 257 runes", `{"kind":"sandbox","name":"` + strings.Repeat("x", orgNameRunes+1) + `"}`, "invalid_org_name"},
		{"an expiry of the client's choosing", `{"kind":"sandbox","name":"x","expiresAt":1}`, "unknown_field"},
		{"a creator of the client's choosing", `{"kind":"sandbox","name":"x","createdBy":"` + world.admin + `"}`, "unknown_field"},
		{"a repeated kind", `{"kind":"sandbox","kind":"standard","name":"x"}`, "duplicate_field"},
		{"a kind that is a number", `{"kind":1,"name":"x"}`, "invalid_field_type"},
	}

	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			post(t, pathOrg, []byte(tc.body), world.outsiderToken).expect(t, tc.name, http.StatusBadRequest, tc.code)
		})
	}

	expectCount(t, "orgs", "1")

	for name, value := range map[string]string{
		"256 ASCII runes":                strings.Repeat("x", orgNameRunes),
		"256 four-byte runes (1024 B)":   strings.Repeat("\U0001F600", orgNameRunes),
		"one rune":                       "x",
		"a name with a quote and a tab":  "a\"b\\c",
		"a name that is a path or a tag": "../<b>x</b>",
	} {
		t.Run("accepts "+name, func(t *testing.T) {
			got := orgCreate(t, world.outsiderToken, "sandbox", value)
			got.expect(t, name, http.StatusCreated, "")

			view := orgDecode[orgView](t, got)
			if view.Name != value {
				t.Errorf("name = %q, want it as sent", view.Name)
			}

			expectCount(t, "orgs WHERE id = ? AND name = ?", "1", view.ID, value)
		})
	}
}

// ---- limits ----------------------------------------------------------------

// orgSeedSandboxes inserts n sandboxes of creator that expire at expires, with
// administrator rows, in the id family fam.
func orgSeedSandboxes(t *testing.T, fam string, n int, creator string, expires int64) {
	t.Helper()

	for i := range n {
		seed(t, insertOrg, idN(fam, i+1), schemaKindSandbox, "seeded", creator, expires, nil, int64(1_700_000_000))
		seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", idN(fam, i+1), creator)
	}
}

// TestOrgSandboxLimit: 25 sandboxes that have not expired, no more; an expired
// one does not count, a deleted one does not, and two creates at the limit
// cannot both pass.
//
//nolint:paralleltest // shares one database
func TestOrgSandboxLimit(t *testing.T) {
	world := orgNewWorld(t)
	now := time.Now().Unix()

	// Twelve that expired are no part of the count.
	orgSeedSandboxes(t, orgFamExpired, 12, world.outsider, now-1)
	orgSeedSandboxes(t, orgFamSandbox, orgMaxSandboxes-2, world.outsider, now+3600)

	// 23 live ones: two creates at once, one place left... and one more.
	first := orgCreate(t, world.outsiderToken, "sandbox", "24th")
	first.expect(t, "24th", http.StatusCreated, "")

	replies := orgRelease(4, func(int) reply { return orgCreate(t, world.outsiderToken, "sandbox", "race") })
	orgNo5xx(t, "creates at the limit", replies)

	tally := orgTally(replies)
	if tally["Created"] != 1 || tally["Conflict "+orgCodeSandboxLimit] != 3 {
		t.Errorf("tally = %v, want one Created and three Conflict %s", tally, orgCodeSandboxLimit)
	}

	expectCount(t, "orgs WHERE kind = 'sandbox' AND created_by = ? AND expires_at > strftime('%s','now')", "25", world.outsider)

	orgCreate(t, world.outsiderToken, "sandbox", "26th").expect(t, "26th", http.StatusConflict, orgCodeSandboxLimit)

	// The limit is per user: another account has all 25 of its own.
	orgCreate(t, world.memberToken, "sandbox", "other user").expect(t, "another user", http.StatusCreated, "")

	// Deleting one makes room, and only one.
	del(t, orgItem(first.mustView(t).ID), world.outsiderToken).expect(t, "delete", http.StatusOK, "")
	orgCreate(t, world.outsiderToken, "sandbox", "again").expect(t, "after delete", http.StatusCreated, "")
	orgCreate(t, world.outsiderToken, "sandbox", "over").expect(t, "over again", http.StatusConflict, orgCodeSandboxLimit)

	// A sandbox that expires this very second no longer counts.
	seed(t, "UPDATE orgs SET expires_at = strftime('%s','now') WHERE id = ?", idN(orgFamSandbox, 1))
	orgCreate(t, world.outsiderToken, "sandbox", "after expiry").expect(t, "expired one", http.StatusCreated, "")
}

// mustView decodes a created organization.
func (r reply) mustView(t *testing.T) orgView {
	t.Helper()

	return orgDecode[orgView](t, r)
}

// TestOrgStandardLimit: five standard organizations in a lifetime, revoked ones
// included, and the count is not given back by revoking.
//
//nolint:paralleltest // shares one database
func TestOrgStandardLimit(t *testing.T) {
	world := orgNewWorld(t)

	// Four organizations the outsider made earlier and that were revoked, which
	// leaves them belonging to none.
	for i := range orgMaxStandard - 1 {
		seed(t, insertOrg, idN(orgFamRevoked, i+1), schemaKindStandard, "old", world.outsider, nil, int64(1_700_000_001),
			int64(1_700_000_000))
	}

	// Two creates at the limit: the fifth and a sixth. Either one may win, only
	// one does, and the loser is told why.
	replies := orgRelease(2, func(int) reply { return orgCreate(t, world.outsiderToken, "standard", "race") })
	orgNo5xx(t, "creates at the limit", replies)

	tally := orgTally(replies)
	if tally["Created"] != 1 || len(tally) != 2 {
		t.Fatalf("tally = %v, want one Created and one refusal", tally)
	}

	if tally["Conflict "+orgCodeOrgLimit]+tally["Conflict "+orgCodeAlready] != 1 {
		t.Errorf("tally = %v, want the loser told org_limit_reached or org_already_member", tally)
	}

	expectCount(t, "orgs WHERE created_by = ? AND kind = 'standard'", "5", world.outsider)

	// Revoking the fifth does not give its place back.
	var made orgView

	for _, r := range replies {
		if r.status == http.StatusCreated {
			made = orgDecode[orgView](t, r)
		}
	}

	del(t, orgItem(made.ID), world.outsiderToken).expect(t, "revoke", http.StatusOK, "")
	orgCreate(t, world.outsiderToken, "standard", "sixth").expect(t, "sixth", http.StatusConflict, orgCodeOrgLimit)
	expectCount(t, "orgs WHERE created_by = ? AND kind = 'standard'", "5", world.outsider)

	// And a sandbox is a different count.
	orgCreate(t, world.outsiderToken, "sandbox", "sbx").expect(t, "sandbox", http.StatusCreated, "")
}

// ---- reads and standing -----------------------------------------------------

// TestOrgStanding is the permission-confusion matrix: for each account's
// standing to the organization, what each route that names it answers. An
// outsider is told 404 as for an id that does not exist; a member is told 403
// for what only an administrator may do; a platform administrator may do all.
//
//nolint:paralleltest // shares one database
func TestOrgStanding(t *testing.T) {
	world := orgNewWorld(t)

	type outcome struct {
		status int
		code   string
	}

	ok := outcome{http.StatusOK, ""}
	hidden := outcome{http.StatusNotFound, orgCodeNotFound}
	denied := outcome{http.StatusForbidden, orgCodeNotAdmin}

	actors := []struct {
		name, token string
		get, rename outcome
		members     outcome
		offers      outcome
	}{
		{"an administrator", world.adminToken, ok, ok, ok, ok},
		{"a second administrator", world.secondToken, ok, ok, ok, ok},
		{"a member", world.memberToken, ok, denied, ok, denied},
		{"an outsider", world.outsiderToken, hidden, hidden, hidden, hidden},
		{"a platform administrator", world.platformToken, ok, ok, ok, ok},
	}

	for _, actor := range actors {
		t.Run(actor.name, func(t *testing.T) {
			check := func(what string, got reply, want outcome) {
				t.Helper()

				got.expect(t, what, want.status, want.code)
			}

			check("get", get(t, orgItem(world.org), actor.token), actor.get)
			check("rename", patch(t, orgItem(world.org), []byte(`{"name":"Acme"}`), actor.token), actor.rename)
			check("members", get(t, orgItem(world.org)+"/member", actor.token), actor.members)
			check("offers", get(t, orgItem(world.org)+"/offer", actor.token), actor.offers)
		})
	}

	// A member who is not an administrator cannot change the organization or its
	// people: nothing below changes a row.
	for what, got := range map[string]reply{
		"revoke":  del(t, orgItem(world.org), world.memberToken),
		"offer":   post(t, orgItem(world.org)+"/offer", orgOfferBody(t, world.outsider, "member"), world.memberToken),
		"promote": patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.memberToken),
		"demote":  patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.memberToken),
		"remove":  del(t, pathMember+"/"+world.second, world.memberToken),
	} {
		got.expect(t, what+" by a member", http.StatusForbidden, orgCodeNotAdmin)
	}

	for what, got := range map[string]reply{
		"revoke":  del(t, orgItem(world.org), world.outsiderToken),
		"offer":   post(t, orgItem(world.org)+"/offer", orgOfferBody(t, world.outsider, "member"), world.outsiderToken),
		"promote": patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.outsiderToken),
		"remove":  del(t, pathMember+"/"+world.member, world.outsiderToken),
	} {
		code := orgCode(what)
		got.expect(t, what+" by an outsider", http.StatusNotFound, code)
	}

	expectCount(t, "orgs WHERE revoked_at IS NOT NULL", "0")
	expectCount(t, "org_admins WHERE org_id = ?", "2", world.org)
	expectCount(t, "users WHERE org_id = ?", "3", world.org)
	expectCount(t, "org_offers", "0")
	expectCount(t, "orgs WHERE name <> 'Acme'", "0")

	// A missing organization is the outsider's answer, byte for byte.
	missing := get(t, orgItem(idMissing), world.adminToken)
	hiddenOrg := get(t, orgItem(idN(orgFamOrg, 2)), world.adminToken)
	missing.expect(t, "missing", http.StatusNotFound, orgCodeNotFound)

	if missing.body != hiddenOrg.body {
		t.Errorf("a missing organization (%q) differs from one that is not there (%q)", missing.body, hiddenOrg.body)
	}

	orgOutsiderSees := get(t, orgItem(world.org), world.outsiderToken)
	if orgOutsiderSees.body != missing.body {
		t.Errorf("an outsider is told %q, a missing id is told %q", orgOutsiderSees.body, missing.body)
	}
}

// orgCode is the code of the 404 an outsider is told on each route of
// TestOrgStanding: an organization is hidden, and so is a user in one.
func orgCode(what string) string {
	if what == "promote" || what == "remove" || what == "demote" {
		return orgCodeMemberMissing
	}

	return orgCodeNotFound
}

// TestOrgListAndPaging: a member lists their organization, an outsider none, a
// platform administrator all of them including revoked ones and sandboxes, with
// keyset paging that neither skips nor repeats a row.
//
//nolint:paralleltest // shares one database
func TestOrgListAndPaging(t *testing.T) {
	world := orgNewWorld(t)

	// Seven more organizations nobody here belongs to, one of them revoked, and
	// three sandboxes of the outsider.
	for i := range 7 {
		seed(t, insertOrg, idN(orgFamOrg, 10+i), schemaKindStandard, "other", world.platform, nil, nil, int64(1_700_000_000))
	}

	seed(t, "UPDATE orgs SET revoked_at = 5 WHERE id = ?", idN(orgFamOrg, 10))
	orgSeedSandboxes(t, orgFamSandbox, 3, world.outsider, time.Now().Unix()+3600)

	list := func(token, query string) orgPage {
		t.Helper()

		got := get(t, pathOrg+query, token)
		got.expect(t, "list "+query, http.StatusOK, "")

		return orgDecode[orgPage](t, got)
	}

	if page := list(world.memberToken, ""); len(page.Orgs) != 1 || page.Orgs[0].ID != world.org {
		t.Errorf("a member lists %+v, want only their organization", page.Orgs)
	}

	// An administrator who also belongs to the organization is listed once, though
	// two of the three sources the list reads from name it.
	if page := list(world.adminToken, ""); len(page.Orgs) != 1 || page.Orgs[0].ID != world.org {
		t.Errorf("an administrator who is a member lists %+v, want their organization once", page.Orgs)
	}

	if page := list(world.outsiderToken, ""); len(page.Orgs) != 3 {
		t.Errorf("an outsider lists %d, want only their three sandboxes", len(page.Orgs))
	}

	// The outsider's three sandboxes, one to a page, come newest first and none is
	// skipped or repeated: each source of the list is cut at the cursor.
	var ids []string

	for cursor, pages := "", 0; pages < 5; pages++ {
		query := "?limit=1"
		if cursor != "" {
			query += "&cursor=" + cursor
		}

		page := list(world.outsiderToken, query)
		for _, org := range page.Orgs {
			ids = append(ids, org.ID)
		}

		if cursor = page.Next; cursor == "" {
			break
		}
	}

	if want := []string{idN(orgFamSandbox, 3), idN(orgFamSandbox, 2), idN(orgFamSandbox, 1)}; !slices.Equal(ids, want) {
		t.Errorf("the outsider paged through %v, want %v", ids, want)
	}

	// All of them, 11 in all, three at a time: ids newest first, none twice.
	seen := map[string]bool{}
	cursor := ""

	for pages := 0; ; pages++ {
		query := "?limit=3"
		if cursor != "" {
			query += "&cursor=" + cursor
		}

		page := list(world.platformToken, query)

		for _, org := range page.Orgs {
			if seen[org.ID] {
				t.Errorf("%s listed twice", org.ID)
			}

			seen[org.ID] = true
		}

		if page.Next == "" {
			break
		}

		cursor = page.Next

		if pages > 6 {
			t.Fatal("paging does not end")
		}
	}

	if len(seen) != 11 {
		t.Errorf("a platform administrator paged through %d organizations, want all 11", len(seen))
	}

	for _, query := range []string{"?limit=0", "?limit=101", "?limit=x", "?limit=1&limit=2", "?cursor=nope", "?cursor="} {
		get(t, pathOrg+query, world.platformToken).expect(t, query, http.StatusBadRequest, "")
	}
}

// ---- change ----------------------------------------------------------------

// TestOrgRenameAndRevoke: renaming, revoking and the platform administrator's
// override. A revoked organization releases its members and deletes its offers
// and administrator rows; it cannot be renamed; revoking twice is a no-op for a
// platform administrator and a 404 for a former administrator.
//
//nolint:paralleltest // shares one database
func TestOrgRenameAndRevoke(t *testing.T) {
	world := orgNewWorld(t)
	orgOfferSeed(t, idN(orgFamOffer, 1), world.org, world.outsider, "admin", world.admin)

	renamed := patch(t, orgItem(world.org), []byte(`{"name":"Renamed"}`), world.adminToken)
	renamed.expect(t, "rename", http.StatusOK, "")

	if view := orgDecode[orgView](t, renamed); view.Name != "Renamed" || view.Status != "active" {
		t.Errorf("renamed = %+v", view)
	}

	patch(t, orgItem(world.org), []byte(`{}`), world.adminToken).expect(t, "no name", http.StatusBadRequest, "invalid_org_name")
	patch(t, orgItem(world.org), []byte(`{"name":"x","kind":"sandbox"}`), world.adminToken).
		expect(t, "a kind", http.StatusBadRequest, "unknown_field")
	patch(t, orgItem(world.org), []byte(`{"name":"`+strings.Repeat("x", orgNameRunes+1)+`"}`), world.adminToken).
		expect(t, "a long name", http.StatusBadRequest, "invalid_org_name")

	// The platform administrator renames and revokes anything.
	patch(t, orgItem(world.org), []byte(`{"name":"By platform"}`), world.platformToken).
		expect(t, "platform rename", http.StatusOK, "")

	revoked := del(t, orgItem(world.org), world.adminToken)
	revoked.expect(t, "revoke", http.StatusOK, "")

	view := orgDecode[orgView](t, revoked)
	if view.Status != "revoked" || view.RevokedAt == nil || view.Kind != "standard" || view.Name != "By platform" {
		t.Errorf("revoked = %+v", view)
	}

	expectCount(t, "users WHERE org_id IS NOT NULL", "0")
	expectCount(t, "org_admins", "0")
	expectCount(t, "org_offers", "0")
	expectCount(t, "orgs WHERE id = ? AND revoked_at IS NOT NULL", "1", world.org)
	expectCount(t, "users", "5")

	// Final: cannot be renamed, by anyone who can still see it.
	patch(t, orgItem(world.org), []byte(`{"name":"Revived"}`), world.platformToken).
		expect(t, "rename revoked", http.StatusConflict, orgCodeInactive)

	// Former administrators and members no longer see it at all.
	for _, token := range []string{world.adminToken, world.memberToken, world.secondToken} {
		get(t, orgItem(world.org), token).expect(t, "former member", http.StatusNotFound, orgCodeNotFound)
		del(t, orgItem(world.org), token).expect(t, "former revoke", http.StatusNotFound, orgCodeNotFound)
	}

	// The platform administrator revokes again: success, and the time stays.
	first := *view.RevokedAt

	again := del(t, orgItem(world.org), world.platformToken)
	again.expect(t, "revoke again", http.StatusOK, "")

	if got := orgDecode[orgView](t, again); got.RevokedAt == nil || *got.RevokedAt != first {
		t.Errorf("revoked again at %v, want the first time %d", got.RevokedAt, first)
	}

	// The members can now create and join elsewhere; the revoked one still
	// counts for its creator's limit.
	orgCreate(t, world.memberToken, "standard", "Fresh").expect(t, "create after release", http.StatusCreated, "")
	expectCount(t, "orgs WHERE created_by = ? AND kind = 'standard'", "1", world.member)
	expectCount(t, "users WHERE org_id IS NOT NULL", "1")
}

// ---- members ---------------------------------------------------------------

// orgMembers reads GET /api/org/{id}/member as the token.
func orgMembers(t *testing.T, org, token, query string) orgPage {
	t.Helper()

	got := get(t, orgItem(org)+"/member"+query, token)
	got.expect(t, "members", http.StatusOK, "")

	return orgDecode[orgPage](t, got)
}

// TestOrgMembers: the member list with who administers, a revoked member who
// stays listed, promoting, demoting, removing and leaving.
//
//nolint:paralleltest // shares one database
func TestOrgMembers(t *testing.T) {
	world := orgNewWorld(t)

	page := orgMembers(t, world.org, world.memberToken, "")
	if len(page.Members) != 3 || page.Next != "" {
		t.Fatalf("members = %+v, want three on one page", page.Members)
	}

	admins := map[string]bool{}
	for _, m := range page.Members {
		admins[m.ID] = m.Admin

		if m.OrgID != world.org || m.Status != "active" || m.RevokedAt != nil {
			t.Errorf("member %+v, want an active member of the organization", m)
		}
	}

	if !admins[world.admin] || !admins[world.second] || admins[world.member] {
		t.Errorf("administrators = %v, want admin and second, not member", admins)
	}

	// Paged, newest first, none skipped.
	first := orgMembers(t, world.org, world.adminToken, "?limit=2")
	if len(first.Members) != 2 || first.Next == "" {
		t.Fatalf("first page = %+v", first)
	}

	rest := orgMembers(t, world.org, world.adminToken, "?limit=2&cursor="+first.Next)
	if len(rest.Members) != 1 || rest.Next != "" {
		t.Fatalf("second page = %+v", rest)
	}

	// Promote and demote, each idempotent.
	promote := patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.adminToken)
	promote.expect(t, "promote", http.StatusOK, "")

	if m := orgDecode[orgMemberView](t, promote); !m.Admin || m.ID != world.member {
		t.Errorf("promoted = %+v", m)
	}

	patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.adminToken).expect(t, "again", http.StatusOK, "")
	expectCount(t, "org_admins WHERE org_id = ?", "3", world.org)

	demote := patch(t, pathMember+"/"+world.member, []byte(`{"admin":false}`), world.secondToken)
	demote.expect(t, "demote", http.StatusOK, "")

	if m := orgDecode[orgMemberView](t, demote); m.Admin {
		t.Errorf("demoted = %+v", m)
	}

	patch(t, pathMember+"/"+world.member, []byte(`{"admin":false}`), world.adminToken).expect(t, "demote again", http.StatusOK, "")
	expectCount(t, "org_admins WHERE org_id = ?", "2", world.org)

	// A member who is not in any organization is not found, and so is one in an
	// organization the caller cannot see.
	patch(t, pathMember+"/"+world.outsider, []byte(`{"admin":true}`), world.adminToken).
		expect(t, "outsider", http.StatusNotFound, orgCodeMemberMissing)
	patch(t, pathMember+"/"+idMissing, []byte(`{"admin":true}`), world.adminToken).
		expect(t, "missing", http.StatusNotFound, orgCodeMemberMissing)

	for _, body := range []string{`{}`, `{"admin":null}`} {
		patch(t, pathMember+"/"+world.member, []byte(body), world.adminToken).
			expect(t, body, http.StatusBadRequest, orgCodeMissingAdmin)
	}

	for _, body := range []string{`{"admin":"yes"}`, `{"admin":1}`, `{"admin":true,"orgId":"x"}`, ``} {
		patch(t, pathMember+"/"+world.member, []byte(body), world.adminToken).expect(t, body, http.StatusBadRequest, "")
	}

	// Another organization's administrator has no say in this one's members.
	other := idN(orgFamOrg, 2)
	orgSeedStandard(t, other, world.outsider)
	orgJoin(t, other, world.outsider, true)

	patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.outsiderToken).
		expect(t, "foreign admin promotes", http.StatusNotFound, orgCodeMemberMissing)
	del(t, pathMember+"/"+world.member, world.outsiderToken).
		expect(t, "foreign admin removes", http.StatusNotFound, orgCodeMemberMissing)
	expectCount(t, "users WHERE org_id = ?", "3", world.org)

	// An administrator removes a member; a member cannot remove another.
	del(t, pathMember+"/"+world.second, world.memberToken).expect(t, "member removes", http.StatusForbidden, orgCodeNotAdmin)

	removed := del(t, pathMember+"/"+world.member, world.adminToken)
	removed.expect(t, "remove", http.StatusOK, "")

	if orgMembership(t, world.member) != orgNone {
		t.Errorf("the removed member still belongs to %s", orgMembership(t, world.member))
	}

	del(t, pathMember+"/"+world.member, world.adminToken).expect(t, "remove again", http.StatusNotFound, orgCodeMemberMissing)

	// Removing an administrator removes their administration with them, and
	// leaving is removing oneself.
	left := del(t, pathMember+"/"+world.second, world.secondToken)
	left.expect(t, "leave", http.StatusOK, "")

	if m := orgDecode[orgMemberView](t, left); m.Admin || m.ID != world.second {
		t.Errorf("left = %+v", m)
	}

	expectCount(t, "org_admins WHERE org_id = ?", "1", world.org)
	expectCount(t, "org_admins WHERE user_id = ?", "0", world.second)

	// The last administrator can neither leave, be removed nor be demoted, by
	// themself or by a platform administrator, and nothing changes.
	for what, got := range map[string]reply{
		"leave":            del(t, pathMember+"/"+world.admin, world.adminToken),
		"remove, platform": del(t, pathMember+"/"+world.admin, world.platformToken),
		"demote":           patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.adminToken),
		"demote, platform": patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.platformToken),
	} {
		got.expect(t, "the last administrator: "+what, http.StatusConflict, orgCodeLastAdmin)
	}

	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", world.org, world.admin)
	expectCount(t, "users WHERE org_id = ?", "1", world.org)

	// A revoked administrator does not count as one: the other may not leave.
	orgJoin(t, world.org, world.second, true)
	seed(t, "UPDATE users SET org_id = ? WHERE id = ?", world.org, world.second)
	seed(t, "UPDATE users SET revoked_at = 5 WHERE id = ?", world.second)

	del(t, pathMember+"/"+world.admin, world.adminToken).expect(t, "leave, other revoked", http.StatusConflict, orgCodeLastAdmin)

	// A revoked member is listed as such, and may be removed by an administrator
	// (and, being revoked, cannot remove themself: they cannot sign in).
	page = orgMembers(t, world.org, world.adminToken, "")

	var seenRevoked bool

	for _, m := range page.Members {
		if m.ID == world.second {
			seenRevoked = m.Status == "revoked" && m.RevokedAt != nil && m.Admin
		}
	}

	if !seenRevoked {
		t.Errorf("members = %+v, want the revoked account listed as revoked", page.Members)
	}

	del(t, pathMember+"/"+world.second, world.adminToken).expect(t, "remove a revoked member", http.StatusOK, "")
	expectCount(t, "org_admins WHERE org_id = ?", "1", world.org)
}

// ---- offers ----------------------------------------------------------------

// TestOrgOffers: offering, the refusals, the lists, accepting and declining.
//
//nolint:paralleltest // shares one database
func TestOrgOffers(t *testing.T) {
	world := orgNewWorld(t)
	offers := orgItem(world.org) + "/offer"

	made := post(t, offers, orgOfferBody(t, world.outsider, "admin"), world.adminToken)
	made.expect(t, "offer", http.StatusCreated, "")

	offer := orgDecode[orgOfferView](t, made)
	if offer.OrgID != world.org || offer.OrgName != "Acme" || offer.Role != "admin" || offer.CreatedBy != world.admin ||
		offer.UserID == nil || *offer.UserID != world.outsider || offer.InvitationID != nil {
		t.Errorf("offer = %+v", offer)
	}

	expectCount(t, "org_offers WHERE id = ? AND kind = 'standard'", "1", offer.ID)

	refusals := []struct {
		name   string
		token  string
		path   string
		body   []byte
		status int
		code   string
	}{
		{"a second offer to the same user", world.adminToken, offers, orgOfferBody(t, world.outsider, "member"),
			http.StatusConflict, orgCodeOfferExists},
		{"to a member of it", world.adminToken, offers, orgOfferBody(t, world.member, "member"),
			http.StatusConflict, orgCodeAlready},
		{"to a user who does not exist", world.adminToken, offers, orgOfferBody(t, idMissing, "member"),
			http.StatusNotFound, orgCodeUserMissing},
		{"by a member", world.memberToken, offers, orgOfferBody(t, world.platform, "member"),
			http.StatusForbidden, orgCodeNotAdmin},
		{"by an outsider", world.outsiderToken, offers, orgOfferBody(t, world.platform, "member"),
			http.StatusNotFound, orgCodeNotFound},
		{"of an organization that does not exist", world.adminToken, orgItem(idMissing) + "/offer",
			orgOfferBody(t, world.platform, "member"), http.StatusNotFound, orgCodeNotFound},
		{"with a role that does not exist", world.adminToken, offers, orgOfferBody(t, world.platform, "owner"),
			http.StatusBadRequest, "invalid_org_role"},
		{"with no role", world.adminToken, offers, []byte(`{"userId":"` + world.platform + `"}`),
			http.StatusBadRequest, "invalid_org_role"},
		{"to a user id in capitals", world.adminToken, offers,
			[]byte(`{"userId":"` + strings.ToUpper(world.platform) + `","role":"member"}`), http.StatusBadRequest, orgCodeInvalidID},
		{"with an unknown field", world.adminToken, offers,
			[]byte(`{"userId":"` + world.platform + `","role":"member","orgId":"x"}`), http.StatusBadRequest, "unknown_field"},
	}

	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			post(t, tc.path, tc.body, tc.token).expect(t, tc.name, tc.status, tc.code)
		})
	}

	expectCount(t, "org_offers", "1")

	// A revoked user receives none.
	seed(t, "UPDATE users SET revoked_at = 5 WHERE id = ?", world.platform)
	post(t, offers, orgOfferBody(t, world.platform, "member"), world.adminToken).
		expect(t, "to a revoked user", http.StatusNotFound, orgCodeUserMissing)
	seed(t, "UPDATE users SET revoked_at = NULL WHERE id = ?", world.platform)

	// The organization's list shows it to its administrators only.
	page := orgDecode[orgPage](t, get(t, offers, world.secondToken))
	if len(page.Offers) != 1 || page.Offers[0].ID != offer.ID {
		t.Errorf("org offers = %+v, want the one", page.Offers)
	}

	// The user's own list shows it to them and to nobody else.
	mine := orgDecode[orgPage](t, get(t, pathOffer, world.outsiderToken))
	if len(mine.Offers) != 1 || mine.Offers[0].ID != offer.ID {
		t.Errorf("my offers = %+v, want the one", mine.Offers)
	}

	if other := orgDecode[orgPage](t, get(t, pathOffer, world.memberToken)); len(other.Offers) != 0 {
		t.Errorf("a member lists %+v, want none", other.Offers)
	}

	// Only the addressee accepts; another account is told it is not found, as
	// for an id that does not exist.
	accept := pathOffer + "/" + offer.ID + "/accept"
	post(t, accept, nil, world.memberToken).expect(t, "someone else accepts", http.StatusNotFound, orgCodeOfferMissing)
	post(t, accept, nil, world.adminToken).expect(t, "the offerer accepts", http.StatusNotFound, orgCodeOfferMissing)
	post(t, accept, nil, world.platformToken).expect(t, "a platform administrator accepts", http.StatusNotFound, orgCodeOfferMissing)
	post(t, pathOffer+"/"+idMissing+"/accept", nil, world.outsiderToken).
		expect(t, "missing", http.StatusNotFound, orgCodeOfferMissing)
	expectCount(t, "org_offers", "1")

	got := post(t, accept, nil, world.outsiderToken)
	got.expect(t, "accept", http.StatusOK, "")

	if view := orgDecode[orgOfferView](t, got); view.ID != offer.ID || view.Role != "admin" {
		t.Errorf("accepted = %+v", view)
	}

	if orgMembership(t, world.outsider) != world.org {
		t.Errorf("the user belongs to %s, want %s", orgMembership(t, world.outsider), world.org)
	}

	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", world.org, world.outsider)
	expectCount(t, "org_offers", "0")

	post(t, accept, nil, world.outsiderToken).expect(t, "accept again", http.StatusNotFound, orgCodeOfferMissing)

	// A user who belongs to an organization cannot accept another's offer, and
	// the offer stays for them.
	other := idN(orgFamOrg, 2)
	orgSeedStandard(t, other, world.platform)
	orgJoin(t, other, world.platform, true)
	orgOfferSeed(t, idN(orgFamOffer, 2), other, world.member, "admin", world.platform)

	post(t, pathOffer+"/"+idN(orgFamOffer, 2)+"/accept", nil, world.memberToken).
		expect(t, "already a member", http.StatusConflict, orgCodeAlready)
	expectCount(t, "org_offers WHERE id = ?", "1", idN(orgFamOffer, 2))
	expectCount(t, "org_admins WHERE user_id = ?", "0", world.member)

	// The addressee declines; an administrator withdraws; neither the offerer's
	// bystanders nor strangers may.
	orgOfferSeed(t, idN(orgFamOffer, 3), world.org, world.platform, "member", world.admin)
	orgOfferSeed(t, idN(orgFamOffer, 4), world.org, world.second, "member", world.admin)

	seedUser(t, orgUser(8), roleMember)
	stranger := seedSession(t, idN(orgFamSession, 8), orgUser(8))

	del(t, pathOffer+"/"+idN(orgFamOffer, 3), world.memberToken).expect(t, "a member withdraws", http.StatusNotFound, orgCodeOfferMissing)
	del(t, pathOffer+"/"+idN(orgFamOffer, 3), stranger).expect(t, "a stranger", http.StatusNotFound, orgCodeOfferMissing)
	del(t, pathOffer+"/"+idN(orgFamOffer, 4), world.platformToken).expect(t, "a platform administrator withdraws another user's offer", http.StatusOK, "")
	orgOfferSeed(t, idN(orgFamOffer, 4), world.org, world.second, "member", world.admin)
	expectCount(t, "org_offers WHERE id IN (?, ?)", "2", idN(orgFamOffer, 3), idN(orgFamOffer, 4))

	del(t, pathOffer+"/"+idN(orgFamOffer, 3), world.platformToken).expect(t, "decline", http.StatusOK, "")
	del(t, pathOffer+"/"+idN(orgFamOffer, 4), world.adminToken).expect(t, "withdraw", http.StatusOK, "")
	del(t, pathOffer+"/"+idN(orgFamOffer, 4), world.adminToken).expect(t, "withdraw again", http.StatusNotFound, orgCodeOfferMissing)
	expectCount(t, "org_offers WHERE id IN (?, ?)", "0", idN(orgFamOffer, 3), idN(orgFamOffer, 4))
}

// TestOrgOfferOnAnInvitation: an offer that rides on an invitation is listed to
// the organization's administrators and withdrawn by them, and withdrawing it
// leaves the invitation untouched; it is not in anyone's own list, and nobody
// can accept it.
//
//nolint:paralleltest // shares one database
func TestOrgOfferOnAnInvitation(t *testing.T) {
	world := orgNewWorld(t)

	seedInvitation(t, idN(orgFamInvite, 1), 3)
	seed(t, "INSERT INTO org_offers (id, org_id, invitation_id, role, created_by, created_at) VALUES (?, ?, ?, 'admin', ?, 1)",
		idN(orgFamOffer, 1), world.org, idN(orgFamInvite, 1), world.admin)

	page := orgDecode[orgPage](t, get(t, orgItem(world.org)+"/offer", world.adminToken))
	if len(page.Offers) != 1 || page.Offers[0].InvitationID == nil || *page.Offers[0].InvitationID != idN(orgFamInvite, 1) ||
		page.Offers[0].UserID != nil {
		t.Fatalf("org offers = %+v, want the invitation's offer", page.Offers)
	}

	for _, token := range []string{world.memberToken, world.outsiderToken, world.platformToken} {
		if mine := orgDecode[orgPage](t, get(t, pathOffer, token)); len(mine.Offers) != 0 {
			t.Errorf("my offers = %+v, want none", mine.Offers)
		}

		post(t, pathOffer+"/"+idN(orgFamOffer, 1)+"/accept", nil, token).
			expect(t, "accept an invitation's offer", http.StatusNotFound, orgCodeOfferMissing)
	}

	del(t, pathOffer+"/"+idN(orgFamOffer, 1), world.memberToken).expect(t, "a member withdraws", http.StatusNotFound, orgCodeOfferMissing)
	del(t, pathOffer+"/"+idN(orgFamOffer, 1), world.secondToken).expect(t, "withdraw", http.StatusOK, "")

	expectCount(t, "org_offers", "0")
	expectCount(t, "invitations WHERE id = ?", "1", idN(orgFamInvite, 1))
	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NULL", "1", idN(orgFamInvite, 1))
}

// TestOrgOfferOfARevokedOrganization: offers die with the organization, and one
// that somehow outlived it is neither listed nor acceptable.
//
//nolint:paralleltest // shares one database
func TestOrgOfferOfARevokedOrganization(t *testing.T) {
	world := orgNewWorld(t)

	orgOfferSeed(t, idN(orgFamOffer, 1), world.org, world.outsider, "member", world.admin)
	del(t, orgItem(world.org), world.adminToken).expect(t, "revoke", http.StatusOK, "")
	expectCount(t, "org_offers", "0")

	// Put an offer back behind the Worker's back, as a stale row would be.
	orgOfferSeed(t, idN(orgFamOffer, 1), world.org, world.outsider, "member", world.admin)

	if mine := orgDecode[orgPage](t, get(t, pathOffer, world.outsiderToken)); len(mine.Offers) != 0 {
		t.Errorf("my offers = %+v, want none of a revoked organization", mine.Offers)
	}

	post(t, pathOffer+"/"+idN(orgFamOffer, 1)+"/accept", nil, world.outsiderToken).
		expect(t, "accept", http.StatusNotFound, orgCodeOfferMissing)
	expectCount(t, "users WHERE org_id IS NOT NULL", "0")

	// No new offers of it.
	post(t, orgItem(world.org)+"/offer", orgOfferBody(t, world.outsider, "member"), world.platformToken).
		expect(t, "offer of a revoked organization", http.StatusConflict, orgCodeInactive)
}

// ---- races -----------------------------------------------------------------

// orgRound is one round of a race: the requests that are released together and
// what must hold when they have all answered.
type orgRound struct {
	// racers each send their request, all at the same moment.
	racers []func() reply

	// judge checks the replies, and what the outcome must be whichever order the
	// requests ran in. The invariants every round shares are checked after it
	// (orgExpectSound), so it states only what is particular to the race.
	judge func(t *testing.T, replies []reply)
}

// orgRace is a race between requests: a state it builds, the requests that run
// against it and the invariant that holds whatever their order. The same table
// serves every interleaving, so a new one is a row and not another loop.
type orgRace struct {
	name string

	// rounds is how many times the race is run, each from a fresh world, so that
	// the order it happened to take is not the only one tried.
	rounds int

	// build seeds the race's state on top of a fresh world and returns the round.
	build func(t *testing.T, world orgWorld) orgRound
}

// orgExpectSound holds what no interleaving may ever produce, whatever the
// race: a user stranded in a revoked organization, an offer, or an administrator,
// of one; an administrator who is not a member; an active organization with no
// administrator; an agent that survives its sandbox, or a key its agent; and a
// secret with no row.
func orgExpectSound(t *testing.T) {
	t.Helper()

	expectCount(t, "users u WHERE EXISTS (SELECT 1 FROM orgs o WHERE o.id = u.org_id AND o.revoked_at IS NOT NULL)", "0")
	expectCount(t, "org_offers f JOIN orgs o ON o.id = f.org_id WHERE o.revoked_at IS NOT NULL", "0")
	expectCount(t, "org_admins a JOIN orgs o ON o.id = a.org_id WHERE o.revoked_at IS NOT NULL", "0")
	expectCount(t, "org_admins a JOIN orgs o ON o.id = a.org_id WHERE o.kind = 'standard' "+
		"AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = a.user_id AND u.org_id = a.org_id)", "0")
	expectCount(t, "orgs o WHERE o.kind = 'standard' AND o.revoked_at IS NULL "+
		"AND NOT EXISTS (SELECT 1 FROM org_admins a WHERE a.org_id = o.id)", "0")
	expectCount(t, "agents WHERE sandbox_id IS NOT NULL AND sandbox_id NOT IN (SELECT id FROM orgs)", "0")
	expectCount(t, "api_keys WHERE agent_id IS NOT NULL AND agent_id NOT IN (SELECT id FROM agents)", "0")
	expectNoOrphanSecrets(t)
}

// orgOneOf fails the test unless the reply is one of the statuses.
func orgOneOf(t *testing.T, what string, got reply, statuses ...int) {
	t.Helper()

	if !slices.Contains(statuses, got.status) {
		t.Errorf("%s: %d %s, want one of %v", what, got.status, got.body, statuses)
	}
}

// orgRevokeOrgRacer revokes the organization as its administrator.
func orgRevokeOrgRacer(t *testing.T, world orgWorld) func() reply {
	t.Helper()

	return func() reply { return del(t, orgItem(world.org), world.adminToken) }
}

// orgReleaseMembers makes the organization hold only its administrator, so that
// the others are free to accept offers to it.
func orgReleaseMembers(t *testing.T, world orgWorld) {
	t.Helper()

	seed(t, "UPDATE users SET org_id = NULL")
	seed(t, "DELETE FROM org_admins")
	orgJoin(t, world.org, world.admin, true)
}

// orgRaceDemote: two administrators demote each other at once. Exactly one request may succeed, and an
// administrator remains.
func orgRaceDemote() orgRace {
	return orgRace{
		name: "two administrators demote each other", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply {
						return patch(t, pathMember+"/"+world.second, []byte(`{"admin":false}`), world.adminToken)
					},
					func() reply {
						return patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.secondToken)
					},
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					if got := orgAdminCount(t, world.org); got != "1" {
						t.Errorf("%s administrators after two demotions, want exactly 1 (%v)", got, orgTally(replies))
					}

					if tally := orgTally(replies); tally["OK"] != 1 {
						t.Errorf("tally = %v, want exactly one OK", tally)
					}
				},
			}
		},
	}
}

// orgRaceLeave: two administrators leave at once. One leaves, the other is refused as the last
// administrator, and the organization keeps one, who is still a member.
func orgRaceLeave() orgRace {
	return orgRace{
		name: "two administrators leave", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply { return del(t, pathMember+"/"+world.admin, world.adminToken) },
					func() reply { return del(t, pathMember+"/"+world.second, world.secondToken) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					tally := orgTally(replies)
					if tally["OK"] != 1 || tally["Conflict "+orgCodeLastAdmin] != 1 {
						t.Errorf("tally = %v, want one OK and one Conflict %s", tally, orgCodeLastAdmin)
					}

					expectCount(t, "users u WHERE u.org_id = ? AND u.id IN (SELECT user_id FROM org_admins WHERE org_id = ?)",
						"1", world.org, world.org)
					expectCount(t, "org_admins WHERE org_id = ?", "1", world.org)
				},
			}
		},
	}
}

// orgRaceDemoteWhileLeaving: an administrator is demoted by the other while they leave. The one who stays
// is untouched and is the administrator whichever order the two take, and the one who is demoted or
// leaves is no administrator.
func orgRaceDemoteWhileLeaving() orgRace {
	return orgRace{
		name: "an administrator is demoted while they leave", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply {
						return patch(t, pathMember+"/"+world.second, []byte(`{"admin":false}`), world.adminToken)
					},
					func() reply { return del(t, pathMember+"/"+world.second, world.secondToken) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					orgOneOf(t, "the demotion", replies[0], http.StatusOK, http.StatusNotFound)
					orgOneOf(t, "the leaving", replies[1], http.StatusOK, http.StatusNotFound)

					if replies[0].status != http.StatusOK && replies[1].status != http.StatusOK {
						t.Errorf("neither the demotion nor the leaving succeeded: %v", orgTally(replies))
					}

					expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", world.org, world.admin)
					expectCount(t, "org_admins WHERE user_id = ?", "0", world.second)
				},
			}
		},
	}
}

// orgRaceDemoteAndLeave: both administrators demote each other and leave at once. However the four
// requests fall, one administrator remains, and is a member.
func orgRaceDemoteAndLeave() orgRace {
	return orgRace{
		name: "two administrators demote and leave at once", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply {
						return patch(t, pathMember+"/"+world.second, []byte(`{"admin":false}`), world.adminToken)
					},
					func() reply {
						return patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.secondToken)
					},
					func() reply { return del(t, pathMember+"/"+world.admin, world.adminToken) },
					func() reply { return del(t, pathMember+"/"+world.second, world.secondToken) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					if got := orgAdminCount(t, world.org); got != "1" {
						t.Errorf("%s administrators, want exactly 1 (%v)", got, orgTally(replies))
					}

					// The one who administers is a member, and exactly one of the two
					// is left in the organization as one.
					expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id AND u.org_id = a.org_id "+
						"WHERE a.org_id = ?", "1", world.org)
				},
			}
		},
	}
}

// orgRaceRevokeAgainstAccept: the organization is revoked while its offers are accepted. Whatever the
// order, nobody belongs to the revoked organization, no offer survives it, and no administrator row is
// left for a user who is not a member.
func orgRaceRevokeAgainstAccept() orgRace {
	return orgRace{
		name: "the organization is revoked while its offers are accepted", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			orgReleaseMembers(t, world)
			orgOfferSeed(t, idN(orgFamOffer, 1), world.org, world.outsider, "admin", world.admin)
			orgOfferSeed(t, idN(orgFamOffer, 2), world.org, world.member, "member", world.admin)
			orgOfferSeed(t, idN(orgFamOffer, 3), world.org, world.platform, "admin", world.admin)

			accept := func(n int, token string) func() reply {
				return func() reply { return post(t, pathOffer+"/"+idN(orgFamOffer, n)+"/accept", nil, token) }
			}

			return orgRound{
				racers: []func() reply{
					orgRevokeOrgRacer(t, world),
					accept(1, world.outsiderToken), accept(2, world.memberToken), accept(3, world.platformToken),
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					expectCount(t, "users WHERE org_id = ?", "0", world.org)
					expectCount(t, "org_offers", "0")
					expectCount(t, "org_admins", "0")
					expectCount(t, "orgs WHERE id = ? AND revoked_at IS NOT NULL", "1", world.org)

					orgOneOf(t, "the revocation", replies[0], http.StatusOK)

					for i, accepted := range replies[1:] {
						orgOneOf(t, "accept "+strconv.Itoa(i+1), accepted, http.StatusOK, http.StatusNotFound)
					}
				},
			}
		},
	}
}

// orgRaceWithdrawAgainstAccept: an offer is accepted while it is withdrawn. Exactly one wins, and the
// state agrees with the one that did.
func orgRaceWithdrawAgainstAccept() orgRace {
	return orgRace{
		name: "an offer is accepted while it is withdrawn", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			orgOfferSeed(t, idN(orgFamOffer, 1), world.org, world.outsider, "admin", world.admin)

			return orgRound{
				racers: []func() reply{
					func() reply { return post(t, pathOffer+"/"+idN(orgFamOffer, 1)+"/accept", nil, world.outsiderToken) },
					func() reply { return del(t, pathOffer+"/"+idN(orgFamOffer, 1), world.adminToken) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					accepted := replies[0].status == http.StatusOK
					withdrawn := replies[1].status == http.StatusOK

					if accepted == withdrawn {
						t.Fatalf("accept = %d, withdraw = %d: neither won, or both did", replies[0].status, replies[1].status)
					}

					member := orgMembership(t, world.outsider) == world.org
					isAdmin := count(t, "org_admins WHERE user_id = ?", world.outsider) == "1"

					if member != accepted || isAdmin != accepted {
						t.Errorf("accepted = %t, withdrawn = %t, but member = %t and admin = %t",
							accepted, withdrawn, member, isAdmin)
					}

					expectCount(t, "org_offers", "0")
				},
			}
		},
	}
}

// orgRaceTwoAccepts: one user accepts two offers of two organizations at once, both naming them an
// administrator. Exactly one wins, the other is told they belong to one already, and there is one
// administrator row, of the organization they joined.
func orgRaceTwoAccepts() orgRace {
	return orgRace{
		name: "one user accepts two offers", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			other := idN(orgFamOrg, 2)
			orgSeedStandard(t, other, world.platform)
			orgJoin(t, other, world.platform, true)

			orgOfferSeed(t, idN(orgFamOffer, 1), world.org, world.outsider, "admin", world.admin)
			orgOfferSeed(t, idN(orgFamOffer, 2), other, world.outsider, "admin", world.platform)

			accept := func(n int) func() reply {
				return func() reply { return post(t, pathOffer+"/"+idN(orgFamOffer, n)+"/accept", nil, world.outsiderToken) }
			}

			return orgRound{
				racers: []func() reply{accept(1), accept(2)},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					tally := orgTally(replies)
					if tally["OK"] != 1 || tally["Conflict "+orgCodeAlready] != 1 {
						t.Errorf("tally = %v, want one OK and one Conflict %s", tally, orgCodeAlready)
					}

					joined := orgMembership(t, world.outsider)
					expectCount(t, "org_admins WHERE user_id = ?", "1", world.outsider)
					expectCount(t, "org_admins WHERE user_id = ? AND org_id = ?", "1", world.outsider, joined)
					expectCount(t, "org_offers", "1")
				},
			}
		},
	}
}

// orgRaceTwoCreates: a user who belongs to none creates six organizations at once. One is made, the
// others are refused as a member, and there is one administrator row.
func orgRaceTwoCreates() orgRace {
	return orgRace{
		name: "a user creates six organizations", rounds: 4,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			creators := make([]func() reply, 6)
			for i := range creators {
				creators[i] = func() reply { return orgCreate(t, world.outsiderToken, "standard", "race") }
			}

			return orgRound{
				racers: creators,
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					tally := orgTally(replies)
					if tally["Created"] != 1 || tally["Conflict "+orgCodeAlready] != 5 {
						t.Errorf("tally = %v, want one Created and five Conflict %s", tally, orgCodeAlready)
					}

					expectCount(t, "orgs WHERE created_by = ?", "1", world.outsider)
					expectCount(t, "org_admins WHERE user_id = ?", "1", world.outsider)
				},
			}
		},
	}
}

// orgRaceRevokeAgainstOffers: the organization is revoked while offers of it are made. An offer is
// either refused or deleted by the revocation: none outlives it.
func orgRaceRevokeAgainstOffers() orgRace {
	return orgRace{
		name: "the organization is revoked while offers are made", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			offer := func(user, role, token string) func() reply {
				return func() reply { return post(t, orgItem(world.org)+"/offer", orgOfferBody(t, user, role), token) }
			}

			return orgRound{
				racers: []func() reply{
					orgRevokeOrgRacer(t, world),
					offer(world.outsider, "admin", world.adminToken),
					offer(world.platform, "member", world.secondToken),
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					orgOneOf(t, "the revocation", replies[0], http.StatusOK)
					orgOneOf(t, "an offer by the administrator", replies[1], http.StatusCreated, http.StatusNotFound, http.StatusConflict)
					orgOneOf(t, "an offer by the second administrator", replies[2], http.StatusCreated, http.StatusNotFound, http.StatusConflict)

					expectCount(t, "org_offers", "0")
					expectCount(t, "orgs WHERE id = ? AND revoked_at IS NOT NULL", "1", world.org)
				},
			}
		},
	}
}

// orgRaceRevokeAgainstInvitations: the organization is revoked while invitations that offer it are
// created. An invitation is either refused, and nothing is created, or created and its offer deleted by
// the revocation: the invitation, the record of who was admitted, is kept either way.
func orgRaceRevokeAgainstInvitations() orgRace {
	return orgRace{
		name: "the organization is revoked while invitations offer it", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			invite := func(role string) func() reply {
				return func() reply {
					return post(t, pathInvitation, invOrgBody(t, "member", 1, world.org, role), world.platformToken)
				}
			}

			return orgRound{
				racers: []func() reply{orgRevokeOrgRacer(t, world), invite("member"), invite("admin")},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					orgOneOf(t, "the revocation", replies[0], http.StatusOK)

					created := 1 // the invitation the world was built with

					for i, invited := range replies[1:] {
						orgOneOf(t, "invitation "+strconv.Itoa(i+1), invited, http.StatusCreated, http.StatusNotFound)

						if invited.status == http.StatusCreated {
							created++
						} else if code := invited.errorCode(); code != "org_not_found" {
							t.Errorf("a refused invitation = %q, want org_not_found", code)
						}
					}

					expectCount(t, "invitations", strconv.Itoa(created))
					expectCount(t, "org_offers", "0")
					expectCount(t, "orgs WHERE id = ? AND revoked_at IS NOT NULL", "1", world.org)
				},
			}
		},
	}
}

// orgRaceRevokeAgainstPromote: the organization is revoked while a member is promoted. Whichever
// happened first, the member is released and is no administrator of it.
func orgRaceRevokeAgainstPromote() orgRace {
	return orgRace{
		name: "the organization is revoked while a member is promoted", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			promote := func(token string) func() reply {
				return func() reply { return patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), token) }
			}

			return orgRound{
				racers: []func() reply{orgRevokeOrgRacer(t, world), promote(world.secondToken), promote(world.adminToken)},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					orgOneOf(t, "the revocation", replies[0], http.StatusOK)
					orgOneOf(t, "a promotion by the second administrator", replies[1],
						http.StatusOK, http.StatusNotFound, http.StatusConflict)
					orgOneOf(t, "a promotion by the administrator", replies[2],
						http.StatusOK, http.StatusNotFound, http.StatusConflict)

					expectCount(t, "org_admins", "0")
					expectCount(t, "users WHERE org_id IS NOT NULL", "0")
					expectCount(t, "orgs WHERE id = ? AND revoked_at IS NOT NULL", "1", world.org)
				},
			}
		},
	}
}

// orgRaceSandboxAgainstUserCreates: a sandbox is deleted while its administrator creates agents in it. An
// agent is either refused or deleted with the sandbox: none survives, and no key or secret is left.
func orgRaceSandboxAgainstUserCreates() orgRace {
	return orgRace{
		name: "a sandbox is deleted while its administrator creates agents in it", rounds: 8,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			sandbox := idN(orgFamSandbox, 1)
			sbSeedSandbox(t, sandbox, world.admin, sbWeek)
			sbSeedAgentWithKey(t, 1, world.admin, sandbox)

			create := func() reply {
				return post(t, pathAgent, mustJSON(t, map[string]any{"name": "racer", "sandboxId": sandbox}), world.adminToken)
			}

			return orgRound{
				racers: []func() reply{
					func() reply { return del(t, orgItem(sandbox), world.adminToken) }, create, create, create,
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					orgOneOf(t, "the delete", replies[0], http.StatusOK)

					for i, created := range replies[1:] {
						orgOneOf(t, "create "+strconv.Itoa(i+1), created, http.StatusCreated, http.StatusNotFound)
					}

					expectCount(t, "orgs WHERE id = ?", "0", sandbox)
					expectCount(t, "agents", "0")
					expectCount(t, "api_keys WHERE agent_id IS NOT NULL", "0")
				},
			}
		},
	}
}

// orgRaceSandboxAgainstAgentCreates: a sandbox is deleted while an agent of it creates agents in it with
// its key. As the sandbox is deleted the key stops resolving, and what was created in the meantime goes
// with the sandbox.
func orgRaceSandboxAgainstAgentCreates() orgRace {
	return orgRace{
		name: "a sandbox is deleted while its agent creates agents in it", rounds: 8,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			sandbox := idN(orgFamSandbox, 1)
			sbSeedSandbox(t, sandbox, world.admin, sbWeek)

			_, key := sbSeedAgentWithKey(t, 1, world.admin, sandbox)

			create := func() reply { return sbAs(t, key, http.MethodPost, pathAgent, []byte(`{"name":"racer"}`)) }

			return orgRound{
				racers: []func() reply{
					func() reply { return del(t, orgItem(sandbox), world.adminToken) }, create, create, create,
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					orgOneOf(t, "the delete", replies[0], http.StatusOK)

					// A create that was refused is told the key is dead (401) or the
					// write found no sandbox to create in (404 or 409).
					for i, created := range replies[1:] {
						orgOneOf(t, "create "+strconv.Itoa(i+1), created,
							http.StatusCreated, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict)
					}

					expectCount(t, "orgs WHERE id = ?", "0", sandbox)
					expectCount(t, "agents", "0")
					expectCount(t, "api_keys WHERE agent_id IS NOT NULL", "0")
				},
			}
		},
	}
}

// orgRaces returns every interleaving of requests that the organization routes must
// survive. Each states its invariant in terms of the outcome, never of the
// order: D1 runs one batch at a time, so what is under test is that each write
// carries its own condition.
func orgRaces() []orgRace {
	return []orgRace{
		orgRaceDemote(),
		orgRaceLeave(),
		orgRaceDemoteWhileLeaving(),
		orgRaceDemoteAndLeave(),
		orgRaceRevokeAgainstAccept(),
		orgRaceWithdrawAgainstAccept(),
		orgRaceTwoAccepts(),
		orgRaceTwoCreates(),
		orgRaceRevokeAgainstOffers(),
		orgRaceRevokeAgainstInvitations(),
		orgRaceRevokeAgainstPromote(),
		orgRaceSandboxAgainstUserCreates(),
		orgRaceSandboxAgainstAgentCreates(),
	}
}

// TestOrgRaces runs each interleaving of orgRaces, over and over, each round
// from a fresh world, and then holds what no interleaving may produce.
//
//nolint:paralleltest // shares one database
func TestOrgRaces(t *testing.T) {
	for _, race := range orgRaces() {
		t.Run(race.name, func(t *testing.T) {
			for round := range race.rounds {
				t.Run("round "+strconv.Itoa(round), func(t *testing.T) {
					world := orgNewWorld(t)
					run := race.build(t, world)

					replies := orgRelease(len(run.racers), func(i int) reply { return run.racers[i]() })
					orgNo5xx(t, race.name, replies)
					run.judge(t, replies)
					orgExpectSound(t)
				})
			}
		})
	}
}

// TestOrgRevokingTheLastAdministratorsAccountIsNotRefused: the last-administrator
// rule is only that demoting or removing the last unrevoked administrator is
// refused. Revoking their ACCOUNT is not, because refusing it would let an
// organization administrator shield themselves from platform revocation. The
// organization is then left with no unrevoked administrator, which no organization
// administrator can change, and a platform administrator's override is how it is
// managed: they promote a member, who is then the administrator.
//
//nolint:paralleltest // shares one database
func TestOrgRevokingTheLastAdministratorsAccountIsNotRefused(t *testing.T) {
	world := orgNewWorld(t)

	// The second administrator steps down, so the first is the last.
	patch(t, pathMember+"/"+world.second, []byte(`{"admin":false}`), world.adminToken).
		expect(t, "the second administrator steps down", http.StatusOK, "")

	// The last one cannot be demoted or leave, which is the whole of the rule.
	patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.adminToken).
		expect(t, "demoting the last administrator", http.StatusConflict, orgCodeLastAdmin)
	del(t, pathMember+"/"+world.admin, world.adminToken).
		expect(t, "the last administrator leaving", http.StatusConflict, orgCodeLastAdmin)

	// Their account may be revoked all the same.
	del(t, usrItem(world.admin), world.platformToken).
		expect(t, "revoking the last administrator's account", http.StatusOK, "")

	get(t, pathSession, world.adminToken).expect(t, "the revoked administrator's session", http.StatusUnauthorized, "")
	expectCount(t, "orgs WHERE id = ? AND revoked_at IS NULL", "1", world.org)
	expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id WHERE a.org_id = ? AND u.revoked_at IS NULL", "0", world.org)

	// Nobody an organization administrator can act as is left, so the members
	// are refused what only an administrator may do.
	patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.memberToken).
		expect(t, "a member promoting themself", http.StatusForbidden, orgCodeNotAdmin)

	// The platform administrator manages it: promotes a member, who now administers.
	patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.platformToken).
		expect(t, "a platform administrator promoting a member", http.StatusOK, "")
	patch(t, pathMember+"/"+world.second, []byte(`{"admin":true}`), world.memberToken).
		expect(t, "the promoted member promoting another", http.StatusOK, "")
	expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id WHERE a.org_id = ? AND u.revoked_at IS NULL", "2", world.org)
}

// ---- size ------------------------------------------------------------------

// TestOrgBodyCaps: a body over a route's cap is refused 413 before anything
// else, signed in or not, and a body exactly at the cap is read.
//
//nolint:paralleltest // shares one database
func TestOrgBodyCaps(t *testing.T) {
	world := orgNewWorld(t)

	pad := func(n int) []byte { return []byte(strings.Repeat(" ", n)) }

	routes := []struct {
		name, method, path string
		cap                int
	}{
		{"create", http.MethodPost, pathOrg, orgBodyCap},
		{"rename", http.MethodPatch, orgItem(world.org), orgBodyCap},
		{"promote", http.MethodPatch, pathMember + "/" + world.member, orgSmallCap},
		{"offer", http.MethodPost, orgItem(world.org) + "/offer", orgSmallCap},
		{"accept", http.MethodPost, pathOffer + "/" + idMissing + "/accept", orgSmallCap},
		{"revoke", http.MethodDelete, orgItem(idMissing), orgSmallCap},
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			over := send(t, request{method: rt.method, path: rt.path, body: pad(rt.cap + 1), token: world.adminToken})
			over.expect(t, "over the cap", http.StatusRequestEntityTooLarge, orgCodeTooLarge)

			anonymous := send(t, request{method: rt.method, path: rt.path, body: pad(rt.cap + 1)})
			anonymous.expect(t, "over the cap, signed out", http.StatusRequestEntityTooLarge, orgCodeTooLarge)

			at := send(t, request{method: rt.method, path: rt.path, body: pad(rt.cap), token: world.adminToken})
			if at.status == http.StatusRequestEntityTooLarge || at.status >= http.StatusInternalServerError {
				t.Errorf("at the cap = %d %s, want it read and answered by the route", at.status, at.body)
			}
		})
	}

	// The largest legitimate name, 256 four-byte runes with every one escaped as
	// a surrogate pair (12 bytes each), fits the cap of a create.
	escaped := strings.Repeat(`\ud83d\ude00`, orgNameRunes)
	body := []byte(`{"kind":"sandbox","name":"` + escaped + `"}`)

	if len(body) > orgBodyCap {
		t.Fatalf("the largest name's body is %d bytes, over the cap %d", len(body), orgBodyCap)
	}

	got := post(t, pathOrg, body, world.outsiderToken)
	got.expect(t, "the largest name", http.StatusCreated, "")

	if view := orgDecode[orgView](t, got); view.Name != strings.Repeat("\U0001F600", orgNameRunes) {
		t.Errorf("the largest name came back as %d bytes", len(view.Name))
	}

	expectCount(t, "orgs WHERE kind = 'sandbox'", "1")
}

// ---- credentials -----------------------------------------------------------

// TestOrgAgentsAndKeys: an agent never changes an organization, whatever scopes
// it was given, and may read them when it has the scope; an agent of a sandbox
// reaches no organization route at all; a user's own key with the scope may do
// what the user may.
//
//nolint:paralleltest // shares one database
func TestOrgAgentsAndKeys(t *testing.T) {
	world := orgNewWorld(t)

	allOrg := `["org:read","org:create","org:update","org:revoke","member:read","member:update","member:revoke",` +
		`"offer:read","offer:create","offer:update","offer:revoke"]`

	sandbox := idN(orgFamSandbox, 1)
	orgSeedSandboxes(t, orgFamSandbox, 1, world.admin, time.Now().Unix()+3600)

	seedAgent(t, idN(orgFamAgent, 1), world.admin, "free")
	seedAgent(t, idN(orgFamAgent, 2), world.admin, "confined")
	seed(t, "UPDATE agents SET sandbox_id = ?, scopes = ? WHERE id = ?", sandbox, allOrg, idN(orgFamAgent, 2))
	seed(t, "UPDATE agents SET scopes = ? WHERE id = ?", allOrg, idN(orgFamAgent, 1))

	freeKey := seedAPIKey(t, idN(orgFamKey, 1), world.admin, idN(orgFamAgent, 1))
	confinedKey := seedAPIKey(t, idN(orgFamKey, 2), world.admin, idN(orgFamAgent, 2))
	userKey := seedAPIKey(t, idN(orgFamKey, 3), world.admin, "")

	seed(t, "UPDATE api_keys SET scope = ?", allOrg)

	as := func(key, method, path string, body []byte) reply {
		t.Helper()

		return send(t, request{method: method, path: path, body: body, bearer: key})
	}

	// An agent with every scope reads, and cannot change anything.
	as(freeKey, http.MethodGet, pathOrg, nil).expect(t, "agent list", http.StatusOK, "")
	as(freeKey, http.MethodGet, orgItem(world.org), nil).expect(t, "agent get", http.StatusOK, "")
	as(freeKey, http.MethodGet, orgItem(world.org)+"/member", nil).expect(t, "agent members", http.StatusOK, "")
	as(freeKey, http.MethodGet, orgItem(world.org)+"/offer", nil).expect(t, "agent offers", http.StatusOK, "")
	as(freeKey, http.MethodGet, pathOffer, nil).expect(t, "agent my offers", http.StatusOK, "")

	for what, got := range map[string]reply{
		"create":  as(freeKey, http.MethodPost, pathOrg, orgCreateBody(t, "sandbox", "x")),
		"rename":  as(freeKey, http.MethodPatch, orgItem(world.org), []byte(`{"name":"x"}`)),
		"revoke":  as(freeKey, http.MethodDelete, orgItem(world.org), nil),
		"promote": as(freeKey, http.MethodPatch, pathMember+"/"+world.member, []byte(`{"admin":true}`)),
		"remove":  as(freeKey, http.MethodDelete, pathMember+"/"+world.member, nil),
		"offer":   as(freeKey, http.MethodPost, orgItem(world.org)+"/offer", orgOfferBody(t, world.outsider, "member")),
		"accept":  as(freeKey, http.MethodPost, pathOffer+"/"+idMissing+"/accept", nil),
		"decline": as(freeKey, http.MethodDelete, pathOffer+"/"+idMissing, nil),
	} {
		got.expect(t, "agent "+what, http.StatusForbidden, "")
	}

	// An agent confined to a sandbox reaches no organization route.
	for what, got := range map[string]reply{
		"list":   as(confinedKey, http.MethodGet, pathOrg, nil),
		"get":    as(confinedKey, http.MethodGet, orgItem(sandbox), nil),
		"create": as(confinedKey, http.MethodPost, pathOrg, orgCreateBody(t, "sandbox", "x")),
		"revoke": as(confinedKey, http.MethodDelete, orgItem(sandbox), nil),
	} {
		got.expect(t, "confined agent "+what, http.StatusForbidden, "")
	}

	expectCount(t, "orgs", "2")
	expectCount(t, "users WHERE org_id = ?", "3", world.org)

	// The user's own key with the scopes does what the user may, and nothing the
	// user may not.
	as(userKey, http.MethodGet, pathOrg, nil).expect(t, "user key list", http.StatusOK, "")
	as(userKey, http.MethodPatch, orgItem(world.org), []byte(`{"name":"By key"}`)).
		expect(t, "user key rename", http.StatusOK, "")
	as(userKey, http.MethodDelete, orgItem(sandbox), nil).expect(t, "user key deletes its sandbox", http.StatusOK, "")

	// Narrowed to one scope, the key may do that and no more.
	seed(t, "UPDATE api_keys SET scope = '[\"org:read\"]' WHERE id = ?", idN(orgFamKey, 3))
	as(userKey, http.MethodGet, pathOrg, nil).expect(t, "narrowed read", http.StatusOK, "")
	as(userKey, http.MethodPatch, orgItem(world.org), []byte(`{"name":"x"}`)).
		expect(t, "narrowed rename", http.StatusForbidden, "insufficient_scope")
}

// ---- the depth test --------------------------------------------------------

// TestOrgDeleteSandboxThroughTheWorker is the required depth test of the design
// (docs/orgs_design.md, principle 5), driven through the Worker: DELETE
// /api/org/{id} of a sandbox that holds agents with keys, labels and OAuth
// grants with access tokens removes all of them and every secret behind them in
// the one request, through D1's trigger limits, and leaves what was not in the
// sandbox. It is the schema test of the same name run end to end: the SQL is the
// store's own, and the caller is a real session.
//
//nolint:paralleltest // shares one database
func TestOrgDeleteSandboxThroughTheWorker(t *testing.T) {
	t.Run("the administrator deletes it", func(t *testing.T) {
		gone, kept := worldOfSandboxes(t)
		token := seedSession(t, idN(orgFamSession, 1), idUserB)

		before := count(t, "secrets")

		got := del(t, orgItem(idN(famSandbox, 1)), token)
		got.expect(t, "delete", http.StatusOK, "")

		view := orgDecode[orgView](t, got)
		if view.ID != idN(famSandbox, 1) || view.Kind != "sandbox" || view.Status != "deleted" {
			t.Errorf("deleted = %+v", view)
		}

		orgExpectSandboxGone(t, gone, kept)

		// Six secrets went (two agents' keys, grants and access tokens), and the
		// session this test signed in with is not one of them.
		if after := count(t, "secrets"); parseInt(t, before)-parseInt(t, after) != 6 {
			t.Errorf("secrets %s -> %s, want six fewer (2 keys, 2 grants, 2 access tokens)", before, after)
		}

		// A second delete is the answer for an id that does not exist.
		del(t, orgItem(idN(famSandbox, 1)), token).expect(t, "delete again", http.StatusNotFound, orgCodeNotFound)
		get(t, orgItem(idN(famSandbox, 1)), token).expect(t, "read it", http.StatusNotFound, orgCodeNotFound)
	})

	t.Run("a stranger cannot, and nothing is touched", func(t *testing.T) {
		worldOfSandboxes(t)
		stranger := seedSession(t, idN(orgFamSession, 2), idUserC)

		secrets, agents := count(t, "secrets"), count(t, "agents")

		del(t, orgItem(idN(famSandbox, 1)), stranger).expect(t, "stranger", http.StatusNotFound, orgCodeNotFound)

		if count(t, "secrets") != secrets || count(t, "agents") != agents {
			t.Error("a refused delete changed rows")
		}

		expectCount(t, "orgs WHERE id = ?", "1", idN(famSandbox, 1))
	})

	t.Run("a platform administrator deletes anyone's", func(t *testing.T) {
		gone, kept := worldOfSandboxes(t)

		seedUser(t, orgUser(9), roleAdmin)
		token := seedSession(t, idN(orgFamSession, 3), orgUser(9))

		del(t, orgItem(idN(famSandbox, 1)), token).expect(t, "platform delete", http.StatusOK, "")
		orgExpectSandboxGone(t, gone, kept)
	})

	t.Run("an expired sandbox is deleted too", func(t *testing.T) {
		gone, kept := worldOfSandboxes(t)
		token := seedSession(t, idN(orgFamSession, 1), idUserB)

		seed(t, "UPDATE orgs SET expires_at = strftime('%s','now') - 10 WHERE id = ?", idN(famSandbox, 1))

		view := orgDecode[orgView](t, get(t, orgItem(idN(famSandbox, 1)), token))
		if view.Status != "expired" {
			t.Errorf("status = %q, want expired", view.Status)
		}

		patch(t, orgItem(idN(famSandbox, 1)), []byte(`{"name":"x"}`), token).
			expect(t, "rename expired", http.StatusConflict, orgCodeInactive)

		del(t, orgItem(idN(famSandbox, 1)), token).expect(t, "delete expired", http.StatusOK, "")
		orgExpectSandboxGone(t, gone, kept)
	})

	t.Run("two deletes at once, one wins", func(t *testing.T) {
		gone, kept := worldOfSandboxes(t)
		token := seedSession(t, idN(orgFamSession, 1), idUserB)

		replies := orgRelease(3, func(int) reply { return del(t, orgItem(idN(famSandbox, 1)), token) })
		orgNo5xx(t, "deletes", replies)

		tally := orgTally(replies)
		if tally["OK"] != 1 || tally["Not Found "+orgCodeNotFound] != 2 {
			t.Errorf("tally = %v, want one OK and two Not Found", tally)
		}

		orgExpectSandboxGone(t, gone, kept)
	})
}

// orgExpectSandboxGone checks the state worldOfSandboxes' first sandbox leaves
// when it is deleted: everything in it is gone, every secret behind it with it,
// and everything outside it is where it was.
func orgExpectSandboxGone(t *testing.T, gone, kept []string) {
	t.Helper()

	expectCount(t, "orgs WHERE id = ?", "0", idN(famSandbox, 1))
	expectCount(t, "agents WHERE sandbox_id = ?", "0", idN(famSandbox, 1))
	expectCount(t, "org_admins WHERE org_id = ?", "0", idN(famSandbox, 1))

	for _, id := range gone {
		expectCount(t, "secrets WHERE id = ?", "0", id)
		expectCount(t, "agents WHERE id = ?", "0", id)
		expectCount(t, "oauth_grants WHERE id = ?", "0", id)
		expectCount(t, "oauth_access_tokens WHERE id = ?", "0", id)
		expectCount(t, "api_keys WHERE id = ?", "0", id)
	}

	expectCount(t, "agent_labels WHERE agent_id IN (?, ?)", "0", idN(famAgent, 1), idN(famAgent, 2))

	for _, id := range kept {
		if count(t, "secrets WHERE id = ?", id) != "1" && count(t, "agents WHERE id = ?", id) != "1" {
			t.Errorf("%s was deleted with the sandbox, but was not in it", id)
		}
	}

	expectCount(t, "agents WHERE id IN (?, ?, ?)", "3", idN(famAgent, 3), idN(famAgent, 4), idN(famAgent, 5))
	expectCount(t, "agent_labels WHERE agent_id IN (?, ?, ?)", "6", idN(famAgent, 3), idN(famAgent, 4), idN(famAgent, 5))
	expectCount(t, "oauth_grants", "3")
	expectCount(t, "oauth_access_tokens", "3")
	expectCount(t, "api_keys", "4")

	// Its administrator was released, and kept everything of their own.
	expectCount(t, "users WHERE id = ? AND org_id = ?", "1", idUserB, idN(famOrg, 1))
	expectCount(t, "orgs WHERE id = ? AND revoked_at IS NULL", "1", idN(famOrg, 1))
	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", idN(famOrg, 1), idUserB)
	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", idN(famSandbox, 2), idUserB)
	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", idN(famSandbox, 3), idUserC)

	// No secret without its row, and no row without its secret.
	expectNoOrphanSecrets(t)
	expectCount(t, "api_keys WHERE id NOT IN (SELECT id FROM secrets)", "0")
	expectCount(t, "oauth_grants WHERE id NOT IN (SELECT id FROM secrets)", "0")
	expectCount(t, "oauth_access_tokens WHERE id NOT IN (SELECT id FROM secrets)", "0")
	expectCount(t, "agent_labels WHERE agent_id NOT IN (SELECT id FROM agents)", "0")
}
