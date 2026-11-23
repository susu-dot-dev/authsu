//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// orgs_test.go drives the organization routes (/api/org and /api/member) against
// the real Worker: the TinyGo wasm, the real D1 driver and the real SQLite the
// migrations created. The unit tests fake the database, so this file proves what
// only the real build can:
//
//   - that every conditional write of internal/store/orgs.go and members.go does
//     what its SQL text says, for each caller standing;
//   - that races between requests (two creates at the sandbox limit, a sandbox
//     deleted against what is created in it, two administrators demoting or
//     revoking each other at once) end in a state no sequential order could not
//     have produced, and never leave an organization without an administrator;
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
)

// Error codes of the organization API, as internal/orgs documents them.
const (
	orgCodeNotFound      = "org_not_found"
	orgCodeMemberMissing = "member_not_found"
	orgCodeNotAdmin      = "org_admin_required"
	orgCodeExpired       = "sandbox_expired"
	orgCodeNotStandard   = "org_not_standard"
	orgCodeNotSandbox    = "org_not_sandbox"
	orgCodeSandboxLimit  = "sandbox_limit_reached"
	orgCodeLastAdmin     = "org_last_admin"
	orgCodePlatformAdmin = "platform_admin_protected"
	orgCodeSelfRevoke    = "self_revoke_refused"
	orgCodeLastPlatform  = "user_last_admin"
	orgCodeMissingAdmin  = "missing_admin"
	orgCodeMemberRevoked = "member_revoked"
	orgCodeTooLarge      = "body_too_large"
	orgCodeInvalidID     = "invalid_id"

	orgMaxSandboxes = 25
	orgSandboxLife  = 7 * 24 * 3600
	orgNameRunes    = 256
	orgBodyCap      = 8 << 10

	orgSmallCap = 1 << 10
)

// Families of ids of this file.
const (
	orgFamUser     = "0e50"
	orgFamSession  = "0e51"
	orgFamOrg      = "0e52"
	orgFamInvite   = "0e54"
	orgFamSandbox  = "0e55"
	orgFamAgent    = "0e56"
	orgFamKey      = "0e57"
	orgFamExpired  = "0e59"
	orgFamCreation = "0e5a"
)

// orgView, orgMember and their pages are the JSON the routes serve.
type orgView struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	CreatedBy string `json:"createdBy"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt *int64 `json:"expiresAt"`
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

type orgPage struct {
	Orgs    []orgView       `json:"orgs"`
	Members []orgMemberView `json:"members"`
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
// administrator of it, an outsider and a platform administrator, who each belong
// to an organization of their own, whose id is not the account's (a route that
// took a user id for an organization id, or the other way, would be found out).
// Its sessions are seeded, so a test spends its requests on the routes under test.
type orgWorld struct {
	admin, member, second, outsider, platform string
	adminToken, memberToken, secondToken      string
	outsiderToken, platformToken              string

	// org is a standard organization of admin, member and second.
	org string

	// outsiderOrg and platformOrg are the organizations the outsider and the
	// platform administrator belong to: their own, with ids of their own.
	outsiderOrg, platformOrg string
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
		org: idN(orgFamOrg, 1), outsiderOrg: idN(orgFamOrg, 21), platformOrg: idN(orgFamOrg, 22),
	}

	// The administrator is written with the organization it created, which the
	// member and the second administrator join; the others have one of their own.
	seedUserWithOrg(t, world.admin, roleMember, world.org, "Acme")
	seedUserIn(t, world.member, roleMember, world.org)
	seedUserIn(t, world.second, roleMember, world.org)
	seedUserOwn(t, world.outsider, roleMember, world.outsiderOrg)
	seedUserOwn(t, world.platform, roleAdmin, world.platformOrg)

	for i, id := range []string{world.admin, world.member, world.second, world.outsider, world.platform} {
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

	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1), (?, ?, 1)",
		world.org, world.admin, world.org, world.second)

	return world
}

// orgSeedStandard inserts an active standard organization made by creator.
func orgSeedStandard(t *testing.T, id, creator string) {
	t.Helper()

	seed(t, insertOrg, id, schemaKindStandard, "Acme", creator, nil, int64(1_700_000_000))
}

// orgJoin makes user a member of org, and an administrator of it when admin.
func orgJoin(t *testing.T, org, user string, admin bool) {
	t.Helper()

	seed(t, "UPDATE users SET org_id = ? WHERE id = ?", org, user)

	if admin {
		seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", org, user)
	}
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

func orgCreateBody(t *testing.T, name string) []byte {
	t.Helper()

	return orgJSON(t, map[string]any{"name": name})
}

// orgCreate creates a sandbox, the only thing a create makes.
func orgCreate(t *testing.T, token, name string) reply {
	t.Helper()

	return post(t, pathOrg, orgCreateBody(t, name), token)
}

func orgItem(id string) string { return pathOrg + "/" + id }

// orgMembership is the organization the user belongs to.
func orgMembership(t *testing.T, user string) string {
	t.Helper()

	return scalar(t, "SELECT org_id FROM users WHERE id = ?", user)
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
	routes := []struct {
		name, method, path string
		body               []byte
	}{
		{"create", http.MethodPost, pathOrg, orgCreateBody(t, "x")},
		{"list", http.MethodGet, pathOrg, nil},
		{"get", http.MethodGet, orgItem(world.org), nil},
		{"rename", http.MethodPatch, orgItem(world.org), []byte(`{"name":"x"}`)},
		{"delete", http.MethodDelete, orgItem(world.org), nil},
		{"members", http.MethodGet, orgItem(world.org) + "/member", nil},
		{"promote", http.MethodPatch, pathMember + "/" + world.member, []byte(`{"admin":true}`)},
		{"revoke", http.MethodDelete, pathMember + "/" + world.member, nil},
	}

	for _, rt := range routes {
		t.Run("signed out "+rt.name, func(t *testing.T) {
			got := send(t, request{method: rt.method, path: rt.path, body: rt.body})
			got.expect(t, rt.name, http.StatusUnauthorized, codeUnauthenticated)
		})
	}

	expectCount(t, "orgs", "3") // the organization, and the two accounts' own
	expectCount(t, "org_admins", "2")
	expectCount(t, "users WHERE org_id = ?", "3", world.org)

	// A revoked account is told it is not signed in, on a read and on a write.
	seed(t, "UPDATE users SET revoked_at = strftime('%s','now') WHERE id = ?", world.member)
	get(t, pathOrg, world.memberToken).expect(t, "revoked, list", http.StatusUnauthorized, codeUnauthenticated)
	orgCreate(t, world.memberToken, "x").expect(t, "revoked, create", http.StatusUnauthorized, codeUnauthenticated)
}

// ---- create ----------------------------------------------------------------

// TestOrgCreateIsOnlyASandbox: POST /api/org makes a sandbox whoever asks, and no
// body can make a standard organization: a member of an organization, an
// administrator of one and a platform administrator are all given a sandbox, and
// keep the organization they have.
//
//nolint:paralleltest // shares one database
func TestOrgCreateIsOnlyASandbox(t *testing.T) {
	world := orgNewWorld(t)

	for _, who := range []struct{ name, token, user string }{
		{"a member", world.memberToken, world.member},
		{"an administrator", world.adminToken, world.admin},
		{"a platform administrator", world.platformToken, world.platform},
	} {
		before := orgMembership(t, who.user)

		got := orgCreate(t, who.token, "Scratch")
		got.expect(t, who.name+" creates", http.StatusCreated, "")

		if view := orgDecode[orgView](t, got); view.Kind != "sandbox" || view.Status != "active" || view.CreatedBy != who.user {
			t.Errorf("%s created %+v, want an active sandbox of theirs", who.name, view)
		}

		if after := orgMembership(t, who.user); after != before {
			t.Errorf("%s belonged to %s and now belongs to %s, want it unchanged", who.name, before, after)
		}
	}

	// A kind cannot be asked for: a standard organization is not created through
	// the API, and neither is a sandbox said to be one.
	for _, body := range []string{`{"kind":"standard","name":"Mine"}`, `{"kind":"sandbox","name":"Mine"}`} {
		post(t, pathOrg, []byte(body), world.outsiderToken).expect(t, body, http.StatusBadRequest, "unknown_field")
	}

	expectCount(t, "orgs WHERE kind = 'standard'", "3")
	expectCount(t, "orgs WHERE kind = 'sandbox'", "3")
	expectCount(t, "orgs", "6")
}

// TestOrgCreateSandbox: a sandbox expires a week after it is made, its creator
// administers it and does not belong to it, and the response is the stored row.
//
//nolint:paralleltest // shares one database
func TestOrgCreateSandbox(t *testing.T) {
	world := orgNewWorld(t)

	before := time.Now().Unix()
	got := orgCreate(t, world.outsiderToken, "Scratch")
	after := time.Now().Unix()

	got.expect(t, "create", http.StatusCreated, "")

	view := orgDecode[orgView](t, got)

	if view.Kind != "sandbox" || view.Status != "active" || view.ExpiresAt == nil ||
		*view.ExpiresAt < before+orgSandboxLife || *view.ExpiresAt > after+orgSandboxLife {
		t.Errorf("created = %+v, want an active sandbox expiring a week after [%d, %d]", view, before, after)
	}

	expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", view.ID, world.outsider)

	if got := orgMembership(t, world.outsider); got != world.outsiderOrg {
		t.Errorf("the sandbox's creator belongs to %s, want its own organization", got)
	}

	// Its administrator reads it, and it is listed for them.
	get(t, orgItem(view.ID), world.outsiderToken).expect(t, "read", http.StatusOK, "")

	page := orgDecode[orgPage](t, get(t, pathOrg, world.outsiderToken))
	if len(page.Orgs) != 2 || page.Orgs[0].ID != view.ID || page.Orgs[1].ID != world.outsiderOrg {
		t.Errorf("list = %+v, want the sandbox and then their own organization", page.Orgs)
	}

	// A sandbox has no members.
	get(t, orgItem(view.ID)+"/member", world.outsiderToken).expect(t, "members", http.StatusConflict, orgCodeNotStandard)
}

// orgNameCase is a body that carries an organization's or sandbox's name at a
// bound of its parser: code is the refusal, or "" when it is accepted as stored.
type orgNameCase struct {
	name, body, code, stored string
}

// orgNameCases are the names at their bounds, which a create and a rename
// treat alike: the bound is 256 runes, and not bytes (a four-byte rune is the
// widest, 1024 bytes in all, which is also what the column's CHECK allows), and
// a name that is not text a person could read, or that no JSON parser reads
// the same way, is refused.
func orgNameCases() []orgNameCase {
	four := "\U0001F600"

	return []orgNameCase{
		{"256 four-byte runes (1024 bytes)", `{"name":"` + strings.Repeat(four, orgNameRunes) + `"}`, "", strings.Repeat(four, orgNameRunes)},
		{"256 four-byte runes, each escaped as a surrogate pair", `{"name":"` + strings.Repeat(`\ud83d\ude00`, orgNameRunes) + `"}`, "", strings.Repeat(four, orgNameRunes)},
		{"256 ASCII runes", `{"name":"` + strings.Repeat("x", orgNameRunes) + `"}`, "", strings.Repeat("x", orgNameRunes)},
		{"257 four-byte runes (1028 bytes)", `{"name":"` + strings.Repeat(four, orgNameRunes+1) + `"}`, "invalid_org_name", ""},
		{"257 four-byte runes, each escaped as a surrogate pair", `{"name":"` + strings.Repeat(`\ud83d\ude00`, orgNameRunes+1) + `"}`, "invalid_org_name", ""},
		{"257 ASCII runes", `{"name":"` + strings.Repeat("x", orgNameRunes+1) + `"}`, "invalid_org_name", ""},
		{"256 four-byte runes and one more of one byte", `{"name":"` + strings.Repeat(four, orgNameRunes) + `x"}`, "invalid_org_name", ""},
		{"an escaped NUL", `{"name":"a\u0000b"}`, "invalid_org_name", ""},
		{"a name that is only an escaped NUL", `{"name":"\u0000"}`, "invalid_org_name", ""},
		{"a raw NUL byte", "{\"name\":\"a\x00b\"}", "invalid_json", ""},
		{"invalid UTF-8", "{\"name\":\"a\xffb\"}", "invalid_text", ""},
		{"invalid UTF-8 at the end", "{\"name\":\"a\xf0\x9f\"}", "invalid_text", ""},
		{"an overlong encoding", "{\"name\":\"\xc0\xaf\"}", "invalid_text", ""},
		{"a lone high surrogate escape", `{"name":"a\ud800"}`, "invalid_text", ""},
		{"a lone low surrogate escape", `{"name":"a\udc00"}`, "invalid_text", ""},
		{"an escaped replacement character", `{"name":"a\ufffdb"}`, "invalid_text", ""},
		{"a replacement character", "{\"name\":\"a\ufffdb\"}", "invalid_text", ""},
		{"a name of spaces", `{"name":"   "}`, "invalid_org_name", ""},
		{"a name of a control character", `{"name":"a\u0007b"}`, "invalid_org_name", ""},
	}
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
		{"a kind of standard", `{"kind":"standard","name":"x"}`, "unknown_field"},
		{"a kind of sandbox", `{"kind":"sandbox","name":"x"}`, "unknown_field"},
		{"no name", `{}`, "invalid_org_name"},
		{"an empty name", `{"name":""}`, "invalid_org_name"},
		{"a name with NUL", `{"name":"a\u0000b"}`, "invalid_org_name"},
		{"a name of 257 runes", `{"name":"` + strings.Repeat("x", orgNameRunes+1) + `"}`, "invalid_org_name"},
		{"an expiry of the client's choosing", `{"name":"x","expiresAt":1}`, "unknown_field"},
		{"a creator of the client's choosing", `{"name":"x","createdBy":"` + world.admin + `"}`, "unknown_field"},
		{"a repeated name", `{"name":"x","name":"y"}`, "duplicate_field"},
		{"a name that is a number", `{"name":1}`, "invalid_field_type"},
	}

	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			post(t, pathOrg, []byte(tc.body), world.outsiderToken).expect(t, tc.name, http.StatusBadRequest, tc.code)
		})
	}

	expectCount(t, "orgs", "3")

	for _, tc := range orgNameCases() {
		t.Run("a name of "+tc.name, func(t *testing.T) {
			got := post(t, pathOrg, []byte(tc.body), world.outsiderToken)

			if tc.code != "" {
				got.expect(t, tc.name, http.StatusBadRequest, tc.code)

				return
			}

			got.expect(t, tc.name, http.StatusCreated, "")

			if view := orgDecode[orgView](t, got); view.Name != tc.stored {
				t.Errorf("name came back as %d bytes, want the %d sent", len(view.Name), len(tc.stored))
			}

			expectCount(t, "orgs WHERE id = ? AND name = ?", "1", orgDecode[orgView](t, got).ID, tc.stored)
		})
	}

	for name, value := range map[string]string{
		"256 ASCII runes":                strings.Repeat("x", orgNameRunes),
		"256 four-byte runes (1024 B)":   strings.Repeat("\U0001F600", orgNameRunes),
		"one rune":                       "x",
		"a name with a quote and a tab":  "a\"b\\c",
		"a name that is a path or a tag": "../<b>x</b>",
	} {
		t.Run("accepts "+name, func(t *testing.T) {
			got := orgCreate(t, world.outsiderToken, value)
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
		seed(t, insertOrg, idN(fam, i+1), schemaKindSandbox, "seeded", creator, expires, int64(1_700_000_000))
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
	first := orgCreate(t, world.outsiderToken, "24th")
	first.expect(t, "24th", http.StatusCreated, "")

	replies := orgRelease(4, func(int) reply { return orgCreate(t, world.outsiderToken, "race") })
	orgNo5xx(t, "creates at the limit", replies)

	tally := orgTally(replies)
	if tally["Created"] != 1 || tally["Conflict "+orgCodeSandboxLimit] != 3 {
		t.Errorf("tally = %v, want one Created and three Conflict %s", tally, orgCodeSandboxLimit)
	}

	expectCount(t, "orgs WHERE kind = 'sandbox' AND created_by = ? AND expires_at > strftime('%s','now')", "25", world.outsider)

	orgCreate(t, world.outsiderToken, "26th").expect(t, "26th", http.StatusConflict, orgCodeSandboxLimit)

	// The limit is per user: another account has all 25 of its own.
	orgCreate(t, world.memberToken, "other user").expect(t, "another user", http.StatusCreated, "")

	// Deleting one makes room, and only one.
	del(t, orgItem(first.mustView(t).ID), world.outsiderToken).expect(t, "delete", http.StatusOK, "")
	orgCreate(t, world.outsiderToken, "again").expect(t, "after delete", http.StatusCreated, "")
	orgCreate(t, world.outsiderToken, "over").expect(t, "over again", http.StatusConflict, orgCodeSandboxLimit)

	// A sandbox that expires this very second no longer counts.
	seed(t, "UPDATE orgs SET expires_at = strftime('%s','now') WHERE id = ?", idN(orgFamSandbox, 1))
	orgCreate(t, world.outsiderToken, "after expiry").expect(t, "expired one", http.StatusCreated, "")
}

// mustView decodes a created organization.
func (r reply) mustView(t *testing.T) orgView {
	t.Helper()

	return orgDecode[orgView](t, r)
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
	}{
		{"an administrator", world.adminToken, ok, ok, ok},
		{"a second administrator", world.secondToken, ok, ok, ok},
		{"a member", world.memberToken, ok, denied, ok},
		{"an outsider", world.outsiderToken, hidden, hidden, hidden},
		{"a platform administrator", world.platformToken, ok, ok, ok},
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
		})
	}

	// A member who is not an administrator cannot change the organization or its
	// people: nothing below changes a row.
	for what, got := range map[string]reply{
		"delete":  del(t, orgItem(world.org), world.memberToken),
		"promote": patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.memberToken),
		"demote":  patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.memberToken),
		"revoke":  del(t, pathMember+"/"+world.second, world.memberToken),
	} {
		got.expect(t, what+" by a member", http.StatusForbidden, orgCodeNotAdmin)
	}

	for what, got := range map[string]reply{
		"delete":  del(t, orgItem(world.org), world.outsiderToken),
		"promote": patch(t, pathMember+"/"+world.member, []byte(`{"admin":true}`), world.outsiderToken),
		"revoke":  del(t, pathMember+"/"+world.member, world.outsiderToken),
	} {
		code := orgCode(what)
		got.expect(t, what+" by an outsider", http.StatusNotFound, code)
	}

	expectCount(t, "orgs", "3")
	expectCount(t, "org_admins WHERE org_id = ?", "2", world.org)
	expectCount(t, "users WHERE org_id = ?", "3", world.org)
	expectCount(t, "users WHERE revoked_at IS NOT NULL", "0")
	expectCount(t, "orgs WHERE id = ? AND name <> 'Acme'", "0", world.org)

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
	if what == "promote" || what == "revoke" || what == "demote" {
		return orgCodeMemberMissing
	}

	return orgCodeNotFound
}

// TestOrgListAndPaging: a member lists their organization, an outsider their own
// organization and their sandboxes, a platform administrator all of them, with keyset paging that
// neither skips nor repeats a row.
//
//nolint:paralleltest // shares one database
func TestOrgListAndPaging(t *testing.T) {
	world := orgNewWorld(t)

	// Seven more organizations nobody here belongs to, and three sandboxes of the
	// outsider, who has an organization of their own besides.
	for i := range 7 {
		seed(t, insertOrg, idN(orgFamOrg, 10+i), schemaKindStandard, "other", world.platform, nil, int64(1_700_000_000))
	}

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

	if page := list(world.outsiderToken, ""); len(page.Orgs) != 4 {
		t.Errorf("an outsider lists %d, want their organization and their three sandboxes", len(page.Orgs))
	}

	// The outsider's three sandboxes and their own organization, one to a page,
	// come newest first and none is skipped or repeated: each source of the list
	// is cut at the cursor.
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

	if want := []string{
		idN(orgFamSandbox, 3), idN(orgFamSandbox, 2), idN(orgFamSandbox, 1), world.outsiderOrg,
	}; !slices.Equal(ids, want) {
		t.Errorf("the outsider paged through %v, want %v", ids, want)
	}

	// All of them, 13 in all, three at a time: ids newest first, none twice.
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

		if pages > 8 {
			t.Fatal("paging does not end")
		}
	}

	if len(seen) != 13 {
		t.Errorf("a platform administrator paged through %d organizations, want all 13", len(seen))
	}

	for _, query := range []string{"?limit=0", "?limit=101", "?limit=x", "?limit=1&limit=2", "?cursor=nope", "?cursor="} {
		get(t, pathOrg+query, world.platformToken).expect(t, query, http.StatusBadRequest, "")
	}
}

// ---- change ----------------------------------------------------------------

// TestOrgRename: renaming, and the platform administrator's override. A rename
// changes the name and nothing else.
//
//nolint:paralleltest // shares one database
func TestOrgRename(t *testing.T) {
	world := orgNewWorld(t)
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

	// The names at the bounds of the parser, as a create has them: a refusal
	// leaves the name as it was, and an acceptance stores it as sent.
	for _, tc := range orgNameCases() {
		t.Run("a name of "+tc.name, func(t *testing.T) {
			current := scalar(t, "SELECT name FROM orgs WHERE id = ?", world.org)
			got := patch(t, orgItem(world.org), []byte(tc.body), world.adminToken)

			if tc.code != "" {
				got.expect(t, tc.name, http.StatusBadRequest, tc.code)
				expectCount(t, "orgs WHERE id = ? AND name = ?", "1", world.org, current)

				return
			}

			got.expect(t, tc.name, http.StatusOK, "")

			if view := orgDecode[orgView](t, got); view.Name != tc.stored {
				t.Errorf("name came back as %d bytes, want the %d sent", len(view.Name), len(tc.stored))
			}

			expectCount(t, "orgs WHERE id = ? AND name = ?", "1", world.org, tc.stored)
		})
	}

	// The same bound holds for a sandbox, whose name its administrator changes.
	sandbox := idN(orgFamSandbox, 1)
	orgSeedSandboxes(t, orgFamSandbox, 1, world.outsider, time.Now().Unix()+3600)

	for _, tc := range orgNameCases() {
		t.Run("a sandbox's name of "+tc.name, func(t *testing.T) {
			got := patch(t, orgItem(sandbox), []byte(tc.body), world.outsiderToken)

			if tc.code != "" {
				got.expect(t, tc.name, http.StatusBadRequest, tc.code)

				return
			}

			got.expect(t, tc.name, http.StatusOK, "")
			expectCount(t, "orgs WHERE id = ? AND name = ?", "1", sandbox, tc.stored)
		})
	}

	// The platform administrator renames anything.
	patch(t, orgItem(world.org), []byte(`{"name":"By platform"}`), world.platformToken).
		expect(t, "platform rename", http.StatusOK, "")

	expectCount(t, "orgs WHERE id = ? AND name = 'By platform' AND kind = 'standard'", "1", world.org)
	expectCount(t, "users WHERE org_id = ?", "3", world.org)
	expectCount(t, "org_admins WHERE org_id = ?", "2", world.org)
}

// TestOrgDeleteRefusesAStandardOrganization: a standard organization is never
// deleted, by anyone. Whoever can see it is told so (409), after the checks on
// who may act: a member who does not administer it is told that first (403), and
// an outsider is told it is not found, as for an id that does not exist.
//
//nolint:paralleltest // shares one database
func TestOrgDeleteRefusesAStandardOrganization(t *testing.T) {
	world := orgNewWorld(t)

	for _, tc := range []struct {
		name, token string
		status      int
		code        string
	}{
		{"an administrator", world.adminToken, http.StatusConflict, orgCodeNotSandbox},
		{"a second administrator", world.secondToken, http.StatusConflict, orgCodeNotSandbox},
		{"a platform administrator", world.platformToken, http.StatusConflict, orgCodeNotSandbox},
		{"a member", world.memberToken, http.StatusForbidden, orgCodeNotAdmin},
		{"an outsider", world.outsiderToken, http.StatusNotFound, orgCodeNotFound},
	} {
		del(t, orgItem(world.org), tc.token).expect(t, tc.name, tc.status, tc.code)
	}

	// The refusal is the same each time, and nothing changed.
	del(t, orgItem(world.org), world.adminToken).expect(t, "again", http.StatusConflict, orgCodeNotSandbox)

	expectCount(t, "orgs WHERE id = ? AND kind = 'standard'", "1", world.org)
	expectCount(t, "org_admins WHERE org_id = ?", "2", world.org)
	expectCount(t, "users WHERE org_id = ?", "3", world.org)
	get(t, orgItem(world.org), world.memberToken).expect(t, "still readable", http.StatusOK, "")
}

// ---- members ---------------------------------------------------------------

// orgMembers reads GET /api/org/{id}/member as the token.
func orgMembers(t *testing.T, org, token, query string) orgPage {
	t.Helper()

	got := get(t, orgItem(org)+"/member"+query, token)
	got.expect(t, "members", http.StatusOK, "")

	return orgDecode[orgPage](t, got)
}

// TestOrgMembers: the member list with who administers, paging, the body of a
// promotion or a demotion, and how a revoked member is listed. Who may promote
// and demote whom, each idempotent, with the last unrevoked administrator never
// demoted and a revoked member never promoted, is TestOrgMemberAuthority.
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

	// A body that does not say whether the member is to administer, or says it as
	// no boolean, is refused before anyone's authority is asked: nothing is
	// written. Who may promote or demote whom, with what answer, is
	// TestOrgMemberAuthority's table.
	for _, body := range []string{`{}`, `{"admin":null}`} {
		patch(t, pathMember+"/"+world.member, []byte(body), world.adminToken).
			expect(t, body, http.StatusBadRequest, orgCodeMissingAdmin)
	}

	for _, body := range []string{`{"admin":"yes"}`, `{"admin":1}`, `{"admin":true,"orgId":"x"}`, ``} {
		patch(t, pathMember+"/"+world.member, []byte(body), world.adminToken).expect(t, body, http.StatusBadRequest, "")
	}

	expectCount(t, "org_admins WHERE org_id = ?", "2", world.org)

	// A revoked member stays listed, as revoked and never as an administrator
	// whatever they administered.
	seed(t, "UPDATE users SET revoked_at = 5 WHERE id = ?", world.second)

	for _, m := range orgMembers(t, world.org, world.adminToken, "").Members {
		if m.ID == world.second && (m.Status != "revoked" || m.RevokedAt == nil || m.Admin) {
			t.Errorf("revoked member = %+v, want it listed as revoked and not an administrator", m)
		}
	}
}

// orgRevoked decodes a member reply and holds that it shows the account as
// revoked, at the stored time, and not as an administrator.
func orgRevoked(t *testing.T, what string, got reply, id string) {
	t.Helper()

	got.expect(t, what, http.StatusOK, "")

	member := orgDecode[orgMemberView](t, got)
	stored := scalar(t, "SELECT revoked_at FROM users WHERE id = ?", id)

	if member.ID != id || member.Status != "revoked" || member.Admin || member.RevokedAt == nil ||
		strconv.FormatInt(*member.RevokedAt, 10) != stored {
		t.Errorf("%s: %+v, want %s revoked at %s", what, member, id, stored)
	}
}

// TestOrgRevokeMember is what a revocation through DELETE /api/member/{id} does
// (docs/users_design.md), told as one sequence: a revoked account stays in the
// organization, listed as revoked and no longer as an administrator, its keys and
// agents end with it, a second revocation keeps the first time, and a platform
// administrator reaches the last administrator of an organization. Who may
// revoke whom, and that every refusal changes nothing, is the table of
// TestOrgRevokeMemberAuthority.
//
//nolint:paralleltest // shares one database
func TestOrgRevokeMember(t *testing.T) {
	world := orgNewWorld(t)

	// The platform administrator also belongs to the organization, as an
	// account of one does, without administering it. A key and an agent for
	// each of the member and the second administrator.
	orgJoin(t, world.org, world.platform, false)

	seedAgent(t, idN(orgFamAgent, 1), world.member, "agent")
	memberKey := seedAPIKey(t, idN(orgFamKey, 1), world.member, "")
	seedAgent(t, idN(orgFamAgent, 3), world.second, "agent")
	seedAPIKey(t, idN(orgFamKey, 3), world.second, idN(orgFamAgent, 3))

	// Who may revoke whom, and that a refusal changes nothing, is the table of
	// TestOrgRevokeMemberAuthority. What follows is what a revocation does.

	// A foreign administrator is told what a missing user is told, byte for byte.
	other := idN(orgFamOrg, 2)
	orgSeedStandard(t, other, world.outsider)
	orgJoin(t, other, world.outsider, true)

	foreign := del(t, pathMember+"/"+world.member, world.outsiderToken)
	missing := del(t, pathMember+"/"+idMissing, world.outsiderToken)
	foreign.expect(t, "foreign administrator", http.StatusNotFound, orgCodeMemberMissing)

	if foreign.body != missing.body {
		t.Errorf("foreign administrator is told %q, a missing user %q", foreign.body, missing.body)
	}

	// An administrator revokes a member: shown as revoked, kept in the
	// organization, its secrets and agents revoked, nobody else's touched.
	orgRevoked(t, "revoke a member", del(t, pathMember+"/"+world.member, world.adminToken), world.member)

	if got := orgMembership(t, world.member); got != world.org {
		t.Errorf("the revoked member belongs to %s, want the organization %s", got, world.org)
	}

	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NOT NULL", "1", idOfToken(t, memberKey))
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NOT NULL", "1", world.member)
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NOT NULL", "0", world.second)
	expectCount(t, "users WHERE revoked_at IS NOT NULL", "1")
	get(t, pathSession, world.memberToken).expect(t, "the revoked member's session", http.StatusUnauthorized, "")

	// Revoking again keeps the first time, for the administrator and for a platform
	// administrator, and a revoked account is still listed with its organization.
	first := scalar(t, "SELECT revoked_at FROM users WHERE id = ?", world.member)

	orgRevoked(t, "revoke again", del(t, pathMember+"/"+world.member, world.adminToken), world.member)
	orgRevoked(t, "revoke again, platform", del(t, pathMember+"/"+world.member, world.platformToken), world.member)

	if got := scalar(t, "SELECT revoked_at FROM users WHERE id = ?", world.member); got != first {
		t.Errorf("revoked_at moved from %s to %s", first, got)
	}

	// An administrator revokes the other administrator, who stays listed as
	// revoked and is no longer an administrator, and the organization keeps the
	// one who revoked.
	orgRevoked(t, "revoke an administrator", del(t, pathMember+"/"+world.second, world.adminToken), world.second)
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NOT NULL", "1", world.second)
	expectCount(t, "api_keys k JOIN secrets s ON s.id = k.id WHERE k.user_id = ? AND s.revoked_at IS NOT NULL", "1",
		world.second)
	expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id WHERE a.org_id = ? AND u.revoked_at IS NULL", "1",
		world.org)

	var listed int

	for _, m := range orgMembers(t, world.org, world.adminToken, "").Members {
		if m.Status == "revoked" {
			listed++

			if m.Admin || m.OrgID != world.org || m.RevokedAt == nil {
				t.Errorf("revoked member listed as %+v", m)
			}
		}
	}

	if listed != 2 {
		t.Errorf("%d revoked members listed, want 2", listed)
	}

	// The revoked administrator can do nothing, and the one left cannot be
	// demoted into an organization without one.
	patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.adminToken).
		expect(t, "demoting the last administrator", http.StatusConflict, orgCodeLastAdmin)

	// A platform administrator revokes a platform administrator, an
	// administrator of an organization and the last administrator of one, and
	// then may revoke themself only while another remains.
	extra := orgUser(6)
	seedUser(t, extra, roleAdmin)
	orgJoin(t, world.org, extra, false)

	orgRevoked(t, "platform revokes platform", del(t, pathMember+"/"+extra, world.platformToken), extra)
	orgRevoked(t, "platform revokes the last administrator", del(t, pathMember+"/"+world.admin, world.platformToken), world.admin)
	expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id WHERE a.org_id = ? AND u.revoked_at IS NULL", "0",
		world.org)
	orgSoleStillRefused(t, world)
}

// orgSoleStillRefused holds that the only platform administrator, who has revoked
// everyone else they could, still cannot revoke themself, through either route.
func orgSoleStillRefused(t *testing.T, world orgWorld) {
	t.Helper()

	del(t, pathMember+"/"+world.platform, world.platformToken).
		expect(t, "the only platform administrator by member", http.StatusConflict, orgCodeLastPlatform)
	del(t, usrItem(world.platform), world.platformToken).
		expect(t, "the only platform administrator by user", http.StatusConflict, orgCodeLastPlatform)
	expectCount(t, "users WHERE id = ? AND revoked_at IS NULL", "1", world.platform)
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
// race: an administrator of a standard organization who is not a member; a
// standard organization with no administrator; an agent that survives its
// sandbox, or a key its agent; and a secret with no row.
func orgExpectSound(t *testing.T) {
	t.Helper()

	expectCount(t, "org_admins a JOIN orgs o ON o.id = a.org_id WHERE o.kind = 'standard' "+
		"AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = a.user_id AND u.org_id = a.org_id)", "0")
	// The own organization a seeded account is given (seedAccount) is named
	// "seeded" and has no administrator row.
	expectCount(t, "orgs o WHERE o.kind = 'standard' AND o.name <> 'seeded' "+
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

// orgRaceRevokeEachOther: two administrators revoke each other at once. Exactly one revocation succeeds:
// the other was made by an account that was revoked first, which is told it is signed out or that
// the member is not found, and the organization keeps one unrevoked administrator.
func orgRaceRevokeEachOther() orgRace {
	return orgRace{
		name: "two administrators revoke each other", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply { return del(t, pathMember+"/"+world.second, world.adminToken) },
					func() reply { return del(t, pathMember+"/"+world.admin, world.secondToken) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					if tally := orgTally(replies); tally["OK"] != 1 {
						t.Errorf("tally = %v, want exactly one OK", tally)
					}

					for i, got := range replies {
						if got.status != http.StatusOK {
							orgOneOf(t, "the revocation "+strconv.Itoa(i), got, http.StatusNotFound, http.StatusUnauthorized)
						}
					}

					expectCount(t, "users WHERE id IN (?, ?) AND revoked_at IS NOT NULL", "1", world.admin, world.second)
					expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id "+
						"WHERE a.org_id = ? AND u.revoked_at IS NULL", "1", world.org)
				},
			}
		},
	}
}

// orgRaceDemoteWhileRevoking: an administrator is demoted by the other while they revoke the other.
// Whichever is first, the second finds the state it left: a demoted administrator may not revoke, and
// a revoked one may not demote. One administrator is left whichever order the two take.
func orgRaceDemoteWhileRevoking() orgRace {
	return orgRace{
		name: "an administrator is demoted while they revoke the one who demotes them", rounds: 12,
		build: func(t *testing.T, world orgWorld) orgRound {
			t.Helper()

			return orgRound{
				racers: []func() reply{
					func() reply {
						return patch(t, pathMember+"/"+world.second, []byte(`{"admin":false}`), world.adminToken)
					},
					func() reply { return del(t, pathMember+"/"+world.admin, world.secondToken) },
				},
				judge: func(t *testing.T, replies []reply) {
					t.Helper()

					if tally := orgTally(replies); tally["OK"] != 1 {
						t.Errorf("tally = %v, want exactly one OK", tally)
					}

					orgOneOf(t, "the demotion", replies[0], http.StatusOK, http.StatusNotFound, http.StatusUnauthorized)
					orgOneOf(t, "the revocation", replies[1], http.StatusOK, http.StatusForbidden)

					expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id "+
						"WHERE a.org_id = ? AND u.revoked_at IS NULL", "1", world.org)
				},
			}
		},
	}
}

// orgRaceDemoteAndRevoke: both administrators demote each other and revoke each other at once. However
// the four requests fall, one unrevoked administrator remains.
func orgRaceDemoteAndRevoke() orgRace {
	return orgRace{
		name: "two administrators demote and revoke each other at once", rounds: 12,
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
					func() reply { return del(t, pathMember+"/"+world.second, world.adminToken) },
					func() reply { return del(t, pathMember+"/"+world.admin, world.secondToken) },
				},
				judge: func(t *testing.T, _ []reply) {
					t.Helper()

					expectCount(t, "org_admins a JOIN users u ON u.id = a.user_id "+
						"WHERE a.org_id = ? AND u.revoked_at IS NULL", "1", world.org)
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
		orgRaceRevokeEachOther(),
		orgRaceDemoteWhileRevoking(),
		orgRaceDemoteAndRevoke(),
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
// rule is that demoting the last unrevoked administrator is refused, and that an
// organization's own administrators never revoke each other or themselves down to
// none. A platform administrator revoking their ACCOUNT is not refused, because
// refusing it would let an organization administrator shield themselves from
// platform revocation. The organization is then left with no unrevoked
// administrator, which no organization administrator can change, and a platform
// administrator's override is how it is managed: they promote a member, who is then
// the administrator.
//
//nolint:paralleltest // shares one database
func TestOrgRevokingTheLastAdministratorsAccountIsNotRefused(t *testing.T) {
	world := orgNewWorld(t)

	// The second administrator steps down, so the first is the last.
	patch(t, pathMember+"/"+world.second, []byte(`{"admin":false}`), world.adminToken).
		expect(t, "the second administrator steps down", http.StatusOK, "")

	// The last one cannot be demoted, and cannot revoke themself.
	patch(t, pathMember+"/"+world.admin, []byte(`{"admin":false}`), world.adminToken).
		expect(t, "demoting the last administrator", http.StatusConflict, orgCodeLastAdmin)
	del(t, pathMember+"/"+world.admin, world.adminToken).
		expect(t, "the last administrator revoking themself", http.StatusForbidden, orgCodeSelfRevoke)

	// Their account may be revoked by a platform administrator all the same, by
	// either route.
	del(t, usrItem(world.admin), world.platformToken).
		expect(t, "revoking the last administrator's account", http.StatusOK, "")

	get(t, pathSession, world.adminToken).expect(t, "the revoked administrator's session", http.StatusUnauthorized, "")
	expectCount(t, "orgs WHERE id = ?", "1", world.org)
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
		{"delete", http.MethodDelete, orgItem(idMissing), orgSmallCap},
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
	body := []byte(`{"name":"` + escaped + `"}`)

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

	allOrg := `["org:read","sandbox:create","org:update","sandbox:revoke","member:read","member:update","member:revoke"]`

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

	for what, got := range map[string]reply{
		"create":  as(freeKey, http.MethodPost, pathOrg, orgCreateBody(t, "x")),
		"rename":  as(freeKey, http.MethodPatch, orgItem(world.org), []byte(`{"name":"x"}`)),
		"delete":  as(freeKey, http.MethodDelete, orgItem(world.org), nil),
		"promote": as(freeKey, http.MethodPatch, pathMember+"/"+world.member, []byte(`{"admin":true}`)),
		"revoke":  as(freeKey, http.MethodDelete, pathMember+"/"+world.member, nil),
	} {
		got.expect(t, "agent "+what, http.StatusForbidden, "")
	}

	// An agent confined to a sandbox reaches no organization route.
	for what, got := range map[string]reply{
		"list":   as(confinedKey, http.MethodGet, pathOrg, nil),
		"get":    as(confinedKey, http.MethodGet, orgItem(sandbox), nil),
		"create": as(confinedKey, http.MethodPost, pathOrg, orgCreateBody(t, "x")),
		"delete": as(confinedKey, http.MethodDelete, orgItem(sandbox), nil),
	} {
		got.expect(t, "confined agent "+what, http.StatusForbidden, "")
	}

	expectCount(t, "orgs", "4")
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
			expect(t, "rename expired", http.StatusConflict, orgCodeExpired)

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
	expectCount(t, "orgs WHERE id = ?", "1", idN(famOrg, 1))
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
