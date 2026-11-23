//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit // route x case sweeps nest loops and repeat case names on purpose
package e2e_test

// boundary_test.go proves everything that happens BEFORE a feature handler runs,
// across the whole API, against the real TinyGo wasm behind workerd. Unit tests
// drive httptest with Go's net/http; only here do TinyGo's ServeMux (which never
// matches method-qualified patterns), its http.MaxBytesReader, its cookie and
// header parsing and workerd's own request handling decide the outcome.
//
// The order of checks is the contract in docs/ARCHITECTURE.md and internal/auth:
// method (405), media type (415), body limit (413), path ids (400), then
// authentication (401), then the requirement (403), then the handler. Every
// table below is generated from ONE route inventory (bndRoutes), and
// TestBndInventoryIsTheWholeSurface cross-checks that inventory against the
// real Worker, so a route added to the product without being listed here (or
// the reverse) fails.
//
// REVIEW.md categories covered: input edge cases (paths, ids, headers, cookies,
// content types), payload size (every cap at -1/0/+1 and far over, including
// chunked bodies and before authentication), permission confusion (role x route
// x credential, role changes mid-session, token confusion), and no information
// oracle (byte-identical 401 bodies; no internals in any error body).

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- the route inventory ----------------------------------------------------

// bndAccess is what a route demands of the caller.
type bndAccess int

const (
	bndPublic bndAccess = iota // no credential
	bndAnySession
	bndAdminOnly
)

// bndRoute is one route of the public surface.
type bndRoute struct {
	name   string
	method string
	// pattern is the declared path; {id} is replaced by an id for requests.
	pattern string
	access  bndAccess
	// maxBody is the route's declared cap in bytes (httpapi.DefaultMaxBody = 1 MiB when unset).
	maxBody int
	// body is a well-formed body the route's handler accepts or at least
	// reaches its own validation with (used to prove "nothing written" on 401/403).
	body string
	// writes names a table whose row count must not change when the request is
	// refused before the handler (401/403/4xx at the boundary); "" for none.
	writes string
}

const (
	bndKiB       = 1 << 10
	bndDefaultMB = 1 << 20
	bndIDToken   = "{id}"
)

// bndRoutes is the complete public surface, derived from the Routes()
// declarations of internal/{firstrun,registration,login,session,agents,
// invitations,users,orgs} and internal/app/app.go (/healthz). The caps are the
// production constants (MaxBeginBody, MaxFinishBody, invitations.MaxBody, the
// users maxBody, the orgs maxBody and maxSmallBody) and httpapi.DefaultMaxBody
// for a route that declares none.
func bndRoutes() []bndRoute {
	return slices.Concat(bndPublicRoutes(), bndSessionInventory(), bndOrgInventory(), bndAdminInventory())
}

// bndPublicRoutes are the routes that need no credential.
func bndPublicRoutes() []bndRoute {
	const regBegin = `{"invitationCode":"x","name":"n","email":"n@example.com"}`

	return []bndRoute{
		bndRouteOf("healthz", http.MethodGet, "/healthz", bndPublic, bndDefaultMB, "", ""),
		bndRouteOf("first-run", http.MethodGet, "/api/first-run", bndPublic, bndDefaultMB, "", ""),
		bndRouteOf("register begin", http.MethodPost, "/api/register/begin", bndPublic, 4*bndKiB, regBegin, "users"),
		bndRouteOf("register finish", http.MethodPost, "/api/register/finish", bndPublic, 32*bndKiB, `{}`, "users"),
		bndRouteOf("login begin", http.MethodPost, "/api/login/begin", bndPublic, bndKiB, `{}`, ""),
		bndRouteOf("login finish", http.MethodPost, "/api/login/finish", bndPublic, 16*bndKiB, `{}`, "sessions"),
	}
}

// bndSessionInventory are the routes any signed-in caller may use.
func bndSessionInventory() []bndRoute {
	const (
		item     = "/api/agent/" + bndIDToken
		revoked  = "secrets WHERE revoked_at IS NOT NULL"
		renamed  = "agents WHERE name = 'renamed'"
		archived = "agents WHERE revoked_at IS NOT NULL"
	)

	session := bndAnySession

	return []bndRoute{
		bndRouteOf("session", http.MethodGet, "/api/session", session, bndDefaultMB, "", ""),
		bndRouteOf("logout", http.MethodPost, "/api/logout", session, bndDefaultMB, "", revoked),
		bndRouteOf("agent list", http.MethodGet, "/api/agent", session, 8*bndKiB, "", ""),
		bndRouteOf("agent create", http.MethodPost, "/api/agent", session, 8*bndKiB, `{"name":"bnd"}`, "agents"),
		bndRouteOf("agent get", http.MethodGet, item, session, 8*bndKiB, "", ""),
		bndRouteOf("agent rename", http.MethodPatch, item, session, 8*bndKiB, `{"name":"renamed"}`, renamed),
		bndRouteOf("agent revoke", http.MethodDelete, item, session, 8*bndKiB, "", archived),
	}
}

// bndOrgInventory are the organization routes. Each needs a session and its own
// scope and no role: whether the caller may act on an organization is decided
// in the write, so at the boundary they are any-session routes. The ids in the
// patterns are an organization's or a user's (a member is named by its user);
// bndWorld.idFor says which a pattern takes.
func bndOrgInventory() []bndRoute {
	const (
		org    = "/api/org/" + bndIDToken
		member = "/api/member/" + bndIDToken
	)

	session := bndAnySession

	return []bndRoute{
		bndRouteOf("sandbox create", http.MethodPost, "/api/org", session, 8*bndKiB, `{"name":"bnd"}`, "orgs"),
		bndRouteOf("org list", http.MethodGet, "/api/org", session, bndKiB, "", ""),
		bndRouteOf("org get", http.MethodGet, org, session, bndKiB, "", ""),
		bndRouteOf("org rename", http.MethodPatch, org, session, 8*bndKiB, `{"name":"renamed"}`,
			"orgs WHERE name = 'renamed'"),
		bndRouteOf("org delete", http.MethodDelete, org, session, bndKiB, "", "orgs"),
		bndRouteOf("member list", http.MethodGet, org+"/member", session, bndKiB, "", ""),
		bndRouteOf("member update", http.MethodPatch, member, session, bndKiB, `{"admin":true}`, "org_admins"),
		bndRouteOf("member revoke", http.MethodDelete, member, session, bndKiB, "", "users WHERE revoked_at IS NOT NULL"),
	}
}

// bndAdminInventory are the routes only an administrator may use.
func bndAdminInventory() []bndRoute {
	const (
		inviteItem = "/api/invitation/" + bndIDToken
		userItem   = "/api/user/" + bndIDToken
		create     = `{"type":"member","numInvites":1}`
	)

	admin := bndAdminOnly

	return []bndRoute{
		bndRouteOf("invitation list", http.MethodGet, "/api/invitation", admin, 4*bndKiB, "", ""),
		bndRouteOf("invitation create", http.MethodPost, "/api/invitation", admin, 4*bndKiB, create, "invitations"),
		bndRouteOf("invitation update", http.MethodPatch, inviteItem, admin, 4*bndKiB, `{"numInvites":7}`,
			"invitations WHERE num_invites = 7"),
		bndRouteOf("invitation revoke", http.MethodDelete, inviteItem, admin, 4*bndKiB, "",
			"secrets WHERE kind = 'invitation' AND revoked_at IS NOT NULL"),
		bndRouteOf("user list", http.MethodGet, "/api/user", admin, bndKiB, "", ""),
		bndRouteOf("user get", http.MethodGet, userItem, admin, bndKiB, "", ""),
		bndRouteOf("user revoke", http.MethodDelete, userItem, admin, bndKiB, "", "users WHERE revoked_at IS NOT NULL"),
	}
}

// bndRouteOf builds one inventory row.
func bndRouteOf(name, method, pattern string, access bndAccess, maxBody int, body, writes string) bndRoute {
	return bndRoute{
		name:    name,
		method:  method,
		pattern: pattern,
		access:  access,
		maxBody: maxBody,
		body:    body,
		writes:  writes,
	}
}

// path returns the request path of r with {id} replaced.
func (r bndRoute) path(id string) string { return strings.ReplaceAll(r.pattern, bndIDToken, id) }

func (r bndRoute) hasID() bool { return strings.Contains(r.pattern, bndIDToken) }

func (r bndRoute) unsafe() bool { return r.method != http.MethodGet && r.method != http.MethodHead }

// bndPatterns returns the distinct path patterns of the inventory, in order.
func bndPatterns() []string {
	var out []string

	for _, r := range bndRoutes() {
		if !slices.Contains(out, r.pattern) {
			out = append(out, r.pattern)
		}
	}

	return out
}

// bndAllowed returns the sorted Allow header a path pattern must answer 405 with.
func bndAllowed(pattern string) string {
	var methods []string

	for _, r := range bndRoutes() {
		if r.pattern == pattern {
			methods = append(methods, r.method)
		}
	}

	slices.Sort(methods)

	return strings.Join(methods, ", ")
}

// bndSessionRoutes are the routes that need a session credential.
func bndSessionRoutes() []bndRoute {
	var out []bndRoute

	for _, r := range bndRoutes() {
		if r.access != bndPublic {
			out = append(out, r)
		}
	}

	return out
}

// bndUnsafeRoutes are the routes that must carry Content-Type: application/json.
func bndUnsafeRoutes() []bndRoute {
	var out []bndRoute

	for _, r := range bndRoutes() {
		if r.unsafe() {
			out = append(out, r)
		}
	}

	return out
}

// ---- helpers ----------------------------------------------------------------

const (
	bndErrNotFound    = `{"error":{"code":"not_found","message":"no such route"}}` + "\n"
	bndErrMethod      = `{"error":{"code":"method_not_allowed","message":"method not allowed"}}` + "\n"
	bndErrUnauth      = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"
	bndErrUnsupported = `{"error":{"code":"unsupported_media_type",` +
		`"message":"request Content-Type must be application/json"}}` + "\n"
	bndErrTooLarge      = `{"error":{"code":"body_too_large","message":"request body is too large"}}` + "\n"
	bndErrForbiddenBody = `{"error":{"code":"forbidden","message":"administrator access is required"}}` + "\n"
)

// bndWorld is a deployment with an admin and a member, each with a live session.
type bndWorld struct {
	admin       passkey
	adminToken  string
	member      passkey
	memberToken string
	// agentID is an agent of the admin, invitationID an invitation row and
	// invitationToken that invitation's token.
	agentID         string
	invitationID    string
	invitationToken string
	// orgID is a standard organization the admin created and administers. The
	// admin does not belong to it: the schema does not ask that, and a world
	// where the member and the admin are both outside it lets the matrix act
	// on it without a state to undo beyond bndRestore's.
	orgID string
	// adminOrgID and adminOrgName are the organization registration created for
	// the admin, which the admin belongs to and bndRestore keeps.
	adminOrgID   string
	adminOrgName string
}

// bndOrgID is the id of the organization a bndWorld holds.
func bndOrgID() string { return idN("0b10", 1) }

// idFor is the id a pattern's {id} takes in this world: the organization for
// the organization routes, the member for a member (a user's id), and the
// agent, the invitation or the user the older routes address.
func (w bndWorld) idFor(pattern string) string {
	switch {
	case strings.HasPrefix(pattern, "/api/invitation"):
		return w.invitationID
	case strings.HasPrefix(pattern, "/api/user"), strings.HasPrefix(pattern, "/api/member"):
		return w.member.userID
	case strings.HasPrefix(pattern, "/api/org"):
		return w.orgID
	default:
		return w.agentID
	}
}

// bndSeedOrg seeds the world's organization, administered by the admin. It is
// written only while the Worker is idle.
func bndSeedOrg(t *testing.T, admin string) {
	t.Helper()

	seed(t, "INSERT INTO orgs (id, kind, name, created_by, created_at) "+
		"VALUES (?, 'standard', 'bnd', ?, strftime('%s','now'))", bndOrgID(), admin)
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, strftime('%s','now'))", bndOrgID(), admin)
}

// bndNewWorld resets the deployment and creates an admin (through the real
// endpoints), a second account promoted to the member role, and one agent and
// one invitation to address.
func bndNewWorld(t *testing.T) bndWorld {
	t.Helper()

	admin := newAdmin(t)
	adminToken := login(t, admin)

	// A second account needs an invitation that grants a role, and none can be
	// created through the API, so the member is seeded as an account with a
	// real passkey: register through a seeded first-run style invitation is not
	// possible, so seed the rows and log in through the real endpoints.
	member := bndSeedMember(t)
	memberToken := login(t, member)

	seed(t, "UPDATE users SET role = ? WHERE id = ?", roleMember, member.userID)

	invitationToken := seedInvitation(t, idInvitationA, 3)

	seedAgent(t, idAgentA, admin.userID, "seeded")

	bndSeedOrg(t, admin.userID)

	return bndWorld{
		admin: admin, adminToken: adminToken, member: member, memberToken: memberToken,
		agentID: idAgentA, invitationID: idInvitationA, invitationToken: invitationToken,
		orgID:      bndOrgID(),
		adminOrgID: scalar(t, "SELECT org_id FROM users WHERE id = ?", admin.userID),
		adminOrgName: scalar(t,
			"SELECT name FROM orgs WHERE id = (SELECT org_id FROM users WHERE id = ?)", admin.userID),
	}
}

// bndSeedMember creates a second account and its passkey in the database, then
// returns the passkey a login can sign with. Registration through the API
// needs a role-granting invitation, which only first run creates (once, before
// any account exists), so the account is seeded directly.
func bndSeedMember(t *testing.T) passkey {
	t.Helper()

	priv := newKey(t)
	credID := randomBytes(32)
	handle := randomBytes(16)
	userID := idN("0b00", 77)

	cose := coseES256(t, priv.X.FillBytes(make([]byte, 32)), priv.Y.FillBytes(make([]byte, 32)))

	seedAccount(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) "+
		"VALUES (?, ?, 'e2e_member', (SELECT id FROM invitations LIMIT 1), strftime('%s','now'))", userID, handle)
	seed(t, "INSERT INTO credentials (id, user_id, credential_id, public_key, flags, metadata, created_at) "+
		"VALUES (?, ?, ?, ?, 5, '{}', strftime('%s','now'))", idN("0c00", 77), userID, credID, cose)

	return passkey{priv: priv, credID: credID, handle: handle, userID: userID}
}

// bndRaw sends a request over a raw TCP connection, so a test can send header
// shapes net/http's client would refuse or normalise (duplicate headers, an
// unusual request target, a chunked body of exact chunk sizes). It returns the
// status line status, the headers and the body.
func bndRaw(t *testing.T, raw string) reply {
	t.Helper()

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(
		t.Context(),
		"tcp",
		strings.TrimPrefix(target.baseURL, "http://"),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	_, err = conn.Write([]byte(raw))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return reply{
		status:     resp.StatusCode,
		body:       string(data),
		header:     resp.Header,
		setCookies: resp.Header.Values("Set-Cookie"),
	}
}

// bndNoCookies fails when r set any cookie.
func bndNoCookies(t *testing.T, what string, r reply) {
	t.Helper()

	if len(r.setCookies) != 0 {
		t.Errorf("%s set cookies %v", what, r.setCookies)
	}
}

// bndSnapshot is the row counts of every table, to prove nothing was written.
func bndSnapshot(t *testing.T) string {
	t.Helper()

	parts := make([]string, 0, len(tables())+9)

	for _, table := range tables() {
		parts = append(parts, table+"="+count(t, table))
	}

	// Cell values that a write to an existing row would change.
	parts = append(parts,
		"revoked_secrets="+count(t, "secrets WHERE revoked_at IS NOT NULL"),
		"secret_expiries="+scalar(t, "SELECT group_concat(expires_at) FROM (SELECT expires_at FROM secrets ORDER BY id)"),
		"revoked_agents="+count(t, "agents WHERE revoked_at IS NOT NULL"),
		"revoked_users="+count(t, "users WHERE revoked_at IS NOT NULL"),
		"agent_names="+scalar(t, "SELECT group_concat(name) FROM (SELECT name FROM agents ORDER BY id)"),
		"agent_labels="+scalar(t, "SELECT group_concat(agent_id||':'||label) "+
			"FROM (SELECT agent_id, label FROM agent_labels ORDER BY agent_id, label)"),
		"org_members="+scalar(t, "SELECT group_concat(id||':'||org_id) "+
			"FROM (SELECT id, org_id FROM users ORDER BY id)"),
		"org_cells="+scalar(t, "SELECT group_concat(id||':'||name) "+
			"FROM (SELECT id, name FROM orgs ORDER BY id)"),
		"org_admin_roles="+scalar(t, "SELECT group_concat(org_id||':'||user_id) "+
			"FROM (SELECT org_id, user_id FROM org_admins ORDER BY org_id, user_id)"),
		"invite_caps="+scalar(t, "SELECT group_concat(num_invites) FROM (SELECT num_invites FROM invitations ORDER BY id)"),
	)

	return strings.Join(parts, " ")
}

// ---- 1. the route inventory -------------------------------------------------

// TestBndInventoryIsTheWholeSurface proves, against the real TinyGo build,
// that the inventory is the complete public surface: every inventory route is
// served by the handler for its own path+method (a request with no
// credential gets the answer its declared access promises), every other method
// on its path is a 405 listing exactly the inventory's methods, and a sweep of
// paths no route claims is a 404. TinyGo's mux never matches method-qualified
// patterns, so this is where "routes each path+method to the right handler"
// is proved.
//
//nolint:paralleltest // shares one database
func TestBndInventoryIsTheWholeSurface(t *testing.T) {
	reset(t)

	exercised := map[string]bool{}

	for _, route := range bndRoutes() {
		t.Run(route.name+"/declared access", func(t *testing.T) {
			// No cookie, a valid-shaped id (so only access decides). The
			// content type is JSON for unsafe methods (send's default).
			got := send(t, request{method: route.method, path: route.path(idMissing), body: bndBodyOf(route)})
			exercised[route.method+" "+route.pattern] = true

			switch route.access {
			case bndPublic:
				if got.status == http.StatusUnauthorized && got.errorCode() == codeUnauthenticated {
					t.Errorf("public route %s answered the session 401: %d %s", route.name, got.status, got.body)
				}

				notRouted := got.status == http.StatusNotFound && got.errorCode() == codeNotFound
				if notRouted || got.status == http.StatusMethodNotAllowed {
					t.Errorf("%s is not routed: %d %s", route.name, got.status, got.body)
				}
			case bndAnySession, bndAdminOnly:
				got.expect(t, route.name+" without a session", http.StatusUnauthorized, codeUnauthenticated)

				if got.body != bndErrUnauth {
					t.Errorf("%s 401 body = %q, want the one opaque body %q", route.name, got.body, bndErrUnauth)
				}
			}
		})
	}

	for _, pattern := range bndPatterns() {
		allow := bndAllowed(pattern)

		for _, method := range []string{
			http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
			http.MethodDelete, http.MethodOptions, http.MethodTrace,
		} {
			if strings.Contains(", "+allow+",", ", "+method+",") {
				continue
			}

			t.Run(pattern+" rejects "+method, func(t *testing.T) {
				// 405 is decided before the media type, the body and the id, so
				// no credential, no content type and a malformed id still get it.
				got := send(t, request{
					method: method, path: strings.ReplaceAll(pattern, bndIDToken, "not-an-id"),
					noType: true, body: []byte("ignored"),
				})

				if got.status != http.StatusMethodNotAllowed || got.header.Get("Allow") != allow {
					t.Errorf("%s %s = %d (Allow %q) %s, want 405 (Allow %q)",
						method, pattern, got.status, got.header.Get("Allow"), got.body, allow)
				}

				if method != http.MethodHead && got.body != bndErrMethod {
					t.Errorf("%s %s body = %q, want %q", method, pattern, got.body, bndErrMethod)
				}

				bndNoCookies(t, method+" "+pattern, got)
			})
		}
	}

	t.Run("every inventory route was exercised", func(t *testing.T) {
		for _, route := range bndRoutes() {
			if !exercised[route.method+" "+route.pattern] {
				t.Errorf("route %s %s was not exercised", route.method, route.pattern)
			}
		}
	})

	t.Run("the inventory has no duplicates", func(t *testing.T) {
		seen := map[string]bool{}

		for _, route := range bndRoutes() {
			key := route.method + " " + route.pattern
			if seen[key] {
				t.Errorf("route %s is listed twice", key)
			}

			seen[key] = true
		}

		if len(seen) != 28 {
			t.Errorf("inventory has %d routes, want the 28 the product declares", len(seen))
		}
	})
}

// bndBodyOf returns the body to send a route: its own valid body, nil for none.
func bndBodyOf(route bndRoute) []byte {
	if route.body == "" {
		return nil
	}

	return []byte(route.body)
}

// TestBndUnknownPathsAreNotFound sweeps near-miss and hostile paths. None may
// reach a handler, none may be answered with anything but the JSON 404 (or,
// where Go's ServeMux itself redirects or cleans a path, the documented
// behaviour of the real mux), with and without a session, for every method.
//
//nolint:paralleltest // shares one database
func TestBndUnknownPathsAreNotFound(t *testing.T) {
	world := bndNewWorld(t)

	paths := []struct{ name, path string }{
		{"root", "/"},
		{"api root", "/api"},
		{"api slash", "/api/"},
		{"unknown", "/nope"},
		{"unknown deep", "/api/nope/deeper"},
		{"healthz trailing slash", "/healthz/"},
		{"healthz extra segment", "/healthz/x"},
		{"healthz upper", "/HEALTHZ"},
		{"healthz title", "/Healthz"},
		{"first-run trailing slash", "/api/first-run/"},
		{"first-run underscore", "/api/first_run"},
		{"session trailing slash", "/api/session/"},
		{"session upper", "/api/Session"},
		{"session upper api", "/API/session"},
		{"session extra segment", "/api/session/extra"},
		{"session dot suffix", "/api/session."},
		{"session semicolon", "/api/session;x=1"},
		{"session encoded slash suffix", "/api/session%2f"},
		{"session encoded NUL suffix", "/api/session%00"},
		{"session dot segment suffix", "/api/session/."},
		{"session dotdot suffix", "/api/session/.."},
		{"logout trailing slash", "/api/logout/"},
		{"agent trailing slash", "/api/agent/"},
		{"agent plural", "/api/agents"},
		{"agent plural id", "/api/agents/" + idMissing},
		{"agent id extra segment", "/api/agent/" + idMissing + "/extra"},
		{"agent id two extra segments", "/api/agent/" + idMissing + "/a/b"},
		{"agent id key subresource", "/api/agent/" + idMissing + "/key"},
		{"agent encoded slash after collection", "/api/agent%2F"},
		{"agent encoded slash id", "/api/agent/%2F"},
		{"agent question mark escaped", "/api/agent%3Fx"},
		{"invitation trailing slash", "/api/invitation/"},
		{"invitation id extra segment", "/api/invitation/" + idMissing + "/x"},
		{"user trailing slash", "/api/user/"},
		{"user id extra segment", "/api/user/" + idMissing + "/x"},
		{"users plural", "/api/users"},
		{"register root", "/api/register"},
		{"register trailing slash", "/api/register/begin/"},
		{"register upper", "/api/register/BEGIN"},
		{"register unknown step", "/api/register/other"},
		{"login root", "/api/login"},
		{"login unknown step", "/api/login/other"},
		{"refresh does not exist", "/api/refresh"},
		{"keys root", "/keys"},
		{"well-known", "/.well-known/security.txt"},
		{"static", "/index.html"},
		{"favicon", "/favicon.ico"},
	}

	for _, tt := range paths {
		for _, method := range []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodPut,
		} {
			for _, credential := range []struct{ name, token string }{{"anonymous", ""}, {"admin", world.adminToken}} {
				t.Run(tt.name+"/"+method+"/"+credential.name, func(t *testing.T) {
					got := send(t, request{method: method, path: tt.path, token: credential.token, body: []byte(`{}`)})

					if got.status != http.StatusNotFound || got.body != bndErrNotFound {
						t.Errorf("%s %s = %d %q, want 404 %q", method, tt.path, got.status, got.body, bndErrNotFound)
					}

					bndNoCookies(t, method+" "+tt.path, got)
				})
			}
		}
	}

	// HEAD answers the 404 status with no body.
	t.Run("HEAD unknown", func(t *testing.T) {
		got := send(t, request{method: http.MethodHead, path: "/nope"})
		if got.status != http.StatusNotFound || got.body != "" {
			t.Errorf("HEAD /nope = %d %q, want 404 with no body", got.status, got.body)
		}
	})

	t.Run("OPTIONS unknown", func(t *testing.T) {
		got := send(t, request{method: http.MethodOptions, path: "/nope"})
		got.expect(t, "OPTIONS /nope", http.StatusNotFound, codeNotFound)
	})

	// Nothing above may have written anything: the first-run invitation and the
	// seeded one, the seeded agent.
	expectCount(t, "agents", "1")
	expectCount(t, "invitations", "2")
}

// TestBndPathCleaningBehaviour records what Go's ServeMux does to a request
// target before routing, on the real TinyGo build. These are NOT 404s: the mux
// redirects a path with empty segments (301, to the cleaned path) and cleans
// dot segments (so the cleaned path is what is routed and authenticated). A
// client that follows a 301 on an unsafe method re-sends it, so it matters
// that the redirect target is always an in-API path and that the cleaned
// request is subject to the same authentication as a direct one.
//
//nolint:paralleltest // shares one database
func TestBndPathCleaningBehaviour(t *testing.T) {
	world := bndNewWorld(t)

	tests := []struct {
		name         string
		raw          string // the request target, sent verbatim
		method       string
		wantStatus   int
		wantLocation string // "" when not a redirect
	}{
		{"double slash prefix redirects", "//api/agent", http.MethodGet, http.StatusMovedPermanently, "/api/agent"},
		{"double slash inside redirects", "/api//agent", http.MethodGet, http.StatusMovedPermanently, "/api/agent"},
		{
			"double slash before id redirects",
			"/api/agent//" + idMissing,
			http.MethodDelete,
			http.StatusMovedPermanently,
			"/api/agent/" + idMissing,
		},
		{
			"double slash on unsafe route redirects",
			"//api/logout",
			http.MethodPost,
			http.StatusMovedPermanently,
			"/api/logout",
		},
		{"double slash healthz redirects", "//healthz", http.MethodGet, http.StatusMovedPermanently, "/healthz"},
		{"dot segment is cleaned", "/api/./session", http.MethodGet, http.StatusOK, ""},
		{"dotdot segment is cleaned", "/api/x/../session", http.MethodGet, http.StatusOK, ""},
		{"dotdot out of id cleans to the session route", "/api/agent/../session", http.MethodGet, http.StatusOK, ""},
		{"encoded dotdot is cleaned too", "/api/agent/%2e%2e/session", http.MethodGet, http.StatusOK, ""},
		{"encoded dot is cleaned", "/api/%2e/session", http.MethodGet, http.StatusOK, ""},
		{"encoded slash in the middle is matched on the decoded path", "/api%2fsession", http.MethodGet, http.StatusOK, ""},
		{
			"encoded slash before an id is matched on the decoded path",
			"/api/agent%2f" + idMissing,
			http.MethodGet,
			http.StatusNotFound,
			"",
		},
		{"encoded slash before an id, upper case", "/api/agent%2F" + idMissing, http.MethodGet, http.StatusNotFound, ""},
		{
			"encoded slash after an id is matched on the decoded path",
			"/api/agent/" + idMissing + "%2f",
			http.MethodGet,
			http.StatusNotFound,
			"",
		},
		{
			"encoded slash directly after the id slash redirects",
			"/api/agent/%2F" + idMissing,
			http.MethodGet,
			http.StatusMovedPermanently,
			"/api/agent/" + idMissing,
		},
		{
			"two encoded slashes redirect",
			"/api/agent%2F%2F" + idMissing,
			http.MethodGet,
			http.StatusMovedPermanently,
			"/api/agent/" + idMissing,
		},
		{"encoded letter is decoded", "/api/%73ession", http.MethodGet, http.StatusOK, ""},
		{"query is not part of the path", "/api/session?x=1", http.MethodGet, http.StatusOK, ""},
		{"empty query is not part of the path", "/api/session?", http.MethodGet, http.StatusOK, ""},
		{"encoded question mark is part of the path", "/api/session%3Fx", http.MethodGet, http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A raw request line: the target is sent exactly as written.
			authed := "Cookie: " + cookieName + "=" + world.adminToken + "\r\n"
			content := ""

			if tt.method != http.MethodGet {
				content = "Content-Type: application/json\r\nContent-Length: 0\r\n"
			}

			got := bndRaw(t, tt.method+" "+tt.raw+" HTTP/1.1\r\nHost: x\r\n"+authed+content+"Connection: close\r\n\r\n")

			if got.status != tt.wantStatus {
				t.Fatalf("%s %s = %d %s, want %d", tt.method, tt.raw, got.status, got.body, tt.wantStatus)
			}

			if loc := got.header.Get("Location"); loc != tt.wantLocation {
				t.Errorf("Location = %q, want %q", loc, tt.wantLocation)
			}

			if tt.wantLocation != "" && strings.HasPrefix(tt.wantLocation, "//") {
				t.Errorf("redirect target %q is protocol-relative: an open redirect", tt.wantLocation)
			}

			// The same cleaned path with no cookie is 401, so cleaning never
			// bypasses authentication.
			if tt.wantStatus == http.StatusOK {
				anon := bndRaw(t, tt.method+" "+tt.raw+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
				if anon.status != http.StatusUnauthorized || anon.body != bndErrUnauth {
					t.Errorf("anonymous %s = %d %q, want the opaque 401", tt.raw, anon.status, anon.body)
				}
			}
		})
	}

	// A redirected unsafe request must not have run anything.
	expectCount(t, "secrets WHERE revoked_at IS NOT NULL", "0")
}

// TestBndRequestTargetsTheRuntimeRefuses records how a malformed request target
// is answered. These never reach Go code in a well-behaved runtime; the test
// pins the observed answer so a regression (a stack trace in a body, say) is
// caught. A percent escape that is not valid is answered by workerd's own error
// page, not by the Worker (see TestBndNoInternalsInErrorBodies).
//
//nolint:paralleltest // shares one database
func TestBndRequestTargetsTheRuntimeRefuses(t *testing.T) {
	reset(t)

	for _, target := range []string{"/api/agent/\x01", "/api/session HTTP/1.1\r\nX: y"} {
		t.Run(fmt.Sprintf("%q", target), func(t *testing.T) {
			got := bndRaw(t, "GET "+target+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
			if got.status < 400 || got.status > 499 {
				t.Errorf("status = %d %q, want a 4xx", got.status, got.body)
			}
		})
	}
}

// ---- 2. content type ---------------------------------------------------------

// bndContentTypes are the Content-Type header values (one header line each)
// and whether the boundary accepts them. The oracle is httpapi.isJSON: exactly
// one header line, media type application/json compared case-insensitively,
// and only charset=utf-8 (case-insensitive) parameters.
func bndContentTypes() []struct {
	name   string
	values []string // header lines; nil = none
	ok     bool
} {
	return []struct {
		name   string
		values []string
		ok     bool
	}{
		{"none", nil, false},
		{"empty string", []string{""}, false},
		{"text/plain", []string{"text/plain"}, false},
		{"text/plain charset", []string{"text/plain; charset=utf-8"}, false},
		{"form urlencoded", []string{"application/x-www-form-urlencoded"}, false},
		{"multipart", []string{"multipart/form-data; boundary=x"}, false},
		{"json", []string{"application/json"}, true},
		{"json charset utf-8", []string{"application/json; charset=utf-8"}, true},
		{"json charset UTF-8", []string{"application/json; charset=UTF-8"}, true},
		{"json charset no space", []string{"application/json;charset=utf-8"}, true},
		{"json repeated charset", []string{"application/json;charset=utf-8;charset=utf-8"}, true},
		{"uppercase JSON", []string{"APPLICATION/JSON"}, true},
		{"mixed case JSON", []string{"Application/Json"}, true},
		{"json leading space", []string{" application/json"}, true},
		{"json trailing space", []string{"application/json "}, true},
		{"json charset utf-16", []string{"application/json; charset=utf-16"}, false},
		{"json charset latin1", []string{"application/json; charset=iso-8859-1"}, false},
		{"json foo=bar", []string{"application/json; foo=bar"}, false},
		{"json foo=bar then charset", []string{"application/json; charset=utf-8; foo=bar"}, false},
		{"json quoted charset", []string{`application/json; charset="utf-8"`}, false},
		{"json trailing semicolon", []string{"application/json;"}, false},
		{"json empty param", []string{"application/json; ;charset=utf-8"}, false},
		{"jsonx", []string{"application/jsonx"}, false},
		{"xjson", []string{"application/xjson"}, false},
		{"json comma text", []string{"application/json,text/plain"}, false},
		{"json comma json", []string{"application/json, application/json"}, false},
		{"text then json", []string{"text/plain, application/json"}, false},
		{"json+ld", []string{"application/ld+json"}, false},
		{"json suffix", []string{"application/vnd.api+json"}, false},
		{"text/json", []string{"text/json"}, false},
		{"json no subtype", []string{"application"}, false},
		{"slash only", []string{"/"}, false},
		{"two json lines", []string{"application/json", "application/json"}, false},
		{"json then text lines", []string{"application/json", "text/plain"}, false},
		{"text then json lines", []string{"text/plain", "application/json"}, false},
		{"json with a control byte suffix", []string{"application/json\x01"}, false},
		{"json with a DEL suffix", []string{"application/json\x7f"}, false},
		{"json with an invalid utf-8 suffix", []string{"application/json\xff"}, false},
		{"json with a tab suffix (trimmed by the HTTP layer)", []string{"application/json\t"}, true},
		{"json with a tab prefix (trimmed by the HTTP layer)", []string{"\tapplication/json"}, true},
	}
}

// bndContentTypeRequest sends route with exactly the given Content-Type header
// lines, over a raw connection so duplicates survive.
func bndContentTypeRequest(t *testing.T, route bndRoute, token string, values []string, body string) reply {
	t.Helper()

	var head strings.Builder

	head.WriteString(route.method + " " + route.path(idMissing) + " HTTP/1.1\r\nHost: x\r\n")

	if token != "" {
		head.WriteString("Cookie: " + cookieName + "=" + token + "\r\n")
	}

	for _, value := range values {
		head.WriteString("Content-Type: " + value + "\r\n")
	}

	fmt.Fprintf(&head, "Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)

	return bndRaw(t, head.String())
}

// TestBndContentTypeOnEveryUnsafeRoute: every route whose method is not
// GET/HEAD requires exactly application/json (optionally charset=utf-8), even
// with an empty body, and refuses anything else with 415 before anything else
// is looked at: not before the 405 check, but before the body limit, the path
// id and the credential. A refusal sets no cookie and writes nothing. This is
// the CSRF defence for the whole API, and it runs through workerd's header
// parsing, which can merge or reorder header lines.
//
//nolint:paralleltest // shares one database
func TestBndContentTypeOnEveryUnsafeRoute(t *testing.T) {
	world := bndNewWorld(t)
	before := bndSnapshot(t)

	// Each route is tried with no credential, and the session routes also with
	// an admin session: the media type is decided before the credential, so the
	// answer is the same, and a valid session never makes a wrong type pass.
	// An ACCEPTED type is let through to the handler, which may legitimately
	// write (a logout revokes the session it is given), so the database is
	// compared only across the refused cases, and the world is restored after
	// each accepted one.
	for _, route := range bndUnsafeRoutes() {
		for _, ct := range bndContentTypes() {
			credentials := []struct{ name, token string }{{"anonymous", ""}}
			if route.access != bndPublic {
				credentials = append(credentials, struct{ name, token string }{"admin", world.adminToken})
			}

			for _, credential := range credentials {
				t.Run(route.name+"/"+ct.name+"/"+credential.name, func(t *testing.T) {
					got := bndContentTypeRequest(t, route, credential.token, ct.values, route.body)

					if ct.ok {
						// Accepted: the boundary lets it through to id parsing,
						// authentication and the handler, so it is anything but a 415.
						if got.status == http.StatusUnsupportedMediaType {
							t.Errorf("Content-Type %q was refused: %d %s", ct.values, got.status, got.body)
						}

						bndRestore(t, world)

						return
					}

					if got.status != http.StatusUnsupportedMediaType || got.body != bndErrUnsupported {
						t.Errorf("Content-Type %q = %d %q, want 415 %q", ct.values, got.status, got.body, bndErrUnsupported)
					}

					bndNoCookies(t, "refused media type", got)

					if after := bndSnapshot(t); after != before {
						t.Errorf("a refused content type changed the database:\n before %s\n after  %s", before, after)
					}
				})
			}
		}
	}

	// A refused request must leave the session it carried untouched: the
	// logout the accepted cases above ran restored it, so it must be usable.
	get(t, pathSession, world.adminToken).expect(t, "the session after the refusals", http.StatusOK, "")
	get(t, pathSession, world.memberToken).expect(t, "the member session after the refusals", http.StatusOK, "")
}

// TestBndContentTypeRuleForSafeMethods: GET and HEAD need no Content-Type, and
// a wrong one on them is harmless (the boundary ignores it); DELETE is an
// unsafe method and needs one even with no body. The 415 never happens on a
// GET route.
//
//nolint:paralleltest // shares one database
func TestBndContentTypeRuleForSafeMethods(t *testing.T) {
	world := bndNewWorld(t)

	for _, route := range bndRoutes() {
		if route.unsafe() {
			continue
		}

		for _, ct := range []string{
			"",
			"text/plain",
			"application/x-www-form-urlencoded",
			"multipart/form-data; boundary=x",
			"application/json",
		} {
			t.Run(route.name+"/"+ct, func(t *testing.T) {
				headers := map[string]string{"Content-Type": ct}
				got := send(
					t,
					request{method: route.method, path: route.path(world.agentID), token: world.adminToken, headers: headers},
				)

				if got.status == http.StatusUnsupportedMediaType {
					t.Errorf("GET %s with Content-Type %q = 415: a safe method needs none", route.pattern, ct)
				}
			})
		}
	}

	t.Run("DELETE without a body still needs the type", func(t *testing.T) {
		for _, route := range bndRoutes() {
			if route.method != http.MethodDelete {
				continue
			}

			got := send(
				t,
				request{method: http.MethodDelete, path: route.path(idMissing), token: world.adminToken, noType: true},
			)
			if got.status != http.StatusUnsupportedMediaType {
				t.Errorf("DELETE %s with no Content-Type = %d %s, want 415", route.pattern, got.status, got.body)
			}
		}
	})

	t.Run("HEAD on a GET route is a 405, with no body", func(t *testing.T) {
		got := send(t, request{method: http.MethodHead, path: "/healthz"})
		if got.status != http.StatusMethodNotAllowed || got.header.Get("Allow") != "GET" || got.body != "" {
			t.Errorf(
				"HEAD /healthz = %d Allow=%q body=%q, want 405 Allow=GET and no body",
				got.status,
				got.header.Get("Allow"),
				got.body,
			)
		}
	})
}

// ---- 3. body limits ----------------------------------------------------------

// bndStatusOf is a GET that reports a transport error instead of failing the
// test, so it is safe to call from a goroutine other than the test's own.
func bndStatusOf(t *testing.T, path, token string) (int, string, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.baseURL+path, http.NoBody)
	if err != nil {
		return 0, "", fmt.Errorf("build request: %w", err)
	}

	if token != "" {
		req.Header.Set("Cookie", cookieName+"="+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("send: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("read: %w", err)
	}

	return resp.StatusCode, string(out), nil
}

// bndBodyOfLen returns a body of exactly n bytes that is whitespace: valid
// leading and trailing JSON whitespace around nothing, so for a route that
// reads no body it is irrelevant, and for one that decodes it is an empty-body
// refusal (400) and never a size error when n <= cap.
func bndBodyOfLen(n int) []byte { return bytes.Repeat([]byte(" "), n) }

// TestBndBodyLimitOnEveryRoute: a body of cap-1 and cap bytes is read (so the
// route answers as it decides, never 413), one of cap+1 is 413 body_too_large
// for every route and every method, ahead of the path id and of
// authentication (so a body that is too large is 413 even with no session and
// even with a malformed id). Declared caps are the production constants.
//
// Far-oversized and chunked uploads are not tested here: workerd races the
// Worker's early 413 against the client's upload and can answer with its own
// 500 "Network connection lost." or stall, which made those cases flaky without
// saying anything about the Worker.
//
//nolint:paralleltest // shares one database
func TestBndBodyLimitOnEveryRoute(t *testing.T) {
	world := bndNewWorld(t)
	before := bndSnapshot(t)

	for _, route := range bndRoutes() {
		credentials := []struct{ name, token string }{{"anonymous", ""}}
		if route.access != bndPublic {
			credentials = append(credentials, struct{ name, token string }{"admin", world.adminToken})
		}

		for _, credential := range credentials {
			path := route.path(idMissing)

			t.Run(route.name+"/"+credential.name+"/cap-1", func(t *testing.T) {
				got := send(
					t,
					request{method: route.method, path: path, token: credential.token, body: bndBodyOfLen(route.maxBody - 1)},
				)
				if got.status == http.StatusRequestEntityTooLarge {
					t.Errorf("cap-1 (%d bytes) = 413 %s", route.maxBody-1, got.body)
				}

				// A body within the cap is read, so a route that ignores it (logout)
				// still acts: put back what it changed.
				bndRestore(t, world)
			})

			t.Run(route.name+"/"+credential.name+"/cap", func(t *testing.T) {
				got := send(
					t,
					request{method: route.method, path: path, token: credential.token, body: bndBodyOfLen(route.maxBody)},
				)
				if got.status == http.StatusRequestEntityTooLarge {
					t.Errorf("cap (%d bytes) = 413 %s: a body of exactly the limit is allowed", route.maxBody, got.body)
				}

				bndRestore(t, world)
			})

			t.Run(route.name+"/"+credential.name+"/cap+1", func(t *testing.T) {
				got := send(
					t,
					request{method: route.method, path: path, token: credential.token, body: bndBodyOfLen(route.maxBody + 1)},
				)
				if got.status != http.StatusRequestEntityTooLarge || got.body != bndErrTooLarge {
					t.Errorf("cap+1 (%d bytes) = %d %q, want 413 %q", route.maxBody+1, got.status, got.body, bndErrTooLarge)
				}

				bndNoCookies(t, "413", got)
			})
		}
	}

	if after := bndSnapshot(t); after != before {
		t.Errorf("a refused body changed the database:\n before %s\n after  %s", before, after)
	}
}

// TestBndBodyLimitOrder pins where 413 sits among the boundary's checks:
// after the method and the media type, before authentication and the path id.
//
//nolint:paralleltest // shares one database
func TestBndBodyLimitOrder(t *testing.T) {
	world := bndNewWorld(t)

	big := func(route bndRoute) []byte { return bndBodyOfLen(route.maxBody + 1) }

	for _, route := range bndRoutes() {
		t.Run(route.name+"/413 before 401", func(t *testing.T) {
			got := send(t, request{method: route.method, path: route.path(idMissing), body: big(route)})
			got.expect(t, route.name+" oversized, no session", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
		})

		if route.hasID() {
			t.Run(route.name+"/413 before invalid_id", func(t *testing.T) {
				got := send(t, request{method: route.method, path: route.path("not-an-id"), body: big(route)})
				got.expect(t, route.name+" oversized, bad id", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
			})
		}

		if route.unsafe() {
			t.Run(route.name+"/415 before 413", func(t *testing.T) {
				got := send(t, request{method: route.method, path: route.path(idMissing), body: big(route), noType: true})
				got.expect(t, route.name+" oversized, no type", http.StatusUnsupportedMediaType, codeUnsupportedType)
			})
		}

		t.Run(route.name+"/405 before 413", func(t *testing.T) {
			other := http.MethodPut
			got := send(t, request{method: other, path: route.path(idMissing), body: big(route)})
			got.expect(t, route.name+" wrong method, oversized", http.StatusMethodNotAllowed, codeMethodNotAllow)
		})

		if route.access != bndPublic {
			t.Run(route.name+"/413 before 403", func(t *testing.T) {
				got := send(
					t,
					request{method: route.method, path: route.path(idMissing), body: big(route), token: world.memberToken},
				)
				got.expect(t, route.name+" oversized, member", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
			})
		}
	}
}

// TestBndBodyOnSafeAndBodylessRoutes: a body on GET and DELETE is read like any
// other and counted against the cap: the routes read no body, but they do not
// let a client stream one in. A body within the cap on a route that reads none
// is ignored.
//
//nolint:paralleltest // shares one database
func TestBndBodyOnSafeAndBodylessRoutes(t *testing.T) {
	world := bndNewWorld(t)

	for _, route := range bndRoutes() {
		if route.body != "" || route.name == "logout" {
			// Routes that read a body are covered by TestBndBodyLimitOnEveryRoute.
			// Logout consumes the session it is given, so the second request of the
			// comparison would see a different state.
			continue
		}

		t.Run(route.name+"/small body is ignored", func(t *testing.T) {
			path := route.path(idMissing)
			plain := send(t, request{method: route.method, path: path, token: world.adminToken})
			withBody := send(
				t,
				request{method: route.method, path: path, token: world.adminToken, body: []byte(`{"ignored":true}`)},
			)

			if plain.status != withBody.status || plain.body != withBody.body {
				t.Errorf("a body changed the answer: %d %q vs %d %q", plain.status, plain.body, withBody.status, withBody.body)
			}
		})
	}
}

// ---- 4. path ids -------------------------------------------------------------

// bndBadIDs are path segments that are not a canonical lower-case UUID. The
// value is the raw (already escaped) segment.
func bndBadIDs() []struct{ name, segment string } {
	valid := idMissing

	return []struct{ name, segment string }{
		{"word", "nope"},
		{"upper-case uuid", strings.ToUpper(valid)},
		{"mixed-case uuid", valid[:30] + "FFFF"[:2] + valid[32:]},
		{"no dashes", strings.ReplaceAll(valid, "-", "")},
		{"35 chars", valid[:35]},
		{"37 chars", valid + "0"},
		{"non-hex", strings.ReplaceAll(valid, "f", "g")},
		{"trailing space", valid + "%20"},
		{"leading space", "%20" + valid},
		{"plus for space", valid + "+"},
		{"percent NUL", "%00"},
		{"percent NUL suffix", valid + "%00"},
		{"percent NUL inside", valid[:10] + "%00" + valid[11:]},
		{"tab", valid + "%09"},
		{"newline", valid + "%0a"},
		{"carriage return", valid + "%0d"},
		{"unicode digit (arabic-indic zero)", strings.Replace(valid, "0", "%D9%A0", 1)},
		{"fullwidth digit", strings.Replace(valid, "0", "%EF%BC%90", 1)},
		{"braces", "%7B" + valid + "%7D"},
		{"urn prefix", "urn:uuid:" + valid},
		{"very long 10k", strings.Repeat("a", 10000)},
		{"long uuid-like 10k", strings.Repeat(valid, 280)},
		{"sql quote", "%27%20OR%201%3D1--"},
		{"sql union", "x%27%20UNION%20SELECT%20*%20FROM%20users--"},
		{"sql comment", valid + "%27--"},
		{"sql semicolon", valid + "%3B%20DROP%20TABLE%20users"},
		{"percent wildcard", "%25"},
		{"glob star", "*"},
		{"dotdot is cleaned elsewhere, encoded dots are an id", "%2e%2e%2e"},
		{"single dot triple", "..."},
		{"backslash", "%5C"},
		{"encoded slash", "%2F"},
		{"encoded slash in uuid", valid[:8] + "%2F" + valid[9:]},
		{"null literal", "null"},
		{"undefined literal", "undefined"},
		{"zero", "0"},
		{"negative", "-1"},
		{"json object", "%7B%7D"},
		{"emoji", "%F0%9F%98%80"},
		{"invalid utf-8", "%C0%AF"},
		{"lone continuation", "%80"},
		{"uuid with dashes moved", "0000000000-00-7000-8000-00000000ffff"},
		{"uuid with extra dash", "00000000-0000-7000-8000-0000-0000ffff"},
		{"all dashes", strings.Repeat("-", 36)},
		{"36 hex no dashes", strings.Repeat("a", 36)},
		{"nil uuid is valid shape", ""}, // replaced below: this row is the "empty segment" case
	}
}

// bndIDRoutes are the routes with an {id}.
func bndIDRoutes() []bndRoute {
	var out []bndRoute

	for _, r := range bndRoutes() {
		if r.hasID() {
			out = append(out, r)
		}
	}

	return out
}

// TestBndMalformedPathIDs: every route with an {id} authenticates first. A
// signed-out caller is 401 and a member on an admin route is 403 whatever the
// id; only a caller who may use the route gets 400 invalid_id for a malformed
// one. The parser refuses and never rewrites: no trimming, case-folding or
// normalising, so an id the database would store differently is never accepted.
//
//nolint:paralleltest // shares one database
func TestBndMalformedPathIDs(t *testing.T) {
	world := bndNewWorld(t)
	before := bndSnapshot(t)

	credentials := []struct{ name, token string }{
		{"no session", ""},
		{"admin session", world.adminToken},
		{"member session", world.memberToken},
	}

	// want is what a credential is told about a malformed id on route: refused
	// as a caller (401, or 403 on an admin route for a member) or, once allowed
	// in, the id itself (400 invalid_id).
	want := func(route bndRoute, token string) (int, string) {
		switch {
		case token == "":
			return http.StatusUnauthorized, codeUnauthenticated
		case route.access == bndAdminOnly && token == world.memberToken:
			return http.StatusForbidden, codeForbidden
		default:
			return http.StatusBadRequest, codeInvalidID
		}
	}

	for _, route := range bndIDRoutes() {
		for _, bad := range bndBadIDs() {
			if bad.segment == "" {
				continue // the empty segment is a different path; see below
			}

			for _, credential := range credentials {
				t.Run(route.name+"/"+bad.name+"/"+credential.name, func(t *testing.T) {
					path := strings.ReplaceAll(route.pattern, bndIDToken, bad.segment)
					// A redirect is kept, not followed: a followed one lands on
					// another route (an id in the middle of a path becomes the
					// route of the cleaned path), which is that route's answer.
					got := send(t, request{
						method: route.method, path: path, token: credential.token, body: bndBodyOf(route), keepRedirect: true,
					})

					// An encoded slash or a dot-only segment changes the path
					// the mux routes (see TestBndUnknownPathsAreNotFound and
					// TestBndPathCleaningBehaviour), so those are 404, the
					// redirect to the cleaned path (an in-API one, never
					// protocol-relative) or the answer the credential would
					// get; everything else is an id the boundary refuses.
					status, code := want(route, credential.token)

					if bndChangesRouting(bad.segment) {
						if got.status == status && got.errorCode() == code {
							return
						}

						location := got.header.Get("Location")
						redirected := got.status == http.StatusMovedPermanently &&
							strings.HasPrefix(location, "/api/") && !strings.HasPrefix(location, "//")

						if got.status != http.StatusNotFound && !redirected {
							t.Errorf("%s = %d %s, want %d %s, 404 or a redirect inside the API", path, got.status, got.body, status, code)
						}

						return
					}

					if got.status != status || got.errorCode() != code {
						t.Errorf("%s %s = %d %q, want %d %s", route.method, path, got.status, got.body, status, code)
					}

					bndNoCookies(t, path, got)
				})
			}
		}

		t.Run(route.name+"/empty segment is not an id", func(t *testing.T) {
			// "/api/agent/" is the trailing-slash path: a 404, never an id error.
			// An id in the middle ("/api/org//member") leaves an empty segment,
			// which the mux redirects to the cleaned path, again never an id
			// error and never a handler.
			path := strings.ReplaceAll(route.pattern, bndIDToken, "")
			got := send(t, request{
				method: route.method, path: path, token: world.adminToken, body: bndBodyOf(route), keepRedirect: true,
			})

			if strings.HasSuffix(route.pattern, bndIDToken) {
				got.expect(t, route.method+" "+path, http.StatusNotFound, codeNotFound)

				return
			}

			cleaned := strings.ReplaceAll(route.pattern, "/"+bndIDToken, "")
			if got.status != http.StatusMovedPermanently || got.header.Get("Location") != cleaned {
				t.Errorf("%s %s = %d %q (Location %q), want a 301 to %s",
					route.method, path, got.status, got.body, got.header.Get("Location"), cleaned)
			}
		})
	}

	if after := bndSnapshot(t); after != before {
		t.Errorf("a malformed id changed the database:\n before %s\n after  %s", before, after)
	}
}

// bndChangesRouting reports whether an id segment is one that the mux treats as
// path structure (an encoded slash, a dot segment) rather than as an id.
func bndChangesRouting(segment string) bool {
	switch segment {
	case "%2F", "%5C", "..", "...", "%2e%2e%2e":
		return strings.Contains(segment, "%2F") || segment == ".."
	}

	return strings.Contains(segment, "%2F")
}

// TestBndValidButMissingIDIsNoOracle: a well-formed id that names nothing is
// answered 401 with no session (the credential check comes before any lookup),
// byte-identical to the answer for an id that exists, so a signed-out caller
// cannot tell whether a resource exists. A member asking about an admin-only
// route gets 403 either way, for the same reason. With a session the
// existing and missing ids answer differently, which is the feature's own
// business and covered by its tests.
//
//nolint:paralleltest // shares one database
func TestBndValidButMissingIDIsNoOracle(t *testing.T) {
	world := bndNewWorld(t)

	existing := map[string]string{
		"/api/agent/" + bndIDToken:      world.agentID,
		"/api/invitation/" + bndIDToken: world.invitationID,
		"/api/user/" + bndIDToken:       world.admin.userID,
	}

	// idOf is the existing id of a route: the organization, and member
	// routes take the world's own, and the older ones their map entry.
	idOf := func(route bndRoute) string {
		if id, ok := existing[route.pattern]; ok {
			return id
		}

		return world.idFor(route.pattern)
	}

	for _, route := range bndIDRoutes() {
		t.Run(route.name+"/anonymous", func(t *testing.T) {
			live := send(t, request{method: route.method, path: route.path(idOf(route)), body: bndBodyOf(route)})
			missing := send(t, request{method: route.method, path: route.path(idMissing), body: bndBodyOf(route)})

			live.expect(t, route.name+" existing id", http.StatusUnauthorized, codeUnauthenticated)
			missing.expect(t, route.name+" missing id", http.StatusUnauthorized, codeUnauthenticated)

			if live.body != missing.body || live.body != bndErrUnauth {
				t.Errorf("anonymous answers differ: existing %q vs missing %q", live.body, missing.body)
			}
		})

		if route.access == bndAdminOnly {
			t.Run(route.name+"/member", func(t *testing.T) {
				live := send(
					t,
					request{
						method: route.method,
						path:   route.path(idOf(route)),
						token:  world.memberToken,
						body:   bndBodyOf(route),
					},
				)
				missing := send(
					t,
					request{method: route.method, path: route.path(idMissing), token: world.memberToken, body: bndBodyOf(route)},
				)

				if live.status != http.StatusForbidden || live.body != missing.body || live.body != bndErrForbiddenBody {
					t.Errorf(
						"member answers: existing %d %q vs missing %d %q, want identical 403",
						live.status,
						live.body,
						missing.status,
						missing.body,
					)
				}
			})
		}
	}
}

// ---- 5. authentication boundary ----------------------------------------------

// bndCookieRequest is a request whose Cookie header lines are given verbatim.
type bndCookieCase struct {
	name string
	// lines are the Cookie header lines; nil sends no Cookie header.
	lines []string
	// headers are extra header lines "Name: value".
	headers []string
}

// bndAuthRequest sends route with the cookie case over a raw connection.
func bndAuthRequest(t *testing.T, route bndRoute, c bndCookieCase) reply {
	t.Helper()

	var head strings.Builder

	head.WriteString(route.method + " " + route.path(idMissing) + " HTTP/1.1\r\nHost: x\r\n")

	for _, line := range c.lines {
		head.WriteString("Cookie: " + line + "\r\n")
	}

	for _, line := range c.headers {
		head.WriteString(line + "\r\n")
	}

	body := route.body
	if route.unsafe() {
		head.WriteString("Content-Type: application/json\r\n")
	}

	fmt.Fprintf(&head, "Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)

	return bndRaw(t, head.String())
}

// bndOneCookie is a case that sends a single Cookie line.
func bndOneCookie(name, line string) bndCookieCase {
	return bndCookieCase{name: name, lines: []string{line}}
}

// bndFlip changes the character of s at the index, staying in the base64url alphabet.
func bndFlip(s string, at int) string {
	b := []byte(s)
	if b[at] == 'A' {
		b[at] = 'B'
	} else {
		b[at] = 'A'
	}

	return string(b)
}

// bndAgentKey creates an agent through the real endpoint and returns its API
// key token: a genuine, active key, which is accepted as a bearer and as
// nothing else.
func bndAgentKey(t *testing.T, sessionToken string) string {
	t.Helper()

	agent := post(t, pathAgent, []byte(`{"name":"audience"}`), sessionToken)
	if agent.status != http.StatusCreated {
		t.Fatalf("create agent = %d %s", agent.status, agent.body)
	}

	var created struct {
		Key struct {
			Token string `json:"token"`
		} `json:"key"`
	}

	err := json.Unmarshal([]byte(agent.body), &created)
	if err != nil || created.Key.Token == "" {
		t.Fatalf("agent key: %v %s", err, agent.body)
	}

	return created.Key.Token
}

// Where a credential is accepted: the session cookie, the Authorization bearer
// header, or nowhere.
const (
	bndCarrierCookie = "cookie"
	bndCarrierBearer = "bearer"
	bndCarrierNone   = ""
)

// bndToken is a token a request may present, and the one carrier that accepts
// it. A token with no carrier is refused wherever it is presented; one with a
// carrier is refused in the other, and accepted in its own.
type bndToken struct {
	name    string
	token   string
	carrier string
}

// bndTokens seeds every credential state the carrier x kind matrix covers, for
// a world with a live admin session and the seeded invitation. Each state is a
// real token whose hash is stored with the secret and kind row the state needs,
// so a refusal is the state's doing and not the token's shape.
//
// The ids "0e.." are this function's own.
func bndTokens(t *testing.T, world bndWorld) []bndToken {
	t.Helper()

	admin := world.admin.userID
	past := "strftime('%s','now') - 1"
	now := "strftime('%s','now')"

	// Seeded state, one secret per row below. set changes the secret's column.
	set := func(id, column, value string) {
		seed(t, "UPDATE secrets SET "+column+" = "+value+" WHERE id = ?", id)
	}

	expiredSession := seedSession(t, idN("0e00", 1), admin)
	set(idN("0e00", 1), "expires_at", past)

	expiringSession := seedSession(t, idN("0e00", 2), admin)
	set(idN("0e00", 2), "expires_at", now)

	revokedSession := seedSession(t, idN("0e00", 3), admin)
	set(idN("0e00", 3), "revoked_at", now)

	pastRevokedSession := seedSession(t, idN("0e00", 4), admin)
	set(idN("0e00", 4), "revoked_at", past)

	expiredKey := seedAPIKey(t, idN("0e01", 1), admin, "")
	set(idN("0e01", 1), "expires_at", past)

	revokedKey := seedAPIKey(t, idN("0e01", 2), admin, "")
	set(idN("0e01", 2), "revoked_at", now)

	expiringKey := seedAPIKey(t, idN("0e01", 6), admin, "")
	set(idN("0e01", 6), "expires_at", now)

	pastRevokedKey := seedAPIKey(t, idN("0e01", 7), admin, "")
	set(idN("0e01", 7), "revoked_at", past)

	// A key and a session of an account that was revoked afterwards.
	seedUser(t, idN("0b00", 90), "e2e_member")

	revokedUserSession := seedSession(t, idN("0e00", 5), idN("0b00", 90))
	revokedUserKey := seedAPIKey(t, idN("0e01", 3), idN("0b00", 90), "")

	seed(t, "UPDATE users SET revoked_at = "+now+" WHERE id = ?", idN("0b00", 90))

	// A key whose own secret is active but whose agent was revoked.
	seedAgent(t, idN("0a10", 1), admin, "revoked agent")

	revokedAgentKey := seedAPIKey(t, idN("0e01", 4), admin, idN("0a10", 1))

	seed(t, "UPDATE agents SET revoked_at = "+now+" WHERE id = ?", idN("0a10", 1))

	// The active ones: only their own carrier accepts them.
	liveKey := bndAgentKey(t, world.adminToken)
	ownKey := seedAPIKey(t, idN("0e01", 5), admin, "")

	// A well-formed token no secret has the hash of, in each kind.
	body := liveKey[len(tokenPrefix(tagAPIKey)):]
	sessionBody := world.adminToken[len(tokenPrefix(tagSession)):]

	return []bndToken{
		{"active session", world.adminToken, bndCarrierCookie},
		{"active agent key", liveKey, bndCarrierBearer},
		{"active key of the user's own", ownKey, bndCarrierBearer},
		{"active invitation", world.invitationToken, bndCarrierNone},

		{"unknown session", newToken(tagSession), bndCarrierNone},
		{"unknown key", newToken(tagAPIKey), bndCarrierNone},
		{"unknown invitation", newToken(tagInvitation), bndCarrierNone},
		{"expired session", expiredSession, bndCarrierNone},
		{"session expiring this second", expiringSession, bndCarrierNone},
		{"session revoked now", revokedSession, bndCarrierNone},
		{"session revoked a second ago", pastRevokedSession, bndCarrierNone},
		{"expired key", expiredKey, bndCarrierNone},
		{"key expiring this second", expiringKey, bndCarrierNone},
		{"key revoked now", revokedKey, bndCarrierNone},
		{"key revoked a second ago", pastRevokedKey, bndCarrierNone},
		{"session of a revoked user", revokedUserSession, bndCarrierNone},
		{"key of a revoked user", revokedUserKey, bndCarrierNone},
		{"key of a revoked agent", revokedAgentKey, bndCarrierNone},

		// The same random body under another tag is another value, and nothing
		// stores it.
		{"the key's body under the session tag", tokenPrefix(tagSession) + body, bndCarrierNone},
		{"the session's body under the key tag", tokenPrefix(tagAPIKey) + sessionBody, bndCarrierNone},
		{"the session's body under the invitation tag", tokenPrefix(tagInvitation) + sessionBody, bndCarrierNone},

		// Not tokens at all.
		{"the prefix of a session alone", tokenPrefix(tagSession), bndCarrierNone},
		{"the prefix of a key alone", tokenPrefix(tagAPIKey), bndCarrierNone},
		{"a session truncated by one character", world.adminToken[:len(world.adminToken)-1], bndCarrierNone},
		{"a key extended by one character", liveKey + "A", bndCarrierNone},
		{"a session with its first character changed", tokenPrefix(tagSession) + bndFlip(sessionBody, 0), bndCarrierNone},
		{"a session with its last character changed", world.adminToken[:len(world.adminToken)-1] + "B", bndCarrierNone},
		{"a session with an upper-case prefix", strings.ToUpper(tokenPrefix(tagSession)) + sessionBody, bndCarrierNone},
		{"a key in upper case", strings.ToUpper(liveKey), bndCarrierNone},
		{"a key with padding", liveKey + "=", bndCarrierNone},
		{"a key with a plus", liveKey[:20] + "+" + liveKey[21:], bndCarrierNone},
		{"the hash in hex", hex.EncodeToString(tokenHash(liveKey)), bndCarrierNone},
		{"garbage", "garbage", bndCarrierNone},
		{"a dotted three-segment value", "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln", bndCarrierNone},
		{"a dotted value", "a.b.c", bndCarrierNone},
	}
}

// bndCarrierCases presents every token in every carrier that does not accept
// it: a cookie and a bearer header for a token with no carrier, and the other
// carrier for one that has a carrier. An empty token is no credential and is
// among the shape cases.
func bndCarrierCases(tokens []bndToken) []bndCookieCase {
	var out []bndCookieCase

	for _, tok := range tokens {
		if tok.carrier != bndCarrierCookie {
			out = append(out, bndOneCookie(tok.name+" as the cookie", cookieName+"="+tok.token))
		}

		if tok.carrier != bndCarrierBearer {
			out = append(out, bndCookieCase{
				name: tok.name + " as a bearer", headers: []string{"Authorization: Bearer " + tok.token},
			})
		}
	}

	return out
}

// bndAuthCases builds every credential shape the authentication boundary must
// refuse with the one opaque 401, for a world with a live admin session.
func bndAuthCases(t *testing.T, world bndWorld) []bndCookieCase {
	t.Helper()

	tokens := bndTokens(t, world)

	var session, key string

	for _, tok := range tokens {
		switch tok.name {
		case "active session":
			session = tok.token
		case "active agent key":
			key = tok.token
		}
	}

	cases := bndCarrierCases(tokens)
	cases = append(cases, bndEmptyCases()...)
	cases = append(cases, bndCookieShapeCases(session, key)...)
	cases = append(cases, bndHeaderCredentialCases(session, key)...)
	cases = append(cases, bndOversizedCookieCases(session)...)

	return cases
}

// bndEmptyCases are credentials with nothing in them.
func bndEmptyCases() []bndCookieCase {
	const cookie = cookieName + "="

	return []bndCookieCase{
		{name: "no cookie header"},
		bndOneCookie("empty cookie value", cookie),
		bndOneCookie("cookie with only whitespace", cookie+" "),
		{name: "a bearer with nothing after the scheme", headers: []string{"Authorization: Bearer"}},
		{name: "a bearer with only a space after the scheme", headers: []string{"Authorization: Bearer "}},
	}
}

// bndCookieShapeCases are ways of presenting a token (genuine or an API key)
// in cookies that must not authenticate: duplicates, other names, other casing.
func bndCookieShapeCases(token, apiKey string) []bndCookieCase {
	const cookie = cookieName + "="

	lines := func(name string, l ...string) bndCookieCase { return bndCookieCase{name: name, lines: l} }

	return []bndCookieCase{
		bndOneCookie("cookie sent twice, same value", cookie+token+"; "+cookie+token),
		bndOneCookie("cookie sent twice on one line, different", cookie+token+"; "+cookie+"garbage"),
		lines("cookie sent in two header lines, same", cookie+token, cookie+token),
		lines("cookie sent in two header lines, different", cookie+token, cookie+apiKey),
		bndOneCookie("empty cookie then the valid one", cookie+"; "+cookie+token),
		bndOneCookie("valid cookie then an empty one", cookie+token+"; "+cookie),
		lines("empty line then the valid one", cookie, cookie+token),
		lines("valid cookie then a garbage line", cookie+token, cookie+"garbage"),
		bndOneCookie("cookie of another name only", "session="+token),
		bndOneCookie("cookie without the host prefix", "host-session="+token),
		bndOneCookie("cookie name lower case", strings.ToLower(cookieName)+"="+token),
		bndOneCookie("cookie name upper case", strings.ToUpper(cookieName)+"="+token),
		bndOneCookie("cookie name with a suffix", cookieName+"x="+token),
		bndOneCookie("cookie name with a prefix", "x"+cookieName+"="+token),
		bndOneCookie("secure-prefix instead of host", "__Secure-session="+token),
		bndOneCookie("token in a differently named cookie among others", "a=1; b="+token+"; c=3"),
		bndOneCookie("token with a quote", cookie+`"`+token+`x"`),
		bndOneCookie("token with a percent escape", cookie+strings.Replace(token, token[:3], "%41%41%41", 1)),
		bndOneCookie("token with a space inside", cookie+token[:20]+" "+token[20:]),
		bndOneCookie("token with a plus", cookie+token[:20]+"+"+token[20:]),
		bndOneCookie("token with padding equals", cookie+token+"=="),
		bndOneCookie("token with unicode", cookie+token[:20]+"\xc3\xa9"+token[20:]),
	}
}

// bndHeaderCredentialCases present a genuine session or API key where it must
// not authenticate: another header, a scheme that is not Bearer, both carriers
// at once, or the Authorization header twice. A genuine API key as a lone
// bearer is a credential and is not a case here (see TestBndCredentialConfusion).
func bndHeaderCredentialCases(token, apiKey string) []bndCookieCase {
	header := func(name string, h ...string) bndCookieCase { return bndCookieCase{name: name, headers: h} }

	return []bndCookieCase{
		header("Authorization bearer lower case scheme with a session", "Authorization: bearer "+token),
		header("Authorization basic", "Authorization: Basic "+b64([]byte("a:"+token))),
		header("Authorization basic holding the API key", "Authorization: Basic "+b64([]byte("a:"+apiKey))),
		header("Authorization raw token", "Authorization: "+token),
		header("Authorization raw API key", "Authorization: "+apiKey),
		header("Authorization with another scheme and the API key", "Authorization: Token "+apiKey),
		header("Authorization bearer with two spaces", "Authorization: Bearer  "+apiKey),
		header("bearer in a custom header", "X-Session: "+token, "X-Auth-Token: "+apiKey),
		header("token in a forwarded url", "X-Original-Url: /?"+cookieName+"="+token),
		// Both carriers at once are ambiguous, whichever is valid and whichever
		// is not.
		header("a session cookie and an agent key as a bearer", "Cookie: "+cookieName+"="+token,
			"Authorization: Bearer "+apiKey),
		header("a session cookie and a garbage bearer", "Cookie: "+cookieName+"="+token, "Authorization: Bearer garbage"),
		header("a garbage cookie and an agent key as a bearer", "Cookie: "+cookieName+"=garbage",
			"Authorization: Bearer "+apiKey),
		header("an empty cookie and an agent key as a bearer", "Cookie: "+cookieName+"=",
			"Authorization: Bearer "+apiKey),
		header("a session cookie and a session as a bearer", "Cookie: "+cookieName+"="+token, "Authorization: Bearer "+token),
		// The Authorization header twice, whichever is valid.
		header("a session as a bearer and the agent key beside it",
			"Authorization: Bearer "+token, "Authorization: Bearer "+apiKey),
		header("the agent key twice", "Authorization: Bearer "+apiKey, "Authorization: Bearer "+apiKey),
		header("the agent key and then garbage", "Authorization: Bearer "+apiKey, "Authorization: Bearer garbage"),
		header("garbage and then the agent key", "Authorization: Bearer garbage", "Authorization: Bearer "+apiKey),
	}
}

// bndOversizedCookieCases are cookies around and above the length of a token:
// a value of the wrong length is refused by the parser before any lookup, as
// the one opaque 401, never a 5xx.
func bndOversizedCookieCases(token string) []bndCookieCase {
	const cookie = cookieName + "="

	return []bndCookieCase{
		bndOneCookie("cookie of 4096 bytes of garbage", cookie+strings.Repeat("a", 4096)),
		bndOneCookie("cookie of 4097 bytes of garbage", cookie+strings.Repeat("a", 4097)),
		bndOneCookie("valid token padded to 4097 bytes", cookie+token+strings.Repeat("A", 4097-len(token))),
		bndOneCookie("cookie of 8 KiB", cookie+strings.Repeat("a", 8192)),
		bndOneCookie("cookie of 60 KB", cookie+strings.Repeat("a", 60000)),
		// net/http returns no cookies at all past 3000 (a defence against cookie
		// floods), so even the genuine token beside them is not seen: a refusal.
		bndOneCookie("3001 cookies with the valid one among them", strings.Repeat("a=1; ", 3000)+cookie+token),
	}
}

// TestBndAuthenticationMatrix: every session route against every credential
// that must NOT authenticate: each token state (active, unknown, expired,
// revoked, its user or agent revoked, malformed) of each kind (session, API key,
// invitation) in each carrier (the cookie, the bearer header) that does not
// accept it, and the request shapes that are ambiguous (two cookies, a cookie
// and a bearer, two Authorization headers). All of them are the same opaque 401
// unauthenticated, with byte-identical bodies across causes (no oracle for
// which check failed), no Set-Cookie, nothing written, and never a 5xx. The
// cases run through the real wasm's cookie and header parsing, the token
// parsers and the real D1 lookup.
//
//nolint:paralleltest // shares one database
func TestBndAuthenticationMatrix(t *testing.T) {
	world := bndNewWorld(t)
	cases := bndAuthCases(t, world)
	before := bndSnapshot(t)

	// The sanity check the matrix rests on: the genuine session works.
	for _, route := range bndSessionRoutes() {
		if route.name == "session" {
			get(t, route.path(""), world.adminToken).expect(t, "the genuine session", http.StatusOK, "")
		}
	}

	bodies := map[string][]string{}

	var mu sync.Mutex

	for _, route := range bndSessionRoutes() {
		for _, c := range cases {
			t.Run(route.name+"/"+c.name, func(t *testing.T) {
				got := bndAuthRequest(t, route, c)

				if got.status != http.StatusUnauthorized || got.body != bndErrUnauth {
					t.Fatalf("%s with %s = %d %q, want the opaque 401 %q", route.name, c.name, got.status, got.body, bndErrUnauth)
				}

				if got.header.Get("WWW-Authenticate") != "" {
					t.Errorf("401 carries WWW-Authenticate %q", got.header.Get("WWW-Authenticate"))
				}

				bndNoCookies(t, c.name, got)

				mu.Lock()
				bodies[got.body] = append(bodies[got.body], route.name+"/"+c.name)
				mu.Unlock()
			})
		}
	}

	t.Run("all 401 bodies are byte-identical", func(t *testing.T) {
		if len(bodies) > 1 {
			t.Errorf("%d different 401 bodies across causes: %v", len(bodies), bodies)
		}
	})

	// The genuine session survived every attack above (nothing revoked it).
	get(t, pathSession, world.adminToken).expect(t, "the genuine session afterwards", http.StatusOK, "")

	if after := bndSnapshot(t); after != before {
		t.Errorf("an unauthenticated request changed the database:\n before %s\n after  %s", before, after)
	}
}

// TestBndCookieSpellingsThatDoAuthenticate records the lenient spellings of a
// valid session cookie that Go's RFC 6265 cookie parser (and so the Worker)
// accepts: surrounding whitespace, whitespace before the equals sign, a
// trailing semicolon or attributes after a semicolon (the Cookie header carries
// no attributes, so they parse as further cookies and are ignored), and a quoted
// value. None of them lets anyone in who does not hold the token, so they are
// harmless; the test pins them so a change in parsing is noticed. A different
// cookie NAME never authenticates (see TestBndAuthenticationMatrix).
//
//nolint:paralleltest // shares one database
func TestBndCookieSpellingsThatDoAuthenticate(t *testing.T) {
	world := bndNewWorld(t)
	token := world.adminToken

	tests := []struct{ name, line string }{
		{"plain", cookieName + "=" + token},
		{"leading space", " " + cookieName + "=" + token},
		{"trailing space", cookieName + "=" + token + " "},
		{"space before equals", cookieName + " =" + token},
		{"tab before equals", cookieName + "\t=" + token},
		{"trailing semicolon", cookieName + "=" + token + ";"},
		{"attributes after a semicolon", cookieName + "=" + token + "; Path=/; Secure"},
		{"another cookie first", "a=1; " + cookieName + "=" + token},
		{"another cookie after", cookieName + "=" + token + "; a=1"},
		{"quoted value", cookieName + "=\"" + token + "\""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bndRaw(t, "GET /api/session HTTP/1.1\r\nHost: x\r\nCookie: "+tt.line+"\r\nConnection: close\r\n\r\n")
			got.expect(t, "GET /api/session with "+tt.name, http.StatusOK, "")
		})
	}
}

// bndStateBreaks are the ways the database can make a once-valid session
// invalid. Each is the SQL that does it to the session whose secret id is {ID}.
// The token carries nothing, so the stored rows are all there is to break.
func bndStateBreaks() []struct {
	name string
	sql  string
} {
	return []struct {
		name string
		sql  string
	}{
		{"revoked", "UPDATE secrets SET revoked_at = strftime('%s','now') - 1 WHERE id = '{ID}'"},
		{"revoked at this second", "UPDATE secrets SET revoked_at = strftime('%s','now') WHERE id = '{ID}'"},
		{"expired in the database", "UPDATE secrets SET expires_at = strftime('%s','now') - 1 WHERE id = '{ID}'"},
		{"expires exactly now", "UPDATE secrets SET expires_at = strftime('%s','now') WHERE id = '{ID}'"},
		{"secret row deleted (its session row goes with it)", "DELETE FROM secrets WHERE id = '{ID}'"},
		{"session row deleted (its secret goes with it)", "DELETE FROM sessions WHERE id = '{ID}'"},
		{"its hash replaced", "UPDATE secrets SET hash = randomblob(32) WHERE id = '{ID}'"},
		{
			"its passkey deleted",
			"DELETE FROM credentials WHERE id = (SELECT credential_id FROM sessions WHERE id = '{ID}')",
		},
		{
			"user revoked",
			"UPDATE users SET revoked_at = strftime('%s','now') - 1 " +
				"WHERE id = (SELECT user_id FROM sessions WHERE id = '{ID}')",
		},
		{
			// An account and its organizations hold each other (the account its
			// organization, the organization its creator), so the organizations it
			// created and the invitations that name them go first, and the
			// account's key to its organization is checked when the statements
			// commit.
			"user deleted",
			"DELETE FROM invitation_orgs; " +
				"DELETE FROM org_admins WHERE user_id = (SELECT user_id FROM sessions WHERE id = '{ID}'); " +
				"DELETE FROM orgs WHERE created_by = (SELECT user_id FROM sessions WHERE id = '{ID}'); " +
				"DELETE FROM users WHERE id = (SELECT user_id FROM sessions WHERE id = '{ID}')",
		},
	}
}

// TestBndStoredSessionStateMatrix: a session whose stored rows say it is no
// longer usable is the same opaque 401 on every session route, whatever the
// reason, with an unchanged body, and the failure is never a 5xx. Each case
// uses a fresh world: they destroy rows.
//
//nolint:paralleltest // shares one database
func TestBndStoredSessionStateMatrix(t *testing.T) {
	for _, stateBreak := range bndStateBreaks() {
		t.Run(stateBreak.name, func(t *testing.T) {
			world := bndNewWorld(t)
			// A second live session of another user, which no break of the first
			// may touch.
			victim := login(t, world.member)

			// Sanity: before the break every session route accepts the token.
			get(t, pathSession, world.adminToken).expect(t, "before", http.StatusOK, "")

			id := idOfToken(t, world.adminToken)
			seedAll(t, sqlStmt(strings.ReplaceAll(stateBreak.sql, "{ID}", id)))

			for _, route := range bndSessionRoutes() {
				got := send(
					t,
					request{method: route.method, path: route.path(idMissing), token: world.adminToken, body: bndBodyOf(route)},
				)

				if got.status != http.StatusUnauthorized || got.body != bndErrUnauth {
					t.Errorf("%s after %q = %d %q, want the opaque 401", route.name, stateBreak.name, got.status, got.body)
				}
			}

			get(t, pathSession, victim).expect(t, "the other user's session", http.StatusOK, "")
		})
	}
}

// TestBndActiveCredentialsAreAcceptedOnlyInTheirCarrier is the positive half of
// the carrier x kind matrix: an active session is accepted from the cookie, an
// active API key from the bearer header, each of an agent or of the user, and
// a revocation scheduled for later has not happened yet, so such a secret is
// still accepted. The same tokens in the other carrier are the matrix's
// refusals.
//
//nolint:paralleltest // shares one database
func TestBndActiveCredentialsAreAcceptedOnlyInTheirCarrier(t *testing.T) {
	world := bndNewWorld(t)

	scheduledSession := seedSession(t, idN("0e00", 1), world.admin.userID)
	scheduledKey := seedAPIKey(t, idN("0e01", 1), world.admin.userID, "")
	ownKey := seedAPIKey(t, idN("0e01", 2), world.admin.userID, "")

	seed(t, "UPDATE secrets SET revoked_at = strftime('%s','now') + 3600 WHERE id IN (?, ?)",
		idN("0e00", 1), idN("0e01", 1))

	tokens := []bndToken{
		{"active session", world.adminToken, bndCarrierCookie},
		{"active member session", world.memberToken, bndCarrierCookie},
		{"session revoked in an hour", scheduledSession, bndCarrierCookie},
		{"agent key", bndAgentKey(t, world.adminToken), bndCarrierBearer},
		{"the user's own key", ownKey, bndCarrierBearer},
		{"key revoked in an hour", scheduledKey, bndCarrierBearer},
	}

	for _, tok := range tokens {
		t.Run(tok.name, func(t *testing.T) {
			var accepted, refused reply

			if tok.carrier == bndCarrierCookie {
				accepted = send(t, request{path: pathSession, token: tok.token})
				refused = send(t, request{path: pathSession, bearer: tok.token})
			} else {
				accepted = send(t, request{path: pathSession, bearer: tok.token})
				refused = send(t, request{path: pathSession, token: tok.token})
			}

			accepted.expect(t, "GET /api/session in its own carrier", http.StatusOK, "")

			if refused.status != http.StatusUnauthorized || refused.body != bndErrUnauth {
				t.Errorf("GET /api/session in the other carrier = %d %q, want the opaque 401", refused.status, refused.body)
			}

			bndNoCookies(t, tok.name, accepted)
		})
	}
}

// ---- 6. permission confusion -------------------------------------------------

// bndOutcome is the status and code a role gets on a route.
type bndOutcome struct {
	status int
	code   string
}

// TestBndPermissionMatrix: role x route x credential over EVERY route, with the
// route's own valid body so a request that is let through reaches its handler.
// The oracle is each route's declared access: public routes answer for anyone;
// any-session routes need a valid session of any role; admin routes need the
// admin role. A refusal (401 or 403) writes NOTHING (row counts and the cells
// the mutations would change are compared before and after), and a request
// that is let through is not a 401 or 403.
//
//nolint:paralleltest // shares one database
func TestBndPermissionMatrix(t *testing.T) {
	world := bndNewWorld(t)

	// A revoked admin: a third account that is an admin and then revoked.
	revokedAdmin := bndSeedExtraAccount(t, 3, roleAdmin)
	revokedToken := login(t, revokedAdmin)

	seed(t, "UPDATE users SET revoked_at = strftime('%s','now') - 1 WHERE id = ?", revokedAdmin.userID)

	// A logged-out admin session is a revoked key.
	loggedOut := login(t, world.admin)
	post(t, pathLogout, nil, loggedOut).expect(t, "logout", http.StatusNoContent, "")

	credentials := []struct {
		name  string
		token string
		// who is what the credential is: anonymous, member, admin, or dead.
		who string
	}{
		{"no session", "", "anonymous"},
		{"member session", world.memberToken, "member"},
		{"admin session", world.adminToken, "admin"},
		{"revoked admin account", revokedToken, "dead"},
		{"logged-out admin session", loggedOut, "dead"},
	}

	for _, route := range bndRoutes() {
		for _, credential := range credentials {
			t.Run(route.name+"/"+credential.name, func(t *testing.T) {
				want := bndExpected(route.access, credential.who)

				before := bndSnapshot(t)
				id := world.idFor(route.pattern)

				got := send(t, request{method: route.method, path: route.path(id), token: credential.token, body: bndBodyOf(route)})

				if want.status != 0 {
					if got.status != want.status || got.errorCode() != want.code {
						t.Fatalf(
							"%s as %s = %d %q, want %d %s",
							route.name,
							credential.name,
							got.status,
							got.body,
							want.status,
							want.code,
						)
					}

					if after := bndSnapshot(t); after != before {
						t.Errorf("a refused request changed the database:\n before %s\n after  %s", before, after)
					}

					return
				}

				// Let through: not an authentication or authorization refusal. A
				// public route's own handler may still refuse the body (its own 401
				// invalid_login, 403 invalid_invitation), which is not the boundary.
				boundaryRefusal := got.errorCode() == codeUnauthenticated || got.errorCode() == codeForbidden
				if boundaryRefusal || got.status >= 500 {
					t.Errorf("%s as %s = %d %q, want it to reach its handler", route.name, credential.name, got.status, got.body)
				}

				// The state is restored for the next case: the mutations above
				// (a revoke, a rename, a cap) would change what later cases see.
				bndRestore(t, world)
			})
		}
	}
}

// bndExpected is the outcome the declared access promises a kind of caller;
// status 0 means "let through".
func bndExpected(access bndAccess, who string) bndOutcome {
	switch access {
	case bndPublic:
		return bndOutcome{}
	case bndAnySession:
		if who == "anonymous" || who == "dead" {
			return bndOutcome{http.StatusUnauthorized, codeUnauthenticated}
		}

		return bndOutcome{}
	case bndAdminOnly:
		switch who {
		case "anonymous", "dead":
			return bndOutcome{http.StatusUnauthorized, codeUnauthenticated}
		case "member":
			return bndOutcome{http.StatusForbidden, codeForbidden}
		}

		return bndOutcome{}
	}

	panic("unknown access")
}

// bndRestore puts back what a let-through request may have changed, so the
// next case in the matrix starts from the same world: the admin's and the
// member's sessions (a logout revokes one), the agent, the invitation, the
// member, and the organization.
func bndRestore(t *testing.T, world bndWorld) {
	t.Helper()

	seed(
		t,
		"UPDATE secrets SET revoked_at = NULL WHERE id IN (?, ?, ?)",
		idOfToken(t, world.adminToken),
		idOfToken(t, world.memberToken),
		world.invitationID,
	)
	seed(t, "UPDATE agents SET revoked_at = NULL, name = 'seeded' WHERE id = ?", world.agentID)
	seed(t, "DELETE FROM agents WHERE id <> ?", world.agentID)
	seed(t, "UPDATE invitations SET num_invites = 3 WHERE id = ?", world.invitationID)
	seed(t, "DELETE FROM invitations WHERE id <> ? AND type <> 'first_run'", world.invitationID)
	seed(t, "UPDATE users SET revoked_at = NULL WHERE id IN (?, ?)", world.admin.userID, world.member.userID)

	// The organizations: every account keeps its own, the admin administers the
	// one registration created for it, and the world's own organization, which
	// no account belongs to, is put back as it was.
	seed(t, "DELETE FROM invitation_orgs")
	seed(t, "DELETE FROM org_admins WHERE NOT (org_id = ? AND user_id = ?)", world.adminOrgID, world.admin.userID)
	seed(t, "DELETE FROM orgs WHERE id NOT IN (SELECT org_id FROM users)")
	seed(t, "UPDATE orgs SET name = ? WHERE id = ?", world.adminOrgName, world.adminOrgID)
	bndSeedOrg(t, world.admin.userID)
}

// bndSeedExtraAccount seeds another account with the role and a passkey.
func bndSeedExtraAccount(t *testing.T, n int, role string) passkey {
	t.Helper()

	priv := newKey(t)
	credID := randomBytes(32)
	handle := randomBytes(16)
	userID := idN("0b00", 100+n)

	cose := coseES256(t, priv.X.FillBytes(make([]byte, 32)), priv.Y.FillBytes(make([]byte, 32)))

	seedAccount(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) "+
		"VALUES (?, ?, ?, (SELECT id FROM invitations LIMIT 1), strftime('%s','now'))", userID, handle, role)
	seed(t, "INSERT INTO credentials (id, user_id, credential_id, public_key, flags, metadata, created_at) "+
		"VALUES (?, ?, ?, ?, 5, '{}', strftime('%s','now'))", idN("0c00", 100+n), userID, credID, cose)

	return passkey{priv: priv, credID: credID, handle: handle, userID: userID}
}

// TestBndRoleChangeTakesEffectOnTheNextRequest: the role is read from the
// account on every request and is in no token (a token carries nothing), so demoting an
// admin makes their very next request 403 (with the same token), promoting a
// member makes theirs succeed, and a revoked account's token is 401 at once.
//
//nolint:paralleltest // shares one database
func TestBndRoleChangeTakesEffectOnTheNextRequest(t *testing.T) {
	world := bndNewWorld(t)

	adminRoutes := []bndRoute{}

	for _, route := range bndRoutes() {
		if route.access == bndAdminOnly && route.method == http.MethodGet {
			adminRoutes = append(adminRoutes, route)
		}
	}

	check := func(token string, want int, label string) {
		t.Helper()

		for _, route := range adminRoutes {
			got := send(t, request{method: route.method, path: route.path(world.member.userID), token: token})
			if got.status != want && (want != http.StatusOK || got.status != http.StatusNotFound) {
				t.Errorf("%s: %s = %d %q, want %d", label, route.name, got.status, got.body, want)
			}
		}
	}

	check(world.adminToken, http.StatusOK, "admin before demotion")

	setRole(t, world.admin.userID, roleMember)
	check(world.adminToken, http.StatusForbidden, "admin demoted mid-session")
	get(t, pathSession, world.adminToken).expect(t, "demoted admin still has a session", http.StatusOK, "")

	setRole(t, world.admin.userID, roleAdmin)
	check(world.adminToken, http.StatusOK, "admin restored")

	check(world.memberToken, http.StatusForbidden, "member before promotion")
	setRole(t, world.member.userID, roleAdmin)
	check(world.memberToken, http.StatusOK, "member promoted mid-session")

	got := get(t, pathSession, world.memberToken)
	if !strings.Contains(got.body, `"role":"admin"`) {
		t.Errorf("session after promotion = %s, want role admin", got.body)
	}

	seed(t, "UPDATE users SET revoked_at = strftime('%s','now') - 1 WHERE id = ?", world.member.userID)
	check(world.memberToken, http.StatusUnauthorized, "promoted member revoked")

	// A role string that merely looks like admin is not admin.
	for _, role := range []string{"Admin", "ADMIN", "admin ", " admin", "administrator", "admin\u200b", "root"} {
		seed(t, "UPDATE users SET role = ? WHERE id = ?", role, world.admin.userID)

		got := get(t, "/api/user", world.adminToken)
		if got.status != http.StatusForbidden && got.status != http.StatusUnauthorized {
			t.Errorf("role %q reached an admin route: %d %s", role, got.status, got.body)
		}
	}
}

// bndKeyMayNot reports whether a default-agent key may not use the route:
// everything but reading agents and the open routes (whoami, logout), by scope
// or by the rule that agents are refused.
func bndKeyMayNot(route string) bool {
	switch route {
	case "session", "logout", "agent list", "agent get":
		return false
	default:
		return true
	}
}

// TestBndCredentialConfusion: tokens that are genuine and stored, but not a
// session for this caller, do not authenticate: an agent API key (a different
// kind) is not a session whatever route it is presented to, and a session is
// not an API key. (The carrier x kind matrix is TestBndAuthenticationMatrix,
// here with every unsafe route and a write check.)
//
//nolint:paralleltest // shares one database
func TestBndCredentialConfusion(t *testing.T) {
	world := bndNewWorld(t)

	created := post(t, pathAgent, []byte(`{"name":"key"}`), world.adminToken)
	if created.status != http.StatusCreated {
		t.Fatalf("create agent = %d %s", created.status, created.body)
	}

	var parsed struct {
		Key struct {
			Token string `json:"token"`
			ID    string `json:"id"`
		} `json:"key"`
	}

	err := json.Unmarshal([]byte(created.body), &parsed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	apiKey := parsed.Key.Token

	// The key is a real secret of kind api_key for the admin, stored by the hash
	// of its token; it must not resolve as a session even though the user is an
	// admin and the token is genuine.
	if stored := mustSecretOf(t, apiKey); stored.id != parsed.Key.ID || stored.kind != kindAPIKey || !stored.kindRow {
		t.Fatalf("the key's secret = %+v, want kind api_key under %s with its row", stored, parsed.Key.ID)
	}

	routes := bndSessionRoutes()

	// An account may have 25 active agents, and every route gets its own key, so
	// the keys are spread over the two accounts, turn and turn about.
	owners := []string{world.adminToken, world.memberToken}

	for i, route := range routes {
		owner := owners[i%len(owners)]

		t.Run(route.name+"/api key as cookie", func(t *testing.T) {
			got := send(t, request{method: route.method, path: route.path(idMissing), token: apiKey, body: bndBodyOf(route)})
			if got.status != http.StatusUnauthorized || got.body != bndErrUnauth {
				t.Errorf("%s with an API key = %d %q, want the opaque 401", route.name, got.status, got.body)
			}
		})

		// An API key is a credential as a bearer: it is verified, never refused
		// as a bad token, and then judged by its scope. The admin's agent holds
		// the default agent bundle, so it can read agents and nothing else, and
		// the admin routes need the role AND an admin scope the bundle lacks.
		// Each route gets its own key: logout ends the key it presents.
		t.Run(route.name+"/api key as bearer", func(t *testing.T) {
			own := bndAgentKey(t, owner)

			got := send(t, request{
				method: route.method, path: route.path(idMissing), body: bndBodyOf(route),
				headers: map[string]string{"Authorization": "Bearer " + own},
			})
			if got.status == http.StatusUnauthorized {
				t.Errorf("%s: a genuine API key as a bearer was refused as unauthenticated: %q", route.name, got.body)
			}

			if bndKeyMayNot(route.name) && got.status != http.StatusForbidden {
				t.Errorf("%s with the default agent bundle = %d %q, want 403", route.name, got.status, got.body)
			}
		})

		t.Run(route.name+"/session as bearer", func(t *testing.T) {
			got := send(t, request{
				method: route.method, path: route.path(idMissing), body: bndBodyOf(route),
				headers: map[string]string{"Authorization": "Bearer " + world.adminToken},
			})
			if got.status != http.StatusUnauthorized || got.body != bndErrUnauth {
				t.Errorf("%s with a session bearer = %d %q, want the opaque 401", route.name, got.status, got.body)
			}
		})
	}

	// The agents this test created are the only writes: the first, and one per
	// route for its own key. No refused request created, renamed or revoked
	// anything, and no key was revoked except by logout ending its own key.
	expectCount(t, "agents WHERE name = 'key'", "1")
	expectCount(t, "agents WHERE name = 'audience'", strconv.Itoa(len(routes)))
	expectCount(t, "agents WHERE revoked_at IS NOT NULL", "0")
	expectCount(t, "agents WHERE name = 'renamed'", "0")
}

// TestBndLogoutBoundary: logout is the one unsafe route whose credential is
// the cookie itself, so it is where the boundary's pieces meet: it needs the
// media type, it clears the cookie with the attributes the session cookie had
// (so a browser replaces it), it revokes that session and no other, and a second
// logout is the same opaque 401 as any request without a session.
//
//nolint:paralleltest // shares one database
func TestBndLogoutBoundary(t *testing.T) {
	world := bndNewWorld(t)
	other := login(t, world.admin)

	got := post(t, pathLogout, nil, world.adminToken)
	if got.status != http.StatusNoContent || got.body != "" {
		t.Fatalf("logout = %d %q, want 204 with no body", got.status, got.body)
	}

	if len(got.setCookies) != 1 {
		t.Fatalf("Set-Cookie = %v, want exactly one", got.setCookies)
	}

	for _, want := range []string{cookieName + "=;", "Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=0"} {
		if !strings.Contains(got.setCookies[0], want) {
			t.Errorf("Set-Cookie %q lacks %q", got.setCookies[0], want)
		}
	}

	if strings.Contains(got.setCookies[0], "Domain=") {
		t.Errorf("Set-Cookie %q has a Domain: __Host- cookies must not", got.setCookies[0])
	}

	// The secret is revoked and kept, not deleted.
	expectCount(t, "secrets WHERE id = ? AND revoked_at <= strftime('%s','now')", "1", idOfToken(t, world.adminToken))
	expectCount(t, "sessions WHERE id = ?", "1", idOfToken(t, world.adminToken))

	again := post(t, pathLogout, nil, world.adminToken)
	if again.status != http.StatusUnauthorized || again.body != bndErrUnauth {
		t.Errorf("second logout = %d %q, want the opaque 401", again.status, again.body)
	}

	bndNoCookies(t, "second logout", again)
	get(t, pathSession, world.adminToken).expect(t, "session after logout", http.StatusUnauthorized, codeUnauthenticated)
	get(t, pathSession, other).expect(t, "another session of the same user", http.StatusOK, "")
}

// TestBndConcurrentCredentialsDoNotLeakAcrossRequests: the boundary keeps no
// per-connection or per-process authentication state, so requests released
// together with different credentials each get the answer their own credential
// earns: the admin and member sessions their own role, a logged-out session
// and garbage the opaque 401, and the anonymous caller the same. Several rounds
// of a start channel across all of them; a verdict that bled from one request
// to another (a cached principal, a shared Call) would show as a wrong status.
//
//nolint:paralleltest // shares one database
func TestBndConcurrentCredentialsDoNotLeakAcrossRequests(t *testing.T) {
	world := bndNewWorld(t)
	dead := login(t, world.admin)
	post(t, pathLogout, nil, dead).expect(t, "logout", http.StatusNoContent, "")

	credentials := []struct {
		name  string
		token string
		want  int
	}{
		{"admin", world.adminToken, http.StatusOK},
		{"member", world.memberToken, http.StatusForbidden},
		{"logged out", dead, http.StatusUnauthorized},
		{"garbage", "garbage", http.StatusUnauthorized},
		{"anonymous", "", http.StatusUnauthorized},
	}

	const rounds, perCredential = 4, 6

	for round := range rounds {
		start := make(chan struct{})

		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			failures []string
		)

		for _, credential := range credentials {
			for range perCredential {
				wg.Go(func() {
					<-start

					status, body, err := bndStatusOf(t, "/api/user", credential.token)
					if err != nil || status != credential.want {
						mu.Lock()
						failures = append(failures, fmt.Sprintf("%s = %d %s %v", credential.name, status, body, err))
						mu.Unlock()
					}
				})
			}
		}

		close(start)
		wg.Wait()

		if len(failures) != 0 {
			t.Errorf("round %d: %d wrong answers: %v", round, len(failures), failures)
		}
	}
}

// TestBndInvitationCreateIsAdminOnly: POST /api/invitation is 401 with no
// session and 403 for a member whatever the body holds (the credential is judged
// before the body is read), and only an admin reaches the handler: an
// uncreatable type is 400 invalid_invitation_type and writes nothing, a
// creatable one is 201 and writes one row.
//
//nolint:paralleltest // shares one database
func TestBndInvitationCreateIsAdminOnly(t *testing.T) {
	world := bndNewWorld(t)
	before := count(t, "invitations")

	types := []string{"first_run", "e2e_invite", "", "FIRST_RUN", "first_run ", "x", "member", "admin"}

	for _, invitationType := range types {
		body := mustJSON(t, map[string]any{"type": invitationType, "numInvites": 1})

		post(t, pathInvitation, body, "").expect(t, "no session", http.StatusUnauthorized, codeUnauthenticated)
		post(t, pathInvitation, body, world.memberToken).expect(t, "member", http.StatusForbidden, codeForbidden)
	}

	// An invalid body is the same 401/403 for a caller who may not create.
	bad := []byte(`nope`)

	post(t, pathInvitation, bad, "").expect(t, "no session, bad body", http.StatusUnauthorized, codeUnauthenticated)
	post(t, pathInvitation, bad, world.memberToken).expect(t, "member, bad body", http.StatusForbidden, codeForbidden)

	expectCount(t, "invitations", before)

	for _, invitationType := range types {
		body := mustJSON(t, map[string]any{"type": invitationType, "numInvites": 1})
		got := post(t, pathInvitation, body, world.adminToken)

		if invitationType == "member" || invitationType == "admin" {
			got.expect(t, "admin creates "+invitationType, http.StatusCreated, "")

			continue
		}

		got.expect(t, "admin type "+invitationType, http.StatusBadRequest, "invalid_invitation_type")
	}

	want, err := strconv.Atoi(before)
	if err != nil {
		t.Fatalf("count %q: %v", before, err)
	}

	expectCount(t, "invitations", strconv.Itoa(want+2))
}

// TestBndNoRefreshRoute: a session is never extended, and there is no route that
// would: any attempt to find one is a plain 404.
//
//nolint:paralleltest // shares one database
func TestBndNoRefreshRoute(t *testing.T) {
	world := bndNewWorld(t)
	expires := scalar(t, "SELECT expires_at FROM secrets WHERE id = ?", idOfToken(t, world.adminToken))

	for _, path := range []string{"/api/refresh", "/api/session/refresh", "/api/token", "/api/sessions", "/api/me"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			got := send(t, request{method: method, path: path, token: world.adminToken})
			got.expect(t, method+" "+path, http.StatusNotFound, codeNotFound)
		}
	}

	id := idOfToken(t, world.adminToken)
	if after := scalar(t, "SELECT expires_at FROM secrets WHERE id = ?", id); after != expires {
		t.Errorf("expires_at changed from %s to %s", expires, after)
	}
}

// ---- 7. healthz, no internals in error bodies --------------------------------

// TestBndHealthz: the liveness check answers 200 {"status":"ok"} for anyone,
// reads neither the cookie nor the database (it answers with a garbage cookie
// and an unreadable id), is cacheless, and is a GET only.
//
//nolint:paralleltest // shares one database
func TestBndHealthz(t *testing.T) {
	reset(t)

	want := `{"status":"ok"}` + "\n"

	tests := []struct {
		name    string
		request request
	}{
		{"plain", request{path: pathHealth}},
		{"garbage cookie", request{path: pathHealth, headers: map[string]string{"Cookie": cookieName + "=garbage"}}},
		{
			"two session cookies",
			request{path: pathHealth, headers: map[string]string{"Cookie": cookieName + "=a; " + cookieName + "=b"}},
		},
		{"query string", request{path: pathHealth + "?x=1&x=2"}},
		{"unknown origin", request{path: pathHealth, headers: map[string]string{"Origin": "https://evil.example"}}},
		{"authorization header", request{path: pathHealth, headers: map[string]string{"Authorization": "Bearer x"}}},
		{"content type on GET", request{path: pathHealth, headers: map[string]string{"Content-Type": "text/plain"}}},
		{"empty database", request{path: pathHealth}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := send(t, tt.request)
			if got.status != http.StatusOK || got.body != want {
				t.Errorf("healthz = %d %q, want 200 %q", got.status, got.body, want)
			}

			if got.header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(
				got.header.Get("Content-Type"),
				"application/json",
			) {
				t.Errorf("headers = %v, want no-store JSON", got.header)
			}

			bndNoCookies(t, "healthz", got)
		})
	}

	t.Run("a body on GET within the cap is ignored", func(t *testing.T) {
		got := send(t, request{path: pathHealth, body: []byte(`{"x":1}`)})
		if got.status != http.StatusOK {
			t.Errorf("healthz with a body = %d %q", got.status, got.body)
		}
	})
}

// bndLeakPatterns are fragments that must never appear in a response body: a
// stack, SQL text, a driver error name, a file path or a runtime frame.
func bndLeakPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`D1_ERROR`),
		regexp.MustCompile(`(?i)sqlite`),
		regexp.MustCompile(`(?i)\bSELECT\b.*\bFROM\b`),
		regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`),
		regexp.MustCompile(`(?i)\bUPDATE\b.*\bSET\b`),
		regexp.MustCompile(`(?i)constraint`),
		regexp.MustCompile(`(?i)\bsecrets\b|\bapi_keys\b|\bcredentials\b|\binvitations\b`),
		regexp.MustCompile(`\.go:\d+`),
		regexp.MustCompile(`/home/|/usr/|/tmp/|node_modules|file://`),
		regexp.MustCompile(`goroutine|panic:|runtime\.|syscall/js|wasm_exec|at .*\(.*:\d+:\d+\)`),
		regexp.MustCompile(`(?i)stack`),
		regexp.MustCompile(`AUTH_HMAC_SECRET|FIRST_RUN_SECRET|OAUTH_SIGNING_KEY|` +
			regexp.QuoteMeta(authHMACSecret) + `|` + regexp.QuoteMeta(firstRunSecret)),
		// The signing key's value, as the variable holds it and as the PEM a
		// careless dump of the key would be. Never empty in a run with a Worker.
		regexp.MustCompile(regexp.QuoteMeta(signingKeyValue()) + `|PRIVATE KEY`),
	}
}

// signingKeyValue is the Worker's OAUTH_SIGNING_KEY, which fails the test run if
// it is missing: an empty value would make a leak pattern match everything, or
// nothing, and either would hide a leak.
func signingKeyValue() string {
	if signingKey == "" {
		panic("e2e: the Worker's OAUTH_SIGNING_KEY is not set")
	}

	return signingKey
}

// bndLeaks returns the patterns that match body.
func bndLeaks(body string) []string {
	var found []string

	for _, pattern := range bndLeakPatterns() {
		if pattern.MatchString(body) {
			found = append(found, pattern.String())
		}
	}

	return found
}

// TestBndNoInternalsInErrorBodies: across a table of triggered failures at
// every layer of the boundary (and a few the feature layer produces), the body
// is always the JSON envelope with a code and a fixed message, and never
// contains a stack, SQL text, a driver error name, a file path or a secret.
//
//nolint:paralleltest // shares one database
func TestBndNoInternalsInErrorBodies(t *testing.T) {
	world := bndNewWorld(t)

	cases := []struct {
		name string
		req  request
		// raw, when set, is sent over a raw connection instead.
		raw    string
		status int
	}{
		{name: "404", req: request{path: "/nope"}, status: 404},
		{name: "405", req: request{method: http.MethodPut, path: "/api/session"}, status: 405},
		{name: "415", req: request{method: http.MethodPost, path: "/api/login/begin", noType: true}, status: 415},
		{name: "413", req: request{method: http.MethodPost, path: "/api/login/begin", body: bndBodyOfLen(2000)}, status: 413},
		{name: "invalid id, signed out", req: request{path: "/api/agent/x"}, status: 401},
		{name: "invalid id, signed in", req: request{path: "/api/agent/x", token: world.adminToken}, status: 400},
		{name: "invalid id with sql, signed out", req: request{path: "/api/agent/%27%20OR%201%3D1--"}, status: 401},
		{
			name: "invalid id with sql, signed in", status: 400,
			req: request{path: "/api/agent/%27%20OR%201%3D1--", token: world.adminToken},
		},
		{name: "401", req: request{path: pathSession}, status: 401},
		{name: "401 garbage cookie", req: request{path: pathSession, token: "garbage"}, status: 401},
		{name: "403", req: request{path: "/api/user", token: world.memberToken}, status: 403},
		{name: "agent missing", req: request{path: "/api/agent/" + idMissing, token: world.adminToken}, status: 404},
		{
			name:   "invitation missing",
			req:    request{method: http.MethodDelete, path: "/api/invitation/" + idMissing, token: world.adminToken},
			status: 404,
		},
		{name: "user missing", req: request{path: "/api/user/" + idMissing, token: world.adminToken}, status: 404},
		{
			name: "invitation type unsupported",
			req: request{
				method: http.MethodPost,
				path:   "/api/invitation",
				token:  world.adminToken,
				body:   []byte(`{"type":"x","numInvites":1}`),
			},
			status: 400,
		},
		{name: "empty body", req: request{method: http.MethodPost, path: "/api/agent", token: world.adminToken}, status: 400},
		{
			name:   "invalid json",
			req:    request{method: http.MethodPost, path: "/api/agent", token: world.adminToken, body: []byte(`{`)},
			status: 400,
		},
		{
			name: "unknown field",
			req: request{
				method: http.MethodPost,
				path:   "/api/agent",
				token:  world.adminToken,
				body:   []byte(`{"name":"a","x":1}`),
			},
			status: 400,
		},
		{
			name: "invalid utf8",
			req: request{
				method: http.MethodPost,
				path:   "/api/agent",
				token:  world.adminToken,
				body:   []byte("{\"name\":\"a\xff\"}"),
			},
			status: 400,
		},
		{
			name:   "login finish garbage",
			req:    request{method: http.MethodPost, path: "/api/login/finish", body: []byte(`{"id":"x"}`)},
			status: 401,
		},
		{
			name:   "register finish garbage",
			req:    request{method: http.MethodPost, path: "/api/register/finish", body: []byte(`{"credential":1}`)},
			status: 400,
		},
		{
			name: "register begin unknown code",
			req: request{
				method: http.MethodPost,
				path:   "/api/register/begin",
				body:   []byte(`{"invitationCode":"` + strings.Repeat("A", 43) + `","name":"n","email":"n@example.com"}`),
			},
			status: -1,
		},
		{
			name: "sql in a body string",
			req: request{
				method: http.MethodPost,
				path:   "/api/agent",
				token:  world.adminToken,
				body:   []byte(`{"name":"'); DROP TABLE agents;--"}`),
			},
			status: 201,
		},
		{name: "revoked session", req: request{path: pathSession, token: "x.y.z"}, status: 401},
		{name: "raw unknown method", raw: "FOO /api/agent HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", status: -1},
		{name: "raw CONNECT", raw: "CONNECT /api/agent HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", status: -1},
		{name: "raw lowercase method", raw: "get /api/agent HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", status: -1},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var got reply

			if tt.raw != "" {
				got = bndRaw(t, tt.raw)
			} else {
				got = send(t, tt.req)
			}

			if tt.status > 0 && got.status != tt.status {
				t.Errorf("status = %d %q, want %d", got.status, got.body, tt.status)
			}

			if leaks := bndLeaks(got.body); len(leaks) != 0 {
				t.Errorf("body leaks internals %v: %q", leaks, got.body)
			}

			for name, values := range got.header {
				for _, value := range values {
					if leaks := bndLeaks(value); len(leaks) != 0 {
						t.Errorf("header %s leaks internals %v: %q", name, leaks, value)
					}
				}
			}

			// Anything the Worker itself answers is the JSON envelope; a body
			// that is not one means the request never reached the Worker
			// (workerd answered it), which is the only way a stack can appear.
			if got.status < 500 && got.status != http.StatusNoContent && got.body != "" {
				var envelope struct {
					Error *struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}

				err := json.Unmarshal([]byte(got.body), &envelope)
				isEnvelope := err == nil && envelope.Error != nil
				isSuccess := got.status >= 200 && got.status < 300

				if !isEnvelope && !isSuccess && tt.raw == "" {
					t.Errorf("a %d body is not the JSON envelope: %q", got.status, got.body)
				}
			}
		})
	}
}

// TestBndRuntimeErrorPagesAreNotTheWorkers: a request target the runtime itself
// cannot parse (a bad percent escape) is refused inside workers-go before any
// handler runs. It must be a 4xx with no stack trace or file paths in the body,
// not the runtime's error page (which was a 500 carrying both, fixed in the
// workers-go fork).
//
//nolint:paralleltest // shares one database
func TestBndRuntimeErrorPagesAreNotTheWorkers(t *testing.T) {
	reset(t)

	for _, target := range []string{"/api/agent/%zz", "/healthz%zz", "/%zz", "/api/agent/%", "/api/agent/%4"} {
		got := bndRaw(t, "GET "+target+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

		if got.status >= 500 {
			t.Errorf("GET %s = %d, want a 4xx (the client sent a malformed URL)", target, got.status)
		}

		if leaks := bndLeaks(got.body); len(leaks) != 0 {
			t.Errorf("GET %s leaks %v: %q", target, leaks, got.body)
		}
	}
}
