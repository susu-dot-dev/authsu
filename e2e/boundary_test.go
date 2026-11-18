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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
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
// invitations,users} and internal/app/app.go (/healthz). The caps are the
// production constants (MaxBeginBody, MaxFinishBody, invitations.MaxBody, the
// users maxBody) and httpapi.DefaultMaxBody for a route that declares none.
func bndRoutes() []bndRoute {
	return slices.Concat(bndPublicRoutes(), bndSessionInventory(), bndAdminInventory())
}

// bndPublicRoutes are the routes that need no credential.
func bndPublicRoutes() []bndRoute {
	const regBegin = `{"invitationCode":"x","name":"n"}`

	return []bndRoute{
		bndRouteOf("healthz", http.MethodGet, "/healthz", bndPublic, bndDefaultMB, "", ""),
		bndRouteOf("first-run", http.MethodGet, "/api/first-run", bndPublic, bndDefaultMB, "", ""),
		bndRouteOf("register begin", http.MethodPost, "/api/register/begin", bndPublic, 4*bndKiB, regBegin, "users"),
		bndRouteOf("register finish", http.MethodPost, "/api/register/finish", bndPublic, 32*bndKiB, `{}`, "users"),
		bndRouteOf("login begin", http.MethodPost, "/api/login/begin", bndPublic, bndKiB, `{}`, ""),
		bndRouteOf("login finish", http.MethodPost, "/api/login/finish", bndPublic, 16*bndKiB, `{}`, "japikeys"),
	}
}

// bndSessionInventory are the routes any signed-in caller may use.
func bndSessionInventory() []bndRoute {
	const (
		item     = "/api/agent/" + bndIDToken
		revoked  = "japikeys WHERE revoked_at IS NOT NULL"
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
			"invitations WHERE revoked_at IS NOT NULL"),
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
	// agent is an agent of the admin, invitation an invitation row, user the member's id.
	agentID      string
	invitationID string
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

	seedInvitation(t, idInvitationA, 3)
	seedAgent(t, idAgentA, admin.userID, "seeded")

	return bndWorld{
		admin: admin, adminToken: adminToken, member: member, memberToken: memberToken,
		agentID: idAgentA, invitationID: idInvitationA,
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

	seed(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) "+
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

	parts := make([]string, 0, len(tables())+6)

	for _, table := range tables() {
		parts = append(parts, table+"="+count(t, table))
	}

	// Cell values that a write to an existing row would change.
	parts = append(parts,
		"revoked_keys="+count(t, "japikeys WHERE revoked_at IS NOT NULL"),
		"revoked_agents="+count(t, "agents WHERE revoked_at IS NOT NULL"),
		"revoked_users="+count(t, "users WHERE revoked_at IS NOT NULL"),
		"revoked_invitations="+count(t, "invitations WHERE revoked_at IS NOT NULL"),
		"agent_names="+scalar(t, "SELECT group_concat(name) FROM (SELECT name FROM agents ORDER BY id)"),
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

		if len(seen) != 20 {
			t.Errorf("inventory has %d routes, want the 20 the product declares", len(seen))
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
		{"keys jwks does not exist", "/keys/.well-known/jwks.json"},
		{"well-known", "/.well-known/jwks.json"},
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
	expectCount(t, "japikeys WHERE revoked_at IS NOT NULL", "0")
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

// bndBigRequest sends a very large body to route and returns the status, body
// and the transport error, if the connection was cut before a response arrived.
func bndBigRequest(t *testing.T, route bndRoute, data []byte) (int, string, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(),
		route.method,
		target.baseURL+route.path(idMissing),
		bytes.NewReader(data),
	)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	if route.unsafe() {
		req.Header.Set("Content-Type", jsonType)
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
// even with a malformed id), and far over the cap (10 MiB) is also 413 quickly
// rather than being buffered. Declared caps are the production constants.
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

	t.Run("far over the cap is 413 and quick", func(t *testing.T) {
		huge := bytes.Repeat([]byte("a"), 10<<20)

		for _, route := range bndRoutes() {
			start := time.Now()
			status, body, err := bndBigRequest(t, route, huge)
			elapsed := time.Since(start)

			// The Worker answers as soon as the cap is exceeded and does not read
			// the rest, so a client still writing may see the connection closed
			// instead of the response. That is an early refusal too, never a
			// buffered read; what is not acceptable is any other status.
			if err == nil && (status != http.StatusRequestEntityTooLarge || body != bndErrTooLarge) {
				t.Errorf("%s with 10 MiB = %d %q, want 413", route.name, status, body)
			}

			if elapsed > 5*time.Second {
				t.Errorf("%s with 10 MiB took %s: the body must not be buffered to the end", route.name, elapsed)
			}
		}
	})

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

// TestBndChunkedBodies sends bodies with no Content-Length (chunked): the cap is
// enforced on bytes read, not on a declared length, so an unknown-length body
// of cap+1 is refused as one with a length is, and one of exactly the cap is
// read. Raw requests are used because net/http's client would pick its own
// framing.
//
//nolint:paralleltest // shares one database
func TestBndChunkedBodies(t *testing.T) {
	reset(t)

	chunked := func(path string, parts ...int) string {
		var b strings.Builder

		b.WriteString("POST " + path + " HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n" +
			"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")

		for _, n := range parts {
			fmt.Fprintf(&b, "%x\r\n%s\r\n", n, strings.Repeat(" ", n))
		}

		b.WriteString("0\r\n\r\n")

		return b.String()
	}

	tests := []struct {
		name  string
		path  string
		parts []int
		want  int
	}{
		{"login begin at cap, one chunk", "/api/login/begin", []int{1024}, http.StatusOK},
		{"login begin at cap, many chunks", "/api/login/begin", []int{1, 1, 1022}, http.StatusOK},
		{"login begin cap+1, one chunk", "/api/login/begin", []int{1025}, http.StatusRequestEntityTooLarge},
		{"login begin cap+1, split", "/api/login/begin", []int{1024, 1}, http.StatusRequestEntityTooLarge},
		{"login begin cap+1, tiny chunks", "/api/login/begin", bndRepeat(1, 1025), http.StatusRequestEntityTooLarge},
		{"login begin empty chunked", "/api/login/begin", nil, http.StatusOK},
		{"register begin cap+1", "/api/register/begin", []int{4*bndKiB + 1}, http.StatusRequestEntityTooLarge},
		{"register finish cap+1", "/api/register/finish", []int{32*bndKiB + 1}, http.StatusRequestEntityTooLarge},
		{"login finish cap+1", "/api/login/finish", []int{16*bndKiB + 1}, http.StatusRequestEntityTooLarge},
		{"invitation cap+1 before auth", "/api/invitation", []int{4*bndKiB + 1}, http.StatusRequestEntityTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bndRaw(t, chunked(tt.path, tt.parts...))
			if got.status != tt.want {
				t.Errorf("status = %d %q, want %d", got.status, got.body, tt.want)
			}

			if tt.want == http.StatusRequestEntityTooLarge && got.body != bndErrTooLarge {
				t.Errorf("body = %q, want %q", got.body, bndErrTooLarge)
			}
		})
	}
}

// bndRepeat returns n copies of v.
func bndRepeat(v, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}

	return out
}

// TestBndContentLengthLies: a declared Content-Length larger than the cap is
// refused before the body is read, and one that is not a number is refused by
// the runtime with a 4xx and never reaches a handler.
//
//nolint:paralleltest // shares one database
func TestBndContentLengthLies(t *testing.T) {
	reset(t)

	t.Run("declared over the cap with the real body over too", func(t *testing.T) {
		got := send(t, request{method: http.MethodPost, path: "/api/login/begin", body: bndBodyOfLen(1025)})
		got.expect(t, "login begin 1025", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
	})

	t.Run("negative content length is refused", func(t *testing.T) {
		got := bndRaw(
			t,
			"POST /api/login/begin HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"+
				"Content-Length: -1\r\nConnection: close\r\n\r\nabc",
		)
		if got.status < 400 || got.status > 499 {
			t.Errorf("status = %d %q, want a 4xx", got.status, got.body)
		}
	})
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
					got := send(t, request{method: route.method, path: path, token: credential.token, body: bndBodyOf(route)})

					// An encoded slash or a dot-only segment changes the path
					// the mux routes (see TestBndUnknownPathsAreNotFound and
					// TestBndPathCleaningBehaviour), so those are 404 or the
					// cleaned route; everything else is an id the boundary refuses.
					status, code := want(route, credential.token)

					if bndChangesRouting(bad.segment) {
						if got.status == status && got.errorCode() == code {
							return
						}

						if got.status != http.StatusNotFound {
							t.Errorf("%s = %d %s, want %d %s or 404", path, got.status, got.body, status, code)
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
			path := strings.ReplaceAll(route.pattern, bndIDToken, "")
			got := send(t, request{method: route.method, path: path, token: world.adminToken, body: bndBodyOf(route)})
			got.expect(t, route.method+" "+path, http.StatusNotFound, codeNotFound)
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

	for _, route := range bndIDRoutes() {
		t.Run(route.name+"/anonymous", func(t *testing.T) {
			live := send(t, request{method: route.method, path: route.path(existing[route.pattern]), body: bndBodyOf(route)})
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
						path:   route.path(existing[route.pattern]),
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

// bndForge builds a JWT-shaped token with the given header and claims, signed
// with key (ES256) or left unsigned/HMAC-signed as the case needs.
type bndForge struct {
	header map[string]any
	claims map[string]any
	// sign is how the signature is made: nil for "", otherwise the function.
	sign func(signingInput string) []byte
}

func (f bndForge) token(t *testing.T) string {
	t.Helper()

	head := b64(mustJSON(t, f.header))
	body := b64(mustJSON(t, f.claims))
	signingInput := head + "." + body

	sig := ""
	if f.sign != nil {
		sig = b64(f.sign(signingInput))
	}

	return signingInput + "." + sig
}

// bndES256 signs signingInput with key as an ES256 JWS (r || s, 32 bytes each).
func bndES256(key *ecdsa.PrivateKey) func(string) []byte {
	return func(signingInput string) []byte {
		digest := sha256.Sum256([]byte(signingInput))

		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			panic(err)
		}

		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])

		return out
	}
}

// bndHS256 signs signingInput with an HMAC-SHA256 under secret.
func bndHS256(secret []byte) func(string) []byte {
	return func(signingInput string) []byte {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(signingInput))

		return mac.Sum(nil)
	}
}

// bndSessionClaims is the claim set of a genuine session token for the given
// kid and user, as the Worker would issue it (iss is "<api origin>/keys/<kid>").
func bndSessionClaims(kid, user string, exp time.Time) map[string]any {
	now := time.Now()

	return map[string]any{
		"aud": "authsu/session", "exp": exp.Unix(), "iat": now.Unix(),
		"iss": target.apiOrigin + "/keys/" + kid, "sub": user, "ver": 2,
	}
}

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

// bndForger builds forged session tokens for one genuine session: it knows the
// session's kid and claims, and a key the Worker has never stored, so every
// token it makes is refused for what it is and the one thing that differs from
// a well-formed token is the thing under test.
type bndForger struct {
	t      *testing.T
	kid    string
	claims map[string]any
	other  *ecdsa.PrivateKey
}

// token returns a token with header (nil = a well-formed ES256 header for the
// session's kid), the claims mutated by mutate, signed by sign (nil = by the
// stored-nowhere key).
func (f bndForger) token(header map[string]any, mutate func(map[string]any), sign func(string) []byte) string {
	f.t.Helper()

	if header == nil {
		header = map[string]any{"alg": "ES256", "kid": f.kid, "typ": "JWT"}
	}

	c := map[string]any{}
	maps.Copy(c, f.claims)

	if mutate != nil {
		mutate(c)
	}

	return bndForge{header: header, claims: c, sign: sign}.token(f.t)
}

// signed is token signed by the key the Worker does not know.
func (f bndForger) signed(header map[string]any, mutate func(map[string]any)) string {
	f.t.Helper()

	return f.token(header, mutate, bndES256(f.other))
}

// hdr is a JWT header for kid with alg and extra members.
func (f bndForger) hdr(alg string, extra map[string]any) map[string]any {
	h := map[string]any{"alg": alg, "kid": f.kid, "typ": "JWT"}
	maps.Copy(h, extra)

	return h
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
// key token: genuine, correctly signed, right issuer and subject, but the
// audience of an API key.
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

// bndAuthCases builds every credential shape the authentication boundary must
// refuse with the one opaque 401, for a world with a live admin session.
func bndAuthCases(t *testing.T, world bndWorld) []bndCookieCase {
	t.Helper()

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	token := world.adminToken
	forger := bndForger{t: t, kid: kidOf(t, token), claims: claimsOf(t, token), other: other}
	apiKey := bndAgentKey(t, token)

	cases := bndMalformedTokenCases(t, token, forger)
	cases = append(cases, bndForgedTokenCases(t, world, forger)...)
	cases = append(cases, bndCookieShapeCases(token, apiKey)...)
	cases = append(cases, bndHeaderCredentialCases(token, apiKey)...)
	cases = append(cases, bndOversizedCookieCases(token)...)

	return cases
}

// bndMalformedTokenCases are tokens that are damaged versions of the genuine one.
func bndMalformedTokenCases(t *testing.T, token string, f bndForger) []bndCookieCase {
	t.Helper()

	const cookie = cookieName + "="

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}

	withRole := b64(mustJSON(t, withClaim(f.claims, "role", "admin")))

	return []bndCookieCase{
		{name: "no cookie header"},
		bndOneCookie("empty cookie value", cookie),
		bndOneCookie("cookie with only whitespace", cookie+" "),
		bndOneCookie("garbage", cookie+"garbage"),
		bndOneCookie("garbage with dots", cookie+"a.b.c"),
		bndOneCookie("three empty segments", cookie+".."),
		bndOneCookie("one dot", cookie+"."),
		bndOneCookie("token with a fourth segment", cookie+token+".x"),
		bndOneCookie("token header only", cookie+parts[0]),
		bndOneCookie("token without signature", cookie+parts[0]+"."+parts[1]+"."),
		bndOneCookie("truncated by one char", cookie+token[:len(token)-1]),
		bndOneCookie("truncated to half", cookie+token[:len(token)/2]),
		bndOneCookie("extended by one char", cookie+token+"A"),
		bndOneCookie("signature flipped", cookie+parts[0]+"."+parts[1]+"."+bndFlip(parts[2], 5)),
		bndOneCookie("signature last char flipped", cookie+parts[0]+"."+parts[1]+"."+bndFlip(parts[2], len(parts[2])-1)),
		bndOneCookie("signature replaced by zeros", cookie+parts[0]+"."+parts[1]+"."+b64(make([]byte, 64))),
		bndOneCookie("payload altered", cookie+parts[0]+"."+bndFlip(parts[1], 7)+"."+parts[2]),
		bndOneCookie("header altered", cookie+bndFlip(parts[0], 3)+"."+parts[1]+"."+parts[2]),
		bndOneCookie("role claim added to payload", cookie+parts[0]+"."+withRole+"."+parts[2]),
	}
}

// bndForgedTokenCases are well-formed tokens that are wrong in one respect.
func bndForgedTokenCases(t *testing.T, world bndWorld, f bndForger) []bndCookieCase {
	t.Helper()

	const cookie = cookieName + "="

	claim := func(k string, v any) func(map[string]any) { return func(c map[string]any) { c[k] = v } }
	drop := func(k string) func(map[string]any) { return func(c map[string]any) { delete(c, k) } }
	exp := time.Now().Add(time.Hour)
	jwk := scalar(t, "SELECT jwk FROM japikeys WHERE kid = ?", f.kid)
	other := func(kid string) map[string]any { return map[string]any{"alg": "ES256", "kid": kid, "typ": "JWT"} }

	return []bndCookieCase{
		bndOneCookie("alg none, no signature", cookie+f.token(f.hdr("none", nil), nil, nil)),
		bndOneCookie("alg None capitalised", cookie+f.token(f.hdr("None", nil), nil, nil)),
		bndOneCookie(
			"alg none with a signature",
			cookie+f.token(f.hdr("none", nil), nil, func(string) []byte { return []byte("x") }),
		),
		bndOneCookie(
			"HS256 under the HMAC secret",
			cookie+f.token(f.hdr("HS256", nil), nil, bndHS256([]byte(authHMACSecret))),
		),
		bndOneCookie("HS256 under the public JWK bytes", cookie+f.token(f.hdr("HS256", nil), nil, bndHS256([]byte(jwk)))),
		bndOneCookie("RS256 header, ES256 signature", cookie+f.signed(f.hdr("RS256", nil), nil)),
		bndOneCookie("ES256 by another key, same kid", cookie+f.signed(nil, nil)),
		bndOneCookie(
			"ES256 by another key, new kid and issuer",
			cookie+f.signed(other(idMissing), claim("iss", target.apiOrigin+"/keys/"+idMissing)),
		),
		bndOneCookie("kid that does not exist, claims genuine", cookie+f.signed(other(idMissing), nil)),
		bndOneCookie("kid not a uuid", cookie+f.signed(other("not-a-uuid"), nil)),
		bndOneCookie("kid missing", cookie+f.signed(map[string]any{"alg": "ES256", "typ": "JWT"}, nil)),
		bndOneCookie("kid is a number", cookie+f.signed(map[string]any{"alg": "ES256", "kid": 7, "typ": "JWT"}, nil)),
		bndOneCookie(
			"jwk embedded in header",
			cookie+f.signed(f.hdr("ES256", map[string]any{"jwk": map[string]any{"kty": "EC"}}), nil),
		),
		bndOneCookie("jku header", cookie+f.signed(f.hdr("ES256", map[string]any{"jku": "https://evil.example/jwks"}), nil)),
		bndOneCookie("wrong audience, forged", cookie+f.signed(nil, claim("aud", "authsu/api_key"))),
		bndOneCookie("audience missing, forged", cookie+f.signed(nil, drop("aud"))),
		bndOneCookie(
			"audience list, forged",
			cookie+f.signed(nil, claim("aud", []string{"authsu/session", "authsu/api_key"})),
		),
		bndOneCookie("wrong issuer, forged", cookie+f.signed(nil, claim("iss", "https://evil.example/keys/"+f.kid))),
		bndOneCookie("expired, forged", cookie+f.signed(nil, claim("exp", time.Now().Add(-time.Hour).Unix()))),
		bndOneCookie("exp missing, forged", cookie+f.signed(nil, drop("exp"))),
		bndOneCookie("exp as string, forged", cookie+f.signed(nil, claim("exp", "9999999999"))),
		bndOneCookie("exp far future, forged", cookie+f.signed(nil, claim("exp", exp.Add(100*365*24*time.Hour).Unix()))),
		bndOneCookie("exp 2^53+1, forged", cookie+f.signed(nil, claim("exp", json.Number("9007199254740993")))),
		bndOneCookie("nbf in the future, forged", cookie+f.signed(nil, claim("nbf", exp.Unix()))),
		bndOneCookie("subject is another user, forged", cookie+f.signed(nil, claim("sub", world.member.userID))),
		bndOneCookie("subject is empty, forged", cookie+f.signed(nil, claim("sub", ""))),
		bndOneCookie("subject is not a string, forged", cookie+f.signed(nil, claim("sub", 1))),
		bndOneCookie("ver unsupported, forged", cookie+f.signed(nil, claim("ver", 99))),
		bndOneCookie("genuine claims, own key, never stored", cookie+bndForge{
			header: f.hdr(
				"ES256",
				nil,
			), claims: bndSessionClaims(idN("0f00", 1), world.admin.userID, exp), sign: bndES256(f.other),
		}.token(t)),
	}
}

// bndCookieShapeCases are ways of presenting a token (genuine or an API key)
// in cookies that must not authenticate: duplicates, other names, other casing.
func bndCookieShapeCases(token, apiKey string) []bndCookieCase {
	const cookie = cookieName + "="

	lines := func(name string, l ...string) bndCookieCase { return bndCookieCase{name: name, lines: l} }

	return []bndCookieCase{
		bndOneCookie("agent API key as the session cookie", cookie+apiKey),
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

// bndHeaderCredentialCases present a genuine session or API key anywhere but
// the session cookie: none of them authenticates.
func bndHeaderCredentialCases(token, apiKey string) []bndCookieCase {
	header := func(name string, h ...string) bndCookieCase { return bndCookieCase{name: name, headers: h} }

	return []bndCookieCase{
		header("Authorization bearer only", "Authorization: Bearer "+token),
		header("Authorization bearer lower case scheme", "Authorization: bearer "+token),
		header("Authorization basic", "Authorization: Basic "+b64([]byte("a:"+token))),
		header("Authorization raw token", "Authorization: "+token),
		header("bearer in a custom header", "X-Session: "+token, "X-Auth-Token: "+token),
		header("token in a forwarded url", "X-Original-Url: /?"+cookieName+"="+token),
		// A genuine API key as a bearer is a credential now and is not a case
		// here (see TestBndCredentialConfusion). Both carriers at once are not:
		// the request is ambiguous, whichever is valid.
		header("a session cookie and an agent key as a bearer", "Cookie: "+cookieName+"="+token,
			"Authorization: Bearer "+apiKey),
		header("a session as a bearer and the agent key beside it",
			"Authorization: Bearer "+token, "Authorization: Bearer "+apiKey),
	}
}

// bndOversizedCookieCases are cookies around and above input.MaxTokenBytes
// (4096): a value over the bound is refused by the parser before any
// verification, as the one opaque 401, never a 5xx.
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

// withClaim returns a copy of claims with k=v.
func withClaim(claims map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	maps.Copy(out, claims)

	out[k] = v

	return out
}

// TestBndAuthenticationMatrix: every session route against every credential
// that must NOT authenticate. All of them are the same opaque 401
// unauthenticated, with byte-identical bodies across causes (no oracle for
// which check failed), no Set-Cookie, nothing written, and never a 5xx. The
// cases run through the real wasm's cookie parsing, JWT verification and the
// real D1 lookup.
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
// invalid. Each returns the SQL that does it to the session of token's kid.
func bndStateBreaks() []struct {
	name string
	sql  string
} {
	return []struct {
		name string
		sql  string
	}{
		{"revoked", "UPDATE japikeys SET revoked_at = strftime('%s','now') - 1 WHERE kid = '{KID}'"},
		{"revoked at this second", "UPDATE japikeys SET revoked_at = strftime('%s','now') WHERE kid = '{KID}'"},
		{"expired in the database", "UPDATE japikeys SET expires_at = strftime('%s','now') - 1 WHERE kid = '{KID}'"},
		{"expires exactly now", "UPDATE japikeys SET expires_at = strftime('%s','now') WHERE kid = '{KID}'"},
		{"key row deleted", "DELETE FROM japikeys WHERE kid = '{KID}'"},
		{
			"its passkey deleted",
			"DELETE FROM credentials WHERE id = (SELECT credential_id FROM japikeys WHERE kid = '{KID}')",
		},
		{
			"user revoked",
			"UPDATE users SET revoked_at = strftime('%s','now') - 1 " +
				"WHERE id = (SELECT user_id FROM japikeys WHERE kid = '{KID}')",
		},
		{"key kind changed to api_key", "UPDATE japikeys SET kind = 'api_key' WHERE kid = '{KID}'"},
		{
			"key belongs to another user",
			"UPDATE japikeys SET user_id = (SELECT id FROM users WHERE id <> " +
				"(SELECT user_id FROM japikeys WHERE kid = '{KID}') LIMIT 1) WHERE kid = '{KID}'",
		},
		{
			"stored jwk replaced by another key",
			"UPDATE japikeys SET jwk = (SELECT jwk FROM japikeys WHERE kid <> '{KID}' LIMIT 1) WHERE kid = '{KID}'",
		},
	}
}

// TestBndStoredSessionStateMatrix: a session whose stored key row says it is no
// longer usable is the same opaque 401 on every session route, whatever the
// reason, with an unchanged body, and the failure is never a 5xx. (A broken
// stored jwk is the one case that is an outage and not a sign-out; it is
// asserted separately below.) Each case uses a fresh world: they destroy rows.
//
//nolint:paralleltest // shares one database
func TestBndStoredSessionStateMatrix(t *testing.T) {
	for _, stateBreak := range bndStateBreaks() {
		t.Run(stateBreak.name, func(t *testing.T) {
			world := bndNewWorld(t)
			// A second live session of another user, so "another user" and
			// "another key's jwk" have a row to point at.
			victim := login(t, world.member)

			// Sanity: before the break every session route accepts the token.
			get(t, pathSession, world.adminToken).expect(t, "before", http.StatusOK, "")

			kid := kidOf(t, world.adminToken)
			seed(t, strings.ReplaceAll(stateBreak.sql, "{KID}", kid))

			brokenJWK := stateBreak.name == "stored jwk replaced by another key"

			for _, route := range bndSessionRoutes() {
				got := send(
					t,
					request{method: route.method, path: route.path(idMissing), token: world.adminToken, body: bndBodyOf(route)},
				)

				if brokenJWK {
					// japikey cannot find the key id in a document that names another:
					// that is the store being wrong, an outage (503), never a 401 and never a 5xx
					// other than the declared unavailable code.
					if got.status != http.StatusServiceUnavailable || got.errorCode() != "session_verify_failed" {
						t.Errorf("%s with a corrupt stored jwk = %d %q, want 503 session_verify_failed", route.name, got.status, got.body)
					}

					continue
				}

				if got.status != http.StatusUnauthorized || got.body != bndErrUnauth {
					t.Errorf("%s after %q = %d %q, want the opaque 401", route.name, stateBreak.name, got.status, got.body)
				}
			}

			// The other user's session is untouched by this user's breakage.
			if stateBreak.name != "user revoked" && stateBreak.name != "key belongs to another user" {
				get(t, pathSession, victim).expect(t, "the other session", http.StatusOK, "")
			}
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
				id := world.agentID

				switch {
				case strings.HasPrefix(route.pattern, "/api/invitation"):
					id = world.invitationID
				case strings.HasPrefix(route.pattern, "/api/user"):
					id = world.member.userID
				}

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
// next case in the matrix starts from the same world: the admin's session key
// (a logout revokes it), the agent, the invitation, and the member.
func bndRestore(t *testing.T, world bndWorld) {
	t.Helper()

	seed(
		t,
		"UPDATE japikeys SET revoked_at = NULL WHERE kid IN (?, ?)",
		kidOf(t, world.adminToken),
		kidOf(t, world.memberToken),
	)
	seed(t, "UPDATE agents SET revoked_at = NULL, name = 'seeded' WHERE id = ?", world.agentID)
	seed(t, "DELETE FROM agents WHERE id <> ?", world.agentID)
	seed(t, "UPDATE invitations SET revoked_at = NULL, num_invites = 3 WHERE id = ?", world.invitationID)
	seed(t, "DELETE FROM invitations WHERE id <> ? AND type <> 'first_run'", world.invitationID)
	seed(t, "UPDATE users SET revoked_at = NULL WHERE id IN (?, ?)", world.admin.userID, world.member.userID)
}

// bndSeedExtraAccount seeds another account with the role and a passkey.
func bndSeedExtraAccount(t *testing.T, n int, role string) passkey {
	t.Helper()

	priv := newKey(t)
	credID := randomBytes(32)
	handle := randomBytes(16)
	userID := idN("0b00", 100+n)

	cose := coseES256(t, priv.X.FillBytes(make([]byte, 32)), priv.Y.FillBytes(make([]byte, 32)))

	seed(t, "INSERT INTO users (id, user_handle, role, invitation_id, created_at) "+
		"VALUES (?, ?, ?, (SELECT id FROM invitations LIMIT 1), strftime('%s','now'))", userID, handle, role)
	seed(t, "INSERT INTO credentials (id, user_id, credential_id, public_key, flags, metadata, created_at) "+
		"VALUES (?, ?, ?, ?, 5, '{}', strftime('%s','now'))", idN("0c00", 100+n), userID, credID, cose)

	return passkey{priv: priv, credID: credID, handle: handle, userID: userID}
}

// TestBndRoleChangeTakesEffectOnTheNextRequest: the role is read from the
// account on every request and is not a claim in the token, so demoting an
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

// TestBndCredentialConfusion: tokens that are genuine, correctly signed and
// stored, but not a session for this caller, do not authenticate: another
// user's session does not act as the owner, an agent API key (a different
// audience and kind) is not a session whatever route it is presented to, and
// a session is not an API key. (Matrix of the audience confusion in
// TestBndAuthenticationMatrix, here with every unsafe route and a write check.)
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

	// The key is a real row of kind api_key for the admin; it must not verify
	// as a session even though the user is an admin and the signature is good.
	expectCount(t, "japikeys WHERE kind = 'api_key' AND kid = '"+parsed.Key.ID+"'", "1")

	routes := bndSessionRoutes()

	for _, route := range routes {
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
			own := bndAgentKey(t, world.adminToken)

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

	expectCount(t, "japikeys WHERE kid = '"+kidOf(t, world.adminToken)+"' AND revoked_at <= strftime('%s','now')", "1")

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
	expires := scalar(t, "SELECT expires_at FROM japikeys WHERE kid = ?", kidOf(t, world.adminToken))

	for _, path := range []string{"/api/refresh", "/api/session/refresh", "/api/token", "/api/sessions", "/api/me"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			got := send(t, request{method: method, path: path, token: world.adminToken})
			got.expect(t, method+" "+path, http.StatusNotFound, codeNotFound)
		}
	}

	if after := scalar(t, "SELECT expires_at FROM japikeys WHERE kid = ?", kidOf(t, world.adminToken)); after != expires {
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
		regexp.MustCompile(`(?i)\bjapikeys\b|\bcredentials\b|\binvitations\b`),
		regexp.MustCompile(`\.go:\d+`),
		regexp.MustCompile(`/home/|/usr/|/tmp/|node_modules|file://`),
		regexp.MustCompile(`goroutine|panic:|runtime\.|syscall/js|wasm_exec|at .*\(.*:\d+:\d+\)`),
		regexp.MustCompile(`(?i)stack`),
		regexp.MustCompile(`AUTH_HMAC_SECRET|FIRST_RUN_SECRET|` +
			regexp.QuoteMeta(authHMACSecret) + `|` + regexp.QuoteMeta(firstRunSecret)),
	}
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
				body:   []byte(`{"invitationCode":"` + strings.Repeat("A", 43) + `","name":"n"}`),
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

// ---- exercised helpers kept honest -------------------------------------------

var (
	_ = base64.StdEncoding
	_ = elliptic.P256
)
