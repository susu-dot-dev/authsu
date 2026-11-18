package invitations_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/invitations"
)

// validCreate is a body POST accepts.
const validCreate = `{"type":"member","numInvites":3,"label":"November workshop"}`

// validUpdate is a body PATCH accepts.
const validUpdate = `{"numInvites":3}`

// routeCase is one invitation route and a request that, from an admin, reaches
// its handler and succeeds.
type routeCase struct {
	name, method, target, body string
	success                    int
}

// allRoutes is the full set of routes. It is the single list the tables below
// range over, so a route added to the package without a row here is caught by
// TestRoutesAreDeclaredAsAdminOnlySessions.
func allRoutes() []routeCase {
	return []routeCase{
		{name: opList, method: http.MethodGet, target: collectionPath, body: "", success: http.StatusOK},
		{name: opCreate, method: http.MethodPost, target: collectionPath, body: validCreate, success: http.StatusCreated},
		{name: opUpdate, method: http.MethodPatch, target: itemPath, body: validUpdate, success: http.StatusOK},
		{name: opRevoke, method: http.MethodDelete, target: itemPath, body: "", success: http.StatusOK},
	}
}

// programmed gives the store answers that make every route succeed.
func programmed(harn *harness) {
	harn.store.updated = storedRow(nil)
	harn.store.applied = true
	harn.store.revoked = storedRow(nil)
}

// TestRoutesAreDeclaredAsAdminOnlySessions pins what the boundary is told about
// each route. It is the permission-confusion table: a route that lost its
// requirement, or was declared public, is a route any member (or anyone) could
// call, and nothing in a handler's own tests would notice.
func TestRoutesAreDeclaredAsAdminOnlySessions(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	routes := invitations.Routes(harn.deps)

	want := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/invitation"},
		{http.MethodPost, "/api/invitation"},
		{http.MethodPatch, "/api/invitation/{id}"},
		{http.MethodDelete, "/api/invitation/{id}"},
	}

	if len(routes) != len(want) {
		t.Fatalf("%d routes declared, want %d", len(routes), len(want))
	}

	if len(allRoutes()) != len(want) {
		t.Fatalf("the behaviour tables cover %d routes, the package declares %d", len(allRoutes()), len(want))
	}

	for i, route := range routes {
		t.Run(want[i].method+" "+want[i].path, func(t *testing.T) {
			t.Parallel()

			wantDeclared(t, route, want[i].method, want[i].path)
		})
	}
}

// wantDeclared checks one route's declaration: where it is, that it needs a
// session and that the requirement is auth.Admin.
func wantDeclared(t *testing.T, route auth.Route, method, path string) {
	t.Helper()

	if route.Method != method || route.Path != path {
		t.Errorf("route = %s %s, want %s %s", route.Method, route.Path, method, path)
	}

	if route.Credential != auth.Session {
		t.Errorf("Credential = %v, want auth.Session", route.Credential)
	}

	// Functions are not comparable, but their code pointer is: this is
	// auth.Admin, and not nil and not some other requirement.
	if route.Require == nil || reflect.ValueOf(route.Require).Pointer() != reflect.ValueOf(auth.Admin).Pointer() {
		t.Error("Require is not auth.Admin")
	}

	if route.MaxBody != invitations.MaxBody || route.Handle == nil {
		t.Errorf("MaxBody = %d (want %d), Handle nil = %t", route.MaxBody, invitations.MaxBody, route.Handle == nil)
	}
}

// TestEveryRouteRequiresAnAdmin runs each route as every kind of caller. Only an
// admin gets through; everyone else is refused before the handler: the store is
// never called, the entropy never read, and a body that would have been refused
// as invalid is not looked at (a member learns nothing about the validation of
// a route they may not use).
func TestEveryRouteRequiresAnAdmin(t *testing.T) {
	t.Parallel()

	actors := []struct {
		name   string
		cookie func(*harness) *http.Cookie
		// status and code are the refusal; code is "" for the caller who is let in.
		status int
		code   string
	}{
		{"no session", func(*harness) *http.Cookie { return nil }, http.StatusUnauthorized, auth.CodeUnauthenticated},
		{"member", (*harness).member, http.StatusForbidden, auth.CodeForbidden},
		{
			"no role", func(h *harness) *http.Cookie { return h.session(adminID, "") },
			http.StatusForbidden, auth.CodeForbidden,
		},
		{
			"role in another case", func(h *harness) *http.Cookie { return h.session(adminID, "Admin") },
			http.StatusForbidden, auth.CodeForbidden,
		},
		{"admin", (*harness).admin, 0, ""},
	}

	for _, route := range allRoutes() {
		for _, actor := range actors {
			t.Run(route.name+"/"+actor.name, func(t *testing.T) {
				t.Parallel()

				harn := newHarness(t)
				programmed(harn)

				rec := harn.do(request{
					method: route.method, target: route.target, body: route.body, cookie: actor.cookie(harn), contentType: "",
				})

				if actor.code == "" {
					if rec.Code != route.success {
						t.Fatalf("admin got %d %s, want %d", rec.Code, rec.Body.String(), route.success)
					}

					if len(harn.store.calls) != 1 {
						t.Errorf("admin made %d store calls, want 1", len(harn.store.calls))
					}

					return
				}

				wantError(t, harn, rec, actor.status, actor.code, actor.code)

				if len(harn.store.calls) != 0 {
					t.Errorf("a refused request reached the store: %v", harn.opsCalled())
				}

				if harn.entropy.taken != 0 || harn.idCalls != 0 || harn.clock.calls != 0 {
					t.Errorf("a refused request ran the handler: entropy %d, ids %d, clock %d",
						harn.entropy.taken, harn.idCalls, harn.clock.calls)
				}
			})
		}
	}
}

// TestAMemberIsRefusedBeforeValidation: a member sending a body that is invalid
// in every way is told 403, the same as with a valid body, so the validation
// rules are not an oracle for someone who may not use the route.
func TestAMemberIsRefusedBeforeValidation(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, method, target, body string }{
		{"create with every field invalid", http.MethodPost, collectionPath,
			`{"type":"first_run","numInvites":0,"label":"` + strings.Repeat("x", 300) + `","expiresAt":1}`},
		{"create that is not JSON", http.MethodPost, collectionPath, garbage},
		{"update with nothing", http.MethodPatch, itemPath, `{}`},
		{"update that is not JSON", http.MethodPatch, itemPath, garbage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			rec := harn.do(request{method: tt.method, target: tt.target, body: tt.body, cookie: harn.member(), contentType: ""})

			wantError(t, harn, rec, http.StatusForbidden, auth.CodeForbidden, auth.CodeForbidden)

			if len(harn.store.calls) != 0 {
				t.Errorf("reached the store: %v", harn.opsCalled())
			}
		})
	}
}

// TestAnItemRouteNeedsAnID: with no id the item path does not exist, and the
// answer is the router's 404, not an invitation's.
func TestAnItemRouteNeedsAnID(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			rec := harn.asAdmin(method, collectionPath+"/", validUpdate)

			wantError(t, harn, rec, http.StatusNotFound, "not_found", "not_found")

			if len(harn.store.calls) != 0 {
				t.Errorf("reached the store: %v", harn.opsCalled())
			}
		})
	}
}

// TestUnknownMethodsAreRefusedWithTheMethodsAPathHas pins which methods each
// path answers, through the boundary's 405 and its Allow header.
func TestUnknownMethodsAreRefusedWithTheMethodsAPathHas(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, method, target, allow string }{
		{"put on the collection", http.MethodPut, collectionPath, "GET, POST"},
		{"delete on the collection", http.MethodDelete, collectionPath, "GET, POST"},
		{"get on an item", http.MethodGet, itemPath, "DELETE, PATCH"},
		{"post on an item", http.MethodPost, itemPath, "DELETE, PATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			rec := harn.do(request{method: tt.method, target: tt.target, body: "", cookie: harn.admin(), contentType: ""})

			wantError(t, harn, rec, http.StatusMethodNotAllowed, "method_not_allowed", "method_not_allowed")

			if got := rec.Header().Get("Allow"); got != tt.allow {
				t.Errorf("Allow = %q, want %q", got, tt.allow)
			}

			if len(harn.store.calls) != 0 {
				t.Errorf("reached the store: %v", harn.opsCalled())
			}
		})
	}
}

// TestRequestsAreRefusedByTheBoundaryBeforeTheStore: the wrong Content-Type on
// an unsafe route and a malformed id never reach the handler.
func TestRequestsAreRefusedByTheBoundaryBeforeTheStore(t *testing.T) {
	t.Parallel()

	// The id is part of the URL the client chooses: every spelling but the
	// canonical lower-case UUID is refused, whatever it would have meant.
	badIDs := map[string]string{
		"upper case":      strings.ToUpper(invID),
		"too short":       "abc",
		"too long":        invID + "0",
		"not hex":         strings.Repeat("g", 36),
		"sql quote":       "%27%20OR%201=1%20--" + strings.Repeat("0", 17),
		"braces":          "{" + invID + "}",
		"trailing space":  invID + "%20",
		"leading space":   "%20" + invID,
		"urn":             "urn:uuid:" + invID,
		"no dashes":       strings.ReplaceAll(invID, "-", ""),
		"dashes misplace": "0000000-00000-7000-8000-0000000000aa",
		"null byte":       "%00" + invID[3:],
	}

	for _, route := range allRoutes()[2:] {
		for name, id := range badIDs {
			t.Run(route.name+"/"+name, func(t *testing.T) {
				t.Parallel()

				harn := newHarness(t)
				programmed(harn)

				rec := harn.asAdmin(route.method, collectionPath+"/"+id, route.body)

				wantError(t, harn, rec, http.StatusBadRequest, "invalid_id", "invalid_id")

				if len(harn.store.calls) != 0 {
					t.Errorf("reached the store: %v", harn.opsCalled())
				}
			})
		}
	}

	for _, route := range allRoutes() {
		t.Run(route.name+"/not json content type", func(t *testing.T) {
			t.Parallel()

			if route.method == http.MethodGet {
				t.Skip("a GET has no body and needs no Content-Type")
			}

			harn := newHarness(t)
			programmed(harn)

			rec := harn.do(request{
				method: route.method, target: route.target, body: route.body, cookie: harn.admin(), contentType: "text/plain",
			})

			wantError(t, harn, rec, http.StatusUnsupportedMediaType, "unsupported_media_type", "unsupported_media_type")

			if len(harn.store.calls) != 0 {
				t.Errorf("reached the store: %v", harn.opsCalled())
			}
		})
	}
}

// TestBodiesAreLimited: a body of MaxBody bytes is read and handled, and one
// byte more is refused with 413 before any parsing or store call. The body at
// the limit is a create whose label is too long, so reaching the handler is
// visible as its 400 and not the boundary's 413.
func TestBodiesAreLimited(t *testing.T) {
	t.Parallel()

	// pad builds a JSON body of exactly size bytes.
	pad := func(size int) string {
		const head, tail = `{"type":"member","numInvites":1,"label":"`, `"}`

		return head + strings.Repeat("a", size-len(head)-len(tail)) + tail
	}

	tests := []struct {
		name, method, target string
		body                 func(size int) string
		atLimit              int
	}{
		{opCreate, http.MethodPost, collectionPath, pad, http.StatusBadRequest},
		{opUpdate, http.MethodPatch, itemPath, func(size int) string {
			return `{"numInvites":1,"x":"` + strings.Repeat("a", size-len(`{"numInvites":1,"x":""}`)) + `"}`
		}, http.StatusBadRequest},
		{opList, http.MethodGet, collectionPath, func(size int) string { return strings.Repeat(" ", size) }, http.StatusOK},
		{opRevoke, http.MethodDelete, itemPath, func(size int) string { return strings.Repeat(" ", size) }, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/at the limit", func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			programmed(harn)

			rec := harn.asAdmin(tt.method, tt.target, tt.body(invitations.MaxBody))
			if rec.Code != tt.atLimit {
				t.Errorf("status = %d, want %d: %s", rec.Code, tt.atLimit, rec.Body.String())
			}
		})

		t.Run(tt.name+"/over the limit", func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			programmed(harn)

			rec := harn.asAdmin(tt.method, tt.target, tt.body(invitations.MaxBody+1))

			wantError(t, harn, rec, http.StatusRequestEntityTooLarge, "body_too_large", "body_too_large")

			if len(harn.store.calls) != 0 || harn.entropy.taken != 0 {
				t.Errorf("an oversized request was handled: %v", harn.opsCalled())
			}
		})
	}
}

// TestRoutesRefuseAMissingDependency: a deployment without a dependency does not
// get an invitation service with a degraded mode, it fails when it is built.
func TestRoutesRefuseAMissingDependency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*invitations.Deps)
	}{
		{"Store", func(d *invitations.Deps) { d.Store = nil }},
		{"Now", func(d *invitations.Deps) { d.Now = nil }},
		{"Entropy", func(d *invitations.Deps) { d.Entropy = nil }},
		{"NewID", func(d *invitations.Deps) { d.NewID = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			deps := newHarness(t).deps
			tt.change(&deps)

			defer func() {
				if recover() == nil {
					t.Error("Routes did not panic")
				}
			}()

			invitations.Routes(deps)
		})
	}
}
