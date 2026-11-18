//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package users_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestAccess is who may call each route: credential × role × route. Only an
// administrator with a live session reaches the store; everyone else is refused
// at the boundary, and the store is not called at all.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestAccess(t *testing.T) {
	t.Parallel()

	actors := []struct {
		name string
		// cookies builds the cookies the request carries.
		cookies func(*rig) []*http.Cookie
		status  int
		body    string
		logged  string
	}{
		{
			name:    "an administrator",
			cookies: func(rg *rig) []*http.Cookie { return []*http.Cookie{rg.signIn(adminID, roleAdmin)} },
			status:  http.StatusOK, body: "", logged: "",
		},
		{
			name:    "no cookie",
			cookies: func(*rig) []*http.Cookie { return nil },
			status:  http.StatusUnauthorized, body: bodyUnauthenticated, logged: "unauthenticated",
		},
		{
			name: "an empty session cookie",
			cookies: func(*rig) []*http.Cookie {
				return []*http.Cookie{sessionCookie("")}
			},
			status: http.StatusUnauthorized, body: bodyUnauthenticated, logged: "unauthenticated",
		},
		{
			name: "a cookie that is not a token",
			cookies: func(*rig) []*http.Cookie {
				return []*http.Cookie{sessionCookie("not-a-token")}
			},
			status: http.StatusUnauthorized, body: bodyUnauthenticated, logged: "unauthenticated",
		},
		{
			name: "a valid session beside a second session cookie",
			cookies: func(rg *rig) []*http.Cookie {
				good := rg.signIn(adminID, roleAdmin)

				return []*http.Cookie{good, sessionCookie("x")}
			},
			status: http.StatusUnauthorized, body: bodyUnauthenticated, logged: "unauthenticated",
		},
		{
			name: "a session the store no longer finds (revoked, expired or its account revoked)",
			cookies: func(rg *rig) []*http.Cookie {
				cookie := rg.signIn(adminID, roleAdmin)
				clear(rg.keys.rows)

				return []*http.Cookie{cookie}
			},
			status: http.StatusUnauthorized, body: bodyUnauthenticated, logged: "unauthenticated",
		},
		{
			name: "the key store is unavailable",
			cookies: func(rg *rig) []*http.Cookie {
				cookie := rg.signIn(adminID, roleAdmin)
				rg.keys.err = errDB

				return []*http.Cookie{cookie}
			},
			status: http.StatusServiceUnavailable, body: bodyUnavailableSession, logged: "session_verify_failed",
		},
		{
			name:    "a member",
			cookies: func(rg *rig) []*http.Cookie { return []*http.Cookie{rg.signIn(targetID, roleMember)} },
			status:  http.StatusForbidden, body: bodyForbidden, logged: "forbidden",
		},
		{
			name:    "an account with no role",
			cookies: func(rg *rig) []*http.Cookie { return []*http.Cookie{rg.signIn(targetID, "")} },
			status:  http.StatusForbidden, body: bodyForbidden, logged: "forbidden",
		},
		{
			name:    "an account whose role differs only in case",
			cookies: func(rg *rig) []*http.Cookie { return []*http.Cookie{rg.signIn(targetID, "Admin")} },
			status:  http.StatusForbidden, body: bodyForbidden, logged: "forbidden",
		},
	}

	for _, rt := range routes() {
		for _, actor := range actors {
			t.Run(rt.name+"/"+actor.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.store.got, rg.store.revoked = userRow(targetID), userRow(targetID)
				rg.store.revoked.RevokedAt = new(int64(1))

				rec := rg.do(request{method: rt.method, target: rt.target, body: "", contentType: "", cookies: actor.cookies(rg)})

				if actor.status == http.StatusOK {
					if rec.Code != http.StatusOK || len(rg.logged) != 0 {
						t.Errorf("response = %d %q, logged %v", rec.Code, rec.Body.String(), rg.logged)
					}

					wantCalls(t, rg.store.calls, []storeCall{expectedCall(rt, rg)})

					return
				}

				wantResponse(t, rg, rec, actor.status, actor.body, actor.logged)
				wantCalls(t, rg.store.calls, nil)
			})
		}
	}
}

// expectedCall is the one call a route makes for an administrator: a revocation
// carries the admin role and the clock, a read neither.
func expectedCall(rt route, rg *rig) storeCall {
	switch rt.op {
	case opList:
		return readCall(opList, "")
	case opGet:
		return readCall(opGet, targetID)
	default:
		return storeCall{op: opRevoke, id: targetID, role: roleAdmin, now: rg.now}
	}
}

// TestRoleIsReadOnEveryRequest: the same session, whose account loses its role
// between two requests, is an administrator on the first and a member on the
// second, because the role comes from the account's row and not the token.
func TestRoleIsReadOnEveryRequest(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	cookie := rg.signIn(adminID, roleAdmin)

	send := func() int { return rg.as(cookie, http.MethodGet, collection).Code }

	if got := send(); got != http.StatusOK {
		t.Fatalf("as an administrator = %d, want 200", got)
	}

	for kid, row := range rg.keys.rows {
		row.Role = roleMember
		rg.keys.rows[kid] = row
	}

	if got := send(); got != http.StatusForbidden {
		t.Errorf("after losing the role = %d, want 403", got)
	}

	wantCalls(t, rg.store.calls, []storeCall{readCall(opList, "")})
}

// TestInvalidIDs: an id that is not a canonical lower-case UUID is refused
// before anything else, whoever asks: the boundary parses path ids first, so
// the answer is 400 even without a session, and the store is never called.
func TestInvalidIDs(t *testing.T) {
	t.Parallel()

	ids := map[string]string{
		"not an id":            "abc",
		"upper case":           strings.ToUpper(targetID),
		"one upper-case digit": "01890000-0000-7000-8000-0000000000AA",
		"not hex":              strings.Repeat("g", 36),
		"one char short":       targetID[:35],
		"one char long":        targetID + "0",
		"dashes misplaced":     "0189000-00000-7000-8000-0000000000aa",
		"no dashes":            strings.ReplaceAll(targetID, "-", ""),
		"leading space":        " " + targetID,
		"trailing space":       targetID + " ",
		"wrapped in braces":    "{" + targetID + "}",
		"a urn prefix":         "urn:uuid:" + targetID,
		"full-width digits":    strings.ReplaceAll(targetID, "0", "０"),
		"a NUL":                targetID[:35] + "\x00",
		"SQL":                  "' OR '1'='1",
	}

	actors := []struct {
		name    string
		cookies func(*rig) []*http.Cookie
	}{
		{name: "administrator", cookies: func(rg *rig) []*http.Cookie {
			return []*http.Cookie{rg.signIn(adminID, roleAdmin)}
		}},
		{name: "member", cookies: func(rg *rig) []*http.Cookie {
			return []*http.Cookie{rg.signIn(targetID, roleMember)}
		}},
		{name: "no session", cookies: func(*rig) []*http.Cookie { return nil }},
	}

	for idName, id := range ids {
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			for _, actor := range actors {
				t.Run(idName+"/"+method+"/"+actor.name, func(t *testing.T) {
					t.Parallel()

					rg := newRig(t)

					rec := rg.do(request{
						method: method, target: itemPrefix + url.PathEscape(id), body: "", contentType: "",
						cookies: actor.cookies(rg),
					})

					// The credential is judged before the id: only a caller the route
					// lets in is told the id is malformed.
					switch actor.name {
					case "no session":
						wantResponse(t, rg, rec, http.StatusUnauthorized, bodyUnauthenticated, "unauthenticated")
					case "member":
						wantResponse(t, rg, rec, http.StatusForbidden, bodyForbidden, "forbidden")
					default:
						wantResponse(t, rg, rec, http.StatusBadRequest, bodyInvalidID, "invalid_id")
					}

					wantCalls(t, rg.store.calls, nil)
				})
			}
		}
	}
}

// TestIDReachesTheStoreAsSent: a canonical id is passed on exactly, with no
// normalisation, on both routes that take one.
func TestIDReachesTheStoreAsSent(t *testing.T) {
	t.Parallel()

	ids := []string{
		targetID,
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"01234567-89ab-cdef-0123-456789abcdef",
	}

	for _, id := range ids {
		for _, rt := range routes()[1:] {
			t.Run(id+"/"+rt.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				cookie := rg.signIn(adminID, roleAdmin)
				rg.store.getErr = store.ErrNotFound

				rg.do(request{
					method: rt.method, target: itemPrefix + id, body: "", contentType: "", cookies: []*http.Cookie{cookie},
				})

				if len(rg.store.calls) != 1 || rg.store.calls[0].id != id || rg.store.calls[0].op != rt.op {
					t.Errorf("store calls = %+v, want one %s of %s", rg.store.calls, rt.op, id)
				}
			})
		}
	}
}

// TestMethods: a path answers only the methods it declares, with 405 and an
// Allow header, before authentication and with no store call.
func TestMethods(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method string
		target string
		allow  string
	}{
		{name: "POST on the collection", method: http.MethodPost, target: collection, allow: "GET"},
		{name: "PUT on the collection", method: http.MethodPut, target: collection, allow: "GET"},
		{name: "PATCH on the collection", method: http.MethodPatch, target: collection, allow: "GET"},
		{name: "DELETE on the collection", method: http.MethodDelete, target: collection, allow: "GET"},
		{name: "POST on an account", method: http.MethodPost, target: itemPrefix + targetID, allow: "DELETE, GET"},
		{name: "PUT on an account", method: http.MethodPut, target: itemPrefix + targetID, allow: "DELETE, GET"},
		{name: "PATCH on an account", method: http.MethodPatch, target: itemPrefix + targetID, allow: "DELETE, GET"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			cookie := rg.signIn(adminID, roleAdmin)

			rec := rg.do(request{
				method: tc.method, target: tc.target, body: "", contentType: "", cookies: []*http.Cookie{cookie},
			})

			wantResponse(t, rg, rec, http.StatusMethodNotAllowed, errorBody("method_not_allowed", "method not allowed"),
				"method_not_allowed")

			if got := rec.Header().Get("Allow"); got != tc.allow {
				t.Errorf("Allow = %q, want %q", got, tc.allow)
			}

			wantCalls(t, rg.store.calls, nil)
		})
	}
}

// TestRequestShape: what the boundary requires of a request before a route's
// handler may run. DELETE changes data, so it needs the JSON content type that
// forces a CORS preflight; a body over the routes' small cap is refused unread.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRequestShape(t *testing.T) {
	t.Parallel()

	const bodyCap = 1024

	cases := []struct {
		name   string
		route  int
		req    request
		status int
		body   string
		logged string
		// reached is whether the route's handler must have run.
		reached bool
	}{
		{
			name: "DELETE without a content type", route: 2,
			req:    request{contentType: "-"},
			status: http.StatusUnsupportedMediaType,
			body:   errorBody("unsupported_media_type", "request Content-Type must be application/json"),
			logged: "unsupported_media_type",
		},
		{
			name: "DELETE as a form", route: 2,
			req:    request{contentType: "application/x-www-form-urlencoded"},
			status: http.StatusUnsupportedMediaType,
			body:   errorBody("unsupported_media_type", "request Content-Type must be application/json"),
			logged: "unsupported_media_type",
		},
		{
			name: "GET needs no content type", route: 0,
			req:    request{contentType: "-"},
			status: http.StatusOK, body: "", logged: "", reached: true,
		},
		{
			name: "a body at the cap is read and ignored", route: 0,
			req:    request{body: strings.Repeat("a", bodyCap)},
			status: http.StatusOK, body: "", logged: "", reached: true,
		},
		{
			name: "a body one byte over the cap, on the list", route: 0,
			req:    request{body: strings.Repeat("a", bodyCap+1)},
			status: http.StatusRequestEntityTooLarge, body: bodyTooLarge, logged: "body_too_large",
		},
		{
			name: "a body one byte over the cap, on a read", route: 1,
			req:    request{body: strings.Repeat("a", bodyCap+1)},
			status: http.StatusRequestEntityTooLarge, body: bodyTooLarge, logged: "body_too_large",
		},
		{
			name: "a body one byte over the cap, on a revocation", route: 2,
			req:    request{body: strings.Repeat("a", bodyCap+1)},
			status: http.StatusRequestEntityTooLarge, body: bodyTooLarge, logged: "body_too_large",
		},
		{
			name: "a body at the cap, on a revocation", route: 2,
			req:    request{body: strings.Repeat("a", bodyCap)},
			status: http.StatusOK, body: "", logged: "", reached: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.store.got, rg.store.revoked = userRow(targetID), userRow(targetID)
			rg.store.revoked.RevokedAt = new(int64(1))

			rt := routes()[tc.route]
			req := tc.req
			req.method, req.target, req.cookies = rt.method, rt.target, []*http.Cookie{rg.signIn(adminID, roleAdmin)}

			rec := rg.do(req)

			if tc.reached {
				if rec.Code != tc.status || len(rg.logged) != 0 || len(rg.store.calls) != 1 {
					t.Errorf("response = %d %q, logged %v, calls %+v", rec.Code, rec.Body.String(), rg.logged, rg.store.calls)
				}

				return
			}

			wantResponse(t, rg, rec, tc.status, tc.body, tc.logged)
			wantCalls(t, rg.store.calls, nil)
		})
	}
}

// TestUnroutedPaths: paths next to the routes are not routes. Each answers the
// JSON 404 for an unknown route, to an administrator too, and calls nothing.
func TestUnroutedPaths(t *testing.T) {
	t.Parallel()

	targets := map[string]string{
		"the collection with a trailing slash, an account with no id": itemPrefix,
		"an account with a further segment":                           itemPrefix + targetID + "/keys",
		"a plural collection":                                         collection + "s",
		"the parent":                                                  "/api",
	}

	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			cookie := rg.signIn(adminID, roleAdmin)

			wantResponse(t, rg, rg.as(cookie, http.MethodGet, target), http.StatusNotFound, bodyNoRoute, "not_found")
			wantCalls(t, rg.store.calls, nil)
		})
	}
}
