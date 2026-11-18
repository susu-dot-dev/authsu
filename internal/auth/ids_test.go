package auth_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// badIDs are path values that are not an input.ID, as a client could spell
// them in a URL.
func badIDs() map[string]string {
	return map[string]string{
		nameUpper:            strings.ToUpper(itemID),
		"not a uuid":         "not-an-id",
		"too short":          itemID[:35],
		"too long":           itemID + "0",
		"no dashes":          strings.ReplaceAll(itemID, "-", ""),
		"dashes misplaced":   "0000000-00000-7000-8000-0000000000aa",
		"braces":             "{" + itemID + "}",
		"percent-encoded":    "%41" + itemID[1:],
		"traversal":          "..%2f" + itemID,
		"urn prefix":         "urn:uuid:" + itemID,
		"a number":           "42",
		"a leading space":    "%20" + itemID[1:],
		"non-hex digits":     "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
		"sql":                "%27%20OR%201=1--",
		"multibyte":          "%C3%A9" + itemID[1:],
		"a NUL":              "%00",
		"a trailing newline": itemID + "%0a",
		"a lookalike letter": strings.Replace(itemID, "a", "%D0%B0", 1),
	}
}

// idContext is a state of the world in which a bad id is sent, and what the
// caller is told: the credential is judged before the id, so only a caller who
// is let in learns that the id is malformed.
type idContext struct {
	env     map[string]string
	cookies cookieFn
	// want is the failure the caller gets on a route with a session.
	status int
	body   string
	code   string
	cause  error
}

// idContexts are the states of the world a bad id is sent in, each with the
// answer the credential alone would give.
func idContexts() map[string]idContext {
	return map[string]idContext{
		"valid session": {
			env: nil, cookies: valid, status: http.StatusBadRequest, body: bodyInvalidID, code: input.CodeInvalidID, cause: nil,
		},
		nameNoCookie: {
			env: nil, cookies: nil, status: http.StatusUnauthorized, body: bodyUnauthenticated, code: auth.CodeUnauthenticated,
			cause: nil,
		},
		"garbage cookie": {
			env: nil, cookies: sessionValue("garbage"), status: http.StatusUnauthorized, body: bodyUnauthenticated,
			code: auth.CodeUnauthenticated, cause: nil,
		},
		"revoked session": {
			env: nil, cookies: afterStoring(revoked), status: http.StatusUnauthorized, body: bodyUnauthenticated,
			code: auth.CodeUnauthenticated, cause: nil,
		},
		"no configuration": {
			env: noSecret(), cookies: valid, status: http.StatusServiceUnavailable, body: bodyNotConfigured,
			code: auth.CodeNotConfigured, cause: nil,
		},
		"store failing": {
			env: nil, cookies: failing(errDB), status: http.StatusServiceUnavailable, body: bodyUnavailable,
			code: store.CodeSessionVerifyFailed, cause: errDB,
		},
	}
}

// TestSessionRoutesJudgeTheCredentialBeforeTheID: on a route with a credential, a
// malformed id never gets an answer of its own before the caller is known: a
// signed-out caller is 401, an unconfigured deployment is 503, and so on, as it
// would be for a good id. Only a caller who is let in is told 400 invalid_id.
// The route does not run either way.
func TestSessionRoutesJudgeTheCredentialBeforeTheID(t *testing.T) {
	t.Parallel()

	for idName, id := range badIDs() {
		for ctxName, world := range idContexts() {
			t.Run(idName+"/"+ctxName, func(t *testing.T) {
				t.Parallel()

				r := newRig(t).with(world.env)

				var cookies []*http.Cookie
				if world.cookies != nil {
					cookies = world.cookies(r)
				}

				rec := r.get(pathItems+id, cookies...)

				wantFailure(t, r, rec, world.status, world.body, world.code, world.cause)

				if len(r.handled) != 0 {
					t.Errorf("route ran %d times, want 0", len(r.handled))
				}
			})
		}
	}
}

// TestAdminRoutesRefuseAMemberBeforeTheID: a signed-in caller the route's
// requirement refuses is 403 whatever the id, so a member learns nothing about
// the id an admin route expects.
func TestAdminRoutesRefuseAMemberBeforeTheID(t *testing.T) {
	t.Parallel()

	for idName, id := range badIDs() {
		t.Run(idName, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			routes := []auth.Route{r.getRoute(patternItem, auth.Authenticated, auth.Needs(scope.UserRead))}
			rec := r.serve(routes, request{target: pathItems + id, cookies: withRole(roleMember)(r)})

			wantFailure(t, r, rec, http.StatusForbidden, bodyForbidden, auth.CodeForbidden, nil)

			if len(r.handled) != 0 {
				t.Errorf("route ran %d times, want 0", len(r.handled))
			}
		})
	}
}

// TestPublicRoutesParseTheID: a route without a credential has no caller to
// judge, so a malformed id is 400 invalid_id there, with no read of the
// configuration, the cookie or the store.
func TestPublicRoutesParseTheID(t *testing.T) {
	t.Parallel()

	for idName, id := range badIDs() {
		for ctxName, world := range idContexts() {
			t.Run(idName+"/"+ctxName, func(t *testing.T) {
				t.Parallel()

				r := newRig(t).with(world.env)

				var cookies []*http.Cookie
				if world.cookies != nil {
					cookies = world.cookies(r)
				}

				rec := r.get(pathPublic+"/"+id, cookies...)

				wantFailure(t, r, rec, http.StatusBadRequest, bodyInvalidID, input.CodeInvalidID, nil)

				if len(r.handled) != 0 || len(r.keys.calls) != 0 {
					t.Errorf("route ran %d times and store was read %d times, want neither", len(r.handled), len(r.keys.calls))
				}
			})
		}
	}
}

// TestTheIDReachesTheRoute: a valid id is parsed and handed to the route.
func TestTheIDReachesTheRoute(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	rec := r.get(pathItems+itemID, sessionCookie(r.session()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body)
	}

	if got := r.handled[0].ID().String(); got != itemID {
		t.Errorf("ID() = %q, want %q", got, itemID)
	}
}
