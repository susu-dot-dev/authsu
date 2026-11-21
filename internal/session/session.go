// Package session is the part of the API a signed-in caller uses to ask about
// and end their own session (docs/login_design.md): who the cookie speaks for,
// and logout.
//
// It is thin because the boundary does the rest. internal/auth reads the cookie,
// resolves the token in the store along with its account, and hands each route
// here a Principal; a request without a valid session never reaches these
// handlers. Login (internal/login) is what issues a session.
package session

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Paths of the routes.
const (
	// PathSession is the path of GET /api/session.
	PathSession = "/api/session"
	// PathLogout is the path of POST /api/logout.
	PathLogout = "/api/logout"
)

// Store is the part of the database the session routes write. *store.Store
// satisfies it. Failures must come back classified, as the store's do, because
// they are sent as they are.
type Store interface {
	// RevokeSecret ends the secret id of the user as of now: the one the request
	// presented, a session or an API key alike. It reports false when there was
	// nothing to revoke: the secret was already revoked.
	RevokeSecret(ctx context.Context, userID, id string, now time.Time) (bool, error)
}

// Deps are the collaborators of Routes. All are required.
type Deps struct {
	// Store revokes the presented session or API key on logout.
	Store Store
	// Now is the clock, the time a logout takes effect.
	Now func() time.Time
}

// WhoAmIResponse is the body of GET /api/session. ExpiresAt is also when the
// user has to sign in again: a session is never extended.
type WhoAmIResponse struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
	// OrgID is the standard organization the account belongs to now. It is
	// absent, like the other optional members of the API, when the account
	// belongs to none.
	OrgID string `json:"orgId,omitempty"`
	// ExpiresAt is when this session ends, in Unix seconds.
	ExpiresAt int64 `json:"expiresAt"`
}

// errRevokedFirst is the cause of a logout that found its session already
// revoked by a concurrent request.
var errRevokedFirst = errors.New("session was revoked by another request")

// Routes returns the session routes, for auth.Handler. It panics when a
// dependency is missing: the routes would fail on first use, and a missing
// dependency is a wiring mistake to find at start, not in a request.
//
//   - GET /api/session: who the session cookie speaks for. It never writes.
//   - POST /api/logout: revoke the presented session or API key now and clear
//     the cookie. A secret that is already gone is a 401, like any request
//     without one.
//
// Both need a session and no more: a caller may always ask about and end their
// own, whatever their role.
func Routes(deps Deps) []auth.Route {
	if deps.Store == nil || deps.Now == nil {
		panic("session: Deps.Store and Deps.Now are required")
	}

	return []auth.Route{
		{
			Method: http.MethodGet, Path: PathSession, MaxBody: 0,
			Credential: auth.Authenticated, Access: auth.Open(), Handle: whoAmI,
		},
		{
			Method: http.MethodPost, Path: PathLogout, MaxBody: 0,
			Credential: auth.Authenticated, Access: auth.Open(), Handle: deps.logout,
		},
	}
}

// whoAmI answers GET /api/session from the verified principal. Everything in it
// was read for this request, so a changed role or a shortened session shows at
// once.
func whoAmI(call *auth.Call) result.Result[httpapi.Response] {
	principal := call.Principal

	return result.Ok(httpapi.JSON(http.StatusOK, WhoAmIResponse{
		UserID:    principal.UserID,
		Role:      principal.Role,
		OrgID:     principal.OrgID,
		ExpiresAt: principal.ExpiresAt.Unix(),
	}))
}

// logout answers POST /api/logout: it revokes the secret the request presented
// (key:revoke_self in docs/permissions_design.md), so a session ends itself and
// an API key ends itself, with no scope. The revocation is one conditional write
// (store.RevokeSecret): the boundary saw the secret active, so a write that
// changes nothing means another request revoked it in between. The secret is
// gone, which is what any request without one is told.
func (d Deps) logout(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.RevokeSecret(call.Request.Context, call.Principal.UserID, call.Principal.SecretID, d.Now())).
		Then(func(revoked bool) (httpapi.Response, error) {
			if !revoked {
				return httpapi.Response{}, auth.Unauthenticated(errRevokedFirst)
			}

			return httpapi.Response{Status: http.StatusNoContent, Body: nil, Cookies: nil}.
				WithCookies(auth.ClearSessionCookie()), nil
		})
}
