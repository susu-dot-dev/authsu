package oauth

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// CodeGrantNotFound is a grant the user does not have: one that does not exist,
// or one that belongs to someone else. 404, alike for both, so a request cannot
// probe another user's grants. It is stable: clients and dashboards may match on
// it.
const CodeGrantNotFound = "grant_not_found"

// grantRoute declares an authenticated grant route with its access.
func grantRoute(
	method, path string, access auth.Access, handle func(*auth.Call) result.Result[httpapi.Response],
) auth.Route {
	return auth.Route{
		Method: method, Path: path, MaxBody: MaxGrantQuery, Credential: auth.Authenticated, Access: access,
		Handle: handle,
	}
}

// AgentRef is the agent that holds a grant, as the user sees it.
type AgentRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GrantView is one of a user's grants as the user sees it: what was approved
// and for which agent. It never carries a token or a hash, because the store
// never selects one.
type GrantView struct {
	ID string `json:"id"`

	// Agent is the agent that holds the grant, with its name now.
	Agent AgentRef `json:"agent"`

	// ClientID is the client's metadata URL and ClientName the name its
	// document gave when the user approved.
	ClientID   string `json:"clientId"`
	ClientName string `json:"clientName"`

	// Resource is the resource server the grant is for, Scopes the resource's
	// scopes it carries in the order they were approved, and OpenID whether it
	// also gets an ID token.
	Resource string   `json:"resource"`
	Scopes   []string `json:"scopes"`
	OpenID   bool     `json:"openid"`

	// CreatedAt is when the user approved, ExpiresAt when the grant lapses if
	// it is not used (30 days from its last exchange; for a grant whose code was
	// not exchanged, when it may be removed, ten minutes after approval) and
	// RevokedAt when it was revoked, absent if it was not. All are Unix seconds.
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
	RevokedAt *int64 `json:"revokedAt,omitempty"`
}

// presentGrant is the user's view of a stored grant. The scope is read as the
// store keeps it, space-delimited, as input.OAuthScopes writes it.
func presentGrant(stored store.Grant) GrantView {
	names := strings.Split(stored.Scope, " ")

	return GrantView{
		ID: stored.ID, Agent: AgentRef{ID: stored.AgentID, Name: stored.AgentName},
		ClientID: stored.ClientID, ClientName: stored.ClientName, Resource: stored.Resource,
		Scopes: slices.DeleteFunc(slices.Clone(names), func(name string) bool { return name == input.OpenIDScope }),
		OpenID: slices.Contains(names, input.OpenIDScope), CreatedAt: stored.CreatedAt, ExpiresAt: stored.ExpiresAt,
		RevokedAt: stored.RevokedAt,
	}
}

// GrantList is the body of GET /api/grant: one page, newest first.
type GrantList struct {
	Grants []GrantView `json:"grants"`

	// Next is the cursor of the following page, to send as the cursor query
	// parameter. It is absent on the last page.
	Next string `json:"next,omitempty"`
}

// page is a parsed list request.
type page struct {
	cursor input.Cursor
	limit  input.PageLimit
}

// parsePage reads the limit and cursor from the query. Each may appear at most
// once: a repeated parameter is ambiguous, and which value wins differs between
// layers, so it is refused rather than guessed.
func parsePage(query map[string][]string) result.Result[page] {
	return result.Of(input.ParsePageLimit(query["limit"])).
		Map(func(limit input.PageLimit) page { return page{limit: limit} }).
		Then(func(p page) (page, error) {
			return result.Of(input.ParseCursor(query["cursor"])).
				Map(func(cursor input.Cursor) page {
					p.cursor = cursor

					return p
				}).
				Get()
		})
}

// listGrants answers GET /api/grant: the caller's grants, revoked and expired
// ones included, newest first. A grant whose code was not yet exchanged is one,
// and can be revoked: whether it has an access token says nothing about whether
// it exists (see store.Grant). Only the caller's are ever read: the store's every
// read names the owner.
func (d Deps) listGrants(call *auth.Call) result.Result[httpapi.Response] {
	return parsePage(call.Request.Query).
		Then(func(p page) (store.GrantPage, error) {
			return d.Store.ListGrants(call.Request.Context, call.Principal.UserID, p.cursor, p.limit)
		}).
		Map(func(stored store.GrantPage) GrantList {
			out := GrantList{Grants: make([]GrantView, 0, len(stored.Grants)), Next: stored.Next}

			for _, grant := range stored.Grants {
				out.Grants = append(out.Grants, presentGrant(grant))
			}

			return out
		}).
		Map(func(out GrantList) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// getGrant answers GET /api/grant/{id}.
func (d Deps) getGrant(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.GetGrant(call.Request.Context, call.Principal.UserID, call.ID())).
		MapErr(grantNotFound).
		Map(presentGrant).
		Map(func(out GrantView) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// revokeGrant answers DELETE /api/grant/{id}: it revokes the caller's grant, and
// its refresh token and access token with it, and answers with the grant as the
// write left it. Revoking a grant that is already revoked succeeds and keeps the
// earlier time, so the call is idempotent. The agent that holds the grant is not
// touched.
func (d Deps) revokeGrant(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.RevokeGrant(call.Request.Context, call.Principal.UserID, call.ID(), d.Now())).
		MapErr(grantNotFound).
		Map(presentGrant).
		Map(func(out GrantView) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// grantNotFound turns the store's "no such row" into the client's 404. The store
// matches by owner as well as id, so another user's grant comes back as the same
// outcome, and so the same response, as one that does not exist. Anything else is
// returned as it is.
func grantNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return noSuchGrant(err)
	}

	return err
}

// noSuchGrant is the client's 404 for a grant the user does not have.
func noSuchGrant(cause error) *apierr.Error {
	return apierr.New(apierr.NotFound, CodeGrantNotFound, "no such grant").WithCause(cause)
}
