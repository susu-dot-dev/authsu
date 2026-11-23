package orgs

import (
	"errors"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// createBody is the body of POST /api/org: a sandbox is the only thing a client
// can create, so it names only what to call it.
type createBody struct {
	// Name is what the sandbox is called.
	Name string `json:"name"`
}

// createSandbox answers POST /api/org. The limit and the expiry are the
// server's, never the request's.
func (d Deps) createSandbox(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return httpapi.Decode[createBody](call.Request).
		Then(func(body createBody) (input.OrgName, error) { return input.ParseOrgName(body.Name) }).
		Then(func(name input.OrgName) (store.Org, error) {
			return d.Store.CreateSandbox(call.Request.Context, store.NewSandbox{
				ID: d.NewID(), Name: name, Creator: call.Principal.UserID,
				ExpiresAt: now.Add(SandboxLifetime), Limit: MaxSandboxesPerUser, CreatedAt: now,
			})
		}).
		MapErr(func(err error) error {
			if errors.Is(err, store.ErrSandboxLimit) {
				return refuse(apierr.Conflict, CodeSandboxLimit, "a user may hold a limited number of sandboxes", err)
			}

			return asOrg(err)
		}).
		Map(func(stored store.Org) httpapi.Response { return created(presentOrg(stored, now)) })
}

// ListResponse is the body of GET /api/org: one page, newest first.
type ListResponse struct {
	Orgs []Org `json:"orgs"`

	// Next is the cursor of the following page, to send as the cursor query
	// parameter. It is absent on the last page.
	Next string `json:"next,omitempty"`
}

// listOrgs answers GET /api/org.
func (d Deps) listOrgs(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return parsePage(call.Request.Query).
		Then(func(p page) (store.OrgPage, error) {
			return d.Store.ListOrgs(call.Request.Context, call.Principal.UserID, auth.RoleAdmin, p.cursor, p.limit)
		}).
		Map(func(stored store.OrgPage) ListResponse {
			out := ListResponse{Orgs: make([]Org, 0, len(stored.Orgs)), Next: stored.Next}

			for _, org := range stored.Orgs {
				out.Orgs = append(out.Orgs, presentOrg(org, now))
			}

			return out
		}).
		Map(ok)
}

// getOrg answers GET /api/org/{id}.
func (d Deps) getOrg(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(d.Store.GetOrg(call.Request.Context, call.ID(), call.Principal.UserID, auth.RoleAdmin)).
		MapErr(asOrg).
		Map(func(stored store.Org) httpapi.Response { return ok(presentOrg(stored, now)) })
}

// renameBody is the body of PATCH /api/org/{id}.
type renameBody struct {
	Name string `json:"name"`
}

// renameOrg answers PATCH /api/org/{id}.
func (d Deps) renameOrg(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return httpapi.Decode[renameBody](call.Request).
		Then(func(body renameBody) (input.OrgName, error) { return input.ParseOrgName(body.Name) }).
		Then(func(name input.OrgName) (store.Org, error) {
			return d.Store.RenameOrg(call.Request.Context, call.ID(), name, call.Principal.UserID, auth.RoleAdmin, now)
		}).
		MapErr(asOrg).
		Map(func(stored store.Org) httpapi.Response { return ok(presentOrg(stored, now)) })
}

// deleteSandbox answers DELETE /api/org/{id}: a sandbox is deleted, with what
// it holds. The response is the sandbox as it was, shown as deleted.
func (d Deps) deleteSandbox(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(d.Store.DeleteSandbox(call.Request.Context, call.ID(), call.Principal.UserID, auth.RoleAdmin)).
		MapErr(asOrg).
		Map(func(stored store.Org) httpapi.Response {
			deleted := presentOrg(stored, now)
			deleted.Status = StatusDeleted

			return ok(deleted)
		})
}
