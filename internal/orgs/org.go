package orgs

import (
	"errors"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// createBody is the body of POST /api/org.
type createBody struct {
	// Kind is "standard" or "sandbox".
	Kind string `json:"kind"`

	// Name is what the organization is called.
	Name string `json:"name"`
}

// creation is a create request that has been parsed.
type creation struct {
	kind input.OrgKind
	name input.OrgName
}

// parseCreate parses the kind and the name, the kind first.
func parseCreate(body createBody) result.Result[creation] {
	return result.Of(input.ParseOrgKind(body.Kind)).
		Map(func(kind input.OrgKind) creation { return creation{kind: kind} }).
		Then(func(c creation) (creation, error) {
			return result.Of(input.ParseOrgName(body.Name)).
				Map(func(name input.OrgName) creation { c.name = name; return c }).
				Get()
		})
}

// createOrg answers POST /api/org. The limit of the kind and the expiry of a
// sandbox are the server's, never the request's.
func (d Deps) createOrg(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return httpapi.Decode[createBody](call.Request).
		Then(func(body createBody) (creation, error) { return parseCreate(body).Get() }).
		Then(func(c creation) (store.Org, error) { return d.write(call, c, now).Get() }).
		Map(func(stored store.Org) httpapi.Response { return created(presentOrg(stored, now)) })
}

// write creates what was asked for, with the limit that applies to its kind.
func (d Deps) write(call *auth.Call, c creation, now time.Time) result.Result[store.Org] {
	limit, code, description := MaxStandardOrgsPerUser, CodeOrgLimit, "a user may create a limited number of organizations"
	if c.kind.Sandbox() {
		limit, code, description = MaxSandboxesPerUser, CodeSandboxLimit, "a user may hold a limited number of sandboxes"
	}

	return result.Of(d.Store.CreateOrg(call.Request.Context, store.NewOrg{
		ID: d.NewID(), Kind: c.kind, Name: c.name, Creator: call.Principal.UserID,
		ExpiresAt: now.Add(SandboxLifetime), Limit: limit, CreatedAt: now,
	})).MapErr(func(err error) error {
		if errors.Is(err, store.ErrOrgLimit) {
			return refuse(apierr.Conflict, code, description, err)
		}

		return asOrg(err)
	})
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

// revokeOrg answers DELETE /api/org/{id}: a standard organization is revoked, and
// a sandbox is deleted, with what it holds. The response is the organization as
// it is left (revoked), or as it was (a sandbox, shown as deleted).
func (d Deps) revokeOrg(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(d.Store.RevokeOrg(call.Request.Context, call.ID(), call.Principal.UserID, auth.RoleAdmin, now)).
		MapErr(asOrg).
		Map(func(end store.OrgEnd) httpapi.Response { return ok(presentEnd(end, now)) })
}

// presentEnd is the client's view of an organization that was just ended.
func presentEnd(end store.OrgEnd, now time.Time) Org {
	out := presentOrg(end.Org, now)

	if end.Deleted {
		out.Status = StatusDeleted
	}

	return out
}
