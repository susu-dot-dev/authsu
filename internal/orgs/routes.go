package orgs

import (
	"errors"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Error codes of the routes themselves. A failure of the store, a bad id, page
// parameter or value has its own code in store or input. They are stable:
// clients and dashboards may match on them.
const (
	// CodeOrgNotFound is an organization the caller may not see: one that does
	// not exist, and one that exists and is not theirs.
	CodeOrgNotFound = "org_not_found"
	// CodeMemberNotFound is a user who does not exist, or whose organization the
	// caller may not see.
	CodeMemberNotFound = "member_not_found"
	// CodeNotAdmin is a caller who can see the organization and does not
	// administer it.
	CodeNotAdmin = "org_admin_required"
	// CodeSandboxExpired is a change to a sandbox that has expired.
	CodeSandboxExpired = "sandbox_expired"
	// CodeNotStandard is a member route that named a sandbox.
	CodeNotStandard = "org_not_standard"
	// CodeNotSandbox is a delete that named a standard organization, which is
	// never deleted.
	CodeNotSandbox = "org_not_sandbox"
	// CodeSandboxLimit is a create refused because the user holds
	// MaxSandboxesPerUser sandboxes that have not expired.
	CodeSandboxLimit = "sandbox_limit_reached"
	// CodeLastAdmin is a demotion that would leave a standard organization
	// without an unrevoked administrator.
	CodeLastAdmin = "org_last_admin"
	// CodeMemberRevoked is a promotion of a member whose account is revoked.
	CodeMemberRevoked = "member_revoked"
	// CodeLastPlatformAdmin is a revocation of the last active platform
	// administrator. It is the code the account routes use for the same refusal
	// (docs/users_design.md).
	CodeLastPlatformAdmin = "user_last_admin"
	// CodePlatformAdminProtected is an organization administrator's revocation of
	// a platform administrator, who only a platform administrator may revoke.
	CodePlatformAdminProtected = "platform_admin_protected"
	// CodeSelfRevoke is an organization administrator's revocation of themself.
	CodeSelfRevoke = "self_revoke_refused"
)

// Paths. A collection takes the verbs of the whole set; a member of one takes the
// verbs of its own.
const (
	orgCollectionPath = "/api/org"
	orgItemPath       = "/api/org/{id}"
	orgMemberPath     = "/api/org/{id}/member"
	memberItemPath    = "/api/member/{id}"
)

// maxBody is the largest request body any route reads, in bytes. The biggest
// legitimate one is a name of 256 four-byte characters, every one escaped as a
// \uXXXX surrogate pair (12 bytes), about 3 KiB, so this leaves room and refuses
// anything that could only be an attempt to make a route read more before a name
// is refused.
const maxBody = 8 << 10

// maxSmallBody is the most a route that reads at most a short object (an id and
// a role, or a flag) or no body at all may be sent. It bounds the work a client
// can make the boundary do before the request is refused.
const maxSmallBody = 1 << 10

// Routes returns the organization routes. It panics when a dependency is nil.
//
// Each needs its own scope and no role: whether the caller may act on an
// organization is the store's to decide, in the write. Every route that changes
// something refuses agents, whatever their scopes (an agent is not the one to
// reorganise its user's organization), and none opts in to a sandbox.
func Routes(deps Deps) []auth.Route {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Now": deps.Now == nil, "NewID": deps.NewID == nil,
	} {
		if missing {
			panic("orgs: Deps." + name + " is required")
		}
	}

	return []auth.Route{
		declare(http.MethodPost, orgCollectionPath, maxBody,
			auth.Needs(scope.SandboxCreate).WithoutAgents(), deps.createSandbox),
		declare(http.MethodGet, orgCollectionPath, maxSmallBody, auth.Needs(scope.OrgRead), deps.listOrgs),
		declare(http.MethodGet, orgItemPath, maxSmallBody, auth.Needs(scope.OrgRead), deps.getOrg),
		declare(http.MethodPatch, orgItemPath, maxBody, auth.Needs(scope.OrgUpdate).WithoutAgents(), deps.renameOrg),
		declare(http.MethodDelete, orgItemPath, maxSmallBody,
			auth.Needs(scope.SandboxRevoke).WithoutAgents(), deps.deleteSandbox),
		declare(http.MethodGet, orgMemberPath, maxSmallBody, auth.Needs(scope.MemberRead), deps.listMembers),
		declare(http.MethodPatch, memberItemPath, maxSmallBody,
			auth.Needs(scope.MemberUpdate).WithoutAgents(), deps.setMemberAdmin),
		declare(http.MethodDelete, memberItemPath, maxSmallBody,
			auth.Needs(scope.MemberRevoke).WithoutAgents(), deps.revokeMember),
	}
}

// declare declares an authenticated route with its access.
func declare(
	method, path string, limit int64, access auth.Access, handle func(*auth.Call) result.Result[httpapi.Response],
) auth.Route {
	return auth.Route{
		Method: method, Path: path, MaxBody: limit, Credential: auth.Authenticated, Access: access, Handle: handle,
	}
}

// Status is where an organization stands. It is derived from the row and the
// clock, never stored.
type Status string

// Statuses.
const (
	// StatusActive means the organization works.
	StatusActive Status = "active"
	// StatusExpired means a sandbox is past its expiry. It still exists, and is
	// inert, until it is deleted.
	StatusExpired Status = "expired"
	// StatusDeleted is a sandbox that was just deleted, in the response to
	// deleting it.
	StatusDeleted Status = "deleted"
)

// Org is one organization or sandbox as a caller who may see it is shown it.
type Org struct {
	ID string `json:"id"`

	// Kind is "standard" or "sandbox".
	Kind string `json:"kind"`
	Name string `json:"name"`

	// CreatedBy is the user who made it.
	CreatedBy string `json:"createdBy"`

	// CreatedAt is in Unix seconds.
	CreatedAt int64 `json:"createdAt"`

	// ExpiresAt is when a sandbox stops working, and is absent for a standard
	// organization.
	ExpiresAt *int64 `json:"expiresAt,omitempty"`

	Status Status `json:"status"`
}

// presentOrg is the client's view of a stored organization at now.
func presentOrg(stored store.Org, now time.Time) Org {
	status := StatusActive
	if !stored.Active(now) {
		status = StatusExpired
	}

	return Org{
		ID: stored.ID, Kind: stored.Kind, Name: stored.Name, CreatedBy: stored.CreatedBy, CreatedAt: stored.CreatedAt,
		ExpiresAt: stored.ExpiresAt, Status: status,
	}
}

// Member is one member of a standard organization.
type Member struct {
	// ID is the user's id.
	ID string `json:"id"`

	// OrgID is the organization they belong to.
	OrgID string `json:"orgId"`

	// Admin is whether they administer it. A revoked member never does, whatever
	// they administered when they were revoked.
	Admin bool `json:"admin"`

	// Status is "active", or "revoked" for a member whose account was revoked: they
	// stay in the organization as a record.
	Status string `json:"status"`

	// CreatedAt is when the account was created, in Unix seconds.
	CreatedAt int64 `json:"createdAt"`

	// RevokedAt is when the account was revoked, and is absent until then.
	RevokedAt *int64 `json:"revokedAt,omitempty"`
}

// Statuses of a member's account.
const (
	memberActive  = "active"
	memberRevoked = "revoked"
)

// presentMember is the client's view of a stored member.
func presentMember(stored store.Member) Member {
	status := memberActive
	if stored.RevokedAt != nil {
		status = memberRevoked
	}

	return Member{
		ID: stored.ID, OrgID: stored.OrgID, Admin: stored.Admin && stored.RevokedAt == nil, Status: status,
		CreatedAt: stored.CreatedAt,
		RevokedAt: stored.RevokedAt,
	}
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
				Map(func(cursor input.Cursor) page { p.cursor = cursor; return p }).
				Get()
		})
}

// ok is the 200 response carrying body.
func ok[T any](body T) httpapi.Response { return httpapi.JSON(http.StatusOK, body) }

// created is the 201 response carrying body.
func created[T any](body T) httpapi.Response { return httpapi.JSON(http.StatusCreated, body) }

// outcome maps what the store says about a request to the client's answer.
// notFound is the 404 of the resource the route is about, which is the only
// outcome that differs between resources; the rest mean the same on every route
// that can meet them. Anything else (a failure the store already classified) is
// returned as it is.
func outcome(err error, notFound func(error) *apierr.Error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return notFound(err)
	case errors.Is(err, store.ErrAccountRevoked):
		return auth.Unauthenticated(err) //nolint:wrapcheck // the boundary's own classified 401, with err as its cause
	default:
		return forbidden(err)
	}
}

// forbidden maps the outcomes of a caller who can see what they asked about and
// may not do it. Anything else is for conflict.
func forbidden(err error) error {
	switch {
	case errors.Is(err, store.ErrNotAdmin):
		return refuse(apierr.Forbidden, CodeNotAdmin, "administering the organization is required", err)
	case errors.Is(err, store.ErrPlatformAdminTarget):
		return refuse(apierr.Forbidden, CodePlatformAdminProtected,
			"only a platform administrator may revoke a platform administrator", err)
	case errors.Is(err, store.ErrSelfRevoke):
		return refuse(apierr.Forbidden, CodeSelfRevoke, "an organization administrator may not revoke themself", err)
	default:
		return conflict(err)
	}
}

// conflict maps the outcomes that are the state the request met, which the
// client resolves by not retrying the same thing. Anything else is returned as it
// is.
func conflict(err error) error {
	switch {
	case errors.Is(err, store.ErrExpired):
		return refuse(apierr.Conflict, CodeSandboxExpired, "the sandbox has expired", err)
	case errors.Is(err, store.ErrNotStandard):
		return refuse(apierr.Conflict, CodeNotStandard, "a sandbox has no members", err)
	case errors.Is(err, store.ErrNotSandbox):
		return refuse(apierr.Conflict, CodeNotSandbox, "only a sandbox can be deleted", err)
	case errors.Is(err, store.ErrMemberRevoked):
		return refuse(apierr.Conflict, CodeMemberRevoked, "a revoked member cannot be made an administrator", err)
	case errors.Is(err, store.ErrLastOrgAdmin):
		return refuse(apierr.Conflict, CodeLastAdmin, "an organization must keep an administrator", err)
	case errors.Is(err, store.ErrLastAdmin):
		return refuse(apierr.Conflict, CodeLastPlatformAdmin, "the last active administrator cannot be revoked", err)
	default:
		return err
	}
}

// asOrg is outcome for a route about an organization.
func asOrg(err error) error { return outcome(err, noSuchOrg) }

// asMember is outcome for a route about a member.
func asMember(err error) error { return outcome(err, noSuchMember) }

// refuse is the classified error for a store outcome, with cause kept for the
// log.
func refuse(kind apierr.Kind, code, description string, cause error) *apierr.Error {
	return apierr.New(kind, code, description).WithCause(cause)
}

// noSuchOrg is the client's 404 for an organization the caller may not see.
func noSuchOrg(cause error) *apierr.Error {
	return refuse(apierr.NotFound, CodeOrgNotFound, "no such organization", cause)
}

// noSuchMember is the client's 404 for a user who belongs to no organization the
// caller may see.
func noSuchMember(cause error) *apierr.Error {
	return refuse(apierr.NotFound, CodeMemberNotFound, "no such member", cause)
}
