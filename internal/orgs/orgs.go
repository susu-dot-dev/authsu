// Package orgs implements the API for the organizations and sandboxes described
// in docs/orgs_design.md: list, read and rename them, create and delete
// sandboxes, and see and change a standard organization's members.
//
//	POST   /api/org                 create a sandbox
//	GET    /api/org                 one page of those the caller belongs to or administers
//	GET    /api/org/{id}            one of them
//	PATCH  /api/org/{id}            rename it
//	DELETE /api/org/{id}            delete a sandbox
//	GET    /api/org/{id}/member     one page of a standard organization's members
//	PATCH  /api/member/{id}         make a member an administrator, or stop them being one
//	DELETE /api/member/{id}         revoke a member's account
//
// # Who may do what
//
// Who looks after an organization is a fact about that organization and not a
// scope, so every route here needs only an ordinary scope (org:, sandbox: and
// member:, none of them an admin scope) and the store decides, in the write that
// depends on it, who the caller is to it:
//
//   - A member sees their organization, its members and who administers it.
//   - An administrator of an organization also renames it, deletes it when it is
//     a sandbox, promotes and demotes its members, and revokes their accounts. A
//     sandbox has exactly one administrator, the user who created it, who does not
//     belong to it: a sandbox has no members.
//   - A platform administrator (an account whose role is auth.RoleAdmin) has the
//     full override: whatever an organization's administrator may do, on any
//     organization, and every organization is listed to them. They alone may
//     revoke a platform administrator, or themself as an administrator.
//   - Anyone else is told an organization is not found, whether it exists or
//     not. A caller who can see an organization but may not do what they asked
//     is told so (403 org_admin_required).
//
// Every route that changes anything refuses an agent, whatever its scopes, so an
// agent cannot reorganise its user's organization; the reads may be used by one.
// No route opts in to a sandbox (auth.Access.InSandbox): an agent that is
// confined to a sandbox reaches none of this.
//
// # Organizations
//
// Every account belongs to one standard organization, which registration binds
// to it (docs/registration_design.md). A client cannot create a standard
// organization, and none is ever revoked or deleted. The only thing a client
// creates is a sandbox, which is temporary: it expires SandboxLifetime after it
// is created, a user may hold MaxSandboxesPerUser that have not expired (409
// sandbox_limit_reached), and it is deleted only by hand, by its administrator
// or a platform administrator. An expired sandbox is not deleted, but is inert
// when read, does not count towards the limit, and cannot be renamed (409
// sandbox_expired). Deleting a standard organization is refused (409
// org_not_sandbox), to a caller who can see it.
//
// An organization is shown with its status: active, expired (a sandbox past
// its expiry), or deleted (the response to deleting a sandbox, which no longer
// exists).
//
// # Members
//
// Belonging to a standard organization is for the life of the account: there is
// no leaving, removing or moving a member. The one way a member ends is
// revocation (docs/users_design.md), which is final, and a revoked member stays
// in the organization as a record, listed with status "revoked", never
// administering it again and still counting against the invitation that created
// it. DELETE /api/member/{id} revokes the member's account and everything
// that belongs to it (its credentials and its agents) and answers with the member
// as revoked, at the time of the first revocation: revoking twice keeps it, so a
// retry is safe. Agents may not make the request, whatever their scopes.
//
// Who may revoke is decided in the write, from the caller's standing at that
// moment. A platform administrator may revoke any member. An administrator of the
// organization may revoke its members, but not a platform administrator, even
// one who belongs to it (403 platform_admin_protected), and not themself (403
// self_revoke_refused). A member who does not administer it is refused (403
// org_admin_required), and a caller who cannot see the organization is told the
// member is not found, as for a user who does not exist. The last active platform
// administrator cannot be revoked, even by themself (409 user_last_admin).
//
// An organization is not left without an unrevoked administrator by its own
// administrators: the one who revokes is an unrevoked administrator and is not
// the member revoked, so another remains, whichever order two administrators who
// revoke each other act in (the second finds themself revoked, and the member
// not found). A platform administrator may revoke the last one, and such an
// organization is then managed by a platform administrator, who may promote a
// member. Demoting an administrator is refused when they are the last unrevoked
// administrator of a standard organization (409 org_last_admin). Promoting an
// administrator, and demoting a member who is not one, succeed and change
// nothing. A revoked member is never promoted (409 member_revoked). The member
// routes that name a sandbox are refused (409 org_not_standard).
//
// A caller who is revoked while a request that changes something runs is told so
// (401), and not that the organization or member was not found, which is what the
// reads, which do not look, say.
//
// # Error codes
//
// Stable: clients and dashboards may match on them. A malformed id has
// input.CodeInvalidID, a bad name has input.CodeInvalidOrgName, a missing
// administrator flag input.CodeMissingAdmin, a bad page parameter
// input.CodeInvalidLimit or input.CodeInvalidCursor, and a database failure the
// code of its store operation (store.CodeOrgCreateFailed and its siblings).
//
//	404 org_not_found          no such organization, or the caller may not see it
//	404 member_not_found       no such user, or the caller may not see their organization
//	403 org_admin_required     the caller can see it but does not administer it
//	403 platform_admin_protected  an organization administrator tried to revoke a platform administrator
//	403 self_revoke_refused    an organization administrator tried to revoke themself
//	409 sandbox_expired        the sandbox has expired and cannot be renamed
//	409 org_not_standard       a member route named a sandbox
//	409 org_not_sandbox        a delete named a standard organization
//	409 sandbox_limit_reached  the user has MaxSandboxesPerUser sandboxes
//	409 org_last_admin         a demotion would leave an organization with no administrator
//	409 member_revoked         a promotion named a member whose account is revoked
//	409 user_last_admin        the member is the last active platform administrator
//	400 missing_admin          PATCH /api/member/{id} did not say whether to make an administrator
//	401 unauthenticated        the caller's account was revoked while a request that changes something ran
package orgs

import (
	"context"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// The limit on the sandboxes one user may hold (docs/orgs_design.md, principle
// 6), and how long a sandbox lasts. The limit is decided in the write that
// creates, so two requests at it cannot both pass.
const (
	// MaxSandboxesPerUser is how many sandboxes that have not expired a user may
	// hold.
	MaxSandboxesPerUser = 25

	// SandboxLifetime is how long a sandbox lasts from its creation. It is fixed:
	// a client does not choose it.
	SandboxLifetime = 7 * 24 * time.Hour
)

// Store is the part of the database the routes use: one interface for each of
// the two things they are about. Every method takes the caller, whose standing
// to the organization is decided in the write, and the role that makes a caller
// a platform administrator. *store.Store satisfies it. A failure must come back
// classified (the store does), because it is sent as is.
type Store interface {
	OrgStore
	MemberStore
}

// OrgStore is the part of Store that is about organizations and sandboxes.
type OrgStore interface {
	// CreateSandbox creates a sandbox, or returns store.ErrAccountRevoked or
	// store.ErrSandboxLimit.
	CreateSandbox(ctx context.Context, sandbox store.NewSandbox) (store.Org, error)
	// GetOrg returns an organization the caller may see, or store.ErrNotFound.
	GetOrg(ctx context.Context, id input.ID, caller, adminRole string) (store.Org, error)
	// ListOrgs returns a page of the organizations the caller may see.
	ListOrgs(
		ctx context.Context, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
	) (store.OrgPage, error)
	// RenameOrg renames one, or returns store.ErrNotFound, store.ErrNotAdmin or
	// store.ErrExpired.
	RenameOrg(
		ctx context.Context, id input.ID, name input.OrgName, caller, adminRole string, now time.Time,
	) (store.Org, error)
	// DeleteSandbox deletes a sandbox and returns it as it was, or returns
	// store.ErrNotFound, store.ErrNotAdmin or store.ErrNotSandbox.
	DeleteSandbox(ctx context.Context, id input.ID, caller, adminRole string) (store.Org, error)
}

// MemberStore is the part of Store that is about the members of an organization.
type MemberStore interface {
	// ListMembers returns a page of a standard organization's members, or
	// store.ErrNotFound or store.ErrNotStandard.
	ListMembers(
		ctx context.Context, id input.ID, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
	) (store.MemberPage, error)
	// SetMemberAdmin promotes or demotes a member, or returns store.ErrNotFound,
	// store.ErrNotAdmin or store.ErrLastOrgAdmin.
	SetMemberAdmin(
		ctx context.Context, id input.ID, admin bool, caller, adminRole string, now time.Time,
	) (store.Member, error)
	// RevokeMember revokes a member's account and returns the member as revoked,
	// or returns store.ErrNotFound, store.ErrNotAdmin,
	// store.ErrPlatformAdminTarget, store.ErrSelfRevoke or store.ErrLastAdmin.
	RevokeMember(
		ctx context.Context, id input.ID, caller, adminRole string, now time.Time,
	) (store.Member, error)
}

// Deps are the collaborators of Routes. All are required: Routes panics on a
// missing one, so a handler never meets a nil dependency.
type Deps struct {
	// Store holds the organizations.
	Store Store

	// Now is the clock.
	Now func() time.Time

	// NewID returns a fresh UUIDv7 in canonical text form.
	NewID func() string
}
