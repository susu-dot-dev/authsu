// Package orgs implements the API for the organizations and sandboxes described
// in docs/orgs_design.md: create, list, read, rename and end them; see and change
// a standard organization's members; and offer, accept, decline and withdraw a
// place in one.
//
//	POST   /api/org                 create an organization or a sandbox
//	GET    /api/org                 one page of those the caller belongs to or administers
//	GET    /api/org/{id}            one of them
//	PATCH  /api/org/{id}            rename it
//	DELETE /api/org/{id}            revoke a standard organization, or delete a sandbox
//	GET    /api/org/{id}/member     one page of a standard organization's members
//	PATCH  /api/member/{id}         make a member an administrator, or stop them being one
//	DELETE /api/member/{id}         remove a member, or leave (the user themself)
//	POST   /api/org/{id}/offer      offer a user a place in a standard organization
//	GET    /api/org/{id}/offer      one page of its offers
//	GET    /api/offer               one page of the offers addressed to the caller
//	POST   /api/offer/{id}/accept   accept one
//	DELETE /api/offer/{id}          decline one, or withdraw one
//
// # Who may do what
//
// Who looks after an organization is a fact about that organization and not a
// scope, so every route here needs only an ordinary scope (org:, member: and
// offer:, none of them an admin scope) and the store decides, in the write that
// depends on it, who the caller is to it:
//
//   - A member sees their organization, its members and who administers it.
//   - An administrator of an organization also renames it, revokes it, offers
//     places in it, withdraws offers, and promotes, demotes and removes members.
//     A sandbox has exactly one administrator, the user who created it, who does
//     not belong to it: a sandbox has no members and receives no offers.
//   - A platform administrator (an account whose role is auth.RoleAdmin) has the
//     full override: whatever an organization's administrator may do, on any
//     organization, and every organization is listed to them.
//   - Anyone else is told an organization is not found, whether it exists or
//     not. A caller who can see an organization but may not do what they asked
//     is told so (403 org_admin_required).
//
// Every route that changes anything refuses an agent, whatever its scopes, so an
// agent cannot reorganise its user's membership; the reads may be used by one. No
// route opts in to a sandbox (auth.Access.InSandbox): an agent that is confined
// to a sandbox reaches none of this.
//
// # Organizations
//
// A user belongs to at most one standard organization, and creating one makes
// its creator a member and its administrator in the same write. A user who
// already belongs to one cannot create another (409 org_already_member), and at
// most MaxStandardOrgsPerUser standard organizations may ever be created by one
// user, revoked ones included, which revoking does not give back (409
// org_limit_reached). A sandbox is temporary: it expires SandboxLifetime after
// it is created, a user may hold MaxSandboxesPerUser that have not expired
// (409 sandbox_limit_reached), and it is deleted only by hand, by its
// administrator or a platform administrator. An expired sandbox is not deleted,
// but is inert when read.
//
// Revoking a standard organization releases its members, deletes its offers and
// its administrator rows, and keeps the organization as a record. Revoking one
// that is already revoked succeeds and keeps the earlier time for a platform
// administrator; its former administrators no longer administer it, and are
// told it is not found. A revoked organization, and an expired sandbox, cannot
// be renamed (409 org_inactive).
//
// An organization is shown with its status: active, revoked (a standard
// organization that was revoked), expired (a sandbox past its expiry), or
// deleted (the response to deleting a sandbox, which no longer exists).
//
// # Members
//
// Demoting an administrator, or removing one (leaving is removing oneself), is
// refused when they are the last unrevoked administrator of a standard
// organization (409 org_last_admin). That is the whole of the invariant:
// revoking the account of the last administrator is not refused, because that
// would let an organization administrator shield themselves from platform
// revocation. Such an organization has no unrevoked administrator, and a
// platform administrator's override is how it is managed (they may promote a
// member, or offer a place as "admin"). Promoting an administrator, and demoting a member
// who is not one, succeed and change nothing. The member and offer routes
// that name a sandbox are refused (409 org_not_standard).
//
// # Offers
//
// An offer to a user carries a role, "member" or "admin": accepting it makes
// the user a member and, for "admin", an administrator too, in the same write,
// and deletes the offer. A user may accept only while they belong to no
// organization (409 org_already_member) and only while the organization is
// active as the write runs, so a user can never join one that was just revoked;
// an offer of a revoked organization is not found. The addressee declines an
// offer, and an administrator or a platform administrator withdraws one, with
// the same route; so are the offers that ride on an invitation, which are shown
// to the organization's administrators and deleted only by withdrawing them, by
// revoking the organization or with their invitation.
//
// # Error codes
//
// Stable: clients and dashboards may match on them. A malformed id has
// input.CodeInvalidID, a bad kind, name or role has input.CodeInvalidOrgKind,
// input.CodeInvalidOrgName or input.CodeInvalidOrgRole, a bad page parameter
// input.CodeInvalidLimit or input.CodeInvalidCursor, and a database failure the
// code of its store operation (store.CodeOrgCreateFailed and its siblings).
//
//	404 org_not_found          no such organization, or the caller may not see it
//	404 member_not_found       the user belongs to no organization, or the caller may not see it
//	404 offer_not_found        no such offer, not the caller's to decline or withdraw,
//	                           or of an organization that is revoked
//	404 offer_user_not_found   the user to offer a place to does not exist, or is revoked
//	403 org_admin_required     the caller can see it but does not administer it
//	409 org_inactive           the organization is revoked or has expired
//	409 org_not_standard       a member or offer route named a sandbox
//	409 org_already_member     the user already belongs to an organization
//	409 org_limit_reached      the user has created MaxStandardOrgsPerUser organizations
//	409 sandbox_limit_reached  the user has MaxSandboxesPerUser sandboxes
//	409 org_last_admin         the change would leave an organization with no administrator
//	409 offer_exists           the user already has an offer from the organization
//	400 missing_admin          PATCH /api/member/{id} did not say whether to make an administrator
//	401 unauthenticated        the caller's account was revoked while the request ran
package orgs

import (
	"context"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// The limits on what one user may create (docs/orgs_design.md, principle 6), and
// how long a sandbox lasts. They are decided in the write that creates, so two
// requests at a limit cannot both pass.
const (
	// MaxSandboxesPerUser is how many sandboxes that have not expired a user may
	// hold.
	MaxSandboxesPerUser = 25

	// MaxStandardOrgsPerUser is how many standard organizations a user may ever
	// create, revoked ones included.
	MaxStandardOrgsPerUser = 5

	// SandboxLifetime is how long a sandbox lasts from its creation. It is fixed:
	// a client does not choose it.
	SandboxLifetime = 7 * 24 * time.Hour
)

// Store is the part of the database the routes use: one interface for each of
// the three things they are about. Every method takes the caller, whose standing
// to the organization is decided in the write, and the role that makes a caller
// a platform administrator. *store.Store satisfies it. A failure must come back
// classified (the store does), because it is sent as is.
type Store interface {
	OrgStore
	MemberStore
	OfferStore
}

// OrgStore is the part of Store that is about organizations and sandboxes.
type OrgStore interface {
	// CreateOrg creates an organization or a sandbox, or returns
	// store.ErrAccountRevoked, store.ErrAlreadyMember or store.ErrOrgLimit.
	CreateOrg(ctx context.Context, org store.NewOrg) (store.Org, error)
	// GetOrg returns an organization the caller may see, or store.ErrNotFound.
	GetOrg(ctx context.Context, id input.ID, caller, adminRole string) (store.Org, error)
	// ListOrgs returns a page of the organizations the caller may see.
	ListOrgs(
		ctx context.Context, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
	) (store.OrgPage, error)
	// RenameOrg renames one, or returns store.ErrNotFound, store.ErrNotAdmin or
	// store.ErrInactive.
	RenameOrg(
		ctx context.Context, id input.ID, name input.OrgName, caller, adminRole string, now time.Time,
	) (store.Org, error)
	// RevokeOrg revokes a standard organization or deletes a sandbox, or returns
	// store.ErrNotFound or store.ErrNotAdmin.
	RevokeOrg(ctx context.Context, id input.ID, caller, adminRole string, now time.Time) (store.OrgEnd, error)
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
	// RemoveMember removes a member, or returns store.ErrNotFound,
	// store.ErrNotAdmin or store.ErrLastOrgAdmin.
	RemoveMember(ctx context.Context, id input.ID, caller, adminRole string) (store.Member, error)
}

// OfferStore is the part of Store that is about offers of a place.
type OfferStore interface {
	// CreateOffer offers a user a place, or returns one of the offer errors of
	// the store (store.ErrNotFound and the rest of the list in its documentation).
	CreateOffer(ctx context.Context, offer store.NewOffer) (store.Offer, error)
	// ListOrgOffers returns a page of an organization's offers, or
	// store.ErrNotFound, store.ErrNotAdmin or store.ErrNotStandard.
	ListOrgOffers(
		ctx context.Context, id input.ID, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
	) (store.OfferPage, error)
	// ListMyOffers returns a page of the offers addressed to the caller.
	ListMyOffers(ctx context.Context, caller string, cursor input.Cursor, limit input.PageLimit) (store.OfferPage, error)
	// AcceptOffer accepts an offer addressed to the caller, or returns
	// store.ErrNotFound or store.ErrAlreadyMember.
	AcceptOffer(ctx context.Context, id input.ID, caller string, now time.Time) (store.Offer, error)
	// RevokeOffer declines or withdraws an offer, or returns store.ErrNotFound.
	RevokeOffer(ctx context.Context, id input.ID, caller, adminRole string) (store.Offer, error)
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
