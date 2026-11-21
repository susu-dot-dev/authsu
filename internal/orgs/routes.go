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
	// CodeMemberNotFound is a user who belongs to no organization, or to one the
	// caller may not see.
	CodeMemberNotFound = "member_not_found"
	// CodeOfferNotFound is an offer that does not exist, that is not the
	// caller's to decline or withdraw, or that is of an organization that is
	// revoked.
	CodeOfferNotFound = "offer_not_found"
	// CodeOfferUserNotFound is the user an offer is addressed to not existing, or
	// being revoked.
	CodeOfferUserNotFound = "offer_user_not_found"
	// CodeNotAdmin is a caller who can see the organization and does not
	// administer it.
	CodeNotAdmin = "org_admin_required"
	// CodeInactive is a change to an organization that is revoked, or a sandbox
	// that has expired.
	CodeInactive = "org_inactive"
	// CodeNotStandard is a member or offer route that named a sandbox.
	CodeNotStandard = "org_not_standard"
	// CodeAlreadyMember is a user who belongs to an organization already, and so
	// cannot create or join one.
	CodeAlreadyMember = "org_already_member"
	// CodeOrgLimit is a create of a standard organization refused because the
	// user has created MaxStandardOrgsPerUser.
	CodeOrgLimit = "org_limit_reached"
	// CodeSandboxLimit is a create of a sandbox refused because the user holds
	// MaxSandboxesPerUser that have not expired.
	CodeSandboxLimit = "sandbox_limit_reached"
	// CodeLastAdmin is a change that would leave a standard organization without
	// an unrevoked administrator.
	CodeLastAdmin = "org_last_admin"
	// CodeOfferExists is an offer to a user who already has one from the
	// organization.
	CodeOfferExists = "offer_exists"
)

// Paths. A collection takes the verbs of the whole set; a member of one takes the
// verbs of its own.
const (
	orgCollectionPath   = "/api/org"
	orgItemPath         = "/api/org/{id}"
	orgMemberPath       = "/api/org/{id}/member"
	orgOfferPath        = "/api/org/{id}/offer"
	memberItemPath      = "/api/member/{id}"
	offerCollectionPath = "/api/offer"
	offerItemPath       = "/api/offer/{id}"
	offerAcceptPath     = "/api/offer/{id}/accept"
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
// reorganise its user's membership), and none opts in to a sandbox.
func Routes(deps Deps) []auth.Route {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Now": deps.Now == nil, "NewID": deps.NewID == nil,
	} {
		if missing {
			panic("orgs: Deps." + name + " is required")
		}
	}

	return []auth.Route{
		declare(http.MethodPost, orgCollectionPath, maxBody, auth.Needs(scope.OrgCreate).WithoutAgents(), deps.createOrg),
		declare(http.MethodGet, orgCollectionPath, maxSmallBody, auth.Needs(scope.OrgRead), deps.listOrgs),
		declare(http.MethodGet, orgItemPath, maxSmallBody, auth.Needs(scope.OrgRead), deps.getOrg),
		declare(http.MethodPatch, orgItemPath, maxBody, auth.Needs(scope.OrgUpdate).WithoutAgents(), deps.renameOrg),
		declare(http.MethodDelete, orgItemPath, maxSmallBody, auth.Needs(scope.OrgRevoke).WithoutAgents(), deps.revokeOrg),
		declare(http.MethodGet, orgMemberPath, maxSmallBody, auth.Needs(scope.MemberRead), deps.listMembers),
		declare(http.MethodPatch, memberItemPath, maxSmallBody,
			auth.Needs(scope.MemberUpdate).WithoutAgents(), deps.setMemberAdmin),
		declare(http.MethodDelete, memberItemPath, maxSmallBody,
			auth.Needs(scope.MemberRevoke).WithoutAgents(), deps.removeMember),
		declare(http.MethodPost, orgOfferPath, maxSmallBody, auth.Needs(scope.OfferCreate).WithoutAgents(), deps.createOffer),
		declare(http.MethodGet, orgOfferPath, maxSmallBody, auth.Needs(scope.OfferRead), deps.listOrgOffers),
		declare(http.MethodGet, offerCollectionPath, maxSmallBody, auth.Needs(scope.OfferRead), deps.listMyOffers),
		declare(http.MethodPost, offerAcceptPath, maxSmallBody,
			auth.Needs(scope.OfferUpdate).WithoutAgents(), deps.acceptOffer),
		declare(http.MethodDelete, offerItemPath, maxSmallBody,
			auth.Needs(scope.OfferRevoke).WithoutAgents(), deps.revokeOffer),
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
	// StatusRevoked means a standard organization was revoked.
	StatusRevoked Status = "revoked"
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

	// RevokedAt is when a standard organization was revoked, and is absent
	// until then.
	RevokedAt *int64 `json:"revokedAt,omitempty"`

	Status Status `json:"status"`
}

// presentOrg is the client's view of a stored organization at now.
func presentOrg(stored store.Org, now time.Time) Org {
	status := StatusActive

	switch {
	case stored.RevokedAt != nil:
		status = StatusRevoked
	case !stored.Active(now):
		status = StatusExpired
	}

	return Org{
		ID: stored.ID, Kind: stored.Kind, Name: stored.Name, CreatedBy: stored.CreatedBy, CreatedAt: stored.CreatedAt,
		ExpiresAt: stored.ExpiresAt, RevokedAt: stored.RevokedAt, Status: status,
	}
}

// Member is one member of a standard organization.
type Member struct {
	// ID is the user's id.
	ID string `json:"id"`

	// OrgID is the organization they belong to.
	OrgID string `json:"orgId"`

	// Admin is whether they administer it.
	Admin bool `json:"admin"`

	// Status is "active", or "revoked" for a member whose account was revoked: they
	// stay in the organization until removed, and do not count as an
	// administrator.
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
		ID: stored.ID, OrgID: stored.OrgID, Admin: stored.Admin, Status: status, CreatedAt: stored.CreatedAt,
		RevokedAt: stored.RevokedAt,
	}
}

// Offer is an offer of a place in a standard organization.
type Offer struct {
	ID string `json:"id"`

	// OrgID and OrgName are the organization offered.
	OrgID   string `json:"orgId"`
	OrgName string `json:"orgName"`

	// UserID is who it is addressed to, and is absent for an offer that rides on
	// an invitation.
	UserID *string `json:"userId,omitempty"`

	// InvitationID is the invitation the offer rides on, and is absent for an
	// offer to an existing user.
	InvitationID *string `json:"invitationId,omitempty"`

	// Role is "member" or "admin": what the person becomes on joining.
	Role string `json:"role"`

	// CreatedBy is who made the offer, and CreatedAt is in Unix seconds.
	CreatedBy string `json:"createdBy"`
	CreatedAt int64  `json:"createdAt"`
}

// presentOffer is the client's view of a stored offer.
func presentOffer(stored store.Offer) Offer {
	return Offer{
		ID: stored.ID, OrgID: stored.OrgID, OrgName: stored.OrgName, UserID: stored.UserID,
		InvitationID: stored.InvitationID, Role: stored.Role, CreatedBy: stored.CreatedBy, CreatedAt: stored.CreatedAt,
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
	case errors.Is(err, store.ErrNotAdmin):
		return refuse(apierr.Forbidden, CodeNotAdmin, "administering the organization is required", err)
	case errors.Is(err, store.ErrTargetNotFound):
		return refuse(apierr.NotFound, CodeOfferUserNotFound, "no such user", err)
	case errors.Is(err, store.ErrAccountRevoked):
		return auth.Unauthenticated(err) //nolint:wrapcheck // the boundary's own classified 401, with err as its cause
	default:
		return conflict(err)
	}
}

// conflict maps the outcomes that are the state the request met, which the
// client resolves by not retrying the same thing. Anything else is returned as it
// is.
func conflict(err error) error {
	switch {
	case errors.Is(err, store.ErrInactive):
		return refuse(apierr.Conflict, CodeInactive, "the organization is revoked or has expired", err)
	case errors.Is(err, store.ErrNotStandard):
		return refuse(apierr.Conflict, CodeNotStandard, "a sandbox has no members and receives no offers", err)
	case errors.Is(err, store.ErrAlreadyMember):
		return refuse(apierr.Conflict, CodeAlreadyMember, "the user already belongs to an organization", err)
	case errors.Is(err, store.ErrLastOrgAdmin):
		return refuse(apierr.Conflict, CodeLastAdmin, "an organization must keep an administrator", err)
	case errors.Is(err, store.ErrOfferExists):
		return refuse(apierr.Conflict, CodeOfferExists, "the user already has an offer from the organization", err)
	default:
		return err
	}
}

// asOrg is outcome for a route about an organization.
func asOrg(err error) error { return outcome(err, noSuchOrg) }

// asMember is outcome for a route about a member.
func asMember(err error) error { return outcome(err, noSuchMember) }

// asOffer is outcome for a route about an offer.
func asOffer(err error) error { return outcome(err, noSuchOffer) }

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

// noSuchOffer is the client's 404 for an offer that does not exist or is not the
// caller's.
func noSuchOffer(cause error) *apierr.Error {
	return refuse(apierr.NotFound, CodeOfferNotFound, "no such offer", cause)
}
