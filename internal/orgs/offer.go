package orgs

import (
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// OfferListResponse is the body of the offer lists: one page, newest first.
type OfferListResponse struct {
	Offers []Offer `json:"offers"`

	// Next is the cursor of the following page, to send as the cursor query
	// parameter. It is absent on the last page.
	Next string `json:"next,omitempty"`
}

// presentOffers is the client's view of a page of stored offers.
func presentOffers(stored store.OfferPage) OfferListResponse {
	out := OfferListResponse{Offers: make([]Offer, 0, len(stored.Offers)), Next: stored.Next}

	for _, offer := range stored.Offers {
		out.Offers = append(out.Offers, presentOffer(offer))
	}

	return out
}

// offerBody is the body of POST /api/org/{id}/offer.
type offerBody struct {
	// UserID is the user the place is offered to.
	UserID string `json:"userId"`

	// Role is "member" or "admin": what they become on accepting.
	Role string `json:"role"`
}

// offering is an offer request that has been parsed.
type offering struct {
	user input.ID
	role input.OrgRole
}

// parseOffer parses the user and the role, the user first.
func parseOffer(body offerBody) result.Result[offering] {
	return result.Of(input.ParseID(body.UserID)).
		Map(func(user input.ID) offering { return offering{user: user} }).
		Then(func(o offering) (offering, error) {
			return result.Of(input.ParseOrgRole(body.Role)).
				Map(func(role input.OrgRole) offering { o.role = role; return o }).
				Get()
		})
}

// createOffer answers POST /api/org/{id}/offer. The organization not being one
// the caller may see is a 404 about the organization.
func (d Deps) createOffer(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[offerBody](call.Request).
		Then(func(body offerBody) (offering, error) { return parseOffer(body).Get() }).
		Then(func(o offering) (store.Offer, error) {
			return d.Store.CreateOffer(call.Request.Context, store.NewOffer{
				ID: d.NewID(), OrgID: call.ID(), UserID: o.user, Role: o.role,
				Caller: call.Principal.UserID, AdminRole: auth.RoleAdmin, CreatedAt: d.Now(),
			})
		}).
		MapErr(asOrg).
		Map(func(stored store.Offer) httpapi.Response { return created(presentOffer(stored)) })
}

// listOrgOffers answers GET /api/org/{id}/offer.
func (d Deps) listOrgOffers(call *auth.Call) result.Result[httpapi.Response] {
	return parsePage(call.Request.Query).
		Then(func(p page) (store.OfferPage, error) {
			return d.Store.ListOrgOffers(
				call.Request.Context, call.ID(), call.Principal.UserID, auth.RoleAdmin, p.cursor, p.limit)
		}).
		MapErr(asOrg).
		Map(func(stored store.OfferPage) httpapi.Response { return ok(presentOffers(stored)) })
}

// listMyOffers answers GET /api/offer: the offers addressed to the caller.
func (d Deps) listMyOffers(call *auth.Call) result.Result[httpapi.Response] {
	return parsePage(call.Request.Query).
		Then(func(p page) (store.OfferPage, error) {
			return d.Store.ListMyOffers(call.Request.Context, call.Principal.UserID, p.cursor, p.limit)
		}).
		Map(func(stored store.OfferPage) httpapi.Response { return ok(presentOffers(stored)) })
}

// acceptOffer answers POST /api/offer/{id}/accept: only the user the offer is
// addressed to may accept it, and the response is the offer as it was.
func (d Deps) acceptOffer(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.AcceptOffer(call.Request.Context, call.ID(), call.Principal.UserID, d.Now())).
		MapErr(asOffer).
		Map(func(stored store.Offer) httpapi.Response { return ok(presentOffer(stored)) })
}

// revokeOffer answers DELETE /api/offer/{id}: the user it is addressed to
// declines it, and an administrator of its organization or a platform
// administrator withdraws it, whether it is addressed to a user or rides on an
// invitation. The response is the offer as it was.
func (d Deps) revokeOffer(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.RevokeOffer(call.Request.Context, call.ID(), call.Principal.UserID, auth.RoleAdmin)).
		MapErr(asOffer).
		Map(func(stored store.Offer) httpapi.Response { return ok(presentOffer(stored)) })
}
