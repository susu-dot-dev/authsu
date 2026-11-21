//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package orgs_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// offerJSON is the exact JSON of an offer to userID of the given role.
func offerJSON(id string) string {
	return `{"id":"` + id + `","orgId":"` + orgID + `","orgName":"Acme","userId":"` + userID + `","role":"member` +
		`","createdBy":"` + otherID + `","createdAt":1700000002}`
}

// invitationOfferJSON is the exact JSON of an offer that rides on invID.
func invitationOfferJSON(id string) string {
	return `{"id":"` + id + `","orgId":"` + orgID + `","orgName":"Acme","invitationId":"` + invID +
		`","role":"admin","createdBy":"` + otherID + `","createdAt":1700000002}`
}

// invitationOffer is a stored offer that rides on invID.
func invitationOffer(id string) store.Offer {
	offer := storedOffer(id)
	offer.UserID, offer.InvitationID, offer.Role = nil, new(invID), store.OfferRoleAdmin

	return offer
}

// TestCreateOffer: the user and the role are parsed, the organization is the
// path's, and every outcome of the store is its own answer.
func TestCreateOffer(t *testing.T) {
	t.Parallel()

	target := "/api/org/" + orgID + "/offer"
	body := `{"userId":"` + otherID + `","role":"member"}`
	call := func(role string) string {
		return fmt.Sprintf("CreateOffer id=%s org=%s user=%s role=%s caller=%s adminRole=%s at=%d",
			newID, orgID, otherID, role, userID, auth.RoleAdmin, now)
	}

	cases := []routeCase{
		{name: "an offer to join as a member", method: http.MethodPost, target: target, body: body,
			program: func(s *fakeStore) { s.createOffer.value = storedOffer(newID) }, status: http.StatusCreated,
			want: line(offerJSON(newID)), calls: []string{call("member")}},
		{name: "an offer to join as an administrator", method: http.MethodPost, target: target,
			body:    `{"userId":"` + otherID + `","role":"admin"}`,
			program: func(s *fakeStore) { s.createOffer.value = invitationOffer(newID) },
			status:  http.StatusCreated, want: line(invitationOfferJSON(newID)), calls: []string{call("admin")}},
		{name: "not found", method: http.MethodPost, target: target, body: body,
			program: func(s *fakeStore) { s.createOffer.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyOrgNotFound, logged: "org_not_found", calls: []string{call("member")}},
		{name: "the caller is not an administrator", method: http.MethodPost, target: target, body: body,
			program: func(s *fakeStore) { s.createOffer.err = store.ErrNotAdmin }, status: http.StatusForbidden,
			want: bodyNotAdmin, logged: "org_admin_required", calls: []string{call("member")}},
		{name: "a sandbox", method: http.MethodPost, target: target, body: body,
			program: func(s *fakeStore) { s.createOffer.err = store.ErrNotStandard }, status: http.StatusConflict,
			want: bodyNotStd, logged: "org_not_standard", calls: []string{call("member")}},
		{name: "a revoked organization", method: http.MethodPost, target: target, body: body,
			program: func(s *fakeStore) { s.createOffer.err = store.ErrInactive }, status: http.StatusConflict,
			want: bodyInactive, logged: "org_inactive", calls: []string{call("member")}},
		{name: "the user does not exist", method: http.MethodPost, target: target, body: body,
			program: func(s *fakeStore) { s.createOffer.err = store.ErrTargetNotFound }, status: http.StatusNotFound,
			want: bodyNoUser, logged: "offer_user_not_found", calls: []string{call("member")}},
		{name: "the user already belongs", method: http.MethodPost, target: target, body: body,
			program: func(s *fakeStore) { s.createOffer.err = store.ErrAlreadyMember }, status: http.StatusConflict,
			want: bodyAlready, logged: "org_already_member", calls: []string{call("member")}},
		{name: "the user already has an offer", method: http.MethodPost, target: target, body: body,
			program: func(s *fakeStore) { s.createOffer.err = store.ErrOfferExists }, status: http.StatusConflict,
			want: bodyExists, logged: "offer_exists", calls: []string{call("member")}},
	}

	cases = addFailures(cases, http.MethodPost, target, body, store.CodeOfferCreateFailed, []string{call("member")},
		func(s *fakeStore, err error) { s.createOffer.err = err })

	cases = append(cases, bodyFailures(http.MethodPost, target, []badBody{
		{name: "no user", body: `{"role":"member"}`, code: input.CodeInvalidID},
		{name: "a user that is not an id", body: `{"userId":"bob","role":"member"}`, code: input.CodeInvalidID},
		{name: "a user in upper case", body: `{"userId":"` + "01890000-0000-7000-8000-0000000000AA" + `","role":"member"}`,
			code: input.CodeInvalidID},
		{name: "no role", body: `{"userId":"` + otherID + `"}`, code: input.CodeInvalidOrgRole},
		{name: "a role that does not exist", body: `{"userId":"` + otherID + `","role":"owner"}`,
			code: input.CodeInvalidOrgRole},
		{name: "a role in upper case", body: `{"userId":"` + otherID + `","role":"Admin"}`, code: input.CodeInvalidOrgRole},
		{name: "an unknown field", body: `{"userId":"` + otherID + `","role":"member","orgId":"x"}`, code: "unknown_field"},
		{name: "an empty body", body: ``, code: "empty_body"},
	})...)

	runCases(t, cases)
}

// TestListOrgOffers: one page of an organization's offers, those to a user and
// those riding on an invitation.
func TestListOrgOffers(t *testing.T) {
	t.Parallel()

	target := "/api/org/" + orgID + "/offer"
	call := func(cursor string, limit int) string {
		return fmt.Sprintf("ListOrgOffers id=%s caller=%s role=%s cursor=%s limit=%d",
			orgID, userID, auth.RoleAdmin, cursor, limit)
	}

	cases := []routeCase{
		{name: "a page with a next", method: http.MethodGet, target: target,
			program: func(s *fakeStore) {
				s.orgOffers.value = store.OfferPage{
					Offers: []store.Offer{storedOffer(offerID), invitationOffer(newID)}, Next: newID,
				}
			},
			status: http.StatusOK,
			want: line(`{"offers":[` + offerJSON(offerID) + `,` + invitationOfferJSON(newID) +
				`],"next":"` + newID + `"}`),
			calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "the last page", method: http.MethodGet, target: target + "?limit=2&cursor=" + cursorID,
			program: func(s *fakeStore) { s.orgOffers.value = store.OfferPage{Offers: []store.Offer{storedOffer(offerID)}} },
			status:  http.StatusOK, want: line(`{"offers":[` + offerJSON(offerID) + `]}`),
			calls: []string{call(cursorID, 2)}},
		{name: "none is an empty list, not null", method: http.MethodGet, target: target,
			status: http.StatusOK, want: line(`{"offers":[]}`), calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "not found", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.orgOffers.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyOrgNotFound, logged: "org_not_found", calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "the caller is not an administrator", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.orgOffers.err = store.ErrNotAdmin }, status: http.StatusForbidden,
			want: bodyNotAdmin, logged: "org_admin_required", calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "a sandbox", method: http.MethodGet, target: target,
			program: func(s *fakeStore) { s.orgOffers.err = store.ErrNotStandard }, status: http.StatusConflict,
			want: bodyNotStd, logged: "org_not_standard", calls: []string{call("-", input.DefaultPageLimit)}},
	}

	cases = addFailures(cases, http.MethodGet, target, "", store.CodeOfferListFailed,
		[]string{call("-", input.DefaultPageLimit)}, func(s *fakeStore, err error) { s.orgOffers.err = err })

	cases = append(cases, queryFailures(target)...)

	runCases(t, cases)
}

// TestListMyOffers: one page of the offers addressed to the caller.
func TestListMyOffers(t *testing.T) {
	t.Parallel()

	call := func(cursor string, limit int) string {
		return fmt.Sprintf("ListMyOffers caller=%s cursor=%s limit=%d", userID, cursor, limit)
	}

	cases := []routeCase{
		{name: "a page", method: http.MethodGet, target: "/api/offer",
			program: func(s *fakeStore) { s.myOffers.value = store.OfferPage{Offers: []store.Offer{storedOffer(offerID)}} },
			status:  http.StatusOK, want: line(`{"offers":[` + offerJSON(offerID) + `]}`),
			calls: []string{call("-", input.DefaultPageLimit)}},
		{name: "a page after a cursor, with a next", method: http.MethodGet, target: "/api/offer?limit=1&cursor=" + cursorID,
			program: func(s *fakeStore) {
				s.myOffers.value = store.OfferPage{Offers: []store.Offer{storedOffer(offerID)}, Next: offerID}
			},
			status: http.StatusOK, want: line(`{"offers":[` + offerJSON(offerID) + `],"next":"` + offerID + `"}`),
			calls: []string{call(cursorID, 1)}},
		{name: "none is an empty list, not null", method: http.MethodGet, target: "/api/offer",
			status: http.StatusOK, want: line(`{"offers":[]}`), calls: []string{call("-", input.DefaultPageLimit)}},
	}

	cases = addFailures(cases, http.MethodGet, "/api/offer", "", store.CodeOfferListFailed,
		[]string{call("-", input.DefaultPageLimit)}, func(s *fakeStore, err error) { s.myOffers.err = err })

	cases = append(cases, queryFailures("/api/offer")...)

	runCases(t, cases)
}

// TestAcceptOffer: only the store knows whether the offer is the caller's, and a
// refusal of any kind is the store's.
func TestAcceptOffer(t *testing.T) {
	t.Parallel()

	target := "/api/offer/" + offerID + "/accept"
	call := fmt.Sprintf("AcceptOffer id=%s caller=%s at=%d", offerID, userID, now)

	cases := []routeCase{
		{name: "accepted", method: http.MethodPost, target: target,
			program: func(s *fakeStore) { s.accept.value = storedOffer(offerID) }, status: http.StatusOK,
			want: line(offerJSON(offerID)), calls: []string{call}},
		{name: "not found", method: http.MethodPost, target: target,
			program: func(s *fakeStore) { s.accept.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyOfferNotFound, logged: "offer_not_found", calls: []string{call}},
		{name: "the user already belongs to an organization", method: http.MethodPost, target: target,
			program: func(s *fakeStore) { s.accept.err = store.ErrAlreadyMember }, status: http.StatusConflict,
			want: bodyAlready, logged: "org_already_member", calls: []string{call}},
	}

	cases = addFailures(cases, http.MethodPost, target, "", store.CodeOfferAcceptFailed, []string{call},
		func(s *fakeStore, err error) { s.accept.err = err })

	cases = append(cases, bodyFailures(http.MethodPost, "/api/offer/x/accept", []badBody{
		{name: "an id that is not an id", body: "", code: input.CodeInvalidID},
	})...)

	runCases(t, cases)
}

// TestRevokeOffer: declining and withdrawing are one route, and what the caller
// may do is the store's to say.
func TestRevokeOffer(t *testing.T) {
	t.Parallel()

	target := "/api/offer/" + offerID
	call := fmt.Sprintf("RevokeOffer id=%s caller=%s role=%s", offerID, userID, auth.RoleAdmin)

	cases := []routeCase{
		{name: "declined or withdrawn", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.revokeOffer.value = storedOffer(offerID) }, status: http.StatusOK,
			want: line(offerJSON(offerID)), calls: []string{call}},
		{name: "an offer that rides on an invitation", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.revokeOffer.value = invitationOffer(offerID) }, status: http.StatusOK,
			want: line(invitationOfferJSON(offerID)), calls: []string{call}},
		{name: "a platform administrator", method: http.MethodDelete, target: target, role: roleAdmin,
			program: func(s *fakeStore) { s.revokeOffer.value = storedOffer(offerID) }, status: http.StatusOK,
			want: line(offerJSON(offerID)), calls: []string{call}},
		{name: "not found, or not the caller's", method: http.MethodDelete, target: target,
			program: func(s *fakeStore) { s.revokeOffer.err = store.ErrNotFound }, status: http.StatusNotFound,
			want: bodyOfferNotFound, logged: "offer_not_found", calls: []string{call}},
	}

	cases = addFailures(cases, http.MethodDelete, target, "", store.CodeOfferRevokeFailed, []string{call},
		func(s *fakeStore, err error) { s.revokeOffer.err = err })

	cases = append(cases, bodyFailures(http.MethodDelete, "/api/offer/"+offerID+"/", []badBody{})...)

	runCases(t, cases)
}
