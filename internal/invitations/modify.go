package invitations

import (
	"errors"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Error codes of the update and revoke routes. They are stable.
const (
	// CodeNotFound is an id no invitation has.
	CodeNotFound = "invitation_not_found"
	// CodeRevoked is an update of a revoked invitation, which is final.
	CodeRevoked = "invitation_revoked"
	// CodeBelowUses is a cap under the accounts the invitation already created.
	// Its data carries {"uses": n}.
	CodeBelowUses = "num_invites_below_uses"
	// CodeMissingNumInvites is an update without numInvites.
	CodeMissingNumInvites = "missing_num_invites"
)

// updateBody is the body of PATCH /api/invitation/{id}, as the client sent it.
// It is a pointer so that a missing field is told from a zero.
type updateBody struct {
	NumInvites *int64 `json:"numInvites"`
}

// update answers PATCH /api/invitation/{id}.
//
// The write is one statement that reports its own outcome: the row it was aimed
// at, and whether the change applied (see the store). Whether it applied, the
// row and its count of accounts are all the same instant, so a registration or
// a revocation cannot land between the write and its explanation, and there is
// no second read.
func (h *handlers) update(call *auth.Call) result.Result[httpapi.Response] {
	id := call.ID()

	return httpapi.Decode[updateBody](call.Request).
		Then(parseUpdate).
		Then(func(n input.NumInvites) (Invitation, error) {
			row, applied, err := h.store.UpdateNumInvites(call.Request.Context, id, n)
			if err != nil {
				return Invitation{}, missing(err)
			}

			if !applied {
				return Invitation{}, refusal(row)
			}

			return present(row, h.now()), nil
		}).
		Map(func(out Invitation) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// parseUpdate requires numInvites and parses it.
func parseUpdate(body updateBody) (input.NumInvites, error) {
	if body.NumInvites == nil {
		return input.NumInvites{}, missingNumInvites()
	}

	return input.ParseNumInvites(*body.NumInvites) //nolint:wrapcheck // the parser's error is the classified client error
}

// missingNumInvites is the refusal of an update that sets nothing.
func missingNumInvites() *apierr.Error {
	return apierr.New(apierr.BadRequest, CodeMissingNumInvites, "numInvites is required")
}

// refusal says why a conditional update did not apply, from the row the
// statement returned. Its own test failed on that row, so exactly one of two
// things is true of it: the invitation was revoked, or it had created more
// accounts than the new cap allows. A revoked invitation is reported as revoked
// whatever its uses.
func refusal(row store.Invitation) *apierr.Error {
	if row.RevokedAt != nil {
		return apierr.New(apierr.Conflict, CodeRevoked, "the invitation is revoked and cannot be changed")
	}

	return apierr.New(apierr.Conflict, CodeBelowUses,
		"numInvites is below the number of accounts this invitation has already created").
		WithData(map[string]int64{"uses": row.Uses})
}

// missing maps the store's absence to 404. Any other failure is already
// classified by the store and passes through.
func missing(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return apierr.Wrap(err, apierr.NotFound, CodeNotFound, "no such invitation")
	}

	return err
}

// revoke answers DELETE /api/invitation/{id}. Revoking one that is already
// revoked succeeds and reports the earlier revocation, which the store keeps:
// the call is idempotent, and a retry cannot move the revocation later. The row
// comes from the write itself, so there is no read after it to disagree with it.
func (h *handlers) revoke(call *auth.Call) result.Result[httpapi.Response] {
	now := h.now()

	return result.Of(h.store.RevokeInvitation(call.Request.Context, call.ID(), now)).
		MapErr(missing).
		Map(func(row store.Invitation) httpapi.Response { return httpapi.JSON(http.StatusOK, present(row, now)) })
}
