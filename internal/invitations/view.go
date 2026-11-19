package invitations

import (
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Status is where an invitation stands now. It is derived from the row and the
// clock, never stored.
type Status string

// Statuses, in the order they are decided: a revoked invitation is revoked
// even if it has also expired or been used up, and an expired one is expired
// even if it is also used up.
const (
	// StatusRevoked means an admin revoked it, and the revocation has taken
	// effect: a revocation scheduled for later has not.
	StatusRevoked Status = "revoked"
	// StatusExpired means its expiry has passed.
	StatusExpired Status = "expired"
	// StatusExhausted means it has created as many accounts as it may.
	StatusExhausted Status = "exhausted"
	// StatusActive means it can still be redeemed.
	StatusActive Status = "active"
)

// Invitation is one invitation as an admin sees it. It never carries the token
// or its hash: the store does not select them, so nothing here could.
type Invitation struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	// NumInvites is how many accounts it may create.
	NumInvites int64 `json:"numInvites"`
	// Uses is how many accounts it has created: the users that point at it.
	Uses   int64  `json:"uses"`
	Status Status `json:"status"`
	// ExpiresAt is when it stops working, in Unix seconds. Every invitation
	// expires, so it is always present.
	ExpiresAt int64 `json:"expiresAt"`
	// RevokedAt and CreatedBy are absent when not set.
	RevokedAt *int64  `json:"revokedAt,omitempty"`
	CreatedBy *string `json:"createdBy,omitempty"`
	// CreatedAt is in Unix seconds.
	CreatedAt int64 `json:"createdAt"`
}

// statusAt returns the status of row at now. Revocation, expiry and the cap
// follow the same rules as the store's active predicate for secrets and its
// redemption query: a secret is active while (revoked_at IS NULL OR
// revoked_at > now) AND expires_at > now. So it is revoked once revoked_at <=
// now, and a revocation set for the future leaves it active until then; and it
// is expired at, not after, its expires_at.
func statusAt(row store.Invitation, now time.Time) Status {
	at := now.Unix()

	switch {
	case row.RevokedAt != nil && *row.RevokedAt <= at:
		return StatusRevoked
	case row.ExpiresAt <= at:
		return StatusExpired
	case row.Uses >= row.NumInvites:
		return StatusExhausted
	default:
		return StatusActive
	}
}

// present is the client's view of row, as of now.
func present(row store.Invitation, now time.Time) Invitation {
	return Invitation{
		ID: row.ID, Type: row.Type, Label: row.Label,
		NumInvites: row.NumInvites, Uses: row.Uses, Status: statusAt(row, now),
		ExpiresAt: row.ExpiresAt, RevokedAt: row.RevokedAt, CreatedBy: row.CreatedBy,
		CreatedAt: row.CreatedAt,
	}
}

// ListResponse is the body of GET /api/invitation.
type ListResponse struct {
	Invitations []Invitation `json:"invitations"`
}

// list answers GET /api/invitation. The order is the store's: newest first.
func (h *handlers) list(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(h.store.ListInvitations(call.Request.Context)).
		Map(func(rows []store.Invitation) httpapi.Response {
			now := h.now()
			out := ListResponse{Invitations: make([]Invitation, 0, len(rows))}

			for _, row := range rows {
				out.Invitations = append(out.Invitations, present(row, now))
			}

			return httpapi.JSON(http.StatusOK, out)
		})
}
