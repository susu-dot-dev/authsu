package store

import (
	"context"
	"fmt"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Error codes of the offer operations. They are stable: clients and dashboards
// may match on them.
const (
	CodeOfferCreateFailed   = "offer_create_failed"
	CodeOfferCreateRejected = "offer_create_rejected"
	CodeOfferListFailed     = "offer_list_failed"
	CodeOfferListRejected   = "offer_list_rejected"
	CodeOfferAcceptFailed   = "offer_accept_failed"
	CodeOfferAcceptRejected = "offer_accept_rejected"
	CodeOfferRevokeFailed   = "offer_revoke_failed"
	CodeOfferRevokeRejected = "offer_revoke_rejected"
)

// Offer is an offer of a place in a standard organization, as stored: addressed
// to a user, or riding on an invitation.
type Offer struct {
	ID string

	// OrgID and OrgName are the organization offered.
	OrgID   string
	OrgName string

	// UserID is the user the offer is addressed to, or nil for an offer that
	// rides on an invitation. Exactly one of UserID and InvitationID is set.
	UserID *string

	// InvitationID is the invitation the offer rides on, or nil.
	InvitationID *string

	// Role is what the person becomes on joining: OfferRoleMember or
	// OfferRoleAdmin.
	Role string

	// CreatedBy is who made the offer.
	CreatedBy string

	// CreatedAt is in Unix seconds.
	CreatedAt int64
}

// readOffer reads one offer row, in the column order every offer statement
// selects or returns: id, org_id, org_name, user_id, invitation_id, role,
// created_by, created_at.
func readOffer(r *row) Offer {
	// Struct fields are evaluated in order, which is the column order.
	return Offer{
		ID: r.text(), OrgID: r.text(), OrgName: r.text(), UserID: r.optText(), InvitationID: r.optText(),
		Role: r.text(), CreatedBy: r.text(), CreatedAt: r.integer(),
	}
}

// offerReturning is the column list of an offer statement that has no join to
// take the organization's name from: RETURNING of a write to org_offers.
const offerReturning = `id, org_id, (SELECT g.name FROM orgs g WHERE g.id = org_offers.org_id) AS org_name,
       user_id, invitation_id, role, created_by, created_at`

// offerSelected is the column list of an offer statement over
// org_offers f JOIN orgs o.
const offerSelected = `f.id AS id, f.org_id AS org_id, o.name AS org_name, f.user_id AS user_id,
       f.invitation_id AS invitation_id, f.role AS role, f.created_by AS created_by, f.created_at AS created_at`

// insertOfferQuery offers a user a place in a standard organization, if the
// caller administers it. Every condition is part of the write:
//
//   - the organization is standard (a sandbox has no members) and not revoked,
//     and the caller administers it, or is a platform administrator;
//   - the user exists and is not revoked, and does not already belong to this
//     organization (belonging to another is allowed: the offer is accepted only
//     once they are free to join);
//   - the user has no offer from the organization already, which the
//     UNIQUE (org_id, user_id) would refuse too, but as a failure of the whole
//     batch that is not told apart from a defect.
//
// A conditional INSERT ... SELECT that matches nothing is not an error.
// RETURNING gives the row, and no row means the offer was refused, and
// offerStandingQuery in the same batch says why.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 offer id, ?5 role, ?6 created_at, ?7 user id, ?8 the
// standard kind.
const insertOfferQuery = `
INSERT INTO org_offers (id, org_id, user_id, role, created_by, created_at)
SELECT ?4, o.id, t.id, ?5, ?2, ?6
FROM orgs o
JOIN users t ON t.id = ?7
WHERE o.id = ?1 AND o.kind = ?8 AND o.revoked_at IS NULL
  AND ` + callerAdministersOrg + `
  AND t.revoked_at IS NULL
  AND (t.org_id IS NULL OR t.org_id <> o.id)
  AND NOT EXISTS (SELECT 1 FROM org_offers x WHERE x.org_id = o.id AND x.user_id = t.id)
RETURNING ` + offerReturning

// offerStandingQuery is the last statement of CreateOffer: why an offer was
// refused, read in the same batch from the state the write saw. No row is an
// organization the caller may not see.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 user id.
const offerStandingQuery = `
SELECT o.kind AS kind, o.revoked_at IS NOT NULL AS org_revoked, ` + callerAdministersOrg + ` AS administers,
       t.id IS NOT NULL AS target_exists, t.revoked_at IS NOT NULL AS target_revoked,
       COALESCE(t.org_id = o.id, 0) AS target_member,
       EXISTS (SELECT 1 FROM org_offers x WHERE x.org_id = o.id AND x.user_id = ?4) AS offer_exists
FROM orgs o
LEFT JOIN users t ON t.id = ?4
WHERE o.id = ?1 AND ` + callerSeesOrg

// NewOffer is an offer to a user to join a standard organization.
type NewOffer struct {
	// ID is the new offer's id.
	ID string

	// OrgID is the organization, and UserID the user it is offered to.
	OrgID  input.ID
	UserID input.ID

	// Role is what the user becomes on joining.
	Role input.OrgRole

	// Caller is the account making the offer, who must administer the
	// organization, or be a platform administrator (AdminRole).
	Caller    string
	AdminRole string

	// CreatedAt is when the offer is made.
	CreatedAt time.Time
}

// offerRefusal is why an offer was not written, as offerStandingQuery reads it.
type offerRefusal struct {
	kind          string
	orgRevoked    bool
	administers   bool
	targetExists  bool
	targetRevoked bool
	targetMember  bool
	offerExists   bool
}

// readOfferRefusal reads the columns of offerStandingQuery.
func readOfferRefusal(r *row) offerRefusal {
	// Struct fields are evaluated in order, which is the column order.
	return offerRefusal{
		kind: r.text(), orgRevoked: r.boolean(), administers: r.boolean(), targetExists: r.boolean(),
		targetRevoked: r.boolean(), targetMember: r.boolean(), offerExists: r.boolean(),
	}
}

// CreateOffer offers a user a place in a standard organization and returns the
// offer as stored. The conditions are in the write (see insertOfferQuery).
//
// It returns ErrNotFound when the caller may not see the organization, ErrNotAdmin
// when they can see it but do not administer it, ErrNotStandard when it is a
// sandbox, ErrInactive when it is revoked, ErrTargetNotFound when the user does
// not exist or is revoked, ErrAlreadyMember when they already belong to the
// organization and ErrOfferExists when they already have an offer from it. A
// write that matched nothing for any other reason is a defect.
func (s *Store) CreateOffer(ctx context.Context, offer NewOffer) (Offer, error) {
	o := op{failed: CodeOfferCreateFailed, rejected: CodeOfferCreateRejected, description: orgsDescription}

	return outcome(s.runChecked(ctx, o,
		Statement{Query: insertOfferQuery, Args: []any{
			offer.OrgID.String(), offer.Caller, offer.AdminRole, offer.ID, offer.Role.String(), offer.CreatedAt.Unix(),
			offer.UserID.String(), OrgKindStandard,
		}},
		Statement{Query: offerStandingQuery, Args: []any{
			offer.OrgID.String(), offer.Caller, offer.AdminRole, offer.UserID.String(),
		}},
	).
		Then(func(results []Result) (Offer, error) {
			return wroteOr(o, results[0].Rows, readOffer, func() (Offer, error) {
				return refusedBy[offerRefusal, Offer](o, results[1].Rows, readOfferRefusal,
					func(why found[offerRefusal]) error { return refusedOffer(o, why) })
			})
		}),
	)
}

// refusedOffer is the outcome of an offer the write did not take, read off its
// standing row.
func refusedOffer(o op, standing found[offerRefusal]) error {
	why := standing.value

	switch {
	case !standing.ok:
		return ErrNotFound
	case !why.administers:
		return ErrNotAdmin
	case why.kind != OrgKindStandard:
		return ErrNotStandard
	case why.orgRevoked:
		return ErrInactive
	case !why.targetExists || why.targetRevoked:
		return ErrTargetNotFound
	case why.targetMember:
		return ErrAlreadyMember
	case why.offerExists:
		return ErrOfferExists
	default:
		return o.defect(fmt.Errorf("%w: an offer matched nothing for no reason the batch can see", errChanges))
	}
}

// listOrgOffersQuery reads one page of the offers of a standard organization the
// caller administers, newest first, those addressed to a user and those riding
// on an invitation. The caller's standing is part of the match, so a caller who
// does not administer it gets no offer, whatever follows. A page asks for one
// row more than it returns.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 cursor (orgsFirstPage for the first page), ?5 rows
// wanted.
const listOrgOffersQuery = `
SELECT ` + offerSelected + `
FROM org_offers f
JOIN orgs o ON o.id = f.org_id
WHERE f.org_id = ?1 AND f.id < ?4 AND ` + callerAdministersOrg + `
ORDER BY f.id DESC
LIMIT ?5`

// OfferPage is one page of offers, newest first.
type OfferPage struct {
	Offers []Offer

	// Next is the cursor of the following page: the id of the last offer of
	// this one. It is empty on the last page.
	Next string
}

// ListOrgOffers returns up to limit of the offers of an organization the caller
// administers (or any, for a platform administrator), with an id below the
// cursor, newest first. The offers and why there may be none are read in the
// same batch.
//
// It returns ErrNotFound when the caller may not see the organization,
// ErrNotAdmin when they can see it but do not administer it, and ErrNotStandard
// when it is a sandbox.
func (s *Store) ListOrgOffers(
	ctx context.Context, id input.ID, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
) (OfferPage, error) {
	o := op{failed: CodeOfferListFailed, rejected: CodeOfferListRejected, description: orgsDescription}

	before, size := pageWindow(cursor, limit)

	return outcome(result.Of(s.run(ctx, o,
		Statement{Query: listOrgOffersQuery, Args: []any{id.String(), caller, adminRole, before, int64(size + 1)}},
		Statement{Query: orgStandingQuery, Args: []any{id.String(), caller, adminRole}},
	)).
		Then(func(results []Result) (OfferPage, error) {
			return lookup(results[1].Rows, o, readOrgStanding).
				Then(found[orgStanding].orNotFound).
				Check(offersVisible).
				Then(func(orgStanding) (OfferPage, error) { return offerPage(o, results[0].Rows, size) }).
				Get()
		}),
	)
}

// offersVisible is the guard of reading an organization's offers: the caller
// administers it, and it is a standard organization.
func offersVisible(standing orgStanding) error {
	if !standing.administer {
		return ErrNotAdmin
	}

	return standardOrg(standing.org)
}

// offerPage decodes the rows of an offer list and cuts the page (see paged).
func offerPage(o op, rows [][]any, size int) (OfferPage, error) {
	return pageOf(o, result.Of(all(rows, o, readOffer)), size, func(offer Offer) string { return offer.ID },
		func(offers []Offer, next string) OfferPage { return OfferPage{Offers: offers, Next: next} })
}

// listMyOffersQuery reads one page of the offers addressed to the caller,
// newest first. An offer of a revoked organization is not shown, though revoking
// deletes them, as accepting would refuse it. Arguments, by number: ?1 caller
// id, ?2 cursor (orgsFirstPage for the first page), ?3 rows wanted.
const listMyOffersQuery = `
SELECT ` + offerSelected + `
FROM org_offers f
JOIN orgs o ON o.id = f.org_id
WHERE f.user_id = ?1 AND f.id < ?2 AND o.revoked_at IS NULL
  AND EXISTS (SELECT 1 FROM users actor WHERE actor.id = ?1 AND actor.revoked_at IS NULL)
ORDER BY f.id DESC
LIMIT ?3`

// ListMyOffers returns up to limit of the offers addressed to the caller with an
// id below the cursor, newest first.
func (s *Store) ListMyOffers(
	ctx context.Context, caller string, cursor input.Cursor, limit input.PageLimit,
) (OfferPage, error) {
	o := op{failed: CodeOfferListFailed, rejected: CodeOfferListRejected, description: orgsDescription}

	before, size := pageWindow(cursor, limit)

	list := Statement{Query: listMyOffersQuery, Args: []any{caller, before, int64(size + 1)}}

	return outcome(result.Of(s.run(ctx, o, list)).
		Then(func(results []Result) (OfferPage, error) { return offerPage(o, results[0].Rows, size) }),
	)
}

// acceptStandingQuery is the first statement of AcceptOffer: the offer, if it is
// addressed to the caller, with what decides how it ends. It is read before the
// writes in the same batch, so it is the state they saw. No row is an offer that
// does not exist or is not the caller's, which is the same answer for both.
//
// Arguments, by number: ?1 offer id, ?2 caller id.
const acceptStandingQuery = `
SELECT ` + offerSelected + `,
       o.revoked_at IS NOT NULL AS org_revoked, u.org_id IS NOT NULL AS member, u.revoked_at IS NOT NULL AS revoked
FROM org_offers f
JOIN orgs o ON o.id = f.org_id
JOIN users u ON u.id = f.user_id
WHERE f.id = ?1 AND f.user_id = ?2`

// acceptOfferAdminQuery makes the caller an administrator of the organization an
// offer of the role ?4 gives them, if the offer is addressed to them, the
// organization is not revoked, and they are an unrevoked user who belongs to no
// organization. It is the first of the writes, so that it sees the user's
// organization as it was before acceptOfferQuery sets it: these are the same
// conditions as that statement's, over the same state, so the two take effect
// together or not at all.
//
// Arguments, by number: ?1 offer id, ?2 caller id, ?3 created_at, ?4 the
// administrator role of an offer.
const acceptOfferAdminQuery = `
INSERT INTO org_admins (org_id, user_id, created_at)
SELECT f.org_id, f.user_id, ?3
FROM org_offers f
JOIN orgs o ON o.id = f.org_id
JOIN users u ON u.id = f.user_id
WHERE f.id = ?1 AND f.user_id = ?2 AND f.role = ?4
  AND o.revoked_at IS NULL AND u.org_id IS NULL AND u.revoked_at IS NULL`

// acceptOfferQuery makes the caller a member of the organization an offer
// addressed to them offers, if it is not revoked as of this write and they
// belong to no organization. The condition is part of the write, which is what
// stops a user joining an organization just after it was revoked and released
// its members, and being stranded in one that no longer works. RETURNING gives
// a row when they joined.
//
// Arguments, by number: ?1 offer id, ?2 caller id.
const acceptOfferQuery = `
UPDATE users
SET org_id = (SELECT f.org_id FROM org_offers f WHERE f.id = ?1 AND f.user_id = ?2)
WHERE id = ?2 AND org_id IS NULL AND revoked_at IS NULL
  AND EXISTS (SELECT 1 FROM org_offers f JOIN orgs o ON o.id = f.org_id
              WHERE f.id = ?1 AND f.user_id = ?2 AND o.revoked_at IS NULL)
RETURNING org_id`

// acceptOfferDeleteQuery deletes an accepted offer: once the user belongs to the
// offered organization it means nothing. Its condition is the outcome of
// acceptOfferQuery, which is the one write that can have put the user in that
// organization when the batch began with an offer for it pending: the user is
// unrevoked and belongs to the offered organization, and it is not revoked. A
// user who joined nothing, because they belong to another organization, or the
// organization was revoked, matches none of it, and the offer is left (it is
// the refusal that is reported, and nothing changes).
//
// The one way this could match without the accept having joined is a user who
// already belonged to the offered organization while an offer to it was
// pending. That cannot arise: CreateOffer refuses a member of the organization
// and one offer per user and organization is unique, so the only way into the
// organization for an existing user is this offer. Were it ever to, the offer
// would be spent all the same. It deletes from org_offers only.
//
// Arguments, by number: ?1 offer id, ?2 caller id.
const acceptOfferDeleteQuery = `
DELETE FROM org_offers
WHERE id = ?1 AND user_id = ?2
  AND EXISTS (SELECT 1 FROM users u JOIN orgs o ON o.id = u.org_id
              WHERE u.id = ?2 AND u.org_id = org_offers.org_id AND u.revoked_at IS NULL AND o.revoked_at IS NULL)`

// acceptedOffer is an offer with what AcceptOffer needs to decide how it ended.
type acceptedOffer struct {
	offer      Offer
	orgRevoked bool
	member     bool
	revoked    bool
}

// readAcceptedOffer reads the columns of readOffer and then the three flags.
func readAcceptedOffer(r *row) acceptedOffer {
	offer := readOffer(r)

	return acceptedOffer{offer: offer, orgRevoked: r.boolean(), member: r.boolean(), revoked: r.boolean()}
}

// AcceptOffer accepts an offer addressed to the caller as one batch: they join
// the organization, become its administrator if the offer says so, and the offer
// is deleted. It returns the offer as it was.
//
// It returns ErrNotFound when the offer does not exist, is not addressed to the
// caller, is of an organization that is revoked, or the caller's account is
// revoked, and ErrAlreadyMember when the caller already belongs to an
// organization. Neither leaves anything changed.
func (s *Store) AcceptOffer(ctx context.Context, id input.ID, caller string, now time.Time) (Offer, error) {
	o := op{failed: CodeOfferAcceptFailed, rejected: CodeOfferAcceptRejected, description: orgsDescription}

	return outcome(s.runChecked(ctx, o,
		Statement{Query: acceptStandingQuery, Args: []any{id.String(), caller}},
		Statement{Query: acceptOfferAdminQuery, Args: []any{id.String(), caller, now.Unix(), OfferRoleAdmin}},
		Statement{Query: acceptOfferQuery, Args: []any{id.String(), caller}},
		Statement{Query: acceptOfferDeleteQuery, Args: []any{id.String(), caller}},
	).
		Then(func(results []Result) (Offer, error) {
			return lookup(results[0].Rows, o, readAcceptedOffer).
				Then(func(before found[acceptedOffer]) (Offer, error) {
					return applied(o, results[2].Rows).
						Then(func(joined bool) (Offer, error) { return offerAccepted(o, before, joined) }).
						Get()
				}).
				Get()
		}),
	)
}

// offerAccepted is the outcome of accepting an offer, read off the offer as the
// batch found it and whether the caller joined: the offer as it was, or why they
// did not.
func offerAccepted(o op, before found[acceptedOffer], joined bool) (Offer, error) {
	switch {
	case !before.ok:
		return Offer{}, ErrNotFound
	case joined:
		return before.value.offer, nil
	case before.value.orgRevoked || before.value.revoked:
		return Offer{}, ErrNotFound
	case before.value.member:
		return Offer{}, ErrAlreadyMember
	default:
		return Offer{}, o.defect(fmt.Errorf("%w: accepting matched nothing for no reason the batch can see", errChanges))
	}
}

// revokeOfferQuery deletes an offer, whether it is declined by the user it is
// addressed to or withdrawn by an administrator of its organization or a
// platform administrator, and whether it is addressed to a user or rides on an
// invitation (the invitation is never touched). The caller's standing is part of
// the delete, so an offer of someone else's is matched by nobody. RETURNING gives
// the offer as it was, and no row means the offer does not exist or the caller
// has no say in it, which is the same answer for both. It deletes from
// org_offers only.
//
// Arguments, by number: ?1 offer id, ?2 caller id, ?3 the platform
// administrator role.
const revokeOfferQuery = `
DELETE FROM org_offers
WHERE id = ?1
  AND (EXISTS (SELECT 1 FROM users actor WHERE actor.id = ?2 AND actor.revoked_at IS NULL
               AND actor.id = org_offers.user_id)
       OR ` + orgSubjectFrom + `org_offers.org_id` + callerAdministersOrgTo + `)
RETURNING ` + offerReturning

// RevokeOffer declines or withdraws an offer and returns it as it was. It
// returns ErrNotFound when there is no such offer or the caller is neither its
// addressee, nor an administrator of its organization, nor a platform
// administrator.
func (s *Store) RevokeOffer(ctx context.Context, id input.ID, caller, adminRole string) (Offer, error) {
	o := op{failed: CodeOfferRevokeFailed, rejected: CodeOfferRevokeRejected, description: orgsDescription}

	return outcome(result.Of(queryOne(ctx, s, o,
		Statement{Query: revokeOfferQuery, Args: []any{id.String(), caller, adminRole}}, readOffer)).
		MapErr(conflictIsDefect(o)),
	)
}
