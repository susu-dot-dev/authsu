//nolint:goconst,prealloc // table-driven tests repeat case names and inputs, and append defect tables to their cases
package store_test

import (
	"context"
	"slices"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

const invitationTestID = "01890000-0000-7000-8000-0000000000e1"

// offerRowOf is the row of an offer: id, org_id, org_name, user_id,
// invitation_id, role, created_by, created_at.
func offerRowOf(id string, user, invitation any, role string) []any {
	return row(id, orgTestID, "Acme", user, invitation, role, targetID, int64(1_700_000_002))
}

// userOffer is an offer to callerID, and invitationOffer one riding on an
// invitation.
func userOffer() []any { return offerRowOf(offerTestI, callerID, nil, store.OfferRoleMember) }
func invitationOffer() []any {
	return offerRowOf(offerTestI, nil, invitationTestID, store.OfferRoleAdmin)
}

// offerKinds are the column kinds of an offer row, for defectResults.
func offerKinds() []string {
	return []string{"text", "text", "text", "optText", "optText", "text", "text", "integer"}
}

// wantUserOffer and wantInvitationOffer are what the rows above decode to.
func wantUserOffer() store.Offer {
	user := callerID

	return store.Offer{
		ID: offerTestI, OrgID: orgTestID, OrgName: "Acme", UserID: &user, Role: store.OfferRoleMember,
		CreatedBy: targetID, CreatedAt: 1_700_000_002,
	}
}

func wantInvitationOffer() store.Offer {
	invitation := invitationTestID

	return store.Offer{
		ID: offerTestI, OrgID: orgTestID, OrgName: "Acme", InvitationID: &invitation, Role: store.OfferRoleAdmin,
		CreatedBy: targetID, CreatedAt: 1_700_000_002,
	}
}

// refusalRow is the row of the standing statement of CreateOffer: kind,
// org_revoked, administers, target_exists, target_revoked, target_member,
// offer_exists.
func refusalRow(kind string, flags ...int64) []any {
	out := []any{kind}
	for _, flag := range flags {
		out = append(out, flag)
	}

	return out
}

// TestCreateOffer: the row the insert returned is the offer, and otherwise the
// standing statement says why, in an order that tells the caller no more than
// they may know.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestCreateOffer(t *testing.T) {
	t.Parallel()

	call := func(s *store.Store) (store.Offer, error) {
		return s.CreateOffer(context.Background(), store.NewOffer{
			ID: offerTestI, OrgID: mustUserID(t, orgTestID), UserID: mustUserID(t, targetID),
			Role: orgRoleOf(t, store.OfferRoleAdmin), Caller: callerID, AdminRole: adminRole, CreatedAt: now,
		})
	}

	standard := store.OrgKindStandard

	// flags are org_revoked, administers, target_exists, target_revoked,
	// target_member and offer_exists.
	refused := func(kind string, flags ...int64) outcome {
		return batchOf(2, map[int][][]any{1: {refusalRow(kind, flags...)}})
	}

	cases := []opCase[store.Offer]{
		{name: "an offer to a user", out: batchOf(2, map[int][][]any{0: {userOffer()}}), want: wantUserOffer()},
		{name: "the standing is not read when it was written", out: batchOf(2, map[int][][]any{
			0: {userOffer()}, 1: {refusalRow(standard, 0, 0, 0, 0, 0, 0)},
		}), want: wantUserOffer()},
		{name: "the caller may not see the organization", out: batchOf(2, nil), err: store.ErrNotFound},
		{name: "the caller does not administer it", out: refused(standard, 0, 0, 1, 0, 0, 0), err: store.ErrNotAdmin},
		{name: "not administering is told before anything about the user", out: refused(standard, 0, 0, 0, 1, 1, 1),
			err: store.ErrNotAdmin},
		{name: "a sandbox", out: refused(store.OrgKindSandbox, 0, 1, 1, 0, 0, 0), err: store.ErrNotStandard},
		{name: "a revoked organization", out: refused(standard, 1, 1, 1, 0, 0, 0), err: store.ErrInactive},
		{name: "a user who does not exist", out: refused(standard, 0, 1, 0, 0, 0, 0), err: store.ErrTargetNotFound},
		{name: "a user who is revoked", out: refused(standard, 0, 1, 1, 1, 0, 0), err: store.ErrTargetNotFound},
		{name: "a user who is already a member", out: refused(standard, 0, 1, 1, 0, 1, 0), err: store.ErrAlreadyMember},
		{name: "a user who already has an offer", out: refused(standard, 0, 1, 1, 0, 0, 1), err: store.ErrOfferExists},
		{name: "a member with an offer is a member first", out: refused(standard, 0, 1, 1, 0, 1, 1),
			err: store.ErrAlreadyMember},
		{name: "refused for no reason the batch can see is a defect", out: refused(standard, 0, 1, 1, 0, 0, 0),
			defect: true},
		{name: "two rows for one id", out: batchOf(2, map[int][][]any{0: {userOffer(), userOffer()}}), defect: true},
		{name: "a refusal that is not a flag", out: refused(standard, 0, 2, 1, 0, 0, 0), defect: true},
		{name: "two refusal rows", out: batchOf(2, map[int][][]any{
			1: {refusalRow(standard, 0, 1, 1, 0, 0, 0), refusalRow(standard, 0, 1, 1, 0, 0, 0)},
		}), defect: true},
	}

	cases = append(cases, rowDefectCases[store.Offer](2, 0, userOffer(), offerKinds()...)...)

	for name, rows := range defectResults(refusalRow(standard, 0, 1, 1, 0, 0, 0),
		"text", "integer", "integer", "integer", "integer", "integer", "integer") {
		cases = append(cases, opCase[store.Offer]{name: "a defective refusal: " + name,
			out: batchOf(2, map[int][][]any{1: rows}), defect: true})
	}

	runOpCases(t, cases, store.CodeOfferCreateRejected, call)

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(batchOf(2, map[int][][]any{0: {userOffer()}}))

		_, err := call(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: append([]string{
					"INSERT INTO org_offers (id, org_id, user_id, role, created_by, created_at) SELECT ?4, o.id, t.id, ?5, ?2, ?6",
					"FROM orgs o JOIN users t ON t.id = ?7",
					// A sandbox, which has no members, and a revoked organization are
					// never offered.
					"WHERE o.id = ?1 AND o.kind = ?8 AND o.revoked_at IS NULL AND",
					// The user exists, is not revoked, does not belong to this
					// organization and has no offer from it.
					"AND t.revoked_at IS NULL AND (t.org_id IS NULL OR t.org_id <> o.id) AND NOT EXISTS " +
						"(SELECT 1 FROM org_offers x WHERE x.org_id = o.id AND x.user_id = t.id)",
					"RETURNING id, org_id, (SELECT g.name FROM orgs g WHERE g.id = org_offers.org_id) AS org_name, " +
						"user_id, invitation_id, role, created_by, created_at",
				}, administersFragments...),
				args: []any{
					orgTestID, callerID, adminRole, offerTestI, store.OfferRoleAdmin, now.Unix(), targetID,
					store.OrgKindStandard,
				},
			},
			wantStatement{
				fragments: append([]string{
					"o.kind AS kind, o.revoked_at IS NOT NULL AS org_revoked,",
					"AS administers, t.id IS NOT NULL AS target_exists, t.revoked_at IS NOT NULL AS target_revoked",
					"COALESCE(t.org_id = o.id, 0) AS target_member",
					"EXISTS (SELECT 1 FROM org_offers x WHERE x.org_id = o.id AND x.user_id = ?4) AS offer_exists",
					"FROM orgs o LEFT JOIN users t ON t.id = ?4 WHERE o.id = ?1 AND",
				}, seesFragments...),
				args: []any{orgTestID, callerID, adminRole, targetID},
			},
		)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runOpFailures(t, 2, store.CodeOfferCreateFailed, store.CodeOfferCreateRejected,
			func(s *store.Store) error { return lastErr(call(s)) })
	})
}

// TestListOrgOffers: the offers and the organization's standing are read in
// one batch, and the standing decides first.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestListOrgOffers(t *testing.T) {
	t.Parallel()

	listing := func(size string, cursor ...string) func(*store.Store) (store.OfferPage, error) {
		return func(s *store.Store) (store.OfferPage, error) {
			return s.ListOrgOffers(context.Background(), mustUserID(t, orgTestID), callerID, adminRole,
				orgCursorOf(t, cursor...), orgLimitOf(t, size))
		}
	}

	listed := func(rows ...[]any) outcome {
		return batchOf(2, map[int][][]any{0: rows, 1: {standing(standardRow(), 1)}})
	}

	second := offerRowOf("01890000-0000-7000-8000-0000000000c0", callerID, nil, store.OfferRoleMember)

	cases := []opCase[store.OfferPage]{
		{name: "none is an empty page, not nil", out: listed(), want: store.OfferPage{Offers: []store.Offer{}}},
		{name: "an offer to a user and one on an invitation", out: listed(userOffer(), invitationOffer()),
			want: store.OfferPage{Offers: []store.Offer{wantUserOffer(), wantInvitationOffer()}}},
		{name: "one more than the page has a next", out: listed(userOffer(), invitationOffer(), second),
			want: store.OfferPage{Offers: []store.Offer{wantUserOffer(), wantInvitationOffer()}, Next: offerTestI}},
		{name: "the caller may not see the organization", out: batchOf(2, map[int][][]any{0: {userOffer()}}),
			err: store.ErrNotFound},
		{name: "the caller sees it and does not administer it", out: batchOf(2, map[int][][]any{
			0: {userOffer()}, 1: {standing(standardRow(), 0)},
		}), err: store.ErrNotAdmin},
		{name: "a sandbox", out: batchOf(2, map[int][][]any{1: {standing(sandboxRow(longAt), 1)}}),
			err: store.ErrNotStandard},
		{name: "more rows than were asked for", out: listed(userOffer(), userOffer(), userOffer(), userOffer()),
			defect: true},
	}

	for name, rows := range defectResults(userOffer(), offerKinds()...) {
		if name == "two rows" {
			continue
		}

		cases = append(cases, opCase[store.OfferPage]{name: "a defective offer row: " + name, out: listed(rows...),
			defect: true})
	}

	for name, rows := range defectResults(standing(standardRow(), 1), append(orgKinds(), "integer")...) {
		cases = append(cases, opCase[store.OfferPage]{name: "a defective standing: " + name,
			out: batchOf(2, map[int][][]any{1: rows}), defect: true})
	}

	runOpCases(t, cases, store.CodeOfferListRejected, listing("2"))

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(listed())

		_, err := listing("25", orgTestID)(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: append([]string{
					"FROM org_offers f JOIN orgs o ON o.id = f.org_id WHERE f.org_id = ?1 AND f.id < ?4 AND",
					"ORDER BY f.id DESC LIMIT ?5",
				}, administersFragments...),
				args: []any{orgTestID, callerID, adminRole, orgTestID, int64(26)},
			},
			wantStatement{
				fragments: []string{"AS administers FROM orgs o WHERE o.id = ?1 AND"},
				args:      []any{orgTestID, callerID, adminRole},
			},
		)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runFailures(t, 2, store.CodeOfferListFailed, store.CodeOfferListRejected, orgsDescription,
			func(s *store.Store) error { return lastErr(listing("2")(s)) })
	})
}

// TestListMyOffers: the caller's own offers, a page of them.
func TestListMyOffers(t *testing.T) {
	t.Parallel()

	listing := func(size string, cursor ...string) func(*store.Store) (store.OfferPage, error) {
		return func(s *store.Store) (store.OfferPage, error) {
			return s.ListMyOffers(context.Background(), callerID, orgCursorOf(t, cursor...), orgLimitOf(t, size))
		}
	}

	second := offerRowOf("01890000-0000-7000-8000-0000000000c0", callerID, nil, store.OfferRoleMember)

	cases := []opCase[store.OfferPage]{
		{name: "none is an empty page, not nil", out: returning(), want: store.OfferPage{Offers: []store.Offer{}}},
		{name: "an offer", out: returning(userOffer()), want: store.OfferPage{Offers: []store.Offer{wantUserOffer()}}},
		{name: "one more than the page has a next", out: returning(userOffer(), second, userOffer()),
			want: store.OfferPage{Offers: []store.Offer{wantUserOffer(), {
				ID: "01890000-0000-7000-8000-0000000000c0", OrgID: orgTestID, OrgName: "Acme", UserID: &[]string{callerID}[0],
				Role: store.OfferRoleMember, CreatedBy: targetID, CreatedAt: 1_700_000_002,
			}}, Next: "01890000-0000-7000-8000-0000000000c0"}},
		{name: "more rows than were asked for", out: returning(userOffer(), userOffer(), userOffer(), userOffer()),
			defect: true},
	}

	for name, rows := range defectResults(userOffer(), offerKinds()...) {
		if name == "two rows" {
			continue
		}

		cases = append(cases, opCase[store.OfferPage]{name: "a defective row: " + name, out: returning(rows...),
			defect: true})
	}

	runOpCases(t, cases, store.CodeOfferListRejected, listing("2"))

	t.Run("the statement", func(t *testing.T) {
		t.Parallel()

		fake := newFake(returning())

		_, err := listing("25", orgTestID)(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake, wantStatement{
			fragments: []string{
				// The caller's own offers, of organizations that are not revoked, while
				// the account is not.
				"FROM org_offers f JOIN orgs o ON o.id = f.org_id WHERE f.user_id = ?1 AND f.id < ?2 " +
					"AND o.revoked_at IS NULL AND EXISTS (SELECT 1 FROM users actor WHERE actor.id = ?1 " +
					"AND actor.revoked_at IS NULL)",
				"ORDER BY f.id DESC LIMIT ?3",
			},
			args: []any{callerID, orgTestID, int64(26)},
		})
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runFailures(t, 1, store.CodeOfferListFailed, store.CodeOfferListRejected, orgsDescription,
			func(s *store.Store) error { return lastErr(listing("2")(s)) })
	})
}

// acceptingRow is the standing statement's row of AcceptOffer: the offer, and
// whether its organization is revoked, the user belongs to an organization, and
// the user is revoked.
func acceptingRow(offer []any, orgRevoked, member, revoked int64) []any {
	return append(slices.Clip(offer), orgRevoked, member, revoked)
}

// TestAcceptOffer: the standing before the writes and the row the join returned
// say what happened.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestAcceptOffer(t *testing.T) {
	t.Parallel()

	call := func(s *store.Store) (store.Offer, error) {
		return s.AcceptOffer(context.Background(), mustUserID(t, offerTestI), callerID, now)
	}

	// batch is the four statements: the standing, the administrator insert, the
	// join and the delete.
	batch := func(standing []any, joined bool) outcome {
		joins := [][]any(nil)
		if joined {
			joins = [][]any{row(orgTestID)}
		}

		return batchOf(4, map[int][][]any{0: {standing}, 2: joins})
	}

	cases := []opCase[store.Offer]{
		{name: "accepted", out: batch(acceptingRow(userOffer(), 0, 0, 0), true), want: wantUserOffer()},
		{name: "accepted as an administrator", out: batch(acceptingRow(
			offerRowOf(offerTestI, callerID, nil, store.OfferRoleAdmin), 0, 0, 0), true),
			want: func() store.Offer { offer := wantUserOffer(); offer.Role = store.OfferRoleAdmin; return offer }()},
		{name: "no such offer, or not the caller's", out: batchOf(4, nil), err: store.ErrNotFound},
		{name: "a join without an offer is not read", out: batchOf(4, map[int][][]any{2: {row(orgTestID)}}),
			err: store.ErrNotFound},
		{name: "the organization was revoked", out: batch(acceptingRow(userOffer(), 1, 0, 0), false),
			err: store.ErrNotFound},
		{name: "the account is revoked", out: batch(acceptingRow(userOffer(), 0, 0, 1), false), err: store.ErrNotFound},
		{name: "the user belongs to an organization", out: batch(acceptingRow(userOffer(), 0, 1, 0), false),
			err: store.ErrAlreadyMember},
		{name: "revoked organization and a member: not found", out: batch(acceptingRow(userOffer(), 1, 1, 0), false),
			err: store.ErrNotFound},
		{name: "refused for no reason the batch can see is a defect", out: batch(acceptingRow(userOffer(), 0, 0, 0), false),
			defect: true},
		{name: "a flag that is not a flag", out: batch(acceptingRow(userOffer(), 2, 0, 0), true), defect: true},
		{name: "a join that is not an id", out: batchOf(4, map[int][][]any{
			0: {acceptingRow(userOffer(), 0, 0, 0)}, 2: {row(int64(1))},
		}), defect: true},
		{name: "two joined rows", out: batchOf(4, map[int][][]any{
			0: {acceptingRow(userOffer(), 0, 0, 0)}, 2: {row(orgTestID), row(orgTestID)},
		}), defect: true},
	}

	for name, rows := range defectResults(acceptingRow(userOffer(), 0, 0, 0),
		append(offerKinds(), "integer", "integer", "integer")...) {
		cases = append(cases, opCase[store.Offer]{name: "a defective standing: " + name,
			out: batchOf(4, map[int][][]any{0: rows, 2: {row(orgTestID)}}), defect: true})
	}

	runOpCases(t, cases, store.CodeOfferAcceptRejected, call)

	t.Run("the statements", func(t *testing.T) {
		t.Parallel()

		fake := newFake(batch(acceptingRow(userOffer(), 0, 0, 0), true))

		_, err := call(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake,
			wantStatement{
				fragments: []string{
					"FROM org_offers f JOIN orgs o ON o.id = f.org_id JOIN users u ON u.id = f.user_id",
					"WHERE f.id = ?1 AND f.user_id = ?2",
					"o.revoked_at IS NOT NULL AS org_revoked, u.org_id IS NOT NULL AS member, u.revoked_at IS NOT NULL AS revoked",
				},
				args: []any{offerTestI, callerID},
			},
			wantStatement{
				fragments: []string{
					// The administrator row is written first, on the same conditions as
					// the join, over the state before it: the offer is the caller's and
					// says admin, the organization is not revoked, and the user belongs
					// to none.
					"INSERT INTO org_admins (org_id, user_id, created_at) SELECT f.org_id, f.user_id, ?3",
					"WHERE f.id = ?1 AND f.user_id = ?2 AND f.role = ?4",
					"AND o.revoked_at IS NULL AND u.org_id IS NULL AND u.revoked_at IS NULL",
				},
				args: []any{offerTestI, callerID, now.Unix(), store.OfferRoleAdmin},
			},
			wantStatement{
				fragments: []string{
					"UPDATE users SET org_id = (SELECT f.org_id FROM org_offers f WHERE f.id = ?1 AND f.user_id = ?2)",
					// The join requires the organization to be active in the write
					// itself, so a user cannot join one just after it released its members.
					"WHERE id = ?2 AND org_id IS NULL AND revoked_at IS NULL",
					"AND EXISTS (SELECT 1 FROM org_offers f JOIN orgs o ON o.id = f.org_id " +
						"WHERE f.id = ?1 AND f.user_id = ?2 AND o.revoked_at IS NULL)",
					"RETURNING org_id",
				},
				args: []any{offerTestI, callerID},
			},
			wantStatement{
				fragments: []string{
					"DELETE FROM org_offers WHERE id = ?1 AND user_id = ?2",
					// Only once the caller belongs to the offered organization, which
					// is active and they are not revoked: what the join leaves.
					"AND EXISTS (SELECT 1 FROM users u JOIN orgs o ON o.id = u.org_id " +
						"WHERE u.id = ?2 AND u.org_id = org_offers.org_id AND u.revoked_at IS NULL AND o.revoked_at IS NULL)",
				},
				args: []any{offerTestI, callerID},
			},
		)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runOpFailures(t, 4, store.CodeOfferAcceptFailed, store.CodeOfferAcceptRejected,
			func(s *store.Store) error { return lastErr(call(s)) })
	})
}

// TestRevokeOffer: the offer as it was, or not found.
func TestRevokeOffer(t *testing.T) {
	t.Parallel()

	call := func(s *store.Store) (store.Offer, error) {
		return s.RevokeOffer(context.Background(), mustUserID(t, offerTestI), callerID, adminRole)
	}

	cases := []opCase[store.Offer]{
		{name: "an offer to a user", out: returning(userOffer()), want: wantUserOffer()},
		{name: "an offer on an invitation", out: returning(invitationOffer()), want: wantInvitationOffer()},
		{name: "none the caller has a say in", out: returning(), err: store.ErrNotFound},
	}

	for name, rows := range defectResults(userOffer(), offerKinds()...) {
		cases = append(cases, opCase[store.Offer]{name: "a defective row: " + name, out: returning(rows...),
			defect: true})
	}

	runOpCases(t, cases, store.CodeOfferRevokeRejected, call)

	t.Run("the statement", func(t *testing.T) {
		t.Parallel()

		fake := newFake(returning(userOffer()))

		_, err := call(fake.store())
		checkErr(t, err, nil)

		checkNumberedStatements(t, fake, wantStatement{
			fragments: append([]string{
				"DELETE FROM org_offers WHERE id = ?1",
				// The addressee declines; an administrator of its organization or a
				// platform administrator withdraws; nobody else has a say.
				"AND (EXISTS (SELECT 1 FROM users actor WHERE actor.id = ?2 AND actor.revoked_at IS NULL " +
					"AND actor.id = org_offers.user_id) OR",
				"RETURNING id, org_id, (SELECT g.name FROM orgs g WHERE g.id = org_offers.org_id) AS org_name",
			}, administersOf("org_offers.org_id")...),
			args: []any{offerTestI, callerID, adminRole},
		})
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runDefectFailures(t, 1, store.CodeOfferRevokeFailed, store.CodeOfferRevokeRejected, orgsDescription,
			func(s *store.Store) error { return lastErr(call(s)) })
	})
}
