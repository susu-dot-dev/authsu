package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Error codes of the organization operations. They are stable: clients and
// dashboards may match on them.
const (
	CodeOrgCreateFailed   = "org_create_failed"
	CodeOrgCreateRejected = "org_create_rejected"
	CodeOrgListFailed     = "org_list_failed"
	CodeOrgListRejected   = "org_list_rejected"
	CodeOrgLookupFailed   = "org_lookup_failed"
	CodeOrgLookupRejected = "org_lookup_rejected"
	CodeOrgUpdateFailed   = "org_update_failed"
	CodeOrgUpdateRejected = "org_update_rejected"
	CodeOrgRevokeFailed   = "org_revoke_failed"
	CodeOrgRevokeRejected = "org_revoke_rejected"
)

// orgsDescription is the client-safe text of every organization operation's
// Unavailable error. Members and offers use it too.
const orgsDescription = "organizations are temporarily unavailable"

// orgsFirstPage is the cursor bound of the first page of an organization, member
// or offer list: every id is below it (see agentsFirstPage). It is internal:
// callers pass an input.Cursor, which is empty for the first page.
const orgsFirstPage = "g"

// The outcomes of the organization, member and offer operations that are the
// state the request met and not a failure. A feature maps each to its client
// code; the operations return them as they are.
var (
	// ErrAccountRevoked means the account that is acting was revoked after its
	// request was authenticated, so nothing was written.
	ErrAccountRevoked = errors.New("the account is revoked")

	// ErrAlreadyMember means the account already belongs to an organization,
	// so it can neither create a standard one nor join another.
	ErrAlreadyMember = errors.New("the account already belongs to an organization")

	// ErrOrgLimit means the account has reached the limit on what it may
	// create: the most standard organizations it may ever create, or the most
	// sandboxes it may hold that have not expired.
	ErrOrgLimit = errors.New("the account has reached the limit of what it may create")

	// ErrNotAdmin means the caller can see the organization but does not
	// administer it, and is not a platform administrator.
	ErrNotAdmin = errors.New("the caller does not administer the organization")

	// ErrInactive means the organization is revoked, or is a sandbox that has
	// expired, and so cannot be changed.
	ErrInactive = errors.New("the organization is revoked or has expired")

	// ErrNotStandard means the organization is a sandbox, which has no members
	// and receives no offers.
	ErrNotStandard = errors.New("the organization is a sandbox")

	// ErrLastOrgAdmin means the change would leave a standard organization
	// without an unrevoked administrator.
	ErrLastOrgAdmin = errors.New("the last unrevoked administrator of the organization cannot be removed")

	// ErrOfferExists means the user already has an offer from the organization.
	ErrOfferExists = errors.New("the user already has an offer from the organization")

	// ErrTargetNotFound means the user an offer is addressed to does not
	// exist or is revoked.
	ErrTargetNotFound = errors.New("the user to offer a place to was not found")
)

// Org is an organization or a sandbox as stored.
type Org struct {
	ID string

	// Kind is OrgKindStandard or OrgKindSandbox.
	Kind string
	Name string

	// CreatedBy is the user who made it.
	CreatedBy string

	// ExpiresAt is when a sandbox stops working, in Unix seconds, and nil for a
	// standard organization.
	ExpiresAt *int64

	// RevokedAt is when a standard organization was revoked, in Unix seconds,
	// and nil while it is not (and always for a sandbox).
	RevokedAt *int64

	// CreatedAt is in Unix seconds.
	CreatedAt int64
}

// Active reports whether the organization works at now: a standard one is not
// revoked, and a sandbox has not expired. It is the Go reading of the
// condition every write that needs an active organization states in SQL.
func (o Org) Active(now time.Time) bool {
	return o.RevokedAt == nil && (o.ExpiresAt == nil || *o.ExpiresAt > now.Unix())
}

// readOrg reads one organization row, in the column order every organization
// statement selects or returns: id, kind, name, created_by, expires_at,
// revoked_at, created_at.
func readOrg(r *row) Org {
	// Struct fields are evaluated in order, which is the column order.
	return Org{
		ID: r.text(), Kind: r.text(), Name: r.text(), CreatedBy: r.text(),
		ExpiresAt: r.optInteger(), RevokedAt: r.optInteger(), CreatedAt: r.integer(),
	}
}

// orgStanding is an organization with whether the caller administers it, as the
// diagnosis statements that follow a conditional write read it.
type orgStanding struct {
	org        Org
	administer bool
}

// readOrgStanding reads the columns of readOrg and then administers.
func readOrgStanding(r *row) orgStanding {
	org := readOrg(r)

	return orgStanding{org: org, administer: r.boolean()}
}

// The conditions every organization write states about who is acting, as SQL
// text to be concatenated into a statement. They are part of the write and not
// a read before it, because D1 has no interactive transaction (docs/DATABASE.md):
// a read could be stale by the time the write ran.
//
// Each reads the caller's account and requires it to be unrevoked, so an
// account revoked after its request was authenticated does nothing. A platform
// administrator is the caller whose role is the one bound as ?3 (which role
// administers is defined in a higher layer, as for RevokeUser) and has the full
// override: whatever an organization's administrator may do, on any
// organization. Every statement that includes one binds the caller's id as ?2
// and that role as ?3.
//
// Who may see and who may administer an organization is stated once, here, and
// every statement that asks it of an organization, whatever it calls it, is built
// from the same text. Each condition is two halves with the SQL expression that
// names the organization between them (orgSubject), so that expression appears
// once in a statement and the condition is never written again by hand, which is
// how the places that ask it would come to disagree. A statement about the
// organization with the id ?1 uses callerSeesOrg or callerAdministersOrg; one
// about a user's own organization (members.go) or an offer's (offers.go) puts
// that column between the halves (callerSeesTargetOrg and the others there).
const (
	// orgSubjectFrom opens both conditions, and the expression naming the
	// organization they are about follows it: a one-row table, so that the
	// condition after it can name the organization as subject.org_id.
	orgSubjectFrom = `EXISTS (SELECT 1 FROM (SELECT `

	// callerSeesOrgTo closes the condition that the caller may see the
	// organization: belongs to it, administers it, or is a platform
	// administrator. A sandbox's administrator does not belong to it, and sees
	// it as its administrator.
	callerSeesOrgTo = ` AS org_id) subject, users actor WHERE actor.id = ?2 AND actor.revoked_at IS NULL
    AND (actor.role = ?3 OR actor.org_id = subject.org_id
         OR EXISTS (SELECT 1 FROM org_admins oa WHERE oa.org_id = subject.org_id AND oa.user_id = actor.id)))`

	// callerAdministersOrgTo closes the condition that the caller administers
	// the organization: has an org_admins row for it, or is a platform
	// administrator. Membership alone is not enough.
	callerAdministersOrgTo = ` AS org_id) subject, users actor WHERE actor.id = ?2 AND actor.revoked_at IS NULL
    AND (actor.role = ?3
         OR EXISTS (SELECT 1 FROM org_admins oa WHERE oa.org_id = subject.org_id AND oa.user_id = actor.id)))`

	// callerSeesOrg holds when the caller may read organization ?1, and
	// callerAdministersOrg when the caller administers it.
	callerSeesOrg        = orgSubjectFrom + `?1` + callerSeesOrgTo
	callerAdministersOrg = orgSubjectFrom + `?1` + callerAdministersOrgTo
)

// insertOrgQuery creates an organization or a sandbox for an account, if the
// account may have another. The conditions are part of the write, so two
// creates at a limit cannot both pass:
//
//   - the creator must be an unrevoked account, read from users here and not
//     trusted from the request;
//   - a standard organization needs a creator that belongs to none (a user
//     belongs to at most one);
//   - the creator must have fewer than ?8 organizations of the kind counted
//     as the limit says: all the standard organizations it ever created,
//     revoked ones included, or the sandboxes that have not expired as of ?5.
//     The organizations are their own record of both, so there is no counter.
//
// A conditional INSERT ... SELECT that matches nothing is not an error, so the
// statements that follow in the batch each depend on this row existing and do
// nothing otherwise, and CreateOrg reads why from the last statement of the
// batch (createOrgStandingQuery), as it reads the row from RETURNING. The id is
// fresh, so the row exists only if this statement wrote it.
//
// The sandbox kind needs an expiry and the standard kind none (the schema's
// CHECKs), which is the caller's ?4: nil for a standard organization.
//
// Arguments, by number: ?1 id, ?2 kind, ?3 name, ?4 expires_at or NULL, ?5
// created_at, ?6 creator id, ?7 the standard kind, ?8 the limit.
const insertOrgQuery = `
INSERT INTO orgs (id, kind, name, created_by, expires_at, revoked_at, created_at)
SELECT ?1, ?2, ?3, u.id, ?4, NULL, ?5
FROM users u
WHERE u.id = ?6
  AND u.revoked_at IS NULL
  AND (?2 <> ?7 OR u.org_id IS NULL)
  AND (SELECT count(*) FROM orgs g
       WHERE g.created_by = u.id AND g.kind = ?2 AND (?2 = ?7 OR g.expires_at > ?5)) < ?8
RETURNING id, kind, name, created_by, expires_at, revoked_at, created_at`

// joinCreatedOrgQuery makes the creator a member of the standard organization
// it has just created, in the same batch. It applies only when insertOrgQuery
// wrote the organization (it names the creator's own, just created) and only
// for the standard kind, since a sandbox has no members: the administrator of a
// sandbox keeps their own organization.
//
// Arguments, by number: ?1 organization id, ?2 creator id, ?3 kind, ?4 the
// standard kind.
const joinCreatedOrgQuery = `
UPDATE users SET org_id = ?1
WHERE id = ?2 AND org_id IS NULL AND ?3 = ?4
  AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = ?1 AND o.created_by = ?2)`

// insertCreatorAdminQuery makes the creator the administrator of what it has
// just created, of either kind. It applies only when insertOrgQuery wrote the
// organization.
//
// Arguments, by number: ?1 organization id, ?2 created_at.
const insertCreatorAdminQuery = `
INSERT INTO org_admins (org_id, user_id, created_at)
SELECT o.id, o.created_by, ?2 FROM orgs o WHERE o.id = ?1`

// createOrgStandingQuery is the last statement of CreateOrg: why the creator was
// refused, read in the same batch as the refused write and so from the state it
// saw. No row is an account that does not exist.
//
// Arguments: creator id.
const createOrgStandingQuery = `
SELECT u.revoked_at IS NOT NULL AS revoked, u.org_id IS NOT NULL AS member FROM users u WHERE u.id = ?1`

// NewOrg is an organization or a sandbox to create.
type NewOrg struct {
	// ID is the new organization's id.
	ID string

	// Kind is what to create, and Name what to call it.
	Kind input.OrgKind
	Name input.OrgName

	// Creator is the account creating it. It administers it, and for a standard
	// organization it also becomes its member.
	Creator string

	// ExpiresAt is when a sandbox stops working. It is not used for a standard
	// organization, which does not expire.
	ExpiresAt time.Time

	// Limit is how many the creator may have of the kind: for a standard
	// organization how many it may ever create, revoked ones included, and for
	// a sandbox how many may exist that have not expired.
	Limit int

	// CreatedAt is when it is created.
	CreatedAt time.Time
}

// CreateOrg creates an organization or a sandbox, and its creator's
// administration of it, as one batch; for a standard organization the creator
// also joins it in the same batch. It returns the organization as stored.
//
// It returns ErrAccountRevoked when the creator is revoked or gone,
// ErrAlreadyMember when a standard organization is refused because the creator
// belongs to one, and ErrOrgLimit when the creator has Limit of the kind. When
// more than one holds, ErrAccountRevoked comes first and then ErrAlreadyMember.
// None of these leaves anything written.
//
// Nothing the batch writes can collide with data that exists (the ids are
// fresh), so a conflict of any kind is a defect, reported as the operation's
// "_rejected" 500.
func (s *Store) CreateOrg(ctx context.Context, org NewOrg) (Org, error) {
	o := op{failed: CodeOrgCreateFailed, rejected: CodeOrgCreateRejected, description: orgsDescription}

	var expires any
	if org.Kind.Sandbox() {
		expires = org.ExpiresAt.Unix()
	}

	created := org.CreatedAt.Unix()

	return outcome(s.runChecked(ctx, o,
		Statement{Query: insertOrgQuery, Args: []any{
			org.ID, org.Kind.String(), org.Name.String(), expires, created, org.Creator, OrgKindStandard, int64(org.Limit),
		}},
		Statement{Query: joinCreatedOrgQuery, Args: []any{org.ID, org.Creator, org.Kind.String(), OrgKindStandard}},
		Statement{Query: insertCreatorAdminQuery, Args: []any{org.ID, created}},
		Statement{Query: createOrgStandingQuery, Args: []any{org.Creator}},
	).
		Then(func(results []Result) (Org, error) {
			return wroteOr(o, results[0].Rows, readOrg, func() (Org, error) {
				return refusedBy[creatorStanding, Org](o, results[3].Rows, readCreatorStanding,
					func(why found[creatorStanding]) error { return refusedCreate(org.Kind, why) })
			})
		}),
	)
}

// creatorStanding is why a create was refused, as createOrgStandingQuery reads
// it: the creator is revoked, or belongs to an organization.
type creatorStanding struct{ revoked, member bool }

// readCreatorStanding reads the columns of createOrgStandingQuery.
func readCreatorStanding(r *row) creatorStanding {
	return creatorStanding{revoked: r.boolean(), member: r.boolean()}
}

// refusedCreate is the outcome of a create that wrote nothing, read off the
// creator's standing: a creator who is gone or revoked is refused first, then a
// user who belongs to an organization (for the standard kind only), and what is
// left is the limit.
func refusedCreate(kind input.OrgKind, why found[creatorStanding]) error {
	switch {
	case !why.ok || why.value.revoked:
		return ErrAccountRevoked
	case !kind.Sandbox() && why.value.member:
		return ErrAlreadyMember
	default:
		return ErrOrgLimit
	}
}

// defectOnConflict turns a conflict into a defect for an operation whose writes
// cannot collide with data that exists: run hands a conflict back as the bare
// sentinel for the feature to interpret, and there is nothing here for it to
// mean. Any other error is returned as it is.
func defectOnConflict(o op, err error) error {
	if errors.Is(err, ErrConflict) {
		return o.defect(err)
	}

	return err
}

// conflictIsDefect is defectOnConflict for the operation o, as the step of a
// result chain that classifies its failure.
func conflictIsDefect(o op) func(error) error {
	return func(err error) error { return defectOnConflict(o, err) }
}

// getOrgQuery reads one organization the caller may see: the one they belong
// to or administer, or any of them for a platform administrator. An
// organization the caller may not see is not found, which is what they are told
// for an id that does not exist at all. The columns are those of readOrg.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role.
const getOrgQuery = `
SELECT o.id AS id, o.kind AS kind, o.name AS name, o.created_by AS created_by, o.expires_at AS expires_at,
       o.revoked_at AS revoked_at, o.created_at AS created_at
FROM orgs o
WHERE o.id = ?1 AND ` + callerSeesOrg

// GetOrg returns an organization the caller may see, or ErrNotFound: an id that
// does not exist, and one the caller neither belongs to nor administers, are
// the same answer. adminRole is the role of a platform administrator, who sees
// every organization.
func (s *Store) GetOrg(ctx context.Context, id input.ID, caller, adminRole string) (Org, error) {
	o := op{failed: CodeOrgLookupFailed, rejected: CodeOrgLookupRejected, description: orgsDescription}

	return queryOne(ctx, s, o,
		Statement{Query: getOrgQuery, Args: []any{id.String(), caller, adminRole}}, readOrg)
}

// listOrgsQuery reads one page of the organizations the caller may see, newest
// first: those they belong to or administer, or every one for a platform
// administrator, revoked and expired ones included. The id is a UUIDv7, so it is
// the sort key and the cursor, as for agents: the page is the organizations with
// an id below the cursor, and a page asks for one row more than it returns so
// the caller can tell whether there is a next page.
//
// The caller's own standing decides which organizations to look at, and is not
// tested against each organization in turn, which would read every organization
// there is for a caller who sees few of them. The ids come from three sources, each
// cut to one page by its own index and joined by UNION, which also drops the id
// of an organization that comes from two (a member who also administers it):
//
//   - every organization, in id order, only when the caller is an unrevoked
//     platform administrator (a condition that does not depend on the
//     organization, so it is settled once, before any is read);
//   - the organizations the caller administers, from org_admins_user_id, which
//     ends in org_id and so reads them in order;
//   - the one organization they belong to, from their own row.
//
// A revoked caller has none of the three, and an id of the cursor or above is
// dropped from each, so every source is read from the cursor on. The page is
// then the first rows, in order, of what the sources gave. Which organizations
// the caller sees is the same as callerSeesOrg: that, and this, are the one
// rule, and a test holds them to it.
//
// Arguments, by number: ?1 caller id, ?2 cursor (orgsFirstPage for the first
// page), ?3 rows wanted, ?4 the platform administrator role.
const listOrgsQuery = `
SELECT o.id AS id, o.kind AS kind, o.name AS name, o.created_by AS created_by, o.expires_at AS expires_at,
       o.revoked_at AS revoked_at, o.created_at AS created_at
FROM orgs o
WHERE o.id IN (
    SELECT id FROM (SELECT g.id AS id FROM orgs g
                    WHERE g.id < ?2
                      AND EXISTS (SELECT 1 FROM users a WHERE a.id = ?1 AND a.revoked_at IS NULL AND a.role = ?4)
                    ORDER BY g.id DESC LIMIT ?3)
    UNION
    SELECT id FROM (SELECT oa.org_id AS id FROM org_admins oa
                    WHERE oa.user_id = ?1 AND oa.org_id < ?2
                      AND EXISTS (SELECT 1 FROM users a WHERE a.id = ?1 AND a.revoked_at IS NULL)
                    ORDER BY oa.org_id DESC LIMIT ?3)
    UNION
    SELECT a.org_id FROM users a WHERE a.id = ?1 AND a.revoked_at IS NULL AND a.org_id < ?2)
ORDER BY o.id DESC
LIMIT ?3`

// OrgPage is one page of organizations, newest first.
type OrgPage struct {
	Orgs []Org

	// Next is the cursor of the following page: the id of the last organization
	// of this one. It is empty on the last page.
	Next string
}

// ListOrgs returns up to limit of the organizations the caller may see with an
// id below the cursor, newest first. An empty cursor starts at the newest.
func (s *Store) ListOrgs(
	ctx context.Context, caller, adminRole string, cursor input.Cursor, limit input.PageLimit,
) (OrgPage, error) {
	o := op{failed: CodeOrgListFailed, rejected: CodeOrgListRejected, description: orgsDescription}

	before, size := pageWindow(cursor, limit)

	return pageOf(o,
		result.Of(queryAll(ctx, s, o,
			Statement{Query: listOrgsQuery, Args: []any{caller, before, int64(size + 1), adminRole}}, readOrg)),
		size, func(org Org) string { return org.ID },
		func(orgs []Org, next string) OrgPage { return OrgPage{Orgs: orgs, Next: next} })
}

// pageWindow is where a keyset page starts (below the cursor's id, or
// orgsFirstPage) and how many rows it holds. A PageLimit made by its parser is
// at least 1; the zero value is read as 1, and not as a page that could never
// name a next one.
func pageWindow(cursor input.Cursor, limit input.PageLimit) (string, int) {
	before := orgsFirstPage
	if id, ok := cursor.ID(); ok {
		before = id.String()
	}

	return before, max(limit.Int(), 1)
}

// renameOrgQuery renames an organization the caller administers, if it is
// active: a standard organization that is not revoked, or a sandbox that has not
// expired. A revoked or expired one is final, as a revoked invitation is:
// changing it would suggest it could be revived. RETURNING gives the row as the
// write left it, and no row means nothing matched: renameOrgStandingQuery says
// why, in the same batch.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 name, ?5 now.
const renameOrgQuery = `
UPDATE orgs SET name = ?4
WHERE id = ?1
  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?5)
  AND ` + callerAdministersOrg + `
RETURNING id, kind, name, created_by, expires_at, revoked_at, created_at`

// orgStandingQuery reads an organization the caller may see, with whether they
// administer it: the last statement of an organization write that matched
// nothing, which reads why from the state the write saw. No row is an
// organization the caller may not see, and a row they do not administer is one
// they may.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role.
const orgStandingQuery = `
SELECT o.id AS id, o.kind AS kind, o.name AS name, o.created_by AS created_by, o.expires_at AS expires_at,
       o.revoked_at AS revoked_at, o.created_at AS created_at, ` + callerAdministersOrg + ` AS administers
FROM orgs o
WHERE o.id = ?1 AND ` + callerSeesOrg

// RenameOrg renames an organization or a sandbox the caller administers (or any
// of them, for a platform administrator) and returns it as the write left it.
//
// It returns ErrNotFound when the caller may not see the organization (which
// includes one that does not exist), ErrNotAdmin when they can see it but do not
// administer it, and ErrInactive when it is revoked or expired. A write that
// matched nothing for any other reason is a defect.
func (s *Store) RenameOrg(
	ctx context.Context, id input.ID, name input.OrgName, caller, adminRole string, now time.Time,
) (Org, error) {
	o := op{failed: CodeOrgUpdateFailed, rejected: CodeOrgUpdateRejected, description: orgsDescription}

	return outcome(s.runChecked(ctx, o,
		Statement{Query: renameOrgQuery, Args: []any{id.String(), caller, adminRole, name.String(), now.Unix()}},
		Statement{Query: orgStandingQuery, Args: []any{id.String(), caller, adminRole}},
	).
		Then(func(results []Result) (Org, error) {
			return wroteOr(o, results[0].Rows, readOrg, func() (Org, error) { return refusedOrg(o, results[1].Rows, now) })
		}),
	)
}

// refusedOrg is why a write to an organization the caller administers matched
// nothing, read off the standing statement that followed it.
func refusedOrg(o op, rows [][]any, now time.Time) (Org, error) {
	return refusedBy[orgStanding, Org](o, rows, readOrgStanding, func(standing found[orgStanding]) error {
		switch {
		case !standing.ok:
			return ErrNotFound
		case !standing.value.administer:
			return ErrNotAdmin
		case !standing.value.org.Active(now):
			return ErrInactive
		default:
			return o.defect(fmt.Errorf("%w: nothing matched for a caller who administers", errChanges))
		}
	})
}

// revokeOrgQuery revokes a standard organization the caller administers, now.
// The row is matched by id and kind, and one that is already revoked keeps its
// earlier time (the COALESCE), so revoking twice succeeds and cannot move the
// revocation later. RETURNING gives the row as it was left, and no row returned
// means the caller may not revoke any standard organization with this id; the
// statements below are conditioned on the same standing, so they too did nothing.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 revoked_at, ?5 the standard kind.
const revokeOrgQuery = `
UPDATE orgs SET revoked_at = COALESCE(revoked_at, ?4)
WHERE id = ?1 AND kind = ?5 AND ` + callerAdministersOrg + `
RETURNING id, kind, name, created_by, expires_at, revoked_at, created_at`

// releaseMembersQuery releases every member of a standard organization the
// caller administers once it is revoked, in the same batch and after
// revokeOrgQuery: a user is never left belonging to an organization that no
// longer works (docs/orgs_design.md, principle 3). It is a write of its own and
// not a cascade, so that joining can require the organization to be active in
// the write that sets it. It applies only when the organization is revoked,
// which includes one that already was, so a repeated revocation finishes a
// release that an earlier one did not.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 the standard kind.
const releaseMembersQuery = `
UPDATE users SET org_id = NULL
WHERE org_id = ?1
  AND ` + callerAdministersOrg + `
  AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = ?1 AND o.kind = ?4 AND o.revoked_at IS NOT NULL)`

// deleteRevokedOrgOffersQuery deletes the offers of a standard organization the
// caller administers once it is revoked: an offer means nothing once its
// organization is. It is a delete, and so named in mayDelete of the store's
// tests, from org_offers only. The platform invitation an offer rides on is
// never touched.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 the standard kind.
const deleteRevokedOrgOffersQuery = `
DELETE FROM org_offers
WHERE org_id = ?1
  AND ` + callerAdministersOrg + `
  AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = ?1 AND o.kind = ?4 AND o.revoked_at IS NOT NULL)`

// deleteRevokedOrgAdminsQuery deletes the administrator rows of a standard
// organization the caller administers once it is revoked. It comes last of the
// organization's statements, because the caller's own standing may be one of the
// rows. It deletes from org_admins only.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 the standard kind.
const deleteRevokedOrgAdminsQuery = `
DELETE FROM org_admins
WHERE org_id = ?1
  AND ` + callerAdministersOrg + `
  AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = ?1 AND o.kind = ?4 AND o.revoked_at IS NOT NULL)`

// deleteSandboxQuery deletes a sandbox the caller administers, by hand: the one
// way a sandbox ends, apart from being inert once it has expired. It is the
// whole of the deletion: the foreign keys do the rest (docs/orgs_design.md,
// principle 5). The sandbox's administrator row goes with it and the
// administrator stays. Its agents go with it, and with each agent its keys,
// labels and OAuth grants, and with them the secrets behind keys and grants
// (the delete triggers), so nothing that belonged to the sandbox is left.
// RETURNING gives the row as it was, and no row means the caller may not delete
// any sandbox with this id.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 the sandbox kind.
const deleteSandboxQuery = `
DELETE FROM orgs
WHERE id = ?1 AND kind = ?4 AND ` + callerAdministersOrg + `
RETURNING id, kind, name, created_by, expires_at, revoked_at, created_at`

// OrgEnd is how an organization ended: a standard organization was revoked, and
// stays as the record, and a sandbox was deleted, and is gone.
type OrgEnd struct {
	// Org is the organization as the write left it. For a deleted sandbox it is
	// the row as it was just before it was deleted.
	Org Org

	// Deleted is true for a sandbox, which no longer exists.
	Deleted bool
}

// RevokeOrg ends an organization the caller administers (or any, for a platform
// administrator) as one batch. A standard organization is revoked: it keeps its
// row, its members are released, and its offers and administrator rows are
// deleted. A sandbox is deleted, with everything that belonged to it. Revoking a
// standard organization that is already revoked succeeds and keeps the earlier
// time, so the call is idempotent for a platform administrator; its former
// administrators no longer administer it, and are told it is not found.
//
// It returns ErrNotFound when the caller may not see the organization, and
// ErrNotAdmin when they can see it but do not administer it. A write that
// matched nothing for any other reason is a defect.
func (s *Store) RevokeOrg(
	ctx context.Context, id input.ID, caller, adminRole string, now time.Time,
) (OrgEnd, error) {
	o := op{failed: CodeOrgRevokeFailed, rejected: CodeOrgRevokeRejected, description: orgsDescription}

	args := []any{id.String(), caller, adminRole}

	return outcome(s.runChecked(ctx, o,
		Statement{Query: revokeOrgQuery, Args: slices.Concat(args, []any{now.Unix(), OrgKindStandard})},
		Statement{Query: releaseMembersQuery, Args: slices.Concat(args, []any{OrgKindStandard})},
		Statement{Query: deleteRevokedOrgOffersQuery, Args: slices.Concat(args, []any{OrgKindStandard})},
		Statement{Query: deleteRevokedOrgAdminsQuery, Args: slices.Concat(args, []any{OrgKindStandard})},
		Statement{Query: deleteSandboxQuery, Args: slices.Concat(args, []any{OrgKindSandbox})},
		Statement{Query: orgStandingQuery, Args: args},
	).
		Then(func(results []Result) (OrgEnd, error) {
			return wroteOr(o, results[0].Rows, readRevoked, func() (OrgEnd, error) {
				return wroteOr(o, results[4].Rows, readDeleted, func() (OrgEnd, error) {
					_, err := refusedOrg(o, results[5].Rows, now)

					return OrgEnd{}, err
				})
			})
		}),
	)
}

// readRevoked reads the row of a revoked standard organization as the end of it,
// and readDeleted that of a deleted sandbox: the columns of readOrg.
func readRevoked(r *row) OrgEnd { return OrgEnd{Org: readOrg(r), Deleted: false} }
func readDeleted(r *row) OrgEnd { return OrgEnd{Org: readOrg(r), Deleted: true} }
