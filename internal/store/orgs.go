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
	CodeOrgDeleteFailed   = "org_delete_failed"
	CodeOrgDeleteRejected = "org_delete_rejected"
)

// orgsDescription is the client-safe text of every organization operation's
// Unavailable error. Members use it too.
const orgsDescription = "organizations are temporarily unavailable"

// orgsFirstPage is the cursor bound of the first page of an organization, member
// list: every id is below it (see agentsFirstPage). It is internal:
// callers pass an input.Cursor, which is empty for the first page.
const orgsFirstPage = "g"

// The outcomes of the organization and member operations that are the
// state the request met and not a failure. A feature maps each to its client
// code; the operations return them as they are.
var (
	// ErrAccountRevoked means the account that is acting was revoked after its
	// request was authenticated, so nothing was written.
	ErrAccountRevoked = errors.New("the account is revoked")

	// ErrSandboxLimit means the account already holds the most sandboxes it may
	// that have not expired.
	ErrSandboxLimit = errors.New("the account has reached the limit of sandboxes")

	// ErrNotAdmin means the caller can see the organization but does not
	// administer it, and is not a platform administrator.
	ErrNotAdmin = errors.New("the caller does not administer the organization")

	// ErrExpired means the organization is a sandbox that has expired, and so
	// cannot be changed.
	ErrExpired = errors.New("the sandbox has expired")

	// ErrNotStandard means the organization is a sandbox, which has no members.
	ErrNotStandard = errors.New("the organization is a sandbox")

	// ErrNotSandbox means the organization is a standard organization, which is
	// never deleted.
	ErrNotSandbox = errors.New("the organization is not a sandbox")

	// ErrMemberRevoked means a promotion named a member whose account is revoked,
	// who never administers anything again.
	ErrMemberRevoked = errors.New("a revoked member cannot be made an administrator")

	// ErrLastOrgAdmin means the change would leave a standard organization
	// without an unrevoked administrator.
	ErrLastOrgAdmin = errors.New("the last unrevoked administrator of the organization cannot be demoted")

	// ErrPlatformAdminTarget means an administrator of an organization tried to
	// revoke a platform administrator, who only a platform administrator may
	// revoke, even when they belong to the organization.
	ErrPlatformAdminTarget = errors.New("only a platform administrator may revoke a platform administrator")

	// ErrSelfRevoke means an administrator of an organization tried to revoke
	// their own account, which only a platform administrator may do.
	ErrSelfRevoke = errors.New("an organization administrator may not revoke themself")
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

	// CreatedAt is in Unix seconds.
	CreatedAt int64
}

// Active reports whether the organization works at now: a standard one always
// does, and a sandbox does until it expires. It is the Go reading of the
// condition every write that needs an active organization states in SQL.
func (o Org) Active(now time.Time) bool {
	return o.ExpiresAt == nil || *o.ExpiresAt > now.Unix()
}

// readOrg reads one organization row, in the column order every organization
// statement selects or returns: id, kind, name, created_by, expires_at,
// created_at.
func readOrg(r *row) Org {
	// Struct fields are evaluated in order, which is the column order.
	return Org{
		ID: r.text(), Kind: r.text(), Name: r.text(), CreatedBy: r.text(),
		ExpiresAt: r.optInteger(), CreatedAt: r.integer(),
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
// about a user's own organization (members.go) puts that column between the
// halves (callerSeesTargetOrg and the others there).
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

// insertSandboxQuery creates a sandbox for an account, if the account may have
// another. The conditions are part of the write, so two creates at the limit
// cannot both pass:
//
//   - the creator must be an unrevoked account, read from users here and not
//     trusted from the request;
//   - the creator must have fewer than ?6 sandboxes that have not expired as of
//     ?4. The sandboxes are their own record of it, so there is no counter. The
//     count is of the sandbox kind (?5) only: the organization every account
//     has is created by its own account too, and is not counted.
//
// A conditional INSERT ... SELECT that matches nothing is not an error, so the
// statement that follows in the batch depends on this row existing and does
// nothing otherwise, and CreateSandbox reads why from the last statement of the
// batch (callerStandingQuery), as it reads the row from RETURNING. The id
// is fresh, so the row exists only if this statement wrote it.
//
// Arguments, by number: ?1 id, ?2 name, ?3 expires_at, ?4 created_at, ?5 the
// sandbox kind, ?6 the limit, ?7 creator id.
const insertSandboxQuery = `
INSERT INTO orgs (id, kind, name, created_by, expires_at, created_at)
SELECT ?1, ?5, ?2, u.id, ?3, ?4
FROM users u
WHERE u.id = ?7
  AND u.revoked_at IS NULL
  AND (SELECT count(*) FROM orgs g
       WHERE g.created_by = u.id AND g.kind = ?5 AND g.expires_at > ?4) < ?6
RETURNING id, kind, name, created_by, expires_at, created_at`

// insertCreatorAdminQuery makes the creator the administrator of the sandbox it
// has just created. It applies only when insertSandboxQuery wrote the sandbox.
//
// Arguments, by number: ?1 sandbox id, ?2 created_at.
const insertCreatorAdminQuery = `
INSERT INTO org_admins (org_id, user_id, created_at)
SELECT o.id, o.created_by, ?2 FROM orgs o WHERE o.id = ?1`

// callerStandingQuery is the last statement of a write that can be refused: whether
// the caller was revoked, read in the same batch as the refused write and so from
// the state it saw. No row is an account that does not exist. It is how a write
// that matched nothing tells a revoked caller (401) from a caller who may not see
// what they asked about (404): every write's conditions require an unrevoked
// caller, so both look the same to it.
//
// Arguments: caller id.
const callerStandingQuery = `
SELECT u.revoked_at IS NOT NULL AS revoked FROM users u WHERE u.id = ?1`

// NewSandbox is a sandbox to create.
type NewSandbox struct {
	// ID is the new sandbox's id, and Name what to call it.
	ID   string
	Name input.OrgName

	// Creator is the account creating it. It administers it, and keeps its own
	// organization.
	Creator string

	// ExpiresAt is when the sandbox stops working.
	ExpiresAt time.Time

	// Limit is how many sandboxes that have not expired the creator may hold.
	Limit int

	// CreatedAt is when it is created.
	CreatedAt time.Time
}

// CreateSandbox creates a sandbox and its creator's administration of it, as one
// batch, and returns the sandbox as stored.
//
// It returns ErrAccountRevoked when the creator is revoked or gone, and
// ErrSandboxLimit when the creator already holds Limit sandboxes that have not
// expired. Neither leaves anything written.
//
// Nothing the batch writes can collide with data that exists (the ids are
// fresh), so a conflict of any kind is a defect, reported as the operation's
// "_rejected" 500.
func (s *Store) CreateSandbox(ctx context.Context, sandbox NewSandbox) (Org, error) {
	o := op{failed: CodeOrgCreateFailed, rejected: CodeOrgCreateRejected, description: orgsDescription}

	created := sandbox.CreatedAt.Unix()

	return outcome(s.runChecked(ctx, o,
		Statement{Query: insertSandboxQuery, Args: []any{
			sandbox.ID, sandbox.Name.String(), sandbox.ExpiresAt.Unix(), created, OrgKindSandbox, int64(sandbox.Limit),
			sandbox.Creator,
		}},
		Statement{Query: insertCreatorAdminQuery, Args: []any{sandbox.ID, created}},
		Statement{Query: callerStandingQuery, Args: []any{sandbox.Creator}},
	).
		Then(func(results []Result) (Org, error) {
			return wroteOr(o, results[0].Rows, readOrg, func() (Org, error) {
				return refusedBy[bool, Org](o, results[2].Rows, readCallerRevoked, refusedCreate)
			})
		}),
	)
}

// readCallerRevoked reads the column of callerStandingQuery: whether the caller
// is revoked.
func readCallerRevoked(r *row) bool { return r.boolean() }

// unseen is why a write's standing statement found no row, read off the
// callerStandingQuery that ended its batch: a caller who is revoked is told so
// (ErrAccountRevoked), and anyone else cannot see what they asked about, which is
// the same answer whether it exists or not (ErrNotFound). Both happen only when
// the write matched nothing, so nothing was written.
func unseen(o op, rows [][]any) error {
	revoked, ok, err := findRow(rows, o, readCallerRevoked)

	switch {
	case err != nil:
		return err
	case ok && revoked:
		return ErrAccountRevoked
	default:
		return ErrNotFound
	}
}

// refusedCreate is the outcome of a create that wrote nothing, read off the
// creator's standing: a creator who is gone or revoked is refused first, and
// what is left is the limit.
func refusedCreate(why found[bool]) error {
	if !why.ok || why.value {
		return ErrAccountRevoked
	}

	return ErrSandboxLimit
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
       o.created_at AS created_at
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
// administrator, expired sandboxes included. The id is a UUIDv7, so it is
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
       o.created_at AS created_at
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
// active: a standard organization always is, and a sandbox is until it expires.
// An expired sandbox is final: changing it would suggest it could be revived.
// RETURNING gives the row as the write left it, and no row means nothing
// matched: orgStandingQuery says why, in the same batch.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 name, ?5 now.
const renameOrgQuery = `
UPDATE orgs SET name = ?4
WHERE id = ?1
  AND (expires_at IS NULL OR expires_at > ?5)
  AND ` + callerAdministersOrg + `
RETURNING id, kind, name, created_by, expires_at, created_at`

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
       o.created_at AS created_at, ` + callerAdministersOrg + ` AS administers
FROM orgs o
WHERE o.id = ?1 AND ` + callerSeesOrg

// RenameOrg renames an organization or a sandbox the caller administers (or any
// of them, for a platform administrator) and returns it as the write left it.
//
// It returns ErrNotFound when the caller may not see the organization (which
// includes one that does not exist), ErrAccountRevoked when the caller was
// revoked, ErrNotAdmin when they can see it but do not administer it, and
// ErrExpired when it is a sandbox that has expired. A write
// that matched nothing for any other reason is a defect.
func (s *Store) RenameOrg(
	ctx context.Context, id input.ID, name input.OrgName, caller, adminRole string, now time.Time,
) (Org, error) {
	o := op{failed: CodeOrgUpdateFailed, rejected: CodeOrgUpdateRejected, description: orgsDescription}

	return outcome(s.runChecked(ctx, o,
		Statement{Query: renameOrgQuery, Args: []any{id.String(), caller, adminRole, name.String(), now.Unix()}},
		Statement{Query: orgStandingQuery, Args: []any{id.String(), caller, adminRole}},
		Statement{Query: callerStandingQuery, Args: []any{caller}},
	).
		Then(func(results []Result) (Org, error) {
			return wroteOr(o, results[0].Rows, readOrg, func() (Org, error) {
				return refusedRename(o, results[1].Rows, results[2].Rows, now)
			})
		}),
	)
}

// refusedRename is why a rename matched nothing, read off the standing statement
// that followed it, and the caller's standing after it for when there is none.
func refusedRename(o op, rows, callerRows [][]any, now time.Time) (Org, error) {
	return refusedBy[orgStanding, Org](o, rows, readOrgStanding, func(standing found[orgStanding]) error {
		switch {
		case !standing.ok:
			return unseen(o, callerRows)
		case !standing.value.administer:
			return ErrNotAdmin
		case !standing.value.org.Active(now):
			return ErrExpired
		default:
			return o.defect(fmt.Errorf("%w: nothing matched for a caller who administers", errChanges))
		}
	})
}

// deleteSandboxQuery deletes a sandbox the caller administers, by hand: the one
// way a sandbox ends, apart from being inert once it has expired, and the one
// way an organization is ever deleted. An expired sandbox may be deleted too. It
// is the whole of the deletion: the foreign keys do the rest
// (docs/orgs_design.md, principle 5). The sandbox's administrator row goes with
// it and the administrator stays. Its agents go with it, and with each agent its
// keys, labels and OAuth grants, and with them the secrets behind keys and
// grants (the delete triggers), so nothing that belonged to the sandbox is left.
// RETURNING gives the row as it was, and no row means the caller may not delete
// any sandbox with this id.
//
// Arguments, by number: ?1 organization id, ?2 caller id, ?3 the platform
// administrator role, ?4 the sandbox kind.
const deleteSandboxQuery = `
DELETE FROM orgs
WHERE id = ?1 AND kind = ?4 AND ` + callerAdministersOrg + `
RETURNING id, kind, name, created_by, expires_at, created_at`

// DeleteSandbox deletes a sandbox the caller administers (or any, for a platform
// administrator), with everything that belonged to it, and returns the row as it
// was just before.
//
// It returns ErrNotFound when the caller may not see the organization,
// ErrAccountRevoked when the caller was revoked, ErrNotAdmin
// when they can see it but do not administer it, and ErrNotSandbox when it is a
// standard organization, which is never deleted. An administrator is told it is
// not a sandbox only after it is known they could administer it: the caller must
// see the organization to learn what it is. A write that matched nothing for any
// other reason is a defect.
func (s *Store) DeleteSandbox(
	ctx context.Context, id input.ID, caller, adminRole string,
) (Org, error) {
	o := op{failed: CodeOrgDeleteFailed, rejected: CodeOrgDeleteRejected, description: orgsDescription}

	args := []any{id.String(), caller, adminRole}

	return outcome(s.runChecked(ctx, o,
		Statement{Query: deleteSandboxQuery, Args: slices.Concat(args, []any{OrgKindSandbox})},
		Statement{Query: orgStandingQuery, Args: args},
		Statement{Query: callerStandingQuery, Args: []any{caller}},
	).
		Then(func(results []Result) (Org, error) {
			return wroteOr(o, results[0].Rows, readOrg, func() (Org, error) {
				return refusedDelete(o, results[1].Rows, results[2].Rows)
			})
		}),
	)
}

// refusedDelete is why a delete matched nothing, read off the standing statement
// that followed it, and the caller's standing after it for when there is none.
func refusedDelete(o op, rows, callerRows [][]any) (Org, error) {
	return refusedBy[orgStanding, Org](o, rows, readOrgStanding, func(standing found[orgStanding]) error {
		switch {
		case !standing.ok:
			return unseen(o, callerRows)
		case !standing.value.administer:
			return ErrNotAdmin
		case standing.value.org.Kind != OrgKindSandbox:
			return ErrNotSandbox
		default:
			return o.defect(fmt.Errorf("%w: nothing matched for a caller who administers a sandbox", errChanges))
		}
	})
}
