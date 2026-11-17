package invitations

// selectColumns are the columns of an invitation row, in the order scanRow
// reads them. The use count is the number of users pointing at the invitation:
// the account is the redemption (docs/invitations_design.md).
//
// The code and its hash are not selected. Nothing here can return them.
const selectColumns = `
SELECT i.id, i.type, i.label, i.num_invites,
       (SELECT count(*) FROM users u WHERE u.invitation_id = i.id),
       i.expires_at, i.revoked_at, i.created_by, i.created_at
FROM invitations i`

// listQuery reads every invitation, revoked ones included, newest first. The id
// is a UUIDv7, so it breaks ties between invitations created in the same
// second in creation order.
const listQuery = selectColumns + `
ORDER BY i.created_at DESC, i.id DESC`

// getQuery reads one invitation. Arguments: id.
const getQuery = selectColumns + `
WHERE i.id = ?`

// insertQuery creates an invitation. The creator is an admin, who is a user,
// so created_by is bound to a real account.
//
// Arguments, in order: id, code_hash, type, label, num_invites, expires_at,
// created_by, created_at.
const insertQuery = `
INSERT INTO invitations (id, code_hash, type, label, num_invites, expires_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

// updateNumInvitesQuery changes how many accounts an invitation may create. It
// is a conditional write, because D1 has no interactive transaction and a
// read-then-write would race with a registration finishing in between:
//
//   - The invitation must not be revoked. A revoked invitation is final, and
//     changing it would suggest it could be revived.
//   - The new cap must not be below the accounts it has already created. The
//     count is read in the write itself, so an account created after the
//     handler looked cannot be left over the cap.
//
// A WHERE that carried those conditions would match nothing when they fail, and
// a write that matches nothing says nothing about why. So the row is matched by
// id alone, the conditions decide whether the SET changes it (the CASE), and
// RETURNING reports the row as the statement left it together with whether the
// change applied. The statement is one transaction, so the row, its count of
// accounts and the verdict are all the same instant: nothing can slip in
// between the write and the account of it. No row returned means no such
// invitation.
//
// The verdict is the CASE's own test, written out again, and not derived from
// the new num_invites: setting the cap to the value it already has would
// otherwise look the same as a refusal. Nothing in the statement changes
// revoked_at or the users table, so the test reads the same in RETURNING as it
// did in the SET.
//
// RETURNING is "applied" (1 or 0) followed by the columns of selectColumns in
// the same order, so rowOfValues reads it. Each column has a distinct name,
// which D1's batch results need: columns that share one collapse into one.
//
// Arguments, by number: ?1 the new num_invites, ?2 the same value (compared
// with the count), ?3 id.
const updateNumInvitesQuery = `
UPDATE invitations
SET num_invites = CASE
      WHEN revoked_at IS NULL
       AND (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) <= ?2
      THEN ?1
      ELSE num_invites
    END
WHERE id = ?3
RETURNING
  (revoked_at IS NULL
   AND (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) <= ?2) AS applied,
  id, type, label, num_invites,
  (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) AS uses,
  expires_at, revoked_at, created_by, created_at`

// revokeQuery revokes an invitation now. One that is already revoked keeps its
// earlier time (the COALESCE), so revoking twice cannot move the revocation
// later (as with sessions). The row is never deleted: accounts reference it, and
// the audit question "who came from this code?" must stay answerable.
//
// The row is matched by id alone and RETURNING gives it back as the statement
// left it, so both ways a revoke can end are the same answer, which the caller
// reads off the row: it was revoked now, or it already was. Neither is told
// apart, because neither differs to the client. No row returned means no such
// invitation, which a WHERE on revoked_at could not distinguish from one that
// was already revoked.
//
// RETURNING is the columns of selectColumns, in that order, so rowOfValues
// reads it. The use count is a column of the row, counted in the same
// statement.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 id.
const revokeQuery = `
UPDATE invitations
SET revoked_at = COALESCE(revoked_at, ?1)
WHERE id = ?2
RETURNING
  id, type, label, num_invites,
  (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) AS uses,
  expires_at, revoked_at, created_by, created_at`
