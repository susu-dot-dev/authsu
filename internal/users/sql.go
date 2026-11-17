package users

// selectColumns are the columns of an account row, in the order scanRow and
// rowOfValues read them. The user handle is not selected: nothing here returns
// it.
const selectColumns = `
SELECT id, role, invitation_id, profile, revoked_at, created_at
FROM users`

// listQuery reads every account, revoked ones included, newest first. The id is
// a UUIDv7, so it breaks ties between accounts created in the same second in
// creation order.
const listQuery = selectColumns + `
ORDER BY created_at DESC, id DESC`

// getQuery reads one account. Arguments: id.
const getQuery = selectColumns + `
WHERE id = ?`

// revokeQuery revokes an account now, unless it is the last active admin.
//
// The guard is part of the write, not a read before it, because D1 has no
// interactive transaction: two admins revoking each other at the same moment
// would each see the other still active, and both writes would apply, leaving
// no admin at all. D1 runs one statement at a time, so here the second write
// sees the first one's revocation and is refused.
//
// The row is matched by id alone, and the guard decides what revoked_at
// becomes:
//
//   - already revoked: it keeps its earlier time (the COALESCE), so revoking
//     twice succeeds and cannot move the revocation later;
//   - not an admin, or an admin while another active admin exists: now;
//   - the last active admin: the CASE has no ELSE, so it stays NULL.
//
// RETURNING gives the row as the statement left it, so the outcome is read off
// the row: revoked_at set means the account is revoked, NULL means the guard
// refused. No row returned means no such account. Nothing is read again
// afterwards, which could see a different state.
//
// RETURNING is the columns of selectColumns, in that order, so rowOfValues
// reads it.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 id, ?3 the admin role.
const revokeQuery = `
UPDATE users
SET revoked_at = COALESCE(revoked_at, CASE
      WHEN role <> ?3
        OR EXISTS (SELECT 1 FROM users other
                   WHERE other.id <> users.id
                     AND other.role = ?3
                     AND other.revoked_at IS NULL)
      THEN ?1
    END)
WHERE id = ?2
RETURNING id, role, invitation_id, profile, revoked_at, created_at`

// revokeKeysQuery revokes every key of the account, in the same batch as
// revokeQuery and after it. Verification already refuses any key of a revoked
// account (it reads users.revoked_at), so this is not what ends the sessions.
// It keeps the keys table honest: a key listed later reads as revoked, and a
// future kind of key whose verification forgot to check the account would
// still be refused.
//
// It applies only if the account is revoked once revokeQuery has run, so a
// refused revocation (the last admin) changes no key. A key whose revocation is
// already due keeps its time; one scheduled for later is brought forward.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 user id.
const revokeKeysQuery = `
UPDATE japikeys
SET revoked_at = ?1
WHERE user_id = ?2
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND revoked_at IS NOT NULL)`
