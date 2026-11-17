package session

// activeKeyQuery reads a key for verification. A key is active when it has not
// been revoked and has not expired. The token carries its own exp and japikey
// checks it; the column is a second, cheap check that costs nothing here.
//
// Revocation is a time and not a flag, compared with now, so the same query
// would serve a revocation scheduled for later; nothing schedules one today.
//
// The role and the account's revocation come from the account, read in this
// same primary-key lookup, so a role change or a revoked account takes effect
// on the next request instead of when the session was minted. That join is why
// the role is not a claim in the token: the key row has to be read anyway, so
// a claim would save nothing and could only be stale (docs/users_design.md).
//
// Arguments: kid, now (unix seconds), now.
const activeKeyQuery = `
SELECT k.jwk, k.user_id, COALESCE(k.credential_id, ''), u.role, k.expires_at
FROM japikeys k
JOIN users u ON u.id = k.user_id
WHERE k.kid = ?
  AND k.kind = 'session'
  AND (k.revoked_at IS NULL OR k.revoked_at > ?)
  AND k.expires_at > ?
  AND u.revoked_at IS NULL`

// InsertSessionQuery issues a session key. granted_from is the hash of the login
// challenge, and the column is UNIQUE, which is what makes a login single use: a
// replay of the same response produces the same hash and collides with the row
// the first login created, so the batch fails and no second session exists.
//
// The account is not bound by the caller: user_id is read from the credential's
// own row, in the write. That makes the session's account the credential's
// owner by construction, and it makes the credential's existence a condition of
// the write. A passkey deleted after finish looked it up (and before this runs)
// leaves the subselect NULL, user_id is NOT NULL, and the batch fails as a
// conflict, which login reports as any other failed login. Without this the
// failure would be the credential_id FOREIGN KEY, which is classified as a
// defect on our side (a 500 that pages someone) for what is a user deleting
// their own passkey.
//
// The subselect also requires the account not to be revoked, for the same
// reason: an admin revoking the account between finish's lookup and this write
// fails the batch as a conflict, so no session is issued to a revoked account.
// (Verification would refuse such a session anyway; this keeps it from
// existing.)
//
// Arguments, in order: kid, credential_id (for the subselect), jwk, expires_at,
// granted_from, credential_id, created_at.
const InsertSessionQuery = `
INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, granted_from, credential_id, created_at)
VALUES (?, (SELECT c.user_id FROM credentials c JOIN users u ON u.id = c.user_id
            WHERE c.id = ? AND u.revoked_at IS NULL), 'session', ?, ?, ?, ?, ?)`

// logoutQuery revokes a session key now. A key that is already revoked keeps its
// earlier time, so logging out twice cannot move a revocation later.
//
// The number of rows it changes is the outcome: one means this request ended the
// session, none means it was already revoked (another request got there first),
// and the handler answers that as any request without a session.
//
// Arguments: revoke_at (unix seconds), kid.
const logoutQuery = `
UPDATE japikeys
SET revoked_at = ?
WHERE kid = ?
  AND kind = 'session'
  AND revoked_at IS NULL`
