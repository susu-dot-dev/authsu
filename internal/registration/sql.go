package registration

// invitationQuery looks up an invitation for begin and finish. It is a plain
// read: begin uses it as an advisory check, and finish uses it to learn the
// invitation's type so Go can choose the role. Neither relies on it for
// authorisation; insertUserQuery re-checks everything in the write.
//
// It returns the type of the invitation only when it is currently redeemable
// (not revoked, not expired, under its cap, and, for first run, no account
// exists yet), and no row otherwise.
//
// Arguments: code_hash, now (unix seconds).
const invitationQuery = `
SELECT i.type
FROM invitations i
WHERE i.code_hash = ?
  AND i.revoked_at IS NULL
  AND (i.expires_at IS NULL OR i.expires_at > ?)
  AND (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) < i.num_invites
  AND (i.type <> 'first_run' OR NOT EXISTS (SELECT 1 FROM users))`

// insertUserQuery creates the account, and is the point of acceptance. Its
// authorisation checks are conditions of the insert itself, so the database
// serialises them: two people finishing at once on a single-use code, or two
// browsers racing to become the first admin, cannot both pass.
//
// The role is chosen by Go from the invitation's type (roleFor) and bound as a
// value. The insert also requires the invitation to still have that type, so a
// type that changed between the read and the write cannot get a role chosen for
// a different one. The client supplies neither.
//
// If no invitation satisfies the conditions the insert matches nothing. A
// conditional insert that matches nothing is not an error, so on its own it
// would not roll the batch back; insertCredentialQuery's required reference to
// the new user is what turns it into a failure.
//
// Arguments, in order: id, user_handle, role, profile, created_at, code_hash,
// type, now.
const insertUserQuery = `
INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at)
SELECT ?, ?, ?, i.id, ?, ?
FROM invitations i
WHERE i.code_hash = ?
  AND i.type = ?
  AND i.revoked_at IS NULL
  AND (i.expires_at IS NULL OR i.expires_at > ?)
  AND (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) < i.num_invites
  AND (i.type <> 'first_run' OR NOT EXISTS (SELECT 1 FROM users))`

// insertCredentialQuery stores the passkey for the user insertUserQuery just
// created, found by its unique user handle. user_id is NOT NULL and references
// users, so when the user insert matched nothing the subselect is NULL and this
// statement fails, which rolls back the whole batch.
//
// Arguments, in order: id, credential_id, user_handle, public_key, flags,
// metadata, created_at.
//
//nolint:gosec // SQL naming the credentials table, not a credential
const insertCredentialQuery = `
INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at)
VALUES (?, ?, (SELECT id FROM users WHERE user_handle = ?), ?, ?, ?, ?)`
