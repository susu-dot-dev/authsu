package store

import (
	"context"
	"time"
)

// KindSession is japikeys.kind of a login session. CreateSession writes it,
// RevokeSession only touches rows of it, and the auth layer verifies tokens of
// it through ActiveKey.
const KindSession = "session"

// Error codes of the key operations. They are stable: clients and dashboards
// may match on them.
const (
	CodeSessionVerifyFailed   = "session_verify_failed"
	CodeSessionVerifyRejected = "session_verify_rejected"
	CodeLoginAcceptFailed     = "login_accept_failed"
	CodeLoginAcceptRejected   = "login_accept_rejected"
	CodeSessionLogoutFailed   = "session_logout_failed"
	CodeSessionLogoutRejected = "session_logout_rejected"
)

// activeKeyQuery reads a key for verification. A key is active when it has not
// been revoked and has not expired. The token carries its own exp and japikey
// checks it; the column is a second, cheap check that costs nothing here.
//
// Revocation is a time and not a flag, compared with now, so the same query
// would serve a revocation scheduled for later; nothing schedules one today.
//
// The role and the account's revocation come from the account, read in this
// same primary-key lookup, so a role change or a revoked account takes effect
// on the next request instead of when the session was created. That join is why
// the role is not a claim in the token: the key row has to be read anyway, so
// a claim would save nothing and could only be stale (docs/users_design.md).
//
// Arguments: kid, kind, now (unix seconds), now.
const activeKeyQuery = `
SELECT k.jwk AS jwk, k.user_id AS user_id, COALESCE(k.credential_id, '') AS credential_id,
       u.role AS role, k.expires_at AS expires_at
FROM japikeys k
JOIN users u ON u.id = k.user_id
WHERE k.kid = ?
  AND k.kind = ?
  AND (k.revoked_at IS NULL OR k.revoked_at > ?)
  AND k.expires_at > ?
  AND u.revoked_at IS NULL`

// ActiveKey is a key that may verify a token, with the account it belongs to.
type ActiveKey struct {
	// JWK is the key's public JWK as stored: the JSON japikey defines.
	JWK []byte

	// UserID is the account the key belongs to.
	UserID string

	// CredentialID is the row id of the passkey that started a session, or ""
	// for a key that has none.
	CredentialID string

	// Role is the account's current role, not the one at the key's creation.
	Role string

	// ExpiresAt is when the key stops being active.
	ExpiresAt time.Time
}

// ActiveKey reads the key kid of the given kind (KindSession for a session) if
// it is active at now: not revoked, not expired, and its account not revoked.
// It reports false when there is no such key.
func (s *Store) ActiveKey(ctx context.Context, kid, kind string, now time.Time) (ActiveKey, bool, error) {
	o := op{failed: CodeSessionVerifyFailed, rejected: CodeSessionVerifyRejected,
		description: "sessions are temporarily unavailable"}

	unix := now.Unix()

	return find(ctx, s, o, Statement{Query: activeKeyQuery, Args: []any{kid, kind, unix, unix}},
		func(r *row) ActiveKey {
			// Struct fields are evaluated in order, which is the column order.
			return ActiveKey{
				JWK: []byte(r.text()), UserID: r.text(), CredentialID: r.text(),
				Role: r.text(), ExpiresAt: r.timestamp(),
			}
		})
}

// updateFlagsQuery stores the flags an accepted assertion reported. Backup
// state and the verified bit legitimately change over a credential's life, and
// the schema comment on credentials.flags says they are updated on login. It
// runs in the same batch as the session insert, so a replayed login that is
// refused updates nothing.
//
// Arguments, in order: flags, credential row id.
const updateFlagsQuery = `UPDATE credentials SET flags = ? WHERE id = ?`

// insertSessionQuery issues a session key. granted_from is the hash of the login
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
// Arguments, in order: kid, credential row id (for the subselect), kind, jwk,
// expires_at, granted_from, credential row id, created_at.
const insertSessionQuery = `
INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, granted_from, credential_id, created_at)
VALUES (?, (SELECT c.user_id FROM credentials c JOIN users u ON u.id = c.user_id
            WHERE c.id = ? AND u.revoked_at IS NULL), ?, ?, ?, ?, ?, ?)`

// NewSession is a session a login has just earned.
type NewSession struct {
	// KeyID is the new key's kid.
	KeyID string

	// CredentialRowID is the row id of the passkey that logged in. The session's
	// account is that passkey's owner.
	CredentialRowID string

	// JWK is the key's public JWK as JSON.
	JWK string

	// ExpiresAt is when the session ends.
	ExpiresAt time.Time

	// GrantedFrom is the SHA-256 of the login challenge that earned the session.
	GrantedFrom []byte

	// Flags are the credential flags the assertion reported, stored on the
	// passkey.
	Flags uint8

	// CreatedAt is when the session was created.
	CreatedAt time.Time
}

// CreateSession records the flags the login reported on its passkey and issues
// the session key, in one batch: neither takes effect without the other.
//
// It returns ErrConflict when the login cannot stand: the challenge was
// already used (a replay), the passkey was deleted, or the account was revoked,
// since the caller looked the passkey up.
func (s *Store) CreateSession(ctx context.Context, session NewSession) error {
	o := op{failed: CodeLoginAcceptFailed, rejected: CodeLoginAcceptRejected,
		description: "login is temporarily unavailable"}

	_, err := s.run(ctx, o,
		Statement{Query: updateFlagsQuery, Args: []any{int64(session.Flags), session.CredentialRowID}},
		Statement{Query: insertSessionQuery, Args: []any{
			session.KeyID, session.CredentialRowID, KindSession, session.JWK, session.ExpiresAt.Unix(),
			session.GrantedFrom, session.CredentialRowID, session.CreatedAt.Unix(),
		}},
	)

	return err
}

// revokeSessionQuery revokes a session key now. A key that is already revoked
// keeps its earlier time, so logging out twice cannot move a revocation later.
//
// The number of rows it changes is the outcome: one means this request ended the
// session, none means it was already revoked (another request got there first),
// and the caller answers that as any request without a session.
//
// Arguments, in order: revoked_at (unix seconds), kid, kind.
const revokeSessionQuery = `
UPDATE japikeys
SET revoked_at = ?
WHERE kid = ?
  AND kind = ?
  AND revoked_at IS NULL`

// RevokeSession ends the session kid as of now. It reports false when there was
// nothing to revoke: the session is unknown, is not a session, or was already
// revoked, perhaps by a concurrent request. Both failure codes of the
// operation are the session_logout pair.
func (s *Store) RevokeSession(ctx context.Context, kid string, now time.Time) (bool, error) {
	o := op{failed: CodeSessionLogoutFailed, rejected: CodeSessionLogoutRejected,
		description: "sessions are temporarily unavailable"}

	results, err := s.run(ctx, o, Statement{Query: revokeSessionQuery, Args: []any{now.Unix(), kid, KindSession}})
	if err != nil {
		return false, err
	}

	return changedOnce(o, results[0])
}
