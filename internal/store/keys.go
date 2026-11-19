package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// Error codes of the key operations. They are stable: clients and dashboards
// may match on them.
const (
	CodeKeyListFailed     = "key_list_failed"
	CodeKeyListRejected   = "key_list_rejected"
	CodeKeyLookupFailed   = "key_lookup_failed"
	CodeKeyLookupRejected = "key_lookup_rejected"
	CodeKeyCreateFailed   = "key_create_failed"
	CodeKeyCreateRejected = "key_create_rejected"
	CodeKeyUpdateFailed   = "key_update_failed"
	CodeKeyUpdateRejected = "key_update_rejected"
	CodeKeyRevokeFailed   = "key_revoke_failed"
	CodeKeyRevokeRejected = "key_revoke_rejected"
)

// keysDescription is the client-safe text of every key operation's Unavailable
// error.
const keysDescription = "keys are temporarily unavailable"

// keysFirstPage is the cursor bound of the first page. Ids are lowercase hex
// and dashes, and 'g' sorts above both, so every id is below it (as for agents,
// agentsFirstPage).
const keysFirstPage = "g"

// Key is one of a user's own API keys as stored, with its secret's times. It
// never carries the token or its hash: no query here selects them. An agent's
// key is never one: these operations match only keys with no agent.
type Key struct {
	ID   string
	Name string

	// Scope is the key's scope list as stored (JSON text).
	Scope string

	// ExpiresAt, CreatedAt are Unix seconds, and RevokedAt is nil for a key that
	// is not revoked. They are the secret's: a key is expired once ExpiresAt
	// has passed, whether or not it was revoked.
	ExpiresAt int64
	RevokedAt *int64
	CreatedAt int64
}

// readKey reads one key row, in the column order every key statement selects or
// returns: id, name, scope, expires_at, revoked_at, created_at.
func readKey(r *row) Key {
	// Struct fields are evaluated in order, which is the column order.
	return Key{
		ID: r.text(), Name: r.text(), Scope: r.text(),
		ExpiresAt: r.integer(), RevokedAt: r.optInteger(), CreatedAt: r.integer(),
	}
}

// keyListQuery reads one page of a user's own keys, revoked and expired ones
// included, newest first. As for agents, the id is a UUIDv7, so it is the sort
// key and the cursor, and a page asks for one row more than it returns so the
// caller can tell whether there is a next page without counting.
//
// A key's expiry, revocation and creation time are on its secret, which is
// joined on the id and the kind together, as the schema's foreign key is. The
// owner and agent_id IS NULL are part of the match: a user's page holds only
// their own keys, never another user's and never an agent's (an agent's keys
// belong to the agent routes). The token's hash is not selected.
//
// Arguments, by number: ?1 user id, ?2 cursor (the id to start below;
// keysFirstPage for the first page), ?3 rows wanted.
const keyListQuery = `
SELECT k.id AS id, k.name AS name, k.scope AS scope, s.expires_at AS expires_at, s.revoked_at AS revoked_at,
       s.created_at AS created_at
FROM api_keys k
JOIN secrets s ON s.id = k.id AND s.kind = k.kind
WHERE k.user_id = ?1 AND k.agent_id IS NULL AND k.id < ?2
ORDER BY k.id DESC
LIMIT ?3`

// KeyPage is one page of a user's own keys, newest first.
type KeyPage struct {
	Keys []Key

	// Next is the cursor of the following page: the id of the last key of this
	// one. It is empty on the last page.
	Next string
}

// ListKeys returns up to limit of the user's own keys with an id below the
// cursor, revoked and expired ones included, newest first. An empty cursor
// starts at the newest key. owner is the authenticated user's id.
func (s *Store) ListKeys(
	ctx context.Context, owner string, cursor input.Cursor, limit input.PageLimit,
) (KeyPage, error) {
	o := op{failed: CodeKeyListFailed, rejected: CodeKeyListRejected, description: keysDescription}

	before := keysFirstPage
	if id, ok := cursor.ID(); ok {
		before = id.String()
	}

	// A PageLimit made by its parser is at least 1; the zero value is read as 1.
	size := max(limit.Int(), 1)
	wanted := size + 1

	keys, err := queryAll(ctx, s, o,
		Statement{Query: keyListQuery, Args: []any{owner, before, int64(wanted)}}, readKey)
	if err != nil {
		return KeyPage{}, err
	}

	// More rows than LIMIT allows is the database not doing what the query says.
	if len(keys) > wanted {
		return KeyPage{}, o.defect(fmt.Errorf("%w: %d rows, want at most %d", errRowCount, len(keys), wanted))
	}

	if len(keys) < wanted {
		return KeyPage{Keys: keys, Next: ""}, nil
	}

	keys = keys[:size]

	return KeyPage{Keys: keys, Next: keys[len(keys)-1].ID}, nil
}

// keyGetQuery reads one of a user's own keys, with the columns of keyListQuery.
// The owner and agent_id IS NULL are part of the match, so another user's key
// and an agent's key are not found, which is what the caller is told for an id
// that does not exist at all.
//
// Arguments, by number: ?1 id, ?2 user id.
const keyGetQuery = `
SELECT k.id AS id, k.name AS name, k.scope AS scope, s.expires_at AS expires_at, s.revoked_at AS revoked_at,
       s.created_at AS created_at
FROM api_keys k
JOIN secrets s ON s.id = k.id AND s.kind = k.kind
WHERE k.id = ?1 AND k.user_id = ?2 AND k.agent_id IS NULL`

// GetKey returns one of the user's own keys. It returns ErrNotFound when the
// user has no such key, which includes an id that belongs to someone else and
// the id of an agent's key.
func (s *Store) GetKey(ctx context.Context, owner string, id input.ID) (Key, error) {
	o := op{failed: CodeKeyLookupFailed, rejected: CodeKeyLookupRejected, description: keysDescription}

	return queryOne(ctx, s, o, Statement{Query: keyGetQuery, Args: []any{id.String(), owner}}, readKey)
}

// insertUserKeyQuery writes the user's own key's row, after its secret
// (insertSecretQuery, in the same batch), if the user may have another. The
// conditions are part of the write, because D1 has no interactive transaction
// and a count read before it would race with another create:
//
//   - the owner is read from users here, not trusted from the request, and must
//     be an active account, so an account revoked after the request was
//     authenticated gets no key;
//   - the owner must have fewer than ?5 keys that are active now. The count is
//     taken in the write, so two creates at the limit cannot both succeed. An
//     active key is one that is neither revoked nor expired as of ?6: the
//     predicate is activeSecretPredicate's, written over a join alias of its
//     own.
//
// A conditional INSERT ... SELECT that matches nothing is not an error, and the
// secret that precedes it in the batch does not depend on the user. So user_id
// is the one value that is NULL when no row is selected: the INSERT names a
// subselect for it, user_id is NOT NULL, and the whole batch fails as a
// conflict, which rolls the secret back with it. Without this the batch would
// commit a secret with no key.
//
// agent_id is never bound: this is a user's own key, so it is NULL.
//
// Arguments, by number: ?1 key id, ?2 kind, ?3 name, ?4 scope, ?5 the most
// active keys a user may have, ?6 now (unix seconds), ?7 user id.
const insertUserKeyQuery = `
INSERT INTO api_keys (id, kind, user_id, agent_id, name, scope)
VALUES (?1, ?2,
        (SELECT u.id FROM users u
         WHERE u.id = ?7
           AND u.revoked_at IS NULL
           AND (SELECT count(*) FROM api_keys a JOIN secrets s ON s.id = a.id AND s.kind = a.kind
                WHERE a.user_id = u.id AND a.agent_id IS NULL
                  AND (s.revoked_at IS NULL OR s.revoked_at > ?6) AND s.expires_at > ?6) < ?5),
        NULL, ?3, ?4)`

// NewKey is a user's own API key as a create writes it. The caller has already
// made the token: the store only records its hash.
type NewKey struct {
	// ID is the key's id, which is also its secret's id. Owner is the user it
	// belongs to.
	ID    string
	Owner string

	// Name is the label the user gave it.
	Name input.KeyName

	// Scope is the key's scope list as JSON. It is authoritative: nothing
	// updates it.
	Scope string

	// Hash is the SHA-256 of the key's token (32 bytes): the token itself is
	// never stored. ExpiresAt is when it stops working.
	Hash      []byte
	ExpiresAt time.Time

	// MaxActive is how many active keys a user may have: the create is refused
	// when the owner already has that many.
	MaxActive int

	// CreatedAt is when the key was created, and the instant "active" is
	// judged at for the limit.
	CreatedAt time.Time
}

// CreateKey writes a user's own key, its secret then its own row, as one batch:
// either both exist or neither does. See insertUserKeyQuery for how the owner
// being revoked or at the limit fails the batch and not just the second
// statement.
//
// It returns ErrConflict in that case: the owner already has MaxActive active
// keys, or the account was revoked after the request was authenticated. The
// write cannot tell which, and a revoked account has no session to be told on.
// The id is a fresh UUIDv7 and the hash that of 256 random bits, so no other
// constraint can conflict.
func (s *Store) CreateKey(ctx context.Context, key NewKey) error {
	o := op{failed: CodeKeyCreateFailed, rejected: CodeKeyCreateRejected, description: keysDescription}

	secret := insertSecret(key.ID, KindAPIKey, key.Hash, key.ExpiresAt.Unix(), key.CreatedAt.Unix())

	// The secret first, and the key's row second: the key's row names a user in
	// a subselect that is NULL when the owner may have no more keys, which
	// fails the batch and rolls the secret back.
	row := Statement{Query: insertUserKeyQuery, Args: []any{
		key.ID, KindAPIKey, key.Name.String(), key.Scope, int64(key.MaxActive), key.CreatedAt.Unix(), key.Owner,
	}}

	_, err := s.run(ctx, o, secret, row)

	return err
}

// keyRenameQuery renames one of a user's own keys, unless it is no longer
// active. A key that is revoked or expired is final, as an agent that is revoked
// is: renaming it would suggest it could be revived, and a listing of dead keys
// should say what they were called when they were used. The owner, agent_id IS
// NULL and the secret being active are all part of the UPDATE, because D1 has no
// interactive transaction and a read before it could be stale by the time it
// ran.
//
// It has no RETURNING: RenameKey reads the key once, after the write, with
// keyGetQuery (see there), so the outcome and the row are the same instant.
//
// Arguments, by number: ?1 name, ?2 id, ?3 user id, ?4 now (unix seconds).
const keyRenameQuery = `
UPDATE api_keys
SET name = ?1
WHERE id = ?2 AND user_id = ?3 AND agent_id IS NULL
  AND id IN (SELECT s.id FROM secrets s
             WHERE s.id = ?2 AND (s.revoked_at IS NULL OR s.revoked_at > ?4) AND s.expires_at > ?4)`

// RenameKey renames one of the user's own keys and returns it as the batch left
// it: a rename, then a read of the key. The batch is one transaction, so the read
// sees the write and nothing another request did in between.
//
// A key that is no longer active (revoked or expired) is returned unchanged, for
// the caller to refuse: the write skips it, so the row comes back with the old
// name. It returns ErrNotFound when the user has no such key, which includes
// one that belongs to someone else and an agent's key.
//
// No statement sets a constrained column to anything the parser has not bounded,
// so a conflict of any kind is a defect on our side.
func (s *Store) RenameKey(
	ctx context.Context, owner string, id input.ID, name input.KeyName, now time.Time,
) (Key, error) {
	o := op{failed: CodeKeyUpdateFailed, rejected: CodeKeyUpdateRejected, description: keysDescription}

	results, err := s.run(ctx, o,
		Statement{Query: keyRenameQuery, Args: []any{name.String(), id.String(), owner, now.Unix()}},
		Statement{Query: keyGetQuery, Args: []any{id.String(), owner}},
	)
	if err != nil {
		return Key{}, rejectKeyConflict(o, err)
	}

	return one(results[1].Rows, o, readKey)
}

// keyRevokeQuery revokes one of a user's own keys, now: a key of the user, with
// no agent, and not the secret the request presented.
//
// The key must be the user's own, in the write itself. An id that is not the
// user's, or names an agent's key, a session or an invitation, matches nothing,
// whatever else it names. The presented credential is excluded in the write
// too (?4): ending the credential making the request is logout's, which needs
// no scope, and a route that needs key:revoke must not become a second way to
// do it.
//
// Only a secret that is not yet revoked as of now is changed. One scheduled to
// be revoked later is brought forward to now, and one already revoked keeps its
// earlier time, so revoking twice cannot move a revocation later. An expired key
// is revoked like any other: the time recorded is when the user ended it.
//
// It has no RETURNING: RevokeKey reads the key after, with keyRevokeReadQuery, so
// the row reports the revocation whichever request made it.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 id, ?3 user id, ?4 the
// presented secret's id.
const keyRevokeQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE id = ?2 AND id <> ?4
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND id IN (SELECT id FROM api_keys WHERE id = ?2 AND user_id = ?3 AND agent_id IS NULL)`

// keyRevokeReadQuery is the last statement of RevokeKey: it reads the key as the
// write left it, with the columns of keyGetQuery, and matches no row for the
// secret the request presented (?3), as the write does not. So the presented
// credential is answered exactly as an id that does not exist, and a request
// cannot use this route to learn anything about it.
//
// Arguments, by number: ?1 id, ?2 user id, ?3 the presented secret's id.
const keyRevokeReadQuery = `
SELECT k.id AS id, k.name AS name, k.scope AS scope, s.expires_at AS expires_at, s.revoked_at AS revoked_at,
       s.created_at AS created_at
FROM api_keys k
JOIN secrets s ON s.id = k.id AND s.kind = k.kind
WHERE k.id = ?1 AND k.user_id = ?2 AND k.agent_id IS NULL AND k.id <> ?3`

// RevokeKey revokes one of the user's own keys as of now, and returns it as the
// write left it. except is the id of the secret the request presented, which is
// never revoked here (see keyRevokeQuery): revoking the credential in use is
// logout's.
//
// Revoking a key that is already revoked succeeds and keeps the earlier time, so
// the call is idempotent. It returns ErrNotFound when the user has no such key,
// which includes one that belongs to someone else, an agent's, and except
// itself: the caller's own credential is not a key this route will touch, and is
// answered as one that does not exist.
func (s *Store) RevokeKey(ctx context.Context, owner string, id input.ID, except string, now time.Time) (Key, error) {
	o := op{failed: CodeKeyRevokeFailed, rejected: CodeKeyRevokeRejected, description: keysDescription}

	results, err := s.run(ctx, o,
		Statement{Query: keyRevokeQuery, Args: []any{now.Unix(), id.String(), owner, except}},
		Statement{Query: keyRevokeReadQuery, Args: []any{id.String(), owner, except}},
	)
	if err != nil {
		return Key{}, rejectKeyConflict(o, err)
	}

	return one(results[1].Rows, o, readKey)
}

// rejectKeyConflict turns a conflict into a defect for an operation that writes
// nothing a constraint of the data could refuse: run passes a conflict through
// for the operation to hand to its feature, and there is none here. Any other
// error is returned as is.
func rejectKeyConflict(o op, err error) error {
	if errors.Is(err, ErrConflict) {
		return o.defect(err)
	}

	return err
}
