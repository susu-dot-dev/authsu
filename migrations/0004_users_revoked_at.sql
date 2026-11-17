-- An account can be revoked.
--
-- Rationale: docs/users_design.md. Conventions are those of 0001.
--
-- revoked_at is when an admin revoked the account, in Unix seconds, or NULL
-- for an account that is not revoked. Any value at all revokes, as with
-- invitations.revoked_at: there is no scheduled account revocation. The row is
-- never deleted, so the audit questions "who was this?" and "who came from
-- this invitation?" stay answerable, and an invitation's use count does not
-- drop when an account it created is revoked.
--
-- A revoked account cannot log in, and none of its sessions verify: both
-- queries read this column (internal/login/sql.go, internal/session/sql.go).
--
-- ADD COLUMN with no default and no constraint is a metadata-only change in
-- SQLite: existing rows read as NULL, which is "not revoked".

ALTER TABLE users ADD COLUMN revoked_at INTEGER;
