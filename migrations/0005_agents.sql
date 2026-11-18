-- agents: software acting on one user's behalf.
--
-- Rationale: docs/agents_design.md and docs/permissions_design.md. Conventions
-- are those of 0001: Unix seconds, UUIDv7 text ids, size CHECKs as a backstop
-- for Go, and no CHECK on a value that grows with the code.
--
-- An agent is not an account. It has no invitation and no passkey: it is
-- something a user has. user_id is its owner, set when it is created and never
-- changed, and it is the user whose authority the agent borrows. The set of a
-- user's agents is flat; nothing records which agent (if any) created another.
--
-- Size CHECKs here bound BYTES and refuse NUL. SQLite's length() on TEXT stops
-- at the first NUL, so length(name) <= 256 alone would accept a name of one
-- character, a NUL and megabytes after it. cast(.. AS BLOB) counts every byte,
-- and instr(.., char(0)) = 0 refuses the NUL outright. Go counts characters
-- (a character is at most 4 bytes), so the byte ceiling is 4x the character
-- limit and only ever fires on a Go bug.
--
-- scopes is the agent's ceiling, as the text of a scope list (see
-- docs/permissions_design.md). It is NOT NULL and always written out in full.
-- Which names are valid is Go's to decide, and changes with the code, so the
-- database never validates the contents: a CHECK here would need a table
-- rebuild every time a scope or bundle was added. The size CHECK is only a
-- backstop. Nothing reads or enforces it yet.
--
-- revoked_at is when the agent was revoked, or NULL. Any value at all revokes,
-- as with users.revoked_at and invitations.revoked_at. The row is never
-- deleted, so "which agent did this?" stays answerable. Revoking an agent
-- revokes its keys; revoking its user revokes it.

CREATE TABLE agents (
    id         TEXT    PRIMARY KEY
                       CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    -- The owner. Accounts are revoked, never deleted, so this never cascades
    -- in practice; it follows the other tables if one ever is.
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- A label chosen by the user, to tell their agents apart.
    name       TEXT    NOT NULL
                       CHECK (typeof(name) = 'text'
                              AND instr(name, char(0)) = 0
                              AND length(cast(name AS BLOB)) BETWEEN 1 AND 1024),

    -- The agent's scope list, stored as text.
    scopes     TEXT    NOT NULL
                       CHECK (typeof(scopes) = 'text'
                              AND instr(scopes, char(0)) = 0
                              AND length(cast(scopes AS BLOB)) BETWEEN 1 AND 1024),

    revoked_at INTEGER,

    created_at INTEGER NOT NULL
);

-- A user's agents, newest first, and the per-user limit on how many exist. The
-- id is a UUIDv7, so it is in creation order: it is the sort key and the
-- pagination cursor, and created_at is only a value to show.
CREATE INDEX agents_user_id ON agents (user_id, id);

-- A key may belong to an agent. The token's subject is still the user (the
-- agent is its actor), so user_id is unchanged and a user's keys, an agent's
-- keys included, still die with the account. NULL for sessions and for a
-- user's own keys.
--
-- ADD COLUMN with a REFERENCES clause is allowed in SQLite when the default is
-- NULL, and is a metadata-only change.
ALTER TABLE japikeys ADD COLUMN agent_id TEXT REFERENCES agents (id) ON DELETE CASCADE;

-- A copy of the token's scope claim, so a key can be listed with what it may
-- do: the token itself is never stored. The signed claim is authoritative. NULL
-- for keys minted before scopes existed, which includes every session.
ALTER TABLE japikeys ADD COLUMN scope TEXT
    CHECK (scope IS NULL OR (typeof(scope) = 'text'
                             AND instr(scope, char(0)) = 0
                             AND length(cast(scope AS BLOB)) BETWEEN 1 AND 1024));

-- An agent's keys, to revoke them with it.
CREATE INDEX japikeys_agent_id ON japikeys (agent_id) WHERE agent_id IS NOT NULL;
