-- The schema: secrets, invitations, users, passkey credentials, sessions,
-- agents and API keys.
--
-- Rationale: docs/secrets_design.md, docs/invitations_design.md,
-- docs/registration_design.md, docs/login_design.md, docs/users_design.md,
-- docs/agents_design.md and docs/permissions_design.md.
--
-- Timestamps are Unix seconds. Identifiers we create are UUIDv7 in canonical
-- text form; hashes and WebAuthn bytes are BLOB.
--
-- Size limits. Every client-influenced column has a size CHECK as a last-line
-- backstop in case input sanitising is ever forgotten in Go. Go still rejects
-- bad input first, with a proper error; a violation here fails the whole
-- statement or batch. SQLite cannot alter a CHECK, so changing a limit means
-- rebuilding the table: the limits below are generous guards against abuse,
-- not tight fits. Three details:
--   * length() counts bytes for a BLOB but characters for TEXT, so every
--     BLOB check also asserts typeof(col) = 'blob'. Columns are loosely typed
--     and would otherwise accept TEXT, which length() would count differently.
--   * The id check bounds size and shape (36 chars of lowercase hex and dashes).
--     It does not validate that the value is a UUIDv7; Go does that.
--   * Free text bounds BYTES and refuses NUL. SQLite's length() on TEXT stops
--     at the first NUL, so length(name) <= 256 alone would accept a name of
--     one character, a NUL and megabytes after it. cast(.. AS BLOB) counts
--     every byte, and instr(.., char(0)) = 0 refuses the NUL outright. Go
--     counts characters (a character is at most 4 bytes), so the byte ceiling
--     is 4x the character limit and only ever fires on a Go bug.
--
-- No CHECK constrains a value that grows with the code (a role, an invitation
-- type, a scope list, the kind of a secret): Go validates those, because
-- changing a CHECK means rebuilding the table (docs/DATABASE.md). The kind
-- column of each kind's own table is the exception: it is fixed to one literal
-- and never changes, so it is an invariant and not an open-ended set.
--
-- Foreign keys are enforced: D1 runs with foreign_keys on and does not allow
-- turning it off. The ON DELETE actions and the triggers below rely on that,
-- and so does the check that a kind's row attaches only to a secret of its
-- own kind.
--
-- invitations and users reference each other (users.invitation_id,
-- invitations.created_by). SQLite does not check foreign keys until a row is
-- written, so the order of the CREATE TABLE statements does not matter. The
-- first-run invitation has a NULL created_by, so there is no insert-order
-- cycle either.

-- ---------------------------------------------------------------------------
-- Secrets: the one base table (docs/secrets_design.md)
-- ---------------------------------------------------------------------------
--
-- A secret is a value the server generates, whose possession is authorization
-- and which the server must be able to revoke. This table holds only what
-- every kind shares; each kind has its own table below, whose primary key is
-- the secret's id. A session, an API key or an invitation is one row here and
-- one row of its kind, under one id.
--
-- A secret is active when
--     (revoked_at IS NULL OR revoked_at > now) AND expires_at > now
-- and every kind answers "is it valid right now?" with exactly that. Revocation
-- takes effect at revoked_at, a time and not a flag: a revocation scheduled for
-- later would work without a schema change. That is also why no index below is
-- partial on revoked_at IS NULL. Revoking again keeps the first time.
--
-- Rows are removed on expires_at, never on revocation. Some kinds hang a
-- single-use guard on their row (sessions.granted_from), and the guard has to
-- outlive whatever it guards; deleting the row early would reopen replay of a
-- login captured just before. Every secret expires, so expires_at is NOT NULL.

CREATE TABLE secrets (
    id         TEXT    PRIMARY KEY
                       CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    -- Which kind's table holds the rest of this secret. Go owns the set of
    -- values, so there is no CHECK on it; each kind's table fixes its own.
    kind       TEXT    NOT NULL
                       CHECK (typeof(kind) = 'text' AND length(kind) BETWEEN 1 AND 64),

    -- SHA-256 of the whole token, prefix included. The token itself is never
    -- stored, and the hash is how a presented token is found. UNIQUE, so a
    -- hash collision fails the insert and cannot make two secrets
    -- indistinguishable.
    hash       BLOB    NOT NULL UNIQUE
                       CHECK (typeof(hash) = 'blob' AND length(hash) = 32),

    expires_at INTEGER NOT NULL,

    -- NULL while the secret is active with no end scheduled.
    revoked_at INTEGER,

    created_at INTEGER NOT NULL,

    -- Makes (id, kind) a foreign key target, so a kind's table can bind its
    -- row to a secret of its own kind and no other. id is already unique; this
    -- adds nothing to what may be stored.
    UNIQUE (id, kind)
);

-- Listing and removal of expired rows, and anything across all kinds.
CREATE INDEX secrets_expires_at ON secrets (expires_at);

-- ---------------------------------------------------------------------------
-- Invitations, users and passkey credentials
-- ---------------------------------------------------------------------------

-- An invitation is a kind of secret. Its expiry, revocation and creation time
-- are on its secret row. The kind column is fixed to 'invitation' and the
-- foreign key is on (id, kind), so this row can attach only to an invitation
-- secret, and no other table can claim the same secret.
--
-- Invitations are never deleted: the accounts they created refer to them
-- (users.invitation_id has no ON DELETE action). Revoke one instead.
CREATE TABLE invitations (
    id          TEXT    PRIMARY KEY
                        CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    kind        TEXT    NOT NULL DEFAULT 'invitation'
                        CHECK (kind = 'invitation'),

    -- What the invitation grants (for example 'first_run'). Go maps the type
    -- to a role and to any extra rules; deliberately not constrained to a set
    -- of values here so new types need no migration.
    type        TEXT    NOT NULL
                        CHECK (typeof(type) = 'text' AND length(type) BETWEEN 1 AND 64),

    -- Typed by an admin. At most 256 characters in Go; the byte ceiling is
    -- 4 bytes per character.
    label       TEXT    NOT NULL DEFAULT ''
                        CHECK (typeof(label) = 'text'
                               AND instr(label, char(0)) = 0
                               AND length(cast(label AS BLOB)) <= 1024),

    -- Maximum number of accounts this invitation may create. "Uses so far"
    -- is the number of users whose invitation_id points here.
    num_invites INTEGER NOT NULL DEFAULT 1 CHECK (num_invites > 0),

    -- NULL for the first-run invitation, and for invitations whose creator
    -- has since been deleted.
    created_by  TEXT    REFERENCES users (id) ON DELETE SET NULL,

    -- Deleting the secret deletes this row. The reverse is the trigger below.
    FOREIGN KEY (id, kind) REFERENCES secrets (id, kind) ON DELETE CASCADE
);

CREATE TABLE users (
    id            TEXT    PRIMARY KEY
                          CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    -- WebAuthn user.id. Random and created at registration begin; unique, so
    -- a signed challenge can produce at most one account. The spec allows at
    -- most 64 bytes and forbids empty.
    user_handle   BLOB    NOT NULL UNIQUE
                          CHECK (typeof(user_handle) = 'blob' AND length(user_handle) BETWEEN 1 AND 64),

    -- Derived from the invitation type at creation. Not constrained to a set
    -- of values here so new roles need no migration.
    role          TEXT    NOT NULL
                          CHECK (typeof(role) = 'text' AND length(role) BETWEEN 1 AND 64),

    -- The account is the redemption. No ON DELETE action, so an invitation
    -- that has created accounts cannot be deleted (revoke it instead).
    invitation_id TEXT    NOT NULL REFERENCES invitations (id),

    -- JSON, currently {"name": "..."}. Supplied by the registering user.
    profile       TEXT    NOT NULL DEFAULT '{}'
                          CHECK (typeof(profile) = 'text' AND json_valid(profile) AND length(profile) <= 1024),

    -- When an admin revoked the account, in Unix seconds, or NULL for an
    -- account that is not revoked (docs/users_design.md). Any value at all
    -- revokes, as with agents.revoked_at: there is no scheduled account
    -- revocation. The row is never deleted, so the audit questions "who was
    -- this?" and "who came from this invitation?" stay answerable, and an
    -- invitation's use count does not drop when an account it created is
    -- revoked.
    --
    -- A revoked account cannot log in, and none of its sessions or keys
    -- resolve: every query that resolves a credential or starts a login reads
    -- this column.
    revoked_at    INTEGER,

    created_at    INTEGER NOT NULL
);

-- Cap check and "who came from this invitation".
CREATE INDEX users_invitation_id ON users (invitation_id);

CREATE TABLE credentials (
    id            TEXT    PRIMARY KEY
                          CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    -- Chosen by the authenticator, not by us. A collision fails the insert
    -- and so the whole registration batch. The spec allows at most 1023 bytes.
    credential_id BLOB    NOT NULL UNIQUE
                          CHECK (typeof(credential_id) = 'blob' AND length(credential_id) BETWEEN 1 AND 1023),

    -- Required, so a credential cannot exist without its account.
    user_id       TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- COSE key. About 77 bytes for ES256 and 270 for RSA-2048; the limit
    -- leaves room for RSA-4096.
    public_key    BLOB    NOT NULL
                          CHECK (typeof(public_key) = 'blob' AND length(public_key) BETWEEN 1 AND 1024),

    -- Packed credential flags (UP, UV, BE, BS). UV and BS can change on login.
    flags         INTEGER NOT NULL CHECK (flags BETWEEN 0 AND 255),

    -- Everything else about the credential that is written once at
    -- registration: attestation type and format, transports, AAGUID,
    -- attachment, raw attestation, extensions. Raw attestation is base64
    -- inside JSON, and TPM attestation can carry certificate chains.
    metadata      TEXT    NOT NULL
                          CHECK (typeof(metadata) = 'text' AND json_valid(metadata) AND length(metadata) <= 16384),

    created_at    INTEGER NOT NULL
);

-- List a user's passkeys.
CREATE INDEX credentials_user_id ON credentials (user_id);

-- One public key belongs to one credential (docs/login_design.md).
--
-- Registration asks for attestation "none", so the response carries no proof
-- that the registrant holds the private key, and public keys are not secret.
-- Without this index anyone with an invitation could register another
-- account's public key under a credential id of their own. The login
-- signature covers neither the credential id nor the user handle, so a
-- response for the real key would then verify against both rows. With it, a
-- signature can only verify against the one row that stores its key, and the
-- user handle check is a consistency check on that row.
--
-- Uniqueness is on the stored bytes. Registration only stores the one
-- canonical COSE encoding of an ES256 key, so a key has exactly one spelling.
-- A format that allowed several would have to be canonicalised before this
-- index means "one key".
CREATE UNIQUE INDEX credentials_public_key ON credentials (public_key);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

-- A session is issued by login and lasts a fixed time: it is never extended or
-- refreshed, so there is one row per login and nothing else writes a session.
-- Its expiry and revocation are on its secret row. Logout is the only thing
-- that revokes one, and sets it to now.
--
-- The kind column is fixed to 'session' and the foreign key is on (id, kind),
-- so this row can attach only to a session secret.
CREATE TABLE sessions (
    id            TEXT    PRIMARY KEY
                          CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    kind          TEXT    NOT NULL DEFAULT 'session'
                          CHECK (kind = 'session'),

    -- The account the session is for. Sessions die with the account.
    user_id       TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- The passkey that started this session. For auditing, and deleting a
    -- passkey ends its sessions.
    credential_id TEXT    NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,

    -- The SHA-256 of the login challenge that issued this session. UNIQUE, so
    -- a replayed login collides on insert and cannot create a second session.
    -- Do not remove the UNIQUE: it is the replay guard. It outlives its
    -- challenge because the session is removed only once it has expired.
    granted_from  BLOB    NOT NULL UNIQUE
                          CHECK (typeof(granted_from) = 'blob' AND length(granted_from) = 32),

    -- Deleting the secret deletes this row. The reverse is the trigger below.
    FOREIGN KEY (id, kind) REFERENCES secrets (id, kind) ON DELETE CASCADE
);

-- A user's sessions, to revoke them with the account.
CREATE INDEX sessions_user_id ON sessions (user_id);

-- The sessions a passkey started: this index is what keeps deleting a passkey,
-- and its cascade, from scanning the table.
CREATE INDEX sessions_credential_id ON sessions (credential_id);

-- ---------------------------------------------------------------------------
-- Agents and their labels
-- ---------------------------------------------------------------------------

-- agents: software acting on one user's behalf (docs/agents_design.md and
-- docs/permissions_design.md).
--
-- An agent is not an account. It has no invitation and no passkey: it is
-- something a user has. user_id is its owner, set when it is created and never
-- changed, and it is the user whose authority the agent borrows. The set of a
-- user's agents is flat; nothing records which agent (if any) created another.
--
-- scopes is the agent's ceiling, as the text of a scope list (see
-- docs/permissions_design.md). It is NOT NULL and always written out in full.
-- Which names are valid is Go's to decide, and changes with the code, so the
-- database never validates the contents: a CHECK here would need a table
-- rebuild every time a scope or bundle was added. The size CHECK is only a
-- backstop.
--
-- revoked_at is when the agent was revoked, or NULL. Any value at all revokes,
-- as with users.revoked_at and secrets.revoked_at. The row is never deleted,
-- so "which agent did this?" stays answerable. Revoking an agent revokes its
-- keys; revoking its user revokes it.
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

-- agent_labels: short tags a user attaches to their own agents, to group and
-- find them (GET /api/agent?label=...). Rationale: docs/agents_design.md.
--
-- Why a table and not a JSON array on agents. A label set is edited by adding
-- or removing ONE member while other requests do the same, and D1 has no
-- interactive transaction, so the edit must be one atomic statement.
-- SQLite's json_patch is RFC 7396 merge-patch, which replaces an array whole and
-- cannot append or remove an element; json_insert/json_remove need an element's
-- index, which is a read the write would race with. A row per label makes
-- "add" an INSERT that ignores a duplicate and "remove" a DELETE, each a single
-- statement that is safe against any interleaving, and the primary key makes
-- the set a set. SQLite also cannot index into JSON, so "agents with label X"
-- over a JSON column would test every element of every agent; here the list
-- seeks the owner's agents by agents_user_id and probes the primary key for
-- each one. There is deliberately no index on label alone: no query looks a
-- label up across owners, so one would only add a write per label added or
-- removed. Add one if such a query is ever introduced.
--
-- Unlike agents, users and invitations, labels are deleted for real when
-- removed. They are mutable metadata chosen by the owner, not a record of
-- authority, so there is nothing for an audit trail to keep: "which agent did
-- this?" is answered by the agent, which is never deleted. A label row has no
-- identity beyond (agent_id, label), so a tombstone would only force every read
-- to filter it out and every re-add to revive it.
--
-- label is bounded in BYTES and refuses NUL, as above. Go accepts only
-- [a-z0-9._-] (see input.Label), so the CHECK is a backstop that fires only on
-- a Go bug; it deliberately does not repeat the alphabet, which is Go's to
-- change (docs/DATABASE.md: no CHECK on a set that grows with the code).
-- ON DELETE CASCADE follows api_keys.agent_id; agents are never deleted in
-- practice.
CREATE TABLE agent_labels (
    agent_id TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,

    label    TEXT NOT NULL
                  CHECK (typeof(label) = 'text'
                         AND instr(label, char(0)) = 0
                         AND length(cast(label AS BLOB)) BETWEEN 1 AND 63),

    -- One row per (agent, label): this is what makes adding idempotent and
    -- what an add's ON CONFLICT targets. It also serves "the labels of an
    -- agent" by prefix, and the list filter's "does this agent have label X"
    -- probe.
    PRIMARY KEY (agent_id, label)
) WITHOUT ROWID;

-- ---------------------------------------------------------------------------
-- API keys
-- ---------------------------------------------------------------------------

-- An API key is a kind of secret that lets a user, or an agent acting for a
-- user, call the API without a browser. Its expiry and revocation are on its
-- secret row.
--
-- The kind column is fixed to 'api_key' and the foreign key is on (id, kind),
-- so this row can attach only to an API key secret: a key cannot be attached
-- to a session's secret.
CREATE TABLE api_keys (
    id       TEXT    PRIMARY KEY
                     CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    kind     TEXT    NOT NULL DEFAULT 'api_key'
                     CHECK (kind = 'api_key'),

    -- The key's subject: whose authority it carries. An agent's key is still
    -- its user's, with the agent as the actor, so a user's keys, an agent's
    -- keys included, die with the account.
    user_id  TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- The agent this key belongs to. NULL is the user's own key.
    agent_id TEXT    REFERENCES agents (id) ON DELETE CASCADE,

    -- What the key may do, as the text of a scope list, so a key can be listed
    -- with its permissions: the token itself is never stored. It is
    -- authoritative and nothing ever updates it. Which names are valid is
    -- Go's to decide, as with agents.scopes, so the CHECK is only a size
    -- backstop.
    scope    TEXT    NOT NULL
                     CHECK (typeof(scope) = 'text'
                            AND instr(scope, char(0)) = 0
                            AND length(cast(scope AS BLOB)) BETWEEN 1 AND 1024),

    -- Deleting the secret deletes this row. The reverse is the trigger below.
    FOREIGN KEY (id, kind) REFERENCES secrets (id, kind) ON DELETE CASCADE
);

-- A user's keys, to revoke them with the account.
CREATE INDEX api_keys_user_id ON api_keys (user_id);

-- An agent's keys, to revoke them with it.
CREATE INDEX api_keys_agent_id ON api_keys (agent_id) WHERE agent_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Deleting a kind's row deletes its secret
-- ---------------------------------------------------------------------------
--
-- A secret and its kind's row exist together and are removed together
-- (docs/secrets_design.md, "Deletion goes both ways"). The foreign keys above
-- cascade from the secret down to its kind's row. They cannot cascade the
-- other way: the secret is referenced by its kind's row and cannot reference
-- its owner, because an invitation has no user. So a delete that starts above
-- a kind's row, such as a user's or a passkey's, removes the sessions or keys
-- through their ON DELETE CASCADE, and these triggers then remove the secrets
-- behind them. Without them such a delete would leave inert secrets that
-- belong to nothing. Triggers fire for rows deleted by a cascade, which relies
-- on foreign keys being enforced.
--
-- An invitation with accounts cannot be deleted at all (see users.invitation_id),
-- so its trigger only runs for an invitation that never created one.
--
-- The kind literal restates the table's fixed kind. The trigger deletes only a
-- secret of that kind, so it can never remove another kind's secret.

CREATE TRIGGER invitations_delete_secret AFTER DELETE ON invitations
BEGIN
    DELETE FROM secrets WHERE id = OLD.id AND kind = 'invitation';
END;

CREATE TRIGGER sessions_delete_secret AFTER DELETE ON sessions
BEGIN
    DELETE FROM secrets WHERE id = OLD.id AND kind = 'session';
END;

CREATE TRIGGER api_keys_delete_secret AFTER DELETE ON api_keys
BEGIN
    DELETE FROM secrets WHERE id = OLD.id AND kind = 'api_key';
END;
