-- The schema: secrets, invitations, users, passkey credentials, organizations
-- and sandboxes, sessions, agents, API keys and OAuth grants.
--
-- Rationale: docs/secrets_design.md, docs/invitations_design.md,
-- docs/registration_design.md, docs/login_design.md, docs/users_design.md,
-- docs/orgs_design.md, docs/agents_design.md, docs/permissions_design.md and
-- docs/oauth_design.md.
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
-- type, a scope list, the kind of a secret, the kind of an organization, the
-- role in an organization): Go validates those, because changing a CHECK means
-- rebuilding the table (docs/DATABASE.md). The kind column of each kind's own
-- table is the exception: it is fixed to one literal and never changes, so it
-- is an invariant and not an open-ended set. So are the few rules about the two
-- kinds of organization below, which restate facts that define them (a sandbox
-- has an expiry and a standard organization has none) and are not a list of
-- values.
--
-- Foreign keys are enforced: D1 runs with foreign_keys on and does not allow
-- turning it off. The ON DELETE actions and the triggers below rely on that,
-- and so does the check that a kind's row attaches only to a secret of its
-- own kind.
--
-- Some tables reference each other: invitations and users (users.invitation_id,
-- invitations.created_by), and users and organizations (users.org_id,
-- orgs.created_by). SQLite does not check a foreign key until a row is written,
-- so the order of the CREATE TABLE statements does not matter. The first-run
-- invitation has a NULL created_by, so there is no insert-order cycle there. An
-- account and its own organization are the cycle that cannot be ordered, so
-- users.org_id is a deferred key (see there).

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

    created_at    INTEGER NOT NULL,

    -- The standard organization the user belongs to, for the life of the
    -- account (docs/orgs_design.md, principle 2). It is set by the insert that
    -- creates the account and never changes, so membership is one fact about
    -- the user and a request never has to say which organization it acts in.
    -- It is a column read with the account, like role and revoked_at, so a
    -- credential's resolve reads it in the same statement.
    --
    -- org_kind is fixed to 'standard' and the foreign key is on (org_id,
    -- org_kind), so a user can belong only to a standard organization and
    -- never to a sandbox, the same device the kind tables use for secrets.
    --
    -- There is no ON DELETE action. A standard organization is never deleted,
    -- so a delete that would leave a member behind is refused.
    --
    -- The key is DEFERRABLE INITIALLY DEFERRED because an account and the
    -- organization created for it reference each other (orgs.created_by), and
    -- registration writes both in one batch, which D1 runs as one transaction:
    -- the key is checked when it commits, whichever row was inserted first.
    org_id        TEXT    NOT NULL,
    org_kind      TEXT    NOT NULL DEFAULT 'standard'
                          CHECK (org_kind = 'standard'),

    FOREIGN KEY (org_id, org_kind) REFERENCES orgs (id, kind)
        DEFERRABLE INITIALLY DEFERRED
);

-- Cap check and "who came from this invitation".
CREATE INDEX users_invitation_id ON users (invitation_id);

-- The members of an organization. Ending in id, the sort key and the pagination
-- cursor of the member list, lets a page read just its rows in order, with no
-- sort of the whole organization.
CREATE INDEX users_org_id ON users (org_id, id);

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
-- Organizations and sandboxes (docs/orgs_design.md)
-- ---------------------------------------------------------------------------

-- An organization is a group of users with administrators; a sandbox is a
-- temporary organization that holds agents and confines them. They are one
-- table with a kind, because both are a named thing with administrators that
-- other things belong to, and one table is one thing to reason about. Go owns
-- the set of kinds ('standard' and 'sandbox'), so kind has only a size CHECK;
-- the rules below that name them are what define each kind.
--
--   * A sandbox has an expiry, and is deleted by hand: an expired one is inert
--     when read (nothing here deletes on time).
--     Deleting it reaches its agents through agents.sandbox_id, and from them
--     their keys, labels and OAuth grants and the secrets behind them
--     (docs/orgs_design.md, principle 5). That is one level of cascade deeper
--     than any other delete, and there is deliberately NO new trigger for it:
--     the four delete triggers at the end of this file are all D1 allows (see
--     "Why only four triggers"), and the existing ones already remove the
--     secrets of the keys and grants the cascade reaches. Whether the depth
--     fits can be shown only on the real database; the end-to-end test of
--     deleting a sandbox that holds agents with keys, labels and grants is
--     required, and if it fails the design is wrong, not the test.
--   * A standard organization has no expiry and is never deleted, so that
--     whatever is attributed to it stays answerable. It is created for an
--     account, as part of registering it.
--
-- created_by is who made it. It has no ON DELETE action: users are revoked and
-- never deleted, and an organization's creator must stay answerable. It is
-- also the one fact the sandbox limit counts (docs/orgs_design.md, principle
-- 6): the sandboxes per user that have not expired. The sandboxes are their
-- own record, so there is no counter to keep in step.
--
-- name is typed by a person and bounded in BYTES and refuses NUL, as
-- agents.name is. Go counts characters (at most 4 bytes each), so the byte
-- ceiling is 4x the 256-character limit.
CREATE TABLE orgs (
    id         TEXT    PRIMARY KEY
                       CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    kind       TEXT    NOT NULL
                       CHECK (typeof(kind) = 'text' AND length(kind) BETWEEN 1 AND 64),

    name       TEXT    NOT NULL
                       CHECK (typeof(name) = 'text'
                              AND instr(name, char(0)) = 0
                              AND length(cast(name AS BLOB)) BETWEEN 1 AND 1024),

    created_by TEXT    NOT NULL REFERENCES users (id),

    -- When a sandbox stops working, in Unix seconds. Required for a sandbox,
    -- NULL for a standard organization, which does not expire. A time and not
    -- a flag, as secrets.expires_at is, so "is it still standing" is read
    -- against now whenever a credential is used.
    expires_at INTEGER,

    created_at INTEGER NOT NULL,

    CHECK (kind <> 'sandbox'  OR expires_at IS NOT NULL),
    CHECK (kind <> 'standard' OR expires_at IS NULL),

    -- Makes (id, kind) a foreign key target, so a user can be bound to a
    -- standard organization and an agent to a sandbox, and no other. id is
    -- already unique; this adds nothing to what may be stored.
    UNIQUE (id, kind)
);

-- The sandbox limit: how many sandboxes a user holds that have not expired, a
-- count over one creator, by kind and expiry.
CREATE INDEX orgs_created_by ON orgs (created_by, kind, expires_at);

-- Who looks after an organization. It is a row and not a role on the user: a
-- role is one value, so a user could never administer two organizations, nor be
-- both a platform administrator and an organization administrator
-- (docs/orgs_design.md, principle 3). It is not a scope either, which can only
-- narrow what a user may already do: who may look after a given organization
-- is a condition of the write that depends on it.
--
-- A sandbox has exactly one administrator, the user who made it, who keeps
-- their own organization. Both foreign keys cascade: deleting a sandbox
-- releases its administrator, who stays, and deleting an account (which only
-- ever happens in tests) takes its rows with it.
--
-- A standard organization is never left without an unrevoked administrator by
-- the write that removes one: demoting an administrator refuses to take the
-- last unrevoked administrator, a count in the write itself, since no CHECK can
-- state it. Revoking the ACCOUNT of the last administrator is not refused:
-- refusing it would let an organization administrator shield themselves from
-- platform revocation. The organization is then left with no unrevoked
-- administrator, and a platform administrator's override (who may do anything
-- an organization administrator may, on any organization) is how it is
-- managed.
CREATE TABLE org_admins (
    org_id     TEXT    NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,

    PRIMARY KEY (org_id, user_id)
) WITHOUT ROWID;

-- The organizations a user administers, and the rows to remove with them. The
-- table is WITHOUT ROWID, so SQLite ends this index with the primary key: it is
-- (user_id, org_id), and a page of the organizations a user administers is read
-- from it in org_id order, which is the sort key of the organization list.
CREATE INDEX org_admins_user_id ON org_admins (user_id);

-- The organization an invitation names (docs/orgs_design.md, principle 2). One
-- row for an invitation that names one, and none for one that does not: an
-- account that registers with the latter is given an organization of its own.
-- The row serves every registration with the invitation, because an invitation
-- may admit several people, and goes only with its invitation (the key
-- cascades; an invitation is revoked and never deleted once it has created an
-- account).
--
-- Only a standard organization can be named: kind is fixed to 'standard' and
-- the foreign key is on (org_id, kind), so a sandbox, which has no members,
-- cannot be. There is no ON DELETE action on it: a standard organization is
-- never deleted, and a delete that would leave an invitation naming it is
-- refused.
--
-- role is what the registrant becomes in the organization: Go owns the set
-- ('member' and 'admin'), so there is only a size CHECK.
CREATE TABLE invitation_orgs (
    invitation_id TEXT    NOT NULL PRIMARY KEY REFERENCES invitations (id) ON DELETE CASCADE,

    org_id        TEXT    NOT NULL,
    kind          TEXT    NOT NULL DEFAULT 'standard'
                          CHECK (kind = 'standard'),

    role          TEXT    NOT NULL
                          CHECK (typeof(role) = 'text' AND length(role) BETWEEN 1 AND 64),

    created_at    INTEGER NOT NULL,

    FOREIGN KEY (org_id, kind) REFERENCES orgs (id, kind)
);

-- The invitations that name an organization. Without it, every delete of an
-- organization (a sandbox, by hand) scans the table to check that no invitation
-- still names it.
CREATE INDEX invitation_orgs_org_id ON invitation_orgs (org_id);

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
--
-- sandbox_id is the sandbox the agent is confined to, or NULL for an ordinary
-- agent (docs/orgs_design.md, principle 4). It is how a restriction is
-- recorded, so it must never fall back to "unrestricted" when what it points
-- at disappears: an agent whose sandbox vanished would otherwise read as an
-- ordinary agent with all of its user's reach. So the key cascades, and the
-- agent is deleted with its sandbox and is not released from it. This is the
-- one agent that is removed and not revoked, and only because nothing outside a
-- sandbox can have recorded it.
--
-- first_party marks the agent that a first-party login creates
-- (docs/oauth_design.md, "First-party login"). Every OAuth grant is held by an
-- agent, and a first-party login has no consent screen and nobody to choose or
-- name one, so authsu creates an ordinary agent for it, named after the app. It
-- is a real agent in every other way: the user lists it, counts it against
-- their limit and can revoke it, which ends its grants. The flag is 1 for those
-- agents and 0 for every other; it only says who created the agent, so a UI may
-- group or hide them. It grants nothing and no query decides authorization from
-- it.
--
-- first_party_client is the client_id of the trusted app the agent was created
-- for, NULL for every other agent. With the owner it identifies the agent a
-- later login of the same user at the same app attaches to, so signing in again
-- reuses it and does not create another (see agents_first_party below).
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

    created_at INTEGER NOT NULL,

    -- sandbox_kind is fixed to 'sandbox' and the foreign key is on (sandbox_id,
    -- sandbox_kind), so an agent can be confined only to a sandbox and never to
    -- a standard organization, which is not a boundary. A NULL sandbox_id
    -- leaves the key unchecked: an ordinary agent.
    sandbox_id   TEXT,
    sandbox_kind TEXT NOT NULL DEFAULT 'sandbox'
                      CHECK (sandbox_kind = 'sandbox'),

    first_party        INTEGER NOT NULL DEFAULT 0
                               CHECK (first_party IN (0, 1)),
    first_party_client TEXT
                       CHECK (first_party_client IS NULL
                              OR (first_party = 1
                                  AND typeof(first_party_client) = 'text'
                                  AND instr(first_party_client, char(0)) = 0
                                  AND length(cast(first_party_client AS BLOB)) BETWEEN 1 AND 512)),

    FOREIGN KEY (sandbox_id, sandbox_kind) REFERENCES orgs (id, kind) ON DELETE CASCADE
);

-- A user's agents, newest first, and the per-user limit on how many exist. The
-- id is a UUIDv7, so it is in creation order: it is the sort key and the
-- pagination cursor, and created_at is only a value to show.
CREATE INDEX agents_user_id ON agents (user_id, id);

-- A sandbox's agents, to list them and to delete them with it. Partial: most
-- agents are ordinary.
CREATE INDEX agents_sandbox_id ON agents (sandbox_id) WHERE sandbox_id IS NOT NULL;

-- The agent a user's first-party login at an app uses. The unique index is what
-- the consent write's ON CONFLICT DO NOTHING relies on, and what makes two first
-- logins racing find one agent. Partial: ordinary agents are unrestricted, and
-- so is a revoked one. Revoking the agent ends its grants and frees its place
-- (the row stays as history), so the next login of that user at that app creates
-- a fresh agent and a fresh grant instead of being locked out for good.
CREATE UNIQUE INDEX agents_first_party ON agents (user_id, first_party_client)
    WHERE first_party_client IS NOT NULL AND revoked_at IS NULL;

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

    -- A label chosen by the user, to tell their keys apart in a list: the
    -- token itself is never stored or shown again. Bounded in BYTES and refuses
    -- NUL, as agents.name is. The key an agent's create issues takes the
    -- agent's name, read from the agent's row in the same write.
    name     TEXT    NOT NULL
                     CHECK (typeof(name) = 'text'
                            AND instr(name, char(0)) = 0
                            AND length(cast(name AS BLOB)) BETWEEN 1 AND 1024),

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

-- A user's keys (listed newest first by id, a UUIDv7, which is the sort key and
-- the pagination cursor), and to revoke them with the account.
CREATE INDEX api_keys_user_id ON api_keys (user_id, id);

-- An agent's keys, to revoke them with it.
CREATE INDEX api_keys_agent_id ON api_keys (agent_id) WHERE agent_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- OAuth grants and their access tokens
-- ---------------------------------------------------------------------------

-- An OAuth grant is what a user approved for a client at consent
-- (docs/oauth_design.md), and it is one kind of secret: the authorization code
-- first, then, rotated in place under the same id and the same secret row, the
-- refresh token. Its expiry and revocation are on its secret row. Until the
-- code is exchanged the expiry is when the row may be removed, not when the code
-- stops working: the code's 60 seconds are judged by the secret's created_at in
-- the exchange write, and the row is kept as long as the consent it records
-- could be replayed (see granted_from). After the exchange it is the refresh
-- token's 30 days from its last exchange.
--
-- The kind column is fixed to 'oauth_grant' and the foreign key is on
-- (id, kind), so this row can attach only to a grant's secret.
--
-- Everything but the user and the agent is what the user approved, written once
-- at consent and never updated: a later change to the client's metadata
-- document, or to the agent, cannot widen it. Which values are valid is Go's to
-- decide, as with scopes, so each text column has only a size and NUL backstop,
-- fitted to the bound of its parser in internal/input (a test holds the two
-- together). Every bound is in BYTES and refuses NUL, as for agents.name; the
-- values are ASCII except client_name, which Go bounds in bytes too.
CREATE TABLE oauth_grants (
    id             TEXT    PRIMARY KEY
                           CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    kind           TEXT    NOT NULL DEFAULT 'oauth_grant'
                           CHECK (kind = 'oauth_grant'),

    -- The subject: whose authority the grant carries. Grants die with the
    -- account, as keys do.
    user_id        TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- The agent that holds the grant: the actor. Every grant has one, either
    -- created at consent or attached from the user's own, so it is NOT NULL:
    -- a consent write that finds no agent for it fails as a constraint failure
    -- and creates nothing (see the store's CreateGrant).
    agent_id       TEXT    NOT NULL REFERENCES agents (id) ON DELETE CASCADE,

    -- The client: the URL of its metadata document, and the name that document
    -- gave it when the user approved, so the list can say what was approved
    -- even if the document changes or disappears.
    client_id      TEXT    NOT NULL
                           CHECK (typeof(client_id) = 'text'
                                  AND instr(client_id, char(0)) = 0
                                  AND length(cast(client_id AS BLOB)) BETWEEN 1 AND 512),

    client_name    TEXT    NOT NULL
                           CHECK (typeof(client_name) = 'text'
                                  AND instr(client_name, char(0)) = 0
                                  AND length(cast(client_name AS BLOB)) BETWEEN 1 AND 128),

    -- The redirect URI the approval was for. The code is exchanged only with the
    -- same value.
    redirect_uri   TEXT    NOT NULL
                           CHECK (typeof(redirect_uri) = 'text'
                                  AND instr(redirect_uri, char(0)) = 0
                                  AND length(cast(redirect_uri AS BLOB)) BETWEEN 1 AND 512),

    -- The resource server the grant is for (its URL, an entry of the fixed list
    -- in code) and the scopes approved at it, space-delimited, as
    -- input.OAuthScopes stores them. A token is good at this resource alone.
    resource       TEXT    NOT NULL
                           CHECK (typeof(resource) = 'text'
                                  AND instr(resource, char(0)) = 0
                                  AND length(cast(resource AS BLOB)) BETWEEN 1 AND 128),

    scope          TEXT    NOT NULL
                           CHECK (typeof(scope) = 'text'
                                  AND instr(scope, char(0)) = 0
                                  AND length(cast(scope AS BLOB)) BETWEEN 1 AND 256),

    -- The PKCE S256 challenge of the request: 43 base64url characters. The code
    -- is exchanged only with the verifier it is the challenge of.
    code_challenge TEXT    NOT NULL
                           CHECK (typeof(code_challenge) = 'text'
                                  AND instr(code_challenge, char(0)) = 0
                                  AND length(cast(code_challenge AS BLOB)) = 43),

    -- The OpenID Connect nonce the client sent, to echo in the ID token, or
    -- NULL when it sent none.
    nonce          TEXT    CHECK (nonce IS NULL
                                  OR (typeof(nonce) = 'text'
                                      AND instr(nonce, char(0)) = 0
                                      AND length(cast(nonce AS BLOB)) BETWEEN 1 AND 128)),

    -- When the user signed in, in Unix seconds: the created_at of the session
    -- that approved, read from its secret in the consent write and never taken
    -- from the request. It is the ID token's auth_time.
    auth_time      INTEGER NOT NULL,

    -- The SHA-256 of the sealed pending request this grant was approved from.
    -- UNIQUE, so a double-submitted or replayed consent collides on insert and
    -- creates neither a second grant nor a second agent. Do not remove the
    -- UNIQUE: it is the replay guard, as sessions.granted_from is. It outlives
    -- its request because the grant is removed only once it has expired, and the
    -- consent write gives the code-stage secret an expiry no earlier than the
    -- sealed request's own (the request's lifetime from consent), not the
    -- code's 60 seconds: otherwise the row could be removed while the request
    -- could still be replayed, and the replay would create a second grant.
    granted_from   BLOB    NOT NULL UNIQUE
                           CHECK (typeof(granted_from) = 'blob' AND length(granted_from) = 32),

    -- Deleting the secret deletes this row. The reverse is the trigger below.
    FOREIGN KEY (id, kind) REFERENCES secrets (id, kind) ON DELETE CASCADE
);

-- A user's grants (listed newest first by id, a UUIDv7, which is the sort key
-- and the pagination cursor), and to revoke them with the account.
CREATE INDEX oauth_grants_user_id ON oauth_grants (user_id, id);

-- An agent's grants, to revoke them with it.
CREATE INDEX oauth_grants_agent_id ON oauth_grants (agent_id);

-- A grant's access token is a kind of secret of its own, so that what a
-- resource server presents is never the grant's: the refresh token stays with
-- the client. There is exactly one row per grant (grant_id is UNIQUE): the
-- first exchange writes it, and every later exchange or refresh replaces the
-- hash, expiry and creation time of its secret row in place and clears any
-- revocation, so a grant is two secret rows however often its client refreshes.
-- A request in flight with the previous token is refused, which is acceptable
-- because the client that refreshed holds the new one. A grant has an access
-- token row once it has been exchanged, and not before. The row can also be
-- removed alone once its secret has expired and been swept, so its absence says
-- nothing about whether the grant was ever exchanged: the next refresh writes
-- it again.
--
-- The row holds the token's scope and nothing else the grant does not have: the
-- resource, the client and the owner are the grant's, joined by grant_id. The
-- kind column is fixed to 'oauth_access' and the foreign key is on (id, kind),
-- as for the other kinds.
CREATE TABLE oauth_access_tokens (
    id       TEXT    PRIMARY KEY
                     CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    kind     TEXT    NOT NULL DEFAULT 'oauth_access'
                     CHECK (kind = 'oauth_access'),

    -- The scopes this token carries, space-delimited, as input.OAuthScopes
    -- stores them: the grant's scope, or the narrower list a refresh asked for
    -- (RFC 6749 section 6: never more than the grant holds, which the rotation
    -- write checks). Introspection and the token response report this, not the
    -- grant's. Bounded as oauth_grants.scope is.
    scope    TEXT    NOT NULL
                     CHECK (typeof(scope) = 'text'
                            AND instr(scope, char(0)) = 0
                            AND length(cast(scope AS BLOB)) BETWEEN 1 AND 256),

    -- The grant this token was issued under. UNIQUE: one token per grant. The
    -- token dies with its grant, but not through this key: it has no ON DELETE
    -- action, and the grant's delete trigger (below) deletes the token's secret,
    -- whose own foreign key then deletes this row, before the statement that
    -- deleted the grant ends and its key is checked. A cascade here and a delete
    -- trigger on this table would each be correct and together are one trigger
    -- too many (see "Why only four triggers").
    grant_id TEXT    NOT NULL UNIQUE REFERENCES oauth_grants (id),

    -- Deleting the secret deletes this row. Deleting this row alone leaves the
    -- secret, which is inert: it has no row to be an access token with.
    FOREIGN KEY (id, kind) REFERENCES secrets (id, kind) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Deleting a kind's row deletes its secret
-- ---------------------------------------------------------------------------
--
-- A secret and its kind's row exist together and are removed together
-- (docs/secrets_design.md, "Deletion goes both ways"). The foreign keys above
-- cascade from the secret down to its kind's row. They cannot cascade the
-- other way: the secret is referenced by its kind's row and cannot reference
-- its owner, because an invitation has no user. So a delete that starts above
-- a kind's row, such as a user's or a passkey's, removes the sessions, keys or
-- grants through their ON DELETE CASCADE, and these triggers then remove the secrets
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

-- Why only four triggers: D1 (workerd's SQLite) refuses a statement whose
-- delete triggers nest too deep ("triggers nested too deep"), which the host's
-- SQLite does not. A delete of a secret cascades to every kind's row, and every
-- kind's row has a trigger that deletes a secret, so the compiler of such a
-- statement follows a chain one trigger and one cascade longer for each kind.
-- With the four triggers here, a hard delete of a user, an agent or a passkey
-- works on D1; with a fifth it failed (the e2e test TestLoginRacingAStateChange is
-- the guard). So the access token, which exists
-- only under a grant, has no trigger of its own: its grant's trigger deletes
-- both secrets.
CREATE TRIGGER oauth_grants_delete_secret AFTER DELETE ON oauth_grants
BEGIN
    DELETE FROM secrets WHERE id = OLD.id AND kind = 'oauth_grant';
    DELETE FROM secrets WHERE kind = 'oauth_access'
        AND id IN (SELECT id FROM oauth_access_tokens WHERE grant_id = OLD.id);
END;
