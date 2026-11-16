-- Invitations, users and passkey credentials.
--
-- Rationale: docs/invitations_design.md and docs/registration_design.md.
-- Timestamps are Unix seconds. Identifiers we mint are UUIDv7 in canonical
-- text form; secrets, hashes and WebAuthn bytes are BLOB.
--
-- Size limits. Every client-influenced column has a size CHECK as a last-line
-- backstop in case input sanitising is ever forgotten in Go. Go still rejects
-- bad input first, with a proper error; a violation here fails the whole
-- statement or batch. SQLite cannot alter a CHECK, so changing a limit means
-- rebuilding the table: the limits below are generous guards against abuse,
-- not tight fits. Two details:
--   * length() counts bytes for a BLOB but characters for TEXT, so every
--     BLOB check also asserts typeof(col) = 'blob'. Columns are loosely typed
--     and would otherwise accept TEXT, which length() would count differently.
--   * The id check bounds size and shape (36 chars of lowercase hex and dashes).
--     It does not validate that the value is a UUIDv7; Go does that.
--
-- invitations and users reference each other. SQLite does not check foreign
-- keys until a row is written, so the order of the two CREATE TABLE
-- statements does not matter. The first-run invitation has a NULL
-- created_by, so there is no insert-order cycle either.

CREATE TABLE invitations (
    id          TEXT    PRIMARY KEY
                        CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    -- SHA-256 of the invite code. The code itself is never stored.
    code_hash   BLOB    NOT NULL UNIQUE
                        CHECK (typeof(code_hash) = 'blob' AND length(code_hash) = 32),

    -- What the invitation grants (for example 'first_run'). Go maps the type
    -- to a role and to any extra rules; deliberately not constrained to a set
    -- of values here so new types need no migration.
    type        TEXT    NOT NULL
                        CHECK (typeof(type) = 'text' AND length(type) BETWEEN 1 AND 64),

    -- Typed by an admin.
    label       TEXT    NOT NULL DEFAULT ''
                        CHECK (typeof(label) = 'text' AND length(label) <= 256),

    -- Maximum number of accounts this invitation may create. "Uses so far"
    -- is the number of users whose invitation_id points here.
    num_invites INTEGER NOT NULL DEFAULT 1 CHECK (num_invites > 0),

    expires_at  INTEGER,
    revoked_at  INTEGER,

    -- NULL for the first-run invitation, and for invitations whose creator
    -- has since been deleted.
    created_by  TEXT    REFERENCES users (id) ON DELETE SET NULL,

    created_at  INTEGER NOT NULL
);

CREATE TABLE users (
    id            TEXT    PRIMARY KEY
                          CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'),

    -- WebAuthn user.id. Random and minted at registration begin; unique, so
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
