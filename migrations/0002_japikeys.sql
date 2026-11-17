-- japikeys: one key per session or API key.
--
-- Rationale: docs/login_design.md. Conventions are those of 0001: Unix
-- seconds, UUIDv7 text ids, size CHECKs as a backstop for Go, and no CHECK on
-- a value that grows with the code (kind).
--
-- Each row is the public half of a key pair whose private half was discarded
-- right after it signed its one JWT. Verifying a token is a read of this table
-- by kid.
--
-- A session is issued by login and lasts a fixed time: it is never extended or
-- refreshed, so there is one row per login and nothing else writes a session.
--
-- Revocation takes effect at revoked_at, a time and not a flag. Logout is the
-- only thing that sets it today, and sets it to now, but a key is active when
-- revoked_at IS NULL OR revoked_at > now, so a revocation scheduled for later
-- would work without a schema change. That is also why the user index below is
-- not partial on revoked_at IS NULL.
--
-- Rows are removed on expires_at, never on revocation: granted_from is what
-- makes a login single use, and deleting the row early would reopen replay of a
-- login captured just before (see the design doc).

CREATE TABLE japikeys (
    -- The token's kid.
    kid           TEXT    PRIMARY KEY
                          CHECK (length(kid) = 36 AND kid NOT GLOB '*[^0-9a-f-]*'),

    -- The token's subject. Keys die with the account.
    user_id       TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- 'session' or 'api_key'. Go interprets it, and the token's audience is
    -- derived from it. Not constrained to a set, like invitations.type.
    kind          TEXT    NOT NULL
                          CHECK (typeof(kind) = 'text' AND length(kind) BETWEEN 1 AND 64),

    -- The public JWK as JSON, in the form japikey defines ({"keys":[...]}),
    -- so a JWKS document could be served from the row unchanged. About 200
    -- bytes.
    jwk           TEXT    NOT NULL
                          CHECK (typeof(jwk) = 'text' AND json_valid(jwk) AND length(jwk) <= 2048),

    -- A copy of the token's exp. The signed claim stays authoritative; the
    -- column makes listing and cleanup range scans.
    expires_at    INTEGER NOT NULL,

    -- NULL while the key is active with no end scheduled.
    revoked_at    INTEGER,

    -- The SHA-256 of the login challenge that issued this session. UNIQUE, so a
    -- replayed login collides on insert and cannot mint a second session. NULL
    -- for API keys, and SQLite treats NULLs as distinct, so any number of them
    -- may share it. Do not remove the UNIQUE: it is the replay guard.
    granted_from  BLOB    UNIQUE
                          CHECK (granted_from IS NULL
                                 OR (typeof(granted_from) = 'blob' AND length(granted_from) = 32)),

    -- The passkey that started this session. For auditing, and deleting a
    -- passkey ends its sessions. NULL for API keys.
    credential_id TEXT    REFERENCES credentials (id) ON DELETE CASCADE,

    -- Opaque JSON, such as an API key's label. Not queried.
    metadata      TEXT    NOT NULL DEFAULT '{}'
                          CHECK (typeof(metadata) = 'text' AND json_valid(metadata) AND length(metadata) <= 1024),

    created_at    INTEGER NOT NULL,

    -- A session has both of its grant columns and an API key has neither, so
    -- a row is never half of each. SQL does not name the kinds.
    CHECK ((granted_from IS NULL) = (credential_id IS NULL))
);

-- A user's keys of one kind that have not expired: equality columns first and
-- the range last, so a lookup seeks to (user, kind) and scans only the
-- unexpired part. Revoked rows stay in it on purpose (see the header).
CREATE INDEX japikeys_user_kind_expires ON japikeys (user_id, kind, expires_at);

-- Cleanup of expired rows, and anything across all users.
CREATE INDEX japikeys_expires_at ON japikeys (expires_at);
