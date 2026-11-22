-- Marks the agent that a first-party login creates (docs/oauth_design.md,
-- "First-party login", and docs/agents_design.md).
--
-- Every OAuth grant is held by an agent (oauth_grants.agent_id is NOT NULL). A
-- first-party login has no consent screen and nobody to choose or name an agent,
-- so authsu creates an ordinary agent for it, named after the app. It is a real
-- agent in every other way: the user lists it, counts it against their limit and
-- can revoke it, which ends its grants.
--
-- first_party only says that authsu created it for a trusted app's sign-in and
-- not the user, so a UI may group or hide such agents. It is 1 for those and 0
-- for every other agent, including all that exist when this migration runs. It
-- grants nothing and no query decides authorization from it.
--
-- first_party_client is the client_id of the trusted app the agent was created
-- for, NULL for every other agent. With the owner it identifies the agent a
-- later login of the same user at the same app attaches to, so signing in again
-- reuses it and does not create a 26th agent. The unique index is what the
-- consent write's ON CONFLICT DO NOTHING relies on, and what makes two first
-- logins racing find one agent. Partial: ordinary agents are unrestricted, and
-- so is a revoked one. Revoking the agent ends its grants and frees its place
-- (the row stays as history), so the next login of that user at that app creates
-- a fresh agent and a fresh grant instead of being locked out for good.
ALTER TABLE agents ADD COLUMN first_party INTEGER NOT NULL DEFAULT 0
    CHECK (first_party IN (0, 1));

ALTER TABLE agents ADD COLUMN first_party_client TEXT
    CHECK (first_party_client IS NULL
           OR (first_party = 1
               AND typeof(first_party_client) = 'text'
               AND instr(first_party_client, char(0)) = 0
               AND length(cast(first_party_client AS BLOB)) BETWEEN 1 AND 512));

CREATE UNIQUE INDEX agents_first_party ON agents (user_id, first_party_client)
    WHERE first_party_client IS NOT NULL AND revoked_at IS NULL;
