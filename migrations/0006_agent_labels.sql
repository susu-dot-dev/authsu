-- agent_labels: short tags a user attaches to their own agents, to group and
-- find them (GET /api/agent?label=...).
--
-- Rationale: docs/agents_design.md. Conventions are those of 0001 and 0005.
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
-- label is bounded in BYTES and refuses NUL, as in 0005. Go accepts only
-- [a-z0-9._-] (see input.Label), so the CHECK is a backstop that fires only on
-- a Go bug; it deliberately does not repeat the alphabet, which is Go's to
-- change (docs/DATABASE.md: no CHECK on a set that grows with the code).
-- ON DELETE CASCADE follows agent_id in japikeys; agents are never deleted in
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
