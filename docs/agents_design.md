# Agents: design direction

> This document sets out the intended direction for agents and *why*. It is not a spec. Once there is code, the code is authoritative for what exists; see "What exists" below for the part that does.

Related: [permissions_design.md](permissions_design.md), [invitations_design.md](invitations_design.md), [users_design.md](users_design.md), [login_design.md](login_design.md)

## What exists

The agent table and its management API are implemented (`internal/agents`, `migrations/0005_agents.sql`). Scopes, API-key verification, OAuth and sharing are not.

| Route | Does |
|---|---|
| `GET /api/agent` | Lists one page of the caller's agents, revoked ones included, newest first. `limit` (1 to 100, default 25) and `cursor` (the `next` of the previous page) are optional and are refused, not corrected, when invalid. The response carries `next` while there is another page. |
| `POST /api/agent` | Creates an agent and returns its first API key, once. |
| `GET /api/agent/{id}` | Reads one of the caller's agents. |
| `PATCH /api/agent/{id}` | Renames it (a revoked agent is refused with 409). |
| `DELETE /api/agent/{id}` | Revokes it and its keys. |

- **Every route acts for the signed-in user, on that user's agents only.** There is no role check, and no route takes an owner: an agent of another user is answered as one that does not exist (404). An admin has no extra reach here, as the design requires.
- **A passkey-backed session is the only credential these routes accept.** Nothing verifies an API key yet, so an agent cannot call them, and so cannot create agents. When keys can authenticate, "agent creates an agent" and the `kind == 'session'` rule for minting keys arrive with scopes.
- **Creating an agent mints its first key in the same batch.** The key is an `api_key` whose subject is the user and whose `act` claim names the agent, with its audience `authsu/api_key` so a session verifier refuses it. The agent and the key stand or fall together: the key's owner is read from the agent's row in the write, so an agent that was not inserted (the user is at the limit, or was revoked in the meantime) fails the whole batch. Only the public key is stored; the token is shown once. There is no rotation or way to mint a second key yet: agents are short-lived, and are replaced by revoking and creating another.
- **Lists are paged by id.** An agent's id is a UUIDv7, so it is in creation order, and it is the sort key and the cursor: a page is the agents with an id below the cursor, newest first. Keyset paging neither skips nor repeats an agent that exists throughout, whatever is created or revoked meanwhile. Revoked agents are never deleted and do not count toward the limit below, so the list can grow without bound; paging is what keeps a response small.
- **A user may have 25 active agents** (`MaxAgentsPerUser`; revoked agents do not count). The count is part of the insert, so two creates at the limit cannot both succeed. A key lasts 90 days (`KeyLifetime`) and is never extended.
- **Revoking an agent revokes it and its keys, and nothing else**, in one batch. **Revoking a user revokes all of their agents** in the same batch as the account, after it, so a refused revocation (the last admin) touches no agent.
- **Text is checked in Go and again, by bytes, in the schema.** A name is refused if it is blank, over 256 characters, or holds control, format (zero-width, bidirectional) or replacement characters. The schema's CHECKs count bytes and refuse NUL, because SQLite's `length()` stops at a NUL and would otherwise let an unbounded value through.
- **Scopes are placeholders.** `agents.scopes` is a `NOT NULL` text column, written as `default:agent` on every agent, and the same text is signed into each key as the `scope` claim and copied to `japikeys.scope`. Nothing reads or enforces it. The database never validates its contents, so adding scopes and bundles needs no migration; the lists will be validated in Go and enforced in a later change, which will be a breaking one for any client that relies on today's defaults.

## The problem

A user wants software to act for them: an assistant, a scheduled job, an integration in another service. Today the only way to allow that is to hand over the user's own credential, and then the software *is* the user. It can do everything the user can, its requests look like theirs, and the only way to stop it is to stop the user.

An agent is software acting on one user's behalf. It has its own identity and credentials, so it can be told apart, limited and stopped, but it always acts *as* its user, never as someone in its own right.

## The central decision: an agent is not a user

Everything else in this document follows from one decision. **An agent is not an account, and it is never the party that holds access.** The user is. An agent is a way for the user to act, narrowed to what the user has allowed it.

That has consequences in three places:

- **Accounts.** Accounts come only from invitations, and the account is the redemption ([invitations_design.md](invitations_design.md)). An agent has no invitation and no passkey, so it is not a user row with a special role. It is something a user has.
- **Resources.** Resources are shared with users, always. Nothing is ever shared with an agent alone (see "Sharing resources").
- **Tokens.** A token used by an agent says the user is the subject and the agent is the actor (see "Tokens: subject and actor").

The alternative, agents as principals of their own, would mean every authorization question has two kinds of answer, every share needs a rule for which kind it names, and an agent could end up holding access its user does not. That is a second authorization system, and an agent becoming a way to gain authority. Keeping the user as the only principal avoids both.

## Goals

1. **An agent is never a way to gain authority.** Whatever an agent can do, its user could already do.
2. **Authority starts with a person.** Every agent belongs to a user who signed in with a passkey, and acts only within what that user may do.
3. **Agents can be stopped one at a time**, without affecting the user or their other agents. Stopping the user stops all of their agents.
4. **Agents are not a second authorization system.** Invitations, users and sessions have already settled how identity, secrets, revocation and live authorization work. Agents reuse those answers.

## The hierarchy

Authority moves in one direction only:

- **Admins invite users.** This is unchanged: invitations are the only way to create an account.
- **Users create agents, and only for themselves.** Creating an agent is a user delegating their own authority, so the agent's owner is whoever made the request. Nobody, including an admin, creates an agent for someone else.
- **An agent may create agents only if it has been explicitly allowed to**, and that permission is elevated and never a default. An agent made this way is an ordinary agent of the same user, not a child of the agent that created it. It can be no more capable than its creator, and it counts against a per-user limit on how many agents there are.

Agents form a flat set under their user, not a tree. Each agent answers to its user and nothing else, so its standing depends only on itself and its user, never on a chain of other agents.

An agent's owner is fixed for its whole life. Transferring an agent would move authority sideways between users, and would make "who was responsible for this?" depend on when you asked.

## Delegation is something a person does

Creating an agent hands out authority, so it must come from the person whose authority it is. A credential that can create agents could use a leak to keep itself alive: create a new agent and new keys before the original key is revoked. So an agent cannot create agents unless its user explicitly allowed it, and only a passkey-backed session can mint keys directly. A user's own API keys may create agents, so that agents can be created programmatically; the remedy for a leaked key is for the user to revoke all of their keys, which ends every agent's keys too.

These rules are expressed with scopes rather than special cases. [permissions_design.md](permissions_design.md) sets them out.

Some authority is never delegated at all. Managing principals (inviting users, administering accounts) stays with people, so "only admins invite users" means an admin, not something an admin configured.

## Credentials

An agent has a stable identity and any number of credentials that let it act:

- **API keys scoped to the agent**, using the same japikey mechanism as sessions ([login_design.md](login_design.md)).
- **OAuth login**, for agents that live in other services and fit a standard authorization flow better than a pasted key.

As with invitations, the credential is not the identity. A key can be rotated or revoked without touching the agent. Revoking the agent ends all of its credentials, and the audit trail names a stable agent rather than whichever key was in use.

## Tokens: subject and actor

A token an agent presents follows the actor model of OAuth token exchange (RFC 8693): the subject (`sub`) is the user, and an actor claim (`act`) names the agent.

This is the central decision written into the token. The subject is the party whose authority is being used and who holds access, and that is always a user. The actor is who is exercising it, and it can only narrow what the subject may do. A service checking access asks the same question it would for the user ("may this user do this?"), then applies the agent's limits. A service that knows nothing about agents still sees a user, and so cannot mistake an agent for an independent party.

It also fits what already exists: a key's subject is a user, and keys die with the account, so an agent's keys end with its user without any extra rule.

## Effective permissions

An agent's permissions are a ceiling that its user (or the system) sets. They are not a grant of new authority. What an agent may do is the intersection of what it is allowed and what its user may do *now*.

The "now" matters. As with roles ([users_design.md](users_design.md)), the user's standing is read live, not copied into the agent or its token. Demoting a user narrows every one of their agents at once, and revoking the user stops them all, with no separate cleanup step that could be forgotten.

## Sharing resources

A future resource authorization system will take a request, find the user and the agent acting for them, work out the effective permissions, and allow or deny.

**Resources are always shared with a user.** There is no such thing as access held by an agent and not its user: anything an agent can reach, its user can reach directly, in their own right. If an agent could hold access its user lacked, the agent would be a way to gain authority.

On top of a share to a user, a resource can narrow what that user's agents may do with it:

- **Allow agents**, as a class or through a general permission such as `agent:read`.
- **Allow only particular agents**, or particular kinds of agent.
- **Deny agents entirely**, so the resource is reachable only by the user acting directly.

These scopes only ever subtract from the user's access. They never stand alone, and they never name an audience other than the user.

## Revocation

- **Revoking an agent revokes that agent and its credentials, and nothing else.** Other agents, including any it created, are unaffected. Each was a separate decision, and each answers only to the user.
- **Revoking a user revokes all of their agents**, because every agent's authority is borrowed from its user.
- **Revoke, never delete**, as for invitations and users, so "who did this?" stays answerable.

## Open questions

- How OAuth agents and user consent fit together.
- Whether a user may mint further keys for an existing agent, once keys can be verified and scoped.
