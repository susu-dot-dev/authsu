# Secrets: design rationale

> This document explains *why* secrets are shaped the way they are. It is not a spec: the code and the migrations are authoritative for what exists. Do not add the details of a kind of secret here; those belong in that kind's design document.

Related: [invitations_design.md](invitations_design.md), [login_design.md](login_design.md), [permissions_design.md](permissions_design.md), [agents_design.md](agents_design.md), [first_run_design.md](first_run_design.md)

## The problem

Several parts of authsu hand a client a value whose possession is the authorization:

- an **invitation code** lets a person create an account;
- a **session** proves a person signed in with a passkey;
- an **API key** lets a user or an agent call the API without a browser;
- an **OAuth grant** lets a client that a user approved obtain access tokens, first through an authorization code and then through refresh tokens.

Each needs the same things: a value nobody can guess, a way to recognise it without being able to recover it, an identity that can be listed and revoked without knowing the value, an expiry, and revocation that takes effect at once. Built separately, each would be one more format, one more hashing rule and one more revocation path to audit. So there is one mechanism, a *secret*, and each kind is built on top of it.

## What is a secret, and what is not

A secret is a value **the server generates**, **whose possession is authorization**, and **which the server must be able to revoke**. All three must hold.

Some things look similar and are deliberately not secrets:

- **Ceremony challenges** (registration, login). They protect the integrity of a passkey ceremony, and are worthless without a passkey's signature. They are stateless and signed, and never stored ([login_design.md](login_design.md)).
- **A pending OAuth authorization request.** It carries the client's parameters through sign-in and consent. The user's approval is what authorizes, not the request, so it is integrity-protected and stateless.
- **Access tokens issued to other services.** A resource server verifies those itself, without asking authsu on every request, so they are signed, short-lived and never stored.
- **Deployment configuration** such as `AUTH_HMAC_SECRET`. The operator supplies it and it is never presented by a client. `FIRST_RUN_SECRET` is the one piece of configuration that becomes a secret: it is the first invitation's token ([first_run_design.md](first_run_design.md)).

## The identity is not the secret

Every secret has an ordinary, non-secret identifier, and that identifier is how it is listed, audited and revoked. The secret value is only what a client presents. The server keeps a hash of it: enough to recognise the value, not enough to recover it.

The consequence is the API-token model everywhere. The value is shown once, when it is issued (in a response body, or set as a cookie), and never again. A lost value is not recovered: it is revoked and a new one issued. Logs and admin views name the identifier, never the value.

## The token

A token is `susu_<tag>_` followed by 43 base64url characters: 32 bytes from a cryptographic random source, which tests inject so that issuing is deterministic.

| Tag | Kind | Presented as |
|---|---|---|
| `inv` | invitation | the code at registration |
| `ses` | session | the session cookie |
| `key` | API key | `Authorization: Bearer` |
| `code` | OAuth grant, before exchange | the authorization code |
| `rt` | OAuth grant, after exchange | the refresh token |

- **The prefix names the kind.** Each place that reads a credential accepts exactly one kind, so a token of the wrong kind is refused by the parser before anything is read from the database. A token that ends up in a log, a chat or a repository says what it is, and secret scanners can recognise it.
- **The length is fixed.** The parser accepts the exact prefix followed by exactly 43 canonical base64url characters, and refuses anything else, rather than trimming or correcting it. The body can itself contain `_` and `-`, so the prefix is matched as a whole and never found by splitting.
- **The token carries no claims.** It is random, and nothing can be read from it. Everything about what it grants is on rows the server reads when it is presented (see "Every fact is read live").

## Hashing

The stored hash is SHA-256 of the whole token string, prefix included. Hashing the prefix as well means the same random body under two tags is two unrelated hashes, so one kind can never be looked up as another.

- **No slow hash.** Key stretching protects low-entropy, human-chosen inputs. A 256-bit random value gains nothing from it.

## Every fact is read live

A token is presented, its hash is found, and the rows it leads to are read in the same statement: the secret, the kind's own row, the user, and the agent if one is acting. Whether it is valid, who it belongs to and what it may do all come from that read.

A self-describing signed token was the alternative, and it buys nothing here. authsu's permissions are worked out on every request from live state: the user's role and standing, the agent's limits, revocation ([permissions_design.md](permissions_design.md)). A claim inside a token could only be a stale copy of one of those, or a ceiling the live read would narrow anyway. The read is needed for revocation regardless, so claims would add a signing key, a larger token and checks of claims against rows, and remove nothing.

What is given up is verification without authsu, and that is intended. A secret is presented only to authsu. Another service never receives one: it gets its own short-lived token, issued for that service alone.

## One base table, one table per kind

Secrets live in one table that holds only what every kind shares: the identifier, the kind, the hash, when it expires, when it was revoked, and when it was created. Each kind has its own table holding what that kind means (whose it is, what it grants, how it came to exist), and that table's primary key is the secret's identifier. A session, an API key, an invitation or a grant is therefore one secret row and one row of its kind, with one identifier between them.

The alternative, one wide table with every kind's columns, would make most columns nullable and need constraints to stop a row being half of two kinds. Those constraints would grow with every kind, and in SQLite changing one means rebuilding the table. Separate tables let each kind declare its own columns honestly, and adding a kind adds a table without touching the others.

The split also puts each question in one place:

- **"Is this secret valid right now?"** is answered by the base table alone, the same way for every kind: not revoked, not expired.
- **"What does it grant?"** is answered by the kind's table, typed as strictly as that kind needs.

### The kind is the source of truth

The kind is stored on the secret, and the database makes it binding. Each kind's table holds a kind column fixed to its own kind, and its foreign key to the base table is on the identifier and the kind together. A secret has exactly one kind, so:

- a row of one kind cannot attach to a secret of another kind;
- two tables can never claim the same secret;
- each kind's table has at most one row per secret, because the identifier is its primary key.

The kind is fixed for each table, so the fixed value is an invariant and not an open-ended set that grows with the code ([DATABASE.md](DATABASE.md)).

### Deletion goes both ways

A secret and its kind's row exist together and are removed together, whichever side the delete starts from:

- **Deleting a secret** (removing expired rows, for instance) cascades through the foreign key to its kind's row.
- **Deleting a kind's row** removes its secret through a trigger on that table. That covers the cascades that start above it. Deleting a user removes their sessions, keys and grants, and the trigger then removes the secrets behind them. Deleting a passkey removes the sessions it started, and their secrets with them.

A foreign key cascades only from the row referenced to the rows that reference it. The secret is referenced by its kind's row, never the other way round: it cannot reference its owner, because an invitation has no user. So the trigger is the one way a delete above a kind's row reaches the secret, and without it every such delete would leave behind a secret that no longer belonged to anything. That secret would be inert, because every lookup joins its kind's table, but it would still be counted, listed and kept. Deleting a user because they have sessions must not be refused, so the cascade has to complete instead.

## Lifecycle

Every operation is one statement or one batch, with its conditions inside the write, never in a read before it ([DATABASE.md](DATABASE.md)).

- **Issue.** The secret and its kind's row are written in one batch, and the kind's row is written only if the secret was. Any condition on issuing, such as an active account, an active agent or a single-use guard, is part of that batch. The value is returned to the caller once.
- **Resolve.** The presented token is parsed for the kind expected where it was read, hashed, and looked up together with its kind's row and the live user and agent, in one statement. It resolves only if every part is active.
- **Revoke.** Revocation is a time, not a flag: a secret is revoked once that time has come, so a revocation scheduled for later would need no change. Revoking again keeps the first time, so retrying is safe and never moves a revocation later. Revoking a user's secrets of every kind is one statement.
- **Expire.** Every secret expires, with no exceptions. The lifetime is the kind's policy, set in code (see the table below). An expired secret is refused exactly as a revoked one is.
- **Rotate.** Only OAuth grants rotate. Rotation replaces the hash in place, under the same identifier, on the condition that the presented hash is still the current one. Two attempts to exchange the same token cannot both succeed, and the old token simply stops matching anything.
- **Remove.** Rows are deleted only when they have expired, never when they are revoked: some kinds hang a single-use guard on their row, and that guard has to outlive whatever it guards (see below). Invitations are never deleted, because the accounts they created refer to them.

### Rotation is once only, and keeps no history

A rotated token can be exchanged once, by whoever presents it first. The server does not keep the previous hash, does not try to detect reuse, and does not revoke a grant when an old token comes back.

Detecting reuse protects only in the narrow case where a thief refreshes first and the real client later returns with the old token. Anyone who holds a refresh token already has the grant, so a stolen token is a compromise however rotation behaves. In exchange, every rotation is one conditional write, with no history to keep and no grace period to tune. A client that exchanges the same token twice, from two processes for instance, is wrong to share it: the second exchange fails, and the user approves the client again.

## Single use belongs to the kinds

The base table has no "consumed" state. Where a kind needs a secret to be used once, it gets that from something it already has:

- **An invitation** is used up by the accounts it creates: the account is the redemption, and the cap is a count of accounts ([invitations_design.md](invitations_design.md)).
- **A login** is single use because the session row records the login challenge it was issued from, uniquely, in the same write that issues it ([login_design.md](login_design.md)). This is the guard that has to outlive its challenge, and it is why a session is removed only once it has expired.
- **An authorization code** is generation zero of its grant. Exchanging it is the first rotation, which replaces the code's hash with the first refresh token's, so a second exchange of the same code matches nothing.

## The kinds

| Kind | Issued by | Lifetime | Rotates |
|---|---|---|---|
| Invitation | an admin, or first run | chosen by the admin, at most ten years, and ten years when not chosen | no |
| Session | login | a fixed 14 days, never extended | no |
| API key | the user, or agent creation | 90 days unless chosen; a user may choose up to a year, and an agent's keys are capped at 90 days | no |
| OAuth grant | the user approving a client | the code: 60 seconds. The refresh token: 30 days from its last exchange | yes |

Each kind's own document carries the rest: who may issue it, what its row records, and how it is used.

## Decisions

- **One mechanism** for every server-issued bearer secret: a base table, and one table per kind sharing its primary key.
- **Tokens** are `susu_<tag>_` plus 32 random bytes in base64url. The tag names the kind, and the parser accepts exactly that shape.
- **Stored as SHA-256 of the whole token.** No slow hash, no pepper, no constant-time comparison.
- **Tokens carry nothing.** Every fact is read live, in the statement that resolves the token.
- **The kind is binding**, through a fixed kind on each kind's table and a foreign key on the identifier and the kind together.
- **Deletion cascades both ways**: a foreign key from the secret to its kind's row, and a trigger from the kind's row back to the secret.
- **Every secret expires.** Revocation is a time that takes effect when it comes.
- **Rotation** replaces the hash in place and succeeds once. There is no reuse detection and no history.
