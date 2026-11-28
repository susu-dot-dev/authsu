# Secrets: design rationale

> This document explains *why* secrets are shaped the way they are. It is not a spec: the code and the migrations are authoritative for what exists. Do not add the details of a kind of secret here; those belong in that kind's design document.

Related: [invitations_design.md](invitations_design.md), [login_design.md](login_design.md), [permissions_design.md](permissions_design.md), [agents_design.md](agents_design.md), [first_run_design.md](first_run_design.md), [oauth_design.md](oauth_design.md)

## The problem

Several parts of authsu hand a client a value whose possession is the authorization:

- an **invitation code** lets a person create an account;
- a **session** proves a person signed in with a passkey;
- an **API key** lets a user or an agent call the API without a browser;
- an **OAuth grant** lets a client that a user approved obtain access tokens, first through an authorization code and then through refresh tokens;
- an **OAuth access token** is what that client presents to a resource server, which asks authsu what it means.

Each needs the same things: a value nobody can guess, a way to recognise it without being able to recover it, an identity that can be listed and revoked without knowing the value, an expiry, and revocation that takes effect at once. Built separately, each would be one more format, one more hashing rule and one more revocation path to audit. So there is one mechanism, a *secret*, and each kind is built on top of it.

## What is a secret, and what is not

A secret is a value **the server generates**, **whose possession is authorization**, and **which the server must be able to revoke**. All three must hold.

Some things look similar and are deliberately not secrets:

- **Ceremony challenges** (registration, login). They protect the integrity of a passkey ceremony, and are worthless without a passkey's signature. They are stateless and signed, and never stored ([login_design.md](login_design.md)).
- **A pending OAuth authorization request.** It carries the client's parameters through sign-in and consent. The user's approval is what authorizes, not the request, so it is integrity-protected and stateless.
- **ID tokens.** A relying party verifies one with a public key, without asking authsu, so it is signed, short-lived and never stored. It says who signed in and grants nothing ([oauth_design.md](oauth_design.md)).
- **Deployment configuration** such as `AUTH_HMAC_SECRET`. The operator supplies it and it is never presented by a client. `FIRST_RUN_SECRET` is the one piece of configuration that becomes a secret: it is the first invitation's token ([first_run_design.md](first_run_design.md)).

## The identity is not the secret

Every secret has an ordinary, non-secret identifier, and that identifier is how it is listed, audited and revoked. The secret value is only what a client presents. The server keeps a hash of it: enough to recognise the value, not enough to recover it.

The consequence is the API-token model everywhere. The value is shown once, when it is issued (in a response body, or set as a cookie), and never again. A lost value is not recovered: it is revoked and a new one issued. Logs and admin views name the identifier, never the value.

## A secret in a response is sealed for anything but a browser

A response body that carries a secret is read by whatever the caller routes it through. For a model-driven client that is inference, whose logs and caches are kept by someone else, and a secret that passes through them is exposed for as long as they live. So a route that returns a secret to a credential that is not a session returns it encrypted to a public key the request carries, and the client's own key opens it. The routes are the ones that issue a secret to software: an agent's first API key and an invitation. A browser session may omit the key and is sent the value as it is, because a browser is not a model's tool, and a session may still ask for it sealed.

The scheme is HPKE from the standard library, with a key sent per request and nothing registered beforehand. It protects a response from being read where it is logged. It is not authentication: anyone who knows the public key can produce a value the client will open, and a replayed response opens again, which a plaintext response permits just as well. The request's own literals are out of its reach: a secret written into a request is already in the log. The other routes that return a secret are not sealed: `POST /api/key`, the consent and the login are session-only by their declarations, and the token endpoint's shape is fixed by OAuth.

A key that is required and absent is refused before anything is generated or written, and a key that cannot be sealed to is refused before the write, so a refusal never leaves a secret that no one was given. The formats are in `internal/seal` and `internal/input`.

## The token

A token is `susu_<tag>_` followed by 43 base64url characters: 32 bytes from a cryptographic random source, which tests inject so that issuing is deterministic.

| Tag | Kind | Presented as |
|---|---|---|
| `inv` | invitation | the code at registration |
| `ses` | session | the session cookie |
| `key` | API key | `Authorization: Bearer` |
| `code` | OAuth grant, before exchange | the authorization code |
| `rt` | OAuth grant, after exchange | the refresh token |
| `at` | OAuth access token | `Authorization: Bearer`, at a resource server, and at authsu's own API for the login resource ([oauth_design.md](oauth_design.md#oauth-scopes-and-authsu-scopes)) |

- **The prefix names the kind.** Each place that reads a credential accepts the kinds it is written for (the cookie one, the bearer header two, told apart by the prefix), so a token of the wrong kind is refused by the parser before anything is read from the database. A token that ends up in a log, a chat or a repository says what it is, and secret scanners can recognise it.
- **The length is fixed.** The parser accepts the exact prefix followed by exactly 43 canonical base64url characters, and refuses anything else, rather than trimming or correcting it. The body can itself contain `_` and `-`, so the prefix is matched as a whole and never found by splitting.
- **The token carries no claims.** It is random, and nothing can be read from it. Everything about what it grants is on rows the server reads when it is presented (see "Every fact is read live").

## Hashing

The stored hash is SHA-256 of the whole token string, prefix included. Hashing the prefix as well means the same random body under two tags is two unrelated hashes, so one kind can never be looked up as another.

- **No slow hash.** Key stretching protects low-entropy, human-chosen inputs. A 256-bit random value gains nothing from it.

## Every fact is read live

A token is presented, its hash is found, and the rows it leads to are read in the same statement: the secret, the kind's own row, the user, and the agent if one is acting. Whether it is valid, who it belongs to and what it may do all come from that read.

A self-describing signed token was the alternative, and it buys nothing here. authsu's permissions are worked out on every request from live state: the user's role and standing, the agent's limits, revocation ([permissions_design.md](permissions_design.md)). A claim inside a token could only be a stale copy of one of those, or a ceiling the live read would narrow anyway. The read is needed for revocation regardless, so claims would add a signing key, a larger token and checks of claims against rows, and remove nothing.

What is given up is verification without authsu, and that is intended. A secret is read only by authsu. Another service may be handed one, an OAuth access token issued for that service alone, but it cannot verify it: it asks authsu what the token means, so revocation reaches it on the next request ([oauth_design.md](oauth_design.md#access-tokens-stay-opaque-so-resource-servers-ask-authsu)).

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

**There are four triggers for five kinds, because of D1.** An access token exists only under its grant, so its grant's trigger deletes both secrets and the access token's table has no trigger of its own. D1 refuses a delete whose triggers nest too deep ("triggers nested too deep"), which the SQLite of the host does not. Every kind's trigger deletes a secret, which cascades to every kind's row, so the nesting grows with each kind. With four triggers a hard delete of a user, an agent or a passkey works on D1, and with five it fails. The cost is that deleting an access token's row alone, which nothing does, leaves its secret behind, inert for the same reason as above. The e2e test `TestLoginRacingAStateChange` is what finds the limit again if a kind is added.

## Lifecycle

Every operation is one statement or one batch, with its conditions inside the write, never in a read before it ([DATABASE.md](DATABASE.md)).

- **Issue.** The secret and its kind's row are written in one batch, and the kind's row is written only if the secret was. Any condition on issuing, such as an active account, an active agent or a single-use guard, is part of that batch. The value is returned to the caller once.
- **Resolve.** The presented token is parsed for the kind expected where it was read, hashed, and looked up together with its kind's row and the live user and agent, in one statement. It resolves only if every part is active.
- **Revoke.** Revocation is a time, not a flag: a secret is revoked once that time has come, so a revocation scheduled for later would need no change. Revoking again keeps the first time, so retrying is safe and never moves a revocation later. Revoking a user's secrets of every kind is one statement.
- **Expire.** Every secret expires, with no exceptions. The lifetime is the kind's policy, set in code (see the table below). An expired secret is refused exactly as a revoked one is.
- **Rotate.** Only OAuth grants rotate. Rotation replaces the hash in place, under the same identifier, on the condition that the presented hash is still the current one. Two attempts to exchange the same token cannot both succeed, and the old token simply stops matching anything. A grant's access token is replaced in place in the same batch (see "One access token per grant").
- **Remove.** Rows are deleted only when they have expired, never when they are revoked: some kinds hang a single-use guard on their row, and that guard has to outlive whatever it guards (see below). So an expiry is set from how long the guard is needed, which for a kind with a shorter working life than its guard is not the working life: the code-stage secret of an OAuth grant is kept for the whole life of the sealed request it was approved from, though the code is good for 60 seconds, and the exchange write enforces those 60 seconds from the secret's creation time instead. Invitations are never deleted, because the accounts they created refer to them. A kind's row can also go before its parent does (an access token's, once its secret has expired), so nothing may treat the absence of one as a fact about the thing it belongs to.

### Rotation is once only, and keeps no history

A rotated token can be exchanged once, by whoever presents it first. The server does not keep the previous hash, does not try to detect reuse, and does not revoke a grant when an old token comes back.

Detecting reuse protects only in the narrow case where a thief refreshes first and the real client later returns with the old token. Anyone who holds a refresh token already has the grant, so a stolen token is a compromise however rotation behaves. In exchange, every rotation is one conditional write, with no history to keep and no grace period to tune. A client that exchanges the same token twice, from two processes for instance, is wrong to share it: the second exchange fails, and the user approves the client again.

### One access token per grant

A grant has at most one access token, a secret of its own kind (`oauth_access`) so that what a resource server holds is never the grant's refresh token. Each exchange or refresh replaces the hash and expiry of that one row in place and sets its scope (the grant's, or the narrower subset a refresh asked for), in the same batch as the grant's rotation and only if the rotation matched, so a grant is two secrets however often its client refreshes. Replacing the token is a rotation without a condition of its own: its guard is the grant's, and the previous access token stops matching at once. A request in flight with it fails, which is accepted because the client that refreshed holds the new one.

## Single use belongs to the kinds

The base table has no "consumed" state. Where a kind needs a secret to be used once, it gets that from something it already has:

- **An invitation** is used up by the accounts it creates: the account is the redemption, and the cap is a count of accounts ([invitations_design.md](invitations_design.md)).
- **A login** is single use because the session row records the login challenge it was issued from, uniquely, in the same write that issues it ([login_design.md](login_design.md)). This is the guard that has to outlive its challenge, and it is why a session is removed only once it has expired.
- **An authorization code** is generation zero of its grant. Exchanging it is the first rotation, which replaces the code's hash with the first refresh token's, so a second exchange of the same code matches nothing.
- **A consent** is single use because the grant row records the pending request it was approved from, uniquely, in the write that creates it ([oauth_design.md](oauth_design.md)). Like a session, this is a guard that has to outlive its request, so the grant's secret does not expire with its authorization code: it is kept as long as the request could still be replayed.

## The kinds

| Kind | Issued by | Lifetime | Rotates |
|---|---|---|---|
| Invitation | an admin, or first run | chosen by the admin, at most ten years, and ten years when not chosen | no |
| Session | login | a fixed 14 days, never extended | no |
| API key | the user, or agent creation | 90 days unless chosen; a user may choose up to a year, and an agent's keys are capped at 90 days | no |
| OAuth grant (`oauth_grant`; tag `code`, then `rt`) | the user approving a client | the code: exchangeable for 60 seconds, with the secret kept ten minutes (the replay guard). The refresh token: 30 days from its last exchange | yes, once only, under the same identifier |
| OAuth access token (`oauth_access`; tag `at`) | the code's exchange, and every refresh | 15 minutes | replaced in place, one row per grant |

Each kind's own document carries the rest: who may issue it, what its row records, and how it is used.

## Decisions

- **One mechanism** for every server-issued bearer secret: a base table, and one table per kind sharing its primary key.
- **Tokens** are `susu_<tag>_` plus 32 random bytes in base64url. The tag names the kind, and the parser accepts exactly that shape.
- **Stored as SHA-256 of the whole token.** No slow hash, no pepper, no constant-time comparison.
- **Tokens carry nothing.** Every fact is read live, in the statement that resolves the token.
- **The kind is binding**, through a fixed kind on each kind's table and a foreign key on the identifier and the kind together.
- **Deletion cascades both ways**: a foreign key from the secret to its kind's row, and a trigger from the kind's row back to the secret (at most four triggers in all: an access token's is its grant's).
- **Every secret expires.** Revocation is a time that takes effect when it comes.
- **Rotation** replaces the hash in place and succeeds once. There is no reuse detection and no history. A grant's access token is replaced in place with it.
