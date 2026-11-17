# Managing users

Admins manage accounts through `/api/user`:

| Route | Does |
|---|---|
| `GET /api/user` | Lists every account, revoked ones included, newest first. |
| `GET /api/user/{id}` | Reads one account. |
| `DELETE /api/user/{id}` | Revokes it. |

Every route requires a session (401) whose account is an admin (403). An account is shown as its id, role, the invitation it came from, its profile, a derived status (`active` or `revoked`), `revokedAt` when set, and `createdAt`. The WebAuthn user handle is never returned.

## Authorization: the role is read live, not carried in the token

The role is not a claim in the session token. It is read from the `users` row on every request, in the same query that verifies the session.

The obvious argument for a role claim is "avoid joining `users`". It does not hold here:

- **The key row is read on every request regardless.** A session's private key is discarded after it signs its one token, so the only copy of the public key is the `japikeys` row. Verification cannot happen without that read, and it is also what makes revocation work.
- **The join is on a primary key, in a query that runs anyway.** It adds no round trip, and round trips are what cost time on D1.
- **A claim can only be stale.** Sessions last two weeks. A role or status change would have to be paired with "revoke every token of this user", and forgetting that step on any future change is a privilege-escalation bug. Reading live makes the database the only source of truth.
- **Claims pay off with stateless verification**, which would mean no per-request read and no instant revocation (so no logout). That is a different system.

Caching the account has the same flaw in another form: an isolate's memory is short-lived and not shared, KV is eventually consistent, and any cache delays a revocation by its TTL. If latency ever matters, the lever is D1 read replication (check current Cloudflare documentation first), not a cache that weakens revocation.

Enforcement is the pattern `/api/invitation` already uses: authenticate, then require the role, then act. Each package defines its own small `Authenticator` interface. A missing database is refused before authenticating, since there is nothing to authorise against.

## Revoking

`DELETE` is used because revocation is what `DELETE` means for invitations: it sets `revoked_at` and keeps the row ([invitations_design.md](invitations_design.md)). `PATCH` stays free for partial updates such as a role change.

- **Revoke, never delete.** The row stays for audit ("who was this?", "who came from this invitation?"). Deleting would cascade to credentials and keys.
- **Idempotent.** Revoking twice succeeds and keeps the first time (`COALESCE`).
- **It takes effect at once, everywhere**, because it is checked where identity is established:
  - session verification reads `users.revoked_at`, so every live session stops verifying on the next request;
  - login does not find a revoked account's credentials, so it is refused exactly like an unknown credential, and the response does not reveal that the account exists;
  - the session insert requires an active account, so an admin revoking between login's lookup and its write cannot leave a session behind.
- **The account's keys are revoked in the same batch**, after the account. Verification already refuses them, so this is not what ends the sessions. It keeps the keys table honest, and protects any future kind of key whose verification forgets to look at the account.

### The last active admin cannot be revoked

The only recovery from having no admin is wiping the database ([first_run_design.md](first_run_design.md)), so a revoke that would leave none is refused with 409 `user_last_admin`. This includes revoking yourself when you are the only admin.

The check is part of the write, not a read before it. D1 has no interactive transaction, so two admins revoking each other at the same moment would each see the other as active and both writes would apply. As one statement, the second sees the first's revocation and is refused. The statement matches the row by id and `RETURNING` gives it back as it left it, so the outcome is read off the row (`revoked_at` set, or still NULL because the guard refused), with no second read to disagree with it. Only active admins count: a revoked admin, or an active account with another role, does not.

## What is not here

- **No role changes.** There is no way to change a role. When there is, it needs the same last-admin guard, and no token invalidation, because the role is read live.
- **No un-revoke.** Revocation is final, as for invitations.
- **No paging or filtering on the list.** It returns every account. Add them when the table is large enough to need it.
- **No per-session management.** Ending one user's sessions without revoking the account, and users listing their own sessions, are open questions in [login_design.md](login_design.md).
