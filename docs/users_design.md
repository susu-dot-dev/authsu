# Managing users: design rationale

> This document explains *why* account management is shaped the way it is. It is not a spec: the code is authoritative for what exists.

Related: [permissions_design.md](permissions_design.md), [invitations_design.md](invitations_design.md), [secrets_design.md](secrets_design.md), [first_run_design.md](first_run_design.md)

Platform administrators list accounts, read one, and revoke one. Organization administrators see the members of their own organization ([orgs_design.md](orgs_design.md)) and may revoke them. The route boundary refuses everyone else before any handler runs, so a signed-out caller and an ordinary member learn nothing about the accounts or what a valid id looks like. An account is shown with its role, the invitation it came from, its profile and whether it is active. The WebAuthn user handle is never shown.

## The role is read live

The role is never copied into a credential. It is read from the account on every request, in the same statement that resolves the credential.

The usual argument for carrying the role with the credential is to avoid reading the account. It does not hold here:

- **The credential is read on every request regardless.** A token is random and carries nothing ([secrets_design.md](secrets_design.md)), so resolving it is a read, and that read is also what makes revocation work.
- **Reading the account adds no round trip.** It is a join on its primary key, in a statement that runs anyway, and round trips are what cost time on D1.
- **A copy can only be stale.** A credential lives for days or months. A role or status change would have to be paired with "revoke every credential of this user", and forgetting that step on any future change would be a privilege-escalation bug. Reading live makes the database the only source of truth.

Caching the account has the same flaw in another form: an isolate's memory is short-lived and not shared, KV is eventually consistent, and any cache delays a revocation by its lifetime. If latency ever matters, the lever is D1 read replication, not a cache that weakens revocation.

## Revoking

Revoking is the one way an account ends. It is final, so a person who is let back in is a new account.

- **Who may revoke.** A platform administrator may revoke any account. An organization administrator may revoke accounts in their own organization, never a platform administrator, even one who belongs to it, and never themselves. An agent may not revoke anyone. Who may revoke is a condition of the write, not an earlier check.
- **Revoke, never delete.** The account stays in its organization as a record, for audit ("who was this?", "who came from this invitation?"), and keeps counting against the invitation that created it. If an account is ever deleted, everything it owns goes with it, its credentials included ([secrets_design.md](secrets_design.md#deletion-goes-both-ways)).
- **Revoking twice keeps the first time**, so a retry is safe.
- **It takes effect at once, everywhere**, because it is checked where identity is established. Sessions, keys and the credentials of the account's agents stop working on the next request, login refuses its passkeys exactly like an unknown passkey, and no credential can be issued to it.
- **Its credentials are revoked in the same write.** Resolving them already refuses them, so this is not what ends them. It keeps every credential's own state honest, and protects any future kind that forgets to look at the account.

### The last active platform administrator cannot be revoked

The only recovery from having no platform administrator is wiping the database ([first_run_design.md](first_run_design.md)), so a revocation that would leave none is refused. That includes revoking yourself when you are the only one.

The check is part of the write, not a read before it. D1 has no interactive transactions, so two administrators revoking each other at the same moment would each see the other as active, and both writes would apply. As one statement, the second sees the first's revocation and is refused. Only active administrators count.

An organization's own administrators cannot revoke each other down to none, but the platform can always step in, so an organization whose administrators were all revoked can still be managed.

## Stored data is checked on the way out

A profile is stored as text the database does not constrain, so before it is sent it is checked. A profile that is not what registration writes is logged, naming the account, and the account is served with an empty profile. The request does not fail: one corrupt row must not hide every other account from the admin who has to find and revoke it, and a revocation that was applied must not be reported as failed.

## What is not here

- **No changes to the platform role.** When there are, they need the same last-administrator guard, and no credential invalidation, because the role is read live.
- **No paging or filtering of the list.** Add them when there are enough accounts to need them.
- **No per-session management.** Ending one user's sessions without revoking the account, and users listing their own sessions, are open questions in [login_design.md](login_design.md).
