# Invitations: design rationale

> This document explains *why* invitations are shaped the way they are. It is not a spec. Field names, endpoints, and SQL fragments below are illustrations of an idea, not a description of the code. When this document and the code disagree about *what* exists, the code wins. If they disagree about *why*, one of them needs revisiting.

Related: [first_run_design.md](first_run_design.md), [registration_design.md](registration_design.md)

## The problem

authsu has no open sign-up. Accounts exist only because someone with authority decided they should. That someone is an admin, and the mechanism is an invitation: an admin mints a secret code, hands it to a person, and that person can turn it into an account.

That makes the invitation the single thing that authorizes account creation. Other pieces of the system, such as signed challenges and passkey attestation, protect the *integrity* of the registration ceremony. None of them decide *who may register*. Keeping that responsibility in one place is the main theme of this document. If authorization leaks into several places, every one of them becomes something to audit.

The design has to handle three kinds of invitation, from simple to hard:

- **The common case:** an invitation for one specific person.
- **The harder case:** an invitation meant for a group, such as "anyone at the November workshop", where one code creates several accounts until a cap or an expiry is reached.
- **The bootstrap case:** before any admin exists, someone has to create the first one. That gets its own document ([first_run_design.md](first_run_design.md)), but it reuses the invitation machinery instead of inventing a parallel one.

## The invite code is not the identity of the invitation

The first instinct is to treat the invite code as the invitation: look it up by code, list invitations by code, revoke by code. That falls apart as soon as you imagine operating the system.

Picture a group code that gets posted publicly and abused. The admin needs to find that invitation, see how many accounts came from it, revoke it, and maybe clean up those accounts. If the code is the identity, the admin needs the plaintext code to do any of this. The system then has to store codes in a recoverable form, and anyone who can read the invitation list can redeem the invitations on it.

So identity and secret are split:

- **Identity:** the invitation has an ordinary, non-secret identifier, plus admin-facing context such as a label, who created it, and when. Listing, auditing, and revocation all work through this identity.
- **Secret:** the code is only the thing a person presents. The server keeps a hash of it, enough to recognize the code when presented but not enough to recover it.

The consequence is the API-token model: the admin sees the code once, at creation. A lost code is not recovered. It is revoked and replaced. That is a small inconvenience in exchange for never holding redeemable secrets at rest.

Plain cryptographic hashing is enough here. No password-style slow hashing is needed, because codes are generated with high entropy and are not human-chosen. Key-stretching exists to protect low-entropy inputs. It buys nothing for a 256-bit random value. The same reasoning means the lookup does not need constant-time comparison: timing leaks on an index lookup of a digest reveal nothing useful about its preimage. Constant-time comparison matters elsewhere, for MAC verification. See [registration_design.md](registration_design.md).

## Entropy is the guessing defense, caps are the abuse defense

These are two different threats, with different defenses:

- **Guessing.** An attacker who has no code tries to find one. The defense is entropy: server-generated random codes make guessing infeasible. This is also why admin-chosen vanity codes like `NOV2026` are deliberately left out for now. They give up the entropy assumption, and supporting them would require rate limiting and mandatory caps to carry weight that entropy currently carries.
- **Abuse of a real code.** A legitimate code ends up in the wrong hands. Entropy is irrelevant here, because the attacker already has the code. The defenses are the limits on the invitation itself: how many accounts it may create, when it stops working, and the admin's ability to revoke it. Being able to find every account that came from a given invitation is what makes cleanup possible afterwards.

## A use is an account, nothing less

This is the decision that most shapes the rest of the system.

Multi-use invitations need some notion of "uses remaining". The obvious design is a redemptions table that records each time a code is redeemed. The question that breaks it is *when* a redemption gets recorded:

- **Recorded at the start of registration:** the code is "spent" before an account exists. A user who closes the tab, fails the biometric prompt, or loses connectivity burns a use for nothing. Worse, anyone holding a code can run the start step repeatedly and drain the invitation without ever creating an account. You also get rows that refer to users who never come into existence: shadow identities, which need cleanup, invite confusion, and make an attack surface.
- **Recorded only when the account is created, atomically with it:** the redemption carries no information that the account itself doesn't. It is a second copy of "this user came from this invitation".

The second option tells us what to do. **The account is the redemption.** A user records which invitation created it, and "uses so far" is simply how many users point at that invitation. As a result:

- There is no state in which an invitation is partly consumed.
- Nothing ever needs garbage collection.
- The audit question "who came from this code?" is the same query as the cap check.

This leads to a hard requirement on registration. There must be exactly one moment where the invitation is checked and the account is created, and those two things must be indivisible. Everything before that moment must be free of side effects. [registration_design.md](registration_design.md) is largely about how to keep that true across a passkey ceremony, which inherently takes two round trips.

## The invitation carries what it grants

An invitation describes the code and also what the resulting account should be, most importantly its role. The role is copied from the invitation when the account is created. The client never supplies it.

This keeps the admin-creates-admin and bootstrap cases from needing special code in registration. The first-run invitation is just an invitation whose grant is "admin". A future "invite a co-admin" feature would be the same thing, minted by an existing admin. Registration does not need to know why an invitation grants admin, only that it does.

## Managing invitations

Admins manage invitations through `/api/invitation`: `GET` lists every invitation (revoked ones included), `POST` creates one, `PATCH /api/invitation/{id}` changes how many accounts it may create, and `DELETE /api/invitation/{id}` revokes it. Every route requires a session whose account is an admin; the role is read from the account on each request, so demoting an admin takes effect at once. The code is the one thing never returned by a read: it is in the response to the `POST` that created the invitation and nowhere else.

A few choices worth keeping in mind:

- **Revoke, never delete.** Accounts reference the invitation, and "who came from this code?" must stay answerable, so `DELETE` sets `revoked_at` and the row stays. Revoking twice succeeds and keeps the first time, so a retry is safe and cannot move a revocation later.
- **Status is derived, not stored.** `revoked`, `expired`, `exhausted` or `active`, decided in that order from the row and the clock. There is no status column to fall out of step with the facts it summarises.
- **The cap cannot go below the accounts already made.** That condition is part of the write, not a check before it, because a registration can finish between a read and a write. A revoked invitation cannot be changed: revocation is final, and editing one would suggest it could be revived.
- **No invitation type can be created yet.** `POST` takes a `type`, and every value is refused. First run is bound to there being no account at all, so only `GET /api/first-run` mints it. A new type is one entry in the invitations package plus its role in `registration.RoleFor`; registration refuses a type that has no role.

## Where invitations are stored

Invitations, users, and credentials all live in D1 rather than a Durable Object. The data is relational and globally shared: admins list invitations, cap checks count users per invitation, and logins look up credentials. D1 fits that shape. The one place that needs strong consistency is the single moment of acceptance, a "check and create" that must not race. A single conditional write inside a D1 transaction provides that. A global Durable Object would also provide it, but it would make every auth operation go through one serialized instance for a guarantee we only need at one point. If narrow strongly-consistent needs appear later, such as rate limiting or per-user counters, they can be handled by Durable Objects scoped to those needs, without moving this data.

## What is deliberately not here yet
- **Vanity codes:** see the entropy discussion above.
- **Rate limiting:** not needed while codes are high-entropy. It becomes necessary if that changes.
