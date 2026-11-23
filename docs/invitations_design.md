# Invitations: design rationale

> This document explains *why* invitations are shaped the way they are. It is not a spec: the code is authoritative for what exists. When this document and the code disagree about *what* exists, the code wins. If they disagree about *why*, one of them needs revisiting.

Related: [secrets_design.md](secrets_design.md), [first_run_design.md](first_run_design.md), [registration_design.md](registration_design.md)

## The problem

authsu has no open sign-up. Accounts exist only because someone with authority decided they should. That someone is an admin, and the mechanism is an invitation: an admin creates a code, hands it to a person, and that person can turn it into an account.

That makes the invitation the single thing that authorizes account creation. Other pieces of the system, such as signed challenges and passkey attestation, protect the *integrity* of the registration ceremony. None of them decide *who may register*. Keeping that responsibility in one place is the main theme of this document. If authorization leaks into several places, every one of them becomes something to audit.

The design has to handle three kinds of invitation, from simple to hard:

- **The common case:** an invitation for one specific person.
- **The harder case:** an invitation meant for a group, such as "anyone at the November workshop", where one code creates several accounts until a cap or an expiry is reached.
- **The bootstrap case:** before any admin exists, someone has to create the first one. That has its own document ([first_run_design.md](first_run_design.md)), but it reuses the invitation machinery instead of inventing a parallel one.

## The code is not the identity of the invitation

The first instinct is to treat the code as the invitation: look it up by code, list invitations by code, revoke by code. That falls apart as soon as you imagine operating the system.

Picture a group code that is posted publicly and abused. The admin needs to find that invitation, see how many accounts came from it, revoke it, and perhaps clean up those accounts. If the code were the identity, the admin would need the plaintext to do any of it, so the system would have to store codes recoverably, and anyone who could read the list could redeem everything on it.

So an invitation is a [secret](secrets_design.md), and secrets split identity from value:

- **Identity:** the invitation has an ordinary, non-secret identifier and admin-facing context (a label, who created it, when). Listing, auditing and revocation all work through it.
- **Secret:** the code is only what a person presents. The server keeps a hash of it, enough to recognise the code but not to recover it.

The admin sees the code once, when it is created. A lost code is not recovered: it is revoked and replaced. That is a small inconvenience in exchange for never holding redeemable secrets at rest.

## Entropy is the guessing defence, caps are the abuse defence

These are two different threats, with different defences:

- **Guessing.** An attacker with no code tries to find one. The defence is entropy: the server generates every code, so guessing is infeasible. This is also why admin-chosen vanity codes like `NOV2026` are left out for now. They give up the entropy assumption, and supporting them would need rate limiting and mandatory caps to carry the weight that entropy carries today.
- **Abuse of a real code.** A legitimate code ends up in the wrong hands. Entropy is irrelevant, because the attacker already has the code. The defences are the invitation's own limits: how many accounts it may create, when it stops working, and the admin's ability to revoke it. Being able to find every account that came from an invitation is what makes cleanup possible afterwards.

## A use is an account, nothing less

This is the decision that most shapes the rest of the system.

Multi-use invitations need some notion of "uses remaining". The obvious design is a table of redemptions. The question that breaks it is *when* a redemption is recorded:

- **At the start of registration:** the code is spent before an account exists. A user who closes the tab or fails the biometric prompt burns a use for nothing, and anyone holding a code can drain it by starting registration repeatedly. It also leaves rows referring to users who never come into existence: shadow identities that need cleanup and become an attack surface.
- **Only when the account is created, atomically with it:** the redemption then says nothing the account does not. It is a second copy of "this user came from this invitation".

**The account is the redemption.** An account records the invitation that created it, and "uses so far" is the number of accounts that point at it. So:

- there is no state in which an invitation is partly consumed;
- nothing needs garbage collection;
- "who came from this code?" is the same question as the cap check.

This puts a hard requirement on registration: exactly one moment where the invitation is checked and the account created, indivisibly, with everything before it free of side effects. [registration_design.md](registration_design.md) is largely about keeping that true across a passkey ceremony, which takes two round trips.

## The invitation carries what it grants

An invitation describes the code and also what the resulting account should be, most importantly its role. The role is copied from the invitation when the account is created, never supplied by the client.

That keeps the admin-creates-admin and bootstrap cases from needing special code in registration. The first-run invitation is an invitation whose grant is "admin". A future "invite a co-admin" feature would be the same thing, created by an existing admin. Registration does not need to know why an invitation grants admin, only that it does.

The kinds of invitation, and the role each grants, are fixed in code together, not in configuration, so a deployment cannot be wired with a kind of invitation that grants no role. First run is creatable only by the bootstrap itself.

An invitation can also name an organization and a role in it, member or administrator. The account joins that organization when it is created. An invitation that names none gets an organization created for its account, which the account administers. Either way the organization is settled in the same write as the account and is never a reason to refuse it ([orgs_design.md](orgs_design.md), principle 2). Because organizations gain accounts only through invitations, the caps are how the platform controls the size of each.

## Managing invitations

Admins list, create, change the cap of and revoke invitations. Every action requires an admin, the role is read on each request so demoting an admin takes effect at once ([users_design.md](users_design.md)), and the code is in the response that created it and nowhere else.

An admin revoked after the request was authenticated and before it was written creates nothing: the creator's standing is a condition of the write that creates the invitation, and the answer is a 401 as for any revoked caller.

- **Revoke, never delete.** Accounts refer to the invitation, and "who came from this code?" must stay answerable, so revoking keeps the invitation. Revoking twice keeps the first time.
- **Every invitation expires.** The admin chooses when, up to ten years ahead, and it is ten years when they do not. There is no invitation that works forever by default.
- **Status is derived, not stored**: revoked, expired, exhausted or active, decided from the facts and the clock. There is no status to fall out of step with what it summarises.
- **The cap can never go below the accounts already created.** That condition is part of the write, because a registration can finish between a read and a write. A seat is an admission: revoking an account does not free its seat, and the way to give capacity back is to raise the cap. A revoked invitation cannot be changed: revocation is final, and editing one would suggest it could be revived.
- **A refused change says why**, and the reason comes from the same statement that attempted the write, so it describes the same instant as the refusal.

## Where invitations are stored

Invitations, accounts and passkeys live in D1 rather than a Durable Object. The data is relational and globally shared: admins list invitations, cap checks count accounts per invitation, and logins look up passkeys. The one place that needs strong consistency is the moment of acceptance, a "check and create" that must not race, and a single conditional write gives that. A global Durable Object would also give it, but would put every auth operation through one serialized instance for a guarantee needed at one point. If narrow strongly-consistent needs appear later, such as rate limiting, Durable Objects scoped to them can handle it without moving this data.

## What is deliberately not here yet

- **Vanity codes**, for the entropy reason above.
- **Rate limiting.** Not needed while codes are high-entropy. It becomes necessary if that changes.
