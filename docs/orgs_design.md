# Organizations: design direction

> This document sets out the direction for organizations and sandboxes and *why*. It is not a spec: the code is authoritative for what exists. Do not add details of features to this document, only describe overall intent if it changes.

Related: [invitations_design.md](invitations_design.md), [agents_design.md](agents_design.md), [permissions_design.md](permissions_design.md), [users_design.md](users_design.md)

## The problem

People who work together need to be told apart from strangers, a group needs someone to look after it who is not a platform administrator, and untrusted software needs somewhere to run where it cannot reach everything its user can.

An **organization** is the group an account belongs to. A **sandbox** is a temporary organization that holds agents and confines them. They are one concept with two kinds, because both are a named thing with administrators that other things belong to, and one table with a kind is one thing to reason about.

## Principles

### 1. The platform controls how many people there are

Invitations are how the platform controls the rate at which people enter the service ([invitations_design.md](invitations_design.md)). An organization must not be a second way in, so nothing an organization does creates an account, and organization administrators cannot invite. An organization has no size limit of its own: the platform sizes it by how many invitations it issues for it. A seat is an admission, so revoking an account never gives its seat back. The platform gives capacity back by raising a cap.

### 2. An account is bound to its organization when it is created

Every account belongs to exactly one standard organization, for the life of the account. It is settled at registration, in the same step as the account, in one of two ways: the invitation names an organization (and a role in it), or it names none and an organization is created for the account, which administers it. Registration never fails because of the organization.

There is no joining, leaving or moving. Belonging to several would mean every request had to say which organization it acts in, and every permission question would have two answers. Creating accounts is easy, so a person who needs a different organization has a different account. Documents and other resources belong to the organization and can be shared across organizations.

Users do not create standard organizations, so the number of them is bounded by the number of accounts and needs no limit of its own.

An agent follows its user. It carries no organization of its own, and what it can reach is what its user can reach. The cost is that an agent can reach whatever its user can. That is the same exposure as inviting the user, and is accepted.

### 3. Looking after an organization is separate from belonging to it, and revoking is how someone leaves service

Administering an organization is held as who administers what, not as a role on the user. A role is one value, so one user could never administer two organizations, nor be both a platform administrator and an organization administrator. It is also not a scope: scopes only narrow what a user could already do ([permissions_design.md](permissions_design.md)), and who may look after a given organization is a gate.

Administrators promote and demote the members of their organization without any invitation, because those people are already in it. A revoked member is never promoted. They can also revoke its accounts ([users_design.md](users_design.md)), but never a platform administrator, and never themselves. An organization is never left without an active administrator by the actions of its own administrators, for the reason the last platform administrator cannot be revoked. Platform administrators override this for every organization, including one whose administrators have all been revoked.

An organization is not a lifecycle thing; its accounts are. It is never deleted or revoked, and an account that is revoked stays in it as a record. Agents are refused for every action that changes who belongs, who administers or who is revoked.

### 4. A user can create sandboxes

A user wants to hand some agents a small, temporary place to work, with a guarantee that nothing they do can reach the user's own, wider access. An agent borrows its user's authority, so for anything the user can reach, the agent could too. Narrowing it with scopes does not help, because scopes say which actions are allowed and not which resources they apply to.

So a sandbox is a boundary, and the only one. An agent of a sandbox reaches a resource only if the resource belongs to the sandbox, and nothing outside is reachable from it, whoever shared what. It is fully self-contained in both directions: nothing outside can name its agents, and nothing inside outlives it. A standard organization is not a boundary: it groups users, and nothing is confined to it.

A sandbox is an organization and not a tag on an agent because a tag is bookkeeping that nothing enforces, so an agent could never be proven contained. It has exactly one administrator, the user who made it, who keeps their own organization. It has no members, and an agent of a sandbox cannot create one, so there is no nesting. As with accounts, there is no getting out: an agent of a sandbox stays in it until it is deleted with it.

A sandbox expires. The service does no scheduled work, and does not need to for the boundary to hold: whether a sandbox still stands is read when a credential is used, so an expired one is inert on the next request. Cleaning up what was inside belongs to whatever owns those resources.

### 5. Ending a sandbox must not lose who did what

Shared documents will outlive the groups around them, and an edit must still say who made it. That is why users, agents and standard organizations are **never deleted**: attribution points at them, and it must always resolve.

The one exception is a sandbox, with the agents inside it. It is fully self-contained (principle 4), so nothing outside can be attributed to it or pinned to it, and deleting it, by hand or on expiry, leaves no authentication data behind. Its administrator stays. A platform invitation is never touched, since it is the record of who was admitted.

A restriction must never fall back to "unrestricted" when what it points at disappears. An agent whose sandbox vanished would otherwise read as an ordinary agent of its user, with all of the user's reach. So the agent is deleted with its sandbox, not released from it.

### 6. Self-serve creation of sandboxes needs abuse controls

Anyone can create sandboxes, so one user must not be able to fill the service with them. A sandbox is always deleted and leaves nothing behind, so there is nothing to accumulate, and the bound is how many a user holds at once, as for their agents ([agents_design.md](agents_design.md)). One that has expired stops counting, since nothing may have removed it yet. The limit is decided where the creating happens, so two requests at once cannot both pass.

## What is not here

- **A limit on an organization's size**, for the reason in principle 1.
- **Joining, leaving or moving between organizations**, and several organizations per account, for the reason in principle 2.
- **Letting an organization's administrators issue platform invitations.** That would delegate admission, and is a separate decision.
- **Binding agents to a standard organization**, for the reason in principle 2.
- **Scheduled deletion of expired sandboxes.** The boundary does not need it, because an expired sandbox is inert when read.
- **Enforcing a sandbox's boundary on resources.** None exist yet to enforce it on, and a path with nothing to enforce it on could not be tested.
