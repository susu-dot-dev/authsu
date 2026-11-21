# Organizations: design direction

> This document sets out the direction for organizations and sandboxes and *why*. It is not a spec: the code is authoritative for what exists. Do not add details of features to this document, only describe overall intent if it changes.

Related: [invitations_design.md](invitations_design.md), [agents_design.md](agents_design.md), [permissions_design.md](permissions_design.md), [users_design.md](users_design.md)

## The problem

Today every account stands alone. People who work together cannot be told apart from strangers, nobody short of a platform administrator can look after a group, and there is nowhere to put untrusted software where it cannot reach everything its user can.

An **organization** is a group of users with administrators. A **sandbox** is a temporary organization that holds agents and confines them. They are one concept with two kinds, because both are a named thing with administrators that other things belong to, and one table with a kind is one thing to reason about.

## Principles

### 1. The platform controls how many people there are

Invitations are how the platform controls the rate at which people enter the service ([invitations_design.md](invitations_design.md)). An organization must not become a second way in, so nothing an organization does creates an account, and an organization has no size limit of its own. The platform controls an organization's size by controlling how many invitations it issues.

### 2. Inviting and joining happen together

A person admitted by the platform should land in their organization in the same step, not be admitted and then have to be found and added. So a platform invitation can carry an offer to join an organization, and the registration that redeems it places the new account there.

The organization is a side effect of registration and never a condition of it. An admitted person must not be turned away because the organization was revoked or changed in between, so in that case they simply register without one.

An existing user joins by being offered a place and accepting it. An offer is its own record, apart from the platform invitation it may ride on: the platform invitation is the record of who was admitted and must be kept, while an offer means nothing once its organization is gone or revoked.

### 3. A user belongs to at most one organization

Membership is one fact about the user, read the same way their role is. Belonging to several would mean every request had to say which organization it acts in, and every permission question would have two answers. Moving is leaving and then joining.

Revoking a standard organization releases its members, so a user is never left belonging to one that no longer works. They stay accounts, and are free to join another. Revoking and joining are separate operations that can meet at the same moment, so joining requires the organization to be active when the join is written, not only when it was offered. Otherwise a person could join just after the release has run, and be stranded in a dead organization with nothing left to free them. This is the rule the rest of the service follows: the condition belongs to the write that depends on it, never to an earlier check. It applies to both ways in: an existing user accepting an offer, and a new account registering with one. Registration still never fails for it: a new account whose organization was revoked simply has none.

An agent follows its user. It carries no organization of its own, so a user joining or leaving never means setting their agents up again: what the agent can reach changes with what the user can reach, and one that tries to reach something its user no longer can fails and is dealt with. The cost is that an agent can reach whatever its user can. That is the same exposure as inviting the user, and is accepted.

Looking after an organization is a separate fact from belonging to it, held as who administers what, not as a role on the user. A role is one value, so one user could never administer two organizations, nor be both a platform administrator and an organization administrator. It is also not a scope: scopes only narrow what a user could already do ([permissions_design.md](permissions_design.md)), and who may look after a given organization is a gate. A standard organization is never left without an administrator, for the reason the last platform administrator cannot be revoked ([users_design.md](users_design.md)).

### 4. A user can create sandboxes

A user wants to hand some agents a small, temporary place to work, with a guarantee that nothing they do can reach the user's own, wider access. An agent borrows its user's authority, so for anything the user can reach, the agent could too. Narrowing it with scopes does not help, because scopes say which actions are allowed and not which resources they apply to.

So a sandbox is a boundary, and the only one. An agent of a sandbox reaches a resource only if the resource belongs to the sandbox, and nothing outside is reachable from it, whoever shared what. It is fully self-contained in both directions: nothing outside can name its agents, and nothing inside outlives it. A standard organization is not a boundary: it groups users, and nothing is confined to it.

A sandbox is an organization and not a tag on an agent because a tag is bookkeeping that nothing enforces, so an agent could never be proven contained. As an organization it is held apart by the same condition that keeps any two groups apart. It has one administrator, the user who made it, who keeps their own organization, so a user can hold several sandboxes while belonging to one organization. It has no members, and an agent of a sandbox cannot create one, so there is no nesting.

A sandbox expires, and is then deleted (principle 5). The service does no scheduled work yet, so it cannot delete one on time, and does not need to for the boundary to hold: whether a sandbox still stands is read when a credential is used, so an expired one is inert on the next request. Cleaning up what was inside belongs to whatever owns those resources.

### 5. Ending an organization must not lose who did what

Shared documents will outlive the groups around them, and an edit must still say who made it. That is why a user and an agent are **never deleted, only revoked**. Attribution points at them, and it must always resolve.

The two kinds differ in what depends on them:

- **A sandbox is always deleted.** It is fully self-contained (principle 4), so nothing outside can be attributed to it or pinned to it, and deleting it leaves no authentication data behind. Whether it is deleted by hand or on expiry, the result is the same, and the service does not have to be the one that gets to it.
- **A standard organization is never deleted, only revoked**, as a user and an agent are. Other services pin things to it, such as documents it owns or has shared, so what it is must stay answerable for as long as they exist. A revoked organization stops working and stays as a record. If one is ever deleted, it will be a decision of its own, not a side effect of anything here.

Deleting a sandbox is one operation that the database finishes, with nothing to remove first and nothing created at the same moment able to survive it. Its administrator is released and stays. A platform invitation is never touched, since it is the record of who was admitted.

The one agent that is removed and not revoked is an agent of a sandbox, and only because of principle 4: the reason to keep an agent is that something outside may have recorded it, and nothing outside a sandbox can. Every other agent keeps the rule.

A restriction must never fall back to "unrestricted" when what it points at disappears. An agent whose sandbox vanished would otherwise read as an ordinary agent of its user, with all of the user's reach. So the agent is deleted with its sandbox, not released from it. Clearing is right for a fact that means "which group", and wrong for one that means "restricted to".

Deleting a sandbox reaches an agent and then its keys and grants, one level further than any removal today, and the database has refused deletes that nest too deep before. Whether it fits can only be shown against the real database, so it is a required end-to-end test, and if it does not fit the design is wrong and not the test.

### 6. Self-serve creation needs abuse controls

Anyone can create organizations and sandboxes, so one user must not be able to fill the service with them. The two kinds are bounded differently, because of principle 5:

- **A sandbox is bounded by how many exist at once.** It is always deleted and leaves nothing behind, so there is nothing to accumulate, and churning one costs only the moment it exists. A user's concurrent sandboxes are limited, as their agents are ([agents_design.md](agents_design.md)). One that has expired stops counting, which is read from its expiry, since nothing may have removed it yet.
- **A standard organization is bounded by how many a user has ever created.** It is never deleted, so revoking one frees nothing: creating, revoking and creating again would otherwise grow what the service keeps without bound, and a limit on how many are active would not stop it. The count is a lifetime one. Because the organizations persist, they are their own record of it, and no separate counter is needed. Revoking an organization does not give the user their count back.

Both limits are decided where the creating happens, so two requests at once cannot both pass.

## What is not here

- **A limit on an organization's size**, for the reason in principle 1.
- **Several organizations per user**, and moving in one step, for the reason in principle 3.
- **Letting an organization's administrators issue platform invitations.** That would delegate admission, and is a separate decision.
- **Binding agents to a standard organization**, for the reason in principle 3.
- **Deleting a standard organization.** It is only revoked, which releases its members (principle 3).
- **Scheduled deletion of expired sandboxes.** A sandbox is always deleted, but doing it on time is not built here: the service does no scheduled work, and the boundary does not need it, because an expired sandbox is inert when read.
- **Enforcing a sandbox's boundary on resources.** None exist yet to enforce it on. Enforcing it waits for the first, since a path with nothing to enforce it on could not be tested.
