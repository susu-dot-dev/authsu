# First-run bootstrap: design rationale

> This document explains *why* bootstrap works the way it does. It is not a spec: the code is authoritative for what exists.

Related: [invitations_design.md](invitations_design.md), [registration_design.md](registration_design.md), [secrets_design.md](secrets_design.md)

## The problem

[Invitations](invitations_design.md) are the only way to create an account, and only admins can create invitations. A freshly deployed authsu has no admins, so nobody could ever get in. Something has to break this circularity exactly once.

Any bootstrap mechanism is, by definition, a way to become admin without being invited. That is a hole in the security model, and the design goals follow from treating it as one:

1. **The hole should require proof that you own the deployment.** Being the first person to visit the site is not proof.
2. **The hole should close itself**, as early as possible and without relying on the operator to remember to close it.
3. **The hole should not be a second authorization system.** The invitation model has already been reasoned about, so the bootstrap reuses it rather than adding a parallel path that needs its own scrutiny.

There is also a fourth goal, about the person doing the setup:

4. **Setup should be a guided, mostly self-driving experience.** The owner has just deployed something and wants to be signed in as admin. They should never have to invent a secret, read docs to find out what to do next, or come back and click "check again". The page should always know which step they are on and take them to the next one.

The rest of the document follows the owner's path, and explains at each step why it is built that way.

## Proof of ownership: a deploy-time secret

What the legitimate owner has, and nobody else has, is the ability to configure the Worker. So bootstrap asks the owner to set a secret, `FIRST_RUN_SECRET`, and treats knowledge of it as proof of ownership. Someone who can set Worker secrets already controls the deployment, so this adds no new trust. It reuses trust the owner already has.

## Reusing invitations: the secret is the invitation's token

Instead of a special "if you know the secret, you may become admin" path, the secret *is* the token of an ordinary invitation: a complete invitation token, in exactly the shape every invitation token has ([secrets_design.md](secrets_design.md)). That invitation grants admin, can be used once, and is marked as the first-run invitation because one extra rule applies to it (below).

This is what satisfies goal 3. From registration's point of view, the first admin redeems an invitation like anyone else, and every property argued for in the invitation design comes along: a single point of acceptance, no shadow users, and the role taken from the invitation rather than the client.

It also shapes the experience. The bootstrap page needs no account-creation flow of its own, and nothing has to create the invitation beforehand. Its whole job is to get the owner to the point where the secret is configured and they hold its token, then hand them to the normal registration page.

### The invitation is created by the registration that redeems it

The first-run invitation is not stored in advance. It comes into being in the same write as the first account, and that write is registration's point of acceptance ([registration_design.md](registration_design.md#the-point-of-acceptance)).

The reason is that nothing else needs it to exist earlier. The invitation is the hash of a token the server already holds in its configuration, so storing it ahead of time records nothing that registration cannot derive on the spot. Creating it earlier would need a request to create it, and the only requests that exist before the owner registers are ones anyone can make. Making one of those perform a write was a trade the earlier design accepted ("a write on what looks like a read"). Creating the invitation inside the registration removes the trade instead of arguing for it: the status route only reads, and the only request that ever writes is one that presents the token.

The write is conditional exactly as the old creation was, and its conditions are in the statements, not in a read before them:

- the presented token is the configured first-run secret, and
- the database has no invitation and no account at all.

When both hold, the batch creates the invitation's secret, then its row, then the account that redeems it, then the account's passkey, each statement conditional on the one before. If any statement matches nothing, the passkey insert fails on its missing account and the whole batch rolls back, the invitation included, so a registration that fails leaves nothing behind. When the conditions do not hold, which is every registration after the first and every registration with any other token, the two creating statements insert nothing and the batch is the ordinary redemption of a stored invitation.

Registration's `begin` accepts the same token in the same case, as an advisory read, so a wrong secret still fails before the passkey prompt.

## The owner's journey

### The page reflects server state

The setup page is a view of the server's bootstrap state, not a wizard with its own memory. On load, and repeatedly afterwards, it asks where things stand:

| State | Meaning |
|-------|---------|
| missing secret | The owner still has to configure something. |
| invitation pending | The secret is configured and the system is empty, so registering with it will create the first account. (A stored first-run invitation that has not been redeemed reads the same.) |
| invitation accepted | An account exists, so setup is over. |

Because the server's state is authoritative, the owner can close the tab, reload, switch machines, or come back tomorrow, and the page picks up at the right step. The single exception is the secret value itself, discussed below.

### Step 1: guiding the owner to set the secret

**The browser generates the secret.** For a short window this value is effectively the admin password, so it must be high-entropy, and asking the owner to invent one would invite something weak. The page generates a complete invitation token from the browser's CSPRNG. The server never generates or displays it: it only receives it through configuration, because configuration is the channel that proves ownership. If the server generated the value and showed it on a page, anyone who reached the page first could read it.

**The page tells the owner exactly what to do.** It shows a ready-to-run command with the value filled in, the equivalent dashboard steps for owners without a local checkout, and the local-development equivalent. It explains briefly why: "setting this proves you own this deployment". A step that looks arbitrary is a step people skip or get wrong.

Registration also needs a permanent signing key, `AUTH_HMAC_SECRET` ([registration_design.md](registration_design.md#what-the-signing-key-is-and-is-not)). It cannot be derived from `FIRST_RUN_SECRET`, which is meant to be temporary, so this step is the natural moment to set both. The server reports only the state of `FIRST_RUN_SECRET`.

### Step 2: waiting for the redeploy

Setting a secret redeploys the Worker. The page does not ask the owner to come back and confirm: it keeps polling, and as soon as the new configuration is live it moves on. The owner runs a command in their terminal and the browser tab advances by itself.

- **A rollout is not instantaneous.** Briefly, some requests may reach the old version, so the page treats the status as something that can move back and forth during that window.
- **The status check only reads.** It creates nothing. "Pending" is a statement about configuration and an empty system, which is what the owner is waiting for, and nothing in the database has to change for it to become true.

The check works from one snapshot: whether any account exists, whether any invitation exists and whether a first-run invitation exists are read together, so the answers describe the same instant. An account means "accepted", and the secret is not even consulted. A first-run invitation means "pending". An invitation of any other kind with no first-run invitation and no account means setup can never finish (see "Recovery is a wipe"). Only when the database has no invitation at all is the secret read, and it must be a well-formed invitation token to read "pending", or the status stays "missing secret".

### The secret has to survive until registration

This is the one piece of state the server cannot help with, and the most likely way for setup to go wrong.

Worker secrets are write-only: once set, neither wrangler nor the dashboard shows the value again, and the server never returns it either. So the browser that generated it is the only place it exists, apart from whatever the owner copied. If it is lost, the owner cannot recover it. Setting a new value is possible while nothing has been stored, because the invitation is created from whatever the secret is when the owner registers. Once an invitation exists, setting a new value does not help, because the invitation is already tied to the old one (see "Closing the hole").

- **If the value is not available** (a different browser, cleared storage, a secret set out of band), ask the owner to paste the value they deployed rather than failing.
- **If the pasted value is wrong**, registration's early, advisory invitation check refuses it before any passkey prompt, and the page can say plainly that the value does not match the one deployed.

### Step 3: handing off to registration

Once the status is pending, the page sends the owner to the ordinary registration page, carrying the token, for example `/register?first-run=true#<token>`.

- **The token travels in the fragment.** Fragments are never sent to the server and do not appear in `Referer`. The registration page reads it and immediately removes it from the address bar and history. It is a short-lived admin credential, so keeping it out of logs, history and shoulder-surfing range is worth the effort.
- **The first-run hint is cosmetic.** It lets the registration page tailor its copy. The server ignores it entirely: first-run handling is decided by whether the token is the configured secret on an empty system, never by what the client claims.

From here, registration is exactly the flow in [registration_design.md](registration_design.md). If two browsers race at this point, its single point of acceptance admits exactly one.

### Step 4: done

After registration, the status is permanently "accepted", and the setup page just points to sign-in. This is the moment to tell the owner they can delete `FIRST_RUN_SECRET`. Nothing depends on them doing it, but tidy deployments are easier to reason about.

## Closing the hole

The hole closes in two stages, each enforced by facts in the database, not by operator action.

**Stage 1: once an invitation exists, no first-run invitation can be created.** The first-run invitation is created only when there are no invitations and no accounts at all, and that condition can never be true again. The condition is part of the write itself, so two racing registrations cannot both create it. A consequence: changing `FIRST_RUN_SECRET` after the invitation exists does nothing, because the invitation is tied to the old token's hash. That is deliberate. Supporting "I lost or changed the secret" after that point would mean reopening the hole based on current configuration, which is exactly the persistent back door this design avoids.

Since the invitation is created by the registration and not before it, the first admin's registration and the creation of the invitation are one event: there is no window in which an invitation exists that nobody has redeemed unless a registration was refused after the invitation was written, and a refused registration writes nothing at all, because the batch rolls back.

**Stage 2: once any account exists, the first-run invitation is dead.** Single use covers the normal case. The first-run invitation adds a stronger condition: it is redeemable only while there are no accounts at all. Single use is a property of the invitation, while "no accounts" is a property of the whole system, and requiring both keeps the path closed however the database came to have accounts. Once an account exists, neither the status check nor registration lets the secret create or redeem anything, so a `FIRST_RUN_SECRET` left in the deployment forever is inert.

### Recovery is a wipe

If the owner loses the secret after the first-run invitation exists, or gets into any other odd state, the answer is to wipe the database and redeploy. Before the first admin exists there is nothing of value to preserve, every recovery path would be a way to reopen the hole, and handling none of them keeps the mechanism small enough to reason about completely. The page's job is to make wiping and redeploying the clearly signposted answer.

A first-run invitation can exist without an account only if it was created by something other than a registration, such as a hand-edited database, or if it has since been revoked or has expired. It reads "pending" and registration refuses its token. That is the same dead end and the same answer.

The server detects one such state itself: a database with an invitation of another kind but no account, where no first-run invitation can ever be created. It says so explicitly, telling the owner to wipe and redeploy, rather than reporting "missing secret" and leaving them to set a secret again forever.

## Threats and how the design answers them

| Threat | Answer |
|--------|--------|
| Someone finds the site before the owner sets up | Without the token they cannot see or redeem anything. The status route only reads, and no other request creates the invitation unless it presents the token. |
| Someone guesses the secret | It is a browser-generated random token, so guessing is infeasible. |
| Someone learns the secret before the owner registers | They could become admin. To learn it they must already control the deployment's configuration or the owner's browser, which is outside the trust boundary. The practical defence is that the guided flow makes the window minutes long. |
| The secret leaks after setup | Inert: the system has accounts, so first run is closed. |
| Two browsers race to become admin | Registration's single point of acceptance admits exactly one, and the creation of the invitation is part of that write, so they cannot both create it. |
| Someone presents a token that is not the secret | It is compared to the configured secret in the write itself. Anything else is refused as an unknown token and creates nothing. |
