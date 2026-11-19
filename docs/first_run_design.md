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

It also shapes the experience. The bootstrap page needs no account-creation flow of its own. Its whole job is to get the owner to the point where the invitation exists and they hold its token, then hand them to the normal registration page.

## The owner's journey

### The page reflects server state

The setup page is a view of the server's bootstrap state, not a wizard with its own memory. On load, and repeatedly afterwards, it asks where things stand:

| State | Meaning |
|-------|---------|
| missing secret | The owner still has to configure something. |
| invitation pending | The first-run invitation exists and is waiting to be redeemed. |
| invitation accepted | An account exists, so setup is over. |

Because the server's state is authoritative, the owner can close the tab, reload, switch machines, or come back tomorrow, and the page picks up at the right step. The single exception is the secret value itself, discussed below.

### Step 1: guiding the owner to set the secret

**The browser generates the secret.** For a short window this value is effectively the admin password, so it must be high-entropy, and asking the owner to invent one would invite something weak. The page generates a complete invitation token from the browser's CSPRNG. The server never generates or displays it: it only receives it through configuration, because configuration is the channel that proves ownership. If the server generated the value and showed it on a page, anyone who reached the page first could read it.

**The page tells the owner exactly what to do.** It shows a ready-to-run command with the value filled in, the equivalent dashboard steps for owners without a local checkout, and the local-development equivalent. It explains briefly why: "setting this proves you own this deployment". A step that looks arbitrary is a step people skip or get wrong.

Registration also needs a permanent signing key, `AUTH_HMAC_SECRET` ([registration_design.md](registration_design.md#what-the-signing-key-is-and-is-not)). It cannot be derived from `FIRST_RUN_SECRET`, which is meant to be temporary, so this step is the natural moment to set both. The server reports only the state of `FIRST_RUN_SECRET`.

### Step 2: waiting for the redeploy

Setting a secret redeploys the Worker. The page does not ask the owner to come back and confirm: it keeps polling, and as soon as the new configuration is live it moves on. The owner runs a command in their terminal and the browser tab advances by itself.

- **A rollout is not instantaneous.** Briefly, some requests may reach the old version, so the page treats the status as something that can move back and forth during that window.
- **Creation happens during a status check.** The first check that sees the secret configured, with an empty system, creates the first-run invitation. A write on what looks like a read is a deliberate trade: the write is idempotent, derived entirely from server configuration, and reveals nothing. It keeps the page a simple poller. It does not matter whose request triggers it, even a stranger's, because it only records the hash of a token the stranger does not have.

The check works from one snapshot: whether any account exists and whether a first-run invitation exists are read together, so the two answers describe the same instant. An account means "accepted", and the secret is not even consulted. A first-run invitation means "pending". Only when neither exists is the secret read, and it must be a well-formed invitation token, or the status stays "missing secret".

### The secret has to survive until registration

This is the one piece of state the server cannot help with, and the most likely way for setup to go wrong.

Worker secrets are write-only: once set, neither wrangler nor the dashboard shows the value again, and the server never returns it either. So the browser that generated it is the only place it exists, apart from whatever the owner copied. If it is lost after the invitation has been created, which happens within seconds of deploying the secret, the owner cannot recover it. Setting a new value does not help, because the invitation is already tied to the old one (see "Closing the hole").

- **If the value is not available** (a different browser, cleared storage, a secret set out of band), ask the owner to paste the value they deployed rather than failing.
- **If the pasted value is wrong**, registration's early, advisory invitation check refuses it before any passkey prompt, and the page can say plainly that the fix is to wipe the database and redeploy.

### Step 3: handing off to registration

Once the invitation is pending, the page sends the owner to the ordinary registration page, carrying the token, for example `/register?first-run=true#<token>`.

- **The token travels in the fragment.** Fragments are never sent to the server and do not appear in `Referer`. The registration page reads it and immediately removes it from the address bar and history. It is a short-lived admin credential, so keeping it out of logs, history and shoulder-surfing range is worth the effort.
- **The first-run hint is cosmetic.** It lets the registration page tailor its copy. The server ignores it entirely: first-run handling is decided by the invitation the token resolves to, never by what the client claims.

From here, registration is exactly the flow in [registration_design.md](registration_design.md). If two browsers race at this point, its single point of acceptance admits exactly one.

### Step 4: done

After registration, the status is permanently "accepted", and the setup page just points to sign-in. This is the moment to tell the owner they can delete `FIRST_RUN_SECRET`. Nothing depends on them doing it, but tidy deployments are easier to reason about.

## Closing the hole

The hole closes in two stages, each enforced by facts in the database, not by operator action.

**Stage 1: once an invitation exists, no first-run invitation can be created.** The server creates it only when there are no invitations and no accounts at all, and that condition can never be true again. The condition is part of the write itself, so two racing status checks cannot both create it. A consequence: changing `FIRST_RUN_SECRET` after creation does nothing, because the invitation is tied to the old token's hash. That is deliberate, and it is why keeping the generated value matters so much. Supporting "I lost or changed the secret" would mean reopening the hole based on current configuration, which is exactly the persistent back door this design avoids.

**Stage 2: once any account exists, the first-run invitation is dead.** Single use covers the normal case. The first-run invitation adds a stronger condition: it is redeemable only while there are no accounts at all. Single use is a property of the invitation, while "no accounts" is a property of the whole system, and requiring both keeps the path closed however the database came to have accounts. Once an account exists, the status check stops consulting the secret, so a `FIRST_RUN_SECRET` left in the deployment forever is inert.

### Recovery is a wipe

If the owner loses the secret mid-bootstrap, changes it after creation, or gets into any other odd state, the answer is to wipe the database and redeploy. Before the first admin exists there is nothing of value to preserve, every recovery path would be a way to reopen the hole, and handling none of them keeps the mechanism small enough to reason about completely. The page's job is to make wiping and redeploying the clearly signposted answer.

The server detects one such state itself: a database with an invitation of another kind but no account, where no first-run invitation can ever be created. It says so explicitly, telling the owner to wipe and redeploy, rather than reporting "missing secret" and leaving them to set a secret again forever.

## Threats and how the design answers them

| Threat | Answer |
|--------|--------|
| Someone finds the site before the owner sets up | Without the token they cannot see or redeem anything. Triggering the creation gains them nothing. |
| Someone guesses the secret | It is a browser-generated random token, so guessing is infeasible. |
| Someone learns the secret before the owner registers | They could become admin. To learn it they must already control the deployment's configuration or the owner's browser, which is outside the trust boundary. The practical defence is that the guided flow makes the window minutes long. |
| The secret leaks after setup | Inert: the system has accounts, so first run is closed. |
| Two browsers race to become admin | Registration's single point of acceptance admits exactly one. |
