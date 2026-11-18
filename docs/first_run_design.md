# First-run bootstrap: design rationale

> This document explains *why* bootstrap works the way it does. It is not a spec. 

Related: [invitations_design.md](invitations_design.md), [registration_design.md](registration_design.md)

## The problem

[Invitations](invitations_design.md) are the only way to create an account, and only admins can create invitations. A freshly deployed authsu has no admins, so nobody can ever get in. Something has to break this circularity exactly once.

Any bootstrap mechanism is, by definition, a way to become admin without being invited. That is a hole in the security model. The design goals follow from treating it as one:

1. **The hole should require proof that you own the deployment.** Being the first person to visit the site is not proof.
2. **The hole should close itself**, as early as possible and without relying on the operator to remember to close it.
3. **The hole should not be a second authorization system.** The invitation model has already been reasoned about. The bootstrap should reuse it rather than add a parallel path that needs its own scrutiny.

There is also a fourth goal, about the person doing the setup:

4. **Setup should be a guided, mostly self-driving experience.** The owner has just deployed something and wants to be signed in as admin. They should never have to invent a secret, read docs to find out what to do next, or come back and click "check again". The page should always know what step they are on and take them to the next one.

The rest of the document follows the owner's path, and explains at each step why it is built that way.

## Proof of ownership: a deploy-time secret

What the legitimate owner has, and nobody else has, is the ability to configure the Worker, with `wrangler secret put` or the Cloudflare dashboard. So bootstrap asks the owner to set a secret, `FIRST_RUN_SECRET`, and treats knowledge of that secret as proof of ownership. Someone who can set Worker secrets already controls the deployment, so this adds no new trust. It reuses trust the owner already has.

## Reusing invitations: the secret becomes an invitation code

Instead of a special "if you know the secret, you may become admin" code path, the secret becomes the code of an ordinary invitation. That invitation grants admin, can be used once, and is marked as the first-run invitation because one extra rule applies to it (below).

This is what satisfies goal 3. From registration's point of view, the first admin redeems an invitation like anyone else. Every property argued for in the invitation design comes along for free: a single point of acceptance, no shadow users, and the role taken from the invitation rather than from the client.

It also shapes the user experience. The bootstrap page doesn't need its own account-creation flow. Its whole job is to get the owner to the point where an invitation exists and they hold its code, then hand them to the normal registration page.

## The owner's journey

### The page reflects server state

The setup page at `/first-run` is a view of the server's bootstrap state, not a wizard with its own memory. On load, and repeatedly afterwards, it asks the server where things stand. The server answers with one of a few states:

| State | Meaning |
|-------|---------|
| missing secret | The owner still has to configure something. |
| invitation pending | The first-run invitation exists and is waiting to be redeemed. |
| invitation accepted | An account exists, so setup is over. |

Because the server's state is authoritative, the owner can close the tab, reload, switch machines, or come back tomorrow, and the page picks up at the right step. Nothing about progress lives only in the browser. The single exception is the secret value itself, discussed below.

### Step 1: guiding the owner to set the secret

When the server reports a missing secret, the page has to get a strong value into the Worker's configuration. That job has two parts.

**The browser generates the secret.** For a short window this value is effectively the admin password, so it must be high-entropy. Asking the owner to invent one would invite something weak. The page generates it with the browser's CSPRNG and encodes it in a copy-paste-safe form (base64url). The server never generates or displays it. It only ever receives the value through configuration, because configuration is the channel that proves ownership. If the server generated the value and showed it on a page, anyone who reached the page first could read it.

**The page tells the owner exactly what to do.** It shows a ready-to-run command with the value filled in, for example:

```console
npx wrangler secret put FIRST_RUN_SECRET
```

It also shows the equivalent dashboard steps, for owners who deployed without a local checkout, and the local-development equivalent (`.dev.vars`). The page should explain briefly why it is asking: "setting this proves you own this deployment". A step that looks arbitrary is a step people skip or get wrong.

Registration also needs a permanent signing key, `AUTH_HMAC_SECRET` (see [registration_design.md](registration_design.md#what-the-signing-key-is-and-isnt)). It can't be derived from `FIRST_RUN_SECRET`, because that secret is meant to be temporary, while every future registration needs the signing key. So this step is the natural moment to set both, and the page shows the command for each. The server reports only the state of `FIRST_RUN_SECRET`: it never looks at the signing key here, and a missing or unusable first-run secret is the one status, "missing secret".

### Step 2: waiting for the redeploy

Setting a secret redeploys the Worker. The page doesn't ask the owner to come back and confirm. It keeps polling the status every few seconds, and as soon as the new configuration is live it moves on by itself. From the owner's point of view, they run a command in their terminal and the browser tab advances on its own. This is the "self-driving" goal in practice.

Two details make polling robust:

- **A rollout isn't instantaneous.** Briefly, some requests may still reach the old version. The page should treat the status as something that can move back and forth during that window, not as a one-way switch that breaks if it bounces.
- **Creation happens during a status check.** The first status check that sees the secret configured, with an empty system, creates the first-run invitation. A write on what looks like a read is a deliberate trade. The write is idempotent, it is derived entirely from server configuration, and it reveals nothing. It keeps the page a simple poller, with no separate "create invitation" step and no ordering to get wrong. It doesn't matter whose request triggers it, even a stranger's, because it only records the hash of a secret the stranger doesn't have.

The check works from one snapshot. A single statement reads both facts it needs, whether any account exists and whether a first-run invitation exists, so the two answers describe the same instant; read as two statements, an account could appear between them. An account means "accepted", and the secret is not even consulted; a first-run invitation means "pending". Only when neither exists is the secret read. It must be at least 32 bytes and must be usable as an invitation code (the base64url alphabet, which is what the browser generates), or the status stays "missing secret". A valid secret is turned into the invitation by the conditional insert described under "Closing the hole". A database that cannot be read or written is a 503 (`first_run_check_failed`, `first_run_create_failed`), and a write the schema refused as a backstop for the code is a 500 (`first_run_check_rejected`, `first_run_create_rejected`), which the client sees as a bare internal error.

### The secret value has to survive until registration

This is the one piece of state the server can't help with, and the most likely way for setup to go wrong.

Worker secrets are write-only. Once set, neither wrangler nor the dashboard will show the value again. The server deliberately never returns the code either. So the browser that generated the value is the only place it exists, apart from whatever the owner copied. If it is lost after the invitation has been created, which happens within seconds of deploying the secret, the owner can't recover it. Setting a new value doesn't help, because the invitation is already tied to the old one (see "Closing the hole").

- **If the value isn't available** (different browser, cleared storage, secret set out-of-band), ask the owner to paste the value they deployed rather than failing.
- **If the pasted value is wrong**, registration's early, advisory invitation check rejects it before any passkey prompt. The page can then say plainly that the code doesn't match the deployed secret, and that the fix is to wipe the database and redeploy.

### Step 3: handing off to registration

Once the server reports a pending first-run invitation, the page sends the owner to the ordinary registration page, carrying the code, for example `/register?first-run=true#<code>`. Each part is chosen deliberately.

**The code travels in the fragment.** Fragments are never sent to the server and don't appear in `Referer`. The registration page reads the fragment and immediately removes it from the address bar and the current history entry. The code is a short-lived admin credential, so keeping it out of server logs, browser history, and shoulder-surfing range is worth the small effort.

**The first-run hint is cosmetic.** The query flag lets the registration page tailor its copy, with something like "Create the administrator account" in place of a generic sign-up form. It doesn't make the owner type anything. The code arrives pre-filled, and the owner only supplies their details and completes the passkey prompt. The server ignores the flag entirely. First-run handling is decided by the invitation the code points at, never by what the client claims.

From here, registration is exactly the flow described in [registration_design.md](registration_design.md). If two browsers race at this point, its single atomic point of acceptance admits exactly one.

### Step 4: done

After registration, the status is permanently "accepted", and the setup page just becomes a pointer to sign in. This is also the right moment to tell the owner they can delete `FIRST_RUN_SECRET`. Nothing depends on them doing it (see below), but tidy deployments are easier to reason about, and the reminder costs nothing.

## Closing the hole

The hole closes in two stages, and each stage is enforced by facts in the database, not by operator action.

**Stage 1: once an invitation exists, no first-run invitation can be created.** The server creates the first-run invitation only when there are no invitations and no users at all. After that the condition can never be true again. The same condition is part of the insert itself, so two racing status checks cannot both create it: the database admits exactly one. This is deliberately enforced at insert time rather than by a schema constraint, which keeps the first-run type from being special-cased in the schema. A consequence: changing `FIRST_RUN_SECRET` after creation does nothing, because the invitation is already tied to the old secret's hash. This is deliberate, and it is why keeping the generated value matters so much to the UX. Supporting "I lost or changed the secret" would mean reopening the hole based on the current configuration, which is exactly the persistent back door this design avoids.

**Stage 2: once any user exists, the first-run invitation is dead.** The invitation's single use covers the normal case. The first-run invitation adds a stronger condition: it is redeemable only while there are no users at all. Single use is a property of the invitation row, while "no users" is a property of the whole system. Requiring both means the path stays closed however the database came to have users. Once a user exists, the status check also stops consulting the secret at all, so a `FIRST_RUN_SECRET` left in the deployment forever is inert.

### Recovery is a wipe

If the owner loses the secret mid-bootstrap, changes it after creation, or gets into any other odd state, the answer is to wipe the database and redeploy. Before the first admin exists there is nothing of value to preserve. Every recovery path would be a way to reopen the hole, and handling none of them keeps the mechanism small enough to reason about completely. The page's job is to make wiping and redeploying the clearly signposted answer when it detects such a state, instead of leaving the owner stuck.

The server detects one such state itself. If the insert is refused, it reads the state once more to see why. A first-run invitation or an account that appeared in between is the ordinary race, and is answered as "pending" or "accepted". If neither exists, then an invitation of some other type is in a database that has no account, so no first-run invitation can ever be created there and no secret will help. The server answers 409 `first_run_blocked`, telling the owner to wipe and redeploy, instead of reporting "missing secret" and leaving them to set a secret again forever. (Today no other invitation type can be created, so this is a guard against a database that was edited or restored by hand.)

## Threats and how the design answers them

| Threat | Answer |
|--------|--------|
| Someone finds the site before the owner sets up | Without the secret they can't see or redeem anything. Triggering the creation gains them nothing. They learn only that setup isn't finished. |
| Someone guesses the secret | It is a browser-generated CSPRNG value, so guessing is infeasible. |
| Someone learns the secret before the owner registers | They could become admin. To learn it they must already control the deployment's configuration or the owner's browser, so this is outside the trust boundary. The practical defense is that the guided flow makes the window minutes long. |
| The secret leaks after setup | Inert: the system has users, so first-run is closed. |
| Two browsers race to become admin | Registration's single atomic point of acceptance admits exactly one. |
