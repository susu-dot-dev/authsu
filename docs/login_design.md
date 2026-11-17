# Login: design rationale

> This document explains *why* login is shaped the way it is. It is not a spec. Request shapes, byte layouts, and SQL fragments below illustrate an idea; the code is authoritative for what actually exists.

Related: [registration_design.md](registration_design.md), [invitations_design.md](invitations_design.md)

## The problem

An authsu account *is* a passkey ([registration_design.md](registration_design.md)). There is no username and no password, so login cannot begin with "who are you?". It has to begin with "prove you hold one of our passkeys", and learn who the user is from the answer.

Login inherits two requirements from registration and adds one of its own:

1. **`begin` leaves nothing behind.** This is the same rule as registration, for the same reason: anyone can call `begin` as often as they like, so it must not grow a table that needs expiry and cleanup.
2. **The flow takes two round trips.** The server has to issue the challenge before the browser calls `navigator.credentials.get()`, and the signed response comes back afterwards.
3. **A login must be single use.** This is what is new. At registration, uniqueness came for free from what was being created: a challenge carried one user handle, and a handle could make at most one account. A login creates nothing like that. Without something else, one captured response could be replayed to get any number of sessions.

Login then has to hand the client something that proves who it is on later requests. That token, and how it is stored, takes up the second half of this document.

## How usernameless login works

Registration asks for a *discoverable* credential (`residentKey: "required"`). The authenticator stores the passkey together with the user handle we chose at registration, and can offer it without being told which account it is for.

So `begin` sends an empty list of allowed credentials. That tells the browser to offer any passkey it holds for our relying party ID. The user picks an account in the operating system's chooser and verifies (biometric or PIN). The response then says who the user is in two ways:

- **The credential id** (`rawId`) is how the account is found. It is unique across all accounts and was stored at registration.
- **The user handle** (`userHandle`) is checked against the account the credential belongs to. It is a consistency check, which is how registration planned it ("the user handle is then just a consistency check").

Neither is covered by the assertion signature, which signs only the authenticator data and the hash of the client data. The login is bound to an account by the lookup: the proof is that the response was signed by the key stored for the credential that was looked up. That holds only while each stored public key belongs to one credential. Registration asks for attestation `none`, so it carries no proof that the registrant holds the private key, and public keys are not secret. If another account could store the same key under a different credential id, a response for the real key would verify against both rows. So `credentials.public_key` is unique (migration `0003`). The index is on the stored bytes, which is one value per key because registration stores only the canonical COSE encoding of an ES256 key; a second key format would have to be canonicalised first.

Everything that happens before the response, including the account chooser, a cancelled prompt, a user with no passkey at all, or a phone used over hybrid transport, happens in the browser and operating system. The server is not involved. A cancelled or empty prompt never reaches `finish`.

The flow, illustratively:

```
POST /api/login/begin    ->  {publicKey: {challenge, rpId, timeout, userVerification: "required"}}
navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(...)})
POST /api/login/finish   <-  PublicKeyCredential.toJSON()  (AuthenticationResponseJSON)
```

We chose the modal flow, where a login button calls `begin` and then `get()`, over conditional mediation, where passkeys appear in the browser's autofill. Conditional mediation needs a challenge issued when the page loads, which then expires while the page sits open. It is easy to add later and changes nothing on the server.

## Roll our own, or use a library

The obvious alternative was go-webauthn. We chose to extend our own verifier instead, for these reasons:

- **The hard part is already ours.** Registration needed strict base64url, strict `clientDataJSON`, strict CBOR, and COSE key validation. We wrote those ourselves because the library was less strict than we needed in several places (see [registration_design.md](registration_design.md#verification)). Login reuses all of them.
- **Login is the simpler ceremony.** Its response carries no attestation object and needs no CBOR. With attested credential data and extensions both refused, the authenticator data is 37 bytes at fixed offsets: the RP ID hash, one flags byte, and a 4-byte counter. The new code is the parser for those 37 bytes, one ECDSA signature check against a key we stored ourselves, and the challenge.
- **Most of the library is code we would refuse to run.** Its protocol package is around 24,000 lines including tests, mostly attestation formats, metadata services, and extensions. We accept none of those.
- **The library does not solve our hardest problem.** It leaves replay to the caller (see the next section).

## The challenge

### Stateless and signed, as at registration

The challenge uses registration's approach: a fixed binary layout carrying its own expiry, authenticated with an HMAC, so that `begin` stores nothing:

```
state     = version || expires_at || nonce               -- illustrative layout
signature = HMAC(K_login, state)
challenge = state || signature
```

Here is how it differs from registration's challenge, and why:

- **It carries a random nonce of its own.** Registration's challenge got its entropy for free from the 32-byte random user handle. At login there is no handle to mint, so the challenge needs its own random bytes: at least the 16 the spec asks for. This is what makes every challenge unique, and as at registration, a test should assert that two calls to `begin` never produce the same challenge.
- **It has no associated data.** Registration bound the invitation code and the account name into the signature, because the client supplies both at `begin`. A login `begin` takes no input, so there is nothing to bind.
- **It uses its own derived key.** Registration's challenge key is derived from the root secret with its own context, and the login key is derived the same way with a different context. Both are integrity keys of the same kind. Separating them means a challenge minted for one ceremony can never verify as the other, even if the `clientDataJSON` type checks were ever wrong.

As at registration, the challenge is read only from `clientDataJSON`, and its expiry is read only after the signature has verified.

### What a leaked challenge key would allow

The registration document makes the point that a signing key which merely protects a ceremony is not an authorization key. The same holds here.

With the login key, an attacker can forge challenges, but a challenge is worthless without a passkey's signature over it. The browser binds that signature to our origin, so the attacker cannot get a user to sign a forged challenge without running script on our origin. A leak is therefore not account takeover. Rotation breaks only ceremonies in flight.

There is one way a leaked key could combine with replay, covered below: a forged challenge with a far-future expiry. `finish` defends against it by refusing any challenge whose signed expiry lies further ahead than the ceremony timeout, even when its signature is valid.

## Replay

### Why login needs its own answer

A stateless challenge cannot be marked as used. At registration this did not matter, because the account it produced enforced uniqueness. At login, the threat is that someone obtains one valid `finish` request body: a malicious browser extension, a log line, a debugging proxy, or a misbehaving intermediary. Without a single-use guarantee, they can replay that body until the challenge expires and get a new session each time.

The signature counter does not help. Synced passkeys always report zero, and we do not store the counter (see registration).

### Options considered

- **Accept the window.** Rely only on a short challenge expiry. This is the weakest option, and it is what a signed-cookie design gives you.
- **Store the challenge at `begin`, consume it at `finish`.** This is what the spec suggests and what go-webauthn recommends when it needs real replay protection: it documents indexing the stored challenge as unique, and offers an option for callers to supply their own challenge so it can be recorded first. It breaks our first requirement: `begin` writes, and anyone can fill the table.
- **Bind the challenge to a cookie set at `begin`.** A replay would then also need the cookie. That raises the bar, but an attacker who captured the request body may well have captured its cookie too, so this cannot replace single use.
- **Keep the challenge stateless; record it at `finish`.** This is the one we chose.

For comparison, go-webauthn itself is stateless only if the caller makes it so. `BeginDiscoverableLogin` returns the challenge in a `SessionData` value that the caller must persist, server-side or "in a signed, opaque cookie", and `finish` checks only that it matches and has not expired. Whether the challenge is single use depends entirely on where the caller kept it and whether they consumed it atomically.

### The chosen shape: consumed as part of the write that issues the session

`begin` still writes nothing. `finish` verifies everything first: the challenge signature and expiry, the client data, the authenticator data, and the assertion signature. Only then does it write. The write that issues the session also records the challenge, and a uniqueness constraint makes that record the single-use guard. The pattern is registration's point of acceptance again: the check is a condition *of* the write, not a read before it. Two concurrent replays of the same response cannot both succeed, because the database admits exactly one.

The record does not need a table of its own. Every successful login issues exactly one key (next section), so the challenge's hash is a unique column on that key's row. A replay collides with the row the first login created, the batch fails, and no second session exists.

This placement has properties the store-at-begin design lacks:

- **Only verified logins write.** Before a row can exist, someone must hold a passkey registered here and produce a valid signature. Calling `begin` costs nothing and fills nothing.
- **Abandoned logins leave nothing behind.** A challenge that never reaches `finish` simply expires.
- **No cleanup job just for challenges.** A record lives exactly as long as the key it is attached to.

A replay rejected by the constraint is reported the same way as any other failed login. It is an authentication failure, not a conflict worth telling the client about.

### The constraint on deleting rows

The challenge record lives on the key's row, so deleting the row deletes the record. That is only safe once the challenge has expired: from then on its HMAC check rejects it anyway. Two rules follow:

- **A session must outlive its challenge.** Session lifetimes are measured in days, and challenges last minutes, so this holds easily. It is the reason `finish` refuses challenges with implausibly distant expiry: a forged long-lived challenge would break it.
- **Rows are removed on expiry, never on revocation.** Logging out sets a revocation time and leaves the row in place until it expires. If logout deleted the row, a response captured just before logout could be replayed for a fresh session within the challenge window.

## The token: japikeys

Login ends by issuing a session. We use the same mechanism as API keys: a *japikey*. For each key we mint a fresh ES256 (P-256) key pair, sign one JWT with the private key, store only the public key, and discard the private key. The JWT is the bearer credential. Verifying it means looking up its public key by key id (`kid`) and checking the signature.

We chose this over an HMAC-signed session token, a random opaque token, and a long-lived signing key:

- **There is no signing secret to leak.** The registration document's key-separation rule ("the key must not be reused for anything where a signature *is* authorization") exists because a leaked session-signing key would mean account takeover. With japikeys no such key exists: every private key is gone once its one token is signed. A database leak exposes only public keys. The remaining trust assumption, which japikey states plainly, is that anyone who can *write* to the database can insert a key of their own.
- **Revocation is per key.** It is a property of the row, and takes effect at the time recorded there. Logout sets it to now.
- **Sessions and API keys are one mechanism.** They share minting, verification, revocation, and listing.
- **Public verifiability stays possible.** A japikey's issuer URL leads to a JWKS document holding just that key. We don't publish these yet, but we store the public key as a JWK so that a `/.well-known/jwks.json`-style endpoint could later be served from the row unchanged. That is most likely to matter for API keys, which third parties may want to verify.
- **The cost is small and was measured.** Minting takes about 1 ms and verifying about 2 ms in our Worker, and the library builds under TinyGo within our size budget.

Every claim the verifier needs is signed into the token: subject, audience, expiry, issued-at, and version. The database is consulted per request for the public key and for revocation, as one primary-key read.

The token reaches the browser as the value of a cookie marked `HttpOnly` and `Secure`, and nothing else: `finish` does not return it in the response body. `HttpOnly` keeps it out of reach of page script, so a script injection on our origin cannot read and exfiltrate it. `Secure` keeps it off plain HTTP.

## Session lifetime

A session lasts a fixed two weeks and is never extended. When it ends the user signs in with their passkey again. The two weeks are a starting value; what matters is the shape.

The token already carries what is needed to enforce this: `iat` and `exp` are signed into it, japikey rejects an expired token, and the stored `expires_at` is a second, cheap check. There is nothing else to track.

### Why not refresh

We designed a refresh endpoint and removed it before shipping. It is worth recording what it would have cost, because it is the obvious thing to add and the reason not to is not obvious:

- **Every extension is a new key, and every key is a row** kept until it expires. To keep that bounded, refresh had to be explicit and limited to the last part of a session's life, and not something that happens on use.
- **A refresh is a second way to be issued a session**, so it needs its own single-use guarantee. Two tabs refreshing at once, or a thief refreshing a stolen cookie, could each turn one session into several. The answer was another unique value on the row, recording what the session was granted from.
- **It is revocation with a grace period.** Replacing a session means ending the old one, but requests already in flight carry the old token, so the old key's revocation had to be scheduled a few seconds ahead. That made "revoked" mean "revoked at or before now" everywhere a key is checked.
- **An always-active user is never signed out**, unless a further limit is added, measured from the original login, which needs the login's time carried along through every refresh.

Each piece is small, and together they are a second state machine beside login, with its own races, tests and failure codes. A fixed lifetime needs none of it. The cost is that a user signs in again every two weeks, which with a passkey is one biometric prompt.

What a fixed lifetime also gives is the simplest possible bound on a stolen cookie: it is good for at most two weeks, and logout ends it sooner.

If sessions ever do need extending, the pieces above are the design: an explicit endpoint limited to the end of a session's life, a unique value recording what the new session was granted from, a scheduled revocation for the old one, and an absolute limit measured from the login.

## The key store

### What the schema has to serve

japikey's own reference schema is deliberately minimal: a key id, a user id, a revoked flag, the JWK, and an opaque metadata blob. Expiry, audience, and creation time live only inside signed tokens, and only the key id is indexed. That is enough to verify. It is not enough for what we need: one table holding both sessions and API keys, which can list a user's active keys, revoke them in bulk, and be cleaned up when they expire. So we kept japikey's core columns and added the ones those uses require.

The uses, and what each one needs:

| Use | Shape | Needs |
|---|---|---|
| Verify a token | by key id | the primary key |
| List a user's active sessions or API keys | by user and kind, not revoked, not expired | a composite index |
| Log out everywhere; revoke all of a user's API keys | the same predicate, as an update | the same composite index |
| Remove expired rows; anything "active across all users" | a range on expiry | an expiry index |
| Single use of a login challenge | uniqueness on insert | a unique hash of the challenge |

## Verification

Like registration, what `finish` accepts is deliberately narrow, and everything outside it fails closed. Most of the strictness is shared with registration and reused rather than restated:

- **The request body** is `AuthenticationResponseJSON`, unmodified and decoded strictly. `id` and `rawId` must be equal, and there must be no client extension results.
- **`clientDataJSON`** is held to registration's rules, with type `webauthn.get`.
- **The challenge** must carry a valid signature under the login key, must not have expired, and must not expire implausibly far ahead.
- **Authenticator data** must be exactly the fixed 37 bytes:
  - the RP ID hash must match;
  - user presence and user verification must both be set;
  - attested credential data and extensions must be absent;
  - reserved bits must be clear;
  - backup state without backup eligibility is invalid.
- **The credential** must exist, and the returned user handle must be present and equal its account's handle. Backup eligibility is fixed for the life of a credential, so a change from what registration stored is refused. Backup state and user verification may legitimately change, and the stored flags can be updated.
- **The signature** is ES256 over the authenticator data followed by the SHA-256 of `clientDataJSON`, checked with the key stored at registration. At registration nothing cryptographically bound the client's claims. Here everything above is covered by this signature, which is why login takes user verification from these signed flags and never from what registration stored.
- **The signature counter** is not checked, consistent with not storing it.

An unknown credential, a mismatched handle, a bad signature, and a replay are all reported identically, so a failed login reveals nothing about which check failed.

## Decisions that were open

- **Replay protection** comes from a stateless signed challenge with its own nonce, recorded as a unique hash on the session row in the same write that issues it. There is no challenge table and no write at `begin`.
- **Library or our own:** our own, extending the existing verifier. go-webauthn is a reference, not a dependency.
- **The session token** is a japikey, issued from the same store as API keys.
- **One table** for sessions and API keys, told apart by a kind column that also determines the token's audience.
- **Each session records the credential that created it**, for auditing. Deleting a passkey ends its sessions.
- **Revocation** is a timestamp that takes effect at that time. Logout sets it to now, but because it is a time and not a flag, a revocation scheduled for later would need no schema change. Rows are removed only after they expire.
- **Delivery:** the japikey is the value of an `HttpOnly`, `Secure` cookie.
- **JWKS documents are not published.** The stored JWK keeps the option open. Whether to publish them is a question for API keys.
- **`finish` is not rate limited.** Everything that needs no stored credential (the client data, the authenticator data, and the challenge's signature and expiry) is checked before the credential is read, so only a response to a challenge we issued, from our origin, costs a lookup. That is a single primary-key read, and since `begin` is open, anyone can still obtain a challenge; limiting can be added later if traffic shows it is needed.
- **No conditional mediation.** Login is the modal flow only (see above).
- **Sessions last a fixed two weeks and are not refreshed.** The user signs in again when one ends. See "Session lifetime".

## Decisions the implementation settled

- **Logout** is `POST /api/logout`. It revokes the presented session at the current time and tells the browser to drop the cookie. The row stays until it expires, for the replay reason above. Logging out a session that is already gone is a 401 like any request without a valid session.
- **The cookie** is named `__Host-session`. The `__Host-` prefix makes a browser refuse it unless it is `Secure`, has `Path=/` and has no `Domain`, so a sibling subdomain cannot set or shadow it. It is `SameSite=Lax`: a session survives following a link to the site, and the cookie is withheld from cross-site subrequests and POSTs, which is also what stops another site from triggering a logout.
- **Reading the session** is `GET /api/session`. It reports who the cookie speaks for and when the session ends, which is also when the user has to sign in again. It never writes.
- **The issuer** of every token is derived from `RP_ORIGIN`, so there is no new setting to get wrong. japikey requires `https`, so plain `http` is accepted for `localhost` only.
- **Configuration** is the deployment's, shared with registration (see [registration_design.md](registration_design.md#deployment-configuration)). Login derives its challenge key from `AUTH_HMAC_SECRET` with its own context. Sessions need no signing key at all: each is a japikey whose private half is discarded as soon as it signs its one token, so there is no key whose leak would be account takeover. When configuration is missing, login answers 503 `login_not_configured` and the session routes 503 `session_not_configured`.
- **The account's role is read when a request is verified**, not copied into the token. A role change takes effect on the next request, at the cost of joining `users` on the one primary-key read.
- **Every response about an unusable session is one answer** (401, `unauthenticated`), whether the cookie is missing, malformed, unknown, expired, revoked or for another audience. The cause goes to the log. A failure to read the store is a 503, never a 401, so an outage cannot look like a verdict on someone's session.

## Open questions

- How an administrator revokes someone else's sessions, and how a user lists and ends their own other sessions. The index for it exists; the endpoints do not.
- Removing expired rows. The design says rows are deleted on expiry and never on revocation, and nothing yet deletes them. The table grows by one row per login, so this can wait, but it should not be forgotten.
