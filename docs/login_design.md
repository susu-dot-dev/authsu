# Login: design rationale

> This document explains *why* login is shaped the way it is. It is not a spec: the code is authoritative for what exists. Byte layouts below illustrate an idea.

Related: [registration_design.md](registration_design.md), [secrets_design.md](secrets_design.md), [users_design.md](users_design.md)

## The problem

An authsu account *is* a passkey ([registration_design.md](registration_design.md)). There is no username and no password, so login cannot begin with "who are you?". It begins with "prove you hold one of our passkeys", and learns who the user is from the answer.

Login inherits two requirements from registration and adds one of its own:

1. **`begin` leaves nothing behind.** Anyone can call it as often as they like, so it must not grow a table that needs expiry and cleanup.
2. **The flow takes two round trips.** The server issues the challenge before the browser calls `navigator.credentials.get()`, and the signed response comes back afterwards.
3. **A login must be single use.** At registration, uniqueness came for free from the account being created. A login creates nothing like that, so without something else one captured response could be replayed for any number of sessions.

Login then hands the client a session: the credential that proves who it is on later requests.

## Usernameless login

Registration asks for a discoverable credential, so the authenticator stores the passkey with the user handle we chose and can offer it without being told which account it is for. `begin` sends an empty list of allowed credentials, the user picks an account in the operating system's chooser and verifies, and the response identifies the account in two ways:

- **The credential id** is how the account is found. It is unique across all accounts.
- **The user handle** must match the account the credential belongs to. It is a consistency check.

Neither is covered by the assertion signature. The login is bound to an account by the lookup: the proof is that the response was signed by the key stored for the credential that was found. That holds only while each stored public key belongs to one credential, and registration's attestation `none` gives no proof that a registrant holds the private key of the key they submit, so a public key may be stored only once across all accounts.

Everything before the response (the chooser, a cancelled prompt, a user with no passkey, a phone over hybrid transport) happens in the browser and operating system. The server is not involved.

Login is the modal flow, where a button calls `begin` and then `get()`. Conditional mediation, where passkeys appear in autofill, needs a challenge issued when the page loads that then expires while the page sits open. It can be added later without changing the server.

## Our own verifier, not a library

Registration already needed strict base64url, strict client data, strict CBOR and COSE key validation, stricter than the obvious library in several places, so those parsers are ours. Login reuses them. Its own new code is small: a fixed 37-byte authenticator data layout (no attestation, no extensions), one ECDSA check against a key we stored, and the challenge. Most of a general WebAuthn library is attestation formats, metadata services and extensions that we would refuse to run, and it leaves replay, our hardest problem, to the caller.

## The challenge

The challenge uses registration's approach: a fixed binary layout carrying its own expiry, authenticated with an HMAC, so that `begin` stores nothing. Both ceremonies share one implementation.

```
state     = version || expires_at || nonce
signature = HMAC(K_login, state)
challenge = state || signature
```

- **The nonce is only entropy**, at least the 16 bytes the spec asks for, so every challenge is unique.
- **There is no associated data.** `begin` takes no input, so there is nothing to bind.
- **The key is login's own**, derived from the root secret with its own context, so a challenge created for one ceremony can never verify as the other.

The challenge is read only from the client data, and its expiry only after its signature has verified.

**A leaked challenge key is not account takeover.** An attacker can forge challenges, but a challenge is worthless without a passkey's signature over it, and the browser binds that signature to our origin. Rotating the key breaks only ceremonies in flight. One combination with replay remains, a forged challenge with a far-future expiry, so `finish` refuses any challenge that expires further ahead than the ceremony timeout, whatever its signature.

## Replay

A stateless challenge cannot be marked as used. The threat is someone who obtains one valid `finish` body: a malicious extension, a log line, a debugging proxy. The signature counter does not help, because synced passkeys always report zero.

The options were:

- **Accept the window**, relying only on a short expiry. The weakest option.
- **Store the challenge at `begin` and consume it at `finish`.** This is the spec's suggestion, but `begin` would write, and anyone could fill the table.
- **Bind the challenge to a cookie set at `begin`.** It raises the bar, but whoever captured the body may well have the cookie too.
- **Keep the challenge stateless and record it at `finish`.** This is the one we chose.

`finish` verifies everything first: the challenge, the client data, the authenticator data and the assertion signature. Only then does it write. The write that issues the session also records the challenge it was issued from, uniquely, so a replay collides with the session the first login created and nothing is issued. Two concurrent replays cannot both succeed, because the database admits exactly one.

The record needs no table of its own: every successful login issues exactly one session, so it lives on that session.

- **Only verified logins write.** Before anything is stored, someone must hold a passkey registered here and produce a valid signature.
- **Abandoned logins leave nothing behind.** A challenge that never reaches `finish` simply expires.
- **No cleanup job just for challenges.** The record lives exactly as long as its session.

A rejected replay is reported like any other failed login.

### What this asks of sessions

The replay guard lives on the session, so removing the session removes the guard. That is safe only once the challenge has expired, when its HMAC check refuses it anyway. Two rules follow:

- **A session outlives its challenge.** Sessions last days and challenges minutes. This is also why `finish` refuses challenges with an implausibly distant expiry.
- **A session is removed only once it has expired, never when it is revoked.** Logging out revokes the session and leaves it in place, because removing it would let a response captured just before logout be replayed within the challenge window.

## The session

A session is a [secret](secrets_design.md) of its own kind: a random token, stored only as a hash, recording the account and the passkey that started it. Like every secret, it carries nothing. Who it belongs to, whether it is still valid and the account's role and standing are read live when it is presented, so a role change or a revocation takes effect on the next request ([users_design.md](users_design.md)).

That also means a session needs no signing key. Nothing has to be protected whose leak would let someone create sessions.

The token reaches the browser only as the value of a cookie marked `HttpOnly` and `Secure`, never in a response body. Page script cannot read it, so a script injection on our origin cannot exfiltrate it, and it never travels over plain HTTP.

The cookie is named with the `__Host-` prefix, so a browser accepts it only when it is `Secure`, has `Path=/` and has no `Domain`, and a sibling subdomain cannot set or shadow it. It is `SameSite=Lax`: a session survives following a link to the site, and the cookie is withheld from cross-site subrequests and POSTs. A request carrying two session cookies is refused rather than choosing one, because whoever controls the other cookie would otherwise decide which session is meant.

Deleting a passkey ends the sessions it started.

## Session lifetime

A session lasts a fixed 14 days and is never extended. When it ends, the user signs in with their passkey again. That bounds a stolen cookie as simply as possible: it is good for at most 14 days, and logout ends it sooner.

Refresh is the obvious addition, and it is deliberately absent:

- **A refresh is a second way to be issued a session**, so it needs its own single-use guarantee. Two tabs refreshing at once, or a thief refreshing a stolen cookie, could each turn one session into several.
- **It is revocation with a grace period.** Requests already in flight carry the old token, so the old session cannot simply end at the moment of refresh.
- **An always-active user is never signed out**, unless a further limit is measured from the original login and carried through every refresh.

Together these are a second state machine beside login, with its own races, tests and failure codes. A fixed lifetime needs none of it, and with a passkey, signing in again is one biometric prompt.

## Verification

What `finish` accepts is narrow, and everything outside it fails closed. Most of the strictness is registration's, reused:

- **The response** is the browser's own JSON, decoded strictly, with no client extension results.
- **The client data** is held to registration's rules, with the type for an assertion.
- **The authenticator data** is exactly the fixed layout. The relying party matches, user presence and user verification are both set, and nothing we did not ask for is present.
- **The credential** exists, and the returned user handle is its account's. A credential's backup eligibility cannot change between registration and login.
- **The signature** is checked with the key stored at registration. Login takes user verification from these signed flags, never from what registration stored, because nothing at registration was signed.

An unknown credential, a handle that is not the account's, a bad signature, a forged or expired challenge and a replay are all one answer, so a failed login reveals nothing about which check failed. Every unusable session (missing, malformed, unknown, expired, revoked) is likewise one answer, and a failure to read the store is never reported as one: an outage must not look like a sign-out.

## Where verification happens

Verifying the session belongs to the route boundary, not to the session feature. The boundary reads the credential, resolves it and settles what the caller may do before any handler runs ([permissions_design.md](permissions_design.md)). The session feature is only what a signed-in caller does with their own session: read who it speaks for and when it ends, and log out, which revokes the presented credential.

## The UI on another origin

The UI is served from `https://susu.dev` and the API from `https://auth.susu.dev`, so the UI's script makes cross-origin requests. Neither of the two consequences weakens the CSRF defence.

- **CORS allows one origin: `UI_ORIGIN`.** That is already the single origin a passkey ceremony is accepted from, so it is by definition the UI's, and reusing it means no second setting that can drift. It is compared as a whole string, with no wildcard, pattern or subdomain flexibility, and it is validated as a bare origin before CORS trusts it, so a mistake such as `null` or `*` allows nothing rather than everything. Credentials are allowed, which is safe only because the origin is exact.
- **Every unsafe route requires `Content-Type: application/json`**, which a browser sends cross-origin only after a preflight succeeds. A preflight succeeds for the UI's origin and no other, so another site still cannot make a browser deliver a state-changing request, nor read a response.

Both rules cover every credentialed route. The OAuth endpoints that non-browser clients call are credential-less, so they take forms and have their own CORS policy without credentials. See [oauth_design.md](oauth_design.md#the-boundary-changes).

The cookie stays `SameSite=Lax`. `SameSite` is about sites (registrable domains), not origins: `susu.dev` and `auth.susu.dev` are the same site, so the UI's credentialed requests carry the cookie and `None` is not needed. The cost is a constraint on deployment: **the UI and the API must share a registrable domain.** A UI on an unrelated domain would need `SameSite=None`, which is a different threat model and is not supported.

Because the sites match, `SameSite` no longer separates the UI from the API's other sibling hosts. What stops a page on another subdomain is CORS: it is not `UI_ORIGIN`, so it can neither send a JSON request nor read a response. Every host under the registrable domain is therefore inside the trust boundary.

| Value | Is | Used for |
|---|---|---|
| `API_ORIGIN` (`https://auth.susu.dev`) | Where this Worker is served | The identity of the service, wherever it has to name itself |
| `UI_ORIGIN` (`https://susu.dev`) | Where the UI and its passkey ceremonies run | The origin ceremonies are accepted from, and the one origin CORS allows |
| Relying party ID (`susu.dev`) | The host of `UI_ORIGIN` | What every passkey is bound to |

The ceremonies run on the UI's page, so the browser writes the UI's origin into the client data and checks the relying party ID against the UI's host. The API's host never appears in a ceremony.

## Decisions

- **Replay protection** comes from a stateless signed challenge, recorded uniquely on the session in the write that issues it. There is no challenge table and no write at `begin`.
- **Our own verifier**, extending registration's. A library is a reference, not a dependency.
- **The session is a secret**, delivered only as an `HttpOnly`, `Secure`, `__Host-` cookie, with nothing in the token and everything read live.
- **Sessions last a fixed 14 days** and are never refreshed.
- **Sessions are removed only after they expire**, never on revocation, so the replay guard outlives its challenge.
- **`finish` is not rate limited.** Everything that needs no stored credential is checked before the credential is read, so only a response to a challenge we issued, from our origin, costs a lookup.
- **No conditional mediation**, for now.

## Open questions

- How a user lists and ends their own other sessions, and how an administrator ends someone's sessions without revoking the account. Revoking the account ends all of them.
