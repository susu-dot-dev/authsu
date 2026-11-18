# Permissions: design direction

> This document sets out the intended direction for permissions and *why*. It is not a spec. Almost nothing in it exists yet: the only parts in code are the `agents.scopes` and `japikeys.scope` columns, written with the placeholder `default:agent` and not read (see [agents_design.md](agents_design.md), "What exists"). Once there is code, the code is authoritative for what exists.

Related: [agents_design.md](agents_design.md), [users_design.md](users_design.md), [login_design.md](login_design.md)

## The problem

[agents_design.md](agents_design.md) says an agent's permissions are a ceiling its user sets, and that "credentials carry scopes". This document says what a scope is, where scopes are stored, how a request's permissions are worked out, and how agents and keys are created without becoming a way to gain authority.

Three things limit a request:

- **The user**, whose authority it always is. Their standing (role, revocation) can change at any time.
- **The agent**, if one is acting. Its limit is set when it is created.
- **The key**, the credential presented. Its limit is set when it is created.

The design keeps one rule throughout: **each layer can only narrow the ones above it.** A key never adds to its agent, and an agent never adds to its user.

## Scopes and bundles

A **scope** names one thing a credential may do, as `resource:verb`, for example `agent:create` or `invitation:read`.

A **bundle** is a named set of scopes defined in code, such as `default:user`, `default:agent` or `default:admin`. Bundles do not contain other bundles. Each one lists its scopes explicitly, so reading a bundle's definition tells you everything it grants.

A scope list (on an agent, on a key) can name individual scopes, bundles, or both: `["default:agent", "agent:create"]`.

Bundles are **expanded when a request is checked**, not when a list is written. Adding a scope to `default:agent` reaches every agent and key that names the bundle. Listing scopes one by one is how to opt out of that: an explicit list never changes.

The default bundles are where "elevated, never a default" lives. `default:user` includes `agent:create`, because users are expected to create agents for most things rather than give their own keys to software. `default:agent` does not, so an agent can create agents only if `agent:create` is named for it.

Scope names that the code does not know are rejected wherever a list is written (creating a key, creating an agent). A typo should fail loudly, not produce a credential that silently can do nothing.

## Where scopes live

| Layer | Stored in | Can it change during a token's life? |
|---|---|---|
| User | `users.role`, unchanged. Each role maps to bundles in code: every user gets `default:user`, and admins also get `default:admin`. | Yes, so it is read live |
| Agent | `agents.scopes`, written when the agent is created | No, for now |
| Key | The `scope` claim in the key's JWT, with a copy on its `japikeys` row | No |

The rule behind the table: **a token may carry only what cannot change while it is valid.** This is the same reasoning that keeps the role out of the session token ([users_design.md](users_design.md)), applied the other way round. A japikey signs exactly one token and then discards its private key, so a key's scopes cannot be edited even in principle. Signing them into the token can never make them stale. The user's role can change, so it stays out of the token and is read on every request, as today.

The claim is authoritative. The row copy exists so that a user can list their keys and see what each can do, since the token itself is never stored.

Signing the scopes into the token also prepares for verifiers that only have a JWKS document ([login_design.md](login_design.md)). Such a verifier can read the most a key can do, but not what it can do *now*: it cannot see revocation or a change of role. It should treat the claim as a ceiling, not an answer.

### Defaults

Every scope list is written out in full when it is created. A row never holds "none" meaning "the default":
An agent with agent.scopes = NULL or a JWT with out any scopes returns zero permissions. 

To build a list up from nothing, leave the bundles out and name individual scopes.

## Effective permissions

On each request:

```
effective = E(key.scope)
          ∩ E(agent.scopes)          if an agent is acting
          ∩ E(role bundles of user)
```

`E` expands bundles. The key's scopes come from the verified token. The user and agent rows are joined into the single read that verification already makes, so this adds no query.

**A session is a user key for this purpose.** It is created with the user's default list like any other key, and goes through the same calculation. Nothing about scopes treats sessions specially.

A key may list scopes its holder does not have. That is harmless, because the intersection removes them, but they are latent: if the holder later gains them, the key gains them too. That is the price of letting a key be created with a plain default, and it is why defaults are bundles rather than snapshots.

## Checks outside scopes

Some requirements are about *what kind of credential* is in use, not what it is allowed. These are checked alongside the scope, never folded into it:

- **`kind == 'session'`**: the credential came from a passkey ceremony, so a person was present. Creating keys requires this.
- **`role == 'admin'`**: admin actions require the role *and* their `default:admin` scope. An admin who creates a key without `default:admin` gets a key that cannot do admin things, even though the admin can.
**`act == XXX`**: All actor tokens are granted under act, so callers can restrict agents from performing actions, regardless of scopes

## Creating keys

The key-creation API requires a session and always refuses when an agent is acting, whatever the scopes. A leaked key cannot use it to create more keys, and an agent cannot create keys for itself or for other agents. The user creates and rotates their agents' keys.

The scopes requested are not checked against the user's: the intersection on each request bounds them. They are checked only against the known names.

Keys only ever have `kind = 'api_key'`. Sessions come only from login.

## Creating agents

`agent:create` creates an agent and returns its first key in the same response. Internally it calls the same key-creation code as the key-creation API, without that API's session and agent checks. This is the only way an agent's key is created other than by its user. Without it, an agent created by software could not act.

Creating an agent requires `agent:create` in the request's effective permissions and counts against the per-user agent limit. What happens next depends on who is asking.

**A user** (by session or key) chooses the new agent's scopes and its key's scopes freely. Both are bounded on every request by the user, so neither can exceed what the user may do. Allowing this from user keys, not only sessions, is deliberate: programmatic creation of agents is a use case. If a user key leaks, the user revokes everything (see "Revocation").

**An agent** is bounded by itself:

- The new agent's `scopes` are a copy of the creating agent's `scopes`.
- The new agent's key scopes must be a subset of the creating key's `scope` list, compared as written. If the creating key holds `["default:agent", "example:scope"]`, the new key may hold either or both of those entries, and nothing else. It cannot hold `invitation:read` alone, even if `default:agent` contains it, because a bundle is passed on whole or not at all.

The literal comparison is what keeps this simple. If one list is contained in another, its expansion is contained in the other's expansion. That holds however the bundles change later, because both are expanded the same way at request time. So:

```
effective(new) = E(new key) ∩ E(new agent) ∩ E(user)
               ⊆ E(creating key) ∩ E(creating agent) ∩ E(user)
               = effective(creator)
```

An agent cannot create an agent more capable than the key it used, and since agents cannot create keys any other way, there is no second route to check.

The new agent is an ordinary agent of the same user, as [agents_design.md](agents_design.md) requires. Nothing records which agent created it, and nothing needs to.

## Revocation

- **`key:revoke_self`** revokes the key making the request.
- **`key:revoke_agent`** revokes keys belonging to the user's agents. Agents are not permitted to use this, because are flat under their user, so an agent holding it could revoke its siblings' keys.

Leak recovery is the user revoking all of their keys. Every key, an agent's included, is a `japikeys` row whose subject is the user, so one revocation by user ends the user's sessions, their keys, and every agent's keys, including any agents the leaked key created. Those agents remain, but with no keys they cannot act.


## 401 and 403 mean different things to a client

The two statuses are kept strictly apart so a client can act on the status alone:

- **401 means the caller's credential is not valid, so the user is signed out.** It is the answer to a request with no session, a malformed, expired, revoked or forged one, and a revoked account (`unauthenticated`), to a login that does not verify (`invalid_login`), and to a logout whose session was already gone. A client treats any 401 from a route that needs a session as "show the sign-in page".
- **403 means the credential is valid and the caller may not do this.** The session stays; the client shows "not allowed" and does not sign the user out. Today that is a member calling an admin route (`forbidden`) and registering with a code that is not redeemable (`invalid_invitation`, which has no session to lose).
- **A failure of ours is never either.** A store that cannot be read is 503 `session_verify_failed`, so an outage cannot look like a sign-out.

The credential is judged before anything else about the request that depends on who is asking: the route's requirement, the path id and the body. A signed-out caller is therefore 401 and a member on an admin route is 403 whatever the id or body holds.

Revoking an account, including your own while another admin remains, does not clear the browser's cookie. The session stops verifying on the next request, which is then a 401, and the client signs out on it.
