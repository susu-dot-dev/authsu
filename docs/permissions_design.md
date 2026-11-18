# Permissions: design direction

> This document sets out the direction for permissions and *why*. It is not a spec: the code is authoritative for what exists, in `internal/scope` (the names, the bundles, the set operations), `internal/input` (`ScopeList`), `internal/auth` (the credential, the effective scopes, `Access`) and the features' route declarations. What is not built yet is marked "Not yet" below: the key-creation API (`key:create`, `key:read`, `key:revoke`) and revoking all of a user's keys.

Related: [agents_design.md](agents_design.md), [users_design.md](users_design.md), [login_design.md](login_design.md)

## The problem

[agents_design.md](agents_design.md) says an agent's permissions are a ceiling its user sets, and that "credentials carry scopes". This document says what a scope is, where scopes are stored, how a request's permissions are worked out, and how agents and keys are created without becoming a way to gain authority.

Three things limit a request:

- **The user**, whose authority it always is. Their standing (role, revocation) can change at any time.
- **The agent**, if one is acting. Its limit is set when it is created.
- **The key**, the credential presented. Its limit is set when it is created.

The design keeps one rule throughout: **each layer can only narrow the ones above it.** A key never adds to its agent, and an agent never adds to its user.

## The role is the gate; scopes only narrow

**The user's role is the primary security gate, and a scope never grants what the role does not.** Scopes exist to restrict a credential further, never to extend it. An admin scope (one the code marks `Admin`) is therefore usable only with the administrator role *and* the scope: the route boundary checks the role whenever a route needs an admin scope, so a route cannot be declared with an admin scope and forget the role check. A member whose agent or key names `default:session`, or `invitation:create` outright, gets nothing from it. This is also why nothing needs to stop a user writing any scope onto their own agent: a scope the user could not use anyway is harmless, and the checks are the same on every request.

Because the role gates, it is not part of the effective-scope intersection (below). It is read live on every request, as it always was.

## Scopes and bundles

A **scope** names one thing a credential may do, as `resource:action`, for example `agent:create` or `invitation:create`.

- **Form.** Both halves are lower-case ASCII words (underscores between words), at most 63 bytes in all. The resource is a singular noun and matches the API path (`/api/agent` is `agent`), so a route's scope follows from its path.
- **Actions** come from a fixed set: `read` (list and get alike; the distinction is not useful), `create`, `update` and `revoke` (nothing is deleted, so there is no `delete`). A new action needs a reason.
- **Self versus others** is a different resource, not a qualifier. A caller can always revoke the key it presents (logout is that), with no scope; `key:revoke` is for the user's *other* keys, including their agents'. Whoami and revoking your own key need no scope: neither widens what anyone can do, and a key with no scopes can still sign itself out.
- **`default` is reserved** as a resource, so a bundle can never look like a scope. Every name, scope or bundle, has the one `a:b` shape; there is no bare `all`.

A **bundle** is a named set of scopes defined in code. Bundles do not contain other bundles. Each one lists its scopes explicitly, so reading a bundle's definition tells you everything it grants.

| Bundle | Holds | Used for |
|---|---|---|
| `default:session` | every scope | what a login session is created with |
| `default:user` | every scope that is not an admin scope | a user's own API keys |
| `default:agent` | `agent:read` | an agent and its keys |

A test requires `default:session` to hold every scope and `default:user` every non-admin one, so a new scope cannot be left out of them silently.

A scope list (on an agent, on a key) can name individual scopes, bundles, or both: `["default:agent", "agent:create"]`.

Bundles are **expanded when a request is checked**, not when a list is written. Adding a scope to `default:agent` reaches every agent and key that names the bundle. Listing scopes one by one is how to opt out of that: an explicit list never changes.

The default bundles are where "elevated, never a default" lives. `default:user` includes `agent:create`, because users are expected to create agents for most things rather than give their own keys to software. `default:agent` does not, so an agent can create agents only if `agent:create` is named for it.

Scope names that the code does not know are rejected wherever a list is written (creating a key, creating an agent): a typo should fail loudly, not produce a credential that silently can do nothing. Reading is the opposite: a name the code no longer knows grants nothing and a stored value that is not a list is the empty list, so removing a scope only ever removes access.

Lists are parsed once, into `input.ScopeList`: at most 32 distinct names, each known, kept exactly as written (no trimming, case-folding or sorting), and an empty list is accepted. A list written by a client is refused whole, with a message that never echoes it.

## Where scopes live

| Layer | Stored in | Can it change during a token's life? |
|---|---|---|
| User | `users.role`, unchanged. It gates admin scopes; it is not mapped to bundles. | Yes, so it is read live |
| Agent | `agents.scopes`, written when the agent is created | No, for now |
| Key | The `scope` claim in the key's JWT, with a copy on its `japikeys` row | No |

Both lists are stored and signed as a **JSON array of strings** (`["default:agent","agent:create"]`). The columns are `TEXT` and never inspect their contents, so the schema did not change. The claim is the same array, so the row's copy is the claim by construction (`auth.Key.Scope` is what callers store).

The rule behind the table: **a token may carry only what cannot change while it is valid.** This is the same reasoning that keeps the role out of the session token ([users_design.md](users_design.md)), applied the other way round. A japikey signs exactly one token and then discards its private key, so a key's scopes cannot be edited even in principle. Signing them into the token can never make them stale. The user's role can change, so it stays out of the token and is read on every request, as today.

The claim is authoritative. The row copy exists so that a user can list their keys and see what each can do, since the token itself is never stored.

Signing the scopes into the token also prepares for verifiers that only have a JWKS document ([login_design.md](login_design.md)). Such a verifier can read the most a key can do, but not what it can do *now*: it cannot see revocation or a change of role. It should treat the claim as a ceiling, not an answer.

### Defaults

Every scope list is written out in full when it is created. A row never holds "none" meaning "the default": a token with no scope claim, a claim of the wrong shape, or an agent whose stored list is not a list has the empty list, which grants nothing. The empty list is a valid, deliberate value (`[]`): a credential that can use only the routes that need no scope.

When a create names no list, the default is written out: a session is `["default:session"]`; an agent and its first key, from a user, are `["default:agent"]`. To build a list up from nothing, leave the bundles out and name individual scopes.

## Effective permissions

On each request:

```
effective = E(key.scope)
          ∩ E(agent.scopes)          if an agent is acting
```

`E` expands bundles. The key's scopes come from the verified token. The agent row is joined into the single read that verification already makes (and a key whose agent is revoked is not active, whatever its own row says), so this adds no query. The role is not a term here: it gates admin scopes separately, before the scope is looked at (see "The role is the gate").

**A session is a user key for this purpose.** It is created with `default:session` and goes through the same calculation. Nothing about scopes treats sessions specially; a stronger "sudo" step-up, if it comes, would be its own mechanism and not a smaller session.

A key may list scopes its holder does not have, an admin scope on a member's key for one. That is harmless, because the role gate refuses them, but they are latent: if the holder is later promoted, the key gains them too. That is the price of letting a key be created with a plain default, and it is why defaults are bundles rather than snapshots.

The credential is read from one of two places and never both: a session from the `__Host-session` cookie, an API key from `Authorization: Bearer`. A request carrying both is ambiguous and is refused (401) without either being verified, as two cookies are. Each carrier fixes the kind it accepts (the audience and the row's kind), so a session cannot be passed off as an API key or the reverse.

## Checks outside scopes

Some requirements are about *what kind of credential* is in use, not what it is allowed. These are checked alongside the scope, never folded into it:

- **`kind == 'session'`**: the credential came from a passkey ceremony, so a person was present. Creating keys requires this.
- **`role == 'admin'`**: admin actions require the role *and* an admin scope, checked together by the boundary for any route that needs one. An admin who creates a key without an admin scope gets a key that cannot do admin things, even though the admin can.
- **An agent is acting** (the token's `act` claim, which must equal the key row's agent): all actor tokens are identifiable, so a route can refuse agents whatever scopes they hold. Renaming and revoking an agent do, because agents are flat under their user.

A route declares all of this as data (`auth.Access`: the scope, `SessionOnly`, `NoAgents`, or `auth.Open()` for a valid credential and nothing more), so reviewing permissions is reading a table, and leaving it out panics when the routes are built. The checks run in a fixed order, all 403 and all after the credential is known to be valid: the role for an admin scope, then the scope, then session-only, then agents.

## Creating keys

*Not yet built.* The key-creation API requires a session and always refuses when an agent is acting, whatever the scopes. A leaked key cannot use it to create more keys, and an agent cannot create keys for itself or for other agents. The user creates and rotates their agents' keys.

The scopes requested are not checked against the user's: the intersection on each request bounds them. They are checked only against the known names.

Keys only ever have `kind = 'api_key'`. Sessions come only from login.

## Creating agents

`agent:create` creates an agent and returns its first key in the same response. Internally it calls the same key-creation code as the key-creation API, without that API's session and agent checks. This is the only way an agent's key is created other than by its user. Without it, an agent created by software could not act.

Creating an agent requires `agent:create` in the request's effective permissions and counts against the per-user agent limit. What happens next depends on who is asking.

**A user** (by session or key) chooses the new agent's scopes and its key's scopes freely. Both are bounded on every request by the role gate and by the lists themselves, so neither can exceed what the user may do. Allowing this from user keys, not only sessions, is deliberate: programmatic creation of agents is a use case. If a user key leaks, the user revokes everything (see "Revocation").

**An agent** is bounded by itself:

- The new agent's `scopes` are a copy of the creating agent's `scopes`.
- The new agent's key scopes must be a subset of the creating key's `scope` list, compared as written. If the creating key holds `["default:agent", "example:scope"]`, the new key may hold either or both of those entries, and nothing else. It cannot hold `invitation:read` alone, even if `default:agent` contains it, because a bundle is passed on whole or not at all.

The literal comparison is what keeps this simple. If one list is contained in another, its expansion is contained in the other's expansion. That holds however the bundles change later, because both are expanded the same way at request time. So:

```
effective(new) = E(new key) ∩ E(new agent)
               ⊆ E(creating key) ∩ E(creating agent)
               = effective(creator)
```

An agent cannot create an agent more capable than the key it used, and since agents cannot create keys any other way, there is no second route to check. The role gate is the same user's for both, so it needs no term.

The new agent's scopes are copied from the creating agent's row *inside the insert*, not taken from the request or from the token, and the insert requires that agent to belong to the owner and to still be active. An agent revoked between being verified and creating an agent therefore creates nothing (409 `agent_limit_reached`, the one answer for every reason the insert matches no row).

The new agent is an ordinary agent of the same user, as [agents_design.md](agents_design.md) requires. Nothing records which agent created it, and nothing needs to.

## Revocation

- **Revoking the key making the request** needs no scope (logout is this, for a session or an API key alike). It revokes the presented key whatever its kind, and the write itself requires the key to be the user's, so the revocation never rests on the read that came before it.
- **`key:revoke`** revokes the user's *other* keys, including their agents'. Agents are not permitted to use this, because they are flat under their user, so an agent holding it could revoke its siblings' keys. *Not yet built*, with the key API.

Revoking all of a user's keys is the simple recovery from a leak: every key, an agent's included, is a `japikeys` row whose subject is the user, so one revocation by user ends the user's sessions, their keys, and every agent's keys. Those agents remain, but with no keys they cannot act. This is deliberately not a larger mechanism: a serious leak would more likely be answered by something wider (rotating a pepper on the keys, say) than by anything here. The one thing the design does insist on is that authorization sits in the write itself, so an agent that is revoked between being verified and creating an agent creates nothing.


## 401 and 403 mean different things to a client

The two statuses are kept strictly apart so a client can act on the status alone:

- **401 means the caller's credential is not valid, so the user is signed out.** It is the answer to a request with no session, a malformed, expired, revoked or forged one, and a revoked account (`unauthenticated`), to a login that does not verify (`invalid_login`), and to a logout whose session was already gone. A client treats any 401 from a route that needs a session as "show the sign-in page".
- **403 means the credential is valid and the caller may not do this.** The session stays; the client shows "not allowed" and does not sign the user out. Today that is a member calling an admin route (`forbidden`) and registering with a code that is not redeemable (`invalid_invitation`, which has no session to lose).
- **A failure of ours is never either.** A store that cannot be read is 503 `session_verify_failed`, so an outage cannot look like a sign-out.

The credential is judged before anything else about the request that depends on who is asking: the route's requirement, the path id and the body. A signed-out caller is therefore 401 and a member on an admin route is 403 whatever the id or body holds.

Revoking an account, including your own while another admin remains, does not clear the browser's cookie. The session stops verifying on the next request, which is then a 401, and the client signs out on it.
