# Permissions: design direction

> This document sets out the direction for permissions and *why*. It is not a spec: the code is authoritative for what exists, in the scope names and bundles, the parsed scope list, the credential and its effective scopes, and each feature's route declarations. What is not built yet is marked "Not yet" below.

Related: [agents_design.md](agents_design.md), [users_design.md](users_design.md), [secrets_design.md](secrets_design.md), [login_design.md](login_design.md)

## The problem

[agents_design.md](agents_design.md) says an agent's permissions are a ceiling its user sets, and that credentials carry scopes. This document says what a scope is, where scopes are held, how a request's permissions are worked out, and how agents and keys are created without becoming a way to gain authority.

Three things limit a request:

- **The user**, whose authority it always is. Their standing (role, revocation) can change at any time.
- **The agent**, if one is acting. Its limit is set when it is created.
- **The credential** presented. Its limit is set when it is issued.

The design keeps one rule throughout: **each layer can only narrow the ones above it.** A credential never adds to its agent, and an agent never adds to its user.

## The role is the gate; scopes only narrow

**The user's role is the primary security gate, and a scope never grants what the role does not.** Scopes exist to restrict a credential further, never to extend it. An admin scope is usable only with the administrator role *and* the scope: the route boundary checks the role whenever a route needs an admin scope, so a route cannot be declared with an admin scope and forget the role. A member whose credential names every admin scope gets nothing from them. This is also why nothing needs to stop a user writing any scope onto their own agent: a scope the user could not use anyway is harmless.

Administering an organization is likewise a gate, held as a relation to that organization and not as a scope ([orgs_design.md](orgs_design.md)). Because the role gates, it is not part of the scope intersection below. It is read live on every request ([users_design.md](users_design.md)).

## Scopes and bundles

A **scope** names one thing a credential may do, as `resource:action`, for example `agent:create`.

- **The resource** is a singular noun matching the API path, so a route's scope follows from its path.
- **Actions** come from a fixed set: `read`, `create`, `update` and `revoke`. Nothing is deleted, so there is no `delete`, and listing and reading are one action.
- **Self versus others** is a different resource, not a qualifier. Reading who you are and revoking the credential you present need no scope: neither widens what anyone can do, and a credential with no scopes can still sign itself out. Revoking your *other* credentials is a scope.
- **`default` is reserved** as a resource, so a bundle can never look like a scope.

A **bundle** is a named set of scopes defined in code. Bundles do not contain other bundles, so reading a bundle's definition tells you everything it grants.

| Bundle | Holds | Used for |
|---|---|---|
| `default:session` | every scope | every session |
| `default:user` | every scope that is not an admin scope, except `member:revoke` | a user's own API keys |
| `default:agent` | `agent:read` | an agent and its keys |

Tests require `default:session` to hold every scope and `default:user` every non-admin one but `member:revoke`, so a new scope cannot be left out of them silently.

A scope list can name individual scopes, bundles, or both. Bundles are **expanded when a request is checked**, not when a list is written, so adding a scope to a bundle reaches every agent and credential that names it. Listing scopes individually is how to opt out: an explicit list never changes.

The default bundles are where "elevated, never a default" lives. `default:user` includes `agent:create`, because users are expected to create agents rather than hand their own keys to software. `default:agent` does not, so an agent can create agents only if that is named for it. `default:user` leaves out `member:revoke`, which revokes other people's accounts: a session has it, and a user who wants a key with that power names it.

Unknown names are refused wherever a list is written, because a typo should fail loudly rather than produce a credential that silently can do nothing. Reading is the opposite: a name the code no longer knows grants nothing, so removing a scope only ever removes access. Lists are parsed once, refused whole when invalid, bounded in length, and kept exactly as written.

## Where scopes live

| Layer | Held as | Can it change while the credential is valid? |
|---|---|---|
| User | Their role. It gates admin scopes; it is not mapped to bundles. | Yes, so it is read live |
| Agent | Its scope list, written when it is created | Only when authsu issues a grant to an agent it created for that grant (the first-party login's, or a new one made at consent): the union of what it holds and the grant's authsu scopes, pruned to the login resource's allowlist. Never for an agent the user attached |
| API key | Its scope list, written when it is issued | No |
| OAuth grant (the login resource's) | The authsu names in its access token's scope, within the login resource's allowlist now | The token's scope never widens; the allowlist is read live |
| Session | Always `default:session` | No |

**The agent's list is its primary permission set, and every credential it holds only narrows it.** A key and a grant are alike in this: each stores a claim of what it may do, and the agent's list, read now, is the ceiling.

**A credential's scopes are fixed when it is issued**, and nothing changes them afterwards. Whatever can change, the role, the account's standing, the agent's standing, is read on every request, in the same read that resolves the credential ([secrets_design.md](secrets_design.md)). A credential carries nothing: the scopes are stored with it and read with it.

**An agent's list changes in one way: authsu writes it when it issues a grant to an agent it created for that grant**, in the same batch as the grant ([oauth_design.md](oauth_design.md#grants-belong-to-agents)). Only the first-party login's agent and a new agent made at a consent are ever written, and an agent the user chose to attach is never changed. The new list is the union of what the agent holds and the grant's authsu scopes, kept to the login resource's allowlist and written in its order. A union never silently narrows an agent whose keys depend on its list, and pruning means a scope removed from the allowlist is gone from the agent at its next sign-in. The agent's list is therefore still the primary permission set: a grant only ever asks for names the user's own sign-in already approved, and what a token may do is still its list narrowed by the agent's.

Every list is written out in full when it is written. Nothing ever means "the default" by being absent, and an empty list is a valid, deliberate value: a credential that can use only the routes that need no scope.

## Effective permissions

On each request:

```
effective = E(credential scopes)
          ∩ E(agent scopes)          if an agent is acting
```

`E` expands bundles. The agent is read in the same statement that resolves the credential, and a credential whose agent is revoked does not resolve, so this adds no query. The role is not a term here: it gates admin scopes separately, before the scope is looked at.

**A session is a user credential for this purpose.** It goes through the same calculation with `default:session`. A stronger step-up, if it comes, would be its own mechanism and not a smaller session.

A credential may list scopes its holder does not have, an admin scope on a member's key for instance. That is harmless, because the role gate refuses them, but they are latent: if the holder is later promoted, the credential gains them. That is the price of creating credentials with plain defaults, and it is why defaults are bundles rather than snapshots.

A request presents exactly one credential, read from one place: a session from its cookie, an API key or an OAuth grant's access token from `Authorization: Bearer`. A request carrying both is ambiguous and is refused without either being resolved. The cookie accepts only a session, and the header only the two bearer kinds, told apart by the token's own tag (`susu_key_`, `susu_at_`), so a session cannot be passed off as a key, a refresh token is not a credential at all, and a key is never resolved as a grant or the reverse.

An OAuth grant is an API key in everything the calculation above says, with one difference in kind: it is a credential held by an outside service, and the routes were written for sessions and keys. So a route accepts it only by saying so (`FromGrants()` in its Access), as a sandboxed agent is refused unless a route says `InSandbox()`; the check is first, has its own code, and holds on open routes and on routes that refuse agents. Only a grant for the deployment's first-party login resource counts, and what it holds is limited to that resource's concrete, non-admin authsu scope names ([oauth_design.md](oauth_design.md#oauth-scopes-and-authsu-scopes)).

## Checks outside scopes

Some requirements are about *what kind of credential* is in use, not what it is allowed. They are checked alongside the scope, never folded into it:

- **A session**: the credential came from a passkey ceremony, so a person was present. Issuing keys requires this.
- **The administrator role**, for any route that needs an admin scope, checked together with the scope.
- **An agent is acting**: every credential an agent holds names the agent, so a route can refuse agents whatever scopes they hold. Renaming and revoking an agent do, because agents are flat under their user. So do the actions that change who administers an organization or who is revoked.

A route that refuses agents refuses an OAuth grant too, since a grant has an agent, unless it also says `GrantsAsUser()`, which relaxes only that for a grant (an agent's API key is still refused) and only on a route that opts in with `FromGrants()` ([oauth_design.md](oauth_design.md#which-routes-take-a-grant-and-why)). A new route that refuses agents is therefore still closed to grants.

A route declares all of this as data, so reviewing permissions is reading a table, and leaving it out fails when the routes are built. The checks run in a fixed order, all after the credential is known to be valid: an OAuth grant on a route that does not accept one, a sandboxed agent on a route that is not for sandboxes, the role for an admin scope, then the scope, then session-only, then agents.

## Issuing keys

Issuing a user's own key requires a session and always refuses when an agent is acting, whatever the scopes. A leaked key cannot be used to issue more keys, and an agent cannot issue keys for itself or for other agents. *Not yet built:* the user issuing and rotating their agents' keys; today an agent's first key is issued only with the agent ([agents_design.md](agents_design.md)).

The scopes requested are checked only against the known names, not against the user's own: the intersection on every request bounds them. A request that names no scopes gets the default user bundle, written out in full.

A key lives 90 days unless its lifetime is chosen. A user's own key may be given up to a year. An agent's keys never live longer than 90 days: an agent's credential is the one most likely to sit in software, so it is the one most worth renewing.

A user's own keys are listed, read, renamed and revoked by the same routes, and only their own: another user's key, and any agent's key, are answered as a key that does not exist. A key's name is the only thing about it that changes; its scopes and expiry are fixed when it is issued. The token is shown once, in the response that issued it.

## Creating agents

`agent:create` creates an agent and returns its first key in the same response, through the same key-issuing code without that path's session and agent checks. This is the only way an agent's key is issued other than by its user; without it, an agent created by software could not act.

Creating an agent requires `agent:create` in the request's effective permissions and counts against the per-user agent limit. What happens next depends on who is asking.

**A user** (by session or key) chooses the new agent's scopes and its key's scopes freely. Both are bounded on every request by the role gate and by the lists themselves, so neither can exceed what the user may do. Allowing this from user keys, not only sessions, is deliberate: creating agents programmatically is a use case. If a user key leaks, the user revokes everything (see "Revocation").

**An agent** is bounded by itself:

- The new agent's scopes are a copy of the creating agent's.
- The new agent's key scopes must be a subset of the creating credential's list, compared as written. A bundle is passed on whole or not at all: a credential holding a bundle cannot hand on one scope from inside it.

The literal comparison is what keeps this simple. If one list is contained in another, its expansion is contained in the other's expansion, however the bundles change later, because both are expanded the same way at request time:

```
effective(new) = E(new key) ∩ E(new agent)
               ⊆ E(creating credential) ∩ E(creating agent)
               = effective(creator)
```

An agent cannot create an agent more capable than the credential it used, and since agents cannot obtain keys any other way, there is no second path to check, apart from one that is not an agent's key: an OAuth grant, which creates agents in a sandbox.

**An OAuth grant** (the first-party app's sign-in) does not copy the creating agent, because the agent it makes is in a sandbox and not beside the creator, so it chooses the lists and the bound is applied to them. Each of the new agent's list and its key's list must be entries, as written, of both the access token's list and the acting agent's list, which is the same containment as above taken against each layer:

```
effective(new) ⊆ E(token) ∩ E(acting agent) = effective(the grant)
```

An absent list defaults to those common entries in the token's order. A request that asks for an entry in only one of the lists is refused whole.

The new agent's scopes are copied from the creating agent *inside the write*, not taken from the request, and the write requires that agent to belong to the owner and still be active. An agent revoked between being resolved and creating an agent therefore creates nothing. The new agent is an ordinary agent of the same user, and nothing records which agent created it.

## Revocation

- **Revoking the credential making the request** needs no scope. Logout is this, for a session or a key alike, and the write itself requires the credential to be the user's.
- **Revoking one of the user's own other keys** needs `key:revoke`, which agents may never use. The write refuses the presented credential, so the route cannot become a second logout.
- **Revoking the user's other credentials**, their agents' included, is a scope that agents may never use: agents are flat under their user, so an agent holding it could revoke its siblings'. *Not yet built.*

Revoking all of a user's credentials is the simple recovery from a leak. Every credential, an agent's included, belongs to the user, so one revocation ends the user's sessions, their keys and every agent's credentials. Those agents remain, but with no credentials they cannot act. The design insists on one thing here: authorization sits in the write itself, so nothing revoked between being resolved and acting can act.

## 401 and 403 mean different things to a client

The two statuses are kept strictly apart so a client can act on the status alone:

- **401 means the credential is not valid, so the user is signed out.** No credential, a malformed, unknown, expired or revoked one, a revoked account, and a login that does not verify. A client treats a 401 as "show the sign-in page".
- **403 means the credential is valid and the caller may not do this.** The session stays, and the client shows "not allowed" without signing anyone out.
- **A failure of ours is neither.** A store that cannot be read is a 503, so an outage cannot look like a sign-out.

The credential is judged before anything else about the request that depends on who is asking: the route's requirement, the path id and the body. A signed-out caller is therefore 401, and a member on an admin route 403, whatever the id or body holds.

Revoking an account does not clear the browser's cookie. The session stops resolving on the next request, which is then a 401, and the client signs out on it.
