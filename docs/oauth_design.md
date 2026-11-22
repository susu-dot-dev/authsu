# OAuth: design rationale

> This document explains *why* OAuth is shaped the way it is. It is not a spec: the code is authoritative for what exists.

Related: [secrets_design.md](secrets_design.md), [agents_design.md](agents_design.md), [permissions_design.md](permissions_design.md), [login_design.md](login_design.md)

## The problem

authsu's credentials are presented only to authsu ([secrets_design.md](secrets_design.md)). Two needs fall outside that:

- **Other services need to know who a request speaks for.** `api.susu.dev` must not be handed a session or an API key, because whoever holds one *is* the user at authsu.
- **Third-party clients need a standard way to be authorized by a person.** A coding harness talking to a remote MCP server expects to open a browser, let the user sign in with their passkey and approve, and come back with a token.

OAuth 2.1 is the standard answer. authsu is the authorization server, the other services are resource servers, and the user is always the subject.

## One mechanism for two scenarios

| Scenario | How it is served |
|---|---|
| A client uses the MCP server at `api.susu.dev` | Authorization code with PKCE, client identified by a Client ID Metadata Document |
| An agent holds an OAuth credential instead of an API key | The same flow, with the grant bound to an agent |

Both share one authorize endpoint, one token endpoint and one kind of grant. A grant is a [secret](secrets_design.md) like the others and follows its lifecycle. An agent cannot start the flow itself: it takes its authority from a passkey assertion by a person who is present ([agents_design.md](agents_design.md#goals)), so a person initializes the grant, or the agent uses an API key.

## Clients are public and identified by a metadata document

Clients are public and use PKCE. There are no client secrets and no registration step: a client's `client_id` is an HTTPS URL, and authsu reads the client's name and redirect URIs from the document at that URL. A harness that supports this needs nothing from us beforehand, and authsu keeps no client list.

This makes authsu fetch a URL a stranger chose, which is the riskiest part of the design. It is treated as untrusted input: the document is parsed once into a type only its parser can construct, redirect URIs match exactly, and what the user approved is recorded on the grant, so a later change to the document cannot widen it. The consent screen shows the client's host, not only the name it claims, because the host is what authsu checked.

Each constraint closes one way a stranger's URL could be turned against authsu or its users:

- **The `client_id` is one canonical spelling.** https only, a public DNS name, a non-empty path, and no userinfo, query, fragment, dot segment, percent-encoding or IP-literal host. It is compared byte for byte wherever it is used (the document must repeat it, a grant stores it), so it must have exactly one spelling. A name in a reserved or private-network zone (`localhost`, `local`, `localdomain`, `internal`, `arpa` with `home.arpa`, `lan`, `home`, `corp`, `intranet`, `private`, `test`, `invalid`, `example`, `onion`) is refused before any fetch, as a first line only: authsu does not rely on the platform to refuse private addresses.
- **The fetch is as small as it can be.** GET with no credentials, redirects refused (a followed redirect has already sent the request somewhere the validation never saw), exactly 200, `application/json`, five seconds, and a 5 KiB body that is refused when larger, never truncated.
- **The document must vouch for itself.** Its `client_id` equals the URL, it has a name and between one and a few redirect URIs, and it is a public client (no secret, `token_endpoint_auth_method` absent or `none`).
- **Redirect URIs are https, or an `http` loopback host for a native client.** Matching is exact, except that a loopback port may differ, or be absent on either side, because the operating system picks it (RFC 8252 section 7.3). The loopback hosts are exactly `127.0.0.1`, `[::1]` and `localhost`, in every resource table and not only the development one (this is a rule about redirect URIs, and a `localhost` `client_id` stays a development-only allowance). **`localhost` is accepted although RFC 8252 section 8.3 says NOT RECOMMENDED**, because a name can be made to resolve elsewhere where an address cannot, but MCP clients in the wild register only `http://localhost`, and refusing it would refuse them. What the name adds over the addresses is a dependence on the person's resolver, which a hosts file or a hostile network could point elsewhere; what it does not add is the exposure that both forms share, any local process that listens on the port, which PKCE (the code is useless without the client's verifier) is there to bound. It is accepted only as the exact lower-case name over `http`: `https://localhost` (there is no certificate a public CA would issue for it, and it is not the plain-http loopback case), `LOCALHOST`, `localhost.`, `a.localhost`, `localhost.evil.com`, userinfo such as `localhost@evil.com`, and an explicit port 80 are refused. The three hosts are distinct: a registration of one does not admit another, so a client that registered `http://localhost/cb` is not served at `http://127.0.0.1:5000/cb`, and the reverse. **Custom-scheme redirect URIs (RFC 8252 section 7.1) are refused**, because a custom scheme is not owned by anyone: any app on the device can register it and take the code. A native client must use a loopback redirect. A document may still list redirects authsu does not accept, such as the custom scheme of its mobile build, because a real client lists one for every platform it runs on: an entry that does not parse is skipped, and the document needs at least one that does. The bounds are not skipped: the count, each entry's length and its being a string are checked on every entry first, so a document cannot hide work behind entries that are ignored. A request for a skipped entry is refused like any redirect the document does not list. **A redirect URI's query may not use a parameter name the authorization response sends** (`code`, `state`, `iss`, `error`, `error_description`; names are compared after percent-decoding, exactly and case-sensitively). RFC 6749 section 3.1.2 requires the registered query to be kept, so the response appends these after it, and a registered `?state=evil` would make the callback carry `state` twice, with clients disagreeing about which copy wins; that undermines `state` (CSRF) and `iss` (the RFC 9207 mix-up defence). Such a URI is refused when a client asks for it and skipped like any other unusable entry when a document lists it.

Unknown members of the document are ignored, which is a deliberate exception to the strict decoding authsu applies to its own JSON. The document is written by the client's operator, and a real one carries many registered members authsu has no use for (logo, policy and terms URIs, grant types, contacts). Refusing them would refuse real clients, and ignoring them costs nothing, because authsu reads only the members it checks and nothing a client says about itself limits what the request is checked against. A member authsu does act on is checked, and a repeated member at any depth is refused.

The development resource table also permits an `http://localhost` `client_id`, so a developer's own client and the end-to-end tests can serve a document without TLS. It is the only plain-http allowance.

**The fetch is triggered by unauthenticated requests**, so anyone can make authsu fetch a URL they chose. That amplification is bounded by the timeout and the size cap and not otherwise. Rate limiting is out of scope for now, and the risk is recorded in the package godoc.

## Resource servers are a fixed list

The services a token can be issued for are a hard-coded list in the code, and adding one is a reviewed code change, not a runtime registration. Each token is issued for exactly one resource, named by the `resource` parameter (RFC 8707) and compared as a whole string, and is refused at any other, so a token leaked from one service is no use at another.

There are two tables, one for production and one for development, and `API_ORIGIN` selects between them: the development table when it is an `http://localhost` origin (with or without a port, by the same rule that lets `API_ORIGIN` be plain http at all), and the production table in every other case, so a mistake can only select the stricter one. There is one build and no switch but that origin.

| | Production | Development |
|---|---|---|
| Resource | `https://api.susu.dev/mcp` | `http://localhost:8788/mcp` |
| Login resource (first party) | `https://app.susu.dev` | `http://localhost:9894` |
| Trusted client | `https://app.susu.dev/oauth/client.json` | `http://localhost:9894/oauth/client.json` |
| Scopes | `mcp:read`, `mcp:write` (login resource: `profile`) | the same |
| Default scopes | both (login resource: `profile`) | both |

The tables also hold the first-party login resource and the trusted clients (below).

The development port sits beside the API's own, as the UI's does. A request that names no `scope` gets the resource's default list, written out in full on the grant, as an API key with no scopes does ([permissions_design.md](permissions_design.md#issuing-keys)). An unknown or repeated scope is refused, and `openid` is the only scope that is not the resource's.

## First-party login

authsu is also the login for the products it is part of. Pages, a first-party app, uses it to learn who a person is, and needs an ID token and nothing at a resource server. Three decisions make that fit the flow above without a second one:

- **A trusted client is a name in code, not a flag in a document.** The trusted clients are a hard-coded list beside the resource tables, compared byte for byte with the `client_id`. Trust changes nothing about how the client is identified: its metadata document is still fetched and still has to list the redirect URI, so a client cannot widen where the code is sent by being trusted. It only admits the client to the login resource.
- **Login is a resource of its own.** The app's origin is a resource whose one scope is `profile`, and only a trusted client may name it; anyone else is told `invalid_target`, as for a resource that does not exist, so a stranger cannot tell it is there. It is a resource and not a special case so that everything bound to a resource still holds: a token for it is introspected at it and nowhere else, and a trusted client cannot reach an `mcp:` scope through it, because a scope must be one the named resource defines. The tolerance for what a standard OpenID Connect client sends is the same narrow: `email` is read as `profile` and `offline_access` is dropped (a refresh token is always issued), neither is stored, and it is decided by the resource, never by the client's say-so.
- **There is nothing to approve, so there is no screen and no agent to choose.** The person is signing in to a product they opened. The authorization endpoint sends the browser to the UI's login page, which only needs a session, and the UI's approval names no agent. The grant still needs an actor, so authsu creates an ordinary agent named after the client, once per user and client, and finds it on every later login. It is an ordinary agent on purpose: the user sees it, it counts against their limit, revoking it revokes its grants, and revoking the user does. Revoking it does not lock the person out of the app: a revoked agent is not found again, so the next login creates a fresh agent and a fresh grant (needing room under the limit, as any new agent does). The only difference is a `first_party` flag, so a UI can group or hide it. What an approval must carry is a property of the pending request and not of the body, so a login that names an agent, and an approval for a third party that names none, are both refused.

The ID token of such a grant also carries the user's name and email from their profile, and `email_verified` as `false`: authsu does not verify an address, and says so instead of leaving the relying party to assume.

## Access tokens stay opaque, so resource servers ask authsu

Access and refresh tokens are ordinary authsu secrets: opaque, and read live. The consequence is intended: a resource server cannot verify an access token on its own, and asks authsu who it speaks for.

This keeps the rule [secrets_design.md](secrets_design.md#every-fact-is-read-live) already set, applied to the new credentials. Revoking a grant, an agent or a user, or changing a role, takes effect on the next request, and no signing key is involved in authorization. The cost is a call from the resource server to authsu on each request, which is accepted.

Lifetimes are short where a value is exposed or waited for, and long where the client has to keep working:

- the **authorization code** is exchangeable for 60 seconds, because the client is waiting for it and it is single use. The exchange write enforces that from the secret's creation time. The secret's own expiry is later (ten minutes from consent, see below), so the row outlives the code;
- the **access token** lives 15 minutes, which bounds only how long a token that was never revoked stays usable, because resource servers ask authsu on every request;
- the **refresh token** lives 30 days from its last exchange, so a grant a client keeps using does not lapse and one it abandons does;
- the **pending request** lives 10 minutes, the time to sign in and approve.

A grant has one access token, and each exchange replaces it in place, so a grant is two secrets however often its client refreshes. A request still in flight with the previous token gets a 401, which is acceptable because the client that refreshed holds the new one.

The access token carries its own scope, stored on its row: the grant's at the exchange, and at a refresh whatever subset was asked for. A refresh may narrow the scope and never widen it (RFC 6749 section 6), and an omitted scope means the grant's, not the previous token's. The scope asked for is compared with the grant's inside the rotation write, together with a `resource` if the request names one (RFC 8707: it must be the grant's, at either grant type). A request that asks for too much is told `invalid_scope` or `invalid_target` and rotates nothing, so the refresh token is not spent on a request the client can correct. Introspection and the token response report the access token's scope. `openid` may be asked for at a refresh only if the grant holds it, like any scope, and it changes nothing: the ID token is issued at the exchange only. A refresh scope with nothing of the resource in it (only `openid`) is refused, as at authorization.

A grant is visible to its user, and revocable, whether or not it has an access token: that row goes when its secret expires and is swept, 15 minutes after an exchange, while the grant lives for its refresh token's 30 days, so a listing that required it would hide a live grant. A grant whose code was never exchanged is listed and revocable until its row is removed, and revoking it makes its code unexchangeable.

### Introspection asks nothing of the caller

A resource server learns what a token means through an introspection endpoint (RFC 7662), and the endpoint does not authenticate the caller. **This deviates from RFC 7662 section 2.1, which says the endpoint MUST require authentication, and the deviation is deliberate.** Resource servers are a fixed list that holds no secret, so there is no credential to check, and the answer is audience-bound instead: the caller must name the `resource` it is, and the answer is active only for a token issued for exactly that resource, and inactive for any other. What it reveals is nothing beyond what holding the token already implies (who it speaks for, its scope, its expiry), to someone who already holds it, and it cannot be used to learn anything about a token that someone does not hold. The token is a 256-bit bearer value, so possessing it is the right to ask what it is. What the endpoint does is bind the answer to the asker: the caller must name the `resource` it is, and the answer is active only for a live access token issued for exactly that resource. Every other case, an unknown token, a token of another kind (a refresh token, a session, a key), an expired or revoked one, a token for another resource, is the same `{"active":false}`. A leaked token is therefore of no use at another service, and cannot be probed there to learn whether it is valid.

## The ID token is the only JWT, and authsu only signs it

OpenID Connect requires the ID token to be a signed JWT, which a relying party verifies with a public key. That is the only place a JWT appears: it says who signed in, and grants nothing.

A failure after the exchange write, such as the ID token failing to sign, burns the code: the write has already rotated it, and a code is single use. That is accepted, because the key is loaded and validated before the write, so the only failure left is one of the signer itself, and the client starts again from the authorization endpoint.

The signing key is a Worker secret of its own, never derived from the HMAC root, which is documented as never used where a signature is authorization.

**There is no JWT library.** authsu only *signs* JWTs, and every byte it signs is server-controlled. It never reads one, so there is no algorithm to be confused, no claim to trust and no signature to verify, and the signer is a few lines of standard-library code with a fixed header.

> **If authsu ever has to read or verify a JWT** (a third-party ID token, a client assertion, an inbound token exchange), replace the whole signer with a vetted crypto library. Do not extend it to parse. Parsing and verifying are where JWT vulnerabilities live.

A test enforces that the signing package has no parse or verify function, so that change is a visible one.

The token is short-lived (five minutes) and is issued only when the code is exchanged, never at a refresh: it records who signed in and when, and the client uses it once. Its subject is the user's id, never the WebAuthn handle, and the time of sign-in is read from the approving session inside the consent write, never from the request.

The key is loaded by its own loader, called only by the token and key-set routes, because parsing an RSA key is expensive under wasm and no other request should pay for it. A missing or invalid key therefore breaks those two routes, which answer 503 `not_configured`, and nothing else.

**Rotating the key invalidates every ID token already issued.** The key set publishes one key and there is no overlap with its predecessor. That is accepted: an ID token is short-lived and read once, so the cost is a client that is mid-flow, and a rotation is rare. Publishing two keys is out of scope until that stops being true.

## Consent and sign-in

The flow reuses passkey login unchanged. The UI handles sign-in and the consent screen, and the user's approval is a first-party call carrying a session. Four decisions:

- **Approval is the authorization.** Everything carried through sign-in is just the client's parameters, so it is stateless and integrity-protected, like a login challenge, and nothing is stored until the user approves.
- **Approval needs a session.** An API key cannot approve a client. Approval is a person delegating, and [permissions_design.md](permissions_design.md#checks-outside-scopes) already keeps "a person was present" as its own check.
- **A request that fails before its redirect URI is trusted never redirects to the client.** An invalid or unfetchable `client_id`, or a `redirect_uri` the client's document does not list, sends the browser to the UI's error page instead, which closes the usual open-redirect hole in authorization servers. Once the redirect URI has been checked against the document, every later failure goes back to the client with `error`, `state` and `iss` (RFC 9207), as the standard requires.
- **Consent is single use.** The grant records a hash of the pending request it was approved from, uniquely, in the write that creates it. A double click or a replay therefore creates neither a second grant nor a second agent. It is the same guard a session has against its login challenge ([secrets_design.md](secrets_design.md#single-use-belongs-to-the-kinds)). The guard lives as long as its row, so the code-stage secret is kept for ten minutes after consent (the sealed request's whole lifetime, counted from the approval, which is no earlier than the request itself expires) and not only for the code's own minute: a row removed sooner would let the request be replayed into a second grant and agent.

Authorize refuses a scope list that names nothing of the resource, such as `openid` alone. An ID token says who signed in and grants nothing, and a grant is the delegation of access to a resource that the user approves for an agent, so a request with nothing to delegate has nothing to approve. A refresh holds to the same rule.

The pending request is sealed with a key derived for it alone and lives ten minutes. It holds only what the client sent plus the client's name as read at authorize time, so the person approves what was fetched when they were sent to the UI, and the UI can show it without authsu storing anything.

## Grants belong to agents

Every grant binds to an agent. On the consent screen the user either creates an agent for the client or attaches the grant to one of their own active agents. This settles the question in [agents_design.md](agents_design.md) about how OAuth agents and user consent fit together: a grant is one more credential an agent holds, beside its API keys.

A new agent is created with an empty list of authsu scopes, because a grant carries none (below). It counts against the per-user agent limit like any other, and the limit is checked inside the write, so consent racing the limit cannot exceed it. Attaching to an existing agent is checked in the write too: the agent must belong to the user and be active, and a missing, foreign or revoked agent is one answer, so consent cannot probe another user's agents.

Everything else follows from that. The user is the subject and the agent is the actor, as for every agent credential. At a resource, the **grant's scopes are the only limit**: the user and the agent contribute liveness and nothing else, so a token resolves only while the user is active and the agent is not revoked. This differs from authsu's own API, where the agent's scopes narrow a credential's ([permissions_design.md](permissions_design.md#effective-permissions)), and the reason is that the agent's scopes are authsu scopes, a different namespace from the resource's (below), so they have nothing to say about `mcp:read`. Revoking the agent or the user revokes its grants, and a single grant can be revoked alone, which is how a person disconnects one tool. A client revoking its own refresh token (RFC 7009) ends the grant and its access token, by the token's hash. If that token was rotated by the same client a moment earlier, the revocation finds nothing, answers 200 as the standard requires, and the grant the new token belongs to stays live: no history of old hashes is kept (see [secrets_design.md](secrets_design.md#rotation-is-once-only-and-keeps-no-history)), so there is nothing to recognise it by. The user can still revoke that grant. Listing and revoking use ordinary scopes (`grant:read`, `grant:revoke`) and the agents feature's naming, so there is no second inventory of connected apps.

## OAuth scopes are not authsu scopes

OAuth scopes name what a client may do at a resource server, and belong to that server's entry in the list. They are a separate namespace from the scopes that protect authsu's own API. A grant carries none of the latter, so **an OAuth grant cannot call authsu's management API.** Creating agents, issuing keys and administering users stay with sessions and API keys. The tokens are not even recognised there: an access or refresh token presented as a Bearer to the API is a 401, because the API accepts exactly one kind of token and these are not it. Accepting access tokens at authsu's own API is out of scope.

## The boundary changes

Four assumptions in the current HTTP boundary do not hold for OAuth, and are changed deliberately, not worked around:

- **Standard OAuth endpoints are form-encoded, not JSON.** JSON-only is today's CSRF defence ([login_design.md](login_design.md#the-ui-on-another-origin)). These routes are exempt because a browser's ambient credentials do not authenticate them: they are authenticated by what the request carries, so a forged cross-site request has nothing to present. A route declares the exemption explicitly, and one that does not is JSON-only. Because the form type is no defence, the boundary accepts it only on a route that takes no credential.
- **Parameters are read the way the standard says, not the way authsu reads its own JSON.** A parameter sent twice is refused, because RFC 6749 section 3.1 makes it ambiguous. A parameter authsu does not recognise is ignored, because the same section requires an authorization server to, and a client that adds one must still work. That is a second deliberate exception to strict decoding, alongside the client's metadata document, and it is bounded: every parameter authsu does read is parsed into an input type that refuses and never rewrites, and a request whose percent-encoding is broken is refused whole.
- **OAuth errors have their own body.** The token, revocation and introspection endpoints answer failures as `{"error":"...","error_description":"..."}` with the standard codes (RFC 6749 section 5.2), because that is what clients parse. A route declares the format, and the rest of the API keeps its own. Neither format carries a cause or an internal detail.
- **CORS gains a second policy.** Discovery, the key set, and the token and revocation endpoints are called by browsers on other origins, so they allow any origin without credentials, which a browser then withholds from such a request. The existing policy, one origin with credentials, stays for the first-party API. A path is in exactly one, and the public ones are an exact list, never a prefix, so a route added later is not published by accident. Authorize and introspect get no CORS at all, not even the first party's: authorize is a browser navigation and introspect is called by servers, so neither answers a preflight as allowed and neither carries an `Access-Control-` header, so a script on any page, the UI's included, cannot read them. A path is in exactly one of the three policies (public, none, and the first party's), and the sets are exact lists the code passes in.

## Decisions

- **authsu is the authorization server** for `api.susu.dev`. Resource servers are two fixed tables in code, production and development, selected by `API_ORIGIN`.
- **Public clients only**, with PKCE (S256), identified by a metadata document. No client secrets, no registration.
- **Access and refresh tokens are opaque secrets**, read live. Resource servers ask authsu; they do not verify.
- **Introspection is unauthenticated and audience-bound.** The caller names the resource, and the answer is active only for a live access token issued for exactly it. This deliberately deviates from RFC 7662 section 2.1.
- **One access token per grant**, replaced in place at each exchange, with its own scope: the grant's, or a subset a refresh asked for, checked in the write. Refresh tokens rotate once only, with no reuse detection.
- **The ID token is the only JWT**, signed with a dedicated Worker secret, and never read.
- **No JWT library.** If authsu ever reads a JWT, all of it moves to a vetted library.
- **A grant belongs to an agent.** The user is the subject and the agent the actor, and at a resource the grant's scopes are the only limit.
- **An OAuth grant carries no authsu scopes.**
- **Approval needs a session**, is the authorization, and is single use.
- **A failure before the redirect URI is trusted never redirects to the client.**
- **A headless agent gets no OAuth credential.** A person initializes a grant, or the agent uses an API key.

## Not done

- **Rate limiting**, including of the unauthenticated metadata fetch.
- **Signing-key overlap** during rotation.
- **Reuse detection** of a rotated refresh token, and so the revocation of a token that was just rotated.
- **Dynamic client registration, client secrets, token exchange, device flow, client credentials and userinfo.**
