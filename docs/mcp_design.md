# MCP endpoint: design rationale

> This document explains *why* the admin MCP endpoint is shaped as it is. It is not a spec: the code and the package documentation of `internal/mcp` are authoritative for what exists. When this document and the code disagree about *what* exists, the code wins.

Related: [permissions_design.md](permissions_design.md), [secrets_design.md](secrets_design.md), [oauth_design.md](oauth_design.md), [invitations_design.md](invitations_design.md)

## The problem

A platform admin wants to do routine administration (make an invitation, look at how many people joined with it, revoke it) by asking their coding harness, without a management UI that has to be kept in step with every route authsu gains. An MCP server is the smallest thing that gives them that: the harness already knows how to call one.

## A tool is a request to a REST route

An MCP tool does not have a logic of its own. It names one REST route, turns the model's arguments into the request that route takes, and sends it through the same route table in process, carrying the caller's own `Authorization` header. The route then does what it does for any caller: reads the credential, requires the administrator role and its scope, parses the body into its own types, and answers in its own format.

That is the whole design, and it has three consequences:

- **The access rule is not duplicated.** A tool can never do more than the caller's key could do over REST, and a new rule or scope on a route applies to its tool at once. `/mcp` itself declares only a valid credential (`auth.Open()`), which is the one place a route's declaration is not its whole access rule; the seam tests in `internal/app` send every tool to its route as an admin, as a member naming the scope and as an admin without it, and that is what ties the tool table to the real routes.
- **Nothing a route parses is parsed twice.** A create's arguments go to the route as they came, so the route's strictness (unknown members, repeated members, bounds) and its error codes are the tool's.
- **A tool cannot reach `/mcp`.** The table a tool runs through is built without the endpoint, and a tool names a route in code, not from input.

## Why it is hand-written

A tools-only server is a few hundred lines: one POST route, JSON-RPC framing and a result shape. The two Go MCP libraries that were tried did not build under the pinned TinyGo (both stop on `hash/maphash`), and the one that could be made to build added about 1.8 MB to a 4.2 MB Worker. The wasm size budget (`scripts/check-size.sh`) is a regression guard and not a platform limit, but a library's weight is also surface to review in a service whose job is authentication. What is paid for instead is following the protocol by hand.

## What it speaks

Streamable HTTP, stateless: a request with an id gets a 200 JSON-RPC response, a notification gets 202, and GET is 405 because there is no stream to open. It serves the protocol versions that open with `initialize` (2025-03-26 to 2025-11-25), which is what current harnesses send first. The newest revision replaces that handshake; it is not served, and a client that tries it first falls back.

A tool's own failure (an id that is not an id, a route that refused) is a result with `isError`, so the model can read it and correct the call. An error of the protocol (unknown tool, malformed message) is a JSON-RPC error.

## The credential

Only an API key. The routes a tool reaches see the `Authorization` header and nothing else, so a browser session, which is a cookie, would pass `/mcp` and fail inside; a session is refused at the endpoint instead. An admin makes a key with the scopes the tools need, and an admin scope is usable only with the administrator role as well, so the key is no more than the admin could do.

A static key in a harness's config or environment is not ideal. The planned answer is OAuth: the harness signs the admin in with a passkey, the consent names the admin scopes, and the token is short-lived and revocable. It is not built. It needs the resource-server half of OAuth (protected resource metadata, a challenge on 401, a credential kind that resolves an access token with the live role), and a way for the routes to act for a grant, since an OAuth grant cannot call the management API today ([oauth_design.md](oauth_design.md)). Until then a harness that can read a key from a file or a helper keeps it out of its config.

## Secrets pass through a model

A tool result is read by a model, so whatever provider hosts it keeps the result. An invitation code in a result would be in those logs, so the create tool never returns one in the clear: the route answers an API key only with the code sealed to the public key the call carries ([secrets_design.md](secrets_design.md)), and the tool forwards `publicKey` as an argument and returns the route's answer. The model cannot make a key pair, so the key comes from the person, and opening the result is a client's job. Until a client tool exists for it, the person generates the key pair and opens the result themselves.

## Creating an organization

There is no tool for it, and no route. An invitation that names no organization already gives each person who registers with it an organization of their own, which they name and administer ([orgs_design.md](orgs_design.md)), so an admin who wants a new organization creates an invitation. An organization with no members would be a record that nobody can reach until an invitation is used, and organizations are never deleted.

## Not done

- OAuth for the endpoint, above.
- The newest protocol revision.
- Who made an invitation through MCP, beyond the key's owner that every invitation already records, and a limit on how fast a key may call.
- Tools for managing existing organizations, members, agents and keys.
