package auth

import (
	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// Codes of the access refusals. They are stable: clients may match on them.
const (
	// CodeForbidden is the caller's credential being valid but not enough: the
	// role is not administrator, the credential is not a session, or an agent is
	// acting where agents are never allowed. The description says which.
	CodeForbidden = "forbidden"
	// CodeInsufficientScope is a credential that lacks the scope the route
	// needs.
	CodeInsufficientScope = "insufficient_scope"
	// CodeSandboxConfined is an agent of a sandbox calling a route that does not
	// declare that it confines its queries to the sandbox (Access.InSandbox).
	CodeSandboxConfined = "sandbox_confined"
	// CodeGrantNotAccepted is an OAuth grant's access token presented to a
	// route that does not declare that it accepts one (Access.FromGrants).
	CodeGrantNotAccepted = "grant_not_accepted"
)

// Access is what a route requires of an authenticated caller. It is data, so
// reviewing permissions is reading a table, and it is checked by the boundary
// after the credential and before the handler.
//
// A route that needs nothing beyond a valid credential says so with Open; the
// zero Access is not Open, so leaving it out is a programming error that
// panics when the routes are built, never a route anyone may call.
//
// # Sandboxes are default-deny
//
// An agent of a sandbox is confined to it: it may reach a resource only if the
// resource belongs to the sandbox (docs/orgs_design.md, principle 4). Nothing
// can prove a route's queries do that, so the boundary refuses by default: a
// principal whose SandboxID is not "" is refused on EVERY authenticated route,
// Open ones included, unless the route's Access opts in with InSandbox. A route
// that opts in takes responsibility for confining every query it makes to
// Principal.SandboxID, and a new route is therefore unreachable from a sandbox
// until someone decides otherwise. The answer does not depend on what the
// agent's scopes or its user's role are.
//
// # Grants are default-deny
//
// An OAuth grant's access token is a credential at authsu's own API, held by an
// agent and limited like an API key's (docs/permissions_design.md), but it is
// handed to an outside service, and the routes were written for sessions and keys.
// So the boundary refuses it by default: a principal of KindGrant is refused on
// EVERY authenticated route, Open ones, routes that refuse agents and
// session-only ones included, unless the route's Access opts in with
// FromGrants. The refusal is its own check and its own code, not a side effect
// of another one (NoAgents would refuse a grant today, because a grant has an
// agent, but a route that allows agents must not thereby allow grants). A new
// route is therefore unreachable with a grant until someone decides otherwise.
//
// The checks, in this order, all 403 and all after the credential is known to
// be valid (a bad credential is always 401, whatever the route requires):
//
//  1. Grant: a principal of KindGrant needs the route to be FromGrants
//     (CodeGrantNotAccepted).
//  2. Sandbox: a principal with a SandboxID needs the route to be InSandbox
//     (CodeSandboxConfined).
//  3. Admin scope: when Scope is an admin scope (scope.IsAdmin) the caller's
//     role must be administrator. The role is the primary gate, read from the
//     database on every request; a scope never grants it.
//  4. Scope: the credential's list, narrowed by the agent's when one is
//     acting, must include Scope. Steps 3 and 4 are one call, Authority.Permits,
//     the only place the role and the lists are combined.
//  5. SessionOnly: the credential must be a passkey session, so a person was
//     present.
//  6. NoAgents: no agent may be acting, whatever its scopes. An OAuth grant
//     has an agent, so NoAgents refuses it, unless the route also says
//     GrantsAsUser (below).
//
// # A grant on a route that refuses agents
//
// NoAgents exists so that software a person pointed at the API cannot do what
// only the person may (an agent is not the one to reorganise its user's
// organizations). A first-party grant is the person's own sign-in to a product
// they opened, and its agent is the stand-in authsu made for it, so a few
// routes that refuse agents are meant to be reachable by exactly that
// credential. A route says so with GrantsAsUser, which is separate from
// FromGrants and from NoAgents: NoAgents alone still refuses every agent, an
// API key's included, and FromGrants alone still refuses a grant on a route
// that refuses agents. Only a route that declares both lets a KindGrant
// principal through the NoAgents check, and it lets nothing else through: an
// agent's API key is still refused, whatever its scopes.
type Access struct {
	// Scope is the scope the route needs. The empty Scope is none: the route
	// needs no scope, only a valid credential.
	Scope scope.Scope

	// SessionOnly requires the credential to be a session (KindSession).
	SessionOnly bool

	// NoAgents refuses a request an agent is acting in. It is for routes where
	// agents are peers under their user and so must not act on each other
	// (renaming or revoking a sibling), or where an agent could gain authority.
	NoAgents bool

	// SandboxOK lets an agent of a sandbox use the route (see InSandbox). The
	// zero value refuses it.
	SandboxOK bool

	// GrantOK lets an OAuth grant's access token use the route (see
	// FromGrants). The zero value refuses it.
	GrantOK bool

	// GrantAsUserOK lets an OAuth grant's access token use a route that refuses
	// agents (see GrantsAsUser). It changes nothing for any other credential.
	GrantAsUserOK bool

	// declared is set by Open and Needs, and only by them, so the zero Access
	// is not mistaken for a declaration.
	declared bool
}

// Open declares a route that needs a valid credential and nothing more: no
// scope, any kind of credential, agents included. It is what whoami and logout are,
// where the caller only ever acts on their own credential.
func Open() Access { return Access{declared: true} }

// Needs declares a route that needs the scope s.
func Needs(s scope.Scope) Access { return Access{Scope: s, declared: true} }

// Sessions returns a copy of a that is only for passkey sessions.
func (a Access) Sessions() Access {
	a.SessionOnly = true

	return a
}

// WithoutAgents returns a copy of a that refuses agents.
func (a Access) WithoutAgents() Access {
	a.NoAgents = true

	return a
}

// InSandbox returns a copy of a that an agent of a sandbox may use. It is the
// route's promise that every query it makes is confined to
// Principal.SandboxID, so that the agent can reach nothing outside the
// sandbox. Without it a sandboxed principal is refused, on an Open route too.
func (a Access) InSandbox() Access {
	a.SandboxOK = true

	return a
}

// FromGrants returns a copy of a that an OAuth grant's access token may use. It
// is the route's promise that it is right for a credential an outside service
// holds: that what the route does is within what Needs says and the scopes of
// the login resource (resource.LoginAuthsuScopes) can ask of it, and that it
// does not rely on the caller being a person, a session or the user themselves.
// Without it a grant is refused, on an Open route too, and on a route that
// allows agents.
func (a Access) FromGrants() Access {
	a.GrantOK = true

	return a
}

// GrantsAsUser returns a copy of a for which the NoAgents rule does not apply
// to an OAuth grant's access token, which always has an agent. It is the
// route's promise that a first-party grant, limited by the scopes the login
// resource allows and by its agent's list, is the right caller for something
// agents are otherwise refused, and it means nothing without both FromGrants
// (which admits the grant at all) and WithoutAgents (the rule it relaxes): a
// route declares the three together, or the relaxation is never reached. It does
// not touch an API key's agent: that stays refused.
func (a Access) GrantsAsUser() Access {
	a.GrantAsUserOK = true

	return a
}

// check applies the access to who, and returns the 403 that refuses, or nil.
// The credential's kind is judged first, then the sandbox, whatever else the
// access declares.
func (a Access) check(who Principal) error {
	switch {
	case who.Kind == KindGrant && !a.GrantOK:
		return grantRefused()
	case who.SandboxID != "" && !a.SandboxOK:
		return confined()
	}

	return a.checkCaller(who)
}

// checkCaller applies the access that is the same for a sandboxed agent and
// anyone else: the role, the scope, the kind of credential, and agents. The
// role and the scope are not judged here: Authority.Permits combines them with
// the credential's and the agent's lists, and says which refused.
func (a Access) checkCaller(who Principal) error {
	switch who.Authority().Permits(a.Scope) {
	case NeedsAdmin:
		return forbidden("administrator access is required")
	case LacksScope:
		return lacksScope(a.Scope)
	case Permitted:
	}

	switch {
	case a.SessionOnly && who.Kind != KindSession:
		return forbidden("a signed-in session is required")
	case a.NoAgents && who.AgentID != "" && (who.Kind != KindGrant || !a.GrantAsUserOK):
		return forbidden("an agent may not do this")
	}

	return nil
}

// grantRefused is the classified 403 for an OAuth grant's access token on a
// route that has not opted in to it (Access.FromGrants).
func grantRefused() *apierr.Error {
	return apierr.New(apierr.Forbidden, CodeGrantNotAccepted, "an OAuth access token may not be used here")
}

// confined is the classified 403 for an agent of a sandbox on a route that has
// not opted in to it (Access.InSandbox).
func confined() *apierr.Error {
	return apierr.New(apierr.Forbidden, CodeSandboxConfined, "an agent of a sandbox may not do this")
}

// forbidden is the classified 403, with a fixed, client-safe description.
func forbidden(description string) *apierr.Error {
	return apierr.New(apierr.Forbidden, CodeForbidden, description)
}

// lacksScope is the classified 403 for a credential without the scope a route
// needs. The scope is named, because it is the route's own and not the
// caller's input, so it reflects nothing a client sent.
func lacksScope(needed scope.Scope) *apierr.Error {
	return apierr.New(apierr.Forbidden, CodeInsufficientScope, "this credential lacks the scope "+string(needed))
}
