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
// until someone decides otherwise. This is the first check, so the answer does
// not depend on what the agent's scopes or its user's role are.
//
// The checks, in this order, all 403 and all after the credential is known to
// be valid (a bad credential is always 401, whatever the route requires):
//
//  1. Sandbox: a principal with a SandboxID needs the route to be InSandbox
//     (CodeSandboxConfined).
//  2. Admin scope: when Scope is an admin scope (scope.IsAdmin) the caller's
//     role must be administrator. The role is the primary gate, read from the
//     database on every request; a scope never grants it.
//  3. Scope: the effective scopes must include Scope.
//  4. SessionOnly: the credential must be a passkey session, so a person was
//     present.
//  5. NoAgents: no agent may be acting, whatever its scopes.
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

// check applies the access to who, and returns the 403 that refuses, or nil.
// The sandbox is judged first, whatever else the access declares.
func (a Access) check(who Principal) error {
	if who.SandboxID != "" && !a.SandboxOK {
		return confined()
	}

	return a.checkCaller(who)
}

// checkCaller applies the access that is the same for a sandboxed agent and
// anyone else: the role, the scope, the kind of credential, and agents.
func (a Access) checkCaller(who Principal) error {
	switch {
	case a.Scope != "" && scope.IsAdmin(a.Scope) && who.Role != RoleAdmin:
		return forbidden("administrator access is required")
	case a.Scope != "" && !who.Effective.Has(a.Scope):
		return lacksScope(a.Scope)
	case a.SessionOnly && who.Kind != KindSession:
		return forbidden("a signed-in session is required")
	case a.NoAgents && who.AgentID != "":
		return forbidden("an agent may not do this")
	}

	return nil
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
