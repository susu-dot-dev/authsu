package auth

import (
	"slices"

	"github.com/susu-dot-dev/authsu/internal/scope"
)

// Verdict is the answer of Permits: whether a route's required scope is
// allowed, and when it is not, which of the two layers refused. The two refuse
// with different codes (Access.checkCaller), so a caller must be able to tell
// them apart.
type Verdict uint8

const (
	// Permitted means the required scope is allowed: the route needs none, or
	// the role and the scope lists all admit it.
	Permitted Verdict = iota
	// NeedsAdmin means the required scope is an admin scope and the user's role
	// is not administrator. The role is the primary gate and is judged before
	// the lists, so a member is told about the role whatever scopes the
	// credential names.
	NeedsAdmin
	// LacksScope means the role admits the scope but the credential's list,
	// narrowed by the agent's when one is acting, does not hold it.
	LacksScope
)

// Authority is everything that decides what a request may do, each part read
// from stored rows for the request and never from a token: the credential's
// own scope list, the acting agent's list, whether an agent is acting, and the
// user's role. It is the single input of Permits and Effective, the only
// functions in which the layers are combined, so a new kind of credential
// plugs in by supplying its own Credential list and, if an agent acts through
// it, the agent's. Nothing else combines them.
//
// Each layer can only narrow the one above it (docs/permissions_design.md):
// the agent's list narrows the credential's, and the role gates admin scopes
// outside the lists. Nothing here adds authority.
type Authority struct {
	// Credential is the credential's own scope list exactly as stored:
	// SessionScope for a session, the key row's list for an API key. A damaged
	// stored list reads as empty (scope.Read).
	Credential scope.List
	// Agent is the acting agent's scope list exactly as stored, read now. It
	// is consulted only when AgentActing, and is empty otherwise.
	Agent scope.List
	// AgentActing is whether an agent is acting. The agent's list narrows the
	// credential's only then; an agent whose list is empty, and so allows
	// nothing, is different from there being no agent.
	AgentActing bool
	// Role is the account's role now.
	Role string
}

// Authority is the inputs of the principal's permissions, as read for the
// request.
func (p Principal) Authority() Authority {
	return Authority{
		Credential: p.Scope, Agent: p.AgentScope, AgentActing: p.AgentID != "", Role: p.Role,
	}
}

// Effective is the scopes the lists allow: the credential's, narrowed by the
// agent's when an agent is acting. It is an intersection and never a union, and
// the role is not in it: Permits judges the role for admin scopes.
func (a Authority) Effective() scope.Set {
	granted := a.Credential.Expand()
	if !a.AgentActing {
		return granted
	}

	return granted.Intersect(a.Agent.Expand())
}

// Permits answers whether the route scope needed is allowed. It is the one
// place the role, the credential's list and the agent's list are combined:
//
//  1. An empty needed is no requirement, and is always Permitted.
//  2. An admin scope needs the administrator role (NeedsAdmin otherwise),
//     whatever the lists name: a scope never grants what the role does not.
//  3. The scope must be in Effective (LacksScope otherwise).
//
// The order is what decides what a caller who fails both is told: the role
// first.
func (a Authority) Permits(needed scope.Scope) Verdict {
	switch {
	case needed == "":
		return Permitted
	case scope.IsAdmin(needed) && a.Role != RoleAdmin:
		return NeedsAdmin
	case !a.Effective().Has(needed):
		return LacksScope
	default:
		return Permitted
	}
}

// MayIssue reports whether a credential the principal issues may hold the list
// wanted: every entry of it must be an entry of the issuing credential's own
// list, compared as written. A bundle is passed on whole or not at all, so a
// credential holding a bundle cannot hand on one scope from inside it.
//
// The literal comparison is what makes it sound: a list contained in another
// has an expansion contained in the other's however the bundles change later,
// and both are expanded the same way at request time, so what is issued can
// never do more than the credential that issued it (docs/permissions_design.md).
// It does not consult the acting agent's list: an agent's key that issues a
// credential gives it the agent's own list (the new agent is a copy of its
// creator), so the agent's narrowing carries over by construction. A credential
// that issues a list of its own choosing, with the agent not copied, must use
// MayIssueWithAgent.
func (p Principal) MayIssue(wanted scope.List) bool {
	return wanted.SubsetOf(p.Scope)
}

// MayIssueWithAgent reports whether a credential the principal issues, whose
// list the principal's request chooses, may hold the list wanted. It is MayIssue
// bounded by the agent too: the agent's list is the primary permission set
// (docs/permissions_design.md), and the credential's only narrows it, so a list
// of the request's choosing must be entries of BOTH the credential's list and,
// when an agent is acting, the agent's, each compared as written. Containment in
// both literal lists gives containment in the intersection of the two
// expansions, however the bundles change later, which is
// what Effective is, so what is issued can never do more than the principal does.
// An acting agent whose list is empty (or damaged, which reads as empty) allows
// only the empty list.
func (p Principal) MayIssueWithAgent(wanted scope.List) bool {
	return p.MayIssue(wanted) && (p.AgentID == "" || wanted.SubsetOf(p.AgentScope))
}

// Common returns the entries of the principal's own list that the acting agent's
// list also holds, as written and in the credential's order: the widest list
// MayIssueWithAgent allows, which is what a list the request does not choose
// defaults to. With no agent acting it is the credential's whole list.
func (p Principal) Common() scope.List {
	if p.AgentID == "" {
		return slices.Clone(p.Scope)
	}

	common := scope.List{}

	for _, name := range p.Scope {
		if slices.Contains(p.AgentScope, name) {
			common = append(common, name)
		}
	}

	return common
}
