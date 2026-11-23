// Package scope is the vocabulary of permissions described in
// docs/permissions_design.md: the scopes a credential may name, the bundles
// that group them, and the set operations the request boundary applies.
//
// # Names
//
// A scope names one thing a credential may do, as "resource:action": both
// halves are lower-case ASCII words (underscores between words), the resource
// is a singular noun matching the API path (/api/agent is "agent"), and the
// action is one of Read (list and get alike), Create, Update or Revoke. There is
// no delete action: deleting a sandbox is "sandbox:revoke". Sandboxes have
// their own scopes to create and revoke; org:read and org:update apply to
// organizations and sandboxes alike. "default" is reserved as a
// resource so a bundle can never look like a scope.
//
// A bundle is a named set of scopes, written "default:<name>". Bundles never
// contain other bundles: each lists its scopes, so reading its definition says
// everything it grants. Every name, scope or bundle, has the one "a:b" shape.
// DefaultSession lists every scope there is, and is what a login session is
// created with.
//
// # Lists
//
// A credential's scopes are a List: the names exactly as written, in the order
// written, each a scope or a bundle. A List is stored as a JSON array of
// strings. A list is expanded (Expand) when a request is checked, never when
// it is written, so adding a
// scope to a bundle reaches every credential that names the bundle.
//
// # Lenient reading, strict writing
//
// Writing a list refuses a name the code does not know (Names), so a typo
// fails loudly. Reading one never fails: a name the code no longer knows
// expands to nothing, and a stored value that is not a list at all is the empty
// list. Removing a scope therefore only ever removes access.
//
// # Admin scopes
//
// Some scopes are admin scopes. A scope never grants authority by itself: the
// route boundary requires the caller's role to be administrator as well as the
// scope (internal/auth), so an admin scope on a member's credential grants
// nothing. Scopes only ever narrow what the user may already do.
//
// The organization scopes (org, sandbox and member) are not admin scopes. Who may
// look after a given organization is a fact about that organization, so the
// store decides it in the write that depends on it, with the platform
// administrator's override beside it; the scope only says whether the
// credential may ask. They are in the session and user bundles and not the
// agent's.
package scope

import (
	"slices"
)

// MaxNameBytes is the longest a scope or bundle name may be, in bytes. It
// bounds each entry of a list a client sends (input.ParseScopeList), and is far
// above the longest name there is: a new name must fit.
const MaxNameBytes = 63

// Scope is one thing a credential may do.
type Scope string

// The scopes. Each is "resource:action".
const (
	// AgentRead lists and reads the caller's agents.
	AgentRead Scope = "agent:read"
	// AgentCreate creates an agent and its first key.
	AgentCreate Scope = "agent:create"
	// AgentUpdate renames an agent.
	AgentUpdate Scope = "agent:update"
	// AgentRevoke revokes an agent and its keys.
	AgentRevoke Scope = "agent:revoke"

	// KeyRead lists and reads the caller's own keys (those of no agent).
	KeyRead Scope = "key:read"
	// KeyCreate creates an API key for the caller.
	KeyCreate Scope = "key:create"
	// KeyUpdate renames one of the caller's own keys.
	KeyUpdate Scope = "key:update"
	// KeyRevoke revokes one of the caller's own keys other than the one
	// presented. A caller can always revoke the credential it presents, with no
	// scope, through logout.
	KeyRevoke Scope = "key:revoke"

	// GrantRead lists and reads the caller's OAuth grants.
	GrantRead Scope = "grant:read"
	// GrantRevoke revokes one of the caller's OAuth grants.
	GrantRevoke Scope = "grant:revoke"

	// OrgRead lists and reads organizations and sandboxes the caller belongs to
	// or administers.
	OrgRead Scope = "org:read"
	// SandboxCreate creates a sandbox.
	SandboxCreate Scope = "sandbox:create"
	// OrgUpdate renames an organization or a sandbox.
	OrgUpdate Scope = "org:update"
	// SandboxRevoke deletes a sandbox.
	SandboxRevoke Scope = "sandbox:revoke"

	// MemberRead lists the members of an organization.
	MemberRead Scope = "member:read"
	// MemberUpdate promotes or demotes a member as an administrator.
	MemberUpdate Scope = "member:update"
	// MemberRevoke revokes the account of a member of an organization.
	MemberRevoke Scope = "member:revoke"

	// InvitationRead lists invitations. Admin only.
	InvitationRead Scope = "invitation:read"
	// InvitationCreate creates an invitation. Admin only.
	InvitationCreate Scope = "invitation:create"
	// InvitationUpdate changes an invitation. Admin only.
	InvitationUpdate Scope = "invitation:update"
	// InvitationRevoke revokes an invitation. Admin only.
	InvitationRevoke Scope = "invitation:revoke"
	// UserRead lists and reads accounts. Admin only.
	UserRead Scope = "user:read"
	// UserRevoke revokes an account. Admin only.
	UserRevoke Scope = "user:revoke"
)

// Names of the bundles. They are written in lists as they are here.
const (
	// DefaultSession is every scope. A login session has it: a session is the
	// user acting in person, so it is limited only by the user's role.
	DefaultSession = "default:session"
	// DefaultUser is every scope that is not an admin scope, except the ones that
	// revoke other people's accounts (member:revoke): the default for a user's own
	// API keys. A key can still be given those by naming them.
	DefaultUser = "default:user"
	// DefaultAgent is the default for an agent and its keys.
	DefaultAgent = "default:agent"
)

// definition is what the code knows about one scope.
type definition struct {
	scope Scope
	admin bool
}

// definitions is every scope, in the order they are documented. It is code and
// not configuration: which scopes exist is part of what the service is.
func definitions() []definition {
	return []definition{
		{AgentRead, false}, {AgentCreate, false}, {AgentUpdate, false}, {AgentRevoke, false},
		{KeyRead, false}, {KeyCreate, false}, {KeyUpdate, false}, {KeyRevoke, false},
		{GrantRead, false}, {GrantRevoke, false},
		{OrgRead, false}, {SandboxCreate, false}, {OrgUpdate, false}, {SandboxRevoke, false},
		{MemberRead, false}, {MemberUpdate, false}, {MemberRevoke, false},
		{InvitationRead, true}, {InvitationCreate, true}, {InvitationUpdate, true}, {InvitationRevoke, true},
		{UserRead, true}, {UserRevoke, true},
	}
}

// bundles are the named groups of scopes, each listing its scopes explicitly.
// A test requires DefaultSession to hold every scope and DefaultUser every
// scope that is not an admin scope, except member:revoke, so a new scope cannot be
// left out of them.
func bundles() map[string][]Scope {
	return map[string][]Scope{
		DefaultSession: {
			AgentRead, AgentCreate, AgentUpdate, AgentRevoke, KeyRead, KeyCreate, KeyUpdate, KeyRevoke,
			GrantRead, GrantRevoke,
			OrgRead, SandboxCreate, OrgUpdate, SandboxRevoke, MemberRead, MemberUpdate, MemberRevoke,
			InvitationRead, InvitationCreate, InvitationUpdate, InvitationRevoke, UserRead, UserRevoke,
		},
		DefaultUser: {
			AgentRead, AgentCreate, AgentUpdate, AgentRevoke, KeyRead, KeyCreate, KeyUpdate, KeyRevoke,
			GrantRead, GrantRevoke,
			OrgRead, SandboxCreate, OrgUpdate, SandboxRevoke, MemberRead, MemberUpdate,
		},
		DefaultAgent: {AgentRead},
	}
}

// IsAdmin reports whether s is an admin scope: one the route boundary refuses
// to anyone who is not an administrator, whatever their credential names.
func IsAdmin(s Scope) bool {
	for _, def := range definitions() {
		if def.scope == s {
			return def.admin
		}
	}

	return false
}

// Known reports whether name is a scope or a bundle.
func Known(name string) bool {
	if _, bundle := bundles()[name]; bundle {
		return true
	}

	for _, def := range definitions() {
		if string(def.scope) == name {
			return true
		}
	}

	return false
}

// Scopes returns every scope, in documented order. It is a copy.
func Scopes() []Scope {
	all := make([]Scope, 0, len(definitions()))

	for _, def := range definitions() {
		all = append(all, def.scope)
	}

	return all
}

// Bundle returns the scopes of a bundle, and reports false for a name that is
// not one. It is a copy.
func Bundle(name string) ([]Scope, bool) {
	members, ok := bundles()[name]

	return slices.Clone(members), ok
}

// Set is a set of scopes: what a list expands to.
type Set struct{ m map[Scope]struct{} }

// Has reports whether s is in the set. The zero Set is empty.
func (set Set) Has(s Scope) bool {
	_, ok := set.m[s]

	return ok
}

// Len is the number of scopes in the set.
func (set Set) Len() int { return len(set.m) }

// Sorted returns the set's scopes in lexical order, for display and tests.
func (set Set) Sorted() []Scope {
	out := make([]Scope, 0, len(set.m))
	for s := range set.m {
		out = append(out, s)
	}

	slices.Sort(out)

	return out
}

// Intersect returns the scopes in both sets. Every layer of a request narrows
// the one above it, and this is how: a set never gains a scope from another.
func (set Set) Intersect(other Set) Set {
	out := Set{m: map[Scope]struct{}{}}

	for s := range set.m {
		if other.Has(s) {
			out.m[s] = struct{}{}
		}
	}

	return out
}
