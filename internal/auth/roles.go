package auth

import (
	"github.com/susu-dot-dev/authsu/internal/store"
)

// RoleAdmin is the role of an administrator. A role is the account's, read from
// the database on every request; a token carries nothing to hold it.
const RoleAdmin = "admin"

// RoleMember is the role of an ordinary account: a signed-in user with no
// administrative authority.
const RoleMember = "member"

// Invitation types an admin may create. The type is what an invitation grants:
// the role of the account that registers with it, copied to the account when it
// is created and never supplied by the registering client.
const (
	// InvitationMember grants RoleMember.
	InvitationMember = "member"
	// InvitationAdmin grants RoleAdmin.
	InvitationAdmin = "admin"
)

// roles maps each invitation type to the role it grants. It is code and not
// configuration: which types exist, and what each grants, is part of what the
// service is, so a deployment cannot mis-wire it. The first-run type is here
// because registration must give it a role, but it is not creatable (see
// CreatableInvitationType).
func roles() map[string]string {
	return map[string]string{
		store.InvitationFirstRun: RoleAdmin,
		InvitationMember:         RoleMember,
		InvitationAdmin:          RoleAdmin,
	}
}

// RoleForInvitation is the role an account gets when it registers with an
// invitation of the given type. It reports false for a type that grants none,
// which registration refuses rather than defaulting to a role. The first-run
// invitation's holder owns the deployment, so is the administrator.
func RoleForInvitation(invitationType string) (string, bool) {
	role, known := roles()[invitationType]

	return role, known
}

// CreatableInvitationType reports whether an admin may create an invitation of
// the given type. Every type but first run is: that one is bound to there being
// no account at all, and is created by the first-run route alone. Because
// creatable is defined as "has a role and is not first run", a creatable type
// always has a role, and registration never meets one it cannot grant.
func CreatableInvitationType(invitationType string) bool {
	_, known := RoleForInvitation(invitationType)

	return known && invitationType != store.InvitationFirstRun
}

// PlatformRole is the role a request is asked to hold to be a platform
// administrator, which the store compares the caller's own role with to give the
// platform administrator's override (docs/orgs_design.md): RoleAdmin for a user,
// whatever they present, and for an agent's key. For an OAuth grant it is the
// empty role, which no account has (the column's CHECK requires one), so the
// override never applies to it.
//
// A grant is a credential an outside service holds, bounded to what its user
// does through that product: it manages the sandboxes the user administers, and
// is not the user's whole standing as the platform's administrator, which is
// a power of a person's session. Deciding it here, from the credential's kind,
// and passing the result as the role every store call compares with, is what
// makes it impossible for a handler to give a grant the override by forgetting a
// check: the handler has no other role to pass, and the store's write states the
// override as requiring a non-empty role (store.platformOverride).
func (p Principal) PlatformRole() string {
	if p.Kind == KindGrant {
		return ""
	}

	return RoleAdmin
}
