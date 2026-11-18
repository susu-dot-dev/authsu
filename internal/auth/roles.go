package auth

import (
	"github.com/susu-dot-dev/authsu/internal/store"
)

// RoleAdmin is the role of an administrator. A role is the account's, read from
// the database on every request; it is never a claim in a token.
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
