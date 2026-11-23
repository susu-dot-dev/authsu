package input

import "github.com/susu-dot-dev/authsu/internal/result"

// The values of an organization's kind and of the role an invitation gives in
// the organization it names. They are a closed set that Go owns: orgs.kind and
// invitation_orgs.role are open-ended text with only a size CHECK
// (docs/DATABASE.md), so these constants are the one place that says which
// values exist, and internal/store binds them as query arguments. A client never
// names a kind (a sandbox is the only one it can create); it does name a role,
// which ParseOrgRole parses. The longest is far inside the CHECK
// `length(kind) BETWEEN 1 AND 64` and `length(role) BETWEEN 1 AND 64`
// (migration 0001); a test holds that, and holds that a new value would too.
const (
	// OrgKindStandard is a group of users with administrators. An account
	// belongs to exactly one, for life, and it is never revoked or deleted.
	OrgKindStandard = "standard"
	// OrgKindSandbox is a temporary organization that holds and confines
	// agents. It has one administrator, no members, and is always deleted.
	OrgKindSandbox = "sandbox"

	// OrgRoleMember is the role of an account that joins an organization as a
	// member.
	OrgRoleMember = "member"
	// OrgRoleAdmin is the role of an account that joins an organization as a
	// member and one of its administrators.
	OrgRoleAdmin = "admin"
)

// Error codes of the organization types.
const (
	CodeInvalidOrgRole = "invalid_org_role"
	// CodeMissingOrgID is an invitation's role without the organization it is
	// for.
	CodeMissingOrgID = "missing_org_id"
	// CodeMissingOrgRole is an invitation's organization without the role in
	// it: the role is never assumed.
	CodeMissingOrgRole = "missing_org_role"
	// CodeMissingAdmin is an administrator flag that was left out or null.
	CodeMissingAdmin = "missing_admin"
)

const (
	descInvalidOrgRole = `role must be "member" or "admin"`
	descMissingOrgID   = "orgId is required with orgRole"
	descMissingOrgRole = "orgRole is required with orgId"
	descMissingAdmin   = "admin is required"
)

// OrgRoles returns the roles an invitation may give, in documented order. It is a
// fresh slice.
func OrgRoles() []string { return []string{OrgRoleMember, OrgRoleAdmin} }

// OrgRole is the role an invitation gives in the organization it names.
type OrgRole struct{ v string }

// ParseOrgRole accepts exactly "member" or "admin". It refuses anything else,
// and never corrects.
func ParseOrgRole(raw string) (OrgRole, error) {
	if raw != OrgRoleMember && raw != OrgRoleAdmin {
		return OrgRole{}, refuse(CodeInvalidOrgRole, descInvalidOrgRole)
	}

	return OrgRole{v: raw}, nil
}

// String returns the role exactly as it was parsed. The zero OrgRole is empty
// and is not a role.
func (r OrgRole) String() string { return r.v }

// Admin reports whether the role is OrgRoleAdmin.
func (r OrgRole) Admin() bool { return r.v == OrgRoleAdmin }

// InvitationOrg is the optional organization that an invitation names: an
// organization and the role in it that whoever registers with the invitation
// gets. The zero InvitationOrg names none.
type InvitationOrg struct {
	id   ID
	role OrgRole
	some bool
}

// ParseInvitationOrg parses the two fields that name an organization, each
// absent (nil, which is also a JSON null) or given. Neither is none, and not an
// error. One without the other is refused, naming the missing one, because a
// role is never assumed and an organization is never named with no role. A given
// value is parsed as ParseID and ParseOrgRole do, the organization first.
// Whether the organization exists and can be named is not known here.
func ParseInvitationOrg(id, role *string) (InvitationOrg, error) {
	switch {
	case id == nil && role == nil:
		return InvitationOrg{}, nil
	case id == nil:
		return InvitationOrg{}, refuse(CodeMissingOrgID, descMissingOrgID)
	case role == nil:
		return InvitationOrg{}, refuse(CodeMissingOrgRole, descMissingOrgRole)
	}

	//nolint:wrapcheck // the parsers' errors are already the classified client errors
	return result.Of(ParseID(*id)).
		Then(func(orgID ID) (InvitationOrg, error) {
			return result.Of(ParseOrgRole(*role)).
				Map(func(orgRole OrgRole) InvitationOrg { return InvitationOrg{id: orgID, role: orgRole, some: true} }).
				Get()
		}).
		Get()
}

// Named reports whether an organization is named. When it is false, OrgID and
// Role are the zero values.
func (o InvitationOrg) Named() bool { return o.some }

// OrgID is the organization named.
func (o InvitationOrg) OrgID() ID { return o.id }

// Role is the role in it.
func (o InvitationOrg) Role() OrgRole { return o.role }

// OrgAdmin is whether a member is to administer their organization.
type OrgAdmin struct{ v bool }

// ParseOrgAdmin accepts a given flag and refuses an absent one (nil, which is
// also a JSON null), so that leaving it out is never read as false: demoting
// someone must be asked for.
func ParseOrgAdmin(raw *bool) (OrgAdmin, error) {
	if raw == nil {
		return OrgAdmin{}, refuse(CodeMissingAdmin, descMissingAdmin)
	}

	return OrgAdmin{v: *raw}, nil
}

// Admin reports whether the member is to be an administrator. The zero
// OrgAdmin is false.
func (a OrgAdmin) Admin() bool { return a.v }
