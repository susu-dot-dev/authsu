package input

import "github.com/susu-dot-dev/authsu/internal/result"

// The values of an organization's kind and of the role an offer carries. They
// are a closed set that Go owns: orgs.kind and org_offers.role are open-ended
// text with only a size CHECK (docs/DATABASE.md), so the parsers below are the
// one place that says which values exist, and internal/store binds the same
// constants as query arguments. The longest is far inside the CHECK
// `length(kind) BETWEEN 1 AND 64` and `length(role) BETWEEN 1 AND 64`
// (migration 0001); a test holds that, and holds that a new value would too.
const (
	// OrgKindStandard is a group of users with administrators. A user belongs
	// to at most one, and it is revoked and never deleted.
	OrgKindStandard = "standard"
	// OrgKindSandbox is a temporary organization that holds and confines
	// agents. It has one administrator, no members, and is always deleted.
	OrgKindSandbox = "sandbox"

	// OrgRoleMember is an offer to join an organization as a member.
	OrgRoleMember = "member"
	// OrgRoleAdmin is an offer to join an organization as a member and one of
	// its administrators.
	OrgRoleAdmin = "admin"
)

// Error codes of the organization types.
const (
	CodeInvalidOrgKind = "invalid_org_kind"
	CodeInvalidOrgRole = "invalid_org_role"
	// CodeMissingOrgID is an offer's role without the organization it is for.
	CodeMissingOrgID = "missing_org_id"
	// CodeMissingOrgRole is an offer's organization without the role it is
	// offered as: the role is never assumed.
	CodeMissingOrgRole = "missing_org_role"
	// CodeMissingAdmin is an administrator flag that was left out or null.
	CodeMissingAdmin = "missing_admin"
)

const (
	descInvalidOrgKind = `kind must be "standard" or "sandbox"`
	descInvalidOrgRole = `role must be "member" or "admin"`
	descMissingOrgID   = "orgId is required with orgRole"
	descMissingOrgRole = "orgRole is required with orgId"
	descMissingAdmin   = "admin is required"
)

// OrgKinds returns the kinds of organization, in documented order. It is a
// fresh slice.
func OrgKinds() []string { return []string{OrgKindStandard, OrgKindSandbox} }

// OrgRoles returns the roles an offer may carry, in documented order. It is a
// fresh slice.
func OrgRoles() []string { return []string{OrgRoleMember, OrgRoleAdmin} }

// OrgKind is which kind of organization a request names.
type OrgKind struct{ v string }

// ParseOrgKind accepts exactly "standard" or "sandbox". It refuses anything
// else, and never corrects: "Standard" and " sandbox" are not aliases.
func ParseOrgKind(raw string) (OrgKind, error) {
	if raw != OrgKindStandard && raw != OrgKindSandbox {
		return OrgKind{}, refuse(CodeInvalidOrgKind, descInvalidOrgKind)
	}

	return OrgKind{v: raw}, nil
}

// String returns the kind exactly as it was parsed. The zero OrgKind is
// empty and is not a kind.
func (k OrgKind) String() string { return k.v }

// Sandbox reports whether the kind is OrgKindSandbox.
func (k OrgKind) Sandbox() bool { return k.v == OrgKindSandbox }

// OrgRole is the role an offer to join an organization carries.
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

// OrgOffer is the optional offer to join an organization that a request
// carries: an organization and the role it is offered as. The zero OrgOffer is
// no offer.
type OrgOffer struct {
	id   ID
	role OrgRole
	some bool
}

// ParseOrgOffer parses the two fields of an offer, each absent (nil, which is
// also a JSON null) or given. Neither is no offer, and not an error. One
// without the other is refused, naming the missing one, because a role is never
// assumed and an organization is never offered with none. A given value is
// parsed as ParseID and ParseOrgRole do, the organization first. Whether the
// organization exists and can be offered is not known here.
func ParseOrgOffer(id, role *string) (OrgOffer, error) {
	switch {
	case id == nil && role == nil:
		return OrgOffer{}, nil
	case id == nil:
		return OrgOffer{}, refuse(CodeMissingOrgID, descMissingOrgID)
	case role == nil:
		return OrgOffer{}, refuse(CodeMissingOrgRole, descMissingOrgRole)
	}

	//nolint:wrapcheck // the parsers' errors are already the classified client errors
	return result.Of(ParseID(*id)).
		Then(func(orgID ID) (OrgOffer, error) {
			return result.Of(ParseOrgRole(*role)).
				Map(func(orgRole OrgRole) OrgOffer { return OrgOffer{id: orgID, role: orgRole, some: true} }).
				Get()
		}).
		Get()
}

// Offered reports whether there is an offer. When it is false, OrgID and Role
// are the zero values.
func (o OrgOffer) Offered() bool { return o.some }

// OrgID is the organization offered.
func (o OrgOffer) OrgID() ID { return o.id }

// Role is the role it is offered as.
func (o OrgOffer) Role() OrgRole { return o.role }

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
