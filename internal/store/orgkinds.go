package store

import "github.com/susu-dot-dev/authsu/internal/input"

// The kinds of organization (orgs.kind) and the roles an invitation gives in the
// organization it names (invitation_orgs.role). The set of each is Go's, and internal/input parses a
// client's spelling of it, so these are that package's constants under the
// names the store binds: a query never writes one of them as a literal, and
// these are the only place in the store that spells them. The migration fixes
// the same text where it is an invariant (users may belong only to a
// 'standard' organization and agents only to a 'sandbox'), and a test holds the
// two together.
const (
	// OrgKindStandard is a group of users with administrators. It is never
	// revoked or deleted.
	OrgKindStandard = input.OrgKindStandard
	// OrgKindSandbox is a temporary organization that holds and confines
	// agents. It is always deleted.
	OrgKindSandbox = input.OrgKindSandbox

	// OrgRoleMember is the role of an account that joins an organization as a
	// member.
	OrgRoleMember = input.OrgRoleMember
	// OrgRoleAdmin is the role of an account that joins an organization as a
	// member and an administrator.
	OrgRoleAdmin = input.OrgRoleAdmin
)
