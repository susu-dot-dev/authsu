package store

import "github.com/susu-dot-dev/authsu/internal/input"

// The kinds of organization (orgs.kind) and the roles an offer carries
// (org_offers.role). The set of each is Go's, and internal/input parses a
// client's spelling of it, so these are that package's constants under the
// names the store binds: a query never writes one of them as a literal, and
// these are the only place in the store that spells them. The migration fixes
// the same text where it is an invariant (users may belong only to a
// 'standard' organization and agents only to a 'sandbox'), and a test holds the
// two together.
const (
	// OrgKindStandard is a group of users with administrators. It is revoked
	// and never deleted.
	OrgKindStandard = input.OrgKindStandard
	// OrgKindSandbox is a temporary organization that holds and confines
	// agents. It is always deleted.
	OrgKindSandbox = input.OrgKindSandbox

	// OfferRoleMember is an offer to join as a member.
	OfferRoleMember = input.OrgRoleMember
	// OfferRoleAdmin is an offer to join as a member and an administrator.
	OfferRoleAdmin = input.OrgRoleAdmin
)
