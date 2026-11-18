package auth

// This file exposes unexported seams to the external test package. It is
// compiled only into tests.

// CreateKeyWith is createKey with the JSON encoder injected, so the failure to
// encode a JWK, which no valid key causes, can be tested.
func CreateKeyWith(marshal func(any) ([]byte, error), issuer Issuer, spec KeySpec) (Key, error) {
	return createKey(marshal, issuer, spec)
}

// CheckAccess exposes Access.check, so the order of the checks can be pinned on
// a Principal built by hand. Every other access test goes through the boundary.
func CheckAccess(a Access, who Principal) error { return a.check(who) }
