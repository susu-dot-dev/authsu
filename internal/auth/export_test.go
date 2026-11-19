package auth

// This file exposes unexported seams to the external test package. It is
// compiled only into tests.

// CheckAccess exposes Access.check, so the order of the checks can be pinned on
// a Principal built by hand. Every other access test goes through the boundary.
func CheckAccess(a Access, who Principal) error { return a.check(who) }
