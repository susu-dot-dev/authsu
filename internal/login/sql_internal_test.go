package login

import (
	"strings"
	"testing"
)

// TestCredentialLookupSkipsRevokedAccounts: the real SQL only runs in e2e, so
// this pins the condition that keeps a revoked account from logging in, close
// to the query.
func TestCredentialLookupSkipsRevokedAccounts(t *testing.T) {
	t.Parallel()

	if !strings.Contains(credentialQuery, "AND u.revoked_at IS NULL") {
		t.Errorf("credential query does not skip revoked accounts:\n%s", credentialQuery)
	}
}
