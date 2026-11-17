package session

import (
	"strings"
	"testing"
)

// squash collapses whitespace so a query can be matched regardless of layout.
func squash(query string) string { return strings.Join(strings.Fields(query), " ") }

// TestActiveKeyChecksRevocationAndExpiry pins what makes a key usable. Revocation
// is compared with now and not tested for NULL alone, so a revocation scheduled
// for later would work without a change here.
func TestActiveKeyChecksRevocationAndExpiry(t *testing.T) {
	t.Parallel()

	query := squash(activeKeyQuery)

	for _, want := range []string{
		"AND (k.revoked_at IS NULL OR k.revoked_at > ?)",
		"AND k.expires_at > ?",
		"AND k.kind = 'session'",
		"AND u.revoked_at IS NULL",
	} {
		if !strings.Contains(query, want) {
			t.Errorf("active key query lacks %q:\n%s", want, query)
		}
	}
}

// TestInsertSessionRefusesARevokedAccount: the account is read from the
// credential in the write, and only an account that is not revoked yields one,
// so the NOT NULL user_id fails the batch otherwise.
func TestInsertSessionRefusesARevokedAccount(t *testing.T) {
	t.Parallel()

	query := squash(InsertSessionQuery)

	for _, want := range []string{"WHERE c.id = ? AND u.revoked_at IS NULL", "JOIN users u ON u.id = c.user_id"} {
		if !strings.Contains(query, want) {
			t.Errorf("session insert lacks %q:\n%s", want, query)
		}
	}
}

// TestLogoutNeverMovesARevocationLater holds that logging out twice keeps the
// first time.
func TestLogoutNeverMovesARevocationLater(t *testing.T) {
	t.Parallel()

	query := squash(logoutQuery)

	for _, want := range []string{"AND revoked_at IS NULL", "AND kind = 'session'"} {
		if !strings.Contains(query, want) {
			t.Errorf("logout lacks %q:\n%s", want, query)
		}
	}
}
