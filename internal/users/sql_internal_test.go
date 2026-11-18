package users

import (
	"strings"
	"testing"
)

// The real SQL only runs in the e2e tests, because D1 only exists in workerd.
// These pin the load-bearing fragments, so a refactor that drops a condition
// fails here, close to the change, and not only in a slow end-to-end run.

func squash(query string) string { return strings.Join(strings.Fields(query), " ") }

func TestQueriesKeepTheirConditions(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		query string
		want  []string
	}{
		"revoke keeps the earlier time": {revokeQuery, []string{"SET revoked_at = COALESCE(revoked_at, CASE"}},
		"revoke spares the last admin": {revokeQuery, []string{
			"WHEN role <> ?3 OR EXISTS (SELECT 1 FROM users other WHERE other.id <> users.id " +
				"AND other.role = ?3 AND other.revoked_at IS NULL) THEN ?1 END)",
		}},
		"revoke is by id and returns the row": {revokeQuery, []string{
			"WHERE id = ?2 RETURNING id, role, invitation_id, profile, revoked_at, created_at",
		}},
		"keys follow only a revoked account": {revokeKeysQuery, []string{
			"WHERE user_id = ?2",
			"AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND revoked_at IS NOT NULL)",
		}},
		"keys never move a revocation later": {revokeKeysQuery, []string{"AND (revoked_at IS NULL OR revoked_at > ?1)"}},
		"agents follow only a revoked account": {revokeAgentsQuery, []string{
			"WHERE user_id = ?2",
			"AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND revoked_at IS NOT NULL)",
		}},
		"agents keep an earlier revocation": {revokeAgentsQuery, []string{"AND revoked_at IS NULL"}},
		"list orders newest first":          {listQuery, []string{"ORDER BY created_at DESC, id DESC"}},
		"get is by id":                      {getQuery, []string{"WHERE id = ?"}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			query := squash(tt.query)
			for _, fragment := range tt.want {
				if !strings.Contains(query, fragment) {
					t.Errorf("query lacks %q:\n%s", fragment, query)
				}
			}
		})
	}
}

// TestRevocationNeverDeletes: an account is never deleted. Its row is the audit
// trail, and deleting it would cascade to its credentials and keys.
func TestRevocationNeverDeletes(t *testing.T) {
	t.Parallel()

	queries := map[string]string{"account": revokeQuery, "keys": revokeKeysQuery, "agents": revokeAgentsQuery}

	for name, query := range queries {
		if strings.Contains(strings.ToUpper(query), "DELETE") {
			t.Errorf("%s query deletes:\n%s", name, query)
		}
	}
}

// TestPathWildcardsNameTheItemPathWildcards: ServeMethods copies only the
// wildcards it is told about, so the list must match the path's.
func TestPathWildcardsNameTheItemPathWildcards(t *testing.T) {
	t.Parallel()

	wildcards := PathWildcards()
	if len(wildcards) != 1 || !strings.Contains(ItemPath, "{"+wildcards[0]+"}") {
		t.Errorf("PathWildcards = %v for %q", wildcards, ItemPath)
	}
}
