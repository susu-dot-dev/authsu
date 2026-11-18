package agents

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
		"list is the owner's page, newest first": {listQuery, []string{
			"WHERE user_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
		}},
		"get needs id and owner": {getQuery, []string{"WHERE id = ? AND user_id = ?"}},
		"create needs an active owner under the limit": {insertAgentQuery, []string{
			"WHERE u.id = ?5 AND u.revoked_at IS NULL",
			"(SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL) < ?6",
		}},
		"create reads the owner from users": {insertAgentQuery, []string{"SELECT ?1, u.id, ?2, ?3, ?4 FROM users u"}},
		"the key's owner comes from the agent's row": {insertKeyQuery, []string{
			"(SELECT user_id FROM agents WHERE id = ?)",
		}},
		"a key is an api_key with no grant": {insertKeyQuery, []string{"'api_key'"}},
		"rename is by id and owner and returns the row": {renameQuery, []string{
			"WHERE id = ?2 AND user_id = ?3 RETURNING id, name, scopes, revoked_at, created_at",
		}},
		"rename spares a revoked agent": {renameQuery, []string{
			"SET name = CASE WHEN revoked_at IS NULL THEN ?1 ELSE name END",
		}},
		"revoke keeps the earlier time": {revokeQuery, []string{"SET revoked_at = COALESCE(revoked_at, ?1)"}},
		"revoke is by id and owner and returns the row": {revokeQuery, []string{
			"WHERE id = ?2 AND user_id = ?3 RETURNING id, name, scopes, revoked_at, created_at",
		}},
		"keys follow only a revoked agent of the owner": {revokeKeysQuery, []string{
			"WHERE agent_id = ?2 AND user_id = ?3",
			"AND EXISTS (SELECT 1 FROM agents WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NOT NULL)",
		}},
		"keys never move a revocation later": {revokeKeysQuery, []string{"AND (revoked_at IS NULL OR revoked_at > ?1)"}},
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

// TestRevocationNeverDeletes: an agent is never deleted. Its row is the audit
// trail, and deleting it would cascade to its keys.
func TestRevocationNeverDeletes(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{
		"agent": revokeQuery, "keys": revokeKeysQuery, nameRename: renameQuery,
	} {
		if strings.Contains(strings.ToUpper(query), "DELETE") {
			t.Errorf("%s query deletes:\n%s", name, query)
		}
	}
}

// TestReadsNeverSelectTheOwner: the owner is the caller, so no read returns it.
func TestReadsNeverSelectTheOwner(t *testing.T) {
	t.Parallel()

	if strings.Contains(strings.Split(squash(selectColumns), " FROM ")[0], "user_id") {
		t.Errorf("selectColumns returns the owner:\n%s", selectColumns)
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

// TestDefaultScopesNameTheDefaultAgentBundle pins the value the migration's
// design says every agent is written with.
func TestDefaultScopesNameTheDefaultAgentBundle(t *testing.T) {
	t.Parallel()

	if DefaultScopes != "default:agent" {
		t.Errorf("DefaultScopes = %q", DefaultScopes)
	}
}
