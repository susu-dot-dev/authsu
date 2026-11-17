package invitations

import (
	"strings"
	"testing"
)

// The real SQL only runs in the e2e tests, because D1 only exists in workerd.
// These pin the load-bearing fragments, so a refactor that drops a condition
// fails here, close to the change, and not only in a slow end-to-end run.

func TestQueriesKeepTheirConditions(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		query string
		want  []string
	}{
		"update refuses a revoked invitation": {updateNumInvitesQuery, []string{"WHEN revoked_at IS NULL"}},
		"update checks the cap in the write": {
			updateNumInvitesQuery, []string{"WHERE u.invitation_id = invitations.id) <= ?2"},
		},
		"update reports the row and the verdict": {
			updateNumInvitesQuery, []string{"RETURNING", ") AS applied,", ") AS uses,"},
		},
		"revoke keeps the earlier time":          {revokeQuery, []string{"COALESCE(revoked_at, ?1)"}},
		"revoke is by id":                        {revokeQuery, []string{"WHERE id = ?2"}},
		"revoke returns the row":                 {revokeQuery, []string{"RETURNING", ") AS uses,"}},
		"update is by id":                        {updateNumInvitesQuery, []string{"WHERE id = ?3"}},
		"list orders newest first":               {listQuery, []string{"ORDER BY i.created_at DESC, i.id DESC"}},
		"list counts accounts that came from it": {listQuery, []string{"WHERE u.invitation_id = i.id"}},
		"get is by id":                           {getQuery, []string{"WHERE i.id = ?"}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, fragment := range tt.want {
				if !strings.Contains(tt.query, fragment) {
					t.Errorf("query lacks %q:\n%s", fragment, tt.query)
				}
			}
		})
	}
}

// TestReadsNeverSelectTheCodeHash: nothing that reads an invitation for a
// client can return the hash of its code.
func TestReadsNeverSelectTheCodeHash(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{"list": listQuery, "get": getQuery} {
		if strings.Contains(query, "code_hash") {
			t.Errorf("%s query selects code_hash:\n%s", name, query)
		}
	}
}

// TestRevocationNeverDeletes: an invitation is never deleted. Accounts reference
// it (the schema forbids deleting one that has created any), and the audit
// question "who came from this code?" must stay answerable.
func TestRevocationNeverDeletes(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{
		"revoke": revokeQuery, "update": updateNumInvitesQuery, "insert": insertQuery,
	} {
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
