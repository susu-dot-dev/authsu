//go:build e2e

//nolint:goconst,funlen,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// schema_test.go holds the constraints of migrations/0001_schema.sql that
// belong to the secrets design: the kind a secret has is binding, and a secret
// and its kind's row are created and removed together.
//
// These are schema tests and not behaviour tests, so no request goes to the
// Worker. They are here, against the real SQLite file the Worker uses with
// foreign keys on as D1 has them, because the store's unit tests can only parse
// the migration's text: whether a FOREIGN KEY on (id, kind) refuses a key
// attached to a session's secret, and whether a trigger fires for a row deleted
// by a cascade, are facts about SQLite that only running the statements can
// show. Like the rest of this package they go through db_test.go for every
// statement, and each test starts from reset.
//
// REVIEW.md categories covered: permission confusion (a kind's row cannot be
// attached to another kind's secret, and no two tables can claim one secret),
// interleaving's database half (deletes from either side leave no secret
// without its row and no row without its secret) and type/bound confusion (a
// hash is exactly 32 bytes of BLOB, never text).

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// schemaWorld resets the deployment and seeds what rows of every kind need to
// exist: an invitation (which an account refers to), the account idUserB, and a
// passkey of it, so a session row can be written.
func schemaWorld(t *testing.T) {
	t.Helper()

	reset(t)
	seedInvitation(t, idInvitationA, 5)
	seedUser(t, idUserB, roleMember)
	seed(t, "INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at) "+
		"VALUES (?, randomblob(32), ?, randomblob(77), 0, '{}', strftime('%s','now'))", idN("0f00", 1), idUserB)
}

// kindRowInserts is the statement that writes a kind's own row for a secret
// whose id is the first argument, and the kind it must be.
var kindRowInserts = map[string]struct{ kind, insert string }{ //nolint:gochecknoglobals // a read-only table of statements
	tableInvitations: {kindInvitation, "INSERT INTO invitations (id, type, label, num_invites) VALUES (?, 'x', '', 1)"},
	tableSessions: {kindSession, "INSERT INTO sessions (id, user_id, credential_id, granted_from) " +
		"VALUES (?, '" + idUserB + "', '" + idN("0f00", 1) + "', randomblob(32))"},
	tableKeys: {kindAPIKey, "INSERT INTO api_keys (id, user_id, agent_id, name, scope) VALUES (?, '" + idUserB + "', NULL, 'k', '[]')"},
}

// TestSchemaAKindRowAttachesOnlyToItsOwnKind: each kind's table is bound to its
// own kind by a foreign key on the id and the kind together. Every table is
// tried against a secret of every kind, and the row is accepted only under the
// kind of its own table. In particular an API key cannot be attached to a
// session's secret, and two tables cannot claim one secret.
//
//nolint:paralleltest // shares one database
func TestSchemaAKindRowAttachesOnlyToItsOwnKind(t *testing.T) {
	schemaWorld(t)

	kinds := []string{kindInvitation, kindSession, kindAPIKey}
	secrets := map[string]string{}

	for i, kind := range kinds {
		id := idN("0f10", i+1)
		secrets[kind] = id

		seedSecret(t, id, kind, newToken(tagSession))
	}

	for table, row := range kindRowInserts {
		for _, secretKind := range kinds {
			t.Run(table+" row on a "+secretKind+" secret", func(t *testing.T) {
				got := refused(t, row.insert, secrets[secretKind])

				if want := secretKind != row.kind; got != want {
					t.Errorf("a %s row under a %s secret: refused = %v, want %v", table, secretKind, got, want)
				}
			})
		}
	}

	// A kind's row has at most one row per secret: the id is its primary key.
	for table, row := range kindRowInserts {
		t.Run(table+" has one row per secret", func(t *testing.T) {
			id := secrets[row.kind]

			seed(t, row.insert, id)

			if !refused(t, row.insert, id) {
				t.Errorf("a second %s row for one secret was accepted", table)
			}
		})
	}
}

// TestSchemaTheKindColumnIsFixed: each kind's table fixes its kind column to
// one literal, so a row cannot claim another kind even where the foreign key
// would allow it, and a kind's secret still refuses a row of another table.
//
//nolint:paralleltest // shares one database
func TestSchemaTheKindColumnIsFixed(t *testing.T) {
	schemaWorld(t)

	seedSecret(t, idN("0f20", 1), kindAPIKey, newToken(tagAPIKey))
	seedSecret(t, idN("0f20", 2), kindSession, newToken(tagSession))
	seedSecret(t, idN("0f20", 3), kindInvitation, newToken(tagInvitation))

	// The three statements each write an explicit kind.
	insertKey := "INSERT INTO api_keys (id, kind, user_id, name, scope) VALUES (?, ?, '" + idUserB + "', 'k', '[]')"
	insertSession := "INSERT INTO sessions (id, kind, user_id, credential_id, granted_from) " +
		"VALUES (?, ?, '" + idUserB + "', '" + idN("0f00", 1) + "', randomblob(32))"
	insertInvitation := "INSERT INTO invitations (id, kind, type, label, num_invites) VALUES (?, ?, 'x', '', 1)"

	tests := []struct {
		name  string
		query string
		id    string
		kind  string
		want  bool // refused
	}{
		{"api_keys with its own kind", insertKey, idN("0f20", 1), kindAPIKey, false},
		{"api_keys with the session kind", insertKey, idN("0f20", 1), kindSession, true},
		{"api_keys with the session kind on a session secret", insertKey, idN("0f20", 2), kindSession, true},
		{"api_keys with a kind in another case", insertKey, idN("0f20", 1), "API_KEY", true},
		{"api_keys with a kind and a trailing space", insertKey, idN("0f20", 1), "api_key ", true},
		{"api_keys with an empty kind", insertKey, idN("0f20", 1), "", true},
		{"sessions with its own kind", insertSession, idN("0f20", 2), kindSession, false},
		{"sessions with the api_key kind", insertSession, idN("0f20", 2), kindAPIKey, true},
		{"sessions with the api_key kind on a key secret", insertSession, idN("0f20", 1), kindAPIKey, true},
		{"sessions with the invitation kind", insertSession, idN("0f20", 2), kindInvitation, true},
		{"invitations with its own kind", insertInvitation, idN("0f20", 3), kindInvitation, false},
		{"invitations with the session kind", insertInvitation, idN("0f20", 3), kindSession, true},
		{"invitations with the session kind on a session secret", insertInvitation, idN("0f20", 2), kindSession, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refused(t, tt.query, tt.id, tt.kind); got != tt.want {
				t.Errorf("refused = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSchemaSecretsAreBounded: the backstop CHECKs of the secrets table and of
// the columns of the kinds that hold bytes, against the real SQLite. A hash is a
// BLOB of 32 bytes and nothing else (TEXT would be counted differently), and the
// hash and the replay guard are unique.
//
//nolint:paralleltest // shares one database
func TestSchemaSecretsAreBounded(t *testing.T) {
	schemaWorld(t)

	// A session secret and its row exist already, to collide with.
	seedSession(t, idN("0f30", 1), idUserB)

	collide := tokenHash(newToken(tagSession))
	seedSecret(t, idN("0f30", 2), kindSession, newToken(tagSession))
	seed(t, "UPDATE secrets SET hash = ? WHERE id = ?", collide, idN("0f30", 2))

	const insert = "INSERT INTO secrets (id, kind, hash, expires_at, revoked_at, created_at) VALUES (?, ?, ?, ?, ?, ?)"

	good := func(mutate func(args []any)) []any {
		args := []any{idN("0f30", 3), "x", tokenHash(newToken(tagSession)), int64(1), nil, int64(1)}
		mutate(args)

		return args
	}

	tests := []struct {
		name string
		args []any
		want bool // refused
	}{
		{"a well-formed secret", good(func([]any) {}), false},
		{"a kind this schema has no table for (Go owns the set)", good(func(a []any) { a[1] = "oauth_grant" }), false},
		{"a revoked secret", good(func(a []any) { a[4] = int64(0) }), false},
		{"an id of 35 characters", good(func(a []any) { a[0] = idN("0f30", 3)[1:] }), true},
		{"an id in upper case", good(func(a []any) { a[0] = strings.ToUpper(idN("0f30", 3)) }), true},
		{"an id with a space", good(func(a []any) { a[0] = strings.Replace(idN("0f30", 3), "-", " ", 1) }), true},
		{"an empty kind", good(func(a []any) { a[1] = "" }), true},
		{"a kind of 65 characters", good(func(a []any) { a[1] = strings.Repeat("k", 65) }), true},
		{"a kind that is not text", good(func(a []any) { a[1] = []byte("x") }), true},
		{"a hash of 31 bytes", good(func(a []any) { a[2] = tokenHash("x")[:31] }), true},
		{"a hash of 33 bytes", good(func(a []any) { a[2] = append(tokenHash("x"), 0) }), true},
		{"a hash that is text of 32 characters", good(func(a []any) { a[2] = strings.Repeat("a", 32) }), true},
		{"a hash that is hex text of 64 characters", good(func(a []any) { a[2] = hex.EncodeToString(tokenHash("x")) }), true},
		{"a hash that is already stored", good(func(a []any) { a[2] = collide }), true},
		{"no expiry", good(func(a []any) { a[3] = nil }), true},
		{"no creation time", good(func(a []any) { a[5] = nil }), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refused(t, insert, tt.args...); got != tt.want {
				t.Errorf("refused = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("a login that was already used", func(t *testing.T) {
		// granted_from is the replay guard: a second session from the same login
		// collides, and a value that is not 32 bytes of BLOB is refused.
		grant := scalar(t, "SELECT hex(granted_from) FROM sessions WHERE id = ?", idN("0f30", 1))
		if grant == "" {
			t.Fatal("the seeded session has no grant")
		}

		const insertSession = "INSERT INTO sessions (id, user_id, credential_id, granted_from) VALUES (?, ?, ?, %s)"

		seedSecret(t, idN("0f30", 4), kindSession, newToken(tagSession))

		for name, tt := range map[string]struct {
			grant string
			want  bool
		}{
			"the same login again":  {"x'" + grant + "'", true},
			"another login":         {"randomblob(32)", false},
			"31 bytes":              {"randomblob(31)", true},
			"33 bytes":              {"randomblob(33)", true},
			"text of 32 characters": {"'" + strings.Repeat("a", 32) + "'", true},
			"no grant at all":       {"NULL", true},
		} {
			query := fmt.Sprintf(insertSession, tt.grant)
			if got := refused(t, query, idN("0f30", 4), idUserB, idN("0f00", 1)); got != tt.want {
				t.Errorf("%s: refused = %v, want %v", name, got, tt.want)
			}
		}
	})

	t.Run("an API key's scope text", func(t *testing.T) {
		seedSecret(t, idN("0f30", 5), kindAPIKey, newToken(tagAPIKey))

		const insertKey = "INSERT INTO api_keys (id, user_id, name, scope) VALUES (?, ?, 'k', ?)"

		for name, tt := range map[string]struct {
			scope string
			want  bool
		}{
			"an empty list":         {"[]", false},
			"1024 bytes":            {strings.Repeat("a", 1024), false},
			"1025 bytes":            {strings.Repeat("a", 1025), true},
			"empty":                 {"", true},
			"a NUL then more bytes": {"a\x00" + strings.Repeat("b", 2000), true},
			"only a NUL":            {"\x00", true},
			"256 four-byte letters": {strings.Repeat("😀", 256), false},
			"257 four-byte letters": {strings.Repeat("😀", 257), true},
			"513 two-byte letters":  {strings.Repeat("é", 513), true},
		} {
			if got := refused(t, insertKey, idN("0f30", 5), idUserB, tt.scope); got != tt.want {
				t.Errorf("%s: refused = %v, want %v", name, got, tt.want)
			}
		}
	})
}

// TestSchemaDeletionGoesBothWays: a secret and its kind's row exist together
// and are removed together, whichever side the delete starts from, and however
// far above them it starts. A foreign key cascades from the secret down to its
// row; a trigger on each kind's table removes the secret when its row goes,
// which is how a delete of a user, a passkey or an agent reaches the secrets
// behind the sessions and keys it removes.
//
//nolint:paralleltest // shares one database
func TestSchemaDeletionGoesBothWays(t *testing.T) {
	// seedSet makes one of each kind of secret, each under a fresh id family, and
	// returns the ids: invitation (no accounts), session, user key, agent key.
	type set struct{ invitation, session, key, agentKey, agent string }

	seedSet := func(t *testing.T) set {
		t.Helper()

		schemaWorld(t)

		out := set{
			invitation: idN("0f40", 1), session: idN("0f40", 2), key: idN("0f40", 3), agentKey: idN("0f40", 4),
			agent: idN("0f40", 5),
		}

		seedInvitation(t, out.invitation, 1)
		seedSession(t, out.session, idUserB)
		seedAPIKey(t, out.key, idUserB, "")
		seedAgent(t, out.agent, idUserB, "bot")
		seedAPIKey(t, out.agentKey, idUserB, out.agent)

		return out
	}

	// gone says that the secret and the kind's row of each id are both absent.
	gone := func(t *testing.T, ids ...string) {
		t.Helper()

		for _, id := range ids {
			expectCount(t, "secrets WHERE id = ?", "0", id)

			for _, table := range []string{tableInvitations, tableSessions, tableKeys} {
				expectCount(t, table+" WHERE id = ?", "0", id)
			}
		}
	}

	// intact says that the secret and the kind's row of the id are both there.
	intact := func(t *testing.T, ids ...string) {
		t.Helper()

		for _, id := range ids {
			expectCount(t, "secrets WHERE id = ?", "1", id)
			expectCount(t, "(SELECT id FROM invitations UNION ALL SELECT id FROM sessions UNION ALL SELECT id FROM api_keys) WHERE id = ?", "1", id)
		}
	}

	t.Run("deleting a secret deletes its kind's row", func(t *testing.T) {
		for _, kind := range []string{"invitation", "session", "key", "agentKey"} {
			ids := seedSet(t)
			id := map[string]string{"invitation": ids.invitation, "session": ids.session, "key": ids.key, "agentKey": ids.agentKey}[kind]

			seed(t, "DELETE FROM secrets WHERE id = ?", id)

			gone(t, id)

			rest := []string{ids.invitation, ids.session, ids.key, ids.agentKey}
			for _, other := range rest {
				if other != id {
					intact(t, other)
				}
			}
		}
	})

	t.Run("deleting a kind's row deletes its secret", func(t *testing.T) {
		for table, pick := range map[string]func(set) string{
			tableInvitations: func(s set) string { return s.invitation },
			tableSessions:    func(s set) string { return s.session },
			tableKeys:        func(s set) string { return s.key },
		} {
			ids := seedSet(t)
			id := pick(ids)

			seed(t, "DELETE FROM "+table+" WHERE id = ?", id)

			gone(t, id)
		}
	})

	t.Run("deleting a user deletes its sessions, keys and their secrets", func(t *testing.T) {
		ids := seedSet(t)

		seedUser(t, idUserC, roleMember)
		seedSession(t, idN("0f40", 9), idUserC)
		seedAPIKey(t, idN("0f40", 10), idUserC, "")

		seed(t, "DELETE FROM users WHERE id = ?", idUserB)

		gone(t, ids.session, ids.key, ids.agentKey)
		expectCount(t, "agents WHERE user_id = ?", "0", idUserB)
		expectCount(t, "credentials WHERE user_id = ?", "0", idUserB)

		// The invitation does not belong to the user, and the bystander does not
		// either.
		intact(t, ids.invitation, idN("0f40", 9), idN("0f40", 10))
		expectCount(t, "secrets", "4") // both invitations and the bystander's session and key

		expectNoOrphanSecrets(t)
	})

	t.Run("deleting a passkey deletes its sessions and their secrets", func(t *testing.T) {
		ids := seedSet(t)
		seedSession(t, idN("0f40", 6), idUserB)

		seed(t, "DELETE FROM credentials WHERE id = ?", ids.session)

		gone(t, ids.session)
		intact(t, ids.invitation, ids.key, ids.agentKey, idN("0f40", 6))
		expectNoOrphanSecrets(t)
	})

	t.Run("deleting an agent deletes its keys and their secrets", func(t *testing.T) {
		ids := seedSet(t)

		seed(t, "DELETE FROM agents WHERE id = ?", ids.agent)

		gone(t, ids.agentKey)
		intact(t, ids.invitation, ids.session, ids.key)
		expectNoOrphanSecrets(t)
	})

	t.Run("an invitation that has accounts cannot be deleted", func(t *testing.T) {
		schemaWorld(t)

		// The account of schemaWorld came from idInvitationA.
		if !refused(t, "DELETE FROM invitations WHERE id = ?", idInvitationA) {
			t.Error("deleting an invitation with an account was accepted")
		}

		// Nor from the secret side, whose cascade would reach the invitation.
		if !refused(t, "DELETE FROM secrets WHERE id = ?", idInvitationA) {
			t.Error("deleting the secret of an invitation with an account was accepted")
		}

		intact(t, idInvitationA)
		expectCount(t, "users WHERE invitation_id = ?", "1", idInvitationA)
	})

	t.Run("an invitation that has no accounts can be deleted, with its secret", func(t *testing.T) {
		schemaWorld(t)
		seedInvitation(t, idInvitationB, 1)

		seed(t, "DELETE FROM invitations WHERE id = ?", idInvitationB)

		gone(t, idInvitationB)
		intact(t, idInvitationA)
	})

	t.Run("deleting the creator of an invitation keeps it, with no creator", func(t *testing.T) {
		schemaWorld(t)
		invInsert(t, idInvitationB, "made by B", 1, 1, nil, nil, new(idUserB))

		seed(t, "DELETE FROM users WHERE id = ?", idUserB)

		intact(t, idInvitationB)
		expectCount(t, "invitations WHERE id = ? AND created_by IS NULL", "1", idInvitationB)
	})
}
