package store_test

import (
	"regexp"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file is the seam between the kinds of secret in Go and the schema. Each
// kind has a constant bound as a query argument, and a table whose kind column
// is fixed to the same text by a CHECK, and whose delete trigger removes only a
// secret of that kind. Nothing but this test compares the two, and a mismatch
// shows up only as a foreign key refusing every write of that kind.
//
// Like schema_test.go it reads the migration's text and cannot run SQL. What the
// constraints do when executed (a key row attaching to a session's secret, the
// cascade through the trigger, a refused delete of an invitation with accounts)
// is checked by the e2e tests against the real database.

// kindTables is every kind of secret with the table that holds its own row.
func kindTables() []struct{ table, kind string } {
	return []struct{ table, kind string }{
		{table: "invitations", kind: store.KindInvitation},
		{table: "sessions", kind: store.KindSession},
		{table: "api_keys", kind: store.KindAPIKey},
	}
}

// tableBody returns the text of a CREATE TABLE statement's column list, from the
// migration with comments removed and whitespace collapsed.
func tableBody(t *testing.T, text, table string) string {
	t.Helper()

	match := regexp.MustCompile(`CREATE TABLE ` + table + ` \((.*?) \);`).FindStringSubmatch(text)
	if match == nil {
		t.Fatalf("no CREATE TABLE %s in the migrations", table)
	}

	return match[1]
}

// TestKindsMatchTheMigration holds that, for each kind, the Go constant is
// exactly the literal the kind's table fixes in its DEFAULT and its CHECK, that
// the table's foreign key to the secret is on the id and the kind together, and
// that the trigger that deletes the secret with the kind's row deletes only a
// secret of that kind.
func TestKindsMatchTheMigration(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	for _, test := range kindTables() {
		t.Run(test.table, func(t *testing.T) {
			t.Parallel()

			body := tableBody(t, text, test.table)

			want := `kind TEXT NOT NULL DEFAULT '` + test.kind + `' CHECK \(kind = '` + test.kind + `'\)`
			if !regexp.MustCompile(want).MatchString(body) {
				t.Errorf("%s does not fix its kind to %q in DEFAULT and CHECK:\n%s", test.table, test.kind, body)
			}

			if !regexp.MustCompile(`FOREIGN KEY \(id, kind\) REFERENCES secrets \(id, kind\) ON DELETE CASCADE`).
				MatchString(body) {
				t.Errorf("%s is not bound to its secret by the id and the kind together:\n%s", test.table, body)
			}

			trigger := `CREATE TRIGGER ` + test.table + `_delete_secret AFTER DELETE ON ` + test.table +
				` BEGIN DELETE FROM secrets WHERE id = OLD.id AND kind = '` + test.kind + `'; END;`
			if !regexp.MustCompile(regexp.QuoteMeta(trigger)).MatchString(text) {
				t.Errorf("no trigger %q in the migrations", trigger)
			}
		})
	}
}

// TestKindsAreTheOnlyOnes holds the table above to the schema: every table that
// is bound to a secret by a foreign key on the id and the kind is in it, so a new
// kind of secret cannot be added without its constant being compared here, the
// kinds are distinct, and the base table itself does not list the values (Go
// owns that set; each kind's table fixes its own).
func TestKindsAreTheOnlyOnes(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	bound := regexp.MustCompile(`FOREIGN KEY \(id, kind\) REFERENCES secrets \(id, kind\)`).FindAllString(text, -1)
	if len(bound) != len(kindTables()) {
		t.Errorf("%d tables are bound to a secret's kind, and %d are compared with a constant", len(bound), len(kindTables()))
	}

	triggers := regexp.MustCompile(`CREATE TRIGGER \w+_delete_secret AFTER DELETE ON`).FindAllString(text, -1)
	if len(triggers) != len(kindTables()) {
		t.Errorf("%d delete triggers, want one for each of the %d kinds", len(triggers), len(kindTables()))
	}

	seen := map[string]bool{}

	for _, test := range kindTables() {
		if seen[test.kind] {
			t.Errorf("kind %q is used by two tables", test.kind)
		}

		seen[test.kind] = true
	}

	secrets := tableBody(t, text, "secrets")
	if regexp.MustCompile(`kind\s*(=|IN|GLOB|LIKE)`).MatchString(secrets) {
		t.Errorf("secrets constrains the values of kind; Go owns that set:\n%s", secrets)
	}
}

// TestSecretSchemaShape holds the parts of the schema that the store's SQL
// depends on and that no Go value can show: the uniqueness that makes a hash
// collision and a login replay fail an insert, the NOT NULL columns that turn a
// conditional insert that matched nothing into a failed batch, and the foreign
// keys that make deleting an invitation with accounts refuse.
func TestSecretSchemaShape(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	tests := []struct {
		name    string
		pattern string
	}{
		{name: "a token's hash is unique", pattern: `CREATE TABLE secrets \(.*? hash BLOB NOT NULL UNIQUE CHECK`},
		{name: "(id, kind) is a foreign key target", pattern: `CREATE TABLE secrets \(.*? UNIQUE \(id, kind\) \);`},
		{name: "every secret expires", pattern: `CREATE TABLE secrets \(.*? expires_at INTEGER NOT NULL,`},
		{name: "revocation is a nullable time", pattern: `CREATE TABLE secrets \(.*? revoked_at INTEGER, created_at`},
		{name: "a login challenge is used once", pattern: `granted_from BLOB NOT NULL UNIQUE CHECK`},
		{name: "a session's account is NOT NULL: no account, no session",
			pattern: `CREATE TABLE sessions \(.*? user_id TEXT NOT NULL REFERENCES users \(id\) ON DELETE CASCADE,`},
		{name: "a session's passkey cascades",
			pattern: `CREATE TABLE sessions \(.*? credential_id TEXT NOT NULL REFERENCES credentials \(id\) ON DELETE CASCADE,`},
		{name: "a key's account is NOT NULL: no agent, no key",
			pattern: `CREATE TABLE api_keys \(.*? user_id TEXT NOT NULL REFERENCES users \(id\) ON DELETE CASCADE,`},
		{name: "a user's own key has no agent",
			pattern: `CREATE TABLE api_keys \(.*? agent_id TEXT REFERENCES agents \(id\) ON DELETE CASCADE,`},
		{name: "a key's scope is required", pattern: `CREATE TABLE api_keys \(.*? scope TEXT NOT NULL CHECK`},
		{name: "an invitation with accounts cannot be deleted",
			pattern: `invitation_id TEXT NOT NULL REFERENCES invitations \(id\),`},
		{name: "an invitation's creator may be gone",
			pattern: `created_by TEXT REFERENCES users \(id\) ON DELETE SET NULL,`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if !regexp.MustCompile(test.pattern).MatchString(text) {
				t.Errorf("no declaration matches %s; was the migration text changed?", test.pattern)
			}
		})
	}
}
