package store_test

import (
	"regexp"
	"testing"
)

// userSchemaBounds are the user operations' bounds against the migrations (see
// schema_test.go for how a row reads). The accounts' profile is written by
// registration and is only read here. What these operations write are the times
// of revoked_at, which the schema does not constrain, and what they bind is the
// admin role the caller names: it is compared with users.role and never
// stored, so it must be a value users.role can hold.
func userSchemaBounds() []bound {
	return []bound{
		// The role is bound in the last-admin guard. The upper bound is the
		// length of the admin role ("admin", which the auth layer defines and
		// this package cannot import); the lower is that of any role.
		{name: "user role length", pattern: `length\(role\) BETWEEN (\d+) AND (\d+)`,
			lowest: 1, highest: len(userAdminRole), exact: false},

		// Every column the revoke statements set exists on its table, and is
		// not NOT NULL: NULL is "not revoked", which the guard relies on.
		{name: "users.revoked_at is a nullable integer",
			pattern: `CREATE TABLE users \(.*?revoked_at INTEGER, created_at INTEGER NOT NULL \)`,
			lowest:  0, highest: 0, exact: false},
	}
}

// TestUserBoundsFitTheSchema holds that the role the revoke guard binds fits the
// schema's CHECK of users.role, and that the revocation columns the user
// statements write are in the migrations.
func TestUserBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	for _, b := range userSchemaBounds() {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()

			matches := regexp.MustCompile(b.pattern).FindAllStringSubmatch(text, -1)
			if len(matches) == 0 {
				t.Fatalf("no CHECK matches %s; was the migration text changed?", b.pattern)
			}

			for _, match := range matches {
				checkBound(t, b, match[1:])
			}
		})
	}
}
