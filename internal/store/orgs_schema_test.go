package store_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file extends the seam of schema_test.go to the organization tables, with
// that file's bound table and checks. orgs.name bounds BYTES and refuses NUL
// like agents.name; orgs.kind and org_offers.role are open-ended text that Go
// owns (docs/DATABASE.md), so only their size is checked, against the longest
// value the parsers accept. Like the other schema tests it reads the
// migrations' text and cannot run SQL: what the constraints do when executed is
// checked by the e2e tests against the real database.

// orgWorstName is the longest OrgName by bytes: the most runes the parser
// allows, each of the longest UTF-8 form.
func orgWorstName(t *testing.T) input.OrgName {
	t.Helper()

	name, err := input.ParseOrgName(strings.Repeat("\U00010000", input.MaxOrgNameRunes))
	if err != nil {
		t.Fatalf("parse the longest organization name: %v", err)
	}

	return name
}

// longestAndShortest returns the lengths of the shortest and longest of values.
func longestAndShortest(values []string) (int, int) {
	lowest, highest := len(values[0]), len(values[0])

	for _, value := range values {
		lowest, highest = min(lowest, len(value)), max(highest, len(value))
	}

	return lowest, highest
}

// orgSchemaBounds lists the organization columns' Go values with the CHECK each
// must fit inside. Each pattern starts at its table, so it matches only that
// column.
func orgSchemaBounds(t *testing.T) []bound {
	t.Helper()

	lowestKind, highestKind := longestAndShortest(input.OrgKinds())
	lowestRole, highestRole := longestAndShortest(input.OrgRoles())

	return []bound{
		{name: "orgs.name bytes",
			pattern: `CREATE TABLE orgs \(.*? name TEXT NOT NULL CHECK \(typeof\(name\) = 'text' ` +
				`AND instr\(name, char\(0\)\) = 0 AND length\(cast\(name AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)`,
			lowest: 1, highest: len(orgWorstName(t).String()), exact: false},
		{name: "orgs.kind length",
			pattern: `CREATE TABLE orgs \(.*? kind TEXT NOT NULL CHECK \(typeof\(kind\) = 'text' ` +
				`AND length\(kind\) BETWEEN (\d+) AND (\d+)\)`,
			lowest: lowestKind, highest: highestKind, exact: false},
		{name: "org_offers.role length",
			pattern: `CREATE TABLE org_offers \(.*? role TEXT NOT NULL CHECK \(typeof\(role\) = 'text' ` +
				`AND length\(role\) BETWEEN (\d+) AND (\d+)\)`,
			lowest: lowestRole, highest: highestRole, exact: false},
	}
}

// TestOrgBoundsFitTheSchema holds that every value Go can send for an
// organization fits its CHECK.
func TestOrgBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	for _, b := range orgSchemaBounds(t) {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()

			matches := regexp.MustCompile(b.pattern).FindAllStringSubmatch(text, -1)
			if len(matches) != 1 {
				t.Fatalf("%d CHECKs match %s, want exactly one; was the migration text changed?", len(matches), b.pattern)
			}

			checkBound(t, b, matches[0][1:])
		})
	}
}

// TestOrgBoundsAreMeaningful guards the table above against a pattern that
// matches but proves nothing: the worst name must really be the largest the
// parser accepts, and the parser must refuse the NUL the CHECK refuses.
func TestOrgBoundsAreMeaningful(t *testing.T) {
	t.Parallel()

	if got, want := len(orgWorstName(t).String()), input.MaxOrgNameRunes*4; got != want {
		t.Errorf("worst-case organization name is %d bytes, want %d", got, want)
	}

	_, err := input.ParseOrgName(strings.Repeat("\U00010000", input.MaxOrgNameRunes+1))
	if err == nil {
		t.Error("a name of one rune more than the maximum was accepted")
	}

	for _, raw := range []string{"\x00", "x\x00y", "org\x00" + strings.Repeat("x", 4096)} {
		_, err = input.ParseOrgName(raw)
		if err == nil {
			t.Errorf("a name holding NUL was accepted: %q", raw[:min(len(raw), 8)])
		}
	}
}

// TestOrgKindsMatchTheMigration holds that each Go constant is exactly the
// literal the schema writes where the value is an invariant: the kind a user
// may belong to, the kind an agent may be confined to, the kind an offer may be
// for, and the two kinds' own rules.
func TestOrgKindsMatchTheMigration(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	tests := []struct {
		name    string
		pattern string
	}{
		{"a user belongs only to a standard organization",
			`org_kind TEXT NOT NULL DEFAULT '` + store.OrgKindStandard + `' ` +
				`CHECK \(org_kind = '` + store.OrgKindStandard + `'\)`},
		{"an agent is confined only to a sandbox",
			`sandbox_kind TEXT NOT NULL DEFAULT '` + store.OrgKindSandbox + `' ` +
				`CHECK \(sandbox_kind = '` + store.OrgKindSandbox + `'\)`},
		{"an offer is only for a standard organization",
			`CREATE TABLE org_offers \(.*? kind TEXT NOT NULL DEFAULT '` + store.OrgKindStandard +
				`' CHECK \(kind = '` + store.OrgKindStandard + `'\)`},
		{"a sandbox expires and is never revoked",
			`CHECK \(kind <> '` + store.OrgKindSandbox + `' OR \(expires_at IS NOT NULL AND revoked_at IS NULL\)\)`},
		{"a standard organization does not expire",
			`CHECK \(kind <> '` + store.OrgKindStandard + `' OR expires_at IS NULL\)`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if !regexp.MustCompile(test.pattern).MatchString(text) {
				t.Errorf("no declaration matches %s; was the migration text changed?", test.pattern)
			}
		})
	}

	// The constants are the parsers' values, so a client's spelling and the
	// store's binding cannot differ.
	if store.OrgKindStandard != input.OrgKindStandard || store.OrgKindSandbox != input.OrgKindSandbox ||
		store.OfferRoleMember != input.OrgRoleMember || store.OfferRoleAdmin != input.OrgRoleAdmin {
		t.Error("a store constant differs from the value the input parser accepts")
	}
}

// TestOrgSchemaShape holds the parts of the schema that the store's SQL depends
// on and that no Go value can show: the keys that keep a user in a standard
// organization and an agent in a sandbox, the cascade that deletes a sandbox's
// agents, the absence of one on everything a standard organization holds, the
// uniqueness that stops a second offer, and the NOT NULL columns that turn a
// conditional insert that matched nothing into a failed batch.
func TestOrgSchemaShape(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	tests := []struct {
		name    string
		pattern string
	}{
		{"an organization's kind and id are a foreign key target", `CREATE TABLE orgs \(.*? UNIQUE \(id, kind\) \);`},
		{"an organization's creator is required and is never deleted",
			`CREATE TABLE orgs \(.*? created_by TEXT NOT NULL REFERENCES users \(id\),`},
		{"a user's membership is on the id and the kind, with no ON DELETE action",
			`FOREIGN KEY \(org_id, org_kind\) REFERENCES orgs \(id, kind\) \);`},
		{"a user may belong to none", `org_id TEXT, org_kind TEXT NOT NULL`},
		{"an agent's sandbox is on the id and the kind and cascades",
			`FOREIGN KEY \(sandbox_id, sandbox_kind\) REFERENCES orgs \(id, kind\) ON DELETE CASCADE`},
		{"an agent may belong to none", `sandbox_id TEXT, sandbox_kind TEXT NOT NULL`},
		{"an administrator is one row per user and organization",
			`CREATE TABLE org_admins \(.*? PRIMARY KEY \(org_id, user_id\) \) WITHOUT ROWID;`},
		{"an administrator row dies with its organization",
			`CREATE TABLE org_admins \( org_id TEXT NOT NULL REFERENCES orgs \(id\) ON DELETE CASCADE,`},
		{"an administrator row dies with its user",
			`user_id TEXT NOT NULL REFERENCES users \(id\) ON DELETE CASCADE, created_at`},
		{"an offer is for a user or an invitation, not both and not neither",
			`CHECK \(\(user_id IS NULL\) <> \(invitation_id IS NULL\)\)`},
		{"a user is offered an organization once", `CREATE TABLE org_offers \(.*? UNIQUE \(org_id, user_id\),`},
		{"an invitation carries one offer, which dies with it",
			`invitation_id TEXT UNIQUE REFERENCES invitations \(id\) ON DELETE CASCADE`},
		{"an offer to a user dies with the user",
			`CREATE TABLE org_offers \(.*? user_id TEXT REFERENCES users \(id\) ON DELETE CASCADE,`},
		{"an offer's organization has no ON DELETE action",
			`FOREIGN KEY \(org_id, kind\) REFERENCES orgs \(id, kind\) \);`},
		{"an offer has a creator and a role",
			`role TEXT NOT NULL CHECK .*? created_by TEXT NOT NULL REFERENCES users \(id\),`},
		// Ending in id, the members' sort key and cursor, so a page of them is read
		// in order without sorting the whole organization.
		{"the members of an organization are indexed in the order they are listed",
			`CREATE INDEX users_org_id ON users \(org_id, id\) WHERE org_id IS NOT NULL;`},
		{"the agents of a sandbox are indexed",
			`CREATE INDEX agents_sandbox_id ON agents \(sandbox_id\) WHERE sandbox_id IS NOT NULL;`},
		{"the creation limits are indexed",
			`CREATE INDEX orgs_created_by ON orgs \(created_by, kind, expires_at\);`},
		{"the administrators of a user are indexed", `CREATE INDEX org_admins_user_id ON org_admins \(user_id\);`},
		{"the offers of a user are indexed",
			`CREATE INDEX org_offers_user_id ON org_offers \(user_id\) WHERE user_id IS NOT NULL;`},
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
