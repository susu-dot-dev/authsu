//go:build e2e

//nolint:goconst,funlen,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// orgs_schema_test.go holds the constraints of migrations/0001_schema.sql that
// belong to the organizations design (docs/orgs_design.md): what an
// organization, an administrator and the organization an invitation names may
// hold, which kind of organization a user and an agent may point at, and what
// deleting one removes.
//
// Like schema_test.go these are schema tests and not behaviour tests: no request
// goes to the Worker. The store's unit tests can only read the migration's
// text, so whether a composite foreign key refuses a user pointing at a
// sandbox, whether SQLite treats a NULL in a UNIQUE as distinct, and above all
// whether deleting a sandbox reaches an agent's keys, labels and OAuth grants
// and the secrets behind them without D1's trigger-depth limit refusing it, are
// facts that only running the statements shows. They go through db_test.go for
// every statement, and each test starts from reset.
//
// REVIEW.md categories covered: permission confusion (a user is never in a
// sandbox, an agent never in a standard organization, an invitation never naming a
// sandbox), type and bound confusion (the CHECKs at their bounds and one past,
// text against BLOB, NUL), and the database half of interleaving (a delete from
// either side leaves nothing dangling and no secret without its row).

import (
	"strings"
	"testing"
	"time"
)

// The kinds of organization as the schema fixes them.
const (
	schemaKindStandard = "standard"
	schemaKindSandbox  = "sandbox"
)

// Families of ids of the organization schema tests.
const (
	famOrg      = "0f80"
	famSandbox  = "0f81"
	famAdmin    = "0f82"
	famAgent    = "0f84"
	famKey      = "0f85"
	famGrant    = "0f86"
	famAccess   = "0f87"
	famDeletion = "0f89"
)

// orgSchemaWorld resets the deployment and seeds the accounts the organization
// rows refer to: idUserB, idUserC and an invitation that has no accounts, so
// that it can also be deleted.
func orgSchemaWorld(t *testing.T) {
	t.Helper()

	schemaWorld(t)
	seedUser(t, idUserC, roleMember)
	seedInvitation(t, idInvitationB, 5)
}

// insertOrg is an organization's row with every column given: id, kind, name,
// created_by, expires_at, created_at.
const insertOrg = "INSERT INTO orgs (id, kind, name, created_by, expires_at, created_at) " +
	"VALUES (?, ?, ?, ?, ?, ?)"

// orgArgs are the arguments of a well-formed standard organization, id
// idN(famOrg, 1), for insertOrg, changed by mutate.
func orgArgs(mutate func(args []any)) []any {
	args := []any{idN(famOrg, 1), schemaKindStandard, "Acme", idUserB, nil, int64(1_700_000_000)}

	mutate(args)

	return args
}

// sandboxArgs are the arguments of a well-formed sandbox, id idN(famSandbox, 1),
// for insertOrg, changed by mutate. It expires a week from the real clock the
// Worker reads, so a test that needs a live sandbox gets one, and the schema
// itself does not look at the clock.
func sandboxArgs(mutate func(args []any)) []any {
	now := time.Now()
	args := []any{
		idN(famSandbox, 1), schemaKindSandbox, "Scratch", idUserB, now.Add(7 * 24 * time.Hour).Unix(), now.Unix(),
	}

	mutate(args)

	return args
}

// seedOrg inserts a standard organization created by idUserB.
func seedOrg(t *testing.T, id string) {
	t.Helper()

	seed(t, insertOrg, orgArgs(func(a []any) { a[0] = id })...)
}

// seedSandbox inserts a sandbox created by creator that expires in a week, and
// makes the creator its administrator.
func seedSandbox(t *testing.T, id, creator string) {
	t.Helper()

	seed(t, insertOrg, sandboxArgs(func(a []any) { a[0], a[3] = id, creator })...)
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, strftime('%s','now'))", id, creator)
}

// TestSchemaOrgs: the backstop CHECKs and keys of orgs against the real SQLite,
// each at its bound and one past it. The two kinds are told apart by what they
// must and must not hold (a sandbox expires, a standard organization never
// does), the name is bounded in bytes and refuses NUL
// (length() on TEXT stops at one), and the creator is required and is a real
// account.
//
//nolint:paralleltest // shares one database
func TestSchemaOrgs(t *testing.T) {
	orgSchemaWorld(t)
	seedOrg(t, idN(famOrg, 2))

	// The positions of the columns in orgArgs.
	const (
		id = iota
		kind
		name
		creator
		expires
		created
	)

	standard := func(column int, value any) []any { return orgArgs(func(a []any) { a[column] = value }) }
	sandbox := func(column int, value any) []any { return sandboxArgs(func(a []any) { a[column] = value }) }

	tests := []struct {
		name string
		args []any
		want bool // refused
	}{
		{"a well-formed standard organization", orgArgs(func([]any) {}), false},
		{"a well-formed sandbox", sandboxArgs(func([]any) {}), false},

		// The rules that define each kind.
		{"a sandbox with no expiry", sandbox(expires, nil), true},
		{"a sandbox that has already expired", sandbox(expires, int64(1)), false},
		{"a standard organization with an expiry", standard(expires, int64(1_700_600_000)), true},
		{"a standard organization expiring at the epoch", standard(expires, int64(0)), true},
		// Go owns the set of kinds, so a kind the code does not know is the code's
		// to refuse, and the two rules above do not apply to it.
		{"a kind the schema has no rule for", standard(kind, "other"), false},
		{"an empty kind", standard(kind, ""), true},
		{"a kind of 64 characters", standard(kind, strings.Repeat("k", 64)), false},
		{"a kind of 65 characters", standard(kind, strings.Repeat("k", 65)), true},
		{"a kind that is a blob", standard(kind, []byte("standard")), true},
		{"a kind in another case is not a standard organization", standard(kind, "STANDARD"), false},
		{"a sandbox kind in another case has no expiry rule", sandbox(kind, "SANDBOX"), false},
		{"no kind", standard(kind, nil), true},

		// name: bytes, never NUL.
		{"a name of 1024 bytes", standard(name, strings.Repeat("a", 1024)), false},
		{"a name of 1025 bytes", standard(name, strings.Repeat("a", 1025)), true},
		{"a name of 256 four-byte characters", standard(name, strings.Repeat("😀", 256)), false},
		{"a name of 257 four-byte characters", standard(name, strings.Repeat("😀", 257)), true},
		{"a name of 513 two-byte characters", standard(name, strings.Repeat("é", 513)), true},
		{"a name of one byte", standard(name, "a"), false},
		{"an empty name", standard(name, ""), true},
		{"only a NUL as the name", standard(name, "\x00"), true},
		{"a name of a NUL then megabytes", standard(name, "a\x00"+strings.Repeat("b", 4096)), true},
		{"a name that is a blob", standard(name, []byte("Acme")), true},
		{"no name", standard(name, nil), true},

		// The identity and creation.
		{"an id of 35 characters", standard(id, idN(famOrg, 1)[1:]), true},
		{"an id in upper case", standard(id, strings.ToUpper(idN(famOrg, 1))), true},
		{"an id that is already used", standard(id, idN(famOrg, 2)), true},
		{"an id that is a sandbox's too", sandbox(id, idN(famOrg, 2)), true},
		{"no creator", standard(creator, nil), true},
		{"a creator that is not an account", standard(creator, idMissing), true},
		{"no creation time", standard(created, nil), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refused(t, insertOrg, tt.args...); got != tt.want {
				t.Errorf("refused = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("an organization's creator cannot be deleted", func(t *testing.T) {
		// Accounts are revoked and never deleted, and what an organization's
		// creator made stays answerable: no ON DELETE action. Only when the
		// organizations it created go with it can the account be deleted.
		if !refused(t, "DELETE FROM users WHERE id = ?", idUserB) {
			t.Error("deleting the creator of an organization was accepted")
		}

		err := inTx(t,
			sqlStmt("DELETE FROM orgs WHERE created_by = ?", idUserB), sqlStmt("DELETE FROM users WHERE id = ?", idUserB))
		if err != nil {
			t.Errorf("deleting an account with the organizations it created was refused: %v", err)
		}
	})
}

// TestSchemaUsersBelongOnlyToAStandardOrganization: users.org_id points at an
// organization by its id and the kind 'standard' together, so an account belongs
// to a standard organization and to nothing else: not a sandbox, not an
// organization that does not exist, and not none, because the column is NOT NULL.
// The key is deferred, so what the commit would refuse is read from the
// transaction's violations (refused), and a transaction that writes an account and
// its organization together is accepted in either order.
//
//nolint:paralleltest // shares one database
func TestSchemaUsersBelongOnlyToAStandardOrganization(t *testing.T) {
	orgSchemaWorld(t)
	seedOrg(t, idN(famOrg, 1))
	seedSandbox(t, idN(famSandbox, 1), idUserB)

	const join = "UPDATE users SET org_id = ? WHERE id = ?"

	const born = "INSERT INTO users (id, user_handle, role, invitation_id, org_id, created_at) " +
		"VALUES (?, randomblob(16), 'member', ?, ?, strftime('%s','now'))"

	tests := []struct {
		name  string
		query string
		args  []any
		want  bool // refused
	}{
		{"an account can be set to a standard organization", join, []any{idN(famOrg, 1), idUserC}, false},
		{"an account cannot be set to none", join, []any{nil, idUserC}, true},
		{"an account cannot belong to a sandbox", join, []any{idN(famSandbox, 1), idUserC}, true},
		{"an account cannot belong to a sandbox even its creator's", join, []any{idN(famSandbox, 1), idUserB}, true},
		{"an account cannot belong to an organization that does not exist", join, []any{idMissing, idUserC}, true},
		{"an account cannot take another kind than standard", "UPDATE users SET org_kind = ? WHERE id = ?", []any{schemaKindSandbox, idUserC}, true},
		{"an account cannot take an empty kind", "UPDATE users SET org_kind = ? WHERE id = ?", []any{"", idUserC}, true},
		{"an account cannot take a kind in another case", "UPDATE users SET org_kind = ? WHERE id = ?", []any{"STANDARD", idUserC}, true},
		{"an account cannot have no kind", "UPDATE users SET org_kind = NULL WHERE id = ?", []any{idUserC}, true},
		{"an account's kind may be restated", "UPDATE users SET org_kind = ? WHERE id = ?", []any{schemaKindStandard, idUserC}, false},
		{"a new account may be born in a standard organization", born, []any{idN(famDeletion, 1), idInvitationA, idN(famOrg, 1)}, false},
		{"a new account may not be born in a sandbox", born, []any{idN(famDeletion, 1), idInvitationA, idN(famSandbox, 1)}, true},
		{"a new account may not be born in an organization that does not exist", born, []any{idN(famDeletion, 1), idInvitationA, idMissing}, true},
		{"a new account may not be born with no organization", born, []any{idN(famDeletion, 1), idInvitationA, nil}, true},
		{
			"a new account may not be born with no organization given",
			"INSERT INTO users (id, user_handle, role, invitation_id, created_at) " +
				"VALUES (?, randomblob(16), 'member', ?, strftime('%s','now'))",
			[]any{idN(famDeletion, 1), idInvitationA}, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refused(t, tt.query, tt.args...); got != tt.want {
				t.Errorf("refused = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("an account's kind is standard when it was never given", func(t *testing.T) {
		if got := scalar(t, "SELECT org_kind FROM users WHERE id = ?", idUserC); got != schemaKindStandard {
			t.Errorf("org_kind = %q, want %q", got, schemaKindStandard)
		}
	})

	// An account and the organization it creates are written together, as
	// registration writes them: the account first, because the organization's key
	// to its creator is checked at once, and the account's key to the organization
	// at the commit. A transaction that leaves an account without its organization
	// is refused at the commit.
	const personal = "INSERT INTO orgs (id, kind, name, created_by, created_at) VALUES (?, 'standard', 'Own', ?, 1)"

	idNew, idOwn := idN(famDeletion, 2), idN(famOrg, 3)

	t.Run("an account and its own organization are accepted in one transaction", func(t *testing.T) {
		err := inTx(t, sqlStmt(born, idNew, idInvitationA, idOwn), sqlStmt(personal, idOwn, idNew))
		if err != nil {
			t.Errorf("the account and its organization were refused: %v", err)
		}

		expectCount(t, "users WHERE id = ? AND org_id = ?", "1", idNew, idOwn)
	})

	t.Run("an organization cannot be written before its creator", func(t *testing.T) {
		err := inTx(t, sqlStmt(personal, idN(famOrg, 4), idN(famDeletion, 3)),
			sqlStmt(born, idN(famDeletion, 3), idInvitationA, idN(famOrg, 4)))
		if err == nil {
			t.Error("an organization of an account that did not exist yet was accepted")
		}
	})

	t.Run("an account whose organization is never written is refused at the commit", func(t *testing.T) {
		err := inTx(t, sqlStmt(born, idN(famDeletion, 4), idInvitationA, idN(famOrg, 5)))
		if err == nil {
			t.Error("an account without its organization was committed")
		}

		expectCount(t, "users WHERE id = ?", "0", idN(famDeletion, 4))
	})
}

// TestSchemaAgentsAreConfinedOnlyToASandbox: agents.sandbox_id points at an
// organization by its id and the kind 'sandbox' together, so an agent is in a
// sandbox or in none, never in a standard organization (which is not a
// boundary) and never in one that does not exist. The key is ON DELETE CASCADE
// (TestSchemaDeletingASandbox).
//
//nolint:paralleltest // shares one database
func TestSchemaAgentsAreConfinedOnlyToASandbox(t *testing.T) {
	orgSchemaWorld(t)
	seedOrg(t, idN(famOrg, 1))
	seedSandbox(t, idN(famSandbox, 1), idUserB)
	seedAgent(t, idN(famAgent, 1), idUserB, "ordinary")

	const confine = "UPDATE agents SET sandbox_id = ? WHERE id = ?"

	const insertAgent = "INSERT INTO agents (id, user_id, name, scopes, sandbox_id, created_at) " +
		"VALUES (?, ?, 'bot', '[]', ?, strftime('%s','now'))"

	tests := []struct {
		name  string
		query string
		args  []any
		want  bool // refused
	}{
		{"an agent is confined to a sandbox", confine, []any{idN(famSandbox, 1), idN(famAgent, 1)}, false},
		{"an agent is released from its sandbox", confine, []any{nil, idN(famAgent, 1)}, false},
		{"an agent cannot be confined to a standard organization", confine, []any{idN(famOrg, 1), idN(famAgent, 1)}, true},
		{"an agent cannot be confined to a sandbox that does not exist", confine, []any{idMissing, idN(famAgent, 1)}, true},
		{"an agent cannot take another kind than sandbox", "UPDATE agents SET sandbox_kind = ? WHERE id = ?", []any{schemaKindStandard, idN(famAgent, 1)}, true},
		{"an agent cannot take an empty kind", "UPDATE agents SET sandbox_kind = ? WHERE id = ?", []any{"", idN(famAgent, 1)}, true},
		{"an agent cannot have no kind", "UPDATE agents SET sandbox_kind = NULL WHERE id = ?", []any{idN(famAgent, 1)}, true},
		{"an agent's kind may be restated", "UPDATE agents SET sandbox_kind = ? WHERE id = ?", []any{schemaKindSandbox, idN(famAgent, 1)}, false},
		{"a new agent may be born in a sandbox", insertAgent, []any{idN(famAgent, 2), idUserB, idN(famSandbox, 1)}, false},
		{"a new agent may be born in none", insertAgent, []any{idN(famAgent, 2), idUserB, nil}, false},
		{"a new agent may not be born in a standard organization", insertAgent, []any{idN(famAgent, 2), idUserB, idN(famOrg, 1)}, true},
		{"a new agent may not be born in a missing sandbox", insertAgent, []any{idN(famAgent, 2), idUserB, idMissing}, true},
		{"a new agent of another account may be born in the sandbox", insertAgent, []any{idN(famAgent, 2), idUserC, idN(famSandbox, 1)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refused(t, tt.query, tt.args...); got != tt.want {
				t.Errorf("refused = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("an agent's kind is sandbox when it was never given", func(t *testing.T) {
		if got := scalar(t, "SELECT sandbox_kind FROM agents WHERE id = ?", idN(famAgent, 1)); got != schemaKindSandbox {
			t.Errorf("sandbox_kind = %q, want %q", got, schemaKindSandbox)
		}
	})
}

// TestSchemaOrgAdmins: an administrator is a row per (organization, user), of
// a real organization and a real account, and the row dies with either.
//
//nolint:paralleltest // shares one database
func TestSchemaOrgAdmins(t *testing.T) {
	orgSchemaWorld(t)
	seedOrg(t, idN(famOrg, 1))
	seedOrg(t, idN(famOrg, 2))
	seedSandbox(t, idN(famSandbox, 1), idUserB)
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", idN(famOrg, 1), idUserB)

	const insert = "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, ?)"

	tests := []struct {
		name string
		args []any
		want bool // refused
	}{
		{"another account administers the organization", []any{idN(famOrg, 1), idUserC, int64(1)}, false},
		{"the same account administers another organization", []any{idN(famOrg, 2), idUserB, int64(1)}, false},
		{"an account administers a sandbox too", []any{idN(famSandbox, 1), idUserC, int64(1)}, false},
		{"the same account twice in one organization", []any{idN(famOrg, 1), idUserB, int64(1)}, true},
		{"the same account twice in a sandbox", []any{idN(famSandbox, 1), idUserB, int64(1)}, true},
		{"an organization that does not exist", []any{idMissing, idUserC, int64(1)}, true},
		{"an account that does not exist", []any{idN(famOrg, 1), idMissing, int64(1)}, true},
		{"no organization", []any{nil, idUserC, int64(1)}, true},
		{"no account", []any{idN(famOrg, 1), nil, int64(1)}, true},
		{"no creation time", []any{idN(famOrg, 1), idUserC, nil}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refused(t, insert, tt.args...); got != tt.want {
				t.Errorf("refused = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("an administrator row dies with its account", func(t *testing.T) {
		seed(t, insert, idN(famOrg, 2), idUserC, int64(1))
		seedUser(t, idN(famDeletion, 1), roleMember)
		seed(t, insert, idN(famOrg, 2), idN(famDeletion, 1), int64(1))

		deleteAccount(t, idN(famDeletion, 1))

		expectCount(t, "org_admins WHERE user_id = ?", "0", idN(famDeletion, 1))
		expectCount(t, "org_admins WHERE org_id = ?", "1", idN(famOrg, 2))
		expectCount(t, "orgs WHERE id = ?", "1", idN(famOrg, 2))
	})

	t.Run("deleting a standard organization that only has administrators removes their rows", func(t *testing.T) {
		seed(t, "DELETE FROM orgs WHERE id = ?", idN(famOrg, 2))

		expectCount(t, "org_admins WHERE org_id = ?", "0", idN(famOrg, 2))
		expectCount(t, "users WHERE id = ?", "1", idUserC)
		expectCount(t, "org_admins WHERE org_id = ?", "1", idN(famOrg, 1))
	})
}

// insertInvitationOrg is the row of the organization an invitation names, with
// every column given: invitation_id, org_id, kind, role, created_at.
const insertInvitationOrg = "INSERT INTO invitation_orgs (invitation_id, org_id, kind, role, created_at) " +
	"VALUES (?, ?, ?, ?, ?)"

// invitationOrgArgs are the arguments of a well-formed row naming the standard
// organization idN(famOrg, 1) on the invitation idInvitationB, changed by mutate.
func invitationOrgArgs(mutate func(args []any)) []any {
	args := []any{idInvitationB, idN(famOrg, 1), schemaKindStandard, "member", int64(1_700_000_000)}

	mutate(args)

	return args
}

// TestSchemaInvitationOrgs: an invitation names at most one organization, which
// is standard, with a role that is a size-bounded text that Go owns.
//
//nolint:paralleltest // shares one database
func TestSchemaInvitationOrgs(t *testing.T) {
	orgSchemaWorld(t)
	seedOrg(t, idN(famOrg, 1))
	seedOrg(t, idN(famOrg, 2))
	seedSandbox(t, idN(famSandbox, 1), idUserB)
	seed(t, insertInvitationOrg, invitationOrgArgs(func([]any) {})...)

	// The positions of the columns in invitationOrgArgs.
	const (
		invitation = iota
		org
		kind
		role
		created
	)

	with := func(changes map[int]any) []any {
		return invitationOrgArgs(func(a []any) {
			a[invitation] = idInvitationA

			for column, value := range changes {
				a[column] = value
			}
		})
	}

	tests := []struct {
		name string
		args []any
		want bool // refused
	}{
		// The invitation: one organization each.
		{"another invitation naming the same organization", with(nil), false},
		{"another invitation naming another organization", with(map[int]any{org: idN(famOrg, 2)}), false},
		{"a second organization on the invitation that names one",
			with(map[int]any{invitation: idInvitationB, org: idN(famOrg, 2)}), true},
		{"the same organization again on the invitation that names it", with(map[int]any{invitation: idInvitationB}), true},
		{"an invitation that does not exist", with(map[int]any{invitation: idMissing}), true},
		{"no invitation", with(map[int]any{invitation: nil}), true},

		// The organization: standard only.
		{"an organization that does not exist", with(map[int]any{org: idMissing}), true},
		{"a sandbox", with(map[int]any{org: idN(famSandbox, 1)}), true},
		{"a sandbox restating the sandbox kind", with(map[int]any{org: idN(famSandbox, 1), kind: schemaKindSandbox}), true},
		{"a standard organization claiming the sandbox kind", with(map[int]any{kind: schemaKindSandbox}), true},
		{"an empty kind", with(map[int]any{kind: ""}), true},
		{"no kind", with(map[int]any{kind: nil}), true},
		{"no organization", with(map[int]any{org: nil}), true},

		// The role: bounded text, Go's set.
		{"a role of 64 characters", with(map[int]any{role: strings.Repeat("r", 64)}), false},
		{"a role of 65 characters", with(map[int]any{role: strings.Repeat("r", 65)}), true},
		{"an admin role", with(map[int]any{role: "admin"}), false},
		{"a role the code does not know", with(map[int]any{role: "owner"}), false},
		{"an empty role", with(map[int]any{role: ""}), true},
		{"a role that is a blob", with(map[int]any{role: []byte("member")}), true},
		{"no role", with(map[int]any{role: nil}), true},

		{"no creation time", with(map[int]any{created: nil}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refused(t, insertInvitationOrg, tt.args...); got != tt.want {
				t.Errorf("refused = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("the kind is standard when it was never given", func(t *testing.T) {
		const insertDefaulted = "INSERT INTO invitation_orgs (invitation_id, org_id, role, created_at) " +
			"VALUES (?, ?, 'member', 1)"

		if refused(t, insertDefaulted, idInvitationA, idN(famOrg, 1)) {
			t.Error("a row without a kind was refused")
		}

		if !refused(t, insertDefaulted, idInvitationA, idN(famSandbox, 1)) {
			t.Error("a row without a kind, naming a sandbox, was accepted")
		}
	})
}

// TestSchemaOrgDeletion: a standard organization is never deleted, and the
// schema is what stops a delete that would strand anything: members and the
// invitations that name it hold it with no ON DELETE action. What an invitation
// names dies with the invitation, and nothing its removal does touches the
// invitation.
//
//nolint:paralleltest // shares one database
func TestSchemaOrgDeletion(t *testing.T) {
	world := func(t *testing.T) {
		t.Helper()

		orgSchemaWorld(t)
		seedOrg(t, idN(famOrg, 1))
		seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", idN(famOrg, 1), idUserB)
		seed(t, "UPDATE users SET org_id = ? WHERE id = ?", idN(famOrg, 1), idUserB)
	}

	names := func(t *testing.T, invitation string) {
		t.Helper()

		seed(t, insertInvitationOrg, invitationOrgArgs(func(a []any) { a[0] = invitation })...)
	}

	t.Run("an organization with a member cannot be deleted", func(t *testing.T) {
		world(t)

		if !refused(t, "DELETE FROM orgs WHERE id = ?", idN(famOrg, 1)) {
			t.Error("deleting an organization with a member was accepted")
		}

		expectCount(t, "orgs WHERE id = ?", "1", idN(famOrg, 1))
		expectCount(t, "users WHERE org_id = ?", "1", idN(famOrg, 1))
	})

	t.Run("an organization whose members moved out can be deleted", func(t *testing.T) {
		world(t)
		seed(t, "UPDATE users SET org_id = id WHERE org_id = ?", idN(famOrg, 1))

		seed(t, "DELETE FROM orgs WHERE id = ?", idN(famOrg, 1))

		expectCount(t, "orgs WHERE id = ?", "0", idN(famOrg, 1))
		expectCount(t, "org_admins", "0")
		expectCount(t, "users WHERE id = ?", "1", idUserB)
	})

	t.Run("an organization an invitation names cannot be deleted", func(t *testing.T) {
		world(t)
		seed(t, "UPDATE users SET org_id = id")
		names(t, idInvitationB)

		if !refused(t, "DELETE FROM orgs WHERE id = ?", idN(famOrg, 1)) {
			t.Error("deleting an organization an invitation names was accepted")
		}

		expectCount(t, "invitation_orgs", "1")
	})

	t.Run("deleting what an invitation names does not touch its invitation", func(t *testing.T) {
		world(t)
		names(t, idInvitationB)

		seed(t, "DELETE FROM invitation_orgs WHERE invitation_id = ?", idInvitationB)

		expectCount(t, "invitations WHERE id = ?", "1", idInvitationB)
		expectCount(t, "secrets WHERE id = ?", "1", idInvitationB)
	})

	t.Run("deleting an invitation deletes what it names and not the organization", func(t *testing.T) {
		world(t)
		names(t, idInvitationB)

		seed(t, "DELETE FROM invitations WHERE id = ?", idInvitationB)

		expectCount(t, "invitation_orgs", "0")
		expectCount(t, "orgs WHERE id = ?", "1", idN(famOrg, 1))
		expectCount(t, "secrets WHERE id = ?", "0", idInvitationB)
		expectNoOrphanSecrets(t)
	})

	t.Run("deleting an invitation's secret deletes what it names too", func(t *testing.T) {
		world(t)
		names(t, idInvitationB)

		seed(t, "DELETE FROM secrets WHERE id = ?", idInvitationB)

		expectCount(t, "invitations WHERE id = ?", "0", idInvitationB)
		expectCount(t, "invitation_orgs", "0")
		expectCount(t, "orgs WHERE id = ?", "1", idN(famOrg, 1))
		expectNoOrphanSecrets(t)
	})

	t.Run("an invitation that has accounts keeps what it names and cannot be deleted", func(t *testing.T) {
		world(t)
		names(t, idInvitationA)

		if !refused(t, "DELETE FROM invitations WHERE id = ?", idInvitationA) {
			t.Error("deleting an invitation with accounts was accepted")
		}

		expectCount(t, "invitation_orgs", "1")
	})

	t.Run("deleting a member account leaves the organization and its other administrators", func(t *testing.T) {
		world(t)
		seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", idN(famOrg, 1), idUserC)
		seed(t, "UPDATE users SET org_id = ? WHERE id = ?", idN(famOrg, 1), idUserC)

		// idUserB created the organization and cannot be deleted: delete the
		// member that did not, with the organization of its own that it left.
		deleteAccount(t, idUserC)

		expectCount(t, "orgs WHERE id = ?", "1", idN(famOrg, 1))
		expectCount(t, "org_admins WHERE org_id = ?", "1", idN(famOrg, 1))
		expectCount(t, "users WHERE org_id = ?", "1", idN(famOrg, 1))
	})
}

// worldOfSandboxes seeds what the depth test below deletes into, and what it
// must leave alone: the doomed sandbox idN(famSandbox, 1) of idUserB with two
// agents holding keys, labels and OAuth grants with access tokens, the same
// things held by an ordinary agent of idUserB, by a second sandbox of the same
// account, and by a sandbox of another account, a standard organization with
// the account as a member and an administrator, and the account's own session
// and key.
//
// It returns the ids that must be gone after the sandbox is deleted, and the
// ids that must remain.
func worldOfSandboxes(t *testing.T) ([]string, []string) {
	t.Helper()

	orgSchemaWorld(t)
	seedOrg(t, idN(famOrg, 1))
	seed(t, "INSERT INTO org_admins (org_id, user_id, created_at) VALUES (?, ?, 1)", idN(famOrg, 1), idUserB)
	seed(t, "UPDATE users SET org_id = ? WHERE id = ?", idN(famOrg, 1), idUserB)

	doomed, sibling, other := idN(famSandbox, 1), idN(famSandbox, 2), idN(famSandbox, 3)

	seedSandbox(t, doomed, idUserB)
	seedSandbox(t, sibling, idUserB)
	seedSandbox(t, other, idUserC)

	// holdings gives an agent a key, two labels and a grant with an access
	// token, and returns the ids of the secrets behind them.
	holdings := func(agent, sandbox, owner string, n int) []string {
		var sandboxID any
		if sandbox != "" {
			sandboxID = sandbox
		}

		seed(t, "INSERT INTO agents (id, user_id, name, scopes, sandbox_id, created_at) "+
			"VALUES (?, ?, 'bot', '[\"default:agent\"]', ?, strftime('%s','now'))", agent, owner, sandboxID)

		key, grant, access := idN(famKey, n), idN(famGrant, n), idN(famAccess, n)

		seedAPIKey(t, key, owner, agent)
		seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'one'), (?, 'two')", agent, agent)

		seedSecret(t, grant, kindOAuthGrant, newToken("code"))
		seed(t, insertOAuthGrant, oauthGrantArgs(func(a []any) {
			a[0], a[2], a[3], a[12] = grant, owner, agent, tokenHash(grant)
		})...)
		seedOAuthAccess(t, access, grant)

		return []string{agent, key, grant, access}
	}

	gone := append(holdings(idN(famAgent, 1), doomed, idUserB, 1), holdings(idN(famAgent, 2), doomed, idUserB, 2)...)

	kept := make([]string, 0, 14)

	kept = append(kept, holdings(idN(famAgent, 3), "", idUserB, 3)...)
	kept = append(kept, holdings(idN(famAgent, 4), sibling, idUserB, 4)...)
	kept = append(kept, holdings(idN(famAgent, 5), other, idUserC, 5)...)

	seedSession(t, idN(famKey, 9), idUserB)
	seedAPIKey(t, idN(famKey, 8), idUserB, "")

	kept = append(kept, idN(famKey, 9), idN(famKey, 8))

	return gone, kept
}

// TestSchemaDeletingASandbox is the required depth test of the organizations
// design (docs/orgs_design.md, principle 5): deleting a sandbox reaches its
// agents, and from them their keys, labels and OAuth grants with their access
// tokens, and every secret behind them, in the one delete, on the real
// database. It is one cascade deeper than any other delete and relies on the
// four delete triggers there are, and D1 has refused deletes that nest too deep
// before: if this test fails the design is wrong and not the test.
//
// What must stay: the sandbox's administrator and that account's other
// sandboxes, agents, session and key, the other accounts', and the standard
// organization the account belongs to with its administrator rows.
//
//nolint:paralleltest // shares one database
func TestSchemaDeletingASandbox(t *testing.T) {
	t.Run("deleting a sandbox deletes everything that was in it and every secret behind it", func(t *testing.T) {
		gone, kept := worldOfSandboxes(t)

		// seed fails the test if the database refuses the delete.
		seed(t, "DELETE FROM orgs WHERE id = ?", idN(famSandbox, 1))

		expectCount(t, "orgs WHERE id = ?", "0", idN(famSandbox, 1))
		expectCount(t, "agents WHERE sandbox_id = ?", "0", idN(famSandbox, 1))
		expectCount(t, "org_admins WHERE org_id = ?", "0", idN(famSandbox, 1))

		for _, id := range gone {
			expectCount(t, "secrets WHERE id = ?", "0", id)
			expectCount(t, "agents WHERE id = ?", "0", id)
			expectCount(t, "oauth_grants WHERE id = ?", "0", id)
			expectCount(t, "oauth_access_tokens WHERE id = ?", "0", id)
			expectCount(t, "api_keys WHERE id = ?", "0", id)
		}

		expectCount(t, "agent_labels WHERE agent_id IN (?, ?)", "0", idN(famAgent, 1), idN(famAgent, 2))

		// What was not in the sandbox is untouched: each kept id is either a
		// secret that still has its row or an agent that is still there.
		for _, id := range kept {
			if count(t, "secrets WHERE id = ?", id) != "1" && count(t, "agents WHERE id = ?", id) != "1" {
				t.Errorf("%s was deleted with the sandbox, but was not in it", id)
			}
		}

		expectCount(t, "agents WHERE id IN (?, ?, ?)", "3", idN(famAgent, 3), idN(famAgent, 4), idN(famAgent, 5))
		expectCount(t, "agent_labels WHERE agent_id IN (?, ?, ?)", "6", idN(famAgent, 3), idN(famAgent, 4), idN(famAgent, 5))
		expectCount(t, "oauth_grants", "3")
		expectCount(t, "oauth_access_tokens", "3")
		expectCount(t, "api_keys", "4")

		// Its administrator was released, and kept everything of their own.
		expectCount(t, "users WHERE id = ?", "1", idUserB)
		expectCount(t, "users WHERE id = ? AND org_id = ?", "1", idUserB, idN(famOrg, 1))
		expectCount(t, "orgs WHERE id = ?", "1", idN(famOrg, 1))
		expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", idN(famOrg, 1), idUserB)
		expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", idN(famSandbox, 2), idUserB)
		expectCount(t, "org_admins WHERE org_id = ? AND user_id = ?", "1", idN(famSandbox, 3), idUserC)
		expectCount(t, "orgs WHERE kind = ?", "2", schemaKindSandbox) // the sibling and the other account's

		expectNoOrphanSecrets(t)
	})

	t.Run("deleting a sandbox that holds nothing", func(t *testing.T) {
		orgSchemaWorld(t)
		seedSandbox(t, idN(famSandbox, 1), idUserB)

		seed(t, "DELETE FROM orgs WHERE id = ?", idN(famSandbox, 1))

		expectCount(t, "orgs WHERE kind = ?", "0", schemaKindSandbox)
		expectCount(t, "org_admins", "0")
		expectCount(t, "users WHERE id = ?", "1", idUserB)
	})

	t.Run("deleting a sandbox that holds an agent with no keys, labels or grants", func(t *testing.T) {
		orgSchemaWorld(t)
		seedSandbox(t, idN(famSandbox, 1), idUserB)
		seed(t, "INSERT INTO agents (id, user_id, name, scopes, sandbox_id, created_at) "+
			"VALUES (?, ?, 'bot', '[]', ?, strftime('%s','now'))", idN(famAgent, 1), idUserB, idN(famSandbox, 1))

		seed(t, "DELETE FROM orgs WHERE id = ?", idN(famSandbox, 1))

		expectCount(t, "agents", "0")
		expectNoOrphanSecrets(t)
	})

	t.Run("deleting a sandbox deletes the agents of every account in it", func(t *testing.T) {
		// A sandbox is confined to its administrator's agents by the Worker, but
		// the schema lets any account's agent be in it, and the delete must not
		// leave one behind: it would read as an ordinary agent.
		orgSchemaWorld(t)
		seedSandbox(t, idN(famSandbox, 1), idUserB)
		seed(t, "INSERT INTO agents (id, user_id, name, scopes, sandbox_id, created_at) "+
			"VALUES (?, ?, 'bot', '[]', ?, strftime('%s','now'))", idN(famAgent, 1), idUserC, idN(famSandbox, 1))
		seedAPIKey(t, idN(famKey, 1), idUserC, idN(famAgent, 1))

		seed(t, "DELETE FROM orgs WHERE id = ?", idN(famSandbox, 1))

		expectCount(t, "agents WHERE user_id = ?", "0", idUserC)
		expectCount(t, "secrets WHERE id = ?", "0", idN(famKey, 1))
		expectNoOrphanSecrets(t)
	})

	t.Run("deleting the account of an agent in a sandbox deletes the agent and leaves the sandbox", func(t *testing.T) {
		// Accounts are never deleted in practice, and one that created an
		// organization cannot be (orgs.created_by): this holds what the schema
		// does for a delete that is allowed, an account that only owns an agent.
		orgSchemaWorld(t)
		seedSandbox(t, idN(famSandbox, 1), idUserB)
		seed(t, "INSERT INTO agents (id, user_id, name, scopes, sandbox_id, created_at) "+
			"VALUES (?, ?, 'bot', '[]', ?, strftime('%s','now'))", idN(famAgent, 1), idUserC, idN(famSandbox, 1))

		deleteAccount(t, idUserC)

		expectCount(t, "agents", "0")
		expectCount(t, "orgs WHERE id = ?", "1", idN(famSandbox, 1))
		expectCount(t, "org_admins WHERE org_id = ?", "1", idN(famSandbox, 1))
	})
}

// TestSchemaOrgIndexes: the indexes the queries of the organization design rely
// on exist, with the shape the migration gives them: partial where most rows
// have none of the column (agents' sandbox).
//
//nolint:paralleltest // shares one database
func TestSchemaOrgIndexes(t *testing.T) {
	orgSchemaWorld(t)

	tests := []struct {
		index   string
		table   string
		partial bool
		unique  bool
	}{
		{"users_org_id", tableUsers, false, false},
		{"agents_sandbox_id", tableAgents, true, false},
		{"orgs_created_by", tableOrgs, false, false},
		{"org_admins_user_id", tableOrgAdmins, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.index, func(t *testing.T) {
			row, found := firstRow(t,
				"SELECT \"partial\", \"unique\" FROM pragma_index_list(?) WHERE name = ?", tt.table, tt.index)
			if !found {
				t.Fatalf("no index %s on %s", tt.index, tt.table)
			}

			if want := []string{boolText(tt.partial), boolText(tt.unique)}; row[0] != want[0] || row[1] != want[1] {
				t.Errorf("%s: partial, unique = %s, %s; want %s, %s", tt.index, row[0], row[1], want[0], want[1])
			}
		})
	}
}

// boolText is how SQLite reports a flag.
func boolText(v bool) string {
	if v {
		return "1"
	}

	return "0"
}
