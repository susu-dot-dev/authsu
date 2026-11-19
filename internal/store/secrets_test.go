//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	sessionsDescription = "sessions are temporarily unavailable"
	loginDescription    = "login is temporarily unavailable"
)

// sessionRow is the row ResolveSession reads: id, user_id, role, expires_at.
func sessionRow() []any {
	return row("session-1", "user-1", "admin", int64(1_700_000_600))
}

// TestResolveSessionDecoding holds how the row becomes an ActiveSession, and
// that no row is an answer and not an error.
func TestResolveSessionDecoding(t *testing.T) {
	t.Parallel()

	active := store.ActiveSession{
		ID: "session-1", UserID: "user-1", Role: "admin",
		ExpiresAt: time.Unix(1_700_000_600, 0),
	}
	member := active
	member.Role = "member"

	tests := []struct {
		name  string
		rows  [][]any
		want  store.ActiveSession
		found bool
	}{
		{name: "an active session", rows: [][]any{sessionRow()}, want: active, found: true},
		{name: "the role is the account's current one", rows: [][]any{with(sessionRow(), 2, "member")},
			want: member, found: true},
		{name: "unknown, wrong kind, expired, revoked or its account revoked", rows: nil},
		{name: "an empty result", rows: [][]any{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, found, err := fake.store().ResolveSession(context.Background(), mustSessionToken(t, 2), now)

			checkErr(t, err, nil)

			if found != test.found {
				t.Errorf("found = %v, want %v", found, test.found)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("session = %+v, want %+v", got, test.want)
			}
		})
	}
}

// TestResolveSessionDefects holds that a result that is not the row the query
// promises is a defect, and not "no session": resolving must not read a broken
// row as an absent one or as a valid one.
func TestResolveSessionDefects(t *testing.T) {
	t.Parallel()

	for name, rows := range defectResults(sessionRow(), "text", "text", "text", "integer") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(rows...))

			got, found, err := fake.store().ResolveSession(context.Background(), mustSessionToken(t, 2), now)

			checkErr(t, err, defectOf(store.CodeSessionVerifyRejected))

			if found || !reflect.DeepEqual(got, store.ActiveSession{}) {
				t.Errorf("a defective row returned %+v, %v", got, found)
			}
		})
	}
}

// TestResolveSessionStatement pins what makes a session usable and the
// arguments that say for whom. The token is looked up by the hash of the whole
// string, the kind is an argument and is asked for twice over (the secret's, and
// the join to the session's own row on id and kind), the shared predicate decides
// activity, and the account must not be revoked.
func TestResolveSessionStatement(t *testing.T) {
	t.Parallel()

	token := mustSessionToken(t, 2)
	fake := newFake(returning())

	_, _, err := fake.store().ResolveSession(context.Background(), token, now)
	checkErr(t, err, nil)

	checkStatements(t, fake, wantStatement{
		fragments: []string{
			"FROM secrets s",
			"JOIN sessions x ON x.id = s.id AND x.kind = s.kind",
			"JOIN users u ON u.id = x.user_id",
			"WHERE s.hash = ?",
			"AND s.kind = ?",
			"AND " + activeFragment,
			"AND u.revoked_at IS NULL",
			"u.role AS role",
		},
		args: []any{token.Hash(), store.KindSession, now.Unix(), now.Unix()},
	})
}

// TestResolveSessionFailures holds how a failed or malformed batch is reported.
func TestResolveSessionFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeSessionVerifyFailed, store.CodeSessionVerifyRejected, sessionsDescription,
		func(s *store.Store) error {
			return lastErr2(s.ResolveSession(context.Background(), mustSessionToken(t, 1), now))
		})
}

// apiKeyRow is the row ResolveAPIKey reads: id, user_id, role, expires_at,
// agent_id, agent_scopes, scope.
func apiKeyRow() []any {
	return row("key-1", "user-1", "member", int64(1_700_000_600), "", "", `["agent:read"]`)
}

// TestResolveAPIKeyDecoding holds how the row becomes an ActiveAPIKey: a user's
// own key reads no agent, an agent's key reads the agent's id and current scopes,
// and the key's own scope is returned as stored.
func TestResolveAPIKeyDecoding(t *testing.T) {
	t.Parallel()

	own := store.ActiveAPIKey{
		ID: "key-1", UserID: "user-1", Role: "member", ExpiresAt: time.Unix(1_700_000_600, 0),
		AgentID: "", AgentScopes: "", Scope: `["agent:read"]`,
	}
	agent := own
	agent.AgentID, agent.AgentScopes = "agent-1", `["default:agent"]`

	tests := []struct {
		name  string
		rows  [][]any
		want  store.ActiveAPIKey
		found bool
	}{
		{name: "a user's own key", rows: [][]any{apiKeyRow()}, want: own, found: true},
		{name: "an agent's key reads the agent's id and current scopes",
			rows: [][]any{with(with(apiKeyRow(), 4, "agent-1"), 5, `["default:agent"]`)}, want: agent, found: true},
		{name: "unknown, wrong kind, expired, revoked, or its account or agent revoked", rows: nil},
		{name: "an empty result", rows: [][]any{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, found, err := fake.store().ResolveAPIKey(context.Background(), mustAPIKeyToken(t, 2), now)

			checkErr(t, err, nil)

			if found != test.found {
				t.Errorf("found = %v, want %v", found, test.found)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("key = %+v, want %+v", got, test.want)
			}
		})
	}
}

// TestResolveAPIKeyDefects is TestResolveSessionDefects for the key row.
func TestResolveAPIKeyDefects(t *testing.T) {
	t.Parallel()

	for name, rows := range defectResults(apiKeyRow(), "text", "text", "text", "integer", "text", "text", "text") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(rows...))

			got, found, err := fake.store().ResolveAPIKey(context.Background(), mustAPIKeyToken(t, 2), now)

			checkErr(t, err, defectOf(store.CodeSessionVerifyRejected))

			if found || !reflect.DeepEqual(got, store.ActiveAPIKey{}) {
				t.Errorf("a defective row returned %+v, %v", got, found)
			}
		})
	}
}

// TestResolveAPIKeyStatement pins what makes a key usable. It reads as a session
// does, and also: the agent's scopes are read now from its row, and a key whose
// agent is revoked is not active whether or not its own secret was revoked with
// it.
func TestResolveAPIKeyStatement(t *testing.T) {
	t.Parallel()

	token := mustAPIKeyToken(t, 2)
	fake := newFake(returning())

	_, _, err := fake.store().ResolveAPIKey(context.Background(), token, now)
	checkErr(t, err, nil)

	checkStatements(t, fake, wantStatement{
		fragments: []string{
			"FROM secrets s",
			"JOIN api_keys k ON k.id = s.id AND k.kind = s.kind",
			"JOIN users u ON u.id = k.user_id",
			"WHERE s.hash = ?",
			"AND s.kind = ?",
			"AND " + activeFragment,
			"AND u.revoked_at IS NULL",
			"k.scope AS scope",
			"LEFT JOIN agents a ON a.id = k.agent_id",
			"COALESCE(a.scopes, '') AS agent_scopes",
			"COALESCE(k.agent_id, '') AS agent_id",
			"AND (k.agent_id IS NULL OR (a.id IS NOT NULL AND a.revoked_at IS NULL))",
		},
		args: []any{token.Hash(), store.KindAPIKey, now.Unix(), now.Unix()},
	})
}

// TestResolveAPIKeyFailures holds how a failed or malformed batch is reported.
func TestResolveAPIKeyFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeSessionVerifyFailed, store.CodeSessionVerifyRejected, sessionsDescription,
		func(s *store.Store) error {
			return lastErr2(s.ResolveAPIKey(context.Background(), mustAPIKeyToken(t, 1), now))
		})
}

// TestResolveQueriesShareTheActivePredicate holds that every query that
// decides whether a presented secret may be used includes the one predicate, so
// none can drift from the others.
func TestResolveQueriesShareTheActivePredicate(t *testing.T) {
	t.Parallel()

	queries := packageQueries(t)

	for _, name := range []string{"resolveSessionQuery", "resolveAPIKeyQuery", "invitationQuery", "insertUserQuery"} {
		if !strings.Contains(squash(queries[name]), activeFragment) {
			t.Errorf("%s does not use the active predicate %q:\n%s", name, activeFragment, queries[name])
		}
	}
}

// TestCreateSession holds the batch a login writes: the flags update, the
// secret, then the session's own row, in that order, in one call.
func TestCreateSession(t *testing.T) {
	t.Parallel()

	expires := time.Unix(1_700_003_723, 0)
	granted := []byte("0123456789abcdef0123456789abcdef")

	tests := []struct {
		name  string
		flags uint8
	}{
		{name: "no flags", flags: 0},
		{name: "user verified and backup eligible", flags: 0x1d},
		{name: "every flag", flags: 0xff},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(applied(3))

			err := fake.store().CreateSession(context.Background(), store.NewSession{
				ID: "session-1", Hash: hashOf(7), CredentialRowID: "cred-row-1", GrantedFrom: granted,
				Flags: test.flags, ExpiresAt: expires, CreatedAt: now,
			})
			checkErr(t, err, nil)

			checkStatements(t, fake,
				wantStatement{
					fragments: []string{"UPDATE credentials SET flags = ? WHERE id = ?"},
					args:      []any{int64(test.flags), "cred-row-1"},
				},
				wantStatement{
					fragments: []string{"INSERT INTO secrets (id, kind, hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"},
					args:      []any{"session-1", store.KindSession, hashOf(7), expires.Unix(), now.Unix()},
				},
				wantStatement{
					fragments: []string{
						"INSERT INTO sessions (id, kind, user_id, credential_id, granted_from)",
						// The account is the passkey's owner, read in the write, and
						// must not be revoked: no row makes user_id NULL and fails
						// the batch, which rolls the secret and the flags back.
						"(SELECT c.user_id FROM credentials c JOIN users u ON u.id = c.user_id " +
							"WHERE c.id = ? AND u.revoked_at IS NULL)",
					},
					args: []any{"session-1", store.KindSession, "cred-row-1", "cred-row-1", granted},
				},
			)
		})
	}
}

// TestCreateSessionOrder holds that the session's own row is written last, after
// the flags and the secret it depends on: a failure of the last statement is
// what undoes the first two.
func TestCreateSessionOrder(t *testing.T) {
	t.Parallel()

	fake := newFake(applied(3))

	err := fake.store().CreateSession(context.Background(), store.NewSession{
		ID: "session-1", Hash: hashOf(7), CredentialRowID: "cred-row-1", GrantedFrom: hashOf(8),
		Flags: 1, ExpiresAt: now, CreatedAt: now,
	})
	checkErr(t, err, nil)

	tables := make([]string, 0, len(fake.calls[0]))

	for _, statement := range fake.calls[0] {
		fields := strings.Fields(statement.Query)
		tables = append(tables, fields[1]+" "+fields[2])
	}

	if want := []string{"credentials SET", "INTO secrets", "INTO sessions"}; !reflect.DeepEqual(tables, want) {
		t.Errorf("statements write %q, want %q", tables, want)
	}
}

// TestCreateSessionFailures holds that a replay, a deleted passkey and a revoked
// account (all conflicts) and every other failure come back as classified.
func TestCreateSessionFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 3, store.CodeLoginAcceptFailed, store.CodeLoginAcceptRejected, loginDescription,
		func(s *store.Store) error {
			return passErr(s.CreateSession(context.Background(), store.NewSession{
				ID: "session-1", Hash: hashOf(7), CredentialRowID: "cred-row-1", GrantedFrom: hashOf(8),
				Flags: 1, ExpiresAt: now, CreatedAt: now,
			}))
		})
}

// TestRevokeSecret holds the outcome of a logout: the number of rows the write
// changed says whether this request ended the secret.
func TestRevokeSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		changes int64
		revoked bool
		err     *wantErr
	}{
		{name: "this request ended the secret", changes: 1, revoked: true},
		{name: "already revoked, unknown, or not the user's", changes: 0},
		{name: "more than one row is impossible for a secret id", changes: 2,
			err: defectOf(store.CodeSessionLogoutRejected)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(changed(test.changes))

			revoked, err := fake.store().RevokeSecret(context.Background(), "user-1", "secret-1", now)

			checkErr(t, err, test.err)

			if revoked != test.revoked {
				t.Errorf("revoked = %v, want %v", revoked, test.revoked)
			}

			// Only a secret not yet revoked as of now is changed: one already
			// revoked keeps its earlier time and one scheduled for later is
			// brought forward, so revoking twice cannot move a revocation
			// later and a change means this request ended it. The secret must
			// be the user's session or API key, in the write itself, and the
			// kind is not a condition beyond that.
			checkBatch(t, fake, wantStatement{
				fragments: []string{
					"UPDATE secrets SET revoked_at = ?1",
					"WHERE id = ?2",
					"AND (revoked_at IS NULL OR revoked_at > ?1)",
					"AND id IN (SELECT id FROM sessions WHERE user_id = ?3 " +
						"UNION ALL SELECT id FROM api_keys WHERE user_id = ?3)",
				},
				args: []any{now.Unix(), "secret-1", "user-1"},
			})
		})
	}
}

// TestRevokeSecretFailures holds how a failed or malformed batch is reported.
func TestRevokeSecretFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeSessionLogoutFailed, store.CodeSessionLogoutRejected, sessionsDescription,
		func(s *store.Store) error {
			return lastErr(s.RevokeSecret(context.Background(), "user-1", "secret-1", now))
		})
}

// TestSecretCodes pins the wire codes the operations report, and the kinds the
// store binds. Clients and dashboards match on the codes, and the kinds must
// equal the literals the migration fixes (TestKindsMatchTheMigration).
func TestSecretCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeSessionVerifyFailed, "session_verify_failed"},
		{store.CodeSessionVerifyRejected, "session_verify_rejected"},
		{store.CodeLoginAcceptFailed, "login_accept_failed"},
		{store.CodeLoginAcceptRejected, "login_accept_rejected"},
		{store.CodeSessionLogoutFailed, "session_logout_failed"},
		{store.CodeSessionLogoutRejected, "session_logout_rejected"},
		{store.KindInvitation, "invitation"},
		{store.KindSession, "session"},
		{store.KindAPIKey, "api_key"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}

// TestRevokeSecretStaysWithinTheUsersSecrets holds that no revoke statement
// writes a bare secret id without scoping it: the only write to secrets whose
// rows are not selected by the user's own tables is the invitation revoke,
// which is matched by the invitation kind, bound as an argument. A write to an
// OAuth secret is scoped through the grant or access token row it belongs to,
// which in turn names the owner (user_id), the presenting client (client_id) or
// the grant the rotation just rotated (the new refresh hash).
func TestRevokeSecretStaysWithinTheUsersSecrets(t *testing.T) {
	t.Parallel()

	for name, query := range packageQueries(t) {
		text := squash(query)
		if !strings.HasPrefix(text, "UPDATE secrets ") {
			continue
		}

		scoped := strings.Contains(text, "id IN (SELECT id FROM sessions") ||
			strings.Contains(text, "id IN (SELECT id FROM api_keys") ||
			strings.Contains(text, "id IN (SELECT g.id FROM oauth_grants g") ||
			strings.Contains(text, "id IN (SELECT t.id FROM oauth_access_tokens t") ||
			strings.Contains(text, "WHERE id = ?2 AND kind = ?3")
		if !scoped {
			t.Errorf("%s updates secrets without scoping them to an owner or a kind:\n%s", name, text)
		}
	}
}
