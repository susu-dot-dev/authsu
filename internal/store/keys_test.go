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

// keyRow is the row ActiveKey reads: jwk, user_id, credential_id, role,
// expires_at, agent_id, agent_scopes.
func keyRow() []any {
	return row(`{"keys":[]}`, "user-1", "cred-row-1", "admin", int64(1_700_000_600), "", "")
}

// TestActiveKeyDecoding holds how the key row becomes an ActiveKey, and that
// no row is an answer and not an error.
func TestActiveKeyDecoding(t *testing.T) {
	t.Parallel()

	active := store.ActiveKey{
		JWK: []byte(`{"keys":[]}`), UserID: "user-1", CredentialID: "cred-row-1", Role: "admin",
		ExpiresAt: time.Unix(1_700_000_600, 0),
	}
	noPasskey := active
	noPasskey.CredentialID = ""
	agentKey := active
	agentKey.CredentialID, agentKey.AgentID, agentKey.AgentScopes = "", "agent-1", `["agent:read"]`

	tests := []struct {
		name  string
		rows  [][]any
		want  store.ActiveKey
		found bool
	}{
		{name: "an active session key", rows: [][]any{keyRow()}, want: active, found: true},
		{name: "a key with no passkey reads an empty credential id",
			rows: [][]any{with(keyRow(), 2, "")}, want: noPasskey, found: true},
		{name: "an agent's key reads the agent's id and current scopes",
			rows: [][]any{with(with(with(keyRow(), 2, ""), 5, "agent-1"), 6, `["agent:read"]`)}, want: agentKey, found: true},
		{name: "no key", rows: nil},
		{name: "an empty result", rows: [][]any{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, found, err := fake.store().ActiveKey(context.Background(), "kid-1", store.KindSession, now)

			checkErr(t, err, nil)

			if found != test.found {
				t.Errorf("found = %v, want %v", found, test.found)
			}

			if !reflect.DeepEqual(got.JWK, test.want.JWK) || got.UserID != test.want.UserID ||
				got.CredentialID != test.want.CredentialID || got.Role != test.want.Role ||
				got.AgentID != test.want.AgentID || got.AgentScopes != test.want.AgentScopes ||
				!got.ExpiresAt.Equal(test.want.ExpiresAt) {
				t.Errorf("key = %+v, want %+v", got, test.want)
			}
		})
	}
}

// TestActiveKeyDefects holds that a result that is not the key row the query
// promises is a defect, and not "no key": verification must not read a broken
// row as an absent one or as a valid one.
func TestActiveKeyDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "two rows", rows: [][]any{keyRow(), keyRow()}},
		{name: "jwk is NULL", rows: [][]any{with(keyRow(), 0, nil)}},
		{name: "jwk is a blob", rows: [][]any{with(keyRow(), 0, []byte("{}"))}},
		{name: "user id is an integer", rows: [][]any{with(keyRow(), 1, int64(1))}},
		{name: "credential id is NULL", rows: [][]any{with(keyRow(), 2, nil)}},
		{name: "role is NULL", rows: [][]any{with(keyRow(), 3, nil)}},
		{name: "expires_at is a float", rows: [][]any{with(keyRow(), 4, 1.7e9)}},
		{name: "expires_at is text", rows: [][]any{with(keyRow(), 4, "soon")}},
		{name: "expires_at is NULL", rows: [][]any{with(keyRow(), 4, nil)}},
		{name: "agent id is NULL", rows: [][]any{with(keyRow(), 5, nil)}},
		{name: "agent id is an integer", rows: [][]any{with(keyRow(), 5, int64(1))}},
		{name: "agent scopes is NULL", rows: [][]any{with(keyRow(), 6, nil)}},
		{name: "agent scopes is a blob", rows: [][]any{with(keyRow(), 6, []byte("[]"))}},
		{name: "a column too few", rows: [][]any{keyRow()[:6]}},
		{name: "four columns", rows: [][]any{keyRow()[:4]}},
		{name: "a column too many", rows: [][]any{append(keyRow(), "extra")}},
		{name: "an empty row", rows: [][]any{row()}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, found, err := fake.store().ActiveKey(context.Background(), "kid-1", store.KindSession, now)

			checkErr(t, err, defectOf(store.CodeSessionVerifyRejected))

			if found || got.UserID != "" || got.JWK != nil {
				t.Errorf("a defective row returned %+v, %v", got, found)
			}
		})
	}
}

// TestActiveKeyStatement pins what makes a key usable and the arguments that
// say for whom. Revocation is compared with now and not tested for NULL alone,
// so a revocation scheduled for later would work without a change; the kind is
// an argument, so a token of one kind cannot verify as another.
func TestActiveKeyStatement(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{store.KindSession, "api_key"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, _, err := fake.store().ActiveKey(context.Background(), "kid-1", kind, now)
			checkErr(t, err, nil)

			checkStatements(t, fake, wantStatement{
				fragments: []string{
					"FROM japikeys k",
					"JOIN users u ON u.id = k.user_id",
					"WHERE k.kid = ?",
					"AND k.kind = ?",
					"AND (k.revoked_at IS NULL OR k.revoked_at > ?)",
					"AND k.expires_at > ?",
					"AND u.revoked_at IS NULL",
					"COALESCE(k.credential_id, '') AS credential_id",
					// The agent's scopes are read now, from its row, and a key of a
					// revoked agent is not active whether or not its own row was
					// revoked with it.
					"LEFT JOIN agents a ON a.id = k.agent_id",
					"COALESCE(a.scopes, '') AS agent_scopes",
					"AND (k.agent_id IS NULL OR (a.id IS NOT NULL AND a.revoked_at IS NULL))",
				},
				args: []any{"kid-1", kind, now.Unix(), now.Unix()},
			})
		})
	}
}

// TestActiveKeyFailures holds how a failed or malformed batch is reported.
func TestActiveKeyFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeSessionVerifyFailed, store.CodeSessionVerifyRejected, sessionsDescription,
		func(s *store.Store) error {
			return lastErr2(s.ActiveKey(context.Background(), "kid-1", store.KindSession, now))
		})
}

// TestCreateSession holds the batch a login writes: the flags update and the
// session insert, in that order, in one call.
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

			fake := newFake(applied(2))

			err := fake.store().CreateSession(context.Background(), store.NewSession{
				KeyID: "kid-1", CredentialRowID: "cred-row-1", JWK: `{"keys":[{}]}`, ExpiresAt: expires,
				GrantedFrom: granted, Scope: `["default:session"]`, Flags: test.flags, CreatedAt: now,
			})
			checkErr(t, err, nil)

			checkStatements(t, fake,
				wantStatement{
					fragments: []string{"UPDATE credentials SET flags = ? WHERE id = ?"},
					args:      []any{int64(test.flags), "cred-row-1"},
				},
				wantStatement{
					fragments: []string{
						"INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, granted_from, credential_id, scope, created_at)",
						"(SELECT c.user_id FROM credentials c JOIN users u ON u.id = c.user_id " +
							"WHERE c.id = ? AND u.revoked_at IS NULL)",
					},
					args: []any{
						"kid-1", "cred-row-1", store.KindSession, `{"keys":[{}]}`, expires.Unix(),
						granted, "cred-row-1", `["default:session"]`, now.Unix(),
					},
				},
			)
		})
	}
}

// TestCreateSessionFailures holds that a replay, a deleted passkey and a revoked
// account (all conflicts) and every other failure come back as classified.
func TestCreateSessionFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 2, store.CodeLoginAcceptFailed, store.CodeLoginAcceptRejected, loginDescription,
		func(s *store.Store) error {
			return passErr(s.CreateSession(context.Background(), store.NewSession{
				KeyID: "kid-1", CredentialRowID: "cred-row-1", JWK: "{}", ExpiresAt: now,
				GrantedFrom: []byte("x"), Flags: 1, CreatedAt: now,
			}))
		})
}

// TestRevokeKey holds the outcome of a logout: the number of rows the write
// changed says whether this request ended the session.
func TestRevokeKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		changes int64
		revoked bool
		err     *wantErr
	}{
		{name: "this request ended the session", changes: 1, revoked: true},
		{name: "already revoked, or unknown", changes: 0},
		{name: "more than one row is impossible for a key id", changes: 2, err: defectOf(store.CodeSessionLogoutRejected)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(changed(test.changes))

			revoked, err := fake.store().RevokeKey(context.Background(), "user-1", "kid-1", now)

			checkErr(t, err, test.err)

			if revoked != test.revoked {
				t.Errorf("revoked = %v, want %v", revoked, test.revoked)
			}

			// A key that is already revoked keeps its earlier time: revoking twice
			// cannot move a revocation later. The kind is not a condition: the key
			// a request presented is the one that ends, session or API key. The
			// owner is: the write itself, and not a read before it, guarantees
			// the key is the user's.
			checkStatements(t, fake, wantStatement{
				fragments: []string{
					"UPDATE japikeys SET revoked_at = ?",
					"WHERE kid = ?",
					"AND user_id = ?",
					"AND revoked_at IS NULL",
				},
				args: []any{now.Unix(), "kid-1", "user-1"},
			})

			if strings.Contains(squash(fake.calls[0][0].Query), "kind") {
				t.Error("the revoke names a kind: it must end whichever key was presented")
			}
		})
	}
}

// TestRevokeKeyFailures holds how a failed or malformed batch is reported.
func TestRevokeKeyFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeSessionLogoutFailed, store.CodeSessionLogoutRejected, sessionsDescription,
		func(s *store.Store) error { return lastErr(s.RevokeKey(context.Background(), "user-1", "kid-1", now)) })
}

// TestKeyCodes pins the wire codes the operations report. Clients and
// dashboards match on them, so they change only deliberately.
func TestKeyCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeSessionVerifyFailed, "session_verify_failed"},
		{store.CodeSessionVerifyRejected, "session_verify_rejected"},
		{store.CodeLoginAcceptFailed, "login_accept_failed"},
		{store.CodeLoginAcceptRejected, "login_accept_rejected"},
		{store.CodeSessionLogoutFailed, "session_logout_failed"},
		{store.CodeSessionLogoutRejected, "session_logout_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}
