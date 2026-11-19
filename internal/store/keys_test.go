//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Everything this file defines at package level is prefixed "key" so that it
// cannot collide with the helpers of another area's test file.

const (
	keysUnavailable = "keys are temporarily unavailable"
	keyOwner        = "user-1"
	keyTarget       = "01900000-0000-7000-8000-000000000042"
	keyPresented    = "01900000-0000-7000-8000-000000000099"
)

// keyIDAt returns the canonical id of the n-th key. A larger n is a later key
// and sorts higher.
func keyIDAt(n int) string { return fmt.Sprintf("01900000-0000-7000-8000-%012d", n) }

// keyRowAt is a returned key row: id, name, scope, expires_at, revoked_at,
// created_at.
func keyRowAt(n int) []any {
	return row(keyIDAt(n), "key "+strconv.Itoa(n), `["agent:read"]`, int64(1_800_000_000+n), nil, int64(1_700_000_000+n))
}

// keyRow is the row of the key keyTarget.
func keyRow() []any {
	return row(keyTarget, "ci", `["agent:read"]`, int64(1_800_000_000), nil, int64(1_700_000_000))
}

// keyRevokedRow is keyRow once it is revoked.
func keyRevokedRow() []any { return with(keyRow(), 4, int64(1_700_000_100)) }

func mustKeyName(tb testing.TB, raw string) input.KeyName {
	tb.Helper()

	name, err := input.ParseKeyName(raw)
	if err != nil {
		tb.Fatalf("parse key name %q: %v", raw, err)
	}

	return name
}

func mustKeyID(tb testing.TB) input.ID {
	tb.Helper()

	id, err := input.ParseID(keyTarget)
	if err != nil {
		tb.Fatalf("parse id %q: %v", keyTarget, err)
	}

	return id
}

// keyRead is one operation that reads a key row, for the tables that hold for
// all of them.
type keyRead struct {
	name     string
	rejected string

	// one is true when the operation reads exactly one row, false for a page.
	one bool

	// outcome is the batch the operation gets for the rows its read returned.
	outcome func(rows ...[]any) outcome

	// call runs the operation and returns the keys it read.
	call func(*store.Store) ([]store.Key, error)
}

// afterWrite is the batch of a write followed by the read of the key: the write
// changed n rows, and the read returned rows.
func afterWrite(n int64, rows ...[]any) outcome {
	return outcome{results: []store.Result{{Changes: n, Rows: nil}, {Changes: 0, Rows: rows}}, err: nil}
}

// keyReadOps are the operations that decode key rows.
func keyReadOps(t *testing.T) []keyRead {
	t.Helper()

	ctx := context.Background()
	id := mustKeyID(t)
	name := mustKeyName(t, "renamed")

	single := func(key store.Key, err error) ([]store.Key, error) { return []store.Key{key}, err }

	return []keyRead{
		{
			name: "list", rejected: store.CodeKeyListRejected, one: false, outcome: returning,
			call: func(s *store.Store) ([]store.Key, error) {
				page, err := s.ListKeys(ctx, keyOwner, mustAgentCursor(t), mustAgentLimit(t))

				return page.Keys, passErr(err)
			},
		},
		{
			name: "get", rejected: store.CodeKeyLookupRejected, one: true, outcome: returning,
			call: func(s *store.Store) ([]store.Key, error) { return single(s.GetKey(ctx, keyOwner, id)) },
		},
		{
			name: "rename", rejected: store.CodeKeyUpdateRejected, one: true,
			outcome: func(rows ...[]any) outcome { return afterWrite(1, rows...) },
			call: func(s *store.Store) ([]store.Key, error) {
				return single(s.RenameKey(ctx, keyOwner, id, name, now))
			},
		},
		{
			name: "revoke", rejected: store.CodeKeyRevokeRejected, one: true,
			outcome: func(rows ...[]any) outcome { return afterWrite(1, rows...) },
			call: func(s *store.Store) ([]store.Key, error) {
				return single(s.RevokeKey(ctx, keyOwner, id, keyPresented, now))
			},
		},
	}
}

// TestKeyDecoding holds how a returned row becomes a Key, for every operation
// that reads one: they share a reader.
func TestKeyDecoding(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)

	tests := []struct {
		name string
		row  []any
		want store.Key
	}{
		{name: "an active key", row: keyRow(), want: store.Key{
			ID: keyTarget, Name: "ci", Scope: `["agent:read"]`, ExpiresAt: 1_800_000_000, RevokedAt: nil,
			CreatedAt: 1_700_000_000,
		}},
		{name: "a revoked key", row: keyRevokedRow(), want: store.Key{
			ID: keyTarget, Name: "ci", Scope: `["agent:read"]`, ExpiresAt: 1_800_000_000, RevokedAt: &revokedAt,
			CreatedAt: 1_700_000_000,
		}},
		{name: "a multibyte name is kept as is", row: with(keyRow(), 1, "デプロイ 🔑"), want: store.Key{
			ID: keyTarget, Name: "デプロイ 🔑", Scope: `["agent:read"]`, ExpiresAt: 1_800_000_000, RevokedAt: nil,
			CreatedAt: 1_700_000_000,
		}},
		{name: "an empty scope list is kept", row: with(keyRow(), 2, "[]"), want: store.Key{
			ID: keyTarget, Name: "ci", Scope: "[]", ExpiresAt: 1_800_000_000, RevokedAt: nil, CreatedAt: 1_700_000_000,
		}},
	}

	for _, op := range keyReadOps(t) {
		for _, test := range tests {
			t.Run(op.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(op.outcome(test.row))

				got, err := op.call(fake.store())
				checkErr(t, err, nil)

				if !reflect.DeepEqual(got, []store.Key{test.want}) {
					t.Errorf("keys = %+v, want %+v", got, test.want)
				}
			})
		}
	}
}

// TestKeyDefects holds that a row that is not the key the statement promises is
// a defect and not a missing key or a wrong one.
func TestKeyDefects(t *testing.T) {
	t.Parallel()

	for _, op := range keyReadOps(t) {
		for name, rows := range defectResults(keyRow(), "text", "text", "text", "integer", "optInteger", "integer") {
			// Two rows is a defect only where one row is promised; a page may hold
			// several.
			if name == "two rows" && !op.one {
				continue
			}

			t.Run(op.name+"/"+name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(op.outcome(rows...))

				got, err := op.call(fake.store())

				checkErr(t, err, defectOf(op.rejected))

				if len(got) > 0 && got[0].ID != "" {
					t.Errorf("a defective row returned %+v", got)
				}
			})
		}
	}
}

// TestKeyNoRowIsNotFound holds that no row from a statement aimed at one key is
// the key not being there, an unclassified sentinel for the feature to name.
func TestKeyNoRowIsNotFound(t *testing.T) {
	t.Parallel()

	for _, op := range keyReadOps(t) {
		if !op.one {
			continue
		}

		t.Run(op.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(op.outcome())

			_, err := op.call(fake.store())
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}

			if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
				t.Errorf("a missing key %v is classified; the feature must decide that", err)
			}
		})
	}
}

// keyPaging is how many rows the database gave back for a page of size, and the
// page that makes: how many keys it holds and whether it names a next one.
type keyPaging struct {
	size, returned, keys int
	next                 bool
}

// keyPagingCases are the pages TestListKeysPaging reads. The limit is the one the
// size stands for; a zero PageLimit is read as 1.
func keyPagingCases() map[string]keyPaging {
	return map[string]keyPaging{
		"no keys":                              {size: 3, returned: 0, keys: 0, next: false},
		"fewer than the limit":                 {size: 3, returned: 2, keys: 2, next: false},
		"exactly the limit: no next page":      {size: 3, returned: 3, keys: 3, next: false},
		"one more than the limit: a next page": {size: 3, returned: 4, keys: 3, next: true},
		"a limit of one, with a next page":     {size: 1, returned: 2, keys: 1, next: true},
		"a limit of one, the last key":         {size: 1, returned: 1, keys: 1, next: false},
		"the default limit":                    {size: 25, returned: 26, keys: 25, next: true},
		"the largest limit":                    {size: 100, returned: 101, keys: 100, next: true},
	}
}

// pageLimitOf is the PageLimit that stands for size: the default for 25, and
// otherwise one that parses as exactly size.
func pageLimitOf(t *testing.T, size int) input.PageLimit {
	t.Helper()

	if size == 25 {
		return mustAgentLimit(t)
	}

	return mustAgentLimit(t, strconv.Itoa(size))
}

// pageResult is a page a read produced, as far as every list's paging is checked:
// the ids on it in order, its cursor, the statement's arguments (argc of them,
// the third being the number of rows asked for) and the id the n-th row of a
// database has.
type pageResult struct {
	ids  []string
	next string
	args []any
	argc int
	idAt func(int) string
}

// pageWant is the page a read must have produced: how many ids it holds, whether
// it names a next page, and the page size the statement must have asked one
// more row than.
type pageWant struct {
	size, ids int
	next      bool
}

// checkPage asserts the page a read produced: the first ids of the rows, in the
// database's order, a cursor that is the id of the last of them, and a statement
// that asked for the page size plus one.
func checkPage(t *testing.T, got pageResult, want pageWant) {
	t.Helper()

	if len(got.ids) != want.ids {
		t.Fatalf("page has %d ids, want %d", len(got.ids), want.ids)
	}

	for i, id := range got.ids {
		if id != got.idAt(1000-i) {
			t.Errorf("row %d is %s, want %s: order must be the database's", i, id, got.idAt(1000-i))
		}
	}

	wantNext := ""
	if want.next {
		wantNext = got.idAt(1000 - (want.ids - 1))
	}

	if got.next != wantNext {
		t.Errorf("next = %q, want %q", got.next, wantNext)
	}

	if len(got.args) != got.argc || got.args[2] != int64(want.size+1) {
		t.Errorf("args = %#v, want %d of them with the page size plus one (%d) third", got.args, got.argc, want.size+1)
	}
}

// checkKeyPage asserts the page a keys read produced.
func checkKeyPage(t *testing.T, page store.KeyPage, fake *fakeExec, test keyPaging) {
	t.Helper()

	if page.Keys == nil {
		t.Fatalf("page has nil keys, want %d", test.keys)
	}

	ids := make([]string, len(page.Keys))
	for i, key := range page.Keys {
		ids[i] = key.ID
	}

	checkPage(t, pageResult{ids: ids, next: page.Next, args: fake.calls[0][0].Args, argc: 3, idAt: keyIDAt},
		pageWant{size: test.size, ids: test.keys, next: test.next})
}

// TestListKeysPaging holds how the rows of a page become the page: the query
// asks for one row more than the page holds, and that extra row only says there
// is a next page, whose cursor is the last key that is returned.
func TestListKeysPaging(t *testing.T) {
	t.Parallel()

	for name, test := range keyPagingCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Newest first: ids fall down the page.
			rows := make([][]any, test.returned)
			for i := range rows {
				rows[i] = keyRowAt(1000 - i)
			}

			fake := newFake(returning(rows...))

			page, err := fake.store().ListKeys(
				context.Background(), keyOwner, mustAgentCursor(t), pageLimitOf(t, test.size))
			checkErr(t, err, nil)

			checkKeyPage(t, page, fake, test)
		})
	}

	t.Run("a zero PageLimit is read as 1", func(t *testing.T) {
		t.Parallel()

		fake := newFake(returning(keyRowAt(1000), keyRowAt(999)))

		page, err := fake.store().ListKeys(context.Background(), keyOwner, mustAgentCursor(t), input.PageLimit{})
		checkErr(t, err, nil)

		checkKeyPage(t, page, fake, keyPaging{size: 1, returned: 2, keys: 1, next: true})
	})
}

// TestListKeysMoreRowsThanAsked holds that a database that returns more rows
// than the LIMIT it was given is a defect.
func TestListKeysMoreRowsThanAsked(t *testing.T) {
	t.Parallel()

	fake := newFake(returning(keyRowAt(5), keyRowAt(4), keyRowAt(3)))

	page, err := fake.store().ListKeys(context.Background(), keyOwner, mustAgentCursor(t), mustAgentLimit(t, "1"))

	checkErr(t, err, defectOf(store.CodeKeyListRejected))

	if page.Keys != nil || page.Next != "" {
		t.Errorf("a defective page returned %+v", page)
	}
}

// TestListKeysStatement pins the query's guards and its arguments in placeholder
// order: the owner scopes the page, only keys with no agent are listed, the
// cursor is an exclusive upper bound on the id, and the first page has a bound
// above every id.
func TestListKeysStatement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cursor input.Cursor
		limit  input.PageLimit
		before string
		rows   int64
	}{
		{name: "first page", cursor: mustAgentCursor(t), limit: mustAgentLimit(t), before: "", rows: 26},
		{name: "after a cursor", cursor: mustAgentCursor(t, agentCursorID), limit: mustAgentLimit(t, "7"),
			before: agentCursorID, rows: 8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, err := fake.store().ListKeys(context.Background(), keyOwner, test.cursor, test.limit)
			checkErr(t, err, nil)

			before := test.before
			if before == "" {
				before = store.KeysFirstPage
			}

			checkBatch(t, fake, wantStatement{
				fragments: []string{
					"FROM api_keys k",
					// The expiry and revocation are the secret's, joined on the id and
					// the kind together.
					"JOIN secrets s ON s.id = k.id AND s.kind = k.kind",
					// The owner, and no agent: an agent's keys are not listed here.
					"WHERE k.user_id = ?1 AND k.agent_id IS NULL AND k.id < ?2",
					"ORDER BY k.id DESC",
					"LIMIT ?3",
				},
				args: []any{keyOwner, before, test.rows},
			})
		})
	}
}

// TestListKeysFailures holds how a failed or malformed batch is reported.
func TestListKeysFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeKeyListFailed, store.CodeKeyListRejected, keysUnavailable,
		func(s *store.Store) error {
			return lastErr(s.ListKeys(context.Background(), keyOwner, mustAgentCursor(t), mustAgentLimit(t)))
		})
}

// TestGetKeyStatement pins that the owner and "no agent" are part of the match,
// so another user's key and an agent's key are not found, and the arguments in
// order.
func TestGetKeyStatement(t *testing.T) {
	t.Parallel()

	fake := newFake(returning(keyRow()))

	_, err := fake.store().GetKey(context.Background(), keyOwner, mustKeyID(t))
	checkErr(t, err, nil)

	checkBatch(t, fake, wantStatement{
		fragments: []string{
			"FROM api_keys k",
			"JOIN secrets s ON s.id = k.id AND s.kind = k.kind",
			"WHERE k.id = ?1 AND k.user_id = ?2 AND k.agent_id IS NULL",
		},
		args: []any{keyTarget, keyOwner},
	})
}

// TestGetKeyFailures holds how a failed or malformed batch is reported.
func TestGetKeyFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeKeyLookupFailed, store.CodeKeyLookupRejected, keysUnavailable,
		func(s *store.Store) error {
			return lastErr(s.GetKey(context.Background(), keyOwner, mustKeyID(t)))
		})
}

// createKeyCase is a user's create and the batch it writes.
type createKeyCase struct {
	name string
	key  store.NewKey
}

func createKeyCases(t *testing.T) []createKeyCase {
	t.Helper()

	expires := time.Unix(1_707_776_123, 0)

	return []createKeyCase{
		{name: "a typical key", key: store.NewKey{
			ID: keyTarget, Owner: keyOwner, Name: mustKeyName(t, "ci"), Scope: `["agent:read"]`, Hash: hashOf(1),
			ExpiresAt: expires, MaxActive: 50, CreatedAt: now,
		}},
		{name: "a multibyte name, no scopes and another limit", key: store.NewKey{
			ID: keyIDAt(7), Owner: "user-2", Name: mustKeyName(t, "デプロイ 🔑"), Scope: `[]`, Hash: hashOf(2),
			ExpiresAt: expires.Add(time.Hour), MaxActive: 1, CreatedAt: now.Add(time.Minute),
		}},
	}
}

// TestCreateKeyStatements pins the batch a create writes: the secret first, then
// the key's own row, whose owner is a subselect that is NULL when the owner is
// revoked or at the limit, so that no key means a failed batch and the secret is
// rolled back.
func TestCreateKeyStatements(t *testing.T) {
	t.Parallel()

	for _, test := range createKeyCases(t) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(applied(2))

			err := fake.store().CreateKey(context.Background(), test.key)
			checkErr(t, err, nil)

			key := test.key

			checkBatch(t, fake,
				wantStatement{
					fragments: []string{"INSERT INTO secrets (id, kind, hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"},
					args:      []any{key.ID, store.KindAPIKey, key.Hash, key.ExpiresAt.Unix(), key.CreatedAt.Unix()},
				},
				wantStatement{
					fragments: []string{
						"INSERT INTO api_keys (id, kind, user_id, agent_id, name, scope)",
						// The owner is read from users, and must be active.
						"(SELECT u.id FROM users u WHERE u.id = ?7 AND u.revoked_at IS NULL",
						// The limit counts the owner's own keys that are active now, in
						// the write: revoked and expired ones do not count.
						"AND (SELECT count(*) FROM api_keys a JOIN secrets s ON s.id = a.id AND s.kind = a.kind " +
							"WHERE a.user_id = u.id AND a.agent_id IS NULL " +
							"AND (s.revoked_at IS NULL OR s.revoked_at > ?6) AND s.expires_at > ?6) < ?5)",
						// A user's own key has no agent.
						"NULL, ?3, ?4)",
					},
					args: []any{
						key.ID, store.KindAPIKey, key.Name.String(), key.Scope, int64(key.MaxActive),
						key.CreatedAt.Unix(), key.Owner,
					},
				},
			)

			for i := range 2 {
				if strings.Contains(squash(fake.calls[0][i].Query), "'api_key'") {
					t.Errorf("statement %d writes the kind as a literal; bind store.KindAPIKey", i)
				}
			}
		})
	}
}

// TestCreateKeyFailures holds that a limit or a revoked owner (conflicts, which
// the feature names) and every other failure come back as classified.
func TestCreateKeyFailures(t *testing.T) {
	t.Parallel()

	key := createKeyCases(t)[0].key

	runFailures(t, 2, store.CodeKeyCreateFailed, store.CodeKeyCreateRejected, keysUnavailable,
		func(s *store.Store) error { return passErr(s.CreateKey(context.Background(), key)) })
}

// keyWriteFailures is infraFailures for an operation that writes nothing a
// constraint of the data could refuse (rename and revoke): a conflict is a
// defect there, and not something for the feature to map.
func keyWriteFailures(statements int, failed, rejected string) []failure {
	return defectConflicts(infraFailures(statements, failed, rejected, keysUnavailable), rejected)
}

// renameStatements are the two statements a rename runs, in order.
func renameStatements() []wantStatement {
	return []wantStatement{
		{
			fragments: []string{
				"UPDATE api_keys SET name = ?1",
				// The owner, and no agent, are in the write.
				"WHERE id = ?2 AND user_id = ?3 AND agent_id IS NULL",
				// Only a key that is active now: a revoked or expired one is final.
				"AND id IN (SELECT s.id FROM secrets s WHERE s.id = ?2 " +
					"AND (s.revoked_at IS NULL OR s.revoked_at > ?4) AND s.expires_at > ?4)",
			},
			args: []any{"renamed", keyTarget, keyOwner, now.Unix()},
		},
		{
			fragments: []string{"FROM api_keys k", "WHERE k.id = ?1 AND k.user_id = ?2 AND k.agent_id IS NULL"},
			args:      []any{keyTarget, keyOwner},
		},
	}
}

// TestRenameKey holds the outcomes of a rename: the row is whatever the closing
// read returns, whether or not the write changed it, so a key that is no longer
// active comes back unchanged for the feature to refuse.
func TestRenameKey(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)
	revoked := store.Key{
		ID: keyTarget, Name: "ci", Scope: `["agent:read"]`, ExpiresAt: 1_800_000_000, RevokedAt: &revokedAt,
		CreatedAt: 1_700_000_000,
	}
	renamed := store.Key{
		ID: keyTarget, Name: "renamed", Scope: `["agent:read"]`, ExpiresAt: 1_800_000_000, RevokedAt: nil,
		CreatedAt: 1_700_000_000,
	}

	tests := []struct {
		name    string
		outcome outcome
		want    store.Key
		err     error
	}{
		{name: "renamed", outcome: afterWrite(1, with(keyRow(), 1, "renamed")), want: renamed},
		{name: "revoked: the write changed nothing", outcome: afterWrite(0, keyRevokedRow()), want: revoked},
		{name: "no such key", outcome: afterWrite(0), err: store.ErrNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(test.outcome)

			got, err := fake.store().RenameKey(
				context.Background(), keyOwner, mustKeyID(t), mustKeyName(t, "renamed"), now)

			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("key = %+v, want %+v", got, test.want)
			}

			checkBatch(t, fake, renameStatements()...)
		})
	}
}

// TestRenameKeyFailures holds that a conflict is as much a defect as a schema
// rule: a rename writes nothing the data could collide with.
func TestRenameKeyFailures(t *testing.T) {
	t.Parallel()

	for _, f := range keyWriteFailures(2, store.CodeKeyUpdateFailed, store.CodeKeyUpdateRejected) {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			_, err := fake.store().RenameKey(
				context.Background(), keyOwner, mustKeyID(t), mustKeyName(t, "renamed"), now)

			checkFailure(t, err, f)

			if errors.Is(err, store.ErrNotFound) {
				t.Error("a failure is reported as a missing key")
			}
		})
	}
}

// revokeKeyStatements are the two statements a revoke runs, in order.
func revokeKeyStatements() []wantStatement {
	return []wantStatement{
		{
			fragments: []string{
				"UPDATE secrets SET revoked_at = ?1",
				// Never the credential the request presented.
				"WHERE id = ?2 AND id <> ?4",
				// A due revocation keeps its time; a later one is brought forward.
				"AND (revoked_at IS NULL OR revoked_at > ?1)",
				// Only the user's own key, with no agent.
				"AND id IN (SELECT id FROM api_keys WHERE id = ?2 AND user_id = ?3 AND agent_id IS NULL)",
			},
			args: []any{now.Unix(), keyTarget, keyOwner, keyPresented},
		},
		{
			fragments: []string{
				"FROM api_keys k",
				// The closing read matches no row for the presented credential, as the
				// write does not.
				"WHERE k.id = ?1 AND k.user_id = ?2 AND k.agent_id IS NULL AND k.id <> ?3",
			},
			args: []any{keyTarget, keyOwner, keyPresented},
		},
	}
}

// TestRevokeKey holds the outcomes of a revoke: the row is whatever the closing
// read returns, so a key revoked earlier is returned with its earlier time, and
// revoking twice succeeds.
func TestRevokeKey(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)
	revoked := store.Key{
		ID: keyTarget, Name: "ci", Scope: `["agent:read"]`, ExpiresAt: 1_800_000_000, RevokedAt: &revokedAt,
		CreatedAt: 1_700_000_000,
	}

	tests := []struct {
		name    string
		outcome outcome
		want    store.Key
		err     error
	}{
		{name: "revoked now", outcome: afterWrite(1, keyRevokedRow()), want: revoked},
		{name: "revoked already: the write changed nothing", outcome: afterWrite(0, keyRevokedRow()), want: revoked},
		{name: "no such key, or the presented credential", outcome: afterWrite(0), err: store.ErrNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(test.outcome)

			got, err := fake.store().RevokeKey(context.Background(), keyOwner, mustKeyID(t), keyPresented, now)

			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("key = %+v, want %+v", got, test.want)
			}

			checkBatch(t, fake, revokeKeyStatements()...)
		})
	}
}

// TestRevokeKeyFailures holds that a conflict is as much a defect as a schema
// rule: a revoke sets nothing the data could collide with.
func TestRevokeKeyFailures(t *testing.T) {
	t.Parallel()

	for _, f := range keyWriteFailures(2, store.CodeKeyRevokeFailed, store.CodeKeyRevokeRejected) {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			_, err := fake.store().RevokeKey(context.Background(), keyOwner, mustKeyID(t), keyPresented, now)

			checkFailure(t, err, f)

			if errors.Is(err, store.ErrNotFound) {
				t.Error("a failure is reported as a missing key")
			}
		})
	}
}

// TestKeyQueriesAreChecked guards the package-wide query checks against passing
// because they never saw the key queries.
func TestKeyQueriesAreChecked(t *testing.T) {
	t.Parallel()

	queries := packageQueries(t)

	for _, name := range []string{
		"keyListQuery", "keyGetQuery", "insertUserKeyQuery", "keyRenameQuery", "keyRevokeQuery", "keyRevokeReadQuery",
		"insertSecretQuery",
	} {
		if _, ok := queries[name]; !ok {
			t.Errorf("query %s was not found", name)
		}
	}
}

// TestKeyQueriesScopeToTheOwnersOwnKeys holds that every statement that reads or
// changes a user's own key names the owner and "no agent" in its match, so a key
// of another user, or of an agent, can be neither seen nor changed. The create
// is the exception: its owner is read from users, and it writes a key with no
// agent.
func TestKeyQueriesScopeToTheOwnersOwnKeys(t *testing.T) {
	t.Parallel()

	queries := packageQueries(t)

	for _, name := range []string{
		"keyListQuery", "keyGetQuery", "keyRenameQuery", "keyRevokeQuery", "keyRevokeReadQuery",
	} {
		text := squash(queries[name])

		if !strings.Contains(text, "user_id = ?") || !strings.Contains(text, "agent_id IS NULL") {
			t.Errorf("%s does not match on the owner and on no agent:\n%s", name, text)
		}
	}
}

// TestKeyCodes pins the wire codes the operations report. Clients and
// dashboards match on them, so they change only deliberately.
func TestKeyCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeKeyListFailed, "key_list_failed"},
		{store.CodeKeyListRejected, "key_list_rejected"},
		{store.CodeKeyLookupFailed, "key_lookup_failed"},
		{store.CodeKeyLookupRejected, "key_lookup_rejected"},
		{store.CodeKeyCreateFailed, "key_create_failed"},
		{store.CodeKeyCreateRejected, "key_create_rejected"},
		{store.CodeKeyUpdateFailed, "key_update_failed"},
		{store.CodeKeyUpdateRejected, "key_update_rejected"},
		{store.CodeKeyRevokeFailed, "key_revoke_failed"},
		{store.CodeKeyRevokeRejected, "key_revoke_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}

// TestKeysFirstPageSortsAboveEveryID holds the property the first page relies on:
// its bound is not an id and sorts above every character an id holds, so
// `id < bound` is true for every key and the first page needs no query of its
// own. (TestAgentsFirstPageSortsAboveEveryID holds the same for agents, in full.)
func TestKeysFirstPageSortsAboveEveryID(t *testing.T) {
	t.Parallel()

	if store.KeysFirstPage != store.AgentsFirstPage {
		t.Errorf("the keys' first page bound %q differs from the agents' %q", store.KeysFirstPage, store.AgentsFirstPage)
	}

	if store.KeysFirstPage <= agentLargestID {
		t.Errorf("the first page bound %q does not sort above the greatest id %q", store.KeysFirstPage, agentLargestID)
	}

	_, err := input.ParseID(store.KeysFirstPage)
	if err == nil {
		t.Errorf("the first page bound %q parses as an id", store.KeysFirstPage)
	}
}
