package session

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"slices"
	"testing"
	"time"
)

// keyDB is a database/sql driver that answers the key lookup with a configured
// row, no row, or an error. D1 only exists inside workerd, so the real SQL is
// proven by the e2e tests; this proves the Go around it.
type keyDB struct {
	row []driver.Value
	err error

	args []driver.Value
}

func (d *keyDB) open(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(keyConnector{d})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

type keyConnector struct{ d *keyDB }

func (c keyConnector) Connect(context.Context) (driver.Conn, error) { return keyConn(c), nil }
func (c keyConnector) Driver() driver.Driver                        { return nil }

type keyConn struct{ d *keyDB }

func (c keyConn) Prepare(string) (driver.Stmt, error) { return keyStmt(c), nil }
func (c keyConn) Close() error                        { return nil }
func (c keyConn) Begin() (driver.Tx, error)           { return nil, errDB }

type keyStmt struct{ d *keyDB }

func (s keyStmt) Close() error  { return nil }
func (s keyStmt) NumInput() int { return -1 }

func (s keyStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errDB }

func (s keyStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.d.args = args

	if s.d.err != nil {
		return nil, s.d.err
	}

	if s.d.row == nil {
		return &keyRows{values: nil, next: 0}, nil
	}

	return &keyRows{values: [][]driver.Value{s.d.row}, next: 0}, nil
}

type keyRows struct {
	values [][]driver.Value
	next   int
}

func (r *keyRows) Columns() []string {
	return []string{"jwk", "user_id", "credential_id", "role", "expires_at"}
}
func (r *keyRows) Close() error { return nil }

func (r *keyRows) Next(dest []driver.Value) error {
	if r.next == len(r.values) {
		return io.EOF
	}

	copy(dest, r.values[r.next])
	r.next++

	return nil
}

func TestSQLReaderReturnsTheActiveKey(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	fake := &keyDB{
		row: []driver.Value{`{"keys":[]}`, testUserID, testCredID, testRole, now.Add(time.Hour).Unix()},
		err: nil, args: nil,
	}

	got, ok, err := NewSQLReader(fake.open(t)).ActiveKey(t.Context(), "kid-1", now)
	if err != nil || !ok {
		t.Fatalf("ActiveKey = %v, %v", ok, err)
	}

	want := ActiveKey{
		JWK: []byte(`{"keys":[]}`), UserID: testUserID, CredentialID: testCredID, Role: testRole,
		ExpiresAt: now.Add(time.Hour),
	}

	if string(got.JWK) != string(want.JWK) || got.UserID != want.UserID || got.CredentialID != want.CredentialID ||
		got.Role != want.Role || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("key = %+v, want %+v", got, want)
	}

	// kid, then now twice (the revocation and expiry comparisons), all bound.
	wantArgs := []driver.Value{"kid-1", now.Unix(), now.Unix()}
	if !slices.Equal(fake.args, wantArgs) {
		t.Errorf("bound = %v, want %v", fake.args, wantArgs)
	}
}

func TestSQLReaderReportsNoActiveKey(t *testing.T) {
	t.Parallel()

	fake := &keyDB{row: nil, err: nil, args: nil}

	_, ok, err := NewSQLReader(fake.open(t)).ActiveKey(t.Context(), "kid-1", time.Now())
	if err != nil || ok {
		t.Errorf("ActiveKey = %v, %v, want not found and no error", ok, err)
	}
}

func TestSQLReaderWrapsDatabaseErrors(t *testing.T) {
	t.Parallel()

	fake := &keyDB{row: nil, err: errDB, args: nil}

	_, _, err := NewSQLReader(fake.open(t)).ActiveKey(t.Context(), "kid-1", time.Now())
	if !errors.Is(err, errDB) {
		t.Errorf("error %v does not wrap the driver error", err)
	}
}
