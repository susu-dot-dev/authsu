package login

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
)

// credentialDB is a database/sql driver that answers the credential lookup with
// a configured row, no row, or an error. D1 only exists inside workerd, so the
// real SQL is proven by the e2e tests; this proves the Go around it.
type credentialDB struct {
	row []driver.Value
	err error

	args []driver.Value
}

func (d *credentialDB) open(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(credentialConnector{d})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

type credentialConnector struct{ d *credentialDB }

func (c credentialConnector) Connect(context.Context) (driver.Conn, error) {
	return credentialConn(c), nil
}
func (c credentialConnector) Driver() driver.Driver { return nil }

type credentialConn struct{ d *credentialDB }

func (c credentialConn) Prepare(string) (driver.Stmt, error) { return credentialStmt(c), nil }
func (c credentialConn) Close() error                        { return nil }
func (c credentialConn) Begin() (driver.Tx, error)           { return nil, errDB }

type credentialStmt struct{ d *credentialDB }

func (s credentialStmt) Close() error  { return nil }
func (s credentialStmt) NumInput() int { return -1 }

func (s credentialStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errDB }

func (s credentialStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.d.args = args

	if s.d.err != nil {
		return nil, s.d.err
	}

	if s.d.row == nil {
		return &credentialRows{values: nil, next: 0}, nil
	}

	return &credentialRows{values: [][]driver.Value{s.d.row}, next: 0}, nil
}

type credentialRows struct {
	values [][]driver.Value
	next   int
}

func (r *credentialRows) Columns() []string {
	return []string{"id", "user_id", "public_key", "flags", "user_handle", "role"}
}
func (r *credentialRows) Close() error { return nil }

func (r *credentialRows) Next(dest []driver.Value) error {
	if r.next == len(r.values) {
		return io.EOF
	}

	copy(dest, r.values[r.next])
	r.next++

	return nil
}

func TestSQLReaderReturnsTheCredentialAndItsAccount(t *testing.T) {
	t.Parallel()

	fake := &credentialDB{
		row: []driver.Value{testCredRowID, testUserID, []byte("cose"), int64(0x05), testHandle(), testRole},
		err: nil, args: nil,
	}

	got, ok, err := NewSQLReader(fake.open(t)).CredentialByID(t.Context(), testCredID())
	if err != nil || !ok {
		t.Fatalf("CredentialByID = %v, %v", ok, err)
	}

	if got.ID != testCredRowID || got.UserID != testUserID || got.Role != testRole || got.Flags != 0x05 {
		t.Errorf("credential = %+v", got)
	}

	if string(got.PublicKey) != "cose" || string(got.UserHandle) != string(testHandle()) {
		t.Errorf("credential key or handle = %q %q", got.PublicKey, got.UserHandle)
	}

	// The id is bound, not interpolated.
	assertBound(t, fake.args, testCredID())
}

// assertBound checks the one bound argument is want.
func assertBound(t *testing.T, args []driver.Value, want []byte) {
	t.Helper()

	if len(args) != 1 {
		t.Fatalf("bound %d values, want 1", len(args))
	}

	got, ok := args[0].([]byte)
	if !ok || !bytes.Equal(got, want) {
		t.Errorf("bound = %v, want the credential id %x", args[0], want)
	}
}

func TestSQLReaderReportsNoCredential(t *testing.T) {
	t.Parallel()

	fake := &credentialDB{row: nil, err: nil, args: nil}

	_, ok, err := NewSQLReader(fake.open(t)).CredentialByID(t.Context(), testCredID())
	if err != nil || ok {
		t.Errorf("CredentialByID = %v, %v, want not found and no error", ok, err)
	}
}

func TestSQLReaderWrapsDatabaseErrors(t *testing.T) {
	t.Parallel()

	fake := &credentialDB{row: nil, err: errDB, args: nil}

	_, _, err := NewSQLReader(fake.open(t)).CredentialByID(t.Context(), testCredID())
	if !errors.Is(err, errDB) {
		t.Errorf("error %v does not wrap the driver error", err)
	}
}
