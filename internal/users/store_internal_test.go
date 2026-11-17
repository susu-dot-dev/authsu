package users

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"slices"
	"testing"
)

// userDB is a database/sql driver that answers the account queries with
// configured rows or an error. D1 only exists inside workerd, so the real SQL is
// proven by the e2e tests; this proves the Go around it.
type userDB struct {
	rows [][]driver.Value
	err  error
	// rowsErr is returned by Next after the rows, as a failure mid-read.
	rowsErr error

	query string
	args  []driver.Value
}

func (d *userDB) open(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(userConnector{d})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

type userConnector struct{ d *userDB }

func (c userConnector) Connect(context.Context) (driver.Conn, error) { return userConn(c), nil }
func (c userConnector) Driver() driver.Driver                        { return nil }

type userConn struct{ d *userDB }

func (c userConn) Prepare(query string) (driver.Stmt, error) {
	c.d.query = query

	return userStmt(c), nil
}
func (c userConn) Close() error              { return nil }
func (c userConn) Begin() (driver.Tx, error) { return nil, errDB }

type userStmt struct{ d *userDB }

func (s userStmt) Close() error                               { return nil }
func (s userStmt) NumInput() int                              { return -1 }
func (s userStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errDB }

func (s userStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.d.args = args

	if s.d.err != nil {
		return nil, s.d.err
	}

	return &userRows{values: s.d.rows, next: 0, err: s.d.rowsErr}, nil
}

type userRows struct {
	values [][]driver.Value
	next   int
	err    error
}

func (r *userRows) Columns() []string {
	return []string{"id", "role", "invitation_id", "profile", "revoked_at", "created_at"}
}
func (r *userRows) Close() error { return nil }

func (r *userRows) Next(dest []driver.Value) error {
	if r.next == len(r.values) {
		if r.err != nil {
			return r.err
		}

		return io.EOF
	}

	copy(dest, r.values[r.next])
	r.next++

	return nil
}

func activeRow() []driver.Value {
	return []driver.Value{testUserID, roleMember, testInvID, testProfile, nil, int64(1000)}
}

func revokedRow() []driver.Value {
	return []driver.Value{testAdminID, roleAdmin, testInvID, "{}", int64(1500), int64(1000)}
}

func TestSQLReaderListsRows(t *testing.T) {
	t.Parallel()

	fake := &userDB{rows: [][]driver.Value{activeRow(), revokedRow()}}

	got, err := NewSQLReader(fake.open(t)).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if fake.query != listQuery {
		t.Errorf("ran %q, want the list query", fake.query)
	}

	want := []Row{
		{ID: testUserID, Role: roleMember, InvitationID: testInvID, Profile: testProfile, RevokedAt: nil, CreatedAt: 1000},
		{
			ID: testAdminID, Role: roleAdmin, InvitationID: testInvID, Profile: "{}",
			RevokedAt: new(int64(1500)), CreatedAt: 1000,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("List = %+v, want %+v", got, want)
	}
}

func TestSQLReaderListsNothingAsAnEmptySlice(t *testing.T) {
	t.Parallel()

	got, err := NewSQLReader((&userDB{}).open(t)).List(t.Context())
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("List = %#v, %v, want an empty non-nil slice", got, err)
	}
}

func TestSQLReaderListErrors(t *testing.T) {
	t.Parallel()

	unscannable := []driver.Value{testUserID, roleMember, testInvID, "{}", nil, "not a number"}

	tests := map[string]*userDB{
		"query fails":      {err: errDB},
		"mid-read fails":   {rows: [][]driver.Value{activeRow()}, rowsErr: errDB},
		"a row won't scan": {rows: [][]driver.Value{unscannable}},
	}

	for name, fake := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := NewSQLReader(fake.open(t)).List(t.Context())
			if err == nil || got != nil {
				t.Errorf("List = %v, %v, want an error and no rows", got, err)
			}
		})
	}
}

func TestSQLReaderGet(t *testing.T) {
	t.Parallel()

	fake := &userDB{rows: [][]driver.Value{activeRow()}}

	got, err := NewSQLReader(fake.open(t)).Get(t.Context(), testUserID)
	if err != nil || got.ID != testUserID {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	if fake.query != getQuery || !slices.Equal(fake.args, []driver.Value{testUserID}) {
		t.Errorf("ran %q with %v", fake.query, fake.args)
	}
}

func TestSQLReaderGetNotFound(t *testing.T) {
	t.Parallel()

	_, err := NewSQLReader((&userDB{}).open(t)).Get(t.Context(), testUserID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get error = %v, want ErrNotFound", err)
	}
}

func TestSQLReaderGetWrapsDatabaseErrors(t *testing.T) {
	t.Parallel()

	_, err := NewSQLReader((&userDB{err: errDB}).open(t)).Get(t.Context(), testUserID)
	if !errors.Is(err, errDB) {
		t.Errorf("error %v does not wrap the driver error", err)
	}
}

// TestRowOfValues: the row a batch returns is read the way scanRow reads one
// from database/sql, including a NULL revoked_at as a nil pointer.
func TestRowOfValues(t *testing.T) {
	t.Parallel()

	got, err := rowOfValues([]any{testUserID, roleAdmin, testInvID, "{}", int64(20), int64(30)})
	if err != nil {
		t.Fatal(err)
	}

	want := Row{
		ID: testUserID, Role: roleAdmin, InvitationID: testInvID, Profile: "{}", RevokedAt: new(int64(20)), CreatedAt: 30,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("row = %+v, want %+v", got, want)
	}

	got, err = rowOfValues([]any{testUserID, roleAdmin, testInvID, "{}", nil, int64(30)})
	if err != nil || got.RevokedAt != nil {
		t.Errorf("row = %+v, %v, want a nil revokedAt", got, err)
	}

	for name, values := range map[string][]any{
		"too few columns":  {testUserID},
		"integer as text":  {int64(1), roleAdmin, testInvID, "{}", nil, int64(30)},
		"text as integer":  {testUserID, roleAdmin, testInvID, "{}", nil, "30"},
		"bad optional":     {testUserID, roleAdmin, testInvID, "{}", "soon", int64(30)},
		"two bad, one err": {int64(1), int64(2), testInvID, "{}", nil, int64(30)},
	} {
		_, err := rowOfValues(values)
		if !errors.Is(err, errRowShape) {
			t.Errorf("%s: error = %v, want errRowShape", name, err)
		}
	}
}
