package agents

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

// agentDB is a database/sql driver that answers the agent queries with
// configured rows or an error. D1 only exists inside workerd, so the real SQL is
// proven by the e2e tests; this proves the Go around it.
type agentDB struct {
	rows [][]driver.Value
	err  error
	// rowsErr is returned by Next after the rows, as a failure mid-read.
	rowsErr error

	query string
	args  []driver.Value
}

func (d *agentDB) open(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(agentConnector{d})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

type agentConnector struct{ d *agentDB }

func (c agentConnector) Connect(context.Context) (driver.Conn, error) { return agentConn(c), nil }
func (c agentConnector) Driver() driver.Driver                        { return nil }

type agentConn struct{ d *agentDB }

func (c agentConn) Prepare(query string) (driver.Stmt, error) {
	c.d.query = query

	return agentStmt(c), nil
}
func (c agentConn) Close() error              { return nil }
func (c agentConn) Begin() (driver.Tx, error) { return nil, errDB }

type agentStmt struct{ d *agentDB }

func (s agentStmt) Close() error                               { return nil }
func (s agentStmt) NumInput() int                              { return -1 }
func (s agentStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errDB }

func (s agentStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.d.args = args

	if s.d.err != nil {
		return nil, s.d.err
	}

	return &agentRows{values: s.d.rows, next: 0, err: s.d.rowsErr}, nil
}

type agentRows struct {
	values [][]driver.Value
	next   int
	err    error
}

func (r *agentRows) Columns() []string {
	return []string{"id", "name", "scopes", "revoked_at", "created_at"}
}
func (r *agentRows) Close() error { return nil }

func (r *agentRows) Next(dest []driver.Value) error {
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
	return []driver.Value{testAgentID, testName, DefaultScopes, nil, int64(1000)}
}

func revokedRow() []driver.Value {
	return []driver.Value{testNewID, "old", DefaultScopes, int64(1500), int64(900)}
}

func TestSQLReaderListsTheUsersRows(t *testing.T) {
	t.Parallel()

	fake := &agentDB{rows: [][]driver.Value{activeRow(), revokedRow()}}

	got, err := NewSQLReader(fake.open(t)).List(t.Context(), testUserID, FirstPage, 26)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	wantArgs := []driver.Value{testUserID, FirstPage, int64(26)}
	if fake.query != listQuery || !slices.Equal(fake.args, wantArgs) {
		t.Errorf("ran %q with %v, want the list query for the user, cursor and size", fake.query, fake.args)
	}

	want := []Row{
		{ID: testAgentID, Name: testName, Scopes: DefaultScopes, RevokedAt: nil, CreatedAt: 1000},
		{ID: testNewID, Name: "old", Scopes: DefaultScopes, RevokedAt: new(int64(1500)), CreatedAt: 900},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("List = %+v, want %+v", got, want)
	}
}

func TestSQLReaderListsNothingAsAnEmptySlice(t *testing.T) {
	t.Parallel()

	got, err := NewSQLReader((&agentDB{}).open(t)).List(t.Context(), testUserID, FirstPage, 26)
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("List = %#v, %v, want an empty non-nil slice", got, err)
	}
}

func TestSQLReaderListErrors(t *testing.T) {
	t.Parallel()

	unscannable := []driver.Value{testAgentID, "a", DefaultScopes, nil, "not a number"}

	tests := map[string]*agentDB{
		"query fails":      {err: errDB},
		"mid-read fails":   {rows: [][]driver.Value{activeRow()}, rowsErr: errDB},
		"a row won't scan": {rows: [][]driver.Value{unscannable}},
	}

	for name, fake := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := NewSQLReader(fake.open(t)).List(t.Context(), testUserID, FirstPage, 26)
			if err == nil || got != nil {
				t.Errorf("List = %v, %v, want an error and no rows", got, err)
			}
		})
	}
}

func TestSQLReaderGetIsScopedToTheOwner(t *testing.T) {
	t.Parallel()

	fake := &agentDB{rows: [][]driver.Value{activeRow()}}

	got, err := NewSQLReader(fake.open(t)).Get(t.Context(), testUserID, testAgentID)
	if err != nil || got.ID != testAgentID {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	if fake.query != getQuery || !slices.Equal(fake.args, []driver.Value{testAgentID, testUserID}) {
		t.Errorf("ran %q with %v, want the id and the owner", fake.query, fake.args)
	}
}

func TestSQLReaderGetNotFound(t *testing.T) {
	t.Parallel()

	_, err := NewSQLReader((&agentDB{}).open(t)).Get(t.Context(), testUserID, testAgentID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get error = %v, want ErrNotFound", err)
	}
}

func TestSQLReaderGetWrapsDatabaseErrors(t *testing.T) {
	t.Parallel()

	_, err := NewSQLReader((&agentDB{err: errDB}).open(t)).Get(t.Context(), testUserID, testAgentID)
	if !errors.Is(err, errDB) {
		t.Errorf("error %v does not wrap the driver error", err)
	}
}

// TestRowOfValues: the row a batch returns is read the way scanRow reads one
// from database/sql, including a NULL revoked_at as a nil pointer.
func TestRowOfValues(t *testing.T) {
	t.Parallel()

	got, err := rowOfValues([]any{testAgentID, "a", DefaultScopes, int64(20), int64(30)})
	if err != nil {
		t.Fatal(err)
	}

	want := Row{ID: testAgentID, Name: "a", Scopes: DefaultScopes, RevokedAt: new(int64(20)), CreatedAt: 30}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("row = %+v, want %+v", got, want)
	}

	got, err = rowOfValues([]any{testAgentID, "a", DefaultScopes, nil, int64(30)})
	if err != nil || got.RevokedAt != nil {
		t.Errorf("row = %+v, %v, want a nil revokedAt", got, err)
	}

	for name, values := range map[string][]any{
		"too few columns":  {testAgentID},
		"integer as text":  {int64(1), "a", DefaultScopes, nil, int64(30)},
		"text as integer":  {testAgentID, "a", DefaultScopes, nil, "30"},
		"bad optional":     {testAgentID, "a", DefaultScopes, "soon", int64(30)},
		"two bad, one err": {int64(1), int64(2), DefaultScopes, nil, int64(30)},
	} {
		_, err := rowOfValues(values)
		if !errors.Is(err, errRowShape) {
			t.Errorf("%s: error = %v, want errRowShape", name, err)
		}
	}
}
