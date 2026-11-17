package invitations

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

// invDB is a database/sql driver that answers the invitation queries with
// configured rows or an error. D1 only exists inside workerd, so the real SQL is
// proven by the e2e tests; this proves the Go around it.
type invDB struct {
	rows [][]driver.Value
	err  error
	// rowsErr is returned by Next after the rows, as a failure mid-read.
	rowsErr error

	query string
	args  []driver.Value
}

func (d *invDB) open(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(invConnector{d})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

type invConnector struct{ d *invDB }

func (c invConnector) Connect(context.Context) (driver.Conn, error) { return invConn(c), nil }
func (c invConnector) Driver() driver.Driver                        { return nil }

type invConn struct{ d *invDB }

func (c invConn) Prepare(query string) (driver.Stmt, error) {
	c.d.query = query

	return invStmt(c), nil
}
func (c invConn) Close() error              { return nil }
func (c invConn) Begin() (driver.Tx, error) { return nil, errDB }

type invStmt struct{ d *invDB }

func (s invStmt) Close() error                               { return nil }
func (s invStmt) NumInput() int                              { return -1 }
func (s invStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errDB }

func (s invStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.d.args = args

	if s.d.err != nil {
		return nil, s.d.err
	}

	return &invRows{values: s.d.rows, next: 0, err: s.d.rowsErr}, nil
}

type invRows struct {
	values [][]driver.Value
	next   int
	err    error
}

func (r *invRows) Columns() []string {
	return []string{"id", "type", "label", "num_invites", "uses", "expires_at", "revoked_at", "created_by", "created_at"}
}
func (r *invRows) Close() error { return nil }

func (r *invRows) Next(dest []driver.Value) error {
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

func plainRow() []driver.Value {
	return []driver.Value{testInvID, testType, noteLabel, int64(5), int64(2), nil, nil, nil, int64(1000)}
}

func fullRow() []driver.Value {
	return []driver.Value{
		testInvID, testType, noteLabel, int64(5), int64(5), int64(2000), int64(1500), testAdminID, int64(1000),
	}
}

func unscannableRow() []driver.Value {
	return []driver.Value{testInvID, testType, noteLabel, "not a number", int64(0), nil, nil, nil, int64(1)}
}

func TestSQLReaderListsRows(t *testing.T) {
	t.Parallel()

	fake := &invDB{rows: [][]driver.Value{plainRow(), fullRow()}}

	got, err := NewSQLReader(fake.open(t)).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if fake.query != listQuery {
		t.Errorf("ran %q, want the list query", fake.query)
	}

	// A NULL column is a nil pointer, a set one points at its value.
	want := []Row{
		{
			ID: testInvID, Type: testType, Label: noteLabel, NumInvites: 5, Uses: 2,
			ExpiresAt: nil, RevokedAt: nil, CreatedBy: nil, CreatedAt: 1000,
		},
		{
			ID: testInvID, Type: testType, Label: noteLabel, NumInvites: 5, Uses: 5,
			ExpiresAt: new(int64(2000)), RevokedAt: new(int64(1500)), CreatedBy: new(testAdminID), CreatedAt: 1000,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("List = %+v, want %+v", got, want)
	}
}

func TestSQLReaderListsNothingAsAnEmptySlice(t *testing.T) {
	t.Parallel()

	got, err := NewSQLReader((&invDB{}).open(t)).List(t.Context())
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("List = %#v, %v, want an empty non-nil slice", got, err)
	}
}

func TestSQLReaderListErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]*invDB{
		"query fails":      {err: errDB},
		"mid-read fails":   {rows: [][]driver.Value{plainRow()}, rowsErr: errDB},
		"a row won't scan": {rows: [][]driver.Value{unscannableRow()}},
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

	fake := &invDB{rows: [][]driver.Value{fullRow()}}

	got, err := NewSQLReader(fake.open(t)).Get(t.Context(), testInvID)
	if err != nil || got.ID != testInvID {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	if fake.query != getQuery || !slices.Equal(fake.args, []driver.Value{testInvID}) {
		t.Errorf("ran %q with %v", fake.query, fake.args)
	}
}

func TestSQLReaderGetNotFound(t *testing.T) {
	t.Parallel()

	_, err := NewSQLReader((&invDB{}).open(t)).Get(t.Context(), testInvID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get error = %v, want ErrNotFound", err)
	}
}

func TestSQLReaderGetWrapsDatabaseErrors(t *testing.T) {
	t.Parallel()

	_, err := NewSQLReader((&invDB{err: errDB}).open(t)).Get(t.Context(), testInvID)
	if !errors.Is(err, errDB) {
		t.Errorf("error %v does not wrap the driver error", err)
	}
}

// TestRowOfValues: the row a batch returns is read the way scanRow reads one
// from database/sql, including NULL columns as nil pointers.
func TestRowOfValues(t *testing.T) {
	t.Parallel()

	t.Run("every column set", func(t *testing.T) {
		t.Parallel()

		got, err := rowOfValues(
			[]any{testInvID, "t", "note", int64(5), int64(2), int64(10), int64(20), testAdminID, int64(30)})
		if err != nil {
			t.Fatal(err)
		}

		want := Row{
			ID: testInvID, Type: "t", Label: "note", NumInvites: 5, Uses: 2,
			ExpiresAt: new(int64(10)), RevokedAt: new(int64(20)), CreatedBy: new(testAdminID), CreatedAt: 30,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("row = %+v, want %+v", got, want)
		}
	})

	t.Run("NULL columns are nil", func(t *testing.T) {
		t.Parallel()

		got, err := rowOfValues([]any{testInvID, "t", "", int64(5), int64(0), nil, nil, nil, int64(30)})
		if err != nil {
			t.Fatal(err)
		}

		if got.ExpiresAt != nil || got.RevokedAt != nil || got.CreatedBy != nil {
			t.Errorf("row = %+v, want nil pointers", got)
		}
	})

	t.Run("refuses what is not a row", func(t *testing.T) {
		t.Parallel()

		for name, values := range map[string][]any{
			"too few columns": {testInvID},
			"text as integer": {testInvID, "t", "", "5", int64(0), nil, nil, nil, int64(30)},
			"integer as text": {int64(1), "t", "", int64(5), int64(0), nil, nil, nil, int64(30)},
			"bad optional":    {testInvID, "t", "", int64(5), int64(0), "soon", nil, nil, int64(30)},
			"bad optional tx": {testInvID, "t", "", int64(5), int64(0), nil, nil, int64(9), int64(30)},
		} {
			_, err := rowOfValues(values)
			if !errors.Is(err, errRowShape) {
				t.Errorf("%s: error = %v, want errRowShape", name, err)
			}
		}
	})
}
