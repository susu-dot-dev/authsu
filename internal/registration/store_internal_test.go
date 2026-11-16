package registration

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
)

// invitationDB is a database/sql driver that answers the invitation lookup
// with a configured row, no row, or an error. D1 only exists inside workerd, so
// the real SQL is proven by the e2e tests; this proves the Go around it.
type invitationDB struct {
	invitationType string
	found          bool
	err            error

	args []driver.Value
}

func (d *invitationDB) open(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(invitationConnector{d})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

type invitationConnector struct{ d *invitationDB }

func (c invitationConnector) Connect(context.Context) (driver.Conn, error) {
	return invitationConn(c), nil
}
func (c invitationConnector) Driver() driver.Driver { return nil }

type invitationConn struct{ d *invitationDB }

func (c invitationConn) Prepare(string) (driver.Stmt, error) { return invitationStmt(c), nil }
func (c invitationConn) Close() error                        { return nil }
func (c invitationConn) Begin() (driver.Tx, error)           { return nil, errDB }

type invitationStmt struct{ d *invitationDB }

func (s invitationStmt) Close() error  { return nil }
func (s invitationStmt) NumInput() int { return -1 }

func (s invitationStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errDB }

func (s invitationStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.d.args = args

	if s.d.err != nil {
		return nil, s.d.err
	}

	if !s.d.found {
		return &invitationRows{values: nil, next: 0}, nil
	}

	return &invitationRows{values: [][]driver.Value{{s.d.invitationType}}, next: 0}, nil
}

type invitationRows struct {
	values [][]driver.Value
	next   int
}

func (r *invitationRows) Columns() []string { return []string{"type"} }
func (r *invitationRows) Close() error      { return nil }

func (r *invitationRows) Next(dest []driver.Value) error {
	if r.next == len(r.values) {
		return io.EOF
	}

	copy(dest, r.values[r.next])
	r.next++

	return nil
}

func TestSQLReader(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		db       invitationDB
		wantType string
		wantOK   bool
		wantErr  bool
	}{
		"redeemable":     {db: invitationDB{invitationType: firstRun, found: true}, wantType: firstRun, wantOK: true},
		"not redeemable": {db: invitationDB{found: false}},
		"database error": {db: invitationDB{err: errDB}, wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fake := tt.db

			got, ok, err := NewSQLReader(fake.open(t)).RedeemableInvitationType(t.Context(), codeHash(testCode), testNow())
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && !errors.Is(err, errDB) {
				t.Errorf("error %v does not wrap the driver error", err)
			}

			if got != tt.wantType || ok != tt.wantOK {
				t.Errorf("got (%q, %v), want (%q, %v)", got, ok, tt.wantType, tt.wantOK)
			}
		})
	}
}

// TestSQLReaderBindsHashAndTime holds the lookup to the rule that values are
// bound, and checks that the code hash, not the code, is what is bound.
func TestSQLReaderBindsHashAndTime(t *testing.T) {
	t.Parallel()

	fake := &invitationDB{invitationType: firstRun, found: true}

	_, _, err := NewSQLReader(fake.open(t)).RedeemableInvitationType(t.Context(), codeHash(testCode), testNow())
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if len(fake.args) != 2 {
		t.Fatalf("bound %d values, want 2 (code hash, now)", len(fake.args))
	}

	if hash, ok := fake.args[0].([]byte); !ok || string(hash) != string(codeHash(testCode)) {
		t.Errorf("first argument = %v, want the code hash", fake.args[0])
	}

	if fake.args[1] != testNow().Unix() {
		t.Errorf("second argument = %v, want %d", fake.args[1], testNow().Unix())
	}
}
