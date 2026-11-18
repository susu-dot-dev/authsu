//go:build e2e

package e2e_test

// db_test.go is the test side channel to the Worker's database, and the only
// file in this package that may open one (TestDatabaseIsOnlyOpenedHere
// enforces it). It exists to PREPARE state (seed rows, reset between tests) and
// to READ state back. It never performs the behaviour under test: every request
// a test is about goes to the Worker over HTTP, through the real wasm, the real
// D1 driver and the real SQL.
//
// Under `wrangler dev` the Worker's D1 is a SQLite file in the state directory.
// Opening it directly costs ~1ms per statement, where `wrangler d1 execute`
// costs ~1.5s: the whole suite used to be bound by that.
//
// Two rules follow from how the file is shared:
//
//   - Writes happen only while the Worker is idle. workerd's own connection does
//     not wait on SQLite's lock, so a seed that lands during a request can make
//     that request fail with SQLITE_BUSY (a 503), which is a test artefact and
//     not a product result. Tests are therefore sequential in their seeding;
//     only the requests inside one test run concurrently.
//   - Reads are always safe: the database is in WAL mode, where a reader never
//     blocks the Worker's writer.

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite" // pure Go: no cgo, never linked into the Worker
)

var (
	dbOnce sync.Once //nolint:gochecknoglobals // one connection pool for the whole run
	dbPool *sql.DB   //nolint:gochecknoglobals // see dbOnce
	errDB  error     //nolint:gochecknoglobals // see dbOnce
)

// database returns the pool for the Worker's D1 file.
func database(t *testing.T) *sql.DB {
	t.Helper()

	dbOnce.Do(func() {
		var file string

		file, errDB = d1File(filepath.Join(target.root, target.state))
		if errDB != nil {
			return
		}

		// foreign_keys is a per-connection pragma and D1 enforces them, so the
		// seeds must too: a seed that D1 would refuse is a wrong seed.
		dsn := "file:" + file + "?_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)"

		dbPool, errDB = sql.Open("sqlite", dsn)
	})

	if errDB != nil {
		t.Fatalf("open the Worker's database: %v", errDB)
	}

	return dbPool
}

// d1File finds the miniflare D1 database: the one .sqlite file that is not the
// metadata store.
func d1File(state string) (string, error) {
	files, err := filepath.Glob(filepath.Join(state, "v3", "d1", "miniflare-D1DatabaseObject", "*.sqlite"))
	if err != nil {
		return "", fmt.Errorf("glob: %w", err)
	}

	var found []string

	for _, file := range files {
		if filepath.Base(file) != "metadata.sqlite" {
			found = append(found, file)
		}
	}

	if len(found) != 1 {
		return "", fmt.Errorf("want exactly one D1 file under %s, found %v: %w", state, found, os.ErrNotExist)
	}

	return found[0], nil
}

// seed runs one statement for its effect. Use ? placeholders and arguments for
// every value, so a seed cannot be broken by a quote and a BLOB is a BLOB.
func seed(t *testing.T, query string, args ...any) {
	t.Helper()

	_, err := database(t).ExecContext(t.Context(), query, args...)
	if err != nil {
		t.Fatalf("seed %q: %v", query, err)
	}
}

// scalar returns the first column of the first row as text, or "" when there is
// no row (or the value is NULL).
func scalar(t *testing.T, query string, args ...any) string {
	t.Helper()

	var out sql.NullString

	err := database(t).QueryRowContext(t.Context(), query, args...).Scan(&out)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("query %q: %v", query, err)
	}

	return out.String
}

// count returns count(*) over "FROM <from>", where from may carry a WHERE.
func count(t *testing.T, from string, args ...any) string {
	t.Helper()

	return scalar(t, "SELECT count(*) FROM "+from, args...)
}

// expectCount fails the test unless count(*) over from is want.
func expectCount(t *testing.T, from, want string, args ...any) {
	t.Helper()

	if got := count(t, from, args...); got != want {
		t.Errorf("count of %s = %s, want %s", from, got, want)
	}
}

// refused reports whether the database refuses the statement: the way a test
// asserts that a schema constraint holds. The statement is run in a transaction
// that is always rolled back, so an accepted one leaves nothing behind.
func refused(t *testing.T, query string, args ...any) bool {
	t.Helper()

	tx, err := database(t).BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(t.Context(), query, args...)

	return err != nil
}

// tableAgents is named because several tests count it.
const (
	tableAgents      = "agents"
	tableCredentials = "credentials"
	tableKeys        = "japikeys"
	tableUsers       = "users"
	tableInvitations = "invitations"
)

// tables are every table a test may leave rows in, children first so a foreign
// key never blocks a delete.
func tables() []string {
	return []string{tableKeys, tableAgents, tableCredentials, tableUsers, tableInvitations}
}

// reset empties every table, so a test starts from a fresh deployment whatever
// ran before it. This is what makes tests independent of source order.
func reset(t *testing.T) {
	t.Helper()

	for _, table := range tables() {
		seed(t, "DELETE FROM "+table)
	}
}
