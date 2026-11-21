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
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// Tables the tests name. Several are counted by many tests.
const (
	tableAgents      = "agents"
	tableLabels      = "agent_labels"
	tableCredentials = "credentials"
	tableKeys        = "api_keys"
	tableSessions    = "sessions"
	tableSecrets     = "secrets"
	tableUsers       = "users"
	tableInvitations = "invitations"

	tableOAuthGrants = "oauth_grants"
	tableOAuthAccess = "oauth_access_tokens"

	tableOrgs      = "orgs"
	tableOrgAdmins = "org_admins"
	tableOrgOffers = "org_offers"
)

// tables are every table a test may leave rows in, in the order that empties
// them without a foreign key ever blocking a delete: a kind's own tables first
// (an access token before its grant),
// then the owners they point at, and last the secrets that no kind row holds
// any more. users go before invitations because users.invitation_id has no
// ON DELETE action. Deleting a session or a key also deletes its secret (a
// trigger), so by the time secrets is emptied it only removes strays.
//
// The organizations sit between the two: offers first (they point at users,
// invitations and organizations with no ON DELETE action that would clear
// them), then administrators, then the organizations, which agents (already
// gone) and users point at. users and orgs point at each other (users.org_id,
// orgs.created_by), so reset releases every member before it deletes either.
func tables() []string {
	return []string{
		tableOAuthAccess, tableOAuthGrants, tableKeys, tableLabels, tableAgents, tableSessions, tableCredentials,
		tableOrgOffers, tableOrgAdmins, tableOrgs, tableUsers, tableInvitations, tableSecrets,
	}
}

// reset empties every table, so a test starts from a fresh deployment whatever
// ran before it. This is what makes tests independent of source order.
func reset(t *testing.T) {
	t.Helper()

	// A member holds its organization with no ON DELETE action, and the
	// organization holds its creator the same way: release the members first,
	// or neither table can be emptied before the other.
	seed(t, "UPDATE users SET org_id = NULL")

	for _, table := range tables() {
		seed(t, "DELETE FROM "+table)
	}
}

// firstRow returns the columns of the first row as text, and whether there was a
// row. A NULL is "". Use it to read several columns in one statement.
func firstRow(t *testing.T, query string, args ...any) ([]string, bool) {
	t.Helper()

	rows, err := database(t).QueryContext(t.Context(), query, args...)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}

	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns of %q: %v", query, err)
	}

	if !rows.Next() {
		err = rows.Err()
		if err != nil {
			t.Fatalf("query %q: %v", query, err)
		}

		return nil, false
	}

	cells := make([]sql.NullString, len(columns))
	targets := make([]any, len(columns))

	for i := range cells {
		targets[i] = &cells[i]
	}

	err = rows.Scan(targets...)
	if err != nil {
		t.Fatalf("scan %q: %v", query, err)
	}

	out := make([]string, len(cells))
	for i, cell := range cells {
		out[i] = cell.String
	}

	return out, true
}

// columnsHolding returns "table.column" for every column of every table that
// holds any of the needles, as text or as bytes. It reads every table the
// database has (sqlite_master), so a table added later is covered without
// anyone remembering to list it. It is how a test shows that a value is stored
// nowhere.
func columnsHolding(t *testing.T, needles ...string) []string {
	t.Helper()

	names := rowsOf(t,
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name")
	found := make([]string, 0, len(names))

	for _, name := range names {
		found = append(found, columnsHoldingIn(t, name, needles)...)
	}

	return found
}

// columnsHoldingIn is columnsHolding for one table.
func columnsHoldingIn(t *testing.T, table string, needles []string) []string {
	t.Helper()

	columns := rowsOf(t, "SELECT name FROM pragma_table_info(?) ORDER BY cid", table)

	quoted := make([]string, len(columns))
	for i, column := range columns {
		quoted[i] = `"` + column + `"`
	}

	rows, err := database(t).QueryContext(t.Context(), "SELECT "+strings.Join(quoted, ", ")+` FROM "`+table+`"`)
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}

	defer func() { _ = rows.Close() }()

	seen := map[string]bool{}

	for rows.Next() {
		cells := make([]any, len(columns))
		targets := make([]any, len(columns))

		for i := range cells {
			targets[i] = &cells[i]
		}

		err = rows.Scan(targets...)
		if err != nil {
			t.Fatalf("scan %s: %v", table, err)
		}

		for i, cell := range cells {
			if cellHolds(cell, needles) {
				seen[table+"."+columns[i]] = true
			}
		}
	}

	err = rows.Err()
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}

	found := make([]string, 0, len(seen))
	for name := range seen {
		found = append(found, name)
	}

	sort.Strings(found)

	return found
}

// cellHolds reports whether one stored value, as text or as bytes, contains any
// of the needles.
func cellHolds(cell any, needles []string) bool {
	var data []byte

	switch value := cell.(type) {
	case string:
		data = []byte(value)
	case []byte:
		data = value
	default:
		return false
	}

	for _, needle := range needles {
		if needle != "" && bytes.Contains(data, []byte(needle)) {
			return true
		}
	}

	return false
}

// rowsOf returns the first column of every row as text.
func rowsOf(t *testing.T, query string, args ...any) []string {
	t.Helper()

	rows, err := database(t).QueryContext(t.Context(), query, args...)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}

	defer func() { _ = rows.Close() }()

	var out []string

	for rows.Next() {
		var cell sql.NullString

		err = rows.Scan(&cell)
		if err != nil {
			t.Fatalf("scan %q: %v", query, err)
		}

		out = append(out, cell.String)
	}

	err = rows.Err()
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}

	return out
}
