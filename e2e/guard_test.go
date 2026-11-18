//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDatabaseIsOnlyOpenedHere holds the rule of db_test.go: the SQLite driver
// is a way to prepare and read back state, so only that file may import it or
// open a connection. Anything under test must go through the Worker over HTTP.
func TestDatabaseIsOnlyOpenedHere(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	forbidden := []string{`"database/sql"`, `modernc.org/sqlite`, "sql.Open(", `"os/exec"`}

	for _, file := range files {
		// This file names the forbidden strings; harness_test.go starts the
		// Worker, which is why it alone may run a command.
		if file == "db_test.go" || file == "guard_test.go" || file == "harness_test.go" {
			continue
		}

		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}

		for _, bad := range forbidden {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s uses %s: only db_test.go may reach the database, and nothing but the harness runs commands", file, bad)
			}
		}
	}
}
