package atomic_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/atomic"
)

// The messages are what D1 actually returns (captured from the local D1 with
// `wrangler d1 execute`), one per kind of constraint.
// d1Message builds a message in the shape D1 returns: the failed rule, then
// SQLite's primary code and the extended code.
func d1Message(rule, extended string) error {
	return fmt.Errorf("%s: SQLITE_CONSTRAINT (extended: %s)", rule, extended) //nolint:err113 // a test fixture
}

var (
	errUnavailable = errors.New("D1_ERROR: network connection lost")
	errUnique      = d1Message("UNIQUE constraint failed: users.user_handle", "SQLITE_CONSTRAINT_UNIQUE")
	errPrimaryKey  = d1Message("UNIQUE constraint failed: users.id", "SQLITE_CONSTRAINT_PRIMARYKEY")
	errNotNull     = d1Message("NOT NULL constraint failed: credentials.user_id", "SQLITE_CONSTRAINT_NOTNULL")
	errCheck       = d1Message("CHECK constraint failed: flags BETWEEN 0 AND 255", "SQLITE_CONSTRAINT_CHECK")
	errForeignKey  = d1Message("FOREIGN KEY constraint failed", "SQLITE_CONSTRAINT_FOREIGNKEY")
	errPrimaryOnly = errors.New("something failed: SQLITE_CONSTRAINT")
	errNewCode     = d1Message("a rule failed", "SQLITE_CONSTRAINT_SOMETHINGNEW")
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err          error
		wantConflict bool
		wantRejected bool
	}{
		"nil":                          {err: nil},
		"outage":                       {err: errUnavailable},
		"unique":                       {err: errUnique, wantConflict: true},
		"primary key":                  {err: errPrimaryKey, wantConflict: true},
		"not null":                     {err: errNotNull, wantConflict: true},
		"check":                        {err: errCheck, wantRejected: true},
		"foreign key":                  {err: errForeignKey, wantRejected: true},
		"primary code only":            {err: errPrimaryOnly, wantRejected: true},
		"extended code not known":      {err: errNewCode, wantRejected: true},
		"wrapped by the call (unique)": {err: fmt.Errorf("d1: %w", errUnique), wantConflict: true},
		"wrapped by the call (check)":  {err: fmt.Errorf("d1: %w", errCheck), wantRejected: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := atomic.Classify(tt.err)

			if errors.Is(got, atomic.ErrConflict) != tt.wantConflict {
				t.Errorf("Classify(%v) conflict = %v, want %v", tt.err, !tt.wantConflict, tt.wantConflict)
			}

			if errors.Is(got, atomic.ErrRejected) != tt.wantRejected {
				t.Errorf("Classify(%v) rejected = %v, want %v", tt.err, !tt.wantRejected, tt.wantRejected)
			}

			// The original error is always kept, for the log.
			if tt.err != nil && !errors.Is(got, tt.err) {
				t.Errorf("Classify(%v) = %v, lost the original error", tt.err, got)
			}

			if tt.err == nil && got != nil {
				t.Errorf("Classify(nil) = %v, want nil", got)
			}
		})
	}
}
