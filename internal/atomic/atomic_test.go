package atomic_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/atomic"
)

var (
	errUnavailable = errors.New("D1_ERROR: network connection lost")
	errNotNull     = errors.New("NOT NULL constraint failed: credentials.user_id: SQLITE_CONSTRAINT")
	errUnique      = errors.New("UNIQUE constraint failed: users.user_handle: SQLITE_CONSTRAINT")
	errForeignKey  = errors.New("SQLITE_CONSTRAINT_FOREIGNKEY")
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err          error
		wantConflict bool
	}{
		"nil":                 {err: nil, wantConflict: false},
		"outage":              {err: errUnavailable, wantConflict: false},
		"not null":            {err: errNotNull, wantConflict: true},
		"unique":              {err: errUnique, wantConflict: true},
		"extended code":       {err: errForeignKey, wantConflict: true},
		"wrapped by the call": {err: fmt.Errorf("d1: %w", errUnique), wantConflict: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := atomic.Classify(tt.err)

			if errors.Is(got, atomic.ErrConflict) != tt.wantConflict {
				t.Errorf("Classify(%v) conflict = %v, want %v", tt.err, !tt.wantConflict, tt.wantConflict)
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
