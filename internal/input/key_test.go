//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"math"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

func TestKeyLifetimeDescriptionStatesTheBound(t *testing.T) {
	t.Parallel()

	_, err := input.ParseKeyLifetime(0)
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidKeyLifetime), input.MaxUserKeyLifetimeDays)
}

// TestParseKeyLifetime: a whole number of days from 1 to a year is accepted and
// is exactly that many 24-hour days; everything else, including every value a
// narrower integer type would wrap into range, is refused.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestParseKeyLifetime(t *testing.T) {
	t.Parallel()

	const day = 24 * time.Hour

	cases := []struct {
		name string
		in   int64
		ok   bool
	}{
		{"one day", 1, true},
		{"two days", 2, true},
		{"the default", input.DefaultKeyLifetimeDays, true},
		{"a year less a day", input.MaxUserKeyLifetimeDays - 1, true},
		{"a year", input.MaxUserKeyLifetimeDays, true},
		{"a year and a day", input.MaxUserKeyLifetimeDays + 1, false},
		{"zero", 0, false},
		{"minus one", -1, false},
		{"2^32 (zero when truncated to 32 bits)", 1 << 32, false},
		{"2^32 + 1 (one when truncated to 32 bits)", 1<<32 + 1, false},
		{"a value whose nanoseconds overflow a duration", math.MaxInt64 / int64(day), false},
		{"int32 max", math.MaxInt32, false},
		{"safe max", input.MaxSafeInteger, false},
		{"safe max + 1", input.MaxSafeInteger + 1, false},
		{"int64 max", math.MaxInt64, false},
		{"int64 min", math.MinInt64, false},
	}

	var description string

	for _, tc := range cases {
		if !tc.ok {
			_, err := input.ParseKeyLifetime(tc.in)
			description = descriptionOf(t, err, input.CodeInvalidKeyLifetime)

			break
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseKeyLifetime(tc.in)
			if !tc.ok {
				requireFixedRefusal(t, err, input.CodeInvalidKeyLifetime, description)

				if got.Duration() != 0 {
					t.Errorf("refused input returned %v", got.Duration())
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			if want := time.Duration(tc.in) * day; got.Duration() != want {
				t.Errorf("Duration() = %v, want %v", got.Duration(), want)
			}
		})
	}
}

// TestKeyLifetimeConstants pins the numbers the design states: 90 days by
// default and a year at most.
func TestKeyLifetimeConstants(t *testing.T) {
	t.Parallel()

	if got := input.DefaultKeyLifetime().Duration(); got != 90*24*time.Hour {
		t.Errorf("DefaultKeyLifetime = %v, want 90 days", got)
	}

	if input.MaxUserKeyLifetimeDays != 365 || input.DefaultKeyLifetimeDays != 90 {
		t.Errorf("bounds = %d and %d, want 365 and 90", input.MaxUserKeyLifetimeDays, input.DefaultKeyLifetimeDays)
	}

	var zero input.KeyLifetime
	if zero.Duration() != 0 {
		t.Errorf("the zero KeyLifetime is %v, want 0", zero.Duration())
	}
}

func FuzzParseKeyLifetime(f *testing.F) {
	for _, seed := range []int64{
		0, 1, 2, input.DefaultKeyLifetimeDays, input.MaxUserKeyLifetimeDays, input.MaxUserKeyLifetimeDays + 1,
		-1, math.MaxInt32, 1 << 32, input.MaxSafeInteger, math.MaxInt64, math.MinInt64,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in int64) {
		got, err := input.ParseKeyLifetime(in)
		inRange := in >= 1 && in <= input.MaxUserKeyLifetimeDays

		if inRange != (err == nil) {
			t.Fatalf("ParseKeyLifetime(%d) err = %v, in range = %v", in, err, inRange)
		}

		if err != nil {
			requireRefusal(t, err, input.CodeInvalidKeyLifetime)

			return
		}

		if got.Duration() != time.Duration(in)*24*time.Hour {
			t.Fatalf("ParseKeyLifetime(%d) = %v", in, got.Duration())
		}
	})
}
