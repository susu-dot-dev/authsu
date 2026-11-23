package store_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file is the seam between the invitation columns and the Go bounds that
// have no regular row in schema_test.go: a CHECK that is only a lower limit, a
// column with no CHECK at all (whose only bound is that JavaScript holds the
// value exactly), and the text of a column Go writes a constant to. The label
// and the token hash are already covered by schemaBounds.
//
// Each row reads one declaration out of the migrations (the whitespace-collapsed
// text, see migrations) with a pattern whose capture groups are the limits it
// states, and a check that says how Go's range breaks them, or "" if it fits.
// Every match of the pattern must hold.

// invitationBound is one declaration of the invitations table checked against
// what Go can send.
type invitationBound struct {
	name    string
	pattern string
	check   func(t *testing.T, limits []int64) string
}

func invitationBounds() []invitationBound {
	return []invitationBound{numInvitesLowerBound(), numInvitesUpperBound(), expiresAtBound(), typeBound()}
}

// numInvitesLowerBound: the schema refuses num_invites <= 0. Go's smallest
// value must be above that, and Go must refuse the value the schema's own limit
// names (the first one the database would refuse).
func numInvitesLowerBound() invitationBound {
	return invitationBound{
		name:    "num_invites has a lower limit below Go's smallest",
		pattern: `num_invites INTEGER NOT NULL DEFAULT 1 CHECK \(num_invites > (\d+)\)`,
		check: func(t *testing.T, limits []int64) string {
			t.Helper()

			if smallest := invNum(t, 1).Int64(); smallest <= limits[0] {
				return "Go sends " + strconv.FormatInt(smallest, 10) + "; the schema requires more than " +
					strconv.FormatInt(limits[0], 10)
			}

			_, err := input.ParseNumInvites(limits[0])
			if err == nil {
				return "Go accepts " + strconv.FormatInt(limits[0], 10) + ", which the schema refuses"
			}

			return ""
		},
	}
}

// numInvitesUpperBound: there is no upper limit in the schema, and D1 moves
// integers through JavaScript as float64, so the cap must stay exactly
// representable.
func numInvitesUpperBound() invitationBound {
	return invitationBound{
		name:    "num_invites is an integer column and Go's largest is JavaScript-safe",
		pattern: `num_invites INTEGER NOT NULL`,
		check: func(t *testing.T, _ []int64) string {
			t.Helper()

			if largest := invNum(t, input.MaxNumInvites).Int64(); largest > input.MaxSafeInteger {
				return "the largest cap " + strconv.FormatInt(largest, 10) + " is not JavaScript-safe"
			}

			_, err := input.ParseNumInvites(input.MaxNumInvites + 1)
			if err == nil {
				return "Go accepts a cap above its own maximum"
			}

			return ""
		},
	}
}

// expiresAtBound: secrets.expires_at is NOT NULL and has no CHECK (the pattern
// needs the comma straight after NOT NULL), so the only bound on it is Go's: no
// larger than a number JavaScript holds exactly, even for a clock that is far
// ahead.
func expiresAtBound() invitationBound {
	return invitationBound{
		name:    "expires_at is an unconstrained integer and Go's largest is JavaScript-safe",
		pattern: `expires_at INTEGER NOT NULL,`,
		check: func(t *testing.T, _ []int64) string {
			t.Helper()

			latest := time.Unix(input.MaxSafeInteger-1, 0)

			largest := invExpiry(t, input.MaxSafeInteger, latest).Unix()
			if largest > input.MaxSafeInteger {
				return "the largest expiry " + strconv.FormatInt(largest, 10) + " is not JavaScript-safe"
			}

			_, err := input.ParseExpiry(input.MaxSafeInteger+1, latest)
			if err == nil {
				return "Go accepts an expiry above the JavaScript-safe range"
			}

			// With the clock of the tests, the farthest expiry is the horizon.
			farthest := invExpiry(t, now.Add(input.ExpiryHorizon).Unix(), now).Unix()
			if farthest > input.MaxSafeInteger {
				return "the farthest expiry is not JavaScript-safe"
			}

			return ""
		},
	}
}

// typeBound: the type is written from a Go constant, not parsed from a client.
func typeBound() invitationBound {
	return invitationBound{
		name: "the first-run type fits the type column",
		pattern: `type TEXT NOT NULL CHECK \(typeof\(type\) = 'text' ` +
			`AND length\(type\) BETWEEN (\d+) AND (\d+)\)`,
		check: func(_ *testing.T, limits []int64) string {
			if limits[1] != store.MaxInvitationTypeLen {
				return "MaxInvitationTypeLen is " + strconv.Itoa(store.MaxInvitationTypeLen) +
					"; the schema allows " + strconv.FormatInt(limits[1], 10)
			}

			length := int64(len(store.InvitationFirstRun))
			if length < limits[0] || length > limits[1] {
				return "the first-run type is " + strconv.FormatInt(length, 10) + " characters; the schema allows " +
					strconv.FormatInt(limits[0], 10) + " to " + strconv.FormatInt(limits[1], 10)
			}

			return ""
		},
	}
}

// TestInvitationBoundsFitTheSchema holds that every value the invitation
// operations can send fits what the invitations table and its secret accept.
func TestInvitationBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	for _, bound := range invitationBounds() {
		t.Run(bound.name, func(t *testing.T) {
			t.Parallel()

			matches := regexp.MustCompile(bound.pattern).FindAllStringSubmatch(text, -1)
			if len(matches) == 0 {
				t.Fatalf("no declaration matches %s; was the migration text changed?", bound.pattern)
			}

			for _, match := range matches {
				limits := make([]int64, 0, len(match)-1)

				for _, limit := range match[1:] {
					number, err := strconv.ParseInt(limit, 10, 64)
					if err != nil {
						t.Fatalf("limit %q is not a number: %v", limit, err)
					}

					limits = append(limits, number)
				}

				if problem := bound.check(t, limits); problem != "" {
					t.Error(problem)
				}
			}
		})
	}
}

// TestInvitationStoreSendsNothingLargerThanItsBounds holds that the values the
// store binds are exactly the parsed ones: the largest cap, the longest label
// and the farthest expiry reach the statement unchanged, so what the bounds
// above prove about the parsers holds for what the database receives.
func TestInvitationStoreSendsNothingLargerThanItsBounds(t *testing.T) {
	t.Parallel()

	fake := newFake(readLast(2)(invitationRow()))

	invitation := newInvitation(t)
	invitation.NumInvites = invNum(t, input.MaxNumInvites)
	invitation.Label = invLabel(t, strings.Repeat("x", input.MaxInvitationLabelRunes))
	invitation.ExpiresAt = invExpiry(t, now.Add(input.ExpiryHorizon).Unix(), now)

	_, err := fake.store().CreateInvitation(t.Context(), invitation)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	secretArgs, invitationArgs := fake.calls[0][0].Args, fake.calls[0][1].Args

	// The arguments are: id, kind, type, the creator (for the subselect that
	// tests it is unrevoked), label, num_invites and the creator.
	if got, _ := invitationArgs[5].(int64); got != input.MaxNumInvites || got > input.MaxSafeInteger {
		t.Errorf("num_invites = %v", invitationArgs[5])
	}

	if got, _ := invitationArgs[4].(string); len(got) != input.MaxInvitationLabelRunes {
		t.Errorf("label has %d bytes, want %d", len(got), input.MaxInvitationLabelRunes)
	}

	if got, _ := secretArgs[3].(int64); got != now.Add(input.ExpiryHorizon).Unix() || got > input.MaxSafeInteger {
		t.Errorf("expires_at = %v", secretArgs[3])
	}
}
