package input

import "time"

// Bounds of the invitation types.
const (
	// MaxNumInvites bounds NumInvites. The schema CHECK is only
	// `num_invites > 0` (migration 0001); the upper bound is a Go policy and
	// is far below MaxSafeInteger.
	MaxNumInvites = 10000

	// ExpiryHorizon is the furthest ahead an Expiry may lie: 10 years of 365
	// days. It is also the default invitation lifetime, for an invitation
	// whose creator names no expiry. The column is `secrets.expires_at INTEGER
	// NOT NULL` (migration 0001), Unix seconds, with no range CHECK; at the
	// current date this is about 2.0e9 seconds, far below MaxSafeInteger.
	ExpiryHorizon = 10 * 365 * 24 * time.Hour
)

// Error codes of the invitation types. The code of the invitation token is
// CodeInvalidInvitation, beside the other token codes.
const (
	CodeInvalidNumInvites = "invalid_num_invites"
	CodeInvalidExpiresAt  = "invalid_expires_at"
)

const (
	descInvalidNumInvites = "num_invites must be an integer from 1 to 10000"
	descInvalidExpiresAt  = "expires_at must be a Unix time in seconds, in the future and at most 10 years ahead"
)

// NumInvites is how many people one invitation may admit.
type NumInvites struct{ v int64 }

// ParseNumInvites accepts 1 to MaxNumInvites.
func ParseNumInvites(raw int64) (NumInvites, error) {
	if raw < 1 || raw > MaxNumInvites {
		return NumInvites{}, refuse(CodeInvalidNumInvites, descInvalidNumInvites)
	}

	return NumInvites{v: raw}, nil
}

// Int64 returns the count.
func (n NumInvites) Int64() int64 { return n.v }

// Expiry is the moment an invitation stops working, in Unix seconds.
type Expiry struct{ v int64 }

// ParseExpiry accepts a Unix time in seconds that is strictly after now and no
// more than ExpiryHorizon ahead of it. The value must also lie within
// +/-MaxSafeInteger, whatever now is. now is a parameter: the package holds no
// clock, and its sub-second part counts, so unix equal to now's whole second is
// in the past.
func ParseExpiry(unix int64, now time.Time) (Expiry, error) {
	// A safe-integer check first, so that time.Unix below cannot wrap and the
	// comparisons are exact. The check is symmetric because a clock before
	// 1970 is arithmetic, not a defect this package is placed to detect.
	if unix > MaxSafeInteger || unix < -MaxSafeInteger {
		return Expiry{}, refuse(CodeInvalidExpiresAt, descInvalidExpiresAt)
	}

	// Time.Sub saturates instead of overflowing, so a distant clock or expiry
	// is simply "more than the horizon".
	at := time.Unix(unix, 0)
	if !at.After(now) || at.Sub(now) > ExpiryHorizon {
		return Expiry{}, refuse(CodeInvalidExpiresAt, descInvalidExpiresAt)
	}

	return Expiry{v: unix}, nil
}

// Unix returns the expiry as Unix seconds.
func (e Expiry) Unix() int64 { return e.v }
