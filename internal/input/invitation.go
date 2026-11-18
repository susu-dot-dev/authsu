package input

import (
	"crypto/sha256"
	"time"
)

// Bounds of the invitation types.
const (
	// MaxInvitationCodeBytes bounds InvitationCode, in bytes. Only its SHA-256
	// is stored (invitations.code_hash, `typeof(code_hash) = 'blob' AND
	// length(code_hash) = 32`, migration 0001), so the code's own length is
	// not constrained by the schema; the bound limits the work a request can
	// cause and the size of a value that is logged or hashed.
	MaxInvitationCodeBytes = 256

	// MaxNumInvites bounds NumInvites. The schema CHECK is only
	// `num_invites > 0` (migration 0001); the upper bound is a Go policy and
	// is far below MaxSafeInteger.
	MaxNumInvites = 10000

	// ExpiryHorizon is the furthest ahead an Expiry may lie: 10 years of 365
	// days. expires_at has no CHECK (migration 0001: `expires_at INTEGER`,
	// Unix seconds); at the current date this is about 2.0e9 seconds, far
	// below MaxSafeInteger.
	ExpiryHorizon = 10 * 365 * 24 * time.Hour
)

// Error codes of the invitation types.
const (
	CodeInvalidInvitation = "invalid_invitation"
	CodeInvalidNumInvites = "invalid_num_invites"
	CodeInvalidExpiresAt  = "invalid_expires_at"
)

const (
	descInvalidInvitation = "invitation code must be 1 to 256 characters from A-Z, a-z, 0-9, '_' and '-'"
	descInvalidNumInvites = "num_invites must be an integer from 1 to 10000"
	descInvalidExpiresAt  = "expires_at must be a Unix time in seconds, in the future and at most 10 years ahead"
)

// InvitationCode is the secret an invitee presents to register.
type InvitationCode struct{ v string }

// ParseInvitationCode accepts 1 to MaxInvitationCodeBytes bytes of the
// base64url alphabet.
func ParseInvitationCode(raw string) (InvitationCode, error) {
	if raw == "" || len(raw) > MaxInvitationCodeBytes || !base64URL(raw) {
		return InvitationCode{}, refuse(CodeInvalidInvitation, descInvalidInvitation)
	}

	return InvitationCode{v: raw}, nil
}

// String returns the code exactly as it was parsed.
func (c InvitationCode) String() string { return c.v }

// Hash returns the SHA-256 of the code: the value stored as
// invitations.code_hash. It is the one place codes are hashed, so a lookup and
// an insert cannot disagree.
func (c InvitationCode) Hash() []byte {
	sum := sha256.Sum256([]byte(c.v))

	return sum[:]
}

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
