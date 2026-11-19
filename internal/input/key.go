package input

import "time"

// Bounds of the key types.
const (
	// DefaultKeyLifetimeDays is how long a key lives when its creator names no
	// lifetime: 90 days (docs/permissions_design.md).
	DefaultKeyLifetimeDays = 90

	// MaxUserKeyLifetimeDays is the longest a user may choose for one of their
	// own keys: a year. An agent's keys never live longer than the default,
	// which is why the agent's create does not take a lifetime at all. A
	// lifetime is never stored, only the expiry it gives (secrets.expires_at,
	// Unix seconds, with no range CHECK), so no schema bound applies.
	MaxUserKeyLifetimeDays = 365
)

// CodeInvalidKeyLifetime is the error code of ParseKeyLifetime.
const CodeInvalidKeyLifetime = "invalid_key_lifetime"

const descInvalidKeyLifetime = "lifetimeDays must be a whole number of days from 1 to 365"

// KeyLifetime is how long a new key of the user's own lives.
type KeyLifetime struct{ v time.Duration }

// ParseKeyLifetime accepts a whole number of days from 1 to
// MaxUserKeyLifetimeDays. A day is 24 hours: there is no calendar, no time
// zone and no fraction, so a client and the server cannot disagree about when
// a key ends. Zero and negative lifetimes are refused, not read as "the
// default" or "forever": a client that wants the default leaves the member out.
func ParseKeyLifetime(days int64) (KeyLifetime, error) {
	if days < 1 || days > MaxUserKeyLifetimeDays {
		return KeyLifetime{}, refuse(CodeInvalidKeyLifetime, descInvalidKeyLifetime)
	}

	return KeyLifetime{v: time.Duration(days) * 24 * time.Hour}, nil
}

// DefaultKeyLifetime is the lifetime of a key whose creator names none.
func DefaultKeyLifetime() KeyLifetime {
	return KeyLifetime{v: DefaultKeyLifetimeDays * 24 * time.Hour}
}

// Duration returns the lifetime.
func (l KeyLifetime) Duration() time.Duration { return l.v }
