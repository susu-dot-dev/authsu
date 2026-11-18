package input

// This file exposes the unexported primitives to the external test package.
// It is compiled only into tests.

// DisplayText exposes displayText with a rule built from plain arguments.
func DisplayText(s string, runes bool, limit int, allowEmpty, identifying bool) bool {
	rule := textRule{unit: unitBytes, max: limit, allowEmpty: allowEmpty, identifying: identifying}
	if runes {
		rule.unit = unitRunes
	}

	return displayText(s, rule)
}

// Decimal exposes decimal.
func Decimal(s string, lo, hi int64) (int64, bool) { return decimal(s, lo, hi) }

// SingleValue exposes singleValue.
func SingleValue(values []string) (string, bool, bool) { return singleValue(values) }

// CanonicalUUID exposes canonicalUUID.
func CanonicalUUID(s string) bool { return canonicalUUID(s) }

// Base64URL exposes base64URL.
func Base64URL(s string) bool { return base64URL(s) }
