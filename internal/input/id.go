package input

// Bounds of the identifier types.
const (
	// IDLen is the length of an ID: the 8-4-4-4-12 text form. Every id column
	// is checked with `length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*'`
	// (secrets, users, credentials, agents and the kind tables in migration
	// 0001), which this form satisfies exactly.
	IDLen = uuidLen
)

// CodeInvalidID is the error code of ParseID.
const CodeInvalidID = "invalid_id"

const descInvalidID = "id must be a lower-case UUID such as 01234567-89ab-cdef-0123-456789abcdef"

// ID identifies a resource, as a client sends it in a path or a cursor.
type ID struct{ v string }

// ParseID accepts exactly the canonical lower-case UUID text form.
func ParseID(raw string) (ID, error) {
	if !canonicalUUID(raw) {
		return ID{}, refuse(CodeInvalidID, descInvalidID)
	}

	return ID{v: raw}, nil
}

// String returns the id exactly as it was parsed.
func (i ID) String() string { return i.v }
