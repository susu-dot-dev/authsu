package input

// Error codes of the sandbox types.
const (
	CodeInvalidSandboxID     = "invalid_sandbox_id"
	CodeInvalidSandboxFilter = "invalid_sandbox_filter"
)

const (
	descInvalidSandboxID     = "sandboxId must be a lower-case UUID such as 01234567-89ab-cdef-0123-456789abcdef"
	descInvalidSandboxFilter = "sandbox must be given at most once, as a lower-case UUID such as " +
		"01234567-89ab-cdef-0123-456789abcdef"
)

// SandboxID names the sandbox a request asks to create an agent in. It is an
// identifier like ID, with its own code, so a client can tell a bad sandboxId
// from a bad path id. It is never stored as it is: the write that uses it checks
// that the sandbox exists and is the caller's.
type SandboxID struct{ v string }

// ParseSandboxID accepts exactly the canonical lower-case UUID text form.
func ParseSandboxID(raw string) (SandboxID, error) {
	if !canonicalUUID(raw) {
		return SandboxID{}, refuse(CodeInvalidSandboxID, descInvalidSandboxID)
	}

	return SandboxID{v: raw}, nil
}

// String returns the id exactly as it was parsed. The zero SandboxID is empty
// and names no sandbox.
func (s SandboxID) String() string { return s.v }

// SandboxFilter is the sandbox a list request asks for, or nothing for no
// filter.
type SandboxFilter struct {
	id  SandboxID
	set bool
}

// ParseSandboxFilter reads the values of the "sandbox" query parameter. No
// values mean no filter. Otherwise there must be exactly one value, a canonical
// id: a repeated parameter is refused, not read as "any of", because which one
// a layer would pick differs and a request must not mean two things. A present
// but empty value is refused, not treated as absent.
func ParseSandboxFilter(values []string) (SandboxFilter, error) {
	raw, present, single := singleValue(values)
	if !single || (present && !canonicalUUID(raw)) {
		return SandboxFilter{}, refuse(CodeInvalidSandboxFilter, descInvalidSandboxFilter)
	}

	if !present {
		return SandboxFilter{}, nil
	}

	return SandboxFilter{id: SandboxID{v: raw}, set: true}, nil
}

// Sandbox returns the sandbox to filter by, and false when there is no filter.
func (f SandboxFilter) Sandbox() (SandboxID, bool) { return f.id, f.set }
