package input

// Bounds of the paging types.
const (
	// DefaultPageLimit is the page size when the client sends none.
	DefaultPageLimit = 25

	// MaxPageLimit bounds PageLimit. A page size is never stored; it becomes a
	// LIMIT, so no schema CHECK applies, and the bound caps the rows (and the
	// response size) one request can pull from the database.
	MaxPageLimit = 100
)

// Error codes of the paging types.
const (
	CodeInvalidLimit  = "invalid_limit"
	CodeInvalidCursor = "invalid_cursor"
)

const (
	descInvalidLimit  = "limit must be a single integer from 1 to 100"
	descInvalidCursor = "cursor must be a single lower-case UUID"
)

// PageLimit is how many rows a list request asks for.
type PageLimit struct{ v int }

// ParsePageLimit reads the values of the "limit" query parameter. No values
// give DefaultPageLimit. Otherwise there must be exactly one value, a
// canonical decimal integer from 1 to MaxPageLimit.
func ParsePageLimit(values []string) (PageLimit, error) {
	raw, present, single := singleValue(values)
	if !single {
		return PageLimit{}, refuse(CodeInvalidLimit, descInvalidLimit)
	}

	if !present {
		return PageLimit{v: DefaultPageLimit}, nil
	}

	n, ok := decimal(raw, 1, MaxPageLimit)
	if !ok {
		return PageLimit{}, refuse(CodeInvalidLimit, descInvalidLimit)
	}

	return PageLimit{v: int(n)}, nil
}

// Int returns the limit.
func (l PageLimit) Int() int { return l.v }

// Cursor is where a list request resumes: the id of the last row of the
// previous page, or nothing for the first page.
type Cursor struct {
	id  ID
	set bool
}

// ParseCursor reads the values of the "cursor" query parameter. No values
// mean the first page. Otherwise there must be exactly one value, a canonical
// ID. A present but empty value is refused, not treated as absent.
func ParseCursor(values []string) (Cursor, error) {
	raw, present, single := singleValue(values)
	if !single {
		return Cursor{}, refuse(CodeInvalidCursor, descInvalidCursor)
	}

	if !present {
		return Cursor{}, nil
	}

	id, err := ParseID(raw)
	if err != nil {
		return Cursor{}, refuse(CodeInvalidCursor, descInvalidCursor)
	}

	return Cursor{id: id, set: true}, nil
}

// ID returns the id to resume after, and false for the first page.
func (c Cursor) ID() (ID, bool) { return c.id, c.set }
