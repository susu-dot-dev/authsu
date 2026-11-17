// Package atomic describes writes that must take effect together or not at all.
//
// D1 has no interactive transactions. Its only atomic primitive is a batch of
// statements that it runs as a transaction and rolls back as a whole if any
// statement fails. That call exists only inside the Worker, so this package
// holds the host-compilable vocabulary for it: the statement type, the
// sentinels for a write the database refused, and the recognition of why. The
// platform supplies the function that actually calls D1.
//
// A conditional INSERT ... SELECT that matches no rows is not an error, so it
// does not roll a batch back by itself. To turn "nothing was inserted" into a
// failed batch, make a later statement depend on the row existing, such as a
// NOT NULL foreign key filled from a subselect. See internal/registration/sql.go.
//
// Which tool answers "did it take effect?" depends on the batch:
//
//   - A batch of several statements that must stand or fall together needs the
//     constraint above. Result.Changes is only readable once the batch has
//     committed, so a zero there cannot undo an earlier statement that did.
//   - A single conditional write, where "matched nothing" is an outcome to
//     report and not a failure, uses the result. Return the row with RETURNING
//     (Result.Rows) so the outcome and the row are the same instant, and do not
//     read the row again afterwards, which could see a different state.
package atomic

import (
	"context"
	"errors"
	"strings"
)

// Statement is one SQL statement with its bound arguments.
type Statement struct {
	Query string
	Args  []any
}

// Result is the outcome of one statement in a batch.
type Result struct {
	// Changes is the number of rows the statement inserted, updated or deleted
	// (D1's meta.changes). A conditional write that matched nothing is not an
	// error, so this is how a caller learns whether it took effect.
	Changes int64

	// Rows are the rows the statement returned, such as from a RETURNING
	// clause, each in the order of the columns the statement named. Values
	// are nil, int64, float64, string or []byte. It is nil when the statement
	// returned no rows.
	//
	// A statement that returns rows can report its own outcome in them, which
	// is the one way to learn why a conditional write did nothing without a
	// second, separate read: see internal/invitations/sql.go.
	Rows [][]any
}

// Batch runs statements as one atomic unit: either every statement takes effect
// or none does. It returns one Result per statement, in order. A write the
// database refused because a constraint failed is reported as an error wrapping
// ErrConflict or ErrRejected (see Classify), and errors.Is says which kind of
// constraint it was; any other failure is returned as is.
type Batch func(ctx context.Context, statements ...Statement) ([]Result, error)

// The constraint failures Classify recognises. A write refused for one of these
// reasons is the database saying "no" rather than being unavailable, but the
// reasons differ in whose fault they are, so they are separate sentinels.
var (
	// ErrConflict means the write collided with data that already exists or
	// with a row it needed that is not there: a value that must be unique was
	// already taken (UNIQUE, PRIMARY KEY), or a column that must be set was
	// NULL because a subselect found nothing (NOT NULL). It is the outcome of
	// the state the request met, so the client can resolve it, by not
	// retrying the same thing.
	ErrConflict = errors.New("write conflicts with existing data")

	// ErrRejected means the write broke a rule the schema enforces as a
	// backstop for the code: a CHECK (a size or shape limit) or a FOREIGN KEY.
	// The code is meant to refuse that input before it reaches the database,
	// so this is a defect or a mismatch between the code and the schema, not
	// something the client did or can fix. Callers should treat it as a server
	// fault.
	ErrRejected = errors.New("write violates a schema rule")
)

// Extended result codes SQLite reports for a failed constraint. D1 includes
// them in the error text as "SQLITE_CONSTRAINT (extended: <code>)"; there is no
// error type to match, so the text is all there is.
const (
	codeUnique     = "SQLITE_CONSTRAINT_UNIQUE"
	codePrimaryKey = "SQLITE_CONSTRAINT_PRIMARYKEY"
	codeNotNull    = "SQLITE_CONSTRAINT_NOTNULL"
	codeCheck      = "SQLITE_CONSTRAINT_CHECK"
	codeForeignKey = "SQLITE_CONSTRAINT_FOREIGNKEY"
)

// Classify wraps err in ErrConflict or ErrRejected when it reports a failed
// constraint, and returns it unchanged otherwise.
//
// The extended result code names which constraint failed, and that decides the
// sentinel: UNIQUE, PRIMARY KEY and NOT NULL are ErrConflict; CHECK and FOREIGN
// KEY are ErrRejected. A constraint failure whose code is not one of those (a
// different or newer extended code, or a driver that reports only the primary
// code) is ErrRejected too: the write was refused, and the safe reading of a
// refusal we cannot attribute to the data is that it is not the client's to
// resolve. The original error is always kept, for the log.
func Classify(err error) error {
	if err == nil {
		return nil
	}

	text := err.Error()

	switch {
	case containsAny(text, codeUnique, codePrimaryKey, codeNotNull):
		return errors.Join(ErrConflict, err)
	case containsAny(text, codeCheck, codeForeignKey, "SQLITE_CONSTRAINT"):
		// The bare "SQLITE_CONSTRAINT" also matches the primary code of every
		// extended one, so this case must come after the specific ones.
		return errors.Join(ErrRejected, err)
	default:
		return err
	}
}

// containsAny reports whether text contains any of the substrings.
func containsAny(text string, substrings ...string) bool {
	for _, substring := range substrings {
		if strings.Contains(text, substring) {
			return true
		}
	}

	return false
}
