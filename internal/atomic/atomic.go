// Package atomic describes writes that must take effect together or not at all.
//
// D1 has no interactive transactions. Its only atomic primitive is a batch of
// statements that it runs as a transaction and rolls back as a whole if any
// statement fails. That call exists only inside the Worker, so this package
// holds the host-compilable vocabulary for it: the statement type, the sentinel
// for a write the database refused, and the recognition of that refusal. The
// platform supplies the function that actually calls D1.
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

// Batch runs statements as one atomic unit: either every statement takes effect
// or none does. A write the database refused because a constraint failed is
// reported as an error wrapping ErrConflict (see Classify); any other failure
// is returned as is.
type Batch func(ctx context.Context, statements ...Statement) error

// ErrConflict means the database refused a write because a constraint failed,
// as opposed to being unavailable: a row the write needed was missing, or a
// value that must be unique was already taken. The client can resolve this (by
// not retrying the same thing); an outage it can only retry.
var ErrConflict = errors.New("write refused by the database")

// Classify wraps err in ErrConflict when it reports a failed constraint, and
// returns it unchanged otherwise. D1 reports a failed batch as a plain error
// whose text is SQLite's, with no type to match, so the text is all there is:
// every constraint failure SQLite reports carries the "SQLITE_CONSTRAINT"
// result-code name.
func Classify(err error) error {
	if err != nil && strings.Contains(err.Error(), "SQLITE_CONSTRAINT") {
		return errors.Join(ErrConflict, err)
	}

	return err
}
