// Package store holds every SQL statement the service runs, one method per
// atomic database operation, and the platform port those statements go through.
//
// # Atomicity
//
// D1 has no interactive transactions. Its only atomic primitive is a batch of
// statements that it runs as a transaction and rolls back as a whole if any
// statement fails. That call exists only inside the Worker, so this package
// holds the host-compilable vocabulary for it: the statement type, the
// sentinels for a write the database refused, and the recognition of why. The
// platform supplies Exec, the function that actually calls D1.
//
// A conditional INSERT ... SELECT that matches no rows is not an error, so it
// does not roll a batch back by itself. To turn "nothing was inserted" into a
// failed batch, make a later statement depend on the row existing, such as a
// NOT NULL foreign key filled from a subselect. See insertCredentialQuery.
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
//
// Every read goes through Exec too, as a one-statement batch, so there is one
// way into the database and one fake for it in tests.
//
// # Column names
//
// A batch returns each row keyed by column name, so columns that share a name
// collapse into one and the row comes back short. Every selected or returned
// expression therefore needs a name that is unique within its statement: alias
// it (COALESCE(x, ”) AS credential_id). A bare column reference is its own
// name. A test parses the package's queries and refuses a list that breaks
// this.
//
// # Outcomes
//
// Business outcomes are typed return values or the sentinels ErrNotFound and
// ErrConflict, which the feature above maps to client codes. Infrastructure
// failures come back already classified as an *apierr.Error: 503 Unavailable
// with the operation's "_failed" code when the database could not be reached
// or failed, and 500 Internal with its "_rejected" code when the database
// refused a write the code should never have sent (a CHECK or FOREIGN KEY) or
// returned something that is not the shape the query promises. Neither carries
// a client-facing detail beyond the operation's fixed description.
//
// # Inputs
//
// Values a client sent arrive as internal/input types, which cannot exist
// unless valid. Values the server generated (ids, timestamps, secret hashes,
// handles) arrive as plain types. The store holds no clock: now is always a
// parameter.
//
// # Adding an operation
//
// Write the SQL as a const named ...Query beside its method, a single string
// literal with the comment that explains why it is atomic and the arguments in
// placeholder order. Name every selected column. Describe the operation's op
// (codes and description). Run the statements with run, or read with queryOne,
// queryAll or find and a reader built from row's column methods, and return the
// sentinel or typed value the feature needs. Then add the operation's cases to
// its _test.go, and rows to schema_test.go for any input bound it stores.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/result"
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

	// Rows are the rows the statement returned, such as from a SELECT or a
	// RETURNING clause, each in the order of the columns the statement named.
	// Values are nil, int64, float64, string or []byte. It is nil when the
	// statement returned no rows.
	//
	// A statement that returns rows can report its own outcome in them, which
	// is the one way to learn why a conditional write did nothing without a
	// second, separate read: see updateNumInvitesQuery.
	Rows [][]any
}

// Exec runs statements as one atomic unit: either every statement takes effect
// or none does. It returns one Result per statement, in order. A write the
// database refused because a constraint failed is reported as an error wrapping
// ErrConflict or ErrRejected (see Classify), and errors.Is says which kind of
// constraint it was; any other failure is returned as is.
type Exec func(ctx context.Context, statements ...Statement) ([]Result, error)

// The failures Classify recognises, and the one lookup outcome. A write refused
// for one of the constraint reasons is the database saying "no" rather than
// being unavailable, but the reasons differ in whose fault they are, so they
// are separate sentinels.
var (
	// ErrConflict means the write collided with data that already exists or
	// with a row it needed that is not there: a value that must be unique was
	// already taken (UNIQUE, PRIMARY KEY), or a column that must be set was
	// NULL because a subselect found nothing (NOT NULL). It is the outcome of
	// the state the request met, so the client can resolve it, by not
	// retrying the same thing. Operations return it as is (it wraps the
	// database error for the log) and the feature maps it to a client code.
	ErrConflict = errors.New("write conflicts with existing data")

	// ErrRejected means the write broke a rule the schema enforces as a
	// backstop for the code: a CHECK (a size or shape limit) or a FOREIGN KEY.
	// The code is meant to refuse that input before it reaches the database,
	// so this is a defect or a mismatch between the code and the schema, not
	// something the client did or can fix. Operations report it as a 500 under
	// their "_rejected" code, so features never see this sentinel.
	ErrRejected = errors.New("write violates a schema rule")

	// ErrNotFound means a lookup by key matched no row. Operations that report
	// absence as a flag (ResolveSession) do not return it.
	ErrNotFound = errors.New("not found")
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

// InvitationFirstRun is invitations.type of the first-run invitation: the one
// that grants the first administrator, and that is redeemable only while no
// account exists. The queries bind it as an argument, so this constant is the
// only place the text is written. The schema does not constrain the set of types
// (docs/DATABASE.md), so Go is the one that knows what the value means.
const InvitationFirstRun = "first_run"

// Store runs the service's database operations over an Exec.
type Store struct {
	exec Exec

	// marshal encodes the JSON columns the store owns (users.profile and
	// credentials.metadata). It is json.Marshal; it is a field only so a test
	// can make the encoding fail, which cannot happen for the fixed types the
	// store passes it.
	marshal func(any) ([]byte, error)
}

// New returns a Store that runs every statement through exec.
func New(exec Exec) *Store {
	return &Store{exec: exec, marshal: json.Marshal}
}

// internalDescription is the fixed text of every defect: a client is told
// nothing about a failure that is the service's own.
const internalDescription = "internal error"

// op names an operation for its failures. Each operation has its own codes so a
// log search or an alert names the step that failed.
type op struct {
	// failed is the code of a database that could not be reached or failed:
	// 503 Unavailable.
	failed string

	// rejected is the code of a defect: the schema refused a write the code
	// should not have sent, or a result is not the shape the query promises.
	// 500 Internal.
	rejected string

	// description is the client-safe text of the Unavailable error. Never an
	// error message.
	description string
}

// unavailable classifies a database failure of the operation.
func (o op) unavailable(err error) error {
	return apierr.Wrap(err, apierr.Unavailable, o.failed, o.description)
}

// defect classifies a failure that is the service's own.
func (o op) defect(err error) error {
	return apierr.Wrap(err, apierr.Internal, o.rejected, internalDescription)
}

// Causes of a defect, kept so the log says what was wrong.
var (
	errRowShape   = errors.New("returned row has an unexpected shape")
	errResultSize = errors.New("batch returned an unexpected number of results")
	errRowCount   = errors.New("statement returned an unexpected number of rows")
	errChanges    = errors.New("statement changed an unexpected number of rows")
)

// run executes statements as one batch and returns one Result per statement.
//
//   - A failure Classify recognised as ErrConflict is returned as is, for the
//     operation to hand to its feature.
//   - A schema rejection is a defect, and any other failure is the database
//     being unavailable.
//   - A batch that returns a different number of results than statements is a
//     defect: the positional reading of the results would be wrong.
func (s *Store) run(ctx context.Context, o op, statements ...Statement) ([]Result, error) {
	results, err := s.exec(ctx, statements...)

	switch {
	case err == nil:
	case errors.Is(err, ErrConflict):
		return nil, err
	case errors.Is(err, ErrRejected):
		return nil, o.defect(err)
	default:
		return nil, o.unavailable(err)
	}

	if len(results) != len(statements) {
		return nil, o.defect(fmt.Errorf("%w: %d results for %d statements", errResultSize, len(results), len(statements)))
	}

	return results, nil
}

// changedOnce reports whether a write changed its row: one change is true, none
// is false (the write's condition matched nothing). Any other count is a
// defect, since the statements it is used for name a primary key.
func changedOnce(o op, res Result) (bool, error) {
	switch res.Changes {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, o.defect(fmt.Errorf("%w: %d", errChanges, res.Changes))
	}
}

// one decodes the single row of a statement's result. No row is ErrNotFound,
// and more than one or a row that does not decode is a defect: a statement for
// which the caller expects at most one row returned more.
func one[T any](rows [][]any, o op, read func(*row) T) (T, error) {
	var zero T

	switch len(rows) {
	case 0:
		return zero, ErrNotFound
	case 1:
	default:
		return zero, o.defect(fmt.Errorf("%w: %d rows, want at most 1", errRowCount, len(rows)))
	}

	value, err := decode(rows[0], read)
	if err != nil {
		return zero, o.defect(err)
	}

	return value, nil
}

// all decodes every row of a statement's result, in order. A row that does not
// decode is a defect. No rows is an empty, non-nil slice.
func all[T any](rows [][]any, o op, read func(*row) T) ([]T, error) {
	out := make([]T, 0, len(rows))

	for _, values := range rows {
		value, err := decode(values, read)
		if err != nil {
			return nil, o.defect(err)
		}

		out = append(out, value)
	}

	return out, nil
}

// paged cuts the rows of a keyset page that asked for one row more than it
// returns (size plus one): fewer than that is the last page, with no cursor; the
// extra row only says there is a next page, whose cursor is the id of the last
// row that is kept. More rows than were asked for is the database not doing what
// the query says, which is a defect. id names a row's id, the sort key.
func paged[T any](o op, rows []T, size int, id func(T) string) ([]T, string, error) {
	wanted := size + 1

	switch {
	case len(rows) > wanted:
		return nil, "", o.defect(fmt.Errorf("%w: %d rows, want at most %d", errRowCount, len(rows), wanted))
	case len(rows) < wanted:
		return rows, "", nil
	default:
		rows = rows[:size]

		return rows, id(rows[len(rows)-1]), nil
	}
}

// queryOne runs one statement and decodes its single row (see one).
func queryOne[T any](ctx context.Context, s *Store, o op, statement Statement, read func(*row) T) (T, error) {
	results, err := s.run(ctx, o, statement)
	if err != nil {
		var zero T

		return zero, err
	}

	return one(results[0].Rows, o, read)
}

// queryAll runs one statement and decodes every row it returned (see all).
func queryAll[T any](ctx context.Context, s *Store, o op, statement Statement, read func(*row) T) ([]T, error) {
	results, err := s.run(ctx, o, statement)
	if err != nil {
		return nil, err
	}

	return all(results[0].Rows, o, read)
}

// find is queryOne for a lookup whose absence is an answer and not an error.
func find[T any](ctx context.Context, s *Store, o op, statement Statement, read func(*row) T) (T, bool, error) {
	results, err := s.run(ctx, o, statement)
	if err != nil {
		var zero T

		return zero, false, err
	}

	return findRow(results[0].Rows, o, read)
}

// findRow is one for a statement whose absence of a row is an answer and not
// an error: it reports whether the row was there.
func findRow[T any](rows [][]any, o op, read func(*row) T) (T, bool, error) {
	value, err := one(rows, o, read)
	if errors.Is(err, ErrNotFound) {
		var zero T

		return zero, false, nil
	}

	return value, err == nil, err
}

// outcome hands the end of a result chain back as a plain value and error, for
// an operation that returns them. Every error in a chain here was classified when
// it arose, by run, one, all, a lookup or the step that refused, so nothing is
// left to wrap.
func outcome[T any](r result.Result[T]) (T, error) {
	return r.Get() //nolint:wrapcheck // every error in the chain is already classified, as the comment says
}

// found is a looked-up row and whether it was there: a lookup whose absence is
// an answer and not an error, so that it can be a step of a result chain.
type found[T any] struct {
	value T
	ok    bool
}

// orNotFound is the row, or ErrNotFound when it was not there.
func (f found[T]) orNotFound() (T, error) {
	if !f.ok {
		var zero T

		return zero, ErrNotFound
	}

	return f.value, nil
}

// lookup is findRow as a step of a result chain.
func lookup[T any](rows [][]any, o op, read func(*row) T) result.Result[found[T]] {
	value, ok, err := findRow(rows, o, read)

	return result.Of(found[T]{value: value, ok: ok}, err)
}

// wroteOr is the outcome of a conditional write that returns its row: the row it
// returned, or what refusal makes of the write having matched nothing. A row
// that does not decode is a defect and is returned as it is.
func wroteOr[T any](o op, rows [][]any, read func(*row) T, refusal func() (T, error)) (T, error) {
	return outcome(lookup(rows, o, read).
		Then(func(wrote found[T]) (T, error) {
			if wrote.ok {
				return wrote.value, nil
			}

			return refusal()
		}),
	)
}

// refusedBy is the error a write that matched nothing is refused with, read off
// the standing statement that followed it in the same batch: why decides it from
// the row, or from its absence. The outcome has no value, which is T's zero. A
// standing row that does not decode is a defect and is returned as it is.
func refusedBy[S, T any](o op, rows [][]any, read func(*row) S, why func(found[S]) error) (T, error) {
	var zero T

	return outcome(lookup(rows, o, read).
		Then(func(standing found[S]) (T, error) { return zero, why(standing) }),
	)
}

// pageOf cuts the decoded rows of a keyset page that asked for one row more than
// it returns (see paged) and builds the page from the rows it keeps and the
// cursor of the next one.
func pageOf[T, P any](
	o op, decoded result.Result[[]T], size int, id func(T) string, build func([]T, string) P,
) (P, error) {
	return outcome(decoded.
		Then(func(rows []T) (P, error) {
			page, next, err := paged(o, rows, size, id)

			return build(page, next), err
		}),
	)
}

// runChecked is run for an operation whose writes cannot collide with data that
// exists, so a conflict is a defect (see defectOnConflict), as the first step of
// a result chain.
func (s *Store) runChecked(ctx context.Context, o op, statements ...Statement) result.Result[[]Result] {
	return result.Of(s.run(ctx, o, statements...)).MapErr(conflictIsDefect(o))
}

// row reads typed values from one returned row, left to right. The first value
// that is missing or not of the type asked for is remembered, and a reader is
// written as a plain sequence of reads that decode checks once at the end.
type row struct {
	values []any
	at     int
	err    error
}

// decode applies read to one returned row and checks that it consumed exactly
// the row's columns: a row with more or fewer columns than the query names is a
// defect, however its values read.
func decode[T any](values []any, read func(*row) T) (T, error) {
	var zero T

	cols := &row{values: values, at: 0, err: nil}
	value := read(cols)

	if cols.err == nil && cols.at != len(values) {
		cols.failf("row has %d columns, want %d", len(values), cols.at)
	}

	if cols.err != nil {
		return zero, cols.err
	}

	return value, nil
}

// failf records the first defect of the row.
func (r *row) failf(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: %s", errRowShape, fmt.Sprintf(format, args...))
	}
}

// next returns the value under the cursor and moves on. Past the end it
// reports a defect and returns nil.
func (r *row) next() any {
	r.at++

	if r.at > len(r.values) {
		r.failf("column %d is missing: row has %d", r.at-1, len(r.values))

		return nil
	}

	return r.values[r.at-1]
}

// mismatch records that the column just read is not of the type wanted.
func (r *row) mismatch(value any, want string) {
	r.failf("column %d is %T, want %s", r.at-1, value, want)
}

// text reads a NOT NULL text column.
func (r *row) text() string {
	value := r.next()

	text, ok := value.(string)
	if !ok {
		r.mismatch(value, "text")
	}

	return text
}

// optText reads a nullable text column: NULL is a nil pointer.
func (r *row) optText() *string {
	if r.skipNull() {
		return nil
	}

	text := r.text()

	return &text
}

// integer reads a NOT NULL integer column. A float64 is a defect even when it
// is whole: the platform reports an integer column as int64.
func (r *row) integer() int64 {
	value := r.next()

	number, ok := value.(int64)
	if !ok {
		r.mismatch(value, "an integer")
	}

	return number
}

// optInteger reads a nullable integer column: NULL is a nil pointer.
func (r *row) optInteger() *int64 {
	if r.skipNull() {
		return nil
	}

	number := r.integer()

	return &number
}

// blob reads a NOT NULL blob column.
func (r *row) blob() []byte {
	value := r.next()

	bytes, ok := value.([]byte)
	if !ok {
		r.mismatch(value, "a blob")
	}

	return bytes
}

// labels reads a column that holds a JSON array of strings, as
// json_group_array produces it. Anything else (not text, not JSON, not an array,
// an element that is not a string) is a defect and returns nil. On success the
// result is never nil: no labels is an empty slice.
//
// Elements are decoded as pointers because encoding/json turns a JSON null
// element of a []string into "" without an error, which would read a corrupt
// column as an empty label.
func (r *row) labels() []string {
	text := r.text()
	if r.err != nil {
		return nil
	}

	var elements []*string

	err := json.Unmarshal([]byte(text), &elements)
	if err != nil || elements == nil {
		r.failf("column %d is not a JSON array of strings", r.at-1)

		return nil
	}

	labels := make([]string, len(elements))

	for i, element := range elements {
		if element == nil {
			r.failf("column %d has a null element", r.at-1)

			return nil
		}

		labels[i] = *element
	}

	return labels
}

// octet reads an integer column the schema checks to 0..255 (credential flags).
// A value outside it is a defect and not a truncation.
func (r *row) octet() uint8 {
	number := r.integer()

	if number < 0 || number > math.MaxUint8 {
		r.failf("column %d is %d, want 0 to 255", r.at-1, number)

		return 0
	}

	return uint8(number)
}

// boolean reads an integer column that holds 0 or 1 (a SQL boolean, such as
// EXISTS). Any other value is a defect.
func (r *row) boolean() bool {
	number := r.integer()

	switch number {
	case 0:
		return false
	case 1:
		return true
	default:
		r.failf("column %d is %d, want 0 or 1", r.at-1, number)

		return false
	}
}

// timestamp reads an integer column that holds Unix seconds.
func (r *row) timestamp() time.Time {
	return time.Unix(r.integer(), 0)
}

// skipNull reports whether the next column is NULL, and moves past it if so.
// A cursor already past the end is not NULL: the read that follows reports it.
func (r *row) skipNull() bool {
	if r.at < len(r.values) && r.values[r.at] == nil {
		r.at++

		return true
	}

	return false
}
