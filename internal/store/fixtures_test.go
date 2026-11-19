//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file is the package's one fixtures file: a recording fake for the
// platform port, builders for what it returns, and the assertions every
// operation's tests share. Fakes and helpers for the tests of one area belong
// in that area's _test.go file.

// now is the clock every test uses. Its second is not zero in any bound
// argument, so a swapped argument is visible.
//
//nolint:gochecknoglobals // a fixed clock shared by the table tests
var now = time.Unix(1_700_000_123, 0)

// activeFragment is the text of the one predicate every query that decides
// whether a presented secret may be used includes, and that takes now twice.
// It is written out here on purpose: changing what "active" means is a change
// to security behaviour, and must change this line with it.
const activeFragment = "(s.revoked_at IS NULL OR s.revoked_at > ?) AND s.expires_at > ?"

// dbError is an error the platform reports, by its text: D1 gives nothing but
// text to recognise a constraint failure by.
type dbError string

func (e dbError) Error() string { return string(e) }

// passErr returns err; a test closure uses it to hand the error of an operation
// to a shared check.
func passErr(err error) error { return err }

// lastErr returns the error of a call that also returned one value, so a test
// closure can hand the error of any operation to a shared check.
func lastErr[T any](_ T, err error) error { return err }

// lastErr2 is lastErr for a call that returned two values.
func lastErr2[T, U any](_ T, _ U, err error) error { return err }

// errUnexpectedCall is what the fake returns when it is called more often than
// it was programmed for.
var errUnexpectedCall = errors.New("fake exec: more calls than programmed outcomes")

// outcome is what one call of the fake returns.
type outcome struct {
	results []store.Result
	err     error
}

// fakeExec is an Exec that records every call and returns the outcome
// programmed for that call: the first call gets the first outcome. A call
// beyond the programmed ones fails, so a test that expects no more calls sees
// an extra one as an error.
type fakeExec struct {
	outcomes []outcome
	calls    [][]store.Statement
}

func newFake(outcomes ...outcome) *fakeExec { return &fakeExec{outcomes: outcomes, calls: nil} }

func (f *fakeExec) exec(_ context.Context, statements ...store.Statement) ([]store.Result, error) {
	f.calls = append(f.calls, slices.Clone(statements))

	if len(f.calls) > len(f.outcomes) {
		return nil, errUnexpectedCall
	}

	next := f.outcomes[len(f.calls)-1]

	return next.results, next.err
}

// store returns a Store over the fake.
func (f *fakeExec) store() *store.Store { return store.New(f.exec) }

// Builders for outcomes and rows.

// row is one returned row.
func row(values ...any) []any { return values }

// with returns a copy of a row with the value at index at replaced, so a table
// can name a row by what is wrong with it.
func with(base []any, at int, value any) []any {
	out := slices.Clone(base)
	out[at] = value

	return out
}

// returning is a one-statement batch that returned rows.
func returning(rows ...[]any) outcome {
	return outcome{results: []store.Result{{Changes: 0, Rows: rows}}, err: nil}
}

// changed is a one-statement batch that changed n rows.
func changed(n int64) outcome {
	return outcome{results: []store.Result{{Changes: n, Rows: nil}}, err: nil}
}

// applied is a batch of n statements that all succeeded without rows.
func applied(n int) outcome { return outcome{results: make([]store.Result, n), err: nil} }

// failing is a batch the platform failed with err.
func failing(err error) outcome { return outcome{results: nil, err: err} }

// Parsers for the input types, which only their parsers can build.

// tokenOf is a valid token of the tag whose random body is the byte seed
// repeated, so a test can name a distinct token by its seed.
func tokenOf(tb testing.TB, tag secret.Tag, seed byte) string {
	tb.Helper()

	raw, err := secret.Generate(bytes.NewReader(bytes.Repeat([]byte{seed}, secret.BodyBytes)), tag)
	if err != nil {
		tb.Fatalf("generate a %s token: %v", tag, err)
	}

	return raw
}

func mustInvitationToken(tb testing.TB, seed byte) input.InvitationToken {
	tb.Helper()

	token, err := input.ParseInvitationToken(tokenOf(tb, secret.TagInvitation, seed))
	if err != nil {
		tb.Fatalf("parse invitation token: %v", err)
	}

	return token
}

func mustSessionToken(tb testing.TB, seed byte) input.SessionToken {
	tb.Helper()

	token, err := input.ParseSessionToken(tokenOf(tb, secret.TagSession, seed))
	if err != nil {
		tb.Fatalf("parse session token: %v", err)
	}

	return token
}

func mustAPIKeyToken(tb testing.TB, seed byte) input.APIKeyToken {
	tb.Helper()

	token, err := input.ParseAPIKeyToken(tokenOf(tb, secret.TagAPIKey, seed))
	if err != nil {
		tb.Fatalf("parse API key token: %v", err)
	}

	return token
}

// hashOf is a 32-byte hash that is not any token's, distinguishable by its
// seed: what a caller hands the store as secret.Hash(token)[:].
func hashOf(seed byte) []byte { return bytes.Repeat([]byte{seed}, sha256.Size) }

func mustName(tb testing.TB, raw string) input.AccountName {
	tb.Helper()

	name, err := input.ParseAccountName(raw)
	if err != nil {
		tb.Fatalf("parse account name %q: %v", raw, err)
	}

	return name
}

// defectResults returns every way the rows a statement returned can fail to be
// the one valid row, by a name for the case: for each column, NULL (unless the
// column is nullable) and a value of each wrong type; a row cut short at every
// length, including empty; a row with an extra column; and two rows. kinds names
// each column: "text", "integer", "optText" or "optInteger". The platform reports
// an integer column as int64, so a float64 is a defect even when whole.
func defectResults(valid []any, kinds ...string) map[string][][]any {
	wrong := map[string][]any{
		"text":       {int64(1), 1.5, []byte("x")},
		"optText":    {int64(1), 1.5, []byte("x")},
		"integer":    {1.5, "1", []byte{1}, true},
		"optInteger": {1.5, "1", []byte{1}, true},
	}

	results := map[string][][]any{"two rows": {valid, valid}}

	for at, kind := range kinds {
		if !strings.HasPrefix(kind, "opt") {
			results[fmt.Sprintf("column %d (%s) is NULL", at, kind)] = [][]any{with(valid, at, nil)}
		}

		for _, value := range wrong[kind] {
			results[fmt.Sprintf("column %d (%s) is a %T", at, kind, value)] = [][]any{with(valid, at, value)}
		}
	}

	for length := range valid {
		results[fmt.Sprintf("a row of %d columns", length)] = [][]any{slices.Clone(valid[:length])}
	}

	results["a column too many"] = [][]any{append(slices.Clone(valid), "extra")}

	return results
}

// Assertions.

// squash collapses whitespace so a query can be matched regardless of layout.
func squash(query string) string { return strings.Join(strings.Fields(query), " ") }

// wantStatement is what a statement of a batch must be: the fragments of its
// SQL that carry the guards (matched against the squashed text), and the exact
// argument list in placeholder order.
type wantStatement struct {
	fragments []string
	args      []any
}

// checkStatements asserts that the fake saw exactly one batch of the wanted
// statements. It also asserts that each statement has as many placeholders as
// arguments, so a numbering slip is caught even where a fragment is not.
func checkStatements(t *testing.T, fake *fakeExec, want ...wantStatement) {
	t.Helper()

	if len(fake.calls) != 1 {
		t.Fatalf("exec called %d times, want exactly one batch", len(fake.calls))
	}

	got := fake.calls[0]
	if len(got) != len(want) {
		t.Fatalf("batch has %d statements, want %d", len(got), len(want))
	}

	for i, expected := range want {
		statement := got[i]
		query := squash(statement.Query)

		for _, fragment := range expected.fragments {
			if !strings.Contains(query, fragment) {
				t.Errorf("statement %d lacks %q:\n%s", i, fragment, query)
			}
		}

		if !reflect.DeepEqual(statement.Args, expected.args) {
			t.Errorf("statement %d args = %#v, want %#v", i, statement.Args, expected.args)
		}

		if marks := strings.Count(query, "?"); marks != len(statement.Args) {
			t.Errorf("statement %d has %d placeholders for %d args:\n%s", i, marks, len(statement.Args), query)
		}
	}
}

// wantErr is an apierr a store operation must return.
type wantErr struct {
	kind        apierr.Kind
	code        string
	description string
}

// checkErr asserts err is the wanted *apierr.Error, or nil when want is nil.
func checkErr(t *testing.T, err error, want *wantErr) {
	t.Helper()

	if want == nil {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return
	}

	failure, ok := errors.AsType[*apierr.Error](err)
	if !ok {
		t.Fatalf("error %v is not an *apierr.Error", err)
	}

	if failure.Kind != want.kind || failure.Code != want.code || failure.Description != want.description {
		t.Errorf("error = {%v %q %q}, want {%v %q %q}",
			failure.Kind, failure.Code, failure.Description, want.kind, want.code, want.description)
	}
}

// failure is a way the platform can fail an operation, and what the operation
// must make of it. Every operation faces the same ones, so they are one table.
type failure struct {
	name    string
	outcome outcome

	// conflict means the error must be the ErrConflict sentinel and not an
	// *apierr.Error: the feature, not the store, decides what a conflict means.
	conflict bool
	want     wantErr
}

// internalDescription is the fixed text of every defect.
const internalDescription = "internal error"

// infraFailures returns the platform failures of an operation that runs
// the given number of statements as one batch, and what each must become.
func infraFailures(statements int, failed, rejected, description string) []failure {
	unavailable := dbError("D1 is down")
	rule := store.Classify(dbError("D1_ERROR: SQLITE_CONSTRAINT_CHECK: CHECK constraint failed"))
	taken := store.Classify(dbError("D1_ERROR: SQLITE_CONSTRAINT_UNIQUE: UNIQUE constraint failed"))
	missing := store.Classify(dbError("D1_ERROR: SQLITE_CONSTRAINT_NOTNULL: NOT NULL constraint failed"))
	unknown := store.Classify(dbError("D1_ERROR: SQLITE_CONSTRAINT: something newer"))

	defect := wantErr{kind: apierr.Internal, code: rejected, description: internalDescription}

	return []failure{
		{name: "database unavailable", outcome: failing(unavailable), conflict: false,
			want: wantErr{kind: apierr.Unavailable, code: failed, description: description}},
		{name: "schema rule refused the write", outcome: failing(rule), conflict: false, want: defect},
		{name: "unattributed constraint failure", outcome: failing(unknown), conflict: false, want: defect},
		{name: "unique value taken", outcome: failing(taken), conflict: true, want: wantErr{}},
		{name: "required row missing", outcome: failing(missing), conflict: true, want: wantErr{}},
		{name: "no results", outcome: outcome{results: nil, err: nil}, conflict: false, want: defect},
		{name: "one result too few", outcome: applied(statements - 1), conflict: false, want: defect},
		{name: "one result too many", outcome: applied(statements + 1), conflict: false, want: defect},
	}
}

// checkFailure asserts what an operation returned for one of infraFailures.
func checkFailure(t *testing.T, err error, f failure) {
	t.Helper()

	if f.conflict {
		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("error = %v, want ErrConflict", err)
		}

		if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
			t.Errorf("conflict %v is classified; the feature must decide that", err)
		}

		return
	}

	checkErr(t, err, &f.want)

	// The database's own error stays in the chain, for the log.
	if f.outcome.err != nil && !errors.Is(err, f.outcome.err) {
		t.Errorf("error %v lost its cause %v", err, f.outcome.err)
	}
}

// defectConflicts is failures for an operation whose writes can violate no
// constraint a client could cause: a conflict there is the schema disagreeing
// with the code, so it comes back as the 500 "_rejected" and never as the bare
// ErrConflict an operation hands to its feature.
func defectConflicts(failures []failure, rejected string) []failure {
	for i := range failures {
		if failures[i].conflict {
			failures[i].conflict = false
			failures[i].want = *defectOf(rejected)
		}
	}

	return failures
}

// runDefectFailures is runFailures for an operation of that kind.
func runDefectFailures(
	t *testing.T, statements int, failed, rejected, description string, call func(*store.Store) error,
) {
	t.Helper()

	for _, f := range defectConflicts(infraFailures(statements, failed, rejected, description), rejected) {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			checkFailure(t, call(fake.store()), f)

			if len(fake.calls) != 1 {
				t.Errorf("exec called %d times, want 1", len(fake.calls))
			}
		})
	}
}

// runFailures runs call against every platform failure of an operation of the
// given number of statements.
func runFailures(t *testing.T, statements int, failed, rejected, description string, call func(*store.Store) error) {
	t.Helper()

	for _, f := range infraFailures(statements, failed, rejected, description) {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			checkFailure(t, call(fake.store()), f)

			if len(fake.calls) != 1 {
				t.Errorf("exec called %d times, want 1", len(fake.calls))
			}
		})
	}
}

// defectOf is the wanted error for a result that is not the shape the query
// promises.
func defectOf(rejected string) *wantErr {
	return &wantErr{kind: apierr.Internal, code: rejected, description: internalDescription}
}
