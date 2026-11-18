//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// helperDefect is the error a helper operation reports for a defect.
func helperDefect() *wantErr {
	return &wantErr{kind: apierr.Internal, code: store.HelperRejected, description: internalDescription}
}

// helperUnavailable is the error a helper operation reports for a failure.
func helperUnavailable() *wantErr {
	return &wantErr{kind: apierr.Unavailable, code: store.HelperFailed, description: store.HelperDescription}
}

// TestClassify holds how a database error becomes a sentinel. The extended
// code decides it; an unattributed constraint failure is a rejection; anything
// else is not a constraint at all.
func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		text     string
		conflict bool
		rejected bool
	}{
		{name: "unique", text: "UNIQUE constraint failed: SQLITE_CONSTRAINT_UNIQUE", conflict: true},
		{name: "primary key", text: "SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT_PRIMARYKEY)", conflict: true},
		{name: "not null", text: "SQLITE_CONSTRAINT_NOTNULL", conflict: true},
		{name: "check", text: "SQLITE_CONSTRAINT_CHECK", rejected: true},
		{name: "foreign key", text: "SQLITE_CONSTRAINT_FOREIGNKEY", rejected: true},
		{name: "primary code only", text: "SQLITE_CONSTRAINT", rejected: true},
		{name: "unknown extended code", text: "SQLITE_CONSTRAINT_TRIGGER", rejected: true},
		{name: "not a constraint", text: "D1_ERROR: network connection lost"},
		{name: "empty text"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cause := dbError(test.text)
			got := store.Classify(cause)

			if errors.Is(got, store.ErrConflict) != test.conflict {
				t.Errorf("Is(ErrConflict) = %v, want %v", !test.conflict, test.conflict)
			}

			if errors.Is(got, store.ErrRejected) != test.rejected {
				t.Errorf("Is(ErrRejected) = %v, want %v", !test.rejected, test.rejected)
			}

			if !errors.Is(got, cause) {
				t.Error("the original error is lost")
			}

			// An error that is not a constraint failure comes back as it was.
			if !test.conflict && !test.rejected && got.Error() != test.text {
				t.Errorf("an unclassified error changed to %v", got)
			}
		})
	}

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		got := store.Classify(nil)
		if got != nil {
			t.Errorf("Classify(nil) = %v", got)
		}
	})
}

// TestDecodeRow holds the strict row decoder: each column type, in a row of
// several, and the rows it accepts. kinds are the column readers, in order.
func TestDecodeRow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []any
		kinds  string
		want   []any
	}{
		{name: "no columns", values: row(), kinds: "", want: []any{}},
		{name: "text", values: row("a"), kinds: "text", want: row("a")},
		{name: "empty text", values: row(""), kinds: "text", want: row("")},
		{name: "integer", values: row(int64(-7)), kinds: "integer", want: row(int64(-7))},
		{name: "blob", values: row([]byte{1, 2}), kinds: "blob", want: row([]byte{1, 2})},
		{name: "empty blob", values: row([]byte{}), kinds: "blob", want: row([]byte{})},
		{name: "optional text present", values: row("x"), kinds: "optText", want: row("x")},
		{name: "optional text null", values: row(nil), kinds: "optText", want: row(nil)},
		{name: "optional integer present", values: row(int64(0)), kinds: "optInteger", want: row(int64(0))},
		{name: "optional integer null", values: row(nil), kinds: "optInteger", want: row(nil)},
		{name: "octet lowest", values: row(int64(0)), kinds: "octet", want: row(uint8(0))},
		{name: "octet highest", values: row(int64(255)), kinds: "octet", want: row(uint8(255))},
		{name: "boolean false", values: row(int64(0)), kinds: "boolean", want: row(false)},
		{name: "boolean true", values: row(int64(1)), kinds: "boolean", want: row(true)},
		{name: "timestamp", values: row(int64(1_700_000_000)), kinds: "timestamp", want: row(time.Unix(1_700_000_000, 0))},
		{
			name:   "every kind in one row, with NULLs between",
			values: row("id", int64(3), nil, []byte{9}, nil, "t"),
			kinds:  "text integer optInteger blob optText text",
			want:   row("id", int64(3), nil, []byte{9}, nil, "t"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := store.DecodeRow(test.values, strings.Fields(test.kinds)...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("decoded %#v, want %#v", got, test.want)
			}
		})
	}
}

// TestDecodeRowDefects holds every way a row can fail to be what its query
// promises: a value of the wrong type (a float where an integer is expected,
// NULL in a NOT NULL column), a value outside its range, and the wrong number
// of columns. The first defect is the one reported.
func TestDecodeRowDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []any
		kinds  string
		defect string // a substring of the error
	}{
		{name: "text got integer", values: row(int64(1)), kinds: "text", defect: "column 0 is int64, want text"},
		{name: "text got NULL", values: row(nil), kinds: "text", defect: "column 0 is <nil>, want text"},
		{name: "text got blob", values: row([]byte("x")), kinds: "text", defect: "want text"},
		{name: "optional text got integer", values: row(int64(1)), kinds: "optText", defect: "want text"},
		{name: "integer got float", values: row(float64(1)), kinds: "integer", defect: "column 0 is float64"},
		{name: "integer got fraction", values: row(1.5), kinds: "integer", defect: "want an integer"},
		{name: "integer got text", values: row("1"), kinds: "integer", defect: "want an integer"},
		{name: "integer got NULL", values: row(nil), kinds: "integer", defect: "want an integer"},
		{name: "optional integer got float", values: row(float64(2)), kinds: "optInteger", defect: "want an integer"},
		{name: "blob got text", values: row("x"), kinds: "blob", defect: "column 0 is string, want a blob"},
		{name: "blob got NULL", values: row(nil), kinds: "blob", defect: "want a blob"},
		{name: "octet above 255", values: row(int64(256)), kinds: "octet", defect: "want 0 to 255"},
		{name: "octet below 0", values: row(int64(-1)), kinds: "octet", defect: "want 0 to 255"},
		{name: "octet got float", values: row(float64(5)), kinds: "octet", defect: "want an integer"},
		{name: "boolean 2", values: row(int64(2)), kinds: "boolean", defect: "want 0 or 1"},
		{name: "boolean -1", values: row(int64(-1)), kinds: "boolean", defect: "want 0 or 1"},
		{name: "boolean got text", values: row("true"), kinds: "boolean", defect: "want an integer"},
		{name: "timestamp got float", values: row(1.7e9), kinds: "timestamp", defect: "want an integer"},
		{name: "too few columns", values: row("a"), kinds: "text integer", defect: "column 1 is missing"},
		{name: "an empty row", values: row(), kinds: "text", defect: "column 0 is missing"},
		{name: "optional column missing", values: row("a"), kinds: "text optInteger", defect: "column 1 is missing"},
		{name: "too many columns", values: row("a", "b"), kinds: "text", defect: "row has 2 columns, want 1"},
		{name: "a trailing NULL nobody reads", values: row("a", nil), kinds: "text", defect: "row has 2 columns"},
		{name: "the first defect wins", values: row(int64(1), 2.5), kinds: "text integer", defect: "column 0 is int64"},
		{name: "a NULL optional keeps later columns numbered", values: row(nil, "x"), kinds: "optText integer",
			defect: "column 1 is string, want an integer"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := store.DecodeRow(test.values, strings.Fields(test.kinds)...)

			if !errors.Is(err, store.ErrRowShape) {
				t.Fatalf("error = %v, want a row shape defect", err)
			}

			if !strings.Contains(err.Error(), test.defect) {
				t.Errorf("error %q does not mention %q", err, test.defect)
			}

			if got != nil {
				t.Errorf("a defective row returned values %v", got)
			}
		})
	}
}

// TestOne holds how a statement's rows become one value: none is not found, one
// is decoded, and more than one or a bad row is a defect.
func TestOne(t *testing.T) {
	t.Parallel()

	good, other := row("a", int64(1)), row("b", int64(2))

	tests := []struct {
		name    string
		rows    [][]any
		want    []any
		missing bool
		defect  bool
	}{
		{name: "nil rows", rows: nil, missing: true},
		{name: "empty rows", rows: [][]any{}, missing: true},
		{name: "one row", rows: [][]any{good}, want: row("a", int64(1))},
		{name: "two rows", rows: [][]any{good, other}, defect: true},
		{name: "one bad row", rows: [][]any{row("c", "not an integer")}, defect: true},
		{name: "one short row", rows: [][]any{row("a")}, defect: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := store.One(test.rows, "text", "integer")

			switch {
			case test.missing:
				if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("error = %v, want ErrNotFound", err)
				}
			case test.defect:
				checkErr(t, err, helperDefect())
			default:
				checkErr(t, err, nil)

				if !reflect.DeepEqual(got, test.want) {
					t.Errorf("got %#v, want %#v", got, test.want)
				}
			}
		})
	}
}

// TestAll holds how a statement's rows become a list: in order, empty when there
// are none, and a defect when any row is bad.
func TestAll(t *testing.T) {
	t.Parallel()

	good, other := row("a", int64(1)), row("b", int64(2))

	tests := []struct {
		name   string
		rows   [][]any
		want   [][]any
		defect bool
	}{
		{name: "nil rows is an empty list", rows: nil, want: [][]any{}},
		{name: "rows in order", rows: [][]any{good, other}, want: [][]any{row("a", int64(1)), row("b", int64(2))}},
		{name: "a bad row among good ones", rows: [][]any{good, row("c", "x"), other}, defect: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := store.All(test.rows, "text", "integer")

			if test.defect {
				checkErr(t, err, helperDefect())

				return
			}

			checkErr(t, err, nil)

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

// helperStatement is a statement the helper tests run: it has one placeholder.
func helperStatement() store.Statement {
	return store.Statement{Query: "SELECT ?", Args: []any{"x"}}
}

// TestRun holds the shared operation helper against the fake: statements go
// through as given, results come back positionally, and every failure of the
// platform is classified.
func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("statements and results pass through in order", func(t *testing.T) {
		t.Parallel()

		fake := newFake(outcome{results: []store.Result{{Changes: 1}, {Changes: 2}}})

		got, err := store.Run(context.Background(), fake.store(), helperStatement(), helperStatement())
		if err != nil || len(got) != 2 || got[0].Changes != 1 || got[1].Changes != 2 {
			t.Fatalf("got %+v, %v", got, err)
		}

		same := wantStatement{fragments: []string{"SELECT ?"}, args: []any{"x"}}
		checkStatements(t, fake, same, same)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		runFailures(t, 1, store.HelperFailed, store.HelperRejected, store.HelperDescription,
			func(s *store.Store) error { return lastErr(store.Run(context.Background(), s, helperStatement())) })
	})
}

// TestQueryOne holds the one-row query helper end to end.
func TestQueryOne(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		outcome  outcome
		want     []any
		notFound bool
		err      *wantErr
	}{
		{name: "a row", outcome: returning(row("v")), want: row("v")},
		{name: "no row", outcome: returning(), notFound: true},
		{name: "two rows", outcome: returning(row("v"), row("w")), err: helperDefect()},
		{name: "a bad row", outcome: returning(row(int64(1))), err: helperDefect()},
		{name: "a failed batch", outcome: failing(dbError("down")), err: helperUnavailable()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := store.QueryOne(context.Background(), newFake(test.outcome).store(), helperStatement(), "text")

			if test.notFound {
				if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("error = %v, want ErrNotFound", err)
				}

				return
			}

			checkErr(t, err, test.err)

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

// TestQueryAll holds the many-rows query helper end to end.
func TestQueryAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		outcome outcome
		want    [][]any
		err     *wantErr
	}{
		{name: "rows in order", outcome: returning(row("a"), row("b")), want: [][]any{row("a"), row("b")}},
		{name: "no rows", outcome: returning(), want: [][]any{}},
		{name: "a bad row", outcome: returning(row("a"), row(nil)), err: helperDefect()},
		{name: "a failed batch", outcome: failing(dbError("down")), err: helperUnavailable()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := store.QueryAll(context.Background(), newFake(test.outcome).store(), helperStatement(), "text")

			checkErr(t, err, test.err)

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

// TestFind holds the lookup helper: absence is an answer, not an error.
func TestFind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		outcome outcome
		want    []any
		found   bool
		err     *wantErr
	}{
		{name: "found", outcome: returning(row("v")), want: row("v"), found: true},
		{name: "absent is not an error", outcome: returning()},
		{name: "two rows", outcome: returning(row("v"), row("w")), err: helperDefect()},
		{name: "a failed batch", outcome: failing(dbError("down")), err: helperUnavailable()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, found, err := store.Find(context.Background(), newFake(test.outcome).store(), helperStatement(), "text")

			checkErr(t, err, test.err)

			if found != test.found || !reflect.DeepEqual(got, test.want) {
				t.Errorf("got %#v, %v; want %#v, %v", got, found, test.want, test.found)
			}
		})
	}
}

// TestChangedOnce holds how a write's change count becomes an outcome: none is
// "the condition matched nothing", one is "applied", and anything else cannot
// come from a statement that names a primary key.
func TestChangedOnce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		changes int64
		applied bool
		defect  bool
	}{
		{name: "none", changes: 0},
		{name: "one", changes: 1, applied: true},
		{name: "two", changes: 2, defect: true},
		{name: "negative", changes: -1, defect: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := store.ChangedOnce(store.Result{Changes: test.changes})

			if test.defect {
				checkErr(t, err, helperDefect())
			} else {
				checkErr(t, err, nil)
			}

			if got != test.applied {
				t.Errorf("applied = %v, want %v", got, test.applied)
			}
		})
	}
}

// TestStoredLiterals pins the literals that are stored in the database, so
// changing one would orphan the rows already there.
func TestStoredLiterals(t *testing.T) {
	t.Parallel()

	if store.InvitationFirstRun != "first_run" {
		t.Errorf("InvitationFirstRun = %q", store.InvitationFirstRun)
	}

	if store.KindSession != "session" {
		t.Errorf("KindSession = %q", store.KindSession)
	}
}
