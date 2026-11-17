package invitations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/session"
)

var errDB = errors.New("database is on fire")

const (
	testAdminID = "00000000-0000-7000-8000-000000000002"
	testInvID   = "00000000-0000-7000-8000-0000000000aa"
	testNewID   = "00000000-0000-7000-8000-0000000000bb"
	testType    = "workshop"
	roleMember  = "member"

	// Strings that recur across the tests.
	noteLabel     = "note"
	dbUnavailable = "database unavailable"
	schemaRejects = "schema rejects it"
	readBackFails = "read back fails"
)

// testNow is the fixed time the tests run at.
func testNow() time.Time { return time.Date(2026, time.November, 16, 12, 0, 0, 0, time.UTC) }

func getenv(string) string { return "" }

// fakeSessions authenticates every request as principal, or fails with err.
type fakeSessions struct {
	principal session.Principal
	err       error
	calls     int
}

func (f *fakeSessions) Authenticate(
	context.Context, func(string) string, httpapi.Request,
) (session.Principal, error) {
	f.calls++

	return f.principal, f.err
}

// fakeReader serves invitations by id, as the database would. A Get after a
// write sees what the test's batch hook stored.
type fakeReader struct {
	rows    map[string]Row
	order   []string
	listErr error
	getErr  error
	gets    int
}

func (f *fakeReader) List(context.Context) ([]Row, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}

	out := make([]Row, 0, len(f.order))
	for _, id := range f.order {
		out = append(out, f.rows[id])
	}

	return out, nil
}

func (f *fakeReader) Get(_ context.Context, id string) (Row, error) {
	f.gets++

	if f.getErr != nil {
		return Row{}, f.getErr
	}

	row, ok := f.rows[id]
	if !ok {
		return Row{}, ErrNotFound
	}

	return row, nil
}

// fakeBatch records the batches it receives and returns a configured error. It
// stands in for D1: onBatch applies the write to the fake reader's rows and
// returns how many rows the statement changed, as D1's meta.changes would. A nil
// onBatch is a write that changes nothing. rows, when set, are the rows the
// statement returns, as a RETURNING clause would. results, when set, replaces
// what the batch returns, for a platform that misreports.
type fakeBatch struct {
	err     error
	batches [][]atomic.Statement
	onBatch func() int64
	rows    [][]any
	results []atomic.Result
}

func (f *fakeBatch) run(_ context.Context, statements ...atomic.Statement) ([]atomic.Result, error) {
	f.batches = append(f.batches, statements)

	if f.err != nil {
		return nil, f.err
	}

	if f.results != nil {
		return f.results, nil
	}

	results := make([]atomic.Result, len(statements))

	if f.onBatch != nil {
		results[0].Changes = f.onBatch()
	}

	results[0].Rows = f.rows

	return results, nil
}

type fixture struct {
	svc      *Service
	sessions *fakeSessions
	reader   *fakeReader
	batcher  *fakeBatch
	entropy  io.Reader
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	fix := &fixture{
		sessions: &fakeSessions{principal: session.Principal{UserID: testAdminID, Role: "admin"}},
		reader:   &fakeReader{rows: map[string]Row{}},
		batcher:  &fakeBatch{},
		entropy:  bytes.NewReader(bytes.Repeat([]byte{0xab}, 4*CodeBytes)),
	}

	fix.svc = NewService(Deps{
		Sessions: fix.sessions,
		Reader:   fix.reader,
		Batch:    fix.batcher.run,
		Now:      testNow,
		Entropy:  fix.entropy,
		NewID:    func() string { return testNewID },
		Types:    []string{testType},
	})

	return fix
}

// store makes row known to the reader, as if it had been inserted.
func (f *fixture) store(row Row) {
	if _, exists := f.reader.rows[row.ID]; !exists {
		f.reader.order = append(f.reader.order, row.ID)
	}

	f.reader.rows[row.ID] = row
}

// returned is row as the update statement returns it: whether it applied, then
// the columns of an invitation row, in the order of selectColumns.
func returned(applied int64, row Row) []any {
	return []any{
		applied, row.ID, row.Type, row.Label, row.NumInvites, row.Uses,
		optional(row.ExpiresAt), optional(row.RevokedAt), optionalText(row.CreatedBy), row.CreatedAt,
	}
}

// invitationColumns is row as a statement that returns only the invitation columns
// returns it, in the order of selectColumns.
func invitationColumns(row Row) []any { return returned(0, row)[1:] }

func optional(value *int64) any {
	if value == nil {
		return nil
	}

	return *value
}

func optionalText(value *string) any {
	if value == nil {
		return nil
	}

	return *value
}

func row(id string) Row {
	return Row{
		ID: id, Type: testType, Label: "", NumInvites: 5, Uses: 2,
		ExpiresAt: nil, RevokedAt: nil, CreatedBy: nil, CreatedAt: testNow().Unix() - 100,
	}
}

// request builds a request carrying body (JSON-encoded unless it is already
// bytes or a string) and the path wildcard id, if any.
func request(t *testing.T, method string, body any, id string) httpapi.Request {
	t.Helper()

	var data []byte

	switch b := body.(type) {
	case nil:
	case string:
		data = []byte(b)
	default:
		var err error

		data, err = json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}

	values := map[string]string{}
	if id != "" {
		values["id"] = id
	}

	return httpapi.Request{
		Method: method, Path: "/", Context: t.Context(), Query: nil, PathValues: values, Body: data, Cookies: nil,
	}
}

func wantFailure(t *testing.T, err error, kind apierr.Kind, code string) {
	t.Helper()

	if err == nil {
		t.Fatal("handler succeeded, want an error")
	}

	failure := apierr.As(err)
	if failure.Kind != kind || failure.Code != code {
		t.Errorf("error = (%d, %q), want (%d, %q)", failure.Kind, failure.Code, kind, code)
	}
}

// bodyOf marshals a successful response's body, so a test can compare JSON.
func bodyOf(t *testing.T, resp httpapi.Response) string {
	t.Helper()

	data, err := json.Marshal(resp.Body)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	return string(data)
}

// failingReader is entropy that fails.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("entropy: %w", errDB) }

// forMethod returns the handler for method, from whichever path has it.
func (r Routes) forMethod(method string) httpapi.Handler {
	if handler, ok := r.Collection[method]; ok {
		return handler
	}

	return r.Item[method]
}
