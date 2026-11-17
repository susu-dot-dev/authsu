package users

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
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
	testUserID  = "00000000-0000-7000-8000-0000000000aa"
	testInvID   = "00000000-0000-7000-8000-0000000000bb"
	roleMember  = "member"
	roleAdmin   = "admin"
	testProfile = `{"name":"Ada"}`
)

// testNow is the fixed time the tests run at.
func testNow() time.Time { return time.Date(2026, time.November, 17, 12, 0, 0, 0, time.UTC) }

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

// fakeReader serves accounts by id, as the database would.
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

// fakeBatch records the batches it receives. rows are what the first statement
// returns, as its RETURNING clause would; results, when set, replace what the
// batch returns, for a platform that misreports.
type fakeBatch struct {
	err     error
	batches [][]atomic.Statement
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
	results[0].Rows = f.rows

	return results, nil
}

type fixture struct {
	svc      *Service
	sessions *fakeSessions
	reader   *fakeReader
	batcher  *fakeBatch
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	fix := &fixture{
		sessions: &fakeSessions{principal: session.Principal{UserID: testAdminID, Role: roleAdmin}},
		reader:   &fakeReader{rows: map[string]Row{}},
		batcher:  &fakeBatch{},
	}

	fix.svc = NewService(Deps{
		Sessions: fix.sessions, Reader: fix.reader, Batch: fix.batcher.run, Now: testNow,
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

func row(id string) Row {
	return Row{
		ID: id, Role: roleMember, InvitationID: testInvID, Profile: testProfile,
		RevokedAt: nil, CreatedAt: testNow().Unix() - 100,
	}
}

// columns is row as the revoke statement returns it, in the order of
// selectColumns.
func columns(r Row) []any {
	var revokedAt any
	if r.RevokedAt != nil {
		revokedAt = *r.RevokedAt
	}

	return []any{r.ID, r.Role, r.InvitationID, r.Profile, revokedAt, r.CreatedAt}
}

// request builds a request carrying the path wildcard id, if any.
func request(t *testing.T, method, id string) httpapi.Request {
	t.Helper()

	values := map[string]string{}
	if id != "" {
		values["id"] = id
	}

	return httpapi.Request{
		Method: method, Path: "/", Context: t.Context(), Query: nil, PathValues: values, Body: nil, Cookies: nil,
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

// itoa formats a Unix time the way JSON encodes it.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// forMethod returns the handler for method on path ("collection" or "item").
func (r Routes) forMethod(path, method string) httpapi.Handler {
	if path == "collection" {
		return r.Collection[method]
	}

	return r.Item[method]
}
