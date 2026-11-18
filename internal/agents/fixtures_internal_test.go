package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/session"
)

var errDB = errors.New("database is on fire")

const (
	testUserID  = "00000000-0000-7000-8000-000000000002"
	testAgentID = "00000000-0000-7000-8000-0000000000aa"
	testNewID   = "00000000-0000-7000-8000-0000000000cc"
	testOrigin  = "https://auth.example.com"
	roleMember  = "member"
	// Names that recur across the tests.
	testName       = "assistant"
	pathCollection = "collection"
	pathItem       = "item"
	badID          = "nope"
	caseDBDown     = "database unavailable"
	caseRejects    = "schema rejects"
	bodyNameA      = `{"name":"a"}`
	nameCreate     = "create"
	nameRename     = "rename"
	nameRevoke     = "revoke"
)

// testNow is the fixed time the tests run at.
func testNow() time.Time { return time.Date(2026, time.November, 17, 12, 0, 0, 0, time.UTC) }

func getenv(name string) string {
	switch name {
	case deploy.VarAPIOrigin:
		return testOrigin
	case deploy.VarUIOrigin:
		return "https://example.com"
	default:
		return ""
	}
}

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

// storedRow is an agent and its owner, as the fake database holds it.
type storedRow struct {
	owner string
	row   Row
}

// fakeReader serves agents by owner and id, as the database would.
type fakeReader struct {
	rows    []storedRow
	listErr error
	getErr  error
	gets    int
	lists   int
	// askedFor records the owner of each read.
	askedFor []string
	// pages records the cursor and size of each list.
	pages []pageAsked
}

// pageAsked is the cursor and size a list was asked for.
type pageAsked struct {
	before string
	limit  int
}

func (f *fakeReader) List(_ context.Context, userID, before string, limit int) ([]Row, error) {
	f.lists++
	f.askedFor = append(f.askedFor, userID)
	f.pages = append(f.pages, pageAsked{before: before, limit: limit})

	if f.listErr != nil {
		return nil, f.listErr
	}

	mine := []Row{}

	for _, stored := range f.rows {
		if stored.owner == userID && stored.row.ID < before {
			mine = append(mine, stored.row)
		}
	}

	// Newest (largest id) first, as the query orders them.
	sort.Slice(mine, func(i, j int) bool { return mine[i].ID > mine[j].ID })

	if len(mine) > limit {
		mine = mine[:limit]
	}

	return mine, nil
}

func (f *fakeReader) Get(_ context.Context, userID, id string) (Row, error) {
	f.gets++
	f.askedFor = append(f.askedFor, userID)

	if f.getErr != nil {
		return Row{}, f.getErr
	}

	for _, stored := range f.rows {
		if stored.owner == userID && stored.row.ID == id {
			return stored.row, nil
		}
	}

	return Row{}, ErrNotFound
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

// fakeMint records the specs it was asked for and returns a fixed key, or fails.
type fakeMint struct {
	err    error
	specs  []session.Spec
	issuer []session.Issuer
}

func (f *fakeMint) run(issuer session.Issuer, spec session.Spec) (session.Key, error) {
	f.specs = append(f.specs, spec)
	f.issuer = append(f.issuer, issuer)

	if f.err != nil {
		return session.Key{}, f.err
	}

	return session.Key{
		ID:        uuid.MustParse(testKeyID),
		JWT:       "header.payload.signature",
		JWK:       []byte(`{"keys":[]}`),
		ExpiresAt: spec.Expires,
		PublicKey: nil,
	}, nil
}

const testKeyID = "00000000-0000-7000-8000-0000000000dd"

type fixture struct {
	svc      *Service
	sessions *fakeSessions
	reader   *fakeReader
	batcher  *fakeBatch
	minter   *fakeMint
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	fix := &fixture{
		sessions: &fakeSessions{principal: session.Principal{UserID: testUserID, Role: roleMember}},
		reader:   &fakeReader{},
		batcher:  &fakeBatch{},
		minter:   &fakeMint{},
	}

	fix.svc = NewService(Deps{
		Sessions: fix.sessions, Reader: fix.reader, Batch: fix.batcher.run, Now: testNow,
		NewID: func() string { return testNewID }, Mint: fix.minter.run,
	})

	return fix
}

// store makes row known to the reader as owner's, as if it had been inserted.
func (f *fixture) store(owner string, row Row) {
	f.reader.rows = append(f.reader.rows, storedRow{owner: owner, row: row})
}

func row(id string) Row {
	return Row{ID: id, Name: testName, Scopes: DefaultScopes, RevokedAt: nil, CreatedAt: testNow().Unix() - 100}
}

// columns is row as a statement returns it, in the order of selectColumns.
func columns(r Row) []any {
	var revokedAt any
	if r.RevokedAt != nil {
		revokedAt = *r.RevokedAt
	}

	return []any{r.ID, r.Name, r.Scopes, revokedAt, r.CreatedAt}
}

// request builds a request carrying the path wildcard id, if any, and body.
func request(t *testing.T, method, id, body string) httpapi.Request {
	t.Helper()

	return requestWithQuery(t, method, id, body, nil)
}

// requestWithQuery is request with URL query parameters.
func requestWithQuery(t *testing.T, method, id, body string, query map[string][]string) httpapi.Request {
	t.Helper()

	values := map[string]string{}
	if id != "" {
		values["id"] = id
	}

	var raw []byte
	if body != "" {
		raw = []byte(body)
	}

	return httpapi.Request{
		Method: method, Path: "/", Context: t.Context(), Query: query, PathValues: values, Body: raw, Cookies: nil,
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

// forMethod returns the handler for method on path ("collection" or "item").
func (r Routes) forMethod(path, method string) httpapi.Handler {
	if path == pathCollection {
		return r.Collection[method]
	}

	return r.Item[method]
}

// list runs GET on the collection with the query parameters.
func (f *fixture) list(t *testing.T, query map[string][]string) (httpapi.Response, error) {
	t.Helper()

	req := requestWithQuery(t, http.MethodGet, "", "", query)

	resp, err := f.svc.Handlers(getenv).Collection[http.MethodGet](req).Get()
	if err != nil {
		return httpapi.Response{}, fmt.Errorf("list: %w", err)
	}

	return resp, nil
}

// call runs the handler for method on path and returns its response or error.
func (f *fixture) call(t *testing.T, path, method, id, body string) (httpapi.Response, error) {
	t.Helper()

	resp, err := f.svc.Handlers(getenv).forMethod(path, method)(request(t, method, id, body)).Get()
	if err != nil {
		return httpapi.Response{}, fmt.Errorf("%s %s: %w", method, path, err)
	}

	return resp, nil
}

// contains reports whether every fragment is in s.
func contains(s string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(s, fragment) {
			return false
		}
	}

	return true
}
