package firstrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

var errBoom = errors.New("boom")

// fakeDB is an in-memory stand-in for D1, which only exists inside workerd. It
// is a database/sql driver that recognises the statements the service issues.
// Its insert obeys the same emptiness rule as the real SQL and, like
// INSERT ... RETURNING, answers with one row when it inserts and none when the
// condition refuses it.
type fakeDB struct {
	users    bool
	firstRun bool
	other    bool // a non-first-run invitation exists

	// raced simulates another caller minting between this request's lookup and
	// its insert: the lookup sees no first-run invitation, but by the time the
	// insert runs one exists.
	raced bool

	failQuery string // statements containing this fail

	minted     int         // insert attempts
	statements []statement // every statement issued, in order
}

// insertArgs returns the arguments of the single insert the service issued.
func (f *fakeDB) insertArgs(t *testing.T) []driver.Value {
	t.Helper()

	for _, stmt := range f.statements {
		if strings.HasPrefix(stmt.text, "INSERT") {
			return stmt.args
		}
	}

	t.Fatal("no insert was issued")

	return nil
}

func (f *fakeDB) open(t *testing.T) *sql.DB {
	t.Helper()

	db := sql.OpenDB(fakeConnector{f})
	t.Cleanup(func() { _ = db.Close() })

	return db
}

type fakeConnector struct{ f *fakeDB }

func (c fakeConnector) Connect(context.Context) (driver.Conn, error) { return fakeConn(c), nil }
func (c fakeConnector) Driver() driver.Driver                        { return nil }

type fakeConn struct{ f *fakeDB }

func (c fakeConn) Prepare(query string) (driver.Stmt, error) { return fakeStmt{c.f, query}, nil }
func (c fakeConn) Close() error                              { return nil }
func (c fakeConn) Begin() (driver.Tx, error)                 { return nil, errBoom }

// statement is one SQL statement as the driver received it: the text and the
// values bound to its placeholders.
type statement struct {
	text string
	args []driver.Value
}

type fakeStmt struct {
	f     *fakeDB
	query string
}

func (s fakeStmt) Close() error  { return nil }
func (s fakeStmt) NumInput() int { return -1 }

// Exec is never used: the service's one write is INSERT ... RETURNING, which
// goes through Query so its outcome comes from the statement itself.
func (s fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errBoom
}

func (s fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	err := s.fail()
	if err != nil {
		return nil, err
	}

	s.f.statements = append(s.f.statements, statement{s.query, args})

	if strings.HasPrefix(s.query, "INSERT") {
		return s.f.insert(args), nil
	}

	found := s.f.firstRun
	if strings.Contains(s.query, "FROM users") {
		found = s.f.users
	}

	return &fakeRows{values: [][]driver.Value{{found}}}, nil
}

// insert applies the first-run insert and returns its RETURNING rows.
func (f *fakeDB) insert(args []driver.Value) *fakeRows {
	f.minted++

	// The real statement is conditional on the system being empty.
	if f.raced || f.users || f.firstRun || f.other {
		return &fakeRows{}
	}

	f.firstRun = true

	return &fakeRows{values: [][]driver.Value{{args[0]}}}
}

// fail reports the configured error for a statement that should fail.
func (s fakeStmt) fail() error {
	if s.f.failQuery == "" || !strings.Contains(s.query, s.f.failQuery) {
		return nil
	}

	return errBoom
}

type fakeRows struct {
	values [][]driver.Value
	next   int
}

func (r *fakeRows) Columns() []string { return []string{"v"} }
func (r *fakeRows) Close() error      { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.next == len(r.values) {
		return io.EOF
	}

	copy(dest, r.values[r.next])
	r.next++

	return nil
}

func fixedNow() time.Time { return time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC) }

func env(value string) func(string) string {
	return func(name string) string {
		if name == SecretName {
			return value
		}

		return ""
	}
}

func newTestService(t *testing.T, fake *fakeDB) *service {
	t.Helper()

	return newService(fake.open(t), fixedNow)
}

func TestCheck(t *testing.T) {
	t.Parallel()

	valid := strings.Repeat("a", MinSecretLen)

	tests := map[string]struct {
		db         fakeDB
		secret     string
		wantStatus Status
	}{
		"users exist": {
			db:         fakeDB{users: true},
			secret:     valid,
			wantStatus: StatusInvitationAccepted,
		},
		"invitation pending": {
			db:         fakeDB{firstRun: true},
			wantStatus: StatusInvitationPending,
		},
		"no secret": {
			wantStatus: StatusMissingSecret,
		},
		"secret too short": {
			secret:     valid[:MinSecretLen-1],
			wantStatus: StatusMissingSecret,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fake := tt.db

			got, err := newTestService(t, &fake).check(t.Context(), env(tt.secret))
			if err != nil {
				t.Fatalf("Check: %v", err)
			}

			if got != tt.wantStatus {
				t.Errorf("status = %q, want %q", got, tt.wantStatus)
			}

			if fake.minted != 0 {
				t.Errorf("insert attempts = %d, want 0", fake.minted)
			}
		})
	}
}

// TestCheckMint covers the cases where check reaches the insert. The status
// must reflect what the insert did, not what the database holds afterwards.
func TestCheckMint(t *testing.T) {
	t.Parallel()

	valid := strings.Repeat("a", MinSecretLen)

	tests := map[string]struct {
		db         fakeDB
		wantStatus Status
	}{
		"valid secret mints": {
			wantStatus: StatusInvitationPending,
		},
		"other invitation blocks mint": {
			db:         fakeDB{other: true},
			wantStatus: StatusMissingSecret,
		},
		// Another caller minted between our lookup and our insert. Our insert
		// was refused, so we must not report an invitation minted from this
		// secret, even though one now exists.
		"lost race": {
			db:         fakeDB{raced: true},
			wantStatus: StatusMissingSecret,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fake := tt.db

			got, err := newTestService(t, &fake).check(t.Context(), env(valid))
			if err != nil {
				t.Fatalf("Check: %v", err)
			}

			if got != tt.wantStatus {
				t.Errorf("status = %q, want %q", got, tt.wantStatus)
			}

			if fake.minted != 1 {
				t.Errorf("insert attempts = %d, want 1", fake.minted)
			}
		})
	}
}

func TestCheckMintsHashOfSecret(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("Zz-_", 11)
	fake := &fakeDB{}

	_, err := newTestService(t, fake).check(t.Context(), env(secret))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	sum := sha256.Sum256([]byte(secret))

	args := fake.insertArgs(t)
	id, _ := args[0].(string)
	hash, ok := args[1].([]byte)

	if !ok || !bytes.Equal(hash, sum[:]) {
		t.Errorf("code hash = %x, want %x", args[1], sum)
	}

	if args[2] != InvitationType {
		t.Errorf("type = %v, want %q", args[2], InvitationType)
	}

	if args[3] != InvitationLabel {
		t.Errorf("label = %v, want %q", args[3], InvitationLabel)
	}

	if args[4] != fixedNow().Unix() {
		t.Errorf("created_at = %v, want %v", args[4], fixedNow().Unix())
	}

	uuidv7 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidv7.MatchString(id) {
		t.Errorf("id = %q, want a lowercase UUIDv7", id)
	}
}

// TestStatementsBindEveryValue guards the rule that values are always bound,
// never concatenated into SQL, even when they are our own constants. It holds
// every statement the service issues to the same standard: no constant's text
// appears in the SQL, and the number of bound values equals the number of
// placeholders.
func TestStatementsBindEveryValue(t *testing.T) {
	t.Parallel()

	fake := &fakeDB{}

	_, err := newTestService(t, fake).check(t.Context(), env(validSecret))
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	// users lookup, first-run lookup, insert. There is no read-back after the
	// insert: its RETURNING clause is the outcome.
	const wantStatements = 3
	if len(fake.statements) != wantStatements {
		t.Fatalf("statements = %d, want %d", len(fake.statements), wantStatements)
	}

	for _, stmt := range fake.statements {
		for _, value := range []string{InvitationType, InvitationLabel} {
			if strings.Contains(stmt.text, value) {
				t.Errorf("SQL inlines %q: %q", value, stmt.text)
			}
		}

		if got, want := len(stmt.args), strings.Count(stmt.text, "?"); got != want {
			t.Errorf("bound %d values for %d placeholders: %q", got, want, stmt.text)
		}
	}
}

// TestLookupBindsType checks that the first-run lookup filters on the bound
// invitation type.
func TestLookupBindsType(t *testing.T) {
	t.Parallel()

	fake := &fakeDB{}

	_, err := newTestService(t, fake).check(t.Context(), env(validSecret))
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	var lookups int

	for _, stmt := range fake.statements {
		if !strings.Contains(stmt.text, "FROM invitations WHERE") {
			continue
		}

		lookups++

		if len(stmt.args) != 1 || stmt.args[0] != InvitationType {
			t.Errorf("lookup bound %v, want [%q]", stmt.args, InvitationType)
		}
	}

	if lookups == 0 {
		t.Error("no first-run lookup was issued")
	}
}

func TestCheckDoesNotReadSecretOnceUsersExist(t *testing.T) {
	t.Parallel()

	getenv := func(string) string {
		t.Error("secret was read although a user exists")

		return ""
	}

	_, err := newTestService(t, &fakeDB{users: true}).check(t.Context(), getenv)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestCheckErrors(t *testing.T) {
	t.Parallel()

	valid := strings.Repeat("a", MinSecretLen)

	tests := map[string]struct {
		db       fakeDB
		wantCode string
	}{
		"users query fails": {
			db: fakeDB{failQuery: "FROM users"}, wantCode: CodeUsersCheckFailed,
		},
		"invitation query fails": {
			db: fakeDB{failQuery: "FROM invitations WHERE"}, wantCode: CodeInvitationCheckFailed,
		},
		"insert fails": {
			db: fakeDB{failQuery: "INSERT"}, wantCode: CodeMintFailed,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fake := tt.db

			status, err := newTestService(t, &fake).check(t.Context(), env(valid))
			if err == nil {
				t.Fatalf("Check = %q, want error", status)
			}

			failure := apierr.As(err)
			if failure.Kind != apierr.Unavailable || failure.Code != tt.wantCode {
				t.Errorf("error = (%d, %q), want (Unavailable, %q)", failure.Kind, failure.Code, tt.wantCode)
			}

			if !errors.Is(err, errBoom) {
				t.Errorf("error %v does not wrap the driver error", err)
			}
		})
	}
}

const (
	noStore     = "no-store"
	validSecret = "0123456789abcdef0123456789abcdef" // MinSecretLen characters
)

func serve(t *testing.T, fake *fakeDB, secret string) (int, string, error) {
	t.Helper()

	res := Handler(fake.open(t), func(string) string { return secret })(httpapi.Request{
		Context: t.Context(),
		Query:   nil,
		Body:    nil,
	})

	resp, err := res.Get()
	if err != nil {
		return 0, "", fmt.Errorf("handler: %w", err)
	}

	body, marshalErr := json.Marshal(resp.Body)
	if marshalErr != nil {
		t.Fatalf("marshal body: %v", marshalErr)
	}

	return resp.Status, string(body), nil
}

func TestHandlerStatus(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		db       fakeDB
		secret   string
		wantBody string
	}{
		"missing secret": {
			wantBody: `{"status":"missing_secret"}`,
		},
		"valid secret mints, so pending": {
			secret:   validSecret,
			wantBody: `{"status":"invitation_pending"}`,
		},
		"invitation already pending": {
			db:       fakeDB{firstRun: true},
			wantBody: `{"status":"invitation_pending"}`,
		},
		"user exists": {
			db:       fakeDB{users: true, firstRun: true},
			wantBody: `{"status":"invitation_accepted"}`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fake := tt.db

			status, body, err := serve(t, &fake, tt.secret)
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}

			if status != http.StatusOK {
				t.Errorf("status = %d, want %d", status, http.StatusOK)
			}

			if body != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

// A database failure reaches the boundary as a classified Unavailable error
// that keeps the driver error as its cause. Hiding the cause from the client is
// the boundary's job, tested in httpapi and end to end.
func TestHandlerDatabaseError(t *testing.T) {
	t.Parallel()

	_, _, err := serve(t, &fakeDB{failQuery: "FROM users"}, validSecret)

	failure := apierr.As(err)
	if failure.Kind != apierr.Unavailable || failure.Code != CodeUsersCheckFailed {
		t.Errorf("error = (%d, %q), want (Unavailable, %q)", failure.Kind, failure.Code, CodeUsersCheckFailed)
	}

	if !errors.Is(err, errBoom) {
		t.Errorf("error = %v, want one wrapping errBoom", err)
	}
}
