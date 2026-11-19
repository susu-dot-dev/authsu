//nolint:gosec // the secrets in these tests are fixtures, not credentials
package firstrun_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// route reads and writes through.
var _ firstrun.Store = (*store.Store)(nil)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB        = errors.New("SELECT EXISTS: database is on fire")
	errNotScript = errors.New("FirstRunState was called more often than the test scripted")
	errCredsRead = errors.New("the credential store was read")
	// errLeaky is a store failure that quotes the secret, as a careless driver
	// message might.
	errLeaky = errors.New("INSERT INTO invitations ... " + validSecret)
)

const (
	// validBody is a canonical token body: 43 base64url characters whose last
	// one has its two unused bits clear.
	validBody = "k3Jx9Qp-Zr2_LmN8vB5tYcD1fGhWaXeUoIiS7dTqA0E"
	// validSecret is a complete invitation token, a valid FIRST_RUN_SECRET.
	validSecret = "susu_inv_" + validBody
	generatedID = "01990000-0000-7000-8000-00000000abcd"
	jsonType    = "application/json"

	unavailableText = "first-run status is temporarily unavailable"
)

// The names of the store calls in a call log.
const (
	callState  = "state"
	callCreate = "create"
)

// The snapshots the database can be in.
func empty() store.FirstRunState {
	return store.FirstRunState{HasUsers: false, HasFirstRunInvitation: false}
}
func invited() store.FirstRunState {
	return store.FirstRunState{HasUsers: false, HasFirstRunInvitation: true}
}
func usersOnly() store.FirstRunState {
	return store.FirstRunState{HasUsers: true, HasFirstRunInvitation: false}
}
func usersAndInvitation() store.FirstRunState {
	return store.FirstRunState{HasUsers: true, HasFirstRunInvitation: true}
}

// reading is a successful FirstRunState answer.
func reading(state store.FirstRunState) stateAnswer { return stateAnswer{state: state, err: nil} }

// requestCookie is a cookie as a browser returns it: only a name and a value.
func requestCookie(name, value string) *http.Cookie {
	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: name, Value: value}
}

// The exact bodies a client gets: the error code and the fixed message are the
// contract, and a cause never appears.
const (
	bodyMissing  = `{"status":"missing_secret"}` + "\n"
	bodyPending  = `{"status":"invitation_pending"}` + "\n"
	bodyAccepted = `{"status":"invitation_accepted"}` + "\n"
	bodyInternal = `{"error":{"code":"internal","message":"internal error"}}` + "\n"
	bodyBlocked  = `{"error":{"code":"first_run_blocked","message":` +
		`"first-run setup cannot finish with this database: wipe it and redeploy"}}` + "\n"
)

// errorBody is the exact body of a failure with this code and message.
func errorBody(code, message string) string {
	return `{"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n"
}

// unavailable is the failure the store reports for a database that failed.
func unavailable(code string) error {
	return apierr.Wrap(errDB, apierr.Unavailable, code, unavailableText)
}

// stateAnswer is what one FirstRunState call returns.
type stateAnswer struct {
	state store.FirstRunState
	err   error
}

// createAnswer is what CreateFirstRunInvitation returns.
type createAnswer struct {
	created bool
	err     error
}

// createCall is one call of CreateFirstRunInvitation.
type createCall struct {
	id        string
	token     string
	hash      string
	label     string
	expiresAt time.Time
	now       time.Time
}

// fakeStore is the first-run store. FirstRunState answers from a script, one
// answer per call in order, and a call past the script is a test failure: the
// number of reads is part of the behaviour. Every call is recorded in order.
type fakeStore struct {
	t       *testing.T
	states  []stateAnswer
	create  createAnswer
	calls   []string
	creates []createCall
}

func (f *fakeStore) FirstRunState(context.Context) (store.FirstRunState, error) {
	f.calls = append(f.calls, callState)

	if len(f.states) == 0 {
		f.t.Error(errNotScript)

		return store.FirstRunState{}, errNotScript
	}

	answer := f.states[0]
	f.states = f.states[1:]

	return answer.state, answer.err
}

func (f *fakeStore) CreateFirstRunInvitation(
	_ context.Context, id string, token input.InvitationToken, label string, expiresAt, now time.Time,
) (bool, error) {
	f.calls = append(f.calls, callCreate)
	f.creates = append(f.creates, createCall{
		id: id, token: token.String(), hash: string(token.Hash()), label: label, expiresAt: expiresAt, now: now,
	})

	return f.create.created, f.create.err
}

// deadCredentials is the credential store of a boundary that must never read
// it: first-run is a route with no credential.
type deadCredentials struct{ calls int }

func (c *deadCredentials) ResolveSession(
	context.Context, input.SessionToken, time.Time,
) (store.ActiveSession, bool, error) {
	c.calls++

	return store.ActiveSession{}, false, errCredsRead
}

func (c *deadCredentials) ResolveAPIKey(
	context.Context, input.APIKeyToken, time.Time,
) (store.ActiveAPIKey, bool, error) {
	c.calls++

	return store.ActiveAPIKey{}, false, errCredsRead
}

// rig is one deployment under test: the real boundary and the real route over a
// fake store.
type rig struct {
	t     *testing.T
	store *fakeStore
	creds *deadCredentials
	env   map[string]string
	now   time.Time

	// reads counts reads of each environment name.
	reads map[string]int
	// ids counts calls of NewID and clock reads counts calls of Now.
	ids, clockReads int
	logged          []*apierr.Error
}

// newRig is a deployment whose database answers states in order.
func newRig(t *testing.T, states ...stateAnswer) *rig {
	t.Helper()

	return &rig{
		t:     t,
		store: &fakeStore{t: t, states: states, create: createAnswer{created: false, err: nil}, calls: nil, creates: nil},
		creds: &deadCredentials{calls: 0},
		env:   map[string]string{},
		now:   time.Date(2026, time.November, 17, 9, 15, 30, 123456789, time.UTC),
		reads: map[string]int{},
	}
}

// routes are the first-run routes over the rig's fakes.
func (r *rig) routes() []auth.Route {
	return firstrun.Routes(firstrun.Deps{
		Store: r.store,
		Now: func() time.Time {
			r.clockReads++

			return r.now
		},
		NewID: func() string {
			r.ids++

			return generatedID
		},
	})
}

// handler is the real boundary over the real routes.
func (r *rig) handler() http.Handler {
	return auth.Handler(r.routes(), auth.Deps{
		Credentials: r.creds,
		Now:         func() time.Time { return r.now },
		Getenv: func(name string) string {
			r.reads[name]++

			return r.env[name]
		},
		Log: func(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) },
	})
}

// request is one request to send.
type request struct {
	method  string
	cookies []*http.Cookie
	body    string
	// contentType defaults to none, which is what a GET sends; "" sends none.
	contentType string
}

// serve sends req to the first-run path and returns the response.
func (r *rig) serve(req request) *httptest.ResponseRecorder {
	r.t.Helper()

	method := req.method
	if method == "" {
		method = http.MethodGet
	}

	httpReq := httptest.NewRequestWithContext(r.t.Context(), method, firstrun.Path, strings.NewReader(req.body))

	if req.contentType != "" {
		httpReq.Header.Set("Content-Type", req.contentType)
	}

	for _, cookie := range req.cookies {
		httpReq.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	r.handler().ServeHTTP(rec, httpReq)

	return rec
}

// migrationLimits reads the numbers a CHECK of the migrations states, by a
// pattern whose capture groups are the numbers, over the migrations' text with
// whitespace collapsed. A pattern that matches nothing fails the test, so a
// reworded migration is noticed.
func migrationLimits(t *testing.T, pattern string) []int {
	t.Helper()

	paths, err := filepath.Glob("../../migrations/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}

	var text strings.Builder

	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // the paths are a glob of the repository's own migrations
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		text.Write(raw)
		text.WriteString("\n")
	}

	match := regexp.MustCompile(pattern).FindStringSubmatch(strings.Join(strings.Fields(text.String()), " "))
	if match == nil {
		t.Fatalf("no CHECK matches %s; was the migration text changed?", pattern)
	}

	limits := make([]int, 0, len(match)-1)

	for _, captured := range match[1:] {
		number, err := strconv.Atoi(captured)
		if err != nil {
			t.Fatalf("limit %q: %v", captured, err)
		}

		limits = append(limits, number)
	}

	return limits
}
