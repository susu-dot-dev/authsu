//nolint:gosec // the secrets in these tests are fixtures, not credentials
package firstrun_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// route reads through.
var _ firstrun.Store = (*store.Store)(nil)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB        = errors.New("SELECT EXISTS: database is on fire")
	errNotScript = errors.New("FirstRunState was called more often than the test scripted")
	errCredsRead = errors.New("the credential store was read")
	// errLeaky is a store failure that quotes the secret, as a careless driver
	// message might.
	errLeaky = errors.New("SELECT EXISTS ... " + validSecret)
)

const (
	// validBody is a canonical token body: 43 base64url characters whose last
	// one has its two unused bits clear.
	validBody = "k3Jx9Qp-Zr2_LmN8vB5tYcD1fGhWaXeUoIiS7dTqA0E"
	// validSecret is a complete invitation token, a valid FIRST_RUN_SECRET.
	validSecret = "susu_inv_" + validBody
	jsonType    = "application/json"

	unavailableText = "first-run status is temporarily unavailable"
)

// The snapshots the database can be in.
func empty() store.FirstRunState { return store.FirstRunState{} }

// invited is a database with a first-run invitation and no account.
func invited() store.FirstRunState {
	return store.FirstRunState{HasInvitations: true, HasFirstRunInvitation: true}
}

// otherInvited is a database with an invitation of another type and no account.
func otherInvited() store.FirstRunState { return store.FirstRunState{HasInvitations: true} }

// usersOnly is a database with an account and no invitation at all.
func usersOnly() store.FirstRunState { return store.FirstRunState{HasUsers: true} }

// usersAndInvitation is a database with an account and a first-run invitation.
func usersAndInvitation() store.FirstRunState {
	return store.FirstRunState{HasUsers: true, HasInvitations: true, HasFirstRunInvitation: true}
}

// usersAndOtherInvitation is a database with an account and an invitation of
// another type.
func usersAndOtherInvitation() store.FirstRunState {
	return store.FirstRunState{HasUsers: true, HasInvitations: true}
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

// fakeStore is the first-run store. FirstRunState answers from a script, one
// answer per call in order, and a call past the script is a test failure: the
// number of reads is part of the behaviour.
type fakeStore struct {
	t      *testing.T
	states []stateAnswer
	calls  int
}

func (f *fakeStore) FirstRunState(context.Context) (store.FirstRunState, error) {
	f.calls++

	if len(f.states) == 0 {
		f.t.Error(errNotScript)

		return store.FirstRunState{}, errNotScript
	}

	answer := f.states[0]
	f.states = f.states[1:]

	return answer.state, answer.err
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

func (c *deadCredentials) ResolveGrant(
	context.Context, input.AccessToken, input.ResourceID, time.Time,
) (store.ActiveGrant, bool, error) {
	c.calls++

	return store.ActiveGrant{}, false, errCredsRead
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
	reads  map[string]int
	logged []*apierr.Error
}

// newRig is a deployment whose database answers states in order.
func newRig(t *testing.T, states ...stateAnswer) *rig {
	t.Helper()

	return &rig{
		t:     t,
		store: &fakeStore{t: t, states: states, calls: 0},
		creds: &deadCredentials{calls: 0},
		env:   map[string]string{},
		now:   time.Date(2026, time.November, 17, 9, 15, 30, 123456789, time.UTC),
		reads: map[string]int{},
	}
}

// routes are the first-run routes over the rig's fakes.
func (r *rig) routes() []auth.Route {
	return firstrun.Routes(firstrun.Deps{Store: r.store})
}

// handler is the real boundary over the real routes.
func (r *rig) handler() http.Handler {
	return auth.Handler(r.routes(), auth.Deps{
		Credentials: r.creds,
		Resources:   resource.Select,
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
