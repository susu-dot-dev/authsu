package session

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

var errDB = errors.New("database is on fire")

// Names that recur across the tests.
const (
	garbage     = "garbage"
	emptyCase   = "empty"
	routeLogout = "logout"
)

const (
	testOrigin   = "https://auth.example.com"
	testUIOrigin = "https://example.com"
	testUserID   = "00000000-0000-7000-8000-000000000002"
	testCredID   = "00000000-0000-7000-8000-000000000001"
	testRole     = "admin"
)

// testNow is the fixed time the tests run at. It is real time, not a fixed
// date: japikey reads the wall clock for the token's own claims, so a token
// minted here would be expired or "from the future" against any other time.
func testNow() time.Time { return time.Now() }

func getenv(overrides map[string]string) func(string) string {
	values := map[string]string{deploy.VarAPIOrigin: testOrigin, deploy.VarUIOrigin: testUIOrigin}

	maps.Copy(values, overrides)

	return func(name string) string { return values[name] }
}

// fakeReader serves keys by kid, as the database would.
type fakeReader struct {
	keys map[string]ActiveKey
	err  error
	// asked records the kids it was asked for.
	asked []string
	// at records the time each lookup was made at.
	at []time.Time
}

func (f *fakeReader) ActiveKey(_ context.Context, kid string, now time.Time) (ActiveKey, bool, error) {
	f.asked = append(f.asked, kid)
	f.at = append(f.at, now)

	if f.err != nil {
		return ActiveKey{}, false, f.err
	}

	key, ok := f.keys[kid]

	return key, ok, nil
}

// fakeBatch records the batches it receives and returns a configured error. Each
// statement reports that it changed one row, as a write that took effect does,
// unless unchanged says it matched nothing. results, when set, replaces what the
// batch returns, for a platform that misreports.
type fakeBatch struct {
	err       error
	batches   [][]atomic.Statement
	unchanged bool
	results   []atomic.Result
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

	if !f.unchanged {
		for i := range results {
			results[i].Changes = 1
		}
	}

	return results, nil
}

// fixture is a service wired to fakes, with a clock we control.
type fixture struct {
	svc     *Service
	reader  *fakeReader
	batcher *fakeBatch
	issuer  Issuer
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	api, err := deploy.ParseOrigin(testOrigin)
	if err != nil {
		t.Fatalf("origin: %v", err)
	}

	issuer := IssuerFor(api)

	fix := &fixture{
		reader:  &fakeReader{keys: map[string]ActiveKey{}, err: nil, asked: nil, at: nil},
		batcher: &fakeBatch{err: nil, batches: nil, unchanged: false, results: nil},
		issuer:  issuer,
		now:     testNow(),
		svc:     nil,
	}

	fix.svc = NewService(Deps{
		Reader: fix.reader,
		Batch:  fix.batcher.run,
		Now:    func() time.Time { return fix.now },
	})

	return fix
}

// verifier is a Verifier on the fixture's reader, issuer and clock.
func (f *fixture) verifier() *Verifier {
	return NewVerifier(f.reader, f.issuer, func() time.Time { return f.now })
}

// issue mints a session that expires at expires and makes it known to the
// reader, as if login had stored it.
func (f *fixture) issue(t *testing.T, expires time.Time) Key {
	t.Helper()

	key, err := Mint(f.issuer, testUserID, expires)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	f.reader.keys[key.ID.String()] = ActiveKey{
		JWK: key.JWK, UserID: testUserID, CredentialID: testCredID, Role: testRole, ExpiresAt: expires,
	}

	return key
}

// sessionCookie is a request cookie as a browser sends it: only the name and
// value, which is all a browser returns. The attributes are for responses.
func sessionCookie(name, value string) *http.Cookie {
	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: name, Value: value}
}

// requestWith is a request carrying key's cookie.
func requestWith(t *testing.T, key Key) httpapi.Request {
	t.Helper()

	return httpapi.Request{
		Method: http.MethodPost, Path: "/", Context: t.Context(), Query: nil, Body: nil,
		Cookies: []*http.Cookie{sessionCookie(CookieName, key.JWT)},
	}
}

// requestWithCookie is a request carrying one cookie with the given name and
// value.
func requestWithCookie(t *testing.T, name, value string) httpapi.Request {
	t.Helper()

	req := noCookie(t)
	req.Cookies = []*http.Cookie{sessionCookie(name, value)}

	return req
}

// noCookie is a request with no session cookie.
func noCookie(t *testing.T) httpapi.Request {
	t.Helper()

	return httpapi.Request{Method: http.MethodPost, Path: "/", Context: t.Context(), Query: nil, Body: nil, Cookies: nil}
}

// wantFailure checks the kind and code of a handler failure.
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
