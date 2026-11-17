package session

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env     map[string]string
		wantErr bool
	}{
		"https origin":         {env: nil},
		"api origin missing":   {env: map[string]string{deploy.VarAPIOrigin: ""}, wantErr: true},
		"api origin not https": {env: map[string]string{deploy.VarAPIOrigin: "http://auth.example.com"}, wantErr: true},
		"ui origin missing":    {env: map[string]string{deploy.VarUIOrigin: ""}, wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := LoadConfig(getenv(tt.env))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
			}
		})
	}
}

func TestWhoAmI(t *testing.T) {
	t.Parallel()

	tests := map[string]time.Duration{
		"fresh session": Lifetime,
		"half way":      Lifetime / 2,
		"about to end":  time.Minute,
	}

	for name, lifeLeft := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			key := fix.issue(t, fix.now.Add(lifeLeft))

			resp, err := fix.svc.WhoAmIHandler(getenv(nil))(requestWith(t, key)).Get()
			if err != nil {
				t.Fatalf("whoami: %v", err)
			}

			wantWhoAmI(t, resp, WhoAmIResponse{
				UserID: testUserID, Role: testRole, ExpiresAt: fix.now.Add(lifeLeft).Unix(),
			})

			// whoami only reads.
			if len(fix.batcher.batches) != 0 || len(resp.Cookies) != 0 {
				t.Errorf("whoami wrote: %d batches, %d cookies", len(fix.batcher.batches), len(resp.Cookies))
			}
		})
	}
}

// wantWhoAmI checks a 200 response carrying want.
func wantWhoAmI(t *testing.T, resp httpapi.Response, want WhoAmIResponse) {
	t.Helper()

	body, ok := resp.Body.(WhoAmIResponse)
	if !ok || resp.Status != http.StatusOK {
		t.Fatalf("response = %d %T", resp.Status, resp.Body)
	}

	if body != want {
		t.Errorf("body = %+v, want %+v", body, want)
	}
}

// TestEveryRouteRefusesWithOneAnswer holds the three handlers to the same rule:
// whatever is wrong with the cookie, the answer is the same 401.
func TestEveryRouteRefusesWithOneAnswer(t *testing.T) {
	t.Parallel()

	routes := map[string]func(*Service, func(string) string) httpapi.Handler{
		"whoami":    (*Service).WhoAmIHandler,
		routeLogout: (*Service).LogoutHandler,
	}

	cases := map[string]func(*testing.T, *fixture) httpapi.Request{
		"no cookie": func(t *testing.T, _ *fixture) httpapi.Request {
			t.Helper()

			return noCookie(t)
		},
		"empty cookie": func(t *testing.T, _ *fixture) httpapi.Request {
			t.Helper()

			return requestWithCookie(t, CookieName, "")
		},
		"another cookie": func(t *testing.T, _ *fixture) httpapi.Request {
			t.Helper()

			return requestWithCookie(t, "other", "x")
		},
		garbage: func(t *testing.T, _ *fixture) httpapi.Request {
			t.Helper()

			return requestWithCookie(t, CookieName, garbage)
		},
		"unknown or revoked key": func(t *testing.T, f *fixture) httpapi.Request {
			t.Helper()

			key := f.issue(t, f.now.Add(Lifetime/2))
			delete(f.reader.keys, key.ID.String())

			return requestWith(t, key)
		},
	}

	for route, handler := range routes {
		for name, build := range cases {
			t.Run(route+"/"+name, func(t *testing.T) {
				t.Parallel()

				fix := newFixture(t)
				req := build(t, fix)

				_, err := handler(fix.svc, getenv(nil))(req).Get()
				wantFailure(t, err, apierr.Unauthorized, CodeUnauthenticated)

				if len(fix.batcher.batches) != 0 {
					t.Errorf("a refused request wrote: %v", fix.batcher.batches)
				}
			})
		}
	}
}

func TestEveryRouteReportsMissingConfigurationAsUnavailable(t *testing.T) {
	t.Parallel()

	routes := map[string]func(*Service, func(string) string) httpapi.Handler{
		"whoami":    (*Service).WhoAmIHandler,
		routeLogout: (*Service).LogoutHandler,
	}

	for route, handler := range routes {
		t.Run(route+"/no origin", func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			key := fix.issue(t, fix.now.Add(Lifetime/2))

			_, err := handler(fix.svc, getenv(map[string]string{deploy.VarAPIOrigin: ""}))(requestWith(t, key)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
		})

		t.Run(route+"/no reader", func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			key := fix.issue(t, fix.now.Add(Lifetime/2))
			fix.svc.reader = nil

			_, err := handler(fix.svc, getenv(nil))(requestWith(t, key)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
		})

		t.Run(route+"/store down", func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			key := fix.issue(t, fix.now.Add(Lifetime/2))
			fix.reader.err = errDB

			_, err := handler(fix.svc, getenv(nil))(requestWith(t, key)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeVerifyFailed)

			if !errors.Is(err, errDB) {
				t.Errorf("err = %v, want it to wrap the cause for the log", err)
			}
		})
	}
}

func TestWritingRoutesReportNoBatchAsUnavailable(t *testing.T) {
	t.Parallel()

	routes := map[string]func(*Service, func(string) string) httpapi.Handler{
		routeLogout: (*Service).LogoutHandler,
	}

	for route, handler := range routes {
		t.Run(route, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			key := fix.issue(t, fix.now.Add(Lifetime/2))
			fix.svc.batch = nil

			_, err := handler(fix.svc, getenv(nil))(requestWith(t, key)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
		})
	}
}

func TestLogoutClearsTheCookie(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))

	resp, err := fix.svc.LogoutHandler(getenv(nil))(requestWith(t, key)).Get()
	if err != nil {
		t.Fatalf("logout: %v", err)
	}

	if resp.Status != http.StatusNoContent || resp.Body != nil {
		t.Errorf("response = %d %v, want 204 with no body", resp.Status, resp.Body)
	}

	if len(resp.Cookies) != 1 || resp.Cookies[0].MaxAge >= 0 || resp.Cookies[0].Value != "" {
		t.Errorf("cookies = %v, want the session cookie cleared", resp.Cookies)
	}
}

func TestLogoutRevokesTheKeyNow(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))

	_, err := fix.svc.LogoutHandler(getenv(nil))(requestWith(t, key)).Get()
	if err != nil {
		t.Fatalf("logout: %v", err)
	}

	if len(fix.batcher.batches) != 1 || len(fix.batcher.batches[0]) != 1 {
		t.Fatalf("batches = %v, want one statement", fix.batcher.batches)
	}

	revoke := fix.batcher.batches[0][0]

	if revoke.Query != logoutQuery {
		t.Error("logout did not run the logout statement")
	}

	// Logout is immediate: now, for the presented key.
	now := fix.now.Unix()
	if revoke.Args[0] != now || revoke.Args[1] != key.ID.String() {
		t.Errorf("revoke args = %v, want now (%d) for the presented key", revoke.Args, now)
	}

	if got, want := len(revoke.Args), strings.Count(revoke.Query, "?"); got != want {
		t.Errorf("logout binds %d values for %d placeholders", got, want)
	}
}

func TestLogoutReportsAFailingWriteAsUnavailable(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))
	fix.batcher.err = errDB

	_, err := fix.svc.LogoutHandler(getenv(nil))(requestWith(t, key)).Get()
	wantFailure(t, err, apierr.Unavailable, CodeLogoutFailed)

	if !errors.Is(err, errDB) {
		t.Errorf("err = %v, want it to wrap the cause for the log", err)
	}
}

// TestLogoutOfASessionRevokedMeanwhileIsUnauthenticated: the write matches no
// row when another request revoked the session after this one authenticated, so
// logout answers as it does for any request without a session.
func TestLogoutOfASessionRevokedMeanwhileIsUnauthenticated(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))
	fix.batcher.unchanged = true

	_, err := fix.svc.LogoutHandler(getenv(nil))(requestWith(t, key)).Get()
	wantFailure(t, err, apierr.Unauthorized, CodeUnauthenticated)
}

func TestLogoutRefusesABatchThatMisreports(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))
	fix.batcher.results = []atomic.Result{}

	_, err := fix.svc.LogoutHandler(getenv(nil))(requestWith(t, key)).Get()
	wantFailure(t, err, apierr.Internal, CodeLogoutFailed)
}

func TestTheSessionRoutesAreOnlyMethodChecked(t *testing.T) {
	t.Parallel()

	// A handler never sees the method: httpapi.Serve answers other methods with
	// a 405 before it runs. This pins that the handlers do not check for
	// themselves, so the rule lives in one place.
	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))

	req := requestWith(t, key)
	req.Method = http.MethodDelete

	_, err := fix.svc.WhoAmIHandler(getenv(nil))(req).Get()
	if err != nil {
		t.Errorf("whoami refused a request on its method: %v", err)
	}
}
