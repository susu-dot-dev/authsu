package registration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/registration"
)

// TestRoutesDeclarations is the permission-confusion test: registration has no
// session to check, so both routes must be open (auth.None) and must not carry a
// requirement, and each carries the body limit its request can legitimately
// need.
func TestRoutesDeclarations(t *testing.T) {
	t.Parallel()

	want := []struct {
		name       string
		method     string
		path       string
		maxBody    int64
		credential auth.Credential
	}{
		{"begin", http.MethodPost, "/api/register/begin", 4 << 10, auth.None},
		{"finish", http.MethodPost, "/api/register/finish", 32 << 10, auth.None},
	}

	got := registration.Routes(newRig(t).deps())

	if len(got) != len(want) {
		t.Fatalf("Routes returned %d routes, want %d", len(got), len(want))
	}

	for i, tc := range want {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			route := got[i]

			if route.Method != tc.method || route.Path != tc.path {
				t.Errorf("route = %s %s, want %s %s", route.Method, route.Path, tc.method, tc.path)
			}

			if route.MaxBody != tc.maxBody {
				t.Errorf("MaxBody = %d, want %d", route.MaxBody, tc.maxBody)
			}

			if route.Credential != tc.credential {
				t.Errorf("Credential = %d, want %d", route.Credential, tc.credential)
			}

			if route.Access != (auth.Access{}) {
				t.Error("a route with no credential declares an access")
			}

			if route.Handle == nil {
				t.Error("Handle is nil")
			}
		})
	}
}

// TestRoutesPanicOnMissingDependency: the wiring is fixed in code, so a missing
// dependency is found by the first test or start, and never by a request.
func TestRoutesPanicOnMissingDependency(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		remove func(*registration.Deps)
	}{
		{"Store", func(d *registration.Deps) { d.Store = nil }},
		{"Now", func(d *registration.Deps) { d.Now = nil }},
		{"Entropy", func(d *registration.Deps) { d.Entropy = nil }},
		{"NewID", func(d *registration.Deps) { d.NewID = nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps := newRig(t).deps()
			tc.remove(&deps)

			defer func() {
				recovered := recover()

				message, _ := recovered.(string)
				if !strings.Contains(message, "Deps."+tc.name) {
					t.Errorf("panic = %v, want one naming Deps.%s", recovered, tc.name)
				}
			}()

			registration.Routes(deps)

			t.Error("Routes did not panic")
		})
	}
}

// TestRoutesAreServedByTheBoundary pins what the boundary does for these
// routes before the handlers run: the method, the content type and the body
// limit, each as its own answer.
func TestRoutesAreServedByTheBoundary(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		req     request
		status  int
		body    string
		allow   string
		logCode string
	}{
		{
			name:    "begin refuses GET",
			req:     request{method: http.MethodGet, target: registration.PathBegin},
			status:  http.StatusMethodNotAllowed,
			body:    errorBody("method_not_allowed", "method not allowed"),
			allow:   "POST",
			logCode: "method_not_allowed",
		},
		{
			name:    "finish refuses PUT",
			req:     request{method: http.MethodPut, target: registration.PathFinish, body: "{}"},
			status:  http.StatusMethodNotAllowed,
			body:    errorBody("method_not_allowed", "method not allowed"),
			allow:   "POST",
			logCode: "method_not_allowed",
		},
		{
			name:    "begin needs a JSON content type",
			req:     request{target: registration.PathBegin, body: beginJSON(testCode, testName), contentType: "text/plain"},
			status:  http.StatusUnsupportedMediaType,
			body:    errorBody("unsupported_media_type", "request Content-Type must be application/json"),
			logCode: "unsupported_media_type",
		},
		{
			name:    "finish needs a content type",
			req:     request{target: registration.PathFinish, body: "{}", contentType: "-"},
			status:  http.StatusUnsupportedMediaType,
			body:    errorBody("unsupported_media_type", "request Content-Type must be application/json"),
			logCode: "unsupported_media_type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.serve(tc.req)

			wantFailure(t, r, rec, tc.status, tc.body, tc.logCode)

			if got := rec.Header().Get("Allow"); got != tc.allow {
				t.Errorf("Allow = %q, want %q", got, tc.allow)
			}

			if len(r.store.redeemed)+len(r.store.created) != 0 {
				t.Error("the store was used for a request the boundary refused")
			}
		})
	}
}

// TestSessionCookiesAreIgnored: an open route never reads the cookie or the key
// store, so a request that carries a bad, or even a good-looking, session cookie
// is answered as one without. (noKeys fails the test if the store is read.)
func TestSessionCookiesAreIgnored(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	rec := r.serve(request{
		target: registration.PathBegin, body: beginJSON(testCode, testName),
		cookies: []*http.Cookie{
			requestCookie(auth.CookieName, "not.a.token"),
			requestCookie(auth.CookieName, "another"),
		},
	})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d (%s), want 200", rec.Code, rec.Body)
	}
}
