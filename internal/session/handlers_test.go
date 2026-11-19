package session_test

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/session"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// clearedCookie is the exact Set-Cookie a logout sends. The attributes are the
// same as the cookie it replaces, because a browser only replaces a cookie with
// the same name, path and domain; and it carries no Domain, which the __Host-
// prefix forbids.
// formType is a content type the JSON routes refuse.
const formType = "application/x-www-form-urlencoded"

const clearedCookie = "__Host-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"

// wantNoCookies fails when the response sets a cookie.
func wantNoCookies(t *testing.T, headers http.Header) {
	t.Helper()

	if got := headers.Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie = %q, want none", got)
	}
}

// present is one way a caller presents a secret: a session cookie or an API key
// as a bearer token.
type present struct {
	name string
	// key presents an API key; otherwise a session is presented.
	key bool
}

// presenters are the two kinds of credential the session routes accept.
func presenters() []present {
	return []present{
		{name: "session", key: false},
		{name: "API key", key: true},
	}
}

// secretFor stores an active secret of the kind p presents and returns the
// request that presents it (a cookie or a bearer header), the token and its id.
func (r *rig) secretFor(p present, owner, role string, expiresAt time.Time) (request, string, string) {
	r.t.Helper()

	if p.key {
		token, id := r.liveKey(owner, role, "", expiresAt)

		return request{authorization: []string{bearer(token)}}, token, id
	}

	cookie, id := r.activeSession(owner, role, expiresAt)

	return request{cookies: []*http.Cookie{cookie}}, cookie.Value, id
}

// kindOf is the kind of secret p presents.
func (p present) kindOf() string {
	if p.key {
		return auth.KindAPIKey
	}

	return auth.KindSession
}

// TestWhoAmI checks the body of GET /api/session: every field comes from the
// verified principal, which is the stored row and not the token, and it is the
// same shape whether a session or an API key is presented.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestWhoAmI(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.December, 1, 8, 0, 0, 0, time.UTC)

	want := func(owner, role string, expires time.Time) string {
		return `{"userId":"` + owner + `","role":"` + role + `","expiresAt":` + strconv.FormatInt(expires.Unix(), 10) + `}`
	}

	tests := []struct {
		name      string
		owner     string
		role      string
		expiresAt time.Time
		want      string
	}{
		{name: "administrator", owner: userID, role: roleAdmin, expiresAt: base, want: want(userID, "admin", base)},
		{name: "member", owner: otherUserID, role: roleMember, expiresAt: base, want: want(otherUserID, "member", base)},
		{
			// The expiry is in whole Unix seconds, truncated and not rounded.
			name: "sub-second expiry is truncated", owner: userID, role: roleAdmin,
			expiresAt: base.Add(999_999_999 * time.Nanosecond), want: want(userID, "admin", base),
		},
		{
			// The stored row says when the secret ends, whatever it was issued
			// for, so this fails if the handler read anything else.
			name: "expiry of the stored row", owner: userID, role: roleAdmin,
			expiresAt: base.AddDate(0, 0, 3), want: want(userID, "admin", base.AddDate(0, 0, 3)),
		},
	}

	for _, p := range presenters() {
		for _, tt := range tests {
			t.Run(p.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				rig := newRig(t)
				req, token, _ := rig.secretFor(p, tt.owner, tt.role, tt.expiresAt)
				req.method, req.target, req.contentType = http.MethodGet, session.PathSession, "-"

				rec := rig.serve(req)

				if rec.Code != http.StatusOK || rec.Body.String() != tt.want+"\n" {
					t.Errorf("response = %d %q, want 200 %q", rec.Code, rec.Body.String(), tt.want)
				}

				if got := rec.Header().Get("Content-Type"); got != jsonType {
					t.Errorf("Content-Type = %q, want %q", got, jsonType)
				}

				wantNoCookies(t, rec.Header())

				if len(rig.store.calls) != 0 {
					t.Errorf("a read wrote: %v", rig.store.calls)
				}

				wantReads := []resolveCall{{kind: p.kindOf(), hash: tokenHash(token), now: rig.authNow}}
				if !slices.Equal(rig.creds.calls, wantReads) {
					t.Errorf("credential reads = %v, want %v", rig.creds.calls, wantReads)
				}

				if len(rig.logged) != 0 {
					t.Errorf("logged %v, want nothing", rig.logged)
				}
			})
		}
	}
}

// TestLogout checks a logout that takes effect, for a session and for an API
// key: either ends the secret it presents, and the cookie is cleared either way.
func TestLogout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		role string
		// contentType is sent as it is; "" is application/json.
		contentType string
		body        string
	}{
		{name: "administrator", role: roleAdmin, contentType: "", body: ""},
		{name: "member", role: roleMember, contentType: "", body: ""},
		{name: "a body is ignored", role: roleMember, contentType: "", body: `{"anything":true}`},
		{name: "json with a charset", role: roleMember, contentType: "application/json; charset=utf-8", body: ""},
	}

	for _, p := range presenters() {
		for _, tt := range tests {
			t.Run(p.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				rig := newRig(t)
				req, _, id := rig.secretFor(p, userID, tt.role, rig.authNow.Add(time.Hour))
				req.method, req.target, req.contentType, req.body = http.MethodPost, session.PathLogout, tt.contentType, tt.body

				rec := rig.serve(req)

				if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
					t.Errorf("response = %d %q, want 204 with no body", rec.Code, rec.Body.String())
				}

				if got := rec.Header().Values("Set-Cookie"); !slices.Equal(got, []string{clearedCookie}) {
					t.Errorf("Set-Cookie = %q, want %q", got, clearedCookie)
				}

				// The secret is revoked as of the routes' clock, not the boundary's,
				// by its own id and for the user who owns it: the write binds the
				// owner too.
				wantRevokes := []revokeCall{{userID: userID, id: id, now: rig.logoutNow}}
				if !slices.Equal(rig.store.calls, wantRevokes) {
					t.Errorf("revocations = %v, want %v", rig.store.calls, wantRevokes)
				}

				if len(rig.logged) != 0 {
					t.Errorf("logged %v, want nothing", rig.logged)
				}
			})
		}
	}
}

// TestLogoutByAnAgentsKeyEndsThatKey: a key that belongs to an agent speaks for
// the agent's owner, and logging out with it revokes that key, for that user.
func TestLogoutByAnAgentsKeyEndsThatKey(t *testing.T) {
	t.Parallel()

	rig := newRig(t)
	token, id := rig.liveKey(userID, roleMember, "00000000-0000-7000-8000-0000000000a1", rig.authNow.Add(time.Hour))

	rec := rig.serve(request{
		method: http.MethodPost, target: session.PathLogout, authorization: []string{bearer(token)},
	})

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d (%s), want 204", rec.Code, rec.Body)
	}

	wantRevokes := []revokeCall{{userID: userID, id: id, now: rig.logoutNow}}
	if !slices.Equal(rig.store.calls, wantRevokes) {
		t.Errorf("revocations = %v, want %v", rig.store.calls, wantRevokes)
	}
}

// logoutOutcome is one case of TestLogoutOutcomes: what the store answers to
// the revocation and what the client must then be told.
type logoutOutcome struct {
	name        string
	revoked     bool
	err         error
	wantStatus  int
	wantBody    string
	wantCode    string
	wantCause   error
	wantCookies bool
}

// checkLogoutOutcome logs out presenting a secret of the kind p does, against a
// store that answers as tt says.
func checkLogoutOutcome(t *testing.T, p present, tt logoutOutcome) {
	t.Helper()

	rig := newRig(t)
	rig.store.revoked, rig.store.err = tt.revoked, tt.err
	req, _, id := rig.secretFor(p, userID, roleMember, rig.authNow.Add(time.Hour))
	req.method, req.target = http.MethodPost, session.PathLogout

	rec := rig.serve(req)

	if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
		t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
	}

	// Whatever the outcome, the write was attempted once, for the
	// presented secret.
	wantRevokes := []revokeCall{{userID: userID, id: id, now: rig.logoutNow}}
	if !slices.Equal(rig.store.calls, wantRevokes) {
		t.Errorf("revocations = %v, want %v", rig.store.calls, wantRevokes)
	}

	if tt.wantCookies {
		if got := rec.Header().Values("Set-Cookie"); !slices.Equal(got, []string{clearedCookie}) {
			t.Errorf("Set-Cookie = %q, want %q", got, clearedCookie)
		}

		return
	}

	wantNoCookies(t, rec.Header())

	if len(rig.logged) != 1 {
		t.Fatalf("logged %d errors, want 1: %v", len(rig.logged), rig.logged)
	}

	if rig.logged[0].Code != tt.wantCode {
		t.Errorf("logged code = %q, want %q", rig.logged[0].Code, tt.wantCode)
	}

	if tt.wantCause != nil && !strings.Contains(rig.logged[0].Error(), tt.wantCause.Error()) {
		t.Errorf("logged error %q does not carry the cause %q", rig.logged[0], tt.wantCause)
	}
}

// TestLogoutOutcomes checks what the store can answer to the revocation, for a
// session and for an API key, and that none of the failures clears the cookie or
// leaks a cause.
func TestLogoutOutcomes(t *testing.T) {
	t.Parallel()

	tests := []logoutOutcome{
		{name: "revoked", revoked: true, err: nil, wantStatus: http.StatusNoContent, wantBody: "", wantCookies: true},
		{
			// Another request revoked the secret between the boundary's read and
			// this write. The secret is gone, which any request without one is
			// told.
			name: "revoked by a concurrent request", revoked: false, err: nil,
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated, wantCode: auth.CodeUnauthenticated,
		},
		{
			name: "database failure", revoked: false,
			err:        apierr.Wrap(errDB, apierr.Unavailable, store.CodeSessionLogoutFailed, unavailableText),
			wantStatus: http.StatusServiceUnavailable, wantBody: bodyLogoutFailed,
			wantCode: store.CodeSessionLogoutFailed, wantCause: errDB,
		},
		{
			name: "malformed result", revoked: false,
			err:        apierr.Wrap(errDB, apierr.Internal, store.CodeSessionLogoutRejected, "internal error"),
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantCode: store.CodeSessionLogoutRejected, wantCause: errDB,
		},
		{
			// The store classifies its own failures; one that did not is still
			// never shown to the client.
			name: "unclassified failure", revoked: false, err: errPlain,
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantCode: "internal", wantCause: errPlain,
		},
	}

	for _, p := range presenters() {
		for _, tt := range tests {
			t.Run(p.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				checkLogoutOutcome(t, p, tt)
			})
		}
	}
}

// TestLogoutRaceIsIndistinguishable: a logout that lost a race with another
// revocation is told exactly what a request without a secret is told, for a
// session and for a key.
func TestLogoutRaceIsIndistinguishable(t *testing.T) {
	t.Parallel()

	for _, p := range presenters() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t)
			rig.store.revoked = false
			req, _, _ := rig.secretFor(p, userID, roleMember, rig.authNow.Add(time.Hour))
			req.method, req.target = http.MethodPost, session.PathLogout

			raced := rig.serve(req)
			none := rig.serve(request{method: http.MethodPost, target: session.PathLogout})

			if raced.Code != http.StatusUnauthorized || raced.Body.String() != none.Body.String() ||
				raced.Header().Get("Content-Type") != none.Header().Get("Content-Type") ||
				raced.Header().Get("Cache-Control") != none.Header().Get("Cache-Control") {
				t.Errorf("raced = %d %q, no secret = %d %q", raced.Code, raced.Body, none.Code, none.Body)
			}

			wantNoCookies(t, raced.Header())
		})
	}
}

// TestLogoutTwice checks the replay: once the secret is revoked, the same one
// is refused at the boundary, so the second logout is a plain 401 and does not
// reach the store.
func TestLogoutTwice(t *testing.T) {
	t.Parallel()

	for _, p := range presenters() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t)
			req, _, _ := rig.secretFor(p, userID, roleMember, rig.authNow.Add(time.Hour))
			req.method, req.target = http.MethodPost, session.PathLogout

			if got := rig.serve(req).Code; got != http.StatusNoContent {
				t.Fatalf("first logout = %d, want 204", got)
			}

			if got := rig.serve(req).Code; got != http.StatusUnauthorized {
				t.Errorf("second logout = %d, want 401", got)
			}

			if len(rig.store.calls) != 1 {
				t.Errorf("revocations = %d, want 1", len(rig.store.calls))
			}
		})
	}
}

// TestLogoutRevokesOnlyThePresentedSecret checks that a logout ends the secret
// presented, by its id, whoever else has secrets.
func TestLogoutRevokesOnlyThePresentedSecret(t *testing.T) {
	t.Parallel()

	for _, p := range presenters() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t)
			other, _ := rig.activeSession(otherUserID, roleAdmin, rig.authNow.Add(time.Hour))
			otherKey, otherKeyID := rig.liveKey(userID, roleMember, "", rig.authNow.Add(time.Hour))
			req, _, id := rig.secretFor(p, userID, roleMember, rig.authNow.Add(time.Hour))
			req.method, req.target = http.MethodPost, session.PathLogout

			if rec := rig.serve(req); rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", rec.Code)
			}

			if len(rig.store.calls) != 1 || rig.store.calls[0].id != id {
				t.Errorf("revoked %v, want only %s", rig.store.calls, id)
			}

			if _, stillActive := rig.creds.rows[tokenHash(other.Value)]; !stillActive {
				t.Error("another user's session was ended")
			}

			if _, stillActive := rig.creds.rows[tokenHash(otherKey)]; !stillActive && otherKeyID != id {
				t.Error("another key was ended")
			}
		})
	}
}

// refusedRoutes are the routes that need a credential.
func refusedRoutes() []struct {
	name           string
	method, target string
} {
	return []struct {
		name           string
		method, target string
	}{
		{name: "who am i", method: http.MethodGet, target: session.PathSession},
		{name: "logout", method: http.MethodPost, target: session.PathLogout},
	}
}

// refusal is one request the boundary refuses.
type refusal struct {
	name       string
	arrange    func(rig *rig) request
	wantStatus int
	wantBody   string
	wantCode   string
	// wantReads are the kinds of credential resolved in the store: none when the
	// request was refused before the store was read.
	wantReads []string
}

// refusals are the situations in which neither route runs.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func refusals() []refusal {
	unauthenticated := func(name string, wantReads []string, arrange func(rig *rig) request) refusal {
		return refusal{
			name: name, arrange: arrange, wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
			wantCode: auth.CodeUnauthenticated, wantReads: wantReads,
		}
	}
	valid := func(rig *rig) (*http.Cookie, string) {
		cookie, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
		token, _ := rig.liveKey(userID, roleAdmin, "", rig.authNow.Add(time.Hour))

		return cookie, token
	}

	return []refusal{
		unauthenticated("no credential", nil, func(*rig) request { return request{} }),
		unauthenticated("empty cookie", nil, func(*rig) request {
			return request{cookies: []*http.Cookie{requestCookie(auth.CookieName, "")}}
		}),
		unauthenticated("a cookie that is not a token", nil, func(*rig) request {
			return request{cookies: []*http.Cookie{requestCookie(auth.CookieName, "not a token")}}
		}),
		unauthenticated("a session token for no stored session", []string{auth.KindSession}, func(rig *rig) request {
			cookie, id := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
			rig.creds.forget(id)

			return request{cookies: []*http.Cookie{cookie}}
		}),
		unauthenticated("only a cookie of another name", nil, func(rig *rig) request {
			cookie, _ := valid(rig)

			return request{cookies: []*http.Cookie{requestCookie("session", cookie.Value)}}
		}),
		unauthenticated("two session cookies", nil, func(rig *rig) request {
			first, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
			second, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))

			return request{cookies: []*http.Cookie{first, second}}
		}),
		unauthenticated("an API key in the cookie", nil, func(rig *rig) request {
			_, token := valid(rig)

			return request{cookies: []*http.Cookie{requestCookie(auth.CookieName, token)}}
		}),
		unauthenticated("a session token as a bearer token", nil, func(rig *rig) request {
			cookie, _ := valid(rig)

			return request{authorization: []string{bearer(cookie.Value)}}
		}),
		unauthenticated("a bearer token that is not a token", nil, func(*rig) request {
			return request{authorization: []string{bearer("not a token")}}
		}),
		unauthenticated("an Authorization header that is not Bearer", nil, func(rig *rig) request {
			_, token := valid(rig)

			return request{authorization: []string{"Basic " + token}}
		}),
		unauthenticated("two Authorization headers", nil, func(rig *rig) request {
			_, token := valid(rig)

			return request{authorization: []string{bearer(token), bearer(token)}}
		}),
		unauthenticated("a cookie and a bearer token", nil, func(rig *rig) request {
			cookie, token := valid(rig)

			return request{cookies: []*http.Cookie{cookie}, authorization: []string{bearer(token)}}
		}),
		unauthenticated("an API key that is not stored", []string{auth.KindAPIKey}, func(rig *rig) request {
			token, id := rig.liveKey(userID, roleAdmin, "", rig.authNow.Add(time.Hour))
			rig.creds.forget(id)

			return request{authorization: []string{bearer(token)}}
		}),
		{
			name: "the credential store fails",
			arrange: func(rig *rig) request {
				cookie, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
				rig.creds.err = apierr.Wrap(errDB, apierr.Unavailable, store.CodeSessionVerifyFailed, unavailableText)

				return request{cookies: []*http.Cookie{cookie}}
			},
			wantStatus: http.StatusServiceUnavailable, wantBody: bodyVerifyFailed, wantCode: store.CodeSessionVerifyFailed,
			wantReads: []string{auth.KindSession},
		},
		{
			name: "the credential store fails for an API key",
			arrange: func(rig *rig) request {
				token, _ := rig.liveKey(userID, roleAdmin, "", rig.authNow.Add(time.Hour))
				rig.creds.err = apierr.Wrap(errDB, apierr.Unavailable, store.CodeSessionVerifyFailed, unavailableText)

				return request{authorization: []string{bearer(token)}}
			},
			wantStatus: http.StatusServiceUnavailable, wantBody: bodyVerifyFailed, wantCode: store.CodeSessionVerifyFailed,
			wantReads: []string{auth.KindAPIKey},
		},
	}
}

// TestRefusedRequests checks that a request the boundary refuses never reaches
// either route: the answer is the boundary's, nothing is written and no cookie
// is set or cleared.
func TestRefusedRequests(t *testing.T) {
	t.Parallel()

	for _, route := range refusedRoutes() {
		for _, sit := range refusals() {
			t.Run(route.name+"/"+sit.name, func(t *testing.T) {
				t.Parallel()

				rig := newRig(t)
				req := sit.arrange(rig)
				req.method, req.target = route.method, route.target

				rec := rig.serve(req)

				if rec.Code != sit.wantStatus || rec.Body.String() != sit.wantBody {
					t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), sit.wantStatus, sit.wantBody)
				}

				wantNoCookies(t, rec.Header())

				if len(rig.store.calls) != 0 {
					t.Errorf("a refused request wrote: %v", rig.store.calls)
				}

				reads := make([]string, 0, len(rig.creds.calls))
				for _, call := range rig.creds.calls {
					reads = append(reads, call.kind)
				}

				if !slices.Equal(reads, sit.wantReads) {
					t.Errorf("credential reads = %v, want %v", reads, sit.wantReads)
				}

				if len(rig.logged) != 1 || rig.logged[0].Code != sit.wantCode {
					t.Errorf("logged = %v, want one %q", rig.logged, sit.wantCode)
				}
			})
		}
	}
}

// TestUnconfiguredDeploymentStillServes: resolving a secret needs no deployment
// configuration (a token carries nothing to check), so neither route is
// affected by a deployment whose settings are missing.
func TestUnconfiguredDeploymentStillServes(t *testing.T) {
	t.Parallel()

	rig := newRig(t)
	cookie, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))

	rec := rig.serve(request{
		method: http.MethodGet, target: session.PathSession, cookies: []*http.Cookie{cookie}, contentType: "-",
	})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d (%s), want 200", rec.Code, rec.Body)
	}
}

// TestHTTPContract checks what the boundary decides before either route runs:
// the method, the content type of an unsafe method and the size of the body.
// None of them reads a credential or writes.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestHTTPContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		req        request
		wantStatus int
		wantAllow  string
	}{
		{
			name:       "GET on logout",
			req:        request{method: http.MethodGet, target: session.PathLogout},
			wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodPost,
		},
		{
			name:       "POST on session",
			req:        request{method: http.MethodPost, target: session.PathSession},
			wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodGet,
		},
		{
			name:       "DELETE on logout",
			req:        request{method: http.MethodDelete, target: session.PathLogout},
			wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodPost,
		},
		{
			name:       "logout without a content type",
			req:        request{method: http.MethodPost, target: session.PathLogout, contentType: "-"},
			wantStatus: http.StatusUnsupportedMediaType, wantAllow: "",
		},
		{
			name:       "logout as a form",
			req:        request{method: http.MethodPost, target: session.PathLogout, contentType: formType},
			wantStatus: http.StatusUnsupportedMediaType, wantAllow: "",
		},
		{
			name: "logout with a body over the limit",
			req: request{
				method: http.MethodPost, target: session.PathLogout,
				body: strings.Repeat("x", httpapi.DefaultMaxBody+1),
			},
			wantStatus: http.StatusRequestEntityTooLarge, wantAllow: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t)
			cookie, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
			tt.req.cookies = []*http.Cookie{cookie}

			rec := rig.serve(tt.req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tt.wantStatus, rec.Body.String())
			}

			if got := rec.Header().Get("Allow"); got != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tt.wantAllow)
			}

			wantNoCookies(t, rec.Header())

			if len(rig.store.calls) != 0 || len(rig.creds.calls) != 0 {
				t.Errorf("a refused request touched the database: revokes %v, reads %v", rig.store.calls, rig.creds.calls)
			}
		})
	}
}
