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
	"github.com/susu-dot-dev/authsu/internal/config"
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

// TestWhoAmI checks the body of GET /api/session: every field comes from the
// verified principal, which is the stored row and not the token.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestWhoAmI(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.December, 1, 8, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		owner     string
		role      string
		expiresAt time.Time
		want      string
	}{
		{
			name: "administrator", owner: userID, role: roleAdmin, expiresAt: base,
			want: `{"userId":"` + userID + `","role":"admin","expiresAt":` + strconv.FormatInt(base.Unix(), 10) + `}`,
		},
		{
			name: "member", owner: otherUserID, role: roleMember, expiresAt: base,
			want: `{"userId":"` + otherUserID + `","role":"member","expiresAt":` + strconv.FormatInt(base.Unix(), 10) + `}`,
		},
		{
			// The expiry is in whole Unix seconds, truncated and not rounded.
			name: "sub-second expiry is truncated", owner: userID, role: roleAdmin,
			expiresAt: base.Add(999_999_999 * time.Nanosecond),
			want:      `{"userId":"` + userID + `","role":"admin","expiresAt":` + strconv.FormatInt(base.Unix(), 10) + `}`,
		},
		{
			// The stored row says when the session ends; the token's own exp
			// is a different time, so this fails if the handler read the wrong
			// one.
			name: "expiry of the stored row, not the token", owner: userID, role: roleAdmin,
			expiresAt: base.AddDate(0, 0, 3),
			want: `{"userId":"` + userID + `","role":"admin","expiresAt":` +
				strconv.FormatInt(base.AddDate(0, 0, 3).Unix(), 10) + `}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t)
			cookie, kid := rig.activeSession(tt.owner, tt.role, tt.expiresAt)

			rec := rig.serve(request{
				method: http.MethodGet, target: session.PathSession, cookies: []*http.Cookie{cookie}, contentType: "-",
			})

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

			wantKeyReads := []keyCall{{kid: kid, kind: auth.KindSession, now: rig.authNow}}
			if !slices.Equal(rig.keys.calls, wantKeyReads) {
				t.Errorf("key reads = %v, want %v", rig.keys.calls, wantKeyReads)
			}

			if len(rig.logged) != 0 {
				t.Errorf("logged %v, want nothing", rig.logged)
			}
		})
	}
}

// TestLogout checks a logout that takes effect.
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t)
			cookie, kid := rig.activeSession(userID, tt.role, rig.authNow.Add(time.Hour))

			rec := rig.serve(request{
				method: http.MethodPost, target: session.PathLogout, cookies: []*http.Cookie{cookie},
				contentType: tt.contentType, body: tt.body,
			})

			if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
				t.Errorf("response = %d %q, want 204 with no body", rec.Code, rec.Body.String())
			}

			if got := rec.Header().Values("Set-Cookie"); !slices.Equal(got, []string{clearedCookie}) {
				t.Errorf("Set-Cookie = %q, want %q", got, clearedCookie)
			}

			// The session is revoked as of the routes' clock, not the boundary's.
			wantRevokes := []revokeCall{{kid: kid, now: rig.logoutNow}}
			if len(rig.store.calls) != 1 || rig.store.calls[0] != wantRevokes[0] {
				t.Errorf("revocations = %v, want %v", rig.store.calls, wantRevokes)
			}

			if len(rig.logged) != 0 {
				t.Errorf("logged %v, want nothing", rig.logged)
			}
		})
	}
}

// TestLogoutOutcomes checks what the store can answer to the revocation, and
// that none of the failures clears the cookie or leaks a cause.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestLogoutOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		revoked     bool
		err         error
		wantStatus  int
		wantBody    string
		wantCode    string
		wantCause   error
		wantCookies bool
	}{
		{name: "revoked", revoked: true, err: nil, wantStatus: http.StatusNoContent, wantBody: "", wantCookies: true},
		{
			// Another request revoked the session between the boundary's read and
			// this write. The session is gone, which any request without one is
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rig := newRig(t)
			rig.store.revoked, rig.store.err = tt.revoked, tt.err
			cookie, _ := rig.activeSession(userID, roleMember, rig.authNow.Add(time.Hour))

			rec := rig.serve(request{method: http.MethodPost, target: session.PathLogout, cookies: []*http.Cookie{cookie}})

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
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
		})
	}
}

// TestLogoutTwice checks the replay: once the session is revoked, the same
// cookie is refused at the boundary, so the second logout is a plain 401 and
// does not reach the store.
func TestLogoutTwice(t *testing.T) {
	t.Parallel()

	rig := newRig(t)
	cookie, _ := rig.activeSession(userID, roleMember, rig.authNow.Add(time.Hour))
	send := func() int {
		return rig.serve(request{method: http.MethodPost, target: session.PathLogout, cookies: []*http.Cookie{cookie}}).Code
	}

	if got := send(); got != http.StatusNoContent {
		t.Fatalf("first logout = %d, want 204", got)
	}

	if got := send(); got != http.StatusUnauthorized {
		t.Errorf("second logout = %d, want 401", got)
	}

	if len(rig.store.calls) != 1 {
		t.Errorf("revocations = %d, want 1", len(rig.store.calls))
	}
}

// TestLogoutRevokesOnlyThePresentedSession checks that a logout ends the
// session presented, by that session's kid, whoever else has sessions.
func TestLogoutRevokesOnlyThePresentedSession(t *testing.T) {
	t.Parallel()

	rig := newRig(t)
	_, otherKid := rig.activeSession(otherUserID, roleAdmin, rig.authNow.Add(time.Hour))
	cookie, kid := rig.activeSession(userID, roleMember, rig.authNow.Add(time.Hour))

	rec := rig.serve(request{method: http.MethodPost, target: session.PathLogout, cookies: []*http.Cookie{cookie}})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}

	if len(rig.store.calls) != 1 || rig.store.calls[0].kid != kid || kid == otherKid {
		t.Errorf("revoked %v, want only %s", rig.store.calls, kid)
	}

	if _, stillActive := rig.keys.rows[otherKid]; !stillActive {
		t.Error("another session was ended")
	}
}

// TestRefusedRequests checks that a request the boundary refuses never reaches
// either route: the answer is the boundary's, nothing is written and no cookie
// is set or cleared.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRefusedRequests(t *testing.T) {
	t.Parallel()

	routes := []struct {
		name           string
		method, target string
	}{
		{name: "who am i", method: http.MethodGet, target: session.PathSession},
		{name: "logout", method: http.MethodPost, target: session.PathLogout},
	}

	situations := []struct {
		name       string
		arrange    func(rig *rig) []*http.Cookie
		wantStatus int
		wantBody   string
		wantCode   string
		// wantKeyReads is whether the key store is expected to be read.
		wantKeyReads bool
	}{
		{
			name:    "no cookie",
			arrange: func(*rig) []*http.Cookie { return nil }, wantStatus: http.StatusUnauthorized,
			wantBody: bodyUnauthenticated, wantCode: auth.CodeUnauthenticated, wantKeyReads: false,
		},
		{
			name: "empty cookie",
			arrange: func(*rig) []*http.Cookie {
				return []*http.Cookie{requestCookie(auth.CookieName, "")}
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated, wantCode: auth.CodeUnauthenticated,
			wantKeyReads: false,
		},
		{
			name: "a cookie that is not a token",
			arrange: func(*rig) []*http.Cookie {
				return []*http.Cookie{requestCookie(auth.CookieName, "not a token")}
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated, wantCode: auth.CodeUnauthenticated,
			wantKeyReads: false,
		},
		{
			name: "a token for no stored key",
			arrange: func(rig *rig) []*http.Cookie {
				cookie, kid := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
				delete(rig.keys.rows, kid)

				return []*http.Cookie{cookie}
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated, wantCode: auth.CodeUnauthenticated,
			wantKeyReads: true,
		},
		{
			name: "only a cookie of another name",
			arrange: func(rig *rig) []*http.Cookie {
				cookie, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))

				return []*http.Cookie{requestCookie("session", cookie.Value)}
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated, wantCode: auth.CodeUnauthenticated,
			wantKeyReads: false,
		},
		{
			// The token is signed for one account and its stored row belongs to
			// another: it is not who it says, whatever the signature.
			name: "the stored key belongs to another account",
			arrange: func(rig *rig) []*http.Cookie {
				cookie, kid := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
				row := rig.keys.rows[kid]
				row.UserID = otherUserID
				rig.keys.rows[kid] = row

				return []*http.Cookie{cookie}
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated, wantCode: auth.CodeUnauthenticated,
			wantKeyReads: true,
		},
		{
			name: "two session cookies",
			arrange: func(rig *rig) []*http.Cookie {
				first, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
				second, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))

				return []*http.Cookie{first, second}
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated, wantCode: auth.CodeUnauthenticated,
			wantKeyReads: false,
		},
		{
			name: "the key store fails",
			arrange: func(rig *rig) []*http.Cookie {
				cookie, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
				rig.keys.err = apierr.Wrap(errDB, apierr.Unavailable, store.CodeSessionVerifyFailed, unavailableText)

				return []*http.Cookie{cookie}
			},
			wantStatus: http.StatusServiceUnavailable, wantBody: bodyVerifyFailed, wantCode: store.CodeSessionVerifyFailed,
			wantKeyReads: true,
		},
		{
			name: "the deployment is not configured",
			arrange: func(rig *rig) []*http.Cookie {
				cookie, _ := rig.activeSession(userID, roleAdmin, rig.authNow.Add(time.Hour))
				delete(rig.env, config.SecretHMAC)

				return []*http.Cookie{cookie}
			},
			wantStatus: http.StatusServiceUnavailable, wantBody: bodyNotConfigured, wantCode: auth.CodeNotConfigured,
			wantKeyReads: false,
		},
	}

	for _, route := range routes {
		for _, sit := range situations {
			t.Run(route.name+"/"+sit.name, func(t *testing.T) {
				t.Parallel()

				rig := newRig(t)
				cookies := sit.arrange(rig)

				rec := rig.serve(request{method: route.method, target: route.target, cookies: cookies})

				if rec.Code != sit.wantStatus || rec.Body.String() != sit.wantBody {
					t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body.String(), sit.wantStatus, sit.wantBody)
				}

				wantNoCookies(t, rec.Header())

				if len(rig.store.calls) != 0 {
					t.Errorf("a refused request wrote: %v", rig.store.calls)
				}

				if (len(rig.keys.calls) != 0) != sit.wantKeyReads {
					t.Errorf("key reads = %v, want reads: %t", rig.keys.calls, sit.wantKeyReads)
				}

				if len(rig.logged) != 1 || rig.logged[0].Code != sit.wantCode {
					t.Errorf("logged = %v, want one %q", rig.logged, sit.wantCode)
				}
			})
		}
	}
}

// TestHTTPContract checks what the boundary decides before either route runs:
// the method, the content type of an unsafe method and the size of the body.
// None of them reads a key or writes.
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

			if len(rig.store.calls) != 0 || len(rig.keys.calls) != 0 {
				t.Errorf("a refused request touched the database: revokes %v, reads %v", rig.store.calls, rig.keys.calls)
			}
		})
	}
}
