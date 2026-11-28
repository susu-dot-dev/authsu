//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// errCheck is what D1 says when a CHECK constraint refuses a statement.
var errCheck = errors.New("D1_ERROR: CHECK constraint failed: SQLITE_CONSTRAINT_CHECK")

// uuidV7 is the canonical text of a version 7 UUID.
var uuidV7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const pathFirstRun = "/api/first-run"

// TestSessionRowSeam is the seam between what D1 hands the Worker and what the
// Go code can trust. The real auth boundary, the real store and the real
// route run over a fake database that answers with the session row exactly as
// D1 produces values (int64 for integers, string for text), and then with
// values the JS side could produce but must never be believed: float64
// integers, NULL in a NOT NULL column, a blob where text belongs, a row of the
// wrong width. Every one of those is a defect (500, a bare "internal" to the
// client, the real code in the log), never a successful sign-in and never a
// sign-out.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestSessionRowSeam(t *testing.T) {
	t.Parallel()

	rejected := []string{store.CodeSessionVerifyRejected}

	tests := map[string]struct {
		// row builds the database's answer from the session.
		row func(s session) step
		// wantStatus is the response status; wantBody is a fragment of the body,
		// or the whole of an error body.
		wantStatus int
		wantBody   string
		wantLogged []string
	}{
		"member, as D1 produces it": {
			row:        func(s session) step { return s.activeSessionStep(roleMember) },
			wantStatus: http.StatusOK, wantBody: `"role":"member"`,
		},
		"admin, as D1 produces it": {
			row:        func(s session) step { return s.activeSessionStep(roleAdmin) },
			wantStatus: http.StatusOK, wantBody: `"role":"admin"`,
		},
		"expires_at as float64": {
			row: func(s session) step {
				expires := float64(s.issued.ExpiresAt.Unix())

				return s.activeSessionRow([]any{s.issued.ID, s.userID, roleMember, expires, ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"expires_at as text": {
			row: func(s session) step {
				return s.activeSessionRow([]any{s.issued.ID, s.userID, roleMember, "1900000000", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"expires_at NULL": {
			row: func(s session) step {
				return s.activeSessionRow([]any{s.issued.ID, s.userID, roleMember, nil, ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"role NULL": {
			row: func(s session) step {
				return s.activeSessionRow([]any{s.issued.ID, s.userID, nil, s.issued.ExpiresAt.Unix(), ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"role as a blob": {
			row: func(s session) step {
				return s.activeSessionRow([]any{
					s.issued.ID, s.userID, []byte(roleAdmin), s.issued.ExpiresAt.Unix(), "",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"id as a blob": {
			row: func(s session) step {
				return s.activeSessionRow([]any{
					[]byte(s.issued.ID), s.userID, roleMember, s.issued.ExpiresAt.Unix(), "",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"user_id as an integer": {
			row: func(s session) step {
				return s.activeSessionRow([]any{s.issued.ID, int64(7), roleMember, s.issued.ExpiresAt.Unix(), ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"a column short": {
			row: func(s session) step {
				return s.activeSessionRow([]any{s.issued.ID, s.userID, roleMember})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"a column too many": {
			row: func(s session) step {
				return s.activeSessionRow([]any{
					s.issued.ID, s.userID, roleMember, s.issued.ExpiresAt.Unix(), "", "extra",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"no row: not active": {
			row: func(session) step {
				return step{match: readSession, results: rows(), err: nil}
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
			wantLogged: []string{auth.CodeUnauthenticated},
		},
		"two rows": {
			row: func(s session) step {
				good := []any{s.issued.ID, s.userID, roleMember, s.issued.ExpiresAt.Unix()}

				return step{match: readSession, results: rows(good, good), err: nil}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"no result at all": {
			row: func(session) step {
				return step{match: readSession, results: nil, err: nil}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"database down": {
			row: func(session) step {
				return step{match: readSession, results: nil, err: errDB}
			},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   `{"error":{"code":"session_verify_failed","message":"sessions are temporarily unavailable"}}` + "\n",
			wantLogged: []string{store.CodeSessionVerifyFailed},
		},
		"schema rule refused the read": {
			row: func(session) step {
				return step{match: readSession, results: nil, err: store.Classify(errCheck)}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, adminID)
			h := newHarness(t, fullEnv(), tt.row(signedIn))

			rec := h.do(request{method: http.MethodGet, path: "/api/session", cookies: []*http.Cookie{signedIn.cookie}})

			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("= %d %s, want %d containing %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if got := h.exec.callCount(); got != 1 {
				t.Errorf("Exec calls = %d, want the one session lookup", got)
			}

			if got := h.loggedCodes(); !slices.Equal(got, tt.wantLogged) {
				t.Errorf("logged codes = %v, want %v", got, tt.wantLogged)
			}

			if strings.Contains(rec.Body.String(), errDB.Error()) {
				t.Errorf("body leaks the cause: %s", rec.Body)
			}

			if rec.Code == http.StatusOK {
				assertWhoAmI(t, rec.Body.Bytes(), signedIn)
			}
		})
	}
}

// TestAPIKeyRowSeam is TestSessionRowSeam for the lookup of an API key: the row
// as D1 produces it is accepted, and every value it could produce but must
// never be believed is a defect. The route is the agent list, which the key's
// scope allows. (A stored scope that is damaged is not a defect: it reads as
// empty and grants nothing, which the auth package pins.)
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestAPIKeyRowSeam(t *testing.T) {
	t.Parallel()

	const (
		agentScopes = `["default:agent"]`
		keyScope    = `["default:agent"]`
	)

	rejected := []string{store.CodeSessionVerifyRejected}

	tests := map[string]struct {
		row        func(k apiKey) step
		wantStatus int
		wantBody   string
		wantLogged []string
		// listed is whether the agent list is read after the lookup.
		listed bool
	}{
		"a user's own key, as D1 produces it": {
			row:        func(k apiKey) step { return k.keyStep(memberID, roleMember, "", "", keyScope) },
			wantStatus: http.StatusOK, wantBody: `"agents":[]`, listed: true,
		},
		"an agent's key, as D1 produces it": {
			row:        func(k apiKey) step { return k.keyStep(memberID, roleMember, agentRowID, agentScopes, keyScope) },
			wantStatus: http.StatusOK, wantBody: `"agents":[]`, listed: true,
		},
		"expires_at as float64": {
			row: func(k apiKey) step {
				return k.keyRow([]any{
					k.issued.ID, memberID, roleMember, float64(k.issued.ExpiresAt.Unix()), "", "", keyScope, "", "",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"role NULL": {
			row: func(k apiKey) step {
				return k.keyRow([]any{k.issued.ID, memberID, nil, k.issued.ExpiresAt.Unix(), "", "", keyScope, "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"id as a blob": {
			row: func(k apiKey) step {
				return k.keyRow([]any{
					[]byte(k.issued.ID), memberID, roleMember, k.issued.ExpiresAt.Unix(), "", "", keyScope, "", "",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"agent id NULL": {
			row: func(k apiKey) step {
				return k.keyRow([]any{
					k.issued.ID, memberID, roleMember, k.issued.ExpiresAt.Unix(), nil, "", keyScope, "", "",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"agent scopes NULL": {
			row: func(k apiKey) step {
				return k.keyRow([]any{
					k.issued.ID, memberID, roleMember, k.issued.ExpiresAt.Unix(), "", nil, keyScope, "", "",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"agent scopes as a blob": {
			row: func(k apiKey) step {
				return k.keyRow([]any{
					k.issued.ID, memberID, roleMember, k.issued.ExpiresAt.Unix(), "", []byte("[]"), keyScope, "", "",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"scope NULL": {
			row: func(k apiKey) step {
				return k.keyRow([]any{
					k.issued.ID, memberID, roleMember, k.issued.ExpiresAt.Unix(), "", "", nil, "", "",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"a column short": {
			row: func(k apiKey) step {
				return k.keyRow([]any{k.issued.ID, memberID, roleMember, k.issued.ExpiresAt.Unix(), "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"a column too many": {
			row: func(k apiKey) step {
				return k.keyRow([]any{
					k.issued.ID, memberID, roleMember, k.issued.ExpiresAt.Unix(), "", "", keyScope, "", "", "extra",
				})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"no row: not active": {
			row:        func(apiKey) step { return step{match: readAPIKey, results: rows(), err: nil} },
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
			wantLogged: []string{auth.CodeUnauthenticated},
		},
		"two rows": {
			row: func(k apiKey) step {
				good := []any{k.issued.ID, memberID, roleMember, k.issued.ExpiresAt.Unix(), "", "", keyScope, "", ""}

				return step{match: readAPIKey, results: rows(good, good), err: nil}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal, wantLogged: rejected,
		},
		"database down": {
			row:        func(apiKey) step { return step{match: readAPIKey, results: nil, err: errDB} },
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   `{"error":{"code":"session_verify_failed","message":"sessions are temporarily unavailable"}}` + "\n",
			wantLogged: []string{store.CodeSessionVerifyFailed},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key := newAPIKey(t)
			script := []step{tt.row(key)}

			if tt.listed {
				script = append(script, step{match: "FROM agents", results: rows(), err: nil})
			}

			h := newHarness(t, fullEnv(), script...)

			rec := h.do(request{method: http.MethodGet, path: "/api/agent", headers: key.headers})

			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("= %d %s, want %d containing %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if got := h.exec.callCount(); got != len(script) {
				t.Errorf("Exec calls = %d, want %d", got, len(script))
			}

			if got := h.loggedCodes(); !slices.Equal(got, tt.wantLogged) {
				t.Errorf("logged codes = %v, want %v", got, tt.wantLogged)
			}

			if strings.Contains(rec.Body.String(), errDB.Error()) {
				t.Errorf("body leaks the cause: %s", rec.Body)
			}
		})
	}
}

// assertWhoAmI checks the body of GET /api/session against the session.
func assertWhoAmI(t *testing.T, body []byte, signedIn session) {
	t.Helper()

	var got struct {
		UserID    string `json:"userId"`
		Role      string `json:"role"`
		ExpiresAt int64  `json:"expiresAt"`
	}

	err := json.Unmarshal(body, &got)
	if err != nil {
		t.Fatalf("body %q: %v", body, err)
	}

	if got.UserID != signedIn.userID || got.ExpiresAt != signedIn.issued.ExpiresAt.Unix() {
		t.Errorf("body = %+v, want user %s expiring %d", got, signedIn.userID, signedIn.issued.ExpiresAt.Unix())
	}
}

// TestSessionReadIsScoped: the lookup the boundary makes is by the hash of the
// token the cookie carries (the whole token, prefix included) and the session
// kind, so an API key's secret is not found as a session, and the time is now.
func TestSessionReadIsScoped(t *testing.T) {
	t.Parallel()

	signedIn := newSession(t, memberID)
	h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleMember))

	rec := h.do(request{method: http.MethodGet, path: "/api/session", cookies: []*http.Cookie{signedIn.cookie}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}

	if len(h.exec.calls) != 1 || len(h.exec.calls[0]) != 1 {
		t.Fatalf("calls = %v, want one single-statement read", h.exec.calls)
	}

	hash := secret.Hash(signedIn.issued.Token)
	args := h.exec.calls[0][0].Args

	if len(args) != 4 || !slices.Equal(asBlob(args[0]), hash[:]) || args[1] != store.KindSession {
		t.Errorf("args = %v, want the token's hash %x and kind %s first", args, hash, store.KindSession)
	}

	if _, isInt := args[2].(int64); !isInt || args[2] != args[3] {
		t.Errorf("time args = %v, %v, want one int64 instant twice", args[2], args[3])
	}
}

// TestRolesAtTheRoutes is the permission-confusion test at the app level: the
// same stack, signed in as an administrator and as a member, on the routes that
// require an administrator and on those that do not. The role is the account's
// as the database says, and a member never gets as far as the feature's own
// read.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRolesAtTheRoutes(t *testing.T) {
	t.Parallel()

	userRow := []any{memberID, roleMember, someID, `{"name":"Mia"}`, nil, int64(1_700_000_000)}

	tests := map[string]struct {
		role       string
		method     string
		path       string
		body       string
		after      []step // answers after the key read
		wantStatus int
		wantBody   string
	}{
		"admin lists users": {
			role: roleAdmin, method: http.MethodGet, path: "/api/user",
			after:      []step{{match: "FROM users", results: rows(userRow), err: nil}},
			wantStatus: http.StatusOK, wantBody: `"profile":{"name":"Mia"}`,
		},
		"member lists users": {
			role: roleMember, method: http.MethodGet, path: "/api/user",
			wantStatus: http.StatusForbidden, wantBody: `"forbidden"`,
		},
		"admin reads a user": {
			role: roleAdmin, method: http.MethodGet, path: "/api/user/" + someID,
			after:      []step{{match: "FROM users", results: rows(userRow), err: nil}},
			wantStatus: http.StatusOK, wantBody: `"role":"member"`,
		},
		"member reads a user": {
			role: roleMember, method: http.MethodGet, path: "/api/user/" + someID,
			wantStatus: http.StatusForbidden, wantBody: `"forbidden"`,
		},
		"admin finds no such user": {
			role: roleAdmin, method: http.MethodGet, path: "/api/user/" + someID,
			after:      []step{{match: "FROM users", results: rows(), err: nil}},
			wantStatus: http.StatusNotFound, wantBody: `"user_not_found"`,
		},
		"member revokes a user": {
			role: roleMember, method: http.MethodDelete, path: "/api/user/" + someID,
			wantStatus: http.StatusForbidden, wantBody: `"forbidden"`,
		},
		"member lists invitations": {
			role: roleMember, method: http.MethodGet, path: "/api/invitation",
			wantStatus: http.StatusForbidden, wantBody: `"forbidden"`,
		},
		"member creates an invitation": {
			role: roleMember, method: http.MethodPost, path: "/api/invitation",
			body:       `{"type":"first_run","numInvites":1}`,
			wantStatus: http.StatusForbidden, wantBody: `"forbidden"`,
		},
		"member updates an invitation": {
			role: roleMember, method: http.MethodPatch, path: "/api/invitation/" + someID,
			body:       `{"numInvites":2}`,
			wantStatus: http.StatusForbidden, wantBody: `"forbidden"`,
		},
		"member revokes an invitation": {
			role: roleMember, method: http.MethodDelete, path: "/api/invitation/" + someID,
			wantStatus: http.StatusForbidden, wantBody: `"forbidden"`,
		},
		"admin lists invitations": {
			role: roleAdmin, method: http.MethodGet, path: "/api/invitation",
			after:      []step{{match: "FROM invitations", results: rows(), err: nil}},
			wantStatus: http.StatusOK, wantBody: `"invitations":[]`,
		},
		"admin cannot create the first-run type": {
			role: roleAdmin, method: http.MethodPost, path: "/api/invitation",
			body:       `{"type":"first_run","numInvites":1}`,
			wantStatus: http.StatusBadRequest, wantBody: `"invalid_invitation_type"`,
		},
		"member lists their agents": {
			role: roleMember, method: http.MethodGet, path: "/api/agent",
			after:      []step{{match: "FROM agents", results: rows(), err: nil}},
			wantStatus: http.StatusOK, wantBody: `"agents":[]`,
		},
		"admin lists their agents": {
			role: roleAdmin, method: http.MethodGet, path: "/api/agent",
			after:      []step{{match: "FROM agents", results: rows(), err: nil}},
			wantStatus: http.StatusOK, wantBody: `"agents":[]`,
		},
		"member asks about their session": {
			role: roleMember, method: http.MethodGet, path: "/api/session",
			wantStatus: http.StatusOK, wantBody: `"role":"member"`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, adminID)
			script := append([]step{signedIn.activeSessionStep(tt.role)}, tt.after...)
			h := newHarness(t, fullEnv(), script...)

			rec := h.do(request{method: tt.method, path: tt.path, body: tt.body, cookies: []*http.Cookie{signedIn.cookie}})

			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("= %d %s, want %d containing %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if got := h.exec.callCount(); got != len(script) {
				t.Errorf("Exec calls = %d, want %d", got, len(script))
			}
		})
	}
}

// TestAgentsBelongToTheCaller: the agent routes act for the signed-in user. The
// owner in the query is the token's account, never anything in the request, and
// the label filter, when there is one, is the fourth argument (NULL for none). A
// user's own reach is not confined, and there is no sandbox filter.
func TestAgentsBelongToTheCaller(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query string
		label any
	}{
		{name: "no filter", query: "?limit=5", label: nil},
		{name: "a label", query: "?limit=5&label=prod", label: "prod"},
		{name: "a label, with an owner in the request", query: "?limit=5&label=a.b-c_d&owner=" + adminID, label: "a.b-c_d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, memberID)
			h := newHarness(t, fullEnv(),
				signedIn.activeSessionStep(roleMember),
				step{match: "FROM agents", results: rows(), err: nil},
			)

			rec := h.do(request{method: http.MethodGet, path: "/api/agent" + tt.query, cookies: []*http.Cookie{signedIn.cookie}})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body)
			}

			args := h.exec.calls[1][0].Args
			want := []any{memberID, nil, int64(6), tt.label, int64(0), nil, nil, "sandbox"}

			// The cursor (argument 1) is the first page's bound and is not compared.
			if len(args) != len(want) || !slices.Equal(slices.Delete(slices.Clone(args), 1, 2), slices.Delete(want, 1, 2)) {
				t.Errorf("agent list args = %v, want the caller's id, a page of 5 plus one, the label %v and no confinement",
					args, tt.label)
			}
		})
	}
}

// clearsSession reports whether cookies expire the session cookie.
func clearsSession(cookies []*http.Cookie) bool {
	for _, cookie := range cookies {
		if cookie.Name == auth.CookieName && cookie.MaxAge < 0 {
			return true
		}
	}

	return false
}

// TestLogout: the whole flow through the real stack, with the one conditional
// write deciding the outcome. A write that changed nothing (another request
// ended the session first) is the 401 any request without a session gets, and
// a write that changed more than one row is a defect.
func TestLogout(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		write      step
		wantStatus int
		wantCookie bool
		wantLogged []string
	}{
		"revoked": {
			write:      step{match: revokeToken, results: changes(1), err: nil},
			wantStatus: http.StatusNoContent, wantCookie: true,
		},
		"already revoked by another request": {
			write:      step{match: revokeToken, results: changes(0), err: nil},
			wantStatus: http.StatusUnauthorized, wantLogged: []string{auth.CodeUnauthenticated},
		},
		"changed two rows": {
			write:      step{match: revokeToken, results: changes(2), err: nil},
			wantStatus: http.StatusInternalServerError, wantLogged: []string{store.CodeSessionLogoutRejected},
		},
		"database down": {
			write:      step{match: revokeToken, results: nil, err: errDB},
			wantStatus: http.StatusServiceUnavailable, wantLogged: []string{store.CodeSessionLogoutFailed},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, memberID)
			h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleMember), tt.write)

			rec := h.do(request{method: http.MethodPost, path: "/api/logout", cookies: []*http.Cookie{signedIn.cookie}})

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body)
			}

			if cleared := clearsSession(rec.Result().Cookies()); cleared != tt.wantCookie {
				t.Errorf("session cookie cleared = %t, want %t", cleared, tt.wantCookie)
			}

			if got := h.loggedCodes(); !slices.Equal(got, tt.wantLogged) {
				t.Errorf("logged codes = %v, want %v", got, tt.wantLogged)
			}

			args := h.exec.calls[1][0].Args
			if len(args) != 3 || args[1] != signedIn.issued.ID || args[2] != memberID {
				t.Errorf("revoke args = %v, want the time, the presented session's id and its owner, and no kind", args)
			}
		})
	}
}

// TestCookieHandling: how the session cookie is read at the app level. Nothing
// but exactly one well-formed session token reaches the database, and none of
// these is that.
func TestCookieHandling(t *testing.T) {
	t.Parallel()

	good := newSession(t, memberID)
	other := newSession(t, adminID)
	key := newAPIKey(t)

	named := func(value string) *http.Cookie { return requestCookie(auth.CookieName, value) }

	tests := map[string]struct {
		cookies []*http.Cookie
	}{
		"none":                          {cookies: nil},
		"another cookie":                {cookies: []*http.Cookie{requestCookie("session", good.issued.Token)}},
		"empty":                         {cookies: []*http.Cookie{named("")}},
		"not a token":                   {cookies: []*http.Cookie{named("not a token!")}},
		"a prefix only":                 {cookies: []*http.Cookie{named("susu_ses_")}},
		"an API key's token":            {cookies: []*http.Cookie{named(key.issued.Token)}},
		"an invitation's token":         {cookies: []*http.Cookie{named(someCode)}},
		"a token one character short":   {cookies: []*http.Cookie{named(good.issued.Token[:len(good.issued.Token)-1])}},
		"a token one character long":    {cookies: []*http.Cookie{named(good.issued.Token + "A")}},
		"a token that is not canonical": {cookies: []*http.Cookie{named(good.issued.Token[:len(good.issued.Token)-1] + "B")}},
		"a token with whitespace":       {cookies: []*http.Cookie{named(" " + good.issued.Token)}},
		"oversized":                     {cookies: []*http.Cookie{named(strings.Repeat("a", 4097))}},
		"two cookies":                   {cookies: []*http.Cookie{good.cookie, other.cookie}},
		"the same cookie twice":         {cookies: []*http.Cookie{good.cookie, good.cookie}},
		"an empty one beside it":        {cookies: []*http.Cookie{named(""), good.cookie}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// No script: none of these gets as far as the database.
			h := newHarness(t, fullEnv())
			rec := h.do(request{method: http.MethodGet, path: "/api/session", cookies: tt.cookies})

			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("= %d %s, want the one 401", rec.Code, rec.Body)
			}

			if got := h.exec.callCount(); got != 0 {
				t.Errorf("Exec calls = %d, want 0", got)
			}
		})
	}
}

// TestBearerHandling: how the Authorization header is read at the app level.
// Nothing but exactly one well-formed API key token reaches the database, and
// none of these is that: not a session's token, not the other kinds of
// credential, not a token in any other form, and not a request that carries the
// session cookie as well.
func TestBearerHandling(t *testing.T) {
	t.Parallel()

	key := newAPIKey(t)
	signedIn := newSession(t, memberID)
	token := key.issued.Token

	tests := map[string]struct {
		headers map[string]string
		cookies []*http.Cookie
	}{
		"a session's token":     {headers: bearer(signedIn.issued.Token)},
		"an invitation's token": {headers: bearer(someCode)},
		"another scheme":        {headers: authorization("Basic " + token)},
		"no scheme":             {headers: authorization(token)},
		"an empty token":        {headers: authorization("Bearer ")},
		"two spaces":            {headers: authorization("Bearer  " + token)},
		"a token that is not canonical": {
			headers: bearer(token[:len(token)-1] + "B"),
		},
		"the cookie as well": {headers: key.headers, cookies: []*http.Cookie{signedIn.cookie}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// No script: none of these gets as far as the database.
			h := newHarness(t, fullEnv())
			rec := h.do(request{method: http.MethodGet, path: "/api/agent", headers: tt.headers, cookies: tt.cookies})

			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("= %d %s, want the one 401", rec.Code, rec.Body)
			}

			if got := h.exec.callCount(); got != 0 {
				t.Errorf("Exec calls = %d, want 0", got)
			}
		})
	}
}

// firstRunToken is a well-formed first-run secret: an invitation token.
//
//nolint:gosec // a throwaway token that only the tests know
const firstRunToken = "susu_inv_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopA"

// TestFirstRunStatusWritesNothing: with the secret configured and an empty
// database, the status check says "pending" and only reads: it is one Exec call
// of one statement, which is a SELECT. The first-run invitation is created by
// the registration that redeems the secret, never by a request a stranger can
// make.
func TestFirstRunStatusWritesNothing(t *testing.T) {
	t.Parallel()

	env := fullEnv()
	env[config.SecretFirstRun] = firstRunToken

	h := newHarness(t, env,
		step{match: "has_users", results: rows([]any{int64(0), int64(0), int64(0)}), err: nil},
	)

	rec := h.do(request{method: http.MethodGet, path: pathFirstRun})

	if want := `{"status":"invitation_pending"}` + "\n"; rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Fatalf("= %d %s, want 200 %s", rec.Code, rec.Body, want)
	}

	calls := h.exec.calls
	if len(calls) != 1 || len(calls[0]) != 1 || !strings.HasPrefix(strings.TrimSpace(calls[0][0].Query), "SELECT") {
		t.Errorf("Exec calls = %v, want one call of one SELECT", calls)
	}

	if strings.Contains(rec.Body.String(), firstRunToken) {
		t.Errorf("body leaks the secret: %s", rec.Body)
	}
}

// TestFirstRunSecretMustBeAnInvitationToken: FIRST_RUN_SECRET is the first
// invitation's token, so anything else is as good as no secret: the status
// check reads the state and reports it missing.
func TestFirstRunSecretMustBeAnInvitationToken(t *testing.T) {
	t.Parallel()

	secrets := map[string]string{
		"unset":                             "",
		"a random string of the old length": strings.Repeat("s", 43),
		"a session's token":                 "susu_ses_" + strings.TrimPrefix(firstRunToken, "susu_inv_"),
		"a token one character short":       firstRunToken[:len(firstRunToken)-1],
		"a token that is not canonical":     firstRunToken[:len(firstRunToken)-1] + "B",
		"a token with whitespace":           firstRunToken + "\n",
	}

	for name, value := range secrets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := fullEnv()
			env[config.SecretFirstRun] = value

			h := newHarness(t, env, step{match: "has_users", results: rows([]any{int64(0), int64(0), int64(0)}), err: nil})

			rec := h.do(request{method: http.MethodGet, path: pathFirstRun})

			if want := `{"status":"missing_secret"}` + "\n"; rec.Code != http.StatusOK || rec.Body.String() != want {
				t.Errorf("= %d %s, want 200 %s", rec.Code, rec.Body, want)
			}

			if got := h.exec.callCount(); got != 1 {
				t.Errorf("Exec calls = %d, want only the state read", got)
			}
		})
	}
}
