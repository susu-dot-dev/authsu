//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// errCheck is what D1 says when a CHECK constraint refuses a statement.
var errCheck = errors.New("D1_ERROR: CHECK constraint failed: SQLITE_CONSTRAINT_CHECK")

// uuidV7 is the canonical text of a version 7 UUID.
var uuidV7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const (
	pathFirstRun      = "/api/first-run"
	activeKeyFragment = "FROM japikeys k"
	jwkMalformed      = `{"keys":"not an array"}`
)

// TestSessionRowSeam is the seam between what D1 hands the Worker and what the
// Go code can trust. The real session boundary, the real store and the real
// route run over a fake database that answers with the key row exactly as D1
// produces values (int64 for integers, string for text, []byte for blobs), and
// then with values the JS side could produce but must never be believed:
// float64 integers, NULL in a NOT NULL column, a blob where text belongs, a
// row of the wrong width. Every one of those is a defect (500, a bare
// "internal" to the client, the real code in the log), never a successful
// sign-in and never a sign-out.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestSessionRowSeam(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// row builds the database's answer from the session's key.
		row func(s session) step
		// wantStatus is the response status; wantBody is a fragment of the body,
		// or the whole of an error body.
		wantStatus int
		wantBody   string
		wantLogged []string
	}{
		"member, as D1 produces it": {
			row:        func(s session) step { return s.activeKeyStep(roleMember) },
			wantStatus: http.StatusOK, wantBody: `"role":"member"`,
		},
		"admin, as D1 produces it": {
			row:        func(s session) step { return s.activeKeyStep(roleAdmin) },
			wantStatus: http.StatusOK, wantBody: `"role":"admin"`,
		},
		"expires_at as float64": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", roleMember, float64(s.key.ExpiresAt.Unix()), "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"expires_at as text": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", roleMember, "1900000000", "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"expires_at NULL": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", roleMember, nil, "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"role NULL": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", nil, s.key.ExpiresAt.Unix(), "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"role as a blob": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", []byte(roleAdmin), s.key.ExpiresAt.Unix(), "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"jwk as a blob": {
			row: func(s session) step {
				return s.activeKeyRow([]any{[]byte(s.key.JWK), s.userID, "", roleMember, s.key.ExpiresAt.Unix(), "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"user_id as an integer": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, int64(7), "", roleMember, s.key.ExpiresAt.Unix(), "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"credential_id NULL": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, nil, roleMember, s.key.ExpiresAt.Unix(), "", ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"agent id NULL": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", roleMember, s.key.ExpiresAt.Unix(), nil, ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"agent scopes NULL": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", roleMember, s.key.ExpiresAt.Unix(), "", nil})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"agent scopes as a blob": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", roleMember, s.key.ExpiresAt.Unix(), "", []byte("[]")})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"a session whose row names an agent: the token has no actor": {
			row: func(s session) step {
				return s.activeKeyRow([]any{
					s.key.JWK, s.userID, "", roleMember, s.key.ExpiresAt.Unix(), agentRowID, `["agent:read"]`,
				})
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
			wantLogged: []string{auth.CodeUnauthenticated},
		},
		"a column short": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", roleMember, s.key.ExpiresAt.Unix(), ""})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"a column too many": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, s.userID, "", roleMember, s.key.ExpiresAt.Unix(), "extra"})
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"no row: not active": {
			row: func(session) step {
				return step{match: activeKeyFragment, results: rows(), err: nil}
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
			wantLogged: []string{auth.CodeUnauthenticated},
		},
		"two rows": {
			row: func(s session) step {
				good := []any{s.key.JWK, s.userID, "", roleMember, s.key.ExpiresAt.Unix()}

				return step{match: activeKeyFragment, results: rows(good, good), err: nil}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"no result at all": {
			row: func(session) step {
				return step{match: activeKeyFragment, results: nil, err: nil}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
		},
		"the row belongs to someone else": {
			row: func(s session) step {
				return s.activeKeyRow([]any{s.key.JWK, memberID, "", roleAdmin, s.key.ExpiresAt.Unix(), "", ""})
			},
			wantStatus: http.StatusUnauthorized, wantBody: bodyUnauthenticated,
			wantLogged: []string{auth.CodeUnauthenticated},
		},
		"stored key is not a JWK": {
			row: func(s session) step {
				return s.activeKeyRow([]any{jwkMalformed, s.userID, "", roleMember, s.key.ExpiresAt.Unix(), "", ""})
			},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   `{"error":{"code":"session_verify_failed","message":"sessions are temporarily unavailable"}}` + "\n",
			wantLogged: []string{store.CodeSessionVerifyFailed},
		},
		"database down": {
			row: func(session) step {
				return step{match: activeKeyFragment, results: nil, err: errDB}
			},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   `{"error":{"code":"session_verify_failed","message":"sessions are temporarily unavailable"}}` + "\n",
			wantLogged: []string{store.CodeSessionVerifyFailed},
		},
		"schema rule refused the read": {
			row: func(session) step {
				return step{match: activeKeyFragment, results: nil, err: store.Classify(errCheck)}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeSessionVerifyRejected},
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
				t.Errorf("Exec calls = %d, want the one key read", got)
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

	if got.UserID != signedIn.userID || got.ExpiresAt != signedIn.key.ExpiresAt.Unix() {
		t.Errorf("body = %+v, want user %s expiring %d", got, signedIn.userID, signedIn.key.ExpiresAt.Unix())
	}
}

// TestSessionReadIsScoped: the key read the boundary makes names the token's
// key id and the session kind, so an API key id presented as a session is not
// found, and the time is now.
func TestSessionReadIsScoped(t *testing.T) {
	t.Parallel()

	signedIn := newSession(t, memberID)
	h := newHarness(t, fullEnv(), signedIn.activeKeyStep(roleMember))

	rec := h.do(request{method: http.MethodGet, path: "/api/session", cookies: []*http.Cookie{signedIn.cookie}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}

	if len(h.exec.calls) != 1 || len(h.exec.calls[0]) != 1 {
		t.Fatalf("calls = %v, want one single-statement read", h.exec.calls)
	}

	args := h.exec.calls[0][0].Args
	if len(args) != 4 || args[0] != signedIn.key.ID.String() || args[1] != store.KindSession {
		t.Errorf("args = %v, want kid %s and kind %s first", args, signedIn.key.ID, store.KindSession)
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
			script := append([]step{signedIn.activeKeyStep(tt.role)}, tt.after...)
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
// owner in the query is the token's account, never anything in the request.
func TestAgentsBelongToTheCaller(t *testing.T) {
	t.Parallel()

	signedIn := newSession(t, memberID)
	h := newHarness(t, fullEnv(),
		signedIn.activeKeyStep(roleMember),
		step{match: "FROM agents", results: rows(), err: nil},
	)

	rec := h.do(request{method: http.MethodGet, path: "/api/agent?limit=5", cookies: []*http.Cookie{signedIn.cookie}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}

	args := h.exec.calls[1][0].Args
	if len(args) != 3 || args[0] != memberID || args[2] != int64(6) {
		t.Errorf("agent list args = %v, want the caller's id and a page of 5 plus one", args)
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
			write:      step{match: "UPDATE japikeys", results: changes(1), err: nil},
			wantStatus: http.StatusNoContent, wantCookie: true,
		},
		"already revoked by another request": {
			write:      step{match: "UPDATE japikeys", results: changes(0), err: nil},
			wantStatus: http.StatusUnauthorized, wantLogged: []string{auth.CodeUnauthenticated},
		},
		"changed two rows": {
			write:      step{match: "UPDATE japikeys", results: changes(2), err: nil},
			wantStatus: http.StatusInternalServerError, wantLogged: []string{store.CodeSessionLogoutRejected},
		},
		"database down": {
			write:      step{match: "UPDATE japikeys", results: nil, err: errDB},
			wantStatus: http.StatusServiceUnavailable, wantLogged: []string{store.CodeSessionLogoutFailed},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, memberID)
			h := newHarness(t, fullEnv(), signedIn.activeKeyStep(roleMember), tt.write)

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
			if len(args) != 3 || args[1] != signedIn.key.ID.String() || args[2] != memberID {
				t.Errorf("revoke args = %v, want the time, the presented key id and its owner, and no kind", args)
			}
		})
	}
}

// TestCookieHandling: how the session cookie is read at the app level. Nothing
// but exactly one well-formed token reaches the database, and none of these is
// that.
func TestCookieHandling(t *testing.T) {
	t.Parallel()

	good := newSession(t, memberID)
	other := newSession(t, adminID)

	named := func(value string) *http.Cookie { return requestCookie(auth.CookieName, value) }

	tests := map[string]struct {
		cookies []*http.Cookie
	}{
		"none":                   {cookies: nil},
		"another cookie":         {cookies: []*http.Cookie{requestCookie("session", good.key.JWT)}},
		"empty":                  {cookies: []*http.Cookie{named("")}},
		"not a token":            {cookies: []*http.Cookie{named("not a token!")}},
		"not a JWT":              {cookies: []*http.Cookie{named("abc")}},
		"oversized":              {cookies: []*http.Cookie{named(strings.Repeat("a", 4097))}},
		"two cookies":            {cookies: []*http.Cookie{good.cookie, other.cookie}},
		"the same cookie twice":  {cookies: []*http.Cookie{good.cookie, good.cookie}},
		"an empty one beside it": {cookies: []*http.Cookie{named(""), good.cookie}},
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

// TestFirstRunCreatesTheInvitation: with the secret configured and an empty
// database, the first status check creates the invitation. It is the one
// write a stranger's request can cause, and it carries what the runtime
// supplies: a UUIDv7 id (canonical text), the hash of the secret and not the
// secret, the first-run type, and the current time as an integer.
func TestFirstRunCreatesTheInvitation(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("s", 43)
	env := fullEnv()
	env[config.SecretFirstRun] = secret

	h := newHarness(t, env,
		step{match: "has_users", results: rows([]any{int64(0), int64(0)}), err: nil},
		step{match: "INSERT INTO invitations", results: rows([]any{someID}), err: nil},
	)

	before := time.Now().Unix()
	rec := h.do(request{method: http.MethodGet, path: pathFirstRun})
	after := time.Now().Unix()

	if want := `{"status":"invitation_pending"}` + "\n"; rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Fatalf("= %d %s, want 200 %s", rec.Code, rec.Body, want)
	}

	args := h.exec.calls[1][0].Args
	if len(args) != 5 {
		t.Fatalf("insert args = %v, want 5", args)
	}

	id, _ := args[0].(string)
	if !uuidV7.MatchString(id) {
		t.Errorf("id = %q, want a canonical UUIDv7", id)
	}

	hash, _ := args[1].([]byte)
	created, _ := args[4].(int64)

	if len(hash) != sha256.Size || args[2] != store.InvitationFirstRun || created < before || created > after {
		t.Errorf("args = %v, want a SHA-256 hash, type %s and a Unix time in [%d, %d]",
			args, store.InvitationFirstRun, before, after)
	}

	if strings.Contains(rec.Body.String(), secret) {
		t.Errorf("body leaks the secret: %s", rec.Body)
	}
}
