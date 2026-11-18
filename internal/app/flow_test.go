//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file runs whole ceremonies through the real stack (boundary, features,
// store, challenge and WebAuthn verification, with the real clock, entropy and
// id source) over a fake database, and feeds what one request wrote into the
// answers of the next, typed as D1 would return them. Each feature's own tests
// fake its neighbours, so the seams between them are only crossed here: what
// registration writes is what login reads, what login writes is what the key
// read of the boundary reads, and every value written fits the schema's CHECK.

// Where the values are in the statements the account batch binds (see
// store.CreateAccount): the user insert, then the credential insert.
const (
	userArgID      = 0
	userArgHandle  = 1
	userArgRole    = 2
	userArgProfile = 3
	userArgType    = 6

	credArgRowID    = 0
	credArgID       = 1
	credArgHandle   = 2
	credArgKey      = 3
	credArgFlags    = 4
	credArgMetadata = 5
)

// Where the values are in the statements of a login (see store.CreateSession):
// the flags update, then the session insert.
const (
	sessionArgKid           = 0
	sessionArgKind          = 2
	sessionArgJWK           = 3
	sessionArgExpires       = 4
	sessionArgGrant         = 5
	sessionArgCredentialRow = 6
)

const (
	pathRegisterBegin  = "/api/register/begin"
	pathRegisterFinish = "/api/register/finish"
	pathLoginBegin     = "/api/login/begin"
	pathLoginFinish    = "/api/login/finish"
	pathSession        = "/api/session"
	pathLogout         = "/api/logout"

	readInvitation = "FROM invitations i"
	readCredential = "FROM credentials c"
	writeAccount   = "INSERT INTO users"
	writeSession   = "UPDATE credentials SET flags"
	readKey        = "FROM japikeys k"
	revokeKey      = "UPDATE japikeys"
	registeredName = "Alice"
)

// errD1Unique is what D1 says when a UNIQUE constraint refuses a write,
// before the store has classified it.
var errD1Unique = errors.New("D1_ERROR: UNIQUE constraint failed: SQLITE_CONSTRAINT_UNIQUE")

// errD1NotNull is the failure of an insert whose subselect found no row.
var errD1NotNull = errors.New("D1_ERROR: NOT NULL constraint failed: SQLITE_CONSTRAINT_NOTNULL")

// registerBegin runs a registration begin for pk and returns the challenge and
// the user handle it issued, remembering the handle on pk.
func registerBegin(t *testing.T, h *harness, pk *passkey, name string) string {
	t.Helper()

	h.expect(step{match: readInvitation, results: rows([]any{store.InvitationFirstRun}), err: nil})

	rec := h.do(request{
		method: http.MethodPost, path: pathRegisterBegin,
		body: `{"invitationCode":"` + someCode + `","name":` + jsonString(t, name) + `}`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("register begin = %d %s", rec.Code, rec.Body)
	}

	challenge, handle := optionsOf(t, rec.Body.Bytes())
	pk.handle = handle

	return challenge
}

// jsonString is the JSON text of a Go string.
func jsonString(t *testing.T, text string) string {
	t.Helper()

	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatalf("encode %q: %v", text, err)
	}

	return string(encoded)
}

// register runs a whole registration of pk under name, with the one outcome the
// account write answers with, and returns the response and the two statements
// the batch carried.
func register(t *testing.T, h *harness, pk *passkey, name string, write step) (int, string, []store.Statement) {
	t.Helper()

	challenge := registerBegin(t, h, pk, name)

	h.expect(step{match: readInvitation, results: rows([]any{store.InvitationFirstRun}), err: nil}, write)

	rec := h.do(request{
		method: http.MethodPost, path: pathRegisterFinish, body: pk.registrationBody(t, challenge, someCode, name),
	})

	return rec.Code, rec.Body.String(), h.lastCall()
}

// accepted is the answer of the account write when it took effect.
func accepted() step {
	return step{match: writeAccount, results: batchOf(2), err: nil}
}

// credentialRowOf is the row the credential lookup answers for what a
// registration wrote, as D1 returns it: text as string, blobs as []byte and
// the flags as int64.
func credentialRowOf(batch []store.Statement) []any {
	user, credential := batch[0].Args, batch[1].Args

	return []any{credential[credArgRowID], user[userArgID], credential[credArgKey], credential[credArgFlags],
		credential[credArgHandle], "admin"}
}

// sizeOf is the size of a bound text or blob argument, and -1 for anything
// else: a column the schema bounds in bytes must be bound as one of the two.
func sizeOf(arg any) int {
	switch value := arg.(type) {
	case string:
		return len(value)
	case []byte:
		return len(value)
	default:
		return -1
	}
}

// fit is one bound argument held to one CHECK of the migrations, whose text the
// pattern reads: the size is within 1 to the limit it captures, or exactly the
// limit when exact.
type fit struct {
	name    string
	pattern string
	arg     any
	exact   bool
}

// checkFits holds every argument of fits to its CHECK.
func checkFits(t *testing.T, fits []fit) {
	t.Helper()

	for _, f := range fits {
		size, limit := sizeOf(f.arg), migrationLimit(t, f.pattern)

		if size < 1 || size > limit || (f.exact && size != limit) {
			t.Errorf("%s = %v is %d bytes; the schema allows %d (exactly: %t)", f.name, f.arg, size, limit, f.exact)
		}
	}
}

// TestRegistrationWritesWhatTheSchemaAndLoginExpect crosses registration's
// writes: the account batch is what the schema accepts, with the types its
// columns need, and carries the values the ceremony fixed (the user handle
// begin issued, the passkey's id and key, the role the server chose).
func TestRegistrationWritesWhatTheSchemaAndLoginExpect(t *testing.T) {
	t.Parallel()

	pk := newPasskey(t)
	h := newHarness(t, fullEnv())

	status, body, batch := register(t, h, &pk, registeredName, accepted())
	if status != http.StatusCreated || len(batch) != 2 {
		t.Fatalf("register finish = %d %s, batch of %d statements", status, body, len(batch))
	}

	user, credential := batch[0].Args, batch[1].Args

	t.Run("the values the ceremony fixed", func(t *testing.T) {
		t.Parallel()

		checkCeremonyValues(t, pk, user, credential)

		if !strings.Contains(body, `"userId":"`+asText(user[userArgID])+`"`) {
			t.Errorf("response %s does not name user %v", body, user[userArgID])
		}
	})

	t.Run("generated ids are UUIDv7 that the routes accept back", func(t *testing.T) {
		t.Parallel()

		for _, id := range []any{user[userArgID], credential[credArgRowID]} {
			_, err := input.ParseID(asText(id))
			if !uuidV7.MatchString(asText(id)) || err != nil {
				t.Errorf("id = %v, want a canonical UUIDv7 that the path parser accepts back: %v", id, err)
			}
		}
	})

	t.Run("sizes the schema allows", func(t *testing.T) {
		t.Parallel()

		checkFits(t, []fit{
			{"public key", `length\(public_key\) BETWEEN 1 AND (\d+)`, credential[credArgKey], false},
			{"credential id", `length\(credential_id\) BETWEEN 1 AND (\d+)`, credential[credArgID], false},
			{"user handle", `length\(user_handle\) BETWEEN 1 AND (\d+)`, user[userArgHandle], false},
			{"profile", `length\(profile\) <= (\d+)`, user[userArgProfile], false},
			{"metadata", `length\(metadata\) <= (\d+)`, credential[credArgMetadata], false},
			{"role", `length\(role\) BETWEEN 1 AND (\d+)`, user[userArgRole], false},
			{"invitation type", `length\(type\) BETWEEN 1 AND (\d+)`, user[userArgType], false},
		})
	})
}

// asText is an argument that must be text, as a string.
func asText(arg any) string {
	text, _ := arg.(string)

	return text
}

// asBlob is an argument that must be a blob, as bytes.
func asBlob(arg any) []byte {
	blob, _ := arg.([]byte)

	return blob
}

// checkCeremonyValues checks the account batch's arguments against what the
// passkey and the begin fixed, and against the types D1 takes.
func checkCeremonyValues(t *testing.T, pk passkey, user, credential []any) {
	t.Helper()

	if !slices.Equal(asBlob(credential[credArgID]), pk.credID) {
		t.Errorf("credential id = %x, want the passkey's %x", credential[credArgID], pk.credID)
	}

	if !slices.Equal(asBlob(credential[credArgKey]), pk.coseKey(t)) {
		t.Errorf("public key = %x, want the canonical COSE key", credential[credArgKey])
	}

	for name, handle := range map[string]any{"user": user[userArgHandle], "credential": credential[credArgHandle]} {
		if !slices.Equal(asBlob(handle), pk.handle) {
			t.Errorf("%s handle = %x, want the one begin issued, %x", name, handle, pk.handle)
		}
	}

	if user[userArgRole] != "admin" || user[userArgType] != store.InvitationFirstRun {
		t.Errorf("role %v for type %v, want admin for first_run", user[userArgRole], user[userArgType])
	}

	if user[userArgProfile] != `{"name":"`+registeredName+`"}` {
		t.Errorf("profile = %v", user[userArgProfile])
	}

	if credential[credArgFlags] != int64(0x05) {
		t.Errorf("flags = %#v, want the int64 UP|UV", credential[credArgFlags])
	}
}

// TestRegistrationFinishOutcomes crosses the account write's outcomes from the
// database's error text, through the real classification of the store, to what
// registration tells the client: a write that finds the invitation used up
// between begin and finish, a replay, a schema refusal and an outage each get
// their own answer, and none leaks the cause.
func TestRegistrationFinishOutcomes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		write      step
		wantStatus int
		wantCode   string
		wantLogged string
	}{
		"invitation used up since the read: the credential insert met a NULL user": {
			write:      step{match: writeAccount, results: nil, err: store.Classify(errD1NotNull)},
			wantStatus: http.StatusConflict, wantCode: "registration_accept_failed", wantLogged: "registration_accept_failed",
		},
		"a replay: the handle or the credential is already stored": {
			write:      step{match: writeAccount, results: nil, err: store.Classify(errD1Unique)},
			wantStatus: http.StatusConflict, wantCode: "registration_accept_failed", wantLogged: "registration_accept_failed",
		},
		"the schema refuses a value": {
			write:      step{match: writeAccount, results: nil, err: store.Classify(errCheck)},
			wantStatus: http.StatusInternalServerError, wantCode: "internal", wantLogged: store.CodeRegistrationAcceptRejected,
		},
		"the database is down": {
			write:      step{match: writeAccount, results: nil, err: errDB},
			wantStatus: http.StatusServiceUnavailable, wantCode: store.CodeRegistrationAcceptFailed,
			wantLogged: store.CodeRegistrationAcceptFailed,
		},
		"the batch answers for one statement only": {
			write:      step{match: writeAccount, results: batchOf(1), err: nil},
			wantStatus: http.StatusInternalServerError, wantCode: "internal", wantLogged: store.CodeRegistrationAcceptRejected,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pk := newPasskey(t)
			h := newHarness(t, fullEnv())

			status, body, _ := register(t, h, &pk, registeredName, tt.write)

			if status != tt.wantStatus || !strings.Contains(body, `"code":"`+tt.wantCode+`"`) {
				t.Errorf("= %d %s, want %d with code %s", status, body, tt.wantStatus, tt.wantCode)
			}

			if strings.Contains(body, errDB.Error()) || strings.Contains(body, "SQLITE") {
				t.Errorf("body leaks the cause: %s", body)
			}

			if got := h.loggedCodes(); !slices.Equal(got, []string{tt.wantLogged}) {
				t.Errorf("logged codes = %v, want [%s]", got, tt.wantLogged)
			}
		})
	}
}

// loginBegin runs a login begin and returns the challenge it issued.
func loginBegin(t *testing.T, h *harness) string {
	t.Helper()

	rec := h.do(request{method: http.MethodPost, path: pathLoginBegin, body: "{}"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login begin = %d %s", rec.Code, rec.Body)
	}

	challenge, _ := optionsOf(t, rec.Body.Bytes())

	return challenge
}

// kidOfToken reads the kid from the header of a JWT, without verifying it.
func kidOfToken(t *testing.T, token string) string {
	t.Helper()

	header, _, found := strings.Cut(token, ".")
	if !found {
		t.Fatalf("token %q has no header", token)
	}

	var parsed struct {
		Kid string `json:"kid"`
	}

	err := json.Unmarshal(unb64(t, header), &parsed)
	if err != nil {
		t.Fatalf("token header: %v", err)
	}

	return parsed.Kid
}

// loggedIn is what a login answered and wrote.
type loggedIn struct {
	// cookie is the session cookie the browser would send back.
	cookie *http.Cookie
	// args are the arguments of the session insert.
	args []any
	// body is the answer.
	UserID    string `json:"userId"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"expiresAt"`
}

// logIn runs a login of pk over the credential lookup, with the one outcome
// the session write answers with, and returns the response.
func logIn(t *testing.T, h *harness, pk passkey, lookup, write step) (*httptest.ResponseRecorder, string) {
	t.Helper()

	challenge := loginBegin(t, h)

	h.expect(lookup, write)

	return h.do(request{method: http.MethodPost, path: pathLoginFinish, body: pk.assertionBody(t, challenge)}), challenge
}

// sessionCookieOf returns the one cookie of a login, which must be the
// HttpOnly, Secure, Lax, host-only session cookie, and must not be in the body.
func sessionCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != auth.CookieName || !cookies[0].HttpOnly || !cookies[0].Secure ||
		cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" || cookies[0].Domain != "" {
		t.Fatalf("cookies = %v, want one HttpOnly Secure Lax host-only session cookie", cookies)
	}

	if strings.Contains(rec.Body.String(), cookies[0].Value) {
		t.Error("the response body carries the session token")
	}

	return cookies[0]
}

// checkLogin checks a login that was accepted and returns what it wrote: the
// lookup was by the registered credential id, the batch is the flags of that
// passkey and then the session, and the answer names the registered account
// without the token in its body.
func checkLogin(
	t *testing.T, h *harness, rec *httptest.ResponseRecorder, pk passkey, account []store.Statement,
) loggedIn {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("login finish = %d %s", rec.Code, rec.Body)
	}

	calls := h.exec.calls
	if got := asBlob(calls[len(calls)-2][0].Args[0]); !slices.Equal(got, pk.credID) {
		t.Errorf("credential lookup by %x, want the registered credential id %x", got, pk.credID)
	}

	cookie := sessionCookieOf(t, rec)

	batch := h.lastCall()
	if len(batch) != 2 || batch[0].Args[0] != int64(0x05) || batch[0].Args[1] != account[1].Args[credArgRowID] {
		t.Fatalf("login batch = %v, want the flags of the registered credential, then the session", batch)
	}

	login := loggedIn{cookie: requestCookie(auth.CookieName, cookie.Value), args: batch[1].Args}

	err := json.Unmarshal(rec.Body.Bytes(), &login)
	if err != nil {
		t.Fatalf("login body %q: %v", rec.Body, err)
	}

	wantUser, wantExpiry := account[0].Args[userArgID], login.args[sessionArgExpires]
	if login.UserID != wantUser || login.Role != "admin" || login.ExpiresAt != wantExpiry {
		t.Errorf("login = %+v, want the registered user, admin, expiring as written", login)
	}

	return login
}

// TestLoginAndSessionFollowRegistration is the whole life of an account across
// the features: registration writes it, login reads it back as D1 would return
// it and writes a session, the key read of the boundary accepts that session
// from exactly what login wrote, logout ends it, and a replay of the login is
// the one 401 any failed login gets.
func TestLoginAndSessionFollowRegistration(t *testing.T) {
	t.Parallel()

	pk := newPasskey(t)
	h := newHarness(t, fullEnv())

	status, body, account := register(t, h, &pk, registeredName, accepted())
	if status != http.StatusCreated {
		t.Fatalf("register finish = %d %s", status, body)
	}

	lookup := step{match: readCredential, results: rows(credentialRowOf(account)), err: nil}
	session := step{match: writeSession, results: batchOf(2), err: nil}

	rec, challenge := logIn(t, h, pk, lookup, session)
	login := checkLogin(t, h, rec, pk, account)

	checkSessionRow(t, login, account, challenge)

	// The boundary accepts the session from exactly what login wrote, typed as
	// D1 returns it, and names the same account.
	keyRow := []any{
		login.args[sessionArgJWK], login.UserID, login.args[sessionArgCredentialRow], "admin", login.ExpiresAt,
	}
	stored := step{match: readKey, results: rows(keyRow), err: nil}

	h.expect(stored)

	rec = h.do(request{method: http.MethodGet, path: pathSession, cookies: []*http.Cookie{login.cookie}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"userId":"`+login.UserID+`"`) {
		t.Fatalf("session = %d %s, want the registered user", rec.Code, rec.Body)
	}

	if read := h.lastCall()[0].Args; read[0] != login.args[sessionArgKid] || read[1] != store.KindSession {
		t.Errorf("key read args = %v, want the session login wrote (%v) as a session", read, login.args[sessionArgKid])
	}

	// Logout ends exactly that key.
	h.expect(stored, step{match: revokeKey, results: changes(1), err: nil})

	rec = h.do(request{method: http.MethodPost, path: pathLogout, cookies: []*http.Cookie{login.cookie}})
	if rec.Code != http.StatusNoContent || !clearsSession(rec.Result().Cookies()) {
		t.Errorf("logout = %d %v, want 204 clearing the cookie", rec.Code, rec.Result().Cookies())
	}

	if revoke := h.lastCall()[0].Args; revoke[1] != login.args[sessionArgKid] || revoke[2] != store.KindSession {
		t.Errorf("revoke args = %v, want the session's kid and kind", revoke)
	}
}

// TestLoginReplayIsTheOne401: the same login response presented again meets the
// database's refusal of the repeated grant, and is answered as any failed login,
// with no cookie.
func TestLoginReplayIsTheOne401(t *testing.T) {
	t.Parallel()

	pk := newPasskey(t)
	h := newHarness(t, fullEnv())

	status, body, account := register(t, h, &pk, registeredName, accepted())
	if status != http.StatusCreated {
		t.Fatalf("register finish = %d %s", status, body)
	}

	rec, _ := logIn(t, h, pk, step{match: readCredential, results: rows(credentialRowOf(account)), err: nil},
		step{match: writeSession, results: nil, err: store.Classify(errD1Unique)})

	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"invalid_login"`) ||
		len(rec.Result().Cookies()) != 0 {
		t.Errorf("replayed login = %d %s %v, want the one 401 and no cookie", rec.Code, rec.Body, rec.Result().Cookies())
	}
}

// checkSessionRow checks the arguments of the session insert of a login: the
// types the columns need, the values the ceremony fixed, and the sizes the
// schema allows.
func checkSessionRow(t *testing.T, login loggedIn, account []store.Statement, challenge string) {
	t.Helper()

	args := login.args

	if args[sessionArgKid] != kidOfToken(t, login.cookie.Value) || args[sessionArgKind] != store.KindSession {
		t.Errorf("kid, kind = %v, %v, want the token's %s and %s",
			args[sessionArgKid], args[sessionArgKind], kidOfToken(t, login.cookie.Value), store.KindSession)
	}

	if args[1] != account[1].Args[credArgRowID] || args[sessionArgCredentialRow] != args[1] {
		t.Errorf("credential row ids = %v and %v, want the registered passkey twice", args[1], args[sessionArgCredentialRow])
	}

	grant := sha256.Sum256(unb64(t, challenge))
	if !slices.Equal(asBlob(args[sessionArgGrant]), grant[:]) {
		t.Errorf("granted_from = %v, want the SHA-256 of the login challenge", args[sessionArgGrant])
	}

	if _, isInt := args[sessionArgExpires].(int64); !isInt {
		t.Errorf("expires_at = %#v, want an int64", args[sessionArgExpires])
	}

	checkFits(t, []fit{
		{"kid", `length\(kid\) = (\d+)`, args[sessionArgKid], true},
		{"jwk", `length\(jwk\) <= (\d+)`, args[sessionArgJWK], false},
		{"kind", `length\(kind\) BETWEEN 1 AND (\d+)`, args[sessionArgKind], false},
		{"granted_from", `length\(granted_from\) = (\d+)`, args[sessionArgGrant], true},
	})
}

// TestLoginFinishOutcomes crosses the credential lookup's answers, as D1 could
// give them, to what login tells the client. An unknown or revoked account's
// passkey and a passkey that fails verification are the same 401; a lookup the
// database could not answer or answered in a shape the store does not trust is
// the service's fault and says so.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestLoginFinishOutcomes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		lookup     func(account []store.Statement) step
		wantStatus int
		wantBody   string
		wantLogged []string
	}{
		"no such passkey, or its account is revoked": {
			lookup:     func([]store.Statement) step { return step{match: readCredential, results: rows(), err: nil} },
			wantStatus: http.StatusUnauthorized, wantBody: `"code":"invalid_login"`, wantLogged: []string{"invalid_login"},
		},
		"flags as a float": {
			lookup: func(account []store.Statement) step {
				row := credentialRowOf(account)
				row[3] = float64(5)

				return step{match: readCredential, results: rows(row), err: nil}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeCredentialLookupRejected},
		},
		"public key as text": {
			lookup: func(account []store.Statement) step {
				row := credentialRowOf(account)
				row[2] = "not a blob"

				return step{match: readCredential, results: rows(row), err: nil}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeCredentialLookupRejected},
		},
		"user handle as text": {
			lookup: func(account []store.Statement) step {
				row := credentialRowOf(account)
				row[4] = "not a blob"

				return step{match: readCredential, results: rows(row), err: nil}
			},
			wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeCredentialLookupRejected},
		},
		"a user handle that is not the account's": {
			lookup: func(account []store.Statement) step {
				row := credentialRowOf(account)
				row[4] = []byte("someone else's handle")

				return step{match: readCredential, results: rows(row), err: nil}
			},
			wantStatus: http.StatusUnauthorized, wantBody: `"code":"invalid_login"`, wantLogged: []string{"invalid_login"},
		},
		"the database is down": {
			lookup:     func([]store.Statement) step { return step{match: readCredential, results: nil, err: errDB} },
			wantStatus: http.StatusServiceUnavailable, wantBody: `"code":"` + store.CodeCredentialLookupFailed + `"`,
			wantLogged: []string{store.CodeCredentialLookupFailed},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pk := newPasskey(t)
			h := newHarness(t, fullEnv())

			status, body, account := register(t, h, &pk, registeredName, accepted())
			if status != http.StatusCreated {
				t.Fatalf("register finish = %d %s", status, body)
			}

			challenge := loginBegin(t, h)

			h.expect(tt.lookup(account))

			rec := h.do(request{method: http.MethodPost, path: pathLoginFinish, body: pk.assertionBody(t, challenge)})

			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("= %d %s, want %d containing %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if len(rec.Result().Cookies()) != 0 {
				t.Errorf("a refused login set cookies: %v", rec.Result().Cookies())
			}

			// The refusal never wrote: only the lookup follows registration's two calls.
			if got := h.exec.callCount(); got != 4 {
				t.Errorf("Exec calls = %d, want 4 (begin read, finish read, account write, lookup)", got)
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

// TestRegisteredProfileIsServedAsJSON crosses registration's profile column to
// the users routes: the name goes into users.profile through the JSON encoder
// (which escapes <, > and & and the line separators), and the users routes
// send the stored text back inside their own JSON, which must still be the
// name the registrant gave.
func TestRegisteredProfileIsServedAsJSON(t *testing.T) {
	t.Parallel()

	names := map[string]string{
		"plain":                         registeredName,
		"markup characters":             `<Ali&ce>`,
		"a quote and a backslash":       `Al"ice\`,
		"line and paragraph breaks":     "Alice\u2028\u2029",
		"four-byte characters":          "Alice \U0001f600",
		"the longest name, all escaped": strings.Repeat("<", 128),
	}

	for name, registered := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pk := newPasskey(t)
			h := newHarness(t, fullEnv())

			status, body, account := register(t, h, &pk, registered, accepted())
			if status != http.StatusCreated {
				t.Fatalf("register finish = %d %s", status, body)
			}

			profile := account[0].Args[userArgProfile]
			signedIn := newSession(t, adminID)
			row := []any{memberID, roleMember, someID, profile, nil, int64(1_700_000_000)}

			h.expect(signedIn.activeKeyStep(roleAdmin), step{match: "FROM users", results: rows(row), err: nil})

			rec := h.do(request{method: http.MethodGet, path: "/api/user", cookies: []*http.Cookie{signedIn.cookie}})
			if rec.Code != http.StatusOK {
				t.Fatalf("list users = %d %s", rec.Code, rec.Body)
			}

			var listed struct {
				Users []struct {
					Profile struct {
						Name string `json:"name"`
					} `json:"profile"`
				} `json:"users"`
			}

			err := json.Unmarshal(rec.Body.Bytes(), &listed)
			if err != nil || len(listed.Users) != 1 {
				t.Fatalf("body %q: %v", rec.Body, err)
			}

			if got := listed.Users[0].Profile.Name; got != registered {
				t.Errorf("profile name = %q, want %q", got, registered)
			}
		})
	}
}

// checkAgentBatch checks the batch of an agent create: the agent of the
// signed-in owner and its api key, whose kid and expiry are the token's, with
// the types and sizes the schema accepts.
func checkAgentBatch(t *testing.T, batch []store.Statement, token string, expires int64) {
	t.Helper()

	if len(batch) != 2 {
		t.Fatalf("batch has %d statements, want the agent and its key", len(batch))
	}

	agent, key := batch[0].Args, batch[1].Args

	// agent: id, name, scopes, created_at, owner, limit. key: kid, agent id,
	// kind, jwk, expires_at, agent id, scope, created_at.
	if agent[4] != memberID || key[2] != store.KindAPIKey || key[1] != agent[0] || key[5] != agent[0] {
		t.Errorf("agent args = %v, key args = %v, want the signed-in owner and an api_key of the new agent", agent, key)
	}

	if key[0] != kidOfToken(t, token) || key[4] != expires {
		t.Errorf("key kid and expiry = %v, %v, want the token's %s and %d", key[0], key[4], kidOfToken(t, token), expires)
	}

	_, err := input.ParseID(asText(agent[0]))
	if !uuidV7.MatchString(asText(agent[0])) || err != nil {
		t.Errorf("agent id = %v, want a canonical UUIDv7 that the routes accept back: %v", agent[0], err)
	}

	checkFits(t, []fit{
		{"kid", `length\(kid\) = (\d+)`, key[0], true},
		{"jwk", `length\(jwk\) <= (\d+)`, key[3], false},
		{"kind", `length\(kind\) BETWEEN 1 AND (\d+)`, key[2], false},
		{"scope", `length\(cast\(scope AS BLOB\)\) BETWEEN 1 AND (\d+)`, key[6], false},
		{"scopes", `length\(cast\(scopes AS BLOB\)\) BETWEEN 1 AND (\d+)`, agent[2], false},
	})
}

// TestAgentCreateWritesWhatTheSchemaAccepts crosses the agent create's batch
// with the real key creation: the agent and its key are written for the
// signed-in account with the types and sizes the schema accepts, and the token
// that comes back once is not accepted as a session, not even when the database
// were to answer a session read with the agent's own key.
func TestAgentCreateWritesWhatTheSchemaAccepts(t *testing.T) {
	t.Parallel()

	signedIn := newSession(t, memberID)
	h := newHarness(t, fullEnv(), signedIn.activeKeyStep(roleMember),
		step{match: "INSERT INTO agents", results: batchOf(2), err: nil})

	rec := h.do(request{
		method: http.MethodPost, path: "/api/agent", body: `{"name":"assistant"}`, cookies: []*http.Cookie{signedIn.cookie},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create agent = %d %s", rec.Code, rec.Body)
	}

	var created struct {
		Key struct {
			Token     string `json:"token"`
			ExpiresAt int64  `json:"expiresAt"`
		} `json:"key"`
	}

	err := json.Unmarshal(rec.Body.Bytes(), &created)
	if err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}

	checkAgentBatch(t, h.lastCall(), created.Key.Token, created.Key.ExpiresAt)

	batch := h.lastCall()
	key := batch[1].Args

	// The agent's token is not a session, whatever the database answers.
	agentKeyRow := []any{key[3], memberID, "", roleMember, key[4]}

	h.expect(step{match: readKey, results: rows(agentKeyRow), err: nil})

	rec = h.do(request{
		method: http.MethodGet, path: pathSession, cookies: []*http.Cookie{requestCookie(auth.CookieName, created.Key.Token)},
	})
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
		t.Errorf("an api key as a session = %d %s, want the one 401", rec.Code, rec.Body)
	}
}
