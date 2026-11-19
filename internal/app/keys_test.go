//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package app_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Where the values are in the statements of a user key create (see
// store.CreateKey): the key's secret insert (laid out as for a login), then the
// key's own row, which takes its owner from a subselect on users.
const (
	userKeyArgID      = 0
	userKeyArgKind    = 1
	userKeyArgName    = 2
	userKeyArgScope   = 3
	userKeyArgMax     = 4
	userKeyArgNow     = 5
	userKeyArgOwner   = 6
	keyPathCollection = "/api/key"
)

// createdKey is what the app returned for a key create.
type createdKey struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	Status    string   `json:"status"`
	ExpiresAt int64    `json:"expiresAt"`
	CreatedAt int64    `json:"createdAt"`
	Token     string   `json:"token"`
}

// createKeyAs creates a key as the signed-in member through the real stack and
// returns the response and the two statements of the batch the app wrote.
func createKeyAs(t *testing.T, body string) (createdKey, []store.Statement) {
	t.Helper()

	signedIn := newSession(t, memberID)
	h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleMember),
		step{match: "INSERT INTO secrets", results: batchOf(2), err: nil})

	rec := h.do(request{
		method: http.MethodPost, path: keyPathCollection, body: body, cookies: []*http.Cookie{signedIn.cookie},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create key = %d %s", rec.Code, rec.Body)
	}

	var created createdKey

	err := json.Unmarshal(rec.Body.Bytes(), &created)
	if err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}

	return created, h.lastCall()
}

// TestKeyCreateWritesWhatTheSchemaAccepts crosses the key create's batch with the
// real key issuing: the secret and the key's own row are written for the
// signed-in account with the types and sizes the schema accepts, the hash is the
// token's, the expiry is the one reported, the kind is bound and never written as
// a literal, and the account is a subselect argument and not the key's column.
func TestKeyCreateWritesWhatTheSchemaAccepts(t *testing.T) {
	t.Parallel()

	created, batch := createKeyAs(t, `{"name":"deploy","scopes":["key:read"],"lifetimeDays":30}`)

	if len(batch) != 2 {
		t.Fatalf("batch has %d statements, want the secret and the key", len(batch))
	}

	secretArgs, key := batch[0].Args, batch[1].Args

	if key[userKeyArgOwner] != memberID || key[userKeyArgKind] != store.KindAPIKey ||
		secretArgs[secretArgKind] != store.KindAPIKey || key[userKeyArgID] != secretArgs[secretArgID] {
		t.Errorf("secret args = %v, key args = %v, want an api_key of the signed-in owner under one id", secretArgs, key)
	}

	checkKeySecret(t, secretArgs, created.Token, created.ExpiresAt)
	checkKeyValues(t, created, secretArgs, key)

	_, err := input.ParseID(asText(secretArgs[secretArgID]))
	if !uuidV7.MatchString(asText(secretArgs[secretArgID])) || err != nil {
		t.Errorf("id = %v, want a canonical UUIDv7 that the routes accept back: %v", secretArgs[secretArgID], err)
	}

	checkFits(t, []fit{
		{"hash", `length\(hash\) = (\d+)`, secretArgs[secretArgHash], true},
		{"kind", `length\(kind\) BETWEEN 1 AND (\d+)`, key[userKeyArgKind], false},
		{"scope", `length\(cast\(scope AS BLOB\)\) BETWEEN 1 AND (\d+)`, key[userKeyArgScope], false},
		// The key's name has its own CHECK, after agent_id and before scope.
		{"name", `CREATE TABLE api_keys .*? name TEXT NOT NULL CHECK \(typeof\(name\) = 'text' ` +
			`AND instr\(name, char\(0\)\) = 0 AND length\(cast\(name AS BLOB\)\) BETWEEN 1 AND (\d+)\)`,
			key[userKeyArgName], false},
	})
}

// checkKeyValues asserts the values the request chose reached the write and the
// response: the name, the scope text, the limit and the creation time, and an
// expiry of the lifetime asked for (30 days) from the creation time.
func checkKeyValues(t *testing.T, created createdKey, secretArgs, key []any) {
	t.Helper()

	if key[userKeyArgName] != "deploy" || key[userKeyArgScope] != `["key:read"]` ||
		key[userKeyArgMax] != int64(50) || key[userKeyArgNow] != secretArgs[secretArgCreated] {
		t.Errorf("key args = %v, want the name, the scope text, the limit and the creation time", key)
	}

	createdAt, _ := secretArgs[secretArgCreated].(int64)
	if want := createdAt + int64(30*24*time.Hour/time.Second); created.ExpiresAt != want {
		t.Errorf("expiresAt = %d, want %d (30 days from creation)", created.ExpiresAt, want)
	}

	if !slices.Equal(created.Scopes, []string{"key:read"}) || created.Status != "active" {
		t.Errorf("returned %+v", created)
	}
}

// TestKeyCreateIsNotAcceptedWithoutASession: issuing a key needs a passkey
// session. The same request with a bearer token, even one that holds every
// scope, is refused at the boundary and writes nothing: the only database call
// is the key's own lookup.
func TestKeyCreateIsNotAcceptedWithoutASession(t *testing.T) {
	t.Parallel()

	key := newAPIKey(t)
	h := newHarness(t, fullEnv(), key.keyStep(memberID, roleMember, "", "", `["default:session"]`))

	rec := h.do(request{method: http.MethodPost, path: keyPathCollection, body: `{"name":"x"}`, headers: key.headers})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"forbidden"`) {
		t.Errorf("a key issuing a key = %d %s, want 403 forbidden", rec.Code, rec.Body)
	}

	if got := h.exec.callCount(); got != 1 {
		t.Errorf("Exec calls = %d, want 1 (the key's lookup only)", got)
	}
}

// TestUserKeyIsAcceptedAsABearerWithTheScopesItWasGiven: a key created by the API
// is presented as a bearer token to a database that answers a lookup of that key
// with the row the create wrote. It lists keys with the scope it was given and
// cannot read agents, which it was not given.
func TestUserKeyIsAcceptedAsABearerWithTheScopesItWasGiven(t *testing.T) {
	t.Parallel()

	created, batch := createKeyAs(t, `{"name":"ci","scopes":["key:read"]}`)
	secretArgs, key := batch[0].Args, batch[1].Args

	// The row the database would return for the lookup: the key's id and expiry,
	// its owner, no agent, and its own scope.
	row := []any{
		secretArgs[secretArgID], memberID, roleMember, secretArgs[secretArgExpires], "", "", key[userKeyArgScope],
	}

	h := newHarness(t, fullEnv(),
		step{match: readAPIKey, results: rows(row), err: nil}, step{match: "FROM api_keys k", results: rows(), err: nil})
	wantBearer(t, h, request{method: http.MethodGet, path: keyPathCollection, headers: bearer(created.Token)},
		http.StatusOK, `{"keys":[]}`)

	read := h.exec.calls[0][0].Args
	if !slices.Equal(asBlob(read[0]), asBlob(secretArgs[secretArgHash])) {
		t.Errorf("lookup args = %v, want the hash the create stored", read)
	}

	// The list was for the key's owner.
	if args := h.exec.calls[1][0].Args; len(args) != 3 || args[0] != memberID {
		t.Errorf("key list args = %v, want the owner first", args)
	}

	// Reading agents needs agent:read, which the key was not given: refused at
	// the boundary, so the only call is the key's own lookup.
	h2 := newHarness(t, fullEnv(), step{match: readAPIKey, results: rows(row), err: nil})
	wantBearer(t, h2, request{method: http.MethodGet, path: "/api/agent", headers: bearer(created.Token)},
		http.StatusForbidden, "insufficient_scope")

	if got := h2.exec.callCount(); got != 1 {
		t.Errorf("Exec calls = %d, want 1", got)
	}
}

// TestKeyRevokeSparesThePresentedKey: through the real SQL, the revoke binds the
// time, the key to end, the owner and the secret the request presented, in the
// order the statements number them, and the closing read binds the same ids.
func TestKeyRevokeSparesThePresentedKey(t *testing.T) {
	t.Parallel()

	signedIn := newSession(t, memberID)
	target := "00000000-0000-7000-8000-0000000000e1"
	revokedRow := []any{target, "ci", `["default:user"]`, int64(4_102_444_800), int64(1_700_000_000), int64(1_600_000_000)}
	results := []store.Result{{Changes: 1, Rows: nil}, {Changes: 0, Rows: [][]any{revokedRow}}}

	h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleMember),
		step{match: "UPDATE secrets", results: results, err: nil})

	rec := h.do(request{
		method: http.MethodDelete, path: keyPathCollection + "/" + target, cookies: []*http.Cookie{signedIn.cookie},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}

	batch := h.lastCall()
	if len(batch) != 2 {
		t.Fatalf("batch has %d statements, want the revoke and the read", len(batch))
	}

	// The revoke binds the time first; the rest, and the read, are these three.
	want := []any{target, memberID, signedIn.issued.ID}

	if !slices.Equal(batch[0].Args[1:], want) || !slices.Equal(batch[1].Args, want) {
		t.Errorf("revoke args = %v and read args = %v, want the key, the owner and the presented session after the time",
			batch[0].Args, batch[1].Args)
	}
}

// TestKeyRowSeam: the key rows D1 hands back are trusted only in the exact shape
// the query promises. Every row the JS side could produce but must never be
// believed (a float64 integer, NULL in a NOT NULL column, a blob for text, a
// short row) is a defect: a 500 with a bare "internal" and the real code in the
// log, never a key shown wrong.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestKeyRowSeam(t *testing.T) {
	t.Parallel()

	good := []any{
		"00000000-0000-7000-8000-0000000000e1", "ci", `["key:read"]`, int64(4_102_444_800), nil, int64(1_800_000_000),
	}

	with := func(at int, value any) []any {
		row := slices.Clone(good)
		row[at] = value

		return row
	}

	tests := map[string]struct {
		row        []any
		wantStatus int
		wantBody   string
		wantLogged []string
	}{
		"as D1 produces it": {row: good, wantStatus: http.StatusOK, wantBody: `"name":"ci"`},
		"revoked": {
			row: with(4, int64(1_700_000_000)), wantStatus: http.StatusOK, wantBody: `"status":"revoked"`,
		},
		"expires_at as float64": {
			row: with(3, float64(4_102_444_800)), wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeKeyLookupRejected},
		},
		"expires_at NULL": {
			row: with(3, nil), wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeKeyLookupRejected},
		},
		"name as a blob": {
			row: with(1, []byte("ci")), wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeKeyLookupRejected},
		},
		"revoked_at as text": {
			row: with(4, "yesterday"), wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeKeyLookupRejected},
		},
		"created_at as float64": {
			row: with(5, 1.8e9), wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeKeyLookupRejected},
		},
		"a row too short": {
			row: good[:5], wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeKeyLookupRejected},
		},
		"a row too long": {
			row: append(slices.Clone(good), "extra"), wantStatus: http.StatusInternalServerError, wantBody: bodyInternal,
			wantLogged: []string{store.CodeKeyLookupRejected},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, memberID)
			h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleMember),
				step{match: "FROM api_keys k", results: rows(tt.row), err: nil})

			rec := h.do(request{
				method: http.MethodGet, path: keyPathCollection + "/" + asText(good[0]),
				cookies: []*http.Cookie{signedIn.cookie},
			})

			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("= %d %s, want %d containing %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if got := h.loggedCodes(); !slices.Equal(got, tt.wantLogged) {
				t.Errorf("logged codes = %v, want %v", got, tt.wantLogged)
			}
		})
	}
}

// TestKeyLifetimeCrossesTheSeam: the lifetimes a client may choose are exactly
// the ones that fit what a secret's expiry stores and the issuer accepts: the
// longest, a year, is issued, and one day more is refused as the client's input
// before any issuer is asked.
func TestKeyLifetimeCrossesTheSeam(t *testing.T) {
	t.Parallel()

	if auth.MaxUserKeyLifetime != time.Duration(input.MaxUserKeyLifetimeDays)*24*time.Hour {
		t.Fatalf("the issuer's longest %v and the parser's %d days differ",
			auth.MaxUserKeyLifetime, input.MaxUserKeyLifetimeDays)
	}

	created, _ := createKeyAs(t, `{"name":"long","lifetimeDays":365}`)
	if want := created.CreatedAt + int64(365*24*time.Hour/time.Second); created.ExpiresAt != want {
		t.Errorf("expiresAt = %d, want %d", created.ExpiresAt, want)
	}

	signedIn := newSession(t, memberID)
	h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleMember))

	rec := h.do(request{
		method: http.MethodPost, path: keyPathCollection, body: `{"name":"toolong","lifetimeDays":366}`,
		cookies: []*http.Cookie{signedIn.cookie},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_key_lifetime") {
		t.Errorf("366 days = %d %s, want 400 invalid_key_lifetime", rec.Code, rec.Body)
	}

	if got := h.exec.callCount(); got != 1 {
		t.Errorf("Exec calls = %d, want 1 (the session's lookup only)", got)
	}
}
