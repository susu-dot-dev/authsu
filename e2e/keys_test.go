//go:build e2e

//nolint:goconst,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// keys_test.go drives /api/key against the real Worker: the TinyGo wasm, the
// real D1 driver and the real SQLite the migrations created. The unit tests
// fake the database, so this file proves what only the real build can:
//
//   - the exact response and stored rows of a create (the key's secret and its
//     own row), that the token is shaped as an API key, stored nowhere but as
//     its hash, and is accepted as the user's own bearer with the scopes and
//     lifetime it was given;
//   - the name, scope and lifetime bounds through the real SQLite CHECKs, and
//     that a name is stored exactly as it was sent;
//   - the per-user cap on active keys, counted in the write, under concurrency,
//     and that revoked and expired keys do not count;
//   - ownership confusion: another user's key, and an agent's key, are 404 on
//     every item route and absent from the list, with the stored rows untouched;
//   - that DELETE never ends the presented key, that revoking twice keeps the
//     first time, and that a revoked key is refused as a bearer at once.
//
// REVIEW.md categories covered: input edge cases (names, JSON shapes, lifetimes,
// query parameters), interleaving (create vs create at the cap, revoke vs
// revoke), payload size (name bounds, the 8 KiB body), permission confusion
// (owner scoping, agents, session-only issuing) and type/bound confusion (runes
// vs bytes, JSON vs Go vs SQLite).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	pathKey = "/api/key"

	keyBundleUser  = "default:user"
	keyCodeLimit   = "key_limit_reached"
	keyCodeMissing = "key_not_found"
	keyCodeBadName = "invalid_key_name"
	keyCodeLife    = "invalid_key_lifetime"
	keyCodeStale   = "key_inactive"

	// keyMax is keys.MaxKeysPerUser.
	keyMax = 50
	// keyDay is a day in seconds, and keyDefaultDays and keyMaxDays the default
	// and the longest lifetime a user may choose.
	keyDay         = 24 * 3600
	keyDefaultDays = 90
	keyMaxDays     = 365

	keyIDPrefix = "0c00" // idN family of keys seeded by this file
)

// kView is the JSON view of a key.
type kView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	Status    string   `json:"status"`
	ExpiresAt int64    `json:"expiresAt"`
	RevokedAt *int64   `json:"revokedAt"`
	CreatedAt int64    `json:"createdAt"`
}

// kCreated is the body of a successful create.
type kCreated struct {
	kView

	Token string `json:"token"`
}

// kPage is the body of a list.
type kPage struct {
	Keys []kView `json:"keys"`
	Next string  `json:"next"`
}

func kDecode[T any](t *testing.T, r reply) T {
	t.Helper()

	var out T

	err := json.Unmarshal([]byte(r.body), &out)
	if err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}

	return out
}

func kItem(id string) string { return pathKey + "/" + id }

// kCreate posts a create with the raw JSON body.
func kCreate(t *testing.T, token, body string) reply {
	t.Helper()

	return post(t, pathKey, []byte(body), token)
}

// kNamed is {"name": <name>} with name JSON-encoded.
func kNamed(t *testing.T, name string) string {
	t.Helper()

	return `{"name":` + string(mustJSON(t, name)) + `}`
}

func kMustCreate(t *testing.T, token, body string) kCreated {
	t.Helper()

	got := kCreate(t, token, body)
	if got.status != http.StatusCreated {
		t.Fatalf("create %s = %d %s, want 201", body, got.status, got.body)
	}

	return kDecode[kCreated](t, got)
}

// kRow reads a key as "user_id|agent_id|name|scope|expires_at|revoked_at".
func kRow(t *testing.T, id string) string {
	t.Helper()

	return scalar(t, "SELECT k.user_id||'|'||ifnull(k.agent_id,'NULL')||'|'||k.name||'|'||k.scope||'|'||"+
		"s.expires_at||'|'||ifnull(s.revoked_at,'NULL') FROM "+keyRows+" AND s.kind = k.kind WHERE k.id = ?", id)
}

// kActive is how many active keys of their own the user has.
func kActive(t *testing.T, owner string) string {
	t.Helper()

	return count(t, keyRows+" AND s.kind = k.kind WHERE k.user_id = ? AND k.agent_id IS NULL "+
		"AND s.revoked_at IS NULL AND s.expires_at > strftime('%s','now')", owner)
}

// kSeedMany inserts n active keys of their own for owner, ids idN(keyIDPrefix, from..).
func kSeedMany(t *testing.T, owner string, from, n int) {
	t.Helper()

	for i := range n {
		seedAPIKey(t, idN(keyIDPrefix, from+i), owner, "")
	}
}

// ---- access ----------------------------------------------------------------

// TestKeyRoutesNeedACredential: signed out is 401 on all five routes and writes
// nothing; any role may use them, since a key is something every user has.
//
//nolint:paralleltest // shares one database
func TestKeyRoutesNeedACredential(t *testing.T) {
	world := agNewPair(t, roleMember)
	seedAPIKey(t, idN(keyIDPrefix, 1), world.a.userID, "")

	routes := []struct {
		name, method, path string
		body               []byte
	}{
		{"list", http.MethodGet, pathKey, nil},
		{"create", http.MethodPost, pathKey, []byte(`{"name":"x"}`)},
		{"get", http.MethodGet, kItem(idN(keyIDPrefix, 1)), nil},
		{"rename", http.MethodPatch, kItem(idN(keyIDPrefix, 1)), []byte(`{"name":"x"}`)},
		{"revoke", http.MethodDelete, kItem(idN(keyIDPrefix, 1)), nil},
	}

	for _, rt := range routes {
		t.Run("signed out "+rt.name, func(t *testing.T) {
			send(t, request{method: rt.method, path: rt.path, body: rt.body}).
				expect(t, rt.name, http.StatusUnauthorized, codeUnauthenticated)
		})
	}

	expectCount(t, "api_keys WHERE name <> 'seeded'", "0")
	expectCount(t, "secrets WHERE revoked_at IS NOT NULL", "0")

	for _, role := range []string{roleAdmin, roleMember, "x", strings.Repeat("r", 64)} {
		t.Run("role "+role[:1], func(t *testing.T) {
			setRole(t, world.b.userID, role)
			get(t, pathKey, world.tokenB).expect(t, "list as "+role, http.StatusOK, "")
			kCreate(t, world.tokenB, kNamed(t, "by "+role[:1])).expect(t, "create as "+role, http.StatusCreated, "")
		})
	}
}

// TestKeyIssuingNeedsASession: a key, even one that holds every scope, cannot
// issue keys: the request is 403 and writes nothing. An agent's key is refused
// for the same reason. Both can still list.
//
//nolint:paralleltest // shares one database
func TestKeyIssuingNeedsASession(t *testing.T) {
	world := agNewPair(t, roleMember)
	created := kMustCreate(t, world.tokenB, `{"name":"holder","scopes":["default:session"]}`)

	before := count(t, "api_keys")

	got := send(t, request{method: http.MethodPost, path: pathKey, body: []byte(`{"name":"child"}`), bearer: created.Token})
	got.expect(t, "a key issuing a key", http.StatusForbidden, codeForbidden)
	expectCount(t, "api_keys", before)

	send(t, request{method: http.MethodGet, path: pathKey, bearer: created.Token}).
		expect(t, "a key listing", http.StatusOK, "")

	// An agent of the same user, with every scope on both its row and its key.
	seedAgent(t, idAgentA, world.b.userID, "bot")
	agentToken := seedAPIKey(t, idN(keyIDPrefix, 90), world.b.userID, idAgentA)
	seed(t, "UPDATE agents SET scopes = '[\"default:session\"]' WHERE id = ?", idAgentA)
	seed(t, "UPDATE api_keys SET scope = '[\"default:session\"]' WHERE id = ?", idN(keyIDPrefix, 90))

	// The seeded agent key is the one new row; issuing adds no other.
	withAgent := count(t, "api_keys")

	send(t, request{method: http.MethodPost, path: pathKey, body: []byte(`{"name":"child"}`), bearer: agentToken}).
		expect(t, "an agent issuing a key", http.StatusForbidden, codeForbidden)
	expectCount(t, "api_keys", withAgent)
}

// ---- create ----------------------------------------------------------------

// TestKeyCreateStoresExactlyWhatItReturns: the exact response, the secret and
// api_keys rows and the token's shape; the token is stored nowhere, is accepted
// as the user's own bearer with the scopes it was given, and is not a session.
//
//nolint:paralleltest // shares one database
func TestKeyCreateStoresExactlyWhatItReturns(t *testing.T) {
	world := agNewPair(t, roleMember)
	before := time.Now().Unix()
	raw := kCreate(t, world.tokenB, `{"name":"ci","scopes":["key:read","agent:read"]}`)
	after := time.Now().Unix()

	raw.expect(t, "create", http.StatusCreated, "")

	if raw.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (the body holds a bearer token)", raw.header.Get("Cache-Control"))
	}

	created := kDecode[kCreated](t, raw)

	expectToken(t, created.Token, tagAPIKey)
	expectStoredNowhere(t, created.Token)
	expectNoOrphanSecrets(t)

	if created.Name != "ci" || created.Status != "active" || !slices.Equal(created.Scopes, []string{"key:read", "agent:read"}) ||
		created.RevokedAt != nil {
		t.Errorf("response = %+v", created)
	}

	if created.CreatedAt < before || created.CreatedAt > after ||
		created.ExpiresAt != created.CreatedAt+keyDefaultDays*keyDay {
		t.Errorf("createdAt = %d, expiresAt = %d, want a creation in [%d, %d] and 90 days after it",
			created.CreatedAt, created.ExpiresAt, before, after)
	}

	stored := mustSecretOf(t, created.Token)
	if stored.id != created.ID || stored.kind != kindAPIKey || !stored.kindRow ||
		stored.expiresAt != created.ExpiresAt || stored.createdAt != created.CreatedAt || stored.revoked {
		t.Errorf("secret = %+v, want the key's own, kept, unrevoked, with the reported times", stored)
	}

	want := world.b.userID + "|NULL|ci|[\"key:read\",\"agent:read\"]|" + strconv.FormatInt(created.ExpiresAt, 10) + "|NULL"
	if got := kRow(t, created.ID); got != want {
		t.Errorf("row = %q, want %q", got, want)
	}

	// Accepted as the user's own bearer, and only as one.
	send(t, request{method: http.MethodGet, path: pathKey, bearer: created.Token}).
		expect(t, "the new key as a bearer", http.StatusOK, "")
	send(t, request{method: http.MethodGet, path: pathKey, token: created.Token}).
		expect(t, "the new key as a session", http.StatusUnauthorized, codeUnauthenticated)
	send(t, request{method: http.MethodGet, path: pathKey, bearer: world.tokenB}).
		expect(t, "a session as a bearer", http.StatusUnauthorized, codeUnauthenticated)

	// The key was given key:read and agent:read, and nothing else: it cannot rename.
	send(t, request{method: http.MethodPatch, path: kItem(created.ID), body: []byte(`{"name":"x"}`), bearer: created.Token}).
		expect(t, "a scope the key lacks", http.StatusForbidden, "insufficient_scope")
}

// TestKeyCreateDefaults: no scope list is the default user bundle, written out
// in full; an empty list stays empty and is a key that can use only the routes
// that need no scope; no lifetime is 90 days.
//
//nolint:paralleltest // shares one database
func TestKeyCreateDefaults(t *testing.T) {
	world := agNewPair(t, roleMember)

	defaulted := kMustCreate(t, world.tokenB, `{"name":"a"}`)
	if !slices.Equal(defaulted.Scopes, []string{keyBundleUser}) {
		t.Errorf("default scopes = %v, want %s", defaulted.Scopes, keyBundleUser)
	}

	if got := scalar(t, "SELECT scope FROM api_keys WHERE id = ?", defaulted.ID); got != `["default:user"]` {
		t.Errorf("stored scope = %q, want the bundle written out in full", got)
	}

	empty := kMustCreate(t, world.tokenB, `{"name":"b","scopes":[]}`)
	if empty.Scopes == nil || len(empty.Scopes) != 0 || scalar(t, "SELECT scope FROM api_keys WHERE id = ?", empty.ID) != "[]" {
		t.Errorf("an empty list came back as %v", empty.Scopes)
	}

	// With no scopes at all, even listing keys is refused, and logout is not.
	send(t, request{method: http.MethodGet, path: pathKey, bearer: empty.Token}).
		expect(t, "a scopeless key listing", http.StatusForbidden, "insufficient_scope")
	send(t, request{method: http.MethodPost, path: pathLogout, bearer: empty.Token}).
		expect(t, "a scopeless key logging out", http.StatusNoContent, "")
	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NOT NULL", "1", empty.ID)
}

// TestKeyCreateLifetimes: a lifetime of whole days from 1 to 365 is that many
// days, and is the expiry stored; anything else is a 400 and writes nothing.
//
//nolint:paralleltest // shares one database
func TestKeyCreateLifetimes(t *testing.T) {
	world := agNewPair(t, roleMember)

	for _, days := range []int{1, 2, keyDefaultDays, keyMaxDays - 1, keyMaxDays} {
		created := kMustCreate(t, world.tokenB, fmt.Sprintf(`{"name":"d%d","lifetimeDays":%d}`, days, days))
		if want := created.CreatedAt + int64(days)*keyDay; created.ExpiresAt != want || mustSecretOf(t, created.Token).expiresAt != want {
			t.Errorf("%d days: expiresAt = %d, want %d", days, created.ExpiresAt, want)
		}
	}

	before := count(t, "api_keys")

	for _, body := range []string{
		`{"name":"x","lifetimeDays":0}`, `{"name":"x","lifetimeDays":-1}`, `{"name":"x","lifetimeDays":366}`,
		`{"name":"x","lifetimeDays":4294967296}`, `{"name":"x","lifetimeDays":4294967297}`,
		`{"name":"x","lifetimeDays":99999999999999999999}`,
	} {
		got := kCreate(t, world.tokenB, body)
		if got.status != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", body, got.status, got.body)
		}
	}

	for _, body := range []string{
		`{"name":"x","lifetimeDays":1.5}`, `{"name":"x","lifetimeDays":"90"}`, `{"name":"x","lifetimeDays":1e2}`,
		`{"name":"x","lifetime":90}`, `{"name":"x","expiresAt":1}`,
	} {
		got := kCreate(t, world.tokenB, body)
		if got.status != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", body, got.status, got.body)
		}
	}

	expectCount(t, "api_keys", before)
}

// TestKeyCreateRefusesBadScopes: a list that names anything but known scopes and
// bundles is refused whole, before anything is written.
//
//nolint:paralleltest // shares one database
func TestKeyCreateRefusesBadScopes(t *testing.T) {
	world := agNewPair(t, roleMember)
	before := count(t, "api_keys")

	for _, list := range []string{
		`["agent:reed"]`, `["nope:read"]`, `["default:admin"]`, `["all"]`, `["*"]`, `[""]`,
		`["agent:read","agent:read"]`, `["agent:read agent:create"]`, `["AGENT:READ"]`, `[" agent:read"]`,
		`["agent:read\u0000"]`, `[1]`, `[null]`, `"agent:read"`, `{}`,
	} {
		got := kCreate(t, world.tokenB, `{"name":"x","scopes":`+list+`}`)
		if got.status != http.StatusBadRequest {
			t.Errorf("scopes %s = %d %s, want 400", list, got.status, got.body)
		}
	}

	expectCount(t, "api_keys", before)
	expectNoOrphanSecrets(t)
}

// TestKeyAdminScopesNeedTheRole: a member may list an admin scope on a key, and
// the key gains nothing from it: the role gates every admin scope whatever a
// token says. The scope is latent, and works if the user is promoted.
//
//nolint:paralleltest // shares one database
func TestKeyAdminScopesNeedTheRole(t *testing.T) {
	world := agNewPair(t, roleMember)
	created := kMustCreate(t, world.tokenB, `{"name":"wishful","scopes":["user:read","key:read"]}`)

	send(t, request{method: http.MethodGet, path: pathUser, bearer: created.Token}).
		expect(t, "a member's key with user:read", http.StatusForbidden, codeForbidden)

	setRole(t, world.b.userID, roleAdmin)
	send(t, request{method: http.MethodGet, path: pathUser, bearer: created.Token}).
		expect(t, "the same key after promotion", http.StatusOK, "")

	setRole(t, world.b.userID, roleMember)
	send(t, request{method: http.MethodGet, path: pathUser, bearer: created.Token}).
		expect(t, "the same key after demotion", http.StatusForbidden, codeForbidden)
}

// TestKeyCreateNames: names go through the real SQLite CHECK. The longest name
// the parser allows (256 four-byte characters, 1024 bytes) is stored exactly as
// sent, byte for byte; one more is refused by the parser; and text a name may
// not hold is refused and writes nothing.
//
//nolint:paralleltest // shares one database
func TestKeyCreateNames(t *testing.T) {
	world := agNewPair(t, roleMember)

	accepted := []string{
		"a", "deploy key", "  padded  ", `a "b" <c> & 'd' \ e`, "key \U0001F511", "'; DROP TABLE api_keys; --",
		"caf\u00e9", strings.Repeat("a", 256), strings.Repeat("\U0001F600", 256),
	}

	for _, name := range accepted {
		created := kMustCreate(t, world.tokenB, kNamed(t, name))
		if created.Name != name || scalar(t, "SELECT hex(CAST(name AS BLOB)) FROM api_keys WHERE id = ?", created.ID) != agHex(name) {
			t.Errorf("name %.40q was not stored exactly as sent", name)
		}
	}

	before := count(t, "api_keys")

	for _, name := range []string{
		"", "   ", "\u00a0", "a\tb", "a\nb", "a\x00b", "a\x7fb", "a\u0085b", "a\u200bb", "\u200d", "a\u202eb",
		"\ufeffa", "cafe\u0301", strings.Repeat("a", 257), strings.Repeat("\U0001F600", 257),
	} {
		got := kCreate(t, world.tokenB, kNamed(t, name))
		if got.status != http.StatusBadRequest {
			t.Errorf("name %.40q = %d %s, want 400", name, got.status, got.body)
		}
	}

	expectCount(t, "api_keys", before)
	expectNoOrphanSecrets(t)
}

// TestKeyCreateBodies: bodies that are not a request are refused before
// anything is written, and so are the sizes the cap refuses.
//
//nolint:paralleltest // shares one database
func TestKeyCreateBodies(t *testing.T) {
	world := agNewPair(t, roleMember)
	before := count(t, "api_keys")

	for _, body := range []string{
		"", "nope", `{"name":"a"`, `["a"]`, `{"name":1}`, `{}`, `{"name":null}`, `null`, `{"Name":"a"}`,
		`{"name":"a","extra":1}`, `{"name":"a","name":"b"}`, `{"name":"a"} {}`, "{\"name\":\"a\xffb\"}",
		`{"name":"a","userId":"` + world.a.userID + `"}`, `{"name":"a","agentId":"` + idAgentA + `"}`,
		`{"name":"a","scopes":"agent:read"}`,
	} {
		got := kCreate(t, world.tokenB, body)
		if got.status != http.StatusBadRequest {
			t.Errorf("body %.40q = %d %s, want 400", body, got.status, got.body)
		}
	}

	const maxBody = 8 << 10

	padded := func(size int) string {
		const head, tail = `{"name":"`, `"}`

		return head + strings.Repeat("a", size-len(head)-len(tail)) + tail
	}

	kCreate(t, world.tokenB, padded(maxBody)).expect(t, "a body at the cap", http.StatusBadRequest, codeBadKeyName())
	kCreate(t, world.tokenB, padded(maxBody+1)).expect(t, "a body over the cap", http.StatusRequestEntityTooLarge, codeBodyTooLarge)

	expectCount(t, "api_keys", before)
}

func codeBadKeyName() string { return keyCodeBadName }

// ---- the cap ---------------------------------------------------------------

// TestKeyCreateLimit: the 51st active key is a 409 whose batch leaves nothing
// behind; a revoked key and an expired one do not count, and another user's keys
// are not counted at all; an agent's keys are not the user's own and do not count.
//
//nolint:paralleltest // shares one database
func TestKeyCreateLimit(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	kSeedMany(t, owner, 1, keyMax)
	kSeedMany(t, world.a.userID, 1000, 5)

	expectCount(t, "api_keys WHERE user_id = ?", strconv.Itoa(keyMax), owner)

	secrets := count(t, "secrets")

	got := kCreate(t, world.tokenB, `{"name":"one too many"}`)
	got.expect(t, "the 51st key", http.StatusConflict, keyCodeLimit)

	expectCount(t, "api_keys WHERE user_id = ?", strconv.Itoa(keyMax), owner)
	expectCount(t, "secrets", secrets)
	expectNoOrphanSecrets(t)

	// Revoking one makes room for exactly one.
	del(t, kItem(idN(keyIDPrefix, 1)), world.tokenB).expect(t, "revoke one", http.StatusOK, "")
	kCreate(t, world.tokenB, `{"name":"fits"}`).expect(t, "after a revoke", http.StatusCreated, "")
	kCreate(t, world.tokenB, `{"name":"does not"}`).expect(t, "at the cap again", http.StatusConflict, keyCodeLimit)

	// An expired key does not count either.
	seed(t, "UPDATE secrets SET expires_at = strftime('%s','now') - 1 WHERE id = ?", idN(keyIDPrefix, 2))
	kCreate(t, world.tokenB, `{"name":"after an expiry"}`).expect(t, "after an expiry", http.StatusCreated, "")

	if got := kActive(t, owner); got != strconv.Itoa(keyMax) {
		t.Errorf("active keys = %s, want %d", got, keyMax)
	}

	// An agent's keys are not the user's own, so they are not counted.
	seedAgent(t, idAgentA, owner, "bot")
	seedAPIKey(t, idN(keyIDPrefix, 900), owner, idAgentA)
	del(t, kItem(idN(keyIDPrefix, 3)), world.tokenB).expect(t, "revoke another", http.StatusOK, "")
	kCreate(t, world.tokenB, `{"name":"agent keys do not count"}`).expect(t, "with an agent key", http.StatusCreated, "")

	// The other user is unaffected by B's cap.
	kCreate(t, world.tokenA, `{"name":"a's"}`).expect(t, "the other user", http.StatusCreated, "")
}

// TestKeyCreateRaceAtTheLimit: creates racing for the last places under the cap
// admit exactly as many as there is room for, the rest are 409, there is no 5xx,
// and no secret is left without its key.
//
//nolint:paralleltest // shares one database
func TestKeyCreateRaceAtTheLimit(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	const room, racers = 3, 12

	kSeedMany(t, owner, 1, keyMax-room)

	replies := agRelease(racers, func(i int) reply {
		return kCreate(t, world.tokenB, `{"name":"racer `+strconv.Itoa(i)+`"}`)
	})

	agNo5xx(t, "racing key creates", replies)

	tally := agTally(replies)
	if tally["201"] != room || tally["409 "+keyCodeLimit] != racers-room {
		t.Errorf("tally = %v, want %d created and %d at the limit", tally, room, racers-room)
	}

	expectCount(t, "api_keys WHERE user_id = ?", strconv.Itoa(keyMax), owner)
	expectNoOrphanSecrets(t)
}

// TestKeyCreateForARevokedOwner: a user revoked after signing in gets no key,
// not even a secret. The credential no longer resolves, so the request is
// refused at the boundary (401) before the write. The write's own guard
// (u.revoked_at IS NULL, which fails the batch whole) is a race with the
// revocation that cannot be made deterministic here; it is the same mechanism
// as the cap, which TestKeyCreateRaceAtTheLimit does exercise on real SQLite.
//
//nolint:paralleltest // shares one database
func TestKeyCreateForARevokedOwner(t *testing.T) {
	world := agNewPair(t, roleMember)

	seed(t, "UPDATE users SET revoked_at = strftime('%s','now') WHERE id = ?", world.b.userID)

	secrets := count(t, "secrets")

	got := kCreate(t, world.tokenB, `{"name":"x"}`)
	if got.status != http.StatusUnauthorized {
		t.Fatalf("create by a revoked account = %d %s, want 401", got.status, got.body)
	}

	expectCount(t, "secrets", secrets)
	expectNoOrphanSecrets(t)
}

// ---- reads -----------------------------------------------------------------

// TestKeyListsHoldOnlyTheCallersOwnKeys: a page is the caller's own keys,
// revoked and expired ones included with their status, newest first, and holds
// neither another user's nor an agent's, whatever the cursor.
//
//nolint:paralleltest // shares one database
func TestKeyListsHoldOnlyTheCallersOwnKeys(t *testing.T) {
	world := agNewPair(t, roleMember)

	mine := []string{idN(keyIDPrefix, 1), idN(keyIDPrefix, 2), idN(keyIDPrefix, 3), idN(keyIDPrefix, 4)}
	for _, id := range mine {
		seedAPIKey(t, id, world.b.userID, "")
	}

	seedAgent(t, idAgentA, world.b.userID, "bot")
	seedAPIKey(t, idN(keyIDPrefix, 50), world.b.userID, idAgentA)
	seedAPIKey(t, idN(keyIDPrefix, 60), world.a.userID, "")

	seed(t, "UPDATE secrets SET revoked_at = strftime('%s','now') - 10 WHERE id = ?", mine[1])
	seed(t, "UPDATE secrets SET expires_at = strftime('%s','now') - 10 WHERE id = ?", mine[2])

	page := kDecode[kPage](t, get(t, pathKey, world.tokenB))

	ids := make([]string, len(page.Keys))
	for i, key := range page.Keys {
		ids[i] = key.ID
	}

	want := []string{mine[3], mine[2], mine[1], mine[0]}
	if !slices.Equal(ids, want) || page.Next != "" {
		t.Fatalf("list = %v next %q, want %v and no next", ids, page.Next, want)
	}

	statuses := map[string]string{mine[0]: "active", mine[1]: "revoked", mine[2]: "expired", mine[3]: "active"}
	for _, key := range page.Keys {
		if key.Status != statuses[key.ID] || (key.Status == "revoked") != (key.RevokedAt != nil) {
			t.Errorf("key %s = %+v, want status %s", key.ID, key, statuses[key.ID])
		}
	}

	// A cursor at the other user's key still returns only B's own, below it.
	below := kDecode[kPage](t, get(t, pathKey+"?cursor="+idN(keyIDPrefix, 60), world.tokenB))
	if len(below.Keys) != len(mine) {
		t.Errorf("a cursor of another user's key returned %d keys, want %d", len(below.Keys), len(mine))
	}

	for _, body := range []string{get(t, pathKey, world.tokenB).body, get(t, kItem(mine[0]), world.tokenB).body} {
		// "agent" alone would match the scope default:agent the seeds carry: an
		// agent's key is shown by its id, and a key's agent by a member of its own.
		for _, forbidden := range []string{"hash", "susu_", "userId", "agentId", "agent_id", idN(keyIDPrefix, 50)} {
			if strings.Contains(body, forbidden) {
				t.Errorf("a read returned %q, which contains %q", body, forbidden)
			}
		}
	}
}

// TestKeyListWalk: following the cursors at every page size sees each key once,
// newest first, with a cursor on every page but the last.
//
//nolint:paralleltest // shares one database
func TestKeyListWalk(t *testing.T) {
	world := agNewPair(t, roleMember)

	const total = 7

	kSeedMany(t, world.b.userID, 1, total)

	for size := 1; size <= total+1; size++ {
		var seen []string

		cursor := ""

		for range total + 2 {
			path := fmt.Sprintf("%s?limit=%d", pathKey, size)
			if cursor != "" {
				path += "&cursor=" + cursor
			}

			page := kDecode[kPage](t, get(t, path, world.tokenB))
			for _, key := range page.Keys {
				seen = append(seen, key.ID)
			}

			if page.Next == "" {
				break
			}

			cursor = page.Next
		}

		if len(seen) != total {
			t.Errorf("size %d saw %d keys, want %d", size, len(seen), total)
		}

		for i := 1; i < len(seen); i++ {
			if seen[i-1] <= seen[i] {
				t.Errorf("size %d: %s is not before %s, want newest first", size, seen[i-1], seen[i])
			}
		}
	}

	for _, query := range []string{"?limit=0", "?limit=101", "?limit=1&limit=2", "?cursor=nope", "?cursor=g", "?cursor=" + idN(keyIDPrefix, 1) + "&cursor=" + idN(keyIDPrefix, 2)} {
		if got := get(t, pathKey+query, world.tokenB); got.status != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", query, got.status, got.body)
		}
	}
}

// ---- ownership -------------------------------------------------------------

// TestKeyOwnershipConfusion: another user's key, an agent's key and a key nobody
// has are one 404 on every item route, byte for byte, as a member and as an
// administrator, and nothing is changed. The control is the owner's own request.
//
//nolint:paralleltest // shares one database
func TestKeyOwnershipConfusion(t *testing.T) {
	world := agNewPair(t, roleMember)

	theirs := idN(keyIDPrefix, 1)
	agents := idN(keyIDPrefix, 2)

	seedAPIKey(t, theirs, world.a.userID, "")
	seedAgent(t, idAgentB, world.b.userID, "bot")
	seedAPIKey(t, agents, world.b.userID, idAgentB)

	snapshot := func() string {
		return scalar(t, "SELECT group_concat(k.id||k.name||ifnull(s.revoked_at,'N'), ',') FROM "+keyRows+" AND s.kind = k.kind ORDER BY k.id")
	}

	before := snapshot()

	type route struct {
		name, method string
		body         []byte
	}

	routes := []route{
		{"get", http.MethodGet, nil},
		{"rename", http.MethodPatch, []byte(`{"name":"hijacked"}`)},
		{"revoke", http.MethodDelete, nil},
	}

	for _, as := range []string{roleMember, roleAdmin} {
		setRole(t, world.b.userID, as)

		for _, rt := range routes {
			missing := send(t, request{method: rt.method, path: kItem(idMissing), body: rt.body, token: world.tokenB})
			missing.expect(t, rt.name+" of a missing key", http.StatusNotFound, keyCodeMissing)

			for name, id := range map[string]string{"another user's": theirs, "an agent's": agents} {
				got := send(t, request{method: rt.method, path: kItem(id), body: rt.body, token: world.tokenB})
				if got.status != missing.status || got.body != missing.body {
					t.Errorf("%s of %s key as %s = %d %s, want the missing key's %d %s",
						rt.name, name, as, got.status, got.body, missing.status, missing.body)
				}
			}
		}
	}

	if after := snapshot(); after != before {
		t.Errorf("keys changed:\nbefore %s\nafter  %s", before, after)
	}

	// The control: the owner's own requests work.
	get(t, kItem(theirs), world.tokenA).expect(t, "owner get", http.StatusOK, "")
	patch(t, kItem(theirs), []byte(`{"name":"mine"}`), world.tokenA).expect(t, "owner rename", http.StatusOK, "")
	del(t, kItem(theirs), world.tokenA).expect(t, "owner revoke", http.StatusOK, "")
}

// ---- rename ----------------------------------------------------------------

// TestKeyRename: the name changes and nothing else does; a revoked or expired
// key is a 409 and is not changed; the bounds are the create's.
//
//nolint:paralleltest // shares one database
func TestKeyRename(t *testing.T) {
	world := agNewPair(t, roleMember)
	created := kMustCreate(t, world.tokenB, `{"name":"old","scopes":["key:read"],"lifetimeDays":30}`)
	row := kRow(t, created.ID)

	got := patch(t, kItem(created.ID), []byte(`{"name":"new"}`), world.tokenB)
	got.expect(t, "rename", http.StatusOK, "")

	renamed := kDecode[kView](t, got)
	if renamed.Name != "new" || renamed.ID != created.ID || renamed.ExpiresAt != created.ExpiresAt ||
		!slices.Equal(renamed.Scopes, created.Scopes) || renamed.Status != "active" {
		t.Errorf("renamed = %+v, want only the name changed from %+v", renamed, created.kView)
	}

	if got := kRow(t, created.ID); got != strings.Replace(row, "|old|", "|new|", 1) {
		t.Errorf("row = %q, want only the name changed from %q", got, row)
	}

	for _, body := range []string{`{}`, `{"name":""}`, `{"name":null}`, `{"name":"a\u0000b"}`, `{"name":"x","scopes":["key:read"]}`,
		`{"name":"x","lifetimeDays":1}`, `{"name":"` + strings.Repeat("a", 257) + `"}`, ``} {
		patch(t, kItem(created.ID), []byte(body), world.tokenB).expect(t, "rename with "+body, http.StatusBadRequest, "")
	}

	if got := kRow(t, created.ID); !strings.Contains(got, "|new|") {
		t.Errorf("a refused rename changed the row to %q", got)
	}

	// Revoked: final.
	del(t, kItem(created.ID), world.tokenB).expect(t, "revoke", http.StatusOK, "")
	patch(t, kItem(created.ID), []byte(`{"name":"later"}`), world.tokenB).expect(t, "rename revoked", http.StatusConflict, keyCodeStale)

	// Expired: final as well.
	other := kMustCreate(t, world.tokenB, `{"name":"short"}`)
	seed(t, "UPDATE secrets SET expires_at = strftime('%s','now') - 1 WHERE id = ?", other.ID)
	patch(t, kItem(other.ID), []byte(`{"name":"later"}`), world.tokenB).expect(t, "rename expired", http.StatusConflict, keyCodeStale)

	if !strings.Contains(kRow(t, created.ID), "|new|") || !strings.Contains(kRow(t, other.ID), "|short|") {
		t.Error("a refused rename changed a stored name")
	}
}

// ---- revoke ----------------------------------------------------------------

// TestKeyRevoke: a revoked key is refused as a bearer at once, its rows stay,
// revoking twice succeeds and keeps the first time, and only that key ends.
//
//nolint:paralleltest // shares one database
func TestKeyRevoke(t *testing.T) {
	world := agNewPair(t, roleMember)
	target := kMustCreate(t, world.tokenB, `{"name":"target"}`)
	bystander := kMustCreate(t, world.tokenB, `{"name":"bystander"}`)

	send(t, request{method: http.MethodGet, path: pathKey, bearer: target.Token}).
		expect(t, "active", http.StatusOK, "")

	first := del(t, kItem(target.ID), world.tokenB)
	first.expect(t, "revoke", http.StatusOK, "")

	revoked := kDecode[kView](t, first)
	if revoked.Status != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("revoked = %+v, want revoked with a time", revoked)
	}

	if stored := mustSecretOf(t, target.Token); !stored.revoked || !stored.kindRow || stored.revokedAt != *revoked.RevokedAt {
		t.Errorf("secret = %+v, want kept, revoked at %d, with its api_keys row", stored, *revoked.RevokedAt)
	}

	send(t, request{method: http.MethodGet, path: pathKey, bearer: target.Token}).
		expect(t, "revoked as a bearer", http.StatusUnauthorized, codeUnauthenticated)

	// Again, later: the same answer and the first time.
	seed(t, "UPDATE secrets SET revoked_at = revoked_at - 100 WHERE id = ?", target.ID)

	second := kDecode[kView](t, del(t, kItem(target.ID), world.tokenB))
	if second.RevokedAt == nil || *second.RevokedAt != *revoked.RevokedAt-100 {
		t.Errorf("second revoke = %+v, want the earlier time %d kept", second, *revoked.RevokedAt-100)
	}

	// A revoked key is still listed and read, as revoked.
	got := kDecode[kView](t, get(t, kItem(target.ID), world.tokenB))
	if got.Status != "revoked" {
		t.Errorf("a revoked key reads as %q", got.Status)
	}

	// The bystander is untouched.
	send(t, request{method: http.MethodGet, path: pathKey, bearer: bystander.Token}).
		expect(t, "bystander", http.StatusOK, "")
}

// TestKeyRevokeAnExpiredKey: an expired key is revoked like any other, at the
// time the user ended it, and reads as revoked from then on.
//
//nolint:paralleltest // shares one database
func TestKeyRevokeAnExpiredKey(t *testing.T) {
	world := agNewPair(t, roleMember)
	expired := kMustCreate(t, world.tokenB, `{"name":"expired"}`)
	seed(t, "UPDATE secrets SET expires_at = strftime('%s','now') - 1 WHERE id = ?", expired.ID)

	got := del(t, kItem(expired.ID), world.tokenB)
	got.expect(t, "revoke an expired key", http.StatusOK, "")

	revoked := kDecode[kView](t, got)
	if revoked.Status != "revoked" || revoked.RevokedAt == nil {
		t.Errorf("revoked = %+v, want revoked with a time", revoked)
	}

	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NOT NULL", "1", expired.ID)
}

// TestKeyScheduledRevocation: a revocation set for later leaves the key active
// until then, everywhere: it still counts toward the cap, can still be renamed
// and reads as active, and a DELETE brings the revocation forward to now.
//
//nolint:paralleltest // shares one database
func TestKeyScheduledRevocation(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	kSeedMany(t, owner, 1, keyMax)
	seed(t, "UPDATE secrets SET revoked_at = strftime('%s','now') + 3600 WHERE id = ?", idN(keyIDPrefix, 1))

	// Still counted: the owner is at the cap.
	kCreate(t, world.tokenB, `{"name":"over"}`).expect(t, "at the cap", http.StatusConflict, keyCodeLimit)

	// Still active to read, and renamable.
	one := kDecode[kView](t, get(t, kItem(idN(keyIDPrefix, 1)), world.tokenB))
	if one.Status != "active" {
		t.Errorf("a key revoked for later reads as %q, want active", one.Status)
	}

	patch(t, kItem(idN(keyIDPrefix, 1)), []byte(`{"name":"still mine"}`), world.tokenB).
		expect(t, "rename", http.StatusOK, "")

	// DELETE brings the revocation forward to now.
	got := kDecode[kView](t, del(t, kItem(idN(keyIDPrefix, 1)), world.tokenB))
	if got.Status != "revoked" || got.RevokedAt == nil || *got.RevokedAt > time.Now().Unix()+5 {
		t.Errorf("revoked = %+v, want revoked at about now", got)
	}

	kCreate(t, world.tokenB, `{"name":"fits"}`).expect(t, "after the revoke", http.StatusCreated, "")
}

// TestKeyRevokeNeverEndsThePresentedKey: DELETE of the key a request is made
// with is a 404 and leaves it active, whatever its scopes, while the same key
// may revoke another of the user's keys. Ending the credential in use is logout.
//
//nolint:paralleltest // shares one database
func TestKeyRevokeNeverEndsThePresentedKey(t *testing.T) {
	world := agNewPair(t, roleMember)
	presented := kMustCreate(t, world.tokenB, `{"name":"presented"}`)
	other := kMustCreate(t, world.tokenB, `{"name":"other"}`)

	send(t, request{method: http.MethodDelete, path: kItem(presented.ID), bearer: presented.Token}).
		expect(t, "revoking the presented key", http.StatusNotFound, keyCodeMissing)
	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NULL", "1", presented.ID)

	send(t, request{method: http.MethodDelete, path: kItem(other.ID), bearer: presented.Token}).
		expect(t, "revoking another key", http.StatusOK, "")
	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NOT NULL", "1", other.ID)

	// The session may revoke the key it did not present, and logout still ends the key.
	send(t, request{method: http.MethodPost, path: pathLogout, bearer: presented.Token}).
		expect(t, "logout of the key", http.StatusNoContent, "")
	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NOT NULL", "1", presented.ID)
}

// TestKeyRevokeRaces: concurrent revokes of one key are all 200 with one
// revokedAt, and revoking while creating at the cap ends consistent.
//
//nolint:paralleltest // shares one database
func TestKeyRevokeRaces(t *testing.T) {
	world := agNewPair(t, roleMember)
	target := kMustCreate(t, world.tokenB, `{"name":"target"}`)

	replies := agRelease(8, func(int) reply { return del(t, kItem(target.ID), world.tokenB) })

	agNo5xx(t, "racing revokes", replies)

	times := map[int64]bool{}

	for _, r := range replies {
		if r.status != http.StatusOK {
			t.Errorf("racing revoke = %d %s, want 200", r.status, r.body)

			continue
		}

		view := kDecode[kView](t, r)
		if view.RevokedAt == nil {
			t.Errorf("racing revoke returned %+v, want a revocation time", view)

			continue
		}

		times[*view.RevokedAt] = true
	}

	stored := mustSecretOf(t, target.Token)
	if len(times) > 2 || !stored.revoked {
		t.Errorf("revocation times seen = %v, stored %+v, want the first time kept", times, stored)
	}

	// Revoke racing creates at the cap: no 5xx, and the count never exceeds the cap.
	kSeedMany(t, world.b.userID, 1, keyMax-1)

	mixed := agRelease(10, func(i int) reply {
		if i%2 == 0 {
			return kCreate(t, world.tokenB, `{"name":"racer `+strconv.Itoa(i)+`"}`)
		}

		return del(t, kItem(idN(keyIDPrefix, 1+i)), world.tokenB)
	})

	agNo5xx(t, "creates racing revokes", mixed)

	if got := kActive(t, world.b.userID); parseInt(t, got) > keyMax {
		t.Errorf("active keys = %s, want at most %d", got, keyMax)
	}

	expectNoOrphanSecrets(t)
}

// TestRevokingAUserRevokesTheirKeys: revoking an account ends every key it
// holds, and the keys stay listed.
//
//nolint:paralleltest // shares one database
func TestRevokingAUserEndsTheirKeys(t *testing.T) {
	world := agNewPair(t, roleMember)
	created := kMustCreate(t, world.tokenB, `{"name":"k"}`)

	send(t, request{method: http.MethodGet, path: pathKey, bearer: created.Token}).expect(t, "before", http.StatusOK, "")

	del(t, pathUser+"/"+world.b.userID, world.tokenA).expect(t, "revoke the user", http.StatusOK, "")

	send(t, request{method: http.MethodGet, path: pathKey, bearer: created.Token}).
		expect(t, "after", http.StatusUnauthorized, codeUnauthenticated)
	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NOT NULL", "1", created.ID)
}

// ---- boundary --------------------------------------------------------------

// TestKeyRouteMethods: the collection answers GET and POST, a key answers GET,
// PATCH and DELETE, and everything else is refused with the Allow header.
//
//nolint:paralleltest // shares one database
func TestKeyRouteMethods(t *testing.T) {
	world := agNewPair(t, roleMember)

	tests := []struct {
		method, path, allow string
	}{
		{http.MethodPut, pathKey, "GET, POST"},
		{http.MethodDelete, pathKey, "GET, POST"},
		{http.MethodPost, kItem(idMissing), "DELETE, GET, PATCH"},
		{http.MethodPut, kItem(idMissing), "DELETE, GET, PATCH"},
	}

	for _, tt := range tests {
		got := send(t, request{method: tt.method, path: tt.path, token: world.tokenB})
		if got.status != http.StatusMethodNotAllowed || got.header.Get("Allow") != tt.allow {
			t.Errorf("%s %s = %d (Allow %q), want 405 with %q", tt.method, tt.path, got.status, got.header.Get("Allow"), tt.allow)
		}
	}

	for _, path := range []string{"/api/keys", pathKey + "/", kItem(idMissing) + "/token"} {
		got := send(t, request{method: http.MethodGet, path: path, token: world.tokenB})
		if got.status != http.StatusNotFound {
			t.Errorf("GET %s = %d %s, want 404", path, got.status, got.body)
		}
	}

	for _, bad := range []string{"nope", strings.ToUpper(idMissing), idMissing + "0"} {
		get(t, kItem(bad), world.tokenB).expect(t, "get "+bad, http.StatusBadRequest, codeInvalidID)
	}

	// A form content type is refused before the body is read, and a key is untouched.
	got := send(t, request{method: http.MethodPost, path: pathKey, body: []byte(`{"name":"x"}`), token: world.tokenB,
		headers: map[string]string{"Content-Type": "text/plain"}})
	got.expect(t, "a form post", http.StatusUnsupportedMediaType, codeUnsupportedType)
}
