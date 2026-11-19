//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// agents_test.go drives /api/agent against the real Worker: the TinyGo wasm,
// the real D1 driver and the real SQLite the migrations created. The unit tests
// fake the database, so this file proves what only the real build can:
//
//   - the exact response and stored rows of a create (the agent, the key's
//     secret and the key's own row), that the token is shaped as an API key
//     and stored nowhere (only its hash), and that it resolves to the user with
//     the agent as actor;
//   - the byte/rune bounds of an agent name through the real SQLite CHECK, and
//     that a name is stored exactly as it was sent (refuse, never rewrite);
//   - the per-user cap of 25 and the "no key without an agent" batch, under
//     concurrency, against the real database;
//   - ownership confusion (another user's agent, an admin's reach), keyset
//     paging, and the idempotence and atomicity of revocation.
//
// REVIEW.md categories covered: input edge cases (names, JSON shapes, query
// parameters), interleaving (create vs create, create vs user revocation,
// rename vs revoke, revoke vs revoke), payload size (name bounds, the 1 MiB
// body), permission confusion (owner scoping, any role, a key as a session) and
// type/bound confusion (runes vs bytes, JSON vs Go vs SQLite).
//
// The full permission matrix of the routes is owned by another file: here only
// a spot check that any role may use them and that signed-out is 401.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// agScopes is the default agent bundle as stored: a JSON array.
	agScopes      = agentScope
	agBundleName  = "default:agent"
	agCodeLimit   = "agent_limit_reached"
	agCodeMissing = "agent_not_found"
	agCodeRevoked = "agent_revoked"
	agCodeBadName = "invalid_agent_name"
	agCodeNoName  = "missing_agent_change"
	agCodeLimitQ  = "invalid_limit"
	agCodeCursorQ = "invalid_cursor"

	// agMaxAgents is agents.MaxAgentsPerUser.
	agMaxAgents = 25
	// agNameRunes is input.MaxAgentNameRunes.
	agNameRunes = 256
	// agKeyLifetime is auth.AgentKeyLifetime in seconds (90 days).
	agKeyLifetime = 90 * 24 * 3600

	agIDPrefix = "0a00" // idN family of agents seeded by this file
	agKeyPref  = "0f00" // idN family of keys seeded by this file
)

// ---- views -----------------------------------------------------------------

// agView is the JSON view of an agent.
type agView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	Status    string   `json:"status"`
	RevokedAt *int64   `json:"revokedAt"`
	CreatedAt int64    `json:"createdAt"`
	Labels    []string `json:"labels"`
}

// agKey is the JSON view of a created key.
type agKey struct {
	ID        string   `json:"id"`
	Token     string   `json:"token"`
	Scopes    []string `json:"scopes"`
	ExpiresAt int64    `json:"expiresAt"`
}

// agCreated is the body of a successful create.
type agCreated struct {
	Agent agView `json:"agent"`
	Key   agKey  `json:"key"`
}

// agPage is the body of a list.
type agPage struct {
	Agents []agView `json:"agents"`
	Next   string   `json:"next"`
}

// agIsDefault reports whether scopes is exactly the default agent bundle.
func agIsDefault(scopes []string) bool { return len(scopes) == 1 && scopes[0] == agBundleName }

func agDecode[T any](t *testing.T, r reply) T {
	t.Helper()

	var out T

	err := json.Unmarshal([]byte(r.body), &out)
	if err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}

	return out
}

// agJSONName is the raw JSON body {"name": <name>} with name JSON-encoded.
func agJSONName(t *testing.T, name string) []byte {
	t.Helper()

	return []byte(`{"name":` + string(mustJSON(t, name)) + `}`)
}

// agCreate posts a create with a JSON-encoded name.
func agCreate(t *testing.T, token, name string) reply {
	t.Helper()

	return post(t, pathAgent, agJSONName(t, name), token)
}

func agMustCreate(t *testing.T, token, name string) agCreated {
	t.Helper()

	got := agCreate(t, token, name)
	if got.status != http.StatusCreated {
		t.Fatalf("create %q = %d %s, want 201", name, got.status, got.body)
	}

	return agDecode[agCreated](t, got)
}

func agItem(id string) string { return pathAgent + "/" + id }

// agSeedMany inserts n active agents of owner, ids idN(agIDPrefix, from..), each
// with a real api_key row. The Worker must be idle.
func agSeedMany(t *testing.T, owner string, from, n int) {
	t.Helper()

	for i := range n {
		id := idN(agIDPrefix, from+i)

		seedAgent(t, id, owner, "bulk-"+strconv.Itoa(from+i))
		seedAPIKey(t, idN(agKeyPref, from+i), owner, id)
	}
}

// agSeedMemberLogin seeds an account (role) with a passkey the test holds, so
// that login() works for it through the real endpoints. An invitation row must
// exist (newAdmin leaves the first-run one).
func agSeedMemberLogin(t *testing.T, id, role string) passkey {
	t.Helper()

	key := newKey(t)
	handle := randomBytes(16)
	credID := randomBytes(32)
	cose := coseES256(t, key.X.FillBytes(make([]byte, 32)), key.Y.FillBytes(make([]byte, 32)))

	seed(t, "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) "+
		"VALUES (?, ?, ?, (SELECT id FROM invitations LIMIT 1), '{\"name\":\"seeded\"}', strftime('%s','now'))",
		id, handle, role)
	seed(t, "INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at) "+
		"VALUES (?, ?, ?, ?, 5, '{}', strftime('%s','now'))", "c"+id[1:], credID, id, cose)

	return passkey{priv: key, credID: credID, handle: handle, userID: id}
}

// agPair is two signed-in users: admin A (the first administrator) and a second
// user B of the given role. Both sessions come from real logins.
type agPair struct {
	a, b           passkey
	tokenA, tokenB string
}

func agNewPair(t *testing.T, roleB string) agPair {
	t.Helper()

	adminKey := newAdmin(t)
	other := agSeedMemberLogin(t, idUserB, roleB)

	return agPair{a: adminKey, b: other, tokenA: login(t, adminKey), tokenB: login(t, other)}
}

// agRow reads one agents row as "user_id|name|scopes|revoked_at|created_at".
func agRow(t *testing.T, id string) string {
	t.Helper()

	return scalar(t, "SELECT user_id||'|'||name||'|'||scopes||'|'||ifnull(revoked_at,'NULL')||'|'||created_at "+
		"FROM agents WHERE id = ?", id)
}

// agNameInDB is the stored name of an agent, hex-encoded, so a byte-for-byte
// comparison is exact whatever the text.
func agNameHex(t *testing.T, id string) string {
	t.Helper()

	return scalar(t, "SELECT hex(CAST(name AS BLOB)) FROM agents WHERE id = ?", id)
}

func agHex(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }

func agActiveAgents(t *testing.T, owner string) string {
	t.Helper()

	return count(t, "agents WHERE user_id = ? AND revoked_at IS NULL", owner)
}

// agRelease starts n goroutines at once, each running fn(i), and returns their
// replies in order.
func agRelease(n int, fn func(i int) reply) []reply {
	out := make([]reply, n)
	start := make(chan struct{})

	var group sync.WaitGroup

	for i := range n {
		group.Go(func() {
			<-start

			out[i] = fn(i)
		})
	}

	close(start)
	group.Wait()

	return out
}

// agTally counts replies by "status code".
func agTally(replies []reply) map[string]int {
	out := map[string]int{}

	for _, r := range replies {
		key := strconv.Itoa(r.status)
		if code := r.errorCode(); code != "" {
			key += " " + code
		}

		out[key]++
	}

	return out
}

// agNo5xx fails the test on any 5xx reply.
func agNo5xx(t *testing.T, what string, replies []reply) {
	t.Helper()

	for _, r := range replies {
		if r.status >= http.StatusInternalServerError {
			t.Errorf("%s: %d %s, want no 5xx", what, r.status, r.body)
		}
	}
}

// ---- access ----------------------------------------------------------------

// TestAgentRoutesNeedASession: signed out is 401 on all five routes and writes
// nothing; any role, including one no route knows, may use them.
//
//nolint:paralleltest // shares one database
func TestAgentRoutesNeedASession(t *testing.T) {
	world := agNewPair(t, roleMember)
	seedAgent(t, idAgentA, world.a.userID, "mine")

	routes := []struct {
		name, method, path string
		body               []byte
	}{
		{"list", http.MethodGet, pathAgent, nil},
		{"create", http.MethodPost, pathAgent, []byte(`{"name":"x"}`)},
		{"get", http.MethodGet, agItem(idAgentA), nil},
		{"rename", http.MethodPatch, agItem(idAgentA), []byte(`{"name":"x"}`)},
		{"revoke", http.MethodDelete, agItem(idAgentA), nil},
	}

	for _, rt := range routes {
		t.Run("signed out "+rt.name, func(t *testing.T) {
			got := send(t, request{method: rt.method, path: rt.path, body: rt.body})
			got.expect(t, rt.name, http.StatusUnauthorized, codeUnauthenticated)
		})
	}

	expectCount(t, "agents WHERE name <> 'mine'", "0")
	expectCount(t, "agents WHERE revoked_at IS NOT NULL", "0")
	expectCount(t, "api_keys", "0")

	// Any role at all: an agent is something every user has.
	for _, role := range []string{roleAdmin, roleMember, "x", strings.Repeat("r", 64)} {
		t.Run("role "+role[:1], func(t *testing.T) {
			setRole(t, world.b.userID, role)
			get(t, pathAgent, world.tokenB).expect(t, "list as "+role, http.StatusOK, "")

			created := agCreate(t, world.tokenB, "by "+role[:1])
			created.expect(t, "create as "+role, http.StatusCreated, "")
		})
	}
}

// ---- create: happy path ----------------------------------------------------

// TestAgentCreateStoresExactlyWhatItReturns: the exact response, the agents
// row, the key's secret and api_keys rows and the token's shape; the token is
// stored nowhere and cannot be used as a session.
//
//nolint:paralleltest // shares one database
func TestAgentCreateStoresExactlyWhatItReturns(t *testing.T) {
	world := agNewPair(t, roleMember)
	before := time.Now().Unix()
	raw := agCreate(t, world.tokenB, "assistant")
	after := time.Now().Unix()

	raw.expect(t, "create", http.StatusCreated, "")

	if ctype := raw.header.Get("Content-Type"); !strings.HasPrefix(ctype, jsonType) {
		t.Errorf("Content-Type = %q, want JSON", ctype)
	}

	if raw.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (the body holds a bearer token)", raw.header.Get("Cache-Control"))
	}

	// The response has exactly these members and no others.
	var generic map[string]map[string]any

	err := json.Unmarshal([]byte(raw.body), &generic)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	wantAgentKeys := []string{"createdAt", "id", "labels", "name", "scopes", "status"}
	wantKeyKeys := []string{"expiresAt", "id", "scopes", "token"}

	if slices.Sorted(mapKeys(generic["agent"])) == nil || !slices.Equal(slices.Sorted(mapKeys(generic["agent"])), wantAgentKeys) {
		t.Errorf("agent members = %v, want %v", slices.Sorted(mapKeys(generic["agent"])), wantAgentKeys)
	}

	if !slices.Equal(slices.Sorted(mapKeys(generic["key"])), wantKeyKeys) {
		t.Errorf("key members = %v, want %v", slices.Sorted(mapKeys(generic["key"])), wantKeyKeys)
	}

	if len(generic) != 2 {
		t.Errorf("top-level members = %d, want agent and key only", len(generic))
	}

	created := agDecode[agCreated](t, raw)
	agent, key := created.Agent, created.Key

	if agent.Name != "assistant" || !agIsDefault(agent.Scopes) || agent.Status != "active" || agent.RevokedAt != nil {
		t.Errorf("agent = %+v, want an active assistant with %s and no revokedAt", agent, agScopes)
	}

	if agent.CreatedAt < before-1 || agent.CreatedAt > after+1 {
		t.Errorf("createdAt = %d, want within [%d, %d]", agent.CreatedAt, before, after)
	}

	if !agIsDefault(key.Scopes) || key.ExpiresAt != agent.CreatedAt+agKeyLifetime {
		t.Errorf("key = {scopes %q, expiresAt %d}, want %s and createdAt+90d = %d",
			key.Scopes, key.ExpiresAt, agScopes, agent.CreatedAt+agKeyLifetime)
	}

	if idErr := agWellFormedID(agent.ID); idErr != "" || agWellFormedID(key.ID) != "" {
		t.Errorf("ids %q %q are not canonical lower-case UUIDs: %s", agent.ID, key.ID, idErr)
	}

	// agents row.
	wantRow := world.b.userID + "|assistant|" + agScopes + "|NULL|" + strconv.FormatInt(agent.CreatedAt, 10)
	if got := agRow(t, agent.ID); got != wantRow {
		t.Errorf("agents row = %q, want %q", got, wantRow)
	}

	// api_keys row: a key of the user, tied to the agent, under the id the
	// response names.
	cols := scalar(t, "SELECT kind||'|'||user_id||'|'||agent_id||'|'||scope FROM api_keys WHERE id = ?", key.ID)
	wantCols := strings.Join([]string{kindAPIKey, world.b.userID, agent.ID, agScopes}, "|")

	if cols != wantCols {
		t.Errorf("api_keys row = %q, want %q", cols, wantCols)
	}

	agVerifyKeySecret(t, created)
	expectToken(t, key.Token, tagAPIKey)
	expectStoredNowhere(t, key.Token)

	// Exactly one agent and one api_key row exist for B.
	expectCount(t, "agents WHERE user_id = ?", "1", world.b.userID)
	expectCount(t, "api_keys", "1")
	expectNoOrphanSecrets(t)

	// The key is not a session: not accepted as the session cookie anywhere.
	agKeyIsNotACredential(t, world.tokenB, key.Token)

	// Reads never show the token again.
	for _, path := range []string{pathAgent, agItem(agent.ID)} {
		got := get(t, path, world.tokenB)
		got.expect(t, "GET "+path, http.StatusOK, "")

		if strings.Contains(got.body, key.Token) || strings.Contains(got.body, "token") || strings.Contains(got.body, key.ID) {
			t.Errorf("GET %s shows key material: %s", path, got.body)
		}
	}
}

func mapKeys[K comparable, V any](m map[K]V) func(func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// agWellFormedID returns "" for a canonical lower-case UUID.
func agWellFormedID(id string) string {
	if len(id) != 36 {
		return "length " + strconv.Itoa(len(id))
	}

	for i, c := range id {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return "dash expected at " + strconv.Itoa(i)
			}
		case (c < '0' || c > '9') && (c < 'a' || c > 'f'):
			return "bad character at " + strconv.Itoa(i)
		}
	}

	return ""
}

// agVerifyKeySecret checks the key's secret row against the response: the id
// is the key's, the hash is SHA-256 of the whole token, it is active for 90
// days from the agent's creation, and the secret has its api_keys row.
func agVerifyKeySecret(t *testing.T, created agCreated) {
	t.Helper()

	key := created.Key

	secret := mustSecretOf(t, key.Token)
	if secret.id != key.ID || secret.kind != kindAPIKey || !secret.kindRow {
		t.Errorf("secret of the token = %+v, want the key %s of kind api_key with its api_keys row", secret, key.ID)
	}

	if secret.revoked || secret.expiresAt != key.ExpiresAt || secret.createdAt != created.Agent.CreatedAt {
		t.Errorf("secret = %+v, want active, expiring at %d (the response), created at %d",
			secret, key.ExpiresAt, created.Agent.CreatedAt)
	}

	if got := scalar(t, "SELECT lower(hex(hash)) FROM secrets WHERE id = ?", key.ID); got != hex.EncodeToString(tokenHash(key.Token)) {
		t.Errorf("secrets.hash = %s, want sha256 of the whole token", got)
	}
}

// agKeyIsNotACredential: the API key is not a session cookie and no route
// accepts it as one; the real session still works.
func agKeyIsNotACredential(t *testing.T, session, key string) {
	t.Helper()

	routes := []struct{ method, path string }{
		{http.MethodGet, pathSession}, {http.MethodPost, pathLogout},
		{http.MethodGet, pathAgent}, {http.MethodPost, pathAgent},
		{http.MethodGet, pathInvitation}, {http.MethodGet, pathUser},
		{http.MethodDelete, agItem(idMissing)}, {http.MethodGet, agItem(idMissing)},
	}

	for _, rt := range routes {
		body := []byte(nil)
		if rt.method == http.MethodPost && rt.path == pathAgent {
			body = []byte(`{"name":"via key"}`)
		}

		got := send(t, request{method: rt.method, path: rt.path, body: body, token: key})
		got.expect(t, "key as session on "+rt.method+" "+rt.path, http.StatusUnauthorized, codeUnauthenticated)

		if len(got.setCookies) != 0 {
			t.Errorf("a refused key set cookies: %v", got.setCookies)
		}
	}

	// The carriers are not interchangeable the other way either: a session
	// token presented as a bearer is not an API key.
	got := send(t, request{method: http.MethodGet, path: pathAgent, bearer: session})
	got.expect(t, "session as bearer", http.StatusUnauthorized, codeUnauthenticated)

	get(t, pathSession, session).expect(t, "real session still works", http.StatusOK, "")
}

// ---- create: names ---------------------------------------------------------

// agNameCase is one request to POST /api/agent. When raw is not empty it is the
// exact body; otherwise the body is {"name": <name>} with name JSON-encoded.
type agNameCase struct {
	label string
	name  string
	raw   string
	// status and code are the expected outcome; code is "" for a 201.
	status int
	code   string
}

// body is the request body of the case.
func (c agNameCase) body(t *testing.T) []byte {
	t.Helper()

	if c.raw != "" {
		return []byte(c.raw)
	}

	return agJSONName(t, c.name)
}

func agRepeat(s string, n int) string { return strings.Repeat(s, n) }

// agOK is a name the parser accepts: it must be stored byte-for-byte.
func agOK(label, name string) agNameCase {
	return agNameCase{label: label, name: name, status: http.StatusCreated}
}

// agBadName is a name (sent as JSON-encoded text) that is refused.
func agBadName(label, name string) agNameCase {
	return agNameCase{label: label, name: name, status: http.StatusBadRequest, code: agCodeBadName}
}

// agBadRaw is a raw body refused with the given code.
func agBadRaw(label, raw, code string) agNameCase {
	return agNameCase{label: label, raw: raw, status: http.StatusBadRequest, code: code}
}

func agNameCases() []agNameCase {
	const (
		emoji4  = "\U0001F600" // 4 bytes, 1 rune
		twoByte = "\u00e9"     // NFC e-acute, 2 bytes
		thrByte = "\u4e2d"     // 3 bytes
	)

	accepted := []agNameCase{
		agOK("one char", "a"),
		agOK("inner spaces", "my  agent v2"),
		agOK("leading space is kept", " lead"),
		agOK("trailing space is kept", "trail "),
		agOK("256 ascii (rune bound)", agRepeat("a", agNameRunes)),
		agOK("256 two-byte runes (512 bytes)", agRepeat(twoByte, agNameRunes)),
		agOK("256 three-byte runes (768 bytes)", agRepeat(thrByte, agNameRunes)),
		agOK("256 four-byte emoji (1024 bytes: exactly the CHECK)", agRepeat(emoji4, agNameRunes)),
		agOK("255 emoji", agRepeat(emoji4, agNameRunes-1)),
		agOK("mixed scripts at 256 runes", agRepeat("a\u00e9\u4e2d\U0001F600", agNameRunes/4)),
		agOK("json-significant characters", `quote " backslash \ slash / < > & '`),
		agOK("html-ish", "<script>alert(1)</script>"),
		agOK("sql-ish", "'; DROP TABLE agents; --"),
		agOK("percent and escape lookalikes", `%00 \u0000 \n`),
		agOK("NFC precomposed accent", "caf\u00e9"),
		agOK("nbsp inside text (Zs)", "a\u00a0b"),
		agOK("private use (Co)", "a\ue000b"),
		agOK("line separator U+2028 (Zl)", "a\u2028b"),
		agOK("variation selector-16 (Mn)", "\u2764\ufe0f"),
		agOK("zero-width joiner U+200D", "a\u200db"),
		agOK("zero-width non-joiner U+200C", "a\u200cb"),
		agOK("ZWJ emoji sequence (family)", "\U0001F468\u200d\U0001F469\u200d\U0001F467"),
		agOK("Persian text with a ZWNJ", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645"),
		{label: "name spelled with a JSON escape", raw: `{"name":"caf\u00e9"}`, name: "caf\u00e9", status: http.StatusCreated},
	}

	refusedNames := []agNameCase{
		agBadName("empty", ""),
		agBadName("spaces only", "   "),
		agBadName("tab only", "\t"),
		agBadName("nbsp only", "\u00a0"),
		agBadName("ideographic space only", "\u3000"),
		agBadName("257 ascii", agRepeat("a", agNameRunes+1)),
		agBadName("257 four-byte emoji", agRepeat(emoji4, agNameRunes+1)),
		agBadName("5000 ascii", agRepeat("a", 5000)),
		agBadName("NUL", "a\x00b"),
		agBadName("only NUL", "\x00"),
		agBadName("NUL then 2000 chars (length() would stop at the NUL)", "a\x00"+agRepeat("b", 2000)),
		agBadName("C0 control U+0001", "a\x01b"),
		agBadName("newline", "a\nb"),
		agBadName("carriage return", "a\rb"),
		agBadName("tab inside", "a\tb"),
		agBadName("DEL", "a\x7fb"),
		agBadName("C1 control U+0085", "a\u0085b"),
		agBadName("escape U+001B", "a\x1bb"),
		agBadName("bidi override U+202E", "a\u202eb"),
		agBadName("bidi isolate U+2066", "a\u2066b"),
		agBadName("left-to-right mark U+200E", "a\u200eb"),
		agBadName("zero-width space U+200B", "a\u200bb"),
		agBadName("only joiners", "\u200d\u200c"),
		agBadName("word joiner U+2060", "a\u2060b"),
		agBadName("BOM U+FEFF", "\ufeffname"),
		agBadName("soft hyphen U+00AD", "a\u00adb"),
		agBadName("non-NFC e + combining acute", "cafe\u0301"),
		agBadName("non-NFC Angstrom sign", "\u212b"),
		agBadName("non-NFC Hangul jamo", "\u1100\u1161"),
		{label: "replacement character U+FFFD", name: "a\ufffdb", status: http.StatusBadRequest, code: "invalid_text"},
		agBadName("tag character U+E0041 (Cf)", "a\U000E0041b"),
	}

	shapes := []agNameCase{
		agBadRaw("empty object", `{}`, agCodeBadName),
		agBadRaw("name null", `{"name":null}`, agCodeBadName),
		agBadRaw("body null", `null`, agCodeBadName),
		agBadRaw("NUL by JSON escape", `{"name":"a\u0000b"}`, agCodeBadName),
		agBadRaw("NUL escape then 2000 bytes", `{"name":"a\u0000`+agRepeat("b", 2000)+`"}`, agCodeBadName),
		agBadRaw("empty body", `-`, "empty_body"),
		agBadRaw("array body", `[]`, "invalid_field_type"),
		agBadRaw("array of object", `[{"name":"a"}]`, "invalid_field_type"),
		agBadRaw("string body", `"a"`, "invalid_field_type"),
		agBadRaw("number body", `5`, "invalid_field_type"),
		agBadRaw("true body", `true`, "invalid_field_type"),
		agBadRaw("truncated object", `{"name":"a"`, "invalid_json"),
		agBadRaw("truncated string", `{"name":"a`, "invalid_json"),
		agBadRaw("single quotes", `{'name':'a'}`, "invalid_json"),
		agBadRaw("unquoted key", `{name:"a"}`, "invalid_json"),
		agBadRaw("trailing comma", `{"name":"a",}`, "invalid_json"),
		agBadRaw("name number", `{"name":5}`, "invalid_field_type"),
		agBadRaw("name float", `{"name":1.5}`, "invalid_field_type"),
		agBadRaw("name bool", `{"name":true}`, "invalid_field_type"),
		agBadRaw("name array", `{"name":["a"]}`, "invalid_field_type"),
		agBadRaw("name object", `{"name":{"v":"a"}}`, "invalid_field_type"),
		agBadRaw("trailing garbage", `{"name":"a"} x`, "trailing_data"),
		agBadRaw("two objects", `{"name":"a"}{"name":"b"}`, "trailing_data"),
		agBadRaw("trailing comma after value", `{"name":"a"},`, "trailing_data"),
		agBadRaw("duplicate name", `{"name":"a","name":"b"}`, "duplicate_field"),
		agBadRaw("duplicate name by escaped spelling", `{"name":"a","n\u0061me":"b"}`, "duplicate_field"),
		agBadRaw("different case key", `{"Name":"a"}`, "unknown_field"),
		agBadRaw("upper case key", `{"NAME":"a"}`, "unknown_field"),
		agBadRaw("unknown userId", `{"name":"a","userId":"`+idUserB+`"}`, "unknown_field"),
		agBadRaw("unknown user_id", `{"name":"a","user_id":"x"}`, "unknown_field"),
		agBadRaw("the singular is not a member", `{"name":"a","scope":["agent:read"]}`, "unknown_field"),
		agBadRaw("unknown id", `{"name":"a","id":"`+idAgentA+`"}`, "unknown_field"),
		agBadRaw("unknown role", `{"name":"a","role":"admin"}`, "unknown_field"),
		agBadRaw("unknown status", `{"name":"a","status":"revoked"}`, "unknown_field"),
		agBadRaw("unknown revokedAt", `{"name":"a","revokedAt":1}`, "unknown_field"),
		agBadRaw("unknown createdAt", `{"name":"a","createdAt":1}`, "unknown_field"),
		agBadRaw("unknown nested", `{"name":"a","x":{"y":[1,2]}}`, "unknown_field"),
		agBadRaw("unknown __proto__", `{"name":"a","__proto__":{"x":1}}`, "unknown_field"),
		agBadRaw("lone high surrogate escape", `{"name":"a\ud800"}`, "invalid_text"),
		agBadRaw("lone low surrogate escape", `{"name":"a\udc00"}`, "invalid_text"),
		agBadRaw("escaped U+FFFD", `{"name":"a\ufffd"}`, "invalid_text"),
		agBadRaw("raw invalid UTF-8 byte", "{\"name\":\"a\xffb\"}", "invalid_text"),
		agBadRaw("raw truncated UTF-8 sequence", "{\"name\":\"a\xe2\x82\"}", "invalid_text"),
		agBadRaw("raw overlong NUL (C0 80)", "{\"name\":\"a\xc0\x80b\"}", "invalid_text"),
		agBadRaw("raw surrogate half (ED A0 80)", "{\"name\":\"a\xed\xa0\x80b\"}", "invalid_text"),
		agBadRaw("raw U+FFFD bytes in a key", "{\"na\xef\xbf\xbdme\":\"a\"}", "invalid_text"),
		agBadRaw("invalid UTF-8 in an unknown key", "{\"name\":\"a\",\"\xff\":1}", "invalid_text"),
		agBadRaw("raw control character in a string", "{\"name\":\"a\x01b\"}", "invalid_json"),
		agBadRaw("raw newline in a string", "{\"name\":\"a\nb\"}", "invalid_json"),
		agBadRaw("invalid escape", `{"name":"a\qb"}`, "invalid_json"),
		agBadRaw("short unicode escape", `{"name":"a\u12"}`, "invalid_json"),
		agBadRaw("BOM before the object", "\xef\xbb\xbf{\"name\":\"a\"}", "invalid_json"),
	}

	return slices.Concat(accepted, refusedNames, shapes)
}

// TestAgentCreateNames is the table of every name and body shape. An accepted
// name is stored byte-for-byte (the stored bytes equal the sent bytes: nothing
// is trimmed, folded or normalised) and fits the real SQLite CHECK; a refused
// one writes nothing at all, not even a key row.
//
//nolint:paralleltest // shares one database
func TestAgentCreateNames(t *testing.T) {
	world := agNewPair(t, roleMember)

	for _, c := range agNameCases() {
		t.Run(c.label, func(t *testing.T) {
			// Each case starts below the cap (the Worker is idle).
			seed(t, "DELETE FROM agents WHERE user_id = ?", world.b.userID)

			body := c.body(t)
			if c.raw == "-" {
				body = []byte{}
			}

			got := send(t, request{method: http.MethodPost, path: pathAgent, body: body, token: world.tokenB})
			got.expect(t, "create", c.status, c.code)

			if c.status != http.StatusCreated {
				expectCount(t, "agents WHERE user_id = ?", "0", world.b.userID)
				expectCount(t, "api_keys", "0")

				return
			}

			created := agDecode[agCreated](t, got)
			if created.Agent.Name != c.name {
				t.Errorf("response name = %q, want %q", created.Agent.Name, c.name)
			}

			if stored := agNameHex(t, created.Agent.ID); stored != agHex(c.name) {
				t.Errorf("stored name bytes = %s, want %s (never rewritten)", stored, agHex(c.name))
			}

			one := agDecode[agView](t, get(t, agItem(created.Agent.ID), world.tokenB))
			if one.Name != c.name {
				t.Errorf("GET name = %q, want %q", one.Name, c.name)
			}

			expectCount(t, "agents WHERE user_id = ?", "1", world.b.userID)
			expectCount(t, "api_keys WHERE agent_id = ?", "1", created.Agent.ID)

			// The agent's first key is named after the agent, byte for byte.
			keyName := scalar(t, "SELECT hex(CAST(name AS BLOB)) FROM api_keys WHERE agent_id = ?", created.Agent.ID)
			if keyName != agHex(c.name) {
				t.Errorf("the agent key's stored name bytes = %s, want %s", keyName, agHex(c.name))
			}

			// A later rename of the agent leaves the key's own name alone.
			patch(t, agItem(created.Agent.ID), []byte(`{"name":"renamed afterwards"}`), world.tokenB).
				expect(t, "rename the agent", http.StatusOK, "")

			if got := scalar(t, "SELECT hex(CAST(name AS BLOB)) FROM api_keys WHERE agent_id = ?", created.Agent.ID); got != agHex(c.name) {
				t.Errorf("renaming the agent changed its key's name to %s", got)
			}
		})
	}
}

// ---- the limit -------------------------------------------------------------

// TestAgentCreateLimit: 25 active agents is the cap; the 26th is 409 and writes
// neither an agent nor a key; revoked agents and other users' agents do not count.
//
//nolint:paralleltest // shares one database
func TestAgentCreateLimit(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	// 24 pre-seeded, the 25th through the API: the last that fits.
	agSeedMany(t, owner, 1, agMaxAgents-1)
	agMustCreate(t, world.tokenB, "number 25")
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", owner)
	expectCount(t, "api_keys", "25")

	keysBefore := count(t, "api_keys")

	got := agCreate(t, world.tokenB, "number 26")
	got.expect(t, "26th", http.StatusConflict, agCodeLimit)

	if !strings.Contains(got.body, "25") || strings.Contains(got.body, "token") {
		t.Errorf("limit body = %s, want the limit and no token", got.body)
	}

	expectCount(t, "agents WHERE user_id = ?", "25", owner)
	expectCount(t, "agents WHERE name = 'number 26'", "0")

	if after := count(t, "api_keys"); after != keysBefore {
		t.Errorf("api_keys = %s after a refused create, was %s: an orphan key row was left behind", after, keysBefore)
	}

	expectNoOrphanSecrets(t)

	expectCount(t, "api_keys WHERE agent_id IS NULL", "0")

	// An invalid body at the cap is still the body's error, not the cap's.
	post(t, pathAgent, []byte(`{}`), world.tokenB).expect(t, "bad name at the cap", http.StatusBadRequest, agCodeBadName)

	// Another user's agents do not count: A (a different user) can still create.
	agMustCreate(t, world.tokenA, "admin agent")

	// Revoking one through the API frees exactly one slot.
	del(t, agItem(idN(agIDPrefix, 1)), world.tokenB).expect(t, "revoke", http.StatusOK, "")
	agMustCreate(t, world.tokenB, "fits again")
	agCreate(t, world.tokenB, "and not twice").expect(t, "after refilling", http.StatusConflict, agCodeLimit)

	// Agents of a revoked user count for nobody: only the owner's active ones.
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", owner)
}

// TestAgentCreateRaceAtTheLimit: with 20 agents the user has room for exactly 5
// more. Many concurrent creates produce exactly 5 agents, never more, and one
// key per agent; the losers are 409 and leave no key.
//
//nolint:paralleltest // shares one database
func TestAgentCreateRaceAtTheLimit(t *testing.T) {
	for _, workers := range []int{8, 12, 16} {
		t.Run(fmt.Sprintf("%d workers", workers), func(t *testing.T) {
			world := agNewPair(t, roleMember)
			owner := world.b.userID

			agSeedMany(t, owner, 1, 20)

			replies := agRelease(workers, func(i int) reply {
				return agCreate(t, world.tokenB, "race-"+strconv.Itoa(i))
			})

			tally := agTally(replies)
			t.Logf("%d workers: %v", workers, tally)
			agNo5xx(t, "create race", replies)

			if tally["201"] != 5 || tally["409 "+agCodeLimit] != workers-5 {
				t.Errorf("outcomes = %v, want exactly 5 created and %d limit refusals", tally, workers-5)
			}

			expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", owner)
			expectCount(t, keyRows+" WHERE revoked_at IS NULL", "25")
			expectCount(t, "agents WHERE name LIKE 'race-%'", "5")
			expectCount(t, "api_keys WHERE agent_id NOT IN (SELECT id FROM agents)", "0")
			expectCount(t, "agents a WHERE NOT EXISTS (SELECT 1 FROM api_keys k WHERE k.agent_id = a.id)", "0")

			// Every 201 carries a key of its own agent, and each winning agent
			// really exists with that key.
			for _, r := range replies {
				if r.status != http.StatusCreated {
					continue
				}

				created := agDecode[agCreated](t, r)
				expectCount(t, "api_keys WHERE id = ? AND agent_id = ? AND user_id = ?", "1",
					created.Key.ID, created.Agent.ID, owner)
			}
		})
	}
}

// TestAgentCreateRaceTwoUsers: two users creating concurrently do not
// interfere: each is bounded by its own cap only.
//
//nolint:paralleltest // shares one database
func TestAgentCreateRaceTwoUsers(t *testing.T) {
	world := agNewPair(t, roleMember)

	// A has 20, B has 23: room for 5 and 2.
	agSeedMany(t, world.a.userID, 1, 20)
	agSeedMany(t, world.b.userID, 101, 23)

	const each = 10

	replies := agRelease(2*each, func(i int) reply {
		if i%2 == 0 {
			return agCreate(t, world.tokenA, "a-"+strconv.Itoa(i))
		}

		return agCreate(t, world.tokenB, "b-"+strconv.Itoa(i))
	})

	agNo5xx(t, "two users", replies)

	var okA, okB int

	for i, r := range replies {
		if r.status == http.StatusCreated {
			if i%2 == 0 {
				okA++
			} else {
				okB++
			}

			continue
		}

		r.expect(t, "loser", http.StatusConflict, agCodeLimit)
	}

	if okA != 5 || okB != 2 {
		t.Errorf("created A=%d B=%d, want 5 and 2", okA, okB)
	}

	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", world.a.userID)
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", world.b.userID)
	expectCount(t, "api_keys WHERE user_id = ?", "25", world.a.userID)
	expectCount(t, "api_keys WHERE user_id = ?", "25", world.b.userID)
}

// TestAgentCreateRacesUserRevocation: an admin revokes user B while B creates
// agents concurrently. Whatever the interleaving, once everything settled no
// active agent and no active key belong to the revoked user, and no request is a
// 5xx. A create that landed after the revocation is refused (the write reads
// the owner as revoked, or verification refuses the session).
//
//nolint:paralleltest // shares one database
func TestAgentCreateRacesUserRevocation(t *testing.T) {
	for round := range 4 {
		t.Run("round "+strconv.Itoa(round), func(t *testing.T) {
			world := agNewPair(t, roleMember)

			const creators = 12

			var revoked reply

			replies := agRelease(creators+1, func(i int) reply {
				if i == creators/2 {
					revoked = del(t, pathUser+"/"+world.b.userID, world.tokenA)

					return revoked
				}

				return agCreate(t, world.tokenB, "racing-"+strconv.Itoa(i))
			})

			t.Logf("round %d: %v", round, agTally(replies))
			agNo5xx(t, "create vs user revocation", replies)
			revoked.expect(t, "revoke the user", http.StatusOK, "")

			expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "0", world.b.userID)
			expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NULL", "0", world.b.userID)

			// Every 201 produced an agent that is now revoked with its key.
			created := 0

			for i, r := range replies {
				if i == creators/2 {
					continue
				}

				if r.status == http.StatusCreated {
					created++

					body := agDecode[agCreated](t, r)
					expectCount(t, "agents WHERE id = ? AND revoked_at IS NOT NULL", "1", body.Agent.ID)
					expectCount(t, "secrets WHERE id = ? AND revoked_at IS NOT NULL", "1", body.Key.ID)

					continue
				}

				if r.status != http.StatusUnauthorized && r.status != http.StatusConflict {
					t.Errorf("a create racing the revocation = %d %s, want 201, 401 or 409", r.status, r.body)
				}
			}

			expectCount(t, "agents WHERE user_id = ?", strconv.Itoa(created), world.b.userID)

			// After the revocation settled, a create is 401 and writes nothing.
			agCreate(t, world.tokenB, "late").expect(t, "create after the revocation", http.StatusUnauthorized, codeUnauthenticated)
			expectCount(t, "agents WHERE name = 'late'", "0")
		})
	}
}

// TestAgentCreateForARevokedOwner: verification refuses a revoked account before
// the write is reached: 401, nothing written (no agent, no key).
//
//nolint:paralleltest // shares one database
func TestAgentCreateForARevokedOwner(t *testing.T) {
	world := agNewPair(t, roleMember)
	del(t, pathUser+"/"+world.b.userID, world.tokenA).expect(t, "revoke B", http.StatusOK, "")

	agCreate(t, world.tokenB, "ghost").expect(t, "create by a revoked user", http.StatusUnauthorized, codeUnauthenticated)
	get(t, pathAgent, world.tokenB).expect(t, "list by a revoked user", http.StatusUnauthorized, codeUnauthenticated)

	expectCount(t, "agents WHERE user_id = ?", "0", world.b.userID)
	expectCount(t, "api_keys", "0")

	expectCount(t, "agents", "0")
}

// ---- list, get, paging -----------------------------------------------------

// TestAgentListShapes: the exact list and item shapes, newest first, revoked
// agents included with revokedAt, never the owner, never a key.
//
//nolint:paralleltest // shares one database
func TestAgentListShapes(t *testing.T) {
	world := agNewPair(t, roleMember)

	empty := get(t, pathAgent, world.tokenB)
	empty.expect(t, "empty list", http.StatusOK, "")

	if strings.TrimSpace(empty.body) != `{"agents":[]}` {
		t.Errorf("empty list = %q, want {\"agents\":[]} (an array, never null; no next)", empty.body)
	}

	seedAgent(t, idN(agIDPrefix, 1), world.b.userID, "first")
	seedAgent(t, idN(agIDPrefix, 2), world.b.userID, "second")
	seedAgent(t, idN(agIDPrefix, 3), world.b.userID, "third")
	seedAPIKey(t, idN(agKeyPref, 1), world.b.userID, idN(agIDPrefix, 1))
	seed(t, "UPDATE agents SET revoked_at = 12345, created_at = 777 WHERE id = ?", idN(agIDPrefix, 2))

	list := get(t, pathAgent, world.tokenB)
	list.expect(t, "list", http.StatusOK, "")

	page := agDecode[agPage](t, list)

	ids := make([]string, 0, len(page.Agents))

	for _, a := range page.Agents {
		ids = append(ids, a.ID)
	}

	want := []string{idN(agIDPrefix, 3), idN(agIDPrefix, 2), idN(agIDPrefix, 1)}
	if !slices.Equal(ids, want) {
		t.Errorf("order = %v, want newest id first %v", ids, want)
	}

	if page.Next != "" || strings.Contains(list.body, `"next"`) {
		t.Errorf("next present on the only page: %s", list.body)
	}

	second := page.Agents[1]
	if second.Status != "revoked" || second.RevokedAt == nil || *second.RevokedAt != 12345 || second.CreatedAt != 777 ||
		second.Name != "second" || !agIsDefault(second.Scopes) {
		t.Errorf("revoked agent = %+v", second)
	}

	third := page.Agents[0]
	if third.Status != "active" || third.RevokedAt != nil {
		t.Errorf("active agent = %+v", third)
	}

	// The raw JSON has no revokedAt on an active agent and no owner anywhere.
	if strings.Count(list.body, "revokedAt") != 1 {
		t.Errorf("revokedAt appears %d times, want once (only the revoked agent): %s", strings.Count(list.body, "revokedAt"), list.body)
	}

	for _, leak := range []string{"userId", "user_id", world.b.userID, world.a.userID, "token", "hash", "susu_key_", "agent_id"} {
		if strings.Contains(list.body, leak) {
			t.Errorf("list leaks %q: %s", leak, list.body)
		}
	}

	// GET one is the same view as the list's.
	for _, a := range page.Agents {
		one := get(t, agItem(a.ID), world.tokenB)
		one.expect(t, "get", http.StatusOK, "")

		if got := agDecode[agView](t, one); !reflect.DeepEqual(got, a) {
			t.Errorf("GET %s = %+v, list had %+v", a.ID, got, a)
		}

		if strings.Contains(one.body, "userId") || strings.Contains(one.body, world.b.userID) {
			t.Errorf("GET leaks the owner: %s", one.body)
		}
	}

	// Ties in createdAt are broken by id: all three above share neither, so seed
	// two with the same created_at and check the id order still holds.
	seed(t, "UPDATE agents SET created_at = 5")

	again := agDecode[agPage](t, get(t, pathAgent, world.tokenB))

	tied := make([]string, 0, len(again.Agents))

	for _, a := range again.Agents {
		tied = append(tied, a.ID)
	}

	if !slices.Equal(tied, want) {
		t.Errorf("order with equal createdAt = %v, want %v", tied, want)
	}
}

// agQueryCase is one query string for GET /api/agent and its outcome.
type agQueryCase struct {
	label string
	query string
	// status is the expected status; for 200 count is the number of agents.
	status int
	code   string
	count  int
}

// TestAgentListQuery is the table of limit and cursor values, over 30 agents (7
// active-plus-revoked would not exercise the default of 25 and the bound of 100).
//
//nolint:paralleltest,funlen // shares one database; the case table is the test
func TestAgentListQuery(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	// 30 agents of B (a mix of revoked, so the cap does not matter: seeded rows),
	// one of A, whose id is the "someone else's cursor".
	for i := 1; i <= 30; i++ {
		seedAgent(t, idN(agIDPrefix, i), owner, "n"+strconv.Itoa(i))
	}

	seedAgent(t, idN(agIDPrefix, 100), world.a.userID, "admins")

	newest := idN(agIDPrefix, 30)
	oldest := idN(agIDPrefix, 1)
	middle := idN(agIDPrefix, 15)
	enc := url.QueryEscape

	bad := func(label, query, code string) agQueryCase {
		return agQueryCase{label: label, query: query, status: http.StatusBadRequest, code: code}
	}

	ok := func(label, query string, n int) agQueryCase {
		return agQueryCase{label: label, query: query, status: http.StatusOK, count: n}
	}

	cases := []agQueryCase{
		ok("no query: default page of 25", "", 25),
		ok("limit 1", "limit=1", 1),
		ok("limit 25", "limit=25", 25),
		ok("limit 30", "limit=30", 30),
		ok("limit 100 (the bound)", "limit=100", 30),
		bad("limit 0", "limit=0", agCodeLimitQ),
		bad("limit 101", "limit=101", agCodeLimitQ),
		bad("limit -1", "limit=-1", agCodeLimitQ),
		bad("limit 1000000", "limit=1000000", agCodeLimitQ),
		bad("limit 2^53", "limit=9007199254740992", agCodeLimitQ),
		bad("limit 2^53+1", "limit=9007199254740993", agCodeLimitQ),
		bad("limit 2^63", "limit=9223372036854775808", agCodeLimitQ),
		bad("limit 2^64", "limit=18446744073709551616", agCodeLimitQ),
		bad("limit 500-digit number", "limit="+agRepeat("9", 500), agCodeLimitQ),
		bad("limit abc", "limit=abc", agCodeLimitQ),
		bad("limit 1.5", "limit=1.5", agCodeLimitQ),
		bad("limit 1.0", "limit=1.0", agCodeLimitQ),
		bad("limit 1e1", "limit=1e1", agCodeLimitQ),
		bad("limit 1e2", "limit=1e2", agCodeLimitQ),
		bad("limit space 5", "limit="+enc(" 5"), agCodeLimitQ),
		bad("limit 5 space", "limit="+enc("5 "), agCodeLimitQ),
		bad("limit plus space-encoded", "limit=%205", agCodeLimitQ),
		bad("limit 00005", "limit=00005", agCodeLimitQ),
		bad("limit 05", "limit=05", agCodeLimitQ),
		bad("limit 0x10", "limit=0x10", agCodeLimitQ),
		bad("limit +5", "limit="+enc("+5"), agCodeLimitQ),
		bad("limit literal +5 (decodes to a space)", "limit=+5", agCodeLimitQ),
		bad("limit -0", "limit=-0", agCodeLimitQ),
		bad("limit 5,5", "limit="+enc("5,5"), agCodeLimitQ),
		bad("limit fullwidth 5", "limit="+enc("\uff15"), agCodeLimitQ),
		bad("limit arabic-indic 5", "limit="+enc("\u0665"), agCodeLimitQ),
		bad("limit NUL byte", "limit=5%00", agCodeLimitQ),
		bad("limit empty", "limit=", agCodeLimitQ),
		bad("limit with no equals", "limit", agCodeLimitQ),
		bad("limit repeated", "limit=1&limit=2", agCodeLimitQ),
		bad("limit repeated same value", "limit=2&limit=2", agCodeLimitQ),
		bad("limit repeated empty", "limit=&limit=2", agCodeLimitQ),
		bad("limit null", "limit=null", agCodeLimitQ),
		bad("limit NaN", "limit=NaN", agCodeLimitQ),
		ok("limit[] is another parameter name: ignored", "limit[]=5", 25),
		ok("unknown parameter is ignored", "offset=5", 25),
		ok("upper-case parameter name is another parameter", "LIMIT=1", 25),
		ok("cursor below the newest", "limit=100&cursor="+newest, 29),
		ok("cursor in the middle", "limit=100&cursor="+middle, 14),
		ok("cursor at the oldest: empty page", "limit=100&cursor="+oldest, 0),
		ok("cursor above everything", "limit=100&cursor=ffffffff-ffff-ffff-ffff-ffffffffffff", 30),
		ok("cursor below everything", "cursor=00000000-0000-0000-0000-000000000000", 0),
		ok("cursor of an id that does not exist (above all)", "limit=100&cursor=00000000-0000-7000-8000-ffffffffffff", 30),
		ok("cursor of ANOTHER user's agent: just a page, no leak", "limit=100&cursor="+idN(agIDPrefix, 100), 30),
		ok("cursor + limit", "limit=5&cursor="+middle, 5),
		bad("cursor upper-case", "cursor="+strings.ToUpper(middle), agCodeCursorQ),
		bad("cursor partial", "cursor="+middle[:20], agCodeCursorQ),
		bad("cursor with a trailing character", "cursor="+middle+"0", agCodeCursorQ),
		bad("cursor without dashes", "cursor="+strings.ReplaceAll(middle, "-", ""), agCodeCursorQ),
		bad("cursor with braces", "cursor="+enc("{"+middle+"}"), agCodeCursorQ),
		bad("cursor urn form", "cursor="+enc("urn:uuid:"+middle), agCodeCursorQ),
		bad("cursor nope", "cursor=nope", agCodeCursorQ),
		bad("cursor g (the store's internal first-page bound)", "cursor=g", agCodeCursorQ),
		bad("cursor 36 g", "cursor="+agRepeat("g", 36), agCodeCursorQ),
		bad("cursor space padded", "cursor="+enc(" "+middle), agCodeCursorQ),
		bad("cursor NUL", "cursor="+middle[:35]+"%00", agCodeCursorQ),
		bad("cursor empty", "cursor=", agCodeCursorQ),
		bad("cursor with no equals", "cursor", agCodeCursorQ),
		bad("cursor repeated", "cursor="+middle+"&cursor="+oldest, agCodeCursorQ),
		bad("cursor repeated same", "cursor="+middle+"&cursor="+middle, agCodeCursorQ),
		bad("cursor sql injection", "cursor="+enc("' OR 1=1 --"), agCodeCursorQ),
		bad("both bad: the limit is reported first", "limit=x&cursor=y", agCodeLimitQ),
		bad("both bad, cursor first in the string", "cursor=y&limit=x", agCodeLimitQ),
		bad("limit fine, cursor bad", "limit=5&cursor=y", agCodeCursorQ),
		bad("limit repeated and cursor bad", "limit=1&limit=2&cursor=y", agCodeLimitQ),
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			got := get(t, pathAgent+"?"+c.query, world.tokenB)
			got.expect(t, "GET ?"+c.query, c.status, c.code)

			if c.status != http.StatusOK {
				return
			}

			page := agDecode[agPage](t, got)
			if len(page.Agents) != c.count {
				t.Errorf("GET ?%s returned %d agents, want %d", c.query, len(page.Agents), c.count)
			}

			// No page ever shows an agent of another user.
			if strings.Contains(got.body, "admins") || strings.Contains(got.body, idN(agIDPrefix, 100)) {
				t.Errorf("GET ?%s leaks another user's agent: %s", c.query, got.body)
			}
		})
	}

	// Pages are exact: at limit 30 with 30 rows there is no next page; at 29 there is.
	full := agDecode[agPage](t, get(t, pathAgent+"?limit=30", world.tokenB))
	if full.Next != "" {
		t.Errorf("next = %q on an exactly full last page, want none", full.Next)
	}

	short := agDecode[agPage](t, get(t, pathAgent+"?limit=29", world.tokenB))
	if short.Next != idN(agIDPrefix, 2) {
		t.Errorf("next = %q, want the id of the last row shown, %s", short.Next, idN(agIDPrefix, 2))
	}

	// The cursor of a page is accepted as is: cursor == last id of the page, and
	// the page after the oldest is empty and has no next.
	last := agDecode[agPage](t, get(t, pathAgent+"?cursor="+oldest, world.tokenB))
	if len(last.Agents) != 0 || last.Next != "" || strings.TrimSpace(get(t, pathAgent+"?cursor="+oldest, world.tokenB).body) != `{"agents":[]}` {
		t.Errorf("page after the oldest = %+v", last)
	}
}

// TestAgentListWalk walks 7 agents at several limits: every agent exactly once,
// in order, with next absent on the last page, even while new agents are
// created between pages (keyset paging neither skips nor repeats).
//
//nolint:paralleltest // shares one database
func TestAgentListWalk(t *testing.T) {
	const total = 7

	for _, limit := range []int{1, 2, 3, 6, 7, 8, 100} {
		t.Run("limit "+strconv.Itoa(limit), func(t *testing.T) {
			world := agNewPair(t, roleMember)
			owner := world.b.userID

			for i := 1; i <= total; i++ {
				seedAgent(t, idN(agIDPrefix, i), owner, "w"+strconv.Itoa(i))
			}

			// Someone else's agents interleave in id order and must never show.
			seedAgent(t, idN(agIDPrefix, 50), world.a.userID, "other")

			// Revoke a couple: revoked rows are paged like any other.
			seed(t, "UPDATE agents SET revoked_at = 99 WHERE id IN (?, ?)", idN(agIDPrefix, 3), idN(agIDPrefix, 6))

			var seen []string

			cursor := ""
			pages := 0

			for {
				path := pathAgent + "?limit=" + strconv.Itoa(limit)
				if cursor != "" {
					path += "&cursor=" + cursor
				}

				got := get(t, path, world.tokenB)
				got.expect(t, "page", http.StatusOK, "")

				page := agDecode[agPage](t, got)
				pages++

				if len(page.Agents) == 0 || len(page.Agents) > limit {
					t.Fatalf("page %d has %d agents with limit %d", pages, len(page.Agents), limit)
				}

				for _, a := range page.Agents {
					seen = append(seen, a.ID)
				}

				if page.Next == "" {
					if strings.Contains(got.body, "next") {
						t.Errorf("last page has a next member: %s", got.body)
					}

					break
				}

				if page.Next != page.Agents[len(page.Agents)-1].ID || len(page.Agents) != limit {
					t.Fatalf("next = %q, want the last id of a full page: %+v", page.Next, page.Agents)
				}

				cursor = page.Next

				if pages > total+2 {
					t.Fatalf("walk does not end: %v", seen)
				}
			}

			var want []string
			for i := total; i >= 1; i-- {
				want = append(want, idN(agIDPrefix, i))
			}

			if !slices.Equal(seen, want) {
				t.Errorf("walk = %v, want %v", seen, want)
			}

			if wantPages := (total + limit - 1) / limit; pages != wantPages {
				t.Errorf("pages = %d, want %d", pages, wantPages)
			}
		})
	}
}

// TestAgentListWalkWhileCreating: agents created between pages (through the
// API and seeded while the Worker is idle) never make a page skip or repeat an
// agent that existed throughout.
//
//nolint:paralleltest // shares one database
func TestAgentListWalkWhileCreating(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	const total = 6

	for i := 1; i <= total; i++ {
		seedAgent(t, idN(agIDPrefix, i), owner, "w"+strconv.Itoa(i))
	}

	var seen []string

	cursor := ""

	for step := 0; ; step++ {
		path := pathAgent + "?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}

		page := agDecode[agPage](t, get(t, path, world.tokenB))
		for _, a := range page.Agents {
			seen = append(seen, a.ID)
		}

		if page.Next == "" {
			break
		}

		cursor = page.Next

		// Between pages: one newer agent through the API (id above every cursor),
		// and a revocation of an agent that is still ahead of the cursor.
		agMustCreate(t, world.tokenB, "between-"+strconv.Itoa(step))

		if step == 0 {
			del(t, agItem(idN(agIDPrefix, 1)), world.tokenB).expect(t, "revoke ahead", http.StatusOK, "")
		}

		if step > total {
			t.Fatalf("walk does not end: %v", seen)
		}
	}

	var want []string
	for i := total; i >= 1; i-- {
		want = append(want, idN(agIDPrefix, i))
	}

	if !slices.Equal(seen, want) {
		t.Errorf("walk while creating = %v, want exactly the original agents once, newest first: %v", seen, want)
	}

	if dup := agDuplicates(seen); dup != "" {
		t.Errorf("duplicate in the walk: %s", dup)
	}
}

func agDuplicates(ids []string) string {
	seen := map[string]bool{}

	for _, id := range ids {
		if seen[id] {
			return id
		}

		seen[id] = true
	}

	return ""
}

// TestAgentGetShapes: GET one by id; a malformed id is 400 invalid_id once the
// session is verified (a signed-out caller is 401 whatever the id); an unknown
// one is 404.
//
//nolint:paralleltest // shares one database
func TestAgentGetShapes(t *testing.T) {
	world := agNewPair(t, roleMember)
	seedAgent(t, idAgentA, world.b.userID, "mine")

	for _, c := range []struct {
		label  string
		path   string
		status int
		code   string
	}{
		{"known", agItem(idAgentA), http.StatusOK, ""},
		{"unknown", agItem(idMissing), http.StatusNotFound, agCodeMissing},
		{"upper-case id", agItem(strings.ToUpper(idAgentA)), http.StatusBadRequest, codeInvalidID},
		{"short id", agItem(idAgentA[:35]), http.StatusBadRequest, codeInvalidID},
		{"long id", agItem(idAgentA + "0"), http.StatusBadRequest, codeInvalidID},
		{"not hex", agItem(strings.Replace(idAgentA, "d001", "g001", 1)), http.StatusBadRequest, codeInvalidID},
		{"no dashes", agItem(strings.ReplaceAll(idAgentA, "-", "")), http.StatusBadRequest, codeInvalidID},
		{"nope", agItem("nope"), http.StatusBadRequest, codeInvalidID},
		{"url-encoded space", agItem("%20"), http.StatusBadRequest, codeInvalidID},
		{"url-encoded id", agItem(strings.Replace(idAgentA, "-", "%2d", 1)), http.StatusOK, ""},
		{"url-encoded slash makes two segments: no route", pathAgent + "/a%2fb", http.StatusNotFound, codeNotFound},
		{"extra segment", agItem(idAgentA) + "/x", http.StatusNotFound, codeNotFound},
		{"query is ignored", agItem(idAgentA) + "?limit=0&cursor=x", http.StatusOK, ""},
		{"collection with trailing slash", pathAgent + "/", http.StatusNotFound, codeNotFound},
	} {
		t.Run(c.label, func(t *testing.T) {
			get(t, c.path, world.tokenB).expect(t, "GET "+c.path, c.status, c.code)
		})
	}

	// The session is verified before the id is read: 401 signed out, bad id or not.
	get(t, agItem("nope"), "").expect(t, "bad id signed out", http.StatusUnauthorized, codeUnauthenticated)
	get(t, agItem(idMissing), "").expect(t, "good id signed out", http.StatusUnauthorized, codeUnauthenticated)
	del(t, agItem("nope"), "").expect(t, "DELETE bad id signed out", http.StatusUnauthorized, codeUnauthenticated)
	patch(t, agItem("nope"), []byte(`{"name":"x"}`), "").
		expect(t, "PATCH bad id signed out", http.StatusUnauthorized, codeUnauthenticated)
}

// TestAgentRouteMethods: only the declared methods are routed (TinyGo's mux
// cannot route by method; the boundary does), with an Allow header.
//
//nolint:paralleltest // shares one database
func TestAgentRouteMethods(t *testing.T) {
	world := agNewPair(t, roleMember)
	seedAgent(t, idAgentA, world.b.userID, "mine")

	for _, c := range []struct {
		method, path, allow string
	}{
		{http.MethodPut, pathAgent, "GET, POST"},
		{http.MethodPatch, pathAgent, "GET, POST"},
		{http.MethodDelete, pathAgent, "GET, POST"},
		{http.MethodPost, agItem(idAgentA), "DELETE, GET, PATCH"},
		{http.MethodPut, agItem(idAgentA), "DELETE, GET, PATCH"},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			got := send(t, request{method: c.method, path: c.path, body: []byte(`{"name":"x"}`), token: world.tokenB})
			got.expect(t, "method", http.StatusMethodNotAllowed, codeMethodNotAllow)

			if allow := got.header.Get("Allow"); allow != c.allow {
				t.Errorf("Allow = %q, want %q", allow, c.allow)
			}
		})
	}

	expectCount(t, "agents", "1")
	expectCount(t, "agents WHERE name = 'mine' AND revoked_at IS NULL", "1")
}

// ---- ownership confusion ---------------------------------------------------

// TestAgentOwnershipConfusion: B's agent id is 404 agent_not_found for A on
// GET, PATCH and DELETE, byte-identical to an id that does not exist at all; A
// cannot rename, revive or revoke it; the list never contains it; and an admin
// has no extra reach.
//
//nolint:paralleltest // shares one database
func TestAgentOwnershipConfusion(t *testing.T) {
	for _, roleB := range []string{roleMember, roleAdmin} {
		t.Run("B is "+roleB, func(t *testing.T) {
			world := agNewPair(t, roleB)

			// B's agent (active), B's revoked agent, and A's own agent.
			seedAgent(t, idAgentB, world.b.userID, "theirs")
			seedAgent(t, idN(agIDPrefix, 7), world.b.userID, "theirs revoked")
			seed(t, "UPDATE agents SET revoked_at = 4242 WHERE id = ?", idN(agIDPrefix, 7))
			seedAPIKey(t, idN(agKeyPref, 1), world.b.userID, idAgentB)
			seedAgent(t, idAgentA, world.a.userID, "mine")

			targets := []string{idAgentB, idN(agIDPrefix, 7)}

			type attempt struct {
				method string
				body   []byte
			}

			attempts := []attempt{
				{http.MethodGet, nil},
				{http.MethodPatch, []byte(`{"name":"taken over"}`)},
				{http.MethodPatch, []byte(`{"name":"x","userId":"` + world.a.userID + `"}`)},
				{http.MethodDelete, nil},
			}

			for _, target := range targets {
				for _, at := range attempts {
					// The reference answer: the same request for an id nobody has.
					missing := send(t, request{method: at.method, path: agItem(idMissing), body: at.body, token: world.tokenA})
					other := send(t, request{method: at.method, path: agItem(target), body: at.body, token: world.tokenA})

					if strings.Contains(string(at.body), "userId") {
						// An unknown field is refused by the body check first, in both cases.
						other.expect(t, "unknown field", http.StatusBadRequest, "unknown_field")

						continue
					}

					other.expect(t, at.method+" B's agent as A", http.StatusNotFound, agCodeMissing)

					if other.body != missing.body || other.status != missing.status {
						t.Errorf("%s of another user's agent differs from a missing id (an existence oracle):\n%d %q\n%d %q",
							at.method, other.status, other.body, missing.status, missing.body)
					}

					if other.header.Get("Content-Type") != missing.header.Get("Content-Type") {
						t.Errorf("Content-Type differs: %q vs %q", other.header.Get("Content-Type"), missing.header.Get("Content-Type"))
					}
				}
			}

			// Nothing of B's moved: name, revoked state and keys.
			if got := agRow(t, idAgentB); got != world.b.userID+"|theirs|"+agScopes+"|NULL|"+scalar(t, "SELECT created_at FROM agents WHERE id = ?", idAgentB) {
				t.Errorf("B's agent changed: %s", got)
			}

			if got := agRow(t, idN(agIDPrefix, 7)); !strings.Contains(got, "|theirs revoked|") || !strings.Contains(got, "|4242|") {
				t.Errorf("B's revoked agent changed (revived or renamed?): %s", got)
			}

			expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NULL", "1", idAgentB)

			// A's list never contains B's agents, and B's id as a cursor is just a page.
			list := get(t, pathAgent, world.tokenA)
			if strings.Contains(list.body, "theirs") || strings.Contains(list.body, idAgentB) {
				t.Errorf("A's list shows B's agents: %s", list.body)
			}

			cursor := get(t, pathAgent+"?cursor="+idAgentB, world.tokenA)
			cursor.expect(t, "A with B's id as cursor", http.StatusOK, "")

			if strings.Contains(cursor.body, "theirs") {
				t.Errorf("a foreign cursor leaks: %s", cursor.body)
			}

			// And symmetrically: B cannot touch A's.
			for _, at := range attempts[:2] {
				send(t, request{method: at.method, path: agItem(idAgentA), body: at.body, token: world.tokenB}).
					expect(t, at.method+" A's agent as B", http.StatusNotFound, agCodeMissing)
			}

			del(t, agItem(idAgentA), world.tokenB).expect(t, "DELETE A's agent as B", http.StatusNotFound, agCodeMissing)
			expectCount(t, "agents WHERE id = ? AND revoked_at IS NULL AND name = 'mine'", "1", idAgentA)

			// A's own agent works.
			get(t, agItem(idAgentA), world.tokenA).expect(t, "A's own", http.StatusOK, "")
		})
	}
}

// ---- rename ----------------------------------------------------------------

// TestAgentRename: the response is the row as the write left it; same name is
// fine; names have the same bounds as create and are stored exactly; a revoked
// agent is 409 agent_revoked and keeps its name; unknown is 404; a missing name
// is missing_agent_change (a patch with no name and no label to change).
//
//nolint:paralleltest,funlen // shares one database; the case table is the test
func TestAgentRename(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	seedAgent(t, idAgentA, owner, "before")
	seedAPIKey(t, idN(agKeyPref, 1), owner, idAgentA)

	item := agItem(idAgentA)
	created := scalar(t, "SELECT created_at FROM agents WHERE id = ?", idAgentA)

	// Happy path: the whole row, other columns untouched.
	got := patch(t, item, []byte(`{"name":"after"}`), world.tokenB)
	got.expect(t, "rename", http.StatusOK, "")

	view := agDecode[agView](t, got)
	if view.ID != idAgentA || view.Name != "after" || !agIsDefault(view.Scopes) || view.Status != "active" ||
		view.RevokedAt != nil || strconv.FormatInt(view.CreatedAt, 10) != created {
		t.Errorf("rename response = %+v", view)
	}

	if row := agRow(t, idAgentA); row != owner+"|after|"+agScopes+"|NULL|"+created {
		t.Errorf("row = %q after rename", row)
	}

	// The same name again is fine and idempotent.
	patch(t, item, []byte(`{"name":"after"}`), world.tokenB).expect(t, "same name", http.StatusOK, "")

	// The key is untouched by a rename.
	expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NULL AND scope = ?", "1", idAgentA, agScopes)

	for _, c := range agNameCases() {
		// Only the shapes that mean the same for a patch: the name cases.
		if c.raw != "" && !strings.HasPrefix(c.raw, `{"name":"`) {
			continue
		}

		t.Run(c.label, func(t *testing.T) {
			before := agNameHex(t, idAgentA)

			body := c.body(t)
			if c.raw == "-" {
				body = []byte{}
			}

			status, code := c.status, c.code
			if status == http.StatusCreated {
				status = http.StatusOK
			}

			got := send(t, request{method: http.MethodPatch, path: item, body: body, token: world.tokenB})
			got.expect(t, "rename", status, code)

			if status != http.StatusOK {
				if now := agNameHex(t, idAgentA); now != before {
					t.Errorf("a refused rename changed the name: %s -> %s", before, now)
				}

				return
			}

			if stored := agNameHex(t, idAgentA); stored != agHex(c.name) {
				t.Errorf("stored name = %s, want %s byte-for-byte", stored, agHex(c.name))
			}

			if agDecode[agView](t, got).Name != c.name {
				t.Errorf("response name differs from the sent name")
			}
		})
	}

	// Shapes of the patch body that are not the create ones.
	for _, c := range []struct {
		label, raw, code string
	}{
		{"empty object", `{}`, agCodeNoName},
		{"name null", `{"name":null}`, agCodeNoName},
		{"body null", `null`, agCodeNoName},
		{"empty string", `{"name":""}`, agCodeBadName},
		{"scopes are not a member of a rename", `{"name":"x","scopes":["agent:read"]}`, "unknown_field"},
		{"array", `[]`, "invalid_field_type"},
		{"trailing data", `{"name":"x"} {}`, "trailing_data"},
		{"duplicate", `{"name":"x","name":"y"}`, "duplicate_field"},
	} {
		t.Run("patch shape: "+c.label, func(t *testing.T) {
			patch(t, item, []byte(c.raw), world.tokenB).expect(t, c.raw, http.StatusBadRequest, c.code)
		})
	}

	// A name error is reported before the agent is looked up: even for an agent
	// that does not exist, and before ownership is known.
	patch(t, agItem(idMissing), []byte(`{}`), world.tokenB).expect(t, "bad body, missing agent", http.StatusBadRequest, agCodeNoName)
	patch(t, agItem(idMissing), []byte(`{"name":"x"}`), world.tokenB).expect(t, "missing agent", http.StatusNotFound, agCodeMissing)

	// Revoke it, then rename: 409, and the name is unchanged.
	del(t, item, world.tokenB).expect(t, "revoke", http.StatusOK, "")

	nameBefore := agNameHex(t, idAgentA)
	refused := patch(t, item, []byte(`{"name":"revived"}`), world.tokenB)
	refused.expect(t, "rename a revoked agent", http.StatusConflict, agCodeRevoked)

	if agNameHex(t, idAgentA) != nameBefore {
		t.Errorf("a revoked agent was renamed")
	}

	if strings.Contains(refused.body, "revived") {
		t.Errorf("the refusal echoes the refused name: %s", refused.body)
	}

	// A bad name on a revoked agent is still the body's error (parsed first).
	patch(t, item, []byte(`{"name":""}`), world.tokenB).expect(t, "bad name on revoked", http.StatusBadRequest, agCodeBadName)

	expectCount(t, "agents WHERE name = 'revived'", "0")
}

// ---- revoke ----------------------------------------------------------------

// TestAgentRevoke: revokes the agent and all its keys in one write; siblings and
// other users are untouched; the row stays; revoking again keeps the first time;
// unknown and other users' agents are 404.
//
//nolint:paralleltest // shares one database
func TestAgentRevoke(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner, other := world.b.userID, world.a.userID

	seedAgent(t, idAgentA, owner, "doomed")
	seedAgent(t, idAgentB, owner, "spared")
	seedAgent(t, idN(agIDPrefix, 9), other, "foreign")

	// Several keys on the doomed agent, one with a revocation scheduled later and
	// one already revoked earlier; one on the sibling; one on the foreign agent.
	seedAPIKey(t, idN(agKeyPref, 1), owner, idAgentA)
	seedAPIKey(t, idN(agKeyPref, 2), owner, idAgentA)
	seedAPIKey(t, idN(agKeyPref, 3), owner, idAgentA)
	seedAPIKey(t, idN(agKeyPref, 4), owner, idAgentB)
	seedAPIKey(t, idN(agKeyPref, 5), other, idN(agIDPrefix, 9))
	seed(t, "UPDATE secrets SET revoked_at = strftime('%s','now') + 100000 WHERE id = ?", idN(agKeyPref, 2))
	seed(t, "UPDATE secrets SET revoked_at = 1000 WHERE id = ?", idN(agKeyPref, 3))

	sessions := count(t, "secrets WHERE kind = 'session' AND revoked_at IS NULL")
	before := time.Now().Unix()
	got := del(t, agItem(idAgentA), world.tokenB)
	after := time.Now().Unix()

	got.expect(t, "revoke", http.StatusOK, "")

	view := agDecode[agView](t, got)
	if view.ID != idAgentA || view.Name != "doomed" || view.Status != "revoked" || view.RevokedAt == nil ||
		*view.RevokedAt < before-1 || *view.RevokedAt > after+1 {
		t.Errorf("revoke response = %+v", view)
	}

	revokedAt := *view.RevokedAt

	// The row stays, with its other columns intact.
	if row := agRow(t, idAgentA); !strings.HasPrefix(row, owner+"|doomed|"+agScopes+"|"+strconv.FormatInt(revokedAt, 10)+"|") {
		t.Errorf("row = %q", row)
	}

	// All its keys are revoked: a future revocation is brought forward, an
	// earlier one is kept.
	for id, want := range map[string]int64{idN(agKeyPref, 1): revokedAt, idN(agKeyPref, 2): revokedAt, idN(agKeyPref, 3): 1000} {
		if got := scalar(t, "SELECT revoked_at FROM secrets WHERE id = ?", id); got != strconv.FormatInt(want, 10) {
			t.Errorf("key %s revoked_at = %s, want %d", id, got, want)
		}
	}

	// Nothing else was touched.
	expectCount(t, "agents WHERE id = ? AND revoked_at IS NULL", "1", idAgentB)
	expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NULL", "1", idAgentB)
	expectCount(t, "agents WHERE id = ? AND revoked_at IS NULL", "1", idN(agIDPrefix, 9))
	expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NULL", "1", idN(agIDPrefix, 9))
	expectCount(t, "secrets WHERE kind = 'session' AND revoked_at IS NULL", sessions)
	expectCount(t, "agents", "3")

	// The user's own session is still good.
	get(t, pathSession, world.tokenB).expect(t, "session after revoking an agent", http.StatusOK, "")

	// Idempotent: revoking again keeps the first time (after a 1-2 s wait the
	// clock has surely moved on).
	time.Sleep(1100 * time.Millisecond)

	again := del(t, agItem(idAgentA), world.tokenB)
	again.expect(t, "revoke again", http.StatusOK, "")

	if rev := agDecode[agView](t, again); rev.RevokedAt == nil || *rev.RevokedAt != revokedAt {
		t.Errorf("second revoke revokedAt = %v, want the first, %d", rev.RevokedAt, revokedAt)
	}

	if got := scalar(t, "SELECT revoked_at FROM secrets WHERE id = ?", idN(agKeyPref, 1)); got != strconv.FormatInt(revokedAt, 10) {
		t.Errorf("key revoked_at moved on the second revoke: %s", got)
	}

	// Unknown and other users' agents are 404 with nothing touched.
	del(t, agItem(idMissing), world.tokenB).expect(t, "unknown", http.StatusNotFound, agCodeMissing)
	del(t, agItem(idN(agIDPrefix, 9)), world.tokenB).expect(t, "foreign", http.StatusNotFound, agCodeMissing)
	expectCount(t, "agents WHERE id = ? AND revoked_at IS NULL", "1", idN(agIDPrefix, 9))
	expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NULL", "1", idN(agIDPrefix, 9))

	// A revoked agent keeps showing in the list and still counts as revoked.
	list := agDecode[agPage](t, get(t, pathAgent, world.tokenB))
	if len(list.Agents) != 2 {
		t.Errorf("list has %d agents, want both of B's (one revoked)", len(list.Agents))
	}
}

// TestAgentRevokedKeyIsNotAccepted: an agent's key is accepted as a bearer only
// while its agent is active. Revoking the agent revokes the key's secret, and
// the token is then refused everywhere.
//
//nolint:paralleltest // shares one database
func TestAgentRevokedKeyIsNotAccepted(t *testing.T) {
	world := agNewPair(t, roleMember)
	created := agMustCreate(t, world.tokenB, "key holder")

	// Active: it is accepted as a bearer, and only as a bearer: never as the
	// session cookie.
	agKeyIsNotACredential(t, world.tokenB, created.Key.Token)
	scBearer(t, http.MethodGet, pathAgent, nil, created.Key.Token).expect(t, "active key as bearer", http.StatusOK, "")

	del(t, agItem(created.Agent.ID), world.tokenB).expect(t, "revoke", http.StatusOK, "")
	expectCount(t, "secrets WHERE id = ? AND revoked_at IS NOT NULL", "1", created.Key.ID)

	// Revoked: the secret and its row stay, and the token is refused as a bearer.
	scBearer(t, http.MethodGet, pathAgent, nil, created.Key.Token).
		expect(t, "revoked key as bearer", http.StatusUnauthorized, codeUnauthenticated)

	if stored := mustSecretOf(t, created.Key.Token); !stored.revoked || !stored.kindRow {
		t.Errorf("revoked key's secret = %+v, want kept, revoked, with its api_keys row", stored)
	}

	agKeyIsNotACredential(t, world.tokenB, created.Key.Token)
}

// TestAgentRevokeRaces: concurrent revokes of one agent are all 200 with one
// revokedAt; rename racing revoke ends consistent; renames after a revoke are
// all 409.
//
//nolint:paralleltest // shares one database
func TestAgentRevokeRaces(t *testing.T) {
	t.Run("8 concurrent revokes", func(t *testing.T) {
		for round := range 3 {
			world := agNewPair(t, roleMember)
			seedAgent(t, idAgentA, world.b.userID, "contended")
			seedAPIKey(t, idN(agKeyPref, 1), world.b.userID, idAgentA)
			seedAPIKey(t, idN(agKeyPref, 2), world.b.userID, idAgentA)

			replies := agRelease(8, func(int) reply { return del(t, agItem(idAgentA), world.tokenB) })
			t.Logf("round %d: %v", round, agTally(replies))
			agNo5xx(t, "revokes", replies)

			stamps := map[int64]bool{}

			for _, r := range replies {
				r.expect(t, "revoke", http.StatusOK, "")

				if rev := agDecode[agView](t, r); rev.RevokedAt != nil {
					stamps[*rev.RevokedAt] = true
				}
			}

			stored := scalar(t, "SELECT revoked_at FROM agents WHERE id = ?", idAgentA)
			if len(stamps) != 1 || !stamps[mustInt(t, stored)] {
				t.Errorf("responses carry revokedAt values %v, stored %s: want exactly one", stamps, stored)
			}

			expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NULL", "0", idAgentA)
			expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at = ?", "2", idAgentA, stored)
		}
	})

	t.Run("rename racing revoke", func(t *testing.T) {
		for round := range 4 {
			world := agNewPair(t, roleMember)
			seedAgent(t, idAgentA, world.b.userID, "original")
			seedAPIKey(t, idN(agKeyPref, 1), world.b.userID, idAgentA)

			const renamers = 10

			replies := agRelease(renamers+1, func(i int) reply {
				if i == renamers/2 {
					return del(t, agItem(idAgentA), world.tokenB)
				}

				return patch(t, agItem(idAgentA), []byte(`{"name":"rename-`+strconv.Itoa(i)+`"}`), world.tokenB)
			})

			t.Logf("round %d: %v", round, agTally(replies))
			agNo5xx(t, "rename vs revoke", replies)

			// The revoke always wins eventually.
			if scalar(t, "SELECT revoked_at IS NOT NULL FROM agents WHERE id = ?", idAgentA) != "1" {
				t.Errorf("the agent is not revoked after the race")
			}

			expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NULL", "0", idAgentA)

			// The stored name is the name of one rename that succeeded BEFORE the
			// revoke (or the original when none did): a 200 rename is the only way
			// to a new name, and a 409 rename wrote nothing.
			stored := scalar(t, "SELECT name FROM agents WHERE id = ?", idAgentA)
			winners := map[string]bool{"original": true}

			for i, r := range replies {
				if i == renamers/2 {
					r.expect(t, "revoke", http.StatusOK, "")

					continue
				}

				switch r.status {
				case http.StatusOK:
					winners["rename-"+strconv.Itoa(i)] = true

					if agDecode[agView](t, r).Name != "rename-"+strconv.Itoa(i) {
						t.Errorf("rename %d answered with another name: %s", i, r.body)
					}
				case http.StatusConflict:
					r.expect(t, "rename after revoke", http.StatusConflict, agCodeRevoked)
				default:
					t.Errorf("rename %d = %d %s, want 200 or 409", i, r.status, r.body)
				}
			}

			if !winners[stored] {
				t.Errorf("stored name %q is not the original nor any name a 200 rename reported: %v", stored, winners)
			}
		}
	})

	t.Run("renames after the revoke are all 409", func(t *testing.T) {
		world := agNewPair(t, roleMember)
		seedAgent(t, idAgentA, world.b.userID, "frozen")
		del(t, agItem(idAgentA), world.tokenB).expect(t, "revoke", http.StatusOK, "")

		replies := agRelease(8, func(i int) reply {
			return patch(t, agItem(idAgentA), []byte(`{"name":"thaw-`+strconv.Itoa(i)+`"}`), world.tokenB)
		})

		for _, r := range replies {
			r.expect(t, "rename after revoke", http.StatusConflict, agCodeRevoked)
		}

		expectCount(t, "agents WHERE name = 'frozen'", "1")
	})

	t.Run("create racing revoke of an agent at the cap", func(t *testing.T) {
		world := agNewPair(t, roleMember)
		agSeedMany(t, world.b.userID, 1, agMaxAgents)

		replies := agRelease(10, func(i int) reply {
			if i == 0 {
				return del(t, agItem(idN(agIDPrefix, 1)), world.tokenB)
			}

			return agCreate(t, world.tokenB, "slot-"+strconv.Itoa(i))
		})

		agNo5xx(t, "create vs revoke", replies)

		// The revoke frees exactly one slot: at most one create fits, and the cap
		// is never exceeded.
		if active := agActiveAgents(t, world.b.userID); active != "25" && active != "24" {
			t.Errorf("active agents = %s, want 24 or 25", active)
		}

		created := 0

		for i, r := range replies {
			if i != 0 && r.status == http.StatusCreated {
				created++
			}
		}

		if created > 1 {
			t.Errorf("%d creates fit after a single revocation: %v", created, agTally(replies))
		}
	})
}

func mustInt(t *testing.T, s string) int64 {
	t.Helper()

	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}

	return n
}

// ---- revoking a user -------------------------------------------------------

// TestRevokingAUserRevokesTheirAgents: an agent's authority is borrowed from its
// user, so revoking the account revokes every agent and every agent key, in one
// write; a refused revocation (the last admin) leaves them untouched; an admin
// cannot revoke another user's agent through the agent routes.
//
//nolint:paralleltest // shares one database
func TestRevokingAUserRevokesTheirAgents(t *testing.T) {
	world := agNewPair(t, roleMember)

	// B has 3 agents (one already revoked at 500), each with a key; A has one.
	for i := 1; i <= 3; i++ {
		seedAgent(t, idN(agIDPrefix, i), world.b.userID, "b"+strconv.Itoa(i))
		seedAPIKey(t, idN(agKeyPref, i), world.b.userID, idN(agIDPrefix, i))
	}

	seed(t, "UPDATE agents SET revoked_at = 500 WHERE id = ?", idN(agIDPrefix, 3))
	seedAgent(t, idN(agIDPrefix, 10), world.a.userID, "a1")
	seedAPIKey(t, idN(agKeyPref, 10), world.a.userID, idN(agIDPrefix, 10))

	// The last admin cannot be revoked, so neither are their agents.
	del(t, pathUser+"/"+world.a.userID, world.tokenA).expect(t, "revoke the last admin", http.StatusConflict, "user_last_admin")
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NOT NULL", "0", world.a.userID)
	expectCount(t, keyRows+" WHERE k.agent_id IS NOT NULL AND k.user_id = ? AND revoked_at IS NOT NULL", "0", world.a.userID)

	// An admin has no reach into another user's agents through /api/agent.
	get(t, agItem(idN(agIDPrefix, 1)), world.tokenA).expect(t, "admin GET B's agent", http.StatusNotFound, agCodeMissing)
	del(t, agItem(idN(agIDPrefix, 1)), world.tokenA).expect(t, "admin DELETE B's agent", http.StatusNotFound, agCodeMissing)
	patch(t, agItem(idN(agIDPrefix, 1)), []byte(`{"name":"admin was here"}`), world.tokenA).
		expect(t, "admin PATCH B's agent", http.StatusNotFound, agCodeMissing)

	// Revoking B (a member) revokes B's agents and keys, not A's.
	del(t, pathUser+"/"+world.b.userID, world.tokenA).expect(t, "revoke B", http.StatusOK, "")

	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "0", world.b.userID)
	expectCount(t, ownedSecrets+" WHERE o.user_id = ? AND s.revoked_at IS NULL", "0", world.b.userID)
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "1", world.a.userID)
	expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NULL", "1", idN(agIDPrefix, 10))

	// The agent that was already revoked keeps its earlier time.
	if got := scalar(t, "SELECT revoked_at FROM agents WHERE id = ?", idN(agIDPrefix, 3)); got != "500" {
		t.Errorf("an already revoked agent's revoked_at = %s after revoking its user, want 500", got)
	}

	// B's rows are all still there (revoke, never delete) but B is signed out.
	expectCount(t, "agents WHERE user_id = ?", "3", world.b.userID)
	get(t, pathAgent, world.tokenB).expect(t, "B after revocation", http.StatusUnauthorized, codeUnauthenticated)

	// Revoking B again keeps everything; A's agent is still active and listed.
	del(t, pathUser+"/"+world.b.userID, world.tokenA).expect(t, "revoke B again", http.StatusOK, "")
	expectCount(t, "agents WHERE user_id = ? AND revoked_at = 500", "1", world.b.userID)

	list := agDecode[agPage](t, get(t, pathAgent, world.tokenA))
	if len(list.Agents) != 1 || list.Agents[0].Name != "a1" || list.Agents[0].Status != "active" {
		t.Errorf("A's list = %+v", list.Agents)
	}
}

// TestAgentCreateCountsOnlyTheOwnersActive checks that
// agents: rows of another user, revoked
// rows and rows of a revoked user are all irrelevant to a user's cap.
//
//nolint:paralleltest // shares one database
func TestAgentCreateCountsOnlyTheOwnersActive(t *testing.T) {
	world := agNewPair(t, roleMember)

	agSeedMany(t, world.a.userID, 1, agMaxAgents)
	agSeedMany(t, world.b.userID, 101, agMaxAgents)
	seed(t, "UPDATE agents SET revoked_at = 1 WHERE id = ?", idN(agIDPrefix, 101))

	// A is full, B has 24 active + 1 revoked: B fits exactly one, A none.
	agCreate(t, world.tokenA, "a over").expect(t, "A at the cap", http.StatusConflict, agCodeLimit)
	agCreate(t, world.tokenB, "b fits").expect(t, "B with a revoked one", http.StatusCreated, "")
	agCreate(t, world.tokenB, "b over").expect(t, "B at the cap", http.StatusConflict, agCodeLimit)
	expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", world.b.userID)
}

// ---- CORS and CSRF on the agent routes --------------------------------------

// TestAgentCORS: the UI origin may preflight every agent route (and only with
// the real method), no other origin gets CORS headers, and a cross-origin
// "simple" write (text/plain) is refused before anything is written, which is
// the CSRF defence of every unsafe route.
//
//nolint:paralleltest // shares one database
func TestAgentCORS(t *testing.T) {
	world := agNewPair(t, roleMember)
	seedAgent(t, idAgentA, world.b.userID, "mine")

	const foreign = "https://evil.example"

	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, pathAgent}, {http.MethodPost, pathAgent},
		{http.MethodGet, agItem(idAgentA)}, {http.MethodPatch, agItem(idAgentA)}, {http.MethodDelete, agItem(idAgentA)},
	} {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			allowed := send(t, request{method: http.MethodOptions, path: rt.path, headers: map[string]string{
				"Origin": target.origin, "Access-Control-Request-Method": rt.method,
				"Access-Control-Request-Headers": "content-type",
			}})
			if allowed.status != http.StatusNoContent || allowed.header.Get("Access-Control-Allow-Methods") != rt.method ||
				allowed.header.Get("Access-Control-Allow-Origin") != target.origin ||
				allowed.header.Get("Access-Control-Allow-Credentials") != "true" ||
				allowed.header.Get("Access-Control-Allow-Headers") != "Content-Type" {
				t.Errorf("preflight from the UI = %d %v, want 204 allowing %s with credentials", allowed.status, allowed.header, rt.method)
			}

			foreignPreflight := send(t, request{method: http.MethodOptions, path: rt.path, headers: map[string]string{
				"Origin": foreign, "Access-Control-Request-Method": rt.method,
			}})
			if foreignPreflight.header.Get("Access-Control-Allow-Origin") != "" ||
				foreignPreflight.header.Get("Access-Control-Allow-Credentials") != "" {
				t.Errorf("preflight from %s got CORS headers: %v", foreign, foreignPreflight.header)
			}

			// An Authorization-style header is not allowed.
			odd := send(t, request{method: http.MethodOptions, path: rt.path, headers: map[string]string{
				"Origin": target.origin, "Access-Control-Request-Method": rt.method,
				"Access-Control-Request-Headers": "authorization",
			}})
			if odd.header.Get("Access-Control-Allow-Headers") != "" {
				t.Errorf("preflight asking for Authorization was allowed: %v", odd.header)
			}
		})
	}

	// A cross-origin write that a browser may send without a preflight is
	// refused by the media type, and writes nothing.
	for _, rt := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodPost, pathAgent, []byte(`{"name":"csrf"}`)},
		{http.MethodPatch, agItem(idAgentA), []byte(`{"name":"csrf"}`)},
		{http.MethodDelete, agItem(idAgentA), nil},
	} {
		got := send(t, request{
			method: rt.method, path: rt.path, body: rt.body, token: world.tokenB,
			headers: map[string]string{"Origin": foreign, "Content-Type": "text/plain"},
		})
		got.expect(t, "cross-origin text/plain "+rt.method, http.StatusUnsupportedMediaType, codeUnsupportedType)

		if got.header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("a foreign origin was allowed on %s: %v", rt.method, got.header)
		}
	}

	expectCount(t, "agents WHERE name = 'csrf'", "0")
	expectCount(t, "agents WHERE id = ? AND revoked_at IS NULL AND name = 'mine'", "1", idAgentA)
}
