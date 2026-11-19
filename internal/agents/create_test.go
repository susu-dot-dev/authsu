package agents_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// nameBody is the body of a create or rename carrying name.
func nameBody(t *testing.T, name string) string {
	t.Helper()

	return marshal(t, map[string]string{fieldName: name})
}

// keyTokenPattern is the shape of an API key token: the key prefix and a
// 43-character base64url body.
var keyTokenPattern = regexp.MustCompile(`^susu_key_[A-Za-z0-9_-]{43}$`)

// TestCreateWritesTheAgentAndItsKey is the whole of a create: one key is
// issued for the agent's lifetime, one write is made, and the key that is
// returned to the client is the one that was written. The token has the shape of
// an API key, only its hash is stored, the key's id and expiry are the ones that
// reached the store, and the returned token is accepted as that agent's key.
func TestCreateWritesTheAgentAndItsKey(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyAssistant)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %q, want 201", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Content-Type"); got != jsonType {
		t.Errorf("Content-Type = %q, want %q", got, jsonType)
	}

	var response agents.CreateResponse

	err := json.Unmarshal(rec.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}

	expires := rg.now.Add(90 * 24 * time.Hour)
	issued := checkKeyIssued(t, rg, expires)
	written := checkWrite(t, rg, issued, expires)

	// The response is built from what was written.
	wantAgent := createdAgent(newAgentID, "assistant", rg.now.Unix())
	if !reflect.DeepEqual(response.Agent, wantAgent) {
		t.Errorf("agent = %+v, want %+v", response.Agent, wantAgent)
	}

	wantKey := agents.Key{
		ID: newKeyID, Token: issued.Token, Scopes: []string{scope.DefaultAgent}, ExpiresAt: expires.Unix(),
	}
	if !reflect.DeepEqual(response.Key, wantKey) {
		t.Errorf("key = %+v, want %+v", response.Key, wantKey)
	}

	checkToken(t, response.Key, written)

	// The agent is the user's, and only theirs.
	mine := rg.as(rg.signIn(userA, roleMember), http.MethodGet, itemPrefix+newAgentID, "")
	theirs := rg.as(rg.signIn(userB, roleMember), http.MethodGet, itemPrefix+newAgentID, "")

	if mine.Code != http.StatusOK || theirs.Code != http.StatusNotFound {
		t.Errorf("the new agent: its owner gets %d, another user %d, want 200 and 404", mine.Code, theirs.Code)
	}
}

// checkKeyIssued asserts that exactly one key was issued, for the agent's key
// lifetime from the routes' clock and without an error, and returns it.
func checkKeyIssued(t *testing.T, rg *rig, expires time.Time) auth.Issued {
	t.Helper()

	if len(rg.issueCalls) != 1 {
		t.Fatalf("issued %d keys, want 1", len(rg.issueCalls))
	}

	call := rg.issueCalls[0]

	if call.now != rg.now || call.lifetime != auth.AgentKeyLifetime || call.err != nil {
		t.Errorf("issued at %v for %v with error %v, want %v for %v and no error",
			call.now, call.lifetime, call.err, rg.now, auth.AgentKeyLifetime)
	}

	if !call.issued.ExpiresAt.Equal(expires) {
		t.Errorf("the key expires at %v, want %v", call.issued.ExpiresAt, expires)
	}

	return call.issued
}

// checkWrite asserts that exactly one write was made, of the agent and of the
// key that was issued, and returns what was written.
func checkWrite(t *testing.T, rg *rig, issued auth.Issued, expires time.Time) store.NewAgent {
	t.Helper()

	name, err := input.ParseAgentName("assistant")
	if err != nil {
		t.Fatal(err)
	}

	want := store.NewAgent{
		ID: newAgentID, Owner: userA, Name: name, Scopes: defaultAgentJSON, KeyScope: defaultAgentJSON,
		MaxActive: agents.MaxAgentsPerUser, KeyID: issued.ID, KeyHash: issued.Hash,
		KeyExpiresAt: expires, CreatedAt: rg.now,
	}

	if len(rg.store.calls) != 1 || rg.store.calls[0].method != methodCreate {
		t.Fatalf("store calls = %+v, want one create", rg.store.calls)
	}

	written := rg.store.calls[0].agent
	if !reflect.DeepEqual(written, want) {
		t.Errorf("written = %+v, want %+v", written, want)
	}

	return written
}

// checkToken asserts that the returned token is the one whose hash was stored,
// and that nothing but the hash was: the token is an API key of the right shape,
// its id is the stored key's, and the stored hash is the SHA-256 of the whole
// token, prefix included.
func checkToken(t *testing.T, key agents.Key, written store.NewAgent) {
	t.Helper()

	if !keyTokenPattern.MatchString(key.Token) {
		t.Errorf("token %q is not susu_key_ and %d characters", key.Token, secret.BodyLen)
	}

	hash := secret.Hash(key.Token)
	if !bytes.Equal(written.KeyHash, hash[:]) || len(written.KeyHash) != sha256.Size {
		t.Errorf("stored hash = %x, want the SHA-256 of the token, %x", written.KeyHash, hash)
	}

	if key.ID != written.KeyID {
		t.Errorf("key id = %q, stored %q", key.ID, written.KeyID)
	}

	stored := string(written.KeyHash) + written.KeyID + written.KeyScope
	if strings.Contains(stored, key.Token) {
		t.Error("the token itself reached the store")
	}
}

// createdAgent is the agent a create returns.
func createdAgent(id, name string, createdAt int64) agents.Agent {
	return agents.Agent{
		ID: id, Name: name, Scopes: []string{scope.DefaultAgent}, Status: agents.StatusActive, RevokedAt: nil,
		CreatedAt: createdAt, Labels: []string{},
	}
}

// TestCreateResponseJSON pins the exact JSON of a create, key included: the key
// has an id, a token, scopes and an expiry, and nothing else.
func TestCreateResponseJSON(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyAssistant)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %q, want 201", rec.Code, rec.Body.String())
	}

	token := rg.issueCalls[0].issued.Token
	want := `{"agent":` + agentJSON(newAgentID, "assistant", rg.now.Unix(), nil) + `,"key":{"id":"` + newKeyID +
		`","token":"` + token + `","scopes":["default:agent"],"expiresAt":` +
		strconv.FormatInt(rg.now.Add(auth.AgentKeyLifetime).Unix(), 10) + `}}` + "\n"

	if rec.Body.String() != want {
		t.Errorf("body = %s, want %s", rec.Body.String(), want)
	}
}

// TestCreatedKeyIsTheAgentsKey: the token a create returns is accepted by the
// boundary as the new agent's key, with the scopes it was given, and only that.
// An agent's token is not accepted where a session is, nor with one character
// changed.
func TestCreatedKeyIsTheAgentsKey(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyAssistant)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %q, want 201", rec.Code, rec.Body.String())
	}

	response := created(t, rec.Body.Bytes())
	written := rg.store.calls[0].agent

	rg.creds.keys[string(written.KeyHash)] = storeKeyRow(written, rg)

	good := rg.withKey("Bearer "+response.Key.Token, http.MethodGet, collection, "")
	if good.Code != http.StatusOK {
		t.Errorf("the returned token was refused: %d %s", good.Code, good.Body)
	}

	altered := response.Key.Token[:len(response.Key.Token)-4] + "AAAA"
	if got := rg.withKey("Bearer "+altered, http.MethodGet, collection, ""); got.Code != http.StatusUnauthorized {
		t.Errorf("an altered token was accepted: %d %s", got.Code, got.Body)
	}

	asSession := rg.serve(request{
		method: http.MethodGet, target: collection, cookies: []*http.Cookie{sessionCookie(response.Key.Token)},
	})
	if asSession.Code != http.StatusUnauthorized {
		t.Errorf("the key was accepted as a session: %d %s", asSession.Code, asSession.Body)
	}
}

// TestCreateAcceptsNamesAsTheyAre: a name is stored and returned exactly as
// sent, never trimmed or rewritten, up to the bounds the schema also holds.
func TestCreateAcceptsNamesAsTheyAre(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "one character", value: "a"},
		{name: "ordinary", value: "my assistant"},
		{name: "leading and trailing spaces are kept", value: "  padded  "},
		{name: "quotes and markup", value: `a "b" <c> & 'd' \ e`},
		{name: "inner double spaces", value: "my  helper bot"},
		{name: "punctuation", value: "ci/cd: nightly (v2)"},
		{name: "an astral emoji", value: "robot \U0001F916"},
		{name: "sql-looking text", value: "'; DROP TABLE agents; --"},
		{name: "a precomposed accent", value: "caf\u00e9"},
		{name: "non-latin", value: "\u30a8\u30fc\u30b8\u30a7\u30f3\u30c8"},
		{name: "an emoji with a variation selector", value: "\u2764\ufe0f"},
		{name: "256 ascii", value: strings.Repeat("a", 256)},
		{name: "256 two-byte characters", value: strings.Repeat("\u00e9", 256)},
		{name: "256 four-byte characters", value: strings.Repeat("\U0001F600", 256)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, nameBody(t, tt.value))

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body %.200q, want 201", rec.Code, rec.Body.String())
			}

			var response agents.CreateResponse

			err := json.Unmarshal(rec.Body.Bytes(), &response)
			if err != nil {
				t.Fatal(err)
			}

			written := rg.store.calls[0].agent.Name.String()

			if response.Agent.Name != tt.value || written != tt.value {
				t.Errorf("name came back as %.60q and was written as %.60q, want %.60q", response.Agent.Name, written, tt.value)
			}

			// The schema allows 1024 bytes.
			if len(written) > 1024 {
				t.Errorf("a name of %d bytes was written; the schema's limit is 1024", len(written))
			}
		})
	}
}

// TestCreateRefusesNamesThatAreNotCanonicalText: one value per rule class, and
// each is refused before a key is created or anything is written.
func TestCreateRefusesNamesThatAreNotCanonicalText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "only spaces", value: "   "},
		{name: "only a no-break space", value: "\u00a0"},
		{name: "only an ideographic space", value: "\u3000"},
		{name: "a tab", value: "a\tb"},
		{name: "a line feed", value: "a\nb"},
		{name: "a NUL, which SQLite's length() stops at", value: "a\x00b"},
		{name: "a delete character", value: "a\x7fb"},
		{name: "a C1 control", value: "a\u0085b"},
		{name: "a zero-width space", value: "a\u200bb"},
		{name: "only joiners", value: "\u200d\u200c"},
		{name: "a bidi override", value: "a\u202eb"},
		{name: "a bidi isolate", value: "a\u2066b"},
		{name: "a byte order mark", value: "\ufeffa"},
		{name: "a soft hyphen", value: "a\u00adb"},
		{name: "decomposed (NFD) text", value: "cafe\u0301"},
		{name: "257 ascii", value: strings.Repeat("a", 257)},
		{name: "257 two-byte characters", value: strings.Repeat("\u00e9", 257)},
		{name: "257 four-byte characters", value: strings.Repeat("\U0001F600", 257)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, nameBody(t, tt.value))

			wantBadRequest(t, rg, rec, codeInvalidName)
			rg.untouched()
		})
	}
}

// TestCreateNamesTheRuleInTheMessage pins the exact refusal, once.
func TestCreateNamesTheRuleInTheMessage(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, `{"name":""}`)

	wantFailure(t, rg, rec, http.StatusBadRequest, errorBody(codeInvalidName,
		"agent name must be 1 to 256 characters of normalised text without control characters or hidden formatting"),
		codeInvalidName)
}

// TestCreateRefusesBodiesThatAreNotARequest: every shape of a bad body, and the
// ones that smuggle a name in under another spelling.
func TestCreateRefusesBodiesThatAreNotARequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		code string
	}{
		{name: "no body", body: "", code: "empty_body"},
		{name: "not json", body: "nope", code: codeInvalidJSON},
		{name: "truncated", body: `{"name":"a"`, code: codeInvalidJSON},
		{name: "an array", body: `["a"]`, code: codeFieldType},
		{name: "a number for the name", body: `{"name":1}`, code: codeFieldType},
		{name: "an object for the name", body: `{"name":{}}`, code: codeFieldType},
		{name: "no name", body: `{}`, code: codeInvalidName},
		{name: "a null name", body: `{"name":null}`, code: codeInvalidName},
		{name: "a null body", body: `null`, code: codeInvalidName},
		{name: "a member in another case", body: `{"Name":"a"}`, code: codeUnknownField},
		{name: "an unknown member", body: `{"name":"a","extra":1}`, code: codeUnknownField},
		{name: "a repeated name", body: `{"name":"a","name":"b"}`, code: codeDuplicate},
		{name: "trailing data", body: `{"name":"a"} {}`, code: "trailing_data"},
		{name: "invalid utf-8", body: "{\"name\":\"a\xffb\"}", code: codeInvalidText},
		{name: "a lone surrogate", body: `{"name":"a\ud800b"}`, code: codeInvalidText},
		{name: "a replacement character", body: `{"name":"a\ufffdb"}`, code: codeInvalidText},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, tt.body)

			wantBadRequest(t, rg, rec, tt.code)
			rg.untouched()
		})
	}
}

// TestCreateRefusesABodyOverTheLimit: a body over the cap is refused before it
// is read, so a huge name can never reach a parser or the database.
func TestCreateRefusesABodyOverTheLimit(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection,
		`{"name":"`+strings.Repeat("a", 2<<20)+`"}`)

	wantFailure(t, rg, rec, http.StatusRequestEntityTooLarge,
		errorBody("body_too_large", "request body is too large"), "body_too_large")
	rg.untouched()
}

// capBody is a create or rename body of exactly size bytes whose name is all
// padding.
func capBody(size int) string {
	const head, tail = `{"name":"`, `"}`

	return head + strings.Repeat("a", size-len(head)-len(tail)) + tail
}

// TestBodyCap pins the cap on every route that reads a body: a body of exactly
// agents.MaxBody bytes is read (and refused by the name rule, being all
// padding), and one byte more is 413 before anything is parsed.
func TestBodyCap(t *testing.T) {
	t.Parallel()

	routes := []struct {
		name, method, target string
		seed                 bool
	}{
		{"create", http.MethodPost, collection, false},
		{"rename", http.MethodPatch, itemPrefix + agentA1, true},
	}

	for _, rt := range routes {
		for _, over := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, over the cap: %v", rt.name, over), func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				if rt.seed {
					rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))
				}

				size := agents.MaxBody
				if over {
					size++
				}

				rec := rg.as(rg.signIn(userA, roleMember), rt.method, rt.target, capBody(size))

				if over {
					wantFailure(t, rg, rec, http.StatusRequestEntityTooLarge,
						errorBody("body_too_large", "request body is too large"), "body_too_large")
				} else {
					wantBadRequest(t, rg, rec, codeInvalidName)
				}

				rg.untouched()
			})
		}
	}
}

// TestLargestLegitimateCreateFitsTheCap: a 256-character name of four-byte
// characters, every one escaped as a surrogate pair, is the largest request a
// client can have a reason to send, and fits with room to spare.
func TestLargestLegitimateCreateFitsTheCap(t *testing.T) {
	t.Parallel()

	body := `{"name":"` + strings.Repeat(`\ud83d\ude00`, 256) + `"}`
	if len(body) > agents.MaxBody/2 {
		t.Fatalf("largest legitimate body is %d bytes, more than half the %d cap", len(body), agents.MaxBody)
	}

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, body)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: %s", rec.Code, rec.Body)
	}
}

// createFailure is one way a create fails, and what it leaves behind.
type createFailure struct {
	name    string
	prepare func(*rig)
	status  int
	body    string
	logged  string
	// issued is how many keys were asked for, and writes how many writes tried.
	issued, writes int
}

// createFailures are the ways a create fails after the request was accepted.
func createFailures() []createFailure {
	return []createFailure{
		{
			name: "the key cannot be issued", prepare: func(rg *rig) { rg.issueErr = errEntropy },
			status: http.StatusInternalServerError, body: bodyInternal, logged: agents.CodeKeyFailed, issued: 1, writes: 0,
		},
		{
			name: "the key's lifetime is refused", prepare: func(rg *rig) { rg.issueErr = auth.ErrKeyLifetime },
			status: http.StatusInternalServerError, body: bodyInternal, logged: agents.CodeKeyFailed, issued: 1, writes: 0,
		},
		{
			name: "the entropy source fails", prepare: func(rg *rig) { rg.entropy = brokenReader{} },
			status: http.StatusInternalServerError, body: bodyInternal, logged: agents.CodeKeyFailed, issued: 1, writes: 0,
		},
		{
			name: "the user is at the limit, or was revoked",
			prepare: func(rg *rig) {
				rg.store.failures[methodCreate] = store.Classify(errNotNull)
			},
			status: http.StatusConflict,
			body:   errorBody("agent_limit_reached", "an account may have at most 25 active agents"),
			logged: agents.CodeLimit, issued: 1, writes: 1,
		},
		{
			name: "the database fails",
			prepare: func(rg *rig) {
				rg.store.failures[methodCreate] = unavailableErr("agent_create_failed")
			},
			status: http.StatusServiceUnavailable,
			body:   errorBody("agent_create_failed", "agents are temporarily unavailable"),
			logged: "agent_create_failed", issued: 1, writes: 1,
		},
	}
}

// TestCreateFailures: what a failed create leaves behind and tells the client.
func TestCreateFailures(t *testing.T) {
	t.Parallel()

	for _, tt := range createFailures() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			tt.prepare(rg)

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyAssistant)

			wantFailure(t, rg, rec, tt.status, tt.body, tt.logged)

			if len(rg.issueCalls) != tt.issued || rg.writes() != tt.writes {
				t.Errorf("issued %d keys and made %d writes, want %d and %d", len(rg.issueCalls), rg.writes(), tt.issued, tt.writes)
			}

			if len(rg.store.rows) != 0 {
				t.Errorf("a failed create left %+v", rg.store.rows)
			}
		})
	}
}

// TestCreateDoesNotLeakTheIssueFailure: a client is told only "internal error".
// The cause of a failed issue is in the log and never in the response.
func TestCreateDoesNotLeakTheIssueFailure(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.entropy = brokenReader{}

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyAssistant)

	if strings.Contains(rec.Body.String(), errEntropy.Error()) {
		t.Errorf("the response carries the cause: %s", rec.Body)
	}

	if len(rg.logged) != 1 || !errors.Is(rg.logged[0], errEntropy) {
		t.Errorf("logged %v, want one failure caused by %v", rg.logged, errEntropy)
	}
}
