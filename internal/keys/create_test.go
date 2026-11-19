package keys_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/keys"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// marshal encodes v as JSON, failing the test if it cannot be.
func marshal(t *testing.T, v any) string {
	t.Helper()

	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return string(encoded)
}

// nameBody is the body of a create or rename carrying name.
func nameBody(t *testing.T, name string) string {
	t.Helper()

	return marshal(t, map[string]string{"name": name})
}

// keyTokenPattern is the shape of an API key token: the key prefix and a
// 43-character base64url body.
var keyTokenPattern = regexp.MustCompile(`^susu_key_[A-Za-z0-9_-]{43}$`)

// created is the parsed body of a successful create.
func created(t *testing.T, body []byte) keys.CreateResponse {
	t.Helper()

	var response keys.CreateResponse

	err := json.Unmarshal(body, &response)
	if err != nil {
		t.Fatalf("body %q: %v", body, err)
	}

	return response
}

// TestCreateWritesTheKey is the whole of a create: one key is issued for the
// default lifetime, one write is made, and the token that is returned to the
// client is the one whose hash was written. The token has the shape of an API
// key, only its hash is stored, the key's id and expiry are the ones that
// reached the store, and the returned token is accepted as that user's own key.
func TestCreateWritesTheKey(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyCI)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %q, want 201", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Content-Type"); got != jsonType {
		t.Errorf("Content-Type = %q, want %q", got, jsonType)
	}

	response := created(t, rec.Body.Bytes())

	checkIssued(t, rg)

	if len(rg.store.calls) != 1 || rg.store.calls[0].method != methodCreate {
		t.Fatalf("store calls = %+v, want one create", rg.store.calls)
	}

	written := rg.store.calls[0].key
	checkWritten(t, rg, written)
	checkResponse(t, rg, response)
	checkToken(t, response.Token, written)
}

// checkIssued asserts that exactly one key was issued, at the clock, for the
// default lifetime.
func checkIssued(t *testing.T, rg *rig) {
	t.Helper()

	if len(rg.issueCalls) != 1 {
		t.Fatalf("issued %d keys, want 1", len(rg.issueCalls))
	}

	call := rg.issueCalls[0]
	if call.now != rg.now || call.lifetime != input.DefaultKeyLifetime().Duration() || call.err != nil {
		t.Errorf("issued at %v for %v with error %v, want %v for %v and no error",
			call.now, call.lifetime, call.err, rg.now, input.DefaultKeyLifetime().Duration())
	}
}

// checkWritten asserts the NewKey the store was given.
func checkWritten(t *testing.T, rg *rig, written store.NewKey) {
	t.Helper()

	name, err := input.ParseKeyName("ci")
	if err != nil {
		t.Fatal(err)
	}

	want := store.NewKey{
		ID: newKeyID, Owner: userA, Name: name, Scope: defaultUserJSON, Hash: rg.issueCalls[0].issued.Hash,
		ExpiresAt: rg.now.Add(90 * 24 * time.Hour), MaxActive: keys.MaxKeysPerUser, CreatedAt: rg.now,
	}

	if !reflect.DeepEqual(written, want) {
		t.Errorf("written = %+v, want %+v", written, want)
	}
}

// checkResponse asserts the key a create returns.
func checkResponse(t *testing.T, rg *rig, response keys.CreateResponse) {
	t.Helper()

	want := keys.CreateResponse{
		ID: newKeyID, Name: "ci", Scopes: []string{scope.DefaultUser}, Status: keys.StatusActive,
		ExpiresAt: rg.now.Add(90 * 24 * time.Hour).Unix(), RevokedAt: nil, CreatedAt: rg.now.Unix(),
		Token: rg.issueCalls[0].issued.Token,
	}

	if !reflect.DeepEqual(response, want) {
		t.Errorf("response = %+v, want %+v", response, want)
	}
}

// checkToken asserts that the returned token is the one whose hash was stored,
// and that nothing but the hash was: the token is an API key of the right shape,
// and the stored hash is the SHA-256 of the whole token, prefix included.
func checkToken(t *testing.T, token string, written store.NewKey) {
	t.Helper()

	if !keyTokenPattern.MatchString(token) {
		t.Errorf("token %q is not susu_key_ and %d characters", token, secret.BodyLen)
	}

	hash := secret.Hash(token)
	if !bytes.Equal(written.Hash, hash[:]) || len(written.Hash) != sha256.Size {
		t.Errorf("stored hash = %x, want the SHA-256 of the token, %x", written.Hash, hash)
	}

	stored := string(written.Hash) + written.ID + written.Scope + written.Name.String()
	if strings.Contains(stored, token) {
		t.Error("the token itself reached the store")
	}
}

// TestCreateResponseJSON pins the exact JSON of a create: the key's fields and
// the token, and nothing else.
func TestCreateResponseJSON(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyCI)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %q, want 201", rec.Code, rec.Body.String())
	}

	token := rg.issueCalls[0].issued.Token
	want := fmt.Sprintf(`{"id":%q,"name":"ci","scopes":["default:user"],"status":"active","expiresAt":%d,`+
		`"createdAt":%d,"token":%q}`+"\n",
		newKeyID, rg.now.Add(input.DefaultKeyLifetime().Duration()).Unix(), rg.now.Unix(), token)

	if rec.Body.String() != want {
		t.Errorf("body = %s, want %s", rec.Body.String(), want)
	}
}

// TestCreatedKeyIsTheUsersOwnKey: the token a create returns is accepted by the
// boundary as the user's own key with the scopes it was given, and nowhere else.
// It is not accepted where a session is, nor with one character changed.
func TestCreatedKeyIsTheUsersOwnKey(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, `{"name":"ci","scopes":["key:read"]}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %q, want 201", rec.Code, rec.Body.String())
	}

	response := created(t, rec.Body.Bytes())
	written := rg.store.calls[0].key

	// Store the row the way the database would, found by the hash that was written.
	rg.creds.keys[string(written.Hash)] = store.ActiveAPIKey{
		ID: written.ID, UserID: written.Owner, Role: roleMember, ExpiresAt: written.ExpiresAt,
		AgentID: "", AgentScopes: "", Scope: written.Scope,
	}

	header := "Bearer " + response.Token

	if got := rg.withKey(header, http.MethodGet, collection, ""); got.Code != http.StatusOK {
		t.Errorf("the returned token was refused: %d %s", got.Code, got.Body)
	}

	// It was given key:read and nothing else: it cannot create, and it cannot
	// create anyway because creating needs a session.
	if got := rg.withKey(header, http.MethodPatch, itemPrefix+keyA1, bodyRenamed); got.Code != http.StatusForbidden {
		t.Errorf("a scope the key was not given was allowed: %d %s", got.Code, got.Body)
	}

	altered := response.Token[:len(response.Token)-4] + "AAAA"
	if got := rg.withKey("Bearer "+altered, http.MethodGet, collection, ""); got.Code != http.StatusUnauthorized {
		t.Errorf("an altered token was accepted: %d %s", got.Code, got.Body)
	}

	asSession := rg.serve(request{
		method: http.MethodGet, target: collection, cookies: []*http.Cookie{sessionCookie(response.Token)},
	})
	if asSession.Code != http.StatusUnauthorized {
		t.Errorf("the key was accepted as a session: %d %s", asSession.Code, asSession.Body)
	}
}

// TestCreateScopes: an absent or null list is the default bundle written out in
// full; a list that is present, even empty, is exactly what was asked for, in
// the order sent. The key's row, the response and the stored text agree.
func TestCreateScopes(t *testing.T) {
	t.Parallel()

	def := []string{scope.DefaultUser}

	tests := []struct {
		name string
		body string
		want []string
	}{
		{"no list: the default", `{"name":"a"}`, def},
		{"a null list: the default", `{"name":"a","scopes":null}`, def},
		{"an empty list stays empty", `{"name":"a","scopes":[]}`, []string{}},
		{"one scope", `{"name":"a","scopes":["key:read"]}`, []string{"key:read"}},
		{
			"a bundle and a scope", `{"name":"a","scopes":["default:agent","key:create"]}`,
			[]string{"default:agent", "key:create"},
		},
		{"the session bundle", `{"name":"a","scopes":["default:session"]}`, []string{"default:session"}},
		{
			"admin scopes are accepted: the role gates them", `{"name":"a","scopes":["user:read"]}`,
			[]string{"user:read"},
		},
		{"order is kept", `{"name":"a","scopes":["key:read","agent:read"]}`, []string{"key:read", "agent:read"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, tt.body)

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}

			response := created(t, rec.Body.Bytes())

			if !slices.Equal(response.Scopes, tt.want) {
				t.Errorf("response scopes = %v, want %v", response.Scopes, tt.want)
			}

			// Responses always carry an array, never null.
			if !strings.Contains(rec.Body.String(), `"scopes":[`) {
				t.Errorf("the body has no scopes array: %s", rec.Body)
			}

			if got := rg.store.calls[0].key.Scope; got != scope.List(tt.want).JSON() {
				t.Errorf("written scope = %s, want %s", got, scope.List(tt.want).JSON())
			}
		})
	}
}

// badScopeLists are JSON lists that name anything but known scopes and bundles.
func badScopeLists() map[string]string {
	repeated := strings.Repeat(`"agent:read",`, 32) + `"agent:read"`

	return map[string]string{
		"an unknown scope":              `["agent:reed"]`,
		"an unknown resource":           `["nope:read"]`,
		"an unknown bundle":             `["default:admin"]`,
		"all is not a name":             `["all"]`,
		"a wildcard":                    `["*"]`,
		"an empty name":                 `[""]`,
		"the same scope twice":          `["agent:read","agent:read"]`,
		"two names in one string":       `["agent:read agent:create"]`,
		caseUpper:                       `["AGENT:READ"]`,
		"padding":                       `[" agent:read"]`,
		"a NUL":                         `["agent:read\u0000"]`,
		"a number":                      `[1]`,
		"null in the list":              `[null]`,
		"an object":                     `[{"agent":"read"}]`,
		"a nested list":                 `[["agent:read"]]`,
		"one name over the entry bound": `[` + repeated + `]`,
		"a name a kilobyte long":        `["` + strings.Repeat("a", 1<<10) + `"]`,
		"a lone surrogate":              `["agent:\ud800"]`,
	}
}

// TestCreateRefusesBadScopes: a list that names anything but known scopes and
// bundles is refused whole, before a key is issued or anything is written, with
// a message that never echoes it.
func TestCreateRefusesBadScopes(t *testing.T) {
	t.Parallel()

	for name, list := range badScopeLists() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, `{"name":"a","scopes":`+list+`}`)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d (%s), want 400", rec.Code, rec.Body.String())
			}

			rg.untouched()
		})
	}

	t.Run("the refusal is fixed text", func(t *testing.T) {
		t.Parallel()

		rg := newRig(t)
		rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection,
			`{"name":"a","scopes":["secret-typo-zzz"]}`)

		wantFailure(t, rg, rec, http.StatusBadRequest,
			errorBody("invalid_scopes", "scopes must be a list of at most 32 distinct, known scope or bundle names"),
			"invalid_scopes")

		if strings.Contains(rec.Body.String(), "typo") {
			t.Error("the refusal echoed the input")
		}
	})
}

// TestCreateRefusesOversizedScopeArrays: an array past the entry bound is
// refused by the decoder (maxitems) before it is allocated or parsed, however
// large, and nothing is issued or written. The last case fills the body limit.
func TestCreateRefusesOversizedScopeArrays(t *testing.T) {
	t.Parallel()

	fill := strings.Repeat(`"a",`, (keys.MaxBody-64)/4) + `"a"`

	tests := []struct {
		name string
		list string
	}{
		{"one past the entry bound", `[` + strings.Repeat(`"agent:read",`, 32) + `"agent:read"]`},
		{"far past the entry bound", `[` + strings.Repeat(`"agent:read",`, 200) + `"agent:read"]`},
		{"an array filling the body limit", `[` + fill + `]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, `{"name":"a","scopes":`+tt.list+`}`)

			wantFailure(t, rg, rec, http.StatusBadRequest,
				errorBody("too_many_items", "request body has an array with too many items"), "too_many_items")
			rg.untouched()
		})
	}
}

// TestScopesOfTheWrongJSONType: a list that is not a JSON array is refused by the
// decoder, before the scope parser sees it.
func TestScopesOfTheWrongJSONType(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"name":"a","scopes":"agent:read"}`, `{"name":"a","scopes":{}}`, `{"name":"a","scopes":1}`,
		`{"name":"a","scopes":true}`,
	} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, body)

			wantBadRequest(t, rg, rec, codeFieldType)
			rg.untouched()
		})
	}
}

// TestCreateLifetime: an absent or null lifetime is the default of 90 days; a
// lifetime of whole days from 1 to 365 is that many days, from the clock, and is
// the expiry that is written and returned. Anything else is refused before a key
// is issued.
func TestCreateLifetime(t *testing.T) {
	t.Parallel()

	const day = 24 * time.Hour

	tests := []struct {
		name string
		body string
		want time.Duration
	}{
		{"absent: the default", `{"name":"a"}`, 90 * day},
		{"null: the default", `{"name":"a","lifetimeDays":null}`, 90 * day},
		{"one day", `{"name":"a","lifetimeDays":1}`, day},
		{"the default, named", `{"name":"a","lifetimeDays":90}`, 90 * day},
		{"a year less a day", `{"name":"a","lifetimeDays":364}`, 364 * day},
		{"a year", `{"name":"a","lifetimeDays":365}`, 365 * day},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, tt.body)

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}

			response := created(t, rec.Body.Bytes())
			want := rg.now.Add(tt.want)

			if response.ExpiresAt != want.Unix() || rg.store.calls[0].key.ExpiresAt.Unix() != want.Unix() {
				t.Errorf("expiresAt = %d, written %d, want %d",
					response.ExpiresAt, rg.store.calls[0].key.ExpiresAt.Unix(), want.Unix())
			}

			if rg.issueCalls[0].lifetime != tt.want {
				t.Errorf("issued for %v, want %v", rg.issueCalls[0].lifetime, tt.want)
			}
		})
	}
}

// TestCreateRefusesALifetimeItCannotRead: a lifetime that is not a whole number
// of days within bounds is refused, never corrected or clamped, before a key is
// issued.
func TestCreateRefusesALifetimeItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		code string
	}{
		{"zero", `{"name":"a","lifetimeDays":0}`, codeLifetime},
		{"negative", `{"name":"a","lifetimeDays":-1}`, codeLifetime},
		{"a year and a day", `{"name":"a","lifetimeDays":366}`, codeLifetime},
		{"far over", `{"name":"a","lifetimeDays":99999999999}`, codeLifetime},
		{"2^32", `{"name":"a","lifetimeDays":4294967296}`, codeLifetime},
		{"2^32 + 1: one when truncated to 32 bits", `{"name":"a","lifetimeDays":4294967297}`, codeLifetime},
		{"a float", `{"name":"a","lifetimeDays":1.5}`, codeFieldType},
		{"an exponent", `{"name":"a","lifetimeDays":1e2}`, codeFieldType},
		{"a string", `{"name":"a","lifetimeDays":"90"}`, codeFieldType},
		{"a boolean", `{"name":"a","lifetimeDays":true}`, codeFieldType},
		{"an object", `{"name":"a","lifetimeDays":{}}`, codeFieldType},
		{"beyond int64", `{"name":"a","lifetimeDays":9223372036854775808}`, codeFieldType},
		{"the lifetime in seconds is not a member", `{"name":"a","lifetime":90}`, codeUnknown},
		{"an expiry is not a member", `{"name":"a","expiresAt":1900000000}`, codeUnknown},
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

// TestCreateAcceptsNamesAsTheyAre: a name is stored and returned exactly as sent,
// never trimmed or rewritten, up to the bounds the schema also holds.
func TestCreateAcceptsNamesAsTheyAre(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "one character", value: "a"},
		{name: "ordinary", value: "deploy key"},
		{name: "leading and trailing spaces are kept", value: "  padded  "},
		{name: "quotes and markup", value: `a "b" <c> & 'd' \ e`},
		{name: "an astral emoji", value: "key \U0001F511"},
		{name: "sql-looking text", value: "'; DROP TABLE api_keys; --"},
		{name: "a precomposed accent", value: "caf\u00e9"},
		{name: "256 ascii", value: strings.Repeat("a", 256)},
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

			response := created(t, rec.Body.Bytes())
			written := rg.store.calls[0].key.Name.String()

			if response.Name != tt.value || written != tt.value {
				t.Errorf("name came back as %.60q and was written as %.60q, want %.60q", response.Name, written, tt.value)
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
		{name: "a tab", value: "a\tb"},
		{name: "a line feed", value: "a\nb"},
		{name: "a NUL, which SQLite's length() stops at", value: "a\x00b"},
		{name: "a delete character", value: "a\x7fb"},
		{name: "a C1 control", value: "a\u0085b"},
		{name: "a zero-width space", value: "a\u200bb"},
		{name: "only joiners", value: "\u200d\u200c"},
		{name: "a bidi override", value: "a\u202eb"},
		{name: "a byte order mark", value: "\ufeffa"},
		{name: "decomposed (NFD) text", value: "cafe\u0301"},
		{name: "257 ascii", value: strings.Repeat("a", 257)},
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
		"key name must be 1 to 256 characters of normalised text without control characters or hidden formatting"),
		codeInvalidName)
}

// TestCreateRefusesBodiesThatAreNotARequest: every shape of a bad body, and the
// ones that smuggle a member in under another spelling or name something no
// request may.
func TestCreateRefusesBodiesThatAreNotARequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		code string
	}{
		{name: "no body", body: "", code: "empty_body"},
		{name: "not json", body: "nope", code: codeBadJSON},
		{name: "truncated", body: `{"name":"a"`, code: codeBadJSON},
		{name: "an array", body: `["a"]`, code: codeFieldType},
		{name: "a number for the name", body: `{"name":1}`, code: codeFieldType},
		{name: "no name", body: `{}`, code: codeInvalidName},
		{name: "a null name", body: `{"name":null}`, code: codeInvalidName},
		{name: "a null body", body: `null`, code: codeInvalidName},
		{name: "a member in another case", body: `{"Name":"a"}`, code: codeUnknown},
		{name: "an unknown member", body: `{"name":"a","extra":1}`, code: codeUnknown},
		{name: "a repeated name", body: `{"name":"a","name":"b"}`, code: "duplicate_field"},
		{name: "trailing data", body: `{"name":"a"} {}`, code: "trailing_data"},
		{name: "invalid utf-8", body: "{\"name\":\"a\xffb\"}", code: "invalid_text"},
		{name: "a lone surrogate", body: `{"name":"a\ud800b"}`, code: "invalid_text"},
	}

	members := []string{
		"userId", "user_id", "owner", "ownerId", "sub", "act", "id", "kind", "status", "revokedAt", "createdAt",
		"agentId", "agent", "hash", "token", "expiresAt", "keyScopes",
	}

	tests = slices.Grow(tests, len(members))

	for _, member := range members {
		tests = append(tests, struct{ name, body, code string }{
			name: "a body naming " + member, body: `{"name":"x","` + member + `":"` + userA + `"}`, code: codeUnknown,
		})
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

// capBody is a create or rename body of exactly size bytes whose name is all
// padding.
func capBody(size int) string {
	const head, tail = `{"name":"`, `"}`

	return head + strings.Repeat("a", size-len(head)-len(tail)) + tail
}

// TestBodyCap pins the cap on every route that reads a body: a body of exactly
// keys.MaxBody bytes is read (and refused by the name rule, being all padding),
// and one byte more is 413 before anything is parsed.
func TestBodyCap(t *testing.T) {
	t.Parallel()

	routes := []struct {
		name, method, target string
		seed                 bool
	}{
		{"create", http.MethodPost, collection, false},
		{"rename", http.MethodPatch, itemPrefix + keyA1, true},
	}

	for _, rt := range routes {
		for _, over := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, over the cap: %v", rt.name, over), func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				if rt.seed {
					rg.seed(userA, stored(keyA1, nameCI, 100, nil))
				}

				size := keys.MaxBody
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
// characters, every one escaped as a surrogate pair, with every scope and a
// lifetime, is the largest request a client can have a reason to send, and fits
// with room to spare.
func TestLargestLegitimateCreateFitsTheCap(t *testing.T) {
	t.Parallel()

	names := make([]string, 0, len(scope.Scopes()))
	for _, s := range scope.Scopes() {
		names = append(names, string(s))
	}

	body := `{"name":"` + strings.Repeat(`\ud83d\ude00`, 256) + `","scopes":` + marshal(t, names) + `,"lifetimeDays":365}`
	if len(body) > keys.MaxBody/2 {
		t.Fatalf("largest legitimate body is %d bytes, more than half the %d cap", len(body), keys.MaxBody)
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
			status: http.StatusInternalServerError, body: bodyInternal, logged: keys.CodeKeyFailed, issued: 1, writes: 0,
		},
		{
			name: "the key's lifetime is refused", prepare: func(rg *rig) { rg.issueErr = auth.ErrKeyLifetime },
			status: http.StatusInternalServerError, body: bodyInternal, logged: keys.CodeKeyFailed, issued: 1, writes: 0,
		},
		{
			name: "the entropy source fails", prepare: func(rg *rig) { rg.entropy = brokenReader{} },
			status: http.StatusInternalServerError, body: bodyInternal, logged: keys.CodeKeyFailed, issued: 1, writes: 0,
		},
		{
			name:    "the user is at the limit, or was revoked",
			prepare: func(rg *rig) { rg.store.failures[methodCreate] = store.Classify(errNotNull) },
			status:  http.StatusConflict,
			body:    errorBody("key_limit_reached", "an account may have at most 50 active keys"),
			logged:  keys.CodeLimit, issued: 1, writes: 1,
		},
		{
			name:    "the database fails",
			prepare: func(rg *rig) { rg.store.failures[methodCreate] = unavailableErr("key_create_failed") },
			status:  http.StatusServiceUnavailable,
			body:    errorBody("key_create_failed", "keys are temporarily unavailable"),
			logged:  "key_create_failed", issued: 1, writes: 1,
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

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyCI)

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

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyCI)

	if strings.Contains(rec.Body.String(), errEntropy.Error()) {
		t.Errorf("the response carries the cause: %s", rec.Body)
	}

	if len(rg.logged) != 1 || !errors.Is(rg.logged[0], errEntropy) {
		t.Errorf("logged %v, want one failure caused by %v", rg.logged, errEntropy)
	}
}

// TestCreateIsTheCallersOwn: whatever else a request says, the key is written for
// the user the session belongs to, with no agent, and a user's key has no way to
// be issued for someone else.
func TestCreateIsTheCallersOwn(t *testing.T) {
	t.Parallel()

	noise := "?owner=" + userA + "&userId=" + userA + "&user_id=" + userA + "&agent=" + agentA1

	rg := newRig(t)
	rec := rg.as(rg.signIn(userB, roleMember), http.MethodPost, collection+noise, bodyCI)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	if len(rg.store.calls) != 1 || rg.store.calls[0].owner != userB || rg.store.calls[0].key.Owner != userB {
		t.Errorf("store calls = %+v, want one create for owner %s", rg.store.calls, userB)
	}

	// The key is listed for B and not for A.
	mine := rg.as(rg.signIn(userB, roleMember), http.MethodGet, collection, "")
	theirs := rg.as(rg.signIn(userA, roleMember), http.MethodGet, collection, "")

	if !strings.Contains(mine.Body.String(), newKeyID) || strings.Contains(theirs.Body.String(), newKeyID) {
		t.Errorf("the new key: B lists %s, A lists %s", mine.Body, theirs.Body)
	}
}

// TestCreateOfEveryKeyCountsTheLimit pins the limit the write is told, so the
// store's guard is the one the API documents.
func TestCreateOfEveryKeyCountsTheLimit(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, bodyCI)

	if got := rg.store.calls[0].key.MaxActive; got != 50 {
		t.Errorf("the write was told the limit is %d, want 50", got)
	}

	if got := strconv.Itoa(keys.MaxKeysPerUser); got != "50" {
		t.Errorf("MaxKeysPerUser = %s", got)
	}
}
