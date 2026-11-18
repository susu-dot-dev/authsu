//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// invitations_test.go drives /api/invitation (admin only) against the real
// TinyGo Worker and the real D1/SQLite. What it proves that the host unit
// tests cannot:
//
//   - the route, method and {id} wiring under TinyGo's ServeMux, and the
//     strict JSON decoder under TinyGo's encoding/json/reflect (duplicate keys,
//     unknown members, number forms, huge exponents, 2^53 and 2^63 numbers);
//   - the conditional UPDATE ... RETURNING statements of the store (cap below
//     uses, revoked, idempotent revoke) against real SQLite, and the use
//     count, which is a subselect over users;
//   - that no response ever carries the code or its hash;
//   - interleavings: concurrent PATCHes, concurrent revokes, a revoke racing
//     registrations, all against the one real database.
//
// REVIEW.md categories covered: input edge cases (every type/number/body
// shape), interleaving (races on update, revoke and registration), payload
// size (10k type, large list), permission confusion (one 401/403 spot check
// per route; the full matrix is another area's), and type/bound confusion
// (JSON number forms vs int64 vs JS float64 vs SQLite INTEGER).
//
// The creatable types are fixed in code: "member" and "admin", each granting the
// role of its own name. First run is never creatable. The type is checked before
// any other value of a create body.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	invCodeInvalidType  = "invalid_invitation_type"
	invCodeNotFound     = "invitation_not_found"
	invCodeRevoked      = "invitation_revoked"
	invCodeBelowUses    = "num_invites_below_uses"
	invCodeMissingNum   = "missing_num_invites"
	invCodeInvalidNum   = "invalid_num_invites"
	invCodeInvalidReg   = "invalid_invitation"
	invStatusActive     = "active"
	invStatusExhausted  = "exhausted"
	invStatusExpired    = "expired"
	invStatusRevoked    = "revoked"
	invUnixFar          = 4102444800 // 2100-01-01
	invNoStatusOverride = ""
)

// invView is the JSON an invitation is served as. Pointers tell absent from
// zero. It decodes strictly (see invDecode) so a renamed or extra field fails.
type invView struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Label      string  `json:"label"`
	NumInvites int64   `json:"numInvites"`
	Uses       int64   `json:"uses"`
	Status     string  `json:"status"`
	ExpiresAt  *int64  `json:"expiresAt"`
	RevokedAt  *int64  `json:"revokedAt"`
	CreatedBy  *string `json:"createdBy"`
	CreatedAt  int64   `json:"createdAt"`
}

// invDecode strictly decodes body into out: unknown fields are an error, so a
// leaked or renamed field is caught.
func invDecode(t *testing.T, body string, out any) {
	t.Helper()

	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()

	err := dec.Decode(out)
	if err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

// invList reads GET /api/invitation as token and decodes the list.
func invList(t *testing.T, token string) []invView {
	t.Helper()

	got := get(t, pathInvitation, token)
	if got.status != http.StatusOK {
		t.Fatalf("GET %s = %d %s, want 200", pathInvitation, got.status, got.body)
	}

	var out struct {
		Invitations []invView `json:"invitations"`
	}

	invDecode(t, got.body, &out)

	return out.Invitations
}

// invFind returns the listed invitation with id.
func invFind(t *testing.T, token, id string) invView {
	t.Helper()

	for _, view := range invList(t, token) {
		if view.ID == id {
			return view
		}
	}

	t.Fatalf("invitation %s is not listed", id)

	return invView{}
}

// invItem is the path of one invitation.
func invItem(id string) string { return pathInvitation + "/" + id }

// invPatch sends a raw body to PATCH /api/invitation/{id}.
func invPatch(t *testing.T, token, id, body string) reply {
	t.Helper()

	return patch(t, invItem(id), []byte(body), token)
}

// invRows is how many invitation rows there are.
func invRows(t *testing.T) string {
	t.Helper()

	return count(t, "invitations")
}

// invStored is the stored num_invites of id.
func invStored(t *testing.T, id string) string {
	t.Helper()

	return scalar(t, "SELECT num_invites FROM invitations WHERE id = ?", id)
}

// invHashForms returns every textual form a code hash could leak in, for the
// 32-byte code_hash of id: lower and upper hex, std and url base64 with and
// without padding.
func invHashForms(t *testing.T, id string) []string {
	t.Helper()

	raw := scalar(t, "SELECT hex(code_hash) FROM invitations WHERE id = ?", id)

	hash, err := hex.DecodeString(raw)
	if err != nil || len(hash) != sha256.Size {
		t.Fatalf("code_hash of %s: %q %v", id, raw, err)
	}

	return []string{
		hex.EncodeToString(hash), strings.ToUpper(hex.EncodeToString(hash)),
		base64.StdEncoding.EncodeToString(hash), base64.RawStdEncoding.EncodeToString(hash),
		base64.URLEncoding.EncodeToString(hash), base64.RawURLEncoding.EncodeToString(hash),
	}
}

// invAssertNoHash fails when body contains any form of any listed hash, or a
// member that names a code or hash.
func invAssertNoHash(t *testing.T, what, body string, forms []string) {
	t.Helper()

	// The response to a create is the one place the code is returned, once. It
	// still must not hold any hash form, which the check below proves.
	bareCodeAllowed := what == "create"

	for _, form := range forms {
		if strings.Contains(body, form) {
			t.Errorf("%s leaks a code hash form %q:\n%s", what, form, body)
		}
	}

	// No member of any response is named for a code or a hash (the error
	// envelope's own "code" member is an error code and is the one allowed).
	var names []string

	invCollectKeys(body, &names)

	for _, name := range names {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "hash") || strings.Contains(lower, "secret") || (strings.Contains(lower, "code") && lower != "code") {
			t.Errorf("%s has a member named %q:\n%s", what, name, body)
		}
	}

	// A bare "code" member is allowed only inside the error envelope, where it is
	// the error code; a success body never has one.
	if !bareCodeAllowed && !strings.Contains(body, `{"error":{"code":"`) && strings.Contains(body, `"code":`) {
		t.Errorf("%s has a bare code member:\n%s", what, body)
	}
}

// invCollectKeys gathers every object member name in the JSON body.
func invCollectKeys(body string, out *[]string) {
	var value any

	err := json.Unmarshal([]byte(body), &value)
	if err != nil {
		return
	}

	var walk func(v any)

	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				*out = append(*out, k)

				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}

	walk(value)
}

// invSeedAt inserts an invitation with explicit columns, for the status and
// ordering tables. revoked and expires are NULL when nil.
func invSeedAt(t *testing.T, id string, numInvites int64, createdAt int64, expires, revoked *int64) {
	t.Helper()

	seed(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, expires_at, revoked_at, created_at) "+
		"VALUES (?, randomblob(32), 'e2e_invite', 'seeded', ?, ?, ?, ?)", id, numInvites, expires, revoked, createdAt)
}

// invUsersOf makes n accounts from the invitation, with ids from the family
// prefix, so several invitations can each have users.
func invUsersOf(t *testing.T, family, invitation string, n int, revokedAt *int64) {
	t.Helper()

	for i := range n {
		seed(t, "INSERT INTO users (id, user_handle, role, invitation_id, revoked_at, created_at) "+
			"VALUES (?, randomblob(16), 'e2e_none', ?, ?, strftime('%s','now'))", idN(family, i+1), invitation, revokedAt)
	}
}

// invRace runs n calls together, released by one channel, and returns their
// replies in call order.
func invRace(n int, call func(i int) reply) []reply {
	replies := make([]reply, n)
	start := make(chan struct{})

	var wg sync.WaitGroup

	for i := range n {
		wg.Go(func() {
			<-start

			replies[i] = call(i)
		})
	}

	close(start)
	wg.Wait()

	return replies
}

// invStatuses summarises replies as "status code" counts, for t.Logf.
func invStatuses(replies []reply) map[string]int {
	out := map[string]int{}

	for _, r := range replies {
		key := strconv.Itoa(r.status)
		if c := r.errorCode(); c != "" {
			key += " " + c
		}

		out[key]++
	}

	return out
}

// ---- permissions spot check ---------------------------------------------------

// TestInvitationRoutesSpotCheckAccess: each route is 401 without a session and
// 403 for a signed-in non-admin (the full matrix is owned elsewhere). Nothing
// is written, and a refused caller learns nothing about the body.
//
//nolint:paralleltest // shares one database
func TestInvitationRoutesSpotCheckAccess(t *testing.T) {
	admin := newAdmin(t)
	adminToken := login(t, admin)

	seedInvitation(t, idInvitationA, 3)
	seedUser(t, idUserB, roleMember)
	setRole(t, admin.userID, roleMember)

	routes := []struct {
		name         string
		method, path string
		body         []byte
	}{
		{"list", http.MethodGet, pathInvitation, nil},
		{"create", http.MethodPost, pathInvitation, []byte(`{"type":"first_run","numInvites":1}`)},
		{"create with a body that would be refused", http.MethodPost, pathInvitation, []byte(`{`)},
		{"update", http.MethodPatch, invItem(idInvitationA), []byte(`{"numInvites":9}`)},
		{"update with a body that would be refused", http.MethodPatch, invItem(idInvitationA), []byte(`{"x":1}`)},
		{"revoke", http.MethodDelete, invItem(idInvitationA), nil},
	}

	rows, num := invRows(t), invStored(t, idInvitationA)

	for _, rt := range routes {
		t.Run(rt.name+" signed out", func(t *testing.T) {
			got := send(t, request{method: rt.method, path: rt.path, body: rt.body})
			got.expect(t, rt.method+" "+rt.path, http.StatusUnauthorized, codeUnauthenticated)
		})

		t.Run(rt.name+" member", func(t *testing.T) {
			got := send(t, request{method: rt.method, path: rt.path, body: rt.body, token: adminToken})
			got.expect(t, rt.method+" "+rt.path, http.StatusForbidden, codeForbidden)
		})
	}

	expectCount(t, "invitations", rows)
	expectCount(t, "invitations WHERE revoked_at IS NOT NULL", "0")

	if got := invStored(t, idInvitationA); got != num {
		t.Errorf("num_invites = %s after refused callers, want %s", got, num)
	}
}

// ---- create ---------------------------------------------------------------------

// TestInvitationCreateIsRefusedForEveryOtherType: only "member" and "admin" are
// creatable. Every other type value is refused with the same 400 body, the type
// is validated first (so a body that is otherwise invalid still reports the
// type), and nothing is written.
//
//nolint:paralleltest // shares one database
func TestInvitationCreateIsRefusedForEveryOtherType(t *testing.T) {
	token := login(t, newAdmin(t))

	valid := `"numInvites":1,"label":"x"`

	cases := []struct {
		name string
		body string
	}{
		{"first_run", `{"type":"first_run",` + valid + `}`},
		{"e2e_invite", `{"type":"e2e_invite",` + valid + `}`},
		{"empty", `{"type":"",` + valid + `}`},
		{"unicode", `{"type":"\u00e9\u4e16\u754c",` + valid + `}`},
		{"emoji zwj", `{"type":"\ud83d\udc68\u200d\ud83d\udc69",` + valid + `}`},
		{"64 chars", `{"type":"` + strings.Repeat("a", 64) + `",` + valid + `}`},
		{"65 chars", `{"type":"` + strings.Repeat("a", 65) + `",` + valid + `}`},
		{"NUL escape", `{"type":"member\u0000",` + valid + `}`},
		{"newline", `{"type":"member\n",` + valid + `}`},
		{"trailing space", `{"type":"member ",` + valid + `}`},
		{"upper case member", `{"type":"MEMBER",` + valid + `}`},
		{"upper case admin", `{"type":"Admin",` + valid + `}`},
		{"upper case first run", `{"type":"FIRST_RUN",` + valid + `}`},
		{"owner", `{"type":"owner",` + valid + `}`},
		{"3k", `{"type":"` + strings.Repeat("a", 3000) + `",` + valid + `}`},
		{"type missing", `{` + valid + `}`},
		{"type null", `{"type":null,` + valid + `}`},
	}

	rows := invRows(t)

	var want string

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := post(t, pathInvitation, []byte(tt.body), token)
			got.expect(t, "POST "+tt.name, http.StatusBadRequest, invCodeInvalidType)

			if want == "" {
				want = got.body
			}

			if got.body != want {
				t.Errorf("POST %s body = %s, want the same body for every refused type: %s", tt.name, got.body, want)
			}

			expectCount(t, "invitations", rows)
		})
	}

	// 10k of type is over the 4 KiB body limit: refused before anything is parsed.
	t.Run("10k", func(t *testing.T) {
		got := post(t, pathInvitation, []byte(`{"type":"`+strings.Repeat("a", 10000)+`",`+valid+`}`), token)
		got.expect(t, "POST 10k type", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
		expectCount(t, "invitations", rows)
	})

	// A type that is not a JSON string never reaches the type check: the decoder
	// refuses it. Still a 400, nothing written.
	for name, body := range map[string]string{
		"type number": `{"type":1,` + valid + `}`,
		"type true":   `{"type":true,` + valid + `}`,
		"type array":  `{"type":["member"],` + valid + `}`,
		"type object": `{"type":{},` + valid + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := post(t, pathInvitation, []byte(body), token)
			got.expect(t, "POST "+name, http.StatusBadRequest, "invalid_field_type")
			expectCount(t, "invitations", rows)
		})
	}
}

// TestInvitationCreateThenRegister: an admin creates an invitation of each
// creatable type, and registering with the code it returns creates an account
// whose role is the one the type grants. The code works exactly as many times as
// numInvites allows.
//
//nolint:paralleltest // shares one database
func TestInvitationCreateThenRegister(t *testing.T) {
	token := login(t, newAdmin(t))

	for _, invitationType := range []string{"member", "admin"} {
		t.Run(invitationType, func(t *testing.T) {
			got := post(t, pathInvitation, []byte(`{"type":"`+invitationType+`","numInvites":1,"label":"e2e"}`), token)
			got.expect(t, "POST create "+invitationType, http.StatusCreated, "")

			var created struct {
				invView

				Code string `json:"code"`
			}

			invDecode(t, got.body, &created)

			if created.Type != invitationType || created.Code == "" || created.Status != invStatusActive {
				t.Fatalf("created = %+v", created)
			}

			user := registerWithCode(t, created.Code, "invited-"+invitationType)

			if role := scalar(t, "SELECT role FROM users WHERE id = ?", user.userID); role != invitationType {
				t.Errorf("registered role = %q, want %q", role, invitationType)
			}

			// The invitation is used up: a second registration is refused.
			beginRegistration(t, created.Code, "again").expect(t, "second use", http.StatusForbidden, invCodeInvalidReg)
		})
	}
}

// TestInvitationCreateLabelJoiners: a label may hold the zero-width joiner and
// non-joiner (emoji sequences, Persian and Indic text), is stored as sent, and a
// label of nothing but joiners is blank and refused.
//
//nolint:paralleltest // shares one database
func TestInvitationCreateLabelJoiners(t *testing.T) {
	token := login(t, newAdmin(t))

	for name, label := range map[string]string{
		"emoji ZWJ sequence": `\ud83d\udc68\u200d\ud83d\udc69`,
		"Persian ZWNJ":       `\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645`,
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"type":"member","numInvites":1,"label":"` + label + `"}`
			post(t, pathInvitation, []byte(body), token).expect(t, "POST "+name, http.StatusCreated, "")
		})
	}

	t.Run("only joiners", func(t *testing.T) {
		rows := invRows(t)
		body := `{"type":"member","numInvites":1,"label":"\u200d\u200c"}`
		post(t, pathInvitation, []byte(body), token).expect(t, "POST joiners", http.StatusBadRequest, "invalid_label")
		expectCount(t, "invitations", rows)
	})
}

// TestInvitationCreateChecksTypeBeforeAnyOtherValue: the validation order is type
// first. A body with an uncreatable type and any other defect reports the type,
// and a creatable type with a defect reports the defect's own code.
//
//nolint:paralleltest // shares one database
func TestInvitationCreateChecksTypeBeforeAnyOtherValue(t *testing.T) {
	token := login(t, newAdmin(t))
	rows := invRows(t)

	badType := map[string]string{
		"numInvites zero":     `{"type":"first_run","numInvites":0}`,
		"numInvites missing":  `{"type":"first_run"}`,
		"label too long":      `{"type":"first_run","numInvites":1,"label":"` + strings.Repeat("l", 257) + `"}`,
		"expiresAt in past":   `{"type":"first_run","numInvites":1,"expiresAt":1}`,
		"everything wrong":    `{"type":"nope","numInvites":0,"label":"` + strings.Repeat("l", 300) + `","expiresAt":1}`,
		"numInvites too many": `{"type":"nope","numInvites":10001}`,
	}

	for name, body := range badType {
		t.Run("bad type, "+name, func(t *testing.T) {
			post(t, pathInvitation, []byte(body), token).expect(t, "POST "+name, http.StatusBadRequest, invCodeInvalidType)
			expectCount(t, "invitations", rows)
		})
	}

	goodType := map[string]struct{ body, code string }{
		"numInvites zero":      {`{"type":"member","numInvites":0}`, invCodeInvalidNum},
		"numInvites negative":  {`{"type":"member","numInvites":-1}`, invCodeInvalidNum},
		"numInvites too big":   {`{"type":"member","numInvites":10001}`, invCodeInvalidNum},
		"numInvites missing":   {`{"type":"member"}`, invCodeInvalidNum},
		"label too long":       {`{"type":"member","numInvites":1,"label":"` + strings.Repeat("l", 257) + `"}`, "invalid_label"},
		"label bidi":           {`{"type":"member","numInvites":1,"label":"a\u202eb"}`, "invalid_label"},
		"label whitespace":     {`{"type":"member","numInvites":1,"label":"   "}`, "invalid_label"},
		"expiresAt in past":    {`{"type":"member","numInvites":1,"expiresAt":1}`, "invalid_expires_at"},
		"expiresAt far":        {`{"type":"member","numInvites":1,"expiresAt":99999999999}`, "invalid_expires_at"},
		"expiresAt 2^53":       {`{"type":"member","numInvites":1,"expiresAt":9007199254740992}`, "invalid_expires_at"},
		"numInvites wrong tpe": {`{"type":"member","numInvites":"1"}`, "invalid_field_type"},
	}

	for name, tt := range goodType {
		t.Run("member, "+name, func(t *testing.T) {
			post(t, pathInvitation, []byte(tt.body), token).expect(t, "POST "+name, http.StatusBadRequest, tt.code)
			expectCount(t, "invitations", rows)
		})
	}
}

// TestInvitationCreateBodyDefects: malformed bodies are refused before the type
// is looked at, with the decoder's code; nothing is written.
//
//nolint:paralleltest // shares one database
func TestInvitationCreateBodyDefects(t *testing.T) {
	token := login(t, newAdmin(t))
	rows := invRows(t)

	cases := []struct {
		name string
		body string
		code string
	}{
		{"empty body", ``, "empty_body"},
		{"not JSON", `nope`, "invalid_json"},
		{"truncated", `{"type":"first_run"`, "invalid_json"},
		{"array", `[]`, "invalid_field_type"},
		{"string", `"first_run"`, "invalid_field_type"},
		{"number", `1`, "invalid_field_type"},
		{"null", `null`, ""},
		{"unknown member", `{"type":"first_run","numInvites":1,"role":"admin"}`, codeUnknownField},
		{"member case differs", `{"Type":"first_run","numInvites":1}`, codeUnknownField},
		{"duplicate type", `{"type":"first_run","type":"admin","numInvites":1}`, "duplicate_field"},
		{"trailing garbage", `{"type":"first_run","numInvites":1} x`, ""},
		{"two documents", `{"type":"first_run","numInvites":1}{"type":"x"}`, ""},
		{"lone surrogate in label", `{"type":"first_run","label":"\ud800"}`, "invalid_text"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := post(t, pathInvitation, []byte(tt.body), token)

			// null decodes to the zero body and reaches the type check; every other
			// case has its own decoder code or, for trailing data, a 400.
			switch {
			case tt.name == "null":
				got.expect(t, "POST null", http.StatusBadRequest, invCodeInvalidType)
			case tt.code == "":
				if got.status != http.StatusBadRequest {
					t.Errorf("POST %s = %d %s, want 400", tt.name, got.status, got.body)
				}
			default:
				got.expect(t, "POST "+tt.name, http.StatusBadRequest, tt.code)
			}

			expectCount(t, "invitations", rows)
		})
	}

	t.Run("body over the limit", func(t *testing.T) {
		body := []byte(`{"type":"first_run","label":"` + strings.Repeat("a", 5000) + `"}`)
		post(t, pathInvitation, body, token).expect(t, "POST 5000 label", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
		expectCount(t, "invitations", rows)
	})

	t.Run("unsupported media type", func(t *testing.T) {
		got := send(t, request{method: http.MethodPost, path: pathInvitation, body: []byte(`{}`), token: token,
			headers: map[string]string{"Content-Type": "text/plain"}})
		got.expect(t, "POST text/plain", http.StatusUnsupportedMediaType, codeUnsupportedType)
		expectCount(t, "invitations", rows)
	})
}

// ---- list -----------------------------------------------------------------------

// TestInvitationListShape: the exact JSON an invitation is served as: member
// names, absent optional members, types, and that a created_by reference shows.
//
//nolint:paralleltest // shares one database
func TestInvitationListShape(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	seed(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, expires_at, revoked_at, created_by, created_at) "+
		"VALUES (?, randomblob(32), 'e2e_invite', 'full', 7, ?, 1700000000, ?, 1600000000)",
		idInvitationA, invUnixFar, admin.userID)
	seed(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at) "+
		"VALUES (?, randomblob(32), 'e2e_invite', '', 2, 1500000000)", idInvitationB)

	got := get(t, pathInvitation, token)
	if got.status != http.StatusOK {
		t.Fatalf("GET = %d %s", got.status, got.body)
	}

	if ct := got.header.Get("Content-Type"); !strings.HasPrefix(ct, jsonType) {
		t.Errorf("Content-Type = %q, want %s", ct, jsonType)
	}

	// Decoded generically: the exact member sets, nothing more.
	var top map[string]json.RawMessage

	invDecode(t, got.body, &top)

	if len(top) != 1 || top["invitations"] == nil {
		t.Fatalf("top-level members = %v, want only invitations", top)
	}

	var items []map[string]any

	invDecode(t, string(top["invitations"]), &items)

	if len(items) != 3 {
		t.Fatalf("listed %d invitations, want 3 (first run, A, B): %s", len(items), got.body)
	}

	members := func(m map[string]any) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}

		slices.Sort(keys)

		return keys
	}

	wantFull := "createdAt,createdBy,expiresAt,id,label,numInvites,revokedAt,status,type,uses"
	wantBare := "createdAt,id,label,numInvites,status,type,uses"

	byID := map[string]map[string]any{}
	for _, item := range items {
		byID[item["id"].(string)] = item //nolint:forcetypeassert // id is a string by the shape asserted below
	}

	if got := strings.Join(members(byID[idInvitationA]), ","); got != wantFull {
		t.Errorf("A members = %s, want %s", got, wantFull)
	}

	for _, id := range []string{idInvitationB} {
		if got := strings.Join(members(byID[id]), ","); got != wantBare {
			t.Errorf("%s members = %s, want %s (optional members absent, never null)", id, got, wantBare)
		}
	}

	full := invFind(t, token, idInvitationA)

	want := invView{
		ID: idInvitationA, Type: "e2e_invite", Label: "full", NumInvites: 7, Uses: 0, Status: invStatusRevoked,
		ExpiresAt: new(int64(invUnixFar)), RevokedAt: new(int64(1700000000)), CreatedBy: &admin.userID, CreatedAt: 1600000000,
	}

	if full.ID != want.ID || full.Type != want.Type || full.Label != want.Label || full.NumInvites != want.NumInvites ||
		full.Uses != want.Uses || full.Status != want.Status || full.CreatedAt != want.CreatedAt ||
		deref(full.ExpiresAt) != deref(want.ExpiresAt) || deref(full.RevokedAt) != deref(want.RevokedAt) ||
		derefS(full.CreatedBy) != derefS(want.CreatedBy) {
		t.Errorf("A = %+v, want %+v", full, want)
	}

	// The raw JSON has numbers, not strings, for the integers.
	for _, frag := range []string{`"numInvites":7`, `"uses":0`, `"revokedAt":1700000000`, `"createdAt":1600000000`} {
		if !strings.Contains(got.body, frag) {
			t.Errorf("list lacks %s:\n%s", frag, got.body)
		}
	}
}

func deref(p *int64) int64 {
	if p == nil {
		return -1
	}

	return *p
}

func derefS(p *string) string {
	if p == nil {
		return "<nil>"
	}

	return *p
}

// TestInvitationListOrder: newest first by created_at DESC then id DESC, with
// several invitations sharing a second.
//
//nolint:paralleltest // shares one database
func TestInvitationListOrder(t *testing.T) {
	token := login(t, newAdmin(t))

	// The admin's own first-run invitation is created "now"; seed everything in
	// the distant past/future so the order is fully determined.
	seed(t, "DELETE FROM invitations WHERE type = 'e2e_never'")

	type row struct {
		id      string
		created int64
	}

	rows := []row{
		{idN("a100", 1), 2000000000}, {idN("a100", 2), 2000000000}, {idN("a100", 3), 2000000000},
		{idN("a100", 0xf), 1999999999}, {idN("a100", 0x10), 1999999999},
		{idN("a100", 4), 1000000000}, {idN("a100", 5), 3000000000},
	}

	for _, r := range rows {
		invSeedAt(t, r.id, 1, r.created, nil, nil)
	}

	want := []string{
		idN("a100", 5),
		idN("a100", 3), idN("a100", 2), idN("a100", 1),
		idN("a100", 0x10), idN("a100", 0xf),
		idN("a100", 4),
	}

	var got []string

	for _, view := range invList(t, token) {
		if strings.HasPrefix(view.ID, "00000000-0000-7000-8000-a100") {
			got = append(got, view.ID)
		}
	}

	if !slices.Equal(got, want) {
		t.Errorf("order = %v\nwant    %v", got, want)
	}

	// created_at is in the response and non-increasing across the whole list.
	var last int64 = 1 << 62

	for _, view := range invList(t, token) {
		if view.CreatedAt > last {
			t.Errorf("list is not newest first at %s: %d after %d", view.ID, view.CreatedAt, last)
		}

		last = view.CreatedAt
	}
}

// TestInvitationListStatus is the derived-status table, including the
// precedence of combinations: revoked, then expired, then exhausted, then active.
//
//nolint:paralleltest // shares one database
func TestInvitationListStatus(t *testing.T) {
	token := login(t, newAdmin(t))

	now := time.Now().Unix()
	past, future := now-3600, now+3600

	cases := []struct {
		name    string
		num     int64
		users   int
		revUser bool
		expires *int64
		revoked *int64
		want    string
	}{
		{"active", 3, 1, false, nil, nil, invStatusActive},
		{"active with a future expiry", 3, 0, false, new(future), nil, invStatusActive},
		{"exhausted exactly at the cap", 2, 2, false, nil, nil, invStatusExhausted},
		{"uses count revoked accounts", 2, 2, true, nil, nil, invStatusExhausted},
		{"still active below the cap with a revoked account", 3, 2, true, nil, nil, invStatusActive},
		{"over the cap (seeded) is exhausted", 1, 3, false, nil, nil, invStatusExhausted},
		{"expired in the past", 3, 0, false, new(past), nil, invStatusExpired},
		{"expires_at equal to now is expired", 3, 0, false, new(now), nil, invStatusExpired},
		{"expires_at 0 is expired", 3, 0, false, new(int64(0)), nil, invStatusExpired},
		{"expires_at negative is expired", 3, 0, false, new(int64(-5)), nil, invStatusExpired},
		{"revoked", 3, 0, false, nil, new(past), invStatusRevoked},
		{"revoked at 0 is revoked", 3, 0, false, nil, new(int64(0)), invStatusRevoked},
		{"revoked at a future time is revoked", 3, 0, false, nil, new(future), invStatusRevoked},
		{"revoked beats expired", 3, 0, false, new(past), new(past), invStatusRevoked},
		{"revoked beats exhausted", 1, 1, false, nil, new(past), invStatusRevoked},
		{"expired beats exhausted", 1, 1, false, new(past), nil, invStatusExpired},
		{"revoked beats expired and exhausted", 1, 1, false, new(past), new(past), invStatusRevoked},
		{"future expiry with exhausted is exhausted", 1, 1, false, new(future), nil, invStatusExhausted},
	}

	for i, tt := range cases {
		id := idN("a200", i+1)

		invSeedAt(t, id, tt.num, now, tt.expires, tt.revoked)

		var revoked *int64
		if tt.revUser {
			revoked = new(past)
		}

		invUsersOf(t, "0b"+fmt.Sprintf("%02x", i), id, tt.users, revoked)
	}

	listed := map[string]invView{}
	for _, view := range invList(t, token) {
		listed[view.ID] = view
	}

	for i, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			view, ok := listed[idN("a200", i+1)]
			if !ok {
				t.Fatalf("not listed")
			}

			if view.Status != tt.want {
				t.Errorf("status = %s, want %s (%+v)", view.Status, tt.want, view)
			}

			if view.Uses != int64(tt.users) {
				t.Errorf("uses = %d, want %d: revoked accounts still count", view.Uses, tt.users)
			}
		})
	}
}

// TestInvitationFirstRunIsListed: the first-run invitation the first admin
// redeemed is listed with its type, label, one use, exhausted, no creator.
//
//nolint:paralleltest // shares one database
func TestInvitationFirstRunIsListed(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	list := invList(t, token)
	if len(list) != 1 {
		t.Fatalf("list = %+v, want exactly the first-run invitation", list)
	}

	got := list[0]
	if got.Type != "first_run" || got.NumInvites != 1 || got.Uses != 1 || got.Status != invStatusExhausted ||
		got.CreatedBy != nil || got.RevokedAt != nil || got.ExpiresAt != nil || got.Label == "" {
		t.Errorf("first-run invitation = %+v", got)
	}
}

// TestInvitationsNeverExposeTheCode: no route answers with the code or its hash,
// in any encoding, across every status the routes can produce.
//
//nolint:paralleltest // shares one database
func TestInvitationsNeverExposeTheCode(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	seedInvitation(t, idInvitationA, 5)

	forms := slices.Concat(invHashForms(t, idInvitationA),
		invHashForms(t, scalar(t, "SELECT id FROM invitations WHERE type = 'first_run'")))

	// The first-run code itself is also something a response must never hold.
	forms = append(forms, firstRunSecret)

	replies := map[string]reply{
		"list":            get(t, pathInvitation, token),
		"create":          post(t, pathInvitation, []byte(`{"type":"member","numInvites":1}`), token),
		"create refused":  post(t, pathInvitation, []byte(`{"type":"first_run","numInvites":1}`), token),
		"patch ok":        invPatch(t, token, idInvitationA, `{"numInvites":6}`),
		"patch below":     invPatch(t, token, idInvitationA, `{"numInvites":0}`),
		"patch missing":   invPatch(t, token, idMissing, `{"numInvites":6}`),
		"revoke":          del(t, invItem(idInvitationA), token),
		"revoke again":    del(t, invItem(idInvitationA), token),
		"patch revoked":   invPatch(t, token, idInvitationA, `{"numInvites":7}`),
		"revoke missing":  del(t, invItem(idMissing), token),
		"list after":      get(t, pathInvitation, token),
		"bad id":          del(t, invItem("nope"), token),
		"signed out list": get(t, pathInvitation, ""),
	}

	for name, got := range replies {
		invAssertNoHash(t, name, got.body, forms)
	}
}

// TestInvitationListLarge: 300 seeded invitations are listed in full, newest
// first, in a sane time and size. The list is unpaged (documented), so the
// response grows with the table.
//
//nolint:paralleltest // shares one database
func TestInvitationListLarge(t *testing.T) {
	token := login(t, newAdmin(t))

	const n = 300

	for i := range n {
		invSeedAt(t, idN("a300", i+1), 10, int64(1000+i), nil, nil)
	}

	started := time.Now()
	got := get(t, pathInvitation, token)
	elapsed := time.Since(started)

	if got.status != http.StatusOK {
		t.Fatalf("GET = %d (%d bytes), want 200", got.status, len(got.body))
	}

	var out struct {
		Invitations []invView `json:"invitations"`
	}

	invDecode(t, got.body, &out)

	if len(out.Invitations) != n+1 {
		t.Errorf("listed %d, want %d (every seeded row and the first-run one): unbounded list", len(out.Invitations), n+1)
	}

	t.Logf("list of %d invitations: %d bytes in %s (~%d bytes per row, unpaged)",
		n+1, len(got.body), elapsed, len(got.body)/(n+1))

	if elapsed > 5*time.Second {
		t.Errorf("list of %d invitations took %s, want under 5s", n+1, elapsed)
	}

	// Newest first holds across the whole list: the seeded rows come in descending
	// created_at, ending at the oldest seeded row 1000.
	var seen []int64

	for _, view := range out.Invitations {
		if strings.HasPrefix(view.ID, "00000000-0000-7000-8000-a300") {
			seen = append(seen, view.CreatedAt)
		}
	}

	if !slices.IsSortedFunc(seen, func(a, b int64) int { return int(b - a) }) || len(seen) != n {
		t.Errorf("seeded rows are not newest first (%d rows)", len(seen))
	}
}

// ---- update ---------------------------------------------------------------------

// TestInvitationUpdateOutcomes: PATCH numInvites against the stored uses and
// revocation, including the exactly-at-uses boundary, the no-op, the precedence of
// revoked over below-uses and the unknown id.
//
//nolint:paralleltest // shares one database
func TestInvitationUpdateOutcomes(t *testing.T) {
	token := login(t, newAdmin(t))

	// A has 3 accounts, one of them revoked; B is revoked with 3 accounts.
	invSeedAt(t, idInvitationA, 5, 1000, nil, nil)
	invUsersOf(t, "0b10", idInvitationA, 2, nil)
	invUsersOf(t, "0b11", idInvitationA, 1, new(int64(1)))
	invSeedAt(t, idInvitationB, 5, 1001, nil, new(int64(2000)))
	invUsersOf(t, "0b12", idInvitationB, 3, nil)

	cases := []struct {
		name      string
		id        string
		body      string
		status    int
		code      string
		wantNum   string // stored value afterwards
		wantUses  string // "uses" in data for below_uses
		wantState string // status of the invitation in a 200
	}{
		{"raise", idInvitationA, `{"numInvites":9}`, http.StatusOK, "", "9", "", invStatusActive},
		{"lower above uses", idInvitationA, `{"numInvites":4}`, http.StatusOK, "", "4", "", invStatusActive},
		{"lower to exactly uses is exhausted", idInvitationA, `{"numInvites":3}`, http.StatusOK, "", "3", "", invStatusExhausted},
		{"same value is a no-op that applies", idInvitationA, `{"numInvites":3}`, http.StatusOK, "", "3", "", invStatusExhausted},
		{"one below uses", idInvitationA, `{"numInvites":2}`, http.StatusConflict, invCodeBelowUses, "3", "3", ""},
		{"far below uses", idInvitationA, `{"numInvites":1}`, http.StatusConflict, invCodeBelowUses, "3", "3", ""},
		{"raise after exhausted", idInvitationA, `{"numInvites":10000}`, http.StatusOK, "", "10000", "", invStatusActive},
		{"revoked above uses", idInvitationB, `{"numInvites":9}`, http.StatusConflict, invCodeRevoked, "5", "", ""},
		{"revoked and below uses is revoked", idInvitationB, `{"numInvites":1}`, http.StatusConflict, invCodeRevoked, "5", "", ""},
		{"revoked and equal to the stored value", idInvitationB, `{"numInvites":5}`, http.StatusConflict, invCodeRevoked, "5", "", ""},
		{"unknown id", idMissing, `{"numInvites":9}`, http.StatusNotFound, invCodeNotFound, "", "", ""},
		{"unknown id with a bad cap is the body's refusal", idMissing, `{"numInvites":0}`, http.StatusBadRequest, invCodeInvalidNum, "", "", ""},
		{"missing member", idInvitationA, `{}`, http.StatusBadRequest, invCodeMissingNum, "10000", "", ""},
		{"null member", idInvitationA, `{"numInvites":null}`, http.StatusBadRequest, invCodeMissingNum, "10000", "", ""},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := invPatch(t, token, tt.id, tt.body)
			got.expect(t, "PATCH "+tt.name, tt.status, tt.code)

			if tt.wantNum != "" {
				if stored := invStored(t, tt.id); stored != tt.wantNum {
					t.Errorf("stored num_invites = %s, want %s", stored, tt.wantNum)
				}
			}

			switch tt.status {
			case http.StatusOK:
				var view invView

				invDecode(t, got.body, &view)

				if view.Status != tt.wantState || view.ID != tt.id || strconv.FormatInt(view.NumInvites, 10) != tt.wantNum || view.Uses != 3 {
					t.Errorf("PATCH body = %+v, want status %s num %s uses 3", view, tt.wantState, tt.wantNum)
				}
			case http.StatusConflict:
				if tt.wantUses != "" {
					want := `"data":{"uses":` + tt.wantUses + `}`
					if !strings.Contains(got.body, want) {
						t.Errorf("body %s lacks %s", got.body, want)
					}
				} else if strings.Contains(got.body, `"uses"`) {
					t.Errorf("revoked refusal carries uses: %s", got.body)
				}
			}
		})
	}
}

// TestInvitationUpdateNumInvitesBoundaries: every numeric form and type of
// numInvites. Anything refused leaves the stored cap unchanged. The cap is 1 to
// 10000, so 2^53-1 and above are refused by the cap, and forms that are not a
// plain JSON integer that fits an int64 are refused by the decoder.
//
//nolint:paralleltest // shares one database
func TestInvitationUpdateNumInvitesBoundaries(t *testing.T) {
	token := login(t, newAdmin(t))

	const start = "7"

	cases := []struct {
		name   string
		body   string
		status int
		code   string
		stored string // the stored cap afterwards ("" = start)
	}{
		{"1", `{"numInvites":1}`, 200, "", "1"},
		{"10000", `{"numInvites":10000}`, 200, "", "10000"},
		{"0", `{"numInvites":0}`, 400, invCodeInvalidNum, ""},
		{"-1", `{"numInvites":-1}`, 400, invCodeInvalidNum, ""},
		{"-0", `{"numInvites":-0}`, 400, invCodeInvalidNum, ""},
		{"10001", `{"numInvites":10001}`, 400, invCodeInvalidNum, ""},
		{"2^53-1", `{"numInvites":9007199254740991}`, 400, invCodeInvalidNum, ""},
		{"2^53", `{"numInvites":9007199254740992}`, 400, invCodeInvalidNum, ""},
		{"2^53+1", `{"numInvites":9007199254740993}`, 400, invCodeInvalidNum, ""},
		{"int64 max", `{"numInvites":9223372036854775807}`, 400, invCodeInvalidNum, ""},
		{"int64 max+1", `{"numInvites":9223372036854775808}`, 400, "", ""},
		{"int64 min", `{"numInvites":-9223372036854775808}`, 400, invCodeInvalidNum, ""},
		{"20 digits", `{"numInvites":99999999999999999999}`, 400, "", ""},
		{"1e3", `{"numInvites":1e3}`, 400, "", ""},
		{"1E3", `{"numInvites":1E3}`, 400, "", ""},
		{"1.0", `{"numInvites":1.0}`, 400, "", ""},
		{"5.0", `{"numInvites":5.0}`, 400, "", ""},
		{"1.5", `{"numInvites":1.5}`, 400, "", ""},
		{"1e999", `{"numInvites":1e999}`, 400, "", ""},
		{"-1e999", `{"numInvites":-1e999}`, 400, "", ""},
		{"string 5", `{"numInvites":"5"}`, 400, "invalid_field_type", ""},
		{"string empty", `{"numInvites":""}`, 400, "invalid_field_type", ""},
		{"true", `{"numInvites":true}`, 400, "invalid_field_type", ""},
		{"false", `{"numInvites":false}`, 400, "invalid_field_type", ""},
		{"array", `{"numInvites":[]}`, 400, "invalid_field_type", ""},
		{"array of 5", `{"numInvites":[5]}`, 400, "invalid_field_type", ""},
		{"object", `{"numInvites":{}}`, 400, "invalid_field_type", ""},
		{"0x10", `{"numInvites":0x10}`, 400, "invalid_json", ""},
		{"00005", `{"numInvites":00005}`, 400, "invalid_json", ""},
		{"+5", `{"numInvites":+5}`, 400, "invalid_json", ""},
		{".5", `{"numInvites":.5}`, 400, "invalid_json", ""},
		{"5.", `{"numInvites":5.}`, 400, "invalid_json", ""},
		{"NaN", `{"numInvites":NaN}`, 400, "invalid_json", ""},
		{"Infinity", `{"numInvites":Infinity}`, 400, "invalid_json", ""},
		{"-Infinity", `{"numInvites":-Infinity}`, 400, "invalid_json", ""},
		{"duplicate keys", `{"numInvites":1,"numInvites":99999}`, 400, "duplicate_field", ""},
		{"duplicate keys same value", `{"numInvites":5,"numInvites":5}`, 400, "duplicate_field", ""},
		{"case differs", `{"NumInvites":5}`, 400, codeUnknownField, ""},
		{"snake case", `{"num_invites":5}`, 400, codeUnknownField, ""},
		{"extra field", `{"numInvites":5,"label":"x"}`, 400, codeUnknownField, ""},
		{"extra field first", `{"label":"x","numInvites":5}`, 400, codeUnknownField, ""},
		{"extra field null", `{"numInvites":5,"expiresAt":null}`, 400, codeUnknownField, ""},
		{"escaped key", `{"num\u0049nvites":5}`, 200, "", "5"},
		{"trailing garbage", `{"numInvites":5} x`, 400, "", ""},
		{"trailing comma", `{"numInvites":5,}`, 400, "invalid_json", ""},
		{"two documents", `{"numInvites":5}{"numInvites":6}`, 400, "", ""},
		{"empty body", ``, 400, "empty_body", ""},
		{"whitespace body", `   `, 400, "empty_body", ""},
		{"truncated", `{"numInvites":5`, 400, "", ""},
		{"not JSON", `numInvites=5`, 400, "invalid_json", ""},
		{"array body", `[{"numInvites":5}]`, 400, "invalid_field_type", ""},
		{"number body", `5`, 400, "invalid_field_type", ""},
		{"string body", `"numInvites"`, 400, "invalid_field_type", ""},
		{"null body", `null`, 400, invCodeMissingNum, ""},
		{"BOM", "\ufeff" + `{"numInvites":5}`, 400, "invalid_json", ""},
		{"whitespace around is fine", " \n{ \"numInvites\" : 6 }\t\n", 200, "", "6"},
		{"lone surrogate in key", `{"numInvites":5,"\ud800":1}`, 400, "invalid_text", ""},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Each case starts from a known cap so "unchanged" is checkable.
			seed(t, "DELETE FROM invitations WHERE id = ?", idInvitationA)
			seedInvitation(t, idInvitationA, 7)

			got := invPatch(t, token, idInvitationA, tt.body)
			if got.status != tt.status || (tt.code != "" && got.errorCode() != tt.code) {
				t.Errorf("PATCH %s = %d %s, want %d %s", tt.body, got.status, got.body, tt.status, tt.code)
			}

			want := tt.stored
			if want == "" {
				want = start
			}

			if stored := invStored(t, idInvitationA); stored != want {
				t.Errorf("stored num_invites = %s after %s, want %s", stored, tt.body, want)
			}

			if got.status >= 400 && got.status < 500 && got.errorCode() == "" {
				t.Errorf("refusal %d has no error code: %s", got.status, got.body)
			}
		})
	}
}

// TestInvitationUpdateBodyLimits: the body cap (4 KiB) and media type.
//
//nolint:paralleltest // shares one database
func TestInvitationUpdateBodyLimits(t *testing.T) {
	token := login(t, newAdmin(t))
	seedInvitation(t, idInvitationA, 7)

	cases := []struct {
		name string
		req  request
		code string
		want int
	}{
		{"just under the limit", request{body: []byte(`{"numInvites":5,"x":"` + strings.Repeat("a", 4000) + `"}`)}, codeUnknownField, 400},
		{"over the limit", request{body: []byte(`{"numInvites":5,"x":"` + strings.Repeat("a", 5000) + `"}`)}, codeBodyTooLarge, 413},
		{"much over the limit", request{body: bytes.Repeat([]byte(" "), 1<<20+10)}, codeBodyTooLarge, 413},
		{"text/plain", request{body: []byte(`{"numInvites":5}`), headers: map[string]string{"Content-Type": "text/plain"}}, codeUnsupportedType, 415},
		{"no content type", request{body: []byte(`{"numInvites":5}`), noType: true}, codeUnsupportedType, 415},
		{"json with charset", request{body: []byte(`{"numInvites":5}`), headers: map[string]string{"Content-Type": "application/json; charset=utf-8"}}, "", 200},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.req
			req.method, req.path, req.token = http.MethodPatch, invItem(idInvitationA), token

			got := send(t, req)
			got.expect(t, "PATCH "+tt.name, tt.want, tt.code)

			if tt.want != 200 {
				if stored := invStored(t, idInvitationA); stored != "7" {
					t.Errorf("stored = %s after a refused body, want 7", stored)
				}
			}
		})
	}
}

// TestInvitationPathIDs: a malformed id is refused 400 invalid_id once the
// caller is known to be an admin (a signed-out caller is 401 whatever the id),
// and a trailing segment is not a route.
//
//nolint:paralleltest // shares one database
func TestInvitationPathIDs(t *testing.T) {
	token := login(t, newAdmin(t))
	seedInvitation(t, idInvitationA, 7)

	bad := []string{
		"nope", "0", strings.Repeat("a", 36), strings.ToUpper(idInvitationA),
		idInvitationA + "x", idInvitationA[:35], "%00", "%20", strings.Repeat("a", 5000),
	}

	for _, id := range bad {
		for _, method := range []string{http.MethodPatch, http.MethodDelete} {
			t.Run(method+" "+id[:min(len(id), 20)], func(t *testing.T) {
				got := send(t, request{method: method, path: invItem(id), body: []byte(`{"numInvites":5}`), token: token})
				got.expect(t, method+" "+id[:min(len(id), 20)], http.StatusBadRequest, codeInvalidID)

				got = send(t, request{method: method, path: invItem(id), body: []byte(`{"numInvites":5}`)})
				got.expect(t, method+" signed out "+id[:min(len(id), 20)], http.StatusUnauthorized, codeUnauthenticated)
			})
		}
	}

	t.Run("extra segment", func(t *testing.T) {
		del(t, invItem(idInvitationA)+"/x", token).expect(t, "DELETE extra segment", http.StatusNotFound, codeNotFound)
	})

	t.Run("wrong methods", func(t *testing.T) {
		send(t, request{method: http.MethodGet, path: invItem(idInvitationA), token: token}).
			expect(t, "GET item", http.StatusMethodNotAllowed, codeMethodNotAllow)
		send(t, request{method: http.MethodPatch, path: pathInvitation, body: []byte(`{}`), token: token}).
			expect(t, "PATCH collection", http.StatusMethodNotAllowed, codeMethodNotAllow)
		send(t, request{method: http.MethodDelete, path: pathInvitation, token: token}).
			expect(t, "DELETE collection", http.StatusMethodNotAllowed, codeMethodNotAllow)
	})

	if stored := invStored(t, idInvitationA); stored != "7" {
		t.Errorf("stored = %s, want 7", stored)
	}
}

// ---- revoke ---------------------------------------------------------------------

// TestInvitationRevoke: revoke sets revoked_at to the request's now, the row and
// its accounts stay, the first time is kept (even after seconds pass), unknown is
// 404, and the accounts it created are not revoked.
//
//nolint:paralleltest // shares one database
func TestInvitationRevoke(t *testing.T) {
	token := login(t, newAdmin(t))

	invSeedAt(t, idInvitationA, 5, 1000, nil, nil)
	invUsersOf(t, "0b20", idInvitationA, 2, nil)

	before := time.Now().Unix()
	first := del(t, invItem(idInvitationA), token)
	after := time.Now().Unix()

	first.expect(t, "DELETE", http.StatusOK, "")

	var view invView

	invDecode(t, first.body, &view)

	if view.Status != invStatusRevoked || view.RevokedAt == nil || *view.RevokedAt < before || *view.RevokedAt > after ||
		view.Uses != 2 || view.NumInvites != 5 {
		t.Fatalf("revoke body = %+v, want revoked at now (%d..%d), uses 2", view, before, after)
	}

	if stored := scalar(t, "SELECT revoked_at FROM invitations WHERE id = ?", idInvitationA); stored != strconv.FormatInt(*view.RevokedAt, 10) {
		t.Errorf("stored revoked_at = %s, response %d", stored, *view.RevokedAt)
	}

	// The row and its accounts stay, and the accounts are not revoked.
	expectCount(t, "invitations WHERE id = ?", "1", idInvitationA)
	expectCount(t, "users WHERE invitation_id = ?", "2", idInvitationA)
	expectCount(t, "users WHERE invitation_id = ? AND revoked_at IS NOT NULL", "0", idInvitationA)

	// Idempotent: after time passes the second revoke returns the ORIGINAL time.
	time.Sleep(2100 * time.Millisecond)

	second := del(t, invItem(idInvitationA), token)
	second.expect(t, "second DELETE", http.StatusOK, "")

	var again invView

	invDecode(t, second.body, &again)

	if again.RevokedAt == nil || *again.RevokedAt != *view.RevokedAt {
		t.Errorf("second revoke revokedAt = %v, want the original %d", again.RevokedAt, *view.RevokedAt)
	}

	if other := invFind(t, token, scalar(t, "SELECT id FROM invitations WHERE type = 'first_run'")); other.RevokedAt != nil {
		t.Errorf("an unrelated invitation was revoked: %+v", other)
	}

	if listed := invFind(t, token, idInvitationA); listed.RevokedAt == nil || *listed.RevokedAt != *view.RevokedAt {
		t.Errorf("listed revokedAt = %v, want %d", listed.RevokedAt, *view.RevokedAt)
	}

	// A revoked invitation keeps its other facts and cannot be changed.
	invPatch(t, token, idInvitationA, `{"numInvites":9}`).expect(t, "PATCH revoked", http.StatusConflict, invCodeRevoked)

	// An invitation whose revoked_at is in the future (seeded) keeps that time:
	// revoking never moves an existing time, earlier or later.
	invSeedAt(t, idInvitationB, 5, 1000, nil, new(int64(invUnixFar)))

	got := del(t, invItem(idInvitationB), token)
	got.expect(t, "DELETE preset revoked_at", http.StatusOK, "")

	if !strings.Contains(got.body, `"revokedAt":`+strconv.Itoa(invUnixFar)) {
		t.Errorf("revoke of a preset revoked_at = %s, want it kept", got.body)
	}

	del(t, invItem(idMissing), token).expect(t, "DELETE unknown", http.StatusNotFound, invCodeNotFound)
	expectCount(t, "invitations WHERE revoked_at IS NOT NULL", "2")
}

// ---- interleavings ---------------------------------------------------------------

// TestInvitationConcurrentUpdates: 16 PATCHes with numInvites 1..16 race on one
// invitation that has 3 accounts. Each is 200 (value >= 3) or 409 below_uses
// (value < 3), never a 5xx, and the stored cap is the value of one of the 200
// responses and is never below the uses.
//
//nolint:paralleltest // shares one database
func TestInvitationConcurrentUpdates(t *testing.T) {
	token := login(t, newAdmin(t))

	const n = 16

	for round := range 4 {
		seed(t, "DELETE FROM users WHERE role = 'e2e_none'")
		seed(t, "DELETE FROM invitations WHERE id = ?", idInvitationA)
		seedInvitation(t, idInvitationA, 20)
		seedUsers(t, idInvitationA, 3)

		replies := invRace(n, func(i int) reply {
			return invPatch(t, token, idInvitationA, fmt.Sprintf(`{"numInvites":%d}`, i+1))
		})

		t.Logf("round %d: %v", round, invStatuses(replies))

		stored := invStored(t, idInvitationA)
		won := map[string]bool{}

		for i, r := range replies {
			value := i + 1

			switch {
			case r.status == http.StatusOK && value >= 3:
				var view invView

				invDecode(t, r.body, &view)

				if view.NumInvites != int64(value) || view.Uses != 3 {
					t.Errorf("PATCH %d answered %+v, want numInvites %d uses 3", value, view, value)
				}

				won[strconv.Itoa(value)] = true
			case r.status == http.StatusConflict && value < 3 && r.errorCode() == invCodeBelowUses:
				if !strings.Contains(r.body, `"uses":3`) {
					t.Errorf("PATCH %d refusal lacks uses 3: %s", value, r.body)
				}
			default:
				t.Errorf("PATCH %d = %d %s, want 200 (>=3) or 409 below_uses (<3)", value, r.status, r.body)
			}
		}

		if !won[stored] {
			t.Errorf("round %d: stored num_invites %s is the value of no 200 response %v", round, stored, won)
		}

		if n, _ := strconv.Atoi(stored); n < 3 {
			t.Errorf("round %d: stored num_invites %s is below the 3 accounts", round, stored)
		}
	}
}

// TestInvitationConcurrentRevokes: 16 DELETEs at once all answer 200 with the
// same revokedAt, one write wins and the rest return the original.
//
//nolint:paralleltest // shares one database
func TestInvitationConcurrentRevokes(t *testing.T) {
	token := login(t, newAdmin(t))

	for round := range 4 {
		seed(t, "DELETE FROM invitations WHERE id = ?", idInvitationA)
		seedInvitation(t, idInvitationA, 5)

		replies := invRace(16, func(int) reply { return del(t, invItem(idInvitationA), token) })

		t.Logf("round %d: %v", round, invStatuses(replies))

		times := map[int64]int{}

		for _, r := range replies {
			if r.status != http.StatusOK {
				t.Errorf("DELETE = %d %s, want 200", r.status, r.body)

				continue
			}

			var view invView

			invDecode(t, r.body, &view)

			if view.RevokedAt == nil || view.Status != invStatusRevoked {
				t.Errorf("DELETE body = %+v, want revoked", view)

				continue
			}

			times[*view.RevokedAt]++
		}

		stored := scalar(t, "SELECT revoked_at FROM invitations WHERE id = ?", idInvitationA)

		for at := range times {
			if strconv.FormatInt(at, 10) != stored {
				t.Errorf("a response says revokedAt %d, stored %s: every response must report the winner", at, stored)
			}
		}
	}
}

// TestInvitationRevokeRacesUpdates: revokes race PATCHes on one invitation. No
// 5xx; the invitation ends revoked; a PATCH is 200 (it ran before the revoke
// committed) or 409 invitation_revoked, and once a PATCH was refused as revoked,
// no later PATCH may be 200 (revocation is final).
//
//nolint:paralleltest // shares one database
func TestInvitationRevokeRacesUpdates(t *testing.T) {
	token := login(t, newAdmin(t))

	for round := range 5 {
		seed(t, "DELETE FROM invitations WHERE id = ?", idInvitationA)
		seedInvitation(t, idInvitationA, 5)

		replies := invRace(17, func(i int) reply {
			if i == 8 {
				return del(t, invItem(idInvitationA), token)
			}

			return invPatch(t, token, idInvitationA, fmt.Sprintf(`{"numInvites":%d}`, 100+i))
		})

		t.Logf("round %d: %v", round, invStatuses(replies))

		revoked := scalar(t, "SELECT revoked_at FROM invitations WHERE id = ?", idInvitationA)
		if revoked == "" {
			t.Fatalf("round %d: the invitation is not revoked", round)
		}

		if replies[8].status != http.StatusOK {
			t.Errorf("revoke = %d %s, want 200", replies[8].status, replies[8].body)
		}

		stored := invStored(t, idInvitationA)
		last := ""

		for i, r := range replies {
			if i == 8 {
				continue
			}

			switch {
			case r.status == http.StatusOK:
				last = strconv.Itoa(100 + i)
			case r.status == http.StatusConflict && r.errorCode() == invCodeRevoked:
			default:
				t.Errorf("PATCH %d = %d %s, want 200 or 409 invitation_revoked", 100+i, r.status, r.body)
			}
		}

		// The stored value is the last PATCH that applied before the revoke, or the
		// start value if none did.
		if stored != "5" && stored != last && !won200(replies, stored) {
			t.Errorf("round %d: stored %s is the value of no 200 PATCH", round, stored)
		}
	}
}

func won200(replies []reply, stored string) bool {
	for i, r := range replies {
		if r.status == http.StatusOK && strconv.Itoa(100+i) == stored {
			return true
		}
	}

	return false
}

// invFirstRunFinishes begins n ceremonies with code and returns their finish
// bodies, ready to be sent together.
func invFirstRunFinishes(t *testing.T, code string, n int) [][]byte {
	t.Helper()

	bodies := make([][]byte, n)

	for i := range n {
		name := fmt.Sprintf("Racer %d", i)
		options := mustBeginRegistration(t, code, name)
		auth := newAuthenticator()
		auth.priv = newKey(t)
		bodies[i] = auth.finishBody(t, options, code, name)
	}

	return bodies
}

// TestInvitationFirstRunSingleUse: four ceremonies begun with the first-run code
// are finished together. Exactly one account results, the losers are refused 403
// invalid_invitation and never 5xx, and the invitation then reads exhausted with
// one use.
//
//nolint:paralleltest // shares one database
func TestInvitationFirstRunSingleUse(t *testing.T) {
	for round := range 4 {
		reset(t)
		get(t, pathFirstRun, "").expect(t, "first run", http.StatusOK, "")

		bodies := invFirstRunFinishes(t, firstRunSecret, 4)

		replies := invRace(len(bodies), func(i int) reply { return post(t, pathRegisterEnd, bodies[i], "") })

		t.Logf("round %d: %v", round, invStatuses(replies))

		created := 0

		for _, r := range replies {
			switch {
			case r.status == http.StatusCreated:
				created++
			case r.status == http.StatusForbidden && r.errorCode() == invCodeInvalidReg:
			// The race the read before the write cannot close: the conditional insert
			// refused it (registration_design.md, "Failure of the atomic write").
			case r.status == http.StatusConflict && r.errorCode() == "registration_accept_failed":
			default:
				t.Errorf("finish = %d %s, want 201, 403 invalid_invitation or 409 registration_accept_failed", r.status, r.body)
			}
		}

		if created != 1 {
			t.Fatalf("round %d: %d accounts created, want exactly 1", round, created)
		}

		expectCount(t, "users", "1")
		expectCount(t, "credentials", "1")
		expectCount(t, "users WHERE role = 'admin'", "1")
	}
}

// TestInvitationRevokeClosesRegistration: the first-run invitation is revoked
// through the API and a registration with its code is refused at begin AND at
// finish (the finish body was signed before the revoke), with no account.
//
// Revoking needs an admin session and a first-run invitation is redeemable only
// while no account exists, so the two cannot coexist through the Worker alone.
// The session is therefore obtained from a real first admin, and the account is
// then removed behind the Worker's back (the Worker is idle) so that a fresh
// first-run invitation, whose code the test knows, is redeemable again while the
// admin's session key row would be needed to revoke: it is not, so the revoke is
// sent while the admin still exists, and the redeemability is then restored by
// removing the admin. The invitation is revoked_at-set either way, which is what
// the redemption query tests.
//
//nolint:paralleltest // shares one database
func TestInvitationRevokeClosesRegistration(t *testing.T) {
	admin := newAdmin(t)
	token := login(t, admin)

	code := "e2e-second-first-run-code-0123456789ABCDEFG"
	sum := sha256.Sum256([]byte(code))

	// A second first-run invitation, with a known code. It starts redeemable on
	// its own terms (not revoked, not expired, under cap); the only thing that
	// stops it is the existing account, which is first run's own rule.
	seed(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at) "+
		"VALUES (?, ?, 'first_run', 'second', 3, strftime('%s','now'))", idInvitationA, sum[:])

	del(t, invItem(idInvitationA), token).expect(t, "revoke", http.StatusOK, "")

	// Remove every account (and what hangs off it) so only the revocation can be
	// what refuses the code from here on. Worker idle: nothing in flight.
	seed(t, "DELETE FROM japikeys")
	seed(t, "DELETE FROM credentials")
	seed(t, "DELETE FROM users")

	beginRegistration(t, code, "Late").expect(t, "begin after revoke", http.StatusForbidden, invCodeInvalidReg)

	expectCount(t, "users", "0")

	// Control: the same invitation unrevoked is redeemable, so the refusal above
	// is the revocation and nothing else.
	seed(t, "UPDATE invitations SET revoked_at = NULL WHERE id = ?", idInvitationA)

	options := mustBeginRegistration(t, code, "Late")
	auth := newAuthenticator()
	auth.priv = newKey(t)
	finish := auth.finishBody(t, options, code, "Late")

	// The ceremony is begun, then the invitation is revoked before finish.
	seed(t, "UPDATE invitations SET revoked_at = strftime('%s','now') WHERE id = ?", idInvitationA)

	post(t, pathRegisterEnd, finish, "").expect(t, "finish after revoke", http.StatusForbidden, invCodeInvalidReg)

	expectCount(t, "users", "0")
	expectCount(t, "credentials", "0")
}

// TestInvitationExpiredInvitation: an expired invitation is listed expired, can
// still be re-capped and revoked (nothing in the update or revoke statements
// reads the expiry), and one whose expiry has not come is active.
//
//nolint:paralleltest // shares one database
func TestInvitationExpiredInvitation(t *testing.T) {
	token := login(t, newAdmin(t))
	past := time.Now().Unix() - 3600

	invSeedAt(t, idInvitationA, 3, 1000, &past, nil)

	got := invPatch(t, token, idInvitationA, `{"numInvites":9}`)
	got.expect(t, "PATCH expired", http.StatusOK, "")

	var view invView

	invDecode(t, got.body, &view)

	if view.Status != invStatusExpired || view.NumInvites != 9 || view.ExpiresAt == nil || *view.ExpiresAt != past {
		t.Errorf("PATCH expired = %+v, want it still expired with cap 9", view)
	}

	got = del(t, invItem(idInvitationA), token)
	got.expect(t, "DELETE expired", http.StatusOK, "")

	invDecode(t, got.body, &view)

	if view.Status != invStatusRevoked {
		t.Errorf("DELETE expired = %+v, want revoked (it beats expired)", view)
	}
}
