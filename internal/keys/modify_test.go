package keys_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/keys"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestRename: the key comes back as the write left it, with its new name, and
// nothing else about it changed. The store is asked, for the session's user, to
// rename exactly the key in the path, as of the clock.
func TestRename(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(keyA1, "ci", 100, nil), stored(keyA2, "other", 200, nil))

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+keyA1, bodyRenamed)

	wantOK(t, rg, rec, keyJSON(keyA1, "renamed", 100, nil)+"\n")

	want := []storeCall{{method: methodRename, owner: userA, id: keyA1, name: "renamed", now: rg.now}}
	if !reflect.DeepEqual(rg.store.calls, want) {
		t.Errorf("store calls = %+v, want %+v", rg.store.calls, want)
	}

	// Only the one key, and only its name.
	if other := rg.store.key(t, keyA2); other.Name != "other" {
		t.Errorf("another key was renamed: %+v", other)
	}

	if got := rg.store.key(t, keyA1); got.Scope != keys.DefaultScopes().JSON() || got.ExpiresAt != farFuture {
		t.Errorf("a rename changed more than the name: %+v", got)
	}
}

// TestRenameAKeyThatIsNoLongerActive: a revoked key and an expired one are final,
// and a rename is a 409 that changes nothing, exactly as for a revoked agent.
func TestRenameAKeyThatIsNoLongerActive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  func(*rig) keyChange
	}{
		{"revoked", func(*rig) keyChange { return keyChange{revokedAt: new(int64(150)), expiresAt: farFuture} }},
		{"revoked and expired", func(*rig) keyChange { return keyChange{revokedAt: new(int64(150)), expiresAt: 200} }},
		{"expired", func(*rig) keyChange { return keyChange{revokedAt: nil, expiresAt: 200} }},
		{"expired this very second", func(rg *rig) keyChange { return keyChange{revokedAt: nil, expiresAt: rg.now.Unix()} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)

			change := tt.key(rg)
			key := stored(keyA1, "ci", 100, change.revokedAt)
			key.ExpiresAt = change.expiresAt
			rg.seed(userA, key)

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+keyA1, bodyRenamed)

			wantFailure(t, rg, rec, http.StatusConflict,
				errorBody("key_inactive", "the key is revoked or expired and cannot be changed"), keys.CodeInactive)

			if got := rg.store.key(t, keyA1); got.Name != "ci" {
				t.Errorf("a refused rename changed the key to %+v", got)
			}
		})
	}
}

// keyChange is how a key in a table differs from an active one.
type keyChange struct {
	revokedAt *int64
	expiresAt int64
}

// TestRenameRefusesWhatItCannotRead: a body that is not exactly a valid name is
// refused before the store is asked, and a body can carry nothing but a name.
func TestRenameRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		code string
	}{
		{"no body", "", "empty_body"},
		{"no name", `{}`, codeInvalidName},
		{"an empty name", `{"name":""}`, codeInvalidName},
		{"a null name", `{"name":null}`, codeInvalidName},
		{"a blank name", `{"name":"   "}`, codeInvalidName},
		{"a name with a control character", `{"name":"a\u0000b"}`, codeInvalidName},
		{"a too long name", `{"name":"` + strings.Repeat("a", 257) + `"}`, codeInvalidName},
		{"not json", "nope", codeBadJSON},
		{"a number for the name", `{"name":1}`, codeFieldType},
		{"scopes are fixed at issue", `{"name":"x","scopes":["key:read"]}`, codeUnknown},
		{"the lifetime is fixed at issue", `{"name":"x","lifetimeDays":1}`, codeUnknown},
		{"the expiry is fixed at issue", `{"name":"x","expiresAt":1}`, codeUnknown},
		{"an owner", `{"name":"x","userId":"` + userA + `"}`, codeUnknown},
		{"an agent", `{"name":"x","agentId":"` + agentA1 + `"}`, codeUnknown},
		{"a revocation", `{"name":"x","revokedAt":1}`, codeUnknown},
		{"a repeated name", `{"name":"a","name":"b"}`, "duplicate_field"},
		{"trailing data", `{"name":"a"} {}`, "trailing_data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(keyA1, "ci", 1, nil))

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+keyA1, tt.body)

			wantBadRequest(t, rg, rec, tt.code)
			rg.untouched()
		})
	}
}

// TestRevoke: the key comes back as the write left it, revoked at the request's
// time, or at the earlier time it already had: revoking twice succeeds and never
// moves the revocation later. The store is asked, for the session's user, to
// revoke exactly the key in the path, as of the clock, and to spare the secret
// the request presented.
func TestRevoke(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  func() store.Key
		// revokedAt is the revocation the response shows.
		revokedAt func(*rig) int64
	}{
		{
			name:      "a fresh key",
			key:       func() store.Key { return stored(keyA1, nameCI, 100, nil) },
			revokedAt: func(rg *rig) int64 { return rg.now.Unix() },
		},
		{
			name:      "a key revoked already",
			key:       func() store.Key { return stored(keyA1, nameCI, 100, new(int64(150))) },
			revokedAt: func(*rig) int64 { return 150 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, tt.key(), stored(keyA2, "beta", 200, nil))

			cookie := rg.signIn(userA, roleMember)
			session := onlySessionID(t, rg)

			rec := rg.as(cookie, http.MethodDelete, itemPrefix+keyA1, "")

			wantOK(t, rg, rec, keyJSON(keyA1, nameCI, 100, new(tt.revokedAt(rg)))+"\n")

			want := []storeCall{{method: methodRevoke, owner: userA, id: keyA1, except: session, now: rg.now}}
			if !reflect.DeepEqual(rg.store.calls, want) {
				t.Errorf("store calls = %+v, want %+v", rg.store.calls, want)
			}

			// Only the one key.
			if other := rg.store.key(t, keyA2); other.RevokedAt != nil {
				t.Errorf("another key was revoked: %+v", other)
			}
		})
	}
}

// onlySessionID is the id of the one session the rig has signed in.
func onlySessionID(t *testing.T, rg *rig) string {
	t.Helper()

	if len(rg.creds.sessions) != 1 {
		t.Fatalf("the rig holds %d sessions, want 1", len(rg.creds.sessions))
	}

	for _, session := range rg.creds.sessions {
		return session.ID
	}

	return ""
}

// TestRevokeOfAKeyThatDoesNotExist: the 404 every other user's key gets.
func TestRevokeOfAKeyThatDoesNotExist(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(keyA1, nameCI, 100, nil))

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodDelete, itemPrefix+nobody, "")

	wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, keys.CodeNotFound)

	if got := rg.store.key(t, keyA1); got.RevokedAt != nil {
		t.Errorf("another key was revoked: %+v", got)
	}
}

// TestRevokeNeverEndsThePresentedKey: the key a request is made with is not
// revoked by DELETE, whatever its scopes. It is answered as a key that does not
// exist, and stays active: ending the credential in use is logout's.
func TestRevokeNeverEndsThePresentedKey(t *testing.T) {
	t.Parallel()

	rg := newRig(t)

	header, presented := rg.signInKey(keySpec{owner: userA, role: roleMember, scope: scope.List{scope.DefaultUser}})

	// The key is also in the store, under the id the boundary reports, so the
	// only thing that stops its revocation is the exclusion.
	rg.seed(userA, stored(presented, "presented", 1, nil), stored(keyA2, "other", 2, nil))

	rec := rg.withKey(header, http.MethodDelete, itemPrefix+presented, "")

	wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, keys.CodeNotFound)

	if got := rg.store.key(t, presented); got.RevokedAt != nil {
		t.Errorf("the presented key was revoked: %+v", got)
	}

	// The same key may revoke another of the user's keys.
	rg.logged = nil

	other := rg.withKey(header, http.MethodDelete, itemPrefix+keyA2, "")
	if other.Code != http.StatusOK {
		t.Errorf("revoking another key = %d %s, want 200", other.Code, other.Body)
	}
}

// TestAnotherUsersKeyIsNotFound is the permission-confusion test of the item
// routes. User B names user A's key, as a member and as an administrator (an
// admin has no extra reach here): the store is asked with B as the owner, the
// answer is the 404 a missing key gets, byte for byte, and A's key is unchanged.
// The control is A making the same request, which works.
func TestAnotherUsersKeyIsNotFound(t *testing.T) {
	t.Parallel()

	routes := []keyRoute{
		{name: routeGet, method: http.MethodGet, target: itemPrefix + keyA1, body: ""},
		{name: routePatch, method: http.MethodPatch, target: itemPrefix + keyA1, body: `{"name":"hijacked"}`},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + keyA1, body: ""},
	}

	for _, route := range routes {
		for _, role := range []string{roleMember, roleAdmin} {
			t.Run(route.name+"/"+role, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(keyA1, nameCI, 1, nil))
				rg.seed(userB, stored(keyB1, "bravo", 2, nil))
				cookieB := rg.signIn(userB, role)

				// B asks for A's key.
				others := rg.as(cookieB, route.method, route.target, route.body)

				wantFailure(t, rg, others, http.StatusNotFound, bodyNotFound, keys.CodeNotFound)

				if len(rg.store.calls) != 1 || rg.store.calls[0].owner != userB || rg.store.calls[0].id != keyA1 {
					t.Errorf("store calls = %+v, want one for owner %s and key %s", rg.store.calls, userB, keyA1)
				}

				// A key nobody has is answered with the same bytes.
				rg.logged = nil
				missing := rg.as(cookieB, route.method, strings.Replace(route.target, keyA1, nobody, 1), route.body)

				if missing.Code != others.Code || missing.Body.String() != others.Body.String() {
					t.Errorf("another user's key = %d %q, a missing one = %d %q: they must be identical",
						others.Code, others.Body.String(), missing.Code, missing.Body.String())
				}

				// Nothing of A's changed.
				if got := rg.store.key(t, keyA1); !reflect.DeepEqual(got, stored(keyA1, nameCI, 1, nil)) {
					t.Errorf("A's key became %+v", got)
				}

				// The control: the owner's own request is not refused.
				rg.logged = nil
				rg.store.calls = nil

				own := rg.as(rg.signIn(userA, roleMember), route.method, route.target, route.body)
				if own.Code != http.StatusOK {
					t.Errorf("the owner's request = %d %q, want 200", own.Code, own.Body.String())
				}
			})
		}
	}
}

// TestAnAgentsKeyIsNotTheUsersOwn: a key that belongs to an agent of the caller is
// never listed, read, renamed or revoked here, and is answered exactly as a key
// that does not exist, so these routes cannot be used to learn an agent's key
// ids or to end an agent's credential without the agent.
func TestAnAgentsKeyIsNotTheUsersOwn(t *testing.T) {
	t.Parallel()

	routes := []keyRoute{
		{name: routeGet, method: http.MethodGet, target: itemPrefix + agentKey, body: ""},
		{name: routePatch, method: http.MethodPatch, target: itemPrefix + agentKey, body: bodyRenamed},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + agentKey, body: ""},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(keyA1, nameCI, 1, nil))
			rg.seedAgentKey(userA, agentA1, stored(agentKey, "bot", 2, nil))

			rec := rg.as(rg.signIn(userA, roleMember), route.method, route.target, route.body)

			wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, keys.CodeNotFound)

			if got := rg.store.key(t, agentKey); got.Name != "bot" || got.RevokedAt != nil {
				t.Errorf("the agent's key became %+v", got)
			}
		})
	}

	t.Run("list", func(t *testing.T) {
		t.Parallel()

		rg := newRig(t)
		rg.seed(userA, stored(keyA1, nameCI, 1, nil))
		rg.seedAgentKey(userA, agentA1, stored(agentKey, "bot", 2, nil))

		rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, collection, "")

		wantOK(t, rg, rec, `{"keys":[`+keyJSON(keyA1, nameCI, 1, nil)+`]}`+"\n")
	})
}

// TestTheOwnerIsAlwaysTheCaller: whatever else a request says, every store call
// is made for the user the credential belongs to, on every route. The requests
// below all try to name user A while signed in as user B.
func TestTheOwnerIsAlwaysTheCaller(t *testing.T) {
	t.Parallel()

	noise := "?owner=" + userA + "&userId=" + userA + "&user_id=" + userA + "&sub=" + userA

	routes := []keyRoute{
		{name: routeList, method: http.MethodGet, target: collection + noise, body: ""},
		{name: routeCreate, method: http.MethodPost, target: collection + noise, body: bodyCI},
		{name: routeGet, method: http.MethodGet, target: itemPrefix + keyA1 + noise, body: ""},
		{name: routePatch, method: http.MethodPatch, target: itemPrefix + keyA1 + noise, body: bodyRenamed},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + keyA1 + noise, body: ""},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(keyA1, nameCI, 1, nil))

			rg.as(rg.signIn(userB, roleMember), route.method, route.target, route.body)

			if len(rg.store.calls) != 1 {
				t.Fatalf("store calls = %+v, want exactly one", rg.store.calls)
			}

			if call := rg.store.calls[0]; call.owner != userB {
				t.Errorf("owner = %q, want the caller's user %q", call.owner, userB)
			}

			if got := rg.store.key(t, keyA1); !reflect.DeepEqual(got, stored(keyA1, nameCI, 1, nil)) {
				t.Errorf("A's key became %+v", got)
			}
		})
	}
}

// TestListsHoldOnlyTheCallersKeys: a page is the caller's own keys and no one
// else's, including when the caller's cursor is an id of someone else's.
func TestListsHoldOnlyTheCallersKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		who    string
		target string
		want   string
	}{
		{
			name: "A", who: userA, target: collection,
			want: `{"keys":[` + keyJSON(keyA2, "alpha two", 3, nil) + `,` + keyJSON(keyA1, nameCI, 1, nil) + `]}`,
		},
		{
			name: "B", who: userB, target: collection,
			want: `{"keys":[` + keyJSON(keyB1, "bravo", 2, nil) + `,` + keyJSON(keyB0, "zero", 4, nil) + `]}`,
		},
		{
			name: "B with a cursor that is A's key", who: userB, target: collection + "?cursor=" + keyA2,
			want: `{"keys":[` + keyJSON(keyB0, "zero", 4, nil) + `]}`,
		},
		{name: "a user with none", who: "00000000-0000-7000-8000-0000000000dd", target: collection, want: bodyNoKeys},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(keyA1, nameCI, 1, nil), stored(keyA2, "alpha two", 3, nil))
			rg.seed(userB, stored(keyB1, "bravo", 2, nil), stored(keyB0, "zero", 4, nil))

			rec := rg.as(rg.signIn(tt.who, roleMember), http.MethodGet, tt.target, "")

			wantOK(t, rg, rec, tt.want+"\n")
		})
	}
}
