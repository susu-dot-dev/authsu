//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// secrets_test.go drives what every kind of secret has in common
// (docs/secrets_design.md) through the Worker: the invitation code, the session
// and the API key are tokens that are shown once and stored only as a hash, and
// each is revoked by something other than itself (logout, an account's
// revocation, an agent's revocation) with the revocation seen on the very next
// request. Each kind's own behaviour is tested in its own file; the schema's
// constraints are in schema_test.go.
//
// REVIEW.md categories covered: permission confusion (a revocation reaching
// exactly what it should: an agent's revocation ends that agent's keys and
// nothing else, an account's ends everything it holds and nobody else's) and
// type/bound confusion (the stored hash is of the whole token, prefix included,
// so a body alone, or the same body under another tag, finds nothing).

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestTokensAreStoredNowhere issues one secret of each kind through the Worker:
// an invitation code, a session, an agent key (and the first-run token is
// already configured). The tokens are shown once, in the response that issued
// them, and no column of any table holds any of them, as text or as bytes, nor
// the 43-character body, nor the 32 bytes the body encodes. What is stored is
// the SHA-256 of the whole token, prefix included, under a secret of the right
// kind with its own row.
//
//nolint:paralleltest // shares one database
func TestTokensAreStoredNowhere(t *testing.T) {
	admin := newAdmin(t)
	session := login(t, admin)

	invited := post(t, pathInvitation, []byte(`{"type":"member","numInvites":1}`), session)
	invited.expect(t, "create an invitation", http.StatusCreated, "")

	var invitation struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}

	err := json.Unmarshal([]byte(invited.body), &invitation)
	if err != nil {
		t.Fatalf("parse %s: %v", invited.body, err)
	}

	made := agMustCreate(t, session, "holder")

	tokens := []struct {
		name  string
		token string
		tag   string
		kind  string
		id    string
	}{
		{"invitation code", invitation.Code, tagInvitation, kindInvitation, invitation.ID},
		{"session", session, tagSession, kindSession, ""},
		{"agent key", made.Key.Token, tagAPIKey, kindAPIKey, made.Key.ID},
		{"first-run token", firstRunSecret, tagInvitation, kindInvitation, ""},
	}

	all := make([]string, 0, len(tokens))

	for _, tok := range tokens {
		all = append(all, tok.token)

		t.Run(tok.name, func(t *testing.T) {
			expectToken(t, tok.token, tok.tag)

			stored := mustSecretOf(t, tok.token)
			if stored.kind != tok.kind || !stored.kindRow || stored.revoked || (tok.id != "" && stored.id != tok.id) {
				t.Errorf("secret = %+v, want an active %s with its own row (id %q)", stored, tok.kind, tok.id)
			}

			// The hash is of the whole string, prefix included: the body alone
			// and the same body under another tag are different values that
			// nothing stores.
			body := tok.token[len(tokenPrefix(tok.tag)):]
			for _, other := range []string{body, tokenPrefix(tagSession) + body, tokenPrefix(tagAPIKey) + body, tokenPrefix(tagInvitation) + body} {
				if other == tok.token {
					continue
				}

				if secretOf(t, other).found {
					t.Errorf("a secret is stored under the hash of %.18s...: the prefix is not part of what is hashed", other)
				}
			}

			if got := scalar(t, "SELECT lower(hex(hash)) FROM secrets WHERE id = ?", stored.id); got != hex.EncodeToString(tokenHash(tok.token)) {
				t.Errorf("secrets.hash = %s, want sha256 of the whole token", got)
			}
		})
	}

	expectStoredNowhere(t, all...)
	expectNoOrphanSecrets(t)

	// Four secrets of three kinds: the first-run invitation, the one created
	// through the API, the session and the key.
	expectCount(t, "secrets", "4")
	expectCount(t, "secrets WHERE kind = 'invitation'", "2")
	expectCount(t, "secrets WHERE kind = 'session'", "1")
	expectCount(t, "secrets WHERE kind = 'api_key'", "1")
}

// TestLogoutOfAnAPIKey: an API key signs itself out. The presented secret is
// revoked, its row and secret are kept, the same token is then refused like any
// request without a credential, and nothing else the user holds is touched.
//
//nolint:paralleltest // shares one database
func TestLogoutOfAnAPIKey(t *testing.T) {
	world := agNewPair(t, roleMember)

	own := seedAPIKey(t, idN("0e20", 1), world.b.userID, "")
	other := seedAPIKey(t, idN("0e20", 2), world.b.userID, "")
	agentKey := agMustCreate(t, world.tokenB, "bystander").Key.Token

	scBearer(t, http.MethodGet, pathSession, nil, own).expect(t, "the key before", http.StatusOK, "")

	got := scBearer(t, http.MethodPost, pathLogout, nil, own)
	got.expect(t, "logout by the key", http.StatusNoContent, "")

	stored := mustSecretOf(t, own)
	if !stored.revoked || !stored.kindRow || stored.kind != kindAPIKey {
		t.Errorf("the key's secret after its logout = %+v, want revoked and kept with its api_keys row", stored)
	}

	scBearer(t, http.MethodGet, pathSession, nil, own).
		expect(t, "the key after its logout", http.StatusUnauthorized, codeUnauthenticated)
	scBearer(t, http.MethodPost, pathLogout, nil, own).
		expect(t, "a second logout by the key", http.StatusUnauthorized, codeUnauthenticated)

	// Nothing else was ended: another key of the user, the agent's key and the session.
	scBearer(t, http.MethodGet, pathSession, nil, other).expect(t, "another key of the user", http.StatusOK, "")
	scBearer(t, http.MethodGet, pathSession, nil, agentKey).expect(t, "the agent's key", http.StatusOK, "")
	get(t, pathSession, world.tokenB).expect(t, "the user's session", http.StatusOK, "")
	expectCount(t, "secrets WHERE revoked_at IS NOT NULL", "1")
}

// TestLogoutRevokesTheSessionAndKeepsItsRows: logout revokes exactly the
// presented session, whose secret and session rows stay (a revoked secret is
// removed only once it has expired), and the user's other sessions and keys
// keep working.
//
//nolint:paralleltest // shares one database
func TestLogoutRevokesTheSessionAndKeepsItsRows(t *testing.T) {
	world := agNewPair(t, roleMember)

	second := login(t, world.b)
	key := agMustCreate(t, world.tokenB, "keeps working").Key.Token
	before := mustSecretOf(t, world.tokenB)

	post(t, pathLogout, nil, world.tokenB).expect(t, "logout", http.StatusNoContent, "")

	after := mustSecretOf(t, world.tokenB)
	if !after.revoked || after.id != before.id || !after.kindRow || after.expiresAt != before.expiresAt {
		t.Errorf("the session's secret after logout = %+v, was %+v: want it revoked and otherwise as it was", after, before)
	}

	get(t, pathSession, world.tokenB).expect(t, "the session after logout", http.StatusUnauthorized, codeUnauthenticated)
	get(t, pathSession, second).expect(t, "another session", http.StatusOK, "")
	scBearer(t, http.MethodGet, pathSession, nil, key).expect(t, "the agent's key", http.StatusOK, "")
	expectCount(t, "secrets WHERE revoked_at IS NOT NULL", "1")
}

// TestUserRevocationEndsEveryCredentialItHolds: an administrator revokes a
// member who holds a session, a key of their own and an agent's key. Each of
// the three is refused on the next request, and the administrator's own
// credentials and another member's are untouched.
//
//nolint:paralleltest // shares one database
func TestUserRevocationEndsEveryCredentialItHolds(t *testing.T) {
	world := agNewPair(t, roleMember)

	owned := struct{ session, own, agent string }{
		session: world.tokenB,
		own:     seedAPIKey(t, idN("0e30", 1), world.b.userID, ""),
		agent:   agMustCreate(t, world.tokenB, "doomed").Key.Token,
	}

	seedUser(t, idUserC, roleMember)

	bystander := struct{ session, key string }{
		session: seedSession(t, idN("0e30", 2), idUserC),
		key:     seedAPIKey(t, idN("0e30", 3), idUserC, ""),
	}

	adminKey := agMustCreate(t, world.tokenA, "admin's").Key.Token

	live := func(what string, want int) {
		t.Helper()

		if got := get(t, pathSession, owned.session); got.status != want {
			t.Errorf("%s: the member's session = %d %s, want %d", what, got.status, got.body, want)
		}

		for name, token := range map[string]string{"own key": owned.own, "agent key": owned.agent} {
			if got := scBearer(t, http.MethodGet, pathSession, nil, token); got.status != want {
				t.Errorf("%s: the member's %s = %d %s, want %d", what, name, got.status, got.body, want)
			}
		}
	}

	live("before", http.StatusOK)

	del(t, pathUser+"/"+world.b.userID, world.tokenA).expect(t, "revoke the member", http.StatusOK, "")

	live("after", http.StatusUnauthorized)

	for _, token := range []string{owned.session, owned.own, owned.agent} {
		if stored := secretOf(t, token); !stored.found || !stored.revoked || !stored.kindRow {
			t.Errorf("a revoked member's secret = %+v, want kept and revoked", stored)
		}
	}

	// Nobody else is touched.
	get(t, pathSession, world.tokenA).expect(t, "the administrator's session", http.StatusOK, "")
	scBearer(t, http.MethodGet, pathSession, nil, adminKey).expect(t, "the administrator's agent key", http.StatusOK, "")
	get(t, pathSession, bystander.session).expect(t, "another member's session", http.StatusOK, "")
	scBearer(t, http.MethodGet, pathSession, nil, bystander.key).expect(t, "another member's key", http.StatusOK, "")
}

// TestAgentRevocationEndsOnlyItsKeys: revoking an agent ends that agent's keys,
// every one of them, on the next request, and nothing else: not the user's
// session, not the user's own key, not another agent's key, and not a key of
// another user's agent.
//
//nolint:paralleltest // shares one database
func TestAgentRevocationEndsOnlyItsKeys(t *testing.T) {
	world := agNewPair(t, roleMember)

	doomed := agMustCreate(t, world.tokenB, "doomed")
	spared := agMustCreate(t, world.tokenB, "spared")
	foreign := agMustCreate(t, world.tokenA, "foreign")

	// A second key on the doomed agent, which creation has no way to make.
	second := seedAPIKey(t, idN("0e40", 1), world.b.userID, doomed.Agent.ID)
	own := seedAPIKey(t, idN("0e40", 2), world.b.userID, "")

	bearers := map[string]string{
		"doomed key": doomed.Key.Token, "doomed second key": second,
		"spared key": spared.Key.Token, "own key": own, "foreign key": foreign.Key.Token,
	}

	for name, token := range bearers {
		scBearer(t, http.MethodGet, pathSession, nil, token).expect(t, name+" before", http.StatusOK, "")
	}

	del(t, agItem(doomed.Agent.ID), world.tokenB).expect(t, "revoke the agent", http.StatusOK, "")

	for name, token := range bearers {
		want := http.StatusOK
		if strings.HasPrefix(name, "doomed") {
			want = http.StatusUnauthorized
		}

		scBearer(t, http.MethodGet, pathSession, nil, token).expect(t, name+" after", want, "")
	}

	get(t, pathSession, world.tokenB).expect(t, "the user's session", http.StatusOK, "")

	// The doomed agent's secrets are revoked and kept; the others are not.
	expectCount(t, keyRows+" WHERE k.agent_id = ? AND revoked_at IS NOT NULL", "2", doomed.Agent.ID)
	expectCount(t, keyRows+" WHERE k.agent_id <> ? AND revoked_at IS NOT NULL", "0", doomed.Agent.ID)
	expectCount(t, "secrets WHERE kind = 'api_key' AND revoked_at IS NOT NULL", "2")
}
