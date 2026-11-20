//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_consent_test.go: the consent write against the real D1. The store tells why
// a consent was refused by reading the column name out of the database's error
// text ("NOT NULL constraint failed: oauth_grants.agent_id"), which the host
// SQLite tests can only assume D1 words the same way. These tests send every
// refusal through the real driver and assert the client's answer, so a D1 that
// worded a constraint differently would show here as a 500 instead of the 401,
// 404 or 409 each case expects.

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const (
	codeConsentReplayed = "consent_replayed"
	codeAgentLimit      = "agent_limit_reached"
	codeAgentNotFound   = "agent_not_found"
	codeInvalidPending  = "invalid_oauth_request"
	codeInvalidConsent  = "invalid_consent"

	// codeInsufficient is a credential that lacks the scope a route needs.
	codeInsufficient = "insufficient_scope"

	// maxAgents is agents.MaxAgentsPerUser.
	maxAgents = 25
)

// oaPending starts an authorization request of a fresh client and returns it.
func oaPending(t *testing.T) (*oauthClient, string) {
	t.Helper()

	client := newOAuthClient(t)

	return client, pendingOf(t, authorize(t, client.authorizeQuery(newPKCE())))
}

// oaNothingWritten fails the test unless no grant, no grant secret and no agent
// beyond agents exists, and no secret is without its row.
func oaNothingWritten(t *testing.T, what string, agents int) {
	t.Helper()

	expectCount(t, tableOAuthGrants, "0")
	expectCount(t, "secrets WHERE kind IN (?, ?)", "0", kindOAuthGrant, kindOAuthAccess)
	expectCount(t, tableAgents, strconv.Itoa(agents))
	expectNoOrphanSecrets(t)

	_ = what
}

// TestOAuthConsentRefusals: each reason a consent is refused, through the real
// D1, with the answer the UI is given and the proof that nothing was written.
//
//nolint:paralleltest // shares one database
func TestOAuthConsentRefusals(t *testing.T) {
	t.Run("the agent limit", func(t *testing.T) {
		holder := newOAuthHolder(t)
		seedMany := func(from, n int) {
			for i := range n {
				seedAgent(t, idN("d100", from+i), holder.userID, "bulk")
			}
		}

		// At 24 the 25th is allowed and the 26th is not.
		seedMany(1, maxAgents-1)

		_, first := oaPending(t)
		consent(t, holder.session, first, true, newAgentChoice("the 25th")).expect(t, "the 25th agent", http.StatusOK, "")
		expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", holder.userID)

		_, second := oaPending(t)
		consent(t, holder.session, second, true, newAgentChoice("the 26th")).
			expect(t, "the 26th agent", http.StatusConflict, codeAgentLimit)
		expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", holder.userID)
		expectCount(t, tableOAuthGrants, "1")
		expectCount(t, "secrets WHERE kind = ?", "1", kindOAuthGrant)
		expectNoOrphanSecrets(t)

		// A limit is on creating agents: an existing one is still chosen.
		consent(t, holder.session, second, true, agentChoiceID(idN("d100", 1))).
			expect(t, "an existing agent at the limit", http.StatusOK, "")
		expectCount(t, tableOAuthGrants, "2")

		// A revoked agent frees a place.
		del(t, pathAgent+"/"+idN("d100", 2), holder.session).expect(t, "revoke an agent", http.StatusOK, "")

		_, third := oaPending(t)
		consent(t, holder.session, third, true, newAgentChoice("after a revocation")).
			expect(t, "a new agent after a revocation", http.StatusOK, "")
		expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", "25", holder.userID)
	})

	t.Run("an agent that is not the user's", func(t *testing.T) {
		holder := newOAuthHolder(t)
		other, _ := secondUser(t)

		seedAgent(t, idAgentA, other, "someone else's")
		seedAgent(t, idAgentB, holder.userID, "mine, revoked")
		seed(t, "UPDATE agents SET revoked_at = strftime('%s','now') - 100 WHERE id = ?", idAgentB)

		for _, tt := range []struct{ name, agent string }{
			{"another user's agent", idAgentA},
			{"a revoked agent", idAgentB},
			{"an agent that does not exist", idMissing},
		} {
			_, pending := oaPending(t)
			consent(t, holder.session, pending, true, agentChoiceID(tt.agent)).
				expect(t, tt.name, http.StatusNotFound, codeAgentNotFound)
		}

		oaNothingWritten(t, "an agent that is not the user's", 2)
		expectCount(t, "agents WHERE id = ? AND revoked_at IS NULL", "1", idAgentA)
	})

	t.Run("a consent used twice", func(t *testing.T) {
		holder := newOAuthHolder(t)
		other, otherSession := secondUser(t)
		seedAgent(t, idAgentA, holder.userID, "mine")

		_, pending := oaPending(t)
		first := consent(t, holder.session, pending, true, newAgentChoice("once"))
		first.expect(t, "the first approval", http.StatusOK, "")

		for _, tt := range []struct {
			name    string
			session string
			agent   map[string]string
		}{
			{"the same answer again", holder.session, newAgentChoice("once")},
			{"another new agent", holder.session, newAgentChoice("twice")},
			{"an existing agent", holder.session, agentChoiceID(idAgentA)},
			{"another user's session", otherSession, newAgentChoice("theirs")},
		} {
			consent(t, tt.session, pending, true, tt.agent).expect(t, tt.name, http.StatusConflict, codeConsentReplayed)
		}

		expectCount(t, tableOAuthGrants, "1")
		expectCount(t, "agents WHERE user_id = ?", "2", holder.userID)
		expectCount(t, tableAgents+" WHERE user_id = ?", "0", other)
		expectCount(t, "secrets WHERE kind = ?", "1", kindOAuthGrant)
		expectNoOrphanSecrets(t)

		// A refusal after an approval is still the replay, and writes nothing.
		consent(t, holder.session, pending, false, nil).
			expect(t, "a refusal of an approved request", http.StatusOK, "")
	})

	t.Run("a session that has ended", func(t *testing.T) {
		holder := newOAuthHolder(t)

		_, pending := oaPending(t)
		post(t, pathLogout, nil, holder.session).expect(t, "logout", http.StatusNoContent, "")
		consent(t, holder.session, pending, true, newAgentChoice("late")).
			expect(t, "a consent after logout", http.StatusUnauthorized, codeUnauthenticated)
		consent(t, "", pending, true, newAgentChoice("none")).
			expect(t, "a consent with no session", http.StatusUnauthorized, codeUnauthenticated)
		oaNothingWritten(t, "a session that has ended", 0)
	})

	t.Run("credentials that are not a session", func(t *testing.T) {
		holder := newOAuthHolder(t)
		seedAgent(t, idAgentA, holder.userID, "keyed")

		userKey := seedAPIKey(t, idN("d200", 1), holder.userID, "")
		agentKey := seedAPIKey(t, idN("d200", 2), holder.userID, idAgentA)

		_, pending := oaPending(t)
		body := consentBody(t, pending, true, newAgentChoice("by a key"))

		for _, tt := range []struct {
			name   string
			bearer string
			status int
			code   string
		}{
			{"a user's API key", userKey, http.StatusForbidden, codeForbidden},
			{"an agent's key", agentKey, http.StatusForbidden, codeForbidden},
			{"an access token", newToken(tagOAuthAccess), http.StatusUnauthorized, codeUnauthenticated},
			{"a refresh token", newToken(tagOAuthRefresh), http.StatusUnauthorized, codeUnauthenticated},
			{"an authorization code", newToken(tagOAuthCode), http.StatusUnauthorized, codeUnauthenticated},
			{"a session token as a bearer", holder.session, http.StatusUnauthorized, codeUnauthenticated},
		} {
			send(t, request{method: http.MethodPost, path: pathOAuthConsent, body: body, bearer: tt.bearer}).
				expect(t, "consent with "+tt.name, tt.status, tt.code)
		}

		oaNothingWritten(t, "credentials that are not a session", 1)
	})

	t.Run("a body that is not an answer", func(t *testing.T) {
		holder := newOAuthHolder(t)
		seedAgent(t, idAgentA, holder.userID, "mine")

		_, pending := oaPending(t)
		quoted := `"` + pending + `"`

		for _, tt := range []struct {
			name   string
			body   string
			status int
			code   string
		}{
			{"no approve", `{"request":` + quoted + `,"agent":{"new":"a"}}`, 400, codeInvalidConsent},
			{"approve as a string", `{"request":` + quoted + `,"approve":"true","agent":{"new":"a"}}`, 400, ""},
			{"an approval with no agent", `{"request":` + quoted + `,"approve":true}`, 400, codeInvalidConsent},
			{"an approval with an empty agent", `{"request":` + quoted + `,"approve":true,"agent":{}}`, 400, codeInvalidConsent},
			{"both a new agent and an id", `{"request":` + quoted + `,"approve":true,"agent":{"new":"a","id":"` + idAgentA + `"}}`, 400, codeInvalidConsent},
			{"a refusal that names an agent", `{"request":` + quoted + `,"approve":false,"agent":{"new":"a"}}`, 400, codeInvalidConsent},
			{"an agent id that is not an id", `{"request":` + quoted + `,"approve":true,"agent":{"id":"x"}}`, 400, "invalid_id"},
			{"an empty agent name", `{"request":` + quoted + `,"approve":true,"agent":{"new":""}}`, 400, "invalid_agent_name"},
			{"an agent name of 257 characters", `{"request":` + quoted + `,"approve":true,"agent":{"new":"` + strings.Repeat("a", 257) + `"}}`, 400, "invalid_agent_name"},
			{"an unknown member", `{"request":` + quoted + `,"approve":true,"agent":{"new":"a"},"scope":"x"}`, 400, codeUnknownField},
			{"no request", `{"approve":true,"agent":{"new":"a"}}`, 400, codeInvalidPending},
			{"an empty request", `{"request":"","approve":true,"agent":{"new":"a"}}`, 400, codeInvalidPending},
			{"a request that is not one", `{"request":"x","approve":true,"agent":{"new":"a"}}`, 400, codeInvalidPending},
			{"a request with a changed byte", `{"request":"` + oaFlip(pending, len(pending)/2) + `","approve":true,"agent":{"new":"a"}}`, 400, codeInvalidPending},
			{"a request with a changed signature", `{"request":"` + oaFlip(pending, len(pending)-1) + `","approve":true,"agent":{"new":"a"}}`, 400, codeInvalidPending},
			{"a truncated request", `{"request":"` + pending[:len(pending)-1] + `","approve":true,"agent":{"new":"a"}}`, 400, codeInvalidPending},
			{"a request with a byte added", `{"request":"` + pending + `A","approve":true,"agent":{"new":"a"}}`, 400, codeInvalidPending},
			{"not JSON", `request=x`, 400, ""},
		} {
			got := post(t, pathOAuthConsent, []byte(tt.body), holder.session)
			got.expect(t, tt.name, tt.status, tt.code)

			if leaks := bndLeaks(got.body); len(leaks) != 0 {
				t.Errorf("%s: the response matches leak patterns %v: %s", tt.name, leaks, got.body)
			}
		}

		oaNothingWritten(t, "a body that is not an answer", 1)

		// None of it used the request up.
		consent(t, holder.session, pending, true, newAgentChoice("at last")).
			expect(t, "the request after every refusal", http.StatusOK, "")
	})

	t.Run("a refusal by the user", func(t *testing.T) {
		holder := newOAuthHolder(t)
		client, pending := oaPending(t)

		got := consent(t, holder.session, pending, false, nil)
		redirect := consentRedirect(t, got)
		params := redirect.Query()
		redirect.RawQuery = ""

		if redirect.String() != client.redirect || params.Get("error") != "access_denied" || params.Get("iss") != target.apiOrigin ||
			params.Get("state") == "" || params.Has("code") {
			t.Errorf("refusal redirect = %s %v", redirect, params)
		}

		oaNothingWritten(t, "a refusal by the user", 0)

		// A refusal uses nothing up either: the same request can still be approved.
		consent(t, holder.session, pending, true, newAgentChoice("changed my mind")).
			expect(t, "an approval after a refusal", http.StatusOK, "")
	})
}

// oaFlip returns s with the character at i replaced by a different one of the
// same alphabet.
func oaFlip(s string, i int) string {
	replacement := "A"
	if s[i] == 'A' {
		replacement = "B"
	}

	return s[:i] + replacement + s[i+1:]
}

// TestOAuthConsentRacingAChange: a state change that lands between the moment
// consent was authenticated and the moment it is written. Seeds cannot be timed
// into that gap from outside, so a trigger does it at the one point inside the
// write that follows the agent and the code's secret and precedes the grant: the
// change is committed, from the write's point of view, just ahead of the grant
// row, which is where the write's own conditions are read. Each case must refuse,
// with the client's answer for that reason (which the store reads out of D1's
// error text) and write nothing at all, and the agent a refused consent was to
// create must not survive it.
//
//nolint:paralleltest // shares one database
func TestOAuthConsentRacingAChange(t *testing.T) {
	cases := []struct {
		name    string
		trigger string
		agent   func(holder oauthHolder) map[string]string
		status  int
		code    string
		// retry is whether the same request can be approved again afterwards.
		retry bool
	}{
		{
			name:    "the session ends, creating an agent",
			trigger: "UPDATE secrets SET revoked_at = strftime('%s','now') - 100 WHERE kind = 'session';",
			agent:   func(oauthHolder) map[string]string { return newAgentChoice("gap") },
			status:  http.StatusUnauthorized, code: codeUnauthenticated,
		},
		{
			name:    "the session ends, picking an agent",
			trigger: "UPDATE secrets SET revoked_at = strftime('%s','now') - 100 WHERE kind = 'session';",
			agent:   func(oauthHolder) map[string]string { return agentChoiceID(idAgentA) },
			status:  http.StatusUnauthorized, code: codeUnauthenticated,
		},
		{
			name:    "the account is revoked, creating an agent",
			trigger: "UPDATE users SET revoked_at = strftime('%s','now');",
			agent:   func(oauthHolder) map[string]string { return newAgentChoice("gap") },
			status:  http.StatusUnauthorized, code: codeUnauthenticated,
		},
		{
			name:    "the account is revoked, picking an agent",
			trigger: "UPDATE users SET revoked_at = strftime('%s','now');",
			agent:   func(oauthHolder) map[string]string { return agentChoiceID(idAgentA) },
			status:  http.StatusUnauthorized, code: codeUnauthenticated,
		},
		{
			name:    "the chosen agent is revoked",
			trigger: "UPDATE agents SET revoked_at = strftime('%s','now');",
			agent:   func(oauthHolder) map[string]string { return agentChoiceID(idAgentA) },
			status:  http.StatusNotFound, code: codeAgentNotFound, retry: true,
		},
		{
			name:    "the chosen agent is deleted",
			trigger: "DELETE FROM agents;",
			agent:   func(oauthHolder) map[string]string { return agentChoiceID(idAgentA) },
			status:  http.StatusNotFound, code: codeAgentNotFound, retry: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			holder := newOAuthHolder(t)
			seedAgent(t, idAgentA, holder.userID, "mine")

			_, pending := oaPending(t)

			seed(t, "CREATE TRIGGER e2e_consent_gap AFTER INSERT ON secrets WHEN NEW.kind = 'oauth_grant' BEGIN "+tt.trigger+" END")

			got := post(t, pathOAuthConsent, consentBody(t, pending, true, tt.agent(holder)), holder.session)

			// Dropped right after the one request, so a failing assertion cannot
			// leave it behind for the next test.
			seed(t, "DROP TRIGGER e2e_consent_gap")

			got.expect(t, tt.name, tt.status, tt.code)

			// The whole batch rolled back: no grant, no code, and no agent the
			// refused consent was to create.
			expectCount(t, tableOAuthGrants, "0")
			expectCount(t, "secrets WHERE kind = ?", "0", kindOAuthGrant)
			expectCount(t, tableAgents, "1")
			expectNoOrphanSecrets(t)

			if leaks := bndLeaks(got.body); len(leaks) != 0 {
				t.Errorf("the response matches leak patterns %v: %s", leaks, got.body)
			}

			if tt.retry {
				// The request was not used up: the refused write took its
				// granted_from back with it.
				consent(t, holder.session, pending, true, newAgentChoice("retried")).
					expect(t, "the same request again, creating an agent", http.StatusOK, "")
			}
		})
	}
}
