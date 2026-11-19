//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_race_test.go: interleavings of concurrent requests against the real D1
// (docs/TESTING.md): requests are prepared, released together, and awaited, and the
// database is read back afterwards. Each test states the invariant that must hold
// whichever request wins, and repeats its race in rounds so that more than one
// ordering is exercised. Which request wins is never asserted, only what holds
// after: exactly one winner where one is meant, the database consistent, and no
// 5xx, which would be a lost race reported as a defect.

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// oaRace runs n calls together, released by one channel, and returns their
// replies in call order.
func oaRace(n int, call func(i int) reply) []reply {
	replies := make([]reply, n)
	start := make(chan struct{})

	var group sync.WaitGroup

	for i := range n {
		group.Go(func() {
			<-start

			replies[i] = call(i)
		})
	}

	close(start)
	group.Wait()

	return replies
}

// oaTally counts replies by "status error".
func oaTally(replies []reply) map[string]int {
	out := map[string]int{}

	for _, r := range replies {
		key := strconv.Itoa(r.status)

		if code := r.errorCode(); code != "" {
			key += " " + code
		} else if code = r.oauthError(); code != "" {
			key += " " + code
		}

		out[key]++
	}

	return out
}

// oaNo5xx fails the test on any 5xx reply.
func oaNo5xx(t *testing.T, what string, replies []reply) {
	t.Helper()

	for _, r := range replies {
		if r.status >= http.StatusInternalServerError {
			t.Errorf("%s: a lost race answered %d %s", what, r.status, r.body)
		}
	}
}

// oaWinners returns the replies that succeeded.
func oaWinners(replies []reply) []reply {
	var out []reply

	for _, r := range replies {
		if r.status == http.StatusOK {
			out = append(out, r)
		}
	}

	return out
}

// oaRaceRounds is how many times each race is run.
const oaRaceRounds = 5

// TestOAuthRaceSameCode: the same authorization code exchanged by several
// requests at once. Exactly one succeeds, the rest are invalid_grant, and the
// grant ends with one refresh token and one access token.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceSameCode(t *testing.T) {
	holder := newOAuthHolder(t)
	seedAgent(t, idAgentA, holder.userID, "racer")

	const callers = 6

	for round := range oaRaceRounds {
		a := approve(t, newOAuthClient(t), holder.session, agentChoiceID(idAgentA))
		grant := idOfToken(t, a.code)

		replies := oaRace(callers, func(int) reply { return a.exchange(t) })
		tally := oaTally(replies)
		t.Logf("round %d: %v", round, tally)

		oaNo5xx(t, "an exchange", replies)

		winners := oaWinners(replies)
		if len(winners) != 1 || tally["400 invalid_grant"] != callers-1 {
			t.Fatalf("round %d: exchanges answered %v, want one 200 and %d invalid_grant", round, tally, callers-1)
		}

		won := mustTokens(t, winners[0])

		if got, _ := introspect(t, won.AccessToken, oauthResource); !got.Active {
			t.Errorf("round %d: the winner's access token is not active", round)
		}

		// One refresh token under the grant's id, and one access token.
		if secret := mustSecretOf(t, won.RefreshToken); secret.id != grant || secret.revoked {
			t.Errorf("round %d: the winner's refresh token = %+v, want the live secret of grant %s", round, secret, grant)
		}

		expectCount(t, "oauth_access_tokens WHERE grant_id = ?", "1", grant)
		expectCount(t, "secrets WHERE kind = ?", strconv.Itoa(round+1), kindOAuthAccess)
		expectNoOrphanSecrets(t)

		a.exchange(t).expectOAuth(t, "the code again", http.StatusBadRequest, "invalid_grant")
	}
}

// TestOAuthRaceSameRefreshToken: the same refresh token presented by several
// requests at once, rounds in a row. Exactly one rotates it, and only the
// winner's tokens work afterwards: the grant still has one access token, which is
// the winner's.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceSameRefreshToken(t *testing.T) {
	holder := newOAuthHolder(t)
	issued := oaIssue(t, holder.session, newAgentChoice("refresh racer"))

	const callers = 6

	current := issued.tokens

	for round := range oaRaceRounds {
		replies := oaRace(callers, func(int) reply { return issued.a.refresh(t, current.RefreshToken) })
		tally := oaTally(replies)
		t.Logf("round %d: %v", round, tally)

		oaNo5xx(t, "a refresh", replies)

		winners := oaWinners(replies)
		if len(winners) != 1 || tally["400 invalid_grant"] != callers-1 {
			t.Fatalf("round %d: refreshes answered %v, want one 200 and %d invalid_grant", round, tally, callers-1)
		}

		won := mustTokens(t, winners[0])

		expectInactive(t, "the replaced access token", current.AccessToken, oauthResource)

		if got, _ := introspect(t, won.AccessToken, oauthResource); !got.Active {
			t.Errorf("round %d: the winner's access token is not active", round)
		}

		issued.a.refresh(t, current.RefreshToken).expectOAuth(t, "the replaced refresh token", http.StatusBadRequest, "invalid_grant")

		expectCount(t, "oauth_access_tokens WHERE grant_id = ?", "1", issued.grant)
		expectCount(t, "secrets WHERE kind = ?", "1", kindOAuthAccess)
		expectCount(t, "secrets WHERE kind = ?", "1", kindOAuthGrant)
		expectNoOrphanSecrets(t)

		current = won
	}
}

// TestOAuthRaceConsentSubmittedTwice: one pending request approved by many
// requests at once, with the same answer and with different ones. One grant and at
// most one agent exist afterwards, and an agent that belongs to a losing consent
// does not.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceConsentSubmittedTwice(t *testing.T) {
	const callers = 8

	t.Run("the same answer", func(t *testing.T) {
		holder := newOAuthHolder(t)

		for round := range oaRaceRounds {
			_, pending := oaPending(t)

			replies := oaRace(callers, func(int) reply {
				return consent(t, holder.session, pending, true, newAgentChoice("double click"))
			})
			tally := oaTally(replies)
			t.Logf("round %d: %v", round, tally)

			oaNo5xx(t, "a consent", replies)

			if tally["200"] != 1 || tally["409 "+codeConsentReplayed] != callers-1 {
				t.Fatalf("round %d: consents answered %v, want one 200 and %d consent_replayed", round, tally, callers-1)
			}

			expectCount(t, tableOAuthGrants, strconv.Itoa(round+1))
			expectCount(t, tableAgents, strconv.Itoa(round+1))
			expectCount(t, "secrets WHERE kind = ?", strconv.Itoa(round+1), kindOAuthGrant)
			expectNoOrphanSecrets(t)
		}
	})

	t.Run("different answers", func(t *testing.T) {
		holder := newOAuthHolder(t)
		seedAgent(t, idAgentA, holder.userID, "existing")

		for round := range oaRaceRounds {
			_, pending := oaPending(t)

			replies := oaRace(callers, func(i int) reply {
				if i%2 == 0 {
					return consent(t, holder.session, pending, true, newAgentChoice("racing "+strconv.Itoa(i)))
				}

				return consent(t, holder.session, pending, true, agentChoiceID(idAgentA))
			})
			tally := oaTally(replies)
			t.Logf("round %d: %v", round, tally)

			oaNo5xx(t, "a consent", replies)

			if tally["200"] != 1 || tally["409 "+codeConsentReplayed] != callers-1 {
				t.Fatalf("round %d: consents answered %v, want one 200 and %d consent_replayed", round, tally, callers-1)
			}

			expectCount(t, tableOAuthGrants, strconv.Itoa(round+1))
			expectCount(t, "secrets WHERE kind = ?", strconv.Itoa(round+1), kindOAuthGrant)

			// Every agent but the seeded one belongs to a grant: a consent that
			// lost took its agent with it.
			expectCount(t, "agents WHERE id != ? AND id NOT IN (SELECT agent_id FROM oauth_grants)", "0", idAgentA)
			expectNoOrphanSecrets(t)
		}
	})

	t.Run("an approval and a refusal", func(t *testing.T) {
		holder := newOAuthHolder(t)

		_, pending := oaPending(t)

		replies := oaRace(callers, func(i int) reply {
			if i == 0 {
				return consent(t, holder.session, pending, false, nil)
			}

			return consent(t, holder.session, pending, true, newAgentChoice("racing"))
		})

		oaNo5xx(t, "a consent", replies)
		expectCount(t, tableOAuthGrants, "1")
		expectCount(t, tableAgents, "1")
	})
}

// TestOAuthRaceConsentAgentLimit: consents that each create an agent, released
// together against a user near the limit of 25 active agents, and against direct
// agent creation, which shares the limit. No more than 25 ever exist, every
// success has its grant and every grant its agent.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceConsentAgentLimit(t *testing.T) {
	for _, tt := range []struct {
		name string
		// have is how many active agents the user has; consents and creates are
		// the numbers of each kind of request.
		have, consents, creates int
	}{
		{"one place left", maxAgents - 1, 6, 0},
		{"five places left", maxAgents - 5, 10, 0},
		{"no place left", maxAgents, 6, 0},
		{"consents against direct creates", maxAgents - 5, 8, 8},
	} {
		t.Run(tt.name, func(t *testing.T) {
			holder := newOAuthHolder(t)

			for i := range tt.have {
				seedAgent(t, idN("d500", i+1), holder.userID, "bulk")
			}

			pendings := make([]string, tt.consents)
			for i := range pendings {
				_, pendings[i] = oaPending(t)
			}

			replies := oaRace(tt.consents+tt.creates, func(i int) reply {
				if i < tt.consents {
					return consent(t, holder.session, pendings[i], true, newAgentChoice("racing "+strconv.Itoa(i)))
				}

				return post(t, pathAgent, mustJSON(t, map[string]string{"name": "direct " + strconv.Itoa(i)}), holder.session)
			})

			oaNo5xx(t, "a creation", replies)

			var granted, created int

			for i, r := range replies {
				switch {
				case i < tt.consents && r.status == http.StatusOK:
					granted++
				case i < tt.consents && r.status == http.StatusConflict && r.errorCode() == codeAgentLimit:
				case i >= tt.consents && r.status == http.StatusCreated:
					created++
				case i >= tt.consents && r.status == http.StatusConflict && r.errorCode() == codeAgentLimit:
				default:
					t.Errorf("request %d answered %d %s", i, r.status, r.body)
				}
			}

			t.Logf("%s: %d consents granted, %d direct creates, of %v", tt.name, granted, created, oaTally(replies))

			// The user ends with exactly the agents the successes made, never more
			// than the limit, and with the limit's worth if there was demand for it:
			// a request is not refused while there is room.
			want := min(maxAgents, tt.have+tt.consents+tt.creates)

			expectCount(t, "agents WHERE user_id = ? AND revoked_at IS NULL", strconv.Itoa(want), holder.userID)

			if tt.have+granted+created != want {
				t.Errorf("%d agents were made by successes, want %d", tt.have+granted+created, want)
			}

			expectCount(t, tableOAuthGrants, strconv.Itoa(granted))
			expectCount(t, "secrets WHERE kind = ?", strconv.Itoa(granted), kindOAuthGrant)
			expectCount(t, "agents WHERE id IN (SELECT agent_id FROM oauth_grants)", strconv.Itoa(granted))
			expectNoOrphanSecrets(t)
		})
	}
}

// TestOAuthRaceAgentRevoked: the agent a grant is bound to is revoked between
// consent and exchange, and while the exchange runs. The exchange then fails with
// invalid_grant, or, if it won the race, whatever it issued is dead the moment the
// revocation lands.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceAgentRevoked(t *testing.T) {
	holder := newOAuthHolder(t)

	t.Run("between consent and exchange", func(t *testing.T) {
		client := newOAuthClient(t)
		a := approve(t, client, holder.session, newAgentChoice("revoked early"))
		agent := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", idOfToken(t, a.code))

		del(t, pathAgent+"/"+agent, holder.session).expect(t, "revoke the agent", http.StatusOK, "")
		a.exchange(t).expectOAuth(t, "the exchange for a revoked agent's grant", http.StatusBadRequest, "invalid_grant")
		expectCount(t, "secrets WHERE kind = ?", "0", kindOAuthAccess)
	})

	t.Run("while the exchange runs", func(t *testing.T) {
		for round := range oaRaceRounds {
			client := newOAuthClient(t)
			a := approve(t, client, holder.session, newAgentChoice("revoked during "+strconv.Itoa(round)))
			agent := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", idOfToken(t, a.code))

			replies := oaRace(2, func(i int) reply {
				if i == 0 {
					return a.exchange(t)
				}

				return del(t, pathAgent+"/"+agent, holder.session)
			})
			oaNo5xx(t, "an exchange or a revocation", replies)

			replies[1].expect(t, "the revocation", http.StatusOK, "")

			if replies[0].status == http.StatusOK {
				won := mustTokens(t, replies[0])
				expectInactive(t, "the access token of a revoked agent's grant", won.AccessToken, oauthResource)
				a.refresh(t, won.RefreshToken).expectOAuth(t, "the refresh token of a revoked agent's grant", http.StatusBadRequest, "invalid_grant")
			} else {
				replies[0].expectOAuth(t, "the exchange that lost", http.StatusBadRequest, "invalid_grant")
			}

			t.Logf("round %d: the exchange answered %d", round, replies[0].status)
			expectNoOrphanSecrets(t)
		}
	})

	t.Run("while a refresh runs", func(t *testing.T) {
		for round := range oaRaceRounds {
			issued := oaIssue(t, holder.session, newAgentChoice("revoked during refresh "+strconv.Itoa(round)))
			agent := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", issued.grant)

			replies := oaRace(3, func(i int) reply {
				if i < 2 {
					return issued.a.refresh(t, issued.tokens.RefreshToken)
				}

				return del(t, pathAgent+"/"+agent, holder.session)
			})
			oaNo5xx(t, "a refresh or a revocation", replies)

			for _, r := range oaWinners(replies[:2]) {
				won := mustTokens(t, r)
				expectInactive(t, "the access token of a revoked agent's grant", won.AccessToken, oauthResource)
			}

			expectInactive(t, "the first access token", issued.tokens.AccessToken, oauthResource)
		}
	})
}

// TestOAuthRaceUserRevoked: the user is revoked while a refresh, an exchange or a
// consent is in flight. Whatever the grant issued before the revocation is dead
// once it has landed, and nothing can be exchanged or refreshed afterwards.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceUserRevoked(t *testing.T) {
	// holder is the administrator, who revokes; each round has its own member.
	holder := newOAuthHolder(t)

	member := func(round int) (string, string) {
		id := idN("b300", round+1)
		seedUser(t, id, roleMember)

		return id, seedSession(t, idN("5e30", round+1), id)
	}

	t.Run("during a refresh", func(t *testing.T) {
		for round := range oaRaceRounds {
			id, session := member(round)
			issued := oaIssue(t, session, newAgentChoice("member agent"))

			replies := oaRace(3, func(i int) reply {
				if i < 2 {
					return issued.a.refresh(t, issued.tokens.RefreshToken)
				}

				return usrRevoke(t, holder.session, id)
			})
			oaNo5xx(t, "a refresh or a revocation", replies)
			replies[2].expect(t, "the user's revocation", http.StatusOK, "")

			for _, r := range oaWinners(replies[:2]) {
				expectInactive(t, "an access token issued around a revocation", mustTokens(t, r).AccessToken, oauthResource)
			}

			expectInactive(t, "the first access token", issued.tokens.AccessToken, oauthResource)

			for _, r := range replies[:2] {
				if r.status != http.StatusOK {
					r.expectOAuth(t, "a refresh that lost", http.StatusBadRequest, "invalid_grant")
				}
			}

			issued.a.refresh(t, issued.tokens.RefreshToken).expectOAuth(t, "a refresh after the revocation", http.StatusBadRequest, "invalid_grant")
		}
	})

	t.Run("during an exchange", func(t *testing.T) {
		for round := range oaRaceRounds {
			id, session := member(round + oaRaceRounds)
			a := approve(t, newOAuthClient(t), session, newAgentChoice("member agent"))

			replies := oaRace(2, func(i int) reply {
				if i == 0 {
					return a.exchange(t)
				}

				return usrRevoke(t, holder.session, id)
			})
			oaNo5xx(t, "an exchange or a revocation", replies)

			if replies[0].status == http.StatusOK {
				expectInactive(t, "the access token of a revoked user", mustTokens(t, replies[0]).AccessToken, oauthResource)
			} else {
				replies[0].expectOAuth(t, "the exchange that lost", http.StatusBadRequest, "invalid_grant")
			}

			a.exchange(t).expectOAuth(t, "an exchange after the revocation", http.StatusBadRequest, "invalid_grant")
		}
	})

	t.Run("during a consent", func(t *testing.T) {
		for round := range oaRaceRounds {
			id, session := member(round + 2*oaRaceRounds)
			client := newOAuthClient(t)
			pair := newPKCE()
			pending := pendingOf(t, authorize(t, client.authorizeQuery(pair)))

			replies := oaRace(2, func(i int) reply {
				if i == 0 {
					return consent(t, session, pending, true, newAgentChoice("member agent"))
				}

				return usrRevoke(t, holder.session, id)
			})
			oaNo5xx(t, "a consent or a revocation", replies)

			if replies[0].status == http.StatusOK {
				// A code issued around a revocation is no good afterwards.
				code := consentRedirect(t, replies[0]).Query().Get("code")
				(approved{client: client, pkce: pair, code: code}).exchange(t).expectOAuth(t, "a code issued to a revoked user", http.StatusBadRequest, "invalid_grant")
			} else {
				replies[0].expect(t, "the consent that lost", http.StatusUnauthorized, codeUnauthenticated)
			}
		}
	})
}

// TestOAuthRaceGrantRevokedDuringUse: a grant revoked while it is being
// introspected, refreshed, or exchanged. Every answer is a clean answer (active or
// not, never an error), and after the revocation has been answered nothing the
// grant issued is live.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceGrantRevokedDuringUse(t *testing.T) {
	holder := newOAuthHolder(t)

	t.Run("during introspection", func(t *testing.T) {
		for round := range oaRaceRounds {
			issued := oaIssue(t, holder.session, newAgentChoice("introspected "+strconv.Itoa(round)))

			replies := oaRace(9, func(i int) reply {
				if i == 4 {
					return del(t, pathGrant+"/"+issued.grant, holder.session)
				}

				return postForm(t, pathOAuthIntrospect, url.Values{"token": {issued.tokens.AccessToken}, "resource": {oauthResource}})
			})
			oaNo5xx(t, "an introspection or the revocation", replies)

			for i, r := range replies {
				switch {
				case i == 4:
					r.expect(t, "the revocation", http.StatusOK, "")
				case r.status != http.StatusOK:
					t.Errorf("introspection answered %d %s", r.status, r.body)
				}
			}

			expectInactive(t, "the access token after the revocation", issued.tokens.AccessToken, oauthResource)
			issued.a.refresh(t, issued.tokens.RefreshToken).expectOAuth(t, "a refresh after the revocation", http.StatusBadRequest, "invalid_grant")
		}
	})

	t.Run("during a refresh", func(t *testing.T) {
		for round := range oaRaceRounds {
			issued := oaIssue(t, holder.session, newAgentChoice("refreshed "+strconv.Itoa(round)))

			replies := oaRace(3, func(i int) reply {
				if i == 2 {
					return del(t, pathGrant+"/"+issued.grant, holder.session)
				}

				return issued.a.refresh(t, issued.tokens.RefreshToken)
			})
			oaNo5xx(t, "a refresh or the revocation", replies)
			replies[2].expect(t, "the revocation", http.StatusOK, "")

			for _, r := range oaWinners(replies[:2]) {
				won := mustTokens(t, r)
				expectInactive(t, "an access token issued around the revocation", won.AccessToken, oauthResource)
				issued.a.refresh(t, won.RefreshToken).expectOAuth(t, "a refresh token issued around the revocation", http.StatusBadRequest, "invalid_grant")
			}
		}
	})

	t.Run("during an exchange", func(t *testing.T) {
		for round := range oaRaceRounds {
			a := approve(t, newOAuthClient(t), holder.session, newAgentChoice("exchanged "+strconv.Itoa(round)))
			grant := idOfToken(t, a.code)

			replies := oaRace(2, func(i int) reply {
				if i == 0 {
					return a.exchange(t)
				}

				return del(t, pathGrant+"/"+grant, holder.session)
			})
			oaNo5xx(t, "an exchange or the revocation", replies)

			if replies[1].status != http.StatusOK && replies[1].status != http.StatusNotFound {
				t.Errorf("the revocation answered %d %s", replies[1].status, replies[1].body)
			}

			if replies[0].status == http.StatusOK {
				expectInactive(t, "the access token of a grant revoked around its exchange", mustTokens(t, replies[0]).AccessToken, oauthResource)
			}

			a.exchange(t).expectOAuth(t, "the code after the revocation", http.StatusBadRequest, "invalid_grant")
		}
	})
}

// TestOAuthRaceIntrospectionDuringARefresh: a refresh replaces the access token
// while it is being introspected. Whichever introspection lands before or after,
// each answer is a clean active or inactive one, and once the refresh has been
// answered the old access token is inactive and the new one active: the two are
// never both live. Introspections are sent both before and after the refresh is
// released so that both orders are exercised, and are read once more after it.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceIntrospectionDuringARefresh(t *testing.T) {
	holder := newOAuthHolder(t)

	for round := range oaRaceRounds {
		issued := oaIssue(t, holder.session, newAgentChoice("introspect "+strconv.Itoa(round)))
		ask := func(token string) reply {
			return postForm(t, pathOAuthIntrospect, url.Values{"token": {token}, "resource": {oauthResource}})
		}

		var refreshed reply

		replies := oaRace(9, func(i int) reply {
			if i == 4 {
				refreshed = issued.a.refresh(t, issued.tokens.RefreshToken)

				return refreshed
			}

			return ask(issued.tokens.AccessToken)
		})
		oaNo5xx(t, "an introspection or the refresh", replies)

		won := mustTokens(t, refreshed)

		for i, r := range replies {
			if i == 4 {
				continue
			}

			if r.status != http.StatusOK {
				t.Errorf("round %d: an introspection answered %d %s", round, r.status, r.body)

				continue
			}

			// Active (before the refresh) or exactly inactive (after): nothing else.
			if body := strings.TrimSpace(r.body); body != `{"active":false}` && !strings.Contains(body, `"active":true`) {
				t.Errorf("round %d: an introspection answered %s", round, body)
			}
		}

		expectInactive(t, "the replaced access token after the refresh", issued.tokens.AccessToken, oauthResource)

		if got, _ := introspect(t, won.AccessToken, oauthResource); !got.Active {
			t.Errorf("round %d: the new access token is not active", round)
		}

		expectCount(t, "oauth_access_tokens WHERE grant_id = ?", "1", issued.grant)
		expectNoOrphanSecrets(t)
	}
}

// TestOAuthRaceClientRevocationDuringUse: the client revokes a token while it is
// refreshed. Revocation is answered 200 whichever way the race goes, never an
// error, and the token that was presented is dead afterwards.
//
// What it does not promise is the design's stated limit (docs/oauth_design.md,
// "no history of old hashes is kept"): revoking a refresh token finds the grant by
// the token's hash, so a revocation that lands after a refresh has rotated that
// token matches nothing, is still answered 200, and leaves the grant the new token
// belongs to live. The test therefore holds the two outcomes apart. Where the
// revocation won, everything is dead and the refresh is refused. Where a refresh
// won first, its tokens are a consistent live pair (the new refresh token rotates
// once more, and its access token is introspected active), and that grant is then
// ended by the revocation of the new token, which is how a client really cleans up.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceClientRevocationDuringUse(t *testing.T) {
	holder := newOAuthHolder(t)

	revoke := func(issued oaIssued, token string) reply {
		return postForm(t, pathOAuthRevoke, url.Values{"token": {token}, "client_id": {issued.a.client.id}})
	}

	t.Run("revoking the refresh token during a refresh", func(t *testing.T) {
		for round := range oaRaceRounds {
			issued := oaIssue(t, holder.session, newAgentChoice("revoked refresh "+strconv.Itoa(round)))

			replies := oaRace(4, func(i int) reply {
				if i == 3 {
					return revoke(issued, issued.tokens.RefreshToken)
				}

				return issued.a.refresh(t, issued.tokens.RefreshToken)
			})
			oaNo5xx(t, "a refresh or the revocation", replies)
			replies[3].expect(t, "the revocation", http.StatusOK, "")

			winners := oaWinners(replies[:3])
			if len(winners) > 1 {
				t.Errorf("round %d: %d refreshes of one token succeeded", round, len(winners))
			}

			// The token that was presented is spent, by the revocation or by the
			// refresh that won, and the access token it was issued with is dead.
			issued.a.refresh(t, issued.tokens.RefreshToken).
				expectOAuth(t, "the refresh token that was presented", http.StatusBadRequest, "invalid_grant")
			expectInactive(t, "the access token that was presented", issued.tokens.AccessToken, oauthResource)

			switch len(winners) {
			case 0:
				// The revocation won: the grant is dead, and a refresh was refused.
				for _, r := range replies[:3] {
					r.expectOAuth(t, "a refresh that lost to the revocation", http.StatusBadRequest, "invalid_grant")
				}
			case 1:
				// A refresh won first: its pair is live and consistent, and the client
				// ends the grant by revoking the token it now holds.
				won := mustTokens(t, winners[0])

				if got, _ := introspect(t, won.AccessToken, oauthResource); got.Active {
					revoke(issued, won.RefreshToken).expect(t, "revoking the new refresh token", http.StatusOK, "")
				}

				issued.a.refresh(t, won.RefreshToken).
					expectOAuth(t, "the new refresh token after it was revoked", http.StatusBadRequest, "invalid_grant")
				expectInactive(t, "the new access token after its refresh token was revoked", won.AccessToken, oauthResource)
			}

			expectNoOrphanSecrets(t)
		}
	})

	t.Run("revoking the access token during a refresh", func(t *testing.T) {
		for round := range oaRaceRounds {
			issued := oaIssue(t, holder.session, newAgentChoice("revoked access "+strconv.Itoa(round)))

			replies := oaRace(4, func(i int) reply {
				if i == 3 {
					return revoke(issued, issued.tokens.AccessToken)
				}

				return issued.a.refresh(t, issued.tokens.RefreshToken)
			})
			oaNo5xx(t, "a refresh or the revocation", replies)
			replies[3].expect(t, "the revocation", http.StatusOK, "")

			// Revoking an access token leaves the grant and its refresh token, so
			// exactly one refresh rotates it whether it ran before or after.
			if winners := oaWinners(replies[:3]); len(winners) != 1 {
				t.Errorf("round %d: %d refreshes succeeded, want exactly one", round, len(winners))
			}

			expectInactive(t, "the access token that was revoked", issued.tokens.AccessToken, oauthResource)
			expectCount(t, "oauth_access_tokens WHERE grant_id = ?", "1", issued.grant)
			expectNoOrphanSecrets(t)
		}
	})
}

// oaIssueScoped is oaIssue for a grant of the scope only, so that a refresh can
// ask for more than the grant holds (mcp:write is a scope of the resource, so the
// request parses, and it is the write that refuses it).
func oaIssueScoped(t *testing.T, session, name, scope string) oaIssued {
	t.Helper()

	client := newOAuthClient(t)
	a := approveWith(t, client, session, newAgentChoice(name), func(q url.Values) { q.Set("scope", scope) })
	grant := idOfToken(t, a.code)

	return oaIssued{a: a, tokens: a.mustExchange(t), grant: grant}
}

// TestOAuthRaceRefreshesAskingForDifferentScopes: one refresh token, of a grant
// that holds mcp:read only, presented by several requests at once, some asking
// for mcp:write as well and some for what the grant holds. Exactly one rotates the
// token. The others are refused as invalid_grant (the token was spent) or
// invalid_scope (they asked for too much and were refused with the token unspent),
// and none is an error. A request that asked for too much never succeeds, and
// when only such requests are made the token is not spent by them.
//
//nolint:paralleltest // shares one database
func TestOAuthRaceRefreshesAskingForDifferentScopes(t *testing.T) {
	holder := newOAuthHolder(t)

	const (
		callers = 6
		wide    = "mcp:read mcp:write"
		narrow  = "mcp:read"
	)

	for round := range oaRaceRounds {
		issued := oaIssueScoped(t, holder.session, "scoped "+strconv.Itoa(round), narrow)

		replies := oaRace(callers, func(i int) reply {
			form := issued.a.refreshForm(issued.tokens.RefreshToken)

			if i%2 == 0 {
				form.Set("scope", wide)
			} else {
				form.Set("scope", narrow)
			}

			return postForm(t, pathOAuthToken, form)
		})
		tally := oaTally(replies)
		t.Logf("round %d: %v", round, tally)

		oaNo5xx(t, "a refresh", replies)

		winners := oaWinners(replies)
		if len(winners) != 1 {
			t.Fatalf("round %d: refreshes answered %v, want exactly one 200", round, tally)
		}

		for i, r := range replies {
			switch {
			case r.status == http.StatusOK:
				if i%2 == 0 {
					t.Errorf("round %d: a refresh asking for more scope than the grant has succeeded", round)
				}
			case r.status != http.StatusBadRequest || (r.oauthError() != "invalid_grant" && r.oauthError() != "invalid_scope"):
				t.Errorf("round %d: a lost refresh answered %d %s, want 400 invalid_grant or invalid_scope", round, r.status, r.body)
			case i%2 == 1 && r.oauthError() != "invalid_grant":
				t.Errorf("round %d: a lost refresh for a scope the grant holds answered %s, want invalid_grant", round, r.body)
			}
		}

		if won := mustTokens(t, winners[0]); won.Scope != narrow {
			t.Errorf("round %d: the winner's scope = %q, want %q", round, won.Scope, narrow)
		}

		expectInactive(t, "the replaced access token", issued.tokens.AccessToken, oauthResource)
		expectCount(t, "oauth_access_tokens WHERE grant_id = ?", "1", issued.grant)
		expectNoOrphanSecrets(t)
	}

	t.Run("only over-wide requests leave the token unspent", func(t *testing.T) {
		issued := oaIssueScoped(t, holder.session, "only wide", narrow)

		replies := oaRace(callers, func(int) reply {
			form := issued.a.refreshForm(issued.tokens.RefreshToken)
			form.Set("scope", wide)

			return postForm(t, pathOAuthToken, form)
		})
		oaNo5xx(t, "an over-wide refresh", replies)

		for _, r := range replies {
			r.expectOAuth(t, "an over-wide refresh", http.StatusBadRequest, "invalid_scope")
		}

		mustTokens(t, issued.a.refresh(t, issued.tokens.RefreshToken))
	})
}
