//go:build e2e

//nolint:funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_supersede_test.go: the real statements that end a user's older grants
// when a newer grant of the same client and resource is exchanged
// (store.supersedeGrantQuery and supersedeAccessQuery), run in the real database.
// The order is the order of consent (the grant's id, a UUIDv7), not of exchange.

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"
)

// supersedeNull is what revokedAtOf reports for a secret that is not revoked.
const supersedeNull = "NULL"

// consentFor approves a request of the client for the session, and returns it
// ready to be exchanged. Consents made one after another get increasing ids.
func consentFor(t *testing.T, client *oauthClient, session string, agent map[string]string) approved {
	t.Helper()

	return approve(t, client, session, agent)
}

// revokedAtOf is the revoked_at of a secret, or supersedeNull.
func revokedAtOf(t *testing.T, id string) string {
	t.Helper()

	return scalar(t, "SELECT ifnull(revoked_at, '"+supersedeNull+"') FROM secrets WHERE id = ?", id)
}

// accessSecretOf is the id of the access token's secret of a grant, or "".
func accessSecretOf(t *testing.T, grant string) string {
	t.Helper()

	if count(t, tableOAuthAccess+" WHERE grant_id = ?", grant) == "0" {
		return ""
	}

	return scalar(t, "SELECT id FROM "+tableOAuthAccess+" WHERE grant_id = ?", grant)
}

// TestOAuthSupersedeOrder: two grants of one user, client and resource, in every
// order of exchange. The newer consent is the one that stays, whichever code is
// exchanged first or last, and an older code exchanged late never ends the newer.
//
//nolint:paralleltest // shares one database
func TestOAuthSupersedeOrder(t *testing.T) {
	tests := []struct {
		name string
		// exchange lists the grants (0 oldest) in the order their codes are exchanged.
		exchange []int
		// refused are the grants whose exchange is refused as invalid_grant,
		// because a newer one already ended them.
		refused []int
		// live are the grants whose tokens work at the end.
		live []int
	}{
		{name: "oldest then newest", exchange: []int{0, 1, 2}, live: []int{2}},
		{name: "newest then oldest", exchange: []int{2, 0, 1}, refused: []int{0, 1}, live: []int{2}},
		{name: "newest, middle, oldest", exchange: []int{2, 1, 0}, refused: []int{0, 1}, live: []int{2}},
		{name: "middle, oldest, newest", exchange: []int{1, 0, 2}, refused: []int{0}, live: []int{2}},
		{name: "the middle ends the oldest only", exchange: []int{1, 0}, refused: []int{0}, live: []int{1}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			holder := newOAuthHolder(t)
			client := newOAuthClient(t)

			grants := make([]approved, 3)
			ids := make([]string, 3)

			for i := range grants {
				grants[i] = consentFor(t, client, holder.session, newAgentChoice("agent "+strconv.Itoa(i)))
				ids[i] = idOfToken(t, grants[i].code)

				// A UUIDv7's order is its creation order, which the rule rests on.
				if i > 0 && ids[i] <= ids[i-1] {
					t.Fatalf("grant ids %s then %s are not in consent order", ids[i-1], ids[i])
				}
			}

			issued := map[int]tokens{}

			for _, i := range test.exchange {
				got := grants[i].exchange(t)

				if slices.Contains(test.refused, i) {
					got.expectOAuth(t, "the exchange of a superseded grant", http.StatusBadRequest, "invalid_grant")

					continue
				}

				issued[i] = mustTokens(t, got)
			}

			for i, tok := range issued {
				expectLiveOrEnded(t, grants[i], tok, slices.Contains(test.live, i))
			}

			for i := range grants {
				ended := !slices.Contains(test.live, i) && slices.Contains(test.exchange, i)
				if ended && revokedAtOf(t, ids[i]) == supersedeNull {
					t.Errorf("grant %d is not revoked in the database", i)
				}
			}

			expectNoOrphanSecrets(t)
		})
	}
}

// expectLiveOrEnded holds that the grant's access token is active and its refresh
// token works, or that neither does and the refresh token is refused.
func expectLiveOrEnded(t *testing.T, a approved, tok tokens, live bool) {
	t.Helper()

	if got, _ := introspect(t, tok.AccessToken, oauthResource); got.Active != live {
		t.Errorf("access token active = %v, want %v", got.Active, live)
	}

	refreshed := a.refresh(t, tok.RefreshToken)
	if live {
		mustTokens(t, refreshed)

		return
	}

	refreshed.expectOAuth(t, "the refresh token of a superseded grant", http.StatusBadRequest, "invalid_grant")
}

// TestOAuthSupersedeScopedToUserClientAndResource: only a grant of the same user,
// the same client and the same resource is ended. A grant of another client, of
// another user, and of another resource is not touched, nor is the agent.
//
//nolint:paralleltest // shares one database
func TestOAuthSupersedeScopedToUserClientAndResource(t *testing.T) {
	holder := newOAuthHolder(t)
	_, otherSession := secondUser(t)
	client := newOAuthClient(t)
	otherClient := newOAuthClient(t)

	seedAgent(t, idAgentA, holder.userID, "shared")

	// The grants, older first: three that must stay, and one that must go.
	anotherClient := consentFor(t, otherClient, holder.session, agentChoiceID(idAgentA))
	anotherUser := consentFor(t, client, otherSession, newAgentChoice("theirs"))
	target := consentFor(t, client, holder.session, agentChoiceID(idAgentA))
	newest := consentFor(t, client, holder.session, agentChoiceID(idAgentA))

	keep := map[string]tokens{
		"another client's": anotherClient.mustExchange(t),
		"another user's":   anotherUser.mustExchange(t),
	}
	older := target.mustExchange(t)

	// The first-party login resource is not one a third party may name, so a grant
	// of another resource is stood in for by the stored resource of an older grant.
	elsewhere := consentFor(t, client, holder.session, agentChoiceID(idAgentA))
	elsewhereID := idOfToken(t, elsewhere.code)
	seed(t, "UPDATE oauth_grants SET resource = ?, scope = ? WHERE id = ?", "http://localhost:9894", "profile", elsewhereID)

	// It is the older of the exchange only if it is consented before: its id sorts
	// below the newest one's, and its resource differs.
	newest.mustExchange(t)

	if got, _ := introspect(t, older.AccessToken, oauthResource); got.Active {
		t.Error("the older grant of the same user, client and resource is still active")
	}

	for name, tok := range keep {
		if got, _ := introspect(t, tok.AccessToken, oauthResource); !got.Active {
			t.Errorf("%s grant was ended", name)
		}
	}

	if got := revokedAtOf(t, elsewhereID); got != supersedeNull {
		t.Errorf("a grant of another resource has revoked_at %s, want NULL", got)
	}

	if got := scalar(t, "SELECT revoked_at IS NULL FROM agents WHERE id = ?", idAgentA); got != "1" {
		t.Errorf("the shared agent was revoked")
	}
}

// TestOAuthSupersedeFailedExchangeEndsNothing: an exchange the write refuses ends
// no other grant: a wrong verifier, a wrong redirect URI, a code past its life, a
// code that was revoked, one that was spent, and one whose agent is revoked.
//
//nolint:paralleltest // shares one database
func TestOAuthSupersedeFailedExchangeEndsNothing(t *testing.T) {
	tests := []struct {
		name string
		// spoil changes the newer grant's request so that its exchange is refused,
		// and returns the form to send.
		spoil func(t *testing.T, holder oauthHolder, newer approved) url.Values
	}{
		{name: "a wrong verifier", spoil: func(_ *testing.T, _ oauthHolder, newer approved) url.Values {
			form := newer.codeForm()
			form.Set("code_verifier", newPKCE().verifier)

			return form
		}},
		{name: "a wrong redirect URI", spoil: func(_ *testing.T, _ oauthHolder, newer approved) url.Values {
			form := newer.codeForm()
			form.Set(paramRedirectURI, newer.client.redirect+"/other")

			return form
		}},
		{name: "another client", spoil: func(t *testing.T, _ oauthHolder, newer approved) url.Values {
			t.Helper()

			form := newer.codeForm()
			form.Set(paramClientID, newOAuthClient(t).id)

			return form
		}},
		{name: "a revoked code", spoil: func(t *testing.T, holder oauthHolder, newer approved) url.Values {
			t.Helper()

			del(t, pathGrant+"/"+idOfToken(t, newer.code), holder.session).expect(t, "revoke", http.StatusOK, "")

			return newer.codeForm()
		}},
		{name: "a code past its life", spoil: func(t *testing.T, _ oauthHolder, newer approved) url.Values {
			t.Helper()

			seed(t, "UPDATE secrets SET created_at = created_at - ? WHERE id = ?", oauthCodeSeconds+60, idOfToken(t, newer.code))

			return newer.codeForm()
		}},
		{name: "a revoked agent", spoil: func(t *testing.T, _ oauthHolder, newer approved) url.Values {
			t.Helper()

			seed(t, "UPDATE agents SET revoked_at = strftime('%s','now') WHERE id = (SELECT agent_id FROM oauth_grants WHERE id = ?)",
				idOfToken(t, newer.code))

			return newer.codeForm()
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			holder := newOAuthHolder(t)
			client := newOAuthClient(t)

			older := consentFor(t, client, holder.session, newAgentChoice("older"))
			olderTokens := older.mustExchange(t)
			olderID := idOfToken(t, olderTokens.RefreshToken)

			newer := consentFor(t, client, holder.session, newAgentChoice("newer"))
			form := test.spoil(t, holder, newer)

			postForm(t, pathOAuthToken, form).expectOAuth(t, "the refused exchange", http.StatusBadRequest, "invalid_grant")

			if got := revokedAtOf(t, olderID); got != supersedeNull {
				t.Errorf("the older grant has revoked_at %s after a refused exchange, want NULL", got)
			}

			if got := revokedAtOf(t, accessSecretOf(t, olderID)); got != supersedeNull {
				t.Errorf("the older grant's access token has revoked_at %s after a refused exchange, want NULL", got)
			}

			if got, _ := introspect(t, olderTokens.AccessToken, oauthResource); !got.Active {
				t.Error("the older grant's access token stopped after a refused exchange")
			}

			mustTokens(t, older.refresh(t, olderTokens.RefreshToken))
		})
	}

	t.Run("a spent code", func(t *testing.T) {
		holder := newOAuthHolder(t)
		client := newOAuthClient(t)

		second := consentFor(t, client, holder.session, newAgentChoice("second"))
		second.mustExchange(t)

		third := consentFor(t, client, holder.session, newAgentChoice("third"))
		thirdTokens := third.mustExchange(t)

		// Replaying the second's code is refused and ends nothing: the third stays.
		second.exchange(t).expectOAuth(t, "a replayed code", http.StatusBadRequest, "invalid_grant")

		if got, _ := introspect(t, thirdTokens.AccessToken, oauthResource); !got.Active {
			t.Error("a replayed older code ended the newest grant")
		}
	})
}

// TestOAuthSupersedeEndsBothSecretsAndKeepsEarlierTimes: the older grant's secret
// and its access token's secret are both revoked at the exchange; an older grant
// that was already revoked keeps its time, and so does the access token that was
// revoked alone; one that was never exchanged is ended too; and an expired grant
// is revoked like any other.
//
//nolint:paralleltest // shares one database
func TestOAuthSupersedeEndsBothSecretsAndKeepsEarlierTimes(t *testing.T) {
	holder := newOAuthHolder(t)
	client := newOAuthClient(t)

	revokedAlready := consentFor(t, client, holder.session, newAgentChoice("revoked"))
	revokedTokens := revokedAlready.mustExchange(t)
	revokedID := idOfToken(t, revokedTokens.RefreshToken)

	accessRevoked := consentFor(t, client, holder.session, newAgentChoice("access revoked"))
	accessRevokedTokens := accessRevoked.mustExchange(t)
	accessRevokedID := idOfToken(t, accessRevokedTokens.RefreshToken)

	live := consentFor(t, client, holder.session, newAgentChoice("live"))
	liveTokens := live.mustExchange(t)
	liveID := idOfToken(t, liveTokens.RefreshToken)

	unexchanged := consentFor(t, client, holder.session, newAgentChoice("unexchanged"))
	unexchangedID := idOfToken(t, unexchanged.code)

	// Earlier revocations, behind the Worker's back so their times are known and
	// early: the grant's own, and another's access token alone. (Exchanging the
	// later grants already ended some of these; the times are set after, then the
	// last is exchanged.)
	newest := consentFor(t, client, holder.session, newAgentChoice("newest"))
	newestID := idOfToken(t, newest.code)

	const early = 1_000_000_000

	seed(t, "UPDATE secrets SET revoked_at = ? WHERE id = ?", early, revokedID)
	seed(t, "UPDATE secrets SET revoked_at = ? WHERE id = ?", early, accessSecretOf(t, revokedID))
	seed(t, "UPDATE secrets SET revoked_at = NULL WHERE id IN (?, ?)", accessRevokedID, accessSecretOf(t, accessRevokedID))
	seed(t, "UPDATE secrets SET revoked_at = ? WHERE id = ?", early+1, accessSecretOf(t, accessRevokedID))

	_ = revokedTokens
	_ = accessRevokedTokens
	_ = liveTokens

	newest.mustExchange(t)

	for _, check := range []struct {
		what, id, want string
	}{
		{"an already revoked grant keeps its time", revokedID, strconv.Itoa(early)},
		{"its access token keeps its time", accessSecretOf(t, revokedID), strconv.Itoa(early)},
		{"an access token revoked alone keeps its time", accessSecretOf(t, accessRevokedID), strconv.Itoa(early + 1)},
	} {
		if got := revokedAtOf(t, check.id); got != check.want {
			t.Errorf("%s: revoked_at = %s, want %s", check.what, got, check.want)
		}
	}

	now := time.Now().Unix()

	for _, check := range []struct {
		what, id string
	}{
		{"a live grant", liveID}, {"its access token", accessSecretOf(t, liveID)},
		{"a grant whose access token was revoked alone", accessRevokedID},
		{"a grant that was never exchanged", unexchangedID},
	} {
		got := revokedAtOf(t, check.id)
		if got == supersedeNull {
			t.Errorf("%s was not revoked", check.what)

			continue
		}

		if at := parseInt(t, got); at < now-120 || at > now+5 {
			t.Errorf("%s: revoked_at = %d, want about now (%d)", check.what, at, now)
		}
	}

	if got := revokedAtOf(t, newestID); got != supersedeNull {
		t.Errorf("the newest grant has revoked_at %s, want NULL", got)
	}

	if got := revokedAtOf(t, accessSecretOf(t, newestID)); got != supersedeNull {
		t.Errorf("the newest grant's access token has revoked_at %s, want NULL", got)
	}

	unexchanged.exchange(t).expectOAuth(t, "an unexchanged code of a superseded grant", http.StatusBadRequest, "invalid_grant")
	expectNoOrphanSecrets(t)
}

// TestOAuthSupersedeFirstPartyLogins: signing in again at the first-party client
// ends the earlier login's grant and its access token, the new access token is a
// credential of authsu's own API and the old one is refused, and the login's agent,
// which both grants share, stays active.
//
//nolint:paralleltest // shares one database
func TestOAuthSupersedeFirstPartyLogins(t *testing.T) {
	holder := newOAuthHolder(t)
	client := firstPartyClient(t)

	signIn := func() (approved, tokens) {
		pair := newPKCE()
		query := loginQuery(client, pair)
		query.Set("scope", "profile agent:read")

		pending := loginPage(t, authorize(t, query))
		code := consentRedirect(t, consent(t, holder.session, pending, true, nil)).Query().Get("code")
		a := approved{client: client, pkce: pair, query: query, code: code}

		return a, a.mustExchange(t)
	}

	first, firstTokens := signIn()
	firstID := idOfToken(t, firstTokens.RefreshToken)

	// Before the second sign-in the first grant works at authsu's own API.
	send(t, request{method: http.MethodGet, path: pathAgent, bearer: firstTokens.AccessToken}).
		expect(t, "the first login's access token", http.StatusOK, "")

	second, secondTokens := signIn()
	secondID := idOfToken(t, secondTokens.RefreshToken)

	send(t, request{method: http.MethodGet, path: pathAgent, bearer: secondTokens.AccessToken}).
		expect(t, "the new login's access token", http.StatusOK, "")
	send(t, request{method: http.MethodGet, path: pathAgent, bearer: firstTokens.AccessToken}).
		expect(t, "the earlier login's access token", http.StatusUnauthorized, codeUnauthenticated)

	expectInactive(t, "the earlier login's access token", firstTokens.AccessToken, loginResource)
	first.refresh(t, firstTokens.RefreshToken).expectOAuth(t, "the earlier login's refresh token", http.StatusBadRequest, "invalid_grant")

	if got := revokedAtOf(t, firstID); got == supersedeNull {
		t.Error("the earlier login's grant is not revoked")
	}

	if got := revokedAtOf(t, secondID); got != supersedeNull {
		t.Errorf("the new login's grant has revoked_at %s", got)
	}

	agent := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", secondID)
	if agent != scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", firstID) {
		t.Fatal("the two logins are held by different agents")
	}

	if got := scalar(t, "SELECT revoked_at IS NULL FROM agents WHERE id = ?", agent); got != "1" {
		t.Error("the login's agent was revoked with the superseded grant")
	}

	mustTokens(t, second.refresh(t, secondTokens.RefreshToken))
	expectNoOrphanSecrets(t)
}

// TestOAuthSupersedeRace: two newer grants' codes are exchanged at once, with an
// older grant of the same user and client. Whichever finishes first, the newest
// consent is the only live grant afterwards, the older two are ended, and no
// request is an error.
//
//nolint:paralleltest // shares one database
func TestOAuthSupersedeRace(t *testing.T) {
	holder := newOAuthHolder(t)

	for round := range oaRaceRounds {
		client := newOAuthClient(t)

		oldest := consentFor(t, client, holder.session, newAgentChoice("oldest "+strconv.Itoa(round)))
		middle := consentFor(t, client, holder.session, newAgentChoice("middle "+strconv.Itoa(round)))
		newest := consentFor(t, client, holder.session, newAgentChoice("newest "+strconv.Itoa(round)))
		newestID := idOfToken(t, newest.code)

		all := []approved{oldest, middle, newest}
		allIDs := []string{idOfToken(t, oldest.code), idOfToken(t, middle.code), newestID}
		replies := oaRace(len(all), func(i int) reply { return all[i].exchange(t) })

		oaNo5xx(t, "an exchange", replies)

		// The newest consent was never ended, whichever order they ran in, so its
		// exchange succeeded.
		if replies[2].status != http.StatusOK {
			t.Fatalf("round %d: the newest grant's exchange = %d %s, want 200", round, replies[2].status, replies[2].body)
		}

		tok := mustTokens(t, replies[2])

		if got, _ := introspect(t, tok.AccessToken, oauthResource); !got.Active {
			t.Errorf("round %d: the newest grant is not live", round)
		}

		if got := revokedAtOf(t, newestID); got != supersedeNull {
			t.Errorf("round %d: the newest grant has revoked_at %s", round, got)
		}

		for i := range all[:2] {
			if got := revokedAtOf(t, allIDs[i]); got == supersedeNull {
				t.Errorf("round %d: the older grant %d was not ended", round, i)
			}

			if replies[i].status == http.StatusOK {
				got, _ := introspect(t, mustTokens(t, replies[i]).AccessToken, oauthResource)
				if got.Active {
					t.Errorf("round %d: the older grant %d's access token is live after the newest was exchanged", round, i)
				}
			}
		}

		expectNoOrphanSecrets(t)
	}
}
