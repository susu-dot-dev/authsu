//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,gocyclo,maintidx,lll // a test that walks one scenario step by step reads best as one function, and its tables repeat inputs on purpose
package e2e_test

// oauth_flow_test.go drives the OAuth authorization server end to end through the
// real Worker: the TinyGo wasm, the real D1 driver and the real SQLite, and a real
// client metadata document served from this process over http://localhost, which
// the development table (selected because the Worker's API_ORIGIN is localhost)
// lets the Worker fetch.
//
// TestOAuthFullFlow is the PLAN's "done when", and logs each step so the e2e log
// shows the whole flow. The ID token is verified here with the standard library
// against the key set the Worker publishes, never with the Worker's own code.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// oaSlack is how far a time the Worker read may be from this process's clock:
// both run on one machine, so it only covers the request's own duration.
const oaSlack = 10 * time.Second

// oaSteps numbers and logs the steps of a scenario.
type oaSteps struct {
	t *testing.T
	n int
}

func (s *oaSteps) logf(format string, args ...any) {
	s.t.Helper()

	s.n++
	s.t.Logf("STEP %2d: %s", s.n, fmt.Sprintf(format, args...))
}

// oaNear fails the test unless got (Unix seconds) is within oaSlack of want.
func oaNear(t *testing.T, what string, got int64, want time.Time) {
	t.Helper()

	if d := time.Unix(got, 0).Sub(want); d < -oaSlack || d > oaSlack {
		t.Errorf("%s = %s, want about %s", what, time.Unix(got, 0).UTC(), want.UTC())
	}
}

// oaJWKS is the key set the Worker publishes.
type oaJWKS struct {
	Keys []struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// oaPublicKey fetches the key set and returns the one key it holds as a stdlib
// key and its kid, after checking the key set is exactly what a verifier needs.
func oaPublicKey(t *testing.T) (*rsa.PublicKey, string) {
	t.Helper()

	got := get(t, pathJWKS, "")
	if got.status != http.StatusOK {
		t.Fatalf("GET %s = %d %s", pathJWKS, got.status, got.body)
	}

	var set oaJWKS

	err := json.Unmarshal([]byte(got.body), &set)
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("key set %s: %v", got.body, err)
	}

	key := set.Keys[0]

	if key.Kty != "RSA" || key.Use != "sig" || key.Alg != "RS256" || key.E != "AQAB" {
		t.Errorf("key = %+v, want an RS256 signature key with e AQAB", key)
	}

	// Only public members: a private exponent or prime in the key set would be a
	// catastrophe the typed decode above would hide.
	var raw struct {
		Keys []map[string]any `json:"keys"`
	}

	_ = json.Unmarshal([]byte(got.body), &raw)

	for name := range raw.Keys[0] {
		if !slices.Contains([]string{"kty", "use", "alg", "kid", "n", "e"}, name) {
			t.Errorf("the key set has member %q, which only a private key has", name)
		}
	}

	modulus, err := base64.RawURLEncoding.Strict().DecodeString(key.N)
	if err != nil || len(modulus) != signingKeyBits/8 || modulus[0] == 0 {
		t.Fatalf("n = %q is not an unpadded 2048-bit big-endian value: %v", key.N, err)
	}

	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: 65537}

	// The key the Worker publishes is the one it was configured with.
	der, err := base64.RawURLEncoding.DecodeString(signingKeyValue())
	if err != nil {
		t.Fatalf("decode the configured key: %v", err)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("parse the configured key: %v", err)
	}

	if private, ok := parsed.(*rsa.PrivateKey); !ok || !private.PublicKey.Equal(pub) {
		t.Errorf("the published key is not the configured OAUTH_SIGNING_KEY")
	}

	digest := sha256.Sum256(modulus)
	if want := base64.RawURLEncoding.EncodeToString(digest[:8]); key.Kid != want {
		t.Errorf("kid = %q, want %q (the first 8 bytes of SHA-256 of the modulus)", key.Kid, want)
	}

	return pub, key.Kid
}

// oaVerifyJWT verifies an RS256 compact JWT with the standard library, and
// returns its header and claims as objects. It fails the test on any defect: the
// shape, the signature, or a header that is not exactly {alg, kid, typ}.
func oaVerifyJWT(t *testing.T, token string, pub *rsa.PublicKey, kid string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("ID token has %d parts, want 3: %.40s", len(parts), token)
	}

	var raw [3][]byte

	for i, part := range parts {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil {
			t.Fatalf("part %d of the ID token is not unpadded canonical base64url: %v", i, err)
		}

		raw[i] = decoded
	}

	var header map[string]any

	err := json.Unmarshal(raw[0], &header)
	if err != nil || len(header) != 3 || header["alg"] != "RS256" || header["typ"] != "JWT" || header["kid"] != kid {
		t.Fatalf("ID token header %s, want exactly alg RS256, typ JWT, kid %s: %v", raw[0], kid, err)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], raw[2])
	if err != nil {
		t.Fatalf("the ID token's signature does not verify against the published key: %v", err)
	}

	// A tampered payload must not verify under the same signature, which holds
	// the check above to its word.
	tampered := sha256.Sum256([]byte(parts[0] + "." + b64([]byte(`{"sub":"x"}`))))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, tampered[:], raw[2]) == nil {
		t.Fatalf("a different payload verifies under the signature")
	}

	var claims map[string]any

	err = json.Unmarshal(raw[1], &claims)
	if err != nil {
		t.Fatalf("claims %s: %v", raw[1], err)
	}

	return claims
}

// oaInt reads a claim that must be a whole number of seconds.
func oaInt(t *testing.T, claims map[string]any, name string) int64 {
	t.Helper()

	value, ok := claims[name].(float64)
	if !ok || value != float64(int64(value)) || value < 0 || value >= 1<<53 {
		t.Errorf("claim %s = %v, want an integer within 2^53-1", name, claims[name])

		return 0
	}

	return int64(value)
}

// TestOAuthFullFlow is the whole authorization flow of docs/oauth_design.md
// through the real Worker: authorize, the UI's reads and consent, the client's
// token exchange (with the ID token verified against the key set), introspection,
// refresh, and revocation of the grant. It runs once for a consent that creates
// the agent and once for one that picks the user's existing agent.
//
//nolint:paralleltest // shares one database
func TestOAuthFullFlow(t *testing.T) {
	for _, variant := range []struct {
		name     string
		existing bool
	}{
		{name: "consent creates a new agent"},
		{name: "consent picks an existing agent", existing: true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			existing := variant.existing
			steps := &oaSteps{t: t}
			holder := newOAuthHolder(t)
			client := newOAuthClient(t)
			pub, kid := oaPublicKey(t)
			pair := newPKCE()
			query := client.authorizeQuery(pair)

			// 1. The client sends the browser to the authorization endpoint.
			started := time.Now()
			authorized := authorize(t, query)
			pending := pendingOf(t, authorized)
			steps.logf("GET /oauth/authorize -> %d, Location %s/oauth/consent?request=<%d chars>; the Worker fetched %s (%d request)",
				authorized.status, target.origin, len(pending), client.id, client.hits.Load())

			if authorized.body != "" || client.hits.Load() != 1 {
				t.Errorf("authorize body %q, client fetches %d; want an empty body and one fetch", authorized.body, client.hits.Load())
			}

			if authorized.header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("the authorization endpoint answered with CORS headers: %v", authorized.header)
			}

			expectCount(t, tableOAuthGrants, "0")

			// 2. The UI reads what to show. It needs no session.
			view := get(t, pathOAuthRequest+"?request="+url.QueryEscape(pending), "")
			steps.logf("GET /api/oauth/request -> %d %s", view.status, view.body)

			var shown struct {
				ClientName   string   `json:"clientName"`
				ClientID     string   `json:"clientId"`
				ClientHost   string   `json:"clientHost"`
				RedirectHost string   `json:"redirectHost"`
				Resource     string   `json:"resource"`
				ResourceName string   `json:"resourceName"`
				Scopes       []string `json:"scopes"`
				OpenID       bool     `json:"openid"`
				ExpiresAt    int64    `json:"expiresAt"`
			}

			err := json.Unmarshal([]byte(view.body), &shown)
			if view.status != http.StatusOK || err != nil {
				t.Fatalf("request view = %d %s: %v", view.status, view.body, err)
			}

			clientURL, _ := url.Parse(client.id)
			redirectURL, _ := url.Parse(client.redirect)

			if shown.ClientName != oauthClientName || shown.ClientID != client.id || shown.ClientHost != clientURL.Host ||
				shown.RedirectHost != redirectURL.Host || shown.Resource != oauthResource ||
				!slices.Equal(shown.Scopes, []string{"mcp:read", "mcp:write"}) || !shown.OpenID || shown.ResourceName == "" {
				t.Errorf("request view = %+v", shown)
			}

			oaNear(t, "the pending request's expiry", shown.ExpiresAt, started.Add(10*time.Minute))

			// 3. The user approves, with a session, choosing the agent.
			choice := newAgentChoice("E2E flow agent")

			agentID := ""

			if existing {
				agentID = idAgentA
				seedAgent(t, agentID, holder.userID, "Existing agent")

				choice = agentChoiceID(agentID)
			}

			approval := consent(t, holder.session, pending, true, choice)
			redirect := consentRedirect(t, approval)
			steps.logf("POST /api/oauth/consent (%s) -> %d, redirect %s", map[bool]string{false: "new agent", true: "existing agent"}[existing],
				approval.status, redirect)

			// 4. The browser goes back to the client with the code, the state and the issuer.
			params := redirect.Query()
			code := params.Get("code")
			redirect.RawQuery = ""

			if redirect.String() != client.redirect || params.Get("state") != query.Get("state") ||
				params.Get("iss") != target.apiOrigin || len(params) != 3 {
				t.Errorf("redirect = %s %v, want %s with code, state %s and iss %s", redirect, params, client.redirect,
					query.Get("state"), target.apiOrigin)
			}

			expectToken(t, code, tagOAuthCode)
			steps.logf("302 to the client: %s?code=%.14s...&state=%s&iss=%s", client.redirect, code, params.Get("state"), params.Get("iss"))

			grantID := idOfToken(t, code)
			expectCount(t, tableOAuthGrants, "1")
			expectCount(t, tableAgents+" WHERE user_id = ?", "1", holder.userID)
			expectStoredNowhere(t, code)

			if !existing {
				agentID = scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", grantID)
				if got := scalar(t, "SELECT scopes || '|' || name FROM agents WHERE id = ?", agentID); got != "[]|E2E flow agent" {
					t.Errorf("the new agent is %q, want no scopes and the chosen name", got)
				}
			} else if got := scalar(t, "SELECT agent_id FROM oauth_grants WHERE id = ?", grantID); got != agentID {
				t.Errorf("the grant's agent = %s, want the existing %s", got, agentID)
			}

			sessionCreated := mustSecretOf(t, holder.session).createdAt
			if got := scalar(t, "SELECT auth_time FROM oauth_grants WHERE id = ?", grantID); got != strconv.FormatInt(sessionCreated, 10) {
				t.Errorf("auth_time = %s, want the session's created_at %d", got, sessionCreated)
			}

			// 5. The client exchanges the code, with its verifier.
			exchanged := time.Now()
			tokenReply := (approved{client: client, pkce: pair, query: query, code: code}).exchange(t)
			issued := mustTokens(t, tokenReply)

			steps.logf("POST /oauth/token (authorization_code) -> %d, token_type %s, expires_in %d, scope %q, %d byte id_token",
				tokenReply.status, issued.TokenType, issued.ExpiresIn, issued.Scope, len(issued.IDToken))

			expectToken(t, issued.AccessToken, tagOAuthAccess)
			expectToken(t, issued.RefreshToken, tagOAuthRefresh)

			if issued.TokenType != "Bearer" || issued.ExpiresIn != oauthAccessSeconds || issued.Scope != oauthScopes {
				t.Errorf("token response = %+v, want Bearer, %d seconds and scope %q", issued, oauthAccessSeconds, oauthScopes)
			}

			if cache := tokenReply.header.Get("Cache-Control"); !strings.Contains(cache, "no-store") {
				t.Errorf("the token response's Cache-Control = %q, RFC 6749 section 5.1 requires no-store", cache)
			}

			if tokenReply.header.Get("Access-Control-Allow-Origin") != "*" || tokenReply.header.Get("Access-Control-Allow-Credentials") != "" {
				t.Errorf("the token endpoint's CORS headers = %v, want * without credentials", tokenReply.header)
			}

			// The ID token, verified with the standard library against the key set.
			claims := oaVerifyJWT(t, issued.IDToken, pub, kid)
			steps.logf("ID token verified with crypto/rsa against %s (kid %s): %v", pathJWKS, kid, claims)

			wantClaims := map[string]any{"iss": target.apiOrigin, "sub": holder.userID, "aud": client.id, "nonce": query.Get("nonce")}
			for name, want := range wantClaims {
				if claims[name] != want {
					t.Errorf("claim %s = %v, want %v", name, claims[name], want)
				}
			}

			if len(claims) != 7 {
				t.Errorf("the ID token has claims %v, want exactly iss, sub, aud, iat, exp, auth_time and nonce", claims)
			}

			oaNear(t, "iat", oaInt(t, claims, "iat"), exchanged)

			if oaInt(t, claims, "exp")-oaInt(t, claims, "iat") != oauthIDTokenSeconds {
				t.Errorf("exp - iat = %d, want %d", oaInt(t, claims, "exp")-oaInt(t, claims, "iat"), oauthIDTokenSeconds)
			}

			if oaInt(t, claims, "auth_time") != sessionCreated {
				t.Errorf("auth_time = %d, want the session's %d", oaInt(t, claims, "auth_time"), sessionCreated)
			}

			// The same code is spent: a second exchange is refused.
			again := (approved{client: client, pkce: pair, query: query, code: code}).exchange(t)
			again.expectOAuth(t, "a second exchange of the code", http.StatusBadRequest, "invalid_grant")

			// What was stored: hashes only, the refresh token under the grant's id, and the expiries.
			expectStoredNowhere(t, issued.AccessToken, issued.RefreshToken)

			refreshRow := mustSecretOf(t, issued.RefreshToken)
			if refreshRow.id != grantID || refreshRow.kind != kindOAuthGrant || refreshRow.revoked {
				t.Errorf("the refresh token's secret = %+v, want the grant's %s, live", refreshRow, grantID)
			}

			oaNear(t, "the refresh token's expiry", refreshRow.expiresAt, exchanged.Add(oauthRefreshSeconds*time.Second))
			oaNear(t, "the access token's expiry", mustSecretOf(t, issued.AccessToken).expiresAt, exchanged.Add(oauthAccessSeconds*time.Second))
			expectCount(t, "secrets WHERE id = ?", "1", grantID)
			expectNoOrphanSecrets(t)

			// 6. A resource server introspects the access token for its resource.
			live, body := introspect(t, issued.AccessToken, oauthResource)
			steps.logf("POST /oauth/introspect (access token) -> %s", body)

			if !live.Active || live.Scope != oauthScopes || live.ClientID != client.id || live.TokenType != "Bearer" ||
				live.Sub != holder.userID || live.AgentID != agentID || live.Aud != oauthResource || live.Iss != target.apiOrigin {
				t.Errorf("introspection = %+v, want the grant's client, user, agent, resource and scope", live)
			}

			oaNear(t, "introspected exp", live.Exp, exchanged.Add(oauthAccessSeconds*time.Second))
			oaNear(t, "introspected iat", live.Iat, exchanged)

			// 7. The client refreshes: new tokens, and no ID token.
			refreshed := (approved{client: client}).refresh(t, issued.RefreshToken)
			rotated := mustTokens(t, refreshed)
			steps.logf("POST /oauth/token (refresh_token) -> %d, new access token %.14s..., new refresh token %.14s..., id_token %q",
				refreshed.status, rotated.AccessToken, rotated.RefreshToken, rotated.IDToken)

			expectToken(t, rotated.AccessToken, tagOAuthAccess)
			expectToken(t, rotated.RefreshToken, tagOAuthRefresh)

			if rotated.AccessToken == issued.AccessToken || rotated.RefreshToken == issued.RefreshToken || rotated.IDToken != "" ||
				rotated.Scope != oauthScopes || rotated.ExpiresIn != oauthAccessSeconds {
				t.Errorf("refresh response = %+v", rotated)
			}

			expectStoredNowhere(t, rotated.AccessToken, rotated.RefreshToken)
			expectCount(t, "secrets WHERE kind = ?", "1", kindOAuthGrant)
			expectCount(t, "secrets WHERE kind = ?", "1", kindOAuthAccess)

			// 8. The old access token is inactive, the old refresh token is refused, and the new access token is live.
			expectInactive(t, "the replaced access token", issued.AccessToken, oauthResource)
			steps.logf("POST /oauth/introspect (replaced access token) -> {\"active\":false}")

			(approved{client: client}).refresh(t, issued.RefreshToken).
				expectOAuth(t, "the replaced refresh token", http.StatusBadRequest, "invalid_grant")

			if again, _ := introspect(t, rotated.AccessToken, oauthResource); !again.Active || again.AgentID != agentID {
				t.Errorf("the new access token is not active: %+v", again)
			}

			// 9. The user lists their grants and revokes this one.
			list := get(t, pathGrant, holder.session)
			steps.logf("GET /api/grant -> %d %s", list.status, list.body)

			var listed struct {
				Grants []struct {
					ID    string `json:"id"`
					Agent struct {
						ID string `json:"id"`
					} `json:"agent"`
					ClientID  string   `json:"clientId"`
					Resource  string   `json:"resource"`
					Scopes    []string `json:"scopes"`
					OpenID    bool     `json:"openid"`
					RevokedAt *int64   `json:"revokedAt"`
				} `json:"grants"`
			}

			err = json.Unmarshal([]byte(list.body), &listed)
			if list.status != http.StatusOK || err != nil || len(listed.Grants) != 1 || listed.Grants[0].ID != grantID ||
				listed.Grants[0].Agent.ID != agentID || listed.Grants[0].ClientID != client.id ||
				listed.Grants[0].Resource != oauthResource || !listed.Grants[0].OpenID || listed.Grants[0].RevokedAt != nil {
				t.Fatalf("grant list = %d %s: %v", list.status, list.body, err)
			}

			revoked := del(t, pathGrant+"/"+grantID, holder.session)
			steps.logf("DELETE /api/grant/%s -> %d %s", grantID, revoked.status, revoked.body)

			if revoked.status != http.StatusOK || !strings.Contains(revoked.body, `"revokedAt"`) {
				t.Errorf("revoke grant = %d %s, want 200 with revokedAt", revoked.status, revoked.body)
			}

			// 10. Nothing the grant issued works any more.
			expectInactive(t, "the access token of a revoked grant", rotated.AccessToken, oauthResource)
			steps.logf("POST /oauth/introspect (after revoking the grant) -> {\"active\":false}")

			(approved{client: client}).refresh(t, rotated.RefreshToken).
				expectOAuth(t, "the refresh token of a revoked grant", http.StatusBadRequest, "invalid_grant")
			steps.logf("POST /oauth/token (refresh_token, after revoking the grant) -> 400 invalid_grant")

			// Revoking again is idempotent and keeps the first revocation time.
			first := scalar(t, "SELECT revoked_at FROM secrets WHERE id = ?", grantID)
			del(t, pathGrant+"/"+grantID, holder.session).expect(t, "a second DELETE of the grant", http.StatusOK, "")

			if got := scalar(t, "SELECT revoked_at FROM secrets WHERE id = ?", grantID); got != first || first == "" {
				t.Errorf("revoked_at changed from %q to %q on a second revocation", first, got)
			}

			// No response of the flow carried a secret of the server.
			for name, text := range map[string]string{
				"authorize": authorized.location(), "view": view.body, "consent": approval.body, "token": tokenReply.body,
				"refresh": refreshed.body, "list": list.body, "revoke": revoked.body,
			} {
				if leaks := bndLeaks(text); len(leaks) != 0 {
					t.Errorf("the %s response matches leak patterns %v", name, leaks)
				}
			}
		})
	}
}
