//nolint:goconst,lll,dupword // table-driven tests repeat inputs on purpose, and the case table is the test; a constant or a line break per row would hide it
package oauth_test

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file holds the first-party login of docs/oauth_design.md: a trusted
// client (resource.Table.Trusted) asks for the login resource, which only it may
// do, the UI is sent to a page that only signs in, consent names no agent and
// authsu keeps one for the client, and the ID token carries the profile.

const (
	// trustedClient is the production table's trusted client and its one
	// redirect URI, which its document registers.
	trustedClient   = resource.ProductionClientID
	trustedRedirect = "https://app.susu.dev/oidc"
	loginResource   = resource.ProductionLoginURL

	// scopeLogin is what a login request is stored as, and scopeOpenIDLogin with
	// an ID token.
	scopeLogin       = "profile"
	scopeOpenIDLogin = "openid profile"
	scopeMCP         = "openid mcp:read"

	codeInvalidConsent = "invalid_consent"
	codeAgentLimit     = "agent_limit_reached"
	codeNoAgent        = "agent_not_found"
	codeInvalidTarget  = "invalid_target"
)

// loginParams are the parameters of a valid first-party login request, as the
// Pages app sends it.
func loginParams() url.Values {
	return url.Values{
		"client_id": {trustedClient}, "redirect_uri": {trustedRedirect}, "response_type": {"code"},
		"code_challenge": {challengeVal}, "code_challenge_method": {"S256"}, "state": {"xyz"},
		"nonce": {"n-1"}, "resource": {loginResource}, "scope": {"openid email profile offline_access"},
	}
}

// loginRig is a rig whose network serves the trusted client's document.
func loginRig(t *testing.T) *rig {
	t.Helper()

	r := newRig(t)
	r.net.answers[trustedClient] = served(document(trustedClient, trustedRedirect))

	return r
}

// loginCodeForm is the token request that exchanges the code of a login.
func loginCodeForm(code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {trustedRedirect},
		"client_id": {trustedClient}, "code_verifier": {verifierVal},
	}
}

// loginPending sends a login request through the endpoint and returns the sealed
// request the UI is sent to, checking it is the login page and not the consent
// one.
func loginPending(t *testing.T, r *rig, params url.Values) string {
	t.Helper()

	rec := r.authorize(params)

	to, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusFound || to.Path != "/oauth/login" ||
		to.Scheme+"://"+to.Host != r.config().UI.String || to.RawQuery != "request="+to.Query().Get("request") {
		t.Fatalf("authorize = %d %q (%v), want 302 to the UI's login page with one request parameter",
			rec.Code, rec.Header().Get("Location"), err)
	}

	return to.Query().Get("request")
}

// loginBody is a consent body of a first-party login, with members added.
func loginBody(t *testing.T, text string, approve bool, agent map[string]any) string {
	t.Helper()

	members := map[string]any{"request": text, "approve": approve}
	if agent != nil {
		members["agent"] = agent
	}

	return consentJSON(t, members)
}

// loginConsent approves a pending login with no agent, signed in as cookie, and
// returns the code.
func loginConsent(r *rig, userCookie *http.Cookie, text string) string {
	r.t.Helper()

	rec := r.consent(userCookie, loginBody(r.t, text, true, nil))

	return redirectOf(r.t, rec, trustedRedirect).Get("code")
}

// loginTokens runs a whole login for userA, with params, and returns its tokens.
func loginTokens(t *testing.T, r *rig, params url.Values) tokenBody {
	t.Helper()

	cookie, _ := r.signIn(userA)
	code := loginConsent(r, cookie, loginPending(t, r, params))

	r.now = r.now.Add(5 * time.Second)

	return wantTokens(t, r.postForm(oauth.PathToken, loginCodeForm(code)))
}

// TestFirstPartyLoginFlow: a trusted client's login goes to the login page,
// consent names no agent, authsu creates one named after the client, and the
// grant is the login resource's with the scope as the resource defines it.
func TestFirstPartyLoginFlow(t *testing.T) {
	t.Parallel()

	r := loginRig(t)
	cookie, _ := r.signIn(userA)
	text := loginPending(t, r, loginParams())

	// The UI reads the request: the scope is stored without the two names no
	// resource defines.
	view := decodeObject(t, r.get(requestTarget(text)))
	if view["resource"] != loginResource || view["openid"] != true ||
		!slices.Equal(anyStrings(view["scopes"]), []string{scopeLogin}) {
		t.Fatalf("request view = %v", view)
	}

	loginConsent(r, cookie, text)

	if len(r.store.grants) != 1 {
		t.Fatalf("%d grants, want 1", len(r.store.grants))
	}

	wantLoginGrant(t, r.store.grants[0])

	if r.store.agentNames[r.store.rows[0].grant.AgentID] != clientName || r.store.activeAgents[userA] != 2 {
		t.Errorf("agent names %v, active %v", r.store.agentNames, r.store.activeAgents)
	}
}

// wantLoginGrant asserts what consent wrote for a first-party login: no chosen
// agent, the agent kept for the client named after it, and the resource's scope.
func wantLoginGrant(t *testing.T, grant store.NewGrant) {
	t.Helper()

	if !grant.FirstParty || grant.NewAgent != nil || grant.FirstPartyName.String() != clientName ||
		grant.FirstPartyMaxActive != 25 || grant.Scope.String() != scopeOpenIDLogin ||
		grant.Resource.String() != loginResource || grant.Owner != userA {
		t.Errorf("grant = %+v", grant)
	}
}

// TestFirstPartyIDToken: the ID token of a login has the profile claims and
// email_verified false, and nothing more than a login's.
func TestFirstPartyIDToken(t *testing.T) {
	t.Parallel()

	tokens := loginTokens(t, loginRig(t), loginParams())
	claims := verifiedIDToken(t, tokens.idToken)

	want := map[string]any{
		"iss": apiOrigin, "sub": userA, "aud": trustedClient, "nonce": "n-1",
		"name": "Alice A", "email": "alice@example.com", "email_verified": false,
	}
	for name, value := range want {
		if claims[name] != value {
			t.Errorf("claim %s = %v, want %v", name, claims[name], value)
		}
	}

	// iat, exp and auth_time are the other three.
	if len(claims) != len(want)+3 || tokens.scope != scopeOpenIDLogin {
		t.Errorf("claims = %v, scope %q", claims, tokens.scope)
	}
}

// TestFirstPartyRefresh: a refresh keeps the login resource and issues no ID
// token.
func TestFirstPartyRefresh(t *testing.T) {
	t.Parallel()

	r := loginRig(t)
	tokens := loginTokens(t, r, loginParams())

	refreshed := wantTokens(t, r.postForm(oauth.PathToken, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.refresh}, "client_id": {trustedClient},
	}))
	if refreshed.idToken != "" || refreshed.scope != scopeOpenIDLogin {
		t.Errorf("refresh = %+v", refreshed)
	}
}

// TestTokenAudience: a token of one resource is inactive at the other, in both
// directions, and active at its own.
func TestTokenAudience(t *testing.T) {
	t.Parallel()

	r := loginRig(t)
	login := loginTokens(t, r, loginParams())
	mcp := r.exchanged(setParam("scope", scopeMCP))

	tests := map[string]struct {
		token, resource string
		active          bool
	}{
		"login token at the login resource": {token: login.access, resource: loginResource, active: true},
		"login token at the MCP resource":   {token: login.access, resource: resourceURL},
		"MCP token at the MCP resource":     {token: mcp.access, resource: resourceURL, active: true},
		"MCP token at the login resource":   {token: mcp.access, resource: loginResource},
	}

	for name, tt := range tests {
		got := decodeObject(t, r.postForm(oauth.PathIntrospect, introspectForm(tt.token, tt.resource)))
		if got["active"] != tt.active {
			t.Errorf("%s: active = %v, want %v", name, got["active"], tt.active)
		}
	}
}

// TestFirstPartyScopes: what a trusted client may ask the login resource for,
// and what is stored. email is the profile, offline_access asks for what is
// always given, neither is stored, and nothing else is tolerated.
func TestFirstPartyScopes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		scope  string
		absent bool
		// want is the stored scope; empty means the request is refused.
		want string
	}{
		"the whole OpenID Connect request": {scope: "openid email profile offline_access", want: scopeOpenIDLogin},
		"email alone is the profile":       {scope: "email", want: scopeLogin},
		"profile alone":                    {scope: "profile", want: scopeLogin},
		"email and profile are one scope":  {scope: "email profile", want: scopeLogin},
		"profile and email, in that order": {scope: "profile email", want: scopeLogin},
		"openid and email":                 {scope: "openid email", want: scopeOpenIDLogin},
		"offline_access is dropped":        {scope: "profile offline_access", want: scopeLogin},
		"no scope is the default":          {absent: true, want: scopeLogin},
		"offline_access alone is nothing":  {scope: "offline_access"},
		"openid alone is nothing":          {scope: "openid"},
		"openid and offline_access":        {scope: "openid offline_access"},
		"a repeated email":                 {scope: "email email"},
		"a repeated offline_access":        {scope: "offline_access offline_access profile"},
		"an MCP scope":                     {scope: "openid profile mcp:read"},
		"an MCP scope with email":          {scope: "email mcp:write"},
		"an unknown scope":                 {scope: "openid profile admin"},
		"an authsu scope":                  {scope: "profile agent:create"},
		"upper case":                       {scope: "openid PROFILE"},
		"two spaces":                       {scope: "openid  profile"},
		"a trailing space":                 {scope: "profile "},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			params := loginParams()

			if tt.absent {
				params.Del("scope")
			} else {
				params.Set("scope", tt.scope)
			}

			if tt.want == "" {
				wantClientError(t, r, r.authorize(params), trustedRedirect, "invalid_scope", descInvalidScope, "xyz")

				return
			}

			cookie, _ := r.signIn(userA)
			loginConsent(r, cookie, loginPending(t, r, params))

			if got := r.store.grants[0].Scope.String(); got != tt.want {
				t.Errorf("stored scope %q, want %q", got, tt.want)
			}
		})
	}
}

// refusedLogin is a login request that goes wrong before consent, and how.
type refusedLogin struct {
	edit func(url.Values)
	// documents are served beside the trusted client's, by client_id.
	documents map[string]string
	// redirect is where a refusal goes, "" for the UI's error page, and
	// wantCode what it carries.
	redirect, wantCode, wantDesc string
}

// refusedLogins are the ways a client is refused the login resource.
func refusedLogins() map[string]refusedLogin {
	const otherOnTheHost = "https://app.susu.dev/oauth/other.json"

	ordinary := func(v url.Values) {
		v.Set("client_id", clientURL)
		v.Set("redirect_uri", redirectURL)
	}

	return map[string]refusedLogin{
		"an ordinary client": {
			edit: ordinary, redirect: redirectURL, wantCode: codeInvalidTarget, wantDesc: descInvalidTarget,
		},
		"an ordinary client asking for the profile alone": {
			edit:     func(v url.Values) { ordinary(v); v.Set("scope", "profile") },
			redirect: redirectURL, wantCode: codeInvalidTarget, wantDesc: descInvalidTarget,
		},
		"another client on the app's host": {
			edit:      func(v url.Values) { v.Set("client_id", otherOnTheHost) },
			documents: map[string]string{otherOnTheHost: document(otherOnTheHost, trustedRedirect)},
			redirect:  trustedRedirect, wantCode: codeInvalidTarget, wantDesc: descInvalidTarget,
		},
		"a redirect URI the document does not list": {
			edit:     func(v url.Values) { v.Set("redirect_uri", "https://app.susu.dev/other") },
			wantCode: "invalid_redirect_uri",
		},
		"the trusted client's own document served with another redirect": {
			documents: map[string]string{trustedClient: document(trustedClient, "https://app.susu.dev/else")},
			wantCode:  "invalid_redirect_uri",
		},
	}
}

// TestLoginResourceIsForTrustedClients: the login resource is refused as an
// unknown resource to a client that is not trusted, in every way a client could
// try for it, and a trusted client is held to the redirect URI its own document
// lists as every client is.
func TestLoginResourceIsForTrustedClients(t *testing.T) {
	t.Parallel()

	for name, tt := range refusedLogins() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)

			for id, body := range tt.documents {
				r.net.answers[id] = served(body)
			}

			params := loginParams()
			if tt.edit != nil {
				tt.edit(params)
			}

			rec := r.authorize(params)

			if tt.redirect == "" {
				wantUIError(t, r, rec, tt.wantCode)

				return
			}

			wantClientError(t, r, rec, tt.redirect, tt.wantCode, tt.wantDesc, "xyz")
		})
	}
}

// TestTrustedClientIsNotGivenMCPThroughLogin: a trusted client that names the MCP
// resource goes the ordinary way, to the consent page, and must choose an agent
// there; and it cannot reach an MCP scope through the login resource.
func TestTrustedClientIsNotGivenMCPThroughLogin(t *testing.T) {
	t.Parallel()

	r := loginRig(t)
	cookie, _ := r.signIn(userA)

	params := loginParams()
	params.Set("resource", resourceURL)
	params.Set("scope", scopeMCP)

	text := wantConsentRedirect(t, r, r.authorize(params))

	// With no agent, the approval is refused: the MCP resource needs an agent.
	wantAPIError(t, r.consent(cookie, loginBody(t, text, true, nil)), http.StatusBadRequest, codeInvalidConsent)

	if len(r.store.grants) != 0 {
		t.Error("an MCP grant was written without an agent")
	}

	// Choosing one works, as for any client, and no first-party agent is made.
	redirectOf(t, r.consent(cookie, approval(t, text, "Pages as an agent")), trustedRedirect)

	if grant := r.store.grants[0]; grant.FirstParty || grant.NewAgent == nil || grant.Scope.String() != scopeMCP {
		t.Errorf("grant = %+v, want an ordinary one with a new agent", grant)
	}
}

// consentAnswer is a body sent for a first-party login, and what comes of it.
type consentAnswer struct {
	approve bool
	agent   map[string]any
	// wantCode is the 400 it is refused with, "" when it is accepted.
	wantCode string
}

// TestFirstPartyConsentAnswers: a first-party login names no agent, and every way
// of naming one is refused before anything is written; a refusal is as for any
// request.
func TestFirstPartyConsentAnswers(t *testing.T) {
	t.Parallel()

	tests := map[string]consentAnswer{
		"an approval with no agent":            {approve: true},
		"an approval naming a new agent":       {approve: true, agent: map[string]any{"new": "x"}, wantCode: codeInvalidConsent},
		"an approval naming an existing agent": {approve: true, agent: map[string]any{"id": agentA1}, wantCode: codeInvalidConsent},
		"an approval naming an empty agent":    {approve: true, agent: map[string]any{}, wantCode: codeInvalidConsent},
		"a refusal":                            {approve: false},
		"a refusal naming an agent":            {approve: false, agent: map[string]any{"new": "x"}, wantCode: codeInvalidConsent},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			cookie, _ := r.signIn(userA)
			rec := r.consent(cookie, loginBody(t, loginPending(t, r, loginParams()), tt.approve, tt.agent))

			switch {
			case tt.wantCode != "":
				wantAPIError(t, rec, http.StatusBadRequest, tt.wantCode)

				if len(r.store.grants) != 0 || r.handedIDs() != 0 {
					t.Errorf("a refused answer wrote %d grants and issued %d ids", len(r.store.grants), r.handedIDs())
				}
			case !tt.approve:
				if params := redirectOf(t, rec, trustedRedirect); params.Get("error") != "access_denied" || len(r.store.grants) != 0 {
					t.Errorf("params = %v, grants %d", params, len(r.store.grants))
				}
			default:
				redirectOf(t, rec, trustedRedirect)

				if len(r.store.grants) != 1 {
					t.Errorf("%d grants, want 1", len(r.store.grants))
				}
			}
		})
	}
}

// agentKept is a user's state before some logins, and what the last one does.
type agentKept struct {
	prepare func(r *rig)
	logins  int
	// wantCode is the refusal of the last login, "" when it succeeds, and
	// wantStatus its status.
	wantCode   string
	wantStatus int
	wantAgents int

	// replaces is the revoked agent the last login must not be held by, "" for none.
	replaces string
}

// TestFirstPartyAgentIsKeptPerClient: signing in again attaches to the agent the
// first login created and makes no second; a user at the agent limit who has
// none is refused as for any consent that creates an agent, and one who has it
// signs in; a revoked one is not revived and not a lockout: the next login is
// held by a fresh agent, which is held to the limit as any new agent is.
func TestFirstPartyAgentIsKeptPerClient(t *testing.T) {
	t.Parallel()

	keep := func(r *rig, active int) {
		r.store.firstPartyAgents[userA+"|"+trustedClient] = agentA1
		r.store.activeAgents[userA] = active
	}

	tests := map[string]agentKept{
		"two logins keep one agent":   {logins: 2, wantAgents: 2},
		"three logins keep one agent": {logins: 3, wantAgents: 2},
		"at the limit with none": {
			prepare: func(r *rig) { r.store.activeAgents[userA] = 25 }, logins: 1,
			wantCode: codeAgentLimit, wantStatus: http.StatusConflict, wantAgents: 25,
		},
		"at the limit with the agent": {prepare: func(r *rig) { keep(r, 25) }, logins: 1, wantAgents: 25},
		"a revoked agent is replaced by a fresh one": {
			prepare: func(r *rig) { keep(r, 1); r.store.revokedAgents[agentA1] = true }, logins: 1,
			wantAgents: 1, replaces: agentA1,
		},
		"a revoked agent is replaced, and then kept": {
			prepare: func(r *rig) { keep(r, 1); r.store.revokedAgents[agentA1] = true }, logins: 3,
			wantAgents: 1, replaces: agentA1,
		},
		"a revoked agent frees its place at the limit": {
			prepare: func(r *rig) { keep(r, 25); r.store.revokedAgents[agentA1] = true }, logins: 1,
			wantAgents: 25, replaces: agentA1,
		},
		"a revoked agent and the user at the limit": {
			prepare: func(r *rig) { keep(r, 26); r.store.revokedAgents[agentA1] = true }, logins: 1,
			wantCode: codeAgentLimit, wantStatus: http.StatusConflict, wantAgents: 26, replaces: agentA1,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			if tt.prepare != nil {
				tt.prepare(r)
			}

			agents := keptAgents(t, r, tt)

			if len(slices.Compact(slices.Clone(agents))) > 1 {
				t.Errorf("agents of the logins = %v, want one", agents)
			}

			if got := r.store.activeAgents[userA]; got != tt.wantAgents {
				t.Errorf("active agents = %d, want %d", got, tt.wantAgents)
			}

			if tt.replaces != "" && slices.Contains(agents, tt.replaces) {
				t.Errorf("agents of the logins = %v, want none to be the revoked %s", agents, tt.replaces)
			}
		})
	}
}

// keptAgents runs the logins of tt and returns the agent that held each grant.
// The last is held to its refusal, if it has one.
func keptAgents(t *testing.T, r *rig, tt agentKept) []string {
	t.Helper()

	cookie, _ := r.signIn(userA)

	var agents []string

	for range tt.logins {
		rec := r.consent(cookie, loginBody(t, loginPending(t, r, loginParams()), true, nil))

		if tt.wantCode != "" {
			wantAPIError(t, rec, tt.wantStatus, tt.wantCode)

			return agents
		}

		redirectOf(t, rec, trustedRedirect)

		agents = append(agents, r.store.rows[len(r.store.rows)-1].grant.AgentID)
	}

	return agents
}

// TestForgedPendingLogin: a sealed request that names the login resource for a
// client that is not trusted is refused when it is read back, though it is signed
// with this deployment's key: the rule is applied to what is read and not only to
// what authorize sealed. The same payload with the trusted client is accepted, so
// the refusal is the client's.
func TestForgedPendingLogin(t *testing.T) {
	t.Parallel()

	mcp := func(scope string) func(map[string]any) {
		return func(f map[string]any) { f["resource"], f["scope"] = resourceURL, scope }
	}
	set := func(member, value string) func(map[string]any) {
		return func(f map[string]any) { f[member] = value }
	}

	tests := map[string]struct {
		edit   func(fields map[string]any)
		wantOK bool
	}{
		"the trusted client":                          {edit: func(map[string]any) {}, wantOK: true},
		"an ordinary client":                          {edit: set("clientId", clientURL)},
		"a client on the app's host":                  {edit: set("clientId", "https://app.susu.dev/other.json")},
		"the trusted client with the MCP resource":    {edit: mcp("mcp:read"), wantOK: true},
		"the login resource with an MCP scope":        {edit: set("scope", "mcp:read")},
		"the login resource with the email name":      {edit: set("scope", "email profile"), wantOK: true},
		"the MCP resource with the email name":        {edit: mcp("email")},
		"the MCP resource with offline_access":        {edit: mcp("offline_access mcp:read")},
		"the login resource with only offline_access": {edit: set("scope", "offline_access")},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			fields := pendingFields(t, r, loginPending(t, r, loginParams()))

			tt.edit(fields)

			rec := r.get(requestTarget(sealed(t, r, nil, oauth.PendingLifetime, encodeFields(t, fields))))

			if tt.wantOK {
				if rec.Code != http.StatusOK {
					t.Errorf("= %d %s, want 200", rec.Code, rec.Body)
				}

				return
			}

			wantInvalidPending(t, r, rec.Code, rec.Body.String())
		})
	}
}

// profileCase is a stored profile and the claims an ID token has of it.
type profileCase struct {
	profile string
	want    map[string]any
	absent  []string
}

// profileCases are the stored profiles an ID token is made from.
func profileCases() map[string]profileCase {
	verified := map[string]any{"email_verified": false}

	with := func(members map[string]any) map[string]any {
		out := map[string]any{"email_verified": false}
		maps.Copy(out, members)

		return out
	}

	return map[string]profileCase{
		"name and email": {
			profile: `{"name":"Alice A","email":"alice@example.com"}`,
			want:    with(map[string]any{"name": "Alice A", "email": "alice@example.com"}),
		},
		"a profile with only a name": {
			profile: `{"name":"Alice A"}`, want: with(map[string]any{"name": "Alice A"}), absent: []string{"email"},
		},
		"an empty profile":                {profile: `{}`, want: verified, absent: []string{"name", "email"}},
		"a profile that is not an object": {profile: `[1]`, want: verified, absent: []string{"name", "email"}},
		"a profile with members of the wrong type": {
			profile: `{"name":5,"email":true}`, want: verified, absent: []string{"name", "email"},
		},
		"a wrong name does not cost the email": {
			profile: `{"name":5,"email":"a@b.c"}`, want: with(map[string]any{"email": "a@b.c"}), absent: []string{"name"},
		},
		"null members are no claims": {
			profile: `{"name":null,"email":null}`, want: verified, absent: []string{"name", "email"},
		},
		"a null name does not cost the email": {
			profile: `{"name":null,"email":"a@b.c"}`, want: with(map[string]any{"email": "a@b.c"}), absent: []string{"name"},
		},
		"members that are structures are no claims": {
			profile: `{"name":{},"email":[]}`, want: verified, absent: []string{"name", "email"},
		},
		"escaped and multibyte text is kept": {
			profile: `{"name":"A\u003c\"ボット 🤖","email":"a@b.c"}`,
			want:    with(map[string]any{"name": "A<\"ボット 🤖", "email": "a@b.c"}),
		},
		"a profile at the column bound": {
			profile: `{"name":"` + strings.Repeat("n", 1000) + `"}`,
			want:    with(map[string]any{"name": strings.Repeat("n", 1000)}), absent: []string{"email"},
		},
		"unknown members are not claims": {
			profile: `{"name":"A","email":"a@b.c","role":"admin"}`,
			want:    with(map[string]any{"name": "A", "email": "a@b.c"}), absent: []string{"role"},
		},
	}
}

// TestProfileClaims: the profile claims are read from the stored profile, and a
// profile that is not usable is no profile and not a failure.
func TestProfileClaims(t *testing.T) {
	t.Parallel()

	for name, tt := range profileCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			r.store.profiles[userA] = tt.profile

			params := loginParams()
			params.Set("scope", scopeOpenIDLogin)

			claims := verifiedIDToken(t, loginTokens(t, r, params).idToken)

			for member, value := range tt.want {
				if claims[member] != value {
					t.Errorf("claim %s = %v, want %v", member, claims[member], value)
				}
			}

			for _, member := range tt.absent {
				if _, found := claims[member]; found {
					t.Errorf("claim %s is present in %v", member, claims)
				}
			}
		})
	}
}

// TestNoProfileClaimsForOtherResources: the MCP resource's ID token has none of
// the profile claims, and a login that did not ask for openid has no ID token.
func TestNoProfileClaimsForOtherResources(t *testing.T) {
	t.Parallel()

	claims := verifiedIDToken(t, newRig(t).exchanged(setParam("scope", scopeMCP)).idToken)

	for _, member := range []string{"name", "email", "email_verified"} {
		if _, found := claims[member]; found {
			t.Errorf("claim %s is present in %v", member, claims)
		}
	}

	params := loginParams()
	params.Set("scope", scopeLogin)

	if tokens := loginTokens(t, loginRig(t), params); tokens.idToken != "" {
		t.Errorf("an ID token %q without openid", tokens.idToken)
	}
}

// TestLoginResourceIsExact: a request for the login resource names its URL
// exactly: the lookalikes of it are refused as any unknown resource.
func TestLoginResourceIsExact(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		loginResource + "/", loginResource + "/oidc", "https://APP.susu.dev", "https://app.susu.dev:443",
		"http://app.susu.dev", resource.DevelopmentLoginURL, "https://app.susu.dev.evil.com",
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			r := loginRig(t)
			params := loginParams()
			params.Set("resource", target)

			wantClientError(t, r, r.authorize(params), trustedRedirect, codeInvalidTarget, descInvalidTarget, "xyz")
		})
	}
}
