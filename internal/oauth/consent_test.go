//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// consentJSON is a consent body with the given members.
func consentJSON(t *testing.T, members map[string]any) string {
	t.Helper()

	body, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}

	return string(body)
}

// approval is the body of an approval that creates an agent named name.
func approval(t *testing.T, text, name string) string {
	t.Helper()

	return consentJSON(t, map[string]any{"request": text, "approve": true, "agent": map[string]any{"new": name}})
}

// consent sends the consent body, signed in as cookie.
func (r *rig) consent(cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{
		method: http.MethodPost, target: oauth.PathConsent, body: body, cookies: []*http.Cookie{cookie},
	})
}

// handedIDs is how many ids the routes asked for.
func (r *rig) handedIDs() int { return r.handed }

// redirectOf decodes a consent answer: a 200 with only a redirect member. It
// returns the added parameters of the redirect to base.
func redirectOf(t *testing.T, rec *httptest.ResponseRecorder, base string) url.Values {
	t.Helper()

	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != jsonType ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("= %d %s %q, want 200 JSON", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}

	var body map[string]string

	err := json.Unmarshal(rec.Body.Bytes(), &body)
	if err != nil || len(body) != 1 {
		t.Fatalf("the body %q is not exactly {redirect}: %v", rec.Body, err)
	}

	return addedParams(t, body["redirect"], base)
}

// hashBytes is the SHA-256 of b.
func hashBytes(b []byte) []byte { return auth.LoginGrant(b) }

// mustDecode decodes a sealed request's text.
func mustDecode(t *testing.T, text string) []byte {
	t.Helper()

	out, err := b64decode(text)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// approved is a case of an approval that succeeds.
type approved struct {
	// edit changes the authorization request, and registered is the redirect URI
	// the client's document lists, if not the usual ones.
	edit       func(url.Values)
	registered string
	agent      map[string]any

	wantAgent func(*testing.T, store.NewGrant)
	wantNonce string
	wantState string
	wantScope string
	wantRedir string
}

// wantNewAgent checks a grant that creates the agent named name.
func wantNewAgent(name string) func(*testing.T, store.NewGrant) {
	return func(t *testing.T, g store.NewGrant) {
		t.Helper()

		if g.AgentID != newAgentID || g.NewAgent == nil || g.NewAgent.Name.String() != name ||
			g.NewAgent.MaxActive != 25 {
			t.Errorf("agent = %q %+v, want a new agent named %q, at most 25", g.AgentID, g.NewAgent, name)
		}
	}
}

// approvals are the approvals that succeed.
func approvals() map[string]approved {
	const defaults = "mcp:read mcp:write"

	reserved := `a b&c=d?e#f%g+h"i\j<k>l`
	every := "\u00dcn\u00ef \"c\u00f6d\u00e9\" <b> & \u65e5\u672c\u8a9e"

	return map[string]approved{
		"a new agent": {
			agent: map[string]any{"new": "Claude Code"}, wantState: "xyz", wantScope: defaults, wantRedir: redirectURL,
			wantAgent: wantNewAgent("Claude Code"),
		},
		"an existing agent": {
			agent: map[string]any{"id": agentA1}, wantState: "xyz", wantScope: defaults, wantRedir: redirectURL,
			wantAgent: func(t *testing.T, g store.NewGrant) {
				t.Helper()

				if g.AgentID != agentA1 || g.NewAgent != nil {
					t.Errorf("agent = %q %+v, want the existing %s and none created", g.AgentID, g.NewAgent, agentA1)
				}
			},
		},
		"every parameter: a nonce, openid and one resource scope": {
			edit:  func(v url.Values) { v.Set("nonce", "n1"); v.Set("scope", "openid mcp:write") },
			agent: map[string]any{"new": "A"}, wantNonce: "n1", wantState: "xyz", wantScope: "openid mcp:write",
			wantRedir: redirectURL, wantAgent: wantNewAgent("A"),
		},
		"no state": {
			edit: func(v url.Values) { v.Del("state") }, agent: map[string]any{"new": "A"},
			wantScope: defaults, wantRedir: redirectURL, wantAgent: wantNewAgent("A"),
		},
		"a state with every reserved character": {
			edit: setParam("state", reserved), agent: map[string]any{"new": "A"}, wantState: reserved,
			wantScope: defaults, wantRedir: redirectURL, wantAgent: wantNewAgent("A"),
		},
		"a loopback redirect, on the port that was asked for": {
			edit: setParam("redirect_uri", "http://127.0.0.1:5555/cb"), agent: map[string]any{"new": "A"},
			wantState: "xyz", wantScope: defaults, wantRedir: "http://127.0.0.1:5555/cb", wantAgent: wantNewAgent("A"),
		},
		"a redirect URI that has a query": {
			edit: setParam("redirect_uri", redirectURL+"?tenant=a"), registered: redirectURL + "?tenant=a",
			agent: map[string]any{"new": "A"}, wantState: "xyz", wantScope: defaults,
			wantRedir: redirectURL + "?tenant=a", wantAgent: wantNewAgent("A"),
		},
		"an agent name with every kind of character": {
			agent: map[string]any{"new": every}, wantState: "xyz", wantScope: defaults, wantRedir: redirectURL,
			wantAgent: wantNewAgent(every),
		},
	}
}

// TestConsentApproves: an approval issues the code and writes the grant with
// what the user approved, from the pending request and never the body, who
// approved, from the session, and the guards: the hash of the sealed request, the
// code's hash and expiry. The answer is the client's redirect URI with the code,
// the state and the issuer.
func TestConsentApproves(t *testing.T) {
	t.Parallel()

	for name, tt := range approvals() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			if tt.registered != "" {
				r.net.answers[clientURL] = served(document(clientURL, tt.registered))
			}

			text := r.pending(tt.edit)
			cookie, sessionID := r.signIn(userA)

			rec := r.consent(cookie, consentJSON(t, map[string]any{"request": text, "approve": true, "agent": tt.agent}))
			params := redirectOf(t, rec, tt.wantRedir)
			code := params.Get("code")

			wantParams := url.Values{"code": {code}, "iss": {apiOrigin}}
			if tt.wantState != "" {
				wantParams.Set("state", tt.wantState)
			}

			if !reflect.DeepEqual(params, wantParams) {
				t.Errorf("added parameters = %v, want %v", params, wantParams)
			}

			if len(r.store.grants) != 1 || len(r.store.calls) != 1 || len(r.logged) != 0 {
				t.Fatalf("grants = %d, calls = %d, logged = %v, want one grant and no failure",
					len(r.store.grants), len(r.store.calls), r.loggedCodes())
			}

			hash := secret.Hash(code)

			wantGrant(t, r.store.grants[0], grantWant{
				owner: userA, session: sessionID, scope: tt.wantScope, nonce: tt.wantNonce, redirect: tt.wantRedir,
				guard: hashBytes(mustDecode(t, text)), codeHash: hash[:], now: r.now,
			})
			tt.wantAgent(t, r.store.grants[0])

			_, err := input.ParseAuthorizationCode(code)
			if err != nil {
				t.Errorf("code = %q, want an authorization code: %v", code, err)
			}
		})
	}
}

// grantWant is what a grant written by consent holds, apart from its agent.
type grantWant struct {
	owner, session, scope, nonce, redirect string
	guard, codeHash                        []byte
	now                                    time.Time
}

// wantGrant asserts every field of a grant that consent wrote.
func wantGrant(t *testing.T, g store.NewGrant, want grantWant) {
	t.Helper()

	nonce := ""
	if g.Nonce != nil {
		nonce = g.Nonce.String()
	}

	got := map[string]any{
		"id": g.ID, "owner": g.Owner, "clientId": g.ClientID.String(), "clientName": g.ClientName,
		"redirect": g.RedirectURI.String(), "resource": g.Resource.String(), "scope": g.Scope.String(),
		"challenge": g.CodeChallenge.String(), "nonce": nonce, "session": g.SessionID,
		"guard": string(g.GrantedFrom), "codeHash": string(g.CodeHash),
		"retainUntil": g.RetainUntil, "createdAt": g.CreatedAt,
	}

	expected := map[string]any{
		"id": grantID, "owner": want.owner, "clientId": clientURL, "clientName": clientName,
		"redirect": want.redirect, "resource": resourceURL, "scope": want.scope,
		"challenge": challengeVal, "nonce": want.nonce, "session": want.session,
		"guard": string(want.guard), "codeHash": string(want.codeHash),
		"retainUntil": want.now.Add(oauth.PendingLifetime), "createdAt": want.now,
	}

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("grant = %v\nwant    %v", got, expected)
	}

	if len(g.GrantedFrom) != 32 || len(g.CodeHash) != 32 {
		t.Errorf("hashes are %d and %d bytes, want 32 each", len(g.GrantedFrom), len(g.CodeHash))
	}
}

// TestConsentKeepsTheReplayGuardAsLongAsTheRequestLives: the grant row's hash of the
// sealed request is the guard against a replay, and the row may be removed once its
// secret has expired. The code is only good for a minute, so the secret must not
// expire with it: it is kept for PendingLifetime from consent, which is no earlier
// than the sealed request's own expiry however late in its life the approval is
// given, and the exchange write is told the code's real life separately.
func TestConsentKeepsTheReplayGuardAsLongAsTheRequestLives(t *testing.T) {
	t.Parallel()

	tests := map[string]time.Duration{
		"approved at once":                    0,
		"approved a minute later":             time.Minute,
		"approved a second before it expires": oauth.PendingLifetime - time.Second,
	}

	for name, delay := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			text := r.pending(nil)
			sealedAt := r.now
			cookie, _ := r.signIn(userA)

			r.now = r.now.Add(delay)
			r.consent(cookie, approval(t, text, "A"))

			if len(r.store.grants) != 1 {
				t.Fatalf("grants = %d, want 1", len(r.store.grants))
			}

			grant := r.store.grants[0]
			requestEnds := sealedAt.Add(oauth.PendingLifetime)

			if grant.RetainUntil.Before(requestEnds) || !grant.RetainUntil.Equal(r.now.Add(oauth.PendingLifetime)) {
				t.Errorf("RetainUntil = %v, want consent + %v, and no earlier than the request's expiry %v",
					grant.RetainUntil, oauth.PendingLifetime, requestEnds)
			}

			if !grant.RetainUntil.After(r.now.Add(auth.CodeLifetime)) {
				t.Errorf("RetainUntil = %v does not outlive the code's life", grant.RetainUntil)
			}
		})
	}
}

// TestConsentRefuses: a refusal writes nothing, issues nothing, and sends the
// client back with access_denied, its state and the issuer.
func TestConsentRefuses(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edit     func(url.Values)
		redirect string
		state    string
	}{
		"with a state":    {edit: nil, redirect: redirectURL, state: "xyz"},
		"without a state": {edit: func(v url.Values) { v.Del("state") }, redirect: redirectURL, state: ""},
		"on a loopback": {
			edit: setParam("redirect_uri", "http://127.0.0.1:5555/cb"), redirect: "http://127.0.0.1:5555/cb", state: "xyz",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			text := r.pending(tt.edit)
			cookie, _ := r.signIn(userA)

			rec := r.consent(cookie, consentJSON(t, map[string]any{"request": text, "approve": false}))

			want := url.Values{
				"error": {"access_denied"}, "error_description": {"the user denied the request"}, "iss": {apiOrigin},
			}

			if tt.state != "" {
				want.Set("state", tt.state)
			}

			if got := redirectOf(t, rec, tt.redirect); !reflect.DeepEqual(got, want) {
				t.Errorf("added parameters = %v, want %v", got, want)
			}

			if len(r.store.calls) != 0 || r.handedIDs() != 0 || len(r.logged) != 0 {
				t.Errorf("a refusal wrote or issued: store calls %v, ids %d, logged %v",
					r.store.calls, r.handedIDs(), r.loggedCodes())
			}
		})
	}
}

// consentBodies builds the bodies of TestConsentBody around one pending request.
func consentBodies(t *testing.T, text string) func(map[string]any) string {
	t.Helper()

	return func(members map[string]any) string {
		all := map[string]any{"request": text}
		maps.Copy(all, members)

		return consentJSON(t, all)
	}
}

// bodyCase is a consent body that must be refused, and with which code.
type bodyCase struct {
	body     string
	wantCode string
}

// shapeCases are the bodies that are not an answer: not JSON of the right shape,
// or an answer that does not say what it does.
func shapeCases(t *testing.T, text string) map[string]bodyCase {
	t.Helper()

	bodies := consentBodies(t, text)
	refusal := func(members map[string]any) string {
		return bodies(map[string]any{"approve": false, "agent": members})
	}
	approving := func(members map[string]any) string {
		return bodies(map[string]any{"approve": true, "agent": members})
	}
	invalid := func(body string) bodyCase { return bodyCase{body: body, wantCode: "invalid_consent"} }

	return map[string]bodyCase{
		"empty body":    {body: ``, wantCode: "empty_body"},
		"not JSON":      {body: `approve`, wantCode: "invalid_json"},
		"an array":      {body: `[]`, wantCode: "invalid_field_type"},
		"null":          invalid(`null`),
		"trailing data": {body: bodies(map[string]any{"approve": false}) + ` {}`, wantCode: "trailing_data"},
		"an unknown member": {
			body: bodies(map[string]any{"approve": false, "extra": 1}), wantCode: "unknown_field",
		},
		"a member in another case": {
			body:     strings.Replace(bodies(map[string]any{"approve": false}), `"approve"`, `"Approve"`, 1),
			wantCode: "unknown_field",
		},
		"a repeated member": {
			body:     strings.Replace(bodies(map[string]any{"approve": false}), `{`, `{"approve":true,`, 1),
			wantCode: "duplicate_field",
		},
		"approve missing":  invalid(bodies(nil)),
		"approve null":     invalid(bodies(map[string]any{"approve": nil})),
		"approve a string": {body: bodies(map[string]any{"approve": "true"}), wantCode: "invalid_field_type"},
		"approve a number": {body: bodies(map[string]any{"approve": 1}), wantCode: "invalid_field_type"},
		"request a number": {
			body: bodies(map[string]any{"request": 5, "approve": false}), wantCode: "invalid_field_type",
		},

		"a refusal that names a new agent":    invalid(refusal(map[string]any{"new": "A"})),
		"a refusal that names an agent by id": invalid(refusal(map[string]any{"id": agentA1})),
		"a refusal that names an empty agent": invalid(refusal(map[string]any{})),
		"an approval with no agent":           invalid(bodies(map[string]any{"approve": true})),
		"an approval with a null agent":       invalid(bodies(map[string]any{"approve": true, "agent": nil})),
		"an approval with an empty agent":     invalid(approving(map[string]any{})),
		"an approval with null members":       invalid(approving(map[string]any{"new": nil, "id": nil})),
		"an approval that names both":         invalid(approving(map[string]any{"new": "A", "id": agentA1})),
		"an agent with an unknown member": {
			body: approving(map[string]any{"new": "A", "scopes": []string{"x"}}), wantCode: "unknown_field",
		},
		"an agent that is a string": {
			body: bodies(map[string]any{"approve": true, "agent": "A"}), wantCode: "invalid_field_type",
		},
	}
}

// memberCases are the bodies whose agent's name or id is not one.
func memberCases(t *testing.T, text string) map[string]bodyCase {
	t.Helper()

	agent := func(members map[string]any) string {
		return consentBodies(t, text)(map[string]any{"approve": true, "agent": members})
	}
	name := func(value any, code string) bodyCase {
		return bodyCase{body: agent(map[string]any{"new": value}), wantCode: code}
	}
	id := func(value string) bodyCase {
		return bodyCase{body: agent(map[string]any{"id": value}), wantCode: "invalid_id"}
	}

	return map[string]bodyCase{
		"a new agent that is a number":        name(5, "invalid_field_type"),
		"a new agent with an empty name":      name("", "invalid_agent_name"),
		"a new agent named by control":        name("a\u0001b", "invalid_agent_name"),
		"a new agent with a bidi override":    name("a\u202eb", "invalid_agent_name"),
		"a new agent named by spaces":         name("   ", "invalid_agent_name"),
		"a new agent name over the bound":     name(strings.Repeat("a", 257), "invalid_agent_name"),
		"an existing agent that is not an id": id("mine"),
		"an existing agent id in upper case":  id(strings.ToUpper(agentA1)),
		"an existing agent that is empty":     id(""),
	}
}

// TestConsentBody: the body is an answer or it is refused before the pending
// request is read, and nothing is written. An approval chooses exactly one agent
// and a refusal none; every member is held to its type and its parser.
func TestConsentBody(t *testing.T) {
	t.Parallel()

	text := newRig(t).pending(nil)
	tests := shapeCases(t, text)

	maps.Copy(tests, memberCases(t, text))

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			cookie, _ := r.signIn(userA)
			rec := r.consent(cookie, tt.body)

			var got struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}

			err := json.Unmarshal(rec.Body.Bytes(), &got)
			if err != nil || rec.Code != http.StatusBadRequest || got.Error.Code != tt.wantCode {
				t.Errorf("= %d %s, want 400 %s", rec.Code, rec.Body, tt.wantCode)
			}

			if !slices.Equal(r.loggedCodes(), []string{tt.wantCode}) {
				t.Errorf("logged %v, want [%s]", r.loggedCodes(), tt.wantCode)
			}

			if len(r.store.calls) != 0 || r.handedIDs() != 0 {
				t.Errorf("a refused body reached the store (%v) or issued ids (%d)", r.store.calls, r.handedIDs())
			}
		})
	}
}

// forbiddenBody is what a valid credential that is not a session is told.
const forbiddenBody = `{"error":{"code":"forbidden","message":"a signed-in session is required"}}` + "\n"

// credentialCase is a request to consent with a credential, and its answer.
type credentialCase struct {
	send       func(*rig) request
	wantStatus int
	wantBody   string
}

// credentialCases are the credentials that may not approve.
func credentialCases(body string) map[string]credentialCase {
	unauthorized := func(send func(*rig) request) credentialCase {
		return credentialCase{send: send, wantStatus: http.StatusUnauthorized, wantBody: bodyUnauth}
	}
	forbidden := func(send func(*rig) request) credentialCase {
		return credentialCase{send: send, wantStatus: http.StatusForbidden, wantBody: forbiddenBody}
	}

	return map[string]credentialCase{
		"no credential": unauthorized(func(*rig) request { return request{body: body} }),
		"a garbage cookie": unauthorized(func(*rig) request {
			//nolint:gosec // a request cookie carries no attributes
			return request{body: body, cookies: []*http.Cookie{{Name: auth.CookieName, Value: "x"}}}
		}),
		"a session that is not active": unauthorized(func(r *rig) request {
			cookie, _ := r.signIn(userA)

			// Another well-formed session token, which no active session has.
			middle := len(cookie.Value) / 2
			other := string(rune('A' + (cookie.Value[middle]-'A'+1)%26))
			cookie.Value = cookie.Value[:middle] + other + cookie.Value[middle+1:]

			return request{body: body, cookies: []*http.Cookie{cookie}}
		}),
		"a session and a key together": unauthorized(func(r *rig) request {
			cookie, _ := r.signIn(userA)

			return request{body: body, cookies: []*http.Cookie{cookie}, authorization: r.signInKey(userA, "")}
		}),
		"an OAuth access token as a bearer": unauthorized(func(*rig) request {
			return request{body: body, authorization: "Bearer susu_at_" + strings.Repeat("A", 43)}
		}),

		// A key is a valid credential, so the caller is known and may not do this.
		"a user's API key": forbidden(func(r *rig) request {
			return request{body: body, authorization: r.signInKey(userA, "")}
		}),
		"an agent's API key": forbidden(func(r *rig) request {
			return request{body: body, authorization: r.signInKey(userA, agentA1)}
		}),
	}
}

// TestConsentCredentials: consent is a person's: only a session answers it. An
// API key of a user or of an agent is a valid credential and is 403, and no
// credential, a bad one, and both together are 401, all by the boundary before
// the body is read, whatever the body is, and nothing is written.
func TestConsentCredentials(t *testing.T) {
	t.Parallel()

	r0 := newRig(t)

	for name, tt := range credentialCases(approval(t, r0.pending(nil), "A")) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			req := tt.send(r)
			req.method, req.target = http.MethodPost, oauth.PathConsent

			rec := r.serve(req)

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("= %d %q, want %d %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if len(r.store.calls) != 0 || r.handedIDs() != 0 {
				t.Errorf("a refused credential reached the store (%v) or issued ids (%d)", r.store.calls, r.handedIDs())
			}
		})
	}
}

// TestConsentMediaType: consent takes JSON only: a form, text or no type at all
// is 415 before any credential is read, which is what keeps a cross-site form
// from approving anything.
func TestConsentMediaType(t *testing.T) {
	t.Parallel()

	for name, contentType := range map[string]string{
		"a form": "application/x-www-form-urlencoded", "text": "text/plain", "multipart": "multipart/form-data",
		"none": "-",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			cookie, _ := r.signIn(userA)
			text := r.pending(nil)

			rec := r.serve(request{
				method: http.MethodPost, target: oauth.PathConsent, body: approval(t, text, "A"),
				contentType: contentType, cookies: []*http.Cookie{cookie},
			})

			if rec.Code != http.StatusUnsupportedMediaType || len(r.store.calls) != 0 {
				t.Errorf("= %d %s, store calls %v, want 415", rec.Code, rec.Body, r.store.calls)
			}
		})
	}
}

// TestConsentPendingRequestMustBeOurs: the request is opened before anything is
// written, and one that is forged, expired, of another purpose or unparseable is
// the same 400 as on the read, and writes nothing, for a refusal as for an
// approval.
func TestConsentPendingRequestMustBeOurs(t *testing.T) {
	t.Parallel()

	r0 := newRig(t)
	cfg := r0.config()
	text := r0.pending(nil)
	payload := encodeFields(t, pendingFields(t, r0, text))

	loginChallenge, _, err := challenge.Create(cfg.LoginKey, &sequence{reads: 1}, r0.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*rig) string{
		"a forged request": func(*rig) string {
			forged := mustDecode(t, text)
			forged[20] ^= 1

			return b64(forged)
		},
		"an expired request": func(r *rig) string {
			r.now = r.now.Add(oauth.PendingLifetime)

			return text
		},
		"a login challenge as the request": func(*rig) string { return b64(loginChallenge) },
		"a sealed request of another key": func(r *rig) string {
			return sealed(t, r, cfg.LoginKey, time.Minute, payload)
		},
		"a signed payload that does not parse": func(r *rig) string {
			return sealed(t, r, nil, time.Minute, []byte(`{"clientId":"http://x"}`))
		},
		"no request at all":          func(*rig) string { return "" },
		"a request over the longest": func(*rig) string { return strings.Repeat("A", 6000) },
	}

	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			cookie, _ := r.signIn(userA)

			rec := r.consent(cookie, approval(t, build(r), "A"))

			wantInvalidPending(t, r, rec.Code, rec.Body.String())

			if r.handedIDs() != 0 {
				t.Errorf("a request that cannot be opened issued %d ids", r.handedIDs())
			}

			r.logged = nil

			rec = r.consent(cookie, consentJSON(t, map[string]any{"request": build(r), "approve": false}))

			wantInvalidPending(t, r, rec.Code, rec.Body.String())
		})
	}
}

// refusedCase is an approval that the write refuses, and what the client is told.
type refusedCase struct {
	setup      func(*rig, string)
	agent      map[string]any
	wantStatus int
	wantBody   string
	wantLogged string
}

// refusals are the writes that are refused.
func refusals() map[string]refusedCase {
	unavailable := apierr.New(apierr.Unavailable, store.CodeGrantCreateFailed, "grants are temporarily unavailable").
		WithCause(errDB)
	noAgent := refusedCase{
		wantStatus: http.StatusNotFound, wantBody: errorBody("agent_not_found", "no such agent"),
		wantLogged: "agent_not_found",
	}
	signedOut := refusedCase{
		agent: map[string]any{"new": "A"}, wantStatus: http.StatusUnauthorized, wantBody: bodyUnauth,
		wantLogged: "unauthenticated",
	}
	failing := func(failure error, status int, body, logged string) refusedCase {
		return refusedCase{
			setup: func(r *rig, _ string) { r.store.failure = failure }, agent: map[string]any{"new": "A"},
			wantStatus: status, wantBody: body, wantLogged: logged,
		}
	}

	another, revoked, missing := noAgent, noAgent, noAgent
	another.agent = map[string]any{"id": agentB1}
	revoked.agent = map[string]any{"id": agentA1}
	revoked.setup = func(r *rig, _ string) { delete(r.store.agents, agentA1) }
	missing.agent = map[string]any{"id": nobody}

	accountRevoked, sessionEnded := signedOut, signedOut
	accountRevoked.setup = func(r *rig, _ string) { r.store.inactiveUsers[userA] = true }
	sessionEnded.setup = func(r *rig, session string) { r.store.endedSessions[session] = true }

	return map[string]refusedCase{
		"the user is at the agent limit": {
			setup: func(r *rig, _ string) { r.store.activeAgents[userA] = 25 },
			agent: map[string]any{"new": "A"}, wantStatus: http.StatusConflict,
			wantBody:   errorBody("agent_limit_reached", "the account has the most active agents it may have"),
			wantLogged: "agent_limit_reached",
		},
		"another user's agent":             another,
		"an agent that is revoked":         revoked,
		"an agent that does not exist":     missing,
		"the account was revoked":          accountRevoked,
		"the session ended":                sessionEnded,
		"a conflict the write cannot name": failing(store.ErrConflict, 500, bodyInternal, "oauth_consent_failed"),
		"the database is down": failing(unavailable, http.StatusServiceUnavailable,
			errorBody(store.CodeGrantCreateFailed, "grants are temporarily unavailable"), store.CodeGrantCreateFailed),
		"a failure that was never classified": failing(errDB, 500, bodyInternal, "internal"),
	}
}

// TestConsentStoreRefusals: each of the write's refusals is its own answer, and
// nothing a client could tell apart reveals more than the write knew: another
// user's agent, a revoked one and one that does not exist are the same 404.
func TestConsentStoreRefusals(t *testing.T) {
	t.Parallel()

	for name, tt := range refusals() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			text := r.pending(nil)
			cookie, session := r.signIn(userA)

			if tt.setup != nil {
				tt.setup(r, session)
			}

			rec := r.consent(cookie, consentJSON(t, map[string]any{"request": text, "approve": true, "agent": tt.agent}))

			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("= %d %q, want %d %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if !slices.Equal(r.loggedCodes(), []string{tt.wantLogged}) {
				t.Errorf("logged %v, want [%s]", r.loggedCodes(), tt.wantLogged)
			}

			if len(r.store.grants) != 0 || len(r.store.calls) != 1 {
				t.Errorf("grants = %d, calls = %d, want the one refused call", len(r.store.grants), len(r.store.calls))
			}

			if strings.Contains(rec.Body.String(), "INSERT") || strings.Contains(rec.Body.String(), "on fire") {
				t.Errorf("the body leaks the cause: %s", rec.Body)
			}
		})
	}
}

// TestConsentIsSingleUse: the same approval submitted twice creates one grant and
// one agent, and the second is a 409 that says so.
func TestConsentIsSingleUse(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	body := approval(t, r.pending(nil), "A")
	cookie, _ := r.signIn(userA)

	redirectOf(t, r.consent(cookie, body), redirectURL)

	second := r.consent(cookie, body)

	if second.Code != http.StatusConflict ||
		second.Body.String() != errorBody("consent_replayed", "this request was already approved") {
		t.Errorf("replay = %d %s, want 409 consent_replayed", second.Code, second.Body)
	}

	if len(r.store.grants) != 1 || r.store.activeAgents[userA] != 2 {
		t.Errorf("grants = %d, agents of the user = %d, want one grant and one new agent",
			len(r.store.grants), r.store.activeAgents[userA])
	}

	if !slices.Equal(r.loggedCodes(), []string{"consent_replayed"}) {
		t.Errorf("logged %v", r.loggedCodes())
	}

	// Another session of the same user replays it just the same.
	other, _ := r.signIn(userA)

	if again := r.consent(other, body); again.Code != http.StatusConflict || len(r.store.grants) != 1 {
		t.Errorf("a replay from another session = %d %s, grants %d", again.Code, again.Body, len(r.store.grants))
	}
}

// TestConsentOfTwoRequests: two requests that differ only in the random value
// they carry are two approvals, each with its own guard, grant and agent.
func TestConsentOfTwoRequests(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	first, second := r.pending(nil), r.pending(nil)
	cookie, _ := r.signIn(userA)

	redirectOf(t, r.consent(cookie, approval(t, first, "A")), redirectURL)
	redirectOf(t, r.consent(cookie, approval(t, second, "B")), redirectURL)

	if len(r.store.grants) != 2 {
		t.Fatalf("grants = %d, want 2", len(r.store.grants))
	}

	one, two := r.store.grants[0], r.store.grants[1]

	if !bytes.Equal(one.GrantedFrom, hashBytes(mustDecode(t, first))) || bytes.Equal(one.GrantedFrom, two.GrantedFrom) {
		t.Errorf("the guards of the two grants are %x and %x", one.GrantedFrom, two.GrantedFrom)
	}

	if one.ID == two.ID || one.AgentID == two.AgentID || bytes.Equal(one.CodeHash, two.CodeHash) {
		t.Error("two grants share an id, an agent or a code")
	}
}

// TestConsentWhoApproves: the grant is the session's user's, and the session
// that presented is the one recorded, whoever's request it was: the pending
// request names no user, so another signed-in person can approve a link they
// were sent and the grant is theirs, with their own agents only.
func TestConsentWhoApproves(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookieB, sessionB := r.signIn(userB)

	rec := r.consent(cookieB, consentJSON(t, map[string]any{
		"request": r.pending(nil), "approve": true, "agent": map[string]any{"id": agentB1},
	}))

	redirectOf(t, rec, redirectURL)

	if grant := r.store.grants[0]; grant.Owner != userB || grant.SessionID != sessionB || grant.AgentID != agentB1 {
		t.Errorf("grant = owner %s session %s agent %s, want user B's", grant.Owner, grant.SessionID, grant.AgentID)
	}

	// And their agents are the only kind they can attach: user A's is not found.
	r.logged = nil

	rec = r.consent(cookieB, consentJSON(t, map[string]any{
		"request": r.pending(nil), "approve": true, "agent": map[string]any{"id": agentA1},
	}))

	if rec.Code != http.StatusNotFound || len(r.store.grants) != 1 {
		t.Errorf("= %d %s, grants %d, want 404 and no second grant", rec.Code, rec.Body, len(r.store.grants))
	}
}

// TestConsentIssueFailure: an authorization code that cannot be issued (the
// entropy source failed) is a server fault before anything is written, and the
// cause is only in the log.
func TestConsentIssueFailure(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	text := r.pending(nil)
	cookie, _ := r.signIn(userA)

	r.entropy = brokenReader{}

	rec := r.consent(cookie, approval(t, text, "A"))

	if rec.Code != http.StatusInternalServerError || rec.Body.String() != bodyInternal {
		t.Errorf("= %d %s, want the bare internal error", rec.Code, rec.Body)
	}

	if len(r.logged) != 1 || r.logged[0].Code != "oauth_code_issue_failed" || !errors.Is(r.logged[0], errEntropy) {
		t.Errorf("logged %v, want oauth_code_issue_failed caused by the entropy", r.loggedCodes())
	}

	if len(r.store.calls) != 0 {
		t.Error("a code that was not issued reached the store")
	}
}

// TestConsentBodyBound: the body cap leaves room for the largest sealed request
// and an agent name of the widest escaped characters, and a body over it is 413
// before anything is read.
func TestConsentBodyBound(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)

	largest := sealed(t, r, nil, time.Minute, []byte(strings.Repeat("x", challenge.MaxPayloadLen)))

	// The widest name the wire can carry writes every character as a surrogate
	// pair escape, 12 bytes each.
	escaped := strings.Repeat(`\ud83d\ude00`, input.MaxAgentNameRunes)
	body := `{"request":"` + largest + `","approve":true,"agent":{"new":"` + escaped + `"}}`

	if len(body) > oauth.MaxConsentBody {
		t.Fatalf("the widest body is %d bytes, over the cap %d", len(body), oauth.MaxConsentBody)
	}

	// It is read to the end: the request inside is not one of ours.
	rec := r.consent(cookie, body)

	wantInvalidPending(t, r, rec.Code, rec.Body.String())

	r.logged = nil

	over := r.consent(cookie, `{"request":"`+strings.Repeat("A", oauth.MaxConsentBody)+`"}`)

	if over.Code != http.StatusRequestEntityTooLarge || len(r.store.calls) != 0 {
		t.Errorf("a body over the cap = %d %s, want 413", over.Code, over.Body)
	}
}
