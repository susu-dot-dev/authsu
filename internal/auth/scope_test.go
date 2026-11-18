//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	agentOne = "00000000-0000-7000-8000-0000000000a1"
	agentTwo = "00000000-0000-7000-8000-0000000000a2"
)

// scopedRoutes is a route table where each route declares one access rule, so a
// request's outcome shows exactly which rule it met. Every route records its
// call, and refusals never reach it.
func (r *rig) scopedRoutes() []auth.Route {
	declare := func(path string, access auth.Access) auth.Route {
		return r.getRoute(path, auth.Authenticated, access)
	}

	return []auth.Route{
		declare("/open", auth.Open()),
		declare("/agent-read", auth.Needs(scope.AgentRead)),
		declare("/agent-create", auth.Needs(scope.AgentCreate)),
		declare("/agent-update", auth.Needs(scope.AgentUpdate).WithoutAgents()),
		declare("/key-create", auth.Needs(scope.KeyCreate).Sessions().WithoutAgents()),
		declare("/user-read", auth.Needs(scope.UserRead)),
		declare("/invitation-create", auth.Needs(scope.InvitationCreate)),
		declare("/open-no-agents", auth.Open().WithoutAgents()),
		declare("/open-sessions", auth.Open().Sessions()),
	}
}

// scopedOutcome is what a request to a scoped route must produce: allowed, or a
// 403 under one of the two codes an access refusal has.
type scopedOutcome uint8

const (
	allowed scopedOutcome = iota
	noScope
	forbiddenAccess
)

// status is the HTTP status of the outcome.
func (o scopedOutcome) status() int {
	if o == allowed {
		return http.StatusOK
	}

	return http.StatusForbidden
}

// code is the error code of a refusal, and "" for a success.
func (o scopedOutcome) code() string {
	switch o {
	case allowed:
		return ""
	case noScope:
		return auth.CodeInsufficientScope
	case forbiddenAccess:
		return auth.CodeForbidden
	}

	return ""
}

// accessCase is one row of the permission table: a credential (a session, a
// user's key, an agent's key) with what it carries and the account's role, the
// route, and the answer.
type accessCase struct {
	name string
	// key builds the request's credential on the rig and returns the
	// Authorization value or the cookie.
	key  credentialFn
	path string
	want scopedOutcome
}

// Names the permission tables share.
const (
	bundleSession = scope.DefaultSession
	bundleUser    = scope.DefaultUser
	bundleAgent   = scope.DefaultAgent
	scopeRead     = "agent:read"
	scopeCreate   = "agent:create"
)

// sessionCases: a session is every scope, limited by the role.
func sessionCases() []accessCase {
	return []accessCase{
		{"session of a member: an open route", member(session), "/open", allowed},
		{"session of a member: a user scope", member(session), "/agent-create", allowed},
		{"session of a member: an admin route is the role's 403", member(session), "/user-read", forbiddenAccess},
		{"session of a member: an admin create is the role's 403", member(session), "/invitation-create", forbiddenAccess},
		{"session of an admin: an admin scope", admin(session), "/user-read", allowed},
		{"session of an admin: another admin scope", admin(session), "/invitation-create", allowed},
		{"session of an admin: a session-only route", admin(session), "/key-create", allowed},
		{"session of an admin: a session route", admin(session), "/open-sessions", allowed},
		{"session: a route that refuses agents", member(session), "/open-no-agents", allowed},
	}
}

// userKeyCases: a user's own API key is limited by what it names.
func userKeyCases() []accessCase {
	return []accessCase{
		{"user bundle: a user scope", userKey(bundleUser), "/agent-read", allowed},
		{"user bundle: an admin scope is not in it", adminKey(bundleUser), "/user-read", noScope},
		{"admin with the session bundle: an admin scope", adminKey(bundleSession), "/user-read", allowed},
		{
			"member with the session bundle: the role gates the admin scope",
			userKey(bundleSession), "/user-read", forbiddenAccess,
		},
		{"one scope: that scope", userKey(scopeRead), "/agent-read", allowed},
		{"one scope: another scope", userKey(scopeRead), "/agent-create", noScope},
		{"no scopes: an open route", userKey(), "/open", allowed},
		{"no scopes: a scoped route", userKey(), "/agent-read", noScope},
		{"a route that wants a session", userKey(bundleSession), "/open-sessions", forbiddenAccess},
		{"create key needs a session", userKey(bundleSession), "/key-create", forbiddenAccess},
		{"no agent, so a route that refuses agents is fine", userKey(bundleUser), "/open-no-agents", allowed},
		{"an unknown name grants nothing", userKey("nope:read"), "/agent-read", noScope},
		{"an unknown name beside a known one", userKey("nope:read", scopeRead), "/agent-read", allowed},
	}
}

// agentKeyCases: an agent's key is the intersection of its key and its agent.
func agentKeyCases() []accessCase {
	both := func(l ...string) credentialFn { return agentKey(list(l...), list(l...)) }

	return []accessCase{
		{"key and agent both allow", both(scopeRead), "/agent-read", allowed},
		{"the key allows, the agent does not", agentKey(list(scopeRead), list()), "/agent-read", noScope},
		{"the agent allows, the key does not", agentKey(list(), list(scopeRead)), "/agent-read", noScope},
		{"bundles intersect", agentKey(list(bundleUser), list(bundleAgent)), "/agent-read", allowed},
		{"outside the agent's bundle", agentKey(list(bundleUser), list(bundleAgent)), "/agent-create", noScope},
		{
			"the agent has it explicitly, the key by bundle",
			agentKey(list(bundleUser), list(bundleAgent, scopeCreate)), "/agent-create", allowed,
		},
		{
			"a key of the session bundle is still capped by the agent",
			agentKey(list(bundleSession), list(bundleAgent)), "/agent-create", noScope,
		},
		{"an open route", agentKey(list(), list()), "/open", allowed},
		{"refused where agents are refused, whatever its scopes", both(bundleSession), "/agent-update", forbiddenAccess},
		{"refused on an open route that refuses agents", agentKey(list(), list()), "/open-no-agents", forbiddenAccess},
		{"never a session route", both(bundleSession), "/open-sessions", forbiddenAccess},
		{"of a member naming admin scopes is the role's 403", both(bundleSession), "/user-read", forbiddenAccess},
		{
			"of an admin with both lists naming it",
			adminAgent(list(bundleSession), list(bundleSession)), "/user-read", allowed,
		},
		{
			"of an admin whose agent does not name it",
			adminAgent(list(bundleSession), list(bundleAgent)), "/user-read", noScope,
		},
		{"of an admin whose key does not name it", adminAgent(list(bundleAgent), list(bundleSession)), "/user-read", noScope},
		{
			"a stored list that is not a list grants nothing",
			agentKeyStored(list(scopeRead), "not json"), "/agent-read", noScope,
		},
		{"a stored list that is empty text grants nothing", agentKeyStored(list(scopeRead), ""), "/agent-read", noScope},
	}
}

// TestAccessMatrix is the permission table, one row per credential, route and
// answer. It drives the real boundary, so the declaration, the token's claim,
// the agent's row and the role are all the real ones.
func TestAccessMatrix(t *testing.T) {
	t.Parallel()

	for _, group := range [][]accessCase{sessionCases(), userKeyCases(), agentKeyCases()} {
		for _, test := range group {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				header, cookie := test.key(r)

				rec := r.serveWith(r.scopedRoutes(), test.path, optionalHeader(header), optionalCookie(cookie))

				checkOutcome(t, r, rec, test.want)
			})
		}
	}
}

// optionalHeader is the Authorization values to send: none for "".
func optionalHeader(header string) []string {
	if header == "" {
		return nil
	}

	return []string{header}
}

// optionalCookie is the cookies to send: none for nil.
func optionalCookie(cookie *http.Cookie) []*http.Cookie {
	if cookie == nil {
		return nil
	}

	return []*http.Cookie{cookie}
}

// checkOutcome checks a response against the outcome of a scoped route: a
// success ran the handler once, and a refusal never reached it, was logged once
// under its code, and says the code in its body.
func checkOutcome(t *testing.T, r *rig, rec *httptest.ResponseRecorder, want scopedOutcome) {
	t.Helper()

	if rec.Code != want.status() {
		t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, want.status())
	}

	if want == allowed {
		if len(r.handled) != 1 {
			t.Errorf("handler ran %d times, want once", len(r.handled))
		}

		return
	}

	if len(r.handled) != 0 {
		t.Errorf("a refused request reached its handler %d times", len(r.handled))
	}

	if len(r.logged) != 1 || r.logged[0].Code != want.code() {
		t.Errorf("logged = %v, want one %s", r.logged, want.code())
	}

	if !strings.Contains(rec.Body.String(), `"code":"`+want.code()+`"`) {
		t.Errorf("body = %s, want code %s", rec.Body, want.code())
	}
}

func list(names ...string) scope.List { return scope.List(slices.Clone(names)) }

// credentialFn builds a credential on a rig.
type credentialFn = func(*rig) (string, *http.Cookie)

// session is a stored session for a user with role.
func session(role string) credentialFn {
	return func(r *rig) (string, *http.Cookie) { return "", sessionCookie(r.sessionFor(userID, role)) }
}

func member(f func(string) credentialFn) credentialFn { return f(roleMember) }
func admin(f func(string) credentialFn) credentialFn  { return f(auth.RoleAdmin) }

// userKey is a stored API key of a member with the given scope names.
func userKey(names ...string) credentialFn { return keyOf(roleMember, names...) }

// adminKey is a stored API key of an administrator with the given scope names.
func adminKey(names ...string) credentialFn { return keyOf(auth.RoleAdmin, names...) }

func keyOf(role string, names ...string) credentialFn {
	return func(r *rig) (string, *http.Cookie) {
		return bearer(r.apiKey(bearerSpec{scope: list(names...), role: role})), nil
	}
}

// agentKey is a stored API key of an agent of a member: the key's list and the
// agent's list.
func agentKey(key, agent scope.List) credentialFn { return agentOf(roleMember, key, agent.JSON()) }

// adminAgent is agentKey for an administrator's agent.
func adminAgent(key, agent scope.List) credentialFn {
	return agentOf(auth.RoleAdmin, key, agent.JSON())
}

// agentKeyStored is agentKey with the agent's list as the raw stored text.
func agentKeyStored(key scope.List, stored string) credentialFn {
	return agentOf(roleMember, key, stored)
}

func agentOf(role string, key scope.List, agentStored string) credentialFn {
	return func(r *rig) (string, *http.Cookie) {
		return bearer(r.apiKey(bearerSpec{scope: key, role: role, agent: agentOne, agentScopes: agentStored})), nil
	}
}

// TestPrincipalCarriesTheScopeLists: what the handler is given is the key's list
// and the agent's list exactly as written, plus their intersection.
func TestPrincipalCarriesTheScopeLists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec bearerSpec
		want principalWant
	}{
		{
			name: "a user's key",
			spec: bearerSpec{scope: list("agent:read", "key:read"), role: roleMember},
			want: principalWant{
				key: []string{"agent:read", "key:read"}, agent: []string{},
				effective: []scope.Scope{scope.AgentRead, scope.KeyRead},
			},
		},
		{
			name: "an agent's key is the intersection",
			spec: bearerSpec{
				scope: list(scope.DefaultUser), role: roleMember, agent: agentOne,
				agentScopes: list("agent:read", "agent:create", "user:read").JSON(),
			},
			want: principalWant{
				key: []string{scope.DefaultUser}, agent: []string{"agent:read", "agent:create", "user:read"},
				agentID: agentOne, effective: []scope.Scope{scope.AgentCreate, scope.AgentRead},
			},
		},
		{
			name: "lists are kept as written, duplicates and order included",
			spec: bearerSpec{scope: list("key:read", "agent:read", "key:read"), role: roleMember},
			want: principalWant{
				key: []string{"key:read", "agent:read", "key:read"}, agent: []string{},
				effective: []scope.Scope{scope.AgentRead, scope.KeyRead},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			key := r.apiKey(test.spec)

			routes := []auth.Route{r.getRoute("/me", auth.Authenticated, auth.Open())}

			rec := r.serveWith(routes, "/me", []string{bearer(key)}, nil)
			if rec.Code != http.StatusOK || len(r.handled) != 1 {
				t.Fatalf("status = %d, ran %d times: %s", rec.Code, len(r.handled), rec.Body)
			}

			checkPrincipal(t, r.handled[0].Principal, key, test.want)
		})
	}
}

// principalWant is what a handler is given for a key.
type principalWant struct {
	key, agent []string
	agentID    string
	effective  []scope.Scope
}

// checkPrincipal checks the Principal of an API key: who, and the two lists as
// written and their intersection.
func checkPrincipal(t *testing.T, who auth.Principal, key auth.Key, want principalWant) {
	t.Helper()

	if who.UserID != userID || who.Kind != auth.KindAPIKey || who.AgentID != want.agentID ||
		who.KeyID != key.ID.String() || who.CredentialID != "" {
		t.Errorf("principal = %+v", who)
	}

	if !slices.Equal([]string(who.KeyScope), want.key) {
		t.Errorf("KeyScope = %v, want %v", who.KeyScope, want.key)
	}

	if !slices.Equal([]string(who.AgentScope), want.agent) {
		t.Errorf("AgentScope = %v, want %v", who.AgentScope, want.agent)
	}

	if got := who.Effective.Sorted(); !slices.Equal(got, want.effective) {
		t.Errorf("Effective = %v, want %v", got, want.effective)
	}
}

// TestTheKeysClaimIsTheScopeNotTheRow: the signed claim is authoritative, and
// the row's copy is only for listing. The fake store's row has no scope field at
// all, so a boundary that read it would see nothing; this holds that the claim is
// what is used, for both a user's key and an agent's.
func TestTheKeysClaimIsTheScopeNotTheRow(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	key := r.apiKey(bearerSpec{scope: list("agent:read"), role: roleMember})

	rec := r.serveWith(r.scopedRoutes(), "/agent-read", []string{bearer(key)}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("a key whose claim names agent:read was refused: %d %s", rec.Code, rec.Body)
	}

	rec = r.serveWith(r.scopedRoutes(), "/agent-create", []string{bearer(key)}, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a key whose claim lacks agent:create was allowed: %d", rec.Code)
	}
}

// TestMalformedScopeClaimsGrantNothing: whatever the token's scope claim is, if
// it is not an array of strings the key can use only open routes. A token the
// service did not create with this shape is signed by a key whose public half is
// in the database, so this is about a defect on our side, not a forgery.
func TestMalformedScopeClaimsGrantNothing(t *testing.T) {
	t.Parallel()

	tests := map[string]any{
		"missing":                  nil,
		"a string":                 "agent:read",
		"a space separated string": "agent:read agent:create",
		"a number":                 1,
		"an object":                map[string]any{"agent:read": true},
		"nested array":             []any{[]any{"agent:read"}},
		"a number in the array":    []any{"agent:read", 1},
		"null elements":            []any{nil},
	}

	for name, claim := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			f := forgeKey(t, r, claim, auth.KindAPIKey)
			r.storeForgedAs(f, auth.KindAPIKey)

			rec := r.serveWith(r.scopedRoutes(), "/agent-read", []string{"Bearer " + f.JWT}, nil)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d (%s), want 403 for a claim that is %s", rec.Code, rec.Body, name)
			}

			rec = r.serveWith(r.scopedRoutes(), "/open", []string{"Bearer " + f.JWT}, nil)
			if rec.Code != http.StatusOK {
				t.Errorf("an open route refused a valid key with a bad scope claim: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

// forgeKey signs an API key token for the standard user with the given scope
// claim, or none when claim is nil.
func forgeKey(t *testing.T, r *rig, claim any, kind string) forged {
	t.Helper()

	return forge(t, r.issuer, r.now, func(claims map[string]any) {
		claims[claimAud] = auth.Audience(kind)

		if claim != nil {
			claims[claimScope] = claim
		}
	})
}

// storeForgedAs stores a forged key's row under kind, owned by a member.
func (r *rig) storeForgedAs(f forged, kind string) {
	r.keys.rows[rowKey{kid: f.ID.String(), kind: kind}] = store.ActiveKey{
		JWK: []byte(f.JWK), UserID: userID, CredentialID: "", Role: roleMember, ExpiresAt: r.now.Add(time.Hour),
	}
}

// agentSpec is a stored key of agentOne whose scopes are bundleAgent on both
// sides: the baseline the actor tests spoil one way at a time.
func agentSpec() bearerSpec {
	return bearerSpec{scope: list(bundleAgent), agent: agentOne, agentScopes: list(bundleAgent).JSON()}
}

// TestActorMustMatchTheRow: the token's actor and the row's agent must agree,
// both ways. A mismatch is not a valid key, so it is a 401, and the rest of the
// request is never judged.
func TestActorMustMatchTheRow(t *testing.T) {
	t.Parallel()

	const ok, no = http.StatusOK, http.StatusUnauthorized

	noAgent := bearerSpec{scope: list(bundleAgent)}

	tests := []struct {
		name string
		spec bearerSpec
		want int
	}{
		{"agent row and matching actor", agentSpec(), ok},
		{"no agent and no actor", noAgent, ok},
		{"agent row, token names another agent", agentSpec().withActor(agentTwo), no},
		{"agent row, token names no actor", agentSpec().withActor(""), no},
		{"no agent row, token names an actor", noAgent.withActor(agentOne), no},
		{"agent row, actor in another case", agentSpec().withActor(strings.ToUpper(agentOne)), no},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			key := r.apiKey(test.spec)

			rec := r.serveWith(r.scopedRoutes(), "/open", []string{bearer(key)}, nil)
			if rec.Code != test.want {
				t.Errorf("status = %d (%s), want %d", rec.Code, rec.Body, test.want)
			}

			if test.want == no && rec.Body.String() != bodyUnauthenticated {
				t.Errorf("body = %q, want the one unauthenticated answer", rec.Body)
			}
		})
	}
}

// forgedWithAct signs an API key token whose act claim is act, as written, and
// stores its row with agent (which may be empty: no agent).
func forgedWithAct(t *testing.T, act any, agent string) (*rig, string) {
	t.Helper()

	r := newRig(t)

	f := forge(t, r.issuer, r.now, func(claims map[string]any) {
		claims[claimAud] = auth.Audience(auth.KindAPIKey)
		claims[claimScope] = []any{bundleAgent}
		claims[claimAct] = act
	})

	row := store.ActiveKey{
		JWK: []byte(f.JWK), UserID: userID, CredentialID: "", Role: roleMember, ExpiresAt: r.now.Add(time.Hour),
		AgentID: agent,
	}
	if agent != "" {
		row.AgentScopes = list(bundleAgent).JSON()
	}

	r.keys.rows[rowKey{kid: f.ID.String(), kind: auth.KindAPIKey}] = row

	return r, "Bearer " + f.JWT
}

// TestMalformedActorClaimIsRefused: an act claim that is present but is not
// {"sub": "<id>"} is not a token this service issued, so it is a 401 whatever
// the row holds: against a key that has an agent and against one that has none.
// It is never read as "no actor" and let through.
func TestMalformedActorClaimIsRefused(t *testing.T) {
	t.Parallel()

	shapes := map[string]any{
		"a string":          agentOne,
		"an array":          []any{agentOne},
		"sub is a number":   map[string]any{claimSub: 1},
		"sub is missing":    map[string]any{"id": agentOne},
		"sub is an object":  map[string]any{claimSub: map[string]any{"id": agentOne}},
		"null":              nil,
		"an empty object":   map[string]any{},
		"sub is empty text": map[string]any{claimSub: ""},
	}

	for name, act := range shapes {
		t.Run(name+" against an agent's row", func(t *testing.T) {
			t.Parallel()

			r, header := forgedWithAct(t, act, agentOne)

			rec := r.serveWith(r.scopedRoutes(), "/open", []string{header}, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status %d, want 401", rec.Code)
			}
		})

		t.Run(name+" against a key with no agent", func(t *testing.T) {
			t.Parallel()

			r, header := forgedWithAct(t, act, "")

			rec := r.serveWith(r.scopedRoutes(), "/open", []string{header}, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status %d (%s), want 401", rec.Code, rec.Body)
			}

			if rec.Body.String() != bodyUnauthenticated {
				t.Errorf("body = %q, want the one unauthenticated answer", rec.Body)
			}
		})
	}
}

// validBearer is the header of a stored API key with no scopes.
func validBearer(r *rig) string { return bearer(r.apiKey(bearerSpec{scope: list()})) }

// bearerCase is one Authorization header, built on a rig, and the status it gets.
type bearerCase struct {
	name  string
	build func(*rig) []string
	want  int
}

// bearerCases are the shapes an Authorization header can take.
func bearerCases() []bearerCase {
	one := func(f func(*rig) string) func(*rig) []string {
		return func(r *rig) []string { return []string{f(r)} }
	}
	token := func(r *rig) string { return r.apiKey(bearerSpec{scope: list()}).JWT }
	fixed := func(value string) func(*rig) []string { return func(*rig) []string { return []string{value} } }

	const ok, no = http.StatusOK, http.StatusUnauthorized

	return []bearerCase{
		{"a bearer token", one(validBearer), ok},
		{"scheme in lower case", one(func(r *rig) string { return "bearer " + token(r) }), ok},
		{"scheme in upper case", one(func(r *rig) string { return "BEARER " + token(r) }), ok},
		{"no header", func(*rig) []string { return nil }, no},
		{"the scheme alone", fixed("Bearer"), no},
		{"the scheme and a space", fixed("Bearer "), no},
		{"basic auth", fixed("Basic dXNlcjpwYXNz"), no},
		{"a token with no scheme", one(token), no},
		{"two spaces before the token", one(func(r *rig) string { return "Bearer  " + token(r) }), no},
		{"a trailing space", one(func(r *rig) string { return validBearer(r) + " " }), no},
		{"a tab instead of a space", one(func(r *rig) string { return "Bearer\t" + token(r) }), no},
		{"two tokens in one header", one(func(r *rig) string { t := token(r); return "Bearer " + t + " " + t }), no},
		{"the header sent twice", func(r *rig) []string { h := validBearer(r); return []string{h, h} }, no},
		{"a good header and a bad one", func(r *rig) []string { return []string{validBearer(r), "Bearer " + garbage} }, no},
		{"garbage", fixed("Bearer " + garbage), no},
		{"an oversized token", fixed("Bearer " + strings.Repeat("a", 5000)), no},
		{"a NUL in the token", fixed("Bearer a\x00b"), no},
		{"a key that is not stored", one(func(r *rig) string { return bearer(r.createKey(r.issuer, auth.KindAPIKey)) }), no},
	}
}

// garbage is a bearer value that is a token by alphabet and nothing else.
const garbage = "garbage"

// TestBearerParsing: the header is parsed strictly and a request that sent a
// credential in the header is never treated as having sent none.
func TestBearerParsing(t *testing.T) {
	t.Parallel()

	for _, test := range bearerCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			rec := r.serveWith(r.scopedRoutes(), "/open", test.build(r), nil)
			if rec.Code != test.want {
				t.Errorf("status = %d (%s), want %d", rec.Code, rec.Body, test.want)
			}

			if test.want == http.StatusUnauthorized && (rec.Body.String() != bodyUnauthenticated || len(r.handled) != 0) {
				t.Errorf("body = %q, handler ran %d times, want the one unauthenticated answer", rec.Body, len(r.handled))
			}
		})
	}
}

// TestCarriersAreNotInterchangeable: a session token presented as a bearer is not
// an API key, and an API key presented as the session cookie is not a session.
// The audience, the kind the row is read with, and the carrier all have to
// agree, so no kind can be passed off as the other.
func TestCarriersAreNotInterchangeable(t *testing.T) {
	t.Parallel()

	t.Run("a session token as a bearer token", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		key := r.session()

		rec := r.serveWith(r.scopedRoutes(), "/open", []string{bearer(key)}, nil)
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
			t.Errorf("response = %d %q, want 401", rec.Code, rec.Body)
		}
	})

	t.Run("an API key as the session cookie", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		key := r.apiKey(bearerSpec{scope: list(scope.DefaultSession)})

		rec := r.serveWith(r.scopedRoutes(), "/open", nil, []*http.Cookie{sessionCookie(key)})
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
			t.Errorf("response = %d %q, want 401", rec.Code, rec.Body)
		}
	})

	t.Run("each read asks the store for its own kind", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		apiKey := r.apiKey(bearerSpec{scope: list()})
		sessionKey := r.session()

		r.serveWith(r.scopedRoutes(), "/open", []string{bearer(apiKey)}, nil)
		r.serveWith(r.scopedRoutes(), "/open", nil, []*http.Cookie{sessionCookie(sessionKey)})

		if len(r.keys.calls) != 2 || r.keys.calls[0].kind != auth.KindAPIKey || r.keys.calls[1].kind != auth.KindSession {
			t.Errorf("store reads = %+v, want one api_key then one session", r.keys.calls)
		}
	})

	t.Run("a kind the store does not hold under that kid", func(t *testing.T) {
		t.Parallel()

		r := newRig(t)
		r.keys.ignoreKind = true
		key := r.session()

		// The store answers for the kid whatever its kind; the audience still
		// refuses a session token on the bearer path.
		rec := r.serveWith(r.scopedRoutes(), "/open", []string{bearer(key)}, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

// TestBothCredentialsAreRefused: a request carrying a session cookie and a
// bearer token is ambiguous, and picking either would let whoever controls the
// other decide. It is refused before either is verified, with the one
// unauthenticated answer.
func TestBothCredentialsAreRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(*rig) ([]string, []*http.Cookie)
	}{
		{"a valid session and a valid key", func(r *rig) ([]string, []*http.Cookie) {
			header := bearer(r.apiKey(bearerSpec{scope: list(bundleSession)}))

			return []string{header}, []*http.Cookie{sessionCookie(r.session())}
		}},
		{"a valid session and a garbage bearer", func(r *rig) ([]string, []*http.Cookie) {
			return []string{"Bearer garbage"}, []*http.Cookie{sessionCookie(r.session())}
		}},
		{"a garbage cookie and a valid key", func(r *rig) ([]string, []*http.Cookie) {
			return []string{bearer(r.apiKey(bearerSpec{scope: list(scope.DefaultSession)}))},
				[]*http.Cookie{requestCookie(auth.CookieName, "garbage")}
		}},
		{"an empty cookie and a valid key", func(r *rig) ([]string, []*http.Cookie) {
			return []string{bearer(r.apiKey(bearerSpec{scope: list(scope.DefaultSession)}))},
				[]*http.Cookie{requestCookie(auth.CookieName, "")}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			headers, cookies := test.build(r)

			rec := r.serveWith(r.scopedRoutes(), "/open", headers, cookies)
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("response = %d %q, want 401 unauthenticated", rec.Code, rec.Body)
			}

			if len(r.keys.calls) != 0 {
				t.Errorf("the store was read %d times; an ambiguous request is refused before any read", len(r.keys.calls))
			}

			if len(r.handled) != 0 {
				t.Error("an ambiguous request reached the handler")
			}

			if len(r.logged) != 1 || !strings.Contains(r.logged[0].Error(), "both a session cookie and a bearer token") {
				t.Errorf("logged = %v, want the cause in the log only", r.logged)
			}
		})
	}
}

// TestCredentialIsJudgedBeforeAccess: a bad credential is 401 on every route, a
// good one that lacks what the route needs is 403, and neither learns anything
// about the route's rule from the other. 401 means signed out and 403 means not
// allowed.
func TestCredentialIsJudgedBeforeAccess(t *testing.T) {
	t.Parallel()

	routes := []string{"/open", "/agent-read", "/user-read", "/key-create", "/agent-update", "/open-no-agents"}

	for _, path := range routes {
		t.Run(path+" with no credential", func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			rec := r.serveWith(r.scopedRoutes(), path, nil, nil)
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("response = %d %q, want the same 401 as every route", rec.Code, rec.Body)
			}
		})

		t.Run(path+" with a revoked agent's key", func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			key := r.apiKey(bearerSpec{
				scope: list(scope.DefaultSession), agent: agentOne, agentScopes: list(scope.DefaultSession).JSON(),
			})
			// The store reports nothing active for a key whose agent is revoked.
			delete(r.keys.rows, rowKey{kid: key.ID.String(), kind: auth.KindAPIKey})

			rec := r.serveWith(r.scopedRoutes(), path, []string{bearer(key)}, nil)
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("response = %d %q, want 401", rec.Code, rec.Body)
			}
		})
	}
}

// TestAccessOrder pins the order of the checks, which decides what a caller who
// fails several of them is told: the role for an admin scope, then the scope,
// then the session requirement, then agents.
func TestAccessOrder(t *testing.T) {
	t.Parallel()

	everything := auth.Needs(scope.UserRead).Sessions().WithoutAgents()

	tests := []struct {
		name     string
		who      auth.Principal
		access   auth.Access
		wantCode string
		wantText string
	}{
		{
			name:     "a member without the scope on an admin route is told about the role",
			who:      auth.Principal{Role: roleMember, Kind: auth.KindAPIKey, AgentID: agentOne},
			access:   everything,
			wantCode: auth.CodeForbidden, wantText: "administrator access is required",
		},
		{
			name:     "an admin without the scope is told about the scope",
			who:      auth.Principal{Role: auth.RoleAdmin, Kind: auth.KindAPIKey, AgentID: agentOne},
			access:   everything,
			wantCode: auth.CodeInsufficientScope, wantText: "this credential lacks the scope user:read",
		},
		{
			name: "an admin with the scope but a key is told it needs a session",
			who: auth.Principal{
				Role: auth.RoleAdmin, Kind: auth.KindAPIKey, AgentID: agentOne, Effective: list(scope.DefaultSession).Expand(),
			},
			access:   everything,
			wantCode: auth.CodeForbidden, wantText: "a signed-in session is required",
		},
		{
			name: "a session of an agent cannot exist, so agents are the last",
			who: auth.Principal{
				Role: auth.RoleAdmin, Kind: auth.KindSession, AgentID: agentOne, Effective: list(scope.DefaultSession).Expand(),
			},
			access:   everything,
			wantCode: auth.CodeForbidden, wantText: "an agent may not do this",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			failure := apierr.As(auth.CheckAccess(test.access, test.who))
			if failure == nil {
				t.Fatal("the access was not refused")
			}

			if failure.Kind != apierr.Forbidden || failure.Code != test.wantCode || failure.Description != test.wantText {
				t.Errorf("refusal = %v %s %q, want 403 %s %q", failure.Kind, failure.Code, failure.Description,
					test.wantCode, test.wantText)
			}
		})
	}
}

// TestAccessPasses: the same access, met in full, is not refused; and the
// zero-value pieces of it (no scope, no flags) refuse nothing.
func TestAccessPasses(t *testing.T) {
	t.Parallel()

	session := auth.Principal{
		Role: auth.RoleAdmin, Kind: auth.KindSession, Effective: list(scope.DefaultSession).Expand(),
	}

	for name, access := range map[string]auth.Access{
		"open":                          auth.Open(),
		"a scope":                       auth.Needs(scope.UserRead),
		"a scope and a session":         auth.Needs(scope.UserRead).Sessions(),
		"a scope and no agents":         auth.Needs(scope.UserRead).WithoutAgents(),
		"a scope, a session, no agents": auth.Needs(scope.UserRead).Sessions().WithoutAgents(),
	} {
		err := auth.CheckAccess(access, session)
		if err != nil {
			t.Errorf("%s: refused a session of an admin with every scope: %v", name, err)
		}
	}
}

// TestAccessBuildersDoNotShareState: Sessions and WithoutAgents return copies,
// so a shared base cannot be changed by deriving from it.
func TestAccessBuildersDoNotShareState(t *testing.T) {
	t.Parallel()

	base := auth.Needs(scope.AgentRead)
	_ = base.Sessions()
	_ = base.WithoutAgents()

	if base != auth.Needs(scope.AgentRead) {
		t.Errorf("deriving from an Access changed it: %+v", base)
	}

	if auth.Open() == (auth.Access{}) {
		t.Error("Open() is the zero Access: a route that forgot its access would be indistinguishable")
	}
}
