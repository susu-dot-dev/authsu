//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// principalWant is what a handler is given for a credential.
type principalWant struct {
	role      string
	secretID  string
	kind      string
	expiresAt time.Time
	agentID   string
	orgID     string
	sandboxID string
	// scope and agentScope are the lists as stored, never nil.
	scope, agentScope []string
	effective         []scope.Scope
}

// checkPrincipal checks every field of the Principal a handler was given.
func checkPrincipal(t *testing.T, got auth.Principal, want principalWant) {
	t.Helper()

	if got.UserID != userID || got.Role != want.role || got.SecretID != want.secretID ||
		got.Kind != want.kind || !got.ExpiresAt.Equal(want.expiresAt) ||
		got.AgentID != want.agentID || got.OrgID != want.orgID || got.SandboxID != want.sandboxID {
		t.Errorf("principal = %+v, want %+v", got, want)
	}

	checkList(t, "Scope", got.Scope, want.scope)
	checkList(t, "AgentScope", got.AgentScope, want.agentScope)

	if effective := got.Authority().Effective().Sorted(); !slices.Equal(effective, want.effective) {
		t.Errorf("Effective = %v, want %v", effective, want.effective)
	}
}

// checkList checks a stored list: exactly as written, and never nil.
func checkList(t *testing.T, name string, got scope.List, want []string) {
	t.Helper()

	if got == nil || !slices.Equal([]string(got), want) {
		t.Errorf("%s = %#v, want %v", name, got, want)
	}
}

// sorted is the scopes of the lists, as Authority.Effective().Sorted returns them.
func sorted(names ...string) []scope.Scope {
	return list(names...).Expand().Sorted()
}

// principalCase is a credential to present and the Principal the handler must
// see for it.
type principalCase struct {
	name string
	// present builds the credential on the rig and says what the principal is.
	present func(r *rig) (carried, principalWant)
}

// sessionPrincipalCase is a stored session of an account with role.
func sessionPrincipalCase(name, role string) principalCase {
	return principalCase{name, func(r *rig) (carried, principalWant) {
		issued := r.sessionFor(role)

		return carried{headers: nil, cookies: []*http.Cookie{sessionCookie(issued)}}, principalWant{
			role: role, secretID: issued.ID, kind: auth.KindSession,
			expiresAt: issued.ExpiresAt, agentID: "",
			scope: []string{scope.DefaultSession}, agentScope: []string{}, effective: sorted(scope.DefaultSession),
		}
	}}
}

// orgSessionPrincipalCase is a stored session of a member of the organization
// org: the principal carries it, and no sandbox.
func orgSessionPrincipalCase(name, org string) principalCase {
	return principalCase{name, func(r *rig) (carried, principalWant) {
		issued := r.sessionFor(roleMember)
		r.setSession(issued, func(row *store.ActiveSession) { row.OrgID = org })

		return carried{headers: nil, cookies: []*http.Cookie{sessionCookie(issued)}}, principalWant{
			role: roleMember, secretID: issued.ID, kind: auth.KindSession,
			expiresAt: issued.ExpiresAt, orgID: org,
			scope: []string{scope.DefaultSession}, agentScope: []string{}, effective: sorted(scope.DefaultSession),
		}
	}}
}

// keyPrincipalCase is a stored API key as spec describes, and the principal it
// must give.
func keyPrincipalCase(name string, spec bearerSpec, want principalWant) principalCase {
	return principalCase{name, func(r *rig) (carried, principalWant) {
		issued := r.apiKey(spec)

		want.secretID, want.expiresAt, want.kind = issued.ID, issued.ExpiresAt, auth.KindAPIKey
		if want.role == "" {
			want.role = roleMember
		}

		return carried{headers: []string{bearer(issued)}, cookies: nil}, want
	}}
}

// damaged are stored scope texts that are not a JSON array of strings.
func damaged() map[string]string {
	return map[string]string{
		"not json":           "not json",
		"empty text":         "",
		"null":               "null",
		"an object":          `{"agent:read":true}`,
		"a string":           `"agent:read"`,
		"numbers":            `[1,2]`,
		"a mixed array":      `["agent:read",1]`,
		"nested arrays":      `[["agent:read"]]`,
		"a truncated array":  `["agent:read"`,
		"a space separated":  "agent:read agent:create",
		"trailing garbage":   `["agent:read"] x`,
		"the wrong brackets": `{"agent:read"}`,
	}
}

// userPrincipalCases are sessions and keys of users.
func userPrincipalCases() []principalCase {
	return []principalCase{
		sessionPrincipalCase("a session of a member", roleMember),
		sessionPrincipalCase("a session of an administrator", auth.RoleAdmin),
		keyPrincipalCase("a user's key",
			bearerSpec{scope: list("agent:read", "key:read"), role: roleMember},
			principalWant{
				scope: []string{"agent:read", "key:read"}, agentScope: []string{}, effective: sorted("agent:read", "key:read"),
			}),
		keyPrincipalCase("a user's key with a bundle",
			bearerSpec{scope: list(scope.DefaultUser), role: roleMember},
			principalWant{scope: []string{scope.DefaultUser}, agentScope: []string{}, effective: sorted(scope.DefaultUser)}),
		keyPrincipalCase("a user's key with no scopes",
			bearerSpec{scope: list(), role: roleMember},
			principalWant{scope: []string{}, agentScope: []string{}, effective: sorted()}),
		orgSessionPrincipalCase("a session of a member of an organization", orgOne),
		keyPrincipalCase("a user's key reads the account's organization",
			bearerSpec{scope: list(scope.DefaultUser), org: orgOne},
			principalWant{
				orgID: orgOne, scope: []string{scope.DefaultUser}, agentScope: []string{}, effective: sorted(scope.DefaultUser),
			}),
		keyPrincipalCase("an administrator's key",
			bearerSpec{scope: list(scope.DefaultSession), role: auth.RoleAdmin},
			principalWant{
				role: auth.RoleAdmin, scope: []string{scope.DefaultSession}, agentScope: []string{},
				effective: sorted(scope.DefaultSession),
			}),
	}
}

// agentPrincipalCases are keys of agents: the intersection of two lists.
func agentPrincipalCases() []principalCase {
	return []principalCase{
		keyPrincipalCase("an agent's key is the intersection",
			bearerSpec{
				scope: list(scope.DefaultUser), role: roleMember, agent: agentOne,
				agentScopes: list("agent:read", "agent:create", "user:read").JSON(),
			},
			principalWant{
				agentID: agentOne, scope: []string{scope.DefaultUser},
				agentScope: []string{"agent:read", "agent:create", "user:read"},
				// user:read is an admin scope, so default:user lacks it.
				effective: sorted("agent:create", "agent:read"),
			}),
		keyPrincipalCase("an agent's key never exceeds the agent",
			bearerSpec{scope: list(scope.DefaultSession), agent: agentOne, agentScopes: list(scope.DefaultAgent).JSON()},
			principalWant{
				agentID: agentOne, scope: []string{scope.DefaultSession}, agentScope: []string{scope.DefaultAgent},
				effective: sorted(scope.DefaultAgent),
			}),
		keyPrincipalCase("an agent's key never exceeds the key",
			bearerSpec{scope: list("agent:read"), agent: agentOne, agentScopes: list(scope.DefaultSession).JSON()},
			principalWant{
				agentID: agentOne, scope: []string{"agent:read"}, agentScope: []string{scope.DefaultSession},
				effective: sorted("agent:read"),
			}),
		keyPrincipalCase("an agent's key reads the agent's sandbox and the account's organization",
			bearerSpec{
				scope: list(scope.DefaultUser), agent: agentOne, agentScopes: list(scope.DefaultAgent).JSON(),
				org: orgOne, sandbox: sandboxOne,
			},
			principalWant{
				agentID: agentOne, orgID: orgOne, sandboxID: sandboxOne, scope: []string{scope.DefaultUser},
				agentScope: []string{scope.DefaultAgent}, effective: sorted(scope.DefaultAgent),
			}),
		keyPrincipalCase("an ordinary agent's key has no sandbox",
			bearerSpec{scope: list(scope.DefaultUser), agent: agentOne, agentScopes: list(scope.DefaultAgent).JSON()},
			principalWant{
				agentID: agentOne, scope: []string{scope.DefaultUser}, agentScope: []string{scope.DefaultAgent},
				effective: sorted(scope.DefaultAgent),
			}),
		keyPrincipalCase("an agent with no scopes leaves the key nothing",
			bearerSpec{scope: list(scope.DefaultSession), agent: agentOne, agentScopes: list().JSON()},
			principalWant{
				agentID: agentOne, scope: []string{scope.DefaultSession}, agentScope: []string{}, effective: sorted(),
			}),
	}
}

// listPrincipalCases are keys that show how a stored list is kept.
func listPrincipalCases() []principalCase {
	return []principalCase{
		keyPrincipalCase("lists are kept as written, duplicates and order included",
			bearerSpec{scope: list("key:read", "agent:read", "key:read"), role: roleMember},
			principalWant{
				scope: []string{"key:read", "agent:read", "key:read"}, agentScope: []string{},
				effective: sorted("agent:read", "key:read"),
			}),
		// JSON null decodes as the empty string, a name that is no scope.
		keyPrincipalCase("a stored list of nulls reads as empty names and grants nothing",
			bearerSpec{}.withStoredScope(`[null]`),
			principalWant{scope: []string{""}, agentScope: []string{}, effective: sorted()}),
		keyPrincipalCase("a name the code does not know is kept and grants nothing",
			bearerSpec{scope: list("nope:read", "agent:read")},
			principalWant{
				scope: []string{"nope:read", "agent:read"}, agentScope: []string{}, effective: sorted("agent:read"),
			}),
	}
}

// damagedPrincipalCases are keys whose stored lists are damaged: each reads as
// empty and grants nothing, and does not make the credential unusable.
func damagedPrincipalCases() []principalCase {
	cases := make([]principalCase, 0, 3*len(damaged()))

	for name, text := range damaged() {
		cases = append(cases,
			keyPrincipalCase("a key whose stored scope is damaged: "+name,
				bearerSpec{role: roleMember}.withStoredScope(text),
				principalWant{scope: []string{}, agentScope: []string{}, effective: sorted()}),
			keyPrincipalCase("an agent's key whose stored scope is damaged: "+name,
				bearerSpec{agent: agentOne, agentScopes: list(scope.DefaultSession).JSON()}.withStoredScope(text),
				principalWant{
					agentID: agentOne, scope: []string{}, agentScope: []string{scope.DefaultSession}, effective: sorted(),
				}),
			keyPrincipalCase("an agent's key whose agent scopes are damaged: "+name,
				bearerSpec{scope: list(scope.DefaultSession), agent: agentOne, agentScopes: text},
				principalWant{
					agentID: agentOne, scope: []string{scope.DefaultSession}, agentScope: []string{}, effective: sorted(),
				}),
		)
	}

	return cases
}

// TestPrincipalIsTheStoredRow: who the caller is comes from the rows the store
// returned for the credential, read now, and the scope lists are the stored
// ones exactly as written plus their intersection. A damaged stored list reads
// as empty and grants nothing.
func TestPrincipalIsTheStoredRow(t *testing.T) {
	t.Parallel()

	names := map[string]bool{}

	for _, test := range slices.Concat(
		userPrincipalCases(), agentPrincipalCases(), listPrincipalCases(), damagedPrincipalCases(),
	) {
		if names[test.name] {
			t.Fatalf("two cases are named %q", test.name)
		}

		names[test.name] = true

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			presented, want := test.present(r)

			// A sandboxed agent reaches only a route that opted in.
			path := pathMe
			if want.sandboxID != "" {
				path = pathMeInSandbox
			}

			rec := r.serveWith(r.standardRoutes(), path, presented.headers, presented.cookies)
			if rec.Code != http.StatusOK || len(r.handled) != 1 {
				t.Fatalf("status = %d, ran %d times: %s", rec.Code, len(r.handled), rec.Body)
			}

			checkPrincipal(t, r.handled[0].Principal, want)

			if len(r.creds.calls) != 1 {
				t.Errorf("store read = %v, want one read", r.creds.calls)
			}
		})
	}
}

// TestRoleIsReadLive: the role is the account's now. A demotion takes effect on
// the next request, and a promotion too, with the same token: nothing about the
// role is in the token, so none can promote itself, and an admin scope on a
// member's key grants nothing until the account is promoted.
func TestRoleIsReadLive(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	issued := r.sessionFor(roleMember)

	rec := r.serve(r.standardRoutes(), request{target: pathAdmin, cookies: []*http.Cookie{sessionCookie(issued)}})
	wantFailure(t, r, rec, http.StatusForbidden, bodyForbidden, auth.CodeForbidden, nil)

	// The same token, when the account is later promoted, is an administrator
	// without a new token.
	r.setSession(issued, func(row *store.ActiveSession) { row.Role = auth.RoleAdmin })

	rec = r.serve(r.standardRoutes(), request{target: pathAdmin, cookies: []*http.Cookie{sessionCookie(issued)}})
	if rec.Code != http.StatusOK {
		t.Errorf("after promotion: status = %d, want 200", rec.Code)
	}

	r.setSession(issued, func(row *store.ActiveSession) { row.Role = roleMember })

	rec = r.serve(r.standardRoutes(), request{target: pathAdmin, cookies: []*http.Cookie{sessionCookie(issued)}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("after demotion: status = %d, want 403", rec.Code)
	}
}

// TestNoneRoutesNeverTouchTheCredential: a None route does not read the cookie,
// the configuration or the store, and its caller has no principal.
func TestNoneRoutesNeverTouchTheCredential(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	rec := r.get(pathPublic, sessionCookie(r.session()))
	if rec.Code != http.StatusOK || rec.Body.String() != bodyOK {
		t.Fatalf("response = %d %q", rec.Code, rec.Body)
	}

	if len(r.creds.calls) != 0 || r.envReads != 0 {
		t.Errorf("store read %d times and configuration %d times, want neither", len(r.creds.calls), r.envReads)
	}

	got := r.handled[0].Principal
	if got.UserID != "" || got.SecretID != "" || got.Authority().Effective().Len() != 0 || got.Scope != nil {
		t.Errorf("principal = %+v, want none", got)
	}
}

// TestUnauthenticatedIsTheOneAnswer is the exported answer features use when
// they learn mid-request that the session is gone.
func TestUnauthenticatedIsTheOneAnswer(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]error{"with a cause": errRevoked, "without one": nil} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			failure, found := errors.AsType[*apierr.Error](auth.Unauthenticated(in))
			if !found {
				t.Fatal("not an *apierr.Error")
			}

			if failure.Kind != apierr.Unauthorized || failure.Code != "unauthenticated" ||
				failure.Description != "not signed in" || failure.Data != nil {
				t.Errorf("error = %+v, want Unauthorized unauthenticated %q", failure, "not signed in")
			}

			if failure.Kind.Status() != http.StatusUnauthorized {
				t.Errorf("status = %d", failure.Kind.Status())
			}

			if in != nil && !errors.Is(failure, in) {
				t.Error("the cause is not kept for the log")
			}
		})
	}
}

// TestPlatformRole: the role a store call compares the caller's own with, to give
// the platform administrator's override, is the platform role for every credential
// but an OAuth grant, whose user's role (even an administrator's) never carries the
// override: the grant is asked as the empty role, which no account has.
func TestPlatformRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		kind string
		role string
		want string
	}{
		{"a session of an administrator", auth.KindSession, auth.RoleAdmin, auth.RoleAdmin},
		{"a session of a member", auth.KindSession, roleMember, auth.RoleAdmin},
		{"an API key of an administrator", auth.KindAPIKey, auth.RoleAdmin, auth.RoleAdmin},
		{"an API key of a member", auth.KindAPIKey, roleMember, auth.RoleAdmin},
		{"a grant of an administrator", auth.KindGrant, auth.RoleAdmin, ""},
		{"a grant of a member", auth.KindGrant, roleMember, ""},
		{"a grant of no role", auth.KindGrant, "", ""},
		{"no kind", "", auth.RoleAdmin, auth.RoleAdmin},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := (auth.Principal{Kind: test.kind, Role: test.role}).PlatformRole(); got != test.want {
				t.Errorf("PlatformRole() = %q, want %q", got, test.want)
			}
		})
	}
}
