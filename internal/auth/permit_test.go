//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"slices"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// permitCase is the inputs of one request and what each question about them
// must answer.
type permitCase struct {
	name string
	// who is the Authority: a credential's list, the agent's, and the role.
	who auth.Authority
	// needed is the route's scope, and want what Permits answers for it.
	needed scope.Scope
	want   auth.Verdict
}

// sessionAuthority is a session of a user with role: default:session, no agent.
func asSession(role string) auth.Authority {
	return auth.Authority{Credential: auth.SessionScope(), Agent: nil, AgentActing: false, Role: role}
}

// keyAuthority is a user's own API key (no agent) of a user with role.
func asKey(role string, held ...string) auth.Authority {
	return auth.Authority{Credential: list(held...), Agent: nil, AgentActing: false, Role: role}
}

// agentAuthority is an agent's API key: the key's list, narrowed by the
// agent's.
func asAgent(role string, key, agent scope.List) auth.Authority {
	return auth.Authority{Credential: key, Agent: agent, AgentActing: true, Role: role}
}

// permitCases is the table behind Permits, Effective and Principal.Authority.
// Each case names the layers that decide it.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func permitCases() []permitCase {
	const (
		admin  = auth.RoleAdmin
		member = roleMember
	)

	return []permitCase{
		// A requirement of none is met by anything, even nothing.
		{"no scope needed: a session", asSession(member), "", auth.Permitted},
		{"no scope needed: an empty key", asKey(member), "", auth.Permitted},
		{
			"no scope needed: an agent with empty lists",
			asAgent(member, list(), list()), "", auth.Permitted,
		},
		{"no scope needed: the zero authority", auth.Authority{}, "", auth.Permitted},

		// Sessions are default:session, limited only by the role.
		{"session: a member's own scope", asSession(member), scope.AgentRead, auth.Permitted},
		{
			"session: a member's non-admin scope that is not in default:user",
			asSession(member), scope.MemberRevoke, auth.Permitted,
		},
		{"session: a member and an admin scope", asSession(member), scope.UserRead, auth.NeedsAdmin},
		{"session: an admin and an admin scope", asSession(admin), scope.UserRead, auth.Permitted},
		{"session: an admin and an ordinary scope", asSession(admin), scope.KeyCreate, auth.Permitted},
		{"session: an unrecognised role is not an admin", asSession("root"), scope.UserRead, auth.NeedsAdmin},
		{"session: the role is case sensitive", asSession("Admin"), scope.UserRead, auth.NeedsAdmin},
		{"session: no role at all is not an admin", asSession(""), scope.UserRead, auth.NeedsAdmin},

		// A user's own key: its list only.
		{"user key: a listed scope", asKey(member, "agent:read"), scope.AgentRead, auth.Permitted},
		{"user key: an unlisted scope", asKey(member, "agent:read"), scope.AgentCreate, auth.LacksScope},
		{"user key: an empty list holds nothing", asKey(member), scope.AgentRead, auth.LacksScope},
		{
			"user key: default:user holds a non-admin scope",
			asKey(member, scope.DefaultUser), scope.AgentCreate, auth.Permitted,
		},
		{
			"user key: default:user leaves out member:revoke",
			asKey(member, scope.DefaultUser), scope.MemberRevoke, auth.LacksScope,
		},
		{
			"user key: member:revoke can be named",
			asKey(member, scope.DefaultUser, "member:revoke"), scope.MemberRevoke, auth.Permitted,
		},
		{
			"user key: default:agent is a small bundle",
			asKey(member, scope.DefaultAgent), scope.AgentRead, auth.Permitted,
		},
		{
			"user key: default:agent does not hold agent:create",
			asKey(member, scope.DefaultAgent), scope.AgentCreate, auth.LacksScope,
		},
		{
			"user key: default:session holds every scope",
			asKey(member, scope.DefaultSession), scope.SandboxRevoke, auth.Permitted,
		},

		// The role is judged before the list: a member is told about the role
		// whether or not the key names the admin scope, and an admin is told
		// about the scope.
		{"admin scope: a member whose key names it", asKey(member, "user:read"), scope.UserRead, auth.NeedsAdmin},
		{
			"admin scope: a member whose key names every scope",
			asKey(member, scope.DefaultSession), scope.UserRead, auth.NeedsAdmin,
		},
		{"admin scope: a member whose key names none", asKey(member), scope.UserRead, auth.NeedsAdmin},
		{"admin scope: an admin whose key names it", asKey(admin, "user:read"), scope.UserRead, auth.Permitted},
		{"admin scope: an admin whose key lacks it", asKey(admin, "agent:read"), scope.UserRead, auth.LacksScope},
		{
			"admin scope: an admin on default:user, which has none",
			asKey(admin, scope.DefaultUser), scope.UserRead, auth.LacksScope,
		},
		{
			"admin scope: an admin on default:session",
			asKey(admin, scope.DefaultSession), scope.InvitationCreate, auth.Permitted,
		},

		// An agent: the key's list narrowed by the agent's.
		{
			"agent key: in both lists",
			asAgent(member, list("agent:read"), list("agent:read")), scope.AgentRead, auth.Permitted,
		},
		{
			"agent key: in the key, not in the agent",
			asAgent(member, list("agent:read", "agent:create"), list("agent:read")), scope.AgentCreate, auth.LacksScope,
		},
		{
			"agent key: in the agent, not in the key",
			asAgent(member, list("agent:read"), list("agent:read", "agent:create")), scope.AgentCreate, auth.LacksScope,
		},
		{
			"agent key: an empty agent list narrows everything away",
			asAgent(member, list(scope.DefaultSession), list()), scope.AgentRead, auth.LacksScope,
		},
		{
			"agent key: an empty key list holds nothing whatever the agent holds",
			asAgent(member, list(), list(scope.DefaultSession)), scope.AgentRead, auth.LacksScope,
		},
		{
			"agent key: an agent that is not acting is not consulted",
			auth.Authority{Credential: list("agent:read"), Agent: list(), AgentActing: false, Role: member},
			scope.AgentRead, auth.Permitted,
		},
		{
			"agent key: the key is narrower than the agent",
			asAgent(member, list("key:read"), list(scope.DefaultUser)), scope.KeyCreate, auth.LacksScope,
		},
		{
			"agent key: the agent is narrower than the key",
			asAgent(member, list(scope.DefaultUser), list(scope.DefaultAgent)), scope.KeyCreate, auth.LacksScope,
		},
		{
			"agent key: the agent is narrower than the key, and the scope is the agent's",
			asAgent(member, list(scope.DefaultUser), list(scope.DefaultAgent)), scope.AgentRead, auth.Permitted,
		},
		{
			"agent key: bundles on both sides expand and intersect",
			asAgent(member, list(scope.DefaultUser), list(scope.DefaultUser)), scope.KeyCreate, auth.Permitted,
		},
		{
			"agent key: a bundle on one side and the scope named on the other",
			asAgent(member, list(scope.DefaultUser), list("key:create")), scope.KeyCreate, auth.Permitted,
		},
		{
			"agent key: a member's agent cannot reach an admin scope on every scope",
			asAgent(member, list(scope.DefaultSession), list(scope.DefaultSession)), scope.UserRead, auth.NeedsAdmin,
		},
		{
			"agent key: an admin's agent with both lists naming the admin scope",
			asAgent(admin, list("user:read"), list("user:read")), scope.UserRead, auth.Permitted,
		},
		{
			"agent key: an admin's agent whose agent list lacks the admin scope",
			asAgent(admin, list(scope.DefaultSession), list(scope.DefaultUser)), scope.UserRead, auth.LacksScope,
		},

		// Names the code does not know grant nothing, and never turn into
		// access by being in both lists.
		{
			"unknown names: only unknown names",
			asKey(member, "nope:read", "default:nothing"), scope.AgentRead, auth.LacksScope,
		},
		{
			"unknown names: beside a known one",
			asKey(member, "nope:read", "agent:read"), scope.AgentRead, auth.Permitted,
		},
		{
			"unknown names: the same unknown name in the key and the agent",
			asAgent(member, list("nope:read"), list("nope:read")), scope.AgentRead, auth.LacksScope,
		},
		{
			"unknown names: an unknown name beside a known one on each side",
			asAgent(member, list("nope:read", "agent:read"), list("agent:read", "also:gone")), scope.AgentRead, auth.Permitted,
		},
		{
			"unknown names: a scope spelled as another case",
			asKey(member, "Agent:Read"), scope.AgentRead, auth.LacksScope,
		},
		{"unknown names: a scope with whitespace", asKey(member, " agent:read"), scope.AgentRead, auth.LacksScope},
		{"unknown names: the empty name", asKey(member, ""), scope.AgentRead, auth.LacksScope},
		{
			"unknown required scope is not granted by a bundle",
			asKey(member, scope.DefaultSession), "nope:read", auth.LacksScope,
		},
		{"unknown required scope is not an admin scope", asSession(member), "nope:read", auth.LacksScope},
	}
}

// TestPermits is the one function that combines the role, the credential's
// list and the agent's.
func TestPermits(t *testing.T) {
	t.Parallel()

	for _, test := range permitCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.who.Permits(test.needed); got != test.want {
				t.Errorf("Permits(%q) = %v, want %v", test.needed, got, test.want)
			}
		})
	}
}

// TestPermitsAgreesWithEffective: outside the role gate, Permits is exactly
// membership in Effective, so the two cannot drift apart. The role never
// appears in Effective: it is the same set for a member and an admin.
func TestPermitsAgreesWithEffective(t *testing.T) {
	t.Parallel()

	for _, test := range permitCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			effective := test.who.Effective()

			asAdmin := test.who
			asAdmin.Role = auth.RoleAdmin

			if !slices.Equal(effective.Sorted(), asAdmin.Effective().Sorted()) {
				t.Errorf("Effective depends on the role: %v vs %v", effective.Sorted(), asAdmin.Effective().Sorted())
			}

			if test.needed == "" {
				return
			}

			// As an administrator no role gate remains, so the verdict is
			// exactly whether the lists hold the scope.
			wantAdmin := auth.LacksScope
			if effective.Has(test.needed) {
				wantAdmin = auth.Permitted
			}

			if got := asAdmin.Permits(test.needed); got != wantAdmin {
				t.Errorf("as an admin Permits(%q) = %v, want %v from Effective %v",
					test.needed, got, wantAdmin, effective.Sorted())
			}

			// A member never gets more than an administrator with the same
			// lists: the verdict is the same or the role gate's.
			if member := test.who.Permits(test.needed); member == auth.Permitted && wantAdmin != auth.Permitted {
				t.Errorf("Permits(%q) = Permitted for a role that is not weaker than an admin", test.needed)
			}
		})
	}
}

// TestPrincipalAuthority: a Principal carries the inputs, and Authority reads
// them as they are, so the one function is fed the stored lists, the role, and
// whether an agent is acting, and nothing else.
func TestPrincipalAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		who  auth.Principal
		want auth.Authority
	}{
		{
			"a session",
			auth.Principal{Role: roleMember, Kind: auth.KindSession, Scope: auth.SessionScope(), AgentScope: list()},
			auth.Authority{Credential: auth.SessionScope(), Agent: list(), AgentActing: false, Role: roleMember},
		},
		{
			"a user's key",
			auth.Principal{Role: auth.RoleAdmin, Kind: auth.KindAPIKey, Scope: list("key:read"), AgentScope: list()},
			auth.Authority{Credential: list("key:read"), Agent: list(), AgentActing: false, Role: auth.RoleAdmin},
		},
		{
			"an agent's key",
			auth.Principal{
				Role: roleMember, Kind: auth.KindAPIKey, AgentID: agentOne,
				Scope: list("key:read"), AgentScope: list("agent:read"),
			},
			auth.Authority{Credential: list("key:read"), Agent: list("agent:read"), AgentActing: true, Role: roleMember},
		},
		{
			"an agent with an empty list is still an agent",
			auth.Principal{
				Role: roleMember, Kind: auth.KindAPIKey, AgentID: agentOne, Scope: list("key:read"), AgentScope: list(),
			},
			auth.Authority{Credential: list("key:read"), Agent: list(), AgentActing: true, Role: roleMember},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := test.who.Authority()
			if got.Role != test.want.Role || got.AgentActing != test.want.AgentActing ||
				!slices.Equal(got.Credential, test.want.Credential) || !slices.Equal(got.Agent, test.want.Agent) {
				t.Errorf("Authority() = %+v, want %+v", got, test.want)
			}
		})
	}
}

// refusalOf is the code and description Access answers for each verdict, which
// clients match on. Permitted has none: the scope step passes, and only the
// later requirements (session, agents) can still refuse.
func refusalOf(v auth.Verdict, needed scope.Scope) (string, string) {
	switch v {
	case auth.NeedsAdmin:
		return auth.CodeForbidden, "administrator access is required"
	case auth.LacksScope:
		return auth.CodeInsufficientScope, "this credential lacks the scope " + string(needed)
	case auth.Permitted:
		return auth.CodeForbidden, "a signed-in session is required"
	}

	return "", ""
}

// TestAccessUsesPermits drives the verdict into the refusal a caller sees, for
// the whole table: NeedsAdmin is the role's 403 and LacksScope the scope's,
// with the codes and messages the clients match on. The route also requires a
// session, which the key presented is not, so a Permitted scope is refused by
// that requirement and by nothing earlier.
func TestAccessUsesPermits(t *testing.T) {
	t.Parallel()

	for _, test := range permitCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			who := auth.Principal{
				Role: test.who.Role, Kind: auth.KindAPIKey, AgentID: "",
				Scope: test.who.Credential, AgentScope: test.who.Agent,
			}
			if test.who.AgentActing {
				who.AgentID = agentOne
			}

			failure := apierr.As(auth.CheckAccess(auth.Access{Scope: test.needed}.Sessions().WithoutAgents().InSandbox(), who))
			if failure == nil {
				t.Fatal("the key was not refused")
			}

			wantCode, wantText := refusalOf(test.want, test.needed)
			if failure.Kind != apierr.Forbidden || failure.Code != wantCode || failure.Description != wantText {
				t.Errorf("refusal = %v %s %q, want 403 %s %q", failure.Kind, failure.Code, failure.Description, wantCode, wantText)
			}
		})
	}
}

// TestMayIssue is the rule that a credential an agent issues may not exceed the
// issuing credential's list: a literal comparison of what was written, so a
// bundle is passed on whole or not at all.
func TestMayIssue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		issuer scope.List
		agent  scope.List
		wanted scope.List
		want   bool
	}{
		{"the empty list from anything", list("agent:read"), list(), list(), true},
		{"the empty list from nothing", list(), list(), list(), true},
		{"anything from nothing", list(), list(scope.DefaultSession), list("agent:read"), false},
		{"the same list", list("agent:read", "key:read"), list(), list("agent:read", "key:read"), true},
		{"a subset", list("agent:read", "key:read"), list(), list("key:read"), true},
		{"the same in another order", list("agent:read", "key:read"), list(), list("key:read", "agent:read"), true},
		{"an entry the issuer lacks", list("agent:read"), list(), list("agent:read", "key:read"), false},
		{"a bundle from its members", list("agent:read"), list(), list(scope.DefaultAgent), false},
		{"one member from inside a bundle", list(scope.DefaultAgent), list(), list("agent:read"), false},
		{"a bundle from itself", list(scope.DefaultUser), list(), list(scope.DefaultUser), true},
		{"a bigger bundle from a smaller", list(scope.DefaultAgent), list(), list(scope.DefaultUser), false},
		{
			"the session bundle from the user bundle",
			list(scope.DefaultUser), list(), list(scope.DefaultSession), false,
		},
		{"an unknown name the issuer also lists", list("nope:read"), list(), list("nope:read"), true},
		{"an unknown name the issuer lacks", list("agent:read"), list(), list("nope:read"), false},
		{
			"the issuing agent's list is not what is compared",
			list("agent:read"), list(scope.DefaultSession), list("key:read"), false,
		},
		{
			"a list the agent lacks but the credential holds",
			list("key:read"), list("agent:read"), list("key:read"), true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			who := auth.Principal{
				Role: roleMember, Kind: auth.KindAPIKey, AgentID: agentOne, Scope: test.issuer, AgentScope: test.agent,
			}

			if got := who.MayIssue(test.wanted); got != test.want {
				t.Errorf("MayIssue(%v) with %v = %v, want %v", test.wanted, test.issuer, got, test.want)
			}
		})
	}
}

// TestMayIssueNeverExceedsTheIssuer is the property the rule exists for: a list
// that may be issued never expands to more than the issuer's own list does.
func TestMayIssueNeverExceedsTheIssuer(t *testing.T) {
	t.Parallel()

	names := []string{
		scope.DefaultSession, scope.DefaultUser, scope.DefaultAgent, "agent:read", "agent:create", "key:read",
		"member:revoke", "user:read", "nope:read",
	}

	lists := make([]scope.List, 0, 1<<len(names))

	for mask := range 1 << len(names) {
		var held scope.List

		for i, name := range names {
			if mask&(1<<i) != 0 {
				held = append(held, name)
			}
		}

		lists = append(lists, held)
	}

	// Sampling every pair of 512 lists would be 262144 cases; every issuer
	// against a spread of wanted lists covers each name in each position.
	for _, issuer := range lists {
		who := auth.Principal{Scope: issuer}
		held := issuer.Expand()

		for step := 0; step < len(lists); step += 37 {
			wanted := lists[step]
			if !who.MayIssue(wanted) {
				continue
			}

			for _, s := range wanted.Expand().Sorted() {
				if !held.Has(s) {
					t.Fatalf("%v may issue %v, which expands to %s that the issuer's list does not hold", issuer, wanted, s)
				}
			}
		}
	}
}

// TestMayIssueWithAgent is the rule for a credential that issues a list of the
// request's choosing: the entries must be in the credential's list AND in the
// acting agent's, as written. The agent's list is the primary one, so a token
// wider than its agent is cut to the agent, and an agent wider than its token to
// the token.
func TestMayIssueWithAgent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		agent  string
		token  scope.List
		held   scope.List
		wanted scope.List
		want   bool
		common scope.List
	}{
		{"within both", "a1", list("agent:read", "org:read"), list("agent:read", "org:read", "key:read"),
			list("agent:read"), true, list("agent:read", "org:read")},
		{"the agent is narrower than the token", "a1", list("agent:read", "org:read"), list("agent:read"),
			list("org:read"), false, list("agent:read")},
		{"the token is narrower than the agent", "a1", list("agent:read"), list("agent:read", "org:read"),
			list("org:read"), false, list("agent:read")},
		{"disjoint lists allow only nothing", "a1", list("agent:read"), list("org:read"),
			list("agent:read"), false, list()},
		{"disjoint lists allow the empty list", "a1", list("agent:read"), list("org:read"), list(), true, list()},
		{"the agent's list is empty", "a1", list("agent:read"), list(), list("agent:read"), false, list()},
		{"the agent's list is empty and so is the request", "a1", list("agent:read"), list(), list(), true, list()},
		{"the same lists, the request's order", "a1", list("agent:read", "org:read"), list("org:read", "agent:read"),
			list("org:read", "agent:read"), true, list("agent:read", "org:read")},
		{"a bundle is not an entry of a list of its members", "a1", list(scope.DefaultAgent), list("agent:read"),
			list(scope.DefaultAgent), false, list()},
		{"a bundle both hold, whole", "a1", list(scope.DefaultAgent), list(scope.DefaultAgent),
			list(scope.DefaultAgent), true, list(scope.DefaultAgent)},
		{"no agent acting is the credential's list alone", "", list("agent:read", "org:read"), list(),
			list("org:read"), true, list("agent:read", "org:read")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			who := auth.Principal{Kind: auth.KindGrant, AgentID: test.agent, Scope: test.token, AgentScope: test.held}

			if got := who.MayIssueWithAgent(test.wanted); got != test.want {
				t.Errorf("MayIssueWithAgent(%v) = %v, want %v", test.wanted, got, test.want)
			}

			if got := who.Common(); !slices.Equal(got, test.common) {
				t.Errorf("Common() = %v, want %v", got, test.common)
			}

			// The default is always allowed, and nothing it holds is beyond the principal.
			if !who.MayIssueWithAgent(who.Common()) {
				t.Errorf("the default %v is refused", who.Common())
			}
		})
	}
}

// TestMayIssueWithAgentNeverExceedsTheEffectiveScopes is the property the rule
// exists for: a list that may be issued, put through the credential and the agent
// as the request will, expands to nothing that Effective does not allow the issuer.
func TestMayIssueWithAgentNeverExceedsTheEffectiveScopes(t *testing.T) {
	t.Parallel()

	names := []string{scope.DefaultAgent, "agent:read", "agent:create", "org:read", "sandbox:create"}

	lists := make([]scope.List, 0, 1<<len(names))

	for mask := range 1 << len(names) {
		var held scope.List

		for i, name := range names {
			if mask&(1<<i) != 0 {
				held = append(held, name)
			}
		}

		lists = append(lists, held)
	}

	for _, token := range lists {
		for _, held := range lists {
			who := auth.Principal{AgentID: "a1", Scope: token, AgentScope: held}
			effective := who.Authority().Effective()

			for _, wanted := range lists {
				if !who.MayIssueWithAgent(wanted) {
					continue
				}

				for _, s := range wanted.Expand().Sorted() {
					if !effective.Has(s) {
						t.Fatalf("token %v, agent %v may issue %v, which holds %s beyond the effective scopes", token, held, wanted, s)
					}
				}
			}
		}
	}
}
