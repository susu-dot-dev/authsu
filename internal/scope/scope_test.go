//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package scope_test

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/scope"
)

// namePattern is the grammar of a scope or bundle name: "a:b", both halves
// lower-case words joined by underscores.
var namePattern = regexp.MustCompile(`^[a-z]+(_[a-z]+)*:[a-z]+(_[a-z]+)*$`)

// actions are the verbs a scope may end in. A new one needs a reason.
func actions() []string { return []string{"read", "create", "update", "revoke"} }

func TestEveryNameHasTheScopeGrammar(t *testing.T) {
	t.Parallel()

	names := make([]string, 0, len(scope.Scopes())+3)

	for _, s := range scope.Scopes() {
		names = append(names, string(s))
	}

	names = append(names, scope.DefaultSession, scope.DefaultUser, scope.DefaultAgent)

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if !namePattern.MatchString(name) {
				t.Errorf("%q does not match %s", name, namePattern)
			}

			if len(name) > scope.MaxNameBytes {
				t.Errorf("%q is %d bytes, above MaxNameBytes %d", name, len(name), scope.MaxNameBytes)
			}
		})
	}
}

func TestScopesUseTheFixedActionsAndAreNotDefault(t *testing.T) {
	t.Parallel()

	for _, s := range scope.Scopes() {
		resource, action, _ := strings.Cut(string(s), ":")

		if resource == "default" {
			t.Errorf("%s uses the reserved resource default", s)
		}

		if !slices.Contains(actions(), action) {
			t.Errorf("%s ends in %q, which is not one of %v", s, action, actions())
		}
	}
}

func TestScopesAreUniqueAndBundlesDoNotShareTheirNames(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}

	for _, s := range scope.Scopes() {
		if seen[string(s)] {
			t.Errorf("%s is defined twice", s)
		}

		seen[string(s)] = true
	}

	for _, name := range []string{scope.DefaultSession, scope.DefaultUser, scope.DefaultAgent} {
		if seen[name] {
			t.Errorf("bundle %s is also a scope", name)
		}

		if _, ok := scope.Bundle(name); !ok {
			t.Errorf("%s is not a bundle", name)
		}

		if !strings.HasPrefix(name, "default:") {
			t.Errorf("bundle %s is not named default:<name>", name)
		}
	}
}

// TestBundlesAreComplete is the guard that a newly added scope cannot be left
// out of the bundles that must hold it.
func TestBundlesAreComplete(t *testing.T) {
	t.Parallel()

	all := scope.Scopes()

	// nonAdmin is what default:user holds: every scope that is not an admin scope,
	// except the one that revokes other people's accounts, which a key must be
	// given by naming it (default:session holds it).
	var nonAdmin []scope.Scope

	for _, s := range all {
		if !scope.IsAdmin(s) && s != scope.MemberRevoke {
			nonAdmin = append(nonAdmin, s)
		}
	}

	tests := []struct {
		bundle string
		want   []scope.Scope
	}{
		{scope.DefaultSession, all},
		{scope.DefaultUser, nonAdmin},
	}

	for _, test := range tests {
		t.Run(test.bundle, func(t *testing.T) {
			t.Parallel()

			got, ok := scope.Bundle(test.bundle)
			if !ok {
				t.Fatalf("%s is not a bundle", test.bundle)
			}

			sortScopes(got)

			want := slices.Clone(test.want)
			sortScopes(want)

			if !slices.Equal(got, want) {
				t.Errorf("%s = %v, want %v", test.bundle, got, want)
			}
		})
	}
}

func TestDefaultAgentGrantsNoAdminScope(t *testing.T) {
	t.Parallel()

	members, _ := scope.Bundle(scope.DefaultAgent)

	for _, s := range members {
		if scope.IsAdmin(s) {
			t.Errorf("default:agent holds the admin scope %s", s)
		}
	}
}

// TestGrantScopesAreForPeopleNotAgents: an agent never holds the scopes that
// read or end OAuth grants, whatever default:agent grows to hold, and a login
// session and a user's own keys do.
func TestGrantScopesAreForPeopleNotAgents(t *testing.T) {
	t.Parallel()

	for _, grant := range []scope.Scope{scope.GrantRead, scope.GrantRevoke} {
		for bundle, want := range map[string]bool{
			scope.DefaultSession: true,
			scope.DefaultUser:    true,
			scope.DefaultAgent:   false,
		} {
			members, _ := scope.Bundle(bundle)

			if got := slices.Contains(members, grant); got != want {
				t.Errorf("%s holds %s = %v, want %v", bundle, grant, got, want)
			}
		}
	}
}

// TestOrganizationScopes: each organization scope exists, is not an admin scope
// (who may look after an organization is decided in the store's write, with the
// platform administrator's override), and is held by a login session, never by
// default:agent, whatever it grows to hold, and by a user's own keys except for
// member:revoke, which revokes other people's accounts and so must be named.
func TestOrganizationScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// user is whether default:user holds it.
		user bool
	}{
		{"org:read", true},
		{"org:update", true},
		{"sandbox:create", true},
		{"sandbox:revoke", true},
		{"member:read", true},
		{"member:update", true},
		{"member:revoke", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !scope.Known(tt.name) || !slices.Contains(scope.Scopes(), scope.Scope(tt.name)) {
				t.Fatalf("%s is not a scope", tt.name)
			}

			if scope.IsAdmin(scope.Scope(tt.name)) {
				t.Errorf("%s is an admin scope", tt.name)
			}

			for bundle, want := range map[string]bool{
				scope.DefaultSession: true, scope.DefaultUser: tt.user, scope.DefaultAgent: false,
			} {
				members, _ := scope.Bundle(bundle)

				if got := slices.Contains(members, scope.Scope(tt.name)); got != want {
					t.Errorf("%s holds %s = %v, want %v", bundle, tt.name, got, want)
				}
			}
		})
	}
}

// TestRevokingOtherAccountsNeedsNaming: the scopes that end other people's
// accounts or hand out places for new ones (user:revoke, member:revoke,
// invitation:create) are held by a login session alone: a user's default key does
// not hold member:revoke (and no admin scope at all), and an agent holds none.
func TestRevokingOtherAccountsNeedsNaming(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scope                 scope.Scope
		session, user, agents bool
	}{
		{scope.UserRevoke, true, false, false},
		{scope.MemberRevoke, true, false, false},
		{scope.InvitationCreate, true, false, false},
		{scope.UserRead, true, false, false},
		{scope.MemberUpdate, true, true, false},
		{scope.SandboxRevoke, true, true, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			t.Parallel()

			for bundle, want := range map[string]bool{
				scope.DefaultSession: tt.session, scope.DefaultUser: tt.user, scope.DefaultAgent: tt.agents,
			} {
				members, _ := scope.Bundle(bundle)

				if got := slices.Contains(members, tt.scope); got != want {
					t.Errorf("%s holds %s = %v, want %v", bundle, tt.scope, got, want)
				}
			}

			// Naming the scope grants it: a key that lists it holds it, and
			// the default bundle alone does not.
			if !(scope.List{string(tt.scope)}).Expand().Has(tt.scope) {
				t.Errorf("a key naming %s does not hold it", tt.scope)
			}

			if got := (scope.List{scope.DefaultUser}).Expand().Has(tt.scope); got != tt.user {
				t.Errorf("a default:user key holds %s = %v, want %v", tt.scope, got, tt.user)
			}
		})
	}
}

func TestBundlesDoNotContainBundles(t *testing.T) {
	t.Parallel()

	for _, name := range []string{scope.DefaultSession, scope.DefaultUser, scope.DefaultAgent} {
		members, _ := scope.Bundle(name)

		for _, s := range members {
			if _, bundle := scope.Bundle(string(s)); bundle {
				t.Errorf("%s contains the bundle %s", name, s)
			}
		}
	}
}

func TestIsAdmin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope scope.Scope
		want  bool
	}{
		{"invitation create", scope.InvitationCreate, true},
		{"user read", scope.UserRead, true},
		{"user revoke", scope.UserRevoke, true},
		{"agent create", scope.AgentCreate, false},
		{"key revoke", scope.KeyRevoke, false},
		{"grant read", scope.GrantRead, false},
		{"grant revoke", scope.GrantRevoke, false},
		{"org read", scope.OrgRead, false},
		{"sandbox create", scope.SandboxCreate, false},
		{"org update", scope.OrgUpdate, false},
		{"sandbox revoke", scope.SandboxRevoke, false},
		{"member read", scope.MemberRead, false},
		{"member update", scope.MemberUpdate, false},
		{"member revoke", scope.MemberRevoke, false},
		{"unknown scope", "nope:read", false},
		{"a bundle is not an admin scope", scope.DefaultSession, false},
		{"empty", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := scope.IsAdmin(test.scope); got != test.want {
				t.Errorf("IsAdmin(%q) = %v, want %v", test.scope, got, test.want)
			}
		})
	}
}

func TestKnown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{"agent:read", true},
		{"user:revoke", true},
		{"grant:read", true},
		{"grant:revoke", true},
		{"org:read", true},
		{"sandbox:create", true},
		{"org:update", true},
		{"sandbox:revoke", true},
		{"member:read", true},
		{"member:update", true},
		{"member:revoke", true},
		{"org:create", false},
		{"org:revoke", false},
		{"org:delete", false},
		{"sandbox:delete", false},
		{"member:create", false},
		{"orgs:read", false},
		{"default:user", true},
		{"default:session", true},
		{"default:agent", true},
		{"", false},
		{"all", false},
		{"agent", false},
		{"agent:", false},
		{":read", false},
		{"Agent:read", false},
		{"agent:read ", false},
		{" agent:read", false},
		{"agent:delete", false},
		{"default:admin", false},
		{"default:nope", false},
		{"agent:read\x00", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := scope.Known(test.name); got != test.want {
				t.Errorf("Known(%q) = %v, want %v", test.name, got, test.want)
			}
		})
	}
}

func TestScopesAndBundleReturnCopies(t *testing.T) {
	t.Parallel()

	first := scope.Scopes()
	first[0] = "tampered:read"

	if scope.Scopes()[0] == "tampered:read" {
		t.Error("Scopes returned the shared slice")
	}

	members, _ := scope.Bundle(scope.DefaultAgent)
	members[0] = "tampered:read"

	again, _ := scope.Bundle(scope.DefaultAgent)
	if again[0] == "tampered:read" {
		t.Error("Bundle returned the shared slice")
	}

	if _, ok := scope.Bundle("agent:read"); ok {
		t.Error("a scope is not a bundle")
	}
}

func TestNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        []string
		wantOK    bool
		wantIndex int
	}{
		{"empty", []string{}, true, -1},
		{"nil", nil, true, -1},
		{"scope", []string{"agent:read"}, true, -1},
		{"bundle and scope", []string{"default:agent", "agent:create"}, true, -1},
		{"unknown first", []string{"nope:read", "agent:read"}, false, 0},
		{"unknown last", []string{"agent:read", "agent:reed"}, false, 1},
		{"empty name", []string{"agent:read", ""}, false, 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			list, err := scope.Names(test.in).Get()
			if test.wantOK {
				checkNamesAccepted(t, test.in, list, err)

				return
			}

			checkNamesRefused(t, test.in, err, test.wantIndex)
		})
	}
}

// checkNamesAccepted holds that an accepted list is the input, unchanged.
func checkNamesAccepted(t *testing.T, in []string, list scope.List, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("Names(%v) error = %v, want none", in, err)
	}

	if !slices.Equal([]string(list), in) && len(in) > 0 {
		t.Errorf("Names changed the list: %v -> %v", in, list)
	}
}

// checkNamesRefused holds that a refusal says which entry was refused, and never
// repeats what the client wrote.
func checkNamesRefused(t *testing.T, in []string, err error, wantIndex int) {
	t.Helper()

	unknown, isUnknown := errors.AsType[scope.UnknownNameError](err)
	if !isUnknown || unknown.Index != wantIndex {
		t.Fatalf("Names(%v) error = %#v, want an UnknownNameError at index %d", in, err, wantIndex)
	}

	for _, name := range in {
		if name != "" && strings.Contains(err.Error(), name) {
			t.Errorf("error %q repeats the client's entry %q", err, name)
		}
	}
}

func TestNamesCopiesItsInput(t *testing.T) {
	t.Parallel()

	in := []string{"agent:read"}
	list, _ := scope.Names(in).Get()
	in[0] = "user:read"

	if list[0] != "agent:read" {
		t.Error("List shares the caller's slice")
	}
}

func TestListJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		list scope.List
		want string
	}{
		{"nil is the empty array", nil, "[]"},
		{"empty", scope.List{}, "[]"},
		{"one", scope.List{"agent:read"}, `["agent:read"]`},
		{
			"order and duplicates kept",
			scope.List{"user:read", "agent:read", "user:read"}, `["user:read","agent:read","user:read"]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.list.JSON(); got != test.want {
				t.Errorf("JSON() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestReadFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		stored string
		want   []string
	}{
		{"array", `["agent:read","default:agent"]`, []string{"agent:read", "default:agent"}},
		{"empty array", `[]`, []string{}},
		{"null", `null`, []string{}},
		{"empty text", ``, []string{}},
		{"old placeholder text", `default:agent`, []string{}},
		{"object", `{"a":1}`, []string{}},
		{"string", `"agent:read"`, []string{}},
		{"mixed types", `["agent:read", 1]`, []string{}},
		{"truncated", `["agent:read"`, []string{}},
		{"unknown names are kept for Expand to ignore", `["nope:read"]`, []string{"nope:read"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := scope.Read(test.stored)
			if got == nil || !slices.Equal([]string(got), test.want) {
				t.Errorf("Read(%q) = %#v, want %#v", test.stored, got, test.want)
			}
		})
	}
}

func TestReadRoundTripsJSON(t *testing.T) {
	t.Parallel()

	for _, list := range []scope.List{{}, {"agent:read"}, {"default:user", "agent:read"}, {"a\"b", "c\\d", "é"}} {
		if got := scope.Read(list.JSON()); !slices.Equal([]string(got), []string(list)) {
			t.Errorf("Read(JSON(%v)) = %v", list, got)
		}
	}
}

func TestClaim(t *testing.T) {
	t.Parallel()

	if got := scope.List(nil).Claim(); got == nil || len(got) != 0 {
		t.Errorf("nil list claim = %#v, want an empty non-nil slice", got)
	}

	list := scope.List{"agent:read"}
	claim := list.Claim()
	claim[0] = "tampered"

	if list[0] != "agent:read" {
		t.Error("Claim shares the list's storage")
	}
}

func TestExpand(t *testing.T) {
	t.Parallel()

	agentBundle, _ := scope.Bundle(scope.DefaultAgent)

	tests := []struct {
		name string
		list scope.List
		want []scope.Scope
	}{
		{"empty grants nothing", scope.List{}, nil},
		{"nil grants nothing", nil, nil},
		{"one scope", scope.List{"agent:create"}, []scope.Scope{scope.AgentCreate}},
		{"bundle", scope.List{scope.DefaultAgent}, agentBundle},
		{
			"bundle and scope",
			scope.List{scope.DefaultAgent, "agent:create"}, append(slices.Clone(agentBundle), scope.AgentCreate),
		},
		{"duplicates collapse", scope.List{"agent:create", "agent:create"}, []scope.Scope{scope.AgentCreate}},
		{"unknown name grants nothing", scope.List{"nope:read", "default:nope", "", "all"}, nil},
		{"unknown beside known", scope.List{"nope:read", "key:read"}, []scope.Scope{scope.KeyRead}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := test.list.Expand().Sorted()
			want := slices.Clone(test.want)
			sortScopes(want)

			if !slices.Equal(got, want) && (len(got) != 0 || len(want) != 0) {
				t.Errorf("Expand(%v) = %v, want %v", test.list, got, want)
			}
		})
	}
}

func TestSessionBundleExpandsToEveryScope(t *testing.T) {
	t.Parallel()

	set := scope.List{scope.DefaultSession}.Expand()

	for _, s := range scope.Scopes() {
		if !set.Has(s) {
			t.Errorf("default:session does not grant %s", s)
		}
	}

	if set.Len() != len(scope.Scopes()) {
		t.Errorf("default:session grants %d scopes, there are %d", set.Len(), len(scope.Scopes()))
	}
}

func TestSetIntersect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b scope.List
		want []scope.Scope
	}{
		{"both empty", scope.List{}, scope.List{}, nil},
		{"one empty", scope.List{scope.DefaultUser}, scope.List{}, nil},
		{"disjoint", scope.List{"agent:read"}, scope.List{"key:read"}, nil},
		{"overlap", scope.List{"agent:read", "key:read"}, scope.List{"key:read", "key:create"}, []scope.Scope{scope.KeyRead}},
		{"identical", scope.List{"key:read"}, scope.List{"key:read"}, []scope.Scope{scope.KeyRead}},
		{
			"bundle narrowed by scope",
			scope.List{scope.DefaultSession}, scope.List{"user:read"}, []scope.Scope{scope.UserRead},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			a, b := test.a.Expand(), test.b.Expand()
			got := a.Intersect(b).Sorted()
			reverse := b.Intersect(a).Sorted()

			if !slices.Equal(got, reverse) {
				t.Errorf("intersection is not symmetric: %v vs %v", got, reverse)
			}

			if len(got) != len(test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}

			for _, s := range got {
				if !a.Has(s) || !b.Has(s) {
					t.Errorf("%s is not in both inputs", s)
				}
			}
		})
	}
}

func TestZeroSetIsEmpty(t *testing.T) {
	t.Parallel()

	var zero scope.Set

	if zero.Has(scope.AgentRead) || zero.Len() != 0 || len(zero.Sorted()) != 0 {
		t.Error("the zero Set is not empty")
	}

	if got := zero.Intersect(scope.List{scope.DefaultSession}.Expand()); got.Len() != 0 {
		t.Errorf("zero intersect = %v", got.Sorted())
	}
}

func TestSubsetOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sub, of scope.List
		want    bool
	}{
		{"empty in empty", scope.List{}, scope.List{}, true},
		{"empty in anything", scope.List{}, scope.List{"agent:read"}, true},
		{"nil in nil", nil, nil, true},
		{"equal", scope.List{"default:agent"}, scope.List{"default:agent"}, true},
		{"one of two", scope.List{"agent:create"}, scope.List{"default:agent", "agent:create"}, true},
		{"both of two", scope.List{"agent:create", "default:agent"}, scope.List{"default:agent", "agent:create"}, true},
		{"order does not matter", scope.List{"b:x", "a:x"}, scope.List{"a:x", "b:x"}, true},
		{"not contained", scope.List{"key:read"}, scope.List{"default:agent"}, false},
		{"bundle member is not the bundle", scope.List{"agent:read"}, scope.List{"default:agent"}, false},
		{"bundle is not its members", scope.List{"default:agent"}, scope.List{"agent:read"}, false},
		{"nonempty in empty", scope.List{"agent:read"}, scope.List{}, false},
		{"one missing of two", scope.List{"agent:read", "key:read"}, scope.List{"agent:read"}, false},
		{"case sensitive", scope.List{"Agent:read"}, scope.List{"agent:read"}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.sub.SubsetOf(test.of); got != test.want {
				t.Errorf("%v.SubsetOf(%v) = %v, want %v", test.sub, test.of, got, test.want)
			}
		})
	}
}

// TestSubsetImpliesExpansionSubset is the property the agent-creates-agent rule
// rests on: a list contained in another, as written, expands to a subset of the
// other's expansion.
func TestSubsetImpliesExpansionSubset(t *testing.T) {
	t.Parallel()

	pool := []string{
		"default:agent", "default:user", "default:session", "agent:read", "key:read", "user:read", "nope:read",
	}

	for mask := range 1 << len(pool) {
		var parent scope.List

		for i, name := range pool {
			if mask&(1<<i) != 0 {
				parent = append(parent, name)
			}
		}

		for childMask := range 1 << len(pool) {
			var child scope.List

			for i, name := range pool {
				if childMask&(1<<i) != 0 {
					child = append(child, name)
				}
			}

			if !child.SubsetOf(parent) {
				continue
			}

			if got := child.Expand().Intersect(parent.Expand()); got.Len() != child.Expand().Len() {
				t.Fatalf("%v is a subset of %v but expands outside it", child, parent)
			}
		}
	}
}

func sortScopes(s []scope.Scope) { slices.Sort(s) }
