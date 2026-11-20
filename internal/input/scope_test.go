//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// scopeListCase is a list a client might send and whether it is accepted.
type scopeListCase struct {
	name string
	in   []string
	ok   bool
}

// scopeListCases are the lists ParseScopeList is held to.
func scopeListCases() []scopeListCase {
	tooMany := make([]string, input.MaxScopeEntries+1)
	for i := range tooMany {
		tooMany[i] = "agent:read"
	}

	return []scopeListCase{
		{"nil is the empty list", nil, true},
		{"empty list", []string{}, true},
		{"one scope", []string{"agent:read"}, true},
		{"one bundle", []string{"default:agent"}, true},
		{"session bundle", []string{"default:session"}, true},
		{"bundle and scope", []string{"default:agent", "agent:create"}, true},
		{"every scope", scopeNames(), true},
		{"admin scope is accepted (the role gates it)", []string{"invitation:create"}, true},
		{"order is kept", []string{"user:read", "agent:read"}, true},
		{"unknown scope", []string{"agent:reed"}, false},
		{"unknown resource", []string{"nope:read"}, false},
		{"unknown bundle", []string{"default:admin"}, false},
		{"all is not a name", []string{"all"}, false},
		{"star", []string{"*"}, false},
		{"empty name", []string{""}, false},
		{"known then empty", []string{"agent:read", ""}, false},
		{"unknown after known", []string{"agent:read", "agent:reed"}, false},
		{"upper case", []string{"Agent:read"}, false},
		{"trailing space", []string{"agent:read "}, false},
		{"leading space", []string{" agent:read"}, false},
		{"two names in one string", []string{"agent:read agent:create"}, false},
		{"comma joined", []string{"agent:read,agent:create"}, false},
		{"trailing newline", []string{"agent:read\n"}, false},
		{"NUL", []string{"agent:read\x00"}, false},
		{"NUL only", []string{"\x00"}, false},
		{"fullwidth colon", []string{"agent\uff1aread"}, false},
		{"invalid utf8", []string{"agent:\xff"}, false},
		{"repeated scope", []string{"agent:read", "agent:read"}, false},
		{"repeated bundle", []string{"default:agent", "default:agent"}, false},
		{"repeated after another", []string{"agent:read", "key:read", "agent:read"}, false},
		{"one over the entry bound", tooMany, false},
		{"huge name", []string{strings.Repeat("a", 1<<20)}, false},
	}
}

func TestParseScopeList(t *testing.T) {
	t.Parallel()

	for _, test := range scopeListCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseScopeList(test.in)
			if !test.ok {
				requireRefusal(t, err, input.CodeInvalidScopes)

				if got.List() == nil || len(got.List()) != 0 {
					t.Errorf("a refusal returned a non-zero list %v", got.List())
				}

				return
			}

			if err != nil {
				t.Fatalf("ParseScopeList(%v) refused: %v", test.in, err)
			}

			if !slices.Equal([]string(got.List()), test.in) && len(test.in) > 0 {
				t.Errorf("list = %v, want exactly %v", got.List(), test.in)
			}

			if got.List() == nil {
				t.Error("List() is nil, want a non-nil empty list")
			}
		})
	}
}

func TestParseScopeListRefusalIsFixedAndDoesNotEchoInput(t *testing.T) {
	t.Parallel()

	_, first := input.ParseScopeList([]string{"secret-typo-aaa"})
	_, second := input.ParseScopeList([]string{"another-typo-bbb"})

	a, b := descriptionOf(t, first, input.CodeInvalidScopes), descriptionOf(t, second, input.CodeInvalidScopes)
	if a != b || strings.Contains(a, "typo") {
		t.Errorf("descriptions differ or echo the input: %q vs %q", a, b)
	}

	requireMentions(t, a, input.MaxScopeEntries)
}

func TestParseScopeListReturnsACopy(t *testing.T) {
	t.Parallel()

	in := []string{"agent:read"}

	parsed, err := input.ParseScopeList(in)
	if err != nil {
		t.Fatal(err)
	}

	in[0] = "user:read"

	list := parsed.List()
	if list[0] != "agent:read" {
		t.Error("the parsed list shares the caller's slice")
	}

	list[0] = "user:read"

	if parsed.List()[0] != "agent:read" {
		t.Error("List shares the value's storage")
	}
}

func TestZeroScopeListIsEmpty(t *testing.T) {
	t.Parallel()

	var zero input.ScopeList

	if got := zero.List(); got == nil || len(got) != 0 {
		t.Errorf("zero ScopeList = %#v, want an empty non-nil list", got)
	}
}

// TestScopeListBoundsFitTheSchema reads the migrations: the stored form of the
// most that is accepted must fit the CHECKs of both columns that hold it.
func TestScopeListBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	// Each column is found in its own table: oauth_grants.scope has the CHECK of
	// api_keys.scope with a bound of its own, for the OAuth scopes of a grant.
	for _, held := range []struct{ table, column string }{{"agents", "scopes"}, {"api_keys", "scope"}} {
		limits := migrationNumbers(t,
			`CREATE TABLE `+held.table+` \(.*?length\(cast\(`+held.column+` AS BLOB\)\) BETWEEN 1 AND (\d+)`)
		last := limits[len(limits)-1]

		if input.MaxScopeListJSONBytes > last {
			t.Errorf("MaxScopeListJSONBytes %d is over the %s CHECK of %d bytes",
				input.MaxScopeListJSONBytes, held.column, last)
		}
	}
}

// TestLongestAcceptedListFitsItsBound builds the largest list the parser
// accepts, every scope and bundle once, and checks its stored form is within
// the bound with room to spare, so a new scope is noticed before it overflows.
func TestLongestAcceptedListFitsItsBound(t *testing.T) {
	t.Parallel()

	all := append(scopeNames(), scope.DefaultSession, scope.DefaultUser, scope.DefaultAgent)

	parsed, err := input.ParseScopeList(all)
	if err != nil {
		t.Fatalf("every name once was refused: %v", err)
	}

	encoded, err := json.Marshal([]string(parsed.List()))
	if err != nil {
		t.Fatal(err)
	}

	if len(encoded) > input.MaxScopeListJSONBytes/2 {
		t.Errorf("every name once is %d bytes, over half of the %d bound: raise the bound deliberately",
			len(encoded), input.MaxScopeListJSONBytes)
	}

	if len(all) > input.MaxScopeEntries {
		t.Errorf("there are %d names, over MaxScopeEntries %d", len(all), input.MaxScopeEntries)
	}
}

func scopeNames() []string {
	names := make([]string, 0, len(scope.Scopes()))

	for _, s := range scope.Scopes() {
		names = append(names, string(s))
	}

	return names
}

// FuzzParseScopeList asserts that an accepted list holds only known, distinct
// names, within the bounds, and round-trips unchanged; and that a refusal always
// carries the type's code.
func FuzzParseScopeList(f *testing.F) {
	for _, seed := range []string{
		"agent:read", "default:agent", "all", "", "agent:read\x00", "agent:read agent:create", "\xff",
	} {
		f.Add(seed, "agent:read", uint8(1))
	}

	f.Fuzz(func(t *testing.T, first, second string, repeat uint8) {
		in := make([]string, 0, 2+int(repeat%4))
		in = append(in, first, second)

		for range repeat % 4 {
			in = append(in, first)
		}

		got, err := input.ParseScopeList(in)
		if err != nil {
			requireRefusal(t, err, input.CodeInvalidScopes)

			return
		}

		checkAcceptedList(t, got.List(), in)
	})
}

// checkAcceptedList checks the invariants of a list the parser accepted.
func checkAcceptedList(t *testing.T, list scope.List, in []string) {
	t.Helper()

	if !slices.Equal([]string(list), in) {
		t.Fatalf("accepted list %v differs from input %v", list, in)
	}

	seen := map[string]bool{}

	for _, name := range list {
		if !scope.Known(name) || seen[name] || len(name) > scope.MaxNameBytes {
			t.Fatalf("accepted a bad name %q in %v", name, list)
		}

		seen[name] = true
	}

	if len(list) > input.MaxScopeEntries || len(list.JSON()) > input.MaxScopeListJSONBytes {
		t.Fatalf("accepted a list over its bounds: %v", list)
	}
}
