package scope

import (
	"encoding/json"
	"slices"
	"strconv"

	"github.com/susu-dot-dev/authsu/internal/result"
)

// List is a credential's scopes exactly as written: scope and bundle names in
// the order given. It is what an agent row and a key row store (as a JSON
// array of strings, see JSON) and what a key's token carries as its scope
// claim.
//
// A List is not validated by being a List: Names is the strict way to make one
// from names a client wrote, and Read is the lenient way to make one from text
// that was stored. The empty list is valid and grants nothing: a
// credential with no scopes can use the routes that need none.
type List []string

// UnknownNameError is why Names refused a list: the name at Index is neither a
// scope nor a bundle.
type UnknownNameError struct {
	// Index is the position of the first refused name.
	Index int
}

// Error describes the refusal by position and never repeats the name: it is
// for a log, and a name is whatever a client sent.
func (e UnknownNameError) Error() string {
	return "scope list entry " + strconv.Itoa(e.Index) + " is not a known scope or bundle"
}

// Names reads names, which a client wrote, as a List. It fails with an
// UnknownNameError for the first name that is not a scope or a bundle, so a typo
// fails loudly instead of producing a credential that silently can do nothing.
// It does not sort, trim or remove duplicates: the caller decides whether
// duplicates are acceptable (input.ParseScopeList refuses them). The List is a
// copy.
func Names(names []string) result.Result[List] {
	for i, name := range names {
		if !Known(name) {
			return result.Fail[List](UnknownNameError{Index: i})
		}
	}

	return result.Ok(List(slices.Clone(names)))
}

// JSON is the stored and signed form of the list: a JSON array of strings.
// The empty list is "[]", never "" and never "null".
func (l List) JSON() string {
	names := []string(l)
	if names == nil {
		names = []string{}
	}

	encoded, err := json.Marshal(names)
	// coverage:ignore: encoding a slice of strings cannot fail
	if err != nil {
		return "[]"
	}

	return string(encoded)
}

// Read reads a list from its stored JSON. It never fails: text that is not a
// JSON array of strings is the empty list, which grants nothing, so a damaged
// or missing value fails closed. Names are not checked here: Expand ignores one
// the code does not know.
func Read(stored string) List {
	var names []string

	err := json.Unmarshal([]byte(stored), &names)
	if err != nil {
		return List{}
	}

	if names == nil {
		return List{}
	}

	return List(names)
}

// FromClaim reads a token's scope claim as a list. The claim decoded from JSON
// is an []any; anything that is not an array of strings is the empty list, so
// a token whose claim is missing or the wrong shape grants nothing.
func FromClaim(claim any) List {
	items, ok := claim.([]any)
	if !ok {
		return List{}
	}

	names := make(List, 0, len(items))

	for _, item := range items {
		name, isString := item.(string)
		if !isString {
			return List{}
		}

		names = append(names, name)
	}

	return names
}

// Claim is the list as the value of a token's scope claim: a []string, which
// JSON encodes as an array.
func (l List) Claim() []string {
	if l == nil {
		return []string{}
	}

	return slices.Clone([]string(l))
}

// Expand returns the scopes the list grants: every named scope, and every
// scope of every named bundle. A name the code does not know grants nothing.
// Bundles are expanded now, not when the list was written, so a scope added to
// a bundle reaches every list that names it.
func (l List) Expand() Set {
	out := Set{m: map[Scope]struct{}{}}
	table := bundles()

	for _, name := range l {
		if members, bundle := table[name]; bundle {
			for _, member := range members {
				out.m[member] = struct{}{}
			}

			continue
		}

		if isScope(name) {
			out.m[Scope(name)] = struct{}{}
		}
	}

	return out
}

// isScope reports whether name is a scope (not a bundle).
func isScope(name string) bool {
	for _, def := range definitions() {
		if string(def.scope) == name {
			return true
		}
	}

	return false
}

// SubsetOf reports whether every entry of l is an entry of of, compared as
// written. A bundle is passed on whole or not at all: "default:agent" is not
// contained in ["agent:read"], even if the bundle holds only that scope today,
// because the bundle may grow. If one list is contained in another, its
// expansion is contained in the other's however the bundles change, which is
// what lets an agent that creates an agent be bounded by the key it used.
func (l List) SubsetOf(of List) bool {
	for _, name := range l {
		if !slices.Contains(of, name) {
			return false
		}
	}

	return true
}
