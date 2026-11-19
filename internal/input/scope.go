package input

import (
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// Bounds of ScopeList.
const (
	// MaxScopeEntries bounds the number of names in a ScopeList. There are far
	// fewer scopes and bundles than this, and duplicates are refused, so a
	// legitimate list is never near it: the bound only keeps the work and the
	// stored text small.
	MaxScopeEntries = 32

	// MaxScopeListJSONBytes is the most the stored form of a ScopeList, the
	// JSON array of its names, may be. It is the schema CHECKs
	// `length(cast(scopes AS BLOB)) BETWEEN 1 AND 1024` on agents.scopes and
	// `length(cast(scope AS BLOB)) BETWEEN 1 AND 1024` on api_keys.scope
	// (migration 0001), which count bytes. The empty list, "[]", is two bytes,
	// so it satisfies them and needs no migration.
	//
	// The parser does not test it, because it cannot be reached: a list is
	// distinct known names, and there are a dozen, so the longest list is every
	// name once. TestLongestAcceptedListFitsItsBound fails long before that
	// nears the bound, so a new scope that would push the longest list towards
	// it is noticed when it is added.
	MaxScopeListJSONBytes = 1024
)

// CodeInvalidScopes is the error code of ParseScopeList.
const CodeInvalidScopes = "invalid_scopes"

const descInvalidScopes = "scopes must be a list of at most 32 distinct, known scope or bundle names"

// ScopeList is the scopes a client asks a new agent or key to have: a list of
// scope and bundle names, each one the code knows, exactly as written.
type ScopeList struct{ v scope.List }

// ParseScopeList accepts a list of at most MaxScopeEntries distinct names, each
// a scope or a bundle the code knows. The empty list is accepted: it is a
// credential that can use only the routes that need no scope. A name that is
// not exactly a known name is refused whole: no trimming, no case folding, no
// "all". A repeated name is refused rather than collapsed, so one stored list
// has exactly one spelling. A nil slice is the empty list. The order is kept.
//
// Whether the user may hold the scopes named is not asked here: every request
// intersects a credential with its user's authority, and an admin scope is
// refused to anyone who is not an administrator, so naming one grants nothing.
func ParseScopeList(names []string) (ScopeList, error) {
	parsed := result.Ok(names).
		Check(withinBound).
		Check(distinct).
		Then(func(names []string) (scope.List, error) { return scope.Names(names).Get() }).
		MapErr(func(error) error { return refuse(CodeInvalidScopes, descInvalidScopes) }).
		Map(func(list scope.List) ScopeList { return ScopeList{v: list} })

	return parsed.Get() //nolint:wrapcheck // every error in the chain is already the classified client error
}

// withinBound refuses a list with more than MaxScopeEntries names.
func withinBound(names []string) error {
	if len(names) > MaxScopeEntries {
		return refuse(CodeInvalidScopes, descInvalidScopes)
	}

	return nil
}

// distinct refuses a list in which a name appears twice.
func distinct(names []string) error {
	if hasDuplicate(names) {
		return refuse(CodeInvalidScopes, descInvalidScopes)
	}

	return nil
}

// hasDuplicate reports whether a name appears twice.
func hasDuplicate(names []string) bool {
	seen := make(map[string]struct{}, len(names))

	for _, name := range names {
		if _, again := seen[name]; again {
			return true
		}

		seen[name] = struct{}{}
	}

	return false
}

// List returns the scopes as a scope.List, exactly as parsed. It is a copy, and
// never nil.
func (l ScopeList) List() scope.List {
	return append(scope.List{}, l.v...)
}
