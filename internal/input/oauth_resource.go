package input

import (
	"slices"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/resource"
)

// Bounds of ResourceID and OAuthScopes.
const (
	// MaxResourceBytes bounds the URL of a resource, which must be an entry of
	// the table. It is the schema CHECK
	// `length(cast(resource AS BLOB)) BETWEEN 1 AND 128` on oauth_grants.resource
	// that the migration must carry. The parser does not test it, because a
	// ResourceID is only ever an entry's URL; TestResourceTablesFitTheirBounds
	// fails if a table entry ever outgrows it.
	MaxResourceBytes = 128

	// MaxOAuthScopeBytes bounds the stored form of OAuthScopes, the space-joined
	// names, in bytes. It is the schema CHECK
	// `length(cast(scope AS BLOB)) BETWEEN 1 AND 256` on oauth_grants.scope that
	// the migration must carry, and the scopes' share of the sealed pending
	// request. The request's own text is held to it before it is split, so a long
	// value costs one comparison.
	MaxOAuthScopeBytes = 256

	// MaxOAuthScopeEntries bounds the names of one OAuthScopes. Duplicates are
	// refused and every name must be one the resource defines (or openid), so
	// a resource would need that many scopes to reach it.
	MaxOAuthScopeEntries = 16
)

// OpenIDScope is the one scope that is not the resource's: it asks for an ID
// token.
const OpenIDScope = "openid"

// The two OpenID Connect scope names a first-party client sends that no resource
// defines. See ParseFirstPartyScopes.
const (
	// EmailScope is OpenID Connect's scope for the email claim. authsu has one
	// profile scope, of which the email is a part, so it is read as that.
	EmailScope = "email"
	// OfflineAccessScope is OpenID Connect's request for a refresh token. authsu
	// issues one with every code exchange, so it asks for nothing more.
	OfflineAccessScope = "offline_access"
)

// Error codes of the resource types.
const (
	CodeInvalidResource   = "invalid_resource"
	CodeInvalidOAuthScope = "invalid_scope"
)

const (
	descInvalidResource   = "resource must be the exact URL of a resource this server issues tokens for"
	descInvalidOAuthScope = "scope must be 1 to 256 characters of known scope names, each given once and " +
		"separated by a single space, at most 16 of them"
)

// ResourceID is the URL of a resource server in the table the deployment
// selected, and the entry it names.
type ResourceID struct{ e resource.Entry }

// ParseResourceID accepts a URL that is exactly the URL of an entry of table
// (resource.Table.Lookup: no case folding, no trailing slash, no default port)
// and refuses everything else, an absent table entry included.
func ParseResourceID(raw string, table resource.Table) (ResourceID, error) {
	entry, found := table.Lookup(raw)
	if !found {
		return ResourceID{}, refuse(CodeInvalidResource, descInvalidResource)
	}

	return ResourceID{e: entry}, nil
}

// String returns the resource's URL, exactly as the table spells it.
func (r ResourceID) String() string { return r.e.URL }

// Entry returns the table entry the URL names. It is a copy.
func (r ResourceID) Entry() resource.Entry {
	entry := r.e
	entry.Scopes = slices.Clone(entry.Scopes)
	entry.Defaults = slices.Clone(entry.Defaults)

	return entry
}

// OAuthScopes is the scope of an authorization request: names the resource
// defines, in the order the client wrote them, and openid if it asked for it.
type OAuthScopes struct {
	v      string
	openid bool
}

// ParseOAuthScopes reads the "scope" parameter of a request for the resource
// entry. present is whether the parameter was sent.
//
// Absent is the resource's default scope list, written out in full: the
// grant never stores "whatever the default is", so a later change to the
// defaults does not change what was approved. The value is not a request, so
// it is not checked.
//
// A present value is the names of RFC 6749 section 3.3: one or more, separated
// by a single space (U+0020). It is refused if it:
//   - is empty. A present, empty "scope" is not the absent one and is not "no
//     scopes", so it is refused rather than guessed. (httpapi.Params already
//     reports an empty parameter as absent, as RFC 6749 section 3.1 says, so a
//     request never reaches this case.);
//   - has a leading, trailing or doubled space, or any other separator (a tab,
//     a comma, a newline, a plus sign): the empty or unknown name it leaves is
//     refused;
//   - names a scope that is not openid and not one of entry.Scopes, compared
//     exactly and case-sensitively. One of authsu's own scopes is no more a
//     resource scope than any other unknown name;
//   - names the same scope twice;
//   - is longer than MaxOAuthScopeBytes or has more than MaxOAuthScopeEntries names.
//
// Order is kept, and it is part of the stored text: "mcp:write mcp:read" and
// "mcp:read mcp:write" are two spellings of one set that this package does
// not make into one. Whether a requested list is within a grant's is not decided
// here: it is a condition of the store's rotation (store.Refresh), where it can
// be compared with the grant without a read that races it.
//
// "openid" alone is a list that parses: this function checks that every name is
// known, not that the list is a request worth making. A caller that takes a
// request refuses a list with no name of the resource in it (Resource), because
// an ID token grants nothing and there would be nothing to approve: the
// authorization endpoint does, and so does a refresh. Every refusal here is
// CodeInvalidOAuthScope, which the token and authorization endpoints report as
// invalid_scope.
//
// The same function reads the stored form of a grant back: String is exactly
// what it accepts.
func ParseOAuthScopes(raw string, present bool, entry resource.Entry) (OAuthScopes, error) {
	if !present {
		return scopesOf(entry.Defaults), nil
	}

	names, ok := scopeNames(raw, entry)
	if !ok {
		return OAuthScopes{}, refuse(CodeInvalidOAuthScope, descInvalidOAuthScope)
	}

	return scopesOf(names), nil
}

// ParseFirstPartyScopes reads the "scope" parameter of a request for a first-party
// login resource (resource.Entry.FirstParty), which only a trusted client may
// make. It is ParseOAuthScopes with the two OpenID Connect names that a
// resource does not define, EmailScope and OfflineAccessScope, tolerated: a
// standard OpenID Connect client sends "openid email profile offline_access"
// without knowing what authsu calls things, and refusing it would refuse the
// first-party app.
//
// The tolerance is as narrow as it can be and widens nothing:
//   - the list is first checked as ParseOAuthScopes checks it, with the two names
//     allowed, so everything else about it (the bounds, a repeated name, an
//     unknown one, a name of another resource such as an MCP scope) is refused as
//     it would be there;
//   - the name offline_access is dropped, because it asks for what is always
//     given;
//   - the name email is read as the entry's profile scope, so it is neither
//     stored nor repeated: a list that names both email and profile names profile
//     once, and the stored list is only names the entry defines, plus openid;
//   - what is stored is the stored form of the result, so a grant never holds
//     either name and the schema's bounds are those of ParseOAuthScopes.
//
// An absent scope is the entry's defaults, as for ParseOAuthScopes. The caller
// refuses a list with no name of the entry in it. The first-party scope is a
// property of the entry and not of the name "profile": the entry's first scope is
// what email stands for.
func ParseFirstPartyScopes(raw string, present bool, entry resource.Entry) (OAuthScopes, error) {
	if !present {
		return scopesOf(entry.Defaults), nil
	}

	names, ok := scopeNames(raw, entry, EmailScope, OfflineAccessScope)
	if !ok || len(entry.Scopes) == 0 {
		return OAuthScopes{}, refuse(CodeInvalidOAuthScope, descInvalidOAuthScope)
	}

	kept := make([]string, 0, len(names))

	for _, name := range names {
		switch name {
		case OfflineAccessScope:
		case EmailScope:
			kept = appendOnce(kept, entry.Scopes[0])
		default:
			kept = appendOnce(kept, name)
		}
	}

	return scopesOf(kept), nil
}

// appendOnce appends name unless the list has it.
func appendOnce(names []string, name string) []string {
	if slices.Contains(names, name) {
		return names
	}

	return append(names, name)
}

// scopeNames splits raw and reports whether it is a valid list of names: each
// openid, one the entry defines, or one of tolerated.
func scopeNames(raw string, entry resource.Entry, tolerated ...string) ([]string, bool) {
	if raw == "" || len(raw) > MaxOAuthScopeBytes {
		return nil, false
	}

	names := strings.Split(raw, " ")
	if len(names) > MaxOAuthScopeEntries || hasDuplicate(names) {
		return nil, false
	}

	for _, name := range names {
		if name != OpenIDScope && !entry.HasScope(name) && !slices.Contains(tolerated, name) {
			return nil, false
		}
	}

	return names, true
}

// scopesOf is the OAuthScopes of the names, which are already checked.
func scopesOf(names []string) OAuthScopes {
	return OAuthScopes{v: strings.Join(names, " "), openid: slices.Contains(names, OpenIDScope)}
}

// String returns the space-joined names in order: the form stored in
// oauth_grants.scope and returned in a token response. For a request that
// sent a scope it is exactly what was sent.
func (s OAuthScopes) String() string { return s.v }

// OpenID reports whether openid was asked for.
func (s OAuthScopes) OpenID() bool { return s.openid }

// Names returns every name, openid included, in order. It is a copy.
func (s OAuthScopes) Names() []string {
	if s.v == "" {
		return []string{}
	}

	return strings.Split(s.v, " ")
}

// Resource returns the names that are the resource's, without openid, in
// order. It is a copy and may be empty.
func (s OAuthScopes) Resource() []string {
	return slices.DeleteFunc(s.Names(), func(name string) bool { return name == OpenIDScope })
}
