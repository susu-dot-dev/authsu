// Package resource is the table of resource servers authsu issues OAuth tokens
// for (docs/oauth_design.md): for each, the name shown at consent, the exact
// URL a client names in the "resource" parameter, the scopes it defines and the
// scopes a grant gets when the client asks for none.
//
// # Two tables
//
// The tables are code, not configuration: a resource is something the service
// is built to be an authorization server for, and a deployment setting would
// let a mistake name any URL as one. There are two, production and development,
// and Select chooses between them from API_ORIGIN:
//
//   - development when API_ORIGIN is an http://localhost origin, with or without
//     a port. That is config's one localhost rule (config.LocalHTTP, which
//     config.ParseOrigin accepts plain http by), so a lookalike such as
//     http://localhost.example.com is not development.
//   - production in every other case, including a value that is not an origin
//     at all, so a mistake can only ever select the stricter table.
//
// Each table has two entries. The first is the MCP resource: production's is
// https://api.susu.dev/mcp, and development's is the same entry at
// http://localhost:8788/mcp. 8788 is fixed the way the dev UI's port
// (DEV_UI_PORT, 3000) is, one above the API's own (DEV_PORT, 8787), so the
// development resource is a separate local server beside the API.
//
// The second is the first-party login resource: the origin of the Pages app
// (https://app.susu.dev, development http://localhost:9894), with the one scope
// "profile". It is not a server that holds data: it is the audience of the
// sign-in a first-party app asks authsu for, so a token for it is bound to that
// app as every token is bound to its resource. It is marked FirstParty, which
// means only a trusted client may ask for it (below).
//
// # Trusted clients
//
// Each table also lists the trusted clients: the first-party apps, by the exact
// client_id they are identified by (https://app.susu.dev/oauth/client.json, and
// http://localhost:9894/oauth/client.json in development). The list is code for
// the reason the resources are: a deployment setting would let a mistake make
// any URL a first party. Being trusted changes nothing about how the client is
// identified or its redirect URI is checked, which is by its own metadata
// document as for every client; it only admits the client to a FirstParty
// resource, where consent needs no agent and no screen (docs/oauth_design.md).
// Trust is a comparison of the whole string and nothing is normalised.
//
// There is no build tag or other switch: one build carries both tables, and
// only API_ORIGIN picks one.
//
// # Scopes
//
// A resource's scopes are written "resource:action" in the same shape as
// authsu's own (internal/scope), such as "mcp:read". They are the vocabulary of
// the OAuth "scope" parameter for that resource and are a separate namespace
// from authsu's: a grant carries none of authsu's scopes, and an authsu scope
// is never a resource scope.
//
// # Development also allows localhost clients
//
// The development table is also what permits a client to be identified by an
// http://localhost client_id (AllowsLocalHTTP), which is how a developer's
// client and the end-to-end tests are served. That is the only plain-http
// allowance, and the production table has none.
package resource

import (
	"net/url"
	"slices"

	"github.com/susu-dot-dev/authsu/internal/config"
)

// The one resource, in each table.
const (
	// Name is shown at consent.
	Name = "Susu MCP"
	// ProductionURL is the resource's URL in the production table.
	ProductionURL = "https://api.susu.dev/mcp"
	// DevelopmentURL is the resource's URL in the development table. Its port,
	// 8788, is DevelopmentPort.
	DevelopmentURL = "http://localhost:8788/mcp"
	// DevelopmentPort is the port of DevelopmentURL.
	DevelopmentPort = 8788

	// ScopeRead and ScopeWrite are the scopes of the resource.
	ScopeRead  = "mcp:read"
	ScopeWrite = "mcp:write"

	// LoginName is shown for the first-party login resource.
	LoginName = "Susu"
	// ProductionLoginURL and DevelopmentLoginURL are the first-party login
	// resource in each table: the origin of the Pages app, with no path.
	ProductionLoginURL  = "https://app.susu.dev"
	DevelopmentLoginURL = "http://localhost:9894"
	// ScopeProfile is the one scope of the first-party login resource.
	ScopeProfile = "profile"

	// ProductionClientID and DevelopmentClientID are the trusted client of each
	// table: the Client ID Metadata Document of the Pages app.
	ProductionClientID  = "https://app.susu.dev/oauth/client.json"
	DevelopmentClientID = "http://localhost:9894/oauth/client.json"
)

// Entry is one resource server.
type Entry struct {
	// Name is shown to the person approving a grant.
	Name string
	// URL is the resource's identifier, compared whole and exactly as written:
	// it is what a client sends as "resource" and what a token is bound to.
	URL string
	// Scopes is every scope the resource defines, in the order they are listed.
	Scopes []string
	// Defaults is the scope list a grant gets when the client asks for none. It
	// is a subset of Scopes.
	Defaults []string
	// FirstParty marks the first-party login resource: only a trusted client may
	// ask for it, and a grant for it is held by the agent authsu keeps
	// for the user and client and not by an agent the person chose. Every other entry is a resource a
	// third party may ask for.
	FirstParty bool
}

// HasScope reports whether the resource defines the scope, by exact match.
func (e Entry) HasScope(name string) bool {
	return slices.Contains(e.Scopes, name)
}

// Table is the set of resources of one deployment. The zero Table is empty and
// not development. A Table is a value: what it returns is a copy, so no caller
// can change the table another request reads.
type Table struct {
	development bool
	entries     []Entry
	trusted     []string
}

// Select returns the table for an API_ORIGIN: development for an http://localhost
// origin, production for everything else (see the package comment).
func Select(apiOrigin string) Table {
	origin, err := config.ParseOrigin(apiOrigin)
	if err == nil && origin.Local() {
		return Table{
			development: true, entries: []Entry{entry(DevelopmentURL), login(DevelopmentLoginURL)},
			trusted: []string{DevelopmentClientID},
		}
	}

	return Table{entries: []Entry{entry(ProductionURL), login(ProductionLoginURL)}, trusted: []string{ProductionClientID}}
}

// entry is the one resource at a URL.
func entry(resourceURL string) Entry {
	return Entry{
		Name:     Name,
		URL:      resourceURL,
		Scopes:   []string{ScopeRead, ScopeWrite},
		Defaults: []string{ScopeRead, ScopeWrite},
	}
}

// login is the first-party login resource at a URL: it defines "profile", which
// is also its default, and only a trusted client may ask for it.
func login(resourceURL string) Entry {
	return Entry{
		Name:       LoginName,
		URL:        resourceURL,
		Scopes:     []string{ScopeProfile},
		Defaults:   []string{ScopeProfile},
		FirstParty: true,
	}
}

// Trusted reports whether clientID is one of the table's trusted clients, by
// exact comparison: no normalisation, so another case, a trailing slash or a
// default port written out is not trusted. The zero table trusts nobody.
func (t Table) Trusted(clientID string) bool {
	return slices.Contains(t.trusted, clientID)
}

// Development reports whether this is the development table.
func (t Table) Development() bool { return t.development }

// Entries returns every resource, in a fixed order.
func (t Table) Entries() []Entry {
	entries := make([]Entry, len(t.entries))
	for i, e := range t.entries {
		entries[i] = e.clone()
	}

	return entries
}

// Lookup finds a resource by its URL, compared exactly: no normalisation, so a
// trailing slash, another case or a default port written out is not the
// resource.
func (t Table) Lookup(resourceURL string) (Entry, bool) {
	for _, e := range t.entries {
		if e.URL == resourceURL {
			return e.clone(), true
		}
	}

	return Entry{}, false
}

// AllowsLocalHTTP reports whether a URL that a client is identified by may be
// plain http: only in the development table, and only for the scheme http and
// the host localhost (config.LocalHTTP), on any port. In the production table it
// is always false. The caller has parsed u and still judges every other part.
func (t Table) AllowsLocalHTTP(u *url.URL) bool {
	return t.development && config.LocalHTTP(u.Scheme, u.Hostname())
}

// clone copies the slices an Entry holds.
func (e Entry) clone() Entry {
	e.Scopes = slices.Clone(e.Scopes)
	e.Defaults = slices.Clone(e.Defaults)

	return e
}
