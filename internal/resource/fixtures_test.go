//nolint:goconst // table-driven tests repeat case names on purpose; a constant per row would hide the table
package resource_test

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

const (
	originLocal     = "http://localhost"
	originLocalPort = "http://localhost:8787"
	originProd      = "https://auth.example.com"

	upperCaseHost = "upper-case host"
	hostLocalhost = "localhost"
	scopeRead     = "mcp:read"
	scopeWrite    = "mcp:write"
	scopeEvil     = "evil:all"
)

// selectCases are the API_ORIGIN values Select is tried with.
func selectCases() map[string]struct {
	origin          string
	wantDevelopment bool
} {
	return map[string]struct {
		origin          string
		wantDevelopment bool
	}{
		hostLocalhost:                   {origin: originLocal, wantDevelopment: true},
		"localhost with port":           {origin: originLocalPort, wantDevelopment: true},
		"https":                         {origin: originProd},
		"https with port":               {origin: "https://auth.example.com:8443"},
		"https localhost":               {origin: "https://localhost"},
		"https localhost with port":     {origin: "https://localhost:8787"},
		"localhost subdomain lookalike": {origin: "http://localhost.evil.com"},
		"localhost suffix lookalike":    {origin: "http://localhostx"},
		"localhost lookalike with port": {origin: "http://localhost.evil.com:8787"},
		"localhost userinfo":            {origin: "http://localhost@evil.com"},
		"localhost with path":           {origin: "http://localhost/path"},
		"localhost bad port":            {origin: "http://localhost:abc"},
		"localhost empty port":          {origin: "http://localhost:"},
		"localhost trailing slash":      {origin: "http://localhost/"},
		"localhost query":               {origin: "http://localhost?x=1"},
		"localhost fragment":            {origin: "http://localhost#x"},
		upperCaseHost:                   {origin: "http://LOCALHOST"},
		"upper-case scheme":             {origin: "HTTP://localhost"},
		"127.0.0.1":                     {origin: "http://127.0.0.1:8787"},
		"http elsewhere":                {origin: "http://auth.example.com"},
		"ws localhost":                  {origin: "ws://localhost"},
		"null":                          {origin: "null"},
		"wildcard":                      {origin: "*"},
		"bare host":                     {origin: hostLocalhost},
		"leading space":                 {origin: " http://localhost"},
		"trailing newline":              {origin: "http://localhost\n"},
		"empty":                         {origin: ""},
	}
}

// lookupCases are the URLs Lookup is tried with against the production table.
func lookupCases() map[string]struct {
	url   string
	found bool
} {
	return map[string]struct {
		url   string
		found bool
	}{
		"exact":                    {url: resource.ProductionURL, found: true},
		"trailing slash":           {url: resource.ProductionURL + "/"},
		upperCaseHost:              {url: "https://API.susu.dev/mcp"},
		"upper-case scheme":        {url: "HTTPS://auth.susu.dev/mcp"},
		"upper-case path":          {url: "https://auth.susu.dev/MCP"},
		"default port":             {url: "https://auth.susu.dev:443/mcp"},
		"query":                    {url: resource.ProductionURL + "?x=1"},
		"fragment":                 {url: resource.ProductionURL + "#x"},
		"path suffix":              {url: resource.ProductionURL + "/x"},
		"path prefix":              {url: "https://auth.susu.dev"},
		"host prefix":              {url: "https://auth.susu.dev.evil.com/mcp"},
		"userinfo":                 {url: "https://auth.susu.dev@evil.com/mcp"},
		"percent-encoded":          {url: "https://auth.susu.dev/%6dcp"},
		"leading space":            {url: " " + resource.ProductionURL},
		"trailing newline":         {url: resource.ProductionURL + "\n"},
		"http":                     {url: "http://auth.susu.dev/mcp"},
		"the development URL":      {url: resource.DevelopmentURL},
		"the authsu origin itself": {url: "https://auth.susu.dev"},
		"empty":                    {url: ""},
	}
}

// localCases are the client URLs AllowsLocalHTTP is tried with.
func localCases() map[string]struct {
	url         string
	development bool
	production  bool
} {
	return map[string]struct {
		url         string
		development bool
		production  bool
	}{
		"localhost":                     {url: "http://localhost/client.json", development: true},
		"localhost with port":           {url: "http://localhost:9000/client.json", development: true},
		"localhost, no path":            {url: "http://localhost", development: true},
		"https localhost":               {url: "https://localhost/client.json"},
		"https elsewhere":               {url: "https://client.example/c.json"},
		"http elsewhere":                {url: "http://client.example/c.json"},
		"localhost subdomain lookalike": {url: "http://localhost.evil.com/c.json"},
		"localhost suffix lookalike":    {url: "http://localhostx/c.json"},
		"localhost prefix lookalike":    {url: "http://xlocalhost/c.json"},
		"userinfo lookalike":            {url: "http://localhost@evil.com/c.json"},
		"127.0.0.1":                     {url: "http://127.0.0.1/c.json"},
		"IPv6 loopback":                 {url: "http://[::1]/c.json"},
		upperCaseHost:                   {url: "http://LOCALHOST/c.json"},
		"trailing dot":                  {url: "http://localhost./c.json"},
		"ws":                            {url: "ws://localhost/c.json"},
	}
}

// hasScopeCases are the scope names HasScope is tried with against the resource.
func hasScopeCases() map[string]bool {
	return map[string]bool{
		scopeRead:      true,
		scopeWrite:     true,
		"MCP:read":     false,
		"mcp:READ":     false,
		"mcp:read ":    false,
		" mcp:read":    false,
		"mcp":          false,
		"mcp:":         false,
		"mcp:delete":   false,
		"mcp:*":        false,
		"openid":       false,
		"agent:read":   false,
		"default:user": false,
		"":             false,
	}
}

// checkURL fails unless the entry's URL is a plain absolute URL: a scheme, a
// host and, for a resource server, a path, with no userinfo, query or fragment,
// written canonically. A first-party login resource is an origin: no path.
func checkURL(t *testing.T, e resource.Entry) {
	t.Helper()

	parsed, err := url.Parse(e.URL)
	if err != nil || !plain(parsed, e.FirstParty) || parsed.String() != e.URL {
		t.Errorf("URL %q is not a plain absolute URL: %v", e.URL, err)
	}

	if e.Name == "" {
		t.Errorf("%q has no name", e.URL)
	}
}

// checkScopes fails unless the entry's scopes are unique, follow the grammar,
// and are not authsu's own.
func checkScopes(t *testing.T, e resource.Entry, grammar *regexp.Regexp) {
	t.Helper()

	if len(e.Scopes) == 0 {
		t.Errorf("%q has no scopes", e.URL)
	}

	seen := map[string]bool{}

	for _, name := range e.Scopes {
		if !scopeNameOK(e, name, grammar) {
			t.Errorf("scope %q is not a resource:action name (or, for a first-party resource, not only %q)",
				name, resource.ScopeProfile)
		}

		if seen[name] {
			t.Errorf("scope %q is listed twice", name)
		}

		seen[name] = true

		// A resource scope is never one of authsu's own, nor a bundle: a client
		// asking for one must not be mistaken for asking for authority at authsu.
		if scope.Known(name) {
			t.Errorf("scope %q is also an authsu scope or bundle", name)
		}

		if !e.HasScope(name) {
			t.Errorf("HasScope(%q) = false for a listed scope", name)
		}
	}
}

// scopeNameOK reports whether a scope's name is acceptable for its entry: a
// resource:action name, except for the first-party login resource, whose one
// scope is the OpenID Connect name "profile".
func scopeNameOK(e resource.Entry, name string, grammar *regexp.Regexp) bool {
	if e.FirstParty {
		return name == resource.ScopeProfile && len(e.Scopes) == 1
	}

	return grammar.MatchString(name) && len(name) <= scope.MaxNameBytes
}

// checkDefaults fails unless the entry's defaults are a non-empty, unique subset
// of its scopes.
func checkDefaults(t *testing.T, e resource.Entry) {
	t.Helper()

	if len(e.Defaults) == 0 {
		t.Errorf("%q has no defaults", e.URL)
	}

	seen := map[string]bool{}

	for _, name := range e.Defaults {
		if !e.HasScope(name) {
			t.Errorf("default %q is not one of the scopes %v", name, e.Scopes)
		}

		if seen[name] {
			t.Errorf("default %q is listed twice", name)
		}

		seen[name] = true
	}
}

// plain reports whether u has a scheme, a host and a path and nothing else; an
// origin, with no path, when origin is true.
func plain(u *url.URL, origin bool) bool {
	hasPath := u.Path != ""

	return u.IsAbs() && u.Host != "" && hasPath != origin && u.User == nil &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// trustedCases are the client_ids Trusted is tried with, with whether each
// table trusts it.
func trustedCases() map[string]struct {
	id                      string
	production, development bool
} {
	return map[string]struct {
		id                      string
		production, development bool
	}{
		"the production app":      {id: resource.ProductionClientID, production: true},
		"the development app":     {id: resource.DevelopmentClientID, development: true},
		"upper-case host":         {id: "https://APP.susu.dev/oauth/client.json"},
		"trailing slash":          {id: resource.ProductionClientID + "/"},
		"default port":            {id: "https://app.susu.dev:443/oauth/client.json"},
		"query":                   {id: resource.ProductionClientID + "?x=1"},
		"another path":            {id: "https://app.susu.dev/oauth/other.json"},
		"another host":            {id: "https://evil.example/oauth/client.json"},
		"a lookalike host":        {id: "https://app.susu.dev.evil.com/oauth/client.json"},
		"userinfo":                {id: "https://app.susu.dev@evil.com/oauth/client.json"},
		"leading space":           {id: " " + resource.ProductionClientID},
		"trailing newline":        {id: resource.ProductionClientID + "\n"},
		"the resource itself":     {id: resource.ProductionURL},
		"the login resource":      {id: resource.ProductionLoginURL},
		"empty":                   {id: ""},
		"http for the production": {id: "http://app.susu.dev/oauth/client.json"},
	}
}
