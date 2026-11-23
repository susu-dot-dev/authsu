package resource_test

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/resource"
)

// TestSelect: the development table is chosen only for a true
// http://localhost origin; every other value gets the production table. The
// lookalikes are the ones config.ParseOrigin is tested with.
func TestSelect(t *testing.T) {
	t.Parallel()

	tests := selectCases()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			table := resource.Select(tt.origin)
			if table.Development() != tt.wantDevelopment {
				t.Fatalf("Development = %v, want %v", table.Development(), tt.wantDevelopment)
			}

			wantURL, wantLogin := resource.ProductionURL, resource.ProductionLoginURL
			if tt.wantDevelopment {
				wantURL, wantLogin = resource.DevelopmentURL, resource.DevelopmentLoginURL
			}

			entries := table.Entries()
			if len(entries) != 2 || entries[0].URL != wantURL || entries[1].URL != wantLogin {
				t.Errorf("entries = %+v, want the resource at %q then the login resource at %q", entries, wantURL, wantLogin)
			}

			// A table never lists the other table's resources.
			others := []string{resource.DevelopmentURL, resource.DevelopmentLoginURL}
			if tt.wantDevelopment {
				others = []string{resource.ProductionURL, resource.ProductionLoginURL}
			}

			for _, other := range others {
				if _, found := table.Lookup(other); found {
					t.Errorf("the table also knows %q", other)
				}
			}
		})
	}
}

// TestTablesAreWellFormed: in both tables every URL parses as an absolute URL
// with a host and no more than a scheme, host and path; names are set; scopes
// are unique and follow the "resource:action" grammar of internal/scope; and
// the defaults are a subset of the scopes.
func TestTablesAreWellFormed(t *testing.T) {
	t.Parallel()

	// "resource:action": lower-case ASCII words, underscores between words.
	grammar := regexp.MustCompile(`^[a-z]+(_[a-z]+)*:[a-z]+(_[a-z]+)*$`)

	for name, table := range map[string]resource.Table{
		"production":  resource.Select(originProd),
		"development": resource.Select(originLocalPort),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			entries := table.Entries()
			if len(entries) == 0 {
				t.Fatal("no resources")
			}

			urls := map[string]bool{}

			for _, e := range entries {
				checkURL(t, e)
				checkScopes(t, e, grammar)
				checkDefaults(t, e)

				if urls[e.URL] {
					t.Errorf("URL %q is listed twice", e.URL)
				}

				urls[e.URL] = true

				// Lookup finds each by its exact URL.
				got, found := table.Lookup(e.URL)
				if !found || got.URL != e.URL || got.Name != e.Name {
					t.Errorf("Lookup(%q) = %+v, %v", e.URL, got, found)
				}
			}
		})
	}
}

// TestTheTablesAreTheSameResource: development differs from production in the
// URLs alone, so what a developer sees is what production does.
func TestTheTablesAreTheSameResource(t *testing.T) {
	t.Parallel()

	prod := resource.Select(originProd).Entries()
	dev := resource.Select(originLocal).Entries()

	if len(prod) != 2 || len(dev) != 2 {
		t.Fatalf("prod %d entries, dev %d", len(prod), len(dev))
	}

	wantURLs := []string{
		"https://auth.susu.dev/mcp", "http://localhost:8788/mcp", "https://app.susu.dev", "http://localhost:9894",
	}
	if got := []string{prod[0].URL, dev[0].URL, prod[1].URL, dev[1].URL}; !slices.Equal(got, wantURLs) {
		t.Errorf("urls = %q, want %q", got, wantURLs)
	}

	if resource.DevelopmentPort != 8788 {
		t.Errorf("DevelopmentPort = %d", resource.DevelopmentPort)
	}

	for i := range prod {
		dev[i].URL = prod[i].URL
		if !sameEntry(prod[i], dev[i]) {
			t.Errorf("tables differ beyond the URL: %+v and %+v", prod[i], dev[i])
		}
	}
}

// TestTheTwoResources: the MCP resource defines the two mcp scopes for anyone, and
// the login resource is first-party and defines only profile.
func TestTheTwoResources(t *testing.T) {
	t.Parallel()

	entries := resource.Select(originProd).Entries()

	if !slices.Equal(entries[0].Scopes, []string{scopeRead, scopeWrite}) || entries[0].FirstParty {
		t.Errorf("the MCP resource = %+v", entries[0])
	}

	login := entries[1]
	if !login.FirstParty || !slices.Equal(login.Scopes, []string{resource.ScopeProfile}) ||
		!slices.Equal(login.Defaults, []string{resource.ScopeProfile}) || login.HasScope(scopeRead) {
		t.Errorf("the login resource = %+v", login)
	}
}

// sameEntry reports whether two entries are equal.
func sameEntry(a, b resource.Entry) bool {
	return a.URL == b.URL && a.Name == b.Name && slices.Equal(a.Scopes, b.Scopes) &&
		slices.Equal(a.Defaults, b.Defaults) && a.FirstParty == b.FirstParty
}

// TestTrusted: a client is trusted by the exact client_id of its table and no
// other spelling, in the table of its deployment only, and the zero table
// trusts nobody.
func TestTrusted(t *testing.T) {
	t.Parallel()

	for name, want := range trustedCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			id := want.id

			if got := resource.Select(originProd).Trusted(id); got != want.production {
				t.Errorf("production: Trusted(%q) = %v, want %v", id, got, want.production)
			}

			if got := resource.Select(originLocalPort).Trusted(id); got != want.development {
				t.Errorf("development: Trusted(%q) = %v, want %v", id, got, want.development)
			}

			if (resource.Table{}).Trusted(id) {
				t.Errorf("the zero table trusts %q", id)
			}
		})
	}
}

// TestLookupIsExact: only the exact URL is a resource. A client that writes it
// another way is a client that has not named the resource, so it is refused
// rather than corrected.
func TestLookupIsExact(t *testing.T) {
	t.Parallel()

	tests := lookupCases()

	table := resource.Select(originProd)

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, found := table.Lookup(tt.url)
			if found != tt.found {
				t.Fatalf("found = %v, want %v", found, tt.found)
			}

			if !found && (got.URL != "" || got.Scopes != nil || got.Defaults != nil) {
				t.Errorf("a miss returned %+v", got)
			}
		})
	}
}

// TestLookupInOtherTables: the development table knows only its own URL, and
// the zero table none.
func TestLookupInOtherTables(t *testing.T) {
	t.Parallel()

	dev := resource.Select(originLocal)
	zero := resource.Table{}

	tests := []struct {
		name string
		got  func() bool
		want bool
	}{
		{"development knows its URL", func() bool { _, found := dev.Lookup(resource.DevelopmentURL); return found }, true},
		{"development does not know the production URL", func() bool {
			_, found := dev.Lookup(resource.ProductionURL)

			return found
		}, false},
		{"the zero table knows no resource", func() bool {
			_, found := zero.Lookup(resource.ProductionURL)

			return found
		}, false},
		{"the zero table is production", zero.Development, false},
		{"the zero table has no entries", func() bool { return len(zero.Entries()) != 0 }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.got(); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHasScope: a scope is exactly one of the resource's, nothing near it.
func TestHasScope(t *testing.T) {
	t.Parallel()

	entry, found := resource.Select(originProd).Lookup(resource.ProductionURL)
	if !found {
		t.Fatal("no resource")
	}

	tests := hasScopeCases()

	for scope, want := range tests {
		// %q keeps an empty scope and one with a space at either end readable.
		t.Run(fmt.Sprintf("%q", scope), func(t *testing.T) {
			t.Parallel()

			if got := entry.HasScope(scope); got != want {
				t.Errorf("HasScope(%q) = %v, want %v", scope, got, want)
			}
		})
	}
}

// TestTablesAreIsolatedCopies: what a caller gets is a copy, so changing it
// cannot change the resource another request sees.
func TestTablesAreIsolatedCopies(t *testing.T) {
	t.Parallel()

	table := resource.Select(originProd)

	entries := table.Entries()
	entries[0].URL = "https://evil.example/mcp"
	entries[0].Scopes[0] = scopeEvil
	entries[0].Defaults[0] = scopeEvil

	looked, found := table.Lookup(resource.ProductionURL)
	if !found {
		t.Fatal("the resource is gone")
	}

	looked.Scopes[0] = scopeEvil
	looked.Defaults[1] = scopeEvil

	fresh := table.Entries()[0]
	if fresh.URL != resource.ProductionURL ||
		!slices.Equal(fresh.Scopes, []string{scopeRead, scopeWrite}) ||
		!slices.Equal(fresh.Defaults, []string{scopeRead, scopeWrite}) {
		t.Errorf("the table was changed through a copy: %+v", fresh)
	}

	if _, found := table.Lookup("https://evil.example/mcp"); found {
		t.Error("a URL written to a copy became a resource")
	}
}

// TestAllowsLocalHTTP: only the development table, and only http://localhost,
// on any port, allows a plain-http client URL.
func TestAllowsLocalHTTP(t *testing.T) {
	t.Parallel()

	tests := localCases()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsed, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			if got := resource.Select(originLocalPort).AllowsLocalHTTP(parsed); got != tt.development {
				t.Errorf("development: AllowsLocalHTTP = %v, want %v", got, tt.development)
			}

			if got := resource.Select(originProd).AllowsLocalHTTP(parsed); got != tt.production {
				t.Errorf("production: AllowsLocalHTTP = %v, want %v", got, tt.production)
			}

			if got := (resource.Table{}).AllowsLocalHTTP(parsed); got != tt.production {
				t.Errorf("zero table: AllowsLocalHTTP = %v, want %v", got, tt.production)
			}
		})
	}
}
