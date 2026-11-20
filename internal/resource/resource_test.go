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

			wantURL := resource.ProductionURL
			if tt.wantDevelopment {
				wantURL = resource.DevelopmentURL
			}

			entries := table.Entries()
			if len(entries) != 1 || entries[0].URL != wantURL {
				t.Errorf("entries = %+v, want one at %q", entries, wantURL)
			}

			// A table never lists the other table's resource.
			other := resource.DevelopmentURL
			if tt.wantDevelopment {
				other = resource.ProductionURL
			}

			if _, found := table.Lookup(other); found {
				t.Errorf("the table also knows %q", other)
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
// URL alone, so what a developer sees is what production does.
func TestTheTablesAreTheSameResource(t *testing.T) {
	t.Parallel()

	prod := resource.Select(originProd).Entries()
	dev := resource.Select(originLocal).Entries()

	if len(prod) != 1 || len(dev) != 1 {
		t.Fatalf("prod %d entries, dev %d", len(prod), len(dev))
	}

	if prod[0].URL != "https://api.susu.dev/mcp" || dev[0].URL != "http://localhost:8788/mcp" {
		t.Errorf("urls = %q, %q", prod[0].URL, dev[0].URL)
	}

	if resource.DevelopmentPort != 8788 {
		t.Errorf("DevelopmentPort = %d", resource.DevelopmentPort)
	}

	dev[0].URL = prod[0].URL
	if prod[0].Name != dev[0].Name || !slices.Equal(prod[0].Scopes, dev[0].Scopes) ||
		!slices.Equal(prod[0].Defaults, dev[0].Defaults) {
		t.Errorf("tables differ beyond the URL: %+v and %+v", prod[0], dev[0])
	}

	if !slices.Equal(prod[0].Scopes, []string{scopeRead, scopeWrite}) {
		t.Errorf("scopes = %v", prod[0].Scopes)
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
