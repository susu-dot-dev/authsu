//nolint:goconst,lll,dupword // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/scope"
)

// resourceRows is the table of ParseResourceID, with the outcome in each of the
// two resource tables.
func resourceRows() []tableCase {
	return []tableCase{
		{"the production resource", resource.ProductionURL, true, false},
		{"the development resource", resource.DevelopmentURL, false, true},
		same("a trailing slash", resource.ProductionURL+"/", false),
		same("a trailing slash on the development one", resource.DevelopmentURL+"/", false),
		same("an upper-case host", "https://API.susu.dev/mcp", false),
		same("an upper-case scheme", "HTTPS://auth.susu.dev/mcp", false),
		same("an upper-case path", "https://auth.susu.dev/MCP", false),
		same("the default port written out", "https://auth.susu.dev:443/mcp", false),
		same("a query", resource.ProductionURL+"?a=1", false),
		same("a fragment", resource.ProductionURL+"#f", false),
		same("a different path", "https://auth.susu.dev/mcp2", false),
		same("a prefix of the path", "https://auth.susu.dev/mc", false),
		same("the origin", "https://auth.susu.dev", false),
		same("an extended path", "https://auth.susu.dev/mcp/x", false),
		same("a subdomain", "https://x.auth.susu.dev/mcp", false),
		same("a lookalike host", "https://auth.susu.dev.evil.com/mcp", false),
		same("userinfo that hides a host", "https://auth.susu.dev@evil.com/mcp", false),
		same("an encoded path", "https://auth.susu.dev/%6dcp", false),
		same("a dot segment", "https://auth.susu.dev/x/../mcp", false),
		same("http for the production resource", "http://auth.susu.dev/mcp", false),
		same("https for the development resource", "https://localhost:8788/mcp", false),
		same("an authsu URL", "https://auth.example.com/", false),
		same("empty", "", false),
		same("a space", " "+resource.ProductionURL, false),
		same("a trailing space", resource.ProductionURL+" ", false),
		same("a trailing newline", resource.ProductionURL+"\n", false),
		same("NUL", resource.ProductionURL+"\x00", false),
		same("non-ASCII", "https://auth.susu.dev/mc\u0440", false),
		same("two resources", resource.ProductionURL+" "+resource.DevelopmentURL, false),
		same("a megabyte", strings.Repeat("a", 1<<20), false),
	}
}

func TestParseResourceID(t *testing.T) {
	t.Parallel()

	parse := func(table resource.Table) func(string) (string, error) {
		return strAdapter(withTable(input.ParseResourceID, table), input.ResourceID.String)
	}

	t.Run("production", func(t *testing.T) {
		t.Parallel()
		runStringTable(t, casesFor(resourceRows(), false), parse(productionTable()), input.CodeInvalidResource)
	})

	t.Run("development", func(t *testing.T) {
		t.Parallel()
		runStringTable(t, casesFor(resourceRows(), true), parse(developmentTable()), input.CodeInvalidResource)
	})

	t.Run("the zero table", func(t *testing.T) {
		t.Parallel()

		_, err := input.ParseResourceID(resource.ProductionURL, resource.Table{})
		requireRefusal(t, err, input.CodeInvalidResource)
	})
}

func TestResourceIDEntry(t *testing.T) {
	t.Parallel()

	id, err := input.ParseResourceID(resource.ProductionURL, productionTable())
	if err != nil {
		t.Fatal(err)
	}

	entry := id.Entry()
	if entry.URL != resource.ProductionURL || entry.Name != resource.Name || !entry.HasScope(resource.ScopeRead) {
		t.Errorf("Entry() = %+v", entry)
	}

	// A caller that changes what it was given changes nothing else.
	entry.Scopes[0] = "evil:all"
	entry.Defaults[0] = "evil:all"

	again := id.Entry()
	if !again.HasScope(resource.ScopeRead) || again.HasScope("evil:all") || again.Defaults[0] != resource.ScopeRead {
		t.Errorf("Entry() shares storage between calls: %+v", again)
	}
}

func FuzzParseResourceID(f *testing.F) {
	for _, seed := range []string{resource.ProductionURL, resource.DevelopmentURL, "", resource.ProductionURL + "/", "x"} {
		f.Add(seed, false)
		f.Add(seed, true)
	}

	_, probe := input.ParseResourceID("\x00", productionTable())
	description := probeDescription(probe)

	f.Fuzz(func(t *testing.T, raw string, development bool) {
		table, want := productionTable(), resource.ProductionURL
		if development {
			table, want = developmentTable(), resource.DevelopmentURL
		}

		id, err := input.ParseResourceID(raw, table)
		if err != nil {
			if raw == want {
				t.Fatalf("refused the table's own URL: %v", err)
			}

			requireFixedRefusal(t, err, input.CodeInvalidResource, description)

			return
		}

		if raw != want || id.String() != raw || id.Entry().URL != raw {
			t.Fatalf("accepted %q, the table's is %q", raw, want)
		}
	})
}

// scopeCase is one row of the ParseOAuthScopes table.
type scopeCase struct {
	name    string
	in      string
	present bool
	// ok is whether it is accepted; when it is, want is String() and openid
	// OpenID().
	ok     bool
	want   string
	openid bool
}

// scopeCases is the table, against the production resource: scopes mcp:read
// and mcp:write, both the default.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func scopeCases() []scopeCase {
	return []scopeCase{
		// Absent: the defaults, written out.
		{"absent", "", false, true, "mcp:read mcp:write", false},
		{"absent, with a value that is ignored", "anything at all", false, true, "mcp:read mcp:write", false},

		// Accepted.
		{"one scope", "mcp:read", true, true, "mcp:read", false},
		{"the other scope", "mcp:write", true, true, "mcp:write", false},
		{"both, in the table's order", "mcp:read mcp:write", true, true, "mcp:read mcp:write", false},
		{"both, in the other order, kept", "mcp:write mcp:read", true, true, "mcp:write mcp:read", false},
		{"openid alone", "openid", true, true, "openid", true},
		{"openid first", "openid mcp:read", true, true, "openid mcp:read", true},
		{"openid last", "mcp:read openid", true, true, "mcp:read openid", true},
		{"openid between", "mcp:read openid mcp:write", true, true, "mcp:read openid mcp:write", true},
		{"all three", "openid mcp:read mcp:write", true, true, "openid mcp:read mcp:write", true},

		// Present and empty.
		{"present and empty", "", true, false, "", false},
		{"a single space", " ", true, false, "", false},
		{"two spaces", "  ", true, false, "", false},

		// Separators.
		{"a leading space", " mcp:read", true, false, "", false},
		{"a trailing space", "mcp:read ", true, false, "", false},
		{"a doubled space", "mcp:read  mcp:write", true, false, "", false},
		{"a tripled space", "mcp:read   mcp:write", true, false, "", false},
		{"a tab", "mcp:read\tmcp:write", true, false, "", false},
		{"a trailing tab", "mcp:read\t", true, false, "", false},
		{"a newline", "mcp:read\nmcp:write", true, false, "", false},
		{"a carriage return", "mcp:read\rmcp:write", true, false, "", false},
		{"a vertical tab", "mcp:read\vmcp:write", true, false, "", false},
		{"a form feed", "mcp:read\fmcp:write", true, false, "", false},
		{"a comma", "mcp:read,mcp:write", true, false, "", false},
		{"a comma and a space", "mcp:read, mcp:write", true, false, "", false},
		{"a plus, which a form decoder turns into a space only on the wire", "mcp:read+mcp:write", true, false, "", false},
		{"a percent-encoded space", "mcp:read%20mcp:write", true, false, "", false},
		{"a semicolon", "mcp:read;mcp:write", true, false, "", false},
		{"a no-break space", "mcp:read\u00a0mcp:write", true, false, "", false},
		{"an ideographic space", "mcp:read\u3000mcp:write", true, false, "", false},
		{"a zero-width space", "mcp:read\u200bmcp:write", true, false, "", false},
		{"NUL", "mcp:read\x00", true, false, "", false},
		{"NUL as a separator", "mcp:read\x00mcp:write", true, false, "", false},
		{"a trailing newline", "mcp:read\n", true, false, "", false},

		// Names.
		{"an unknown scope", "mcp:admin", true, false, "", false},
		{"a known and an unknown scope", "mcp:read mcp:admin", true, false, "", false},
		{"openid and an unknown scope", "openid profile", true, false, "", false},
		{"profile", "profile", true, false, "", false},
		{"email", "email", true, false, "", false},
		{"offline_access", "offline_access", true, false, "", false},
		{"upper-case scope", "MCP:READ", true, false, "", false},
		{"a capitalised scope", "Mcp:read", true, false, "", false},
		{"upper-case openid", "OpenID", true, false, "", false},
		{"a prefix of a scope", "mcp", true, false, "", false},
		{"a scope with no action", "mcp:", true, false, "", false},
		{"a scope with an extra part", "mcp:read:all", true, false, "", false},
		{"a scope with a suffix", "mcp:read2", true, false, "", false},
		{"a wildcard", "*", true, false, "", false},
		{"a resource wildcard", "mcp:*", true, false, "", false},
		{"all", "all", true, false, "", false},
		{"a Cyrillic lookalike", "mcp:r\u0435ad", true, false, "", false},
		{"a fullwidth colon", "mcp\uff1aread", true, false, "", false},
		{"invalid UTF-8", "mcp:read\xff", true, false, "", false},
		{"an authsu scope", string(scope.UserRead), true, false, "", false},
		{"an authsu scope with a resource one", "mcp:read " + string(scope.KeyCreate), true, false, "", false},
		{"an authsu bundle", scope.DefaultSession, true, false, "", false},
		{"a resource URL", resource.ProductionURL, true, false, "", false},

		// Duplicates.
		{"a repeated scope", "mcp:read" + " " + "mcp:read", true, false, "", false},
		{"a repeated scope, not adjacent", "mcp:read mcp:write mcp:read", true, false, "", false},
		{"a repeated openid", "openid" + " " + "openid", true, false, "", false},
		{"a repeated openid, not adjacent", "openid mcp:read openid", true, false, "", false},

		// Size.
		{"a megabyte", strings.Repeat("mcp:read ", 1<<17), true, false, "", false},
		{"a megabyte of one scope", strings.Repeat("a", 1<<20), true, false, "", false},
	}
}

func TestParseOAuthScopes(t *testing.T) {
	t.Parallel()

	entry := resourceEntry(t)

	_, probe := input.ParseOAuthScopes("\x00", true, entry)
	description := descriptionOf(t, probe, input.CodeInvalidOAuthScope)

	for _, tc := range scopeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseOAuthScopes(tc.in, tc.present, entry)
			if !tc.ok {
				requireFixedRefusal(t, err, input.CodeInvalidOAuthScope, description)

				if got.String() != "" || got.OpenID() {
					t.Errorf("a refused value returned %q", got.String())
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			requireStoredScopes(t, tc, got, entry)
		})
	}
}

// requireStoredScopes checks an accepted value: it is what was sent, or the
// defaults, and its stored form reads back as itself.
func requireStoredScopes(t *testing.T, tc scopeCase, got input.OAuthScopes, entry resource.Entry) {
	t.Helper()

	if got.String() != tc.want || got.OpenID() != tc.openid || (tc.present && got.String() != tc.in) {
		t.Errorf("String() = %q, OpenID() = %v; want %q, %v", got.String(), got.OpenID(), tc.want, tc.openid)
	}

	again, err := input.ParseOAuthScopes(got.String(), true, entry)
	if err != nil || again != got {
		t.Errorf("the stored form %q reads back as %v, %v", got.String(), again, err)
	}
}

// TestOAuthScopesBounds: the entry may define any number of scopes, the request
// may name only so many, and only so long.
func TestOAuthScopesBounds(t *testing.T) {
	t.Parallel()

	names := make([]string, 40)
	for i := range names {
		names[i] = "s" + strconv.Itoa(i)
	}

	many := resource.Entry{URL: "x", Scopes: names, Defaults: names[:1]}

	long := func(n int) string { return strings.Repeat("a", n) }
	one := func(n int) resource.Entry { return resource.Entry{Scopes: []string{long(n)}} }

	for _, tc := range []struct {
		name  string
		entry resource.Entry
		in    string
		ok    bool
	}{
		{"the most names", many, strings.Join(names[:input.MaxOAuthScopeEntries], " "), true},
		{"one name over", many, strings.Join(names[:input.MaxOAuthScopeEntries+1], " "), false},
		{"all forty names", many, strings.Join(names, " "), false},
		{"the longest text", one(input.MaxOAuthScopeBytes), long(input.MaxOAuthScopeBytes), true},
		{"one byte over", one(input.MaxOAuthScopeBytes + 1), long(input.MaxOAuthScopeBytes + 1), false},
		{
			"the longest text of two names",
			resource.Entry{Scopes: []string{long(input.MaxOAuthScopeBytes - 2), "b"}},
			long(input.MaxOAuthScopeBytes-2) + " b",
			true,
		},
		{
			"one byte over, of two names",
			resource.Entry{Scopes: []string{long(input.MaxOAuthScopeBytes - 1), "b"}},
			long(input.MaxOAuthScopeBytes-1) + " b",
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseOAuthScopes(tc.in, true, tc.entry)
			if tc.ok {
				if err != nil || got.String() != tc.in {
					t.Errorf("= %q, %v", got.String(), err)
				}

				return
			}

			requireRefusal(t, err, input.CodeInvalidOAuthScope)
		})
	}
}

// TestOAuthScopesDefaultsAreWrittenOut: absent is the entry's defaults, whatever
// they are, in the entry's order and never aliased to it.
func TestOAuthScopesDefaultsAreWrittenOut(t *testing.T) {
	t.Parallel()

	entry := resource.Entry{URL: "x", Scopes: []string{"a:x", "b:y", "c:z"}, Defaults: []string{"c:z", "a:x"}}

	got, err := input.ParseOAuthScopes("", false, entry)
	if err != nil || got.String() != "c:z a:x" || got.OpenID() {
		t.Fatalf("= %q, %v, %v", got.String(), got.OpenID(), err)
	}

	entry.Defaults[0] = "evil"

	if got.String() != "c:z a:x" {
		t.Errorf("the value changed with the entry: %q", got.String())
	}
}

func scopesOf(t *testing.T, raw string) input.OAuthScopes {
	t.Helper()

	got, err := input.ParseOAuthScopes(raw, true, resourceEntry(t))
	if err != nil {
		t.Fatal(err)
	}

	return got
}

func TestOAuthScopesAccessors(t *testing.T) {
	t.Parallel()

	all := scopesOf(t, "mcp:write openid mcp:read")

	if got := all.Names(); !slices.Equal(got, []string{"mcp:write", "openid", "mcp:read"}) {
		t.Errorf("Names() = %v", got)
	}

	if got := all.Resource(); !slices.Equal(got, []string{"mcp:write", "mcp:read"}) {
		t.Errorf("Resource() = %v", got)
	}

	if got := scopesOf(t, "openid").Resource(); len(got) != 0 {
		t.Errorf("Resource() of openid alone = %v", got)
	}
}

// TestOAuthScopesSlicesAreCopies: what a caller does to a returned slice does not
// reach the value.
func TestOAuthScopesSlicesAreCopies(t *testing.T) {
	t.Parallel()

	all := scopesOf(t, "mcp:write openid mcp:read")

	all.Names()[0] = "evil"
	all.Resource()[0] = "evil"

	if got := all.String(); got != "mcp:write openid mcp:read" || slices.Contains(all.Names(), "evil") {
		t.Errorf("a returned slice changed the value: %q", got)
	}
}

func TestZeroOAuthScopesIsEmpty(t *testing.T) {
	t.Parallel()

	var zero input.OAuthScopes

	requireNoFlaws(t, "the zero value",
		flaw{len(zero.Names()) != 0 || len(zero.Resource()) != 0, "has names"},
		flaw{zero.OpenID(), "has openid"},
	)
}

// TestResourceTablesFitTheirBounds: every entry of both tables, written out as
// the longest scope a request could name, fits the bounds the schema carries,
// so a legitimate grant never reaches a CHECK. It fails if a table is changed
// to outgrow them.
func TestResourceTablesFitTheirBounds(t *testing.T) {
	t.Parallel()

	for _, table := range []resource.Table{productionTable(), developmentTable()} {
		for _, entry := range table.Entries() {
			requireEntryFits(t, entry)
		}
	}
}

func requireEntryFits(t *testing.T, entry resource.Entry) {
	t.Helper()

	if len(entry.URL) > input.MaxResourceBytes {
		t.Errorf("%s is %d bytes, over MaxResourceBytes %d", entry.URL, len(entry.URL), input.MaxResourceBytes)
	}

	requireNoFlaws(t, entry.URL,
		flaw{entry.HasScope(input.OpenIDScope), "defines openid, which is not the resource's"},
		flaw{len(entry.Defaults) == 0, "has no default scopes"},
		flaw{len(entry.Scopes)+1 > input.MaxOAuthScopeEntries, "has more scopes than a request may name"},
	)

	for _, name := range entry.Scopes {
		_, err := scope.Names([]string{name}).Get()
		if err == nil {
			t.Errorf("%s: %q is one of authsu's own scopes", entry.URL, name)
		}
	}

	// The whole of what the entry can be asked, in the request's own form, is accepted.
	text := strings.Join(append(slices.Clone(entry.Scopes), input.OpenIDScope), " ")

	got, err := input.ParseOAuthScopes(text, true, entry)
	if err != nil || got.String() != text {
		t.Errorf("%s: every scope (%d bytes) is refused: %q, %v", entry.URL, len(text), got.String(), err)
	}

	defaults, err := input.ParseOAuthScopes("", false, entry)
	if err != nil || defaults.String() != strings.Join(entry.Defaults, " ") {
		t.Errorf("%s: defaults = %q, %v", entry.URL, defaults.String(), err)
	}
}

func FuzzParseOAuthScopes(f *testing.F) {
	for _, tc := range scopeCases() {
		f.Add(tc.in)
	}

	f.Add("mcp:read mcp:write openid")

	entry, _ := productionTable().Lookup(resource.ProductionURL)

	_, probe := input.ParseOAuthScopes("\x00", true, entry)
	description := probeDescription(probe)

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := input.ParseOAuthScopes(raw, true, entry)
		if err != nil {
			requireFixedRefusal(t, err, input.CodeInvalidOAuthScope, description)

			return
		}

		if got.String() != raw || len(raw) > input.MaxOAuthScopeBytes {
			t.Fatalf("String() = %q, want %q", got.String(), raw)
		}

		requireKnownDistinctNames(t, raw, got, entry)

		again, err := input.ParseOAuthScopes(got.String(), true, entry)
		if err != nil || again != got {
			t.Fatalf("re-parse of %q = %v, %v", raw, again, err)
		}
	})
}

// requireKnownDistinctNames checks an accepted scope: every name is known and
// appears once, and OpenID says whether openid is one of them.
func requireKnownDistinctNames(t *testing.T, raw string, got input.OAuthScopes, entry resource.Entry) {
	t.Helper()

	seen := map[string]bool{}

	for name := range strings.SplitSeq(raw, " ") {
		if seen[name] || (name != "openid" && !entry.HasScope(name)) || !slices.Contains(got.Names(), name) {
			t.Fatalf("accepted %q with the name %q", raw, name)
		}

		seen[name] = true
	}

	if got.OpenID() != seen["openid"] {
		t.Fatalf("OpenID() = %v for %q", got.OpenID(), raw)
	}
}

// firstPartyScopeCases is the table of ParseFirstPartyScopes, against the login
// resource, whose one scope is profile. want is what is stored, and openid
// whether it asks for an ID token. email is the profile and offline_access is
// dropped, so neither is ever stored; anything else is as strict as for any
// resource.
func firstPartyScopeCases() []scopeCase {
	return []scopeCase{
		// Absent: the defaults, written out.
		{"absent", "", false, true, "profile", false},
		{"absent, with a value that is ignored", "anything", false, true, "profile", false},

		// Accepted, with the two names read.
		{"profile", "profile", true, true, "profile", false},
		{"openid profile", "openid profile", true, true, "openid profile", true},
		{"the whole OpenID Connect request", "openid email profile offline_access", true, true, "openid profile", true},
		{"email is the profile", "email", true, true, "profile", false},
		{"email, kept where it stood", "openid email", true, true, "openid profile", true},
		{"email then profile is one", "email profile", true, true, "profile", false},
		{"profile then email is one", "profile email", true, true, "profile", false},
		{"offline_access is dropped", "profile offline_access", true, true, "profile", false},
		{"offline_access first", "offline_access openid profile", true, true, "openid profile", true},
		{"openid alone", "openid", true, true, "openid", true},
		{"openid and offline_access", "openid offline_access", true, true, "openid", true},
		{"offline_access alone", "offline_access", true, true, "", false},

		// Refused as for any resource.
		{"present and empty", "", true, false, "", false},
		{"a leading space", " profile", true, false, "", false},
		{"a trailing space", "profile ", true, false, "", false},
		{"a doubled space", "openid  profile", true, false, "", false},
		{"a tab", "openid\tprofile", true, false, "", false},
		{"a comma", "openid,profile", true, false, "", false},
		{"NUL", "profile\x00", true, false, "", false},
		{"upper-case profile", "PROFILE", true, false, "", false},
		{"upper-case email", "Email", true, false, "", false},
		{"upper-case offline_access", "OFFLINE_ACCESS", true, false, "", false},
		{"offline-access", "offline-access", true, false, "", false},
		{"an unknown scope", "openid profile admin", true, false, "", false},
		{"an MCP scope", "openid profile mcp:read", true, false, "", false},
		{"an MCP scope with email", "email mcp:write", true, false, "", false},
		{"an authsu scope", string(scope.UserRead), true, false, "", false},
		{"address, which is not offered", "openid address", true, false, "", false},
		{"phone, which is not offered", "phone", true, false, "", false},
		{"a repeated profile", "profile profile", true, false, "", false},
		{"a repeated email", "email email", true, false, "", false},
		{"a repeated offline_access", "offline_access profile offline_access", true, false, "", false},
		{"a repeated openid", "openid profile openid", true, false, "", false},
		{"a megabyte", strings.Repeat("profile ", 1<<17), true, false, "", false},
		{"more names than a request may have", strings.Repeat("a ", input.MaxOAuthScopeEntries) + "profile", true, false, "", false},
	}
}

// TestParseFirstPartyScopes: the login resource's scope is read as any
// resource's, with email read as profile and offline_access dropped. Nothing the
// resource does not define is stored.
func TestParseFirstPartyScopes(t *testing.T) {
	t.Parallel()

	entry := loginEntry(t)

	_, probe := input.ParseFirstPartyScopes("\x00", true, entry)
	description := descriptionOf(t, probe, input.CodeInvalidOAuthScope)

	for _, tc := range firstPartyScopeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseFirstPartyScopes(tc.in, tc.present, entry)
			if !tc.ok {
				requireFixedRefusal(t, err, input.CodeInvalidOAuthScope, description)

				if got.String() != "" || got.OpenID() {
					t.Errorf("a refused value returned %q", got.String())
				}

				return
			}

			if err != nil {
				t.Fatalf("refused: %v", err)
			}

			requireFirstPartyStored(t, tc, got, entry)
		})
	}
}

// requireFirstPartyStored holds what an accepted login scope is stored as: the
// expected text, neither tolerated name, and a form the strict parser reads back
// as it is.
func requireFirstPartyStored(t *testing.T, tc scopeCase, got input.OAuthScopes, entry resource.Entry) {
	t.Helper()

	if got.String() != tc.want || got.OpenID() != tc.openid ||
		slices.Contains(got.Names(), input.EmailScope) || slices.Contains(got.Names(), input.OfflineAccessScope) {
		t.Errorf("String() = %q, OpenID() = %v, want %q, %v and neither email nor offline_access",
			got.String(), got.OpenID(), tc.want, tc.openid)
	}

	if got.String() == "" {
		return
	}

	again, err := input.ParseOAuthScopes(got.String(), true, entry)
	if err != nil || again.String() != got.String() {
		t.Errorf("the stored %q is not read back as it is: %q, %v", got.String(), again.String(), err)
	}
}

// TestFirstPartyNamesAreRefusedElsewhere: email and offline_access are the login
// resource's tolerance alone. The strict parser refuses each, for the login
// resource and for the MCP resource, and the tolerant one refuses email for an
// entry with no scope for it to stand for.
func TestFirstPartyNamesAreRefusedElsewhere(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"email", "offline_access", "openid email profile offline_access", "profile email"} {
		for name, entry := range map[string]resource.Entry{"login": loginEntry(t), "mcp": resourceEntry(t)} {
			t.Run(name+" "+raw, func(t *testing.T) {
				t.Parallel()

				_, err := input.ParseOAuthScopes(raw, true, entry)
				requireRefusal(t, err, input.CodeInvalidOAuthScope)
			})
		}
	}

	_, err := input.ParseFirstPartyScopes("email", true, resource.Entry{})
	requireRefusal(t, err, input.CodeInvalidOAuthScope)
}

func FuzzParseFirstPartyScopes(f *testing.F) {
	for _, tc := range firstPartyScopeCases() {
		f.Add(tc.in)
	}

	entry, _ := productionTable().Lookup(resource.ProductionLoginURL)

	_, probe := input.ParseFirstPartyScopes("\x00", true, entry)
	description := probeDescription(probe)

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := input.ParseFirstPartyScopes(raw, true, entry)
		if err != nil {
			requireFixedRefusal(t, err, input.CodeInvalidOAuthScope, description)

			return
		}

		if len(raw) > input.MaxOAuthScopeBytes {
			t.Fatalf("accepted %d bytes", len(raw))
		}

		// Whatever was accepted is stored as only openid and the entry's scope, once
		// each, and reads back through the strict parser.
		for _, name := range got.Names() {
			if name != input.OpenIDScope && !entry.HasScope(name) {
				t.Fatalf("stored %q from %q", name, raw)
			}
		}

		if len(got.Names()) > 0 {
			again, err := input.ParseOAuthScopes(got.String(), true, entry)
			if err != nil || again.String() != got.String() {
				t.Fatalf("the stored %q does not read back: %v", got.String(), err)
			}
		}
	})
}
