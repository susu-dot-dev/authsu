//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
)

// longHost is a 253-byte host of three 63-character labels and one of 61, the
// longest a DNS name may be.
func longHost() string {
	label := strings.Repeat("a", 63)

	return label + "." + label + "." + label + "." + strings.Repeat("a", 61)
}

// clientIDRows is the table of ParseClientID, with the outcome in each of the
// two resource tables.
func clientIDRows() []tableCase {
	return slices.Concat(clientIDAccepted(), clientIDShapeRows(), clientIDHostRows())
}

// clientIDAccepted are the rows of a client_id that is accepted.
func clientIDAccepted() []tableCase {
	const base = "https://example.com/"

	return []tableCase{
		// Accepted.
		same("a document at a path", "https://example.com/client.json", true),
		same("a deeper path", "https://example.com/oauth/client-metadata.json", true),
		same("a trailing slash after a name", "https://example.com/client/", true),
		same("an explicit port that is not the default", "https://example.com:8443/c", true),
		same("port 1", "https://example.com:1/c", true),
		same("port 65535", "https://example.com:65535/c", true),
		same("subdomains", "https://client.sub.example.co.uk/x", true),
		same("a punycode label", "https://xn--bcher-kva.example.com/x", true),
		same("hyphens inside labels", "https://a-b.example-site.com/x", true),
		same("a label that is all digits, not the last", "https://1.example.com/x", true),
		same("a DNS name that starts like an address", "https://127.0.0.1.example.com/x", true),
		same("a last label that ends in a digit", "https://example.com1/x", true),
		same("an @ in the path", "https://example.com/a@b", true),
		same("a path with upper-case letters", "https://example.com/Client.JSON", true),
		same("dots inside a segment", "https://example.com/a..b/.../...x", true),
		same("a dot-prefixed segment", "https://example.com/.well-known/client", true),
		same("an empty segment", "https://example.com/a//b", true),
		same("a semicolon and a comma in the path", "https://example.com/a;b,c", true),
		same("the longest DNS name", "https://"+longHost()+"/x", true),
		same("exactly the bound", base+strings.Repeat("a", input.MaxClientIDBytes-len(base)), true),

		// The development table alone allows http, for localhost.
		{"http localhost with a path", "http://localhost/client.json", false, true},
		{"http localhost with a port", "http://localhost:8080/client.json", false, true},
		{"http localhost, port 65535", "http://localhost:65535/c", false, true},
		{"http localhost, deep path", "http://localhost:9000/a/b/c.json", false, true},
	}
}

// clientIDShapeRows are the rows about the scheme, the path, userinfo, the query,
// the fragment, dot segments, percent-encoding, the port and case.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func clientIDShapeRows() []tableCase {
	return []tableCase{
		// http is refused everywhere else.
		same("http for a public host", "http://example.com/client.json", false),
		same("http for a lookalike of localhost", "http://localhost.example.com/c", false),
		same("http for a subdomain of localhost", "http://app.localhost/c", false),
		same("http for upper-case LOCALHOST", "http://LOCALHOST/c", false),
		same("http for 127.0.0.1", "http://127.0.0.1/c", false),
		same("http for [::1]", "http://[::1]:8080/c", false),
		same("http localhost, the default port written out", "http://localhost:80/c", false),
		same("http localhost, an empty port", "http://localhost:/c", false),
		same("http localhost, port 0", "http://localhost:0/c", false),
		same("http localhost, port 65536", "http://localhost:65536/c", false),
		same("http localhost, a leading zero in the port", "http://localhost:08080/c", false),
		same("http localhost, no path", "http://localhost", false),
		same("http localhost, the root path", "http://localhost/", false),
		same("http localhost, a query", "http://localhost/c?a=1", false),
		same("http localhost, userinfo", "http://user@localhost/c", false),
		same("http localhost, a fragment", "http://localhost/c#f", false),
		same("http localhost, a dot segment", "http://localhost/a/../c", false),
		same("https localhost", "https://localhost/c", false),
		same("https localhost with a port", "https://localhost:8443/c", false),
		same("a host that ends in .localhost", "https://app.localhost/c", false),

		// Scheme, and what is not an absolute URL.
		same("empty", "", false),
		same("a scheme only", "https://", false),
		same("an empty host", "https:///x", false),
		same("no scheme", "example.com/client.json", false),
		same("a scheme-relative URL", "//example.com/client.json", false),
		same("a path", "/client.json", false),
		same("an opaque URL", "https:example.com/client.json", false),
		same("mailto", "mailto:a@example.com", false),
		same("ftp", "ftp://example.com/client.json", false),
		same("javascript", "javascript:alert(1)", false),
		same("data", "data:application/json,{}", false),
		same("file", "file:///etc/passwd", false),
		same("a custom scheme", "myapp://example.com/client.json", false),
		same("upper-case scheme", "HTTPS://example.com/client.json", false),
		same("capitalised scheme", "Https://example.com/client.json", false),
		same("scheme with a space", "ht tps://example.com/c", false),
		same("two schemes", "https://https://example.com/c", false),

		// The path.
		same("no path", "https://example.com", false),
		same("the root path", "https://example.com/", false),
		same("the root path with a port", "https://example.com:8443/", false),

		// Userinfo.
		same("a user", "https://user@example.com/c", false),
		same("a user and password", "https://user:pw@example.com/c", false),
		same("an empty userinfo", "https://@example.com/c", false),
		same("a lookalike host before the @", "https://example.com@evil.com/c", false),
		same("a host and port before the @", "https://example.com:443@evil.com/c", false),
		same("a password that looks like a port", "https://example.com:pw@evil.com/c", false),

		// Fragment and query.
		same("an empty fragment", "https://example.com/c#", false),
		same("a fragment", "https://example.com/c#frag", false),
		same("a fragment before the path", "https://example.com#/c", false),
		same("a fragment that looks like userinfo", "https://example.com/c#@evil.com", false),
		same("an empty query", "https://example.com/c?", false),
		same("a query", "https://example.com/c?a=1", false),
		same("a query before the path", "https://example.com?x/y", false),
		same("a query and a fragment", "https://example.com/c?a=1#f", false),

		// Dot segments, spelled every way.
		same("a single dot", "https://example.com/.", false),
		same("two dots", "https://example.com/..", false),
		same("a dot in the middle", "https://example.com/a/./b", false),
		same("two dots in the middle", "https://example.com/a/../b", false),
		same("two dots at the end", "https://example.com/a/..", false),
		same("a dot at the end", "https://example.com/a/.", false),
		same("a dot and a slash", "https://example.com/./", false),
		same("a dot first", "https://example.com/./c", false),
		same("two dots first", "https://example.com/../c", false),
		same("an encoded dot", "https://example.com/%2e", false),
		same("an upper-case encoded dot", "https://example.com/%2E/c", false),
		same("two encoded dots", "https://example.com/%2e%2e/c", false),
		same("two upper-case encoded dots", "https://example.com/a/%2E%2E/b", false),
		same("a dot and an encoded dot", "https://example.com/.%2e/c", false),
		same("an encoded dot and a dot", "https://example.com/%2e./c", false),
		same("an encoded slash after dots", "https://example.com/a/..%2fb", false),
		same("an encoded backslash", "https://example.com/a%5cb", false),

		// Percent-encoding, anywhere.
		same("an encoded space", "https://example.com/a%20b", false),
		same("an encoded letter", "https://example.com/%41", false),
		same("an encoded slash", "https://example.com/a%2fb", false),
		same("an encoded percent", "https://example.com/a%25b", false),
		same("a percent that starts nothing", "https://example.com/a%zz", false),
		same("a bare percent", "https://example.com/a%", false),
		same("an encoded NUL", "https://example.com/a%00", false),
		same("an encoded letter in the host", "https://%65xample.com/c", false),
		same("an encoded letter inside the host", "https://exam%70le.com/c", false),
		same("an encoded slash after the host", "https://example.com%2f/c", false),
		same("an encoded dot in the host", "https://example%2ecom/c", false),
		same("an encoded multibyte character in the host", "https://%C3%A9.example/c", false),

		// Backslashes, which some parsers read as a slash.
		same("a backslash before an @", "https://example.com\\@evil.com/c", false),
		same("a backslash in the path", "https://example.com/a\\b", false),
		same("backslashes for slashes", "https:\\\\example.com\\c", false),
		same("a backslash after the scheme's slashes", "https://\\example.com/c", false),

		// The port.
		same("the default port written out", "https://example.com:443/c", false),
		same("an empty port", "https://example.com:/c", false),
		same("an empty port and no path", "https://example.com:", false),
		same("a port with a leading zero", "https://example.com:0443/c", false),
		same("port 0", "https://example.com:0/c", false),
		same("port 65536", "https://example.com:65536/c", false),
		same("port 99999", "https://example.com:99999/c", false),
		same("a negative port", "https://example.com:-1/c", false),
		same("a signed port", "https://example.com:+8443/c", false),
		same("a port of letters", "https://example.com:abc/c", false),
		same("a port with a space", "https://example.com:84 43/c", false),
		same("two ports", "https://example.com:8443:8443/c", false),
		same("a hex port", "https://example.com:0x1bb/c", false),
		same("a huge port", "https://example.com:"+strings.Repeat("9", 100)+"/c", false),

		// Case.
		same("a capitalised host", "https://Example.com/c", false),
		same("an upper-case host", "https://EXAMPLE.COM/c", false),
		same("an upper-case last label", "https://example.COM/c", false),
		same("an upper-case punycode label", "https://XN--bcher-kva.example.com/c", false),
		same("an upper-case port-less host with a path", "https://Example.com:8443/c", false),
	}
}

// clientIDHostRows are the rows about the host: addresses in every spelling,
// reserved names and malformed names.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func clientIDHostRows() []tableCase {
	label64 := strings.Repeat("a", 64)

	return []tableCase{
		// IP literals.
		same("IPv4 loopback", "https://127.0.0.1/c", false),
		same("IPv4 loopback with a port", "https://127.0.0.1:8443/c", false),
		same("IPv4 private, 192.168", "https://192.168.0.1/c", false),
		same("IPv4 private, 10", "https://10.0.0.1:8443/c", false),
		same("IPv4 private, 172.16", "https://172.16.0.1/c", false),
		same("the cloud metadata address", "https://169.254.169.254/latest/meta-data", false),
		same("IPv4 any", "https://0.0.0.0/c", false),
		same("a public IPv4", "https://1.1.1.1/c", false),
		same("IPv4 with a trailing dot", "https://1.2.3.4./c", false),
		same("IPv4 as one decimal number", "https://2130706433/c", false),
		same("IPv4 as one hex number", "https://0x7f000001/c", false),
		same("IPv4 as one octal number", "https://017700000001/c", false),
		same("IPv4 with a hex first part", "https://0x7f.1/c", false),
		same("IPv4 with a hex last part", "https://1.0x7f/c", false),
		same("IPv4 of two parts", "https://127.1/c", false),
		same("IPv4 of three parts", "https://127.0.1/c", false),
		same("IPv4 with octal parts", "https://0177.0.0.1/c", false),
		same("IPv4 zero", "https://0/c", false),
		same("IPv4 with a leading zero", "https://127.0.0.01/c", false),
		same("IPv4 with a numeric last label and a name before it", "https://example.123/c", false),
		same("IPv4 with a hex last label and a name before it", "https://example.0x7f/c", false),
		same("IPv6 loopback", "https://[::1]/c", false),
		same("IPv6 loopback with a port", "https://[::1]:8443/c", false),
		same("IPv6 documentation address", "https://[2001:db8::1]/c", false),
		same("IPv6 mapped IPv4", "https://[::ffff:127.0.0.1]/c", false),
		same("IPv6 loopback, long form", "https://[0:0:0:0:0:0:0:1]/c", false),
		same("IPv6 with a zone", "https://[fe80::1%25eth0]/c", false),
		same("IPv6 unspecified", "https://[::]/c", false),
		same("a name in brackets", "https://[example.com]/c", false),
		same("an unclosed bracket", "https://[::1/c", false),

		// Reserved and single-label names.
		same("one label", "https://intranet/c", false),
		same("one label with a port", "https://intranet:8443/c", false),
		same("a .local name", "https://printer.local/c", false),
		same("a .internal name", "https://svc.internal/c", false),
		same("a .localdomain name", "https://host.localdomain/c", false),
		same("a reverse-lookup name", "https://1.0.0.127.in-addr.arpa/c", false),
		same("a .localhost name", "https://a.b.localhost/c", false),

		// The last label decides, and every one of the reserved ones is refused
		// alone and under a name, because a name under them resolves inside a
		// network or nowhere. A reserved word as any other label is a name like
		// another.
		same("a .lan name", "https://nas.lan/c", false),
		same("a .home name", "https://router.home/c", false),
		same("a .home.arpa name", "https://router.home.arpa/c", false),
		same("a .corp name", "https://wiki.corp/c", false),
		same("a .intranet name", "https://hr.intranet/c", false),
		same("a .private name", "https://git.private/c", false),
		same("a .test name", "https://client.test/c", false),
		same("a .invalid name", "https://client.invalid/c", false),
		same("a .example name", "https://client.example/c", false),
		same("a .onion name", "https://abcdefghij234567.onion/c", false),
		same("a .arpa name", "https://client.arpa/c", false),
		same("a reserved name under another", "https://a.b.c.corp/c", false),
		same("a reserved name with a port", "https://nas.lan:8443/c", false),
		same("a reserved name over http, which only exactly localhost may be", "http://nas.lan/c", false),
		same("a reserved name under localhost over http", "http://nas.localhost:8080/c", false),
		same("a reserved word as a first label", "https://lan.example.com/c", true),
		same("a reserved word as a middle label", "https://client.test.example.com/c", true),
		same("a reserved word inside a last label", "https://client.mylan/c", true),
		same("a name that only ends like a reserved one", "https://client.notlocal/c", true),
		same("a .example.org name", "https://client.example.org/c", true),

		// Malformed names.
		same("a trailing dot", "https://example.com./c", false),
		same("a leading dot", "https://.example.com/c", false),
		same("an empty label", "https://example..com/c", false),
		same("a leading hyphen", "https://-a.example.com/c", false),
		same("a trailing hyphen", "https://a-.example.com/c", false),
		same("an underscore", "https://exa_mple.com/c", false),
		same("a label of 64 characters", "https://"+label64+".com/c", false),
		same("a label of 63 characters", "https://"+label64[:63]+".com/c", true),
		same("a name of 254 bytes", "https://"+longHost()+"a/c", false),
		same("a space in the host", "https://exa mple.com/c", false),
		same("a fullwidth dot", "https://example\u3002com/c", false),
		same("a fullwidth letter", "https://exampl\uff45.com/c", false),
		same("a non-ASCII letter in the host", "https://ex\u00e4mple.com/c", false),
		same("a CJK host", "https://\u4f8b\u3048.jp/c", false),
		same("a Cyrillic lookalike", "https://\u0435xample.com/c", false),
		same("a zero-width space in the host", "https://exam\u200bple.com/c", false),
		same("a comma in the host", "https://exa,mple.com/c", false),
		same("a star in the host", "https://*.example.com/c", false),
		same("a colon-only port separator", "https://:8443/c", false),

		// Characters that are never in a URL.
		same("a leading space", " https://example.com/c", false),
		same("a trailing space", "https://example.com/c ", false),
		same("a space in the path", "https://example.com/a b", false),
		same("a tab", "https://example.com/a\tb", false),
		same("a trailing newline", "https://example.com/c\n", false),
		same("a newline in the path", "https://example.com/a\nb", false),
		same("a carriage return", "https://example.com/a\rb", false),
		same("NUL at the end", "https://example.com/c\x00", false),
		same("NUL in the path", "https://example.com/a\x00b", false),
		same("NUL in the host", "https://exam\x00ple.com/c", false),
		same("NUL first", "\x00https://example.com/c", false),
		same("DEL", "https://example.com/a\x7fb", false),
		same("a C1 control", "https://example.com/a\u0085b", false),
		same("a non-ASCII letter in the path", "https://example.com/caf\u00e9", false),
		same("an emoji in the path", "https://example.com/\U0001F600", false),
		same("a bidi override", "https://example.com/\u202ejson", false),
		same("invalid UTF-8", "https://example.com/a\xffb", false),
		same("a double quote", "https://example.com/a\"b", false),
		same("angle brackets", "https://example.com/<a>", false),
		same("a caret", "https://example.com/a^b", false),
		same("a backtick", "https://example.com/a`b", false),
		same("braces", "https://example.com/{a}", false),
		same("a pipe", "https://example.com/a|b", false),

		// Size.
		same("one over the bound", "https://example.com/"+strings.Repeat("a", input.MaxClientIDBytes), false),
		same("a megabyte of path", "https://example.com/"+strings.Repeat("a", 1<<20), false),
		same("a megabyte of NULs", strings.Repeat("\x00", 1<<20), false),
	}
}

// clientIDParser is ParseClientID with a table, as runStringTable takes it.
func clientIDParser(table resource.Table) func(string) (string, error) {
	return strAdapter(withTable(input.ParseClientID, table), input.ClientID.String)
}

func TestParseClientID(t *testing.T) {
	t.Parallel()

	rows := clientIDRows()

	t.Run("production", func(t *testing.T) {
		t.Parallel()
		runStringTable(t, casesFor(rows, false), clientIDParser(productionTable()), input.CodeInvalidClientID)
	})

	t.Run("development", func(t *testing.T) {
		t.Parallel()
		runStringTable(t, casesFor(rows, true), clientIDParser(developmentTable()), input.CodeInvalidClientID)
	})

	t.Run("the zero table", func(t *testing.T) {
		t.Parallel()

		// A table that is neither selects nothing: it does not allow http.
		_, err := input.ParseClientID("http://localhost/c", resource.Table{})
		requireRefusal(t, err, input.CodeInvalidClientID)

		got, err := input.ParseClientID("https://example.com/c", resource.Table{})
		if err != nil || got.String() != "https://example.com/c" {
			t.Errorf("https with the zero table: %q, %v", got.String(), err)
		}
	})
}

func TestClientIDHost(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"https://example.com/c":      "example.com",
		"https://example.com:8443/c": "example.com:8443",
	} {
		id, err := input.ParseClientID(in, productionTable())
		if err != nil || id.Host() != want {
			t.Errorf("Host() of %q = %q, %v; want %q", in, id.Host(), err, want)
		}
	}

	local, err := input.ParseClientID("http://localhost:8080/c", developmentTable())
	if err != nil || local.Host() != "localhost:8080" {
		t.Errorf("Host() = %q, %v", local.Host(), err)
	}
}

func TestClientIDDescriptionStatesTheBound(t *testing.T) {
	t.Parallel()

	_, err := input.ParseClientID("", productionTable())
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidClientID), input.MaxClientIDBytes)
}

// TestAcceptedClientIDsAreUnambiguous states, with the standard library as an
// independent check, what every accepted client_id has in common, for the whole
// table: it parses, the parse is the string, and the host is no address.
func TestAcceptedClientIDsAreUnambiguous(t *testing.T) {
	t.Parallel()

	for _, development := range []bool{false, true} {
		for _, tc := range casesFor(clientIDRows(), development) {
			if !tc.ok {
				continue
			}

			table := productionTable()
			if development {
				table = developmentTable()
			}

			id, err := input.ParseClientID(tc.in, table)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			requireUnambiguousClientID(t, id.String())
		}
	}
}

// flaw is a statement that must be false of an accepted value.
type flaw struct {
	present bool
	what    string
}

// requireNoFlaws fails the test for every flaw that is present.
func requireNoFlaws(t *testing.T, raw string, flaws ...flaw) {
	t.Helper()

	for _, f := range flaws {
		if f.present {
			t.Errorf("%q: %s", raw, f.what)
		}
	}
}

func requireUnambiguousClientID(t *testing.T, raw string) {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("%q does not parse: %v", raw, err)
	}

	dotSegment := slices.ContainsFunc(strings.Split(u.Path, "/"), func(segment string) bool {
		return segment == "." || segment == ".."
	})

	requireNoFlaws(t, raw,
		flaw{u.String() != raw, "is not the canonical spelling"},
		flaw{u.User != nil, "has userinfo"},
		flaw{u.Fragment != "" || u.RawQuery != "" || u.ForceQuery, "has a fragment or a query"},
		flaw{u.Opaque != "", "is opaque"},
		flaw{strings.ContainsAny(raw, "%\\ "), "has percent-encoding, a backslash or a space"},
		flaw{u.Path == "" || u.Path == "/", "has no path"},
		flaw{dotSegment, "has a dot segment"},
	)

	requireUnambiguousHost(t, u)
}

// requireUnambiguousHost checks the authority of an accepted client_id.
func requireUnambiguousHost(t *testing.T, u *url.URL) {
	t.Helper()

	host := u.Hostname()
	address := u.Scheme == "https" && (net.ParseIP(host) != nil || isAddress(host))

	requireNoFlaws(t, u.String(),
		flaw{address, "has an IP address as host"},
		flaw{host != strings.ToLower(host) || u.Scheme != strings.ToLower(u.Scheme), "is not lower case"},
		flaw{u.Scheme == "http" && host != "localhost", "is plain http for another host"},
		flaw{u.Port() == "443" || u.Port() == "80", "writes a default port"},
		flaw{strings.HasSuffix(u.Host, ":"), "writes an empty port"},
	)
}

// isAddress reports whether host is an address in any of the spellings a URL
// parser may read: the standard library's, a dotted or one-number IPv4 with
// decimal, octal or hex parts.
func isAddress(host string) bool {
	_, err := netip.ParseAddr(host)
	if err == nil {
		return true
	}

	last := host[strings.LastIndexByte(host, '.')+1:]

	return last != "" && (last[0] >= '0' && last[0] <= '9')
}

func FuzzParseClientID(f *testing.F) {
	for _, row := range clientIDRows() {
		f.Add(row.in, false)
		f.Add(row.in, true)
	}

	_, probe := input.ParseClientID("\x00\xff\x00", productionTable())
	description := probeDescription(probe)

	f.Fuzz(func(t *testing.T, raw string, development bool) {
		table := productionTable()
		if development {
			table = developmentTable()
		}

		id, err := input.ParseClientID(raw, table)
		if err != nil {
			requireFixedRefusal(t, err, input.CodeInvalidClientID, description)

			return
		}

		if id.String() != raw {
			t.Fatalf("String() = %q, want %q", id.String(), raw)
		}

		again, err := input.ParseClientID(raw, table)
		if err != nil || again != id {
			t.Fatalf("re-parse of %q = %v, %v", raw, again, err)
		}

		if len(raw) > input.MaxClientIDBytes {
			t.Fatalf("accepted %d bytes", len(raw))
		}

		requireUnambiguousClientID(t, raw)

		if strings.HasPrefix(raw, "http://") && !development {
			t.Fatalf("accepted %q without the development table", raw)
		}
	})
}
