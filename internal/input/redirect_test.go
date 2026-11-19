//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// redirectCases is the table of ParseRedirectURI.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func redirectCases() []parseCase {
	const base = "https://example.com/"

	label64 := strings.Repeat("a", 64)

	return []parseCase{
		// Accepted: https.
		{"https with a path", "https://app.example.com/cb", true},
		{"https with no path", "https://example.com", true},
		{"https with the root path", "https://example.com/", true},
		{"https with a trailing slash", "https://example.com/cb/", true},
		{"https with a query", "https://example.com/cb?x=1&y=2", true},
		{"https with an encoded query", "https://example.com/cb?x=%20a", true},
		{"https with an encoded path", "https://example.com/%41/b", true},
		{"https with a port", "https://example.com:8443/cb", true},
		{"https with a dot segment, which is only compared", "https://example.com/a/../cb", true},
		{"https with a path in upper case", "https://example.com/CB", true},
		{"https for a DNS name that starts like loopback", "https://127.0.0.1.evil.com/cb", true},
		{"https for a name of one letter labels", "https://a.b/cb", true},
		{"https with a 63 character label", "https://" + label64[:63] + ".com/cb", true},
		{"exactly the bound", base + strings.Repeat("a", input.MaxRedirectURIBytes-len(base)), true},

		// Accepted: loopback.
		{"IPv4 loopback", "http://127.0.0.1/cb", true},
		{"IPv4 loopback, no path", "http://127.0.0.1", true},
		{"IPv4 loopback with a port", "http://127.0.0.1:8080/cb", true},
		{"IPv4 loopback, port 1", "http://127.0.0.1:1/cb", true},
		{"IPv4 loopback, port 65535", "http://127.0.0.1:65535/cb", true},
		{"IPv4 loopback with a query", "http://127.0.0.1:8080/cb?x=1", true},
		{"IPv6 loopback", "http://[::1]/cb", true},
		{"IPv6 loopback with a port", "http://[::1]:49152/cb", true},
		{"IPv6 loopback, no path", "http://[::1]:49152", true},

		// Accepted: localhost is loopback, in every table.
		{"localhost", "http://localhost/cb", true},
		{"localhost with a port", "http://localhost:8080/cb", true},
		{"localhost, port 1", "http://localhost:1/cb", true},
		{"localhost, port 65535", "http://localhost:65535/cb", true},
		{"localhost, no path", "http://localhost", true},
		{"localhost, no path with a port", "http://localhost:3000", true},
		{"localhost with a query", "http://localhost:8080/cb?x=1", true},
		{"localhost with the root path", "http://localhost/", true},

		// Refused: lookalikes of localhost.
		{"https localhost", "https://localhost/cb", false},
		{"https localhost with a port", "https://localhost:8443/cb", false},
		{"upper-case LOCALHOST", "http://LOCALHOST/cb", false},
		{"capitalised Localhost", "http://Localhost/cb", false},
		{"localhost with a trailing dot", "http://localhost./cb", false},
		{"localhost with a trailing dot and a port", "http://localhost.:8080/cb", false},
		{"a subdomain of localhost", "http://a.localhost/cb", false},
		{"a subdomain of localhost with a port", "http://a.localhost:8080/cb", false},
		{"localhost as a subdomain of another name", "http://localhost.evil.com/cb", false},
		{"localhost as a subdomain of another name, port", "http://localhost.evil.com:8080/cb", false},
		{"a name that starts like localhost", "http://localhostx/cb", false},
		{"a name that ends like localhost", "http://xlocalhost/cb", false},
		{"localhost userinfo that hides a host", "http://localhost@evil.com/cb", false},
		{"localhost userinfo with a port that hides a host", "http://localhost:80@evil.com/cb", false},
		{"localhost with a password", "http://localhost:pw@evil.com/cb", false},
		{"localhost, the default port written out", "http://localhost:80/cb", false},
		{"localhost, an empty port", "http://localhost:/cb", false},
		{"localhost, port 0", "http://localhost:0/cb", false},
		{"localhost, port 65536", "http://localhost:65536/cb", false},
		{"localhost, a port with a leading zero", "http://localhost:08080/cb", false},
		{"localhost, a port of letters", "http://localhost:abc/cb", false},
		{"localhost with a fragment", "http://localhost/cb#f", false},
		{"localhost with a backslash", "http://localhost\\@evil.com/cb", false},
		{"an encoded localhost", "http://local%68ost/cb", false},
		{"an upper-case scheme for localhost", "HTTP://localhost/cb", false},
		{"localhost with a space", "http://local host/cb", false},
		{"localhost with a NUL", "http://localhost\x00/cb", false},

		// Refused: other spellings of loopback.
		{"a lookalike of loopback", "http://127.0.0.1.evil.com/cb", false},
		{"a lookalike of loopback with a port", "http://127.0.0.1.evil.com:8080/cb", false},
		{"a lookalike of loopback, no path", "http://127.0.0.1.evil.com", false},
		{"another loopback address", "http://127.0.0.2/cb", false},
		{"a short loopback", "http://127.1/cb", false},
		{"a hex loopback", "http://0x7f.1/cb", false},
		{"a one-number loopback", "http://2130706433/cb", false},
		{"an octal loopback", "http://0177.0.0.1/cb", false},
		{"a loopback with a leading zero", "http://127.0.0.01/cb", false},
		{"IPv6 loopback, long form", "http://[0:0:0:0:0:0:0:1]/cb", false},
		{"IPv6 loopback, leading zeros", "http://[::01]/cb", false},
		{"IPv6 loopback, a zero-compressed spelling", "http://[0::1]/cb", false},
		{"IPv6 mapped IPv4 loopback", "http://[::ffff:127.0.0.1]/cb", false},
		{"IPv6 other address", "http://[2001:db8::1]/cb", false},
		{"IPv6 unspecified", "http://[::]/cb", false},
		{"IPv4 any", "http://0.0.0.0/cb", false},
		{"https IPv4 loopback", "https://127.0.0.1/cb", false},
		{"https IPv6 loopback", "https://[::1]/cb", false},
		{"https IPv4 address", "https://192.168.0.1/cb", false},
		{"https IPv4 as a number", "https://2130706433/cb", false},
		{"https one label", "https://intranet/cb", false},
		{"http for a public host", "http://example.com/cb", false},
		{"http for a public host with a port", "http://example.com:8080/cb", false},
		{"http for a subdomain of localhost", "http://app.localhost/cb", false},
		{"http for a one-label name that is not localhost", "http://intranet/cb", false},
		{"http for a name under .local", "http://printer.local/cb", false},

		// Refused: lookalikes.
		{"a fragment that looks like userinfo", "https://evil.com#@good", false},
		{"a fragment after a path that looks like userinfo", "https://evil.com/cb#@good.com", false},
		{"userinfo that looks like a host", "https://good.com@evil.com/cb", false},
		{"userinfo that looks like a host and port", "https://good.com:443@evil.com/cb", false},
		{"userinfo that looks like a host and password", "https://good.com:pw@evil.com/cb", false},
		{"an empty userinfo", "https://@example.com/cb", false},
		{"loopback userinfo that hides a host", "http://127.0.0.1@evil.com/cb", false},
		{"loopback userinfo with a port that hides a host", "http://127.0.0.1:80@evil.com/cb", false},
		{"a backslash before an @", "https://good.com\\@evil.com/cb", false},
		{"a backslash for a slash", "https://example.com\\cb", false},
		{"backslashes for slashes", "https:\\\\example.com\\cb", false},
		{"loopback with a backslash", "http://127.0.0.1\\@evil.com/cb", false},

		// Refused: other schemes.
		{"a custom scheme", "myapp://cb", false},
		{"a custom scheme with a host and path", "myapp://example.com/cb", false},
		{"a reverse-domain scheme", "com.example.app:/oauth2redirect", false},
		{"a custom scheme with one slash", "myapp:/cb", false},
		{"the out-of-band URN", "urn:ietf:wg:oauth:2.0:oob", false},
		{"javascript", "javascript:alert(1)", false},
		{"data", "data:text/html,<script>1</script>", false},
		{"file", "file:///etc/passwd", false},
		{"ftp", "ftp://example.com/cb", false},
		{"a browser extension", "chrome-extension://abcdef/cb", false},
		{"an editor", "vscode://publisher.ext/cb", false},
		{"ws", "ws://example.com/cb", false},
		{"wss", "wss://example.com/cb", false},
		{"a scheme only", "https://", false},
		{"an empty host", "https:///cb", false},
		{"an opaque https", "https:example.com/cb", false},
		{"no scheme", "example.com/cb", false},
		{"a scheme-relative URL", "//example.com/cb", false},
		{"a path", "/cb", false},
		{"empty", "", false},
		{"two schemes", "https://https://example.com/cb", false},

		// Refused: case.
		{"an upper-case scheme", "HTTPS://example.com/cb", false},
		{"an upper-case scheme for loopback", "HTTP://127.0.0.1/cb", false},
		{"a capitalised scheme", "Https://example.com/cb", false},
		{"a capitalised host", "https://Example.com/cb", false},
		{"an upper-case host", "https://EXAMPLE.COM/cb", false},
		{"an upper-case last label", "https://example.COM/cb", false},

		// Refused: fragment.
		{"an empty fragment", "https://example.com/cb#", false},
		{"a fragment", "https://example.com/cb#f", false},
		{"a fragment on loopback", "http://127.0.0.1/cb#f", false},
		{"a fragment before the path", "https://example.com#/cb", false},
		{"a query and a fragment", "https://example.com/cb?a=1#f", false},

		// Refused: percent-encoding in the host.
		{"an encoded letter", "https://%65xample.com/cb", false},
		{"an encoded letter inside the host", "https://exam%70le.com/cb", false},
		{"an encoded dot", "https://example%2ecom/cb", false},
		{"an encoded multibyte character", "https://%C3%A9.example/cb", false},
		{"an encoded loopback", "http://127.0.0.%31/cb", false},
		{"an encoded host before a path", "https://example.com%2fevil.com/cb", false},

		// Refused: the port.
		{"https default port written out", "https://example.com:443/cb", false},
		{"https default port with no path", "https://example.com:443", false},
		{"http default port for loopback", "http://127.0.0.1:80/cb", false},
		{"http default port for IPv6 loopback", "http://[::1]:80/cb", false},
		{"an empty port", "https://example.com:/cb", false},
		{"an empty port for loopback", "http://127.0.0.1:/cb", false},
		{"an empty port for IPv6 loopback", "http://[::1]:/cb", false},
		{"a port with a leading zero", "http://127.0.0.1:08080/cb", false},
		{"a default port with a leading zero", "https://example.com:0443/cb", false},
		{"port 0", "http://127.0.0.1:0/cb", false},
		{"port 65536", "http://127.0.0.1:65536/cb", false},
		{"a negative port", "http://127.0.0.1:-1/cb", false},
		{"a signed port", "http://127.0.0.1:+8080/cb", false},
		{"a port of letters", "http://127.0.0.1:abc/cb", false},
		{"a port with a space", "http://127.0.0.1:80 80/cb", false},
		{"a hex port", "http://127.0.0.1:0x1f90/cb", false},
		{"two ports", "http://127.0.0.1:8080:8080/cb", false},
		{"a huge port", "http://127.0.0.1:" + strings.Repeat("9", 100) + "/cb", false},

		// Refused: malformed hosts.
		{"a trailing dot", "https://example.com./cb", false},
		{"a leading dot", "https://.example.com/cb", false},
		{"an empty label", "https://example..com/cb", false},
		{"a leading hyphen", "https://-a.example.com/cb", false},
		{"an underscore", "https://exa_mple.com/cb", false},
		{"a label of 64 characters", "https://" + label64 + ".com/cb", false},
		{"a non-ASCII host", "https://ex\u00e4mple.com/cb", false},
		{"a Cyrillic lookalike", "https://\u0435xample.com/cb", false},
		{"a fullwidth dot", "https://example\u3002com/cb", false},
		{"a space in the host", "https://exa mple.com/cb", false},

		// Refused: characters that are never in a URL.
		{"a leading space", " https://example.com/cb", false},
		{"a trailing space", "https://example.com/cb ", false},
		{"a space in the path", "https://example.com/a b", false},
		{"a tab", "https://example.com/a\tb", false},
		{"a trailing newline", "https://example.com/cb\n", false},
		{"a newline in the query", "https://example.com/cb?a=\nb", false},
		{"NUL at the end", "https://example.com/cb\x00", false},
		{"NUL in the host", "https://exam\x00ple.com/cb", false},
		{"NUL first", "\x00https://example.com/cb", false},
		{"DEL", "https://example.com/a\x7fb", false},
		{"a non-ASCII letter in the path", "https://example.com/caf\u00e9", false},
		{"an emoji in the query", "https://example.com/cb?a=\U0001F600", false},
		{"a bidi override", "https://example.com/\u202ecb", false},
		{"invalid UTF-8", "https://example.com/a\xffb", false},
		{"a double quote", "https://example.com/a\"b", false},
		{"angle brackets", "https://example.com/<a>", false},

		// Size.
		{"one over the bound", base + strings.Repeat("a", input.MaxRedirectURIBytes-len(base)+1), false},
		{"a megabyte of path", base + strings.Repeat("a", 1<<20), false},
		{"a megabyte of NULs", strings.Repeat("\x00", 1<<20), false},
	}
}

// reservedQueryCases are the rows of ParseRedirectURI about the query: it may
// not use a parameter name the authorization response itself sends.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func reservedQueryCases() []parseCase {
	return []parseCase{
		// Accepted: a query whose names are not ones the authorization response sends.
		// Names are exact and case-sensitive, and only a name counts, never a value.
		{"a query with an encoded NUL value", "https://example.com/cb?x=%00", true},
		{"a query that does not decode, which is not a reserved name", "https://example.com/cb?x=%zz", true},
		{"a query name that does not decode, which is not a reserved name", "https://example.com/cb?%zz=1", true},
		{"a query name that is code with an encoded NUL", "https://example.com/cb?code%00=1", true},
		{"a query name of a capitalised code", "https://example.com/cb?Code=1", true},
		{"a query name of an upper-case STATE", "https://example.com/cb?STATE=1", true},
		{"a query name that extends code", "https://example.com/cb?codex=1", true},
		{"a query name that is a prefix of state", "https://example.com/cb?stat=1", true},
		{"a query name that is a prefix of error_description", "https://example.com/cb?error_=1", true},
		{"a query name that contains iss", "https://example.com/cb?issuer=1", true},
		{"a query name that is code with a space from a plus", "https://example.com/cb?code+=1", true},
		{"a query name that is a plus", "https://example.com/cb?+=1", true},
		{"a reserved name as a value", "https://example.com/cb?x=code", true},
		{"a reserved name as a value after another pair", "https://example.com/cb?x=1&y=state", true},
		{"a reserved name inside a value, after a second equals sign", "https://example.com/cb?x=1=code", true},
		{"a reserved name joined to a name by a semicolon", "https://example.com/cb?a=1;code=2", true},
		{"a reserved name after a semicolon that is no separator", "https://example.com/cb?a;code=2", true},
		{"two ordinary pairs", "https://example.com/cb?a=1&b=2", true},
		{"a trailing question mark", "https://example.com/cb?", true},
		{"only empty pairs", "https://example.com/cb?&&", true},
		{"an empty name with a value", "https://example.com/cb?=code", true},
		{"loopback with an ordinary query", "http://127.0.0.1:8080/cb?a=1&b=2", true},

		// Refused: a query that uses a parameter name the authorization response
		// itself sends. The response appends it after the registered query, so the
		// callback would carry it twice.
		{"a query with code alone with a value", "https://example.com/cb?code=1", false},
		{"a query with code alone with no equals sign", "https://example.com/cb?code", false},
		{"a query with code alone with an empty value", "https://example.com/cb?code=", false},
		{"a query with code as the first pair", "https://example.com/cb?code=1&x=2", false},
		{"a query with code as a middle pair", "https://example.com/cb?x=1&code=2&y=3", false},
		{"a query with code as the last pair", "https://example.com/cb?x=1&y=2&code=3", false},
		{"a query with state alone with a value", "https://example.com/cb?state=1", false},
		{"a query with state alone with no equals sign", "https://example.com/cb?state", false},
		{"a query with state alone with an empty value", "https://example.com/cb?state=", false},
		{"a query with state as the first pair", "https://example.com/cb?state=1&x=2", false},
		{"a query with state as a middle pair", "https://example.com/cb?x=1&state=2&y=3", false},
		{"a query with state as the last pair", "https://example.com/cb?x=1&y=2&state=3", false},
		{"a query with iss alone with a value", "https://example.com/cb?iss=1", false},
		{"a query with iss alone with no equals sign", "https://example.com/cb?iss", false},
		{"a query with iss alone with an empty value", "https://example.com/cb?iss=", false},
		{"a query with iss as the first pair", "https://example.com/cb?iss=1&x=2", false},
		{"a query with iss as a middle pair", "https://example.com/cb?x=1&iss=2&y=3", false},
		{"a query with iss as the last pair", "https://example.com/cb?x=1&y=2&iss=3", false},
		{"a query with error alone with a value", "https://example.com/cb?error=1", false},
		{"a query with error alone with no equals sign", "https://example.com/cb?error", false},
		{"a query with error alone with an empty value", "https://example.com/cb?error=", false},
		{"a query with error as the first pair", "https://example.com/cb?error=1&x=2", false},
		{"a query with error as a middle pair", "https://example.com/cb?x=1&error=2&y=3", false},
		{"a query with error as the last pair", "https://example.com/cb?x=1&y=2&error=3", false},
		{"a query with error_description alone with a value", "https://example.com/cb?error_description=1", false},
		{"a query with error_description alone with no equals sign", "https://example.com/cb?error_description", false},
		{"a query with error_description alone with an empty value", "https://example.com/cb?error_description=", false},
		{"a query with error_description as the first pair", "https://example.com/cb?error_description=1&x=2", false},
		{"a query with error_description as a middle pair", "https://example.com/cb?x=1&error_description=2&y=3", false},
		{"a query with error_description as the last pair", "https://example.com/cb?x=1&y=2&error_description=3", false},
		{"a reserved name on loopback", "http://127.0.0.1:8080/cb?state=evil", false},
		{"a reserved name on localhost", "http://localhost/cb?code=1", false},
		{"a reserved name after empty pairs", "https://example.com/cb?&&iss=1", false},
		{"a reserved name before empty pairs", "https://example.com/cb?iss&&", false},
		{"a reserved name with no equals sign after another pair", "https://example.com/cb?a=1&code", false},
		{"a reserved name after a trailing ampersand", "https://example.com/cb?a=1&&code=2", false},
		{"a reserved name with a second equals sign in its value", "https://example.com/cb?code=a=b", false},
		{"a reserved name whose value does not decode", "https://example.com/cb?code=%zz", false},
		{"a reserved name beside a name that does not decode", "https://example.com/cb?%zz=1&state=2", false},
		{"the same reserved name twice", "https://example.com/cb?state=1&state=2", false},
		{"two different reserved names", "https://example.com/cb?code=1&state=2", false},
		{"the shape of the attack", "https://example.com/cb?state=evil&iss=https://x", false},
		{"an encoded c in code", "https://example.com/cb?%63ode=1", false},
		{"an encoded a in state", "https://example.com/cb?st%61te=1", false},
		{"an encoded i in iss", "https://example.com/cb?%69ss=1", false},
		{"an encoded o in error", "https://example.com/cb?err%6Fr=1", false},
		{"an encoded o in error, lower-case hex", "https://example.com/cb?err%6fr=1", false},
		{"an encoded underscore in error_description", "https://example.com/cb?error%5Fdescription=1", false},
		{"a fully encoded code", "https://example.com/cb?%63%6f%64%65=1", false},
		{"an encoded reserved name with no equals sign", "https://example.com/cb?%63ode", false},
		{"an encoded reserved name as the last pair", "https://example.com/cb?x=1&st%61te=2", false},
	}
}

func TestParseRedirectURI(t *testing.T) {
	t.Parallel()

	parse := strAdapter(input.ParseRedirectURI, input.RedirectURI.String)

	runStringTable(t, redirectCases(), parse, input.CodeInvalidRedirectURI)
}

func TestParseRedirectURIReservedQueryNames(t *testing.T) {
	t.Parallel()

	parse := strAdapter(input.ParseRedirectURI, input.RedirectURI.String)

	runStringTable(t, reservedQueryCases(), parse, input.CodeInvalidRedirectURI)
}

func TestRedirectURIDescriptionStatesTheBound(t *testing.T) {
	t.Parallel()

	_, err := input.ParseRedirectURI("")
	requireMentions(t, descriptionOf(t, err, input.CodeInvalidRedirectURI), input.MaxRedirectURIBytes)
}

func TestRedirectURIHostAndLoopback(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in       string
		host     string
		loopback bool
	}{
		{"https://example.com/cb", "example.com", false},
		{"https://example.com:8443/cb", "example.com:8443", false},
		{"http://127.0.0.1/cb", "127.0.0.1", true},
		{"http://127.0.0.1:8080/cb", "127.0.0.1:8080", true},
		{"http://[::1]/cb", "[::1]", true},
		{"http://[::1]:9/cb", "[::1]:9", true},
		{"http://localhost/cb", "localhost", true},
		{"http://localhost:3000/cb", "localhost:3000", true},
	} {
		got, err := input.ParseRedirectURI(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}

		if got.Host() != tc.host || got.Loopback() != tc.loopback {
			t.Errorf("%q: Host() = %q, Loopback() = %v; want %q, %v", tc.in, got.Host(), got.Loopback(), tc.host, tc.loopback)
		}
	}
}

// matchCases are the (request, registered) pairs of RedirectURI.Matches. Both
// sides must parse: a pair with a side that does not is a case of
// TestParseRedirectURI, and appears here only as the lookalike it is.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func matchCases() []struct {
	name       string
	request    string
	registered string
	want       bool
} {
	return []struct {
		name       string
		request    string
		registered string
		want       bool
	}{
		{"the same https URI", "https://example.com/cb", "https://example.com/cb", true},
		{"the same https URI with a query", "https://example.com/cb?a=1", "https://example.com/cb?a=1", true},
		{"the same https URI with a port", "https://example.com:8443/cb", "https://example.com:8443/cb", true},
		{"the same https URI with no path", "https://example.com", "https://example.com", true},
		{"a different path", "https://example.com/cb2", "https://example.com/cb", false},
		{"a path that extends the registered one", "https://example.com/cb/x", "https://example.com/cb", false},
		{"a trailing slash", "https://example.com/cb/", "https://example.com/cb", false},
		{"a trailing slash registered", "https://example.com/cb", "https://example.com/cb/", false},
		{"no path and the root path", "https://example.com", "https://example.com/", false},
		{"a different query", "https://example.com/cb?a=2", "https://example.com/cb?a=1", false},
		{"a query that was not registered", "https://example.com/cb?a=1", "https://example.com/cb", false},
		{"a query that only the registration has", "https://example.com/cb", "https://example.com/cb?a=1", false},
		{"a different host", "https://evil.com/cb", "https://example.com/cb", false},
		{"a subdomain", "https://a.example.com/cb", "https://example.com/cb", false},
		{"a different port, which is free only for loopback", "https://example.com:8443/cb", "https://example.com/cb", false},
		{"another different port", "https://example.com:9443/cb", "https://example.com:8443/cb", false},
		{"an encoded path against the plain one", "https://example.com/%41", "https://example.com/A", false},
		{"https against http loopback", "https://127.0.0.1.evil.com/cb", "http://127.0.0.1/cb", false},
		{"a DNS name like loopback against a port", "https://127.0.0.1.evil.com/cb", "http://127.0.0.1:8080/cb", false},
		{"loopback against https of the same path", "http://127.0.0.1/cb", "https://example.com/cb", false},
		{"https against a registered loopback of the same text", "https://example.com/cb", "http://127.0.0.1/cb", false},

		{"loopback, the same", "http://127.0.0.1:8080/cb", "http://127.0.0.1:8080/cb", true},
		{"loopback, another port", "http://127.0.0.1:51234/cb", "http://127.0.0.1:8080/cb", true},
		{"loopback, a port where the registration has none", "http://127.0.0.1:51234/cb", "http://127.0.0.1/cb", true},
		{"loopback, no port where the registration has one", "http://127.0.0.1/cb", "http://127.0.0.1:8080/cb", true},
		{"loopback, neither has a port", "http://127.0.0.1/cb", "http://127.0.0.1/cb", true},
		{"loopback, no path", "http://127.0.0.1:1", "http://127.0.0.1:2", true},
		{"loopback with a query, another port", "http://127.0.0.1:1/cb?a=1", "http://127.0.0.1:2/cb?a=1", true},
		{"IPv6 loopback, another port", "http://[::1]:51234/cb", "http://[::1]:8080/cb", true},
		{"IPv6 loopback, no port", "http://[::1]/cb", "http://[::1]:8080/cb", true},
		{"loopback, a different path", "http://127.0.0.1:8080/cb2", "http://127.0.0.1:8080/cb", false},
		{"loopback, a different path and port", "http://127.0.0.1:1/cb2", "http://127.0.0.1:2/cb", false},
		{"loopback, a trailing slash", "http://127.0.0.1:8080/cb/", "http://127.0.0.1:8080/cb", false},
		{"loopback, a different query", "http://127.0.0.1:1/cb?a=2", "http://127.0.0.1:2/cb?a=1", false},
		{"loopback, a query that was not registered", "http://127.0.0.1:1/cb?a=1", "http://127.0.0.1:2/cb", false},
		{"loopback, IPv4 against IPv6", "http://[::1]:8080/cb", "http://127.0.0.1:8080/cb", false},
		{"loopback, IPv6 against IPv4", "http://127.0.0.1:8080/cb", "http://[::1]:8080/cb", false},

		// localhost is loopback, and a host of its own.
		{"localhost, the same", "http://localhost:8080/cb", "http://localhost:8080/cb", true},
		{"localhost, another port", "http://localhost:51234/cb", "http://localhost:8080/cb", true},
		{"localhost, a port where the registration has none", "http://localhost:51234/cb", "http://localhost/cb", true},
		{"localhost, no port where the registration has one", "http://localhost/cb", "http://localhost:8080/cb", true},
		{"localhost, neither has a port", "http://localhost/cb", "http://localhost/cb", true},
		{"localhost, no path", "http://localhost:1", "http://localhost:2", true},
		{"localhost with a query, another port", "http://localhost:1/cb?a=1", "http://localhost:2/cb?a=1", true},
		{"localhost, a different path", "http://localhost:8080/cb2", "http://localhost:8080/cb", false},
		{"localhost, a different path and port", "http://localhost:1/cb2", "http://localhost:2/cb", false},
		{"localhost, a trailing slash", "http://localhost:8080/cb/", "http://localhost:8080/cb", false},
		{"localhost, a different query", "http://localhost:1/cb?a=2", "http://localhost:2/cb?a=1", false},
		{"localhost, a query that was not registered", "http://localhost:1/cb?a=1", "http://localhost:2/cb", false},
		{"localhost against IPv4 loopback", "http://localhost:8080/cb", "http://127.0.0.1:8080/cb", false},
		{"IPv4 loopback against localhost", "http://127.0.0.1:8080/cb", "http://localhost:8080/cb", false},
		{"localhost against IPv6 loopback", "http://localhost:8080/cb", "http://[::1]:8080/cb", false},
		{"IPv6 loopback against localhost", "http://[::1]:8080/cb", "http://localhost:8080/cb", false},
		{"localhost against IPv4 loopback, no ports", "http://localhost/cb", "http://127.0.0.1/cb", false},
		{"localhost against a https name of the same path", "http://localhost/cb", "https://example.com/cb", false},
		{"a https name against a registered localhost", "https://example.com/cb", "http://localhost/cb", false},
		{"localhost against a name that contains it", "https://localhost.example.com/cb", "http://localhost/cb", false},
	}
}

func TestRedirectURIMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range matchCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			request, err := input.ParseRedirectURI(tc.request)
			if err != nil {
				t.Fatalf("request %q: %v", tc.request, err)
			}

			registered, err := input.ParseRedirectURI(tc.registered)
			if err != nil {
				t.Fatalf("registered %q: %v", tc.registered, err)
			}

			if got := request.Matches(registered); got != tc.want {
				t.Errorf("%q.Matches(%q) = %v, want %v", tc.request, tc.registered, got, tc.want)
			}
		})
	}
}

// TestRedirectURILookalikesAreNeverMatched pairs each lookalike, which fails to
// parse, with the URI it imitates: there is no value of the type to match it
// with, so a request that sends one is refused before any registration is read.
func TestRedirectURILookalikesAreNeverMatched(t *testing.T) {
	t.Parallel()

	for _, lookalike := range []string{
		"https://evil.com#@good",
		"http://127.0.0.1.evil.com",
		"http://127.0.0.1.evil.com/cb",
		"http://localhost.evil.com",
		"http://localhost.evil.com:8080/cb",
		"http://localhost@evil.com/cb",
		"http://localhost:80@evil.com/cb",
		"http://localhost./cb",
		"http://LOCALHOST/cb",
		"http://a.localhost/cb",
		"https://good.com@evil.com/cb",
	} {
		_, err := input.ParseRedirectURI(lookalike)
		requireRefusal(t, err, input.CodeInvalidRedirectURI)
	}
}

// TestRedirectURIMatchesIsSymmetricForLoopback: whichever of two URIs is the
// request and whichever is registered, the answer is the same.
func TestRedirectURIMatchesIsSymmetric(t *testing.T) {
	t.Parallel()

	for _, tc := range matchCases() {
		request, err := input.ParseRedirectURI(tc.request)
		if err != nil {
			t.Fatal(err)
		}

		registered, err := input.ParseRedirectURI(tc.registered)
		if err != nil {
			t.Fatal(err)
		}

		if request.Matches(registered) != registered.Matches(request) {
			t.Errorf("%q and %q match one way and not the other", tc.request, tc.registered)
		}
	}
}

func TestZeroRedirectURIMatchesNothing(t *testing.T) {
	t.Parallel()

	var zero input.RedirectURI

	known, err := input.ParseRedirectURI("https://example.com/cb")
	if err != nil {
		t.Fatal(err)
	}

	if zero.Matches(zero) || zero.Matches(known) || known.Matches(zero) {
		t.Error("the zero RedirectURI matched")
	}
}

func FuzzParseRedirectURI(f *testing.F) {
	seeds := append(seedsOf(redirectCases()), seedsOf(reservedQueryCases())...)

	fuzzInvariants(f, seeds, input.ParseRedirectURI, input.RedirectURI.String,
		input.CodeInvalidRedirectURI, requireSafeRedirect)
}

// requireSafeRedirect states what is true of every accepted redirect URI.
func requireSafeRedirect(t *testing.T, raw string) {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("%q does not parse: %v", raw, err)
	}

	loopback := u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost")

	// An accepted URI matches itself, and says whether it is a loopback one.
	parsed, _ := input.ParseRedirectURI(raw)

	requireNoFlaws(t, raw,
		flaw{u.String() != raw, "is not the canonical spelling"},
		flaw{u.Scheme != "https" && !loopback, "is neither https nor loopback"},
		flaw{u.User != nil || u.Fragment != "", "has userinfo or a fragment"},
		flaw{strings.ContainsAny(raw, "#\\ "), "has a fragment, a backslash or a space"},
		flaw{len(raw) > input.MaxRedirectURIBytes, "is over the bound"},
		flaw{!parsed.Matches(parsed), "does not match itself"},
		flaw{parsed.Loopback() != loopback, "is wrong about being loopback"},
	)
}
