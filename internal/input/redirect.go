package input

import (
	"net/url"
	"strings"
)

// MaxRedirectURIBytes bounds RedirectURI, in bytes. The URI is ASCII, so bytes
// and characters are the same. It is the schema CHECK
// `length(cast(redirect_uri AS BLOB)) BETWEEN 1 AND 512` on
// oauth_grants.redirect_uri that the migration must carry, and the
// redirect_uri's share of the sealed pending request.
const MaxRedirectURIBytes = 512

// CodeInvalidRedirectURI is the error code of ParseRedirectURI.
const CodeInvalidRedirectURI = "invalid_redirect_uri"

const descInvalidRedirectURI = "redirect_uri must be an https URL, or an http URL for 127.0.0.1, [::1] or " +
	"localhost, of at most 512 characters, as lower-case ASCII, with no userinfo, fragment, port 443 or port 80"

// Loopback hosts of a native client (RFC 8252 section 7.3), and nothing else.
// localhost is one although RFC 8252 section 8.3 says NOT RECOMMENDED for it,
// because a name can be made to resolve elsewhere and an address cannot: MCP
// clients in the wild register only http://localhost, and refusing it would
// refuse them. It is accepted as the exact lower-case name and as nothing near
// it, and as a host of its own: it is never the same host as either address
// (see RedirectURI.Matches), so a registration of one does not admit another.
const (
	loopbackIPv4      = "127.0.0.1"
	loopbackIPv6      = "::1"
	loopbackLocalhost = "localhost"
)

// isLoopbackHost reports whether host, as plainAuthority returns it, is one of
// the three loopback hosts, compared exactly.
func isLoopbackHost(host string) bool {
	return host == loopbackIPv4 || host == loopbackIPv6 || host == loopbackLocalhost
}

// RedirectURI is a URI an authorization response is sent to: the one a client
// asks for, or one its metadata document registers.
type RedirectURI struct {
	v, host string
	// base is v without the port for a loopback URI, and v for any other. Two
	// URIs match (Matches) when their bases are equal.
	base     string
	loopback bool
}

// ParseRedirectURI accepts an absolute URI in its canonical spelling that
// is one of:
//   - https, with a public DNS name as host (dnsName: no IP address, in any
//     spelling, and no single-label name such as localhost);
//   - http, with the host exactly 127.0.0.1, exactly [::1] or exactly localhost,
//     on any port: the loopback redirect of a native client. In every resource
//     table: this is a rule about redirect URIs and not the development-only
//     allowance of a localhost client_id. [0:0:0:0:0:0:0:1], 127.1, "localhost.",
//     "LOCALHOST", "a.localhost" and "localhost.evil.com" are refused, and so is
//     any loopback host over https, https://localhost included: there is no
//     certificate a public CA would issue for it, and it is not the plain-http
//     loopback redirect that is being allowed.
//
// Custom schemes (myapp://, com.example:/) are refused, as are userinfo, a
// fragment, a backslash, an upper-case scheme or host, percent-encoding in the
// host, an empty port ("host:"), a port outside 1 to 65535 or written with a
// leading zero, the default port written out (443 for https, 80 for http), and
// anything over MaxRedirectURIBytes, non-ASCII, space or control characters.
// A query is allowed and is part of what must match; the path may be empty.
// The query must not use a parameter name the authorization response itself
// sends (reservedQueryName): the response appends them after the registered
// query, so the callback would carry the name twice and clients disagree about
// which copy wins, which would undermine state and iss.
//
// A redirect URI is never fetched, only compared, so unlike a client_id it may
// hold percent-encoding in its path and query and a dot segment. It is compared
// whole, so each is only its exact spelling.
func ParseRedirectURI(raw string) (RedirectURI, error) {
	u, ok := canonicalURL(raw, MaxRedirectURIBytes)
	if !ok {
		return RedirectURI{}, refuse(CodeInvalidRedirectURI, descInvalidRedirectURI)
	}

	host, ok := plainAuthority(u)
	loopback := ok && u.Scheme == schemeHTTP && isLoopbackHost(host)

	if !ok || (!loopback && (u.Scheme != schemeHTTPS || !dnsName(host))) || hasReservedQueryName(u.RawQuery) {
		return RedirectURI{}, refuse(CodeInvalidRedirectURI, descInvalidRedirectURI)
	}

	base := raw
	if loopback {
		base = withoutPort(u, host)
	}

	return RedirectURI{v: raw, host: u.Host, base: base, loopback: loopback}, nil
}

// reservedQueryName reports whether name is a parameter an authorization
// response sends (RFC 6749 section 4.1.2, RFC 9207), which a redirect URI's
// query may not use.
func reservedQueryName(name string) bool {
	switch name {
	case "code", "state", "iss", "error", "error_description":
		return true
	default:
		return false
	}
}

// hasReservedQueryName reports whether the query names a reserved parameter. It
// reads the query as httpapi.ParseParams does: pairs split at "&" only, the
// name being what precedes the first "=" (a pair without one is all name),
// percent-decoded, and compared exactly (case-sensitive). A name that does not
// decode is not a reserved one. An empty pair has the empty name, which is not.
func hasReservedQueryName(rawQuery string) bool {
	for pair := range strings.SplitSeq(rawQuery, "&") {
		name, _, _ := strings.Cut(pair, "=")

		decoded, err := url.QueryUnescape(name)
		if err == nil && reservedQueryName(decoded) {
			return true
		}
	}

	return false
}

// withoutPort is u written without its port, for a loopback host. An IPv6
// host is bracketed again, as Hostname removed them.
func withoutPort(u *url.URL, host string) string {
	bare := *u
	bare.Host = host

	if strings.Contains(host, ":") {
		bare.Host = "[" + host + "]"
	}

	return bare.String()
}

// Matches reports whether a request for r is allowed by the URI registered by
// the client. They match when they are the same string. The one exception is a
// loopback URI (RFC 8252 section 7.3), where the port is picked by the client's
// operating system at run time and so may differ, or be absent on either side;
// scheme, host (127.0.0.1, [::1] and localhost are three different hosts), path
// and query must still be identical. A loopback URI never matches a URI that is
// not one, so "http://127.0.0.1.evil.com/cb" is not "http://127.0.0.1/cb", and a
// registration of 127.0.0.1 does not admit localhost, nor the reverse.
//
// The zero RedirectURI matches nothing.
func (r RedirectURI) Matches(registered RedirectURI) bool {
	return r.base != "" && r.loopback == registered.loopback && r.base == registered.base
}

// Loopback reports whether the URI is an http loopback URI (127.0.0.1, [::1] or
// localhost), one whose port is free in Matches.
func (r RedirectURI) Loopback() bool { return r.loopback }

// String returns the URI exactly as it was parsed.
func (r RedirectURI) String() string { return r.v }

// Host returns the host of the URI, with its port if it has one, as shown to
// the person approving the client.
func (r RedirectURI) Host() string { return r.host }
