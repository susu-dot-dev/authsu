package input

import (
	"net/url"
	"strings"
)

// This file holds what the two URL types, ClientID and RedirectURI, share: the
// canonical-form test and the rules for the authority (host and port). Neither
// type is ever built from a URL that has been rewritten; a spelling that is not
// the canonical one is refused.

const (
	// maxPort is the largest TCP port.
	maxPort = 65535

	// maxHostBytes and maxLabelLen are the DNS limits (RFC 1035) on a name and
	// on one of its labels.
	maxHostBytes = 253
	maxLabelLen  = 63

	// minLabels is the fewest labels of a public name: a name and a top-level domain.
	minLabels = 2

	// defaultHTTPSPort and defaultHTTPPort are the ports a scheme implies; a URL
	// that writes one out has a second spelling, so it is refused.
	defaultHTTPSPort = 443
	defaultHTTPPort  = 80
)

// Schemes the URL types accept.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// isURLByte reports whether c is printable ASCII other than space: 0x21 to
// 0x7E. NUL, every control character, space, DEL and every non-ASCII byte are
// outside it, so a URL is refused before it is parsed if it holds one.
func isURLByte(c byte) bool { return c > ' ' && c < 0x7f }

// canonicalURL parses raw as an absolute URL with an authority, and returns it
// only if raw is exactly its canonical spelling. It reports false for:
//   - the empty string, one longer than maxBytes, or one holding a byte outside
//     printable ASCII (checked first, so a huge or hostile input is refused
//     before it is parsed);
//   - '#' (a fragment, and the lookalike "https://evil.com#@good") and '\\'
//     (which some parsers read as '/');
//   - a URL net/url cannot parse, or one with no host (an opaque or relative
//     URL), or with userinfo;
//   - a URL that net/url would write differently: an upper-case scheme, an
//     empty fragment, an escape that need not be one, a character it would
//     escape. The caller compares the one string it stores, so this leaves one
//     client spelling per URL.
func canonicalURL(raw string, maxBytes int) (*url.URL, bool) {
	if raw == "" || len(raw) > maxBytes || !onlyBytes(raw, isURLByte) || strings.ContainsAny(raw, `#\`) {
		return nil, false
	}

	u, err := url.Parse(raw)
	if err != nil || u.String() != raw || u.User != nil || u.Host == "" {
		return nil, false
	}

	return u, true
}

// plainAuthority checks the host and port of u and returns the host without its
// port or brackets. It reports false for:
//   - an upper-case letter anywhere in the authority (a host is compared as
//     written, so it is never case-folded here);
//   - '%' in the authority (percent-encoding in a host, or an IPv6 zone);
//   - a port that is empty ("host:"), not a canonical decimal in 1 to 65535
//     (so "0443" is refused), or the scheme's default written out.
func plainAuthority(u *url.URL) (string, bool) {
	if u.Host != strings.ToLower(u.Host) || strings.Contains(u.Host, "%") || strings.HasSuffix(u.Host, ":") {
		return "", false
	}

	if port := u.Port(); port != "" {
		n, ok := decimal(port, 1, maxPort)
		if !ok || n == defaultPort(u.Scheme) {
			return "", false
		}
	}

	return u.Hostname(), true
}

// defaultPort is the port a scheme implies. Only http and https reach it.
func defaultPort(scheme string) int64 {
	if scheme == schemeHTTPS {
		return defaultHTTPSPort
	}

	return defaultHTTPPort
}

// dnsName reports whether host is a lower-case DNS name that could not be read
// as an address: at least two labels of 1 to 63 characters from [a-z0-9-], none
// starting or ending with '-', 253 bytes at most, and a last label that starts
// with a letter.
//
// The last-label rule is what keeps every spelling of an IP address out. A
// browser (the WHATWG URL parser) and inet_aton read "127.1", "0x7f.1",
// "2130706433", "017700000001" and "0x7f000001" as IPv4, and what they have in
// common is a last label that starts with a digit; no top-level domain does. An
// IPv6 literal is bracketed and holds ':', which no label may. A name with one
// label ("localhost", "intranet") is refused for the same reason: it does not
// name a public host.
func dnsName(host string) bool {
	if host == "" || len(host) > maxHostBytes {
		return false
	}

	labels := strings.Split(host, ".")
	if len(labels) < minLabels {
		return false
	}

	for _, label := range labels {
		if !dnsLabel(label) {
			return false
		}
	}

	last := labels[len(labels)-1]

	return last[0] >= 'a' && last[0] <= 'z'
}

// dnsLabel reports whether label is 1 to 63 characters of [a-z0-9-] that does
// not start or end with '-'.
func dnsLabel(label string) bool {
	return label != "" && len(label) <= maxLabelLen &&
		label[0] != '-' && label[len(label)-1] != '-' &&
		onlyBytes(label, func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' })
}
