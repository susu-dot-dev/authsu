package input

import (
	"net/url"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/resource"
)

// MaxClientIDBytes bounds ClientID, in bytes. The URL is ASCII, so bytes and
// characters are the same. It is the schema CHECK
// `length(cast(client_id AS BLOB)) BETWEEN 1 AND 512` on oauth_grants.client_id
// that the migration must carry. It is also the client_id's share of the sealed
// pending request (challenge.MaxPayloadLen; see TestPendingRequestFitsItsPayload).
const MaxClientIDBytes = 512

// CodeInvalidClientID is the error code of ParseClientID.
const CodeInvalidClientID = "invalid_client_id"

const descInvalidClientID = "client_id must be an https URL of at most 512 characters, as lower-case ASCII, " +
	"naming a public host and a path, with no userinfo, port 443, query, fragment, percent-encoding or dot segment"

// ClientID is the identifier of an OAuth client: the URL of its Client ID
// Metadata Document.
type ClientID struct{ v, host string }

// ParseClientID accepts exactly the canonical spelling of an absolute URL that
// this server may fetch as a client's metadata document, and refuses
// everything else. The URL is compared byte for byte wherever it is used (the
// document must repeat it, a grant stores it), so it has one spelling:
//   - scheme https. Plain http is accepted only where table.AllowsLocalHTTP
//     says so (the development table, host localhost, any port), so a developer
//     and the end-to-end tests can serve a client from their own machine;
//   - printable ASCII only: no NUL, control character, space or non-ASCII byte,
//     and at most MaxClientIDBytes;
//   - no userinfo, fragment, query or backslash; no '%' at all, so there is no
//     percent-encoded dot segment ("%2e%2e"), slash or host to decode;
//   - a path of more than "/", with no "." or ".." segment;
//   - a lower-case host: a public DNS name (dnsName) that is not an IP address
//     in any spelling and not a reserved name, or localhost where allowed;
//   - a port, if any, in 1 to 65535 written canonically, not the default one
//     and not empty ("host:");
//   - a spelling net/url would write identically, so an upper-case scheme or
//     host is refused rather than folded.
func ParseClientID(raw string, table resource.Table) (ClientID, error) {
	u, ok := canonicalURL(raw, MaxClientIDBytes)
	if !ok || strings.ContainsAny(raw, "?%") || !clientIDLocation(u, table) {
		return ClientID{}, refuse(CodeInvalidClientID, descInvalidClientID)
	}

	return ClientID{v: raw, host: u.Host}, nil
}

// clientIDLocation checks the scheme, authority and path of a canonical u.
func clientIDLocation(u *url.URL, table resource.Table) bool {
	host, ok := plainAuthority(u)
	if !ok || u.Path == "" || u.Path == "/" || dotSegment(u.Path) {
		return false
	}

	if table.AllowsLocalHTTP(u) {
		return true
	}

	return u.Scheme == schemeHTTPS && dnsName(host) && !reservedTLD(host)
}

// reservedTLDs are the last labels of names that are never public hosts, and so
// are never a client_id's: the names of loopback and link-local use (RFC 6761,
// RFC 6762, RFC 6761's "invalid", "test", "localhost", "example" and the
// special-use "local" and "onion", RFC 7686), the reverse-lookup and home
// network zones ("arpa", which includes "home.arpa" of RFC 8375), and the
// private-network suffixes that routers, directories and corporate networks use
// in practice ("internal", "lan", "home", "corp", "intranet", "private",
// "localdomain"). None of these can be registered, or none is delegated in the
// public DNS, so a name under one that resolves does so inside a network.
//
//nolint:gochecknoglobals // a fixed table, read only
var reservedTLDs = map[string]bool{
	"localhost": true, "local": true, "localdomain": true, "internal": true, "arpa": true,
	"lan": true, "home": true, "corp": true, "intranet": true, "private": true,
	"test": true, "invalid": true, "example": true, "onion": true,
}

// reservedTLD reports whether host, a dnsName, ends in a last label that is
// never a public host (reservedTLDs). A client_id is fetched by this server, so
// a name that resolves inside a network is refused before any fetch. It is a
// first line only: the fetch must still not trust the platform or the name's
// resolution. The one name of this kind that is allowed is exactly localhost, by
// the development table's rule (resource.Table.AllowsLocalHTTP), which is
// checked before this and over plain http only: a name under localhost, or
// localhost over https, is refused.
func reservedTLD(host string) bool {
	return reservedTLDs[host[strings.LastIndexByte(host, '.')+1:]]
}

// dotSegment reports whether a path has a "." or ".." segment.
func dotSegment(path string) bool {
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}

	return false
}

// String returns the URL exactly as it was parsed.
func (c ClientID) String() string { return c.v }

// Host returns the host of the URL, with its port if it has one, as shown to
// the person approving the client.
func (c ClientID) Host() string { return c.host }
