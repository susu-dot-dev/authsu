package input

import (
	"encoding/json"
	"slices"

	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Bounds of ClientMetadata.
const (
	// MaxClientMetadataBytes bounds the document, in bytes: the 5 KiB the fetch
	// reads at most. The fetch refuses a longer body without truncating it; the
	// parser holds the same line so it does not depend on the caller.
	MaxClientMetadataBytes = 5 * 1024

	// MaxClientNameBytes bounds client_name, in bytes. It is the schema CHECK
	// `length(cast(client_name AS BLOB)) BETWEEN 1 AND 128` on
	// oauth_grants.client_name that the migration must carry, and its share of
	// the sealed pending request. Bytes, not characters, like AccountName: 128
	// bytes is 42 characters of the widest script.
	MaxClientNameBytes = 128

	// MaxRedirectURIs bounds the redirect_uris of a document. They are not
	// stored: only the one a request used is.
	MaxRedirectURIs = 10
)

// Error codes of the client's metadata and its name.
const (
	// CodeInvalidClientMetadata is the error code of ParseClientMetadata.
	CodeInvalidClientMetadata = "invalid_client_metadata"

	// CodeInvalidClientName is the error code of ParseClientName.
	CodeInvalidClientName = "invalid_client_name"
)

const descInvalidClientName = "client_name must be 1 to 128 bytes of normalised text without control characters " +
	"or formatting characters"

const descInvalidClientMetadata = "the client metadata document must be a JSON object of at most 5120 bytes, " +
	"with no repeated member, whose client_id is the URL it was fetched from, with a client_name of 1 to 128 bytes " +
	"and 1 to 10 redirect_uris of at most 512 bytes each, at least one of them valid, and whose " +
	"token_endpoint_auth_method is none if present"

// authNone is the one token_endpoint_auth_method of a public client.
const authNone = "none"

// ClientName is the name a client's metadata document gave itself, as it is
// shown to the person approving the client. It is what identifies the client to
// them, so it is held to the strictest display rule: it admits no formatting
// character at all, joiners included.
type ClientName struct{ v string }

// ParseClientName accepts display text of 1 to MaxClientNameBytes bytes, with
// the rule of AccountName: valid, normalised, with no control, bidi or other
// format character, and not blank. It is the one rule for a client_name: a
// document's is parsed with it (ParseClientMetadata), and so is the name a
// sealed authorization request carries back.
func ParseClientName(raw string) (ClientName, error) {
	if !displayText(raw, textRule{unit: unitBytes, max: MaxClientNameBytes, allowEmpty: false, identifying: true}) {
		return ClientName{}, refuse(CodeInvalidClientName, descInvalidClientName)
	}

	return ClientName{v: raw}, nil
}

// String returns the name exactly as it was parsed.
func (n ClientName) String() string { return n.v }

// ClientMetadata is a Client ID Metadata Document that was fetched from a
// client_id and checked against it.
type ClientMetadata struct {
	clientID  ClientID
	name      ClientName
	redirects []RedirectURI
}

// ParseClientMetadata reads the body fetched from clientID, and refuses it, with
// CodeInvalidClientMetadata, unless it is a JSON object that:
//   - is at most MaxClientMetadataBytes long, valid UTF-8 with no U+FFFD, a single
//     value with nothing after it, and has no member repeated at any depth
//     (httpapi.Decode's rules). Member names are matched exactly, so "Client_ID"
//     is not "client_id";
//   - has a client_id string equal to clientID by exact string comparison: the
//     document says it is the client the URL names;
//   - has a client_name that ParseClientName accepts: display text of at most
//     MaxClientNameBytes bytes, held to the rule for text that identifies
//     someone, joiners refused too, because it is shown to the person approving
//     the client;
//   - has 1 to MaxRedirectURIs redirect_uris, each a string of at most
//     MaxRedirectURIBytes bytes, and at least one a RedirectURI that
//     ParseRedirectURI accepts. An entry that is not one is skipped (see
//     parseRedirects), so one custom-scheme or localhost entry does not refuse a
//     client that lists others;
//   - has no token_endpoint_auth_method, or has "none", and has no client_secret
//     or client_secret_expires_at (a client of this server is public);
//   - has the members it reads (client_id, client_name, redirect_uris,
//     token_endpoint_auth_method) of the JSON type they have, so a number
//     where a string belongs is refused, and "null" is no better than absent.
//
// Unknown members are ignored. This is a deliberate exception to the strict
// decoding of JSON bodies (httpapi.Decode refuses them), for the same reason
// as for unknown request parameters: the document is written by the client's
// operator, not by us, and the registered metadata of RFC 7591 and the CIMD
// draft (logo_uri, client_uri, policy_uri, tos_uri, grant_types,
// response_types, scope, contacts, jwks, software_id, application_type, ...) is
// the normal content of a real one. Refusing them would refuse real clients,
// and ignoring them costs nothing: this server reads only the members above,
// and what a client says about its own grant types or scopes limits nothing
// that the request does not. A member this server does act on, and whose
// presence would change the answer, is named above and checked.
func ParseClientMetadata(clientID ClientID, body []byte) (ClientMetadata, error) {
	parsed := result.Ok(body).
		Check(func(body []byte) error {
			if len(body) > MaxClientMetadataBytes {
				return refuse(CodeInvalidClientMetadata, descInvalidClientMetadata)
			}

			return nil
		}).
		Then(decodeMembers).
		Then(func(members map[string]json.RawMessage) (ClientMetadata, error) {
			return readMetadata(clientID, members)
		}).
		MapErr(func(error) error { return refuse(CodeInvalidClientMetadata, descInvalidClientMetadata) })

	return parsed.Get() //nolint:wrapcheck // every error in the chain is already the classified client error
}

// decodeMembers reads the body as one JSON object, with the strictness of
// httpapi.Decode (no repeated member at any depth, valid text, nothing after the
// value) and no opinion on which members there are: the map type has no
// structure, so no member is unknown to it.
func decodeMembers(body []byte) (map[string]json.RawMessage, error) {
	members := httpapi.Decode[map[string]json.RawMessage](httpapi.Request{Body: body})

	return members.Get() //nolint:wrapcheck // ParseClientMetadata replaces the error
}

// reader decodes members of a document, keeping the first failure.
type reader struct {
	members map[string]json.RawMessage
	err     error
}

// read decodes members[key] into a T, and reports whether it was present. A
// member of another JSON type is the reader's failure. A "null" decodes to T's
// zero value, present.
func read[T any](r *reader, key string) (T, bool) {
	var value T

	raw, present := r.members[key]
	if !present {
		return value, false
	}

	err := json.Unmarshal(raw, &value)
	if err != nil && r.err == nil {
		r.err = err
	}

	return value, true
}

// readMetadata applies the rules of ParseClientMetadata to the members.
func readMetadata(clientID ClientID, members map[string]json.RawMessage) (ClientMetadata, error) {
	// A client of this server is public, and a document is public too, so a
	// secret in it is a mistake or an attempt (the CIMD draft forbids both).
	_, hasSecret := members["client_secret"]
	_, hasSecretExpiry := members["client_secret_expires_at"]

	if hasSecret || hasSecretExpiry {
		return ClientMetadata{}, refuse(CodeInvalidClientMetadata, descInvalidClientMetadata)
	}

	r := &reader{members: members}
	documentID, _ := read[string](r, "client_id")
	name, _ := read[string](r, "client_name")
	uris, _ := read[[]*string](r, "redirect_uris")
	method, hasMethod := read[string](r, "token_endpoint_auth_method")

	parsedName, nameErr := ParseClientName(name)

	if r.err != nil || documentID != clientID.String() || (hasMethod && method != authNone) || nameErr != nil {
		return ClientMetadata{}, refuse(CodeInvalidClientMetadata, descInvalidClientMetadata)
	}

	redirects, err := parseRedirects(uris)
	if err != nil {
		return ClientMetadata{}, refuse(CodeInvalidClientMetadata, descInvalidClientMetadata)
	}

	return ClientMetadata{clientID: clientID, name: parsedName, redirects: redirects}, nil
}

// parseRedirects reads the redirect_uris: 1 to MaxRedirectURIs entries, each a
// string (a null is not one) of at most MaxRedirectURIBytes bytes, of which at
// least one is a RedirectURI. The
// bounds are checked on every entry before any is parsed, and a document that
// breaks one is refused whole, so a document cannot hide work from them behind
// entries that are skipped.
//
// An entry that is not a RedirectURI is skipped and not an error. A real
// client lists the redirects of every platform it runs on, among them ones this
// server never accepts (a custom scheme for a native app, which RFC 8252 section
// 7.1 allows and this server does not, a localhost address, a URI of another
// shape), and refusing the document for one of them would refuse a client that
// has a usable redirect. Registers matches only against the entries that parsed,
// and exactly, so a skipped entry registers nothing.
func parseRedirects(uris []*string) ([]RedirectURI, error) {
	// A JSON null decodes into a nil element, where a string would decode to ""
	// without an error: it is not a string, so it is not skipped but refused.
	if len(uris) == 0 || len(uris) > MaxRedirectURIs || slices.Contains(uris, nil) {
		return nil, refuse(CodeInvalidClientMetadata, descInvalidClientMetadata)
	}

	if slices.ContainsFunc(uris, func(raw *string) bool { return len(*raw) > MaxRedirectURIBytes }) {
		return nil, refuse(CodeInvalidClientMetadata, descInvalidClientMetadata)
	}

	redirects := make([]RedirectURI, 0, len(uris))

	for _, raw := range uris {
		parsed, err := ParseRedirectURI(*raw)
		if err == nil {
			redirects = append(redirects, parsed)
		}
	}

	if len(redirects) == 0 {
		return nil, refuse(CodeInvalidClientMetadata, descInvalidClientMetadata)
	}

	return redirects, nil
}

// ClientID returns the URL the document was fetched from.
func (m ClientMetadata) ClientID() ClientID { return m.clientID }

// Name returns the client_name, exactly as the document spells it.
func (m ClientMetadata) Name() string { return m.name.v }

// ClientName returns the client_name as the parsed value.
func (m ClientMetadata) ClientName() ClientName { return m.name }

// RedirectURIs returns the registered redirect URIs in the document's order. It
// is a copy.
func (m ClientMetadata) RedirectURIs() []RedirectURI { return slices.Clone(m.redirects) }

// Registers reports whether the document allows a request for uri: some
// registered URI Matches it. The zero ClientMetadata registers nothing.
func (m ClientMetadata) Registers(uri RedirectURI) bool {
	return slices.ContainsFunc(m.redirects, uri.Matches)
}
