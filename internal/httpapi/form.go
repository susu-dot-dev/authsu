package httpapi

import (
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Params is the recognised parameters of one form body or query string, parsed
// by ParseParams. A handler reads each with Get and parses it into an
// internal/input type; Params itself decides nothing about what a value means.
type Params struct {
	known  map[string]struct{}
	values map[string]string
}

// FormParams parses the request body as application/x-www-form-urlencoded and
// returns the parameters named names: see ParseParams. It is for a route that
// declares MediaForm; the boundary has already refused any other Content-Type
// and a body over the route's limit.
func (r Request) FormParams(names ...string) result.Result[Params] {
	return ParseParams(string(r.Body), names...)
}

// QueryParams parses the request's raw query string with the rules of
// ParseParams: it is FormParams for a GET. It reads RawQuery, not Query,
// because net/http's own parse silently drops what it cannot decode and keeps
// every value of a repeated name, which is the leniency these rules remove.
func (r Request) QueryParams(names ...string) result.Result[Params] {
	return ParseParams(r.RawQuery, names...)
}

// Get returns the value of the recognised parameter name and whether it was
// sent with a value. A parameter that was sent empty ("a=") or with no "="
// ("a") is reported absent, because RFC 6749 section 3.1 says one sent without
// a value is to be treated as omitted. Asking for a name that was not declared
// to ParseParams is a programming error and panics, which the boundary reports
// as an internal error: a misspelt name would otherwise read as "absent" for
// ever.
func (p Params) Get(name string) (string, bool) {
	if _, recognised := p.known[name]; !recognised {
		panic("httpapi: parameter " + name + " was not declared to ParseParams")
	}

	value, present := p.values[name]

	return value, present
}

// ParseParams parses raw as application/x-www-form-urlencoded (the body of a
// form, or a URL's query string) and keeps the parameters named names. The
// rules, which are the whole of what a handler can rely on:
//
//   - Pairs are separated by "&" only. A ";" is an ordinary character, as it is
//     in the HTML form encoding, so no pair means two things to two parsers.
//     An empty pair ("a=1&&b=2", a trailing "&") is skipped.
//   - A pair is split at its first "=", and name and value are each decoded:
//     "%XX" is a byte, "+" is a space, and anything else is itself. A "%" not
//     followed by two hex digits is refused (400 invalid_encoding), in every
//     pair, recognised or not: a request whose syntax is broken is not read
//     in part. A literal "+" must be sent as "%2B"; "%20" and "+" are both a
//     space.
//   - A name is matched exactly after decoding (case-sensitive), so "%73cope"
//     is "scope". A pair whose name is empty ("=x", "=") is refused (400
//     invalid_parameter_name).
//   - A recognised name may appear once (400 duplicate_parameter), whatever its
//     values: "a=1&a=1", and "a=&a=1", are both refused, because a parameter
//     sent twice is ambiguous (RFC 6749 section 3.1). The decoded name is what
//     is counted, so "a" and "%61" are the same parameter.
//   - A recognised value must be valid UTF-8 and contain no NUL byte (400
//     invalid_text). The check is on the decoded value, so "%00" and "%FF" are
//     refused.
//   - A parameter that is not in names is ignored: its value is never decoded
//     for meaning or checked beyond the percent-encoding rule above, and it may
//     repeat. RFC 6749 section 3.1 requires this of an authorization server, so
//     a client that adds a parameter authsu does not know still works. It is a
//     deliberate exception to the strict decoding of JSON bodies (Decode
//     refuses an unknown field), made for interoperability, and it applies to
//     OAuth requests only.
//   - An empty value ("a=") and a pair with no "=" ("a") are the same: the
//     parameter is absent (see Params.Get).
//
// The caller bounds raw: the boundary refuses a body or query string over the
// route's MaxBody before any handler runs.
func ParseParams(raw string, names ...string) result.Result[Params] {
	params := Params{known: make(map[string]struct{}, len(names)), values: make(map[string]string, len(names))}

	for _, name := range names {
		params.known[name] = struct{}{}
	}

	seen := make(map[string]struct{}, len(names))

	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}

		err := params.add(pair, seen)
		if err != nil {
			return result.Fail[Params](err)
		}
	}

	return result.Ok(params)
}

// add decodes one non-empty pair and keeps it if it is recognised. seen holds
// the recognised names already added.
func (p Params) add(pair string, seen map[string]struct{}) *apierr.Error {
	rawName, rawValue, _ := strings.Cut(pair, "=")

	name, nameErr := url.QueryUnescape(rawName)
	value, valueErr := url.QueryUnescape(rawValue)

	switch {
	case nameErr != nil:
		return apierr.New(apierr.BadRequest, "invalid_encoding", "a parameter name is not validly percent-encoded").
			WithCause(nameErr)
	case valueErr != nil:
		return apierr.New(apierr.BadRequest, "invalid_encoding", "a parameter value is not validly percent-encoded").
			WithCause(valueErr)
	case name == "":
		return apierr.New(apierr.BadRequest, "invalid_parameter_name", "a parameter has no name")
	}

	if _, recognised := p.known[name]; !recognised {
		return nil
	}

	if _, repeated := seen[name]; repeated {
		return apierr.New(apierr.BadRequest, "duplicate_parameter", "a parameter was sent more than once")
	}

	seen[name] = struct{}{}

	if strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
		return apierr.New(apierr.BadRequest, "invalid_text", "a parameter is not valid text")
	}

	if value != "" {
		p.values[name] = value
	}

	return nil
}
