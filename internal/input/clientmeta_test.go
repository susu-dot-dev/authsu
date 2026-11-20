//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

const metadataURL = "https://client.example.com/oauth/client.json"

// authNone is the member that names the one accepted auth method.
const authNone = `"token_endpoint_auth_method":"none"`

// goodURI is the one redirect URI of a valid document.
const goodURI = "https://client.example.com/cb"

// The raw JSON of the three required members of a valid document.
const (
	jsonID   = `"` + metadataURL + `"`
	jsonName = `"Example Client"`
	jsonURIs = `["https://client.example.com/cb"]`
)

// docOf returns a document of the given raw JSON values for client_id,
// client_name and redirect_uris, then the extra members. A value that is empty
// leaves its member out.
func docOf(id, name, uris string, extra ...string) string {
	members := make([]string, 0, 3+len(extra))

	for _, member := range [][2]string{{"client_id", id}, {"client_name", name}, {"redirect_uris", uris}} {
		if member[1] != "" {
			members = append(members, `"`+member[0]+`":`+member[1])
		}
	}

	return "{" + strings.Join(append(members, extra...), ",") + "}"
}

// metadataDoc returns a valid document with the extra members.
func metadataDoc(extra ...string) string { return docOf(jsonID, jsonName, jsonURIs, extra...) }

// quoted is s as a JSON string.
func quoted(t *testing.T, s string) string {
	t.Helper()

	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	return string(encoded)
}

// withName is a valid document with the given client_name.
func withName(t *testing.T, name string) string {
	t.Helper()

	return docOf(jsonID, quoted(t, name), jsonURIs)
}

// withRedirects is a valid document with these redirect_uris.
func withRedirects(t *testing.T, uris ...string) string {
	t.Helper()

	encoded, err := json.Marshal(uris)
	if err != nil {
		t.Fatal(err)
	}

	return docOf(jsonID, jsonName, string(encoded))
}

// padded is a valid document of exactly n bytes, padded by an unknown member.
func padded(n int) string {
	const head = `{"x":"`

	doc := metadataDoc()
	filler := n - len(doc) - len(head) - 1 // the `",` added, less the `{` of doc that is dropped

	return head + strings.Repeat("a", filler) + `",` + doc[1:]
}

// metadataCases is the table of ParseClientMetadata, against metadataURL.
func metadataCases(t *testing.T) []parseCase {
	t.Helper()

	return slices.Concat(
		acceptedMetadata(t), malformedMetadata(t), repeatedMetadata(), clientIDMetadata(), clientNameMetadata(t),
		redirectMetadata(t), authMethodMetadata(), sizeMetadata(),
	)
}

func acceptedMetadata(t *testing.T) []parseCase {
	t.Helper()

	uris := redirectURIList(input.MaxRedirectURIs)
	spaced := " {\n \"client_id\" : " + jsonID + " ,\n\"client_name\":" + jsonName + ",\n" +
		"\"redirect_uris\" : [ \"https://client.example.com/cb\" ] }\n"

	return []parseCase{
		{"the minimal document", metadataDoc(), true},
		{"with whitespace", spaced, true},
		{"members in another order", `{"redirect_uris":` + jsonURIs + `,"client_name":"x","client_id":` + jsonID + `}`, true},
		{"auth method none", metadataDoc(authNone), true},
		{"the usual optional members", metadataDoc(
			`"client_uri":"https://client.example.com/"`, `"logo_uri":"https://client.example.com/logo.png"`,
			`"tos_uri":"https://client.example.com/tos"`, `"policy_uri":"https://client.example.com/privacy"`,
			`"grant_types":["authorization_code","refresh_token"]`, `"response_types":["code"]`,
			`"scope":"mcp:read mcp:write"`, `"application_type":"native"`, `"contacts":["a@example.com"]`,
			`"software_id":"abc"`, `"software_version":"1.2"`), true},
		{"an unknown member of any type", metadataDoc(`"x1":1`, `"x2":null`, `"x3":true`, `"x4":{"a":[1,{"b":2}]}`), true},
		{"an unknown member that is a key set", metadataDoc(`"jwks":{"keys":[{"kty":"RSA","n":"abc","e":"AQAB"}]}`), true},
		{"a member that differs by case, which is ignored", metadataDoc(`"Client_ID":"https://evil.example/c"`), true},
		{"a member named as a known one in capitals, which is ignored", metadataDoc(`"CLIENT_NAME":"Evil"`), true},
		{"an unknown member with an escaped name", metadataDoc(`"unknown\u0041":1`), true},
		{"a deeply nested unknown member", metadataDoc(`"x":` + strings.Repeat("[", 1000) + strings.Repeat("]", 1000)), true},
		{"the most redirect URIs", withRedirects(t, uris...), true},
		{"a loopback redirect", withRedirects(t, "http://127.0.0.1/cb", "http://[::1]:8080/cb", "http://localhost/cb"), true},
		{"redirects of every kind", withRedirects(t, goodURI, "http://127.0.0.1/cb", "https://o.example.org/x?a=b"), true},
		{"the same redirect twice", withRedirects(t, goodURI, goodURI), true},
		{"a name of one character", withName(t, "x"), true},
		{"a name of the bound", withName(t, strings.Repeat("a", input.MaxClientNameBytes)), true},
		{"a name with spaces and punctuation", withName(t, `My "App" <v2> & co.`), true},
		{"a name in CJK", withName(t, "\u65e5\u672c\u8a9e\u30a2\u30d7\u30ea"), true},
		{"a name of 3-byte characters in the bound", withName(t, strings.Repeat("\u65e5", input.MaxClientNameBytes/3)), true},
		{"a name written with an escape", docOf(jsonID, `"A\u0042C"`, jsonURIs), true},
		{"a client_id written with an escape", strings.Replace(metadataDoc(), "client.json", "client.js\\u006fn", 1), true},
		{"the largest document", padded(input.MaxClientMetadataBytes), true},
	}
}

// redirectURIList is n distinct valid redirect URIs.
func redirectURIList(n int) []string {
	uris := make([]string, n)
	for i := range uris {
		uris[i] = "https://client.example.com/cb" + strings.Repeat("a", i)
	}

	return uris
}

func malformedMetadata(t *testing.T) []parseCase {
	t.Helper()

	whole := metadataDoc()

	return []parseCase{
		{"empty", "", false},
		{"only whitespace", " \n", false},
		{"null", "null", false},
		{"an array", "[]", false},
		{"an array of the document", "[" + whole + "]", false},
		{"a string", `"x"`, false},
		{"a number", "1", false},
		{"a boolean", "true", false},
		{"an empty object", "{}", false},
		{"truncated", whole[:len(whole)-1], false},
		{"truncated in the middle", whole[:30], false},
		{"a document twice", whole + whole, false},
		{"a document and a trailing value", whole + " 1", false},
		{"a document and trailing garbage", whole + "x", false},
		{"a trailing comma", strings.TrimSuffix(whole, "}") + ",}", false},
		{"single quotes", strings.ReplaceAll(whole, `"`, "'"), false},
		{"unquoted names", `{client_id:` + jsonID + `}`, false},
		{"a comment", "/* c */" + whole, false},
		{"a byte order mark", "\ufeff" + whole, false},
		{"NUL", whole + "\x00", false},
		{"NUL in a string", withName(t, "a\x00b"), false},
		{"a raw newline in a string", strings.Replace(whole, "Example Client", "Example\nClient", 1), false},
		{"invalid UTF-8 in an unknown member", metadataDoc(`"x":"a` + "\xff" + `b"`), false},
		{"invalid UTF-8 in the name", strings.Replace(whole, "Example Client", "Example \xff", 1), false},
		{"an unpaired surrogate escape", metadataDoc(`"x":"\ud800"`), false},
		{"U+FFFD in an unknown member", metadataDoc(`"x":"\ufffd"`), false},
		{"U+FFFD in a member name", metadataDoc(`"\ufffd":1`), false},
	}
}

func repeatedMetadata() []parseCase {
	return []parseCase{
		{"a repeated client_id", metadataDoc(`"client_id":` + jsonID), false},
		{"a repeated client_id with another value", metadataDoc(`"client_id":"https://evil.example/c"`), false},
		{"a repeated client_name", metadataDoc(`"client_name":"Other"`), false},
		{"a repeated redirect_uris", metadataDoc(`"redirect_uris":["https://evil.example/cb"]`), false},
		{"a repeated auth method", metadataDoc(authNone, authNone), false},
		{"a repeated unknown member", metadataDoc(`"x":1`, `"x":2`), false},
		{"a repeated member spelled with an escape", metadataDoc(`"clien\u0074_id":"https://evil.example/c"`), false},
		{"a repeated member inside an unknown member", metadataDoc(`"jwks":{"a":1,"a":2}`), false},
		{"a repeated member inside an array", metadataDoc(`"x":[{"a":1,"a":2}]`), false},
	}
}

func clientIDMetadata() []parseCase {
	other := func(from, to string) string { return strings.Replace(metadataDoc(), from, to, 1) }

	return []parseCase{
		{"no client_id", docOf("", jsonName, jsonURIs), false},
		{"a different client_id", other(metadataURL, "https://client.example.com/other.json"), false},
		{"a client_id with a trailing slash", other(metadataURL+`"`, metadataURL+`/"`), false},
		{"a client_id with an upper-case host", other("https://client.", "https://Client."), false},
		{"a client_id with an upper-case scheme", other("https://client.", "HTTPS://client."), false},
		{"a client_id over http", other("https://client.", "http://client."), false},
		{"a client_id with the default port", other("example.com/oauth", "example.com:443/oauth"), false},
		{"a client_id with a query", other(metadataURL+`"`, metadataURL+`?a=1"`), false},
		{"a client_id with a fragment", other(metadataURL+`"`, metadataURL+`#f"`), false},
		{"a client_id that is empty", docOf(`""`, jsonName, jsonURIs), false},
		{"a client_id that is null", docOf("null", jsonName, jsonURIs), false},
		{"a client_id that is a number", docOf("1", jsonName, jsonURIs), false},
		{"a client_id that is an array", docOf("["+jsonID+"]", jsonName, jsonURIs), false},
		{"a client_id that is an object", docOf("{}", jsonName, jsonURIs), false},
		{"the member name in the wrong case", other(`"client_id"`, `"Client_ID"`), false},
	}
}

func clientNameMetadata(t *testing.T) []parseCase {
	t.Helper()

	wide := input.MaxClientNameBytes/3 + 1

	return []parseCase{
		{"no client_name", docOf(jsonID, "", jsonURIs), false},
		{"an empty name", withName(t, ""), false},
		{"a name of spaces", withName(t, "   "), false},
		{"a name of one over the bound", withName(t, strings.Repeat("a", input.MaxClientNameBytes+1)), false},
		{"a name of 3-byte characters over the bound", withName(t, strings.Repeat("\u65e5", wide)), false},
		{"a name with a control character", withName(t, "a\x01b"), false},
		{"a name with a tab", withName(t, "a\tb"), false},
		{"a name with a newline", withName(t, "a\nb"), false},
		{"a name with a bidi override", withName(t, "a\u202eb"), false},
		{"a name with a zero-width space", withName(t, "a\u200bb"), false},
		{"a name with a joiner", withName(t, "a\u200db"), false},
		{"a name with a byte order mark", withName(t, "\ufeffa"), false},
		{"a name that is not normalised", withName(t, "cafe\u0301"), false},
		{"a name with U+FFFD", withName(t, "a\ufffdb"), false},
		{"a name that is null", docOf(jsonID, "null", jsonURIs), false},
		{"a name that is a number", docOf(jsonID, "1", jsonURIs), false},
		{"a name that is an object", docOf(jsonID, `{"en":"x"}`, jsonURIs), false},
		{"a name that is an array", docOf(jsonID, `["x"]`, jsonURIs), false},
	}
}

func redirectMetadata(t *testing.T) []parseCase {
	t.Helper()

	long := "https://client.example.com/" + strings.Repeat("a", input.MaxRedirectURIBytes)

	return []parseCase{
		{"no redirect_uris", docOf(jsonID, jsonName, ""), false},
		{"an empty list", withRedirects(t), false},
		{"one over the most", withRedirects(t, redirectURIList(input.MaxRedirectURIs+1)...), false},
		{"a redirect_uris that is null", docOf(jsonID, jsonName, "null"), false},
		{"a redirect_uris that is a string", docOf(jsonID, jsonName, `"https://client.example.com/cb"`), false},
		{"a redirect_uris that is an object", docOf(jsonID, jsonName, "{}"), false},
		{"an element that is a number", docOf(jsonID, jsonName, "[1]"), false},
		{"an element that is null", docOf(jsonID, jsonName, "[null]"), false},
		{"an element that is a list", docOf(jsonID, jsonName, `[["https://client.example.com/cb"]]`), false},
		{"an empty element", withRedirects(t, ""), false},
		// An entry that is not a RedirectURI is skipped, and a document with at
		// least one that is, is accepted. Without one it is refused.
		{"a valid element and an empty one", withRedirects(t, "https://client.example.com/cb", ""), true},
		{"a valid element and a custom scheme", withRedirects(t, "https://client.example.com/cb", "myapp://cb"), true},
		{"a custom scheme first", withRedirects(t, "myapp://cb", "https://client.example.com/cb"), true},
		{"a valid element among https localhost, a custom scheme, http and a relative URI", withRedirects(t,
			"https://localhost:8080/cb", "com.example.app:/cb", "http://client.example.com/cb", "/cb",
			"https://client.example.com/cb", "https://Client.example.com/cb"), true},
		{"the most entries, one of them valid", withRedirects(t, append(slices.Repeat([]string{"myapp://cb"},
			input.MaxRedirectURIs-1), goodURI)...), true},
		{"a reserved query name beside a valid element", withRedirects(t,
			"https://client.example.com/cb?state=evil&iss=https://x", "https://client.example.com/cb"), true},
		{"a valid element, then a reserved query name", withRedirects(t,
			"https://client.example.com/cb", "https://client.example.com/cb?code=1"), true},
		{"an encoded reserved query name beside a valid element", withRedirects(t,
			"https://client.example.com/cb?%63ode=1", "http://127.0.0.1:9/cb"), true},
		{"only a reserved query name", withRedirects(t, "https://client.example.com/cb?state=evil"), false},
		{"only reserved query names", withRedirects(t,
			"https://client.example.com/cb?iss=1", "http://localhost/cb?error",
			"https://client.example.com/cb?error_description="), false},
		{"no valid element among several", withRedirects(t, "myapp://cb", "https://localhost/cb", "", "/cb"), false},
		{"a custom scheme", withRedirects(t, "myapp://cb"), false},
		{"https localhost", withRedirects(t, "https://localhost/cb"), false},
		{"localhost is loopback, in a document", withRedirects(t, "http://localhost/cb"), true},
		{"localhost with a port", withRedirects(t, "http://localhost:3000/cb"), true},
		{"localhost, a lookalike", withRedirects(t, "http://localhost.evil.com/cb"), false},
		{"localhost, upper case", withRedirects(t, "http://LOCALHOST/cb"), false},
		// The bounds are held on every entry, skipped or not: a document cannot be
		// accepted with an entry over the byte bound, or one of another type.
		{"a valid element and one over the bound", withRedirects(t, goodURI, long), false},
		{"a skipped element over the bound", withRedirects(t, goodURI,
			"myapp://"+strings.Repeat("a", input.MaxRedirectURIBytes)), false},
		{"a valid element and a number", docOf(jsonID, jsonName, `["`+goodURI+`",1]`), false},
		{"a valid element and a null", docOf(jsonID, jsonName, `["`+goodURI+`",null]`), false},
		{"a valid element and a list", docOf(jsonID, jsonName, `["`+goodURI+`",["`+goodURI+`"]]`), false},
		{"one over the most, the extra a skipped one", withRedirects(t, append(redirectURIList(input.MaxRedirectURIs),
			"myapp://cb")...), false},
		{"http for a public host", withRedirects(t, "http://client.example.com/cb"), false},
		{"a fragment that looks like userinfo", withRedirects(t, "https://evil.com#@good"), false},
		{"a lookalike of loopback", withRedirects(t, "http://127.0.0.1.evil.com/cb"), false},
		{"an upper-case host", withRedirects(t, "https://Client.example.com/cb"), false},
		{"the default port written out", withRedirects(t, "https://client.example.com:443/cb"), false},
		{"a relative URI", withRedirects(t, "/cb"), false},
		{"a URI with a space", withRedirects(t, "https://client.example.com/c b"), false},
		{"a URI over the bound", withRedirects(t, long), false},
		{"a URI of exactly the bound", withRedirects(t, "https://client.example.com/"+strings.Repeat("a",
			input.MaxRedirectURIBytes-len("https://client.example.com/"))), true},
	}
}

func authMethodMetadata() []parseCase {
	method := func(value string) string { return metadataDoc(`"token_endpoint_auth_method":` + value) }

	return []parseCase{
		{"client_secret_basic", method(`"client_secret_basic"`), false},
		{"client_secret_post", method(`"client_secret_post"`), false},
		{"client_secret_jwt", method(`"client_secret_jwt"`), false},
		{"private_key_jwt", method(`"private_key_jwt"`), false},
		{"an auth method of None", method(`"None"`), false},
		{"an auth method of NONE", method(`"NONE"`), false},
		{"an auth method with a space", method(`"none "`), false},
		{"an empty auth method", method(`""`), false},
		{"a null auth method", method("null"), false},
		{"a numeric auth method", method("0"), false},
		{"a list as the auth method", method(`["none"]`), false},
		{"a client_secret", metadataDoc(`"client_secret":"s3cret"`), false},
		{"an empty client_secret", metadataDoc(`"client_secret":""`), false},
		{"a null client_secret", metadataDoc(`"client_secret":null`), false},
		{"a client_secret_expires_at", metadataDoc(`"client_secret_expires_at":0`), false},
		{"a secret beside a valid auth method", metadataDoc(authNone, `"client_secret":"x"`), false},
	}
}

func sizeMetadata() []parseCase {
	return []parseCase{
		{"one byte over the largest document", padded(input.MaxClientMetadataBytes + 1), false},
		{"a megabyte", padded(1 << 20), false},
		{"a megabyte of whitespace and a document", strings.Repeat(" ", 1<<20) + metadataDoc(), false},
	}
}

// metadataParser parses a document as the client at metadataURL.
func metadataParser(tb testing.TB) func([]byte) (input.ClientMetadata, error) {
	tb.Helper()

	id, err := input.ParseClientID(metadataURL, productionTable())
	if err != nil {
		tb.Fatal(err)
	}

	return partial(input.ParseClientMetadata, id)
}

// validateMetadata is what is true of every accepted document.
func validateMetadata(got input.ClientMetadata) error {
	count := len(got.RedirectURIs())

	if got.ClientID().String() != metadataURL || got.Name() == "" || len(got.Name()) > input.MaxClientNameBytes ||
		count < 1 || count > input.MaxRedirectURIs {
		return errMetadata
	}

	return nil
}

type metadataError string

func (e metadataError) Error() string { return string(e) }

const errMetadata = metadataError("an accepted document broke an invariant")

func TestParseClientMetadata(t *testing.T) {
	t.Parallel()

	for _, n := range []int{input.MaxClientMetadataBytes, input.MaxClientMetadataBytes + 1, 1 << 20} {
		if got := len(padded(n)); got != n {
			t.Fatalf("padded(%d) is %d bytes", n, got)
		}
	}

	parse := metadataParser(t)

	runStringTable(t, metadataCases(t), func(raw string) (string, error) {
		got, err := parse([]byte(raw))
		if err != nil {
			return "", err
		}

		return raw, validateMetadata(got)
	}, input.CodeInvalidClientMetadata)
}

// TestClientMetadataReadsItsMembers: what an accepted document gives back.
func TestClientMetadataReadsItsMembers(t *testing.T) {
	t.Parallel()

	id, err := input.ParseClientID(metadataURL, productionTable())
	if err != nil {
		t.Fatal(err)
	}

	doc := `{"client_id":"` + metadataURL + `","client_name":"My \"App\"","redirect_uris":` +
		`["https://client.example.com/cb","http://127.0.0.1:8080/cb"],"logo_uri":"x"}`

	got, err := input.ParseClientMetadata(id, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}

	if got.ClientID() != id || got.Name() != `My "App"` || got.ClientName().String() != got.Name() {
		t.Errorf("ClientID() = %v, Name() = %q, ClientName() = %q", got.ClientID(), got.Name(), got.ClientName())
	}

	uris := got.RedirectURIs()
	if len(uris) != 2 || uris[0].String() != "https://client.example.com/cb" ||
		uris[1].String() != "http://127.0.0.1:8080/cb" {
		t.Fatalf("RedirectURIs() = %v", uris)
	}

	// The slice is a copy.
	uris[0] = uris[1]

	if got.RedirectURIs()[0].String() != "https://client.example.com/cb" {
		t.Error("RedirectURIs() shares storage between calls")
	}
}

// registersCase is a request and whether the document of TestClientMetadataRegisters
// registers it.
type registersCase struct {
	request string
	want    bool
}

// registersCases are the requests asked of that document.
func registersCases() []registersCase {
	return []registersCase{
		{"https://client.example.com/cb", true},
		{"https://client.example.com/cb2", false},
		{"https://client.example.com/cb/", false},
		{"https://client.example.com:8443/cb", false},
		{"https://client.example.org/cb", false},
		{"https://evil.com/cb", false},
		{"http://127.0.0.1:8080/native", true},
		{"http://127.0.0.1:55555/native", true},
		{"http://127.0.0.1/native", true},
		{"http://127.0.0.1:55555/other", false},
		{"http://127.0.0.1:55555/native?a=1", false},
		{"http://[::1]:55555/native", false},
		{"http://[::1]:55555/v6", true},
		{"http://127.0.0.1:55555/v6", false},
		{"https://127.0.0.1.evil.com/native", false},
		{"https://127.0.0.1.evil.com:8080/native", false},
		{"http://localhost:3000/mcp", true},
		{"http://localhost:55555/mcp", true},
		{"http://localhost/mcp", true},
		{"http://localhost:55555/other", false},
		// A registered localhost is not 127.0.0.1 or [::1], and the reverse.
		{"http://127.0.0.1:3000/mcp", false},
		{"http://[::1]:3000/mcp", false},
		{"http://localhost:8080/native", false},
		{"http://localhost:55555/v6", false},
		{"https://localhost.evil.com/mcp", false},
	}
}

// TestClientMetadataRegisters: a request is allowed by exact string, or by a
// loopback URI with any port; nothing else.
func TestClientMetadataRegisters(t *testing.T) {
	t.Parallel()

	id, err := input.ParseClientID(metadataURL, productionTable())
	if err != nil {
		t.Fatal(err)
	}

	doc := withRedirects(t, "https://client.example.com/cb", "http://127.0.0.1:8080/native", "http://[::1]/v6",
		"http://localhost:3000/mcp")

	got, err := input.ParseClientMetadata(id, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range registersCases() {
		request, err := input.ParseRedirectURI(tc.request)
		if err != nil {
			t.Fatalf("%q: %v", tc.request, err)
		}

		if got.Registers(request) != tc.want {
			t.Errorf("Registers(%q) = %v, want %v", tc.request, !tc.want, tc.want)
		}
	}

	var zero input.ClientMetadata

	known, _ := input.ParseRedirectURI("https://client.example.com/cb")
	if zero.Registers(known) || got.Registers(input.RedirectURI{}) {
		t.Error("a zero value was registered")
	}
}

// TestClientMetadataSkipsRedirectsItCannotUse: an entry that does not parse is not
// registered, whatever it names, and the ones that parse keep their order. A
// request for the skipped one is refused like any other that is not listed.
func TestClientMetadataSkipsRedirectsItCannotUse(t *testing.T) {
	t.Parallel()

	id, err := input.ParseClientID(metadataURL, productionTable())
	if err != nil {
		t.Fatal(err)
	}

	skipped := []string{
		"myapp://cb", "https://localhost:8080/cb", "com.example.app:/cb", "https://client.example.com/c b",
		"https://client.example.com/one?state=evil", "http://127.0.0.1:9/two?iss=https://x",
	}
	doc := withRedirects(t, skipped[0], "https://client.example.com/one", skipped[1], skipped[2],
		"http://127.0.0.1:9/two", skipped[3], skipped[4], skipped[5])

	got, err := input.ParseClientMetadata(id, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}

	parsed := got.RedirectURIs()
	kept := make([]string, 0, len(parsed))

	for _, uri := range parsed {
		kept = append(kept, uri.String())
	}

	if want := []string{"https://client.example.com/one", "http://127.0.0.1:9/two"}; !slices.Equal(kept, want) {
		t.Errorf("RedirectURIs = %v, want %v", kept, want)
	}

	for _, raw := range skipped {
		// The ones that parse as a RedirectURI at all are still not registered.
		request, err := input.ParseRedirectURI(raw)
		if err == nil && got.Registers(request) {
			t.Errorf("a skipped entry %q is registered", raw)
		}
	}
}

// TestClientMetadataIsBoundToItsClientID: the document names one URL and is
// accepted only for it.
func TestClientMetadataIsBoundToItsClientID(t *testing.T) {
	t.Parallel()

	other, err := input.ParseClientID("https://other.example.com/client.json", productionTable())
	if err != nil {
		t.Fatal(err)
	}

	_, err = input.ParseClientMetadata(other, []byte(metadataDoc()))
	requireRefusal(t, err, input.CodeInvalidClientMetadata)

	// The zero ClientID matches no document.
	_, err = input.ParseClientMetadata(input.ClientID{}, []byte(metadataDoc()))
	requireRefusal(t, err, input.CodeInvalidClientMetadata)
}

func TestClientMetadataDescriptionStatesTheBounds(t *testing.T) {
	t.Parallel()

	_, err := metadataParser(t)(nil)
	description := descriptionOf(t, err, input.CodeInvalidClientMetadata)

	requireMentions(t, description, input.MaxClientMetadataBytes)
	requireMentions(t, description, input.MaxClientNameBytes)
	requireMentions(t, description, input.MaxRedirectURIs)
}

func FuzzParseClientMetadata(f *testing.F) {
	for _, seed := range seedsOf(metadataCases(&testing.T{})) {
		if len(seed) < 8192 {
			f.Add([]byte(seed))
		}
	}

	parse := metadataParser(f)
	_, probe := parse([]byte("\x00"))
	description := probeDescription(probe)

	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := parse(body)
		if err != nil {
			requireFixedRefusal(t, err, input.CodeInvalidClientMetadata, description)

			return
		}

		if validateMetadata(got) != nil || len(body) > input.MaxClientMetadataBytes || !json.Valid(body) {
			t.Fatalf("accepted %q", body)
		}

		requireDocumentSaysSo(t, body)

		for _, uri := range got.RedirectURIs() {
			_, err := input.ParseRedirectURI(uri.String())
			if err != nil || !got.Registers(uri) {
				t.Fatalf("accepted the redirect URI %q: %v", uri, err)
			}
		}
	})
}

// requireDocumentSaysSo checks that an accepted body names the client it was
// accepted for and holds no secret, reading it with the standard library.
func requireDocumentSaysSo(t *testing.T, body []byte) {
	t.Helper()

	var members map[string]json.RawMessage

	err := json.Unmarshal(body, &members)
	if err != nil {
		t.Fatal(err)
	}

	var documentID string

	err = json.Unmarshal(members["client_id"], &documentID)
	if err != nil || documentID != metadataURL {
		t.Fatalf("accepted a document whose client_id is %q: %v", documentID, err)
	}

	for _, name := range []string{"client_secret", "client_secret_expires_at"} {
		if _, found := members[name]; found {
			t.Fatalf("accepted a document with %s", name)
		}
	}
}
