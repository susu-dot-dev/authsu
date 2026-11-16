package registration

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

// These tests state what the request handlers must accept and refuse at the
// edges of the WebAuthn JSON encoding (section 5.1, RegistrationResponseJSON)
// and of the account name (section 5.4.3). Some of them fail until the
// behaviour is implemented; they describe the intended behaviour, not the
// current one.

// postFinish runs the finish handler on a raw body.
func postFinish(t *testing.T, fix *fixture, body []byte) (httpapi.Response, error) {
	t.Helper()

	resp, err := fix.svc.FinishHandler(getenv(nil))(httpapi.Request{
		Method: http.MethodPost, Path: "/", Context: t.Context(), Query: nil, Body: body,
	}).Get()
	if err != nil {
		return httpapi.Response{}, fmt.Errorf("finish: %w", err)
	}

	return resp, nil
}

// asMap turns a FinishRequest into its JSON object, so tests can add members
// the struct does not have.
func asMap(t *testing.T, req FinishRequest) map[string]any {
	t.Helper()

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out map[string]any

	err = json.Unmarshal(data, &out)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return data
}

// storedTransports returns the transports written to credentials.metadata.
func storedTransports(t *testing.T, fix *fixture) []string {
	t.Helper()

	if len(fix.batcher.batches) != 1 {
		t.Fatalf("batches = %d, want 1", len(fix.batcher.batches))
	}

	raw, _ := fix.batcher.batches[0][1].Args[credArgMetadata].(string)

	var meta credentialMetadata

	err := json.Unmarshal([]byte(raw), &meta)
	if err != nil {
		t.Fatalf("metadata %q: %v", raw, err)
	}

	return meta.Transports
}

// Transport values (section 5.8.4) the tests use more than once.
const (
	transportUSB      = "usb"
	transportInternal = "internal"
)

// TestFinishBoundsTransports covers response.transports. Section 5.2.1 says the
// client reports "zero or more unique DOMStrings in lexicographical order",
// which SHOULD be AuthenticatorTransport values, and that relying parties
// "SHOULD accept and store unknown values". So unknown values are kept, but the
// list is bounded (at most 8 entries of 1 to 32 printable-ASCII bytes) and must
// be unique and sorted, and anything else is the client's error, refused before
// the database.
func TestFinishBoundsTransports(t *testing.T) {
	t.Parallel()

	refused := map[string][]string{
		"too many entries":    {"a", "b", "c", "d", "e", "f", "g", "h", "i"},
		"an entry too long":   {strings.Repeat("x", 33)},
		"an empty entry":      {""},
		"a NUL":               {transportUSB + "\x00"},
		"a control character": {transportUSB + "\t"},
		"non-ASCII":           {"us\u00e9"},
		"a duplicate":         {transportUSB, transportUSB},
		"not sorted":          {transportUSB, "nfc"},
		"far too long":        {strings.Repeat("x", 20000)},
	}

	for name, transports := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			req := beginThenRespond(t, fix, newAuthenticator())
			req.Credential.Response.Transports = transports

			_, err := postFinish(t, fix, mustJSON(t, req))
			wantFailure(t, err, apierr.BadRequest, CodeInvalidCredential)

			if len(fix.batcher.batches) != 0 {
				t.Error("a refused registration reached the database")
			}
		})
	}

	accepted := map[string][]string{
		"none reported":      {},
		"a platform passkey": {"hybrid", transportInternal},
		"a security key":     {"nfc", transportUSB},
		"an unknown value":   {"carrier-pigeon", transportInternal},
		"the most allowed": {
			"a", "b", "c", "d", "e", "f", "g", strings.Repeat("z", 32),
		},
	}

	for name, transports := range accepted {
		t.Run("stores "+name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			req := beginThenRespond(t, fix, newAuthenticator())
			req.Credential.Response.Transports = transports

			_, err := postFinish(t, fix, mustJSON(t, req))
			if err != nil {
				t.Fatalf("finish: %v", err)
			}

			if got := storedTransports(t, fix); !slices.Equal(got, transports) {
				t.Errorf("stored transports = %q, want %q", got, transports)
			}
		})
	}
}

// toJSONParts derives the members PublicKeyCredential.toJSON() adds to a
// registration response: authenticatorData, publicKey (DER
// SubjectPublicKeyInfo) and publicKeyAlgorithm, from the attestation object.
func toJSONParts(t *testing.T, req FinishRequest) (string, string) {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(req.Credential.Response.AttestationObject)
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}

	var object struct {
		AuthData []byte `cbor:"authData"`
	}

	err = cbor.Unmarshal(raw, &object)
	if err != nil {
		t.Fatalf("decode attestation object: %v", err)
	}

	const credIDLenAt = 32 + 1 + 4 + 16

	idLen := int(binary.BigEndian.Uint16(object.AuthData[credIDLenAt:]))

	var key map[int]any

	err = cbor.Unmarshal(object.AuthData[credIDLenAt+2+idLen:], &key)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	x, _ := key[-2].([]byte)
	y, _ := key[-3].([]byte)

	point, err := ecdh.P256().NewPublicKey(slices.Concat([]byte{0x04}, x, y))
	if err != nil {
		t.Fatalf("point: %v", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(point)
	if err != nil {
		t.Fatalf("SPKI: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(object.AuthData), base64.RawURLEncoding.EncodeToString(spki)
}

// browserShaped is req as PublicKeyCredential.toJSON() writes it
// (RegistrationResponseJSON, section 5.1), with every member a browser sends.
func browserShaped(t *testing.T, req FinishRequest) map[string]any {
	t.Helper()

	body := asMap(t, req)
	authData, publicKey := toJSONParts(t, req)

	credential, _ := body["credential"].(map[string]any)
	credential["authenticatorAttachment"] = "platform"
	credential["clientExtensionResults"] = map[string]any{}

	response, _ := credential["response"].(map[string]any)
	response["authenticatorData"] = authData
	response["publicKey"] = publicKey
	response["publicKeyAlgorithm"] = -7

	return body
}

// TestFinishAcceptsWhatToJSONProduces covers the request shape a real browser
// sends: the output of PublicKeyCredential.toJSON(), unmodified. Refusing its
// members would force every frontend to strip them, which is where a frontend
// ends up sending something other than what the browser produced.
func TestFinishAcceptsWhatToJSONProduces(t *testing.T) {
	t.Parallel()

	withoutPublicKey := func(body map[string]any) {
		credential, _ := body["credential"].(map[string]any)
		response, _ := credential["response"].(map[string]any)
		// publicKey is the one optional member of the response.
		delete(response, "publicKey")
	}

	withoutAttachment := func(body map[string]any) {
		credential, _ := body["credential"].(map[string]any)
		// authenticatorAttachment is optional.
		delete(credential, "authenticatorAttachment")
	}

	tests := map[string]func(map[string]any){
		"every member":                    func(map[string]any) {},
		"without publicKey":               withoutPublicKey,
		"without authenticatorAttachment": withoutAttachment,
	}

	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			body := browserShaped(t, beginThenRespond(t, fix, newAuthenticator()))
			edit(body)

			resp, err := postFinish(t, fix, mustJSON(t, body))
			if err != nil {
				t.Fatalf("finish: %v", err)
			}

			if resp.Status != http.StatusCreated {
				t.Errorf("status = %d, want %d", resp.Status, http.StatusCreated)
			}
		})
	}
}

// TestFinishRefusesClientExtensionResults covers clientExtensionResults: we
// request no extensions, so any output is unsolicited, and section 7.1 lets the
// relying party refuse it. It must be refused as an invalid credential, not as
// an unknown member of the request.
func TestFinishRefusesClientExtensionResults(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	body := browserShaped(t, beginThenRespond(t, fix, newAuthenticator()))
	credential, _ := body["credential"].(map[string]any)
	credential["clientExtensionResults"] = map[string]any{"credProps": map[string]any{"rk": true}}

	_, err := postFinish(t, fix, mustJSON(t, body))
	wantFailure(t, err, apierr.BadRequest, CodeInvalidCredential)

	if len(fix.batcher.batches) != 0 {
		t.Error("a refused registration reached the database")
	}
}

// TestNameRefusesInvisibleAndControlCharacters covers the account name, which
// the browser shows in its passkey prompt and which is stored as the display
// name. Section 5.4.3 asks relying parties to enforce the PRECIS Nickname
// profile; authsu enforces its core: no control (Cc) or format (Cf) code
// points, which include NUL, bidirectional overrides and zero-width
// characters, and text in Unicode Normalization Form C.
func TestNameRefusesInvisibleAndControlCharacters(t *testing.T) {
	t.Parallel()

	refused := map[string]string{
		"NUL":                      "Ali\x00ce",
		"a tab":                    "Ali\tce",
		"a newline":                "Alice\n",
		"DEL":                      "Alice\x7f",
		"a C1 control":             "Alice\u0085",
		"a right-to-left override": "\u202eecilA",
		"a left-to-right isolate":  "Alice\u2066",
		"a zero-width space":       "Ali\u200bce",
		"a zero-width joiner":      "Ali\u200dce",
		"a byte order mark":        "\ufeffAlice",
		"a soft hyphen":            "Ali\u00adce",
		"decomposed (not NFC)":     "Rene\u0301e",
		"decomposed Hangul":        "\u1100\u1161",
	}

	for name, value := range refused {
		t.Run("begin refuses "+name, func(t *testing.T) {
			t.Parallel()

			_, err := begin(t, newFixture(t), getenv(nil), BeginRequest{InvitationCode: testCode, Name: value})
			wantFailure(t, err, apierr.BadRequest, CodeInvalidName)
		})
	}

	t.Run("finish refuses a right-to-left override", func(t *testing.T) {
		t.Parallel()

		fix := newFixture(t)
		req := beginThenRespond(t, fix, newAuthenticator())
		req.Name = "\u202eecilA"

		_, err := postFinish(t, fix, mustJSON(t, req))
		wantFailure(t, err, apierr.BadRequest, CodeInvalidName)
	})
}

// TestNameAcceptsOrdinaryText covers names the rules above must not refuse.
func TestNameAcceptsOrdinaryText(t *testing.T) {
	t.Parallel()

	accepted := map[string]string{
		"ASCII":                         "Alice",
		"Latin with accents":            "Ren\u00e9e M\u00fcller",
		"CJK":                           "\u7530\u4e2d\u502b",
		"Arabic":                        "\u0639\u0644\u064a",
		"an emoji":                      "Alice \U0001f600",
		"a precomposed Hangul syllable": "\uac00",
	}

	for name, value := range accepted {
		t.Run("begin accepts "+name, func(t *testing.T) {
			t.Parallel()

			options, err := begin(t, newFixture(t), getenv(nil), BeginRequest{InvitationCode: testCode, Name: value})
			if err != nil {
				t.Fatalf("begin: %v", err)
			}

			if options.PublicKey.User.Name != value {
				t.Errorf("name = %q, want %q", options.PublicKey.User.Name, value)
			}
		})
	}
}

// TestNameRefusesInvalidUTF8 covers a name whose bytes are not UTF-8. The
// request decoder must not repair it to U+FFFD before validation sees it.
func TestNameRefusesInvalidUTF8(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	body := []byte(`{"invitationCode":"` + testCode + `","name":"Ali` + "\xff" + `ce"}`)

	resp, err := fix.svc.BeginHandler(getenv(nil))(httpapi.Request{
		Method: http.MethodPost, Path: "/", Context: t.Context(), Query: nil, Body: body,
	}).Get()
	if err == nil {
		t.Fatalf("begin accepted invalid UTF-8 and echoed name %q", nameOf(resp))
	}

	if kind := apierr.As(err).Kind; kind != apierr.BadRequest {
		t.Errorf("kind = %d, want BadRequest", kind)
	}
}

func nameOf(resp httpapi.Response) string {
	options, _ := resp.Body.(creationOptions)

	return options.PublicKey.User.Name
}

// TestFinishBindsTheNameItParsed shows the challenge commits to the name finish
// decodes: a body whose repeated name member would decode to another name
// cannot reuse a challenge signed for the first. (Strict decoding refuses the
// repeat outright; this holds whichever way it is refused.)
func TestFinishBindsTheNameItParsed(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	body := mustJSON(t, beginThenRespond(t, fix, newAuthenticator()))
	body = bytes.Replace(body, []byte(`"name":"`+testName+`"`), []byte(`"name":"`+testName+`","name":"Mallory"`), 1)

	_, err := postFinish(t, fix, body)
	if err == nil {
		t.Fatal("finish accepted a body with the name repeated")
	}

	if len(fix.batcher.batches) != 0 {
		t.Error("a refused registration reached the database")
	}
}
