package webauthn

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// FuzzVerify feeds arbitrary bytes through every parser as the three
// client-controlled members of a registration. The properties are that it never
// panics, and that whatever it accepts satisfies the invariants the rest of the
// system relies on (a bounded credential id, a re-parsable canonical key).
//
// Run it with `go test -fuzz=FuzzVerify ./internal/webauthn`. Under plain
// `go test` it replays the seed corpus below, which includes a valid response.
func FuzzVerify(f *testing.F) {
	// A valid response seeds the corpus, so mutation starts from the deep
	// parse paths instead of having to discover the format.
	valid := validResponse(f)
	reg := valid.build(f)
	client, _ := base64.RawURLEncoding.DecodeString(reg.ClientDataJSON)
	object, _ := base64.RawURLEncoding.DecodeString(reg.AttestationObject)

	f.Add(client, object, reg.ID, reg.RawID)
	minimal := []byte(`{"type":"webauthn.create","challenge":"AAAA","origin":"` + testOrigin + `"}`)

	f.Add(minimal, []byte{0xa0}, "AA", "AA")
	f.Add([]byte(`{`), []byte{0xbf, 0xff}, "", "")
	duplicated := []byte(`{"type":"webauthn.create","type":"x"}`)
	truncatedObject := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'}

	f.Add(duplicated, truncatedObject, "!", "!")

	f.Fuzz(func(t *testing.T, clientData, attestation []byte, id, rawID string) {
		got, err := Verify(Registration{
			ID:                id,
			RawID:             rawID,
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientData),
			AttestationObject: base64.RawURLEncoding.EncodeToString(attestation),
			Transports:        nil,
		}, testRP())
		if err != nil {
			return
		}

		if n := len(got.Credential.ID); n == 0 || n > maxCredentialIDLen {
			t.Fatalf("accepted a credential id of %d bytes", n)
		}

		if len(got.Challenge) == 0 {
			t.Fatal("accepted an empty challenge")
		}

		// The stored key must be one we would accept again, byte for byte.
		dec, decErr := newDecoder(strictOptions(), cbor.CTAP2EncOptions())
		if decErr != nil {
			t.Fatalf("decoder: %v", decErr)
		}

		again, parseErr := parseCOSEKey(dec, got.Credential.PublicKey)
		if parseErr != nil || !bytes.Equal(again, got.Credential.PublicKey) {
			t.Fatalf("stored key does not round-trip: %v", parseErr)
		}
	})
}

// FuzzParseClientData fuzzes the JSON side alone, which has the most surface:
// whatever is accepted must carry a non-empty challenge and the exact origin.
func FuzzParseClientData(f *testing.F) {
	f.Add([]byte(`{"type":"webauthn.create","challenge":"AAAA","origin":"` + testOrigin + `"}`))
	f.Add([]byte(`{"type":"webauthn.create","challenge":"AAAA","origin":"` + testOrigin + `","crossOrigin":false}`))
	f.Add([]byte(`{"type":"webauthn.create","origin":"x","origin":"y"}`))
	f.Add([]byte(`{"type":"webauthn.create","challenge":"AAAA","origin":"https:\/\/auth.example.com"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		challenge, _, err := ParseClientData(raw, testRP())
		if err != nil {
			return
		}

		if len(challenge) == 0 {
			t.Fatal("accepted an empty challenge")
		}

		// Compare the decoded member, not the raw bytes: JSON escapes such as
		// "https:\/\/..." are the same origin but not the same bytes.
		members, parseErr := strictObject(raw)
		if parseErr != nil {
			t.Fatalf("accepted client data that does not parse: %v", parseErr)
		}

		origin, originErr := requiredString(members, "origin")
		if originErr != nil || origin != testOrigin {
			t.Fatalf("accepted client data whose origin is not the relying party's: %q", raw)
		}
	})
}
