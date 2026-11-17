package webauthn

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// This file pins how the login verifier treats input that go-webauthn reads
// differently, and the properties the signature check is relied on for. It came
// out of a security review of the login verifier against go-webauthn's
// ValidatePasskeyLogin; each case notes where the library differs. The
// signature covers clientDataJSON and authenticator data, so a parsing
// difference there can only be exploited by whoever holds the private key; the
// cases matter because they are what a second parser (a proxy, a log pipeline,
// a future library swap) would read differently.

// ecdsaSignature is the ASN.1 shape of an ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}

func parseSignature(tb testing.TB, der []byte) ecdsaSignature {
	tb.Helper()

	var sig ecdsaSignature

	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 {
		tb.Fatalf("parse signature: %v (rest %d)", err, len(rest))
	}

	return sig
}

func marshalSignature(tb testing.TB, r, s *big.Int) []byte {
	tb.Helper()

	out, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		tb.Fatalf("marshal signature: %v", err)
	}

	return out
}

// curveOrder is n, the order of P-256.
func curveOrder() *big.Int { return elliptic.P256().Params().N }

// TestVerifyAssertionRefusesScalarsOutOfRange covers signatures whose integers
// are not in [1, n-1]. They are well-formed DER, so only the verifier's range
// check refuses them; a verifier without one is open to the classic r = 0 or
// s = 0 forgeries.
func TestVerifyAssertionRefusesScalarsOutOfRange(t *testing.T) {
	t.Parallel()

	n := curveOrder()
	edits := map[string]func(ecdsaSignature) (*big.Int, *big.Int){
		"r is zero":     func(sig ecdsaSignature) (*big.Int, *big.Int) { return big.NewInt(0), sig.S },
		"s is zero":     func(sig ecdsaSignature) (*big.Int, *big.Int) { return sig.R, big.NewInt(0) },
		"r and s zero":  func(ecdsaSignature) (*big.Int, *big.Int) { return big.NewInt(0), big.NewInt(0) },
		"r is n":        func(sig ecdsaSignature) (*big.Int, *big.Int) { return new(big.Int).Set(n), sig.S },
		"s is n":        func(sig ecdsaSignature) (*big.Int, *big.Int) { return sig.R, new(big.Int).Set(n) },
		"r plus n":      func(sig ecdsaSignature) (*big.Int, *big.Int) { return new(big.Int).Add(sig.R, n), sig.S },
		"s plus n":      func(sig ecdsaSignature) (*big.Int, *big.Int) { return sig.R, new(big.Int).Add(sig.S, n) },
		"s negated":     func(sig ecdsaSignature) (*big.Int, *big.Int) { return sig.R, new(big.Int).Neg(sig.S) },
		"r and s equal": func(sig ecdsaSignature) (*big.Int, *big.Int) { return sig.R, sig.R },
	}

	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := validAssertion(t)
			c.tamper = func(der []byte) []byte {
				r, s := edit(parseSignature(t, der))

				return marshalSignature(t, r, s)
			}

			_, err := verifyAssertion(c.build(t), c.stored(t), testRP())
			if !errors.Is(err, ErrAssertion) {
				t.Errorf("err = %v, want it to wrap %v", err, ErrAssertion)
			}
		})
	}
}

// TestVerifyAssertionAcceptsHighS pins a deliberate choice: (r, n-s) is a
// second valid signature for every (r, s), and it is accepted, as go-webauthn
// accepts it. A captured response can therefore be resent with different
// signature bytes, so single use must not be keyed on the signature. It is not:
// the session row records the challenge (see internal/login), and the e2e
// suite replays a malleated signature to prove it.
func TestVerifyAssertionAcceptsHighS(t *testing.T) {
	t.Parallel()

	c := validAssertion(t)
	c.tamper = func(der []byte) []byte {
		sig := parseSignature(t, der)

		return marshalSignature(t, sig.R, new(big.Int).Sub(curveOrder(), sig.S))
	}

	_, err := verifyAssertion(c.build(t), c.stored(t), testRP())
	if err != nil {
		t.Fatalf("verifyAssertion with n-s: %v", err)
	}
}

// editEncoded decodes a base64url member, applies edit, and re-encodes it.
func editEncoded(tb testing.TB, encoded *string, edit func([]byte) []byte) {
	tb.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(*encoded)
	if err != nil {
		tb.Fatalf("decode: %v", err)
	}

	*encoded = base64.RawURLEncoding.EncodeToString(edit(raw))
}

// TestVerifyAssertionSignatureCoversEveryAuthDataBit flips each bit of the 37
// bytes of authenticator data after signing. Every flip must be refused. The
// counter bytes pass every other check, so for them the signature is the only
// thing that can refuse, which proves it covers the bytes as sent.
func TestVerifyAssertionSignatureCoversEveryAuthDataBit(t *testing.T) {
	t.Parallel()

	c := validAssertion(t)
	signed := c.build(t)
	stored := c.stored(t)

	for i := range fixedAuthData {
		for bit := range 8 {
			a := signed
			editEncoded(t, &a.AuthenticatorData, func(raw []byte) []byte {
				out := bytes.Clone(raw)
				out[i] ^= 1 << bit

				return out
			})

			_, err := verifyAssertion(a, stored, testRP())
			if err == nil {
				t.Errorf("byte %d bit %d flipped was accepted", i, bit)
			}

			if i >= rpIDHashLen+flagsLen && !errors.Is(err, ErrAssertion) {
				t.Errorf("counter byte %d bit %d: err = %v, want the signature to refuse it", i, bit, err)
			}
		}
	}
}

// TestVerifyAssertionHashesClientDataAsSent covers clientDataJSON edited after
// signing into a document every JSON parser reads identically: whitespace, an
// escape, member order. The signature covers the bytes, not the meaning, so
// each must fail at the signature (a verifier that re-serialised the document
// before hashing would accept them).
func TestVerifyAssertionHashesClientDataAsSent(t *testing.T) {
	t.Parallel()

	c := validAssertion(t)
	c.rawClient = clientDataWith(`"type":"webauthn.get"`, challengeMember(), originMember)
	signed := c.build(t)
	stored := c.stored(t)

	edits := map[string]func([]byte) []byte{
		"leading space":  func(raw []byte) []byte { return append([]byte(" "), raw...) },
		"trailing space": func(raw []byte) []byte { return append(bytes.Clone(raw), ' ') },
		"escaped name": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"type"`), []byte(`"\u0074ype"`), 1)
		},
		"members reordered": func([]byte) []byte {
			return clientDataWith(originMember, challengeMember(), `"type":"webauthn.get"`)
		},
	}

	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := signed
			editEncoded(t, &a.ClientDataJSON, edit)

			_, err := verifyAssertion(a, stored, testRP())
			if !errors.Is(err, ErrAssertion) || !strings.Contains(err.Error(), "signature") {
				t.Errorf("err = %v, want the signature to refuse it", err)
			}
		})
	}
}

// assertionRejection is one assertion edit and the sentinel it must fail with.
type assertionRejection struct {
	edit func(*assertionCase)
	want error
}

func runAssertionRejections(t *testing.T, tests map[string]assertionRejection) {
	t.Helper()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := validAssertion(t)
			tt.edit(&c)

			_, err := verifyAssertion(c.build(t), c.stored(t), testRP())
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want it to wrap %v", err, tt.want)
			}
		})
	}
}

// TestVerifyAssertionRefusesWhatTheLibraryAccepts lists assertions go-webauthn's
// ValidatePasskeyLogin accepts (checked against the cloned library with the
// default configuration, one origin and user verification required) and this
// verifier refuses. None is something a conforming browser writes.
func TestVerifyAssertionRefusesWhatTheLibraryAccepts(t *testing.T) {
	t.Parallel()

	challenge := challengeMember()
	get := `"type":"webauthn.get"`
	client := func(members ...string) func(*assertionCase) {
		return func(c *assertionCase) { c.rawClient = clientDataWith(members...) }
	}
	origin := func(value string) func(*assertionCase) {
		return client(get, challenge, `"origin":"`+value+`"`)
	}

	runAssertionRejections(t, map[string]assertionRejection{
		// The library matches names case-insensitively (encoding/json).
		"Type in another case": {edit: client(`"Type":"webauthn.get"`, challenge, originMember), want: ErrClientData},
		// The library keeps the last of a repeated name.
		"origin repeated, evil first": {
			edit: client(get, challenge, `"origin":"https://evil.example"`, originMember), want: ErrClientData,
		},
		// The library compares scheme and host only, case-insensitively, with
		// the default port normalised away.
		"origin host in upper case": {edit: origin("https://AUTH.EXAMPLE.COM"), want: ErrClientData},
		"origin with :443":          {edit: origin(testOrigin + ":443"), want: ErrClientData},
		"origin with a path":        {edit: origin(testOrigin + "/evil"), want: ErrClientData},
		"origin with userinfo":      {edit: origin("https://evil.example@auth.example.com"), want: ErrClientData},
		// The library reads null as false and ignores an empty topOrigin.
		"crossOrigin null": {edit: client(get, challenge, originMember, `"crossOrigin":null`), want: ErrClientData},
		"topOrigin empty":  {edit: client(get, challenge, originMember, `"topOrigin":""`), want: ErrClientData},
		// The library ignores reserved bits and accepts extension data.
		"RFU1 set": {edit: func(c *assertionCase) { c.flags |= 0x02 }, want: ErrAuthData},
		"RFU2 set": {edit: func(c *assertionCase) { c.flags |= 0x20 }, want: ErrAuthData},
		"extension data": {
			edit: func(c *assertionCase) {
				c.flags |= byte(flagExtensionData)
				c.authData = append(c.authDataBytes(), mustCBOR(t, map[string]any{"credProtect": 1})...)
			},
			want: ErrAuthData,
		},
	})
}

// TestVerifyAssertionRefusesEncodingsTheLibraryAccepts is the same for the
// base64url members. The library strips "=" from rawId and userHandle, decodes
// without Strict (so unused bits are ignored), and its decoder skips CR and LF.
func TestVerifyAssertionRefusesEncodingsTheLibraryAccepts(t *testing.T) {
	t.Parallel()

	// longID has a length whose encoding leaves unused bits.
	longID := []byte("credential-id-0123456789!")
	edited := func(edit func(*Assertion)) func(*assertionCase) {
		return func(c *assertionCase) {
			c.credID = longID
			c.post = edit
		}
	}
	newline := func(s string) string { return s[:4] + "\r\n" + s[4:] }

	runAssertionRejections(t, map[string]assertionRejection{
		"rawId padded":         {edit: edited(func(a *Assertion) { a.RawID += "=" }), want: ErrAssertion},
		"rawId with a newline": {edit: edited(func(a *Assertion) { a.RawID = newline(a.RawID) }), want: ErrAssertion},
		"rawId with unused bits": {
			edit: edited(func(a *Assertion) { a.RawID = flipUnusedBit(t, a.RawID) }), want: ErrAssertion,
		},
		"id with a newline":   {edit: edited(func(a *Assertion) { a.ID = newline(a.ID) }), want: ErrAssertion},
		"id with unused bits": {edit: edited(func(a *Assertion) { a.ID = flipUnusedBit(t, a.ID) }), want: ErrAssertion},
		"userHandle padded":   {edit: edited(func(a *Assertion) { a.UserHandle += "=" }), want: ErrAssertion},
		"userHandle with a newline": {
			edit: edited(func(a *Assertion) { a.UserHandle = newline(a.UserHandle) }), want: ErrAssertion,
		},
	})
}

// TestVerifyAssertionRefusesCaseVariantMembers covers clientDataJSON members
// whose names differ from a checked member only in case. JSON names are case
// sensitive, so to a strict reader they are unknown members; but
// go-webauthn's encoding/json folds case and keeps the last, so it reads the
// attacker's value from each of these. A document that two parsers read as
// different origins, types or cross-origin states must be refused, not
// interpreted: no browser writes one.
func TestVerifyAssertionRefusesCaseVariantMembers(t *testing.T) {
	t.Parallel()

	get := `"type":"webauthn.get"`

	with := func(extra string) []byte { return clientDataWith(get, challengeMember(), originMember, extra) }

	tests := map[string][]byte{
		"ORIGIN naming another site": with(`"ORIGIN":"https://evil.example"`),
		"Type naming registration":   with(`"Type":"webauthn.create"`),
		"crossorigin true":           with(`"crossorigin":true`),
		"Challenge naming another":   with(`"Challenge":"AAAA"`),
		"TopOrigin present":          with(`"TopOrigin":"https://evil.example"`),
		// encoding/json also folds U+017F (long s) to "s".
		"crossOrigin with a long s": with("\"cro\u017fsOrigin\":true"),
		"long s escaped in JSON":    with(`"cro\u017fsOrigin":true`),
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := validAssertion(t)
			c.rawClient = raw

			_, err := verifyAssertion(c.build(t), c.stored(t), testRP())
			if !errors.Is(err, ErrClientData) {
				t.Errorf("err = %v, want it to wrap %v: a case variant of a checked member was accepted", err, ErrClientData)
			}
		})
	}
}

// TestVerifyAssertionBindingIsByLookup pins what the signature does not cover:
// the credential id and the user handle. Neither is signed (section 6.3.3 signs
// authenticator data and the client data hash only), so the verifier proves
// "this response was signed by the key stored for the row the caller looked
// up", and the user handle check is a consistency check against that row, not
// a proof. The same signed bytes verify under any credential id and handle the
// caller pairs with that key.
func TestVerifyAssertionBindingIsByLookup(t *testing.T) {
	t.Parallel()

	c := validAssertion(t)
	signed := c.build(t)

	relabelled := signed
	relabelled.ID = base64.RawURLEncoding.EncodeToString([]byte("another-credential-id"))
	relabelled.RawID = relabelled.ID
	relabelled.UserHandle = base64.RawURLEncoding.EncodeToString([]byte("another-account"))

	stored := c.stored(t)
	stored.UserHandle = []byte("another-account")

	got, err := verifyAssertion(relabelled, stored, testRP())
	if err != nil {
		t.Fatalf("verifyAssertion: %v", err)
	}

	if string(got.CredentialID) != "another-credential-id" {
		t.Errorf("credential id = %q", got.CredentialID)
	}
}
