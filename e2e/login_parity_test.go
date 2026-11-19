//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it, and a test that walks one scenario step by step reads best as one function
package e2e_test

// login_parity_test.go sends the Worker the login inputs a security review
// compared against github.com/go-webauthn/webauthn and the Go standard library.
// The host tests cover the same cases under Go; these prove the TinyGo build
// agrees, because the ES256 check (crypto/ecdsa and its ASN.1 parsing), the JSON
// readers and base64 all run as TinyGo compiled them, and TinyGo's reflect and
// encoding/json are where a parser difference would hide.
//
// REVIEW.md categories covered: input edge cases (one DER spelling of a
// signature; each clientDataJSON member and authenticator-data byte), type and
// bound confusion (scalars at 0, n, n+s; padded base64; case variants of
// members) and permission confusion (login CSRF from another site).
//
// Every refusal must be the one 401 invalid_login answer (or the documented 400
// for a malformed body) and must write nothing.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

// lgDER is an ECDSA signature's two integers.
type lgDER struct {
	R, S *big.Int
}

// lgSplit parses a signature the test itself just signed. A failure is a bug in
// the test, so it panics rather than threading a *testing.T through every
// table row.
func lgSplit(der []byte) lgDER {
	var sig lgDER

	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 {
		panic(fmt.Sprintf("parse signature: %v (%d bytes left)", err, len(rest)))
	}

	return sig
}

// lgJoin encodes r and s as a DER signature, without any validation.
func lgJoin(r, s *big.Int) []byte {
	out, err := asn1.Marshal(lgDER{R: r, S: s})
	if err != nil {
		panic(fmt.Sprintf("marshal signature: %v", err))
	}

	return out
}

// lgMalleate returns the high-S spelling (r, n-s) of a signature: a different
// valid signature of the same message.
func lgMalleate(der []byte) []byte {
	sig := lgSplit(der)

	return lgJoin(sig.R, new(big.Int).Sub(elliptic.P256().Params().N, sig.S))
}

// lgFixedLength returns a sequence of two minimal INTEGERs whose encodings are
// short-form, so the edits below can index the bytes. A P-256 signature is at
// most 72 bytes, so DER lengths are always short-form.
func lgSeq(body []byte) []byte {
	return append([]byte{0x30, lgLen(len(body))}, body...)
}

func lgInt(raw []byte) []byte {
	return append([]byte{0x02, lgLen(len(raw))}, raw...)
}

// lgLen is a DER short-form length. Every test signature is under 128 bytes.
func lgLen(n int) byte {
	if n < 0 || n > 127 {
		panic(fmt.Sprintf("DER length %d is not short-form", n))
	}

	return byte(n)
}

// lgRawInts splits a DER signature into the content bytes of r and s.
func lgRawInts(der []byte) ([]byte, []byte) {
	rLen := int(der[3])
	sLen := int(der[5+rLen])

	return bytes.Clone(der[4 : 4+rLen]), bytes.Clone(der[6+rLen : 6+rLen+sLen])
}

// lgSignParts signs authData and client with pk's key: the signature a
// genuine authenticator would produce for exactly those bytes.
func lgSignParts(t *testing.T, pk passkey, authData, client []byte) signedLogin {
	t.Helper()

	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))

	sig, err := ecdsa.SignASN1(rand.Reader, pk.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signedLogin{pk: pk, client: client, authData: authData, sig: sig}
}

// TestLoginSignatureSpellings holds that the ES256 verifier, as TinyGo built
// it, accepts exactly one DER spelling of a signature, refuses scalars outside
// [1, n-1], and that the one valid spelling it does accept is not replayable.
//
//nolint:paralleltest // shares one database
func TestLoginSignatureSpellings(t *testing.T) {
	pk := newAdmin(t)
	n := elliptic.P256().Params().N

	one := big.NewInt(1)

	spellings := []struct {
		name string
		edit func(der []byte) []byte
	}{
		{"trailing zero byte", func(der []byte) []byte { return append(bytes.Clone(der), 0) }},
		{"trailing garbage", func(der []byte) []byte { return append(bytes.Clone(der), 0xde, 0xad) }},
		{"a second signature appended", func(der []byte) []byte { return append(bytes.Clone(der), der...) }},
		{"leading zero byte", func(der []byte) []byte { return append([]byte{0}, der...) }},
		{"long-form sequence length", func(der []byte) []byte {
			return append([]byte{0x30, 0x81, der[1]}, der[2:]...)
		}},
		{"long-form sequence length, two bytes", func(der []byte) []byte {
			return append([]byte{0x30, 0x82, 0x00, der[1]}, der[2:]...)
		}},
		{"indefinite sequence length", func(der []byte) []byte {
			return append(append([]byte{0x30, 0x80}, der[2:]...), 0, 0)
		}},
		{"sequence length too short", func(der []byte) []byte {
			out := bytes.Clone(der)
			out[1]--

			return out
		}},
		{"sequence length too long", func(der []byte) []byte {
			out := bytes.Clone(der)
			out[1]++

			return out
		}},
		{"BER-padded r", func(der []byte) []byte {
			r, s := lgRawInts(der)

			return lgSeq(append(lgInt(append([]byte{0x00}, r...)), lgInt(s)...))
		}},
		{"BER-padded s", func(der []byte) []byte {
			r, s := lgRawInts(der)

			return lgSeq(append(lgInt(r), lgInt(append([]byte{0x00}, s...))...))
		}},
		{"BER-padded r and s", func(der []byte) []byte {
			r, s := lgRawInts(der)

			return lgSeq(append(lgInt(append([]byte{0x00}, r...)), lgInt(append([]byte{0x00}, s...))...))
		}},
		{"long-form integer length", func(der []byte) []byte {
			r, s := lgRawInts(der)

			return lgSeq(append([]byte{0x02, 0x81, lgLen(len(r))}, append(r, lgInt(s)...)...))
		}},
		{"wrong sequence tag", func(der []byte) []byte {
			out := bytes.Clone(der)
			out[0] = 0x31 // SET

			return out
		}},
		{"wrong integer tag", func(der []byte) []byte {
			out := bytes.Clone(der)
			out[2] = 0x04 // OCTET STRING

			return out
		}},
		{"empty", func([]byte) []byte { return nil }},
		{"one byte", func([]byte) []byte { return []byte{0x30} }},
		{"empty sequence", func([]byte) []byte { return []byte{0x30, 0x00} }},
		{"only r", func(der []byte) []byte {
			r, _ := lgRawInts(der)

			return lgSeq(lgInt(r))
		}},
		{"three integers", func(der []byte) []byte {
			r, s := lgRawInts(der)

			return lgSeq(append(append(lgInt(r), lgInt(s)...), lgInt([]byte{1})...))
		}},
		{"the r and s swapped", func(der []byte) []byte {
			r, s := lgRawInts(der)

			return lgSeq(append(lgInt(s), lgInt(r)...))
		}},
		{"raw r||s, no DER", func(der []byte) []byte {
			sig := lgSplit(der)

			return append(sig.R.FillBytes(make([]byte, 32)), sig.S.FillBytes(make([]byte, 32))...)
		}},
		{"oversized: 81 bytes", func(der []byte) []byte {
			return append(bytes.Clone(der), make([]byte, 81-len(der))...)
		}},
		{"oversized: 200 bytes", func(der []byte) []byte {
			return append(bytes.Clone(der), make([]byte, 200-len(der))...)
		}},
		{"scalar r = 0", func(der []byte) []byte { return lgJoin(big.NewInt(0), lgSplit(der).S) }},
		{"scalar s = 0", func(der []byte) []byte { return lgJoin(lgSplit(der).R, big.NewInt(0)) }},
		{"scalar r = s = 0", func([]byte) []byte { return lgJoin(big.NewInt(0), big.NewInt(0)) }},
		{"scalar r = n", func(der []byte) []byte { return lgJoin(new(big.Int).Set(n), lgSplit(der).S) }},
		{"scalar s = n", func(der []byte) []byte { return lgJoin(lgSplit(der).R, new(big.Int).Set(n)) }},
		{"scalar s + n", func(der []byte) []byte {
			sig := lgSplit(der)

			return lgJoin(sig.R, new(big.Int).Add(sig.S, n))
		}},
		{"scalar r + n", func(der []byte) []byte {
			sig := lgSplit(der)

			return lgJoin(new(big.Int).Add(sig.R, n), sig.S)
		}},
		{"scalar r = 1, s = 1", func([]byte) []byte { return lgJoin(one, one) }},
		{"scalar r = 2^256", func(der []byte) []byte {
			return lgJoin(new(big.Int).Lsh(one, 256), lgSplit(der).S)
		}},
		{"negative r (no 0x00 pad)", func(der []byte) []byte {
			r, s := lgRawInts(der)

			neg := bytes.Clone(r)
			neg[0] |= 0x80

			if neg[0] == r[0] { // r already had the top bit, with its pad: strip the pad
				neg = r[1:]
			}

			return lgSeq(append(lgInt(neg), lgInt(s)...))
		}},
		{"negative s (no 0x00 pad)", func(der []byte) []byte {
			r, s := lgRawInts(der)

			neg := bytes.Clone(s)
			neg[0] |= 0x80

			if neg[0] == s[0] {
				neg = s[1:]
			}

			return lgSeq(append(lgInt(r), lgInt(neg)...))
		}},
		{"r of 33 bytes of 0xff", func(der []byte) []byte {
			_, s := lgRawInts(der)

			return lgSeq(append(lgInt(bytes.Repeat([]byte{0xff}, 33)), lgInt(s)...))
		}},
		{"s bit flipped", func(der []byte) []byte {
			out := bytes.Clone(der)
			out[len(out)-1] ^= 0x01

			return out
		}},
		{"r bit flipped", func(der []byte) []byte {
			out := bytes.Clone(der)
			out[5] ^= 0x01

			return out
		}},
	}

	for _, tt := range spellings {
		t.Run(tt.name, func(t *testing.T) {
			s := pk.assertion().sign(t, beginLogin(t), nil)

			lgExpectRefused(t, s.withSig(tt.edit(s.sig)).body(t, nil))
		})
	}

	t.Run("control: the canonical DER is accepted", func(t *testing.T) {
		s := pk.assertion().sign(t, beginLogin(t), nil)

		lgExpectAccepted(t, s.body(t, nil))
	})

	t.Run("control: re-encoding the integers canonically is accepted", func(t *testing.T) {
		s := pk.assertion().sign(t, beginLogin(t), nil)
		sig := lgSplit(s.sig)

		lgExpectAccepted(t, s.withSig(lgJoin(sig.R, sig.S)).body(t, nil))
	})
}

// TestLoginSignatureCoversTheBytes holds that the signature covers the
// authenticator data and clientDataJSON exactly as sent: any byte changed after
// signing is refused.
//
//nolint:paralleltest // shares one database
func TestLoginSignatureCoversTheBytes(t *testing.T) {
	pk := newAdmin(t)

	cases := []struct {
		name string
		edit func(s *signedLogin)
	}{
		{"counter changed after signing", func(s *signedLogin) {
			s.authData = bytes.Clone(s.authData)
			s.authData[36] ^= 1
		}},
		{"counter high byte changed", func(s *signedLogin) {
			s.authData = bytes.Clone(s.authData)
			s.authData[33] = 0xff
		}},
		{"flags changed after signing: BE added", func(s *signedLogin) {
			s.authData = bytes.Clone(s.authData)
			s.authData[32] |= 0x08
		}},
		{"flags changed after signing: UV removed", func(s *signedLogin) {
			s.authData = bytes.Clone(s.authData)
			s.authData[32] &^= flagUV
		}},
		{"rpIdHash bit flipped after signing", func(s *signedLogin) {
			s.authData = bytes.Clone(s.authData)
			s.authData[0] ^= 1
		}},
		{"rpIdHash last byte flipped after signing", func(s *signedLogin) {
			s.authData = bytes.Clone(s.authData)
			s.authData[31] ^= 1
		}},
		{"clientDataJSON respaced after signing", func(s *signedLogin) { s.client = append(bytes.Clone(s.client), ' ') }},
		{"clientDataJSON member order changed after signing", func(s *signedLogin) {
			s.client = bytes.Replace(s.client, []byte(`"type":"webauthn.get",`), nil, 1)
			s.client = append([]byte(`{"type":"webauthn.get",`), bytes.TrimPrefix(s.client, []byte("{"))...)
		}},
		{"clientDataJSON with a trailing newline", func(s *signedLogin) { s.client = append(bytes.Clone(s.client), '\n') }},
		{"clientDataJSON with a unicode-escaped letter", func(s *signedLogin) {
			s.client = bytes.Replace(s.client, []byte(`"type"`), []byte(`"typ\u0065"`), 1)
		}},
		{"signature of another message", func(s *signedLogin) {
			other := pk.assertion().sign(t, beginLogin(t), nil)
			s.sig = other.sig
		}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s := pk.assertion().sign(t, beginLogin(t), nil)
			tt.edit(&s)

			lgExpectRefused(t, s.body(t, nil))
		})
	}

	expectCount(t, "sessions", "0")
}

// TestLoginClientDataMembers sends clientDataJSON documents that no browser
// writes but that a looser parser would read differently. The Worker reads the
// document strictly: members matched exactly once, no case folding, and
// crossOrigin and topOrigin refused when set.
//
//nolint:paralleltest // shares one database
func TestLoginClientDataMembers(t *testing.T) {
	pk := newAdmin(t)

	ours := `"origin":"` + target.origin + `"`

	cases := []struct {
		name    string
		members func(challenge string) string // JSON object text
		accept  bool
	}{
		{"control: the browser's serialization", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"crossOrigin":false}`
		}, true},
		{"control: crossOrigin absent", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `}`
		}, true},
		{"control: extra unknown member, as browsers may add", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"androidPackageName":"x"}`
		}, true},
		{"control: member order is free", func(c string) string {
			return `{` + ours + `,"challenge":"` + c + `","type":"webauthn.get"}`
		}, true},
		{"control: whitespace inside the document", func(c string) string {
			return ` { "type" : "webauthn.get" , "challenge" : "` + c + `" , ` + ours + ` } `
		}, true},

		{"origin repeated, evil first", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"https://evil.example",` + ours + `}`
		}, false},
		{"origin repeated, ours first", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"origin":"https://evil.example"}`
		}, false},
		{"origin repeated identically", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,` + ours + `}`
		}, false},
		{"type repeated", func(c string) string {
			return `{"type":"webauthn.create","type":"webauthn.get","challenge":"` + c + `",` + ours + `}`
		}, false},
		{"challenge repeated", func(c string) string {
			return `{"type":"webauthn.get","challenge":"AAAA","challenge":"` + c + `",` + ours + `}`
		}, false},
		{"ORIGIN naming another site beside ours", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"ORIGIN":"https://evil.example"}`
		}, false},
		{"Origin in another case beside ours", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"Origin":"` + target.origin + `"}`
		}, false},
		{"only ORIGIN, none of ours", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","ORIGIN":"` + target.origin + `"}`
		}, false},
		{"Type in another case", func(c string) string {
			return `{"type":"webauthn.get","Type":"webauthn.create","challenge":"` + c + `",` + ours + `}`
		}, false},
		{"CHALLENGE in another case", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","CHALLENGE":"AAAA",` + ours + `}`
		}, false},
		{"crossorigin in lower case", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"crossorigin":true}`
		}, false},
		{"topOrigin present", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"topOrigin":"` + target.origin + `"}`
		}, false},
		{"topOrigin empty", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"topOrigin":""}`
		}, false},
		{"topOrigin null", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"topOrigin":null}`
		}, false},
		{"crossOrigin null", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"crossOrigin":null}`
		}, false},
		{"crossOrigin true", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"crossOrigin":true}`
		}, false},
		{"crossOrigin as a string", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"crossOrigin":"false"}`
		}, false},
		{"crossOrigin as 0", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"crossOrigin":0}`
		}, false},
		{"origin in upper case", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"` + strings.ToUpper(target.origin) + `"}`
		}, false},
		{"origin with a path", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"` + target.origin + `/evil"}`
		}, false},
		{"origin with a trailing slash", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"` + target.origin + `/"}`
		}, false},
		{"origin with another port", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"http://localhost:3001"}`
		}, false},
		{"origin with the default port spelled out", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"http://localhost:80"}`
		}, false},
		{"origin with userinfo", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"http://x@localhost:3000"}`
		}, false},
		{"origin a prefix of ours", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"http://localhost:300"}`
		}, false},
		{"origin ours with a suffix", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"` + target.origin + `.evil.example"}`
		}, false},
		{"origin escaped to look the same", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":"http:\/\/localhost:3000"}`
		}, true}, // JSON allows \/ and it decodes to the same string: both parsers agree
		{"origin null", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":null}`
		}, false},
		{"origin missing", func(c string) string { return `{"type":"webauthn.get","challenge":"` + c + `"}` }, false},
		{"origin as a number", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `","origin":3000}`
		}, false},
		{"type missing", func(c string) string { return `{"challenge":"` + c + `",` + ours + `}` }, false},
		{"type null", func(c string) string { return `{"type":null,"challenge":"` + c + `",` + ours + `}` }, false},
		{"challenge missing", func(string) string { return `{"type":"webauthn.get",` + ours + `}` }, false},
		{"challenge null", func(string) string { return `{"type":"webauthn.get","challenge":null,` + ours + `}` }, false},
		{"challenge as a number", func(string) string { return `{"type":"webauthn.get","challenge":1,` + ours + `}` }, false},
		{"challenge padded", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `=",` + ours + `}`
		}, false},
		{"challenge in standard base64", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + strings.NewReplacer("-", "+", "_", "/").Replace(c) + `==",` + ours + `}`
		}, false},
		{"challenge as an array", func(c string) string {
			return `{"type":"webauthn.get","challenge":["` + c + `"],` + ours + `}`
		}, false},
		{"not an object: array", func(string) string { return `[]` }, false},
		{"not an object: string", func(string) string { return `"x"` }, false},
		{"not an object: null", func(string) string { return `null` }, false},
		{"empty object", func(string) string { return `{}` }, false},
		{"empty document", func(string) string { return `` }, false},
		{"trailing data after the object", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `}x`
		}, false},
		{"two objects", func(c string) string {
			doc := `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `}`

			return doc + doc
		}, false},
		{"truncated", func(c string) string { return `{"type":"webauthn.get","challenge":"` + c + `",` + ours }, false},
		{"invalid UTF-8 in an unknown member", func(c string) string {
			return `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `,"x":"` + "\xff" + `"}`
		}, true}, // an unknown member is ignored by the strict reader (it is not decoded)
		{"UTF-8 BOM before the document", func(c string) string {
			return "\xef\xbb\xbf" + `{"type":"webauthn.get","challenge":"` + c + `",` + ours + `}`
		}, false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			options := beginLogin(t)
			client := []byte(tt.members(options.PublicKey.Challenge))
			body := pk.assertion().sign(t, options, client).body(t, nil)

			if tt.accept {
				lgExpectAccepted(t, body)

				return
			}

			lgExpectRefused(t, body)
		})
	}

	t.Run("clientDataJSON of 2048 bytes (the bound) with padding members is accepted", func(t *testing.T) {
		options := beginLogin(t)

		head := `{"type":"webauthn.get","challenge":"` + options.PublicKey.Challenge + `",` + ours + `,"x":"`
		client := []byte(head + strings.Repeat("a", 2048-len(head)-2) + `"}`)

		if len(client) != 2048 {
			t.Fatalf("client data is %d bytes, want 2048", len(client))
		}

		lgExpectAccepted(t, pk.assertion().sign(t, options, client).body(t, nil))
	})

	t.Run("clientDataJSON of 2049 bytes is refused", func(t *testing.T) {
		options := beginLogin(t)

		head := `{"type":"webauthn.get","challenge":"` + options.PublicKey.Challenge + `",` + ours + `,"x":"`
		client := []byte(head + strings.Repeat("a", 2049-len(head)-2) + `"}`)

		if len(client) != 2049 {
			t.Fatalf("client data is %d bytes, want 2049", len(client))
		}

		lgExpectRefused(t, pk.assertion().sign(t, options, client).body(t, nil))
	})
}

// TestLoginAuthenticatorData sends authenticator data of every wrong shape,
// correctly signed, so only the shape is what is wrong.
//
//nolint:paralleltest // shares one database
func TestLoginAuthenticatorData(t *testing.T) {
	pk := newAdmin(t)

	cases := []struct {
		name string
		edit func(authData []byte) []byte
	}{
		{"36 bytes", func(a []byte) []byte { return a[:36] }},
		{"38 bytes", func(a []byte) []byte { return append(bytes.Clone(a), 0) }},
		{"empty", func([]byte) []byte { return nil }},
		{"32 bytes (hash only)", func(a []byte) []byte { return a[:32] }},
		{"ED set and an extension map appended", func(a []byte) []byte {
			out := bytes.Clone(a)
			out[32] |= 0x80

			return append(out, 0xa0) // an empty CBOR map
		}},
		{"ED set with nothing appended", func(a []byte) []byte {
			out := bytes.Clone(a)
			out[32] |= 0x80

			return out
		}},
		{"AT set with nothing appended", func(a []byte) []byte {
			out := bytes.Clone(a)
			out[32] |= flagAT

			return out
		}},
		{"AT set and attested data appended", func(a []byte) []byte {
			out := bytes.Clone(a)
			out[32] |= flagAT

			return append(out, make([]byte, 16+2+32+77)...)
		}},
		{"rpIdHash of another site", func(a []byte) []byte {
			out := bytes.Clone(a)
			copy(out, sha256sum([]byte("evil.example")))

			return out
		}},
		{"rpIdHash all zero", func(a []byte) []byte {
			out := bytes.Clone(a)
			clear(out[:32])

			return out
		}},
		{"rpIdHash of the origin instead of the id", func(a []byte) []byte {
			out := bytes.Clone(a)
			copy(out, sha256sum([]byte(target.origin)))

			return out
		}},
		{"rpIdHash of the id with a trailing dot", func(a []byte) []byte {
			out := bytes.Clone(a)
			copy(out, sha256sum([]byte(rpID+".")))

			return out
		}},
		{"reserved bit 1", func(a []byte) []byte { out := bytes.Clone(a); out[32] |= 0x02; return out }},
		{"reserved bit 5", func(a []byte) []byte { out := bytes.Clone(a); out[32] |= 0x20; return out }},
		{"BS without BE", func(a []byte) []byte { out := bytes.Clone(a); out[32] |= 0x10; return out }},
		{"BE where registration stored none", func(a []byte) []byte { out := bytes.Clone(a); out[32] |= 0x08; return out }},
		{"UP cleared", func(a []byte) []byte { out := bytes.Clone(a); out[32] &^= flagUP; return out }},
		{"UV cleared", func(a []byte) []byte { out := bytes.Clone(a); out[32] &^= flagUV; return out }},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			options := beginLogin(t)
			s := pk.assertion().sign(t, options, nil)

			// Re-sign over the edited authenticator data with the right key, so
			// the signature is valid for what is sent: the shape alone is wrong.
			s.authData = tt.edit(s.authData)
			s = lgResign(t, pk, s)

			lgExpectRefused(t, s.body(t, nil))
		})
	}

	t.Run("a non-zero counter is read and ignored", func(t *testing.T) {
		s := pk.assertion().sign(t, beginLogin(t), nil)
		s.authData = bytes.Clone(s.authData)
		s.authData[36] = 0x2a

		lgExpectAccepted(t, lgResign(t, pk, s).body(t, nil))
	})

	t.Run("a counter that goes backwards is not a clone alarm", func(t *testing.T) {
		high := pk.assertion().sign(t, beginLogin(t), nil)
		high.authData = bytes.Clone(high.authData)
		high.authData[33] = 0x01

		lgExpectAccepted(t, lgResign(t, pk, high).body(t, nil))

		low := pk.assertion().sign(t, beginLogin(t), nil)
		lgExpectAccepted(t, low.body(t, nil))
	})
}

// lgResign signs s's current authenticator data and client data with the
// passkey's key, so an edit of either is covered by a valid signature.
func lgResign(t *testing.T, pk passkey, s signedLogin) signedLogin {
	t.Helper()

	return lgSignParts(t, pk, s.authData, s.client)
}

// TestLoginBodySpellings sends the finish body's base64 members and names in
// the spellings a looser decoder accepts.
//
//nolint:paralleltest // shares one database
func TestLoginBodySpellings(t *testing.T) {
	pk := newAdmin(t)

	id := b64(pk.credID)
	handle := b64(pk.handle)

	// Text edits of an honest body that keep it valid JSON and the same shape.
	cases := []struct {
		name     string
		old, new func(s signedLogin) string
		status   int
		code     string
	}{
		{
			"rawId padded",
			func(signedLogin) string { return `"rawId":"` + id + `"` },
			func(signedLogin) string { return `"rawId":"` + id + `="` },
			http.StatusUnauthorized, codeInvalidLogin,
		},
		{
			"id padded",
			func(signedLogin) string { return `"id":"` + id + `"` },
			func(signedLogin) string { return `"id":"` + id + `="` },
			http.StatusUnauthorized, codeInvalidLogin,
		},
		{
			"userHandle padded",
			func(signedLogin) string { return `"userHandle":"` + handle + `"` },
			func(signedLogin) string { return `"userHandle":"` + handle + `="` },
			http.StatusUnauthorized, codeInvalidLogin,
		},
		{
			"id and rawId differ",
			func(signedLogin) string { return `"id":"` + id + `"` },
			func(signedLogin) string { return `"id":"` + b64(randomBytes(32)) + `"` },
			http.StatusUnauthorized, codeInvalidLogin,
		},
		{
			"id is the standard base64 spelling of a credential id with + or /",
			func(signedLogin) string { return `"id":"` + id + `"` },
			func(signedLogin) string { return `"id":"` + base64.StdEncoding.EncodeToString(pk.credID) + `"` },
			http.StatusUnauthorized, codeInvalidLogin,
		},
		{
			"id empty",
			func(signedLogin) string { return `"id":"` + id + `"` },
			func(signedLogin) string { return `"id":""` },
			http.StatusUnauthorized, codeInvalidLogin,
		},
		{
			"userHandle empty string",
			func(signedLogin) string { return `"userHandle":"` + handle + `"` },
			func(signedLogin) string { return `"userHandle":""` },
			http.StatusUnauthorized, codeInvalidLogin,
		},
		{
			"userHandle is the standard base64 spelling",
			func(signedLogin) string { return `"userHandle":"` + handle + `"` },
			func(signedLogin) string { return `"userHandle":"` + handle + `/"` },
			http.StatusUnauthorized, codeInvalidLogin,
		},
		{
			"response member in another case",
			func(signedLogin) string { return `"signature"` },
			func(signedLogin) string { return `"Signature"` },
			http.StatusBadRequest, codeUnknownField,
		},
		{
			"authenticatorData in another case",
			func(signedLogin) string { return `"authenticatorData"` },
			func(signedLogin) string { return `"AuthenticatorData"` },
			http.StatusBadRequest, codeUnknownField,
		},
		{
			"rawId in another case",
			func(signedLogin) string { return `"rawId"` },
			func(signedLogin) string { return `"rawid"` },
			http.StatusBadRequest, codeUnknownField,
		},
		{
			"control: id written with a unicode escape of a letter in its VALUE",
			func(signedLogin) string { return `"type":"public-key"` },
			func(signedLogin) string { return `"type":"public\u002dkey"` },
			http.StatusOK, "",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s := pk.assertion().sign(t, beginLogin(t), nil)
			honest := string(s.body(t, nil))

			if !strings.Contains(honest, tt.old(s)) {
				t.Fatalf("honest body lacks %s: %s", tt.old(s), honest)
			}

			body := strings.Replace(honest, tt.old(s), tt.new(s), 1)

			before := lgSnapshot(t)
			got := post(t, pathLoginEnd, []byte(body), "")
			got.expect(t, "finish", tt.status, tt.code)

			if tt.status == http.StatusOK {
				if got.session() == "" {
					t.Error("an accepted login set no cookie")
				}

				return
			}

			if len(got.setCookies) != 0 {
				t.Errorf("set cookies %q", got.setCookies)
			}

			if after := lgSnapshot(t); after != before {
				t.Errorf("the database changed: %+v -> %+v", before, after)
			}
		})
	}
}

// ---- login CSRF -----------------------------------------------------------

// TestLoginRefusesACrossSiteFormPost covers login CSRF. The login challenge is
// not bound to the browser that asked for it, so an attacker can fetch one from
// the open begin, sign it with their own passkey, and have a page on any site
// post the finish body. An HTML form with enctype="text/plain" needs no CORS
// preflight: it writes name=value, and the "=" can land inside
// authenticatorAttachment, the one member that holds free text, so the body is
// valid JSON. It is a top-level navigation, so the browser stores the session
// cookie the response sets (SameSite=Lax limits sending a cookie, not storing
// one), and the victim is signed in as the attacker.
//
// finish must refuse it: the request is not application/json, which a
// same-origin frontend always sends and a cross-site form cannot.
//
//nolint:paralleltest // shares one database
func TestLoginRefusesACrossSiteFormPost(t *testing.T) {
	attacker := newAdmin(t)

	// What the attacker's page writes into its form, after fetching a challenge
	// itself and signing it with its own key.
	json := attacker.assertion().sign(t, beginLogin(t), nil).body(t, map[string]any{"authenticatorAttachment": "x=y"})

	name, value, found := strings.Cut(string(json), "=")
	if !found || strings.Count(string(json), "=") != 1 {
		t.Fatalf("the body is not one text/plain name=value pair: %s", json)
	}

	// text/plain form encoding: name=value CRLF, nothing escaped.
	posted := []byte(name + "=" + value + "\r\n")

	crossSite := map[string]string{
		"Origin":         "https://evil.example",
		"Sec-Fetch-Site": "cross-site",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
	}

	forms := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{"text/plain form", "text/plain", posted},
		{"text/plain with a charset", "text/plain;charset=UTF-8", posted},
		{"urlencoded form", "application/x-www-form-urlencoded", posted},
		{"multipart form", "multipart/form-data; boundary=x", posted},
		{"no content type", "-", posted},
		{"text/plain carrying the honest JSON", "text/plain", json},
		{"application/json with another parameter", "application/json; boundary=x", json},
		{"application/jsonx", "application/jsonx", json},
		{"application/json twice", "application/json, application/json", json},
		{"application/x-www-form-urlencoded; application/json", "application/x-www-form-urlencoded; application/json", json},
	}

	for _, tt := range forms {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{"Content-Type": tt.contentType}
			maps.Copy(headers, crossSite)

			if tt.contentType == "-" {
				headers["Content-Type"] = ""
			}

			got := send(t, request{method: http.MethodPost, path: pathLoginEnd, body: tt.body, headers: headers, noType: tt.contentType == "-"})

			if got.status != http.StatusUnsupportedMediaType || got.errorCode() != codeUnsupportedType {
				t.Errorf("cross-site %s finish = %d %s, want 415 %s: a cross-site form must not reach the handler",
					tt.name, got.status, got.body, codeUnsupportedType)
			}

			if len(got.setCookies) != 0 {
				t.Errorf("cross-site form was given cookies %q", got.setCookies)
			}

			// The Worker allows no other origin: no CORS header, so a browser
			// refuses to expose the response to the attacker's script either.
			if got.header.Get("Access-Control-Allow-Origin") != "" || got.header.Get("Access-Control-Allow-Credentials") != "" {
				t.Errorf("CORS headers for an evil origin: %v", got.header)
			}

			expectCount(t, "sessions", "0")
		})
	}

	// A JSON request from another origin would need a preflight, which fails.
	t.Run("preflight from another origin is not answered", func(t *testing.T) {
		for _, origin := range []string{
			"https://evil.example", "null", "*", target.origin + ".evil.example", target.origin + "/", "http://localhost:3001",
			strings.ToUpper(target.origin), "https://localhost:3000", "",
		} {
			got := send(t, request{
				method: http.MethodOptions, path: pathLoginEnd,
				headers: map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"},
			})

			if got.status == http.StatusNoContent || got.header.Get("Access-Control-Allow-Origin") != "" ||
				got.header.Get("Access-Control-Allow-Methods") != "" || got.header.Get("Access-Control-Allow-Credentials") != "" {
				t.Errorf("preflight from %q = %d %v, want no CORS grant", origin, got.status, got.header)
			}
		}
	})

	// A JSON post that names an evil Origin cannot be sent by a browser without
	// a preflight that fails, so the Worker has nothing to refuse here: a
	// non-browser client may send it, and it is a login of the attacker's own
	// passkey. What the Worker must never do is grant CORS to the evil origin,
	// which would let the attacker's script read the response.
	t.Run("a JSON post that names an evil origin is not granted CORS", func(t *testing.T) {
		got := send(t, request{
			method: http.MethodPost, path: pathLoginEnd,
			body:    attacker.assertion().sign(t, beginLogin(t), nil).body(t, nil),
			headers: map[string]string{"Origin": "https://evil.example"},
		})

		if got.header.Get("Access-Control-Allow-Origin") != "" || got.header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("CORS headers granted to an evil origin: %v", got.header)
		}

		if got.header.Get("Vary") != "Origin" {
			t.Errorf("Vary = %q, want Origin so a shared cache never serves one origin's answer to another", got.header.Get("Vary"))
		}
	})

	// The one origin that is allowed (the UI) is granted, with credentials: the
	// legitimate flow's CORS still works, so the refusals above are not an
	// artefact of CORS being off.
	t.Run("the UI origin is allowed and its preflight answered", func(t *testing.T) {
		got := send(t, request{
			method: http.MethodOptions, path: pathLoginEnd,
			headers: map[string]string{
				"Origin": target.origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type",
			},
		})

		if got.status != http.StatusNoContent || got.header.Get("Access-Control-Allow-Origin") != target.origin ||
			got.header.Get("Access-Control-Allow-Credentials") != "true" {
			t.Errorf("UI preflight = %d %v, want 204 with the UI origin and credentials", got.status, got.header)
		}

		login := send(t, request{
			method: http.MethodPost, path: pathLoginEnd,
			body:    attacker.assertion().sign(t, beginLogin(t), nil).body(t, nil),
			headers: map[string]string{"Origin": target.origin},
		})

		if login.status != http.StatusOK || login.header.Get("Access-Control-Allow-Origin") != target.origin {
			t.Errorf("login from the UI origin = %d %v", login.status, login.header)
		}
	})

	// Nothing a form posted created a session: the only ones are the two
	// logins above that were genuine JSON requests (one naming an evil Origin
	// and no CORS grant, one from the UI).
	t.Run("nothing was signed in by a form", func(t *testing.T) {
		expectCount(t, "sessions", "2")
	})
}
