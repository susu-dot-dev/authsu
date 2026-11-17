package webauthn

import (
	"bytes"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

// This file pins how the parsers treat input that different WebAuthn
// implementations read differently: letter case, repeated names, escapes,
// embedded NULs, invalid UTF-8, alternative base64 and non-canonical CBOR. It
// came out of a review against github.com/go-webauthn/webauthn; each case notes
// where that library differs, because a difference is where a bypass would
// live if this package ever shared input with another parser.

// clientDataWith returns clientDataJSON with the given members, in order, as
// raw JSON text. Raw text is needed for what a Go map cannot express: repeated
// names, escapes, invalid UTF-8.
func clientDataWith(members ...string) []byte {
	return []byte("{" + strings.Join(members, ",") + "}")
}

const (
	typeMember   = `"type":"webauthn.create"`
	originMember = `"origin":"` + testOrigin + `"`
)

// challengeMember is the challenge member validResponse echoes.
func challengeMember() string {
	return `"challenge":"` + base64.RawURLEncoding.EncodeToString([]byte(testChalText)) + `"`
}

func withRawClient(raw []byte) func(*response) {
	return func(r *response) { r.rawClient = raw }
}

// concat joins byte strings, for CBOR written by hand.
func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// TestVerifyRejectsAmbiguousClientData covers clientDataJSON that means one
// thing to a lenient parser and another to a strict one. go-webauthn decodes
// with plain encoding/json, so it matches names case-insensitively, keeps the
// last of a repeated name, and compares origins by parsed scheme and host only.
// Every one of these it accepts; we must not.
func TestVerifyRejectsAmbiguousClientData(t *testing.T) {
	t.Parallel()

	raw := func(members ...string) func(*response) { return withRawClient(clientDataWith(members...)) }
	plus := func(extra string) func(*response) { return raw(typeMember, challengeMember(), originMember, extra) }
	challengeIs := func(value string) func(*response) { return raw(typeMember, `"challenge":`+value, originMember) }

	runRejections(t, map[string]rejection{
		// go-webauthn keeps the last value, so a proxy that checks the first
		// origin and a verifier that uses the last disagree.
		"origin repeated, evil first": {
			mutate:  raw(typeMember, challengeMember(), `"origin":"https://evil.example"`, originMember),
			wantErr: ErrClientData,
		},
		"origin name in upper case": {
			mutate: raw(typeMember, challengeMember(), `"ORIGIN":"`+testOrigin+`"`), wantErr: ErrClientData,
		},
		// encoding/json folds case and keeps the last match, so it would read
		// the evil origin here; a strict reader alone would read ours.
		"ORIGIN beside origin": {
			mutate:  raw(typeMember, challengeMember(), originMember, `"ORIGIN":"https://evil.example"`),
			wantErr: ErrClientData,
		},
		// The decoder unescapes names before the duplicate check, so an escaped
		// spelling of a name is still the same name.
		"type repeated through an escape": {
			mutate:  raw(typeMember, `"\u0074ype":"webauthn.get"`, challengeMember(), originMember),
			wantErr: ErrClientData,
		},
		"type with an escaped NUL": {
			mutate: raw(`"type":"webauthn.create\u0000"`, challengeMember(), originMember), wantErr: ErrClientData,
		},
		// go-webauthn only looks at topOrigin when it is non-empty.
		"topOrigin empty": {mutate: plus(`"topOrigin":""`), wantErr: ErrClientData},
		"topOrigin null":  {mutate: plus(`"topOrigin":null`), wantErr: ErrClientData},
		// crossOrigin is a boolean (section 5.8.1). null is not a boolean,
		// and encoding/json would silently read it as false.
		"crossOrigin null":     {mutate: plus(`"crossOrigin":null`), wantErr: ErrClientData},
		"crossOrigin a number": {mutate: plus(`"crossOrigin":0`), wantErr: ErrClientData},
		// A deliberate deviation: section 7.1 step 5 strips a leading BOM, but
		// no conforming client writes one, so it is refused.
		"byte order mark": {
			mutate: withRawClient(concat([]byte("\xef\xbb\xbf"),
				clientDataWith(typeMember, challengeMember(), originMember))),
			wantErr: ErrClientData,
		},
		"challenge padded":                   {mutate: challengeIs(`"AAA="`), wantErr: ErrClientData},
		"challenge in the standard alphabet": {mutate: challengeIs(`"AA+/"`), wantErr: ErrClientData},
		"challenge is a number":              {mutate: challengeIs(`1`), wantErr: ErrClientData},
		"challenge is null":                  {mutate: challengeIs(`null`), wantErr: ErrClientData},
	})
}

// TestVerifyRejectsOriginsNotAsSerialized covers origins that name our host
// under a looser reading. go-webauthn compares scheme and host only, so it
// accepts the path, userinfo, case and port variants. A serialized origin
// (RFC 6454) has no path, no userinfo, a lower-case host and no default port,
// so none of these was written by a browser.
func TestVerifyRejectsOriginsNotAsSerialized(t *testing.T) {
	t.Parallel()

	origin := func(value string) rejection {
		return rejection{
			mutate:  withRawClient(clientDataWith(typeMember, challengeMember(), `"origin":"`+value+`"`)),
			edit:    nil,
			wantErr: ErrClientData,
		}
	}

	runRejections(t, map[string]rejection{
		"with a path":            origin(testOrigin + "/path"),
		"with userinfo":          origin("https://evil@auth.example.com"),
		"host in upper case":     origin("https://AUTH.EXAMPLE.COM"),
		"with the default port":  origin(testOrigin + ":443"),
		"over http":              origin("http://auth.example.com"),
		"with an escaped NUL":    origin(testOrigin + `\u0000`),
		"with a raw NUL":         origin(testOrigin + "\x00"),
		"with invalid UTF-8":     origin(testOrigin + "\xff"),
		"with a lone surrogate":  origin(testOrigin + `\ud800`),
		"with a homoglyph host":  origin("https://\u0430uth.example.com"),
		"with a trailing space":  origin(testOrigin + " "),
		"with a trailing escape": origin(testOrigin + `\/`),
	})
}

// TestVerifyRejectsAmbiguousAttestation covers CBOR type confusion and
// embedded NULs in the attestation object.
func TestVerifyRejectsAmbiguousAttestation(t *testing.T) {
	t.Parallel()

	base := validResponse(t)
	authData := base.authData(t)

	object := func(members map[any]any) func(*response) {
		return func(r *response) { r.rawAttObject = mustCBOR(t, members) }
	}

	runRejections(t, map[string]rejection{
		"fmt as a byte string": {
			mutate: object(map[any]any{
				memberFmt: []byte(noneFormat), memberAttStmt: map[string]any{}, memberAuthData: authData,
			}),
			wantErr: ErrAttestation,
		},
		"authData as a text string": {
			mutate: object(map[any]any{
				memberFmt: noneFormat, memberAttStmt: map[string]any{}, memberAuthData: string(authData),
			}),
			wantErr: ErrAttestation,
		},
		"attStmt as an array": {
			mutate:  object(map[any]any{memberFmt: noneFormat, memberAttStmt: []any{}, memberAuthData: authData}),
			wantErr: ErrAttestation,
		},
		"an integer member": {
			mutate:  object(map[any]any{memberFmt: noneFormat, memberAttStmt: map[string]any{}, memberAuthData: authData, 1: 1}),
			wantErr: ErrAttestation,
		},
		// The struct field is matched before the duplicate check, so a
		// case-folded second spelling is caught as a repeat of the first.
		"fmt and FMT": {
			mutate: object(map[any]any{
				memberFmt: noneFormat, "FMT": "packed", memberAttStmt: map[string]any{}, memberAuthData: authData,
			}),
			wantErr: ErrAttestation,
		},
		"fmt with a NUL":   {mutate: func(r *response) { r.format = noneFormat + "\x00" }, wantErr: ErrAttestation},
		"fmt in uppercase": {mutate: func(r *response) { r.format = "NONE" }, wantErr: ErrAttestation},
		"fmt with invalid UTF-8": {
			mutate: func(r *response) {
				// A text string "non\xff" written by hand: the encoder refuses it.
				r.rawAttObject = concat([]byte{0xa3},
					mustCBOR(t, memberFmt), []byte{0x64, 'n', 'o', 'n', 0xff},
					mustCBOR(t, memberAttStmt), []byte{0xa0},
					mustCBOR(t, memberAuthData), mustCBOR(t, authData))
			},
			wantErr: ErrAttestation,
		},
	})
}

// p256Prime is the field prime of P-256.
func p256Prime(tb testing.TB) *big.Int {
	tb.Helper()

	p, ok := new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	if !ok {
		tb.Fatal("parse p")
	}

	return p
}

// smallXPoint returns the P-256 point with the smallest positive x. Its x is
// tiny, so x+p still fits in 32 bytes: the same field element, encoded
// non-canonically.
func smallXPoint(tb testing.TB) (*big.Int, *big.Int) {
	tb.Helper()

	p := p256Prime(tb)

	b, ok := new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	if !ok {
		tb.Fatal("parse b")
	}

	const searchLimit = 100

	for i := int64(1); i < searchLimit; i++ {
		x := big.NewInt(i)
		// y² = x³ - 3x + b
		rhs := new(big.Int).Exp(x, big.NewInt(3), p)
		rhs.Sub(rhs, new(big.Int).Mul(big.NewInt(3), x))
		rhs.Add(rhs, b)
		rhs.Mod(rhs, p)

		if y := new(big.Int).ModSqrt(rhs, p); y != nil {
			return x, y
		}
	}

	tb.Fatal("no small-x point")

	return nil, nil
}

func coord(v *big.Int) []byte { return v.FillBytes(make([]byte, coordinateLen)) }

// TestPublicKeyRejectsAmbiguousKeys covers keys that are numerically valid
// under one reading and not another, and parameters go-webauthn keeps.
func TestPublicKeyRejectsAmbiguousKeys(t *testing.T) {
	t.Parallel()

	x, y := smallXPoint(t)
	nonCanonicalX := new(big.Int).Add(x, p256Prime(t))
	valid := validKey(t)
	validX, _ := valid[-2].([]byte)

	withKey := func(edit func(coseMap)) func(*response) {
		return func(r *response) { r.key = keyWith(t, edit) }
	}

	runRejections(t, map[string]rejection{
		// x+p reduces to a point on the curve, so a parser that reduced
		// coordinates mod p would accept it and store a different encoding of
		// the same key. crypto/ecdh refuses a coordinate that is not reduced.
		"x not reduced mod p": {
			mutate:  withKey(func(k coseMap) { k[-2], k[-3] = coord(nonCanonicalX), coord(y) }),
			wantErr: ErrPublicKey,
		},
		"x with a leading zero byte": {
			mutate:  withKey(func(k coseMap) { k[-2] = append([]byte{0}, validX...) }),
			wantErr: ErrPublicKey,
		},
		"the point at infinity": {
			mutate:  withKey(func(k coseMap) { k[-2], k[-3] = make([]byte, coordinateLen), make([]byte, coordinateLen) }),
			wantErr: ErrPublicKey,
		},
		"curve P-384":           {mutate: withKey(func(k coseMap) { k[-1] = 2 }), wantErr: ErrPublicKey},
		"algorithm ESP256 (-9)": {mutate: withKey(func(k coseMap) { k[3] = -9 }), wantErr: ErrPublicKey},
		"key type OKP":          {mutate: withKey(func(k coseMap) { k[1] = 1 }), wantErr: ErrPublicKey},
		// go-webauthn keeps every parameter it does not understand in the key
		// it stores, including a private key. We refuse them.
		"kid present": {mutate: withKey(func(k coseMap) { k[2] = []byte("kid") }), wantErr: ErrPublicKey},
	})
}

// TestPublicKeyRejectsMistypedKeys covers COSE keys whose members have the
// wrong CBOR type, or labels that are not integers.
func TestPublicKeyRejectsMistypedKeys(t *testing.T) {
	t.Parallel()

	valid := validKey(t)
	validX, _ := valid[-2].([]byte)

	withKey := func(edit func(coseMap)) func(*response) {
		return func(r *response) { r.key = keyWith(t, edit) }
	}

	runRejections(t, map[string]rejection{
		"key type as a float":   {mutate: withKey(func(k coseMap) { k[1] = 2.0 }), wantErr: ErrPublicKey},
		"key type as a boolean": {mutate: withKey(func(k coseMap) { k[1] = true }), wantErr: ErrPublicKey},
		"x as a text string": {
			mutate:  withKey(func(k coseMap) { k[-2] = string(validX) }),
			wantErr: ErrPublicKey,
		},
		"labels as text": {
			mutate: func(r *response) {
				r.key = mustCBOR(t, map[string]any{"1": 2, "3": -7, "-1": 1, "-2": valid[-2], "-3": valid[-3]})
			},
			wantErr: ErrPublicKey,
		},
		"kty given as both 1 and \"1\"": {
			mutate: func(r *response) {
				r.key = mustCBOR(t, map[any]any{1: 2, "1": 2, 3: -7, -1: 1, -2: valid[-2], -3: valid[-3]})
			},
			wantErr: ErrPublicKey,
		},
		"algorithm below int64": {
			mutate: func(r *response) {
				// {1: 2, 3: -2^64, ...}: a negative integer no int64 holds.
				r.key = concat(
					[]byte{0xa5, 0x01, 0x02, 0x03, 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x01, 0x21},
					mustCBOR(t, valid[-2]), []byte{0x22}, mustCBOR(t, valid[-3]))
			},
			wantErr: ErrPublicKey,
		},
		"x as an array of bytes": {
			// Refused by the collection bound before the type is considered.
			mutate: withKey(func(k coseMap) {
				items := make([]any, 0, len(validX))
				for _, b := range validX {
					items = append(items, b)
				}

				k[-2] = items
			}),
			wantErr: ErrPublicKey,
		},
	})
}

// TestPublicKeyAcceptsTheOtherRoot pins that the second y for an x is a
// distinct, valid key, so validation is a real curve check and not a
// comparison against one expected encoding.
func TestPublicKeyAcceptsTheOtherRoot(t *testing.T) {
	t.Parallel()

	x, y := smallXPoint(t)

	for name, root := range map[string]*big.Int{"y": y, "p-y": new(big.Int).Sub(p256Prime(t), y)} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp := validResponse(t)
			resp.key = coseMap{1: 2, 3: -7, -1: 1, -2: coord(x), -3: coord(root)}

			_, err := Verify(resp.build(t), testRP())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestVerifyRejectsAlternativeBase64 covers base64 spellings other than the
// unpadded URL alphabet that PublicKeyCredential.toJSON() writes. go-webauthn
// strips trailing "=" from rawId and the response members, so it accepts the
// padded ones.
func TestVerifyRejectsAlternativeBase64(t *testing.T) {
	t.Parallel()

	pad := func(s string) string { return s + strings.Repeat("=", (4-len(s)%4)%4) }

	runRejections(t, map[string]rejection{
		"id padded":    {edit: func(reg *Registration) { reg.ID += "=" }, wantErr: ErrAuthData},
		"rawId padded": {edit: func(reg *Registration) { reg.RawID += "=" }, wantErr: ErrAuthData},
		"clientDataJSON padded": {
			edit:    func(reg *Registration) { reg.ClientDataJSON = pad(reg.ClientDataJSON) + "=" },
			wantErr: ErrClientData,
		},
		"attestationObject in the standard alphabet": {
			edit: func(reg *Registration) {
				raw, _ := base64.RawURLEncoding.DecodeString(reg.AttestationObject)
				std := base64.RawStdEncoding.EncodeToString(raw)

				if !strings.ContainsAny(std, "+/") {
					t.Fatal("fixture has no character that differs between the alphabets")
				}

				reg.AttestationObject = std
			},
			wantErr: ErrAttestation,
		},
	})
}

// flipUnusedBit sets the lowest bit of the last character of unpadded
// base64url whose length leaves unused bits (len%4 of 2 or 3). The result
// decodes to the same bytes under a lenient decoder.
func flipUnusedBit(tb testing.TB, encoded string) string {
	tb.Helper()

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	if n := len(encoded) % 4; n != 2 && n != 3 {
		tb.Fatalf("%d characters leave no unused bits", len(encoded))
	}

	last := strings.IndexByte(alphabet, encoded[len(encoded)-1])

	return encoded[:len(encoded)-1] + string(alphabet[last^1])
}

// TestVerifyRejectsNonCanonicalBase64 covers spellings that decode to the
// right bytes but are not the base64url encoding (section 3: no padding, "no
// line breaks, whitespace, or other additional characters"). Section 7.1 step
// 8 compares C.challenge with "the base64url encoding" of the challenge, so
// there is exactly one acceptable spelling of each value. Go's decoder skips CR
// and LF even in Strict mode, and without Strict ignores the unused bits of the
// last character.
func TestVerifyRejectsNonCanonicalBase64(t *testing.T) {
	t.Parallel()

	// 73 bytes, the length of a real challenge, so its encoding (98
	// characters) has unused bits.
	challenge := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("z", 73)))
	withChallenge := func(value string) func(*response) {
		return withRawClient(clientDataWith(typeMember, `"challenge":"`+value+`"`, originMember))
	}

	// 25 bytes, so the credential id's encoding has unused bits too.
	longerID := func(r *response) { r.credID = []byte("credential-id-0123456789!") }
	insert := func(s, extra string) string { return s[:4] + extra + s[4:] }

	runRejections(t, map[string]rejection{
		"challenge with a newline":         {mutate: withChallenge(insert(challenge, `\n`)), wantErr: ErrClientData},
		"challenge with a carriage return": {mutate: withChallenge(insert(challenge, `\r`)), wantErr: ErrClientData},
		"challenge with unused bits set":   {mutate: withChallenge(flipUnusedBit(t, challenge)), wantErr: ErrClientData},
		"clientDataJSON with CR LF": {
			edit:    func(reg *Registration) { reg.ClientDataJSON = insert(reg.ClientDataJSON, "\r\n") },
			wantErr: ErrClientData,
		},
		"attestationObject with a newline": {
			edit:    func(reg *Registration) { reg.AttestationObject = insert(reg.AttestationObject, "\n") },
			wantErr: ErrAttestation,
		},
		"id with a newline":    {edit: func(reg *Registration) { reg.ID = insert(reg.ID, "\n") }, wantErr: ErrAuthData},
		"rawId with a newline": {edit: func(reg *Registration) { reg.RawID = insert(reg.RawID, "\n") }, wantErr: ErrAuthData},
		"id with unused bits set": {
			mutate:  longerID,
			edit:    func(reg *Registration) { reg.ID = flipUnusedBit(t, reg.ID) },
			wantErr: ErrAuthData,
		},
		"rawId with unused bits set": {
			mutate:  longerID,
			edit:    func(reg *Registration) { reg.RawID = flipUnusedBit(t, reg.RawID) },
			wantErr: ErrAuthData,
		},
	})
}

// TestVerifyRejectsCaseFoldedCBORNames covers attestation object members
// spelled in another case. fxamacker/cbor falls back to a case-insensitive
// match against struct fields unless told otherwise; "FMT" is not "fmt", so it
// is an unknown member and must be refused, as strictOptions documents.
// go-webauthn accepts all of these.
func TestVerifyRejectsCaseFoldedCBORNames(t *testing.T) {
	t.Parallel()

	authData := validResponse(t).authData(t)

	object := func(fmtName, stmtName, dataName string) func(*response) {
		return func(r *response) {
			r.rawAttObject = mustCBOR(t, map[string]any{fmtName: noneFormat, stmtName: map[string]any{}, dataName: authData})
		}
	}

	runRejections(t, map[string]rejection{
		"FMT":      {mutate: object("FMT", memberAttStmt, memberAuthData), wantErr: ErrAttestation},
		"ATTSTMT":  {mutate: object(memberFmt, "ATTSTMT", memberAuthData), wantErr: ErrAttestation},
		"AuthData": {mutate: object(memberFmt, memberAttStmt, "AuthData"), wantErr: ErrAttestation},
	})
}

// TestVerifyRejectsNonCanonicalCBOR covers CBOR that decodes to the right
// values but is not in CTAP2 canonical form, which section 2.4 says decoders
// SHOULD reject: map keys out of canonical order, and integers or lengths not
// in their shortest form.
func TestVerifyRejectsNonCanonicalCBOR(t *testing.T) {
	t.Parallel()

	base := validResponse(t)
	authData := base.authData(t)
	key := validKey(t)

	// keyBytes writes {1: kty, 3: -7, -1: 1, -2: x, -3: y} with the given
	// encodings of the label 1 and the kty value, in the given order.
	keyBytes := func(label1, kty []byte, xFirst bool) []byte {
		x := concat([]byte{0x21}, mustCBOR(t, key[-2]))
		y := concat([]byte{0x22}, mustCBOR(t, key[-3]))

		if !xFirst {
			x, y = y, x
		}

		return concat([]byte{0xa5}, label1, kty, []byte{0x03, 0x26, 0x20, 0x01}, x, y)
	}

	// object writes the attestation object members in the given order, with
	// fmt's value encoded as given.
	object := func(fmtValue []byte, order ...string) func(*response) {
		return func(r *response) {
			values := map[string][]byte{
				memberFmt: fmtValue, memberAttStmt: {0xa0}, memberAuthData: mustCBOR(t, authData),
			}

			parts := make([][]byte, 0, 1+2*len(order))
			parts = append(parts, []byte{0xa3})

			for _, name := range order {
				parts = append(parts, mustCBOR(t, name), values[name])
			}

			r.rawAttObject = concat(parts...)
		}
	}

	canonicalFmt := mustCBOR(t, noneFormat)
	longFmt := append([]byte{0x78, 0x04}, noneFormat...) // "none" with a one-byte length prefix

	runRejections(t, map[string]rejection{
		"attestation object members out of order": {
			mutate:  object(canonicalFmt, memberAuthData, memberFmt, memberAttStmt),
			wantErr: ErrAttestation,
		},
		"fmt length not minimal": {
			mutate:  object(longFmt, memberFmt, memberAttStmt, memberAuthData),
			wantErr: ErrAttestation,
		},
		"key label 1 not minimal": {
			mutate:  func(r *response) { r.key = keyBytes([]byte{0x18, 0x01}, []byte{0x02}, true) },
			wantErr: ErrPublicKey,
		},
		"key type value not minimal": {
			mutate:  func(r *response) { r.key = keyBytes([]byte{0x01}, []byte{0x18, 0x02}, true) },
			wantErr: ErrPublicKey,
		},
		"key labels out of order": {
			mutate:  func(r *response) { r.key = keyBytes([]byte{0x01}, []byte{0x02}, false) },
			wantErr: ErrPublicKey,
		},
	})
}

// TestVerifyAcceptsByDesign pins inputs that are accepted on purpose, each
// for the reason given. They are not what a browser writes, but they mean the
// same thing to every JSON parser, or the decision was made to tolerate them.
func TestVerifyAcceptsByDesign(t *testing.T) {
	t.Parallel()

	authData := validResponse(t).authData(t)

	object := func(members map[string]any) func(*response) {
		return func(r *response) { r.rawAttObject = mustCBOR(t, members) }
	}

	tests := map[string]func(*response){
		// clientDataJSON is read as JSON (section 7.1 step 6), and escapes are
		// JSON: they are decoded before any comparison.
		"origin with escaped slashes": withRawClient(clientDataWith(
			typeMember, challengeMember(), `"origin":"https:\/\/auth.example.com"`)),
		"type name escaped": withRawClient(clientDataWith(
			`"\u0074ype":"webauthn.create"`, challengeMember(), originMember)),
		// tokenBinding is reserved in Level 3 and not verified.
		"tokenBinding with an unknown status": withRawClient(clientDataWith(
			typeMember, challengeMember(), originMember, `"tokenBinding":{"status":"bogus"}`)),
		// A missing or null attStmt is read as the empty statement.
		"attStmt missing": object(map[string]any{memberFmt: noneFormat, memberAuthData: authData}),
		"attStmt null":    object(map[string]any{memberFmt: noneFormat, memberAttStmt: nil, memberAuthData: authData}),
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp := validResponse(t)
			mutate(&resp)

			_, err := Verify(resp.build(t), testRP())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}
