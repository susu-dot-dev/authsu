//go:build e2e

//nolint:goconst,funlen,lll,maintidx // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// registration_parity_test.go sends the Worker registration inputs that the
// host unit tests refuse and requires the Worker to refuse them the same way.
//
// The verifier's CBOR, JSON and COSE parsers and its curve check are
// reflection-driven and run under TinyGo in production, but their unit tests run
// under Go. TinyGo compiles the same sources with its own reflect, runtime and
// crypto, so "refused on the host" is not "refused in the Worker" until this
// suite shows it.
//
// Technique: an invitation whose type has no role. A response that passes every
// verifier check, the challenge and the invitation read then fails at the role
// mapping with 500 "internal" and writes nothing. That makes "the verifier
// refused it" (400 invalid_credential) distinguishable from "the verifier
// accepted it" (500) without creating an account, and a control row proves the
// honest response really reaches that step, so a 400 is the parser's and not an
// artefact of the harness.
//
// REVIEW.md categories covered: input edge cases and type/bound confusion at
// the CBOR, JSON and elliptic-curve layers (TinyGo reflection, big integers,
// byte strings versus text strings).

import (
	"crypto/elliptic"
	"encoding/hex"
	"maps"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

const (
	parityCode = "e2e-parity-invitation-0123456789ABCDEFGHIJKLMN"
	parityID   = "00000000-0000-7000-8000-00000000c201"
)

// regParityBegin begins a ceremony for the role-less parity invitation.
func regParityBegin(t *testing.T) creationOptions {
	t.Helper()

	return mustBeginRegistration(t, parityCode, "Parity")
}

// regField is a P-256 coordinate as 32 big-endian bytes.
func regField(v *big.Int) []byte { return v.FillBytes(make([]byte, 32)) }

// regCoseKey is a COSE_Key with the given coordinates and extra members.
func regCoseKey(t *testing.T, x, y []byte, extra map[int64]any) []byte {
	t.Helper()

	key := map[int64]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}
	maps.Copy(key, extra)

	return mustCBOR(t, key)
}

// regSmallXPoint is the P-256 point with the smallest positive x, so that x+p
// still fits in 32 bytes (a coordinate that is congruent to a valid one but not
// reduced).
func regSmallXPoint(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()

	params := elliptic.P256().Params()

	for i := int64(1); i < 100; i++ {
		x := big.NewInt(i)
		rhs := new(big.Int).Exp(x, big.NewInt(3), params.P)
		rhs.Sub(rhs, new(big.Int).Mul(big.NewInt(3), x))
		rhs.Add(rhs, params.B)
		rhs.Mod(rhs, params.P)

		if y := new(big.Int).ModSqrt(rhs, params.P); y != nil {
			return x, y
		}
	}

	t.Fatal("no small-x point")

	return nil, nil
}

// regCBORMap writes a definite-length CBOR map of the given raw encoded items
// (key, value, key, value...) in the order given: the caller controls order,
// repeats and canonical form.
func regCBORMap(items ...[]byte) []byte {
	out := []byte{0xa0 + byte(len(items)/2)}

	for _, item := range items {
		out = append(out, item...)
	}

	return out
}

// regText and regBytes are the canonical CBOR text and byte string items.
func regText(s string) []byte { return regCBOR(s) }

func regBytes(b []byte) []byte { return regCBOR(b) }

// regParityCases are registration responses the verifier must refuse, keyed by
// what is wrong. Each edits an authenticator.
func regParityCases(t *testing.T) []struct {
	name string
	edit func(a *authenticator)
} {
	t.Helper()

	x, y := regSmallXPoint(t)
	p := elliptic.P256().Params().P
	key := newKey(t)
	validX, validY := regField(key.X), regField(key.Y)
	zero := make([]byte, 32)

	object := func(build func(authData []byte) []byte) func(*authenticator) {
		return func(a *authenticator) { a.object = build }
	}

	clientData := func(build func(challenge string) []byte) func(*authenticator) {
		return func(a *authenticator) { a.clientData = build }
	}

	cose := func(raw []byte) func(*authenticator) {
		return func(a *authenticator) { a.cose = raw }
	}

	cases := []struct {
		name string
		edit func(a *authenticator)
	}{
		// ---- the curve: crypto/ecdh compiled by TinyGo ----
		{"point not on the curve", cose(regCoseKey(t, validX, zero, nil))},
		{"point not on the curve (y is x)", cose(regCoseKey(t, validX, validX, nil))},
		{"point at infinity (0, 0)", cose(regCoseKey(t, zero, zero, nil))},
		{"x is 0, y arbitrary", cose(regCoseKey(t, zero, validY, nil))},
		{"y is 0, x arbitrary", cose(regCoseKey(t, validX, zero, nil))},
		{"coordinate not reduced mod p (x+p)", cose(regCoseKey(t, regField(new(big.Int).Add(x, p)), regField(y), nil))},
		{"coordinates equal to p", cose(regCoseKey(t, regField(p), regField(p), nil))},
		{"coordinates all 0xff", cose(regCoseKey(t, repeatByte(0xff, 32), repeatByte(0xff, 32), nil))},
		{"x of 31 bytes", cose(regCoseKey(t, validX[1:], validY, nil))},
		{"y of 31 bytes", cose(regCoseKey(t, validX, validY[1:], nil))},
		{"x of 33 bytes", cose(regCoseKey(t, append([]byte{0}, validX...), validY, nil))},
		{"x and y empty", cose(regCoseKey(t, []byte{}, []byte{}, nil))},
		{"coordinates as text strings", cose(mustCBOR(t, map[int64]any{1: 2, 3: -7, -1: 1, -2: string(validX), -3: string(validY)}))},
		{"coordinates swapped", cose(regCoseKey(t, validY, validX, nil))},

		// ---- the COSE key's other members ----
		{"private key d in the COSE key", cose(regCoseKey(t, validX, validY, map[int64]any{-4: make([]byte, 32)}))},
		{"key_ops in the COSE key", cose(regCoseKey(t, validX, validY, map[int64]any{4: []int{2}}))},
		{"kid in the COSE key", cose(regCoseKey(t, validX, validY, map[int64]any{2: []byte("kid")}))},
		{"base IV in the COSE key", cose(regCoseKey(t, validX, validY, map[int64]any{5: []byte("iv")}))},
		{"a text-labelled member in the COSE key", cose(mustCBOR(t, map[any]any{1: 2, 3: -7, -1: 1, -2: validX, -3: validY, "extra": 1}))},
		{"wrong kty (OKP, 1)", cose(mustCBOR(t, map[int64]any{1: 1, 3: -7, -1: 1, -2: validX, -3: validY}))},
		{"wrong kty (RSA, 3)", cose(mustCBOR(t, map[int64]any{1: 3, 3: -7, -1: 1, -2: validX, -3: validY}))},
		{"kty missing", cose(mustCBOR(t, map[int64]any{3: -7, -1: 1, -2: validX, -3: validY}))},
		{"kty as text", cose(mustCBOR(t, map[int64]any{3: -7, -1: 1, -2: validX, -3: validY, 1: "EC2"}))},
		{"wrong alg (ES384, -35)", cose(mustCBOR(t, map[int64]any{1: 2, 3: -35, -1: 1, -2: validX, -3: validY}))},
		{"wrong alg (RS256, -257)", cose(mustCBOR(t, map[int64]any{1: 2, 3: -257, -1: 1, -2: validX, -3: validY}))},
		{"wrong alg (EdDSA, -8)", cose(mustCBOR(t, map[int64]any{1: 2, 3: -8, -1: 1, -2: validX, -3: validY}))},
		{"alg zero", cose(mustCBOR(t, map[int64]any{1: 2, 3: 0, -1: 1, -2: validX, -3: validY}))},
		{"alg missing", cose(mustCBOR(t, map[int64]any{1: 2, -1: 1, -2: validX, -3: validY}))},
		{"wrong crv (P-384, 2)", cose(mustCBOR(t, map[int64]any{1: 2, 3: -7, -1: 2, -2: validX, -3: validY}))},
		{"wrong crv (P-521, 3)", cose(mustCBOR(t, map[int64]any{1: 2, 3: -7, -1: 3, -2: validX, -3: validY}))},
		{"wrong crv (secp256k1, 8)", cose(mustCBOR(t, map[int64]any{1: 2, 3: -7, -1: 8, -2: validX, -3: validY}))},
		{"crv zero", cose(mustCBOR(t, map[int64]any{1: 2, 3: -7, -1: 0, -2: validX, -3: validY}))},
		{"crv missing", cose(mustCBOR(t, map[int64]any{1: 2, 3: -7, -2: validX, -3: validY}))},
		{"x missing", cose(mustCBOR(t, map[int64]any{1: 2, 3: -7, -1: 1, -3: validY}))},
		{"y missing", cose(mustCBOR(t, map[int64]any{1: 2, 3: -7, -1: 1, -2: validX}))},
		{"an empty COSE key", cose(regCBOR(map[int64]any{}))},
		{"COSE key is a CBOR array", cose(regCBOR([]any{2, -7}))},
		{"COSE key is CBOR null", cose([]byte{0xf6})},
		{"COSE key is absent", cose([]byte{})},

		// ---- the COSE key's CBOR form ----
		{"COSE key map keys out of order", cose(regCBORMap(
			regCBOR(1), regCBOR(2), regCBOR(3), regCBOR(-7), regCBOR(-2), regBytes(validX), regCBOR(-1), regCBOR(1), regCBOR(-3), regBytes(validY)))},
		{"COSE key with a duplicate key (kty twice)", cose(regCBORMap(
			regCBOR(1), regCBOR(2), regCBOR(1), regCBOR(2), regCBOR(3), regCBOR(-7), regCBOR(-1), regCBOR(1), regCBOR(-2), regBytes(validX), regCBOR(-3), regBytes(validY)))},
		{"COSE key with a duplicate x, the bogus one first", cose(regCBORMap(
			regCBOR(1), regCBOR(2), regCBOR(3), regCBOR(-7), regCBOR(-1), regCBOR(1), regCBOR(-2), regBytes(zero), regCBOR(-2), regBytes(validX), regCBOR(-3), regBytes(validY)))},
		{"COSE key with a non-shortest integer (kty 2 as 0x1802)", cose(regCBORMap(
			regCBOR(1), []byte{0x18, 0x02}, regCBOR(3), regCBOR(-7), regCBOR(-1), regCBOR(1), regCBOR(-2), regBytes(validX), regCBOR(-3), regBytes(validY)))},
		{"COSE key whose x byte string has a non-shortest length (the item ends early)", cose(func() []byte {
			out := regCBORMap(regCBOR(1), regCBOR(2), regCBOR(3), regCBOR(-7), regCBOR(-1), regCBOR(1), regCBOR(-2))
			// byte string of 32 with a one-byte length argument the long way: 0x58 0x20 is the
			// shortest; the longer 0x59 0x00 0x20 is not.
			out = append(out, 0x59, 0x00, 0x20)
			out = append(out, validX...)
			out = append(out, regCBOR(-3)...)

			return append(out, regBytes(validY)...)
		}())},
		{"COSE key as an indefinite-length map", cose(append(append([]byte{0xbf},
			regCBOR(1)...), append(regCBOR(2), append(regCBOR(3), append(regCBOR(-7), append(regCBOR(-1), append(regCBOR(1),
			append(regCBOR(-2), append(regBytes(validX), append(regCBOR(-3), append(regBytes(validY), 0xff)...)...)...)...)...)...)...)...)...))},
		{"COSE key whose x is an indefinite-length byte string (the item ends early)", cose(func() []byte {
			out := regCBORMap(regCBOR(1), regCBOR(2), regCBOR(3), regCBOR(-7), regCBOR(-1), regCBOR(1), regCBOR(-2))
			out = append(out, 0x5f, 0x58, 0x20)
			out = append(out, validX...)
			out = append(out, 0xff)
			out = append(out, regCBOR(-3)...)

			return append(out, regBytes(validY)...)
		}())},
		{"COSE key wrapped in a CBOR tag", cose(append([]byte{0xc0}, regCoseKey(t, validX, validY, nil)...))},
		{"COSE key followed by trailing bytes", cose(append(regCoseKey(t, validX, validY, nil), 0x00))},
		{"COSE key followed by a second COSE key", cose(append(regCoseKey(t, validX, validY, nil), regCoseKey(t, validX, validY, nil)...))},
		{"COSE key with a float where kty is", cose(regCBORMap(
			regCBOR(1), []byte{0xf9, 0x40, 0x00}, regCBOR(3), regCBOR(-7), regCBOR(-1), regCBOR(1), regCBOR(-2), regBytes(validX), regCBOR(-3), regBytes(validY)))},

		// ---- the attestation object ----
		{"attestation object member repeated (fmt twice)", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("fmt"), regText("none"),
				regText("attStmt"), []byte{0xa0}, regText("authData"), regBytes(authData))
		})},
		{"attestation object authData repeated, the real one second", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0},
				regText("authData"), regBytes([]byte("bogus")), regText("authData"), regBytes(authData))
		})},
		{"attestation object member in another case (FMT)", object(func(authData []byte) []byte {
			return regCBORMap(regText("FMT"), regText("none"), regText("attStmt"), []byte{0xa0}, regText("authData"), regBytes(authData))
		})},
		{"attestation object member in another case (AuthData)", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0}, regText("AuthData"), regBytes(authData))
		})},
		{"attestation object member in another case (attstmt)", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("attstmt"), []byte{0xa0}, regText("authData"), regBytes(authData))
		})},
		{"attestation object with an unknown member in canonical position", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("zzz"), regCBOR(1), regText("attStmt"), []byte{0xa0},
				regText("authData"), regBytes(authData))
		})},
		{"attestation object not canonical (authData first)", object(func(authData []byte) []byte {
			return regCBORMap(regText("authData"), regBytes(authData), regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0})
		})},
		{"attestation object not canonical (fmt, authData, attStmt)", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("authData"), regBytes(authData), regText("attStmt"), []byte{0xa0})
		})},
		{"attestation object not canonical (long-form length for fmt key)", object(func(authData []byte) []byte {
			return regCBORMap([]byte{0x78, 0x03, 'f', 'm', 't'}, regText("none"), regText("attStmt"), []byte{0xa0}, regText("authData"), regBytes(authData))
		})},
		{"attestation object not canonical (map length 3 spelled in two bytes)", object(func(authData []byte) []byte {
			body := regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0}, regText("authData"), regBytes(authData))

			return append([]byte{0xb8, 0x03}, body[1:]...)
		})},
		{"attestation object with trailing bytes", object(func(authData []byte) []byte {
			return append(regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0},
				regText("authData"), regBytes(authData)), 0x00)
		})},
		{"attestation object followed by a second object", object(func(authData []byte) []byte {
			one := regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0}, regText("authData"), regBytes(authData))

			return append(append([]byte(nil), one...), one...)
		})},
		{"attestation object as an indefinite-length map", object(func(authData []byte) []byte {
			out := []byte{0xbf}
			out = append(out, regText("fmt")...)
			out = append(out, regText("none")...)
			out = append(out, regText("attStmt")...)
			out = append(out, 0xa0)
			out = append(out, regText("authData")...)
			out = append(out, regBytes(authData)...)

			return append(out, 0xff)
		})},
		{"attestation object with an indefinite-length attStmt", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xbf, 0xff},
				regText("authData"), regBytes(authData))
		})},
		{"attestation object with an indefinite-length text string for fmt", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), []byte{0x7f, 0x64, 'n', 'o', 'n', 'e', 0xff},
				regText("attStmt"), []byte{0xa0}, regText("authData"), regBytes(authData))
		})},
		{"attestation object whose authData is an indefinite-length byte string (the item ends early)", object(func(authData []byte) []byte {
			out := regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0}, regText("authData"))
			out = append(out, 0x5f)
			out = append(out, regBytes(authData)...)

			return append(out, 0xff)
		})},
		{"attestation object wrapped in a CBOR tag", object(func(authData []byte) []byte {
			return append([]byte{0xc0}, regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0},
				regText("authData"), regBytes(authData))...)
		})},
		{"attestation object with a tagged authData", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0},
				regText("authData"), append([]byte{0xc0}, regBytes(authData)...))
		})},
		{"attestation object with authData as a text string", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0},
				regText("authData"), regText(string(authData)))
		})},
		{"attestation object with fmt as a byte string", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regBytes([]byte("none")), regText("attStmt"), []byte{0xa0},
				regText("authData"), regBytes(authData))
		})},
		{"attestation object with integer map keys", object(func(authData []byte) []byte {
			return regCBORMap(regCBOR(1), regText("none"), regCBOR(2), []byte{0xa0}, regCBOR(3), regBytes(authData))
		})},
		{"attestation object nested past the depth bound", object(func(authData []byte) []byte {
			deep := []byte{0xa0}
			for range 8 {
				deep = append(append([]byte{0xa1}, regText("a")...), deep...)
			}

			return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), deep, regText("authData"), regBytes(authData))
		})},
		{"attestation object with a map of more than 16 pairs in attStmt", object(func(authData []byte) []byte {
			stmt := make([]byte, 0, 2+20*4)
			stmt = append(stmt, 0xb8, 20)

			for i := range 20 {
				stmt = append(stmt, regCBOR(string(rune('a'+i)))...)
				stmt = append(stmt, regCBOR(i)...)
			}

			return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), stmt, regText("authData"), regBytes(authData))
		})},
		{"attestation object claiming a huge map length", object(func([]byte) []byte {
			return []byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		})},
		{"attestation object claiming a huge byte string length", object(func([]byte) []byte {
			return []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0,
				0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		})},
		{"attestation object truncated mid-item", object(func(authData []byte) []byte {
			full := regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0}, regText("authData"), regBytes(authData))

			return full[:len(full)-5]
		})},
		{"attestation object of one byte", object(func([]byte) []byte { return []byte{0xa3} })},
		{"attestation object is CBOR undefined", object(func([]byte) []byte { return []byte{0xf7} })},
		{"attestation object with a float member value", object(func(authData []byte) []byte {
			return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xf9, 0x3c, 0x00},
				regText("authData"), regBytes(authData))
		})},

		// ---- clientDataJSON ----
		{"origin repeated, evil first", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"https://evil.example","origin":"` + target.origin + `"}`)
		})},
		{"origin repeated, evil last", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","origin":"https://evil.example"}`)
		})},
		{"origin repeated with identical values", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","origin":"` + target.origin + `"}`)
		})},
		{"type repeated", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.get","type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `"}`)
		})},
		{"origin member in another case beside the real one", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"https://evil.example","ORIGIN":"` + target.origin + `"}`)
		})},
		{"origin member ONLY in another case", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","ORIGIN":"` + target.origin + `"}`)
		})},
		{"type member in another case", clientData(func(c string) []byte {
			return []byte(`{"Type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `"}`)
		})},
		{"challenge member in another case", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","CHALLENGE":"` + c + `","origin":"` + target.origin + `"}`)
		})},
		{"crossOrigin member in another case, true", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","CrossOrigin":true}`)
		})},
		{"topOrigin member in upper case", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","TOPORIGIN":"x"}`)
		})},
		{"crossOrigin null", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","crossOrigin":null}`)
		})},
		{"crossOrigin true", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","crossOrigin":true}`)
		})},
		{"crossOrigin as a string", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","crossOrigin":"false"}`)
		})},
		{"crossOrigin as a number", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","crossOrigin":0}`)
		})},
		{"topOrigin present beside crossOrigin false", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","crossOrigin":false,"topOrigin":"` + target.origin + `"}`)
		})},
		{"topOrigin present alone", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","topOrigin":"https://evil.example"}`)
		})},
		{"topOrigin null", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","topOrigin":null}`)
		})},
		{"origin with a path", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `/x"}`)
		})},
		{"origin with a trailing slash", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `/"}`)
		})},
		{"origin in upper case", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + strings.ToUpper(target.origin) + `"}`)
		})},
		{"origin with another port", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"http://localhost:3001"}`)
		})},
		{"origin with a user-info prefix", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"http://evil.example@localhost:3000"}`)
		})},
		{"origin with a trailing NUL escape", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `\u0000"}`)
		})},
		{"origin with a trailing space", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + ` "}`)
		})},
		{"origin as an array", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":["` + target.origin + `"]}`)
		})},
		{"origin null", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":null}`)
		})},
		{"challenge with a newline escape", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c[:10] + `\n` + c[10:] + `","origin":"` + target.origin + `"}`)
		})},
		{"challenge with a lone surrogate escape", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `\ud800","origin":"` + target.origin + `"}`)
		})},
		{"clientDataJSON with a raw newline in a string", clientData(func(c string) []byte {
			return []byte("{\"type\":\"webauthn.create\",\"challenge\":\"" + c + "\",\"origin\":\"" + target.origin + "\",\"x\":\"a\nb\"}")
		})},
		{"clientDataJSON with a comment", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create",/*x*/"challenge":"` + c + `","origin":"` + target.origin + `"}`)
		})},
		{"clientDataJSON with a trailing comma", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `",}`)
		})},
		{"clientDataJSON with single quotes", clientData(func(c string) []byte {
			return []byte(`{'type':'webauthn.create','challenge':'` + c + `','origin':'` + target.origin + `'}`)
		})},
		{"clientDataJSON with a NaN member", clientData(func(c string) []byte {
			return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","x":NaN}`)
		})},
	}

	return cases
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}

	return out
}

// TestRegistrationParity runs every case against the Worker. Each one begins a
// fresh ceremony for the role-less invitation and must be refused with 400
// invalid_credential by the verifier, writing nothing.
//
//nolint:paralleltest // shares one database
func TestRegistrationParity(t *testing.T) {
	reset(t)
	regSeedInvitation(t, parityID, parityCode, regNoRoleType, 1, "")

	// The control: an honest response passes the verifier, the challenge and the
	// invitation read, and is refused only for the invitation's missing role.
	// Without it a refusal below could be the harness failing, not the parser.
	t.Run("control: an honest response reaches the role check", func(t *testing.T) {
		got := post(t, pathRegisterEnd, newAuthenticator().finishBody(t, regParityBegin(t), parityCode, "Parity"), "")
		if got.status != http.StatusInternalServerError || got.errorCode() != "internal" {
			t.Fatalf("finish = %d %s, want 500 internal (verified, then refused for having no role)", got.status, got.body)
		}
	})

	for _, tt := range regParityCases(t) {
		t.Run(tt.name, func(t *testing.T) {
			options := regParityBegin(t)
			auth := newAuthenticator()
			tt.edit(&auth)

			got := post(t, pathRegisterEnd, auth.finishBody(t, options, parityCode, "Parity"), "")
			if got.status != http.StatusBadRequest || got.errorCode() != regCodeCred {
				t.Errorf("finish = %d %.300s, want 400 %s", got.status, got.body, regCodeCred)
			}
		})
	}

	regExpectNothingWritten(t, "parity")
}

// TestRegistrationParityAccepted is the other half of parity: spellings that
// are legal and must reach the role check (500), proving the parser is not
// refusing too much under TinyGo. Each is something a real browser or
// authenticator can send.
//
//nolint:paralleltest // shares one database
func TestRegistrationParityAccepted(t *testing.T) {
	reset(t)
	regSeedInvitation(t, parityID, parityCode, regNoRoleType, 1, "")

	accepted := []struct {
		name string
		edit func(a *authenticator)
	}{
		{"canonical object, empty attStmt", func(*authenticator) {}},
		{"attStmt absent is read as empty", func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBORMap(regText("fmt"), regText("none"), regText("authData"), regBytes(authData))
			}
		}},
		{"attStmt null is read as empty", func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xf6}, regText("authData"), regBytes(authData))
			}
		}},
		{"clientDataJSON with the members in another order", func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"origin":"` + target.origin + `","crossOrigin":false,"challenge":"` + c + `","type":"webauthn.create"}`)
			}
		}},
		{"clientDataJSON with whitespace", func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(" {\n \"type\" : \"webauthn.create\",\n \"challenge\":\"" + c + "\" ,\n\"origin\":\"" + target.origin + "\"\n}\n")
			}
		}},
		{"clientDataJSON without crossOrigin", func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `"}`)
			}
		}},
		{"clientDataJSON with crossOrigin false", func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","crossOrigin":false}`)
			}
		}},
		{"clientDataJSON with unknown members of every JSON type", func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin +
					`","other_keys_can_be_added_here":"x","n":1,"f":1.5,"b":true,"z":null,"a":[1,{"k":"v"}],"o":{"k":[]}}`)
			}
		}},
		{"clientDataJSON with escapes that decode to the same strings", func(a *authenticator) {
			a.clientData = func(c string) []byte {
				// "webauthn.create" with the dot escaped as \u002e, and the origin's slashes escaped.
				escaped := strings.ReplaceAll(target.origin, "/", `\/`)

				return []byte(`{"type":"webauthn\u002ecreate","challenge":"` + c + `","origin":"` + escaped + `"}`)
			}
		}},
		{"clientDataJSON with invalid UTF-8 inside an unknown member (ignored, as the spec lets clients add members)", func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","x":"` + "\xff" + `"}`)
			}
		}},
		{"clientDataJSON with a member named like a field after a dot", func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","origin2":"x","typed":"y"}`)
			}
		}},
		{"authenticator data with a non-zero signature counter", func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				authData[36] = 0x7f // low byte of the counter

				return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0},
					regText("authData"), regBytes(authData))
			}
		}},
		{"authenticator data with a non-zero AAGUID", func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				for i := 37; i < 53; i++ {
					authData[i] = byte(i)
				}

				return regCBORMap(regText("fmt"), regText("none"), regText("attStmt"), []byte{0xa0},
					regText("authData"), regBytes(authData))
			}
		}},
		{"BE and BS set together", func(a *authenticator) { a.flags = flagUP | flagUV | flagAT | 0x08 | 0x10 }},
		{"BE alone", func(a *authenticator) { a.flags = flagUP | flagUV | flagAT | 0x08 }},
	}

	for _, tt := range accepted {
		t.Run(tt.name, func(t *testing.T) {
			options := regParityBegin(t)
			auth := newAuthenticator()
			tt.edit(&auth)

			got := post(t, pathRegisterEnd, auth.finishBody(t, options, parityCode, "Parity"), "")
			if got.status != http.StatusInternalServerError || got.errorCode() != "internal" {
				t.Errorf("finish = %d %.300s, want 500 internal (accepted by the verifier, refused for having no role)", got.status, got.body)
			}
		})
	}

	regExpectNothingWritten(t, "parity accepted")
}

// TestRegistrationParityHonestKeys registers keys of the awkward shapes an
// honest authenticator can produce (a coordinate with leading zero bytes, the
// smallest x) and checks they are accepted by the TinyGo curve check and stored
// byte for byte.
//
//nolint:paralleltest // shares one database
func TestRegistrationParityHonestKeys(t *testing.T) {
	x, y := regSmallXPoint(t)

	tests := []struct {
		name string
		x, y []byte
	}{
		{"the smallest-x point (31 leading zero bytes in x)", regField(x), regField(y)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regOpenFirstRun(t)

			options := mustBeginRegistration(t, firstRunSecret, "Alice")
			auth := newAuthenticator()
			auth.cose = regCoseKey(t, tt.x, tt.y, nil)

			post(t, pathRegisterEnd, auth.finishBody(t, options, firstRunSecret, "Alice"), "").
				expect(t, "finish", http.StatusCreated, "")

			if got := scalar(t, "SELECT hex(public_key) FROM credentials"); got != strings.ToUpper(hex.EncodeToString(auth.cose)) {
				t.Errorf("stored key = %s, want %X", got, auth.cose)
			}
		})
	}
}
