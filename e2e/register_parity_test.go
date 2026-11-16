//go:build e2e

package e2e_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The verifier's parsers and its curve check run under TinyGo in production
// but are unit-tested under Go. TinyGo compiles the same sources, but its
// reflect, runtime and crypto/rand are its own, and the CBOR and JSON decoders
// are reflection-driven. These tests send the Worker inputs the host tests
// refuse and require the Worker to refuse them too.
//
// They use an invitation whose type has no role. A response that passes every
// check then fails at the role mapping with 500, writing nothing, so "refused
// by the verifier" (400 invalid_credential) is distinguishable from "accepted
// by the verifier" without creating an account.

const (
	// parityCode is the invitation code of the role-less invitation.
	parityCode = "e2e-parity-invitation-0123456789ABCDEFGHIJKL"
	// parityType is an invitation type that maps to no role.
	parityType = "e2e_no_role"
	// fmtMember and attStmtMember are attestation object member names.
	fmtMember     = "fmt"
	noneFormat    = "none"
	attStmtMember = "attStmt"
)

// seedRolelessInvitation inserts the invitation the parity tests use.
func seedRolelessInvitation(t *testing.T) {
	t.Helper()

	sum := sha256.Sum256([]byte(parityCode))

	query(t, "DELETE FROM invitations WHERE type = '"+parityType+"'")
	query(t, "INSERT INTO invitations (id, code_hash, type, label, num_invites, created_at) VALUES "+
		"('00000000-0000-7000-8000-0000000e2e01', X'"+hex.EncodeToString(sum[:])+"', '"+parityType+"', 'e2e parity', 1, 0)")
}

func mustParityBegin(t *testing.T) creationOptions {
	t.Helper()

	status, body := beginRegistration(t, parityCode, "Parity")
	if status != http.StatusOK {
		t.Fatalf("begin = %d %s, want 200", status, body)
	}

	return decodeOptions(t, body)
}

func decodeOptions(t *testing.T, body string) creationOptions {
	t.Helper()

	var options creationOptions

	err := json.Unmarshal([]byte(body), &options)
	if err != nil {
		t.Fatalf("parse begin response: %v\n%s", err, body)
	}

	return options
}

func mustEncoder(t *testing.T) cbor.EncMode {
	t.Helper()

	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	return encoder
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()

	out, err := mustEncoder(t).Marshal(v)
	if err != nil {
		t.Fatalf("marshal CBOR: %v", err)
	}

	return out
}

// p256 returns the field prime and the curve's b.
func p256(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()

	params := elliptic.P256().Params()

	return params.P, params.B
}

// smallXPoint is the P-256 point with the smallest positive x, so that x+p
// still fits in 32 bytes.
func smallXPoint(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()

	p, b := p256(t)

	for i := int64(1); i < 100; i++ {
		x := big.NewInt(i)
		rhs := new(big.Int).Exp(x, big.NewInt(3), p)
		rhs.Sub(rhs, new(big.Int).Mul(big.NewInt(3), x))
		rhs.Add(rhs, b)
		rhs.Mod(rhs, p)

		if y := new(big.Int).ModSqrt(rhs, p); y != nil {
			return x, y
		}
	}

	t.Fatal("no small-x point")

	return nil, nil
}

func coordinate(v *big.Int) []byte { return v.FillBytes(make([]byte, 32)) }

// coseKey is a COSE_Key with the given coordinates and extra parameters.
func coseKey(t *testing.T, x, y []byte, extra map[int64]any) []byte {
	t.Helper()

	key := map[int64]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}
	maps.Copy(key, extra)

	return mustMarshal(t, key)
}

func freshKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	return key
}

// clientDataJSON is raw client data with the given members after type,
// challenge and origin.
func clientDataJSON(challenge, origin string, members ...string) []byte {
	all := append([]string{
		`"type":"webauthn.create"`, `"challenge":"` + challenge + `"`, `"origin":"` + origin + `"`,
	}, members...)

	return []byte("{" + strings.Join(all, ",") + "}")
}

// parityCases are responses the verifier must refuse, keyed by what is wrong.
func parityCases(t *testing.T) map[string]func(*authenticator) {
	t.Helper()

	cases := keyCases(t)
	maps.Copy(cases, parserCases(t))

	return cases
}

// keyCases are credential public keys the verifier must refuse. The curve
// check is the lynchpin, and it is crypto/ecdh compiled by TinyGo.
func keyCases(t *testing.T) map[string]func(*authenticator) {
	t.Helper()

	x, y := smallXPoint(t)
	p, _ := p256(t)
	key := freshKey(t)
	validX, validY := coordinate(key.X), coordinate(key.Y)

	return map[string]func(*authenticator){
		"point not on the curve": func(a *authenticator) {
			a.cose = coseKey(t, validX, make([]byte, 32), nil)
		},
		"point at infinity": func(a *authenticator) {
			a.cose = coseKey(t, make([]byte, 32), make([]byte, 32), nil)
		},
		"coordinate not reduced mod p": func(a *authenticator) {
			a.cose = coseKey(t, coordinate(new(big.Int).Add(x, p)), coordinate(y), nil)
		},
		"private key in the COSE key": func(a *authenticator) {
			a.cose = coseKey(t, validX, validY, map[int64]any{-4: make([]byte, 32)})
		},
	}
}

// parserCases are CBOR and JSON the verifier must refuse.
func parserCases(t *testing.T) map[string]func(*authenticator) {
	t.Helper()

	return map[string]func(*authenticator){
		"repeated attestation object member": func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				obj := []byte{0xa4}
				for _, item := range []any{fmtMember, noneFormat, fmtMember, noneFormat, attStmtMember} {
					obj = append(obj, mustMarshal(t, item)...)
				}

				obj = append(obj, 0xa0)
				obj = append(obj, mustMarshal(t, "authData")...)

				return append(obj, mustMarshal(t, authData)...)
			}
		},
		"attestation object member in another case": func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return mustMarshal(t, map[string]any{"FMT": noneFormat, attStmtMember: map[string]any{}, "authData": authData})
			}
		},
		"attestation object not canonical": func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				obj := []byte{0xa3}
				obj = append(obj, mustMarshal(t, "authData")...)
				obj = append(obj, mustMarshal(t, authData)...)
				obj = append(obj, mustMarshal(t, fmtMember)...)
				obj = append(obj, mustMarshal(t, noneFormat)...)
				obj = append(obj, mustMarshal(t, attStmtMember)...)

				return append(obj, 0xa0)
			}
		},
		"origin repeated, evil first": func(a *authenticator) {
			origin := a.origin
			a.clientData = func(challenge string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + challenge +
					`","origin":"https://evil.example","origin":"` + origin + `"}`)
			}
		},
		"origin name in another case": func(a *authenticator) {
			origin := a.origin
			a.clientData = func(challenge string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + challenge + `","ORIGIN":"` + origin + `"}`)
			}
		},
		"crossOrigin null": func(a *authenticator) {
			origin := a.origin
			a.clientData = func(challenge string) []byte {
				return clientDataJSON(challenge, origin, `"crossOrigin":null`)
			}
		},
		"challenge with a newline": func(a *authenticator) {
			origin := a.origin
			a.clientData = func(challenge string) []byte {
				return clientDataJSON(challenge[:10]+`\n`+challenge[10:], origin)
			}
		},
	}
}

// workerParsesLikeTheHost runs parityCases against the Worker.
func workerParsesLikeTheHost(t *testing.T) {
	seedRolelessInvitation(t)

	t.Cleanup(func() { query(t, "DELETE FROM invitations WHERE type = '"+parityType+"'") })

	users := query(t, "SELECT count(*) AS v FROM users")

	// The control: an honest response passes the verifier and the challenge,
	// and is refused only for the invitation's missing role. Without it a
	// refusal below could be the oracle failing rather than the parser.
	t.Run("control: an honest response reaches the role check", func(t *testing.T) {
		options := mustParityBegin(t)

		status, body := postJSON(t, registerPath+"/finish", newAuthenticator().finishBody(t, options, parityCode, "Parity"))
		if status != http.StatusInternalServerError || !strings.Contains(body, `"internal"`) {
			t.Fatalf("finish = %d %s, want 500 internal (verified, then refused for having no role)", status, body)
		}
	})

	for name, edit := range parityCases(t) {
		t.Run(name, func(t *testing.T) {
			options := mustParityBegin(t)
			auth := newAuthenticator()
			edit(&auth)

			status, body := postJSON(t, registerPath+"/finish", auth.finishBody(t, options, parityCode, "Parity"))
			if status != http.StatusBadRequest || !strings.Contains(body, `"`+codeInvalidCredential+`"`) {
				t.Errorf("finish = %d %s, want 400 %s", status, body, codeInvalidCredential)
			}
		})
	}

	expectCount(t, "users", users)
}
