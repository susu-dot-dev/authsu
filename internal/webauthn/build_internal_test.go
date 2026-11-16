package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/rand/v2"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const (
	testRPID     = "auth.example.com"
	testOrigin   = "https://auth.example.com"
	testChalText = "0123456789abcdef0123456789abcdef0123456789abcdef"
)

// testRP is the relying party the tests verify against.
func testRP() RelyingParty { return RelyingParty{ID: testRPID, Origin: testOrigin} }

// Attestation object member names.
const (
	memberFmt      = "fmt"
	memberAttStmt  = "attStmt"
	memberAuthData = "authData"
)

// response describes a registration response to build. The zero value is not
// valid; use validResponse and change fields to make a case fail.
type response struct {
	clientData    map[string]any
	rawClient     []byte // used instead of clientData when set
	format        string
	attStmt       map[string]any
	rpID          string
	flags         byte
	aaguid        [16]byte
	credID        []byte
	idLenOverride *uint16
	key           any    // a coseKey-shaped value, or raw CBOR bytes
	trailing      []byte // appended to authData
	rawAttObject  []byte // used instead of the built object when set
	id, rawID     string // reported ids; default to the credential id
}

// coseMap is a COSE_Key as a CBOR map with integer labels.
type coseMap map[int64]any

// keyWith returns validKey with edit applied. Tests use it to break one thing.
func keyWith(tb testing.TB, edit func(coseMap)) coseMap {
	tb.Helper()

	key := validKey(tb)
	edit(key)

	return key
}

func validKey(tb testing.TB) coseMap {
	tb.Helper()

	// A fresh key on every call: since Go 1.26 GenerateKey ignores its
	// reader, so a test that needs one key twice must keep it.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.NewChaCha8([32]byte{1}))
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}

	return coseMap{
		1:  2,
		3:  -7,
		-1: 1,
		-2: priv.X.FillBytes(make([]byte, 32)),
		-3: priv.Y.FillBytes(make([]byte, 32)),
	}
}

func validResponse(tb testing.TB) response {
	tb.Helper()

	return response{
		clientData: map[string]any{
			"type":      "webauthn.create",
			"challenge": base64.RawURLEncoding.EncodeToString([]byte(testChalText)),
			"origin":    testOrigin,
		},
		format: noneFormat,
		rpID:   testRPID,
		// UP | UV | AT
		flags:  0x01 | 0x04 | 0x40,
		aaguid: [16]byte{0xaa, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		credID: []byte("credential-id-0123456789"),
		key:    validKey(tb),
	}
}

func mustCBOR(tb testing.TB, v any) []byte {
	tb.Helper()

	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		tb.Fatalf("encoder: %v", err)
	}

	out, err := mode.Marshal(v)
	if err != nil {
		tb.Fatalf("marshal CBOR: %v", err)
	}

	return out
}

func (r response) authData(tb testing.TB) []byte {
	tb.Helper()

	hash := sha256.Sum256([]byte(r.rpID))

	out := append([]byte(nil), hash[:]...)
	out = append(out, r.flags)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = append(out, r.aaguid[:]...)

	idLen := uint16(len(r.credID)) //nolint:gosec // test ids are short
	if r.idLenOverride != nil {
		idLen = *r.idLenOverride
	}

	out = binary.BigEndian.AppendUint16(out, idLen)
	out = append(out, r.credID...)

	switch key := r.key.(type) {
	case []byte:
		out = append(out, key...)
	default:
		out = append(out, mustCBOR(tb, key)...)
	}

	return append(out, r.trailing...)
}

// build returns the Registration as the browser would send it.
func (r response) build(tb testing.TB) Registration {
	tb.Helper()

	client := r.rawClient
	if client == nil {
		var err error

		client, err = json.Marshal(r.clientData)
		if err != nil {
			tb.Fatalf("marshal client data: %v", err)
		}
	}

	object := r.rawAttObject
	if object == nil {
		statement := r.attStmt
		if statement == nil {
			statement = map[string]any{}
		}

		object = mustCBOR(tb, map[string]any{
			memberFmt:      r.format,
			memberAttStmt:  statement,
			memberAuthData: r.authData(tb),
		})
	}

	id := base64.RawURLEncoding.EncodeToString(r.credID)

	reg := Registration{
		ID:                id,
		RawID:             id,
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(client),
		AttestationObject: base64.RawURLEncoding.EncodeToString(object),
		// Sorted and unique, as section 5.2.1 says clients report them.
		Transports: []string{"hybrid", "internal"},
	}

	if r.id != "" {
		reg.ID = r.id
	}

	if r.rawID != "" {
		reg.RawID = r.rawID
	}

	return reg
}
