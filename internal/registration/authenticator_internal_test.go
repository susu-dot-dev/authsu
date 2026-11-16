package registration

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

// authenticator is a software authenticator for tests: it turns the creation
// options begin returned into the response a browser would send.
type authenticator struct {
	rpID   string
	origin string
	flags  byte
	credID []byte
	// clientDataType is the clientData type; "webauthn.create" when empty.
	clientDataType string
	// challenge overrides the challenge echoed in clientDataJSON.
	challenge []byte
}

func newAuthenticator() authenticator {
	return authenticator{
		rpID:   testRPID,
		origin: testOrigin,
		// UP | UV | AT
		flags:          0x01 | 0x04 | 0x40,
		credID:         []byte("credential-id-0123456789"),
		clientDataType: "",
		challenge:      nil,
	}
}

func (a authenticator) respond(t *testing.T, options creationOptions) FinishRequest {
	t.Helper()

	id := base64.RawURLEncoding.EncodeToString(a.credID)

	return FinishRequest{
		InvitationCode: testCode,
		Name:           testName,
		Credential: credential{
			ID: id, RawID: id, Type: "public-key",
			Response: credentialResult{
				ClientDataJSON:    base64.RawURLEncoding.EncodeToString(a.clientData(t, options)),
				AttestationObject: base64.RawURLEncoding.EncodeToString(a.attestationObject(t)),
				Transports:        []string{transportInternal},
			},
		},
	}
}

// clientData is the clientDataJSON the browser would write.
func (a authenticator) clientData(t *testing.T, options creationOptions) []byte {
	t.Helper()

	challenge := a.challenge
	if challenge == nil {
		var err error

		challenge, err = base64.RawURLEncoding.DecodeString(options.PublicKey.Challenge)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
	}

	typ := a.clientDataType
	if typ == "" {
		typ = "webauthn.create"
	}

	out, err := json.Marshal(map[string]any{
		"type":      typ,
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    a.origin,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	return out
}

// attestationObject is a "none" attestation over a fresh ES256 key.
func (a authenticator) attestationObject(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.NewChaCha8([32]byte{9}))
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	cose, err := encoder.Marshal(map[int64]any{
		1: 2, 3: -7, -1: 1,
		-2: key.X.FillBytes(make([]byte, 32)),
		-3: key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("cose: %v", err)
	}

	hash := sha256.Sum256([]byte(a.rpID))

	authData := make([]byte, 0, len(hash)+1+4+16+2+len(a.credID)+len(cose))
	authData = append(authData, hash[:]...)
	authData = append(authData, a.flags)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(min(len(a.credID), 1023)))
	authData = append(authData, a.credID...)
	authData = append(authData, cose...)

	object, err := encoder.Marshal(map[string]any{"fmt": noneFormat, "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}

	return object
}
