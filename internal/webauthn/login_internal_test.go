package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// testHandle is the account's user handle.
func testHandle() []byte { return []byte("user-handle-0123456789abcdef0123") }

const (
	notBase64 = "***"
	emptyCase = "empty"
)

// assertionCase describes an assertion to build and sign. Start from
// validAssertion and change one field to make one check fail.
type assertionCase struct {
	key        *ecdsa.PrivateKey
	clientData map[string]any
	rawClient  []byte
	rpID       string
	flags      byte
	credID     []byte
	authData   []byte // replaces the built authenticator data when set
	handle     []byte
	omitHandle bool
	// tamper edits the signature after it is made.
	tamper func([]byte) []byte
	// storedFlags are the flags registration stored for the credential.
	storedFlags Flags
	id, rawID   string
	// post edits the built assertion's encoded members, after signing.
	post func(*Assertion)
}

// verifyAssertion runs both phases of verification, as the login handler does.
func verifyAssertion(a Assertion, stored Stored, rp RelyingParty) (Asserted, error) {
	parsed, err := ParseAssertion(a, rp)
	if err != nil {
		return Asserted{}, err
	}

	return parsed.Verify(stored)
}

func validAssertion(tb testing.TB) assertionCase {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}

	return assertionCase{
		key: key,
		clientData: map[string]any{
			"type":      "webauthn.get",
			"challenge": base64.RawURLEncoding.EncodeToString([]byte(testChalText)),
			"origin":    testOrigin,
		},
		rpID: testRPID,
		// UP | UV
		flags:       0x01 | 0x04,
		credID:      []byte("credential-id-0123456789"),
		handle:      testHandle(),
		storedFlags: FlagUserPresent | FlagUserVerified,
	}
}

func (c assertionCase) cose(tb testing.TB) []byte {
	tb.Helper()

	return mustCBOR(tb, coseMap{
		1:  2,
		3:  -7,
		-1: 1,
		-2: c.key.X.FillBytes(make([]byte, 32)),
		-3: c.key.Y.FillBytes(make([]byte, 32)),
	})
}

// stored is what registration would have stored for this credential.
func (c assertionCase) stored(tb testing.TB) Stored {
	tb.Helper()

	return Stored{PublicKey: c.cose(tb), Flags: c.storedFlags, UserHandle: testHandle()}
}

// authDataBytes returns the authenticator data the case builds.
func (c assertionCase) authDataBytes() []byte {
	if c.authData != nil {
		return c.authData
	}

	hash := sha256.Sum256([]byte(c.rpID))

	out := append([]byte(nil), hash[:]...)
	out = append(out, c.flags)

	return binary.BigEndian.AppendUint32(out, 0)
}

// clientBytes returns the clientDataJSON the case builds.
func (c assertionCase) clientBytes(tb testing.TB) []byte {
	tb.Helper()

	if c.rawClient != nil {
		return c.rawClient
	}

	client, err := json.Marshal(c.clientData)
	if err != nil {
		tb.Fatalf("marshal client data: %v", err)
	}

	return client
}

// sign signs authData || SHA-256(client) with key, as an authenticator does.
func sign(tb testing.TB, key *ecdsa.PrivateKey, authData, client []byte) []byte {
	tb.Helper()

	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))

	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		tb.Fatalf("sign: %v", err)
	}

	return signature
}

func (c assertionCase) build(tb testing.TB) Assertion {
	tb.Helper()

	client := c.clientBytes(tb)
	authData := c.authDataBytes()
	signature := sign(tb, c.key, authData, client)

	if c.tamper != nil {
		signature = c.tamper(signature)
	}

	id := base64.RawURLEncoding.EncodeToString(c.credID)

	out := Assertion{
		ID:                id,
		RawID:             id,
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(client),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
		Signature:         base64.RawURLEncoding.EncodeToString(signature),
		UserHandle:        "",
	}

	if !c.omitHandle {
		out.UserHandle = base64.RawURLEncoding.EncodeToString(c.handle)
	}

	if c.id != "" {
		out.ID = c.id
	}

	if c.rawID != "" {
		out.RawID = c.rawID
	}

	if c.post != nil {
		c.post(&out)
	}

	return out
}

func TestVerifyAssertionAccepts(t *testing.T) {
	t.Parallel()

	c := validAssertion(t)

	got, err := verifyAssertion(c.build(t), c.stored(t), testRP())
	if err != nil {
		t.Fatalf("verifyAssertion: %v", err)
	}

	if string(got.Challenge) != testChalText {
		t.Errorf("challenge = %q, want %q", got.Challenge, testChalText)
	}

	if !bytes.Equal(got.CredentialID, c.credID) {
		t.Errorf("credential id = %x, want %x", got.CredentialID, c.credID)
	}

	if got.Flags != FlagUserPresent|FlagUserVerified {
		t.Errorf("flags = %08b", got.Flags)
	}
}

func TestVerifyAssertionReportsBackupStateChange(t *testing.T) {
	t.Parallel()

	// Backup state may change over a credential's life (it is synced later),
	// and the new flags are what the caller stores.
	c := validAssertion(t)
	c.storedFlags |= FlagBackupEligible
	c.flags |= byte(FlagBackupEligible | FlagBackupState)

	got, err := verifyAssertion(c.build(t), c.stored(t), testRP())
	if err != nil {
		t.Fatalf("verifyAssertion: %v", err)
	}

	if got.Flags&FlagBackupState == 0 {
		t.Errorf("flags = %08b, want backup state reported", got.Flags)
	}
}

func TestVerifyAssertionRefusesClientData(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edit func(*assertionCase)
		want error
	}{
		"wrong ceremony type": {
			edit: func(c *assertionCase) { c.clientData["type"] = "webauthn.create" },
			want: ErrClientData,
		},
		"wrong origin": {
			edit: func(c *assertionCase) { c.clientData["origin"] = "https://evil.example.com" },
			want: ErrClientData,
		},
		"cross origin": {
			edit: func(c *assertionCase) { c.clientData["crossOrigin"] = true },
			want: ErrClientData,
		},
		"duplicate member": {
			edit: func(c *assertionCase) { c.rawClient = []byte(`{"type":"webauthn.get","type":"webauthn.get"}`) },
			want: ErrClientData,
		},
	}

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

func TestVerifyAssertionRefusesAuthData(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edit func(*assertionCase)
		want error
	}{
		"wrong relying party": {
			edit: func(c *assertionCase) { c.rpID = "evil.example.com" },
			want: ErrAuthData,
		},
		"user presence missing": {
			edit: func(c *assertionCase) { c.flags = 0x04 },
			want: ErrAuthData,
		},
		"user verification missing": {
			edit: func(c *assertionCase) { c.flags = 0x01 },
			want: ErrAuthData,
		},
		"attested credential data present": {
			edit: func(c *assertionCase) { c.flags |= 0x40 },
			want: ErrAuthData,
		},
		"extension data present": {
			edit: func(c *assertionCase) { c.flags |= 0x80 },
			want: ErrAuthData,
		},
		"reserved bit set": {
			edit: func(c *assertionCase) { c.flags |= 0x02 },
			want: ErrAuthData,
		},
		"authenticator data too short": {
			edit: func(c *assertionCase) { c.authData = make([]byte, fixedAuthData-1) },
			want: ErrAuthData,
		},
		"authenticator data too long": {
			edit: func(c *assertionCase) { c.authData = append(c.authDataBytes(), 0) },
			want: ErrAuthData,
		},
	}

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

func TestVerifyAssertionRefusesBackupFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edit func(*assertionCase)
		want error
	}{
		"backup state without eligibility": {
			edit: func(c *assertionCase) { c.flags |= byte(FlagBackupState) },
			want: ErrAuthData,
		},
		"backup eligibility gained": {
			edit: func(c *assertionCase) { c.flags |= byte(FlagBackupEligible) },
			want: ErrAuthData,
		},
		"backup eligibility lost": {
			edit: func(c *assertionCase) { c.storedFlags |= FlagBackupEligible },
			want: ErrAuthData,
		},
	}

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

func TestVerifyAssertionRefusesIdentity(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edit func(*assertionCase)
		want error
	}{
		"missing user handle": {
			edit: func(c *assertionCase) { c.omitHandle = true },
			want: ErrAssertion,
		},
		"another account's user handle": {
			edit: func(c *assertionCase) { c.handle = []byte("someone-else") },
			want: ErrAssertion,
		},
		"oversized user handle": {
			edit: func(c *assertionCase) { c.handle = bytes.Repeat([]byte{1}, MaxUserHandle+1) },
			want: ErrAssertion,
		},
		"id and rawId differ": {
			edit: func(c *assertionCase) { c.id = base64.RawURLEncoding.EncodeToString([]byte("other")) },
			want: ErrAssertion,
		},
		"id is not base64url": {
			edit: func(c *assertionCase) { c.id = "!!" },
			want: ErrAssertion,
		},
	}

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

func TestVerifyAssertionRefusesSignature(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edit func(*assertionCase)
		want error
	}{
		"signature by another key": {
			edit: func(c *assertionCase) {
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate key: %v", err)
				}

				c.tamper = func([]byte) []byte { return sign(t, other, c.authDataBytes(), c.clientBytes(t)) }
			},
			want: ErrAssertion,
		},
		"signature with a trailing byte": {
			edit: func(c *assertionCase) { c.tamper = func(sig []byte) []byte { return append(sig, 0) } },
			want: ErrAssertion,
		},
		"signature truncated": {
			edit: func(c *assertionCase) { c.tamper = func(sig []byte) []byte { return sig[:len(sig)-1] } },
			want: ErrAssertion,
		},
		"signature flipped": {
			edit: func(c *assertionCase) {
				c.tamper = func(sig []byte) []byte {
					out := bytes.Clone(sig)
					out[len(out)-1] ^= 1

					return out
				}
			},
			want: ErrAssertion,
		},
	}

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

func TestVerifyAssertionRefusesMalformedEncodings(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edit func(*Assertion)
		want error
	}{
		"clientDataJSON padded": {
			edit: func(a *Assertion) { a.ClientDataJSON += "=" },
			want: ErrClientData,
		},
		"clientDataJSON oversized": {
			edit: func(a *Assertion) {
				a.ClientDataJSON = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, MaxClientDataJSON+1))
			},
			want: ErrClientData,
		},
		"authenticatorData with a line break": {
			edit: func(a *Assertion) { a.AuthenticatorData = a.AuthenticatorData[:4] + "\n" + a.AuthenticatorData[4:] },
			want: ErrAuthData,
		},
		"signature oversized": {
			edit: func(a *Assertion) {
				a.Signature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, MaxSignature+1))
			},
			want: ErrAssertion,
		},
		"signature not base64url": {
			edit: func(a *Assertion) { a.Signature = notBase64 },
			want: ErrAssertion,
		},
		"user handle not base64url": {
			edit: func(a *Assertion) { a.UserHandle = notBase64 },
			want: ErrAssertion,
		},
		"rawId empty": {
			edit: func(a *Assertion) { a.RawID = "" },
			want: ErrAssertion,
		},
		"rawId oversized": {
			edit: func(a *Assertion) {
				a.RawID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, maxCredentialIDLen+1))
			},
			want: ErrAssertion,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := validAssertion(t)
			a := c.build(t)
			tt.edit(&a)

			_, err := verifyAssertion(a, c.stored(t), testRP())
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want it to wrap %v", err, tt.want)
			}
		})
	}
}

func TestVerifyAssertionRefusesBadStoredKeys(t *testing.T) {
	t.Parallel()

	c := validAssertion(t)
	good := c.stored(t)

	notOnCurve := mustCBOR(t, coseMap{
		1: 2, 3: -7, -1: 1,
		-2: bytes.Repeat([]byte{1}, 32), -3: bytes.Repeat([]byte{2}, 32),
	})
	wrongAlg := mustCBOR(t, keyWith(t, func(k coseMap) { k[3] = -257 }))

	tests := map[string][]byte{
		"garbage":      []byte("not cbor"),
		emptyCase:      nil,
		"not on curve": notOnCurve,
		"not ES256":    wrongAlg,
		"trailing":     append(bytes.Clone(good.PublicKey), 0),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			stored := good
			stored.PublicKey = key

			_, err := verifyAssertion(c.build(t), stored, testRP())
			if !errors.Is(err, ErrPublicKey) {
				t.Errorf("err = %v, want it to wrap %v", err, ErrPublicKey)
			}
		})
	}
}

func TestStoredKeyFailsWhenTheDecoderCannotBeBuilt(t *testing.T) {
	t.Parallel()

	_, err := storedKey(cbor.DecOptions{MaxNestedLevels: 1}, validAssertion(t).cose(t))
	if !errors.Is(err, ErrPublicKey) {
		t.Errorf("err = %v, want it to wrap %v", err, ErrPublicKey)
	}
}

// paddableSignature returns an ES256 signature over digest whose r has no high
// bit and whose lengths are short-form, so each of the non-canonical spellings
// below can be built from it. It retries because only some signatures qualify.
func paddableSignature(tb testing.TB, key *ecdsa.PrivateKey, digest []byte) []byte {
	tb.Helper()

	for range 256 {
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			tb.Fatalf("sign: %v", err)
		}

		if sig[1] < 0x80 && sig[4] < 0x80 {
			return sig
		}
	}

	tb.Fatal("could not get a signature that can be padded")

	return nil
}

// nonCanonicalSpellings are other ways to write the DER of sig.
func nonCanonicalSpellings(sig []byte) map[string][]byte {
	// uint8 conversions of lengths that are all below 0x80 here (checked by
	// paddableSignature), so none can overflow.
	rLen := sig[3]
	padded := append([]byte{0x02, rLen + 1, 0x00}, sig[4:4+int(rLen)]...)
	padded = append(padded, sig[4+int(rLen):]...)

	return map[string][]byte{
		"trailing byte":      append(bytes.Clone(sig), 0),
		"long-form length":   append([]byte{0x30, 0x81, sig[1]}, sig[2:]...),
		"indefinite length":  append(append([]byte{0x30, 0x80}, sig[2:]...), 0, 0),
		"padded integer":     append([]byte{0x30, byte(len(padded))}, padded...), //nolint:gosec // short-form, below 0x80
		"leading zero bytes": append([]byte{0}, sig...),
	}
}

// TestSignatureHasOneSpelling pins the property verifyES256 relies on: the
// standard library's ASN.1 verifier accepts only the one strict DER encoding of
// a signature. If a future Go release relaxed that, this fails.
func TestSignatureHasOneSpelling(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	digest := sha256.Sum256([]byte("message"))
	sig := paddableSignature(t, key, digest[:])

	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatal("the canonical signature was refused")
	}

	for name, variant := range nonCanonicalSpellings(sig) {
		if ecdsa.VerifyASN1(&key.PublicKey, digest[:], variant) {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestParseAssertionReturnsTheRawID(t *testing.T) {
	t.Parallel()

	c := validAssertion(t)

	parsed, err := ParseAssertion(c.build(t), testRP())
	if err != nil || !bytes.Equal(parsed.CredentialID, c.credID) || string(parsed.Challenge) != testChalText {
		t.Errorf("ParseAssertion = %x, %q, %v, want %x, %q",
			parsed.CredentialID, parsed.Challenge, err, c.credID, testChalText)
	}
}

// TestParseAssertionNeedsNoStoredCredential pins the split the login handler
// relies on to refuse before reading its database: parsing accepts what only
// the stored credential can refuse (another account's handle, a changed
// backup eligibility, another key's signature), and Verify refuses each.
func TestParseAssertionNeedsNoStoredCredential(t *testing.T) {
	t.Parallel()

	c := validAssertion(t)

	parsed, err := ParseAssertion(c.build(t), testRP())
	if err != nil {
		t.Fatalf("ParseAssertion: %v", err)
	}

	other := validAssertion(t)
	mismatches := map[string]func(*Stored){
		"another account": func(s *Stored) { s.UserHandle = []byte("someone-else") },
		"backup eligible": func(s *Stored) { s.Flags |= FlagBackupEligible },
		"another key":     func(s *Stored) { s.PublicKey = other.cose(t) },
	}

	for name, edit := range mismatches {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			stored := c.stored(t)
			edit(&stored)

			_, err := parsed.Verify(stored)
			if err == nil {
				t.Error("Verify accepted a mismatching stored credential")
			}
		})
	}
}

// TestAssertionClientDataIsStrict pins that the login path reads clientDataJSON
// as strictly as registration does, using a case registration is tested on.
func TestAssertionClientDataIsStrict(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"type":"webauthn.get","challenge":"AAAA","origin":"` + testOrigin + `","crossOrigin":null}`)

	_, _, err := ParseAssertionClientData(raw, testRP())
	if !errors.Is(err, ErrClientData) || !strings.Contains(err.Error(), "crossOrigin") {
		t.Errorf("err = %v, want a crossOrigin refusal", err)
	}
}
