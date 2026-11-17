package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestVerifyAccepts(t *testing.T) {
	t.Parallel()

	resp := validResponse(t)

	got, err := Verify(resp.build(t), testRP())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if string(got.Challenge) != testChalText {
		t.Errorf("challenge = %q, want %q", got.Challenge, testChalText)
	}

	cred := got.Credential

	if !bytes.Equal(cred.ID, resp.credID) {
		t.Errorf("credential id = %x, want %x", cred.ID, resp.credID)
	}

	if cred.AAGUID != resp.aaguid {
		t.Errorf("aaguid = %x, want %x", cred.AAGUID, resp.aaguid)
	}

	if cred.Flags != FlagUserPresent|FlagUserVerified|flagAttestedCredentialData {
		t.Errorf("flags = %08b", cred.Flags)
	}

	if cred.Flags.Stored() != uint8(FlagUserPresent|FlagUserVerified) {
		t.Errorf("stored flags = %08b, want UP|UV only", cred.Flags.Stored())
	}

	if strings.Join(cred.Transports, ",") != transportHybrid+","+transportInternal {
		t.Errorf("transports = %v", cred.Transports)
	}

	// The stored key is our canonical re-encoding of the validated parts.
	if !bytes.Equal(cred.PublicKey, mustCBOR(t, resp.key)) {
		t.Errorf("public key = %x, want the canonical encoding %x", cred.PublicKey, mustCBOR(t, resp.key))
	}
}

func TestVerifyKeepsBackupBits(t *testing.T) {
	t.Parallel()

	resp := validResponse(t)
	resp.flags |= byte(FlagBackupEligible | FlagBackupState)

	got, err := Verify(resp.build(t), testRP())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	want := uint8(FlagUserPresent | FlagUserVerified | FlagBackupEligible | FlagBackupState)
	if got.Credential.Flags.Stored() != want {
		t.Errorf("stored flags = %08b, want %08b", got.Credential.Flags.Stored(), want)
	}
}

// rejection is one way a response can be refused: mutate edits the response
// before it is built, edit changes the built Registration. A case uses one.
type rejection struct {
	mutate  func(r *response)
	edit    func(reg *Registration)
	wantErr error
}

func runRejections(t *testing.T, tests map[string]rejection) {
	t.Helper()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp := validResponse(t)

			if tt.mutate != nil {
				tt.mutate(&resp)
			}

			reg := resp.build(t)

			if tt.edit != nil {
				tt.edit(&reg)
			}

			got, err := Verify(reg, testRP())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify error = %v, want %v", err, tt.wantErr)
			}

			if len(got.Challenge) != 0 || len(got.Credential.ID) != 0 || len(got.Credential.PublicKey) != 0 {
				t.Errorf("Verify returned %+v alongside an error", got)
			}
		})
	}
}

// maxAttestationObjectForTest is spare capacity for hand-built CBOR in tests.
const maxAttestationObjectForTest = 256

func b64Of(n int) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("a"), n)) }

func TestVerifyRejectsClientData(t *testing.T) {
	t.Parallel()

	setClient := func(key string, value any) func(*response) {
		return func(r *response) { r.clientData[key] = value }
	}

	dropMember := func(key string) func(*response) {
		return func(r *response) { delete(r.clientData, key) }
	}

	runRejections(t, map[string]rejection{
		"not base64url": {edit: func(reg *Registration) { reg.ClientDataJSON = "!!!" }, wantErr: ErrClientData},
		"too large": {
			edit:    func(reg *Registration) { reg.ClientDataJSON = b64Of(MaxClientDataJSON + 1) },
			wantErr: ErrClientData,
		},
		emptyCase:             {edit: func(reg *Registration) { reg.ClientDataJSON = "" }, wantErr: ErrClientData},
		"wrong ceremony type": {mutate: setClient("type", "webauthn.get"), wantErr: ErrClientData},
		"wrong origin":        {mutate: setClient("origin", "https://evil.example.com"), wantErr: ErrClientData},
		"origin plus a slash": {mutate: setClient("origin", testOrigin+"/"), wantErr: ErrClientData},
		"origin is a longer host": {
			mutate: setClient("origin", testOrigin+".evil.com"), wantErr: ErrClientData,
		},
		"cross origin":                  {mutate: setClient("crossOrigin", true), wantErr: ErrClientData},
		"top origin present":            {mutate: setClient("topOrigin", testOrigin), wantErr: ErrClientData},
		"cross origin is not a boolean": {mutate: setClient("crossOrigin", "false"), wantErr: ErrClientData},
		"challenge is not base64url":    {mutate: setClient("challenge", notBase64), wantErr: ErrClientData},
		"challenge is empty":            {mutate: setClient("challenge", ""), wantErr: ErrClientData},
		"challenge is missing":          {mutate: dropMember("challenge"), wantErr: ErrClientData},
		"origin is not a string":        {mutate: setClient("origin", 7), wantErr: ErrClientData},
		"type is missing":               {mutate: dropMember("type"), wantErr: ErrClientData},
		"origin is missing":             {mutate: dropMember("origin"), wantErr: ErrClientData},
	})
}

func TestVerifyRejectsAttestationObject(t *testing.T) {
	t.Parallel()

	runRejections(t, map[string]rejection{
		"not base64url": {edit: func(reg *Registration) { reg.AttestationObject = "!!!" }, wantErr: ErrAttestation},
		"too large": {
			edit:    func(reg *Registration) { reg.AttestationObject = b64Of(MaxAttestationObject + 1) },
			wantErr: ErrAttestation,
		},
		"not CBOR": {
			mutate:  func(r *response) { r.rawAttObject = []byte("not cbor") },
			wantErr: ErrAttestation,
		},
		"format is packed": {mutate: func(r *response) { r.format = "packed" }, wantErr: ErrAttestation},
		"statement is not empty": {
			mutate:  func(r *response) { r.attStmt = map[string]any{"alg": -7, "sig": []byte{1}} },
			wantErr: ErrAttestation,
		},
	})
}

// rawObject builds an attestation object from the response's authData with the
// given extra members, for cases a Go map cannot express.
func rawObject(t *testing.T, r response, mutate func([]byte) []byte) func(*response) {
	t.Helper()

	return func(resp *response) {
		object := mustCBOR(t, map[string]any{
			memberFmt: noneFormat, memberAttStmt: map[string]any{}, memberAuthData: r.authData(t),
		})
		resp.rawAttObject = mutate(object)
	}
}

func TestVerifyRejectsMalformedAttestationCBOR(t *testing.T) {
	t.Parallel()

	base := validResponse(t)

	runRejections(t, map[string]rejection{
		"unknown member": {
			mutate: func(r *response) {
				r.rawAttObject = mustCBOR(t, map[string]any{
					memberFmt: noneFormat, memberAttStmt: map[string]any{}, memberAuthData: base.authData(t), "extra": 1,
				})
			},
			wantErr: ErrAttestation,
		},
		"trailing bytes": {
			mutate:  rawObject(t, base, func(o []byte) []byte { return append(o, 0x00) }),
			wantErr: ErrAttestation,
		},
		"duplicate key": {
			mutate: func(r *response) {
				// {"fmt":"none","fmt":"none",...} by hand: a Go map cannot hold a duplicate.
				obj := make([]byte, 1, maxAttestationObjectForTest)
				obj[0] = 0xa4

				for _, item := range []any{memberFmt, noneFormat, memberFmt, noneFormat, memberAttStmt} {
					obj = append(obj, mustCBOR(t, item)...)
				}

				obj = append(obj, 0xa0)
				obj = append(obj, mustCBOR(t, memberAuthData)...)
				obj = append(obj, mustCBOR(t, base.authData(t))...)
				r.rawAttObject = obj
			},
			wantErr: ErrAttestation,
		},
		"indefinite-length map": {
			mutate: func(r *response) {
				obj := make([]byte, 1, maxAttestationObjectForTest)
				obj[0] = 0xbf
				obj = append(obj, mustCBOR(t, memberFmt)...)
				obj = append(obj, mustCBOR(t, noneFormat)...)
				obj = append(obj, 0xff)
				r.rawAttObject = obj
			},
			wantErr: ErrAttestation,
		},
	})
}

func TestVerifyRejectsAuthenticatorData(t *testing.T) {
	t.Parallel()

	unset := func(flag Flags) func(*response) {
		return func(r *response) { r.flags &^= byte(flag) }
	}

	set := func(bits byte) func(*response) {
		return func(r *response) { r.flags |= bits }
	}

	idLen := func(n uint16) func(*response) {
		return func(r *response) { r.idLenOverride = &n }
	}

	runRejections(t, map[string]rejection{
		"rp id hash is for another rp": {mutate: func(r *response) { r.rpID = "evil.example.com" }, wantErr: ErrAuthData},
		"user presence not set":        {mutate: unset(FlagUserPresent), wantErr: ErrAuthData},
		"user verification not set":    {mutate: unset(FlagUserVerified), wantErr: ErrAuthData},
		"no attested credential data":  {mutate: unset(flagAttestedCredentialData), wantErr: ErrAuthData},
		"extension data flag set":      {mutate: set(byte(flagExtensionData)), wantErr: ErrAuthData},
		"reserved bit 1 set":           {mutate: set(1 << 1), wantErr: ErrAuthData},
		"reserved bit 5 set":           {mutate: set(1 << 5), wantErr: ErrAuthData},
		"backup state without backup eligibility": {
			mutate: set(byte(FlagBackupState)), wantErr: ErrAuthData,
		},
		"too short": {
			mutate: func(r *response) {
				r.rawAttObject = mustCBOR(t, map[string]any{
					memberFmt: noneFormat, memberAttStmt: map[string]any{}, memberAuthData: []byte{1, 2, 3},
				})
			},
			wantErr: ErrAuthData,
		},
		"credential id length zero":        {mutate: idLen(0), wantErr: ErrAuthData},
		"credential id length over limit":  {mutate: idLen(maxCredentialIDLen + 1), wantErr: ErrAuthData},
		"credential id runs past the data": {mutate: idLen(1000), wantErr: ErrAuthData},
		"bytes after the public key":       {mutate: func(r *response) { r.trailing = []byte{0x00} }, wantErr: ErrPublicKey},
	})
}

func TestVerifyRejectsMismatchedCredentialID(t *testing.T) {
	t.Parallel()

	other := base64.RawURLEncoding.EncodeToString([]byte("other"))

	runRejections(t, map[string]rejection{
		"reported id differs":          {edit: func(reg *Registration) { reg.ID = other }, wantErr: ErrAuthData},
		"reported raw id differs":      {edit: func(reg *Registration) { reg.RawID = other }, wantErr: ErrAuthData},
		"reported id is not base64url": {edit: func(reg *Registration) { reg.ID = notBase64 }, wantErr: ErrAuthData},
	})
}

func TestVerifyRejectsRawClientData(t *testing.T) {
	t.Parallel()

	valid := `"type":"webauthn.create","challenge":"AAAA","origin":"` + testOrigin + `"`

	tests := map[string]string{
		"not JSON":              `nope`,
		"JSON array":            `[]`,
		"JSON string":           `"x"`,
		"empty object":          `{}`,
		"truncated":             `{"type":"webauthn.create"`,
		"duplicate type":        `{"type":"webauthn.get",` + valid + `}`,
		"duplicate origin":      `{"origin":"https://evil",` + valid + `}`,
		"differently cased":     `{"Type":"webauthn.create","challenge":"AAAA","origin":"` + testOrigin + `"}`,
		"trailing data":         `{` + valid + `} {}`,
		"trailing garbage":      `{` + valid + `}x`,
		"non-string key":        `{1:2}`,
		"unterminated object":   `{` + valid,
		"unterminated key":      `{"type"`,
		"lone open brace":       `{`,
		"wrong closing bracket": `{"type":"webauthn.create"]`,
		"bad value":             `{"type":}`,
		"type is not a string":  `{"type":1,"challenge":"AAAA","origin":"` + testOrigin + `"}`,
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp := validResponse(t)
			resp.rawClient = []byte(raw)

			_, err := Verify(resp.build(t), testRP())
			if !errors.Is(err, ErrClientData) {
				t.Errorf("Verify error = %v, want ErrClientData", err)
			}
		})
	}
}

// TestVerifyIgnoresUnknownClientDataMembers pins the one place we are lenient:
// the spec allows extra members, so they must not fail an honest browser.
func TestVerifyIgnoresUnknownClientDataMembers(t *testing.T) {
	t.Parallel()

	resp := validResponse(t)
	resp.clientData["crossOrigin"] = false
	resp.clientData["other_keys_can_be_added_here"] = "do not compare clientDataJSON against a template"

	_, err := Verify(resp.build(t), testRP())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestParseClientDataReturnsHash(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"type":"webauthn.create","challenge":"AAAA","origin":"` + testOrigin + `"}`)

	challenge, hash, err := ParseClientData(raw, testRP())
	if err != nil {
		t.Fatalf("ParseClientData: %v", err)
	}

	if !bytes.Equal(challenge, []byte{0, 0, 0}) {
		t.Errorf("challenge = %x, want 000000", challenge)
	}

	if hash != sha256.Sum256(raw) {
		t.Errorf("hash = %x, want the SHA-256 of the raw JSON", hash)
	}
}

func TestPublicKeyRejects(t *testing.T) {
	t.Parallel()

	drop := func(labels ...int64) func(coseMap) {
		return func(k coseMap) {
			for _, label := range labels {
				delete(k, label)
			}
		}
	}

	put := func(label int64, value any) func(coseMap) {
		return func(k coseMap) { k[label] = value }
	}

	withKey := func(edit func(coseMap)) func(*response) {
		return func(r *response) { r.key = keyWith(t, edit) }
	}

	withRaw := func(raw []byte) func(*response) {
		return func(r *response) { r.key = raw }
	}

	canonical := mustCBOR(t, validKey(t))
	duplicateLabel := append([]byte{0xa6, 0x01, 0x02, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01},
		append(mustCBOR(t, int64(-2)), mustCBOR(t, make([]byte, 32))...)...)

	runRejections(t, map[string]rejection{
		"wrong key type":      {mutate: withKey(put(1, 3)), wantErr: ErrPublicKey},
		"missing key type":    {mutate: withKey(drop(1)), wantErr: ErrPublicKey},
		"wrong algorithm":     {mutate: withKey(put(3, -257)), wantErr: ErrPublicKey},
		"missing algorithm":   {mutate: withKey(drop(3)), wantErr: ErrPublicKey},
		"wrong curve":         {mutate: withKey(put(-1, 2)), wantErr: ErrPublicKey},
		"missing curve":       {mutate: withKey(drop(-1)), wantErr: ErrPublicKey},
		"short x":             {mutate: withKey(put(-2, []byte{1, 2, 3})), wantErr: ErrPublicKey},
		"short y":             {mutate: withKey(put(-3, []byte{1, 2, 3})), wantErr: ErrPublicKey},
		"missing coordinates": {mutate: withKey(drop(-2, -3)), wantErr: ErrPublicKey},
		"point not on curve":  {mutate: withKey(put(-3, make([]byte, 32))), wantErr: ErrPublicKey},
		"private key present": {mutate: withKey(put(-4, make([]byte, 32))), wantErr: ErrPublicKey},
		"unknown parameter":   {mutate: withKey(put(4, []byte{1})), wantErr: ErrPublicKey},
		"not a map":           {mutate: withRaw([]byte{1, 2, 3}), wantErr: ErrPublicKey},
		"duplicate label":     {mutate: withRaw(duplicateLabel), wantErr: ErrPublicKey},
		emptyCase:             {mutate: withRaw([]byte{}), wantErr: ErrPublicKey},
		"tagged":              {mutate: withRaw(append([]byte{0xc1}, canonical...)), wantErr: ErrPublicKey},
	})
}

func TestVerifyFailsWhenDecoderCannotBeBuilt(t *testing.T) {
	t.Parallel()

	_, err := verifyWith(cbor.DecOptions{MaxNestedLevels: 1}, validResponse(t).build(t), testRP())
	if !errors.Is(err, ErrAttestation) {
		t.Errorf("verifyWith error = %v, want ErrAttestation", err)
	}
}

func TestNewDecoderRejectsBadOptions(t *testing.T) {
	t.Parallel()

	_, err := newDecoder(cbor.DecOptions{MaxNestedLevels: 1}, cbor.CTAP2EncOptions()) // below the library's minimum of 4
	if err == nil {
		t.Fatal("newDecoder accepted invalid options")
	}
}

func TestNewDecoderRejectsBadEncodingOptions(t *testing.T) {
	t.Parallel()

	_, err := newDecoder(strictOptions(), cbor.EncOptions{Sort: cbor.SortMode(99)})
	if err == nil {
		t.Fatal("newDecoder accepted invalid encoding options")
	}
}

// Transport values (section 5.8.4) the transport tests use more than once.
const (
	transportNFC      = "nfc"
	transportUSB      = "usb"
	transportHybrid   = "hybrid"
	transportInternal = "internal"
)

// verifyTransports runs Verify on a valid registration that reports
// transports, and fails the test if the caller's slice is modified.
func verifyTransports(t *testing.T, transports []string) (Verified, error) {
	t.Helper()

	reg := validResponse(t).build(t)
	reg.Transports = transports
	original := slices.Clone(transports)

	got, err := Verify(reg, testRP())

	if !slices.Equal(reg.Transports, original) {
		t.Errorf("Verify modified the caller's transports: %v, was %v", reg.Transports, original)
	}

	return got, err
}

// distinct returns n distinct printable-ASCII transports, in descending order
// so a list of them is never already sorted.
func distinct(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("t%03d", n-i)
	}

	return out
}

// repeated returns n copies of transport.
func repeated(transport string, n int) []string {
	return slices.Repeat([]string{transport}, n)
}

// TestVerifyCanonicalizesTransports covers the transport hints. Section 5.2.1
// says clients report them sorted and unique, but real providers do not (one
// sent "hybrid" after "internal"), and the hints are not security-relevant, so
// Verify accepts any order and repeats and stores a canonical list: sorted,
// duplicates removed. Unknown values are kept, and nothing is truncated.
func TestVerifyCanonicalizesTransports(t *testing.T) {
	t.Parallel()

	maxLen := strings.Repeat("z", maxTransportLen)

	tests := map[string]struct {
		sent []string
		want []string
	}{
		"none":       {sent: nil, want: nil},
		"empty list": {sent: []string{}, want: []string{}},
		"already canonical": {
			sent: []string{transportHybrid, transportInternal},
			want: []string{transportHybrid, transportInternal},
		},
		"an unknown value": {
			sent: []string{"carrier-pigeon", transportInternal},
			want: []string{"carrier-pigeon", transportInternal},
		},
		"out of order, as providers send": {
			sent: []string{transportInternal, transportHybrid},
			want: []string{transportHybrid, transportInternal},
		},
		"reverse sorted": {sent: []string{transportUSB, transportNFC}, want: []string{transportNFC, transportUSB}},
		"a duplicate":    {sent: []string{transportNFC, transportNFC}, want: []string{transportNFC}},
		"unsorted with scattered duplicates": {
			sent: []string{transportUSB, transportNFC, transportUSB, transportInternal, transportNFC},
			want: []string{transportInternal, transportNFC, transportUSB},
		},
		"an entry of the maximum length, out of order": {
			sent: []string{maxLen, "a"},
			want: []string{"a", maxLen},
		},
		"the most entries allowed": {
			sent: distinct(MaxTransports),
			want: slices.Sorted(slices.Values(distinct(MaxTransports))),
		},
		"the most entries allowed, all repeats": {
			sent: repeated("a", MaxTransports),
			want: []string{"a"},
		},
		"the most entries allowed, half repeats": {
			sent: slices.Concat(distinct(MaxTransports/2), distinct(MaxTransports/2)),
			want: slices.Sorted(slices.Values(distinct(MaxTransports / 2))),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := verifyTransports(t, tt.sent)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}

			if !slices.Equal(got.Credential.Transports, tt.want) || (got.Credential.Transports == nil) != (tt.want == nil) {
				t.Errorf("transports = %#v, want %#v", got.Credential.Transports, tt.want)
			}
		})
	}
}

// TestVerifyRefusesBadTransports covers what is still refused, whole and not
// truncated: a list over the count limit (counted as sent, so repeats do not
// hide a flood and the list is refused before it is sorted), or an entry that
// is empty, over the length limit or not printable ASCII, wherever it sits in
// the list.
func TestVerifyRefusesBadTransports(t *testing.T) {
	t.Parallel()

	overLen := strings.Repeat("z", maxTransportLen+1)

	tests := map[string][]string{
		"one over the count limit":                 distinct(MaxTransports + 1),
		"one over, though every entry is a repeat": repeated("a", MaxTransports+1),
		"one over, though they merge below the limit": slices.Concat(
			distinct(MaxTransports/2), distinct(MaxTransports/2), []string{"x"}),
		"far over the count limit":               repeated("a", 100000),
		"one entry one byte too long":            {overLen},
		"too long, among valid unsorted entries": {transportUSB, overLen, transportNFC},
		"far too long":                           {strings.Repeat("z", 20000)},
		"an empty entry":                         {""},
		"an empty entry, last":                   {transportUSB, transportNFC, ""},
		"a control":                              {transportUSB + "\t"},
		"a NUL":                                  {transportUSB + "\x00"},
		"DEL":                                    {transportUSB + "\x7f"},
		"non-ASCII":                              {"us\u00e9"},
		"a bad entry after a good one":           {transportUSB, "us\u00e9"},
		"a bad entry at the count limit":         append(distinct(MaxTransports-1), ""),
	}

	for name, sent := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := verifyTransports(t, sent)
			if !errors.Is(err, ErrTransports) {
				t.Errorf("Verify error = %v, want ErrTransports", err)
			}

			if got.Credential.Transports != nil || got.Challenge != nil {
				t.Errorf("a refused registration returned a partial result: %+v", got)
			}
		})
	}
}

func TestEncodeCanonicalRejectsBadOptions(t *testing.T) {
	t.Parallel()

	_, err := encodeCanonical(cbor.EncOptions{Sort: cbor.SortMode(99)}, coseKey{})
	if !errors.Is(err, ErrPublicKey) {
		t.Errorf("encodeCanonical error = %v, want ErrPublicKey", err)
	}
}

func TestEncodeCanonicalRejectsUnencodableValue(t *testing.T) {
	t.Parallel()

	_, err := encodeCanonical(cbor.CTAP2EncOptions(), func() {})
	if !errors.Is(err, ErrPublicKey) {
		t.Errorf("encodeCanonical error = %v, want ErrPublicKey", err)
	}
}
