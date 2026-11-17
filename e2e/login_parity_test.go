//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

// This file sends the Worker the login inputs a security review compared
// against github.com/go-webauthn/webauthn. The host tests cover the same cases
// under Go; these prove the TinyGo build agrees, because the signature check
// (crypto/ecdsa and its ASN.1 parsing) and the JSON readers run as TinyGo
// compiled them. Every refusal must be the one invalid_login answer and must
// write nothing.

// Member names and values of the finish body.
const (
	publicKeyType    = "public-key"
	responseMember   = "response"
	clientDataMember = "clientDataJSON"
	rawIDMember      = "rawId"
)

// signedLogin is a signed answer to one set of request options, kept in parts
// so a test can change any of them after signing.
type signedLogin struct {
	pk       passkey
	client   []byte
	authData []byte
	sig      []byte
}

// sign answers options honestly, signing over client (the default
// clientDataJSON when nil).
func (pk passkey) sign(t *testing.T, options requestOptions, client []byte) signedLogin {
	t.Helper()

	a := pk.assertion()
	if client == nil {
		client = a.clientData(t, options)
	}

	authData := a.authDataPrefix()
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))

	sig, err := ecdsa.SignASN1(rand.Reader, pk.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signedLogin{pk: pk, client: client, authData: authData, sig: sig}
}

// body is the finish request for s, with extra top-level members merged in.
func (s signedLogin) body(t *testing.T, extra map[string]any) string {
	t.Helper()

	id := base64.RawURLEncoding.EncodeToString(s.pk.credID)
	members := map[string]any{
		"id": id, rawIDMember: id, typeMember: publicKeyType,
		responseMember: map[string]any{
			clientDataMember:    base64.RawURLEncoding.EncodeToString(s.client),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(s.authData),
			"signature":         base64.RawURLEncoding.EncodeToString(s.sig),
			"userHandle":        base64.RawURLEncoding.EncodeToString(s.pk.handle),
		},
	}

	maps.Copy(members, extra)

	out, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("body: %v", err)
	}

	return string(out)
}

// withSig returns s with its signature replaced.
func (s signedLogin) withSig(sig []byte) signedLogin {
	s.sig = sig

	return s
}

type derSignature struct {
	R, S *big.Int
}

func splitSignature(t *testing.T, der []byte) derSignature {
	t.Helper()

	var sig derSignature

	_, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		t.Fatalf("parse signature: %v", err)
	}

	return sig
}

func joinSignature(t *testing.T, r, s *big.Int) []byte {
	t.Helper()

	out, err := asn1.Marshal(derSignature{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal signature: %v", err)
	}

	return out
}

// padR re-encodes der with one redundant zero byte in front of r: valid BER,
// not DER. A P-256 signature is at most 72 bytes, so every length is short-form.
func padR(der []byte) []byte {
	rLen := der[3]
	inner := make([]byte, 0, len(der))
	inner = append(inner, 0x02, rLen+1, 0x00)
	inner = append(inner, der[4:4+int(rLen)]...)
	inner = append(inner, der[4+int(rLen):]...)

	return append([]byte{0x30, der[1] + 1}, inner...)
}

// expectRefused posts body and requires the one refusal, with no cookie.
func expectRefused(t *testing.T, body string) {
	t.Helper()

	got := call(t, http.MethodPost, loginPath+"/finish", []byte(body), "")
	if got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"`+codeInvalid+`"`) {
		t.Errorf("finish = %d %s, want 401 %s", got.status, got.body, codeInvalid)
	}

	if got.session() != "" {
		t.Error("a refused login set a session cookie")
	}
}

// expectAccepted posts body and requires a session.
func expectAccepted(t *testing.T, body string) {
	t.Helper()

	got := call(t, http.MethodPost, loginPath+"/finish", []byte(body), "")
	if got.status != http.StatusOK || got.session() == "" {
		t.Errorf("finish = %d %s, want 200 with a session cookie", got.status, got.body)
	}
}

// TestLoginSignatureUnderTinyGo checks the ES256 verifier as TinyGo built it:
// it accepts exactly one DER spelling of a signature, refuses scalars outside
// [1, n-1] and bytes changed after signing, and accepts the malleated (r, n-s),
// which must not reopen replay.
//
//nolint:paralleltest // shares one database with the other tests
func TestLoginSignatureUnderTinyGo(t *testing.T) {
	pk := registerPasskey(t)
	n := elliptic.P256().Params().N

	spellings := map[string]func([]byte) []byte{
		"trailing byte":      func(der []byte) []byte { return append(bytes.Clone(der), 0) },
		"leading zero byte":  func(der []byte) []byte { return append([]byte{0}, der...) },
		"long-form length":   func(der []byte) []byte { return append([]byte{0x30, 0x81, der[1]}, der[2:]...) },
		"indefinite length":  func(der []byte) []byte { return append(append([]byte{0x30, 0x80}, der[2:]...), 0, 0) },
		"BER-padded integer": padR,
		"empty":              func([]byte) []byte { return nil },
	}

	for name, edit := range spellings {
		t.Run("spelling "+name, func(t *testing.T) {
			s := pk.sign(t, beginLogin(t), nil)
			expectRefused(t, s.withSig(edit(s.sig)).body(t, nil))
		})
	}

	scalars := map[string]func(derSignature) (*big.Int, *big.Int){
		"r zero":   func(sig derSignature) (*big.Int, *big.Int) { return big.NewInt(0), sig.S },
		"s zero":   func(sig derSignature) (*big.Int, *big.Int) { return sig.R, big.NewInt(0) },
		"s is n":   func(sig derSignature) (*big.Int, *big.Int) { return sig.R, new(big.Int).Set(n) },
		"s plus n": func(sig derSignature) (*big.Int, *big.Int) { return sig.R, new(big.Int).Add(sig.S, n) },
		"r plus n": func(sig derSignature) (*big.Int, *big.Int) { return new(big.Int).Add(sig.R, n), sig.S },
	}

	for name, edit := range scalars {
		t.Run("scalar "+name, func(t *testing.T) {
			s := pk.sign(t, beginLogin(t), nil)
			r, sv := edit(splitSignature(t, s.sig))
			expectRefused(t, s.withSig(joinSignature(t, r, sv)).body(t, nil))
		})
	}

	expectCount(t, "japikeys", "0")
}

// TestLoginSignatureCoversTheBytesUnderTinyGo checks that the signature covers
// authenticator data and clientDataJSON as sent, and that the malleated
// (r, n-s), which verifies, does not reopen replay.
//
//nolint:paralleltest // shares one database with the other tests
func TestLoginSignatureCoversTheBytesUnderTinyGo(t *testing.T) {
	pk := registerPasskey(t)
	n := elliptic.P256().Params().N

	t.Run("counter changed after signing", func(t *testing.T) {
		s := pk.sign(t, beginLogin(t), nil)
		s.authData = bytes.Clone(s.authData)
		s.authData[len(s.authData)-1] ^= 1
		expectRefused(t, s.body(t, nil))
	})

	t.Run("clientDataJSON respaced after signing", func(t *testing.T) {
		s := pk.sign(t, beginLogin(t), nil)
		s.client = append(bytes.Clone(s.client), ' ')
		expectRefused(t, s.body(t, nil))
	})

	expectCount(t, "japikeys", "0")

	t.Run("high-S is accepted and does not reopen replay", func(t *testing.T) {
		s := pk.sign(t, beginLogin(t), nil)
		sig := splitSignature(t, s.sig)
		malleated := s.withSig(joinSignature(t, sig.R, new(big.Int).Sub(n, sig.S)))

		// Both spellings verify; whichever arrives first spends the challenge.
		expectAccepted(t, malleated.body(t, nil))
		expectRefused(t, s.body(t, nil))
		expectRefused(t, malleated.body(t, nil))

		expectCount(t, "japikeys", "1")
	})
}

// TestLoginParsersUnderTinyGo checks the strict readers as TinyGo built them,
// on inputs go-webauthn accepts.
//
//nolint:paralleltest // shares one database with the other tests
func TestLoginParsersUnderTinyGo(t *testing.T) {
	pk := registerPasskey(t)

	clientFor := func(options requestOptions, members string) []byte {
		return []byte(`{"type":"webauthn.get","challenge":"` + options.PublicKey.Challenge + `",` + members + `}`)
	}
	ours := `"origin":"` + target.origin + `"`

	// clientDataJSON members after type and challenge.
	clientRefusals := map[string]string{
		"origin repeated, evil first": `"origin":"https://evil.example",` + ours,
		"topOrigin empty":             ours + `,"topOrigin":""`,
		"crossOrigin null":            ours + `,"crossOrigin":null`,
		"origin in upper case":        `"origin":"` + strings.ToUpper(target.origin) + `"`,
		"origin with a path":          `"origin":"` + target.origin + `/evil"`,
	}

	for name, members := range clientRefusals {
		t.Run(name, func(t *testing.T) {
			options := beginLogin(t)
			expectRefused(t, pk.sign(t, options, clientFor(options, members)).body(t, nil))
		})
	}

	id := base64.RawURLEncoding.EncodeToString(pk.credID)
	handle := base64.RawURLEncoding.EncodeToString(pk.handle)

	// Text edits of an honest body.
	bodyRefusals := map[string][2]string{
		"rawId padded":      {`"rawId":"` + id + `"`, `"rawId":"` + id + `="`},
		"userHandle padded": {`"userHandle":"` + handle + `"`, `"userHandle":"` + handle + `="`},
	}

	for name, edit := range bodyRefusals {
		t.Run(name, func(t *testing.T) {
			expectRefused(t, strings.Replace(pk.sign(t, beginLogin(t), nil).body(t, nil), edit[0], edit[1], 1))
		})
	}

	// The body is read before the assertion, so a body go-webauthn would read
	// case-insensitively is a malformed request (400), not a failed login.
	t.Run("response member in another case", func(t *testing.T) {
		body := strings.Replace(pk.sign(t, beginLogin(t), nil).body(t, nil), `"signature"`, `"Signature"`, 1)

		got := call(t, http.MethodPost, loginPath+"/finish", []byte(body), "")
		if got.status != http.StatusBadRequest || !strings.Contains(got.body, `"unknown_field"`) {
			t.Errorf("finish = %d %s, want 400 unknown_field", got.status, got.body)
		}
	})

	expectCount(t, "japikeys", "0")

	// A member that differs from origin only in case is read as the origin
	// by go-webauthn (see TestVerifyAssertionRefusesCaseVariantMembers), so a
	// document carrying one must be refused.
	t.Run("ORIGIN naming another site", func(t *testing.T) {
		options := beginLogin(t)
		client := clientFor(options, ours+`,"ORIGIN":"https://evil.example"`)
		expectRefused(t, pk.sign(t, options, client).body(t, nil))
	})

	expectCount(t, "japikeys", "0")
}

// TestLoginRefusesACrossSiteFormPost covers login CSRF. The login challenge
// is not bound to the browser that asked for it, so an attacker can fetch one
// from the unauthenticated begin, sign it with their own passkey, and have a
// page on any site post the finish body. An HTML form posted with
// enctype="text/plain" needs no CORS preflight: it writes name=value, and the
// "=" can land inside authenticatorAttachment, the one member that holds free
// text, so the body is valid JSON. It is a top-level navigation, so the
// browser stores the session cookie the response sets (SameSite=Lax limits
// sending a cookie, not storing one), and the victim is signed in as the
// attacker.
//
// finish must refuse it: the request is not application/json and comes from
// another site, which a same-origin frontend never sends.
//
//nolint:paralleltest // shares one database with the other tests
func TestLoginRefusesACrossSiteFormPost(t *testing.T) {
	attacker := registerPasskey(t)

	// What the attacker's page writes into its form, after fetching a
	// challenge itself and signing it with its own key.
	body := attacker.sign(t, beginLogin(t), nil).body(t, map[string]any{"authenticatorAttachment": "x=y"})

	name, value, found := strings.Cut(body, "=")
	if !found || strings.Count(body, "=") != 1 {
		t.Fatalf("the body is not one text/plain name=value pair: %s", body)
	}

	// text/plain form encoding: name=value CRLF, nothing escaped.
	posted := name + "=" + value + "\r\n"

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		target.baseURL+loginPath+"/finish", strings.NewReader(posted))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)
	got := reply{
		status: resp.StatusCode, body: string(data),
		setCookies: resp.Header.Values("Set-Cookie"), header: resp.Header,
	}

	if got.status == http.StatusOK || got.session() != "" {
		t.Errorf("cross-site text/plain finish = %d %s with cookie %v: a cross-site form signed the browser in",
			got.status, got.body, got.setCookies)
	}

	expectCount(t, "japikeys", "0")
}
