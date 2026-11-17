package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/japikey_go"

	"github.com/susu-dot-dev/authsu/internal/deploy"
)

func TestAudienceIsDerivedFromTheKind(t *testing.T) {
	t.Parallel()

	if got := Audience(KindSession); got != "authsu/session" {
		t.Errorf("Audience = %q", got)
	}

	// Distinct kinds must have distinct audiences, or a token for one would
	// verify as the other.
	if Audience(KindSession) == Audience("api_key") {
		t.Error("session and api_key share an audience")
	}
}

func TestLoginGrantIsTheHashOfTheChallenge(t *testing.T) {
	t.Parallel()

	challenge := []byte("0123456789abcdef0123456789abcdef")
	grant := LoginGrant(challenge)

	// The column's CHECK is 32 bytes.
	if len(grant) != 32 {
		t.Errorf("grant is %d bytes, want 32 (the column's CHECK)", len(grant))
	}

	// Deterministic, so a replay produces the same value and collides.
	if !bytes.Equal(grant, LoginGrant(challenge)) {
		t.Error("a grant is not deterministic: a replay would not collide")
	}

	if bytes.Equal(grant, LoginGrant([]byte("another challenge"))) {
		t.Error("different challenges produced the same grant")
	}

	// It is a hash: the challenge is not recoverable from what is stored.
	if bytes.Contains(grant, challenge) {
		t.Error("the grant contains the challenge")
	}
}

// TestIssuerFor: the issuer is the API's origin plus /keys, and plain http is
// carried through only for the localhost origin deploy.ParseOrigin allowed.
func TestIssuerFor(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		origin       string
		wantBase     string
		wantInsecure bool
	}{
		"https":           {origin: "https://auth.example.com", wantBase: "https://auth.example.com/keys"},
		"https with port": {origin: "https://auth.example.com:8443", wantBase: "https://auth.example.com:8443/keys"},
		"localhost http": {
			origin: "http://localhost:8787", wantBase: "http://localhost:8787/keys", wantInsecure: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			api, err := deploy.ParseOrigin(tt.origin)
			if err != nil {
				t.Fatalf("ParseOrigin: %v", err)
			}

			got := IssuerFor(api)
			if got.Base != tt.wantBase || got.Insecure != tt.wantInsecure {
				t.Errorf("issuer = %+v, want base %q insecure %v", got, tt.wantBase, tt.wantInsecure)
			}
		})
	}
}

// storedJWK decodes the single key in a stored JWK document.
func storedJWK(t *testing.T, document []byte) map[string]any {
	t.Helper()

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}

	err := json.Unmarshal(document, &doc)
	if err != nil || len(doc.Keys) != 1 {
		t.Fatalf("jwk = %s: %v", document, err)
	}

	return doc.Keys[0]
}

func TestMintProducesAStorableKey(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	expires := fix.now.Add(Lifetime)

	key, err := Mint(fix.issuer, testUserID, expires)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if key.JWT == "" || key.ExpiresAt != expires {
		t.Errorf("key = %+v", key)
	}

	if _, ok := key.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("public key is %T", key.PublicKey)
	}

	// The JWK is small enough for the column's CHECK (2048).
	if len(key.JWK) > 2048 {
		t.Errorf("jwk is %d bytes", len(key.JWK))
	}
}

// TestMintStoresOnlyThePublicKey holds the property the whole design rests on:
// the private half is discarded, so nothing that is stored can sign.
func TestMintStoresOnlyThePublicKey(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	key, err := Mint(fix.issuer, testUserID, fix.now.Add(Lifetime))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	jwk := storedJWK(t, key.JWK)

	if jwk["kid"] != key.ID.String() || jwk["alg"] != "ES256" || jwk["crv"] != "P-256" {
		t.Errorf("jwk = %v", jwk)
	}

	// "d" is the private scalar.
	if _, private := jwk["d"]; private {
		t.Error("the stored JWK carries a private key")
	}
}

func TestMintFailsOnAnInvalidRequest(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	tests := map[string]struct {
		issuer  Issuer
		user    string
		expires time.Time
	}{
		"empty subject":      {issuer: fix.issuer, user: "", expires: fix.now.Add(time.Hour)},
		"already expired":    {issuer: fix.issuer, user: testUserID, expires: fix.now.Add(-time.Hour)},
		"not a valid issuer": {issuer: Issuer{Base: "not a url"}, user: testUserID, expires: fix.now.Add(time.Hour)},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := Mint(tt.issuer, tt.user, tt.expires)
			if err == nil {
				t.Error("Mint succeeded, want an error")
			}
		})
	}
}

func TestVerifyAcceptsAMintedSession(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))

	got, err := fix.verifier().Verify(t.Context(), key.JWT)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if got.UserID != testUserID || got.KeyID != key.ID.String() || got.CredentialID != testCredID || got.Role != testRole {
		t.Errorf("principal = %+v", got)
	}

	// The lookup is at the verifier's clock: that is the time a scheduled
	// revocation is compared against.
	if len(fix.reader.at) != 1 || !fix.reader.at[0].Equal(fix.now) {
		t.Errorf("lookup times = %v, want %v", fix.reader.at, fix.now)
	}
}

func TestVerifyRefusesWithOneAnswer(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*fixture, Key) string{
		// Not in the database (unknown, revoked and expired rows are all
		// "not active" to the reader).
		"unknown key": func(f *fixture, k Key) string {
			delete(f.reader.keys, k.ID.String())

			return k.JWT
		},
		garbage:   func(*fixture, Key) string { return garbage },
		emptyCase: func(*fixture, Key) string { return "" },
		// A valid token for another account's key.
		"subject is not the key's owner": func(f *fixture, k Key) string {
			stored := f.reader.keys[k.ID.String()]
			stored.UserID = "00000000-0000-7000-8000-0000000000ff"
			f.reader.keys[k.ID.String()] = stored

			return k.JWT
		},
		"signed by another key": func(f *fixture, k Key) string {
			other := f.issue(t, f.now.Add(Lifetime))
			// The row for k's kid holds another key's public half.
			stored := f.reader.keys[k.ID.String()]
			stored.JWK = bytes.ReplaceAll(other.JWK, []byte(other.ID.String()), []byte(k.ID.String()))
			f.reader.keys[k.ID.String()] = stored

			return k.JWT
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			key := fix.issue(t, fix.now.Add(Lifetime))

			_, err := fix.verifier().Verify(t.Context(), setup(fix, key))
			if !errors.Is(err, ErrUnauthorized) {
				t.Errorf("err = %v, want %v", err, ErrUnauthorized)
			}

			if errors.Is(err, ErrUnavailable) {
				t.Error("a verdict on the token was reported as unavailability")
			}
		})
	}
}

func TestVerifyRefusesAnotherIssuer(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))

	other, err := deploy.ParseOrigin("https://other.example.com")
	if err != nil {
		t.Fatalf("origin: %v", err)
	}

	elsewhere := IssuerFor(other)

	_, err = NewVerifier(fix.reader, elsewhere, func() time.Time { return fix.now }).Verify(t.Context(), key.JWT)
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want %v", err, ErrUnauthorized)
	}

	// A token for another issuer must not cost a database read.
	if len(fix.reader.asked) != 0 {
		t.Errorf("a token for another issuer reached the store: %v", fix.reader.asked)
	}
}

func TestVerifyRefusesAnotherAudience(t *testing.T) {
	t.Parallel()

	// A key minted for another kind is a valid japikey for this issuer, but
	// not a session.
	fix := newFixture(t)

	minted, err := japikey.NewJAPIKey(japikey.Config{
		Subject: testUserID, Issuer: fix.issuer.Base, Audience: Audience("api_key"),
		ExpiresAt: fix.now.Add(Lifetime), Claims: nil, AllowInsecureHTTP: fix.issuer.Insecure,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	document, err := minted.ToJWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}

	jwk, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	fix.reader.keys[minted.KeyID.String()] = ActiveKey{
		JWK: jwk, UserID: testUserID, CredentialID: "", Role: "", ExpiresAt: fix.now.Add(Lifetime),
	}

	_, err = fix.verifier().Verify(t.Context(), minted.JWT)
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("an API key verified as a session: %v", err)
	}
}

func TestVerifyReportsAStoreFailureAsUnavailable(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))
	fix.reader.err = errDB

	_, err := fix.verifier().Verify(t.Context(), key.JWT)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want unavailable and not unauthorized", err)
	}

	if !errors.Is(err, errDB) {
		t.Errorf("err = %v, want it to wrap the cause for the log", err)
	}
}

func TestVerifyReportsACorruptStoredKeyAsUnavailable(t *testing.T) {
	t.Parallel()

	// A row whose JWK is not a valid key is the database being wrong, not the
	// token: it says nothing about the caller.
	tests := map[string][]byte{
		"not json":      []byte(garbage),
		"empty":         nil,
		"another kid":   nil,
		"no keys":       []byte(`{"keys":[]}`),
		"private field": []byte(`{"keys":[{"kty":"EC","d":"x"}]}`),
	}

	for name, jwk := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			key := fix.issue(t, fix.now.Add(Lifetime))

			stored := fix.reader.keys[key.ID.String()]

			stored.JWK = jwk
			if name == "another kid" {
				stored.JWK = []byte(strings.Replace(string(key.JWK), key.ID.String(), "00000000-0000-7000-8000-0000000000aa", 1))
			}

			fix.reader.keys[key.ID.String()] = stored

			_, err := fix.verifier().Verify(t.Context(), key.JWT)
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("err = %v, want %v", err, ErrUnavailable)
			}
		})
	}
}

func TestVerifyReportsABadIssuerAsUnavailable(t *testing.T) {
	t.Parallel()

	// An invalid issuer is the deployment being wrong, not the token.
	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))

	_, err := NewVerifier(fix.reader, Issuer{Base: ""}, func() time.Time { return fix.now }).Verify(t.Context(), key.JWT)
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want %v", err, ErrUnavailable)
	}
}

func TestCookie(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))

	cookie := Cookie(key)

	if cookie.Name != CookieName || cookie.Value != key.JWT {
		t.Errorf("cookie = %+v", cookie)
	}

	if !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Errorf("name %q lacks the __Host- prefix, so a sibling subdomain could set it", cookie.Name)
	}

	if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" {
		t.Errorf("cookie = %+v, want HttpOnly, Secure, Path=/ and no Domain (the __Host- requirements)", cookie)
	}

	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}

	// The browser drops the cookie when the session ends.
	if !cookie.Expires.Equal(key.ExpiresAt) {
		t.Errorf("Expires = %v, want %v", cookie.Expires, key.ExpiresAt)
	}
}

func TestClearCookieExpiresIt(t *testing.T) {
	t.Parallel()

	cookie := ClearCookie()

	if cookie.Name != CookieName || cookie.Value != "" || cookie.MaxAge >= 0 {
		t.Errorf("cookie = %+v, want an empty, immediately expiring session cookie", cookie)
	}

	// It must match the attributes of the cookie it clears, or a browser keeps
	// the original.
	if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" {
		t.Errorf("cookie = %+v, want the same __Host- attributes as the session cookie", cookie)
	}
}

func TestMintFailsWhenTheKeyCannotBeEncoded(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	_, err := mintWith(func(any) ([]byte, error) { return nil, errDB }, fix.issuer, testUserID, fix.now.Add(time.Hour))
	if !errors.Is(err, errDB) {
		t.Errorf("err = %v, want it to wrap the encoder's error", err)
	}
}

func TestVerifyReportsACancelledLookupAsUnavailable(t *testing.T) {
	t.Parallel()

	// A caller that has gone away is not a verdict on the token.
	fix := newFixture(t)
	key := fix.issue(t, fix.now.Add(Lifetime))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := fix.verifier().Verify(ctx, key.JWT)
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want %v", err, ErrUnavailable)
	}
}
