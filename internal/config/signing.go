package config

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// SecretOAuthSigningKey is the Worker secret holding the RSA private key the ID
// tokens are signed with (docs/oauth_design.md). It is its own secret and is
// never derived from SecretHMAC: the root secret is symmetric key material that
// is rotated as a whole, while a signing key is published as a public key
// (JWKS) and is rotated on its own.
//
// The value is the key's PKCS#8 DER encoding in base64url without padding, as
// one line, so it fits a .dev.vars file and a `wrangler secret put` stdin pipe
// unchanged. Make it with:
//
//	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER |
//	  base64 -w0 | tr '+/' '-_' | tr -d '='
const SecretOAuthSigningKey = "OAUTH_SIGNING_KEY" //nolint:gosec // the name of a secret, not its value

// What a signing key may be.
const (
	// MinSigningKeyBits and MaxSigningKeyBits bound the modulus, inclusive. Below
	// 2048 bits a key is no longer considered strong, and above 4096 signing
	// costs more CPU in the Worker than a token is worth.
	MinSigningKeyBits = 2048
	MaxSigningKeyBits = 4096
	// SigningKeyExponent is the one public exponent accepted. Every verifier
	// supports it and the JWKS "e" is its fixed "AQAB".
	SigningKeyExponent = 65537
	// MaxSigningKeyChars bounds the encoded secret. A 4096 bit key is about
	// 3200 characters, so this leaves room and only stops a runaway value from
	// being decoded and parsed.
	MaxSigningKeyChars = 8192
)

// kidBytes is how much of the modulus digest the key ID keeps.
const kidBytes = 8

// ErrSigningKey means OAUTH_SIGNING_KEY is missing or is not an RSA key the
// service accepts. Like ErrSecret and ErrOrigin it describes the deployment,
// not the request, and the caller answers it 503 not_configured. The wrapped
// reason names what is wrong and never includes any of the value.
var ErrSigningKey = errors.New("oauth signing key is missing or invalid")

// SigningKey is a loaded OAUTH_SIGNING_KEY: an RSA private key accepted for
// signing, and its key ID. The zero value holds no key and is never returned
// with a nil error.
type SigningKey struct {
	private *rsa.PrivateKey
	kid     string
}

// JWK is a public RSA key as a JSON Web Key (RFC 7517), the form the key set at
// /.well-known/jwks.json lists. n and e are base64url, big-endian, unsigned and
// without padding.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// LoadSigningKey reads and validates OAUTH_SIGNING_KEY. It is a separate loader
// from Load on purpose: parsing and checking an RSA key is expensive under
// wasm, and only the token and key set handlers need it, so no other request
// pays for it. getenv is the same per-request reader Load takes.
//
// The value must be exactly base64url without padding, strictly: the standard
// alphabet, padding, whitespace (a trailing newline included) and
// non-canonical trailing bits are refused, so one key has one spelling. What
// it decodes to must be a PKCS#8 PrivateKeyInfo holding an RSA key and nothing
// after it (a PKCS#1 key, an EC or Ed25519 key, and trailing bytes are all
// refused), with a modulus of MinSigningKeyBits to MaxSigningKeyBits bits and
// the exponent SigningKeyExponent. Every failure is ErrSigningKey.
func LoadSigningKey(getenv func(string) string) (SigningKey, error) {
	return ParseSigningKey(getenv(SecretOAuthSigningKey))
}

// ParseSigningKey is LoadSigningKey for a value already read.
func ParseSigningKey(value string) (SigningKey, error) {
	der, err := decodeSigningKey(value)
	if err != nil {
		return SigningKey{}, err
	}

	// x509.ParsePKCS8PrivateKey ignores whatever follows the key, so the end of the
	// DER is checked here: one key has one spelling.
	rest, err := asn1.Unmarshal(der, &asn1.RawValue{})
	if err != nil {
		return SigningKey{}, signingKeyError("is not a PKCS#8 private key")
	}

	if len(rest) != 0 {
		return SigningKey{}, signingKeyError("has trailing data after the key")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return SigningKey{}, signingKeyError("is not a PKCS#8 private key")
	}

	private, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return SigningKey{}, signingKeyError("is not an RSA key")
	}

	err = checkSigningKey(private)
	if err != nil {
		return SigningKey{}, err
	}

	return SigningKey{private: private, kid: keyID(private.N)}, nil
}

// decodeSigningKey decodes the secret, strictly.
func decodeSigningKey(value string) ([]byte, error) {
	if value == "" {
		return nil, signingKeyError("is not set")
	}

	// The decoder skips CR and LF wherever they are, so a value spread over lines
	// would decode: refuse them first.
	if len(value) > MaxSigningKeyChars || strings.ContainsAny(value, "\r\n") {
		return nil, signingKeyError("is not one line of at most MaxSigningKeyChars characters")
	}

	der, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, signingKeyError("is not base64url without padding")
	}

	return der, nil
}

// checkSigningKey refuses a key outside the accepted shape.
func checkSigningKey(key *rsa.PrivateKey) error {
	if bits := key.N.BitLen(); bits < MinSigningKeyBits || bits > MaxSigningKeyBits {
		return signingKeyError(fmt.Sprintf("must be %d to %d bits, not %d", MinSigningKeyBits, MaxSigningKeyBits, bits))
	}

	if key.E != SigningKeyExponent {
		return signingKeyError(fmt.Sprintf("must have the public exponent %d", SigningKeyExponent))
	}

	return nil
}

// signingKeyError is ErrSigningKey with the reason the value was refused.
func signingKeyError(reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrSigningKey, SecretOAuthSigningKey, reason)
}

// keyID is the key ID of a modulus: base64url of the first eight bytes of the
// SHA-256 of its big-endian bytes. It is derived from the public key alone, so
// the same key always has the same ID, and the JWKS and every token agree on it.
func keyID(modulus *big.Int) string {
	digest := sha256.Sum256(modulus.Bytes())

	return base64.RawURLEncoding.EncodeToString(digest[:kidBytes])
}

// Private is the private key, to sign with.
func (k SigningKey) Private() *rsa.PrivateKey { return k.private }

// KeyID is the "kid" the key is published and signed under.
func (k SigningKey) KeyID() string { return k.kid }

// JWK is the public half as a key for the key set: use "sig", algorithm RS256.
// "n" is the modulus and "e" the exponent, both big-endian, unsigned and
// without leading zero bytes, which for the one accepted exponent is "AQAB".
func (k SigningKey) JWK() JWK {
	public := k.private.PublicKey

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: k.kid,
		N:   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}
}
