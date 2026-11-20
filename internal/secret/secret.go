// Package secret generates and hashes the bearer secrets authsu issues:
// invitations, sessions, API keys and the OAuth authorization code, refresh
// token and access token.
//
// # The token
//
// A token is a prefix followed by a body:
//
//	susu_<tag>_<43 base64url characters>
//
// The body is 32 bytes (BodyBytes) from a cryptographic random source, encoded
// as base64url without padding, which is always BodyLen characters. The token
// carries nothing else: it is random, and nothing can be read from it.
//
// The prefix, "susu_" and a tag, names the kind of secret. A reader that
// expects one kind refuses a token of any other before it reads anything, and
// a token that ends up in a log, a chat or a repository says what it is, so
// secret scanners can recognise it. The body may itself contain '_' and '-',
// so a reader must match the whole prefix and never find it by splitting.
//
// # The hash
//
// What is stored is Hash: SHA-256 of the whole token string, prefix included.
// Hashing the prefix means one random body under two tags gives two unrelated
// hashes, so a secret of one kind can never be looked up as another. There is
// no slow hash and no pepper: key stretching protects low-entropy, human-chosen
// inputs, and a 256-bit random value gains nothing from it.
//
// # Randomness
//
// Generate never reads a global source. The caller passes the io.Reader
// (crypto/rand.Reader in production), so tests inject a deterministic or
// failing one.
//
// This package knows nothing of what a kind means, where a hash is stored or
// who a secret belongs to. Parsing a token that comes back from a client is the
// job of internal/input, which builds on Prefix, BodyLen and Hash.
package secret

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// Tag names a kind of secret inside its token's prefix.
type Tag string

// The tags. Each appears in the token as "susu_<tag>_".
const (
	TagInvitation Tag = "inv"
	TagSession    Tag = "ses"
	TagAPIKey     Tag = "key"

	// TagOAuthCode is an OAuth authorization code, before it is exchanged
	// ("susu_code_"). The grant it belongs to keeps its id and becomes a
	// refresh token at the exchange.
	TagOAuthCode Tag = "code"
	// TagOAuthRefresh is an OAuth refresh token ("susu_rt_"): the same grant
	// secret as the code it replaces, under the same id.
	TagOAuthRefresh Tag = "rt"
	// TagOAuthAccess is an OAuth access token ("susu_at_"), presented to a
	// resource server and read back by introspection.
	TagOAuthAccess Tag = "at"
)

// Sizes of a token body.
const (
	// BodyBytes is the number of random bytes in a token body: 256 bits.
	BodyBytes = 32

	// BodyLen is the length of the body as base64url without padding:
	// ceil(32*8/6) = 43 characters. The last one carries 4 data bits and 2
	// unused bits, which a canonical encoding leaves zero.
	BodyLen = 43
)

// brand starts every token, ahead of the tag.
const brand = "susu_"

// Prefix returns the start of every token of the kind named by tag:
// "susu_" + tag + "_".
func Prefix(tag Tag) string { return brand + string(tag) + "_" }

// Generate returns a new token of the kind named by tag: Prefix(tag) followed
// by BodyBytes bytes read from r, base64url-encoded without padding. It reads
// exactly BodyBytes bytes, and a reader that fails or ends early is an error.
func Generate(r io.Reader, tag Tag) (string, error) {
	var body [BodyBytes]byte

	_, err := io.ReadFull(r, body[:])
	if err != nil {
		return "", fmt.Errorf("read %d random bytes for a token: %w", BodyBytes, err)
	}

	return Prefix(tag) + base64.RawURLEncoding.EncodeToString(body[:]), nil
}

// Hash returns the SHA-256 of the whole token string, prefix included, as its
// UTF-8 bytes. It is the one place tokens are hashed, so an insert and a lookup
// cannot disagree.
func Hash(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }
