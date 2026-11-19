package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

const testMaxTTL = 5 * time.Minute

func testKey() []byte { return bytes.Repeat([]byte{0x4b}, 32) }

func otherKey() []byte { return bytes.Repeat([]byte{0x4c}, 32) }

// testNowSeconds is the fixed clock, in whole Unix seconds well after the epoch.
const testNowSeconds = 1_900_000_000

func testNow() time.Time { return time.Unix(testNowSeconds, 0) }

// counterEntropy returns a reader that never repeats a byte run: 1, 2, 3, ...
// wrapping at 256. Two nonces read from the same reader always differ.
func counterEntropy() io.Reader { return &counter{next: 1} }

type counter struct{ next byte }

func (c *counter) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.next
		c.next++
	}

	return len(p), nil
}

// firstNonce is what a fresh counterEntropy yields for the nonce.
func firstNonce() []byte {
	nonce := make([]byte, NonceLen)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	return nonce
}

// forge builds a challenge by hand from the documented layout, independently
// of Create, so tests can produce challenges Create never would (any version,
// any expiry) and pin the layout itself. The tag is correct for key and ad.
func forge(key []byte, ver byte, seconds uint64, nonce []byte, ad ...[]byte) []byte {
	state := make([]byte, 0, Len)
	state = append(state, ver)
	state = binary.BigEndian.AppendUint64(state, seconds)
	state = append(state, nonce...)

	mac := hmac.New(sha256.New, key)
	mac.Write(state)

	for _, item := range ad {
		sum := sha256.Sum256(item)

		mac.Write(sum[:])
	}

	return mac.Sum(state)
}

// valid creates the standard challenge: expires one TTL after testNow, bound
// to the given associated data.
func valid(t *testing.T, ad ...[]byte) []byte {
	t.Helper()

	challenge, _, err := Create(testKey(), counterEntropy(), testNow().Add(testMaxTTL), ad...)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	return challenge
}

func adOf(items ...string) [][]byte {
	out := make([][]byte, len(items))
	for i, item := range items {
		out[i] = []byte(item)
	}

	return out
}

// sum256 is SHA-256 of s as a slice.
func sum256(s string) []byte {
	sum := sha256.Sum256([]byte(s))

	return sum[:]
}

// forgeSealed builds a sealed payload by hand from the documented layout,
// independently of Seal, so tests can produce values Seal never would (any
// version, any expiry, a payload over the bound). The tag is correct for key.
func forgeSealed(key []byte, ver byte, seconds uint64, payload []byte) []byte {
	state := make([]byte, 0, sealedOverhead+len(payload))
	state = append(state, ver)
	state = binary.BigEndian.AppendUint64(state, seconds)
	state = append(state, payload...)

	mac := hmac.New(sha256.New, key)
	mac.Write(state)

	return mac.Sum(state)
}

// testPayload is the standard payload: bytes with no structure, as the
// package must treat every payload.
func testPayload() []byte { return []byte("client_id=https://app.example/c&state=xyz\x00\xff") }

// validSealed seals the standard payload, expiring one TTL after testNow.
func validSealed(t *testing.T) []byte {
	t.Helper()

	sealed, err := Seal(testKey(), testNow().Add(testMaxTTL), testPayload())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	return sealed
}

// derivedKey derives a key from a root with a context, the way internal/config
// does (HMAC-SHA256 of the context under the root), so a test can hold keys
// from two contexts without importing config.
func derivedKey(root, context string) []byte {
	mac := hmac.New(sha256.New, []byte(root))
	mac.Write([]byte(context))

	return mac.Sum(nil)
}
