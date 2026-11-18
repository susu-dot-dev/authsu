package config

import (
	"bytes"
	"strings"
	"testing"
)

const internalTestSecret = "internal-test-secret-0123456789ABCDEFGHIJ"

// TestDeriveKey: the derivation is deterministic, sized for HMAC-SHA-256, and
// independent across contexts and roots.
func TestDeriveKey(t *testing.T) {
	t.Parallel()

	key := deriveKey(internalTestSecret, "authsu/a")

	if len(key) != 32 {
		t.Errorf("key is %d bytes, want 32", len(key))
	}

	if !bytes.Equal(key, deriveKey(internalTestSecret, "authsu/a")) {
		t.Error("derivation is not deterministic")
	}

	// Distinct contexts give independent keys, so a key made for one purpose
	// reveals nothing about another: this is what keeps a registration
	// challenge from verifying as a login challenge.
	if bytes.Equal(key, deriveKey(internalTestSecret, "authsu/b")) {
		t.Error("two contexts derived the same key")
	}

	if bytes.Equal(key, deriveKey(internalTestSecret+"x", "authsu/a")) {
		t.Error("two roots derived the same key")
	}

	// The root is never the key.
	if bytes.Contains(key, []byte(internalTestSecret)) {
		t.Error("the derived key contains the root secret")
	}
}

// TestDerivationContextsAreDistinct: the registry is the one list of contexts
// the keys on Config are derived with, and two keys that shared a context
// would be one key. A key added to Config must add its context to the
// registry, or this test cannot see it.
func TestDerivationContextsAreDistinct(t *testing.T) {
	t.Parallel()

	if got := len(derivationContexts()); got != 2 {
		t.Fatalf("registry has %d contexts; update this test and Config together", got)
	}

	seen := map[string]int{}

	for index, context := range derivationContexts() {
		if context == "" || !strings.HasPrefix(context, "authsu/") || !strings.HasSuffix(context, "/v1") {
			t.Errorf("context %d = %q: want a non-empty %q...%q name", index, context, "authsu/", "/v1")
		}

		if previous, clash := seen[context]; clash {
			t.Errorf("contexts %d and %d are both %q", previous, index, context)
		}

		seen[context] = index
	}
}

// TestDerivationContextsAreRegistered: each named context is in the registry,
// so the distinctness test above covers it.
func TestDerivationContextsAreRegistered(t *testing.T) {
	t.Parallel()

	registered := map[string]bool{}
	for _, context := range derivationContexts() {
		registered[context] = true
	}

	for name, context := range map[string]string{
		"registration": registrationContext,
		"login":        loginContext,
	} {
		if !registered[context] {
			t.Errorf("%s context %q is not in derivationContexts()", name, context)
		}
	}
}
