package deploy_test

import (
	"bytes"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/deploy"
)

const (
	testSecret = "deploy-secret-0123456789ABCDEFGHIJKLMNOPQ"
	testRPID   = "auth.example.com"
	testOrigin = "https://auth.example.com"
	testRPName = "Example Auth"
)

func env(overrides map[string]string) func(string) string {
	values := map[string]string{
		deploy.SecretHMAC:  testSecret,
		deploy.VarRPID:     testRPID,
		deploy.VarRPOrigin: testOrigin,
		deploy.VarRPName:   testRPName,
	}

	maps.Copy(values, overrides)

	return func(name string) string { return values[name] }
}

func TestLoadReadsTheConfiguration(t *testing.T) {
	t.Parallel()

	cfg, err := deploy.Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Root != testSecret || cfg.RP.ID != testRPID || cfg.RP.Origin != testOrigin || cfg.RPName != testRPName {
		t.Errorf("config = %+v", cfg)
	}
}

func TestLoadAcceptsTheShortestSecret(t *testing.T) {
	t.Parallel()

	_, err := deploy.Load(env(map[string]string{deploy.SecretHMAC: strings.Repeat("a", deploy.MinSecretLen)}))
	if err != nil {
		t.Errorf("a secret of exactly MinSecretLen was refused: %v", err)
	}
}

func TestLoadRefusesIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		overrides map[string]string
		want      error
	}{
		"secret missing": {overrides: map[string]string{deploy.SecretHMAC: ""}, want: deploy.ErrSecret},
		"secret too short": {
			overrides: map[string]string{deploy.SecretHMAC: strings.Repeat("a", deploy.MinSecretLen-1)},
			want:      deploy.ErrSecret,
		},
		"rp id missing":   {overrides: map[string]string{deploy.VarRPID: ""}, want: deploy.ErrRelyingParty},
		"rp origin":       {overrides: map[string]string{deploy.VarRPOrigin: ""}, want: deploy.ErrRelyingParty},
		"rp name missing": {overrides: map[string]string{deploy.VarRPName: ""}, want: deploy.ErrRelyingParty},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := deploy.Load(env(tt.overrides))
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	t.Parallel()

	key := deploy.DeriveKey(testSecret, "authsu/a")

	if len(key) != 32 {
		t.Errorf("key is %d bytes, want 32", len(key))
	}

	if !bytes.Equal(key, deploy.DeriveKey(testSecret, "authsu/a")) {
		t.Error("derivation is not deterministic")
	}

	// Distinct contexts give independent keys, so a key made for one purpose
	// reveals nothing about another: this is what keeps a registration
	// challenge from verifying as a login challenge.
	if bytes.Equal(key, deploy.DeriveKey(testSecret, "authsu/b")) {
		t.Error("two contexts derived the same key")
	}

	if bytes.Equal(key, deploy.DeriveKey(testSecret+"x", "authsu/a")) {
		t.Error("two roots derived the same key")
	}

	// The root is never the key.
	if bytes.Contains(key, []byte(testSecret)) {
		t.Error("the derived key contains the root secret")
	}
}
