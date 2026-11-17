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
	testSecret    = "deploy-secret-0123456789ABCDEFGHIJKLMNOPQ"
	testAPIOrigin = "https://auth.example.com"
	testUIOrigin  = "https://example.com"

	hostLocalhost = "localhost"
	hostAPI       = "auth.example.com"
)

func env(overrides map[string]string) func(string) string {
	values := map[string]string{
		deploy.SecretHMAC:   testSecret,
		deploy.VarAPIOrigin: testAPIOrigin,
		deploy.VarUIOrigin:  testUIOrigin,
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

	if cfg.Root != testSecret || cfg.API.String != testAPIOrigin || cfg.UI.String != testUIOrigin {
		t.Errorf("config = %+v", cfg)
	}

	// The relying party is the UI's, not the API's: ceremonies run on the UI's
	// pages, so the browser writes the UI's origin and the RP ID is its host.
	if cfg.RP.ID != "example.com" || cfg.RP.Origin != testUIOrigin || cfg.RPName != "example.com" {
		t.Errorf("relying party = %+v name %q", cfg.RP, cfg.RPName)
	}
}

// TestLoadDerivesTheRelyingPartyFromTheHost: the RP ID is the hostname alone, so
// a port is never part of it (a browser refuses an RP ID with one) and the
// scheme never is either.
func TestLoadDerivesTheRelyingPartyFromTheHost(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ui     string
		wantID string
	}{
		"https":          {ui: "https://susu.dev", wantID: "susu.dev"},
		"https and port": {ui: "https://susu.dev:8443", wantID: "susu.dev"},
		"localhost port": {ui: "http://localhost:3000", wantID: hostLocalhost},
		"localhost":      {ui: "http://localhost", wantID: hostLocalhost},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := deploy.Load(env(map[string]string{deploy.VarUIOrigin: tt.ui}))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			if cfg.RP.ID != tt.wantID || cfg.RPName != tt.wantID || cfg.RP.Origin != tt.ui {
				t.Errorf("RP = %+v name %q, want id %q origin %q", cfg.RP, cfg.RPName, tt.wantID, tt.ui)
			}
		})
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
		"api origin missing": {overrides: map[string]string{deploy.VarAPIOrigin: ""}, want: deploy.ErrOrigin},
		"ui origin missing":  {overrides: map[string]string{deploy.VarUIOrigin: ""}, want: deploy.ErrOrigin},
		"api origin invalid": {overrides: map[string]string{deploy.VarAPIOrigin: hostAPI}, want: deploy.ErrOrigin},
		"ui origin invalid":  {overrides: map[string]string{deploy.VarUIOrigin: "null"}, want: deploy.ErrOrigin},
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

func TestParseOrigin(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		origin       string
		wantHost     string
		wantInsecure bool
		wantErr      bool
	}{
		"https":           {origin: "https://auth.example.com", wantHost: hostAPI},
		"https with port": {origin: "https://auth.example.com:8443", wantHost: hostAPI},
		"localhost http":  {origin: "http://localhost:8787", wantHost: hostLocalhost, wantInsecure: true},
		"localhost bare":  {origin: "http://localhost", wantHost: hostLocalhost, wantInsecure: true},
		// Only the host "localhost" may be insecure. A prefix match would let a
		// lookalike host through, with an http issuer and so an http cookie.
		"localhost subdomain lookalike": {origin: "http://localhost.evil.com", wantErr: true},
		"localhost suffix lookalike":    {origin: "http://localhostx", wantErr: true},
		"localhost lookalike with port": {origin: "http://localhost.evil.com:8787", wantErr: true},
		"localhost userinfo":            {origin: "http://localhost@evil.com", wantErr: true},
		"localhost with path":           {origin: "http://localhost/path", wantErr: true},
		"localhost bad port":            {origin: "http://localhost:abc", wantErr: true},
		"localhost empty port":          {origin: "http://localhost:", wantErr: true},
		"https lookalike userinfo":      {origin: "https://auth.example.com@evil.com", wantErr: true},
		"trailing slash":                {origin: "https://auth.example.com/", wantErr: true},
		"path":                          {origin: "https://auth.example.com/keys", wantErr: true},
		"query":                         {origin: "https://auth.example.com?x=1", wantErr: true},
		"empty query":                   {origin: "https://auth.example.com?", wantErr: true},
		"fragment":                      {origin: "https://auth.example.com#x", wantErr: true},
		"opaque":                        {origin: "https:auth.example.com", wantErr: true},
		// A browser sends the origin lower-cased, so another spelling would
		// never match an Origin header or clientDataJSON.
		"upper-case host":   {origin: "https://AUTH.example.com", wantErr: true},
		"upper-case scheme": {origin: "HTTPS://auth.example.com", wantErr: true},
		// Plain http is for localhost only: anywhere else it would put the
		// session cookie on a network.
		"http elsewhere": {origin: "http://auth.example.com", wantErr: true},
		"other scheme":   {origin: "ftp://auth.example.com", wantErr: true},
		"null origin":    {origin: "null", wantErr: true},
		"wildcard":       {origin: "*", wantErr: true},
		"bare host":      {origin: hostAPI, wantErr: true},
		"empty":          {origin: "", wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := deploy.ParseOrigin(tt.origin)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if !errors.Is(err, deploy.ErrOrigin) {
					t.Errorf("err = %v, want ErrOrigin", err)
				}

				return
			}

			want := deploy.Origin{String: tt.origin, Host: tt.wantHost, Insecure: tt.wantInsecure}
			if got != want {
				t.Errorf("origin = %+v, want %+v", got, want)
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
