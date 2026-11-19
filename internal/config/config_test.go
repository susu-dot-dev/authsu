package config_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/config"
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
		config.SecretHMAC:   testSecret,
		config.VarAPIOrigin: testAPIOrigin,
		config.VarUIOrigin:  testUIOrigin,
	}

	maps.Copy(values, overrides)

	return func(name string) string { return values[name] }
}

func TestLoadReadsTheConfiguration(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.API.String != testAPIOrigin || cfg.UI.String != testUIOrigin {
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

			cfg, err := config.Load(env(map[string]string{config.VarUIOrigin: tt.ui}))
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

	_, err := config.Load(env(map[string]string{config.SecretHMAC: strings.Repeat("a", config.MinSecretLen)}))
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
		"secret missing": {overrides: map[string]string{config.SecretHMAC: ""}, want: config.ErrSecret},
		"secret too short": {
			overrides: map[string]string{config.SecretHMAC: strings.Repeat("a", config.MinSecretLen-1)},
			want:      config.ErrSecret,
		},
		"api origin missing": {overrides: map[string]string{config.VarAPIOrigin: ""}, want: config.ErrOrigin},
		"ui origin missing":  {overrides: map[string]string{config.VarUIOrigin: ""}, want: config.ErrOrigin},
		"api origin invalid": {overrides: map[string]string{config.VarAPIOrigin: hostAPI}, want: config.ErrOrigin},
		"ui origin invalid":  {overrides: map[string]string{config.VarUIOrigin: "null"}, want: config.ErrOrigin},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Load(env(tt.overrides))
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseOrigin(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		origin   string
		wantHost string
		wantErr  bool
	}{
		"https":           {origin: "https://auth.example.com", wantHost: hostAPI},
		"https with port": {origin: "https://auth.example.com:8443", wantHost: hostAPI},
		"localhost http":  {origin: "http://localhost:8787", wantHost: hostLocalhost},
		"localhost bare":  {origin: "http://localhost", wantHost: hostLocalhost},
		// Only the host "localhost" may be insecure. A prefix match would let a
		// lookalike host through, so an http origin would be accepted for it.
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

			got, err := config.ParseOrigin(tt.origin)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if !errors.Is(err, config.ErrOrigin) {
					t.Errorf("err = %v, want ErrOrigin", err)
				}

				return
			}

			want := config.Origin{String: tt.origin, Host: tt.wantHost}
			if got != want {
				t.Errorf("origin = %+v, want %+v", got, want)
			}
		})
	}
}

// TestLoadDerivesTheChallengeKeys pins each key to its context, spelled out
// here as a literal on purpose: the strings are part of the signed format, so
// changing one must be a deliberate edit of this test too.
func TestLoadDerivesTheChallengeKeys(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		secret  string
		context string
		key     func(config.Config) []byte
	}{
		"registration": {
			secret:  testSecret,
			context: "authsu/registration-challenge/v1",
			key:     func(c config.Config) []byte { return c.RegistrationKey },
		},
		"login": {
			secret:  testSecret,
			context: "authsu/login-challenge/v1",
			key:     func(c config.Config) []byte { return c.LoginKey },
		},
		"oauth request": {
			secret:  testSecret,
			context: "authsu/oauth-request/v1",
			key:     func(c config.Config) []byte { return c.OAuthRequestKey },
		},
		"oauth request, another secret": {
			secret:  strings.Repeat("z", config.MinSecretLen),
			context: "authsu/oauth-request/v1",
			key:     func(c config.Config) []byte { return c.OAuthRequestKey },
		},
		"registration, another secret": {
			secret:  strings.Repeat("z", config.MinSecretLen),
			context: "authsu/registration-challenge/v1",
			key:     func(c config.Config) []byte { return c.RegistrationKey },
		},
		"login, another secret": {
			secret:  strings.Repeat("z", config.MinSecretLen),
			context: "authsu/login-challenge/v1",
			key:     func(c config.Config) []byte { return c.LoginKey },
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(env(map[string]string{config.SecretHMAC: tt.secret}))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			got := tt.key(cfg)
			if want := hmacSHA256(tt.secret, tt.context); !bytes.Equal(got, want) {
				t.Errorf("key = %x, want %x", got, want)
			}

			if len(got) != 32 || bytes.Contains(got, []byte(tt.secret)) {
				t.Errorf("key %x is not a derived 32-byte key", got)
			}
		})
	}
}

// TestChallengeKeysAreIndependent: a registration challenge must never verify
// as a login one, so the two keys differ, and each differs from the root and
// changes with it.
func TestChallengeKeysAreIndependent(t *testing.T) {
	t.Parallel()

	first, err := config.Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	second, err := config.Load(env(map[string]string{config.SecretHMAC: testSecret + "x"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	keys := map[string][]byte{
		"registration":                first.RegistrationKey,
		"login":                       first.LoginKey,
		"oauth request":               first.OAuthRequestKey,
		"registration, another root":  second.RegistrationKey,
		"login, another root":         second.LoginKey,
		"oauth request, another root": second.OAuthRequestKey,
		"the root itself":             []byte(testSecret),
		"the root with another tail":  []byte(testSecret + "x"),
	}

	seen := map[string]string{}

	for name, key := range keys {
		if previous, clash := seen[string(key)]; clash {
			t.Errorf("%s and %s are the same key", name, previous)
		}

		seen[string(key)] = name
	}
}

// TestFirstRunSecret: the first-run secret comes back exactly as configured,
// with no judgement of it, and "" when it is not set.
func TestFirstRunSecret(t *testing.T) {
	t.Parallel()

	for name, secret := range map[string]string{
		"missing":           "",
		"short":             "a",
		"generated":         strings.Repeat("Ab-_9", 8) + "xyz",
		"not base64url":     "has a space\n+/=",
		"longer than token": strings.Repeat("a", 300),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := config.FirstRunSecret(env(map[string]string{config.SecretFirstRun: secret}))
			if got != secret {
				t.Errorf("FirstRunSecret = %q, want %q unchanged", got, secret)
			}
		})
	}
}

// TestFirstRunSecretReadsTheNamedSecret: only FIRST_RUN_SECRET is read, so the
// root secret can never be mistaken for the first-run token.
func TestFirstRunSecretReadsTheNamedSecret(t *testing.T) {
	t.Parallel()

	if config.SecretFirstRun != "FIRST_RUN_SECRET" {
		t.Errorf("SecretFirstRun = %q", config.SecretFirstRun)
	}

	var asked []string

	got := config.FirstRunSecret(func(name string) string {
		asked = append(asked, name)

		return strings.Repeat("a", 40)
	})

	if got == "" || len(asked) != 1 || asked[0] != "FIRST_RUN_SECRET" {
		t.Errorf("got = %q, asked = %v, want one read of FIRST_RUN_SECRET", got, asked)
	}

	// The root secret is long and valid, but is not the first-run secret.
	if got := config.FirstRunSecret(env(nil)); got != "" {
		t.Error("the root secret was returned as the first-run secret")
	}
}

// hmacSHA256 is the derivation spelled out independently of the package:
// HMAC-SHA-256 keyed with the root secret over the context.
func hmacSHA256(root, context string) []byte {
	mac := hmac.New(sha256.New, []byte(root))
	mac.Write([]byte(context))

	return mac.Sum(nil)
}

// TestLocalHTTP: the one localhost rule, shared by ParseOrigin and by what
// selects the development resource table.
func TestLocalHTTP(t *testing.T) {
	t.Parallel()

	const (
		schemeHTTP  = "http"
		schemeHTTPS = "https"
	)

	tests := map[string]struct {
		scheme, host string
		want         bool
	}{
		"http localhost":            {scheme: schemeHTTP, host: hostLocalhost, want: true},
		"https localhost":           {scheme: schemeHTTPS, host: hostLocalhost},
		"http elsewhere":            {scheme: schemeHTTP, host: hostAPI},
		"http subdomain lookalike":  {scheme: schemeHTTP, host: "localhost.evil.com"},
		"http suffix lookalike":     {scheme: schemeHTTP, host: "localhostx"},
		"http prefix lookalike":     {scheme: schemeHTTP, host: "xlocalhost"},
		"http 127.0.0.1":            {scheme: schemeHTTP, host: "127.0.0.1"},
		"http upper-case host":      {scheme: schemeHTTP, host: "LOCALHOST"},
		"upper-case scheme":         {scheme: "HTTP", host: hostLocalhost},
		"nothing":                   {},
		"ws localhost":              {scheme: "ws", host: hostLocalhost},
		"http localhost, a trailer": {scheme: schemeHTTP, host: "localhost."},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := config.LocalHTTP(tt.scheme, tt.host); got != tt.want {
				t.Errorf("LocalHTTP(%q, %q) = %v, want %v", tt.scheme, tt.host, got, tt.want)
			}
		})
	}
}

// TestOriginLocal: of the origins ParseOrigin accepts, exactly the http ones are
// local, and they agree with LocalHTTP.
func TestOriginLocal(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"http://" + hostLocalhost:                   true,
		"http://" + hostLocalhost + ":8787":         true,
		"https://" + hostLocalhost:                  false,
		"https://" + hostLocalhost + ":8443":        false,
		testUIOrigin:                                false,
		"https://" + hostLocalhost + ".example.com": false,
	}

	for value, want := range tests {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			origin, err := config.ParseOrigin(value)
			if err != nil {
				t.Fatalf("ParseOrigin: %v", err)
			}

			if got := origin.Local(); got != want {
				t.Errorf("Local = %v, want %v", got, want)
			}
		})
	}

	t.Run("the zero Origin is not local", func(t *testing.T) {
		t.Parallel()

		if (config.Origin{}).Local() {
			t.Error("the zero Origin is local")
		}
	})
}
