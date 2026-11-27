//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/oauth"
)

// strs is a JSON array of strings, as encoding/json decodes one into an any.
func strs(values ...string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}

	return out
}

// authorizationServerMetadata is the exact document of RFC 8414 for an issuer
// and its scopes.
func authorizationServerMetadata(issuer string, scopes ...string) map[string]any {
	return map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"introspection_endpoint": issuer + "/oauth/introspect",
		"jwks_uri":               issuer + "/.well-known/jwks.json",

		"scopes_supported":                              strs(scopes...),
		"response_types_supported":                      strs("code"),
		"response_modes_supported":                      strs("query"),
		"grant_types_supported":                         strs("authorization_code", "refresh_token"),
		"code_challenge_methods_supported":              strs("S256"),
		"token_endpoint_auth_methods_supported":         strs("none"),
		"revocation_endpoint_auth_methods_supported":    strs("none"),
		"introspection_endpoint_auth_methods_supported": strs("none"),

		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	}
}

// openIDMetadata is the exact OpenID Connect Discovery document: the same, and
// what OIDC requires on top.
func openIDMetadata(issuer string, scopes ...string) map[string]any {
	doc := authorizationServerMetadata(issuer, scopes...)

	maps.Copy(doc, map[string]any{
		"subject_types_supported":               strs("public"),
		"id_token_signing_alg_values_supported": strs("RS256"),
		"claims_supported": strs(
			"iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "name", "email", "email_verified"),
	})

	return doc
}

// decodeObject decodes a response body as a JSON object.
func decodeObject(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var doc map[string]any

	err := json.Unmarshal(rec.Body.Bytes(), &doc)
	if err != nil {
		t.Fatalf("the body %q is not a JSON object: %v", rec.Body.String(), err)
	}

	return doc
}

// TestDiscoveryDocuments: both documents say exactly what the deployment does,
// derived from its configuration: the endpoints are under API_ORIGIN, the issuer
// is API_ORIGIN, the scopes are openid and every scope of the selected table. A
// member that is added, dropped or changed fails here, and a document in the
// development deployment has the same scopes and its own origin.
func TestDiscoveryDocuments(t *testing.T) {
	t.Parallel()

	// The login resource's scopes are profile and the authsu scopes a grant for
	// it may hold (resource.LoginAuthsuScopes), then the two names a standard
	// OpenID Connect client sends.
	scopes := []string{
		"openid", "mcp:read", "mcp:write", "profile",
		"sandbox:create", "sandbox:revoke", "org:read", "agent:create", "agent:read",
		"email", "offline_access",
	}

	tests := map[string]struct {
		env    map[string]string
		path   string
		wanted map[string]any
	}{
		"authorization server metadata": {
			env: fullEnv(), path: oauth.PathMetadata, wanted: authorizationServerMetadata(apiOrigin, scopes...),
		},
		"openid configuration": {
			env: fullEnv(), path: oauth.PathOpenIDConfiguration, wanted: openIDMetadata(apiOrigin, scopes...),
		},
		"authorization server metadata, development": {
			env: devEnv(), path: oauth.PathMetadata,
			wanted: authorizationServerMetadata("http://localhost:8787", scopes...),
		},
		"openid configuration, development": {
			env: devEnv(), path: oauth.PathOpenIDConfiguration,
			wanted: openIDMetadata("http://localhost:8787", scopes...),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRigWith(t, tt.env)
			rec := r.get(tt.path)

			if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != jsonType {
				t.Fatalf("= %d %s %q, want 200 JSON", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
			}

			if got := decodeObject(t, rec); !reflect.DeepEqual(got, tt.wanted) {
				t.Errorf("document = %v\nwant       %v", got, tt.wanted)
			}

			if rec.Header().Get("Cache-Control") != "no-store" || len(r.logged) != 0 {
				t.Errorf("Cache-Control = %q, logged = %v", rec.Header().Get("Cache-Control"), r.logged)
			}

			if len(r.net.sent()) != 0 || len(r.store.calls) != 0 {
				t.Error("a discovery document reached the network or the store")
			}
		})
	}
}

// TestDiscoveryNeedsConfiguration: a deployment without its configuration cannot
// say who it is, so it answers 503 not_configured and never a document with
// empty endpoints. The key set is separate: it needs the signing key and nothing
// else.
func TestDiscoveryNeedsConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		unset string
		path  string
	}{
		"metadata without the secret":      {config.SecretHMAC, oauth.PathMetadata},
		"metadata without the api origin":  {config.VarAPIOrigin, oauth.PathMetadata},
		"metadata without the ui origin":   {config.VarUIOrigin, oauth.PathMetadata},
		"openid without the secret":        {config.SecretHMAC, oauth.PathOpenIDConfiguration},
		"openid without the api origin":    {config.VarAPIOrigin, oauth.PathOpenIDConfiguration},
		"jwks without the signing key":     {config.SecretOAuthSigningKey, oauth.PathJWKS},
		"authorize without the api origin": {config.VarAPIOrigin, oauth.PathAuthorize + "?client_id=x"},
		"request without the secret":       {config.SecretHMAC, oauth.PathRequest + "?request=x"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := fullEnv()
			delete(env, tt.unset)

			r := newRigWith(t, env)
			rec := r.get(tt.path)

			if rec.Code != http.StatusServiceUnavailable || len(r.logged) != 1 || r.logged[0].Code != "not_configured" {
				t.Errorf("= %d %s, logged %v, want 503 not_configured", rec.Code, rec.Body, r.loggedCodes())
			}

			if len(r.net.sent()) != 0 || len(r.store.calls) != 0 {
				t.Error("the request reached the network or the store")
			}
		})
	}
}

// TestDiscoveryIgnoresTheQuery: the documents read nothing from the request.
func TestDiscoveryIgnoresTheQuery(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	plain := r.get(oauth.PathMetadata)
	noisy := r.get(oauth.PathMetadata + "?issuer=https://evil.example&x=1&x=2")

	if noisy.Code != http.StatusOK || noisy.Body.String() != plain.Body.String() {
		t.Errorf("a query changed the document: %d %s", noisy.Code, noisy.Body)
	}
}

// keySetOf decodes the key set of a response: the members of each key, as text.
func keySetOf(t *testing.T, rec *httptest.ResponseRecorder) []map[string]string {
	t.Helper()

	var set struct {
		Keys []map[string]string `json:"keys"`
	}

	err := json.Unmarshal(rec.Body.Bytes(), &set)
	if err != nil {
		t.Fatalf("the body %q is not a key set: %v", rec.Body, err)
	}

	return set.Keys
}

// TestKeySet: the key set holds the one public key of the signing key, with
// the identifier an ID token's header names, and no private member.
func TestKeySet(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	key, err := config.ParseSigningKey(testSigningKey)
	if err != nil {
		t.Fatal(err)
	}

	rec := r.get(oauth.PathJWKS)

	if rec.Code != http.StatusOK || len(r.logged) != 0 {
		t.Fatalf("= %d %q, logged %v, want 200", rec.Code, rec.Body, r.loggedCodes())
	}

	jwk := key.JWK()
	want := map[string]string{"kty": jwk.Kty, "use": jwk.Use, "alg": jwk.Alg, "kid": jwk.Kid, "n": jwk.N, "e": jwk.E}

	if keys := keySetOf(t, rec); len(keys) != 1 || !reflect.DeepEqual(keys[0], want) {
		t.Errorf("keys = %v, want exactly %v", keys, want)
	}

	// What an ID token's header must be able to name, and what RFC 7518 says.
	fixed := map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": key.KeyID()}
	for member, value := range fixed {
		if want[member] != value {
			t.Errorf("%s = %q, want %q", member, want[member], value)
		}
	}

	if rec.Header().Get("Content-Type") != jsonType {
		t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
}

// TestKeySetWithAnInvalidKey: a key that is not a key is 503 not_configured,
// not an empty set, and the key itself is nowhere in the response or the log's
// description.
func TestKeySetWithAnInvalidKey(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"not base64":  "not a key!",
		"not a key":   "AAAA",
		"empty":       "",
		"with a line": testSigningKey + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := fullEnv()
			env[config.SecretOAuthSigningKey] = value

			r := newRigWith(t, env)
			rec := r.get(oauth.PathJWKS)

			if rec.Code != http.StatusServiceUnavailable || len(r.logged) != 1 || r.logged[0].Code != "not_configured" {
				t.Errorf("= %d %s, logged %v, want 503 not_configured", rec.Code, rec.Body, r.loggedCodes())
			}

			if value != "" && strings.Contains(rec.Body.String(), value) {
				t.Errorf("the body %q holds the key", rec.Body)
			}
		})
	}
}
