//go:build e2e

//nolint:goconst,funlen,cyclop,gocognit,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_public_test.go: the OAuth routes that need no credential, as a browser or
// a stranger sees them: the discovery documents and the key set (readable from any
// origin, never with credentials), the endpoints that get no CORS at all, and the
// boundary's own answers (method, media type, size) on the OAuth routes.

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const (
	hdrAllowOrigin  = "Access-Control-Allow-Origin"
	hdrAllowCreds   = "Access-Control-Allow-Credentials"
	hdrAllowMethods = "Access-Control-Allow-Methods"
	hdrRequestMeth  = "Access-Control-Request-Method"

	strangerOrigin = "https://stranger.example"
)

// TestOAuthDiscovery: the two discovery documents say what this server does,
// with the endpoints under the Worker's own origin, and the key set holds exactly
// the configured public key. All three are open to any origin without
// credentials, whoever asks.
//
//nolint:paralleltest // shares one database
func TestOAuthDiscovery(t *testing.T) {
	reset(t)

	origins := []struct{ name, origin string }{
		{"no origin", ""}, {"the UI's origin", target.origin}, {"a stranger's origin", strangerOrigin},
	}

	for _, path := range []string{pathOAuthMetadata, pathOpenIDConfig, pathJWKS} {
		for _, from := range origins {
			t.Run(path+"/"+from.name, func(t *testing.T) {
				got := send(t, request{path: path, headers: map[string]string{"Origin": from.origin}})
				if got.status != http.StatusOK || !strings.HasPrefix(got.header.Get("Content-Type"), jsonType) {
					t.Fatalf("GET %s = %d %q %s", path, got.status, got.header.Get("Content-Type"), got.body)
				}

				if got.header.Get(hdrAllowOrigin) != "*" || got.header.Get(hdrAllowCreds) != "" {
					t.Errorf("CORS headers of %s = %v, want origin * and no credentials", path, got.header)
				}

				if leaks := bndLeaks(got.body); len(leaks) != 0 {
					t.Errorf("%s matches leak patterns %v", path, leaks)
				}
			})
		}
	}

	t.Run("the RFC 8414 document", func(t *testing.T) {
		var doc map[string]any

		got := get(t, pathOAuthMetadata, "")

		err := json.Unmarshal([]byte(got.body), &doc)
		if err != nil {
			t.Fatalf("parse %s: %v", got.body, err)
		}

		want := map[string]any{
			"issuer":                                target.apiOrigin,
			"authorization_endpoint":                target.apiOrigin + pathOAuthAuthorize,
			"token_endpoint":                        target.apiOrigin + pathOAuthToken,
			"revocation_endpoint":                   target.apiOrigin + pathOAuthRevoke,
			"introspection_endpoint":                target.apiOrigin + pathOAuthIntrospect,
			"jwks_uri":                              target.apiOrigin + pathJWKS,
			"client_id_metadata_document_supported": true,
			"authorization_response_iss_parameter_supported": true,
		}

		for name, value := range want {
			if doc[name] != value {
				t.Errorf("%s = %v, want %v", name, doc[name], value)
			}
		}

		lists := map[string][]string{
			"response_types_supported":                      {"code"},
			"response_modes_supported":                      {"query"},
			"grant_types_supported":                         {"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":              {"S256"},
			"token_endpoint_auth_methods_supported":         {"none"},
			"revocation_endpoint_auth_methods_supported":    {"none"},
			"introspection_endpoint_auth_methods_supported": {"none"},
			"scopes_supported":                              {"openid", "mcp:read", "mcp:write", "profile", "email", "offline_access"},
		}

		for name, wantList := range lists {
			if got := oaStrings(doc[name]); !slices.Equal(got, wantList) {
				t.Errorf("%s = %v, want %v", name, got, wantList)
			}
		}
	})

	t.Run("the OpenID Connect document", func(t *testing.T) {
		var doc map[string]any

		got := get(t, pathOpenIDConfig, "")

		err := json.Unmarshal([]byte(got.body), &doc)
		if err != nil {
			t.Fatalf("parse %s: %v", got.body, err)
		}

		if doc["issuer"] != target.apiOrigin || doc["jwks_uri"] != target.apiOrigin+pathJWKS {
			t.Errorf("issuer and jwks_uri = %v, %v", doc["issuer"], doc["jwks_uri"])
		}

		lists := map[string][]string{
			"id_token_signing_alg_values_supported": {"RS256"},
			"subject_types_supported":               {"public"},
			"claims_supported":                      {"iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "name", "email", "email_verified"},
		}

		for name, wantList := range lists {
			if got := oaStrings(doc[name]); !slices.Equal(got, wantList) {
				t.Errorf("%s = %v, want %v", name, got, wantList)
			}
		}
	})

	t.Run("the key set is the configured public key", func(t *testing.T) {
		oaPublicKey(t)
	})
}

// oaStrings reads a JSON array of strings.
func oaStrings(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))

	for _, item := range items {
		text, _ := item.(string)
		out = append(out, text)
	}

	return out
}

// TestOAuthCORS: which OAuth routes a page on another origin may call. The
// discovery documents, the key set and the token and revocation endpoints allow
// any origin and never credentials, including their preflight and their errors.
// The authorization endpoint (a navigation) and introspection (called by servers)
// allow no stranger, and a preflight to either is not answered with an allowance.
//
//nolint:paralleltest // shares one database
func TestOAuthCORS(t *testing.T) {
	reset(t)

	t.Run("public paths", func(t *testing.T) {
		cases := []struct {
			path    string
			method  string
			methods string // Access-Control-Allow-Methods of the preflight
		}{
			{pathOAuthMetadata, http.MethodGet, http.MethodGet},
			{pathOpenIDConfig, http.MethodGet, http.MethodGet},
			{pathJWKS, http.MethodGet, http.MethodGet},
			{pathOAuthToken, http.MethodPost, http.MethodPost},
			{pathOAuthRevoke, http.MethodPost, http.MethodPost},
		}

		for _, tt := range cases {
			t.Run(tt.path+" preflight", func(t *testing.T) {
				got := send(t, request{method: http.MethodOptions, path: tt.path, headers: map[string]string{
					"Origin": strangerOrigin, hdrRequestMeth: tt.method, "Access-Control-Request-Headers": "content-type",
				}})
				if got.status != http.StatusNoContent || got.header.Get(hdrAllowOrigin) != "*" ||
					got.header.Get(hdrAllowMethods) != tt.methods || got.header.Get(hdrAllowCreds) != "" ||
					got.header.Get("Access-Control-Allow-Headers") != "Content-Type" {
					t.Errorf("preflight of %s = %d %v", tt.path, got.status, got.header)
				}
			})
		}

		t.Run("a preflight asking for a header it does not allow gets no allowance of it", func(t *testing.T) {
			got := send(t, request{method: http.MethodOptions, path: pathOAuthToken, headers: map[string]string{
				"Origin": strangerOrigin, hdrRequestMeth: "POST", "Access-Control-Request-Headers": "authorization",
			}})
			if got.header.Get("Access-Control-Allow-Headers") != "" {
				t.Errorf("allowed headers = %q for a request for authorization", got.header.Get("Access-Control-Allow-Headers"))
			}
		})

		t.Run("an error response is readable by any origin too", func(t *testing.T) {
			for _, path := range []string{pathOAuthToken, pathOAuthRevoke} {
				got := send(t, request{
					method: http.MethodPost, path: path, body: []byte("{}"),
					headers: map[string]string{"Origin": strangerOrigin},
				})
				if got.status != http.StatusUnsupportedMediaType || got.header.Get(hdrAllowOrigin) != "*" ||
					got.header.Get(hdrAllowCreds) != "" {
					t.Errorf("POST %s with JSON from a stranger = %d %v", path, got.status, got.header)
				}
			}
		})
	})

	t.Run("authorize and introspect", func(t *testing.T) {
		client := newOAuthClient(t)
		query := client.authorizeQuery(newPKCE())

		// No origin gets an allowance, the UI's own included: neither is a call a
		// page makes.
		for _, from := range []string{"", strangerOrigin, target.origin} {
			label := "from " + from
			if from == "" {
				label = "with no origin"
			}

			t.Run("authorize "+label, func(t *testing.T) {
				got := send(t, request{
					path: pathOAuthAuthorize + "?" + query.Encode(), keepRedirect: true, headers: map[string]string{"Origin": from},
				})
				if got.status != http.StatusFound || got.header.Get(hdrAllowOrigin) != "" || got.header.Get(hdrAllowCreds) != "" {
					t.Errorf("authorize from %q = %d %v", from, got.status, got.header)
				}
			})

			t.Run("introspect "+label, func(t *testing.T) {
				got := send(t, request{method: http.MethodPost, path: pathOAuthIntrospect, body: []byte("token=x&resource=y"),
					headers: map[string]string{"Origin": from, "Content-Type": formType}})
				if got.status != http.StatusOK || got.header.Get(hdrAllowOrigin) != "" || got.header.Get(hdrAllowCreds) != "" {
					t.Errorf("introspect from %q = %d %v", from, got.status, got.header)
				}
			})
		}

		for _, tt := range []struct{ path, method string }{
			{pathOAuthAuthorize, http.MethodGet}, {pathOAuthIntrospect, http.MethodPost},
		} {
			t.Run(tt.path+" preflight from a stranger", func(t *testing.T) {
				got := send(t, request{method: http.MethodOptions, path: tt.path, headers: map[string]string{
					"Origin": strangerOrigin, hdrRequestMeth: tt.method,
				}})
				if got.header.Get(hdrAllowOrigin) != "" || got.header.Get(hdrAllowMethods) != "" || got.header.Get(hdrAllowCreds) != "" {
					t.Errorf("preflight of %s from a stranger = %d %v", tt.path, got.status, got.header)
				}
			})
		}
	})

	t.Run("the credentialed routes keep the UI's policy", func(t *testing.T) {
		for _, path := range []string{pathOAuthRequest + "?request=x", pathGrant, pathOAuthConsent} {
			ui := send(t, request{path: path, headers: map[string]string{"Origin": target.origin}})
			if ui.header.Get(hdrAllowOrigin) != target.origin || ui.header.Get(hdrAllowCreds) != "true" {
				t.Errorf("%s from the UI: %v, want its origin with credentials", path, ui.header)
			}

			stranger := send(t, request{path: path, headers: map[string]string{"Origin": strangerOrigin}})
			if stranger.header.Get(hdrAllowOrigin) != "" || stranger.header.Get(hdrAllowCreds) != "" {
				t.Errorf("%s from a stranger: %v, want no allowance", path, stranger.header)
			}
		}
	})
}
