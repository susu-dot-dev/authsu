package oauth

import (
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// metadataDocument is the authorization server metadata of RFC 8414, with
// the members RFC 9207 (authorization_response_iss_parameter_supported) and the
// Client ID Metadata Document draft (client_id_metadata_document_supported) add.
// Every member is derived from the request's configuration, so the document says
// what the deployment does and cannot drift from it: the endpoints are under
// API_ORIGIN, the scopes are the selected resource table's.
//
//nolint:tagliatelle // RFC 8414 names the members, in snake case
type metadataDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	ScopesSupported                           []string `json:"scopes_supported"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	ResponseModesSupported                    []string `json:"response_modes_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`

	ClientIDMetadataDocumentSupported          bool `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// openIDDocument is the same document with what OpenID Connect Discovery 1.0
// requires on top: the subject types, the ID token's signing algorithm, and the
// claims the ID token carries.
//
//nolint:tagliatelle // OpenID Connect Discovery names the members, in snake case
type openIDDocument struct {
	metadataDocument

	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// idTokenClaims are the claims of the ID token (docs/oauth_design.md): who
// signed in and when, for whom the token is, and the request's nonce, and for a
// first-party login the user's name and email, with email_verified false because
// authsu does not verify addresses. The token grants nothing.
func idTokenClaims() []string {
	return []string{"iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "name", "email", "email_verified"}
}

// document builds the metadata for cfg's deployment. The "none" client
// authentication is what a public client uses at the token, revocation and
// introspection endpoints: none of them authenticates a client, which is why
// they are a request's own proof (a code with its verifier, a token) and never
// a credential. response_modes_supported is query only: a response is never
// sent in a fragment or a form post, and the default (query and fragment) would
// say it is.
func (d Deps) document(cfg config.Config) metadataDocument {
	none := []string{"none"}
	scopes := []string{input.OpenIDScope}

	for _, entry := range d.table(cfg).Entries() {
		scopes = append(scopes, entry.Scopes...)

		// A first-party login also accepts the two OpenID Connect names a
		// standard client sends (input.ParseFirstPartyScopes), so the document
		// lists them, once, for a client that checks.
		if entry.FirstParty {
			scopes = append(scopes, input.EmailScope, input.OfflineAccessScope)
		}
	}

	return metadataDocument{
		Issuer:                cfg.API.String,
		AuthorizationEndpoint: cfg.API.String + PathAuthorize,
		TokenEndpoint:         cfg.API.String + PathToken,
		RevocationEndpoint:    cfg.API.String + PathRevoke,
		IntrospectionEndpoint: cfg.API.String + PathIntrospect,
		JWKSURI:               cfg.API.String + PathJWKS,

		ScopesSupported:                           scopes,
		ResponseTypesSupported:                    []string{paramCode},
		ResponseModesSupported:                    []string{"query"},
		GrantTypesSupported:                       []string{input.GrantAuthorizationCode, input.GrantRefreshToken},
		CodeChallengeMethodsSupported:             []string{"S256"},
		TokenEndpointAuthMethodsSupported:         none,
		RevocationEndpointAuthMethodsSupported:    none,
		IntrospectionEndpointAuthMethodsSupported: none,

		ClientIDMetadataDocumentSupported:          true,
		AuthorizationResponseIssParameterSupported: true,
	}
}

// metadata answers GET /.well-known/oauth-authorization-server.
func (d Deps) metadata(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(call.Config()).
		Map(d.document).
		Map(func(doc metadataDocument) httpapi.Response { return httpapi.JSON(http.StatusOK, doc) })
}

// openIDConfiguration answers GET /.well-known/openid-configuration.
func (d Deps) openIDConfiguration(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(call.Config()).
		Map(func(cfg config.Config) openIDDocument {
			return openIDDocument{
				metadataDocument:                 d.document(cfg),
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
				ClaimsSupported:                  idTokenClaims(),
			}
		}).
		Map(func(doc openIDDocument) httpapi.Response { return httpapi.JSON(http.StatusOK, doc) })
}
