// Package oauth is the OAuth 2.1 authorization server of docs/oauth_design.md:
// discovery, the key set, the authorization endpoint, the consent API the UI
// calls, and the endpoints a client and a resource server call.
//
//	GET    /.well-known/oauth-authorization-server  RFC 8414 metadata
//	GET    /.well-known/openid-configuration        OpenID Connect Discovery
//	GET    /.well-known/jwks.json                   the ID token's public key
//	GET    /oauth/authorize                         starts a request; only ever answers 302
//	GET    /api/oauth/request?request=              what the consent screen shows
//	POST   /api/oauth/consent                       the user's answer; returns where to go next
//	POST   /oauth/token                             authorization code or refresh token for tokens
//	POST   /oauth/revoke                            RFC 7009 revocation of a refresh or access token
//	POST   /oauth/introspect                        RFC 7662, for a resource server, audience-bound
//	GET    /api/grant                               the user's grants, newest first
//	GET    /api/grant/{id}                          one of the user's grants
//	DELETE /api/grant/{id}                          revoke one, with its tokens
//
// Each route lives in its own file (metadata.go, jwks.go, authorize.go,
// request.go, consent.go, token.go, revoke.go, introspect.go, grants.go) and the
// helpers they share are in shared.go and pending.go, so a route is added with
// one file and one line of Routes.
//
// # The authorization request
//
// Nothing is stored until the user approves. GET /oauth/authorize checks the
// client's request and, if it is acceptable, seals everything it parsed into a
// pending request (pending.go) and redirects the browser to the UI with it. The
// UI shows the request (GET /api/oauth/request), signs the user in if need be,
// and sends the user's answer back with the same sealed value (POST
// /api/oauth/consent). The sealed value is integrity-protected and expires in
// PendingLifetime; consent is single use because the grant row records the hash
// of the sealed value in a unique column (store.CreateGrant).
//
// # First-party login
//
// A trusted client (resource.Table.Trusted) may name the first-party login
// resource, and its request is sent to the UI's /oauth/login page, which only
// signs the person in, instead of the consent page. The UI's approval names no
// agent, and the grant is held by the agent authsu keeps for that user and
// client (store.NewGrant.FirstParty). What an approval must carry follows the
// opened request, never the body (chooseAgent). The ID token of such a grant
// carries the user's name and email, with email_verified false.
//
// # The token endpoints
//
// The token, revocation and introspection endpoints are for software and not a
// person. They take application/x-www-form-urlencoded and answer in the RFC 6749
// error format, and none takes a credential: a public client is identified by
// its client_id and holds the tokens, and a resource server holds nothing. Each
// declares that explicitly (form in shared.go), and the boundary refuses a form
// on any route that needs a credential.
//
// Every value they read is parsed into an internal/input type before anything is
// issued or written. A parameter they do not read is ignored and one they read
// is refused if repeated (RFC 6749 section 3.1). The token endpoint does not
// fetch the client's metadata document again: a grant records the client_id and
// the redirect URI the user approved, and the write that spends a code requires
// both to match, so the document cannot widen the grant after consent.
//
// # Errors: where they go
//
// The redirect URI is trusted only once the client's metadata document, fetched
// from its client_id, registers it. Every failure up to and including that point
// answers 302 to the UI's error page (UI_ORIGIN/oauth/error?error=<code>) and
// never to the client, so a request cannot make this server redirect to a URI a
// stranger chose, and the person sees what went wrong instead of a client's
// page. Every failure after it answers 302 to the redirect URI with error,
// error_description, state and iss (RFC 6749 section 4.1.2.1, RFC 9207). The
// codes are in shared.go.
//
// # Risk: an unauthenticated request makes an outbound fetch
//
// GET /oauth/authorize needs no credential and fetches the document at the
// client_id it is given, so anyone can make this Worker send requests to a URL
// of their choice, and to as many as they like. The fetch is bounded by what
// internal/fetch enforces (GET only, no redirect, a 5 s timeout, a 5 KiB body
// cap, a JSON content type) and by what input.ParseClientID admits (https, a
// public DNS name, never an IP address or a reserved name). The fetch is made
// as soon as client_id and redirect_uri parse, before the other parameters are
// looked at, because a failure of any of them is reported to the client at a
// redirect URI that is trusted only once the document lists it: a request that is
// wrong in every other parameter still costs one fetch. Rate limiting is out of
// scope of this package, so the risk is amplification and nothing worse: the
// response is never sent to the person who asked, and no credential or cookie is
// sent to the target.
package oauth

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/fetch"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// The routes. The paths of the endpoints a client calls are also in the
// discovery documents, so they are named once here.
const (
	// PathMetadata is the RFC 8414 authorization server metadata.
	PathMetadata = "/.well-known/oauth-authorization-server"
	// PathOpenIDConfiguration is the OpenID Connect discovery document.
	PathOpenIDConfiguration = "/.well-known/openid-configuration"
	// PathJWKS is the key set the ID token is verified with.
	PathJWKS = "/.well-known/jwks.json"
	// PathAuthorize is the authorization endpoint.
	PathAuthorize = "/oauth/authorize"
	// PathToken is the token endpoint.
	PathToken = "/oauth/token" //nolint:gosec // a path, not a credential
	// PathRevoke is the revocation endpoint (RFC 7009).
	PathRevoke = "/oauth/revoke"
	// PathIntrospect is the introspection endpoint (RFC 7662).
	PathIntrospect = "/oauth/introspect"
	// PathRequest is the UI's read of a pending authorization request.
	PathRequest = "/api/oauth/request"
	// PathConsent is the UI's answer to one.
	PathConsent = "/api/oauth/consent"
	// PathGrants is the user's list of grants, and PathGrant one of them.
	PathGrants = "/api/grant"
	PathGrant  = "/api/grant/{id}"
)

// The pages of the UI the authorization endpoint sends the browser to, relative
// to UI_ORIGIN.
const (
	uiConsentPath = "/oauth/consent"
	uiLoginPath   = "/oauth/login"
	uiErrorPath   = "/oauth/error"
)

// Limits of the routes, in bytes of the request's query string or body.
const (
	// MaxDiscoveryBody caps the request to a discovery document or the key set,
	// which read nothing from it.
	MaxDiscoveryBody = 1 << 10

	// MaxQuery caps the query string of the authorization endpoint and of the
	// read of a pending request. The widest legitimate authorization request is
	// about 6 KiB with every value percent-encoded (the bounds are in
	// internal/input), and the sealed value the UI sends back is under 5.6 KiB.
	MaxQuery = 8 << 10

	// MaxConsentBody caps the consent body: the sealed value, as much as 5.6 KiB,
	// and an agent name of at most 256 characters, as much as 3 KiB with every
	// one escaped, and the framing.
	MaxConsentBody = 12 << 10

	// MaxTokenBody caps the token request. Its values are bounded by input
	// (a client_id and a redirect_uri of 512 bytes, a verifier of 128, a scope
	// of 256 and a resource of 128, a token of 53 or fewer), which is under 1.8
	// KiB, and as much as 5.4 KiB with every byte percent-encoded.
	MaxTokenBody = 8 << 10

	// MaxRevokeBody caps the revocation request: a client_id of at most 512
	// bytes, and a token, which may be any text the client holds (a token that
	// is not ours is answered like any other), so the cap is what a token that
	// is not ours may be as long as, about 2 KiB after the client_id.
	MaxRevokeBody = 4 << 10

	// MaxIntrospectBody caps the introspection request: a token of 53 bytes
	// and a resource of at most 128, each as much as three times that encoded.
	MaxIntrospectBody = 2 << 10

	// MaxGrantQuery caps the query string of the grant routes, which read a
	// limit and a cursor (a UUID) and nothing else.
	MaxGrantQuery = 1 << 10
)

// PendingLifetime is how long a pending authorization request can be approved.
// It is how long a person has to sign in and read the consent screen, and it is
// the validity of the sealed value, so it is also how long a replayed link is
// of any use.
const PendingLifetime = 10 * time.Minute

// Store is the part of the database the OAuth routes use. *store.Store
// satisfies it. A failure must come back classified (the store does), because
// it is sent as it is.
type Store interface {
	// CreateGrant writes the grant of an approved request, with its agent when
	// the user chose to create one, as one batch. It returns one of the
	// store's refusals (ErrGrantReplayed, ErrAgentLimit, ErrAgentUnavailable,
	// ErrUserInactive, ErrSessionInactive), in which case nothing was written.
	CreateGrant(ctx context.Context, grant store.NewGrant) error

	// ExchangeCode spends an authorization code and gives the grant its first
	// refresh and access tokens, as one atomic write, or returns
	// store.ErrInvalidGrant when nothing matched, or store.ErrInvalidTarget when
	// the code is good and the resource it named is not the grant's (and writes
	// nothing).
	ExchangeCode(ctx context.Context, exchange store.CodeExchange, now time.Time) (store.Exchanged, error)
	// Refresh rotates a refresh token and replaces the grant's access token with
	// one of the scope that was asked for, or returns store.ErrInvalidGrant, or,
	// for a token that is live and the client's, store.ErrInvalidScope or
	// store.ErrInvalidTarget when the scope or the resource asked for is not
	// within the grant's. A refusal writes nothing and the token stays good.
	Refresh(ctx context.Context, exchange store.RefreshExchange, now time.Time) (store.Exchanged, error)
	// IntrospectAccessToken reads a live access token for exactly this
	// resource, and reports false for any other.
	IntrospectAccessToken(
		ctx context.Context, token input.AccessToken, resource input.ResourceID, now time.Time,
	) (store.ActiveAccessToken, bool, error)
	// RevokeRefreshToken revokes the grant a refresh token belongs to and its
	// access token, if it is the client's. A token that is not one is no error.
	RevokeRefreshToken(ctx context.Context, token input.RefreshToken, client input.ClientID, now time.Time) error
	// RevokeAccessToken revokes an access token, only, if it is the client's.
	RevokeAccessToken(ctx context.Context, token input.AccessToken, client input.ClientID, now time.Time) error

	// ListGrants returns a page of the owner's grants, newest first, whether or
	// not their codes were exchanged.
	ListGrants(
		ctx context.Context, owner string, cursor input.Cursor, limit input.PageLimit,
	) (store.GrantPage, error)
	// GetGrant returns one of the owner's grants, or store.ErrNotFound.
	GetGrant(ctx context.Context, owner string, id input.ID) (store.Grant, error)
	// RevokeGrant revokes one of the owner's grants and its access token and
	// returns it as the write left it, or store.ErrNotFound.
	RevokeGrant(ctx context.Context, owner string, id input.ID, now time.Time) (store.Grant, error)
}

// Deps are the collaborators of Routes. All are required: Routes panics on a
// missing one, so a handler never meets a nil dependency.
type Deps struct {
	// Store holds the grants.
	Store Store

	// Resources selects the table of resource servers for an API_ORIGIN
	// (resource.Select in production). It is a function because the
	// configuration is read per request.
	Resources func(apiOrigin string) resource.Table

	// Fetch sends the request for a client's metadata document (the platform's
	// fetch in production). It must not follow redirects.
	Fetch fetch.Doer

	// Now is the clock.
	Now func() time.Time

	// Entropy is the source of randomness the pending request's random value
	// and the authorization code are generated from (crypto/rand.Reader in
	// production).
	Entropy io.Reader

	// NewID returns a fresh UUIDv7 in canonical text form: the id of a grant
	// and of an agent that consent creates.
	NewID func() string

	// MaxAgents is how many active agents a user may have, which the write of a
	// new agent enforces (agents.MaxAgentsPerUser in production). It is passed in
	// because a feature does not import another.
	MaxAgents int

	// Log records a request that was answered with a redirect, with the cause,
	// which a redirect cannot carry: it is where the reason for an error page
	// is.
	Log httpapi.Logger
}

// PublicPaths are the paths that are called from a browser on any origin, and so
// get the credential-less CORS policy (httpapi.CORS): the discovery documents,
// the key set, and the token and revocation endpoints. They authenticate by what
// the request carries and never by a cookie. The list is exact paths, and a test
// holds every route at one of them to the credential None.
func PublicPaths() []string {
	return []string{PathMetadata, PathOpenIDConfiguration, PathJWKS, PathToken, PathRevoke}
}

// NoCORSPaths are the paths that get no CORS at all, whatever the origin
// (httpapi.CORS): the authorization endpoint, which a browser navigates to and
// no script reads, and introspection, which a resource server calls and no
// browser should. Without this they would fall under the credentialed policy of
// the first party's origin, which would let a page on that origin call them with
// the user's cookies, and neither wants that. The list is exact paths and
// disjoint from PublicPaths, and a test holds every route at one of them to the
// credential None.
func NoCORSPaths() []string {
	return []string{PathAuthorize, PathIntrospect}
}

// Routes returns the OAuth routes. The discovery, key set, authorization,
// pending-request and token-endpoint routes need no credential: they are called
// before the user has a session, or by software that has none, and the token
// endpoints are authenticated by what the request carries. Consent is the one
// that authorizes, and it needs a session (a person was present) and refuses
// agents and API keys: an approval is a person delegating. The grant routes are
// the user's own: reading a grant needs grant:read, as listing keys needs
// key:read, and revoking needs grant:revoke and refuses agents, which are peers.
//
// It panics when a dependency is missing.
func Routes(deps Deps) []auth.Route {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Resources": deps.Resources == nil, "Fetch": deps.Fetch == nil,
		"Now": deps.Now == nil, "Entropy": deps.Entropy == nil, "NewID": deps.NewID == nil,
		"MaxAgents": deps.MaxAgents <= 0, "Log": deps.Log == nil,
	} {
		if missing {
			panic("oauth: Deps." + name + " is required")
		}
	}

	return []auth.Route{
		open(PathMetadata, MaxDiscoveryBody, deps.metadata),
		open(PathOpenIDConfiguration, MaxDiscoveryBody, deps.openIDConfiguration),
		open(PathJWKS, MaxDiscoveryBody, deps.jwks),
		openOAuth(PathAuthorize, MaxQuery, deps.authorize),
		open(PathRequest, MaxQuery, deps.request),
		{
			Method: http.MethodPost, Path: PathConsent, MaxBody: MaxConsentBody,
			Credential: auth.Authenticated, Access: auth.Open().Sessions().WithoutAgents(), Handle: deps.consent,
		},
		form(PathToken, MaxTokenBody, deps.token),
		form(PathRevoke, MaxRevokeBody, deps.revoke),
		form(PathIntrospect, MaxIntrospectBody, deps.introspect),
		grantRoute(http.MethodGet, PathGrants, auth.Needs(scope.GrantRead), deps.listGrants),
		grantRoute(http.MethodGet, PathGrant, auth.Needs(scope.GrantRead), deps.getGrant),
		grantRoute(http.MethodDelete, PathGrant, auth.Needs(scope.GrantRevoke).WithoutAgents(), deps.revokeGrant),
	}
}
