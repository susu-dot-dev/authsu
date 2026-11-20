package oauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/jws"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// IDTokenLifetime is how long an ID token is valid. It is read once, by the
// client that asked for it, so it is short.
const IDTokenLifetime = 5 * time.Minute

// bearer is the only token_type of an access token (RFC 6750).
const bearer = "Bearer"

// TokenResponse is the body of a successful POST /oauth/token (RFC 6749 section
// 5.1). expires_in is the access token's lifetime in whole seconds. Scope is the
// scope of the access token, always given: the grant's at an exchange, and at a
// refresh the subset that was asked for or, if none was, the grant's. IDToken is
// present only for a code exchange of a grant that asked for openid.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`  //nolint:tagliatelle // RFC 6749 section 5.1 names this member
	TokenType    string `json:"token_type"`    //nolint:tagliatelle // RFC 6749 section 5.1 names this member
	ExpiresIn    int64  `json:"expires_in"`    //nolint:tagliatelle // RFC 6749 section 5.1 names this member
	RefreshToken string `json:"refresh_token"` //nolint:tagliatelle // RFC 6749 section 5.1 names this member
	Scope        string `json:"scope"`
	//nolint:tagliatelle // OpenID Connect Core section 3.1.3.3 names this member
	IDToken string `json:"id_token,omitempty"`
}

// idClaims are the claims of the ID token (OpenID Connect Core section 2): the
// issuer, the user's id as subject, the client as audience, the issue and expiry
// times, when the user signed in, and the nonce the client sent, if it did. Every
// number is an integer of seconds, which jws.Sign holds to 2^53-1.
type idClaims struct {
	Issuer   string  `json:"iss"`
	Subject  string  `json:"sub"`
	Audience string  `json:"aud"`
	IssuedAt int64   `json:"iat"`
	Expires  int64   `json:"exp"`
	AuthTime int64   `json:"auth_time"` //nolint:tagliatelle // OpenID Connect Core section 2 names this claim
	Nonce    *string `json:"nonce,omitempty"`
}

// Why a token request was refused, for the log.
var errUnknownScope = errors.New("the scope is not valid for any resource")

// tokenParams are every parameter either grant type of the token endpoint
// reads, so a repeated one is refused whichever grant type it is sent with.
func tokenParams() []string {
	return []string{
		"grant_type", "client_id", paramCode, "redirect_uri", "code_verifier", "refresh_token", "scope", "resource",
	}
}

// tokenCall is what a token request carries through its steps: the request, the
// deployment's configuration, and the one reading of the clock the whole request
// uses, so the tokens' expiries, the store's "active" and the ID token's times
// are one instant.
type tokenCall struct {
	call *auth.Call
	cfg  config.Config
	now  time.Time
}

// token answers POST /oauth/token: the two grants of OAuth 2.1 that a public
// client uses, selected by grant_type.
//
// The request is parsed whole before anything is issued or written: every
// parameter it reads is a parsed value, and the first that is refused ends it
// with the code the RFC gives it. The codes, and why:
//
//   - invalid_request: the grant_type, or a parameter the grant type requires,
//     is missing; or a parameter is repeated or the form is broken (the
//     boundary's 400, 413 and 415 are this code too).
//   - unsupported_grant_type: the grant_type is present and is not one of the
//     two.
//   - invalid_client: the client_id does not parse. Clients are public and never
//     authenticate, so there is no 401 (RFC 6749 section 5.2 gives that to a
//     failed Authorization header); the 400 is the one httpapi documents.
//   - invalid_grant: a code, refresh token, redirect_uri or code_verifier that
//     does not parse, or that the store finds no live grant for. A value that
//     cannot be the one the grant holds is answered as one that is not, so the
//     answer reveals nothing about the grant, and RFC 7636 section 4.6 gives a
//     verifier that does not match this code. A verifier of the wrong length
//     (42 or 129 characters) is not a malformed request but one that can match
//     nothing, so it is the same invalid_grant and never reaches the store.
//   - invalid_scope: a refresh's scope that is not valid for the resource, names
//     nothing of it (only openid), or asks for something the grant does not hold
//     (see Scope and resource below).
//   - invalid_target: a request's resource that is not an entry of the table, or
//     is not the grant's (see Scope and resource below).
//   - server_error and temporarily_unavailable: the store, the entropy source or
//     the signer failed, and the configuration or the signing key is missing.
//     The boundary sends these, whatever their cause, with fixed text.
//
// # Scope and resource
//
// A refresh may narrow the grant's scope and may not widen it (RFC 6749 section
// 6), and an omitted scope is the grant's own. A resource named at either grant
// type must be the grant's (RFC 8707 section 2.2). Both are conditions of the
// store's rotation (store.Refresh, store.ExchangeCode), because only the write can
// compare them with the grant without a read that races it. A request that fails
// either is refused with invalid_scope or invalid_target and nothing is rotated,
// so the client's refresh token or code is not spent on a mistake it can correct
// (the store tells these apart only for a token that is otherwise live and the
// client's, so they reveal nothing to anyone who does not hold one). Before the
// write, the request is parsed: a scope must be valid for the resource it names,
// or for some resource of the table, and name something of it (openid alone is no
// access: the authorization endpoint refuses it too), and a resource must be an
// entry of the table.
//
// The access token carries the scope that was asked for (or the grant's), and the
// response and introspection report it. openid may be asked for at a refresh
// only if the grant holds it, like any scope, and it changes nothing: an ID token
// records who signed in and is issued at the exchange only.
//
// # The authorization code
//
// The client's metadata document is not fetched again: the grant records the
// client_id and the redirect URI the user approved, and the write that spends the
// code requires both to equal the request's, as well as the PKCE challenge of the
// verifier, so the document cannot widen what was approved.
//
// The ID token needs the signing key, and whether it is needed is only known
// from the grant, which is only read by the write that spends the code. So the
// signing key is loaded for every code exchange, before the write, and a
// deployment without a valid key answers 503 before it spends anything: a code
// is never burned for a failure of the server's own configuration. A refresh
// issues no ID token and loads no key.
func (d Deps) token(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(call.Config()).
		Then(func(cfg config.Config) (httpapi.Response, error) {
			return call.Request.FormParams(tokenParams()...).
				MapErr(refusing(oauthInvalidRequest)).
				Then(func(params httpapi.Params) (TokenResponse, error) {
					return d.grantType(tokenCall{call: call, cfg: cfg, now: now}, params).Get()
				}).
				Map(func(out TokenResponse) httpapi.Response { return httpapi.JSON(http.StatusOK, out) }).
				Get()
		})
}

// grantType dispatches on the grant_type.
func (d Deps) grantType(tc tokenCall, params httpapi.Params) result.Result[TokenResponse] {
	table := d.table(tc.cfg)

	return requiredAs(params, "grant_type", oauthUnsupportedGrant, input.ParseGrantType).
		Then(func(kind input.GrantType) (TokenResponse, error) {
			if kind.AuthorizationCode() {
				return d.fromCode(tc, params, table).Get()
			}

			return d.fromRefresh(tc, params, table).Get()
		})
}

// clientOf reads the client_id the request names. Clients are public: it is who
// the request says it is, and every grant is bound to it in the write.
func clientOf(params httpapi.Params, table resource.Table) result.Result[input.ClientID] {
	return requiredAs(params, "client_id", oauthInvalidClient,
		func(raw string) (input.ClientID, error) { return input.ParseClientID(raw, table) })
}

// target reads the optional resource a token request may name (RFC 8707 section
// 2.2): it must be an entry of the table, or the request is an invalid_target.
// That it is also the grant's is the store's to check (see token).
func target(params httpapi.Params, table resource.Table) result.Result[*input.ResourceID] {
	raw, _ := params.Get("resource")

	return result.Of(optional(raw, func(text string) (input.ResourceID, error) {
		return input.ParseResourceID(text, table)
	})).MapErr(refusing(oauthInvalidTarget))
}

// resourceEntries are the entries a refresh's scope may be a scope of: the one
// the request named, or, when it named none, any of the table's.
func resourceEntries(table resource.Table, named *input.ResourceID) []resource.Entry {
	if named != nil {
		return []resource.Entry{named.Entry()}
	}

	return table.Entries()
}

// scopesOfAny parses raw as the scope of the first entry it is valid for. Which
// resource the grant is for is not known until the write, which compares the
// scope with the grant's own, so a scope that is valid for any entry is parsed
// here and one that is for none is refused.
func scopesOfAny(raw string, entries []resource.Entry) result.Result[input.OAuthScopes] {
	for _, entry := range entries {
		parsed := result.Of(input.ParseOAuthScopes(raw, true, entry))
		if parsed.Err() == nil {
			return parsed
		}
	}

	return result.Fail[input.OAuthScopes](errUnknownScope)
}

// codeRequest is a parsed authorization_code request.
type codeRequest struct {
	client   input.ClientID
	code     input.AuthorizationCode
	redirect input.RedirectURI
	verifier input.CodeVerifier

	// resource is the resource the request named, or nil.
	resource *input.ResourceID
}

// parseCode parses an authorization_code request, in the order of the table in
// token. The scope of an authorization_code request is not read: the grant has
// it.
func parseCode(params httpapi.Params, table resource.Table) result.Result[codeRequest] {
	return clientOf(params, table).
		Map(func(client input.ClientID) codeRequest { return codeRequest{client: client} }).
		Then(step(params, withCode)).
		Then(step(params, withRedirectURI)).
		Then(step(params, withVerifier)).
		Then(step(params, withCodeTarget(table)))
}

// withCode requires the code. One that is not an authorization code is an
// invalid_grant, as is a refresh token or an access token presented as one.
func withCode(params httpapi.Params, req codeRequest) result.Result[codeRequest] {
	return requiredAs(params, paramCode, oauthInvalidGrant, input.ParseAuthorizationCode).
		Map(func(code input.AuthorizationCode) codeRequest {
			req.code = code

			return req
		})
}

// withRedirectURI requires the redirect_uri, which is required because the
// authorization request always had one (RFC 6749 section 4.1.3). The store
// compares it as the exact text the request used.
func withRedirectURI(params httpapi.Params, req codeRequest) result.Result[codeRequest] {
	return requiredAs(params, "redirect_uri", oauthInvalidGrant, input.ParseRedirectURI).
		Map(func(uri input.RedirectURI) codeRequest {
			req.redirect = uri

			return req
		})
}

// withVerifier requires the PKCE code_verifier (RFC 7636 section 4.5).
func withVerifier(params httpapi.Params, req codeRequest) result.Result[codeRequest] {
	return requiredAs(params, "code_verifier", oauthInvalidGrant, input.ParseCodeVerifier).
		Map(func(verifier input.CodeVerifier) codeRequest {
			req.verifier = verifier

			return req
		})
}

// withCodeTarget reads the resource the request named, if it did.
func withCodeTarget(table resource.Table) func(httpapi.Params, codeRequest) result.Result[codeRequest] {
	return func(params httpapi.Params, req codeRequest) result.Result[codeRequest] {
		return target(params, table).Map(func(named *input.ResourceID) codeRequest {
			req.resource = named

			return req
		})
	}
}

// issuedTokens are the two tokens a rotation issues.
type issuedTokens struct {
	refresh auth.Issued
	access  auth.Issued
}

// issueTokens issues a refresh token and an access token. Nothing is written: a
// failure of the entropy source ends the request before the store is asked.
func (d Deps) issueTokens(now time.Time) result.Result[issuedTokens] {
	return result.Of(auth.IssueRefreshToken(d.Entropy, now)).
		Then(func(refresh auth.Issued) (issuedTokens, error) {
			return result.Of(auth.IssueAccessToken(d.Entropy, d.NewID, now)).
				Map(func(access auth.Issued) issuedTokens { return issuedTokens{refresh: refresh, access: access} }).
				Get()
		}).
		MapErr(refusing(oauthServerError))
}

// newTokens is what the store records of the issued tokens: their hashes and
// expiries, and the id the grant's access token is created under the first time.
func (i issuedTokens) newTokens() store.NewTokens {
	return store.NewTokens{
		RefreshHash: i.refresh.Hash, RefreshExpiresAt: i.refresh.ExpiresAt,
		AccessID: i.access.ID, AccessHash: i.access.Hash, AccessExpiresAt: i.access.ExpiresAt,
	}
}

// response is the token response for the grant as the rotation left it.
func (i issuedTokens) response(grant store.Exchanged) TokenResponse {
	return TokenResponse{
		AccessToken: i.access.Token, TokenType: bearer, ExpiresIn: int64(auth.AccessTokenLifetime / time.Second),
		RefreshToken: i.refresh.Token, Scope: grant.Scope,
	}
}

// rejected maps the store's refusal of a rotation to the client's answer. Nothing
// matched, and the write cannot say why, is an invalid_grant, so the client is
// not told. A live token whose request asked for a scope or a resource the grant
// does not allow is an invalid_scope or an invalid_target. Any other failure is
// returned as it is: the store classified it.
func rejected(err error) error {
	switch {
	case errors.Is(err, store.ErrInvalidGrant):
		return failure(oauthInvalidGrant, err)
	case errors.Is(err, store.ErrInvalidScope):
		return failure(oauthInvalidScope, err)
	case errors.Is(err, store.ErrInvalidTarget):
		return failure(oauthInvalidTarget, err)
	default:
		return err
	}
}

// fromCode answers an authorization_code request: the code is exchanged for the
// grant's first tokens, with an ID token if the grant asked for openid.
func (d Deps) fromCode(tc tokenCall, params httpapi.Params, table resource.Table) result.Result[TokenResponse] {
	return parseCode(params, table).
		Then(func(req codeRequest) (TokenResponse, error) {
			// The key is loaded before anything is issued or written, so a
			// missing one spends nothing.
			return result.Of(tc.call.SigningKey()).
				Then(func(key config.SigningKey) (TokenResponse, error) { return d.redeem(tc, req, key).Get() }).
				Get()
		})
}

// redeem issues the tokens, spends the code for them in one write, and answers
// with the ID token if one was asked for.
func (d Deps) redeem(tc tokenCall, req codeRequest, key config.SigningKey) result.Result[TokenResponse] {
	return d.issueTokens(tc.now).
		Then(func(issued issuedTokens) (TokenResponse, error) {
			exchanged, err := d.Store.ExchangeCode(tc.call.Request.Context, store.CodeExchange{
				Code: req.code, ClientID: req.client, RedirectURI: req.redirect, Verifier: req.verifier,
				Resource: req.resource, CodeLifetime: auth.CodeLifetime, Tokens: issued.newTokens(),
			}, tc.now)
			if err != nil {
				return TokenResponse{}, rejected(err)
			}

			return d.identify(tc, key, exchanged).
				Map(func(idToken string) TokenResponse {
					out := issued.response(exchanged)
					out.IDToken = idToken

					return out
				}).
				Get()
		})
}

// identify is the ID token of an exchanged grant, or "" when the grant did not
// ask for openid. The grant's resource and scope are read back through their
// parsers, as the pending request's are: they were parsed when approved and are
// parsed again, because what is stored may be older than the table. One that no
// longer parses is the service's defect, not the client's, and the client is told
// server_error.
func (d Deps) identify(tc tokenCall, key config.SigningKey, grant store.Exchanged) result.Result[string] {
	return result.Of(input.ParseResourceID(grant.Resource, d.table(tc.cfg))).
		Then(func(target input.ResourceID) (input.OAuthScopes, error) {
			return input.ParseOAuthScopes(grant.Scope, true, target.Entry())
		}).
		MapErr(refusing(oauthServerError)).
		Then(func(scopes input.OAuthScopes) (string, error) {
			if !scopes.OpenID() {
				return "", nil
			}

			return signIDToken(tc, key, grant).Get()
		})
}

// signIDToken signs the ID token of a grant: see idClaims. It is issued at the
// exchange only, with the sign-in time the grant recorded at consent and the
// nonce the client sent at authorization.
func signIDToken(tc tokenCall, key config.SigningKey, grant store.Exchanged) result.Result[string] {
	claims := idClaims{
		Issuer: tc.cfg.API.String, Subject: grant.UserID, Audience: grant.ClientID,
		IssuedAt: tc.now.Unix(), Expires: tc.now.Add(IDTokenLifetime).Unix(), AuthTime: grant.AuthTime.Unix(),
		Nonce: grant.Nonce,
	}

	return result.Of(jws.Sign(key.Private(), key.KeyID(), claims)).MapErr(refusing(oauthServerError))
}

// refreshRequest is a parsed refresh_token request.
type refreshRequest struct {
	client input.ClientID
	token  input.RefreshToken

	// resource is the resource the request named, or nil, and scope the scope it
	// asked for, or nil for the grant's own.
	resource *input.ResourceID
	scope    *input.OAuthScopes
}

// parseRefresh parses a refresh_token request. The resource and the scope are
// optional, and the store holds them to the grant (see token).
func parseRefresh(params httpapi.Params, table resource.Table) result.Result[refreshRequest] {
	return clientOf(params, table).
		Then(func(client input.ClientID) (refreshRequest, error) {
			return requiredAs(params, "refresh_token", oauthInvalidGrant, input.ParseRefreshToken).
				Map(func(token input.RefreshToken) refreshRequest { return refreshRequest{client: client, token: token} }).
				Get()
		}).
		Then(step(params, withRefreshTarget(table))).
		Then(step(params, withRefreshScope(table)))
}

// withRefreshTarget reads the resource the request named, if it did.
func withRefreshTarget(table resource.Table) func(httpapi.Params, refreshRequest) result.Result[refreshRequest] {
	return func(params httpapi.Params, req refreshRequest) result.Result[refreshRequest] {
		return target(params, table).Map(func(named *input.ResourceID) refreshRequest {
			req.resource = named

			return req
		})
	}
}

// withRefreshScope reads the scope the request asked for, if it did: it must be
// valid for the resource the request named or, if it named none, for some
// resource of the table, and name something of it, as the authorization endpoint
// requires (a scope of only openid is no access to delegate). Whether the grant
// holds it is the write's to decide.
func withRefreshScope(table resource.Table) func(httpapi.Params, refreshRequest) result.Result[refreshRequest] {
	return func(params httpapi.Params, req refreshRequest) result.Result[refreshRequest] {
		raw, present := params.Get("scope")
		if !present {
			return result.Ok(req)
		}

		return scopesOfAny(raw, resourceEntries(table, req.resource)).
			Check(requireResourceScope).
			MapErr(refusing(oauthInvalidScope)).
			Map(func(scopes input.OAuthScopes) refreshRequest {
				req.scope = &scopes

				return req
			})
	}
}

// fromRefresh answers a refresh_token request: the refresh token is exchanged
// for the grant's next tokens. No ID token is issued: it records who signed in
// and is read once, at the exchange.
func (d Deps) fromRefresh(tc tokenCall, params httpapi.Params, table resource.Table) result.Result[TokenResponse] {
	return parseRefresh(params, table).
		Then(func(req refreshRequest) (TokenResponse, error) {
			return d.issueTokens(tc.now).
				Then(func(issued issuedTokens) (TokenResponse, error) {
					exchanged, err := d.Store.Refresh(tc.call.Request.Context, store.RefreshExchange{
						Token: req.token, ClientID: req.client, Scope: req.scope, Resource: req.resource,
						Tokens: issued.newTokens(),
					}, tc.now)
					if err != nil {
						return TokenResponse{}, rejected(err)
					}

					return issued.response(exchanged), nil
				}).
				Get()
		})
}
