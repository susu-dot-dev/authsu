package oauth

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/fetch"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Why an authorization request was refused, for the log. The client is told only
// the OAuth code (and the UI the same code), never these.
var (
	errMissingParameter = errors.New("a required parameter is missing")
	errNotRegistered    = errors.New("the client's document does not register the redirect URI")
	errNoResourceScope  = errors.New("the scope names no scope of the resource")
)

// trusted is a client and a redirect URI that the client's own document
// vouches for: the document was fetched from the client_id, is the client_id's,
// and lists the redirect URI. Only a value of this type may be redirected to.
type trusted struct {
	meta     input.ClientMetadata
	redirect input.RedirectURI
}

// candidate is a client_id and a redirect URI that parse and are not yet
// vouched for by anything.
type candidate struct {
	clientID input.ClientID
	redirect input.RedirectURI
}

// authorize answers GET /oauth/authorize (RFC 6749 section 4.1.1, with PKCE, RFC
// 7636, and resource indicators, RFC 8707). It answers 302 and only 302, whether
// the request is acceptable or not (a failure of the configuration is the one
// exception: it is the boundary's 503).
//
// The request is judged in two stages, and which stage a failure is in decides
// where the browser is sent:
//
//   - Before the redirect URI is trusted: client_id and redirect_uri, the
//     client's document, and that the document lists the redirect URI. Every
//     failure is a 302 to the UI's error page with the error code and nothing
//     else (trust). A duplicated client_id or redirect_uri is here too: which
//     of the two was meant cannot be known.
//   - After: every other parameter. Every failure is a 302 to the redirect URI,
//     with error, error_description, state (only a state that parsed) and iss
//     (answer).
//
// Parameters other than the ones this reads are ignored, as RFC 6749 section
// 3.1 requires, and every one it reads must appear at most once.
//
// What a failure of either stage was, in full, is logged (Deps.Log): a redirect
// carries only the code, because a cause can quote what the other server sent.
func (d Deps) authorize(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(call.Config()).
		Map(func(cfg config.Config) httpapi.Response { return d.authorizeWith(call, cfg) })
}

// authorizeWith answers the request under cfg: see authorize.
func (d Deps) authorizeWith(call *auth.Call, cfg config.Config) httpapi.Response {
	table := d.table(cfg)

	vouched, err := d.trust(call, table).Get()
	if err != nil {
		d.Log(call.Request, apierr.As(err))

		return redirect(uiPage(cfg, uiErrorPath, url.Values{paramError: {oauthCode(err)}}))
	}

	state := echoable(call.Request)

	text, err := d.parseRequest(call.Request, table, vouched).
		Then(func(request pendingRequest) (string, error) { return d.seal(cfg, request, d.Now()).Get() }).
		Get()
	if err != nil {
		d.Log(call.Request, apierr.As(err))

		return redirect(errorURL(cfg, vouched.redirect, state, oauthCode(err)))
	}

	return redirect(uiPage(cfg, uiConsentPath, url.Values{"request": {text}}))
}

// errorURL is where the browser is sent for an error after the redirect URI is
// trusted: the redirect URI with error and its fixed description, the state if
// there is one, and the issuer (RFC 6749 section 4.1.2.1, RFC 9207). The
// issuer is always sent, so a client can tell which server answered.
func errorURL(cfg config.Config, to input.RedirectURI, state *input.State, code string) string {
	params := url.Values{paramError: {code}, "error_description": {describe(code)}, "iss": {cfg.API.String}}

	if state != nil {
		params.Set("state", state.String())
	}

	return withQuery(to.String(), params)
}

// trust decides whether the redirect URI can be trusted, and returns it with
// the client's document if so. The document is fetched as soon as client_id and
// redirect_uri parse: the other parameters are not checked first, because a
// failure of any of them is reported to the client at its redirect URI, which
// is not trusted until the document lists it. So a request that is wrong in
// every other parameter still costs one fetch, and the fetch is the cost the
// package godoc names.
func (d Deps) trust(call *auth.Call, table resource.Table) result.Result[trusted] {
	return call.Request.QueryParams("client_id", "redirect_uri").
		MapErr(refusing(oauthInvalidRequest)).
		Then(func(params httpapi.Params) (candidate, error) { return candidateOf(params, table).Get() }).
		Then(func(c candidate) (trusted, error) { return d.vouch(call, c).Get() })
}

// required returns the value of the parameter name, which the request must have
// sent.
func required(params httpapi.Params, name string) result.Result[string] {
	value, present := params.Get(name)
	if !present {
		return result.Fail[string](fmt.Errorf("%w: %s", errMissingParameter, name))
	}

	return result.Ok(value)
}

// candidateOf parses the client_id and the redirect_uri. A missing one is an
// invalid_request, a client_id that does not parse is an invalid_client, and a
// redirect_uri that does not is an invalid_redirect_uri.
func candidateOf(params httpapi.Params, table resource.Table) result.Result[candidate] {
	return required(params, "client_id").
		MapErr(refusing(oauthInvalidRequest)).
		Then(func(raw string) (input.ClientID, error) {
			return result.Of(input.ParseClientID(raw, table)).MapErr(refusing(oauthInvalidClient)).Get()
		}).
		Then(func(id input.ClientID) (candidate, error) {
			return required(params, "redirect_uri").
				MapErr(refusing(oauthInvalidRequest)).
				Then(func(raw string) (input.RedirectURI, error) {
					return result.Of(input.ParseRedirectURI(raw)).MapErr(refusing(oauthInvalidRedirectURI)).Get()
				}).
				Map(func(uri input.RedirectURI) candidate { return candidate{clientID: id, redirect: uri} }).
				Get()
		})
}

// vouch fetches the client's document and checks it: it must be the client_id's
// document (input.ParseClientMetadata) and must list the redirect URI, matched
// as input.RedirectURI.Matches says (exactly, except for the port of a loopback
// URI).
func (d Deps) vouch(call *auth.Call, c candidate) result.Result[trusted] {
	return fetch.GetJSON(call.Request.Context, d.Fetch, fetch.DefaultLimits(), c.clientID.String()).
		MapErr(unfetchable).
		Then(func(body []byte) (input.ClientMetadata, error) {
			return result.Of(input.ParseClientMetadata(c.clientID, body)).MapErr(refusing(oauthInvalidClient)).Get()
		}).
		Check(func(meta input.ClientMetadata) error {
			if !meta.Registers(c.redirect) {
				return failure(oauthInvalidRedirectURI, errNotRegistered)
			}

			return nil
		}).
		Map(func(meta input.ClientMetadata) trusted { return trusted{meta: meta, redirect: c.redirect} })
}

// unfetchable classifies a failed fetch of a client's document. One that never
// got an answer in time (the connection failed or the timeout ended) may succeed
// if tried again, so the person is told to try again; every other failure (a
// status, a redirect, a content type, a size) is a client that is wrong and will
// stay wrong.
func unfetchable(err error) error {
	if errors.Is(err, fetch.ErrTransport) || errors.Is(err, fetch.ErrAborted) {
		return failure(oauthTemporarilyDown, err)
	}

	return failure(oauthInvalidClient, err)
}

// echoable is the state to hand back to the client in an error, if there is a
// usable one: it parses, and was sent once. It is read on its own so that a
// repeated scope, say, does not cost the client its state. An unusable state is
// never echoed, because what a parser refused must not go into a URL.
func echoable(req httpapi.Request) *input.State {
	state, err := req.QueryParams(paramState).
		Then(func(params httpapi.Params) (*input.State, error) {
			raw, _ := params.Get(paramState)

			return optional(raw, input.ParseState)
		}).Get()
	if err != nil {
		return nil
	}

	return state
}

// parameters are the parameters of the authorization request that follow the
// redirect URI being trusted.
func parameters() []string {
	return []string{
		"response_type", "code_challenge", "code_challenge_method", paramState, "nonce", "resource", "scope",
	}
}

// parseRequest parses the rest of the request, in the order of its checks, and
// the first failure ends it. The request is the client's and the redirect URI
// is trusted, so the failure is the client's to be told.
func (d Deps) parseRequest(req httpapi.Request, table resource.Table, vouched trusted) result.Result[pendingRequest] {
	return req.QueryParams(parameters()...).
		MapErr(refusing(oauthInvalidRequest)).
		Then(func(params httpapi.Params) (pendingRequest, error) {
			start := pendingRequest{
				clientID: vouched.meta.ClientID(), clientName: vouched.meta.ClientName(), redirectURI: vouched.redirect,
			}

			return result.Ok(start).
				Then(step(params, withResponseType)).
				Then(step(params, withChallenge)).
				Then(step(params, withMethod)).
				Then(step(params, withState)).
				Then(step(params, withNonce)).
				Then(step(params, withResource(table))).
				Then(step(params, withScope)).
				Get()
		})
}

// step adapts a parsing step to the one-argument form of a chain. The steps keep
// their Result, and this is where it ends: every failure of a step is already
// the classified OAuth failure of its parameter.
func step[T any](
	params httpapi.Params, parse func(httpapi.Params, T) result.Result[T],
) func(T) (T, error) {
	return func(req T) (T, error) { return parse(params, req).Get() }
}

// withResponseType requires response_type=code. Absent is an invalid_request, and
// anything else (token, the implicit flow OAuth 2.1 removed, or a combination)
// is an unsupported_response_type.
func withResponseType(params httpapi.Params, req pendingRequest) result.Result[pendingRequest] {
	return required(params, "response_type").
		MapErr(refusing(oauthInvalidRequest)).
		Then(func(raw string) (input.ResponseType, error) {
			return result.Of(input.ParseResponseType(raw)).MapErr(refusing(oauthUnsupportedResponse)).Get()
		}).
		Map(func(input.ResponseType) pendingRequest { return req })
}

// withChallenge requires a PKCE code_challenge (RFC 7636): a public client has
// nothing else to bind the code to.
func withChallenge(params httpapi.Params, req pendingRequest) result.Result[pendingRequest] {
	return required(params, "code_challenge").
		Then(input.ParseCodeChallenge).
		MapErr(refusing(oauthInvalidRequest)).
		Map(func(challenge input.CodeChallenge) pendingRequest {
			req.challenge = challenge

			return req
		})
}

// withMethod requires code_challenge_method=S256. RFC 7636 reads an absent
// method as "plain", which makes the challenge the verifier and so protects
// nothing, so it is not a default here: absent and plain are both refused, as an
// invalid_request.
func withMethod(params httpapi.Params, req pendingRequest) result.Result[pendingRequest] {
	return required(params, "code_challenge_method").
		Then(input.ParseCodeChallengeMethod).
		MapErr(refusing(oauthInvalidRequest)).
		Map(func(input.CodeChallengeMethod) pendingRequest { return req })
}

// withState reads the optional state.
func withState(params httpapi.Params, req pendingRequest) result.Result[pendingRequest] {
	raw, _ := params.Get(paramState)

	return result.Of(optional(raw, input.ParseState)).
		MapErr(refusing(oauthInvalidRequest)).
		Map(func(state *input.State) pendingRequest {
			req.state = state

			return req
		})
}

// withNonce reads the optional nonce of an OpenID Connect request.
func withNonce(params httpapi.Params, req pendingRequest) result.Result[pendingRequest] {
	raw, _ := params.Get("nonce")

	return result.Of(optional(raw, input.ParseNonce)).
		MapErr(refusing(oauthInvalidRequest)).
		Map(func(nonce *input.Nonce) pendingRequest {
			req.nonce = nonce

			return req
		})
}

// withResource requires the resource indicator of RFC 8707, which must be a
// resource of the table, exactly. A token is issued for exactly one resource
// (docs/oauth_design.md), so the request must name it: it is not guessed from
// the table, even while the table has one entry, so a client that does not say
// which resource it wants is found out now and not when a second is added. Both
// a missing and an unknown resource are invalid_target.
func withResource(table resource.Table) func(httpapi.Params, pendingRequest) result.Result[pendingRequest] {
	return func(params httpapi.Params, req pendingRequest) result.Result[pendingRequest] {
		return required(params, "resource").
			Then(func(raw string) (input.ResourceID, error) { return input.ParseResourceID(raw, table) }).
			MapErr(refusing(oauthInvalidTarget)).
			Map(func(target input.ResourceID) pendingRequest {
				req.resource = target

				return req
			})
	}
}

// withScope reads the scope against the resource's. An absent scope is the
// resource's defaults, written out. A scope that names no scope of the resource
// (only openid) is refused: an ID token grants nothing, and a grant is the
// delegation of access to a resource, which the user approves for an agent, so a
// request with nothing to delegate has nothing to approve.
func withScope(params httpapi.Params, req pendingRequest) result.Result[pendingRequest] {
	raw, present := params.Get("scope")

	return result.Of(input.ParseOAuthScopes(raw, present, req.resource.Entry())).
		Check(requireResourceScope).
		MapErr(refusing(oauthInvalidScope)).
		Map(func(scope input.OAuthScopes) pendingRequest {
			req.scope = scope

			return req
		})
}
