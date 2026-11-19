package oauth

import (
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Introspection is the body of POST /oauth/introspect (RFC 7662 section 2.2).
// Active is false, and every other member is absent, for any token that is not a
// live access token issued for exactly the resource asked about. Otherwise:
//
//   - Scope is the access token's own scopes, space-delimited: the grant's, or the
//     narrower list a refresh asked for. At a resource they are the only limit.
//     ClientID is the client the token was issued to.
//   - Sub is the user's id, who the request speaks for, and AgentID is the agent
//     that holds the grant, who acts for them (an extension member: the standard
//     has none for an actor, and a resource server that attributes what it does
//     wants both).
//   - Aud is the resource, and Iss is this server's issuer.
//   - Exp and Iat are the token's expiry and issue time, as integers of seconds
//     within 2^53-1. A replaced token has the issue time of its replacement.
type Introspection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`  //nolint:tagliatelle // RFC 7662 section 2.2 names this member
	TokenType string `json:"token_type,omitempty"` //nolint:tagliatelle // RFC 7662 section 2.2 names this member
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	AgentID   string `json:"agent_id,omitempty"` //nolint:tagliatelle // an extension member, named as the standard's are
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
}

// question is a parsed introspection request: what is asked, and of which
// resource. Neither is known to be valid: an answer to a value that is not is
// "inactive", which is why they are the request's own text.
type question struct {
	token    string
	resource string
}

// introspect answers POST /oauth/introspect (RFC 7662). It asks nothing of its
// caller: a resource server holds no secret, and the token is itself a 256-bit
// value, so possessing it is the right to ask what it is. What the endpoint does
// is bind the answer to who asks, through the resource the caller names.
//
// A request must carry the token and the resource, or it is an invalid_request:
// a caller that does not say which resource it is cannot be answered. Everything
// after that is a 200, and the answer is {"active":false} for every way the
// token can fail to be a live access token for that resource, and the one
// answer for all of them, so the endpoint is no oracle:
//
//   - a token that is not an access token (a refresh token, a code, a session or
//     an API key, anything), and a token that is malformed;
//   - an access token that is unknown, expired or revoked, whose grant, account
//     or agent is revoked, or that was issued for another resource: a token for
//     resource A asked about as B is inactive, so a token that leaked from one
//     service is no use at another and cannot be probed there;
//   - a resource that is not one of the table's. This is deliberately not an
//     error: an error for an unknown resource would tell a caller which resources
//     exist and, with a token, nothing more than the inactive answer does.
//
// There is no CORS (a server calls it, not a browser) and the answer is never
// cached (the boundary sets Cache-Control: no-store).
func (d Deps) introspect(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(call.Config()).
		Then(func(cfg config.Config) (httpapi.Response, error) {
			return call.Request.FormParams("token", "resource").
				MapErr(refusing(oauthInvalidRequest)).
				Then(func(params httpapi.Params) (question, error) { return parseQuestion(params).Get() }).
				Then(func(asked question) (Introspection, error) { return d.answer(call, cfg, asked, now).Get() }).
				Map(func(out Introspection) httpapi.Response { return httpapi.JSON(http.StatusOK, out) }).
				Get()
		})
}

// parseQuestion requires the token and the resource.
func parseQuestion(params httpapi.Params) result.Result[question] {
	return required(params, "token").
		MapErr(refusing(oauthInvalidRequest)).
		Then(func(token string) (question, error) {
			return required(params, "resource").
				MapErr(refusing(oauthInvalidRequest)).
				Map(func(target string) question { return question{token: token, resource: target} }).
				Get()
		})
}

// answer reads the token, if it parses as an access token for a resource of the
// table, and answers for what the store finds. A token or a resource that does
// not parse is not a failure: it is an answer, the inactive one, and it reaches
// the store no more than any other token that is not live.
func (d Deps) answer(call *auth.Call, cfg config.Config, asked question, now time.Time) result.Result[Introspection] {
	token, tokenErr := input.ParseAccessToken(asked.token)
	target, targetErr := input.ParseResourceID(asked.resource, d.table(cfg))

	if tokenErr != nil || targetErr != nil {
		return result.Ok(Introspection{})
	}

	live, found, err := d.Store.IntrospectAccessToken(call.Request.Context, token, target, now)

	return result.Of(live, err).Map(func(live store.ActiveAccessToken) Introspection {
		if !found {
			return Introspection{}
		}

		return activeIntrospection(cfg, live)
	})
}

// activeIntrospection is the answer for a live access token.
func activeIntrospection(cfg config.Config, live store.ActiveAccessToken) Introspection {
	return Introspection{
		Active: true, Scope: live.Scope, ClientID: live.ClientID, TokenType: bearer,
		Exp: live.ExpiresAt.Unix(), Iat: live.IssuedAt.Unix(), Sub: live.UserID, AgentID: live.AgentID,
		Aud: live.Resource, Iss: cfg.API.String,
	}
}
