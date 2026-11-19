package oauth

import (
	"context"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// revocation is a parsed revocation request: the token as the client sent it,
// which is any text and is not parsed until it is known to be of a kind we
// revoke, and the client that holds it.
type revocation struct {
	token  string
	client input.ClientID
}

// revoke answers POST /oauth/revoke (RFC 7009): the client says it no longer
// needs a token, and it is revoked if it is a refresh token or an access token
// issued to that client.
//
// The answer is 200 with no body for every request that is well formed, whether
// or not anything was revoked (RFC 7009 section 2.2): a token that is unknown,
// expired, already revoked, another client's, or not one of ours at all (a code,
// a session or API key, anything) is not an error, so the endpoint is no oracle
// for which tokens exist or whose they are. Nothing is written for a token that
// is not an access or refresh token. A request that is not well formed is an
// invalid_request: the token or the client_id missing, a repeated parameter, a
// broken form. A client_id that does not parse is an invalid_client.
//
// The token_type_hint is read as a recognised parameter, so a repeated one is
// refused as any is, and then ignored: the hint is an optimisation (RFC 7009
// section 2.1) and an unrecognised or wrong one must not make the request fail.
// A token says what it is by its prefix, which the parsers check, so the hint has
// nothing to add. A refresh token revokes its grant and its access token; an
// access token revokes only itself, so the client can refresh into another
// (store.RevokeAccessToken).
func (d Deps) revoke(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(call.Config()).
		Then(func(cfg config.Config) (httpapi.Response, error) {
			return call.Request.FormParams("token", "token_type_hint", "client_id").
				MapErr(refusing(oauthInvalidRequest)).
				Then(func(params httpapi.Params) (revocation, error) { return parseRevocation(params, d.table(cfg)).Get() }).
				Then(func(rev revocation) (httpapi.Response, error) {
					return d.revokeToken(call.Request.Context, rev, now).
						Map(func(revocation) httpapi.Response { return httpapi.JSON(http.StatusOK, nil) }).
						Get()
				}).
				Get()
		})
}

// parseRevocation reads the client and the token.
func parseRevocation(params httpapi.Params, table resource.Table) result.Result[revocation] {
	return clientOf(params, table).
		Then(func(client input.ClientID) (revocation, error) {
			return required(params, "token").
				MapErr(refusing(oauthInvalidRequest)).
				Map(func(token string) revocation { return revocation{token: token, client: client} }).
				Get()
		})
}

// revokeToken revokes the token if it is a refresh token or an access token, and
// does nothing for anything else. It answers with the revocation it was given, so
// the chain it ends goes on to the response.
func (d Deps) revokeToken(ctx context.Context, rev revocation, now time.Time) result.Result[revocation] {
	refresh, refreshErr := input.ParseRefreshToken(rev.token)
	if refreshErr == nil {
		return result.Of(rev, d.Store.RevokeRefreshToken(ctx, refresh, rev.client, now))
	}

	access, accessErr := input.ParseAccessToken(rev.token)
	if accessErr == nil {
		return result.Of(rev, d.Store.RevokeAccessToken(ctx, access, rev.client, now))
	}

	return result.Ok(rev)
}
