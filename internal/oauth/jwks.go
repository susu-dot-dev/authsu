package oauth

import (
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// keySet is a JWK Set (RFC 7517): the public keys an ID token is verified with.
type keySet struct {
	Keys []config.JWK `json:"keys"`
}

// jwks answers GET /.well-known/jwks.json with the one key the ID token is
// signed with. The key is the deployment's OAUTH_SIGNING_KEY, loaded for this
// request and not before (auth.Call.SigningKey), and a deployment without a valid
// one answers 503 not_configured: there is no ID token to verify, and an empty
// set would say there is none to trust. Only the public half is published.
// There is no rotation overlap, so the set holds exactly one key.
func (d Deps) jwks(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(call.SigningKey()).
		Map(func(key config.SigningKey) keySet { return keySet{Keys: []config.JWK{key.JWK()}} }).
		Map(func(set keySet) httpapi.Response { return httpapi.JSON(http.StatusOK, set) })
}
