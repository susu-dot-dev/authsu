package oauth

import (
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// RequestView is the body of GET /api/oauth/request: what the consent screen
// shows about a pending request. The client's name is what its own document
// claims, so it is shown beside the hosts, which are what this server checked:
// the host of the client_id (where the document came from) and the host of the
// redirect URI (where the user is sent back to). It carries nothing that
// authorizes: the sealed value the UI already holds is what consent is
// answered with.
type RequestView struct {
	// ClientName is the name the client's document gave itself, and ClientID the
	// URL of that document.
	ClientName string `json:"clientName"`
	ClientID   string `json:"clientId"`

	// ClientHost and RedirectHost are the hosts, with their ports if they have
	// one, of the client_id and of the redirect URI.
	ClientHost   string `json:"clientHost"`
	RedirectHost string `json:"redirectHost"`

	// Resource is the URL of the resource server the grant is for and
	// ResourceName its name.
	Resource     string `json:"resource"`
	ResourceName string `json:"resourceName"`

	// Scopes are the resource's scopes the grant would carry, in the order the
	// client asked for them, and OpenID is whether it also asked for an ID
	// token.
	Scopes []string `json:"scopes"`
	OpenID bool     `json:"openid"`

	// ExpiresAt is when the request stops being accepted, in Unix seconds.
	ExpiresAt int64 `json:"expiresAt"`
}

// request answers GET /api/oauth/request?request=<sealed>: the UI reads what a
// client asked for before it asks the user. It needs no credential, because it
// reveals only what the client's request said and what is public about it, to
// whoever holds the sealed value, which was sent to their browser. The value is
// opened as for consent (Deps.open), and every member is parsed again.
func (d Deps) request(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(call.Config()).
		Then(func(cfg config.Config) (opened, error) { return d.openQuery(call.Request, cfg, now).Get() }).
		Map(viewOf).
		Map(func(view RequestView) httpapi.Response { return httpapi.JSON(http.StatusOK, view) })
}

// openQuery opens the pending request in the request query's one "request"
// parameter. A missing or repeated one is the same CodeInvalidPending as any
// other value that cannot be opened.
func (d Deps) openQuery(req httpapi.Request, cfg config.Config, now time.Time) result.Result[opened] {
	return req.QueryParams("request").
		Then(func(params httpapi.Params) (string, error) { return required(params, "request").Get() }).
		MapErr(func(cause error) error { return invalidPending(cause) }).
		Then(func(raw string) (opened, error) { return d.open(cfg, raw, now).Get() })
}

// viewOf is what the consent screen is shown for an opened request.
func viewOf(pending opened) RequestView {
	request := pending.request

	return RequestView{
		ClientName: request.clientName.String(), ClientID: request.clientID.String(), ClientHost: request.clientID.Host(),
		RedirectHost: request.redirectURI.Host(), Resource: request.resource.String(),
		ResourceName: request.resource.Entry().Name, Scopes: request.scope.Resource(), OpenID: request.scope.OpenID(),
		ExpiresAt: request.expiresAt,
	}
}
