package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// consentBody is the body of POST /api/oauth/consent.
type consentBody struct {
	// Request is the sealed pending request the UI was sent, unchanged.
	Request string `json:"request"`

	// Approve is the user's answer. It must be present: a body that does not say
	// is not an approval and not a refusal.
	Approve *bool `json:"approve"`

	// Agent is the agent that will hold the grant, which an approval must choose
	// and a refusal must not.
	Agent *agentChoice `json:"agent"`
}

// agentChoice is the agent an approval gives the grant to: exactly one of a
// new agent, which is created with the grant, and an existing one.
type agentChoice struct {
	New *string `json:"new"`
	ID  *string `json:"id"`
}

// ConsentResponse is the body of POST /api/oauth/consent. The UI navigates the
// browser to Redirect, which is the client's redirect URI with the code (an
// approval) or with access_denied (a refusal), the client's state and the
// issuer. It is a body and not a 302 because the UI called this with a script,
// and a script cannot follow a redirect to another origin.
type ConsentResponse struct {
	Redirect string `json:"redirect"`
}

// answer is a consent body that has been parsed: a refusal, or an approval with
// the agent chosen.
type answer struct {
	approve bool

	// newAgent is the name of the agent to create, or nil; agentID is the id of
	// the agent to attach to, or nil. An approval has exactly one of the two, and
	// a refusal neither, and neither does the approval of a first-party login:
	// authsu keeps the agent for that.
	newAgent *input.AgentName
	agentID  *input.ID
}

// errBadAnswer is why a consent body was refused, for the log.
var (
	errNoApprove       = errors.New("approve is missing")
	errRefusalAgent    = errors.New("a refusal names an agent")
	errNoAgentChoice   = errors.New("an approval names neither a new agent nor an existing one")
	errBothAgentChoice = errors.New("an approval names both a new agent and an existing one")
	errLoginAgent      = errors.New("a first-party login names an agent")
)

// invalidConsent is the 400 for a body that is not an answer.
func invalidConsent(cause error) *apierr.Error {
	return apierr.New(apierr.BadRequest, CodeInvalidConsent,
		"the body must say approve, and an approval must choose one agent (a new one or an existing one), "+
			"except a first-party login, which must choose none").
		WithCause(cause)
}

// parseAnswer parses what the user chose, before the pending request is read.
// The rules are strict, because this is what authorizes:
//
//   - approve must be present and a boolean (the decoder refuses another type
//     and an unknown member);
//   - a refusal must not name an agent, because there is nothing for an agent to
//     hold, and a client that sends one has misunderstood the call;
//   - an approval that names an agent must name exactly one of agent.new (a
//     name) and agent.id (an id), parsed as an agent's name and as an id. An
//     approval that names none is parsed as such, and is only acceptable for a
//     first-party login: which kind it is belongs to the pending request, so it
//     is decided by chooseAgent once the request is open.
func parseAnswer(body consentBody) result.Result[answer] {
	switch {
	case body.Approve == nil:
		return result.Fail[answer](invalidConsent(errNoApprove))
	case !*body.Approve && body.Agent != nil:
		return result.Fail[answer](invalidConsent(errRefusalAgent))
	case !*body.Approve:
		return result.Ok(answer{approve: false})
	case body.Agent == nil:
		return result.Ok(answer{approve: true})
	case body.Agent.New == nil && body.Agent.ID == nil:
		return result.Fail[answer](invalidConsent(errNoAgentChoice))
	case body.Agent.New != nil && body.Agent.ID != nil:
		return result.Fail[answer](invalidConsent(errBothAgentChoice))
	}

	return parseAgent(*body.Agent)
}

// chooseAgent holds an answer to what the opened request needs, which only the
// request can say. An approval of a first-party login has no agent to choose, so
// it must name none: authsu keeps the agent for it, and a first-party login
// cannot be attached to an agent the user has. An approval of any other request
// must have chosen one. A refusal needs nothing. The request, never the body,
// says which kind it is.
func chooseAgent(chosen answer, firstParty bool) error {
	hasAgent := chosen.newAgent != nil || chosen.agentID != nil

	switch {
	case !chosen.approve:
		return nil
	case firstParty && hasAgent:
		return invalidConsent(errLoginAgent)
	case !firstParty && !hasAgent:
		return invalidConsent(errNoAgentChoice)
	default:
		return nil
	}
}

// parseAgent parses the one agent an approval chose.
func parseAgent(choice agentChoice) result.Result[answer] {
	if choice.New != nil {
		return result.Of(input.ParseAgentName(*choice.New)).
			Map(func(name input.AgentName) answer { return answer{approve: true, newAgent: &name} })
	}

	return result.Of(input.ParseID(*choice.ID)).
		Map(func(id input.ID) answer { return answer{approve: true, agentID: &id} })
}

// consent answers POST /api/oauth/consent: the user's answer to a pending
// request. The route needs a session, and refuses agents (and so API keys), so
// a person was present: an approval is a person delegating, and it is the
// authorization itself.
//
// The body is parsed first, and then the pending request is opened, so a
// malformed answer is refused before anything is read and a pending request
// that is forged, expired or of another purpose is refused before anything is
// written. Then:
//
//   - A refusal writes nothing and answers with the client's redirect URI and
//     access_denied.
//   - An approval issues the authorization code and writes the grant, and its
//     agent if the user chose to create one, as one batch (store.CreateGrant),
//     in which the account, the agent and the approving session are checked
//     again. The grant records the SHA-256 of the sealed value in a unique
//     column, so the same approval submitted twice (a double click, a replay)
//     creates one grant and one agent, and the second is CodeConsentReplayed.
//
// The answer is the URL for the UI to send the browser to (ConsentResponse).
func (d Deps) consent(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return httpapi.Decode[consentBody](call.Request).
		Then(func(body consentBody) (httpapi.Response, error) {
			return parseAnswer(body).
				Then(func(chosen answer) (httpapi.Response, error) {
					return d.respond(call, body.Request, chosen, now).Get()
				}).
				Get()
		})
}

// respond opens the pending request and answers it as chosen, after holding the
// choice to what the request needs (chooseAgent).
func (d Deps) respond(call *auth.Call, raw string, chosen answer, now time.Time) result.Result[httpapi.Response] {
	return result.Of(call.Config()).
		Then(func(cfg config.Config) (httpapi.Response, error) {
			return d.open(cfg, raw, now).
				Check(func(pending opened) error { return chooseAgent(chosen, pending.request.firstPartyLogin()) }).
				Then(func(pending opened) (ConsentResponse, error) {
					return d.settle(call, cfg, pending, chosen, now).Get()
				}).
				Map(func(out ConsentResponse) httpapi.Response { return httpapi.JSON(http.StatusOK, out) }).
				Get()
		})
}

// settle is the answer to an opened request: the refusal, or the grant.
func (d Deps) settle(
	call *auth.Call, cfg config.Config, pending opened, chosen answer, now time.Time,
) result.Result[ConsentResponse] {
	if !chosen.approve {
		return result.Ok(ConsentResponse{Redirect: responseURL(cfg, pending.request, url.Values{
			paramError: {oauthAccessDenied}, "error_description": {describe(oauthAccessDenied)},
		})})
	}

	return d.grant(call, pending, chosen, now).
		Map(func(code string) ConsentResponse {
			return ConsentResponse{Redirect: responseURL(cfg, pending.request, url.Values{paramCode: {code}})}
		})
}

// responseURL is the redirect URI of an opened request with params and, as in
// every authorization response, the client's state and the issuer.
func responseURL(cfg config.Config, request pendingRequest, params url.Values) string {
	params.Set("iss", cfg.API.String)

	if request.state != nil {
		params.Set(paramState, request.state.String())
	}

	return withQuery(request.redirectURI.String(), params)
}

// grant issues the authorization code for an approved request and writes the
// grant that holds it, and returns the code, which is shown once and never
// stored: only its hash is. The ids come from NewID: the grant's is the code's
// secret id and stays the grant's for its life, and a new agent's is a second.
func (d Deps) grant(call *auth.Call, pending opened, chosen answer, now time.Time) result.Result[string] {
	return result.Of(auth.IssueGrantCode(d.Entropy, d.NewID, now)).
		MapErr(func(cause error) error {
			return apierr.New(apierr.Internal, CodeIssueFailed, "could not issue the authorization code").WithCause(cause)
		}).
		Then(func(code auth.Issued) (string, error) {
			err := d.Store.CreateGrant(call.Request.Context, d.newGrant(call, pending, chosen, code, now))

			return code.Token, refused(err)
		})
}

// newGrant is the write of an approved request: what the user approved, taken
// from the opened request and never from the body; who approved, from the
// authenticated session; and the code's hash.
//
// The code-stage secret is kept for PendingLifetime from now and not for the
// code's own minute (auth.CodeLifetime, which the exchange write enforces from
// the secret's creation time). The grant's granted_from is the single-use guard of
// the sealed request, which stays valid for up to PendingLifetime after it was
// sealed, which is before now: a row removed sooner would let a replay of the
// request create a second grant and agent.
func (d Deps) newGrant(call *auth.Call, pending opened, chosen answer, code auth.Issued, now time.Time) store.NewGrant {
	request := pending.request

	grant := store.NewGrant{
		ID: code.ID, Owner: call.Principal.UserID,
		ClientID: request.clientID, ClientName: request.clientName.String(), RedirectURI: request.redirectURI,
		Resource: request.resource, Scope: request.scope, CodeChallenge: request.challenge, Nonce: request.nonce,
		SessionID: call.Principal.SecretID, GrantedFrom: hashOf(pending.sealed),
		CodeHash: code.Hash, RetainUntil: now.Add(PendingLifetime), CreatedAt: now,
	}

	switch {
	case request.firstPartyLogin():
		// Authsu keeps one agent for the user and this client, named after the
		// client, which the write creates the first time and finds after.
		grant.AgentID = d.NewID()
		grant.FirstParty = true
		grant.FirstPartyName = request.firstPartyName()
		grant.FirstPartyMaxActive = d.MaxAgents
	case chosen.newAgent != nil:
		grant.AgentID = d.NewID()
		grant.NewAgent = &store.GrantAgent{Name: *chosen.newAgent, MaxActive: d.MaxAgents}
	default:
		grant.AgentID = chosen.agentID.String()
	}

	return grant
}

// refused maps the refusals of store.CreateGrant to the client's answers; any
// other failure is returned as it is. The agent is not found alike whether it
// does not exist, is another user's, is revoked or is an agent of a sandbox (a
// grant is held by an outside service, and such an agent is confined to its
// sandbox), because the write cannot tell them apart and a request must not
// probe another user's agents. An account or a
// session that ended after the request was authenticated is what any request
// without a session is told, a 401.
func refused(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrGrantReplayed):
		return replayed(err)
	case errors.Is(err, store.ErrAgentLimit):
		return atAgentLimit(err)
	case errors.Is(err, store.ErrAgentUnavailable):
		return noSuchAgent(err)
	case errors.Is(err, store.ErrUserInactive), errors.Is(err, store.ErrSessionInactive):
		//nolint:wrapcheck // auth classifies it: it is the 401 every request without a session gets
		return auth.Unauthenticated(err)
	case errors.Is(err, store.ErrConflict):
		return unrecorded(err)
	default:
		return err
	}
}

// replayed is the client's 409 for an approval that was already used.
func replayed(cause error) *apierr.Error {
	return apierr.New(apierr.Conflict, CodeConsentReplayed, "this request was already approved").WithCause(cause)
}

// atAgentLimit is the client's 409 for a user who has the most agents they may.
func atAgentLimit(cause error) *apierr.Error {
	return apierr.New(apierr.Conflict, CodeAgentLimit, "the account has the most active agents it may have").
		WithCause(cause)
}

// noSuchAgent is the client's 404 for an agent the user does not have.
func noSuchAgent(cause error) *apierr.Error {
	return apierr.New(apierr.NotFound, CodeAgentNotFound, "no such agent").WithCause(cause)
}

// unrecorded is the 500 for a refusal the write cannot name.
func unrecorded(cause error) *apierr.Error {
	return apierr.New(apierr.Internal, CodeConsentFailed, "could not record the approval").WithCause(cause)
}
