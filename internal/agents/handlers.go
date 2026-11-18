package agents

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Error codes of the agent routes themselves. A failure of the store, a bad
// path id, a bad page parameter or a bad name has its own code in store or
// input. They are stable: clients and dashboards may match on them.
const (
	// CodeNotFound is an agent the user does not have: one that does not
	// exist, and one that belongs to someone else.
	CodeNotFound = "agent_not_found"
	// CodeLimit is a create refused because the user already has
	// MaxAgentsPerUser active agents, or has been revoked since signing in.
	CodeLimit = "agent_limit_reached"
	// CodeKeyFailed is the creation of an agent's key failing, before anything
	// was written.
	CodeKeyFailed = "agent_key_failed"
	// CodeMissingName is a rename without a name.
	CodeMissingName = "missing_agent_name"
	// CodeRevoked is a rename of an agent that is revoked.
	CodeRevoked = "agent_revoked"
)

// Paths. The collection takes GET and POST; one agent takes GET, PATCH and
// DELETE.
const (
	collectionPath = "/api/agent"
	itemPath       = "/api/agent/{id}"
)

// MaxBody is the largest request body any agent route reads, in bytes. The
// biggest legitimate one is a name of 256 four-byte characters, every one
// escaped as a \uXXXX surrogate pair (12 bytes), about 3 KiB, so this leaves
// room and refuses anything that could only be an attempt to make the route
// read more before a name is refused.
const MaxBody = 8 << 10

// Routes returns the agent routes. Every one needs a session and nothing more:
// an agent is something every user has, and each route acts only on the
// caller's own, so no role is required. It panics when a dependency is nil.
func Routes(deps Deps) []auth.Route {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Now": deps.Now == nil, "NewID": deps.NewID == nil, "CreateKey": deps.CreateKey == nil,
	} {
		if missing {
			panic("agents: Deps." + name + " is required")
		}
	}

	return []auth.Route{
		session(http.MethodGet, collectionPath, deps.list),
		session(http.MethodPost, collectionPath, deps.create),
		session(http.MethodGet, itemPath, deps.get),
		session(http.MethodPatch, itemPath, deps.rename),
		session(http.MethodDelete, itemPath, deps.revoke),
	}
}

// session declares a route that needs a session and no requirement.
func session(method, path string, handle func(*auth.Call) result.Result[httpapi.Response]) auth.Route {
	return auth.Route{
		Method: method, Path: path, MaxBody: MaxBody, Credential: auth.Session, Require: nil, Handle: handle,
	}
}

// ListResponse is the body of GET /api/agent: one page, newest first.
type ListResponse struct {
	Agents []Agent `json:"agents"`

	// Next is the cursor of the following page, to send as the cursor query
	// parameter. It is absent on the last page.
	Next string `json:"next,omitempty"`
}

// page is a parsed list request.
type page struct {
	cursor input.Cursor
	limit  input.PageLimit
}

// parsePage reads the limit and cursor from the query. Each may appear at most
// once: a repeated parameter is ambiguous, and which value wins differs between
// layers, so it is refused rather than guessed.
func parsePage(query map[string][]string) (page, error) {
	limit, err := input.ParsePageLimit(query["limit"])
	if err != nil {
		return page{}, err //nolint:wrapcheck // the parser's error is already the classified client error
	}

	cursor, err := input.ParseCursor(query["cursor"])
	if err != nil {
		return page{}, err //nolint:wrapcheck // the parser's error is already the classified client error
	}

	return page{cursor: cursor, limit: limit}, nil
}

func (d Deps) list(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(parsePage(call.Request.Query)).
		Then(func(p page) (store.AgentPage, error) {
			return d.Store.ListAgents(call.Request.Context, call.Principal.UserID, p.cursor, p.limit)
		}).
		Map(func(stored store.AgentPage) ListResponse {
			out := ListResponse{Agents: make([]Agent, 0, len(stored.Agents)), Next: stored.Next}

			for _, agent := range stored.Agents {
				out.Agents = append(out.Agents, present(agent))
			}

			return out
		}).
		Map(func(out ListResponse) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

func (d Deps) get(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.GetAgent(call.Request.Context, call.Principal.UserID, call.ID())).
		MapErr(notFound).
		Map(present).
		Map(func(out Agent) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// notFound turns the store's "no such row" into the client's 404. The store
// matches by owner as well as id, so an agent of another user comes back as
// the same outcome, and so the same response, as one that does not exist.
// Anything else is returned as it is.
func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return noSuchAgent(err)
	}

	return err
}

// noSuchAgent is the client's 404 for an agent the user does not have.
func noSuchAgent(cause error) *apierr.Error {
	return apierr.New(apierr.NotFound, CodeNotFound, "no such agent").WithCause(cause)
}

// createBody is the body of POST /api/agent.
type createBody struct {
	// Name is a label for the agent.
	Name string `json:"name"`
}

// CreateResponse is the body of a created agent. Key is the only time the
// agent's API key is ever returned.
type CreateResponse struct {
	Agent Agent `json:"agent"`
	Key   Key   `json:"key"`
}

// Key is an API key as the response to a create shows it.
type Key struct {
	// ID is the key's kid.
	ID string `json:"id"`

	// Token is the bearer token. It is not stored and cannot be shown again.
	Token string `json:"token"`

	// Scope is the scope list signed into the token.
	Scope string `json:"scope"`

	// ExpiresAt is when the key stops working, in Unix seconds.
	ExpiresAt int64 `json:"expiresAt"`
}

// parseCreate parses the new agent's name.
func parseCreate(body createBody) (input.AgentName, error) {
	return input.ParseAgentName(body.Name) //nolint:wrapcheck // the parser's error is already the classified client error
}

// creation is a create request that has been planned: the agent and its key
// exactly as they will be written, and the key's token.
type creation struct {
	agent store.NewAgent
	token string
}

func (d Deps) create(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[createBody](call.Request).
		Then(parseCreate).
		Then(func(name input.AgentName) (creation, error) { return d.plan(call, name).Get() }).
		Then(func(plan creation) (creation, error) {
			return plan, d.Store.CreateAgent(call.Request.Context, plan.agent)
		}).
		MapErr(limitReached).
		Map(respondCreated).
		Map(func(out CreateResponse) httpapi.Response { return httpapi.JSON(http.StatusCreated, out) })
}

// limitReached is the client's answer to a create the store refused as a
// conflict: the user already has MaxAgentsPerUser active agents, or their
// account was revoked after the request was authenticated (the write cannot
// tell which, and a revoked account has no session to be told on). The id and
// the kid are fresh UUIDv7s, so no other constraint can conflict. Any other
// failure is returned as it is.
func limitReached(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return atLimit(err)
	}

	return err
}

// atLimit is the client's 409 for an owner who may have no more active agents.
func atLimit(cause error) *apierr.Error {
	return apierr.New(apierr.Conflict, CodeLimit,
		fmt.Sprintf("an account may have at most %d active agents", MaxAgentsPerUser)).WithCause(cause)
}

// plan decides everything about the new agent that does not need the database:
// its id, its default scopes, and its first key. The key is created here,
// before the write, so a failure to create it writes nothing.
//
// The token's subject is the user, and its actor names the agent
// (docs/agents_design.md): a service that knows nothing about agents sees the
// user, and one that does can tell the agent apart. The scopes are signed in as
// a claim that nothing reads yet. The user is the session's, never the
// request's.
func (d Deps) plan(call *auth.Call, name input.AgentName) result.Result[creation] {
	return result.Of(call.Config()).
		Then(func(cfg config.Config) (creation, error) {
			now := d.Now()
			id := d.NewID()
			owner := call.Principal.UserID
			expires := now.Add(KeyLifetime)

			key, err := d.CreateKey(auth.IssuerFor(cfg.API), auth.KeySpec{
				Kind: auth.KindAPIKey, Subject: owner, Expires: expires,
				Claims: map[string]any{
					"act":   map[string]any{"sub": id},
					"scope": DefaultScopes,
				},
			})
			if err != nil {
				return creation{}, apierr.Wrap(err, apierr.Internal, CodeKeyFailed, "internal error")
			}

			return creation{
				agent: store.NewAgent{
					ID: id, Owner: owner, Name: name, Scopes: DefaultScopes, MaxActive: MaxAgentsPerUser,
					KeyID: key.ID.String(), KeyJWK: key.JWK, KeyExpiresAt: key.ExpiresAt, CreatedAt: now,
				},
				token: key.JWT,
			}, nil
		})
}

// respondCreated is the response to a create, built from what was written: the
// row is never read back.
func respondCreated(plan creation) CreateResponse {
	agent := plan.agent

	return CreateResponse{
		Agent: Agent{
			ID: agent.ID, Name: agent.Name.String(), Scopes: agent.Scopes, Status: StatusActive,
			RevokedAt: nil, CreatedAt: agent.CreatedAt.Unix(),
		},
		Key: Key{ID: agent.KeyID, Token: plan.token, Scope: agent.Scopes, ExpiresAt: agent.KeyExpiresAt.Unix()},
	}
}

// renameBody is the body of PATCH /api/agent/{id}. It is a patch, so each
// field is optional, but at least one must be present; the name is the only
// one there is.
type renameBody struct {
	Name *string `json:"name"`
}

func (d Deps) rename(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[renameBody](call.Request).
		Then(parseRename).
		Then(func(name input.AgentName) (store.Agent, error) {
			return d.Store.RenameAgent(call.Request.Context, call.Principal.UserID, call.ID(), name)
		}).
		MapErr(notFound).
		// The store returns the row as the write left it, so a revoked agent
		// comes back with its old name and is refused here.
		Check(func(agent store.Agent) error {
			if agent.RevokedAt != nil {
				return apierr.New(apierr.Conflict, CodeRevoked, "the agent is revoked and cannot be changed")
			}

			return nil
		}).
		Map(present).
		Map(func(out Agent) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// parseRename requires the name to be present, then parses it.
func parseRename(body renameBody) (input.AgentName, error) {
	if body.Name == nil {
		return input.AgentName{}, missingName()
	}

	return input.ParseAgentName(*body.Name) //nolint:wrapcheck // the parser's error is already the classified client error
}

// missingName is the client's 400 for a rename that names nothing to change.
func missingName() *apierr.Error {
	return apierr.New(apierr.BadRequest, CodeMissingName, "name is required")
}

// revoke revokes an agent and every key it holds, as one batch, and returns the
// agent as the write left it. Revoking an agent that is already revoked
// succeeds and keeps the earlier time, so the call is idempotent. Other agents
// of the same user are not touched.
func (d Deps) revoke(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(d.Store.RevokeAgent(call.Request.Context, call.Principal.UserID, call.ID(), d.Now())).
		MapErr(notFound).
		Map(present).
		Map(func(out Agent) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}
