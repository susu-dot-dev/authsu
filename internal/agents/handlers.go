package agents

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
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
	// CodeKeyFailed is the issue of an agent's key failing, before anything
	// was written.
	CodeKeyFailed = "agent_key_failed"
	// CodeNothingToChange is a PATCH that names nothing to change: no name, and
	// no label to add or remove.
	CodeNothingToChange = "missing_agent_change"
	// CodeRevoked is a change to an agent that is revoked.
	CodeRevoked = "agent_revoked"
	// CodeScopesInherited is an agent that tried to choose the scopes of the
	// agent it creates: they are always its own.
	CodeScopesInherited = "agent_scopes_inherited"
	// CodeKeyScopesExceeded is an agent that asked for a key holding a scope its
	// own key does not list.
	CodeKeyScopesExceeded = "key_scopes_exceeded"
	// CodeSandboxNotFound is a create that names a sandbox the user does not
	// administer or that has expired: one that does not exist, one that belongs
	// to someone else, a standard organization and one that has run out are
	// answered alike.
	CodeSandboxNotFound = "sandbox_not_found"
	// CodeSandboxInherited is an agent that tried to choose the sandbox of the
	// agent it creates: it is always its own.
	CodeSandboxInherited = "agent_sandbox_inherited"
	// CodeLabelLimit is a PATCH that would leave an agent with more than
	// input.MaxLabelsPerAgent labels. Nothing in the request took effect.
	CodeLabelLimit = "agent_label_limit_reached"
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

// Routes returns the agent routes. Each needs its own scope and no role: an
// agent is something every user has, and each route acts only on the caller's
// own.
//
// Renaming and revoking refuse agents whatever their scopes. Agents are flat
// under their user, so an agent holding those scopes could act on its siblings,
// and nothing about "an agent may manage agents" is meant to include that.
// Creating is the one route an agent may use, when it is given agent:create, and
// it is bounded by the rules in create.
//
// The list, the read and the create opt in to agents of a sandbox (InSandbox),
// the only routes that do: each therefore owes the boundary that every query it
// makes is confined to Principal.SandboxID, so that such an agent reaches only
// the agents of its own sandbox. Every other route here, and in every other
// feature, refuses it at the boundary.
//
// It panics when a dependency is nil.
func Routes(deps Deps) []auth.Route {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Now": deps.Now == nil, "NewID": deps.NewID == nil, "Entropy": deps.Entropy == nil,
		"IssueAPIKey": deps.IssueAPIKey == nil,
		"Seal":        deps.Seal == nil,
	} {
		if missing {
			panic("agents: Deps." + name + " is required")
		}
	}

	return []auth.Route{
		declare(http.MethodGet, collectionPath, auth.Needs(scope.AgentRead).InSandbox(), deps.list),
		declare(http.MethodPost, collectionPath, auth.Needs(scope.AgentCreate).InSandbox(), deps.create),
		declare(http.MethodGet, itemPath, auth.Needs(scope.AgentRead).InSandbox(), deps.get),
		declare(http.MethodPatch, itemPath, auth.Needs(scope.AgentUpdate).WithoutAgents(), deps.patch),
		declare(http.MethodDelete, itemPath, auth.Needs(scope.AgentRevoke).WithoutAgents(), deps.revoke),
	}
}

// declare declares an authenticated route with its access.
func declare(
	method, path string, access auth.Access, handle func(*auth.Call) result.Result[httpapi.Response],
) auth.Route {
	return auth.Route{
		Method: method, Path: path, MaxBody: MaxBody, Credential: auth.Authenticated, Access: access, Handle: handle,
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
	filter store.AgentFilter
}

// parsePage reads the limit, cursor, label and sandbox from the query. Each may appear
// at most once: a repeated parameter is ambiguous, and which value wins differs
// between layers, so it is refused rather than guessed.
func parsePage(query map[string][]string) result.Result[page] {
	return result.Of(input.ParsePageLimit(query["limit"])).
		Map(func(limit input.PageLimit) page { return page{limit: limit} }).
		Then(func(p page) (page, error) {
			return result.Of(input.ParseCursor(query["cursor"])).
				Map(func(cursor input.Cursor) page { p.cursor = cursor; return p }).
				Get()
		}).
		Then(func(p page) (page, error) {
			return result.Of(input.ParseLabelFilter(query["label"])).
				Map(func(filter input.LabelFilter) page { p.filter.Label = filter; return p }).
				Get()
		}).
		Then(func(p page) (page, error) {
			return result.Of(input.ParseSandboxFilter(query["sandbox"])).
				Map(func(filter input.SandboxFilter) page { p.filter.Sandbox = filter; return p }).
				Get()
		})
}

// reach is which agents the caller may reach. A user, with a session or one of
// their own keys, reaches every agent they own. An agent reaches only those in
// its own sandbox, or only the ordinary ones when it is in none, so a sandbox's
// agents are neither seen from outside it nor able to see out. Which one it is
// comes from the credential, never from the request.
func reach(who auth.Principal) store.AgentReach {
	if who.AgentID == "" {
		return store.OwnAgents(who.UserID)
	}

	return store.SandboxAgents(who.UserID, who.SandboxID)
}

func (d Deps) list(call *auth.Call) result.Result[httpapi.Response] {
	return parsePage(call.Request.Query).
		Then(func(p page) (store.AgentPage, error) {
			return d.Store.ListAgents(call.Request.Context, reach(call.Principal), p.cursor, p.limit, p.filter)
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
	return result.Of(d.Store.GetAgent(call.Request.Context, reach(call.Principal), call.ID())).
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

	// Labels are the labels the new agent starts with. Absent, null and empty
	// all mean none. They are written in the same batch as the agent, so a
	// create either gives the agent every one of them or creates nothing. The
	// array carries a maxitems tag, so the decoder refuses an oversized one
	// before it has allocated it; input.ParseLabelSet checks the bound again.
	Labels *[]string `json:"labels" maxitems:"20"`

	// Scopes is the new agent's scope list, and KeyScopes its first key's.
	// Absent means the default (DefaultScopes); an empty list is a credential
	// that can use only the routes that need no scope. An agent creating an
	// agent may not set Scopes (they are copied from the creator) and may set
	// KeyScopes only to entries of its own key's list.
	Scopes    *[]string `json:"scopes"`
	KeyScopes *[]string `json:"keyScopes"`

	// SandboxID is the sandbox to create the agent in. Absent and null mean an
	// ordinary agent for a user. A user must administer the sandbox, and it must
	// not have expired. An agent may not choose: its new agent is in its own
	// sandbox, so it may only omit this or repeat its own.
	SandboxID *string `json:"sandboxId"`

	// PublicKey is the key the first key's token is sealed to: the base64url of
	// the suite byte and an X25519 public key (input.PublicKey). A session may
	// omit it and be sent the token as it is; any other credential must send
	// it (auth.Recipient).
	PublicKey *string `json:"publicKey"`
}

// CreateResponse is the body of a created agent. Key is the only time the
// agent's API key is ever returned.
type CreateResponse struct {
	Agent Agent `json:"agent"`
	Key   Key   `json:"key"`
}

// Key is an API key as the response to a create shows it.
type Key struct {
	// ID is the key's id, the identifier it is listed and revoked by.
	ID string `json:"id"`

	// Token is the bearer token ("susu_key_..."). Only its hash is stored, so
	// it cannot be shown again. It is absent when the request carried a public
	// key, and Sealed is present instead.
	Token string `json:"token,omitempty"`

	// Sealed is the token sealed to the request's public key (internal/seal).
	// It is absent when Token is present.
	Sealed string `json:"sealed,omitempty"`

	// Scopes is the key's scope list as stored, as written.
	Scopes []string `json:"scopes"`

	// ExpiresAt is when the key stops working, in Unix seconds.
	ExpiresAt int64 `json:"expiresAt"`
}

// request is a create request that has been parsed: the name, the labels, the
// scope lists and the sandbox the new agent and its key are to have. sandbox is
// the zero value when the request names none.
type request struct {
	name      input.AgentName
	labels    input.LabelSet
	scopes    scope.List
	keyScopes scope.List
	sandbox   input.SandboxID
	// recipient is the key the first key's token is sealed to, the zero value
	// when the caller is to be sent it as it is.
	recipient input.PublicKey
}

// parseCreate parses the new agent's name, labels and scope lists. A scope list
// that is absent is the default; one that is present is parsed strictly, so a
// typo or an unknown name is a 400 and not a credential that silently can do
// nothing.
//
// The caller decides what an absent list means (an agent creating an agent
// inherits), so absence is reported and not resolved here.
func parseCreate(body createBody) result.Result[request] {
	return result.Of(input.ParseAgentName(body.Name)).
		Map(func(name input.AgentName) request { return request{name: name} }).
		Then(func(req request) (request, error) {
			return result.Of(input.ParseLabelSet(deref(body.Labels))).
				Map(func(labels input.LabelSet) request { req.labels = labels; return req }).
				Get()
		}).
		Then(func(req request) (request, error) {
			return parseOptionalScopes(body.Scopes).
				Map(func(scopes scope.List) request { req.scopes = scopes; return req }).
				Get()
		}).
		Then(func(req request) (request, error) {
			return parseOptionalScopes(body.KeyScopes).
				Map(func(scopes scope.List) request { req.keyScopes = scopes; return req }).
				Get()
		}).
		Then(func(req request) (request, error) {
			return parseOptionalSandbox(body.SandboxID).
				Map(func(sandbox input.SandboxID) request { req.sandbox = sandbox; return req }).
				Get()
		})
}

// parseOptionalSandbox parses the sandbox a create names, which may be absent
// (the zero SandboxID). A present one is parsed strictly, the empty string
// included.
func parseOptionalSandbox(raw *string) result.Result[input.SandboxID] {
	if raw == nil {
		return result.Ok(input.SandboxID{})
	}

	return result.Of(input.ParseSandboxID(*raw))
}

// parseOptionalScopes parses a scope list that may be absent. Absent is nil and
// present, even empty, is a non-nil list, which is how "not given" and "given
// as nothing" stay different.
func parseOptionalScopes(raw *[]string) result.Result[scope.List] {
	if raw == nil {
		return result.Ok(scope.List(nil))
	}

	return result.Of(input.ParseScopeList(*raw)).
		Map(func(parsed input.ScopeList) scope.List { return parsed.List() })
}

// creation is a create request that has been planned: the agent, its key and its
// labels exactly as they will be written, and the key's token, as the response
// shows it: plain in token, or sealed in sealed. Once written it also holds the
// agent's scopes as the write stored them.
type creation struct {
	agent  store.NewAgent
	token  string
	sealed string
	// keyScopes is what the response reports for the key: the list stored on
	// the key's row.
	keyScopes scope.List
	// scopes is what the response reports for the agent. It is set from the
	// write's own result, never from the plan, because an agent's create copies
	// the creating agent's scopes from its row in the write.
	scopes scope.List
	// sandbox is the sandbox the agent is in, "" for none, set from the write
	// too: an agent's create copies it from the creating agent's row.
	sandbox string
}

func (d Deps) create(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[createBody](call.Request).
		Then(func(body createBody) (request, error) { return d.parseRequest(call, body).Get() }).
		Then(func(req request) (request, error) { return resolveScopes(call.Principal, req).Get() }).
		Then(func(req request) (request, error) { return resolveSandbox(call.Principal, req).Get() }).
		Then(func(req request) (creation, error) { return d.plan(call, req).Get() }).
		Then(func(plan creation) (creation, error) { return d.write(call, plan).Get() }).
		MapErr(createRefused).
		Map(respondCreated).
		Map(func(out CreateResponse) httpapi.Response { return httpapi.JSON(http.StatusCreated, out) })
}

// parseRequest parses the body of a create and decides who the first key's
// token is sealed to. The recipient is decided here, before anything is issued
// or written, so a credential that must send one and did not is refused with
// nothing created.
func (d Deps) parseRequest(call *auth.Call, body createBody) result.Result[request] {
	return parseCreate(body).
		Then(func(req request) (request, error) {
			return auth.Recipient(call.Principal, body.PublicKey).
				Map(func(to input.PublicKey) request { req.recipient = to; return req }).
				Get()
		})
}

// write stores the plan and records the scopes and the sandbox the write
// returned on it, which are what the response reports for the agent.
func (d Deps) write(call *auth.Call, plan creation) result.Result[creation] {
	return result.Of(d.Store.CreateAgent(call.Request.Context, plan.agent)).
		Map(func(stored store.CreatedAgent) creation {
			plan.scopes = scope.Read(stored.Scopes)
			plan.sandbox = stored.SandboxID

			return plan
		})
}

// resolveScopes decides the scope lists of the new agent and its key, from who
// is asking.
//
// A user (a session or one of their own keys) chooses both freely, with the
// default for an absent list. Neither can exceed what the user may do: every
// request is bounded by the user's role, and an admin scope is refused to a
// member whatever a credential names, so there is nothing to compare here.
//
// An agent is bounded by itself. The new agent's scopes are a copy of its own,
// so they may not be set; its key's scopes must be entries of the creating key's
// list as written, and default to that list. The literal comparison is what
// makes it sound: a list contained in another has an expansion contained in the
// other's however the bundles change later, so the new agent can never do more
// than the key that created it (docs/permissions_design.md).
func resolveScopes(who auth.Principal, req request) result.Result[request] {
	if who.AgentID == "" {
		return result.Ok(userScopes(req))
	}

	if req.scopes != nil {
		return result.Fail[request](scopesInherited())
	}

	req.scopes = who.AgentScope

	if req.keyScopes == nil {
		req.keyScopes = who.Scope

		return result.Ok(req)
	}

	if !req.keyScopes.SubsetOf(who.Scope) {
		return result.Fail[request](keyScopesExceeded())
	}

	return result.Ok(req)
}

// scopesInherited is the client's 403 for an agent that tried to choose the
// scopes of the agent it creates.
func scopesInherited() *apierr.Error {
	return apierr.New(apierr.Forbidden, CodeScopesInherited,
		"an agent creates agents with its own scopes and may not choose them")
}

// keyScopesExceeded is the client's 403 for an agent that asked for a key
// holding more than the key it is using.
func keyScopesExceeded() *apierr.Error {
	return apierr.New(apierr.Forbidden, CodeKeyScopesExceeded,
		"the new key may only hold scopes the creating key holds")
}

// resolveSandbox decides the sandbox of the new agent, from who is asking.
//
// A user names the sandbox, or none, and the write checks that they administer
// it and that it has not expired, so there is nothing to compare here. An agent
// does not choose: its new agent is in its own sandbox, or in none when it is
// in none, and the write reads that from the agent's row. A request that names
// any other sandbox is refused, so a client that expects one is told it did not
// get it, rather than silently given another. Naming its own is allowed, and
// the same as naming none.
func resolveSandbox(who auth.Principal, req request) result.Result[request] {
	if who.AgentID == "" {
		return result.Ok(req)
	}

	if named := req.sandbox.String(); named != "" && named != who.SandboxID {
		return result.Fail[request](sandboxInherited())
	}

	return result.Ok(req)
}

// sandboxInherited is the client's 403 for an agent that tried to choose the
// sandbox of the agent it creates.
func sandboxInherited() *apierr.Error {
	return apierr.New(apierr.Forbidden, CodeSandboxInherited,
		"an agent creates agents in its own sandbox and may not choose another")
}

// userScopes applies the default to a user's request: an absent list is
// DefaultScopes.
func userScopes(req request) request {
	if req.scopes == nil {
		req.scopes = DefaultScopes()
	}

	if req.keyScopes == nil {
		req.keyScopes = DefaultScopes()
	}

	return req
}

// createRefused is the client's answer to a create the store refused. A sandbox
// the user does not administer, or that has expired, is a 404. Otherwise a
// conflict is the user already having MaxAgentsPerUser active agents, their
// account having been revoked after the request was authenticated, or the
// creating agent having been revoked or its sandbox having expired (the write
// cannot tell which, and a revoked account has no session to be told on). The
// id and the key id are fresh UUIDv7s, so no other constraint can conflict. The
// sandbox is judged first because the store's refusal for it also carries the
// conflict. Any other failure is returned as it is.
func createRefused(err error) error {
	switch {
	case errors.Is(err, store.ErrSandboxUnavailable):
		return noSuchSandbox(err)
	case errors.Is(err, store.ErrConflict):
		return atLimit(err)
	default:
		return err
	}
}

// noSuchSandbox is the client's 404 for a sandbox the user cannot create an
// agent in.
func noSuchSandbox(cause error) *apierr.Error {
	return apierr.New(apierr.NotFound, CodeSandboxNotFound, "no such sandbox").WithCause(cause)
}

// atLimit is the client's 409 for an owner who may have no more active agents.
func atLimit(cause error) *apierr.Error {
	return apierr.New(apierr.Conflict, CodeLimit,
		fmt.Sprintf("an account may have at most %d active agents", MaxAgentsPerUser)).WithCause(cause)
}

// plan decides everything about the new agent that does not need the database:
// its id and its first key. The key is issued here, before the write, so a
// failure to issue it writes nothing. The key belongs to the agent through the
// write, which stores it under the agent's id and the caller's user, never the
// request's, and it lives auth.AgentKeyLifetime.
//
// When an agent is creating, its id goes to the store, which reads the new
// agent's scopes from that agent's row in the write and ignores any list given
// here. The response reports the list the write returns, so it is the row's
// even if the creating agent's scopes changed between the request being
// verified and the write.
func (d Deps) plan(call *auth.Call, req request) result.Result[creation] {
	now := d.Now()
	id := d.NewID()
	owner := call.Principal.UserID

	issued, err := d.IssueAPIKey(d.Entropy, d.NewID, now, auth.AgentKeyLifetime)
	if err != nil {
		return result.Fail[creation](apierr.Wrap(err, apierr.Internal, CodeKeyFailed, "internal error"))
	}

	// Sealing is the last thing that can fail, and it is before the write, so a
	// key that cannot be sealed to creates nothing.
	sealed, err := auth.SealTo(d.Seal, req.recipient, issued.Token).Get()
	if err != nil {
		return result.Fail[creation](err)
	}

	token := issued.Token
	if sealed != "" {
		token = ""
	}

	return result.Ok(creation{
		agent: store.NewAgent{
			ID: id, Owner: owner, Name: req.name, Scopes: req.scopes.JSON(), KeyScope: req.keyScopes.JSON(),
			Labels: req.labels, CreatedBy: call.Principal.AgentID, Sandbox: req.sandbox, MaxActive: MaxAgentsPerUser,
			KeyID: issued.ID, KeyHash: issued.Hash, KeyExpiresAt: issued.ExpiresAt, CreatedAt: now,
		},
		token:     token,
		sealed:    sealed,
		keyScopes: req.keyScopes,
	})
}

// respondCreated is the response to a create, built from what was written: the
// agent's scopes and sandbox are the ones the write returned, and the row is not read back.
// The labels are the ones the batch wrote, in ascending order as every read of
// an agent lists them, and an empty list when there are none.
func respondCreated(plan creation) CreateResponse {
	agent := plan.agent

	var sandbox *string
	if plan.sandbox != "" {
		sandbox = &plan.sandbox
	}

	return CreateResponse{
		Agent: Agent{
			ID: agent.ID, Name: agent.Name.String(), Scopes: plan.scopes.Claim(), Status: StatusActive,
			RevokedAt: nil, CreatedAt: agent.CreatedAt.Unix(), Labels: sortedLabels(agent.Labels), SandboxID: sandbox,
		},
		Key: Key{
			ID: agent.KeyID, Token: plan.token, Sealed: plan.sealed, Scopes: plan.keyScopes.Claim(),
			ExpiresAt: agent.KeyExpiresAt.Unix(),
		},
	}
}

// sortedLabels is the text of a create's labels in ascending order, as an agent
// is always shown, and never nil: an agent with no labels has an empty list.
func sortedLabels(set input.LabelSet) []string {
	labels := set.Labels()
	text := make([]string, len(labels))

	for i, label := range labels {
		text[i] = label.String()
	}

	slices.Sort(text)

	return text
}

// patchBody is the body of PATCH /api/agent/{id}. Every member is optional, but
// at least one must be present.
//
// Labels are changed by adding and removing members and never by sending the
// whole set, so two requests that change different labels cannot undo each
// other: sending the set would turn every edit into a read-modify-write that
// the second writer wins. Adding a label the agent has, and removing one it
// lacks, succeed and change nothing, so a retry is safe.
//
// The arrays carry maxitems tags, so the decoder refuses an oversized one before
// it has allocated it; input.ParseLabelPatch checks the bound again.
type patchBody struct {
	Name         *string   `json:"name"`
	AddLabels    *[]string `json:"addLabels"    maxitems:"20"`
	RemoveLabels *[]string `json:"removeLabels" maxitems:"20"`
}

// change is a parsed PATCH: what to write.
type change struct {
	name   *input.AgentName
	labels input.LabelPatch
}

func (d Deps) patch(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[patchBody](call.Request).
		Then(parsePatch).
		Then(func(c change) (store.Agent, error) {
			return d.Store.PatchAgent(call.Request.Context, call.Principal.UserID, call.ID(), store.AgentPatch{
				Name: c.name, Labels: c.labels, MaxLabels: input.MaxLabelsPerAgent,
			})
		}).
		MapErr(patchFailed).
		// The store returns the row as the batch left it, and every write of it
		// skips a revoked agent, so a revoked agent comes back unchanged and is
		// refused here.
		Check(func(agent store.Agent) error {
			if agent.RevokedAt != nil {
				return apierr.New(apierr.Conflict, CodeRevoked, "the agent is revoked and cannot be changed")
			}

			return nil
		}).
		Map(present).
		Map(func(out Agent) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// parsePatch parses every part of a patch that is present, and refuses one that
// changes nothing. A member that is present but null is absent, as for any
// optional member.
func parsePatch(body patchBody) (change, error) {
	var name *input.AgentName

	if body.Name != nil {
		parsed, err := input.ParseAgentName(*body.Name)
		if err != nil {
			return change{}, err //nolint:wrapcheck // the parser's error is already the classified client error
		}

		name = &parsed
	}

	labels, err := input.ParseLabelPatch(deref(body.AddLabels), deref(body.RemoveLabels))
	if err != nil {
		return change{}, err //nolint:wrapcheck // the parser's error is already the classified client error
	}

	if name == nil && labels.Empty() {
		return change{}, nothingToChange()
	}

	return change{name: name, labels: labels}, nil
}

// nothingToChange is the client's 400 for a PATCH that names nothing to change.
func nothingToChange() *apierr.Error {
	return apierr.New(apierr.BadRequest, CodeNothingToChange, "a name, labels to add or labels to remove is required")
}

// deref returns the list a pointer holds, or none.
func deref(list *[]string) []string {
	if list == nil {
		return nil
	}

	return *list
}

// patchFailed maps what the store says about a patch to the client's answer: no
// such agent is a 404 and a patch that would exceed the label limit is a 409.
// Anything else is returned as it is.
func patchFailed(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return noSuchAgent(err)
	case errors.Is(err, store.ErrConflict):
		return labelLimit(err)
	default:
		return err
	}
}

// labelLimit is the client's 409 for a patch that would leave an agent with more
// labels than it may have. The store's batch changed nothing.
func labelLimit(cause error) *apierr.Error {
	return apierr.New(apierr.Conflict, CodeLabelLimit,
		fmt.Sprintf("an agent may have at most %d labels", input.MaxLabelsPerAgent)).WithCause(cause)
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
