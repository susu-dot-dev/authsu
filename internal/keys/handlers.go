package keys

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Error codes of the key routes themselves. A failure of the store, a bad path
// id, a bad page parameter, a bad name, scope list or lifetime has its own code
// in store or input. They are stable: clients and dashboards may match on them.
const (
	// CodeNotFound is a key the user does not have: one that does not exist, one
	// that belongs to someone else, an agent's, and the one the request
	// presented (which only logout ends).
	CodeNotFound = "key_not_found"
	// CodeLimit is a create refused because the user already has MaxKeysPerUser
	// active keys, or has been revoked since signing in.
	CodeLimit = "key_limit_reached"
	// CodeKeyFailed is the issue of a key failing, before anything was written.
	CodeKeyFailed = "key_issue_failed"
	// CodeInactive is a rename of a key that is revoked or expired.
	CodeInactive = "key_inactive"
)

// Paths. The collection takes GET and POST; one key takes GET, PATCH and DELETE.
const (
	collectionPath = "/api/key"
	itemPath       = "/api/key/{id}"
)

// MaxBody is the largest request body any key route reads, in bytes. The
// biggest legitimate one is a name of 256 four-byte characters, every one
// escaped as a \uXXXX surrogate pair (12 bytes), about 3 KiB, so this leaves
// room and refuses anything that could only be an attempt to make the route
// read more before a name is refused.
const MaxBody = 8 << 10

// Routes returns the key routes. Each needs its own scope and no role: a key is
// something every user has, and each route acts only on the caller's own.
//
// Issuing needs a session and refuses agents. Renaming and revoking refuse
// agents too: they are the user's to manage, and an agent holding the scope
// could otherwise act on keys that are not its own. Listing and reading are open
// to a key with key:read, so software can see which of the user's keys exist.
//
// It panics when a dependency is nil.
func Routes(deps Deps) []auth.Route {
	for name, missing := range map[string]bool{
		"Store": deps.Store == nil, "Now": deps.Now == nil, "NewID": deps.NewID == nil, "Entropy": deps.Entropy == nil,
		"IssueUserAPIKey": deps.IssueUserAPIKey == nil,
	} {
		if missing {
			panic("keys: Deps." + name + " is required")
		}
	}

	return []auth.Route{
		declare(http.MethodGet, collectionPath, auth.Needs(scope.KeyRead), deps.list),
		declare(http.MethodPost, collectionPath, auth.Needs(scope.KeyCreate).Sessions().WithoutAgents(), deps.create),
		declare(http.MethodGet, itemPath, auth.Needs(scope.KeyRead), deps.get),
		declare(http.MethodPatch, itemPath, auth.Needs(scope.KeyUpdate).WithoutAgents(), deps.patch),
		declare(http.MethodDelete, itemPath, auth.Needs(scope.KeyRevoke).WithoutAgents(), deps.revoke),
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

// ListResponse is the body of GET /api/key: one page, newest first.
type ListResponse struct {
	Keys []Key `json:"keys"`

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
func parsePage(query map[string][]string) result.Result[page] {
	return result.Of(input.ParsePageLimit(query["limit"])).
		Map(func(limit input.PageLimit) page { return page{limit: limit} }).
		Then(func(p page) (page, error) {
			return result.Of(input.ParseCursor(query["cursor"])).
				Map(func(cursor input.Cursor) page { p.cursor = cursor; return p }).
				Get()
		})
}

func (d Deps) list(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return parsePage(call.Request.Query).
		Then(func(p page) (store.KeyPage, error) {
			return d.Store.ListKeys(call.Request.Context, call.Principal.UserID, p.cursor, p.limit)
		}).
		Map(func(stored store.KeyPage) ListResponse {
			out := ListResponse{Keys: make([]Key, 0, len(stored.Keys)), Next: stored.Next}

			for _, key := range stored.Keys {
				out.Keys = append(out.Keys, present(key, now))
			}

			return out
		}).
		Map(func(out ListResponse) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

func (d Deps) get(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(d.Store.GetKey(call.Request.Context, call.Principal.UserID, call.ID())).
		MapErr(notFound).
		Map(func(stored store.Key) Key { return present(stored, now) }).
		Map(func(out Key) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// notFound turns the store's "no such row" into the client's 404. The store
// matches by owner as well as id, and only keys with no agent, so a key of
// another user and an agent's key come back as the same outcome, and so the
// same response, as one that does not exist. Anything else is returned as it
// is.
func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return noSuchKey(err)
	}

	return err
}

// noSuchKey is the client's 404 for a key the user does not have.
func noSuchKey(cause error) *apierr.Error {
	return apierr.New(apierr.NotFound, CodeNotFound, "no such key").WithCause(cause)
}

// createBody is the body of POST /api/key.
type createBody struct {
	// Name is a label for the key.
	Name string `json:"name"`

	// Scopes is the key's scope list. Absent (or null) means the default
	// (DefaultScopes); an empty list is a credential that can use only the
	// routes that need no scope. The names are checked against the known ones
	// and no further: every request is bounded by the user's role and by the
	// list itself, so a key can never exceed what the user may do
	// (docs/permissions_design.md). input.ParseScopeList bounds it.
	Scopes *[]string `json:"scopes" maxitems:"32"`

	// LifetimeDays is how long the key lives, in whole days from 1 to
	// input.MaxUserKeyLifetimeDays. Absent (or null) means
	// input.DefaultKeyLifetimeDays.
	LifetimeDays *int64 `json:"lifetimeDays"`
}

// CreateResponse is the body of a created key. Token is the only time the key's
// token is ever returned.
type CreateResponse struct {
	Key

	// Token is the bearer token ("susu_key_..."). Only its hash is stored, so it
	// cannot be shown again.
	Token string `json:"token"`
}

// request is a create request that has been parsed.
type request struct {
	name     input.KeyName
	scopes   scope.List
	lifetime input.KeyLifetime
}

// parseCreate parses the new key's name, scopes and lifetime. An absent scope
// list is the default and one that is present is parsed strictly, so a typo or
// an unknown name is a 400 and not a credential that silently can do nothing.
// An absent lifetime is the default of input.DefaultKeyLifetime and a present
// one is parsed strictly.
func parseCreate(body createBody) result.Result[request] {
	return result.Of(input.ParseKeyName(body.Name)).
		Map(func(name input.KeyName) request { return request{name: name} }).
		Then(func(req request) (request, error) {
			return parseScopes(body.Scopes).
				Map(func(scopes scope.List) request { req.scopes = scopes; return req }).
				Get()
		}).
		Then(func(req request) (request, error) {
			return parseLifetime(body.LifetimeDays).
				Map(func(lifetime input.KeyLifetime) request { req.lifetime = lifetime; return req }).
				Get()
		})
}

// parseScopes parses a scope list that may be absent: absent is the default,
// written out in full, and present (even empty) is exactly what was asked for.
func parseScopes(raw *[]string) result.Result[scope.List] {
	if raw == nil {
		return result.Ok(DefaultScopes())
	}

	return result.Of(input.ParseScopeList(*raw)).
		Map(func(parsed input.ScopeList) scope.List { return parsed.List() })
}

// parseLifetime parses a lifetime that may be absent.
func parseLifetime(raw *int64) result.Result[input.KeyLifetime] {
	if raw == nil {
		return result.Ok(input.DefaultKeyLifetime())
	}

	return result.Of(input.ParseKeyLifetime(*raw))
}

// creation is a create request that has been planned: the key exactly as it
// will be written, and its token.
type creation struct {
	key    store.NewKey
	token  string
	scopes scope.List
}

func (d Deps) create(call *auth.Call) result.Result[httpapi.Response] {
	return httpapi.Decode[createBody](call.Request).
		Then(func(body createBody) (request, error) { return parseCreate(body).Get() }).
		Then(func(req request) (creation, error) { return d.plan(call, req).Get() }).
		Then(func(plan creation) (creation, error) {
			return plan, d.Store.CreateKey(call.Request.Context, plan.key)
		}).
		MapErr(limitReached).
		Map(respondCreated).
		Map(func(out CreateResponse) httpapi.Response { return httpapi.JSON(http.StatusCreated, out) })
}

// plan decides everything about the new key that does not need the database: its
// token and id. The token is issued here, before the write, so a failure to
// issue it writes nothing. The key's owner is the caller's user, never the
// request's.
func (d Deps) plan(call *auth.Call, req request) result.Result[creation] {
	now := d.Now()

	issued, err := d.IssueUserAPIKey(d.Entropy, d.NewID, now, req.lifetime.Duration())
	if err != nil {
		return result.Fail[creation](apierr.Wrap(err, apierr.Internal, CodeKeyFailed, "internal error"))
	}

	return result.Ok(creation{
		key: store.NewKey{
			ID: issued.ID, Owner: call.Principal.UserID, Name: req.name, Scope: req.scopes.JSON(),
			Hash: issued.Hash, ExpiresAt: issued.ExpiresAt, MaxActive: MaxKeysPerUser, CreatedAt: now,
		},
		token:  issued.Token,
		scopes: req.scopes,
	})
}

// limitReached is the client's answer to a create the store refused as a
// conflict: the user already has MaxKeysPerUser active keys, or their account
// was revoked after the request was authenticated (the write cannot tell which,
// and a revoked account has no session to be told on). The id and the token's
// hash are fresh, so no other constraint can conflict. Any other failure is
// returned as it is.
func limitReached(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return atLimit(err)
	}

	return err
}

// atLimit is the client's 409 for an owner who may have no more active keys.
func atLimit(cause error) *apierr.Error {
	return apierr.New(apierr.Conflict, CodeLimit,
		fmt.Sprintf("an account may have at most %d active keys", MaxKeysPerUser)).WithCause(cause)
}

// respondCreated is the response to a create, built from what was written: the
// row is not read back, and the scopes are the list that was stored.
func respondCreated(plan creation) CreateResponse {
	key := plan.key

	return CreateResponse{
		ID: key.ID, Name: key.Name.String(), Scopes: plan.scopes.Claim(), Status: StatusActive,
		ExpiresAt: key.ExpiresAt.Unix(), RevokedAt: nil, CreatedAt: key.CreatedAt.Unix(),
		Token: plan.token,
	}
}

// patchBody is the body of PATCH /api/key/{id}. The name is the only thing about
// a key that can change: its scopes are fixed when it is issued and its expiry
// is fixed with its secret.
type patchBody struct {
	Name string `json:"name"`
}

func (d Deps) patch(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return httpapi.Decode[patchBody](call.Request).
		Then(func(body patchBody) (input.KeyName, error) { return input.ParseKeyName(body.Name) }).
		Then(func(name input.KeyName) (store.Key, error) {
			return d.Store.RenameKey(call.Request.Context, call.Principal.UserID, call.ID(), name, now)
		}).
		MapErr(notFound).
		// The store returns the row as the write left it, and the write skips a
		// key that is no longer active, so a revoked or expired key comes back
		// unchanged and is refused here.
		Check(func(key store.Key) error {
			if present(key, now).Status != StatusActive {
				return apierr.New(apierr.Conflict, CodeInactive, "the key is revoked or expired and cannot be changed")
			}

			return nil
		}).
		Map(func(stored store.Key) Key { return present(stored, now) }).
		Map(func(out Key) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}

// revoke revokes one of the user's own keys now, and returns it as the write
// left it. Revoking a key that is already revoked succeeds and keeps the earlier
// time, so the call is idempotent. The key the request presented is never
// revoked here: the store's write and read both exclude it, so it is answered as
// a key that does not exist.
func (d Deps) revoke(call *auth.Call) result.Result[httpapi.Response] {
	now := d.Now()

	return result.Of(d.Store.RevokeKey(
		call.Request.Context, call.Principal.UserID, call.ID(), call.Principal.SecretID, now)).
		MapErr(notFound).
		Map(func(stored store.Key) Key { return present(stored, now) }).
		Map(func(out Key) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
}
