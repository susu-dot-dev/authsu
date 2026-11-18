package agents

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// Error codes. Each failing step has its own, so a log line or an alert names
// the step. They are stable: clients and dashboards may match on them.
const (
	CodeNotConfigured  = "agents_not_configured"
	CodeListFailed     = "agent_list_failed"
	CodeLookupFailed   = "agent_lookup_failed"
	CodeCreateFailed   = "agent_create_failed"
	CodeCreateRejected = "agent_create_rejected"
	CodeLimit          = "agent_limit_reached"
	CodeKeyFailed      = "agent_key_failed"
	CodeUpdateFailed   = "agent_update_failed"
	CodeUpdateRejected = "agent_update_rejected"
	CodeRevokeFailed   = "agent_revoke_failed"
	CodeRevokeRejected = "agent_revoke_rejected"
	CodeNotFound       = "agent_not_found"
	CodeInvalidID      = "invalid_agent_id"
	CodeInvalidName    = "invalid_agent_name"
	CodeMissingName    = "missing_agent_name"
	CodeInvalidLimit   = "invalid_limit"
	CodeInvalidCursor  = "invalid_cursor"
	CodeRevoked        = "agent_revoked"
)

// PathWildcards returns the {name} wildcards of ItemPath, for
// httpapi.ServeMethods.
func PathWildcards() []string { return []string{"id"} }

// Paths. The collection takes GET and POST; one agent takes GET, PATCH and
// DELETE.
const (
	CollectionPath = "/api/agent"
	ItemPath       = "/api/agent/{id}"
)

// canonicalUUIDLen is the length of a UUID in 8-4-4-4-12 form.
const canonicalUUIDLen = 36

func notConfigured(cause error) error {
	return fail(cause, apierr.Unavailable, CodeNotConfigured, "agents are not available")
}

func badRequest(code, description string) error {
	return fail(nil, apierr.BadRequest, code, description)
}

// fail builds a classified error. It goes through apierr.Wrap, which keeps the
// innermost classification, so a failure that already carries one is not
// reclassified; cause may be nil for a failure with nothing underneath it.
func fail(cause error, kind apierr.Kind, code, description string) error {
	if cause == nil {
		return apierr.Wrap(errRefused, kind, code, description)
	}

	return apierr.Wrap(cause, kind, code, description)
}

// errRefused is the cause of a failure that has nothing underneath it, so Wrap
// (which is nil-in, nil-out) still produces an error.
var errRefused = errors.New("refused")

// owner authenticates the request: the agents it is about are the signed-in
// user's, and no role is needed, because an agent is something every user has.
// Agents are created and managed by a person, so a passkey-backed session is
// what this API accepts; nothing else authenticates yet.
//
// A missing store is refused first, without authenticating: there is nothing to
// authorise against.
func (s *Service) owner(
	ctx context.Context, getenv func(string) string, req httpapi.Request,
) result.Result[session.Principal] {
	return result.Ok(req).
		Check(func(httpapi.Request) error { return s.requireStore() }).
		Then(func(req httpapi.Request) (session.Principal, error) {
			// Authenticate's errors are already classified (401, or 503 when
			// sessions cannot be verified); Wrap keeps that.
			principal, err := s.sessions.Authenticate(ctx, getenv, req)

			return principal, apierr.Wrap(err, apierr.Unauthorized, session.CodeUnauthenticated, "not signed in")
		})
}

// writer is owner that also checks there is a way to write.
func (s *Service) writer(
	ctx context.Context, getenv func(string) string, req httpapi.Request,
) result.Result[session.Principal] {
	return s.owner(ctx, getenv, req).
		Check(func(session.Principal) error { return s.requireBatch() })
}

func (s *Service) requireStore() error {
	if s.reader == nil {
		return notConfigured(errNoStore)
	}

	return nil
}

func (s *Service) requireBatch() error {
	if s.batch == nil {
		return notConfigured(errNoStore)
	}

	return nil
}

// Routes are the handlers of the two paths, each by method, ready for
// httpapi.ServeMethods.
type Routes struct {
	// Collection is CollectionPath: GET lists, POST creates.
	Collection map[string]httpapi.Handler
	// Item is ItemPath: GET reads, PATCH renames, DELETE revokes.
	Item map[string]httpapi.Handler
}

// Handlers returns the handlers for both paths.
func (s *Service) Handlers(getenv func(string) string) Routes {
	return Routes{
		Collection: map[string]httpapi.Handler{
			http.MethodGet:  s.listHandler(getenv),
			http.MethodPost: s.createHandler(getenv),
		},
		Item: map[string]httpapi.Handler{
			http.MethodGet:    s.getHandler(getenv),
			http.MethodPatch:  s.renameHandler(getenv),
			http.MethodDelete: s.revokeHandler(getenv),
		},
	}
}

// ListResponse is the body of GET /api/agent: one page, newest first.
type ListResponse struct {
	Agents []Agent `json:"agents"`
	// Next is the cursor of the following page, to send as the cursor query
	// parameter. It is absent on the last page.
	Next string `json:"next,omitempty"`
}

// page is a validated list request: the id to start below, and the most agents
// to return.
type page struct {
	userID string
	before string
	limit  int
}

func (s *Service) listHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		// The query is validated first, like a create's body: a malformed
		// request is refused the same way for everyone.
		return result.Of(pageOf(req)).
			Then(func(p page) (page, error) {
				return s.owner(req.Context, getenv, req).
					Map(func(principal session.Principal) page {
						p.userID = principal.UserID

						return p
					}).
					Get()
			}).
			Then(func(p page) (ListResponse, error) { return s.readPage(req.Context, p) }).
			Map(func(out ListResponse) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

// pageOf reads the limit and cursor from the query. Each may appear at most
// once: a repeated parameter is ambiguous, and which value wins differs between
// layers, so it is refused rather than guessed.
func pageOf(req httpapi.Request) (page, error) {
	limit, err := limitOf(req.Query["limit"])
	if err != nil {
		return page{}, err
	}

	before, err := cursorOf(req.Query["cursor"])
	if err != nil {
		return page{}, err
	}

	return page{userID: "", before: before, limit: limit}, nil
}

// limitOf reads the limit: absent is DefaultPageSize, and anything but a plain
// decimal from 1 to MaxPageSize is refused, not clamped, so a client that asks
// for too much is told.
func limitOf(values []string) (int, error) {
	if len(values) == 0 {
		return DefaultPageSize, nil
	}

	if len(values) != 1 {
		return 0, badRequest(CodeInvalidLimit, "limit may be given once")
	}

	limit, ok := parseLimit(values[0])
	if !ok {
		return 0, badRequest(CodeInvalidLimit, limitDescription())
	}

	return limit, nil
}

// parseLimit reads text as digits only (no sign, space or prefix) of at most as
// many digits as MaxPageSize, so the conversion cannot overflow, within 1 to
// MaxPageSize.
func parseLimit(text string) (int, bool) {
	if len(text) == 0 || len(text) > len(strconv.Itoa(MaxPageSize)) || strings.Trim(text, "0123456789") != "" {
		return 0, false
	}

	limit, err := strconv.Atoi(text)

	return limit, err == nil && limit >= 1 && limit <= MaxPageSize
}

func limitDescription() string {
	return fmt.Sprintf("limit must be a whole number from 1 to %d", MaxPageSize)
}

// cursorOf reads the cursor, which is an agent id: absent is the first page.
func cursorOf(values []string) (string, error) {
	switch len(values) {
	case 0:
		return FirstPage, nil
	case 1:
	default:
		return "", badRequest(CodeInvalidCursor, "cursor may be given once")
	}

	if !isCanonicalUUID(values[0]) {
		return "", badRequest(CodeInvalidCursor, "cursor is not valid")
	}

	return values[0], nil
}

// readPage reads one more agent than the page holds. If it is there, there is a
// next page, and it starts below the last agent that is returned.
func (s *Service) readPage(ctx context.Context, p page) (ListResponse, error) {
	rows, err := s.reader.List(ctx, p.userID, p.before, p.limit+1)
	if err != nil {
		return ListResponse{}, apierr.Wrap(err, apierr.Unavailable, CodeListFailed, "agents are temporarily unavailable")
	}

	next := ""

	if len(rows) > p.limit {
		rows = rows[:p.limit]
		next = rows[p.limit-1].ID
	}

	out := presentAll(rows)
	out.Next = next

	return out, nil
}

func presentAll(rows []Row) ListResponse {
	out := ListResponse{Agents: make([]Agent, 0, len(rows)), Next: ""}

	for _, row := range rows {
		out.Agents = append(out.Agents, present(row))
	}

	return out
}

// present is the client's view of row.
func present(row Row) Agent {
	return Agent{
		ID: row.ID, Name: row.Name, Scopes: row.Scopes, Status: StatusOf(row),
		RevokedAt: row.RevokedAt, CreatedAt: row.CreatedAt,
	}
}

func (s *Service) getHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return s.owner(req.Context, getenv, req).
			Then(func(principal session.Principal) (target, error) { return targetOf(principal, req) }).
			Then(func(t target) (Row, error) { return s.readOne(req.Context, t) }).
			Map(present).
			Map(func(out Agent) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

// target is the agent a request is about, and the user whose agent it must be.
type target struct {
	userID string
	id     string
}

// targetOf reads the agent id from the path, for the signed-in user.
func targetOf(principal session.Principal, req httpapi.Request) (target, error) {
	id, err := idOf(req)

	return target{userID: principal.UserID, id: id}, err
}

func (s *Service) readOne(ctx context.Context, t target) (Row, error) {
	row, err := s.reader.Get(ctx, t.userID, t.id)

	switch {
	case err == nil:
		return row, nil
	case errors.Is(err, ErrNotFound):
		return Row{}, notFound()
	default:
		return Row{}, apierr.Wrap(err, apierr.Unavailable, CodeLookupFailed, "agents are temporarily unavailable")
	}
}

func notFound() error {
	return fail(nil, apierr.NotFound, CodeNotFound, "no such agent")
}

// idOf reads the agent id from the path. It is checked for shape before it
// reaches SQL, though it is only ever bound as a value.
func idOf(req httpapi.Request) (string, error) {
	id := req.PathValues["id"]

	if !isCanonicalUUID(id) {
		return "", badRequest(CodeInvalidID, "agent id is not valid")
	}

	return id, nil
}

// isCanonicalUUID reports whether id is a UUID in lowercase 8-4-4-4-12 form:
// dashes where they belong and lowercase hex everywhere else.
func isCanonicalUUID(id string) bool {
	if len(id) != canonicalUUIDLen {
		return false
	}

	for i := range len(id) {
		if !isUUIDChar(i, id[i]) {
			return false
		}
	}

	return true
}

// isUUIDChar reports whether c may stand at position i of a canonical UUID.
func isUUIDChar(i int, c byte) bool {
	if i == 8 || i == 13 || i == 18 || i == 23 {
		return c == '-'
	}

	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// validateName requires a name of 1 to MaxNameChars characters that is not
// only whitespace: it is how a user tells their agents apart. Because it is
// shown to people, it also refuses what can make two names look alike or hide
// text: control characters (NUL included, which SQLite's length() stops at),
// format characters such as the zero-width and bidirectional-override ones,
// and the replacement character, which is what encoding/json leaves for
// invalid UTF-8 or a lone surrogate.
func validateName(name string) error {
	if strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > MaxNameChars ||
		strings.IndexFunc(name, isForbiddenNameRune) >= 0 {
		return badRequest(CodeInvalidName, fmt.Sprintf("name must be 1 to %d printable characters", MaxNameChars))
	}

	return nil
}

func isForbiddenNameRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError
}

// CreateRequest is the body of POST /api/agent.
type CreateRequest struct {
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

func (s *Service) createHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		// Validation comes first: it learns nothing about the store, and a
		// malformed request is refused the same way for everyone.
		return httpapi.Decode[CreateRequest](req).
			Check(func(in CreateRequest) error { return validateName(in.Name) }).
			Then(func(in CreateRequest) (creation, error) {
				return s.writer(req.Context, getenv, req).
					Then(func(principal session.Principal) (creation, error) { return s.plan(getenv, principal, in).Get() }).
					Get()
			}).
			Then(func(c creation) (CreateResponse, error) { return s.create(req.Context, c).Get() }).
			Map(func(out CreateResponse) httpapi.Response { return httpapi.JSON(http.StatusCreated, out) })
	}
}

// creation is a validated create request, the user making it, and the key the
// agent will start with.
type creation struct {
	userID string
	row    Row
	key    session.Key
}

// plan decides everything about the new agent that does not need the database:
// its id, its default scopes, and its first key. The key is minted here, before
// the write, so a failure to mint writes nothing.
//
// The token's subject is the user, and its actor names the agent
// (docs/agents_design.md): a service that knows nothing about agents sees the
// user, and one that does can tell the agent apart. The scopes are signed in as
// a claim that nothing reads yet.
func (s *Service) plan(
	getenv func(string) string, principal session.Principal, in CreateRequest,
) result.Result[creation] {
	return result.Of(session.LoadConfig(getenv)).
		MapErr(func(err error) error {
			return fail(err, apierr.Unavailable, session.CodeNotConfigured, "sessions are not available")
		}).
		Then(func(cfg session.Config) (creation, error) {
			now := s.now()
			row := Row{ID: s.newID(), Name: in.Name, Scopes: DefaultScopes, RevokedAt: nil, CreatedAt: now.Unix()}

			key, err := s.mint(cfg.Issuer, session.Spec{
				Kind: session.KindAPIKey, Subject: principal.UserID, Expires: now.Add(KeyLifetime),
				Claims: map[string]any{
					"act":   map[string]any{"sub": row.ID},
					"scope": row.Scopes,
				},
			})

			return creation{userID: principal.UserID, row: row, key: key},
				apierr.Wrap(err, apierr.Internal, CodeKeyFailed, "internal error")
		})
}

// create writes the agent and its first key as one batch: either both exist or
// neither does. See insertAgentQuery and insertKeyQuery for how the user being
// revoked or at the limit fails the batch and not just the first statement.
func (s *Service) create(ctx context.Context, c creation) result.Result[CreateResponse] {
	return s.run(ctx, []atomic.Statement{
		{Query: insertAgentQuery, Args: []any{
			c.row.ID, c.row.Name, c.row.Scopes, c.row.CreatedAt, c.userID, int64(MaxAgentsPerUser),
		}},
		{Query: insertKeyQuery, Args: []any{
			c.key.ID.String(), c.row.ID, string(c.key.JWK), c.key.ExpiresAt.Unix(), c.row.ID, c.row.Scopes, c.row.CreatedAt,
		}},
	}, createError, CodeCreateRejected).
		Map(func([]atomic.Result) CreateResponse {
			return CreateResponse{
				Agent: present(c.row),
				Key: Key{
					ID: c.key.ID.String(), Token: c.key.JWT, Scope: c.row.Scopes, ExpiresAt: c.key.ExpiresAt.Unix(),
				},
			}
		})
}

// createError classifies a failed create. A conflict is the batch's own
// guards: the user already has MaxAgentsPerUser agents, or their account was
// revoked after the request was authenticated (the write cannot tell which, and
// a revoked account has no session to be told on). The id and the kid are fresh
// UUIDv7s, so no other constraint can conflict. A rejection is a defect on our
// side (500 under its own code), and anything else is the database being
// unavailable (503).
func createError(err error) error {
	switch {
	case errors.Is(err, atomic.ErrConflict):
		return apierr.Wrap(err, apierr.Conflict, CodeLimit,
			fmt.Sprintf("an account may have at most %d active agents", MaxAgentsPerUser))
	case errors.Is(err, atomic.ErrRejected):
		return apierr.Wrap(err, apierr.Internal, CodeCreateRejected, "internal error")
	default:
		return apierr.Wrap(err, apierr.Unavailable, CodeCreateFailed, "agents are temporarily unavailable")
	}
}

// RenameRequest is the body of PATCH /api/agent/{id}. It is a patch, so each
// field is optional, but at least one must be present; the name is the only
// one there is.
type RenameRequest struct {
	Name *string `json:"name"`
}

func (s *Service) renameHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return httpapi.Decode[RenameRequest](req).
			Check(validateRename).
			Then(func(in RenameRequest) (rename, error) {
				return s.writer(req.Context, getenv, req).
					Then(func(principal session.Principal) (target, error) { return targetOf(principal, req) }).
					Map(func(t target) rename { return rename{target: t, name: *in.Name} }).
					Get()
			}).
			Then(func(r rename) (Row, error) { return s.rename(req.Context, r).Get() }).
			Map(present).
			Map(func(out Agent) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

// rename is a validated rename: which agent, and its new name.
type rename struct {
	target

	name string
}

func validateRename(in RenameRequest) error {
	if in.Name == nil {
		return badRequest(CodeMissingName, "name is required")
	}

	return validateName(*in.Name)
}

// rename changes the name and returns the agent as the write left it. A revoked
// agent keeps its name and is refused with 409: the row comes back from the
// same statement that decided, so there is no read in between to disagree.
func (s *Service) rename(ctx context.Context, r rename) result.Result[Row] {
	return s.writeOne(ctx, []atomic.Statement{
		{Query: renameQuery, Args: []any{r.name, r.id, r.userID}},
	}, writeError(CodeUpdateFailed, CodeUpdateRejected), CodeUpdateRejected).
		Check(func(row Row) error {
			if row.RevokedAt != nil {
				return fail(nil, apierr.Conflict, CodeRevoked, "the agent is revoked and cannot be changed")
			}

			return nil
		})
}

func (s *Service) revokeHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return s.writer(req.Context, getenv, req).
			Then(func(principal session.Principal) (target, error) { return targetOf(principal, req) }).
			Then(func(t target) (Row, error) { return s.revoke(req.Context, t).Get() }).
			Map(present).
			Map(func(out Agent) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

// revoke revokes an agent and every key it holds, as one batch, and returns the
// agent as the write left it. Revoking an agent that is already revoked
// succeeds and keeps the earlier time, so the call is idempotent. Other agents
// of the same user are not touched.
func (s *Service) revoke(ctx context.Context, t target) result.Result[Row] {
	now := s.now().Unix()

	return s.writeOne(ctx, []atomic.Statement{
		{Query: revokeQuery, Args: []any{now, t.id, t.userID}},
		{Query: revokeKeysQuery, Args: []any{now, t.id, t.userID}},
	}, writeError(CodeRevokeFailed, CodeRevokeRejected), CodeRevokeRejected)
}

// run runs statements as one batch and returns one result per statement. A
// batch that returns anything else is the platform misreporting, which is a
// defect on our side, reported under rejected. classify turns a failed batch
// into the caller's classified error.
func (s *Service) run(
	ctx context.Context, statements []atomic.Statement, classify func(error) error, rejected string,
) result.Result[[]atomic.Result] {
	return result.Of(s.batch(ctx, statements...)).
		MapErr(classify).
		Check(func(results []atomic.Result) error {
			if len(results) != len(statements) {
				return apierr.Wrap(errBatchResults, apierr.Internal, rejected, "internal error")
			}

			return nil
		})
}

// writeOne runs statements as one batch, the first of which returns the agent
// it was aimed at, and reads that row. No row is a missing agent (404): every
// statement matches by owner as well as id, so an agent of another user is one
// too.
func (s *Service) writeOne(
	ctx context.Context, statements []atomic.Statement, classify func(error) error, rejected string,
) result.Result[Row] {
	return s.run(ctx, statements, classify, rejected).
		Then(func(results []atomic.Result) (Row, error) { return returnedRow(results[0].Rows, rejected) })
}

// returnedRow reads the one agent row a statement returned. None is a missing
// agent (404). More than one, or a row that is not an agent, is the platform
// returning something the statement cannot produce, which is a defect on our
// side, reported under rejected.
func returnedRow(rows [][]any, rejected string) (Row, error) {
	if len(rows) == 0 {
		return Row{}, notFound()
	}

	if len(rows) != 1 {
		return Row{}, apierr.Wrap(errBatchResults, apierr.Internal, rejected, "internal error")
	}

	row, err := rowOfValues(rows[0])
	if err != nil {
		return Row{}, apierr.Wrap(err, apierr.Internal, rejected, "internal error")
	}

	return row, nil
}

// errBatchResults is the cause of a batch that did not return what the
// statements promised.
var errBatchResults = errors.New("batch returned the wrong number of results")

// writeError returns the classifier for a failed rename or revoke. Neither
// inserts or sets a constrained column to anything the code has not checked, so
// any constraint failure is a defect on our side (500 under its own code);
// anything else is the database being unavailable (503).
func writeError(failed, rejected string) func(error) error {
	return func(err error) error {
		if errors.Is(err, atomic.ErrRejected) || errors.Is(err, atomic.ErrConflict) {
			return apierr.Wrap(err, apierr.Internal, rejected, "internal error")
		}

		return apierr.Wrap(err, apierr.Unavailable, failed, "agents are temporarily unavailable")
	}
}
