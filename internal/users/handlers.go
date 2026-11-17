package users

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// Error codes. Each failing step has its own, so a log line or an alert names
// the step. They are stable: clients and dashboards may match on them.
const (
	CodeNotConfigured  = "users_not_configured"
	CodeForbidden      = "users_forbidden"
	CodeListFailed     = "user_list_failed"
	CodeLookupFailed   = "user_lookup_failed"
	CodeRevokeFailed   = "user_revoke_failed"
	CodeRevokeRejected = "user_revoke_rejected"
	CodeNotFound       = "user_not_found"
	CodeInvalidID      = "invalid_user_id"
	CodeLastAdmin      = "user_last_admin"
)

// PathWildcards returns the {name} wildcards of ItemPath, for
// httpapi.ServeMethods.
func PathWildcards() []string { return []string{"id"} }

// Paths. The collection takes GET; one account takes GET and DELETE.
const (
	CollectionPath = "/api/user"
	ItemPath       = "/api/user/{id}"
)

// canonicalUUIDLen is the length of a UUID in 8-4-4-4-12 form.
const canonicalUUIDLen = 36

func notConfigured(cause error) error {
	return apierr.Wrap(cause, apierr.Unavailable, CodeNotConfigured, "user management is not available")
}

// refusal builds a classified error with nothing underneath it.
func refusal(kind apierr.Kind, code, description string) error {
	return apierr.Wrap(errRefused, kind, code, description)
}

// errRefused is the cause of a failure that has nothing underneath it, so Wrap
// (which is nil-in, nil-out) still produces an error.
var errRefused = errors.New("refused")

// admin authenticates the request and requires an admin. The account's role is
// read from the database on every request (see session.Verifier), so a role
// removed since login is refused here.
//
// A missing store is refused first, without authenticating: there is nothing to
// authorise against.
func (s *Service) admin(
	ctx context.Context, getenv func(string) string, req httpapi.Request,
) result.Result[session.Principal] {
	return result.Ok(req).
		Check(func(httpapi.Request) error { return s.requireStore() }).
		Then(func(req httpapi.Request) (session.Principal, error) {
			// Authenticate's errors are already classified (401, or 503 when
			// sessions cannot be verified); Wrap keeps that.
			principal, err := s.sessions.Authenticate(ctx, getenv, req)

			return principal, apierr.Wrap(err, apierr.Unauthorized, session.CodeUnauthenticated, "not signed in")
		}).
		Check(requireAdmin)
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

// requireAdmin refuses a principal that is not an admin.
func requireAdmin(principal session.Principal) error {
	if principal.Role != registration.RoleAdmin {
		return refusal(apierr.Forbidden, CodeForbidden, "administrator access is required")
	}

	return nil
}

// Routes are the handlers of the two paths, each by method, ready for
// httpapi.ServeMethods.
type Routes struct {
	// Collection is CollectionPath: GET lists.
	Collection map[string]httpapi.Handler
	// Item is ItemPath: GET reads, DELETE revokes.
	Item map[string]httpapi.Handler
}

// Handlers returns the handlers for both paths.
func (s *Service) Handlers(getenv func(string) string) Routes {
	return Routes{
		Collection: map[string]httpapi.Handler{
			http.MethodGet: s.listHandler(getenv),
		},
		Item: map[string]httpapi.Handler{
			http.MethodGet:    s.getHandler(getenv),
			http.MethodDelete: s.revokeHandler(getenv),
		},
	}
}

// ListResponse is the body of GET /api/user.
type ListResponse struct {
	Users []User `json:"users"`
}

func (s *Service) listHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return s.admin(req.Context, getenv, req).
			Then(func(session.Principal) ([]Row, error) { return s.readAll(req.Context) }).
			Map(presentAll).
			Map(func(out ListResponse) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

func (s *Service) readAll(ctx context.Context) ([]Row, error) {
	rows, err := s.reader.List(ctx)

	return rows, apierr.Wrap(err, apierr.Unavailable, CodeListFailed, "users are temporarily unavailable")
}

func presentAll(rows []Row) ListResponse {
	out := ListResponse{Users: make([]User, 0, len(rows))}

	for _, row := range rows {
		out.Users = append(out.Users, present(row))
	}

	return out
}

// present is the client's view of row.
func present(row Row) User {
	return User{
		ID: row.ID, Role: row.Role, InvitationID: row.InvitationID, Profile: json.RawMessage(row.Profile),
		Status: StatusOf(row), RevokedAt: row.RevokedAt, CreatedAt: row.CreatedAt,
	}
}

func (s *Service) getHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return s.admin(req.Context, getenv, req).
			Then(func(session.Principal) (string, error) { return idOf(req) }).
			Then(func(id string) (Row, error) { return s.readOne(req.Context, id) }).
			Map(present).
			Map(func(out User) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

func (s *Service) readOne(ctx context.Context, id string) (Row, error) {
	row, err := s.reader.Get(ctx, id)

	switch {
	case err == nil:
		return row, nil
	case errors.Is(err, ErrNotFound):
		return Row{}, notFound()
	default:
		return Row{}, apierr.Wrap(err, apierr.Unavailable, CodeLookupFailed, "users are temporarily unavailable")
	}
}

func notFound() error {
	return refusal(apierr.NotFound, CodeNotFound, "no such user")
}

// idOf reads the account id from the path. It is checked for shape before it
// reaches SQL, though it is only ever bound as a value.
func idOf(req httpapi.Request) (string, error) {
	id := req.PathValues["id"]

	if len(id) != canonicalUUIDLen || strings.Trim(id, "0123456789abcdef-") != "" {
		return "", refusal(apierr.BadRequest, CodeInvalidID, "user id is not valid")
	}

	return id, nil
}

func (s *Service) revokeHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return s.admin(req.Context, getenv, req).
			Check(func(session.Principal) error { return s.requireBatch() }).
			Then(func(session.Principal) (string, error) { return idOf(req) }).
			Then(func(id string) (Row, error) { return s.revoke(req.Context, id) }).
			Map(present).
			Map(func(out User) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

// revoke revokes an account and every key it holds, as one batch, and returns
// the account as the write left it. Revoking an account that is already
// revoked succeeds and keeps the earlier time, so the call is idempotent. The
// last active admin is refused with 409; see revokeQuery for why that check is
// inside the write.
func (s *Service) revoke(ctx context.Context, id string) (Row, error) {
	now := s.now().Unix()

	statements := []atomic.Statement{
		{Query: revokeQuery, Args: []any{now, id, registration.RoleAdmin}},
		{Query: revokeKeysQuery, Args: []any{now, id}},
	}

	results, err := s.batch(ctx, statements...)
	if err != nil {
		return Row{}, writeError(err)
	}

	// One result per statement; anything else is the platform misreporting.
	if len(results) != len(statements) {
		return Row{}, rejected(errBatchResults)
	}

	row, err := returnedRow(results[0].Rows)
	if err != nil {
		return Row{}, err
	}

	if row.RevokedAt == nil {
		return Row{}, refusal(apierr.Conflict, CodeLastAdmin, "the last active administrator cannot be revoked")
	}

	return row, nil
}

// returnedRow reads the one account row the revoke returned. None is a missing
// account (404). More than one, or a row that is not an account, is the
// platform returning something the statement cannot produce.
func returnedRow(rows [][]any) (Row, error) {
	if len(rows) == 0 {
		return Row{}, notFound()
	}

	if len(rows) != 1 {
		return Row{}, rejected(errBatchResults)
	}

	row, err := rowOfValues(rows[0])
	if err != nil {
		return Row{}, rejected(err)
	}

	return row, nil
}

// rejected is a defect on our side: 500 under its own code.
func rejected(cause error) error {
	return apierr.Wrap(cause, apierr.Internal, CodeRevokeRejected, "internal error")
}

// errBatchResults is the cause of a batch that did not return what the
// statements promised.
var errBatchResults = errors.New("batch returned the wrong number of results")

// writeError classifies a failed revoke. Neither statement inserts or sets a
// constrained column to anything but a time, so any constraint failure is a
// defect on our side (500); anything else is the database being unavailable
// (503).
func writeError(err error) error {
	if errors.Is(err, atomic.ErrRejected) || errors.Is(err, atomic.ErrConflict) {
		return rejected(err)
	}

	return apierr.Wrap(err, apierr.Unavailable, CodeRevokeFailed, "users are temporarily unavailable")
}
