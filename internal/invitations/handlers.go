package invitations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

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
	CodeNotConfigured    = "invitations_not_configured"
	CodeForbidden        = "invitations_forbidden"
	CodeListFailed       = "invitation_list_failed"
	CodeLookupFailed     = "invitation_lookup_failed"
	CodeCreateFailed     = "invitation_create_failed"
	CodeCreateRejected   = "invitation_create_rejected"
	CodeCodeFailed       = "invitation_code_failed"
	CodeUpdateFailed     = "invitation_update_failed"
	CodeUpdateRejected   = "invitation_update_rejected"
	CodeRevokeFailed     = "invitation_revoke_failed"
	CodeRevokeRejected   = "invitation_revoke_rejected"
	CodeNotFound         = "invitation_not_found"
	CodeInvalidID        = "invalid_invitation_id"
	CodeInvalidType      = "invalid_invitation_type"
	CodeInvalidNum       = "invalid_num_invites"
	CodeInvalidLabel     = "invalid_label"
	CodeInvalidExpiry    = "invalid_expires_at"
	CodeRevoked          = "invitation_revoked"
	CodeBelowUses        = "num_invites_below_uses"
	CodeMissingNumInvite = "missing_num_invites"
)

// PathWildcards returns the {name} wildcards of ItemPath, for
// httpapi.ServeMethods.
func PathWildcards() []string { return []string{"id"} }

// Paths. The collection takes GET and POST; one invitation takes PATCH and
// DELETE. The id is a path wildcard, which TinyGo's mux matches the same way
// as Go's (a test pins this in e2e).
const (
	CollectionPath = "/api/invitation"
	ItemPath       = "/api/invitation/{id}"
)

// canonicalUUIDLen is the length of a UUID in 8-4-4-4-12 form.
const canonicalUUIDLen = 36

func notConfigured(cause error) error {
	return fail(cause, apierr.Unavailable, CodeNotConfigured, "invitations are not available")
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

// requireStore refuses when there is no database to read from.
func (s *Service) requireStore() error {
	if s.reader == nil {
		return notConfigured(errNoStore)
	}

	return nil
}

// requireBatch refuses when there is no way to write.
func (s *Service) requireBatch() error {
	if s.batch == nil {
		return notConfigured(errNoStore)
	}

	return nil
}

// requireAdmin refuses a principal that is not an admin.
func requireAdmin(principal session.Principal) error {
	if principal.Role != registration.RoleAdmin {
		return fail(nil, apierr.Forbidden, CodeForbidden, "administrator access is required")
	}

	return nil
}

// Routes are the handlers of the two paths, each by method, ready for
// httpapi.ServeMethods.
type Routes struct {
	// Collection is CollectionPath: GET lists, POST creates.
	Collection map[string]httpapi.Handler
	// Item is ItemPath: PATCH updates, DELETE revokes.
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
			http.MethodPatch:  s.updateHandler(getenv),
			http.MethodDelete: s.revokeHandler(getenv),
		},
	}
}

// ListResponse is the body of GET /api/invitation.
type ListResponse struct {
	Invitations []Invitation `json:"invitations"`
}

func (s *Service) listHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return s.admin(req.Context, getenv, req).
			Then(func(session.Principal) ([]Row, error) { return s.readAll(req.Context) }).
			Map(s.presentAll).
			Map(func(out ListResponse) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

// readAll reads every invitation.
func (s *Service) readAll(ctx context.Context) ([]Row, error) {
	rows, err := s.reader.List(ctx)

	return rows, apierr.Wrap(err, apierr.Unavailable, CodeListFailed, "invitations are temporarily unavailable")
}

// presentAll is the client's view of rows, as of now.
func (s *Service) presentAll(rows []Row) ListResponse {
	now := s.now()
	out := ListResponse{Invitations: make([]Invitation, 0, len(rows))}

	for _, row := range rows {
		out.Invitations = append(out.Invitations, present(row, StatusOf(row, now)))
	}

	return out
}

// present is the client's view of row.
func present(row Row, status Status) Invitation {
	return Invitation{
		ID: row.ID, Type: row.Type, Label: row.Label,
		NumInvites: row.NumInvites, Uses: row.Uses, Status: status,
		ExpiresAt: row.ExpiresAt, RevokedAt: row.RevokedAt, CreatedBy: row.CreatedBy,
		CreatedAt: row.CreatedAt,
	}
}

// CreateRequest is the body of POST /api/invitation.
type CreateRequest struct {
	// Type is what the invitation grants. See CreatableTypes.
	Type string `json:"type"`
	// NumInvites is how many accounts it may create.
	NumInvites int64 `json:"numInvites"`
	// Label is a note for admins. Optional.
	Label string `json:"label"`
	// ExpiresAt is when it stops working, in Unix seconds. Optional.
	ExpiresAt *int64 `json:"expiresAt"`
}

// CreateResponse is the body of a created invitation. Code is the only time it
// is ever returned.
type CreateResponse struct {
	Invitation

	// Code is what to hand to the invitee. It is not stored, and cannot be
	// shown again: a lost code is revoked and replaced.
	Code string `json:"code"`
}

func (s *Service) createHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		// Validation comes first: it learns nothing about the store, and a
		// malformed request is refused the same way for everyone.
		return s.validateCreate(httpapi.Decode[CreateRequest](req)).
			Then(func(in CreateRequest) (creation, error) {
				return s.writer(req.Context, getenv, req).
					Map(func(principal session.Principal) creation { return creation{principal: principal, in: in} }).
					Get()
			}).
			Then(func(c creation) (CreateResponse, error) { return s.create(req.Context, c).Get() }).
			Map(func(out CreateResponse) httpapi.Response { return httpapi.JSON(http.StatusCreated, out) })
	}
}

// creation is a validated create request and the admin making it.
type creation struct {
	principal session.Principal
	in        CreateRequest
}

// writer authenticates an admin and checks that there is a way to write.
func (s *Service) writer(
	ctx context.Context, getenv func(string) string, req httpapi.Request,
) result.Result[session.Principal] {
	return s.admin(ctx, getenv, req).
		Check(func(session.Principal) error { return s.requireBatch() })
}

// validateCreate runs the checks that refuse a request no state of the store
// could make valid. They run before authentication, which is safe: they learn
// nothing about the store and reveal nothing about the deployment.
func (s *Service) validateCreate(in result.Result[CreateRequest]) result.Result[CreateRequest] {
	return in.
		Check(s.validateType).
		Check(func(in CreateRequest) error { return validateNumInvites(in.NumInvites) }).
		Check(validateLabel).
		Check(s.validateExpiry)
}

// validateType requires a type that can be created. First run is named in its
// refusal, because it is the one type an admin might reasonably expect here.
func (s *Service) validateType(in CreateRequest) error {
	if _, ok := s.creatable[in.Type]; ok {
		return nil
	}

	if in.Type == firstRunType {
		return badRequest(CodeInvalidType, "the first-run invitation is created by GET /api/first-run, not here")
	}

	return badRequest(CodeInvalidType, "invitation type is not supported")
}

func validateLabel(in CreateRequest) error {
	if utf8.RuneCountInString(in.Label) > MaxLabelChars {
		return badRequest(CodeInvalidLabel, "label is too long")
	}

	return nil
}

func (s *Service) validateExpiry(in CreateRequest) error {
	if in.ExpiresAt != nil && *in.ExpiresAt <= s.now().Unix() {
		return badRequest(CodeInvalidExpiry, "expiresAt must be in the future")
	}

	return nil
}

func validateNumInvites(n int64) error {
	if n < 1 || n > MaxNumInvites {
		return badRequest(CodeInvalidNum, fmt.Sprintf("numInvites must be between 1 and %d", MaxNumInvites))
	}

	return nil
}

// create mints a code, then writes the invitation holding only its hash.
func (s *Service) create(ctx context.Context, c creation) result.Result[CreateResponse] {
	return newCode(s.entropy).
		MapErr(func(err error) error {
			return apierr.Wrap(err, apierr.Internal, CodeCodeFailed, "internal error")
		}).
		Then(func(code string) (CreateResponse, error) {
			row := Row{
				ID: s.newID(), Type: c.in.Type, Label: c.in.Label, NumInvites: c.in.NumInvites, Uses: 0,
				ExpiresAt: c.in.ExpiresAt, RevokedAt: nil, CreatedBy: &c.principal.UserID, CreatedAt: s.now().Unix(),
			}

			_, err := s.batch(ctx, atomic.Statement{Query: insertQuery, Args: []any{
				row.ID, codeHash(code), row.Type, row.Label, row.NumInvites, nullable(row.ExpiresAt),
				c.principal.UserID, row.CreatedAt,
			}})

			return CreateResponse{Invitation: present(row, StatusOf(row, s.now())), Code: code},
				writeError(err, CodeCreateFailed, CodeCreateRejected)
		})
}

// nullable binds a nil pointer as SQL NULL and any other as its value.
func nullable(value *int64) any {
	if value == nil {
		return nil
	}

	return *value
}

// writeError classifies a failed write by why the database refused it, as the
// other services do: a conflict is the client's to resolve (409), a rejection
// is a defect on our side (500 under its own code), and anything else is the
// database being unavailable (503).
func writeError(err error, failed, rejected string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, atomic.ErrConflict):
		return apierr.Wrap(err, apierr.Conflict, failed, "the change conflicts with existing data")
	case errors.Is(err, atomic.ErrRejected):
		return apierr.Wrap(err, apierr.Internal, rejected, "internal error")
	default:
		return apierr.Wrap(err, apierr.Unavailable, failed, "invitations are temporarily unavailable")
	}
}

// UpdateRequest is the body of PATCH /api/invitation/{id}. It is a patch, so
// each field is optional, but at least one must be present.
type UpdateRequest struct {
	NumInvites *int64 `json:"numInvites"`
}

func (s *Service) updateHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return httpapi.Decode[UpdateRequest](req).
			Check(validateUpdate).
			Then(func(in UpdateRequest) (change, error) {
				return s.targeted(req.Context, getenv, req).
					Map(func(id string) change { return change{id: id, numInvites: *in.NumInvites} }).Get()
			}).
			Then(func(c change) (Invitation, error) { return s.update(req.Context, c).Get() }).
			Map(func(out Invitation) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

// change is a validated update: which invitation, and its new cap.
type change struct {
	id         string
	numInvites int64
}

// targeted authenticates an admin, checks that there is a way to write, and
// returns the id of the invitation the request is about.
func (s *Service) targeted(
	ctx context.Context, getenv func(string) string, req httpapi.Request,
) result.Result[string] {
	return s.writer(ctx, getenv, req).
		Then(func(session.Principal) (string, error) { return idOf(req) })
}

func validateUpdate(in UpdateRequest) error {
	if in.NumInvites == nil {
		return badRequest(CodeMissingNumInvite, "numInvites is required")
	}

	return validateNumInvites(*in.NumInvites)
}

// update changes the cap and returns the invitation as the write left it.
//
// The write is one statement that reports its own outcome: it returns the row
// it was aimed at, with whether the change applied (see updateNumInvitesQuery).
// D1 runs it as one transaction, so whether it applied, the row, and the count
// of accounts in that row are all the same instant. A registration or a
// revocation cannot land between the write and its explanation, so there is no
// second read and nothing to reconcile. No row returned means no such
// invitation.
func (s *Service) update(ctx context.Context, c change) result.Result[Invitation] {
	return s.run(ctx, atomic.Statement{
		Query: updateNumInvitesQuery, Args: []any{c.numInvites, c.numInvites, c.id},
	}, CodeUpdateFailed, CodeUpdateRejected).
		Map(func(one atomic.Result) [][]any { return one.Rows }).
		Then(decodeOutcome).
		Then(func(out outcome) (Row, error) { return out.row, out.refusal }).
		Map(s.presentNow)
}

// outcome is what the update statement returned: the row, and the refusal if it
// did not apply.
type outcome struct {
	row     Row
	refusal error
}

// decodeOutcome reads the update's returned rows. The first column of the row
// says whether the change applied; when it did not, the row says why, as of the
// same instant the write ran.
func decodeOutcome(rows [][]any) (outcome, error) {
	// No row is a missing invitation. Otherwise there must be exactly one, led
	// by the verdict; anything else is not what the statement can return.
	if len(rows) == 0 {
		return outcome{}, notFound()
	}

	if len(rows) != 1 || len(rows[0]) != rowColumns+1 {
		return outcome{}, apierr.Wrap(errBatchResults, apierr.Internal, CodeUpdateRejected, "internal error")
	}

	applied, ok := rows[0][0].(int64)
	if !ok {
		return outcome{}, apierr.Wrap(errRowShape, apierr.Internal, CodeUpdateRejected, "internal error")
	}

	row, err := returnedRow([][]any{rows[0][1:]}, CodeUpdateRejected)
	if err != nil {
		return outcome{}, err
	}

	if applied != 1 {
		return outcome{row: row, refusal: refused(row)}, nil
	}

	return outcome{row: row, refusal: nil}, nil
}

// returnedRow reads the one invitation row a statement returned. None is a
// missing invitation (404). More than one, or a row that is not an invitation,
// is the platform returning something the statement cannot produce, which is a
// defect on our side, reported under rejected.
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

// run runs one statement and returns its result, classifying a refusal under
// the given codes. A batch that did not return one result for the one statement
// is the platform misreporting, which is a defect on our side.
func (s *Service) run(
	ctx context.Context, stmt atomic.Statement, failed, rejected string,
) result.Result[atomic.Result] {
	results, err := s.batch(ctx, stmt)
	if err != nil {
		return result.Fail[atomic.Result](writeError(err, failed, rejected))
	}

	if len(results) != 1 {
		return result.Fail[atomic.Result](apierr.Wrap(errBatchResults, apierr.Internal, rejected, "internal error"))
	}

	return result.Ok(results[0])
}

// errBatchResults is the cause of a batch that did not return what the
// statement promised: one result per statement, with the rows it names.
var errBatchResults = errors.New("batch returned the wrong number of results")

// refused says why a conditional update did not apply, from the row as the
// statement returned it. The write's own test failed on that row, so exactly
// one of two things is true of it: the invitation was revoked, or it had
// created more accounts than the new cap allows. There is no third case to
// guess at, because the row and the verdict come from the same statement.
func refused(row Row) error {
	if row.RevokedAt != nil {
		return fail(nil, apierr.Conflict, CodeRevoked, "the invitation is revoked and cannot be changed")
	}

	return belowUses(row.Uses)
}

// presentNow is the client's view of row, as of now.
func (s *Service) presentNow(row Row) Invitation {
	return present(row, StatusOf(row, s.now()))
}

func notFound() error {
	return fail(nil, apierr.NotFound, CodeNotFound, "no such invitation")
}

// belowUses refuses a cap under the accounts the invitation has already
// created, and tells the client how many that is.
func belowUses(uses int64) error {
	failure := apierr.New(apierr.Conflict, CodeBelowUses,
		"numInvites is below the number of accounts this invitation has already created").
		WithData(map[string]int64{"uses": uses})

	return fail(failure, apierr.Conflict, CodeBelowUses, failure.Description)
}

// idOf reads the invitation id from the path. It is checked for shape before it
// reaches SQL, though it is only ever bound as a value.
func idOf(req httpapi.Request) (string, error) {
	id := req.PathValues["id"]

	if len(id) != canonicalUUIDLen || strings.Trim(id, "0123456789abcdef-") != "" {
		return "", badRequest(CodeInvalidID, "invitation id is not valid")
	}

	return id, nil
}

func (s *Service) revokeHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		return s.targeted(req.Context, getenv, req).
			Then(func(id string) (Invitation, error) { return s.revoke(req.Context, id).Get() }).
			Map(func(out Invitation) httpapi.Response { return httpapi.JSON(http.StatusOK, out) })
	}
}

// revoke revokes an invitation and returns it as the write left it. Revoking
// one that is already revoked succeeds and changes nothing, so the call is
// idempotent: the earlier revocation time is kept (see revokeQuery). The row
// comes from the write itself, so there is no read after it to disagree with it.
func (s *Service) revoke(ctx context.Context, id string) result.Result[Invitation] {
	return s.run(ctx, atomic.Statement{Query: revokeQuery, Args: []any{s.now().Unix(), id}},
		CodeRevokeFailed, CodeRevokeRejected).
		Then(func(one atomic.Result) (Row, error) { return returnedRow(one.Rows, CodeRevokeRejected) }).
		Map(s.presentNow)
}
