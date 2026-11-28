package users

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Error codes of this package. They are stable: clients and dashboards may
// match on them. Failures of the database have the store's codes
// (store.CodeUserListFailed and its siblings), and a malformed id has
// input.CodeInvalidID.
const (
	// CodeNotFound means there is no account with the id.
	CodeNotFound = "user_not_found"
	// CodeLastAdmin means the account is the last active administrator.
	CodeLastAdmin = "user_last_admin"
	// CodeProfileInvalid means a stored profile is not a JSON object. The
	// schema does not constrain it, and registration writes an object, so this
	// is a defect in the stored data. It is logged under this code with the
	// account named, and the account is served with an empty profile: the
	// request does not fail.
	CodeProfileInvalid = "user_profile_invalid"
)

// errProfile is the cause, in the log, of a stored profile that is not a JSON
// object.
var errProfile = errors.New("profile is not a JSON object")

// Status is where an account stands. It is derived from the row, never stored.
type Status string

// Statuses.
const (
	// StatusActive means the account can log in.
	StatusActive Status = "active"
	// StatusRevoked means it was revoked, which is final.
	StatusRevoked Status = "revoked"
)

// User is one account as an admin sees it. It never carries the WebAuthn user
// handle, which is an identifier for authenticators, not for people: the store
// does not select it, so there is nothing here to leak.
type User struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	// InvitationID is the invitation the account was created from.
	InvitationID string `json:"invitationId"`
	// Profile is users.profile as stored: a JSON object, such as the name given
	// at registration. An account whose stored profile is not one is served
	// with {} (see present).
	Profile json.RawMessage `json:"profile"`
	Status  Status          `json:"status"`
	// RevokedAt is absent when the account is not revoked.
	RevokedAt *int64 `json:"revokedAt,omitempty"`
	// CreatedAt is in Unix seconds.
	CreatedAt int64 `json:"createdAt"`
}

// ListResponse is the body of GET /api/user: one page, newest first.
type ListResponse struct {
	Users []User `json:"users"`

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

// handlers are the route bodies, with what they depend on.
type handlers struct {
	store Store
	now   func() time.Time
	log   httpapi.Logger
}

// list answers GET /api/user.
func (h handlers) list(call *auth.Call) result.Result[httpapi.Response] {
	return parsePage(call.Request.Query).
		Then(func(p page) (store.UserPage, error) {
			return h.store.ListUsers(call.Request.Context, p.cursor, p.limit)
		}).
		Map(func(stored store.UserPage) ListResponse { return h.presentAll(call.Request, stored) }).
		Map(ok)
}

// self answers GET /api/user/me: the caller's own account, which the boundary
// has just resolved, read again with the same store call as any other so it is
// shown exactly as an administrator sees an account, whatever has changed
// since. The caller is an account the boundary found active, so an account that
// is not found is one that was removed in between, and is told the same as for
// any other.
func (h handlers) self(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(input.ParseID(call.Principal.UserID)).
		Then(func(id input.ID) (store.User, error) { return h.store.GetUser(call.Request.Context, id) }).
		MapErr(outcome).
		Map(func(stored store.User) User { return h.present(call.Request, stored) }).
		Map(ok)
}

// get answers GET /api/user/{id}.
func (h handlers) get(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(h.store.GetUser(call.Request.Context, call.ID())).
		MapErr(outcome).
		Map(func(stored store.User) User { return h.present(call.Request, stored) }).
		Map(ok)
}

// revoke answers DELETE /api/user/{id}. Revoking an account that is already
// revoked succeeds and reports the earlier time, and so does an admin revoking
// themself while another active admin remains. The caller is the admin: the
// route's access is the role, and the store checks it again in the write.
func (h handlers) revoke(call *auth.Call) result.Result[httpapi.Response] {
	return result.Of(h.store.RevokeUser(
		call.Request.Context, call.ID(), call.Principal.UserID, auth.RoleAdmin, h.now())).
		MapErr(outcome).
		Map(func(stored store.User) User { return h.present(call.Request, stored) }).
		Map(ok)
}

// ok is the 200 response carrying body.
func ok[T any](body T) httpapi.Response { return httpapi.JSON(http.StatusOK, body) }

// outcome maps the store's business outcomes to client errors. Anything else
// is a failure the store already classified, and is returned as it is.
func outcome(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return refuse(apierr.NotFound, CodeNotFound, "no such user", err)
	case errors.Is(err, store.ErrAccountRevoked):
		// The caller was revoked after the request was authenticated.
		return auth.Unauthenticated(err) //nolint:wrapcheck // the boundary's own classified 401, with err as its cause
	case errors.Is(err, store.ErrLastAdmin):
		return refuse(apierr.Conflict, CodeLastAdmin, "the last active administrator cannot be revoked", err)
	default:
		return err
	}
}

// refuse is the classified error for a store outcome or a defect, with cause
// kept for the log.
func refuse(kind apierr.Kind, code, description string, cause error) *apierr.Error {
	return apierr.New(kind, code, description).WithCause(cause)
}

// presentAll is the client's view of a page of accounts. The list is an empty
// array, never null, when there are none.
func (h handlers) presentAll(req httpapi.Request, stored store.UserPage) ListResponse {
	out := ListResponse{Users: make([]User, 0, len(stored.Users)), Next: stored.Next}

	for _, user := range stored.Users {
		out.Users = append(out.Users, h.present(req, user))
	}

	return out
}

// present is the client's view of an account. The profile is sent as stored,
// which json would otherwise refuse only when marshalling the response, as an
// anonymous "marshal_failed" with nothing to say which row it was. A profile
// that is not a JSON object is logged, naming the account, and replaced by an
// empty object: the account is still listed and a revocation that was applied
// is still reported as done.
func (h handlers) present(req httpapi.Request, stored store.User) User {
	profile := json.RawMessage(stored.Profile)

	if !isObject(stored.Profile) {
		h.log(req, refuse(apierr.Internal, CodeProfileInvalid, "stored profile is not a JSON object",
			fmt.Errorf("%w: account %s", errProfile, stored.ID)))

		profile = json.RawMessage(emptyProfile)
	}

	status := StatusActive
	if stored.RevokedAt != nil {
		status = StatusRevoked
	}

	return User{
		ID: stored.ID, Role: stored.Role, InvitationID: stored.InvitationID,
		Profile: profile, Status: status,
		RevokedAt: stored.RevokedAt, CreatedAt: stored.CreatedAt,
	}
}

// emptyProfile is what an account whose stored profile is unusable is served
// with.
const emptyProfile = `{}`

// isObject reports whether text is one valid JSON object in valid UTF-8, which
// is what makes it safe to write into a response as it is: json.Valid alone
// accepts invalid UTF-8 inside a string.
func isObject(text string) bool {
	return utf8.ValidString(text) &&
		strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "{") &&
		json.Valid([]byte(text))
}
