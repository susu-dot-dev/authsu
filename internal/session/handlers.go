package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Error codes. Each failing step has its own, so a log line or an alert names
// the step. They are stable: clients and dashboards may match on them.
const (
	CodeNotConfigured   = "session_not_configured"
	CodeUnauthenticated = "unauthenticated"
	CodeVerifyFailed    = "session_verify_failed"
	CodeLogoutFailed    = "session_logout_failed"
)

// Config is what the handlers need from the deployment: the issuer, derived from
// the API origin.
type Config struct {
	Issuer Issuer
}

// LoadConfig reads and validates configuration for a request. Missing
// configuration is the deployment being broken, not the request being wrong, so
// it is Unavailable, with a code that names it for the log.
func LoadConfig(getenv func(string) string) (Config, error) {
	api, _, err := deploy.Origins(getenv)
	if err != nil {
		return Config{}, notConfigured(err)
	}

	return Config{Issuer: IssuerFor(api)}, nil
}

// Service handles the requests that act on an existing session.
type Service struct {
	reader Reader
	batch  atomic.Batch
	now    func() time.Time
}

// Deps are the service's collaborators.
type Deps struct {
	Reader Reader
	// Batch performs the atomic write logout ends with. Nil disables it.
	Batch atomic.Batch
	// Now is the clock.
	Now func() time.Time
}

// NewService returns a Service.
func NewService(deps Deps) *Service {
	return &Service{
		reader: deps.Reader,
		batch:  deps.Batch,
		now:    deps.Now,
	}
}

// Cookie builds the session cookie for key. It is HttpOnly (page script cannot
// read it), Secure (not sent over plain HTTP), Path=/ with no Domain (which the
// __Host- prefix requires, and which keeps it to this host), and SameSite=Lax:
// a session survives a user following a link to the site, and is withheld from
// cross-site subrequests and POSTs, which is also what stops another site from
// triggering a logout. The UI may be on another origin than this API, but it
// must be on the same site (susu.dev and auth.susu.dev; localhost on two
// ports), so the UI's credentialed fetches still carry the cookie. SameSite
// compares registrable domains, not origins, which is why Lax suffices and
// None is not needed.
func Cookie(key Key) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    key.JWT,
		Path:     "/",
		Expires:  key.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie expires the session cookie in the browser.
func ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// token returns the session cookie's value, if the request has one.
func token(req httpapi.Request) (string, bool) {
	for _, cookie := range req.Cookies {
		if cookie.Name == CookieName && cookie.Value != "" {
			return cookie.Value, true
		}
	}

	return "", false
}

var errNoCookie = errors.New("no session cookie")

var errNoStore = errors.New("no database is configured")

func notConfigured(cause error) error {
	return fail(cause, apierr.Unavailable, CodeNotConfigured, "sessions are not available")
}

// unauthenticated is the one answer to every token that is not a valid
// session: no cookie, malformed, unknown, revoked, expired, wrong audience. The
// caller learns nothing about which.
func unauthenticated(cause error) error {
	return fail(cause, apierr.Unauthorized, CodeUnauthenticated, "not signed in")
}

// verifyError classifies a failed verification: a verdict on the token is 401,
// and a failure to read the store is 503, which says nothing about the token.
func verifyError(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return fail(err, apierr.Unavailable, CodeVerifyFailed, "sessions are temporarily unavailable")
	}

	return unauthenticated(err)
}

// fail builds a classified error, keeping the innermost classification.
func fail(cause error, kind apierr.Kind, code, description string) error {
	return apierr.Wrap(cause, kind, code, description)
}

// WhoAmIResponse is the body of GET /api/session. ExpiresAt is also when the
// user has to sign in again: a session is never extended.
type WhoAmIResponse struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
	// ExpiresAt is when this session ends, in Unix seconds.
	ExpiresAt int64 `json:"expiresAt"`
}

// WhoAmIHandler returns GET /api/session: who the session cookie speaks for. It
// reads and never writes.
func (s *Service) WhoAmIHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		principal, err := s.Authenticate(req.Context, getenv, req)
		if err != nil {
			return result.Fail[httpapi.Response](err)
		}

		return result.Ok(httpapi.JSON(http.StatusOK, WhoAmIResponse{
			UserID:    principal.UserID,
			Role:      principal.Role,
			ExpiresAt: principal.ExpiresAt.Unix(),
		}))
	}
}

// LogoutHandler returns POST /api/logout: revoke the presented session now and
// clear the cookie. It is idempotent in effect: a session that is already gone
// is a 401 like any other request without one, and the cookie is cleared by the
// browser regardless.
func (s *Service) LogoutHandler(getenv func(string) string) httpapi.Handler {
	return func(req httpapi.Request) result.Result[httpapi.Response] {
		err := s.logout(req.Context, getenv, req)
		if err != nil {
			return result.Fail[httpapi.Response](err)
		}

		return result.Ok(httpapi.Response{Status: http.StatusNoContent, Body: nil}.WithCookies(ClearCookie()))
	}
}

// Authenticate verifies the request's session cookie and returns who it speaks
// for. It is what every authenticated route starts with. A request without a
// valid session is 401 unauthenticated (whatever was wrong with the token), and
// a deployment that cannot verify sessions is 503; the error is already
// classified, so a handler returns it as is.
func (s *Service) Authenticate(
	ctx context.Context, getenv func(string) string, req httpapi.Request,
) (Principal, error) {
	cfg, err := LoadConfig(getenv)
	if err != nil {
		return Principal{}, err
	}

	if s.reader == nil {
		return Principal{}, notConfigured(errNoStore)
	}

	raw, ok := token(req)
	if !ok {
		return Principal{}, unauthenticated(errNoCookie)
	}

	principal, err := NewVerifier(s.reader, cfg.Issuer, s.now).Verify(ctx, raw)
	if err != nil {
		return Principal{}, verifyError(err)
	}

	return principal, nil
}

func (s *Service) logout(ctx context.Context, getenv func(string) string, req httpapi.Request) error {
	principal, err := s.Authenticate(ctx, getenv, req)
	if err != nil {
		return err
	}

	if s.batch == nil {
		return notConfigured(errNoStore)
	}

	at := s.now().Unix()

	results, err := s.batch(ctx, atomic.Statement{Query: logoutQuery, Args: []any{at, principal.KeyID}})
	if err != nil {
		return fail(fmt.Errorf("revoke session: %w", err), apierr.Unavailable, CodeLogoutFailed,
			"sessions are temporarily unavailable")
	}

	// The write is conditional on the key not being revoked already, and a
	// write that matches nothing is not an error. Authenticate saw an active
	// key, so no change means another request revoked it in between: the
	// session is gone, which is what a request without one is told.
	if len(results) != 1 {
		return fail(errBatchResults, apierr.Internal, CodeLogoutFailed, "internal error")
	}

	if results[0].Changes == 0 {
		return unauthenticated(errRevokedFirst)
	}

	return nil
}

// errBatchResults is the cause of a batch that did not return one result for
// its one statement, which the platform's Batch promises it does.
var errBatchResults = errors.New("batch returned the wrong number of results")

// errRevokedFirst is the cause of a logout that found its session already
// revoked by a concurrent request.
var errRevokedFirst = errors.New("session was revoked by another request")
