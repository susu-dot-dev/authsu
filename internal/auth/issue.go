package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// The kinds of credential a request can present. They are the values the store
// records for a secret's kind, so a credential is read under the kind it was
// written with.
const (
	// KindSession is a login session, carried in a cookie.
	KindSession = store.KindSession
	// KindAPIKey is a key presented as a bearer token, by a user's software or
	// by an agent.
	KindAPIKey = store.KindAPIKey
)

// Lifetimes of the credentials auth issues. They are policy, set here and not
// stored: a secret's expiry is fixed when it is issued and never extended.
const (
	// SessionLifetime is how long a session lasts. A session is not renewed:
	// the lifetime is the whole of it, and it is what bounds how long a stolen
	// cookie is good for.
	SessionLifetime = 14 * 24 * time.Hour

	// AgentKeyLifetime is how long an agent's key lasts.
	AgentKeyLifetime = 90 * 24 * time.Hour

	// MaxAgentKeyLifetime is the longest an agent's key may live. An agent's
	// credential is the one most likely to sit in software, so it is the one
	// most worth renewing. IssueAPIKey refuses anything longer.
	MaxAgentKeyLifetime = 90 * 24 * time.Hour

	// MaxUserKeyLifetime is the longest a user may give one of their own keys:
	// a year. IssueUserAPIKey refuses anything longer, so the API's parser
	// (input.ParseKeyLifetime) and this limit are two checks of one rule.
	MaxUserKeyLifetime = 365 * 24 * time.Hour

	// CodeLifetime is how long an OAuth authorization code can be exchanged.
	// It is single use and the client is waiting for it, so it is short.
	CodeLifetime = 60 * time.Second

	// RefreshTokenLifetime is how long an OAuth refresh token lasts, counted
	// from the exchange or refresh that issued it. Each exchange issues a new
	// token and so a new lifetime: a grant that a client keeps using does not
	// lapse, and one it abandons does.
	RefreshTokenLifetime = 30 * 24 * time.Hour

	// AccessTokenLifetime is how long an OAuth access token lasts. A resource
	// server asks authsu about every request, so this bounds only how long a
	// token that was never revoked stays usable.
	AccessTokenLifetime = 15 * time.Minute
)

// CookieName is the session cookie. The __Host- prefix makes browsers refuse
// the cookie unless it is Secure, has Path=/ and has no Domain, so a sibling
// subdomain cannot set or shadow it.
const CookieName = "__Host-session"

// ErrKeyLifetime is why IssueAPIKey or IssueUserAPIKey refused a lifetime: it is
// not positive or is longer than the issuer's maximum. It is a defect of the
// caller, never of a client's input, which is parsed before it gets this far.
var ErrKeyLifetime = errors.New("API key lifetime is out of range")

// Issued is a secret that has just been issued: what is shown to the client
// once, and what is stored.
type Issued struct {
	// ID is the secret's identifier, from the caller's id source. It is how the
	// secret is listed, audited and revoked, and it is not secret. It is empty
	// for a secret that is stored under an id it already has
	// (IssueRefreshToken).
	ID string
	// Token is the value the client presents ("susu_<tag>_..."). It is shown
	// once and never stored.
	Token string
	// Hash is secret.Hash(Token), the 32 bytes that are stored.
	Hash []byte
	// ExpiresAt is when the secret stops being active.
	ExpiresAt time.Time
}

// IssueSession issues a session token that expires SessionLifetime after now.
// Randomness comes from r and the id from newID, so tests inject both; a reader
// that fails or ends early is an error, which the caller reports as an
// internal failure. Nothing is stored: the caller writes the Hash and the ID
// (store.CreateSession).
func IssueSession(r io.Reader, newID func() string, now time.Time) (Issued, error) {
	return issue(r, newID, secret.TagSession, now.Add(SessionLifetime)).Get() //nolint:wrapcheck // issue wraps its error
}

// IssueAPIKey issues an API key token for an agent that expires lifetime after
// now. It refuses a lifetime that is not positive or is longer than
// MaxAgentKeyLifetime with ErrKeyLifetime. Randomness comes from r and the id
// from newID, as for IssueSession. Nothing is stored: the caller writes the Hash
// and the ID.
func IssueAPIKey(r io.Reader, newID func() string, now time.Time, lifetime time.Duration) (Issued, error) {
	return issueKey(r, newID, now, lifetime, MaxAgentKeyLifetime)
}

// IssueUserAPIKey is IssueAPIKey for a key that belongs to a user and not to an
// agent: it allows a lifetime up to MaxUserKeyLifetime. It is a separate issuer,
// and not a parameter of the agent's, so that the code that issues an agent's
// key cannot be handed a longer ceiling by mistake.
func IssueUserAPIKey(r io.Reader, newID func() string, now time.Time, lifetime time.Duration) (Issued, error) {
	return issueKey(r, newID, now, lifetime, MaxUserKeyLifetime)
}

// issueKey issues an API key token that lives lifetime, which must be positive
// and at most longest.
func issueKey(r io.Reader, newID func() string, now time.Time, lifetime, longest time.Duration) (Issued, error) {
	if lifetime <= 0 || lifetime > longest {
		return Issued{}, fmt.Errorf("%w: %v is not in (0, %v]", ErrKeyLifetime, lifetime, longest)
	}

	return issue(r, newID, secret.TagAPIKey, now.Add(lifetime)).Get() //nolint:wrapcheck // issue wraps its error
}

// IssueGrantCode issues the authorization code of a new OAuth grant, which
// expires CodeLifetime after now. Randomness and the id come from r and newID
// as for IssueSession; the id is the grant's, and it stays the grant's for its
// whole life: the refresh token that replaces the code is stored under it.
// Nothing is stored: the caller writes the Hash and the ID.
func IssueGrantCode(r io.Reader, newID func() string, now time.Time) (Issued, error) {
	return issueToken(r, newID, secret.TagOAuthCode, now.Add(CodeLifetime))
}

// IssueRefreshToken issues the refresh token that replaces an OAuth grant's
// code (and its previous refresh token), which expires RefreshTokenLifetime
// after now. The grant keeps the id it was created with, and the caller
// rotates the Hash under it, so no id is generated and Issued.ID is empty.
// Randomness comes from r. Nothing is stored.
func IssueRefreshToken(r io.Reader, now time.Time) (Issued, error) {
	return issueToken(r, noID, secret.TagOAuthRefresh, now.Add(RefreshTokenLifetime))
}

// IssueAccessToken issues an OAuth access token that expires AccessTokenLifetime
// after now. A grant has one access token, replaced in place at each exchange,
// so newID's value is used the first time a grant gets one and ignored when the
// caller replaces the hash and expiry of the secret it already has. Randomness
// comes from r. Nothing is stored.
func IssueAccessToken(r io.Reader, newID func() string, now time.Time) (Issued, error) {
	return issueToken(r, newID, secret.TagOAuthAccess, now.Add(AccessTokenLifetime))
}

// issueToken is issue as a plain (value, error) pair.
func issueToken(r io.Reader, newID func() string, tag secret.Tag, expiresAt time.Time) (Issued, error) {
	return issue(r, newID, tag, expiresAt).Get() //nolint:wrapcheck // issue wraps its error
}

// noID is the id source of a secret that is stored under an id it already has.
func noID() string { return "" }

// issue generates a token of tag and builds what is stored and shown for it.
func issue(r io.Reader, newID func() string, tag secret.Tag, expiresAt time.Time) result.Result[Issued] {
	return result.Of(secret.Generate(r, tag)).
		MapErr(func(err error) error { return fmt.Errorf("issue a %s secret: %w", tag, err) }).
		Map(func(token string) Issued {
			hash := secret.Hash(token)

			return Issued{ID: newID(), Token: token, Hash: hash[:], ExpiresAt: expiresAt}
		})
}

// SessionScope is the scope list every session carries: the default:session
// bundle, which is every scope. A session is the user acting in person, so it
// is limited only by the user's role (admin scopes need the administrator role
// whatever a credential says). A session is not narrowed at login: a stronger
// step-up would be its own mechanism, not a smaller session. The list is not
// stored; the code is its one source.
func SessionScope() scope.List { return scope.List{scope.DefaultSession} }

// LoginGrant is the granted_from value for the session a login challenge
// produced: the SHA-256 of the challenge. The column is unique, so a replayed
// login produces the same value and collides with the session the first one
// made.
func LoginGrant(challenge []byte) []byte {
	sum := sha256.Sum256(challenge)

	return sum[:]
}

// SessionCookie builds the session cookie for an issued session: its value is
// the token and it lasts until the session expires. It is HttpOnly (page
// script cannot read it), Secure (not sent over plain HTTP), Path=/ with no
// Domain (which the __Host- prefix requires, and which keeps it to this host),
// and SameSite=Lax: a session survives a user following a link to the site, and
// is withheld from cross-site subrequests and POSTs, which is also what stops
// another site from triggering a logout. The UI may be on another origin than
// this API, but it must be on the same site (susu.dev and auth.susu.dev;
// localhost on two ports), so the UI's credentialed fetches still carry the
// cookie. SameSite compares registrable domains, not origins, which is why Lax
// suffices and None is not needed.
func SessionCookie(issued Issued) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    issued.Token,
		Path:     "/",
		Expires:  issued.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearSessionCookie expires the session cookie in the browser. It carries the
// same attributes as SessionCookie, because a browser only replaces a cookie
// that has the same name, path and domain.
func ClearSessionCookie() *http.Cookie {
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
