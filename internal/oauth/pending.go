package oauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// This file is the pending authorization request: what the authorization
// endpoint seals, and what the UI's two routes open. It is the one place that
// knows the sealed layout and how it is read back.

// randomBytes is the length of the random value a pending request carries. A
// sealed value is deterministic in its key, expiry and payload
// (challenge.Seal), so without it two identical requests in the same second
// would produce the same sealed value, the same hash, and so one consent for
// both. 16 bytes is the 128 bits of a UUID, and its base64url is
// randomChars characters.
const (
	randomBytes = 16
	randomChars = 22
)

// maxExactInt is the largest integer a JavaScript number holds exactly (2^53-1),
// the bound of every integer this service sends to a browser.
const maxExactInt = 1<<53 - 1

// pendingRequest is an authorization request that has been parsed: every
// field is an input type, whether it was just read from the client's query or
// read back from a sealed value, so everything downstream of either holds only
// parsed values.
type pendingRequest struct {
	clientID    input.ClientID
	clientName  input.ClientName
	redirectURI input.RedirectURI
	challenge   input.CodeChallenge
	state       *input.State
	nonce       *input.Nonce
	resource    input.ResourceID
	scope       input.OAuthScopes
	// expiresAt is when a sealed request stops being accepted, in Unix seconds,
	// as its payload says. It is zero for a request that was not read from a
	// sealed value.
	expiresAt int64
}

// pendingWire is the sealed payload: the request's values as text, the
// client_name read from the client's document when the request was made, a random
// value, and when the request lapses. It is JSON, encoded without HTML
// escaping and within the bounds input's TestPendingRequestFitsItsPayload
// checks. The sealed value is signed and not encrypted, so it holds nothing
// secret: every member is something the client sent or its public document said.
type pendingWire struct {
	ClientID      string `json:"clientId"`
	ClientName    string `json:"clientName"`
	RedirectURI   string `json:"redirectUri"`
	CodeChallenge string `json:"codeChallenge"`
	// State and Nonce are absent when the client sent none: a parser refuses
	// an empty one, so empty is unambiguous.
	State  string `json:"state,omitempty"`
	Nonce  string `json:"nonce,omitempty"`
	Scope  string `json:"scope"`
	Random string `json:"random"`
	// Resource is the URL of the resource server the request is for.
	Resource string `json:"resource"`
	// ExpiresAt is when the sealed value stops being accepted, in Unix seconds:
	// the same instant as its own expiry, which the sealed form does not give
	// back.
	ExpiresAt int64 `json:"expiresAt"`
}

// wire is the payload of p, sealed with random until expires.
func (p pendingRequest) wire(random string, expires time.Time) pendingWire {
	wire := pendingWire{
		ClientID: p.clientID.String(), ClientName: p.clientName.String(), RedirectURI: p.redirectURI.String(),
		CodeChallenge: p.challenge.String(), Resource: p.resource.String(), Scope: p.scope.String(),
		Random: random, ExpiresAt: expires.Unix(),
	}

	if p.state != nil {
		wire.State = p.state.String()
	}

	if p.nonce != nil {
		wire.Nonce = p.nonce.String()
	}

	return wire
}

// optional parses raw with parse when it is present. The sealed payload leaves
// out what the client did not send, and no parser accepts an empty value, so
// absent is "".
func optional[T any](raw string, parse func(string) (T, error)) (*T, error) {
	if raw == "" {
		return nil, nil //nolint:nilnil // absent is a value, and a nil pointer is how the request says so
	}

	parsed, err := parse(raw)
	if err != nil {
		return nil, err
	}

	return &parsed, nil
}

// errRandom and errExpiry are why a payload's own bookkeeping members were
// refused. They are only ever in the log.
var (
	errRandom = errors.New("the random value is not 16 bytes of unpadded base64url")
	errExpiry = errors.New("the expiry is not a positive integer a browser holds exactly")
)

// checkBookkeeping refuses a random value that is not what seal writes, and an
// expiry that is not a plausible time.
func (w pendingWire) checkBookkeeping() error {
	random, err := base64.RawURLEncoding.Strict().DecodeString(w.Random)

	switch {
	case err != nil || len(random) != randomBytes:
		return errRandom
	case w.ExpiresAt <= 0 || w.ExpiresAt > maxExactInt:
		return errExpiry
	default:
		return nil
	}
}

// parseScopes reads a scope against the entry it is for: the first-party login
// entry tolerates what a standard OpenID Connect client sends (see
// input.ParseFirstPartyScopes), every other is read strictly.
func parseScopes(raw string, present bool, entry resource.Entry) (input.OAuthScopes, error) {
	parse := input.ParseOAuthScopes
	if entry.FirstParty {
		parse = input.ParseFirstPartyScopes
	}

	scopes, err := parse(raw, present, entry)
	if err != nil {
		return input.OAuthScopes{}, fmt.Errorf("scope: %w", err)
	}

	return scopes, nil
}

// firstPartyLogin reports whether the request is a first-party login: it is for
// a first-party login resource, which only a trusted client can have asked for
// (admit). Its consent needs no screen and no agent: the grant is held by the
// agent authsu keeps for this user and client (store.NewGrant.FirstParty), not
// one the person chose.
func (p pendingRequest) firstPartyLogin() bool {
	return p.resource.Entry().FirstParty
}

// firstPartyName is the name of the agent a first-party login creates: the name
// the client's own document gave itself, which is already bounded and has already
// passed ClientName's stricter rules, so it is always a valid AgentName.
func (p pendingRequest) firstPartyName() input.AgentName {
	name, err := input.ParseAgentName(p.clientName.String())
	// coverage:ignore: a client name is at most 128 bytes of text AgentName also accepts
	if err != nil {
		panic("oauth: a client name is not an agent name: " + err.Error())
	}

	return name
}

// requireResourceScope refuses a scope that names nothing of the resource, as the
// authorization endpoint does: such a request is never sealed, so one that is
// read back is not one of ours.
func requireResourceScope(scope input.OAuthScopes) error {
	if len(scope.Resource()) == 0 {
		return errNoResourceScope
	}

	return nil
}

// parse reads every member of the payload through its parser, against the
// table of the deployment. The payload is signed by this server, so each of
// these was a parsed value once; they are parsed again because what is read back
// may come from another version of the service (a request in flight across a
// deploy that changed a bound, or the table), and a value that no longer parses
// must be refused here and not trusted because it was once sealed. Any failure
// is CodeInvalidPending, with every cause in the log.
//
// The members do not feed one another, so they are parsed together and the
// failures joined, which is the shape CONTRIBUTING allows over a chain here.
func (w pendingWire) parse(table resource.Table) result.Result[pendingRequest] {
	clientID, idErr := input.ParseClientID(w.ClientID, table)
	name, nameErr := input.ParseClientName(w.ClientName)
	redirectURI, redirectErr := input.ParseRedirectURI(w.RedirectURI)
	code, codeErr := input.ParseCodeChallenge(w.CodeChallenge)
	state, stateErr := optional(w.State, input.ParseState)
	nonce, nonceErr := optional(w.Nonce, input.ParseNonce)
	target, targetErr := input.ParseResourceID(w.Resource, table)
	scopes, scopeErr := parseScopes(w.Scope, true, target.Entry())

	// The sealed value is read back as untrusted as any other, so the rule that a
	// first-party login is for a trusted client is applied again here, against
	// the table of now: a value sealed before a client stopped being trusted, or
	// one forged for a first-party resource with another client's id, is refused.
	err := errors.Join(
		idErr, nameErr, redirectErr, codeErr, stateErr, nonceErr, targetErr, scopeErr,
		requireResourceScope(scopes), w.checkBookkeeping(), admitSealed(table, clientID, target, idErr, targetErr))
	if err != nil {
		return result.Fail[pendingRequest](invalidPending(err))
	}

	return result.Ok(pendingRequest{
		clientID: clientID, clientName: name, redirectURI: redirectURI, challenge: code,
		state: state, nonce: nonce, resource: target, scope: scopes, expiresAt: w.ExpiresAt,
	})
}

// admitSealed applies admit to what a sealed value holds, when both parsed. A
// member that did not parse is already an error of its own, joined with this one
// by the caller, so there is nothing more to say about it here.
func admitSealed(table resource.Table, client input.ClientID, target input.ResourceID, idErr, targetErr error) error {
	if errors.Join(idErr, targetErr) != nil {
		return errors.Join(idErr, targetErr)
	}

	return admit(table, client, target)
}

// invalidPending is the 400 for a pending request that cannot be used.
func invalidPending(cause error) *apierr.Error {
	return apierr.New(apierr.BadRequest, CodeInvalidPending,
		"the authorization request is not valid or has expired; start again from the application").WithCause(cause)
}

// seal returns the pending request for p as the text the UI is sent: the
// payload sealed with the deployment's request key until PendingLifetime from
// now, as unpadded base64url. The random value comes from the injected entropy.
func (d Deps) seal(cfg config.Config, p pendingRequest, now time.Time) result.Result[string] {
	random := make([]byte, randomBytes)

	_, err := io.ReadFull(d.Entropy, random)
	if err != nil {
		return result.Fail[string](failure(oauthServerError, err))
	}

	expires := now.Add(PendingLifetime)
	payload := encode(p.wire(base64.RawURLEncoding.EncodeToString(random), expires))

	return result.Of(challenge.Seal(cfg.OAuthRequestKey, expires, payload)).
		MapErr(refusing(oauthServerError)).
		Map(base64.RawURLEncoding.EncodeToString)
}

// opened is a pending request that was read back from the text the UI sent.
type opened struct {
	// request is every member of the payload, parsed.
	request pendingRequest
	// sealed is the sealed value as it was sent, whose SHA-256 a grant records
	// as its single-use guard.
	sealed []byte
}

// errPendingTooLong and errPendingEncoding are why the text of a pending request
// was refused before it was opened. They are only ever in the log.
var (
	errPendingTooLong  = errors.New("the pending request is longer than any sealed value")
	errPendingEncoding = errors.New("the pending request is not unpadded base64url")
)

// open reads the pending request back from raw, the text the UI was sent. It
// refuses, with CodeInvalidPending, anything that is not exactly what seal
// returned and has not expired: a length that no sealed value has (checked
// before it is decoded), anything but canonical unpadded base64url, a value
// whose signature is not the deployment's request key's over exactly these bytes
// (a login or registration challenge, or a value sealed for another purpose or
// key, included: the layouts and the keys differ), a value past its expiry or
// expiring later than PendingLifetime from now, and a payload that does not parse
// (pendingWire.parse).
//
// The request key is the 32 bytes config derives, so the key length that
// challenge.OpenSealed would call a server fault cannot occur and every failure
// of it is the request's.
func (d Deps) open(cfg config.Config, raw string, now time.Time) result.Result[opened] {
	table := d.table(cfg)

	return decodePending(raw).
		Then(func(sealed []byte) (opened, error) {
			return result.Of(challenge.OpenSealed(cfg.OAuthRequestKey, sealed, now, PendingLifetime)).
				MapErr(func(cause error) error { return invalidPending(cause) }).
				Then(func(payload []byte) (pendingWire, error) {
					return httpapi.Decode[pendingWire](httpapi.Request{Body: payload}).
						MapErr(func(cause error) error { return invalidPending(cause) }).Get()
				}).
				Then(func(wire pendingWire) (pendingRequest, error) { return wire.parse(table).Get() }).
				Map(func(request pendingRequest) opened { return opened{request: request, sealed: sealed} }).
				Get()
		})
}

// decodePending decodes the text of a pending request, within the longest length
// a sealed value has and in the one canonical spelling, so a sealed value has
// exactly one text and the hash a grant records is of what was signed.
func decodePending(raw string) result.Result[[]byte] {
	if len(raw) > base64.RawURLEncoding.EncodedLen(challenge.MaxSealedLen) {
		return result.Fail[[]byte](invalidPending(errPendingTooLong))
	}

	// The decoder skips carriage returns and line feeds, so they are refused
	// first: a sealed value has one spelling.
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || strings.ContainsAny(raw, "\r\n") {
		return result.Fail[[]byte](invalidPending(errors.Join(errPendingEncoding, err)))
	}

	return result.Ok(sealed)
}
