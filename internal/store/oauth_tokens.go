package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// Error codes of the OAuth token operations. They are stable: clients and
// dashboards may match on them.
const (
	CodeOAuthExchangeFailed     = "oauth_exchange_failed"
	CodeOAuthExchangeRejected   = "oauth_exchange_rejected"
	CodeOAuthRefreshFailed      = "oauth_refresh_failed"
	CodeOAuthRefreshRejected    = "oauth_refresh_rejected"
	CodeOAuthIntrospectFailed   = "oauth_introspect_failed"
	CodeOAuthIntrospectRejected = "oauth_introspect_rejected"
	CodeOAuthRevokeFailed       = "oauth_revoke_failed"
	CodeOAuthRevokeRejected     = "oauth_revoke_rejected"
)

// tokensDescription is the client-safe text of every OAuth token operation's
// Unavailable error.
const tokensDescription = "tokens are temporarily unavailable"

// The refusals of ExchangeCode and Refresh. Each is the rotation's own reason
// for writing nothing, and none is a failure of the service. The feature maps
// each to its OAuth error code.
var (
	// ErrInvalidGrant is what ExchangeCode and Refresh report when nothing
	// matched: the token is unknown, is of another kind, was already exchanged,
	// has expired or was revoked, belongs to another client or (for a code) was
	// bound to another redirect URI or PKCE challenge or is older than its life,
	// or its account or agent is revoked. The write cannot tell which and the
	// answer must not, so the feature maps it to invalid_grant (RFC 6749 section
	// 5.2). Nothing was written.
	ErrInvalidGrant = errors.New("no live grant matches the presented token")

	// ErrInvalidScope means the token was live and was the client's, and the
	// scope asked for names something the grant does not hold (RFC 6749 section
	// 6: a refresh must not widen it). Nothing was written, and in particular the
	// refresh token was not spent, so the client can ask again.
	ErrInvalidScope = errors.New("the requested scope is not within the grant's scope")

	// ErrInvalidTarget means the token was live and was the client's, and the
	// resource asked for is not the grant's (RFC 8707 section 2.2). Nothing was
	// written: the token was not spent.
	ErrInvalidTarget = errors.New("the requested resource is not the grant's resource")
)

// NewTokens is what a grant is rotated to at an exchange or a refresh. The
// caller has already issued the tokens (auth.IssueRefreshToken and
// auth.IssueAccessToken): the store only records their hashes.
type NewTokens struct {
	// RefreshHash is the SHA-256 of the new refresh token (32 bytes), which
	// replaces the hash of the code or the previous refresh token under the
	// grant's id. RefreshExpiresAt is when it stops working.
	RefreshHash      []byte
	RefreshExpiresAt time.Time

	// AccessID is the id of the access token's secret, used only the first time
	// the grant gets one: later the secret it already has is replaced in place
	// and this id is ignored. AccessHash is the SHA-256 of the new access token
	// (32 bytes) and AccessExpiresAt is when it stops working.
	AccessID        string
	AccessHash      []byte
	AccessExpiresAt time.Time
}

// Exchanged is what an exchange or a refresh learned of the grant it rotated,
// as the rotation left it: what the token response and the ID token need.
type Exchanged struct {
	// GrantID is the grant's id, UserID its subject and AgentID the agent that
	// holds it.
	GrantID string
	UserID  string
	AgentID string

	// ClientID is the grant's client and Resource the resource server it is for.
	ClientID string
	Resource string

	// Scope is the scope of the access token the rotation issued,
	// space-delimited, as input.OAuthScopes stores them: the grant's own at an
	// exchange, and at a refresh the subset that was asked for or, when none was,
	// the grant's. Whether openid is among them is for the caller to read off
	// Scope.
	Scope string

	// Nonce is the OpenID Connect nonce the client sent at authorization, or nil.
	Nonce *string

	// AuthTime is when the user signed in: the approving session's creation,
	// recorded on the grant at consent.
	AuthTime time.Time

	// Profile is the subject's users.profile as stored, the JSON text of an
	// object, read in the same statement as the rotation. It is for the ID token
	// of a first-party login, and the caller decides whether any of it goes there.
	Profile string
}

// readExchanged reads the row an exchange returns, in the order its statement
// names the columns: grant_id, user_id, agent_id, client_id, resource, scope,
// nonce, auth_time, profile.
func readExchanged(r *row) Exchanged {
	// Struct fields are evaluated in order, which is the column order.
	return Exchanged{
		GrantID: r.text(), UserID: r.text(), AgentID: r.text(), ClientID: r.text(), Resource: r.text(),
		Scope: r.text(), Nonce: r.optText(), AuthTime: r.timestamp(), Profile: r.text(),
	}
}

// exchangedReturning is the RETURNING clause of both rotations, up to the scope:
// the columns readExchanged reads. RETURNING may name only the table the UPDATE
// changes, so the grant's columns are scalar subselects on the secret's id, which
// is the grant's: the row comes back as the statement left it, in the same
// instant. The scope, which is the access token's and not always the grant's, is
// each rotation's own (codeReturning, refreshReturning), between the resource and
// the nonce.
const exchangedReturning = `RETURNING id AS grant_id,
  (SELECT g.user_id FROM oauth_grants g WHERE g.id = secrets.id) AS user_id,
  (SELECT g.agent_id FROM oauth_grants g WHERE g.id = secrets.id) AS agent_id,
  (SELECT g.client_id FROM oauth_grants g WHERE g.id = secrets.id) AS client_id,
  (SELECT g.resource FROM oauth_grants g WHERE g.id = secrets.id) AS resource,
  `

// exchangedReturningRest is the rest of the RETURNING clause, after the scope.
const exchangedReturningRest = `,
  (SELECT g.nonce FROM oauth_grants g WHERE g.id = secrets.id) AS nonce,
  (SELECT g.auth_time FROM oauth_grants g WHERE g.id = secrets.id) AS auth_time,
  (SELECT u.profile FROM oauth_grants g JOIN users u ON u.id = g.user_id WHERE g.id = secrets.id) AS profile`

// grantScopeReturning is the scope an exchange returns when it is not narrowed:
// the grant's.
const grantScopeReturning = `(SELECT g.scope FROM oauth_grants g WHERE g.id = secrets.id) AS scope`

// scopeWithinGrant is the condition that every name of the JSON array bound to
// the placeholder is one of the grant's scope names. The grant's scope is a
// space-delimited list of names that contain no space, so a name is within it
// when it is found between two delimiters, and a name that is only part of
// another (mcp:read in mcp:readwrite) is not. An empty array is within every
// grant. It is a condition of the rotation and not a read before it: see
// rotateRefreshQuery. Its alias g is the grant. json_each is part of the JSON
// functions D1 supports.
//
// The placeholder is the number written in the text below, and no other query
// may reuse the fragment with another numbering.
const scopeWithinGrant = `NOT EXISTS (SELECT 1 FROM json_each(?5) j
                    WHERE instr(' ' || g.scope || ' ', ' ' || j.value || ' ') = 0)`

// codeSecretConditions are the conditions on the grant's secret for the exchange
// of a code: the hash is the code's and it is a grant's secret (a hash is of the
// whole token, prefix included, so a refresh token's, an access token's or a
// key's is never equal to a code's, and the tag is part of the match); it is
// active; and the code is younger than its life. The secret's creation time is
// the consent's, and is not changed by the rotation, so "younger than its life" is
// judged on the one instant the code was issued. The expiry is not the code's
// (it is the row's retention: see NewGrant.RetainUntil).
//
// Arguments: ?1 the code's hash, ?2 the grant kind, ?3 now, ?7 the code's life in
// seconds. The text has no table alias: it is used inside a subselect of secrets
// and in the UPDATE of it.
//
//nolint:gosec // SQL naming the hash column of the secrets table, not a credential
const codeSecretConditions = `hash = ?1 AND kind = ?2
  AND (revoked_at IS NULL OR revoked_at > ?3) AND expires_at > ?3
  AND created_at + ?7 > ?3`

// codeGrantConditions are the conditions on the grant of the exchange of a code,
// over the alias g: the account and the agent that holds the grant are not
// revoked and the agent is in no sandbox (as introspectQuery: consent never
// attaches an agent of a sandbox to a grant, and one that somehow did is
// refused here and not trusted), and it is the presented client's, approved for
// the presented redirect URI and for the PKCE challenge of the presented
// verifier. Arguments: ?4 client_id, ?5 redirect_uri, ?6 code_challenge.
const codeGrantConditions = `FROM oauth_grants g
             JOIN users u ON u.id = g.user_id AND u.revoked_at IS NULL
             JOIN agents a ON a.id = g.agent_id AND a.revoked_at IS NULL AND a.sandbox_id IS NULL
             WHERE g.client_id = ?4 AND g.redirect_uri = ?5 AND g.code_challenge = ?6`

// rotateCodeQuery is the exchange of an authorization code: it rotates the
// grant's secret in place, from the code's hash to the first refresh token's,
// and gives the new token's expiry, in one UPDATE whose conditions are all in
// its WHERE. D1 has no interactive transaction, so nothing is read before it:
// two exchanges of one code are two batches that run one after the other, and
// the second finds the hash already replaced and matches nothing, so exactly one
// of them succeeds.
//
// The secret is rotated only if every one of these holds, at the same instant
// (codeSecretConditions, codeGrantConditions):
//
//   - its hash is the presented code's, and it is a grant's secret;
//   - it is active, and the code is younger than its life (60 seconds from
//     consent: judged from the secret's creation time, because the secret's expiry
//     is the retention of the consent guard, ten minutes);
//   - the grant is the presented client's, and was approved for the presented
//     redirect URI and for the PKCE challenge of the presented verifier. The
//     challenge is computed in Go and compared here, so a wrong verifier
//     rotates nothing, and the code stays good for the client that holds the
//     right one (RFC 7636);
//   - when the request named a resource (RFC 8707), it is the grant's, by exact
//     comparison;
//   - the account is not revoked and the agent that holds the grant is not
//     revoked.
//
// RETURNING gives the grant as the statement left it, so the outcome and the
// row are the same instant: no row means nothing matched, and nothing else of
// the batch (the access token's statements) took effect. The statements after it
// find their grant by the new refresh hash, which only this UPDATE can have
// written. Nothing is read again afterwards. The access token of a code exchange
// carries the grant's whole scope.
//
// The previous hash is not kept, and a code presented again does not revoke
// what its first exchange issued, though RFC 6749 section 4.1.2 says it
// SHOULD: the secret no longer holds anything to recognise it by, so the second
// attempt is indistinguishable from an unknown code. docs/secrets_design.md
// ("Rotation is once only") chose that over keeping history.
//
// Arguments, by number: ?1 the code's hash, ?2 the grant kind, ?3 now (unix
// seconds), ?4 client_id, ?5 redirect_uri, ?6 code_challenge, ?7 the code's life
// (seconds), ?8 the resource the request named (NULL for none), ?9 the new
// refresh hash, ?10 its expiry (unix seconds). The conditions are the first
// eight, in that order, so diagnoseCodeQuery shares them.
const rotateCodeQuery = `
UPDATE secrets
SET hash = ?9, expires_at = ?10
WHERE ` + codeSecretConditions + `
  AND id IN (SELECT g.id ` + codeGrantConditions + `
               AND (?8 IS NULL OR g.resource = ?8))
` + exchangedReturning + grantScopeReturning + exchangedReturningRest

// diagnoseCodeQuery runs after rotateCodeQuery in the same batch, to say why a
// rotation that matched nothing did, when the only thing wrong is the resource
// the request named. It selects the grant under every condition of the rotation
// but that one: the same text, so the two cannot drift. A row therefore means
// the token is live and is the client's (and the redirect URI and the verifier
// are right), and only the resource differs. When the rotation matched, it
// replaced the hash, so this finds nothing; in a batch the statements run one
// after the other, so no other request can come between them. A request that
// presented a wrong verifier, or a code that is spent, is told nothing here.
//
// scope_ok is constant: a code exchange asks for no scope.
//
// Arguments are the first eight of rotateCodeQuery, by the same numbers.
const diagnoseCodeQuery = `
SELECT (?8 IS NULL OR g.resource = ?8) AS resource_ok, 1 AS scope_ok
` + codeGrantConditions + `
  AND g.id IN (SELECT id FROM secrets WHERE ` + codeSecretConditions + `)`

// refreshSecretConditions are the conditions on the grant's secret for a refresh:
// the hash is the refresh token's and it is a grant's secret, and it is active.
// Arguments: ?1 the token's hash, ?2 the grant kind, ?3 now (unix seconds).
//
//nolint:gosec // SQL naming the hash column of the secrets table, not a credential
const refreshSecretConditions = `hash = ?1 AND kind = ?2
  AND (revoked_at IS NULL OR revoked_at > ?3) AND expires_at > ?3`

// refreshGrantConditions are the conditions on the grant of a refresh, over the
// alias g: the account and the agent are not revoked, the agent is in no
// sandbox (as for codeGrantConditions), and the grant is the presented
// client's (?4). The redirect URI and the PKCE challenge are not part
// of it: a refresh is made by whoever holds the token, and the client is the one
// condition a public client can be held to.
const refreshGrantConditions = `FROM oauth_grants g
             JOIN users u ON u.id = g.user_id AND u.revoked_at IS NULL
             JOIN agents a ON a.id = g.agent_id AND a.revoked_at IS NULL AND a.sandbox_id IS NULL
             WHERE g.client_id = ?4`

// rotateRefreshQuery is the refresh of a refresh token: rotateCodeQuery's rotation
// keyed on the refresh token's hash and the client. The new expiry is 30 days
// from now, not from the first exchange, so a grant that is used does not lapse.
// Two refreshes of one token are two batches, and exactly one succeeds.
//
// Beyond the conditions on the secret, the account and the agent
// (refreshSecretConditions, refreshGrantConditions), the rotation requires, in
// the write itself:
//
//   - the scope asked for is within the grant's (scopeWithinGrant), as RFC 6749
//     section 6 requires: a refresh may narrow the scope and must not widen it,
//     and an omitted scope is the grant's own. It is the grant's scope, and not
//     the previous access token's, that bounds it, because that is what "the
//     scope originally granted" is;
//   - the resource asked for, if any, is the grant's (RFC 8707 section 2.2).
//
// When one of those two fails nothing is rotated, so the client's refresh token
// is not spent on a request it can correct: diagnoseRefreshQuery tells which.
// RETURNING gives the scope of the access token that is being issued: the one
// asked for, or the grant's.
//
// Arguments, by number: ?1 the token's hash, ?2 the grant kind, ?3 now (unix
// seconds), ?4 client_id, ?5 the scope names asked for, as a JSON array of strings
// ("[]" for none), ?6 the resource asked for (NULL for none), ?7 the scope text
// asked for (NULL for none), ?8 the new refresh hash, ?9 its expiry (unix
// seconds). The conditions are the first six, in that order, so
// diagnoseRefreshQuery shares them.
const rotateRefreshQuery = `
UPDATE secrets
SET hash = ?8, expires_at = ?9
WHERE ` + refreshSecretConditions + `
  AND id IN (SELECT g.id ` + refreshGrantConditions + `
               AND ` + scopeWithinGrant + `
               AND (?6 IS NULL OR g.resource = ?6))
` + exchangedReturning + `COALESCE(?7, (SELECT g.scope FROM oauth_grants g WHERE g.id = secrets.id)) AS scope` +
	exchangedReturningRest

// diagnoseRefreshQuery is diagnoseCodeQuery for a refresh: it runs after
// rotateRefreshQuery in the same batch and, when that matched nothing, says
// whether the live token's client asked for a scope or a resource the grant does
// not allow. Arguments are the first six of rotateRefreshQuery, by the same
// numbers.
const diagnoseRefreshQuery = `
SELECT (?6 IS NULL OR g.resource = ?6) AS resource_ok, ` + scopeWithinGrant + ` AS scope_ok
` + refreshGrantConditions + `
  AND g.id IN (SELECT id FROM secrets WHERE ` + refreshSecretConditions + `)`

// replaceAccessQuery gives a grant that already has an access token its new one,
// in place: the access token's secret takes the new hash and expiry and a new
// creation time (the token's iat), and its revocation is cleared, because the
// secret is reused for a token that was never revoked. The old token stops
// matching anything at once.
//
// It applies only to the grant the rotation just rotated, which it finds by the
// new refresh hash: that hash is 256 random bits that only the rotation's UPDATE
// can have written, so no other grant can satisfy it, and when the rotation
// matched nothing neither does this. A grant that has no access token yet
// matches nothing here (insertAccessSecretQuery gives it one).
//
// A revoked grant never gets here: its secret is not active, so it is never
// rotated. A grant whose access token alone was revoked (RFC 7009) is refreshed
// into a live one.
//
// Arguments, by number: ?1 the new access hash, ?2 its expiry (unix seconds),
// ?3 now (unix seconds), ?4 the access kind, ?5 the grant kind, ?6 the new
// refresh hash.
const replaceAccessQuery = `
UPDATE secrets
SET hash = ?1, expires_at = ?2, revoked_at = NULL, created_at = ?3
WHERE kind = ?4
  AND id IN (SELECT t.id FROM oauth_access_tokens t
             JOIN secrets g ON g.id = t.grant_id AND g.kind = ?5 AND g.hash = ?6)`

// replaceAccessScopeQuery sets the scope of the access token replaceAccessQuery
// just replaced, in the same batch and under the same condition: it is the one of
// the grant the rotation rotated, found by the new refresh hash. The scope is the
// one the refresh asked for or, when it asked for none, the grant's. When the
// grant has no access token yet nothing matches (insertAccessRowQuery writes the
// first with its scope).
//
// Arguments, by number: ?1 the scope text asked for (NULL for none), ?2 the grant
// kind, ?3 the new refresh hash.
const replaceAccessScopeQuery = `
UPDATE oauth_access_tokens
SET scope = COALESCE(?1, (SELECT g.scope FROM oauth_grants g WHERE g.id = oauth_access_tokens.grant_id))
WHERE grant_id IN (SELECT s.id FROM secrets s WHERE s.kind = ?2 AND s.hash = ?3)`

// insertAccessSecretQuery writes the secret of a grant's first access token, only
// if the rotation matched (a secret with the new refresh hash exists, which only
// the rotation can have made so) and the grant has no access token yet. A
// conditional INSERT ... SELECT that matches nothing is not an error and the
// batch goes on: the rest of it matches nothing too.
//
// Arguments, by number: ?1 access secret id, ?2 the access kind, ?3 its hash, ?4
// its expiry (unix seconds), ?5 now (unix seconds), ?6 the new refresh hash, ?7
// the grant kind.
//
//nolint:gosec // SQL naming the secrets table, not a credential
const insertAccessSecretQuery = `
INSERT INTO secrets (id, kind, hash, expires_at, created_at)
SELECT ?1, ?2, ?3, ?4, ?5
WHERE EXISTS (SELECT 1 FROM secrets g WHERE g.hash = ?6 AND g.kind = ?7)
  AND NOT EXISTS (SELECT 1 FROM oauth_access_tokens t
                  JOIN secrets g ON g.id = t.grant_id AND g.kind = ?7 AND g.hash = ?6)`

// insertAccessRowQuery writes the access token's own row, after its secret in
// the same batch: only if that secret was written (the previous statement
// matched, so a secret with this id and kind exists), and for the grant the
// rotation just rotated. The id is fresh for every call, so only that statement
// can have made it. grant_id is UNIQUE, so a second row for a grant would fail
// the batch; the condition keeps a grant that already has one from reaching it.
// Its scope is the one the rotation asked for or, when it asked for none, the
// grant's.
//
// Arguments, by number: ?1 access secret id, ?2 the access kind, ?3 the new
// refresh hash, ?4 the grant kind, ?5 the scope text asked for (NULL for none).
const insertAccessRowQuery = `
INSERT INTO oauth_access_tokens (id, kind, grant_id, scope)
SELECT ?1, ?2, g.id, COALESCE(?5, og.scope)
FROM secrets g
JOIN oauth_grants og ON og.id = g.id
WHERE g.hash = ?3 AND g.kind = ?4
  AND EXISTS (SELECT 1 FROM secrets x WHERE x.id = ?1 AND x.kind = ?2)`

// accessStatements are the four statements that follow a rotation in the same
// batch and give the rotated grant its access token: replace the one it has, with
// its scope, or write the first. They find the grant by the new refresh hash
// alone, so they need no result from the rotation and run unconditionally; when
// the rotation matched nothing they match nothing. scope is the scope text the
// access token carries, or nil for the grant's own.
func accessStatements(tokens NewTokens, scope any, now time.Time) []Statement {
	unix := now.Unix()

	return []Statement{
		{Query: replaceAccessQuery, Args: []any{
			tokens.AccessHash, tokens.AccessExpiresAt.Unix(), unix, KindOAuthAccess, KindOAuthGrant, tokens.RefreshHash,
		}},
		{Query: replaceAccessScopeQuery, Args: []any{scope, KindOAuthGrant, tokens.RefreshHash}},
		{Query: insertAccessSecretQuery, Args: []any{
			tokens.AccessID, KindOAuthAccess, tokens.AccessHash, tokens.AccessExpiresAt.Unix(), unix,
			tokens.RefreshHash, KindOAuthGrant,
		}},
		{Query: insertAccessRowQuery, Args: []any{
			tokens.AccessID, KindOAuthAccess, tokens.RefreshHash, KindOAuthGrant, scope,
		}},
	}
}

// CodeExchange is an authorization code presented at the token endpoint, with
// what it is checked against and what it is exchanged for.
type CodeExchange struct {
	// Code is the presented authorization code.
	Code input.AuthorizationCode

	// ClientID and RedirectURI are the values the request presented, and the
	// grant must have been approved for exactly these. Verifier is the PKCE
	// code verifier, whose S256 challenge the grant must hold.
	ClientID    input.ClientID
	RedirectURI input.RedirectURI
	Verifier    input.CodeVerifier

	// Resource is the resource the request named (RFC 8707), or nil. When it is
	// set it must be the grant's, or the exchange is ErrInvalidTarget.
	Resource *input.ResourceID

	// CodeLifetime is how long after consent the code can be exchanged: the
	// write requires the code to be younger than this, judged at now. A zero
	// lifetime refuses every code. It is whole seconds, as expiries are.
	CodeLifetime time.Duration

	// Tokens are the tokens the grant is rotated to.
	Tokens NewTokens
}

// ExchangeCode exchanges an authorization code for the grant's first refresh
// token and access token, as one batch: the rotation, which carries every
// condition and reports the grant (see rotateCodeQuery), the diagnosis of a
// rotation that matched nothing, and the access token's statements, which write
// only if the rotation matched.
//
// It returns ErrInvalidGrant when nothing matched, and ErrInvalidTarget when the
// code is live and right in every way and only the resource it named is not the
// grant's; in both nothing was written. A code is single use: of two concurrent
// exchanges exactly one succeeds. A conflict of any kind is a defect: the new
// hashes are random and the access id fresh, so nothing the batch writes can
// collide.
func (s *Store) ExchangeCode(ctx context.Context, exchange CodeExchange, now time.Time) (Exchanged, error) {
	o := op{failed: CodeOAuthExchangeFailed, rejected: CodeOAuthExchangeRejected, description: tokensDescription}

	tokens := exchange.Tokens

	// The conditions are the first eight arguments, which the diagnosis shares.
	conditions := []any{
		exchange.Code.Hash(), KindOAuthGrant, now.Unix(), exchange.ClientID.String(), exchange.RedirectURI.String(),
		exchange.Verifier.Challenge().String(), int64(exchange.CodeLifetime / time.Second), resourceArg(exchange.Resource),
	}

	rotate := Statement{Query: rotateCodeQuery, Args: append(slices.Clone(conditions),
		tokens.RefreshHash, tokens.RefreshExpiresAt.Unix())}
	diagnose := Statement{Query: diagnoseCodeQuery, Args: conditions}

	return s.rotate(ctx, o, rotationOf{rotate: rotate, diagnose: diagnose, scope: nil}, tokens, now)
}

// resourceArg is the argument of an optional resource: its URL, or NULL.
func resourceArg(target *input.ResourceID) any {
	if target == nil {
		return nil
	}

	return target.String()
}

// RefreshExchange is a refresh token presented at the token endpoint, with what
// it is checked against and what it is exchanged for.
type RefreshExchange struct {
	// Token is the presented refresh token, and ClientID the client the
	// request presented: the grant must be that client's.
	Token    input.RefreshToken
	ClientID input.ClientID

	// Scope is the scope the request asked for, or nil for none. When it is set
	// every name of it must be one of the grant's, or the refresh is
	// ErrInvalidScope; the access token carries exactly these. When it is nil
	// the access token carries the grant's scope. The caller has already refused
	// a scope that names nothing of the resource.
	Scope *input.OAuthScopes

	// Resource is the resource the request named (RFC 8707), or nil. When it is
	// set it must be the grant's, or the refresh is ErrInvalidTarget.
	Resource *input.ResourceID

	// Tokens are the tokens the grant is rotated to.
	Tokens NewTokens
}

// Refresh exchanges a refresh token for the grant's next refresh token and access
// token, as ExchangeCode does with a code (see rotateRefreshQuery for what must
// hold). The new refresh token's expiry is the one Tokens carries, 30 days from
// now, and the access token the grant has is replaced in place: the previous one
// stops working at once.
//
// It returns ErrInvalidGrant when nothing matched, and ErrInvalidScope or
// ErrInvalidTarget (the resource is reported first) when the token is live and
// the client's and only the scope or the resource asked for is not within the
// grant's. In each nothing was written and the refresh token stays good. Of two
// concurrent refreshes of one token exactly one succeeds.
func (s *Store) Refresh(ctx context.Context, exchange RefreshExchange, now time.Time) (Exchanged, error) {
	o := op{failed: CodeOAuthRefreshFailed, rejected: CodeOAuthRefreshRejected, description: tokensDescription}

	tokens := exchange.Tokens

	// The conditions are the first six arguments, which the diagnosis shares.
	names, scope := scopeArgs(exchange.Scope)
	conditions := []any{
		exchange.Token.Hash(), KindOAuthGrant, now.Unix(), exchange.ClientID.String(), names, resourceArg(exchange.Resource),
	}

	rotate := Statement{Query: rotateRefreshQuery, Args: append(slices.Clone(conditions),
		scope, tokens.RefreshHash, tokens.RefreshExpiresAt.Unix())}
	diagnose := Statement{Query: diagnoseRefreshQuery, Args: conditions}

	return s.rotate(ctx, o, rotationOf{rotate: rotate, diagnose: diagnose, scope: scope}, tokens, now)
}

// scopeArgs are the two arguments of a requested scope: its names as a JSON array
// of strings, which the rotation checks against the grant's, and its text, which
// the access token carries. With no scope they are "[]", which is within every
// grant, and NULL, which is the grant's own scope.
func scopeArgs(scope *input.OAuthScopes) (string, any) {
	if scope == nil {
		return "[]", nil
	}

	// A list of strings always encodes.
	names, err := json.Marshal(scope.Names())
	// coverage:ignore: marshalling a slice of strings cannot fail
	if err != nil {
		panic("store: scope names: " + err.Error())
	}

	return string(names), scope.String()
}

// rotationOf is the statements of one rotation: the UPDATE, its diagnosis, and
// the scope text the access token carries (nil for the grant's own).
type rotationOf struct {
	rotate   Statement
	diagnose Statement
	scope    any
}

// rotate runs a rotation, its diagnosis and the statements that give its grant its
// access token as one batch, and reads the grant off the rotation's row. A
// rotation that matched nothing is told apart by the diagnosis, which reads the
// same grant under the same conditions in the same batch.
func (s *Store) rotate(
	ctx context.Context, o op, r rotationOf, tokens NewTokens, now time.Time,
) (Exchanged, error) {
	statements := append([]Statement{r.rotate, r.diagnose}, accessStatements(tokens, r.scope, now)...)

	results, err := s.run(ctx, o, statements...)
	if err != nil {
		return Exchanged{}, rejectGrantConflict(o, err)
	}

	exchanged, err := one(results[0].Rows, o, readExchanged)
	if !errors.Is(err, ErrNotFound) {
		return exchanged, err
	}

	why, found, err := findRow(results[1].Rows, o, readDiagnosis)
	if err != nil {
		return Exchanged{}, err
	}

	return Exchanged{}, why.refusal(found)
}

// diagnosis is what a rotation that matched nothing learned of the live grant it
// was presented for: whether the resource and the scope asked for are within it.
type diagnosis struct {
	resourceOK bool
	scopeOK    bool
}

// readDiagnosis reads the row of diagnoseCodeQuery and diagnoseRefreshQuery:
// resource_ok, scope_ok.
func readDiagnosis(r *row) diagnosis {
	return diagnosis{resourceOK: r.boolean(), scopeOK: r.boolean()}
}

// refusal is the error of a rotation that matched nothing. found is whether the
// diagnosis found the live grant: if it did not, nothing about the token is
// right and the answer is ErrInvalidGrant, which says nothing else. If it did
// and both asks are within the grant, the rotation cannot have failed for the
// reason the diagnosis tests, and the answer is the same ErrInvalidGrant.
func (d diagnosis) refusal(found bool) error {
	switch {
	case found && !d.resourceOK:
		return ErrInvalidTarget
	case found && !d.scopeOK:
		return ErrInvalidScope
	default:
		return ErrInvalidGrant
	}
}

// introspectQuery reads a presented access token's hash, as resolveSessionQuery
// reads a session's: the access token's secret, its own row, the grant, the
// grant's secret, the account and the agent in one statement, so whether the
// token is live, whose it is and what it was granted all come from the same
// instant. A token carries nothing that could go stale.
//
// The token is live only if all of these hold:
//
//   - its secret is active (activeSecretPredicate's rule, over the alias s) and
//     is an access token's, and its own row is joined on the id and the kind
//     together;
//   - the grant's secret is active too, so revoking the grant (or its agent, or
//     its user, which revoke the same secret) ends the access token at once;
//   - the account is not revoked, and the agent that holds the grant is not,
//     and is in no sandbox: consent never attaches an agent of a sandbox to a
//     grant (insertGrantQuery), so there is none, and a token that somehow
//     reached one is refused here rather than trusted;
//   - the grant is for exactly the resource asked about, by exact comparison, so
//     a token for one resource is not live at another.
//
// A token that fails any of them has no row, and the answers are
// indistinguishable. The scope is the access token's own (a refresh may have
// narrowed it from the grant's, and it is never wider): at a resource it is the
// only limit, and the agent and the account contribute liveness only. The
// token's hash is not selected.
//
// Arguments, by number: ?1 the token's hash, ?2 the access kind, ?3 now (unix
// seconds), ?4 resource, ?5 the grant kind.
const introspectQuery = `
SELECT g.id AS grant_id, g.user_id AS user_id, g.agent_id AS agent_id, g.client_id AS client_id,
       g.resource AS resource, t.scope AS scope, s.created_at AS issued_at, s.expires_at AS expires_at
FROM secrets s
JOIN oauth_access_tokens t ON t.id = s.id AND t.kind = s.kind
JOIN oauth_grants g ON g.id = t.grant_id
JOIN secrets gs ON gs.id = g.id AND gs.kind = g.kind
JOIN users u ON u.id = g.user_id
JOIN agents a ON a.id = g.agent_id
WHERE s.hash = ?1
  AND s.kind = ?2
  AND (s.revoked_at IS NULL OR s.revoked_at > ?3) AND s.expires_at > ?3
  AND gs.kind = ?5
  AND (gs.revoked_at IS NULL OR gs.revoked_at > ?3) AND gs.expires_at > ?3
  AND u.revoked_at IS NULL
  AND a.revoked_at IS NULL
  AND a.sandbox_id IS NULL
  AND g.resource = ?4`

// ActiveAccessToken is an access token that may be used, with what it was
// granted. The caller adds what is not stored: the issuer, the token type.
type ActiveAccessToken struct {
	// GrantID is the grant the token was issued under, and UserID the account
	// it speaks for (the subject). AgentID is the agent that holds the grant.
	GrantID string
	UserID  string
	AgentID string

	// ClientID is the client it was issued to, Resource the resource server it
	// is for and Scope the scopes this token carries, space-delimited: the
	// grant's, or the narrower list a refresh asked for.
	ClientID string
	Resource string
	Scope    string

	// IssuedAt is when this token was issued (it is replaced at each exchange
	// and refresh) and ExpiresAt when it stops being active.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IntrospectAccessToken reads the access token the token names if it is live at
// now for exactly this resource: not revoked or expired, its grant not revoked
// or expired, its account and agent not revoked. It reports false otherwise, so
// an unknown, wrong-kind, expired, revoked, revoked-agent, revoked-user and
// other-resource token are indistinguishable.
func (s *Store) IntrospectAccessToken(
	ctx context.Context, token input.AccessToken, resource input.ResourceID, now time.Time,
) (ActiveAccessToken, bool, error) {
	o := op{failed: CodeOAuthIntrospectFailed, rejected: CodeOAuthIntrospectRejected, description: tokensDescription}

	return find(ctx, s, o,
		Statement{Query: introspectQuery, Args: []any{
			token.Hash(), KindOAuthAccess, now.Unix(), resource.String(), KindOAuthGrant,
		}},
		func(r *row) ActiveAccessToken {
			// Struct fields are evaluated in order, which is the column order.
			return ActiveAccessToken{
				GrantID: r.text(), UserID: r.text(), AgentID: r.text(), ClientID: r.text(), Resource: r.text(),
				Scope: r.text(), IssuedAt: r.timestamp(), ExpiresAt: r.timestamp(),
			}
		})
}

// revokeRefreshTokenQuery revokes the grant that a refresh token names, now,
// for the client that presented it (RFC 7009 section 2.1: a token is revoked
// only for the client it was issued to). The hash is of the whole token, so only
// a refresh token's can match a grant's secret that has been rotated.
//
// Only a secret that is not yet revoked as of now is changed, as for every
// revoke: one already revoked keeps its earlier time, so revoking twice cannot
// move a revocation later. An unknown token, another client's or one whose
// secret is of another kind matches nothing, and that is not an error: the
// endpoint answers the same either way (RFC 7009 section 2.2).
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 the token's hash, ?3
// the grant kind, ?4 client_id.
const revokeRefreshTokenQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE hash = ?2 AND kind = ?3
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND id IN (SELECT g.id FROM oauth_grants g WHERE g.client_id = ?4)`

// revokeRefreshAccessQuery revokes the access token of the grant a refresh token
// names, in the same batch as revokeRefreshTokenQuery and after it, under the
// same conditions (the hash is the grant's secret's, the client the grant's), so
// revoking a refresh token takes the grant's access token with it (RFC 7009
// section 2.1 permits it and the grant is one thing to its user). A revocation
// already due keeps its time.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 the refresh token's
// hash, ?3 client_id, ?4 the grant kind.
const revokeRefreshAccessQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE (revoked_at IS NULL OR revoked_at > ?1)
  AND id IN (SELECT t.id FROM oauth_access_tokens t
             JOIN oauth_grants g ON g.id = t.grant_id
             JOIN secrets gs ON gs.id = g.id AND gs.kind = ?4
             WHERE gs.hash = ?2 AND g.client_id = ?3)`

// RevokeRefreshToken revokes the grant the refresh token belongs to, and its
// access token, as of now, as one batch, if the grant is the client's. A token
// that is unknown, expired, already revoked, another client's or of no live
// grant is not an error: the caller answers the same either way, as RFC 7009
// requires, and learns nothing about the token. Of two concurrent revocations
// the first time is kept.
//
// As for the other revokes, a constraint failure of any kind is a defect.
func (s *Store) RevokeRefreshToken(
	ctx context.Context, token input.RefreshToken, client input.ClientID, now time.Time,
) error {
	o := op{failed: CodeOAuthRevokeFailed, rejected: CodeOAuthRevokeRejected, description: tokensDescription}

	_, err := s.run(ctx, o,
		Statement{Query: revokeRefreshTokenQuery, Args: []any{now.Unix(), token.Hash(), KindOAuthGrant, client.String()}},
		Statement{Query: revokeRefreshAccessQuery, Args: []any{now.Unix(), token.Hash(), client.String(), KindOAuthGrant}},
	)

	return rejectGrantConflict(o, err)
}

// revokeAccessTokenQuery revokes the access token's own secret, now, for the
// client it was issued to, and nothing else: the grant and its refresh token
// stay, so the client can refresh into a new access token (RFC 7009 section
// 2.1: revoking an access token need not revoke the refresh token). The token
// must be an access token of a grant of the presenting client, and an
// already-due revocation keeps its time. An unknown token matches nothing and
// is not an error.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 the token's hash, ?3
// the access kind, ?4 client_id.
const revokeAccessTokenQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE hash = ?2 AND kind = ?3
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND id IN (SELECT t.id FROM oauth_access_tokens t
             JOIN oauth_grants g ON g.id = t.grant_id
             WHERE g.client_id = ?4)`

// RevokeAccessToken revokes the access token, only, as of now, if it was issued
// to the client. The grant and its refresh token are not touched. As for
// RevokeRefreshToken, an unknown token or another client's is not an error.
func (s *Store) RevokeAccessToken(
	ctx context.Context, token input.AccessToken, client input.ClientID, now time.Time,
) error {
	o := op{failed: CodeOAuthRevokeFailed, rejected: CodeOAuthRevokeRejected, description: tokensDescription}

	_, err := s.run(ctx, o,
		Statement{Query: revokeAccessTokenQuery, Args: []any{now.Unix(), token.Hash(), KindOAuthAccess, client.String()}},
	)

	return rejectGrantConflict(o, err)
}
