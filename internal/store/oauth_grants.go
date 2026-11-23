package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// Error codes of the OAuth grant operations. They are stable: clients and
// dashboards may match on them.
const (
	CodeGrantCreateFailed   = "oauth_grant_create_failed"
	CodeGrantCreateRejected = "oauth_grant_create_rejected"
	CodeGrantListFailed     = "oauth_grant_list_failed"
	CodeGrantListRejected   = "oauth_grant_list_rejected"
	CodeGrantLookupFailed   = "oauth_grant_lookup_failed"
	CodeGrantLookupRejected = "oauth_grant_lookup_rejected"
	CodeGrantRevokeFailed   = "oauth_grant_revoke_failed"
	CodeGrantRevokeRejected = "oauth_grant_revoke_rejected"
)

// grantsDescription is the client-safe text of every grant operation's
// Unavailable error.
const grantsDescription = "grants are temporarily unavailable"

// grantsFirstPage is the cursor bound of the first page, as for agents
// (agentsFirstPage): every id is below it.
const grantsFirstPage = "g"

// maxGrantStatements is the most statements CreateGrant runs: the agent, the code's
// secret and the grant.
const maxGrantStatements = 3

// GrantAgentScopes is the scope list of an agent that consent creates: empty. A
// grant carries no authsu scopes, so an agent made for one holds none either.
// The write binds it as an argument, so no caller can give such an agent more.
const GrantAgentScopes = "[]"

// The refusals of CreateGrant. Each is the consent write's own reason for
// creating nothing, so the feature can answer the person approving, and none is
// a failure of the service. A write that fails for any other constraint, such
// as a collision of a generated id, comes back as the bare ErrConflict.
var (
	// ErrGrantReplayed means this consent was already used: its sealed request's
	// hash is on a grant (granted_from is UNIQUE). A double-click or a replay
	// creates neither a second grant nor a second agent.
	ErrGrantReplayed = errors.New("the consent was already used")

	// ErrAgentLimit means the user already has the most active agents they may
	// have, so the new agent was not created.
	ErrAgentLimit = errors.New("the user has the most active agents they may have")

	// ErrAgentUnavailable means the agent the grant was to attach to is not
	// there, is not the user's, is revoked, or is in a sandbox. The write cannot
	// tell which, and they are answered alike so that a request cannot probe
	// another user's agents.
	ErrAgentUnavailable = errors.New("the agent is not an active agent of the user")

	// ErrUserInactive means the account was revoked after the request was
	// authenticated.
	ErrUserInactive = errors.New("the account is revoked")

	// ErrSessionInactive means the session that approved is no longer active, or
	// is not the user's: it was ended (logout, revocation) or expired after the
	// request was authenticated.
	ErrSessionInactive = errors.New("the approving session is no longer active")
)

// FirstPartyAgentScopes is the scope list of the agent a first-party login
// creates: empty, as for any agent consent creates (GrantAgentScopes).
const FirstPartyAgentScopes = GrantAgentScopes

// GrantAgent is an agent that consent creates for a grant.
type GrantAgent struct {
	// Name is the label the user gave it.
	Name input.AgentName

	// MaxActive is how many active agents a user may have: the create is
	// refused when the owner already has that many.
	MaxActive int
}

// NewGrant is an OAuth grant as consent writes it: its authorization code, the
// grant row and, when the user chose to create one, its agent. The caller has
// already issued the code: the store only records its hash.
type NewGrant struct {
	// ID is the grant's id, which is also its secret's id, and stays its id
	// when the code is rotated into a refresh token. Owner is the user who
	// approved, and the grant's subject.
	ID    string
	Owner string

	// AgentID is the agent that holds the grant. With NewAgent nil it is an
	// existing agent of the owner, which must be active; with NewAgent set it is
	// the id of the agent to create, a fresh UUIDv7 (GrantAgentScopes, none).
	AgentID  string
	NewAgent *GrantAgent

	// FirstParty is set for a first-party login (resource.Entry.FirstParty), where
	// nobody chooses an agent: the grant is held by the agent authsu keeps for
	// this owner and ClientID (agents.first_party_client), which the write creates
	// under AgentID with the name FirstPartyName if the owner has none, and
	// otherwise finds. It is an ordinary agent, flagged first_party, so it is
	// listed, counted against the limit and revocable. NewAgent must be nil.
	FirstParty          bool
	FirstPartyName      input.AgentName
	FirstPartyMaxActive int

	// What the user approved, stored on the grant as it is: the client, the name
	// its metadata document gave it, the redirect URI, the resource, the scopes
	// at it, the PKCE challenge and the nonce (nil when the client sent none).
	// ClientName is bounded in bytes by input.MaxClientNameBytes where the
	// document is parsed.
	ClientID      input.ClientID
	ClientName    string
	RedirectURI   input.RedirectURI
	Resource      input.ResourceID
	Scope         input.OAuthScopes
	CodeChallenge input.CodeChallenge
	Nonce         *input.Nonce

	// SessionID is the secret id of the session that approved. The grant's
	// auth_time is that secret's created_at, read in the write, and the write
	// requires the session to be the owner's and active.
	SessionID string

	// GrantedFrom is the SHA-256 of the sealed pending request (32 bytes): the
	// single-use guard.
	GrantedFrom []byte

	// CodeHash is the SHA-256 of the authorization code (32 bytes): the code
	// itself is never stored.
	CodeHash []byte

	// RetainUntil is the expiry of the code-stage secret: the earliest the row
	// may be removed, and so the end of the replay guard (GrantedFrom lives on
	// the row). It is NOT when the code stops working: the code's own, much
	// shorter, life is enforced by the exchange write from the secret's creation
	// time (CodeExchange.CodeLifetime). It must be no earlier than the sealed
	// pending request's own expiry, or a removed row would let that request be
	// replayed into a second grant and agent: the caller passes consent time plus
	// the request's whole lifetime, which is later than the request's expiry
	// because the request was sealed before it was approved. The exchange
	// replaces it with the refresh token's expiry.
	RetainUntil time.Time

	// CreatedAt is when consent was given, and the instant "active" is judged at.
	CreatedAt time.Time
}

// insertGrantQuery writes the grant's own row, after its secret
// (insertSecretQuery) and, when the user chose to create an agent, after the
// agent (insertAgentQuery), in the same batch. Every condition on consent is
// part of this write, because D1 has no interactive transaction and a read
// before it would race: an account revoked, an agent revoked, or a session
// logged out between the request's authentication and here must create nothing.
//
// A conditional INSERT ... SELECT that matches nothing is not an error, and the
// statements before this one in the batch do not depend on it. So each
// condition is a subselect that is NULL when it fails, for a NOT NULL column:
// the batch then fails as a constraint failure, which rolls back the agent and
// the secret with it, and which column failed says why (see CreateGrant):
//
//   - user_id is read from users and must be an active account;
//   - agent_id is read from agents and must be the owner's own, active and in
//     no sandbox. A grant is a credential an outside service holds, and an agent
//     of a sandbox is confined to it and reaches nothing else, so consent
//     cannot attach one (the agent reads as unavailable, as a revoked one
//     does). For an agent created in this batch the subselect finds it; when
//     the agent insert matched nothing (the account was revoked, or the user
//     was at the limit) it is NULL. For a first-party login (?16 is 1) it is the
//     owner's agent for this client (first_party_client), which must be active:
//     the agent ?4 would name is not used, so a first-party login cannot attach
//     to any agent the user chose. A revoked first-party agent is not it: the
//     agent insert of the same batch creates a fresh one in its place;
//   - auth_time is the created_at of the approving session's secret, which must
//     be that user's session and active at ?14. It is never taken from the
//     request.
//
// SQLite checks NOT NULL constraints in column order, user_id first, so an
// account that is revoked is reported as that and not as the missing agent it
// also caused. granted_from is UNIQUE, which is the replay guard: a second
// submission of the same consent finds the first one's row and fails here, and
// takes its own agent insert and secret back with it. The other columns of the
// table are bounded by CHECKs that only a bug in Go's parsers could fail.
//
// The kind of the session secret is bound, not written, as for every query.
//
// Arguments, by number: ?1 grant id, ?2 kind, ?3 user id, ?4 agent id, ?5
// client_id, ?6 client_name, ?7 redirect_uri, ?8 resource, ?9 scope, ?10
// code_challenge, ?11 nonce (NULL for none), ?12 the session's secret id, ?13
// the session kind, ?14 now (unix seconds), ?15 granted_from, ?16 whether the
// grant is a first-party login's (1), held by the owner's agent for ?5, or not
// (0), held by the agent ?4 names.
const insertGrantQuery = `
INSERT INTO oauth_grants (id, kind, user_id, agent_id, client_id, client_name, redirect_uri, resource, scope,
                          code_challenge, nonce, auth_time, granted_from)
VALUES (?1, ?2,
        (SELECT u.id FROM users u WHERE u.id = ?3 AND u.revoked_at IS NULL),
        (SELECT a.id FROM agents a WHERE a.user_id = ?3 AND a.revoked_at IS NULL AND a.sandbox_id IS NULL
                                         AND ((?16 = 0 AND a.id = ?4)
                                              OR (?16 = 1 AND a.first_party_client = ?5))),
        ?5, ?6, ?7, ?8, ?9, ?10, ?11,
        (SELECT s.created_at FROM secrets s JOIN sessions x ON x.id = s.id AND x.kind = s.kind
         WHERE s.id = ?12 AND s.kind = ?13 AND x.user_id = ?3
           AND (s.revoked_at IS NULL OR s.revoked_at > ?14) AND s.expires_at > ?14),
        ?15)`

// insertFirstPartyAgentQuery creates the agent of a first-party login if the
// owner has none for this client, in the batch of its consent and before the
// grant. It is insertAgentQuery with the first_party columns and the same
// conditions: the owner is active and has room (ownerHasRoomForAgent), so the
// agent counts against the limit as any does. The unique index
// (user_id, first_party_client) and ON CONFLICT DO NOTHING make the first login
// create it and a later one, or one racing it, find it.
//
// A user who already has the agent can sign in again at the limit: the room
// condition is waived when an active one exists, because nothing is added. A
// revoked agent does not count as existing: the unique index covers active agents
// only (the agents_first_party index), so after the user revokes it the
// next login creates a fresh agent, which needs room as any new one does. A user
// at the limit who has none gets no row, the grant's agent_id is NULL, and the
// batch fails as the limit, as for a consent that creates an agent.
//
// Arguments, by number: ?1 id, ?2 name, ?3 scopes, ?4 created_at, ?5 user id, ?6
// the maximum active agents a user may have, ?7 the client_id.
const insertFirstPartyAgentQuery = `
INSERT INTO agents (id, user_id, name, scopes, created_at, first_party, first_party_client)
SELECT ?1, u.id, ?2, ?3, ?4, 1, ?7
FROM users u
WHERE u.id = ?5
  AND u.revoked_at IS NULL
  AND (EXISTS (SELECT 1 FROM agents f WHERE f.user_id = u.id AND f.first_party_client = ?7
                      AND f.revoked_at IS NULL)
       OR ` + ownerHasRoomForAgent + `)
ON CONFLICT DO NOTHING`

// CreateGrant writes a grant for an approved request as one batch: the agent
// when the user chose to create one (for a first-party login, the agent authsu
// keeps for the client, created if the owner has none), the secret of the authorization code, and
// the grant's own row. Either all of them exist or none does.
//
// It returns one of the refusals above, wrapping the database's error for the
// log, when the consent cannot stand:
//
//   - ErrUserInactive: the account was revoked;
//   - ErrAgentLimit: a new agent was asked for and the user is at the limit;
//   - ErrAgentUnavailable: an existing agent was asked for and it is not the
//     user's, is revoked or is in a sandbox;
//   - ErrSessionInactive: the approving session ended or is not the user's;
//   - ErrGrantReplayed: this consent was already used.
//
// Which condition failed is read from the constraint the database names (see
// insertGrantQuery). Several can hold at once and the first in that order is
// reported; in particular a consent replayed after it took the user to the agent
// limit is reported as the limit, not as a replay: either way it creates
// nothing, and the first request's response is the one that mattered. Any
// failure it cannot attribute (the generated ids and hash are fresh, so a
// collision on them is as unlikely as one of 256 random bits) is the bare
// ErrConflict.
func (s *Store) CreateGrant(ctx context.Context, grant NewGrant) error {
	o := op{failed: CodeGrantCreateFailed, rejected: CodeGrantCreateRejected, description: grantsDescription}

	created := grant.CreatedAt.Unix()

	var nonce any
	if grant.Nonce != nil {
		nonce = grant.Nonce.String()
	}

	statements := make([]Statement, 0, maxGrantStatements)

	switch {
	case grant.FirstParty:
		statements = append(statements,
			Statement{Query: insertFirstPartyAgentQuery, Args: []any{
				grant.AgentID, grant.FirstPartyName.String(), FirstPartyAgentScopes, created, grant.Owner,
				int64(grant.FirstPartyMaxActive), grant.ClientID.String(),
			}})
	case grant.NewAgent != nil:
		statements = append(statements, agentInsert(
			grant.AgentID, grant.NewAgent.Name.String(), GrantAgentScopes, created, grant.Owner,
			grant.NewAgent.MaxActive, ""))
	}

	firstParty := int64(0)
	if grant.FirstParty {
		firstParty = 1
	}

	statements = append(statements,
		insertSecret(grant.ID, KindOAuthGrant, grant.CodeHash, grant.RetainUntil.Unix(), created),
		Statement{Query: insertGrantQuery, Args: []any{
			grant.ID, KindOAuthGrant, grant.Owner, grant.AgentID, grant.ClientID.String(), grant.ClientName,
			grant.RedirectURI.String(), grant.Resource.String(), grant.Scope.String(), grant.CodeChallenge.String(),
			nonce, grant.SessionID, KindSession, created, grant.GrantedFrom, firstParty,
		}},
	)

	_, err := s.run(ctx, o, statements...)

	return refuseGrant(err, grant.NewAgent != nil || grant.FirstParty)
}

// refuseGrant names the refusal a failed CreateGrant batch is: see CreateGrant.
// newAgent says whether the batch could create an agent (a chosen new one, or a
// first-party login's), which is what a missing agent_id means.
func refuseGrant(err error, newAgent bool) error {
	if err == nil || !errors.Is(err, ErrConflict) {
		return err
	}

	// The first that names its column is the one reported, in the order the
	// database checks them (user_id first).
	agentID := ErrAgentUnavailable
	if newAgent {
		agentID = ErrAgentLimit
	}

	for _, refusal := range []struct {
		column string
		is     error
	}{
		{"oauth_grants.user_id", ErrUserInactive},
		{"oauth_grants.agent_id", agentID},
		{"oauth_grants.auth_time", ErrSessionInactive},
		{"oauth_grants.granted_from", ErrGrantReplayed},
	} {
		if failedOn(err, refusal.column) {
			return fmt.Errorf("%w: %w", refusal.is, err)
		}
	}

	return err
}

// failedOn reports whether the database's error text names the column
// ("oauth_grants.agent_id"), which is how SQLite says which constraint a write
// broke: "NOT NULL constraint failed: oauth_grants.agent_id". D1 gives nothing
// but this text to tell constraints apart by, as Classify does.
func failedOn(err error, column string) bool {
	return strings.Contains(err.Error(), column)
}

// Grant is one of a user's OAuth grants as stored, with its secret's times and
// the agent that holds it. It never carries a token or its hash: no query here
// selects them. Every grant row is one, whether or not its code was exchanged:
// whether an access token row exists says nothing about it (it is removed once
// its secret expires and is swept, while the grant lives on for its refresh
// token's 30 days), so it is never a filter. A grant whose code has not been
// exchanged is visible, and revocable, until its row is removed.
type Grant struct {
	ID string

	// AgentID is the agent that holds the grant, and AgentName its name now.
	AgentID   string
	AgentName string

	// ClientID is the client's metadata URL and ClientName the name its document
	// gave when the user approved.
	ClientID   string
	ClientName string

	// Resource is the resource server the grant is for, and Scope the scopes
	// approved at it, space-delimited, as input.OAuthScopes stores them.
	Resource string
	Scope    string

	// ExpiresAt, CreatedAt are Unix seconds, and RevokedAt is nil for a grant
	// that is not revoked. They are the grant's secret's: ExpiresAt is when the
	// refresh token lapses (30 days from its last exchange; for a grant whose
	// code was not exchanged, when its row may be removed, which is later than
	// the code's own minute: NewGrant.RetainUntil) and CreatedAt when the user
	// approved. A grant is expired once ExpiresAt has passed, whether or not it
	// was revoked.
	ExpiresAt int64
	RevokedAt *int64
	CreatedAt int64
}

// readGrant reads one grant row, in the column order every grant statement
// selects: id, agent_id, agent_name, client_id, client_name, resource, scope,
// expires_at, revoked_at, created_at.
func readGrant(r *row) Grant {
	// Struct fields are evaluated in order, which is the column order.
	return Grant{
		ID: r.text(), AgentID: r.text(), AgentName: r.text(), ClientID: r.text(), ClientName: r.text(),
		Resource: r.text(), Scope: r.text(),
		ExpiresAt: r.integer(), RevokedAt: r.optInteger(), CreatedAt: r.integer(),
	}
}

// grantListQuery reads one page of a user's grants, revoked and expired ones
// included, newest first, with keyListQuery's paging: the id is a UUIDv7, so it
// is the sort key and the cursor, and a page asks for one row more than it
// returns.
//
// A grant's expiry, revocation and creation time are on its secret, joined on
// the id and the kind together, as the schema's foreign key is. The owner is
// part of the match, so a user's page holds only their grants. There is no
// condition on the grant's access token: its row goes when its secret expires
// and is swept, 15 minutes after an exchange, while the grant it belongs to is
// good for 30 days, so "has an access token" would hide a live grant that its
// user could then neither see nor revoke. A grant whose code was never
// exchanged is listed for as long as its row is kept. The agent is joined for
// its name. The token's hash is not selected.
//
// Arguments, by number: ?1 user id, ?2 cursor (the id to start below;
// grantsFirstPage for the first page), ?3 rows wanted.
const grantListQuery = `
SELECT g.id AS id, g.agent_id AS agent_id, a.name AS agent_name, g.client_id AS client_id,
       g.client_name AS client_name, g.resource AS resource, g.scope AS scope,
       s.expires_at AS expires_at, s.revoked_at AS revoked_at, s.created_at AS created_at
FROM oauth_grants g
JOIN secrets s ON s.id = g.id AND s.kind = g.kind
JOIN agents a ON a.id = g.agent_id
WHERE g.user_id = ?1 AND g.id < ?2
ORDER BY g.id DESC
LIMIT ?3`

// GrantPage is one page of a user's grants, newest first.
type GrantPage struct {
	Grants []Grant

	// Next is the cursor of the following page: the id of the last grant of this
	// one. It is empty on the last page.
	Next string
}

// ListGrants returns up to limit of the user's grants with an id below the
// cursor, revoked and expired ones included, newest first. An empty cursor
// starts at the newest grant. owner is the authenticated user's id.
func (s *Store) ListGrants(
	ctx context.Context, owner string, cursor input.Cursor, limit input.PageLimit,
) (GrantPage, error) {
	o := op{failed: CodeGrantListFailed, rejected: CodeGrantListRejected, description: grantsDescription}

	before := grantsFirstPage
	if id, ok := cursor.ID(); ok {
		before = id.String()
	}

	// A PageLimit made by its parser is at least 1; the zero value is read as 1.
	size := max(limit.Int(), 1)
	wanted := size + 1

	grants, err := queryAll(ctx, s, o,
		Statement{Query: grantListQuery, Args: []any{owner, before, int64(wanted)}}, readGrant)
	if err != nil {
		return GrantPage{}, err
	}

	page, next, err := paged(o, grants, size, func(grant Grant) string { return grant.ID })

	return GrantPage{Grants: page, Next: next}, err
}

// grantGetQuery reads one of a user's grants, with the columns of grantListQuery
// and the same conditions: the owner is part of the match, so another user's
// grant is not found, which is what the caller is told for an id that does not
// exist at all.
//
// Arguments, by number: ?1 id, ?2 user id.
const grantGetQuery = `
SELECT g.id AS id, g.agent_id AS agent_id, a.name AS agent_name, g.client_id AS client_id,
       g.client_name AS client_name, g.resource AS resource, g.scope AS scope,
       s.expires_at AS expires_at, s.revoked_at AS revoked_at, s.created_at AS created_at
FROM oauth_grants g
JOIN secrets s ON s.id = g.id AND s.kind = g.kind
JOIN agents a ON a.id = g.agent_id
WHERE g.id = ?1 AND g.user_id = ?2`

// GetGrant returns one of the user's grants. It returns ErrNotFound when the
// user has no such grant, which includes an id that belongs to someone else.
func (s *Store) GetGrant(ctx context.Context, owner string, id input.ID) (Grant, error) {
	o := op{failed: CodeGrantLookupFailed, rejected: CodeGrantLookupRejected, description: grantsDescription}

	return queryOne(ctx, s, o, Statement{Query: grantGetQuery, Args: []any{id.String(), owner}}, readGrant)
}

// grantRevokeQuery revokes the secret of one of a user's grants, now. The grant
// must be the user's, in the write itself: an id that is not the user's, or
// names a session or a key, matches nothing, whatever else it names. A grant
// whose code was not exchanged is revoked like any other, and its code can no
// longer be exchanged: the exchange requires the secret to be active.
//
// Only a secret that is not yet revoked as of now is changed, as for keys: one
// scheduled to be revoked later is brought forward to now, and one already
// revoked keeps its earlier time, so revoking twice cannot move a revocation
// later. An expired grant is revoked like any other: the time recorded is when
// the user ended it.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 grant id, ?3 user id.
const grantRevokeQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE id = ?2
  AND (revoked_at IS NULL OR revoked_at > ?1)
  AND id IN (SELECT g.id FROM oauth_grants g
             WHERE g.id = ?2 AND g.user_id = ?3)`

// grantRevokeAccessQuery revokes the secret of the access token of the same
// grant, in the same batch as grantRevokeQuery and after it, under the same
// conditions on the grant and the same rule for a revocation already due. A
// grant's access token must stop with it: introspection joins the grant's own
// secret as well, but the secrets table is kept honest, as for an account's.
//
// Arguments, by number: ?1 revoked_at (unix seconds), ?2 grant id, ?3 user id.
const grantRevokeAccessQuery = `
UPDATE secrets
SET revoked_at = ?1
WHERE (revoked_at IS NULL OR revoked_at > ?1)
  AND id IN (SELECT t.id FROM oauth_access_tokens t
             JOIN oauth_grants g ON g.id = t.grant_id
             WHERE g.id = ?2 AND g.user_id = ?3)`

// RevokeGrant revokes one of the user's grants as of now and returns it as the
// writes left it: the grant's secret, which ends its refresh token, and its
// access token's. Revoking a grant that is already revoked succeeds and keeps
// the earlier time, so the call is idempotent. Other grants, and the agent that
// holds it, are not touched. It returns ErrNotFound when the user has no such
// grant, which includes one that belongs to someone else, and in that case no
// secret is touched. A grant whose code was not yet exchanged is revoked like
// any other, and that code is then refused at the exchange.
//
// As for the other revokes, a constraint failure of any kind is a defect: the
// writes set nothing the data could collide with.
func (s *Store) RevokeGrant(ctx context.Context, owner string, id input.ID, now time.Time) (Grant, error) {
	o := op{failed: CodeGrantRevokeFailed, rejected: CodeGrantRevokeRejected, description: grantsDescription}

	results, err := s.run(ctx, o,
		Statement{Query: grantRevokeQuery, Args: []any{now.Unix(), id.String(), owner}},
		Statement{Query: grantRevokeAccessQuery, Args: []any{now.Unix(), id.String(), owner}},
		Statement{Query: grantGetQuery, Args: []any{id.String(), owner}},
	)
	if err != nil {
		return Grant{}, rejectGrantConflict(o, err)
	}

	return one(results[2].Rows, o, readGrant)
}

// rejectGrantConflict turns a conflict into a defect for an operation that
// writes nothing a constraint of the data could refuse: run passes a conflict
// through for the operation to hand to its feature, and there is none here. Any
// other error is returned as is.
func rejectGrantConflict(o op, err error) error {
	if errors.Is(err, ErrConflict) {
		return o.defect(err)
	}

	return err
}
