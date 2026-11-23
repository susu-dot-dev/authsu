//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Everything this file defines at package level is prefixed "grant" or "oauth" so
// that it cannot collide with the helpers of another area's test file. The
// builders for the OAuth input types are shared with oauth_tokens_test.go and
// oauth_schema_test.go.

const (
	grantsUnavailable = "grants are temporarily unavailable"
	grantOwner        = "user-1"
	grantTarget       = "01900000-0000-7000-8000-000000000042"
	grantAgent        = "01900000-0000-7000-8000-0000000000a1"
	grantSession      = "01900000-0000-7000-8000-0000000000b1"
	grantNewAgent     = "01900000-0000-7000-8000-0000000000c1"
)

// grantIDAt returns the canonical id of the n-th grant. A larger n is a later
// grant and sorts higher.
func grantIDAt(n int) string { return fmt.Sprintf("01900000-0000-7000-8000-%012d", n) }

// grantRowAt is a returned grant row: id, agent_id, agent_name, client_id,
// client_name, resource, scope, expires_at, revoked_at, created_at.
func grantRowAt(n int) []any {
	return row(grantIDAt(n), agentIDAt(n), "bot "+strconv.Itoa(n), "https://client.example.com/app", "Client",
		resource.ProductionURL, "mcp:read openid", int64(1_800_000_000+n), nil, int64(1_700_000_000+n))
}

// grantRow is the row of the grant grantTarget.
func grantRow() []any {
	return row(grantTarget, grantAgent, "build bot", "https://client.example.com/app", "Client",
		resource.ProductionURL, "mcp:read openid", int64(1_800_000_000), nil, int64(1_700_000_000))
}

// grantRevokedRow is grantRow once it is revoked.
func grantRevokedRow() []any { return with(grantRow(), 8, int64(1_700_000_100)) }

// grantColumnKinds are the column kinds of a grant row, for defectResults.
func grantColumnKinds() []string {
	return []string{
		"text", "text", "text", "text", "text", "text", "text", "integer", "optInteger", "integer",
	}
}

// oauthTable is the production table of resource servers, and oauthDevTable the
// development one, which allows a localhost client.
//
//nolint:gochecknoglobals // fixed tables shared by the tests
var (
	oauthTable    = resource.Select("https://auth.susu.dev")
	oauthDevTable = resource.Select("http://localhost:8787")
)

const (
	oauthClient   = "https://client.example.com/app"
	oauthRedirect = "https://client.example/cb"
)

func mustClientID(tb testing.TB, raw string, table resource.Table) input.ClientID {
	tb.Helper()

	id, err := input.ParseClientID(raw, table)
	if err != nil {
		tb.Fatalf("parse client_id %q: %v", raw, err)
	}

	return id
}

func mustRedirectURI(tb testing.TB, raw string) input.RedirectURI {
	tb.Helper()

	uri, err := input.ParseRedirectURI(raw)
	if err != nil {
		tb.Fatalf("parse redirect_uri %q: %v", raw, err)
	}

	return uri
}

func mustResourceID(tb testing.TB) input.ResourceID {
	tb.Helper()

	id, err := input.ParseResourceID(resource.ProductionURL, oauthTable)
	if err != nil {
		tb.Fatalf("parse resource: %v", err)
	}

	return id
}

func mustOAuthScopes(tb testing.TB, raw string) input.OAuthScopes {
	tb.Helper()

	entry := mustResourceID(tb).Entry()

	scopes, err := input.ParseOAuthScopes(raw, true, entry)
	if err != nil {
		tb.Fatalf("parse scope %q: %v", raw, err)
	}

	return scopes
}

func mustVerifier(tb testing.TB, raw string) input.CodeVerifier {
	tb.Helper()

	verifier, err := input.ParseCodeVerifier(raw)
	if err != nil {
		tb.Fatalf("parse code verifier %q: %v", raw, err)
	}

	return verifier
}

func mustNonce(tb testing.TB, raw string) input.Nonce {
	tb.Helper()

	nonce, err := input.ParseNonce(raw)
	if err != nil {
		tb.Fatalf("parse nonce %q: %v", raw, err)
	}

	return nonce
}

func mustAuthorizationCode(tb testing.TB, seed byte) input.AuthorizationCode {
	tb.Helper()

	token, err := input.ParseAuthorizationCode(tokenOf(tb, secret.TagOAuthCode, seed))
	if err != nil {
		tb.Fatalf("parse authorization code: %v", err)
	}

	return token
}

func mustRefreshToken(tb testing.TB, seed byte) input.RefreshToken {
	tb.Helper()

	token, err := input.ParseRefreshToken(tokenOf(tb, secret.TagOAuthRefresh, seed))
	if err != nil {
		tb.Fatalf("parse refresh token: %v", err)
	}

	return token
}

func mustAccessToken(tb testing.TB, seed byte) input.AccessToken {
	tb.Helper()

	token, err := input.ParseAccessToken(tokenOf(tb, secret.TagOAuthAccess, seed))
	if err != nil {
		tb.Fatalf("parse access token: %v", err)
	}

	return token
}

func mustGrantID(tb testing.TB) input.ID {
	tb.Helper()

	id, err := input.ParseID(grantTarget)
	if err != nil {
		tb.Fatalf("parse id %q: %v", grantTarget, err)
	}

	return id
}

// grantRead is one operation that reads a grant row, for the tables that hold for
// all of them.
type grantRead struct {
	name     string
	rejected string

	// one is true when the operation reads exactly one row, false for a page.
	one bool

	// outcome is the batch the operation gets for the rows its read returned.
	outcome func(rows ...[]any) outcome

	// call runs the operation and returns the grants it read.
	call func(*store.Store) ([]store.Grant, error)
}

// afterRevokes is the batch of the two writes of a grant revoke followed by the
// read of the grant: the writes changed secrets, and the read returned rows.
func afterRevokes(rows ...[]any) outcome {
	return outcome{results: []store.Result{
		{Changes: 1, Rows: nil}, {Changes: 1, Rows: nil}, {Changes: 0, Rows: rows},
	}, err: nil}
}

// grantReadOps are the operations that decode grant rows.
func grantReadOps(t *testing.T) []grantRead {
	t.Helper()

	ctx := context.Background()
	id := mustGrantID(t)

	single := func(grant store.Grant, err error) ([]store.Grant, error) { return []store.Grant{grant}, err }

	return []grantRead{
		{
			name: "list", rejected: store.CodeGrantListRejected, one: false, outcome: returning,
			call: func(s *store.Store) ([]store.Grant, error) {
				page, err := s.ListGrants(ctx, grantOwner, mustAgentCursor(t), mustAgentLimit(t))

				return page.Grants, passErr(err)
			},
		},
		{
			name: "get", rejected: store.CodeGrantLookupRejected, one: true, outcome: returning,
			call: func(s *store.Store) ([]store.Grant, error) { return single(s.GetGrant(ctx, grantOwner, id)) },
		},
		{
			name: "revoke", rejected: store.CodeGrantRevokeRejected, one: true, outcome: afterRevokes,
			call: func(s *store.Store) ([]store.Grant, error) { return single(s.RevokeGrant(ctx, grantOwner, id, now)) },
		},
	}
}

// TestGrantDecoding holds how a returned row becomes a Grant, for every operation
// that reads one: they share a reader.
func TestGrantDecoding(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)

	tests := []struct {
		name string
		row  []any
		want store.Grant
	}{
		{name: "an active grant", row: grantRow(), want: store.Grant{
			ID: grantTarget, AgentID: grantAgent, AgentName: "build bot", ClientID: "https://client.example.com/app",
			ClientName: "Client", Resource: resource.ProductionURL, Scope: "mcp:read openid", ExpiresAt: 1_800_000_000,
			RevokedAt: nil, CreatedAt: 1_700_000_000,
		}},
		{name: "a revoked grant", row: grantRevokedRow(), want: store.Grant{
			ID: grantTarget, AgentID: grantAgent, AgentName: "build bot", ClientID: "https://client.example.com/app",
			ClientName: "Client", Resource: resource.ProductionURL, Scope: "mcp:read openid", ExpiresAt: 1_800_000_000,
			RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
		}},
		{name: "multibyte names are kept as they are", row: with(with(grantRow(), 2, "ボット 🤖"), 4, "デプロイ 🔑"),
			want: store.Grant{
				ID: grantTarget, AgentID: grantAgent, AgentName: "ボット 🤖", ClientID: "https://client.example.com/app",
				ClientName: "デプロイ 🔑", Resource: resource.ProductionURL, Scope: "mcp:read openid",
				ExpiresAt: 1_800_000_000, RevokedAt: nil, CreatedAt: 1_700_000_000,
			}},
		{name: "the scopes are the stored text", row: with(grantRow(), 6, "mcp:read"), want: store.Grant{
			ID: grantTarget, AgentID: grantAgent, AgentName: "build bot", ClientID: "https://client.example.com/app",
			ClientName: "Client", Resource: resource.ProductionURL, Scope: "mcp:read", ExpiresAt: 1_800_000_000,
			RevokedAt: nil, CreatedAt: 1_700_000_000,
		}},
	}

	for _, op := range grantReadOps(t) {
		for _, test := range tests {
			t.Run(op.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(op.outcome(test.row))

				got, err := op.call(fake.store())
				checkErr(t, err, nil)

				if !reflect.DeepEqual(got, []store.Grant{test.want}) {
					t.Errorf("grants = %+v, want %+v", got, test.want)
				}
			})
		}
	}
}

// TestGrantDefects holds that a row that is not the grant the statement promises
// is a defect and not a missing grant or a wrong one.
func TestGrantDefects(t *testing.T) {
	t.Parallel()

	for _, op := range grantReadOps(t) {
		for name, rows := range defectResults(grantRow(), grantColumnKinds()...) {
			// Two rows is a defect only where one row is promised; a page may hold
			// several.
			if name == "two rows" && !op.one {
				continue
			}

			t.Run(op.name+"/"+name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(op.outcome(rows...))

				got, err := op.call(fake.store())

				checkErr(t, err, defectOf(op.rejected))

				if len(got) > 0 && got[0].ID != "" {
					t.Errorf("a defective row returned %+v", got)
				}
			})
		}
	}
}

// TestGrantNoRowIsNotFound holds that no row from a statement aimed at one grant
// is the grant not being there, an unclassified sentinel for the feature to
// name.
func TestGrantNoRowIsNotFound(t *testing.T) {
	t.Parallel()

	for _, op := range grantReadOps(t) {
		if !op.one {
			continue
		}

		t.Run(op.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(op.outcome())

			_, err := op.call(fake.store())
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}

			if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
				t.Errorf("a missing grant %v is classified; the feature must decide that", err)
			}
		})
	}
}

// checkGrantPage asserts the page a grants read produced.
func checkGrantPage(t *testing.T, page store.GrantPage, fake *fakeExec, test keyPaging) {
	t.Helper()

	if page.Grants == nil {
		t.Fatalf("page has nil grants, want %d", test.keys)
	}

	ids := make([]string, len(page.Grants))
	for i, grant := range page.Grants {
		ids[i] = grant.ID
	}

	checkPage(t, pageResult{ids: ids, next: page.Next, args: fake.calls[0][0].Args, argc: 3, idAt: grantIDAt},
		pageWant{size: test.size, ids: test.keys, next: test.next})
}

// listGrantsPage runs ListGrants over a database that returned the given number
// of rows, newest first, for a page of the given size.
func listGrantsPage(t *testing.T, returned int, limit input.PageLimit) (store.GrantPage, *fakeExec) {
	t.Helper()

	rows := make([][]any, returned)
	for i := range rows {
		rows[i] = grantRowAt(1000 - i)
	}

	fake := newFake(returning(rows...))

	page, err := fake.store().ListGrants(context.Background(), grantOwner, mustAgentCursor(t), limit)
	checkErr(t, err, nil)

	return page, fake
}

// TestListGrantsPaging holds how the rows of a page become the page: the query
// asks for one row more than the page holds, and that extra row only says there
// is a next page, whose cursor is the last grant that is returned.
func TestListGrantsPaging(t *testing.T) {
	t.Parallel()

	for name, test := range keyPagingCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			page, fake := listGrantsPage(t, test.returned, pageLimitOf(t, test.size))

			checkGrantPage(t, page, fake, test)
		})
	}

	t.Run("a zero PageLimit is read as 1", func(t *testing.T) {
		t.Parallel()

		page, fake := listGrantsPage(t, 2, input.PageLimit{})

		checkGrantPage(t, page, fake, keyPaging{size: 1, returned: 2, keys: 1, next: true})
	})
}

// TestListGrantsMoreRowsThanAsked holds that a database that returns more rows
// than the LIMIT it was given is a defect.
func TestListGrantsMoreRowsThanAsked(t *testing.T) {
	t.Parallel()

	fake := newFake(returning(grantRowAt(5), grantRowAt(4), grantRowAt(3)))

	page, err := fake.store().ListGrants(context.Background(), grantOwner, mustAgentCursor(t), mustAgentLimit(t, "1"))

	checkErr(t, err, defectOf(store.CodeGrantListRejected))

	if page.Grants != nil || page.Next != "" {
		t.Errorf("a defective page returned %+v", page)
	}
}

// grantReadFragments are the guards both reads of a grant carry: the grant's
// secret is joined on the id and the kind together, and the agent for its name.
// Nothing here may depend on the grant's access token (see
// TestGrantVisibilityDoesNotDependOnAccessTokens).
func grantReadFragments() []string {
	return []string{
		"FROM oauth_grants g",
		"JOIN secrets s ON s.id = g.id AND s.kind = g.kind",
		"JOIN agents a ON a.id = g.agent_id",
	}
}

// TestListGrantsStatement pins the query's guards and its arguments in
// placeholder order: the owner scopes the page, the cursor is an exclusive upper
// bound on the id, and the first page has a bound above every id.
func TestListGrantsStatement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cursor input.Cursor
		limit  input.PageLimit
		before string
		rows   int64
	}{
		{name: "first page", cursor: mustAgentCursor(t), limit: mustAgentLimit(t), before: "", rows: 26},
		{name: "after a cursor", cursor: mustAgentCursor(t, agentCursorID), limit: mustAgentLimit(t, "7"),
			before: agentCursorID, rows: 8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, err := fake.store().ListGrants(context.Background(), grantOwner, test.cursor, test.limit)
			checkErr(t, err, nil)

			before := test.before
			if before == "" {
				before = store.GrantsFirstPage
			}

			checkBatch(t, fake, wantStatement{
				fragments: append(grantReadFragments(),
					"WHERE g.user_id = ?1 AND g.id < ?2",
					"ORDER BY g.id DESC",
					"LIMIT ?3",
				),
				args: []any{grantOwner, before, test.rows},
			})
		})
	}
}

// TestListGrantsFailures holds how a failed or malformed batch is reported.
func TestListGrantsFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeGrantListFailed, store.CodeGrantListRejected, grantsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.ListGrants(context.Background(), grantOwner, mustAgentCursor(t), mustAgentLimit(t)))
		})
}

// TestGetGrantStatement pins that the owner is part of the match, so another
// user's grant is not found, and the arguments in order.
func TestGetGrantStatement(t *testing.T) {
	t.Parallel()

	fake := newFake(returning(grantRow()))

	_, err := fake.store().GetGrant(context.Background(), grantOwner, mustGrantID(t))
	checkErr(t, err, nil)

	checkBatch(t, fake, wantStatement{
		fragments: append(grantReadFragments(), "WHERE g.id = ?1 AND g.user_id = ?2"),
		args:      []any{grantTarget, grantOwner},
	})
}

// TestGetGrantFailures holds how a failed or malformed batch is reported.
func TestGetGrantFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeGrantLookupFailed, store.CodeGrantLookupRejected, grantsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.GetGrant(context.Background(), grantOwner, mustGrantID(t)))
		})
}

// createGrantCase is a consent and the batch it writes.
type createGrantCase struct {
	name  string
	grant store.NewGrant

	// agent is the statement an agent that is created adds, nil for an existing
	// agent.
	newAgent bool

	// firstParty is the statement a first-party login adds: the owner's agent for
	// the client, created if there is none.
	firstParty bool
}

func createGrantCases(t *testing.T) []createGrantCase {
	t.Helper()

	typical := store.NewGrant{
		ID: grantTarget, Owner: grantOwner, AgentID: grantAgent, NewAgent: nil,
		ClientID: mustClientID(t, oauthClient, oauthTable), ClientName: "Client",
		RedirectURI: mustRedirectURI(t, oauthRedirect), Resource: mustResourceID(t),
		Scope:         mustOAuthScopes(t, "mcp:read openid"),
		CodeChallenge: mustVerifier(t, strings.Repeat("a", 43)).Challenge(), Nonce: nil,
		SessionID: grantSession, GrantedFrom: hashOf(2), CodeHash: hashOf(1),
		RetainUntil: now.Add(10 * time.Minute), CreatedAt: now,
	}

	nonce := mustNonce(t, "n-0S6_WzA2Mj")
	agentName := mustAgentName(t, "ボット 🤖")

	withAgent := typical
	withAgent.ID, withAgent.AgentID = grantIDAt(7), grantNewAgent
	withAgent.NewAgent = &store.GrantAgent{Name: agentName, MaxActive: 25}
	withAgent.Nonce = &nonce
	withAgent.ClientName = "デプロイ 🔑"
	withAgent.Scope = mustOAuthScopes(t, "mcp:write")
	withAgent.CodeChallenge = mustVerifier(t, strings.Repeat("Zy-._~9", 10)).Challenge()
	withAgent.SessionID, withAgent.GrantedFrom, withAgent.CodeHash = grantIDAt(9), hashOf(4), hashOf(3)
	withAgent.RetainUntil, withAgent.CreatedAt = now.Add(12*time.Minute), now.Add(time.Second)

	login := typical
	login.ID, login.AgentID = grantIDAt(11), grantNewAgent
	login.FirstParty, login.FirstPartyMaxActive = true, 25
	login.FirstPartyName = mustAgentName(t, "Pages 🌐")
	login.Scope = mustOAuthScopes(t, "mcp:read")
	login.SessionID, login.GrantedFrom, login.CodeHash = grantIDAt(13), hashOf(6), hashOf(5)

	return []createGrantCase{
		{name: "an existing agent and no nonce", grant: typical, newAgent: false},
		{name: "a new agent, a nonce and multibyte names", grant: withAgent, newAgent: true},
		{name: "a first-party login", grant: login, firstParty: true},
	}
}

// firstPartyAgentWant is the statement that creates the agent of a first-party
// login, or finds the active one the owner has for the client.
func firstPartyAgentWant(grant store.NewGrant) wantStatement {
	return wantStatement{
		fragments: []string{
			"INSERT INTO agents (id, user_id, name, scopes, created_at, first_party, first_party_client)",
			"SELECT ?1, u.id, ?2, ?3, ?4, 1, ?7",
			"WHERE u.id = ?5 AND u.revoked_at IS NULL",
			// An agent the owner already has for the client is found and is not
			// held to the limit; one that is not there is created within it.
			// A revoked agent is not found: the user gets a fresh one, within the limit.
			"AND (EXISTS (SELECT 1 FROM agents f WHERE f.user_id = u.id AND f.first_party_client = ?7 " +
				"AND f.revoked_at IS NULL) " +
				"OR (SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL",
			") < ?6)",
			"ON CONFLICT DO NOTHING",
		},
		args: []any{
			grant.AgentID, grant.FirstPartyName.String(), "[]", grant.CreatedAt.Unix(), grant.Owner,
			int64(grant.FirstPartyMaxActive), grant.ClientID.String(),
		},
	}
}

// createGrantWant is the batch a consent must write.
func createGrantWant(grant store.NewGrant, newAgent, firstParty bool) []wantStatement {
	var nonce any
	if grant.Nonce != nil {
		nonce = grant.Nonce.String()
	}

	var want []wantStatement

	if firstParty {
		want = append(want, firstPartyAgentWant(grant))
	}

	if newAgent {
		want = append(want, wantStatement{
			fragments: []string{
				"INSERT INTO agents (id, user_id, name, scopes, created_at, sandbox_id)",
				// The owner is read from users and must be active, and the limit
				// counts the owner's active agents in the write.
				"WHERE u.id = ?5 AND u.revoked_at IS NULL",
				"AND (SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL",
				"AND (a.sandbox_id IS NULL OR EXISTS (SELECT 1 FROM orgs g WHERE g.id = a.sandbox_id AND g.expires_at > ?4))) < ?6",
			},
			// A consent never puts the agent it creates in a sandbox: ?7 is NULL.
			args: []any{
				grant.AgentID, grant.NewAgent.Name.String(), "[]", grant.CreatedAt.Unix(), grant.Owner,
				int64(grant.NewAgent.MaxActive), nil, store.OrgKindSandbox,
			},
		})
	}

	firstPartyArg := int64(0)
	if firstParty {
		firstPartyArg = 1
	}

	return append(want,
		wantStatement{
			fragments: []string{"INSERT INTO secrets (id, kind, hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"},
			args: []any{
				grant.ID, store.KindOAuthGrant, grant.CodeHash, grant.RetainUntil.Unix(), grant.CreatedAt.Unix(),
			},
		},
		wantStatement{
			fragments: []string{
				"INSERT INTO oauth_grants (id, kind, user_id, agent_id, client_id, client_name, redirect_uri, " +
					"resource, scope, code_challenge, nonce, auth_time, granted_from)",
				// The account must be active.
				"(SELECT u.id FROM users u WHERE u.id = ?3 AND u.revoked_at IS NULL)",
				// The agent must be the owner's, active and in no sandbox: one
				// created in this batch is found, and none is NULL. An agent of a
				// sandbox reads as unavailable, so consent cannot attach one. For
				// an ordinary consent it is the agent ?4 names; for a first-party
				// login (?16) it is the owner's agent for the client and never one
				// the user chose.
				"(SELECT a.id FROM agents a WHERE a.user_id = ?3 AND a.revoked_at IS NULL " +
					"AND a.sandbox_id IS NULL AND ((?16 = 0 AND a.id = ?4) OR (?16 = 1 AND a.first_party_client = ?5)))",
				// auth_time is the approving session's secret's creation, and the
				// session must be the owner's and active now.
				"(SELECT s.created_at FROM secrets s JOIN sessions x ON x.id = s.id AND x.kind = s.kind " +
					"WHERE s.id = ?12 AND s.kind = ?13 AND x.user_id = ?3 " +
					"AND (s.revoked_at IS NULL OR s.revoked_at > ?14) AND s.expires_at > ?14)",
			},
			args: []any{
				grant.ID, store.KindOAuthGrant, grant.Owner, grant.AgentID, grant.ClientID.String(), grant.ClientName,
				grant.RedirectURI.String(), grant.Resource.String(), grant.Scope.String(),
				grant.CodeChallenge.String(), nonce, grant.SessionID, store.KindSession, grant.CreatedAt.Unix(),
				grant.GrantedFrom, firstPartyArg,
			},
		},
	)
}

// TestCreateGrantStatements pins the batch a consent writes: the agent when one
// is created (with its limit in the write, and no scopes), the secret of the
// code, then the grant's own row, whose user, agent and auth_time are subselects
// that are NULL when the account, the agent or the session cannot stand, so that
// no grant means a failed batch and the earlier writes are rolled back.
func TestCreateGrantStatements(t *testing.T) {
	t.Parallel()

	for _, test := range createGrantCases(t) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			statements := 2

			switch {
			case test.firstParty, test.newAgent:
				statements = 3
			}

			fake := newFake(applied(statements))

			err := fake.store().CreateGrant(context.Background(), test.grant)
			checkErr(t, err, nil)

			checkBatch(t, fake, createGrantWant(test.grant, test.newAgent, test.firstParty)...)

			// The challenge is the 43 characters of an S256 challenge, never a verifier.
			challenge, _ := fake.calls[0][len(fake.calls[0])-1].Args[9].(string)
			if len(challenge) != input.CodeChallengeLen {
				t.Errorf("code_challenge argument = %q, want %d characters", challenge, input.CodeChallengeLen)
			}
		})
	}
}

// grantRefusal is a constraint failure of the consent batch, and the refusal it
// must be named.
type grantRefusal struct {
	name     string
	text     string
	newAgent bool
	// firstParty is a first-party login, which can create its agent and so is
	// refused at the limit as a consent that creates one is.
	firstParty bool
	want       error
}

// grantRefusals are the failures CreateGrant names, as D1 reports them: the
// extended code and the column.
func grantRefusals() []grantRefusal {
	notNull := func(column string) string {
		return "D1_ERROR: NOT NULL constraint failed: " + column + ": SQLITE_CONSTRAINT_NOTNULL"
	}

	return []grantRefusal{
		{name: "the account is revoked", text: notNull("oauth_grants.user_id"), newAgent: false, want: store.ErrUserInactive},
		{name: "the account is revoked, creating an agent", text: notNull("oauth_grants.user_id"), newAgent: true,
			want: store.ErrUserInactive},
		{name: "the user is at the limit", text: notNull("oauth_grants.agent_id"), newAgent: true,
			want: store.ErrAgentLimit},
		{name: "the agent is not the user's or is revoked", text: notNull("oauth_grants.agent_id"), newAgent: false,
			want: store.ErrAgentUnavailable},
		{name: "a first-party login of a user at the limit", text: notNull("oauth_grants.agent_id"), firstParty: true,
			want: store.ErrAgentLimit},
		{name: "a first-party login whose account is revoked", text: notNull("oauth_grants.user_id"), firstParty: true,
			want: store.ErrUserInactive},
		{name: "a first-party login whose session ended", text: notNull("oauth_grants.auth_time"), firstParty: true,
			want: store.ErrSessionInactive},
		{name: "a first-party login that was used", firstParty: true, want: store.ErrGrantReplayed,
			text: "D1_ERROR: UNIQUE constraint failed: oauth_grants.granted_from: SQLITE_CONSTRAINT_UNIQUE"},
		{name: "the session ended", text: notNull("oauth_grants.auth_time"), newAgent: false,
			want: store.ErrSessionInactive},
		{name: "the session ended, creating an agent", text: notNull("oauth_grants.auth_time"), newAgent: true,
			want: store.ErrSessionInactive},
		{name: "the consent was used", newAgent: false, want: store.ErrGrantReplayed,
			text: "D1_ERROR: UNIQUE constraint failed: oauth_grants.granted_from: SQLITE_CONSTRAINT_UNIQUE"},
		{name: "the consent was used, creating an agent", newAgent: true, want: store.ErrGrantReplayed,
			text: "D1_ERROR: UNIQUE constraint failed: oauth_grants.granted_from: SQLITE_CONSTRAINT_UNIQUE"},
	}
}

// TestCreateGrantRefusals holds that each way the consent batch fails is named,
// the cause is kept for the log, and no other refusal is claimed.
func TestCreateGrantRefusals(t *testing.T) {
	t.Parallel()

	all := []error{
		store.ErrUserInactive, store.ErrAgentLimit, store.ErrAgentUnavailable, store.ErrSessionInactive,
		store.ErrGrantReplayed,
	}

	cases := createGrantCases(t)

	for _, test := range grantRefusals() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			grant, statements := cases[0].grant, 2

			switch {
			case test.newAgent:
				grant, statements = cases[1].grant, 3
			case test.firstParty:
				grant, statements = cases[2].grant, 3
			}

			fake := newFake(failing(store.Classify(dbError(test.text))))

			err := fake.store().CreateGrant(context.Background(), grant)

			for _, refusal := range all {
				want := errors.Is(refusal, test.want)
				if got := errors.Is(err, refusal); got != want {
					t.Errorf("errors.Is(%v) = %v, want %v", refusal, got, want)
				}
			}

			// Each is a kind of conflict, for a feature that does not tell them apart.
			if !errors.Is(err, store.ErrConflict) {
				t.Errorf("a refusal %v is not an ErrConflict", err)
			}

			if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
				t.Errorf("a refusal %v is classified; the feature must decide that", err)
			}

			if !strings.Contains(err.Error(), test.text) {
				t.Errorf("error %q lost the database's text %q", err, test.text)
			}

			if got := len(fake.calls[0]); got != statements {
				t.Errorf("batch has %d statements, want %d", got, statements)
			}
		})
	}
}

// TestCreateGrantUnattributedConflicts holds that a conflict the write cannot
// attribute is the bare ErrConflict and never one of the named refusals: a
// column of another table, another constraint on a column that is named, and
// text that names no column.
func TestCreateGrantUnattributedConflicts(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, text string }{
		{name: "the code's hash is taken",
			text: "D1_ERROR: UNIQUE constraint failed: secrets.hash: SQLITE_CONSTRAINT_UNIQUE"},
		{name: "the id is taken",
			text: "D1_ERROR: UNIQUE constraint failed: oauth_grants.id: SQLITE_CONSTRAINT_PRIMARYKEY"},
		{name: "the new agent's id is taken",
			text: "D1_ERROR: UNIQUE constraint failed: agents.id: SQLITE_CONSTRAINT_PRIMARYKEY"},
		{name: "no column is named", text: "D1_ERROR: NOT NULL constraint failed: SQLITE_CONSTRAINT_NOTNULL"},
		{name: "a column of another table of a similar name",
			text: "D1_ERROR: NOT NULL constraint failed: oauth_access_tokens.grant_id: SQLITE_CONSTRAINT_NOTNULL"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, c := range createGrantCases(t) {
				fake := newFake(failing(store.Classify(dbError(test.text))))

				err := fake.store().CreateGrant(context.Background(), c.grant)

				if !errors.Is(err, store.ErrConflict) {
					t.Fatalf("error = %v, want ErrConflict", err)
				}

				for _, refusal := range []error{
					store.ErrUserInactive, store.ErrAgentLimit, store.ErrAgentUnavailable, store.ErrSessionInactive,
					store.ErrGrantReplayed,
				} {
					if errors.Is(err, refusal) {
						t.Errorf("an unattributed conflict is %v", refusal)
					}
				}
			}
		})
	}
}

// TestCreateGrantRuleFailureIsADefect holds that a CHECK or FOREIGN KEY refusal
// is a defect even when it names a column of the grant: it is the code
// disagreeing with the schema, not the consent being refused.
func TestCreateGrantRuleFailureIsADefect(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"D1_ERROR: CHECK constraint failed: oauth_grants.agent_id: SQLITE_CONSTRAINT_CHECK",
		"D1_ERROR: FOREIGN KEY constraint failed: oauth_grants.user_id: SQLITE_CONSTRAINT_FOREIGNKEY",
	} {
		fake := newFake(failing(store.Classify(dbError(text))))

		err := fake.store().CreateGrant(context.Background(), createGrantCases(t)[0].grant)

		checkErr(t, err, defectOf(store.CodeGrantCreateRejected))
	}
}

// TestCreateGrantFailures holds how a failed or malformed batch is reported, for
// a consent with an existing agent (two statements) and with a new one (three).
func TestCreateGrantFailures(t *testing.T) {
	t.Parallel()

	for _, test := range createGrantCases(t) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			statements := 2

			switch {
			case test.firstParty, test.newAgent:
				statements = 3
			}

			runFailures(t, statements, store.CodeGrantCreateFailed, store.CodeGrantCreateRejected, grantsUnavailable,
				func(s *store.Store) error { return passErr(s.CreateGrant(context.Background(), test.grant)) })
		})
	}
}

// grantWriteFailures is infraFailures for an operation that writes nothing a
// constraint of the data could refuse (a revoke): a conflict is a defect there.
func grantWriteFailures(statements int, failed, rejected, description string) []failure {
	return defectConflicts(infraFailures(statements, failed, rejected, description), rejected)
}

// revokeGrantStatements are the three statements a revoke runs, in order.
func revokeGrantStatements() []wantStatement {
	return []wantStatement{
		{
			fragments: []string{
				"UPDATE secrets SET revoked_at = ?1",
				// A due revocation keeps its time; a later one is brought forward.
				"WHERE id = ?2 AND (revoked_at IS NULL OR revoked_at > ?1)",
				// Only the user's own grant, whether or not it was exchanged.
				"AND id IN (SELECT g.id FROM oauth_grants g WHERE g.id = ?2 AND g.user_id = ?3)",
			},
			args: []any{now.Unix(), grantTarget, grantOwner},
		},
		{
			fragments: []string{
				// The grant's access token, under the same conditions on the grant.
				"UPDATE secrets SET revoked_at = ?1",
				"WHERE (revoked_at IS NULL OR revoked_at > ?1)",
				"AND id IN (SELECT t.id FROM oauth_access_tokens t JOIN oauth_grants g ON g.id = t.grant_id " +
					"WHERE g.id = ?2 AND g.user_id = ?3)",
			},
			args: []any{now.Unix(), grantTarget, grantOwner},
		},
		{
			fragments: append(grantReadFragments(), "WHERE g.id = ?1 AND g.user_id = ?2"),
			args:      []any{grantTarget, grantOwner},
		},
	}
}

// TestRevokeGrant holds the outcomes of a revoke: the row is whatever the closing
// read returns, so a grant revoked earlier is returned with its earlier time, and
// revoking twice succeeds.
func TestRevokeGrant(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)
	revoked := store.Grant{
		ID: grantTarget, AgentID: grantAgent, AgentName: "build bot", ClientID: "https://client.example.com/app",
		ClientName: "Client", Resource: resource.ProductionURL, Scope: "mcp:read openid", ExpiresAt: 1_800_000_000,
		RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
	}

	tests := []struct {
		name    string
		outcome outcome
		want    store.Grant
		err     error
	}{
		{name: "revoked now", outcome: afterRevokes(grantRevokedRow()), want: revoked},
		{name: "revoked already: the writes changed nothing", want: revoked, outcome: outcome{
			results: []store.Result{
				{Changes: 0, Rows: nil}, {Changes: 0, Rows: nil}, {Changes: 0, Rows: [][]any{grantRevokedRow()}},
			},
			err: nil,
		}},
		{name: "no such grant", outcome: afterRevokes(), err: store.ErrNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(test.outcome)

			got, err := fake.store().RevokeGrant(context.Background(), grantOwner, mustGrantID(t), now)

			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("grant = %+v, want %+v", got, test.want)
			}

			checkBatch(t, fake, revokeGrantStatements()...)
		})
	}
}

// TestRevokeGrantFailures holds that a conflict is as much a defect as a schema
// rule: a revoke sets nothing the data could collide with.
func TestRevokeGrantFailures(t *testing.T) {
	t.Parallel()

	failures := grantWriteFailures(3, store.CodeGrantRevokeFailed, store.CodeGrantRevokeRejected, grantsUnavailable)

	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			_, err := fake.store().RevokeGrant(context.Background(), grantOwner, mustGrantID(t), now)

			checkFailure(t, err, f)

			if errors.Is(err, store.ErrNotFound) {
				t.Error("a failure is reported as a missing grant")
			}
		})
	}
}

// queryGuard is a rule about the text of some statements: each of queries must
// start with prefix (when set), contain every mustContain fragment and none of
// mustNotContain. The text is compared with its whitespace squashed; upper
// folds its case first, for rules about SQL keywords.
type queryGuard struct {
	name           string
	queries        []string
	prefix         string
	mustContain    []string
	mustNotContain []string
	upper          bool
}

// runQueryGuards checks every guard against the package's own query constants.
func runQueryGuards(t *testing.T, guards []queryGuard) {
	t.Helper()

	queries := packageQueries(t)

	for _, guard := range guards {
		t.Run(guard.name, func(t *testing.T) {
			t.Parallel()

			for _, name := range guard.queries {
				text, found := queries[name]
				if !found {
					t.Fatalf("there is no query %s", name)
				}

				for _, problem := range guard.problems(squash(text)) {
					t.Errorf("%s %s:\n%s", name, problem, text)
				}
			}
		})
	}
}

// problems lists the ways a statement, with its whitespace squashed, breaks the
// guard.
func (g queryGuard) problems(text string) []string {
	if g.upper {
		text = strings.ToUpper(text)
	}

	var problems []string

	if !strings.HasPrefix(text, g.prefix) {
		problems = append(problems, fmt.Sprintf("does not start with %q", g.prefix))
	}

	for _, fragment := range g.mustContain {
		if !strings.Contains(text, fragment) {
			problems = append(problems, fmt.Sprintf("does not contain %q", fragment))
		}
	}

	for _, fragment := range g.mustNotContain {
		if strings.Contains(text, fragment) {
			problems = append(problems, fmt.Sprintf("contains %q", fragment))
		}
	}

	return problems
}

// accessTokenTable is the table of the access tokens a grant issues.
const accessTokenTable = "oauth_access" + "_tokens"

// TestGrantQueryGuards holds the text of the statements on grants. Every one that
// reads or changes a user's grant names the owner in its match, so a grant of
// another user can be neither seen nor changed, and the two that read one select
// no hash.
//
// No statement that lists, reads or revokes a grant's own secret asks whether the
// grant has an access token. That row goes when its secret has expired and been
// swept (15 minutes after an exchange), while the grant lives 30 days, so a
// condition on it would hide a live grant from its user, who could then neither
// see nor revoke it. Revoking the access token's secret is a separate statement,
// which names the table because it must.
func TestGrantQueryGuards(t *testing.T) {
	t.Parallel()

	runQueryGuards(t, []queryGuard{
		{
			name:        "every grant statement matches on the owner",
			queries:     []string{"grantListQuery", "grantGetQuery", "grantRevokeQuery", "grantRevokeAccessQuery"},
			mustContain: []string{"user_id = ?"},
		},
		{
			name:           "reading a grant selects or names no hash",
			queries:        []string{"grantListQuery", "grantGetQuery"},
			mustNotContain: []string{"hash"},
		},
		{
			name:           "a grant's own statements do not depend on its access token",
			queries:        []string{"grantListQuery", "grantGetQuery", "grantRevokeQuery"},
			mustNotContain: []string{accessTokenTable},
		},
		{
			name:        "revoking a grant's access token names it",
			queries:     []string{"grantRevokeAccessQuery"},
			mustContain: []string{accessTokenTable},
		},
	})
}

// TestGrantCodes pins the wire codes the operations report. Clients and
// dashboards match on them, so they change only deliberately.
func TestGrantCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeGrantCreateFailed, "oauth_grant_create_failed"},
		{store.CodeGrantCreateRejected, "oauth_grant_create_rejected"},
		{store.CodeGrantListFailed, "oauth_grant_list_failed"},
		{store.CodeGrantListRejected, "oauth_grant_list_rejected"},
		{store.CodeGrantLookupFailed, "oauth_grant_lookup_failed"},
		{store.CodeGrantLookupRejected, "oauth_grant_lookup_rejected"},
		{store.CodeGrantRevokeFailed, "oauth_grant_revoke_failed"},
		{store.CodeGrantRevokeRejected, "oauth_grant_revoke_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}

// TestGrantAgentsHaveNoScopes pins the scope list of an agent consent creates: a
// grant carries no authsu scopes, so neither does its agent.
func TestGrantAgentsHaveNoScopes(t *testing.T) {
	t.Parallel()

	if store.GrantAgentScopes != "[]" {
		t.Errorf("GrantAgentScopes = %q, want the empty list", store.GrantAgentScopes)
	}
}

// TestGrantsFirstPageSortsAboveEveryID holds the property the first page relies on,
// as for keys: its bound is not an id and sorts above every character an id holds.
func TestGrantsFirstPageSortsAboveEveryID(t *testing.T) {
	t.Parallel()

	if store.GrantsFirstPage != store.AgentsFirstPage {
		t.Errorf("the grants' first page bound %q differs from the agents' %q",
			store.GrantsFirstPage, store.AgentsFirstPage)
	}

	if store.GrantsFirstPage <= agentLargestID {
		t.Errorf("the first page bound %q does not sort above the greatest id %q", store.GrantsFirstPage, agentLargestID)
	}

	_, err := input.ParseID(store.GrantsFirstPage)
	if err == nil {
		t.Errorf("the first page bound %q parses as an id", store.GrantsFirstPage)
	}
}
