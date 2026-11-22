//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Everything this file defines at package level is prefixed "token" or "exchange"
// so that it cannot collide with the helpers of another area's test file.

const tokensUnavailable = "tokens are temporarily unavailable"

// exchangedRow is the row a rotation returns: grant_id, user_id, agent_id,
// client_id, resource, scope, nonce, auth_time, profile.
func exchangedRow() []any {
	return row(grantTarget, grantOwner, grantAgent, oauthClient, resource.ProductionURL, "mcp:read openid", "n-1",
		int64(1_699_999_000), exchangedProfile)
}

// exchangedProfile is the users.profile an exchange reports.
const exchangedProfile = `{"name":"Alice A","email":"alice@example.com"}`

// exchangedKinds are the column kinds of exchangedRow, for defectResults.
func exchangedKinds() []string {
	return []string{"text", "text", "text", "text", "text", "text", "optText", "integer", "text"}
}

// tokensRotated is the batch of a rotation and the five statements after it: the
// rotation returned rows, the diagnosis (which finds nothing when the rotation
// matched) and the access token's four statements changed rows.
func tokensRotated(rows ...[]any) outcome {
	return outcome{results: []store.Result{
		{Changes: 0, Rows: rows}, {Changes: 0, Rows: nil}, {Changes: 1, Rows: nil}, {Changes: 1, Rows: nil},
		{Changes: 0, Rows: nil}, {Changes: 0, Rows: nil},
	}, err: nil}
}

// tokensRefused is the batch of a rotation that matched nothing, whose diagnosis
// returned rows.
func tokensRefused(diagnosis ...[]any) outcome {
	return outcome{results: []store.Result{
		{Changes: 0, Rows: nil}, {Changes: 0, Rows: diagnosis}, {Changes: 0, Rows: nil}, {Changes: 0, Rows: nil},
		{Changes: 0, Rows: nil}, {Changes: 0, Rows: nil},
	}, err: nil}
}

// rotationStatements is how many statements a rotation batch has: the rotation,
// its diagnosis and the access token's four.
const rotationStatements = 6

// exchangeTokens are the tokens a grant is rotated to, each value told apart by
// its seed so that a swapped argument is visible.
func exchangeTokens(seed byte) store.NewTokens {
	return store.NewTokens{
		RefreshHash: hashOf(seed), RefreshExpiresAt: now.Add(30*24*time.Hour + time.Duration(seed)*time.Second),
		AccessID: grantIDAt(int(seed) + 500), AccessHash: hashOf(seed + 1),
		AccessExpiresAt: now.Add(15*time.Minute + time.Duration(seed)*time.Second),
	}
}

// accessStatements are the four statements that follow a rotation's diagnosis,
// in order, and what each carries: they find the grant by the new refresh hash
// alone. scope is the scope text the access token carries, nil for the grant's.
func accessStatements(tokens store.NewTokens, scope any) []wantStatement {
	return []wantStatement{
		{
			fragments: []string{
				// The access token the grant has is replaced in place, and a
				// revocation of the old one does not carry over.
				"UPDATE secrets SET hash = ?1, expires_at = ?2, revoked_at = NULL, created_at = ?3",
				"WHERE kind = ?4",
				"AND id IN (SELECT t.id FROM oauth_access_tokens t " +
					"JOIN secrets g ON g.id = t.grant_id AND g.kind = ?5 AND g.hash = ?6)",
			},
			args: []any{
				tokens.AccessHash, tokens.AccessExpiresAt.Unix(), now.Unix(), store.KindOAuthAccess, store.KindOAuthGrant,
				tokens.RefreshHash,
			},
		},
		{
			fragments: []string{
				// Its scope: the one asked for, or the grant's, for the grant the
				// rotation rotated and no other.
				"UPDATE oauth_access_tokens SET scope = COALESCE(?1, " +
					"(SELECT g.scope FROM oauth_grants g WHERE g.id = oauth_access_tokens.grant_id))",
				"WHERE grant_id IN (SELECT s.id FROM secrets s WHERE s.kind = ?2 AND s.hash = ?3)",
			},
			args: []any{scope, store.KindOAuthGrant, tokens.RefreshHash},
		},
		{
			fragments: []string{
				// The first access token, only for the rotated grant and only when
				// it has none.
				"INSERT INTO secrets (id, kind, hash, expires_at, created_at) SELECT ?1, ?2, ?3, ?4, ?5",
				"WHERE EXISTS (SELECT 1 FROM secrets g WHERE g.hash = ?6 AND g.kind = ?7)",
				"AND NOT EXISTS (SELECT 1 FROM oauth_access_tokens t " +
					"JOIN secrets g ON g.id = t.grant_id AND g.kind = ?7 AND g.hash = ?6)",
			},
			args: []any{
				tokens.AccessID, store.KindOAuthAccess, tokens.AccessHash, tokens.AccessExpiresAt.Unix(), now.Unix(),
				tokens.RefreshHash, store.KindOAuthGrant,
			},
		},
		{
			fragments: []string{
				// Its row, with its scope, only if its secret was written, for the
				// rotated grant.
				"INSERT INTO oauth_access_tokens (id, kind, grant_id, scope) " +
					"SELECT ?1, ?2, g.id, COALESCE(?5, og.scope) FROM secrets g JOIN oauth_grants og ON og.id = g.id",
				"WHERE g.hash = ?3 AND g.kind = ?4",
				"AND EXISTS (SELECT 1 FROM secrets x WHERE x.id = ?1 AND x.kind = ?2)",
			},
			args: []any{tokens.AccessID, store.KindOAuthAccess, tokens.RefreshHash, store.KindOAuthGrant, scope},
		},
	}
}

// exchangeCase is a code presented at the token endpoint.
type exchangeCase struct {
	name     string
	exchange store.CodeExchange
}

func exchangeCases(t *testing.T) []exchangeCase {
	t.Helper()

	target := mustResourceID(t)

	return []exchangeCase{
		{name: "a typical exchange", exchange: store.CodeExchange{
			Code: mustAuthorizationCode(t, 1), ClientID: mustClientID(t, oauthClient, oauthTable),
			RedirectURI: mustRedirectURI(t, oauthRedirect), Verifier: mustVerifier(t, strings.Repeat("a", 43)),
			Resource: nil, CodeLifetime: time.Minute, Tokens: exchangeTokens(10),
		}},
		{name: "another client, redirect, verifier, resource, life and tokens", exchange: store.CodeExchange{
			Code:        mustAuthorizationCode(t, 2),
			ClientID:    mustClientID(t, "http://localhost:3000/client.json", oauthDevTable),
			RedirectURI: mustRedirectURI(t, "http://127.0.0.1:8123/callback"),
			Verifier:    mustVerifier(t, strings.Repeat("Zy-._~9", 18)),
			Resource:    &target, CodeLifetime: 90*time.Second + 500*time.Millisecond,
			Tokens: exchangeTokens(20),
		}},
	}
}

// exchangeStatements is the batch an exchange must run, for the exchange.
func exchangeStatements(ex store.CodeExchange) []wantStatement {
	tokens := ex.Tokens

	var named any
	if ex.Resource != nil {
		named = ex.Resource.String()
	}

	conditions := []any{
		ex.Code.Hash(), store.KindOAuthGrant, now.Unix(), ex.ClientID.String(), ex.RedirectURI.String(),
		ex.Verifier.Challenge().String(), int64(ex.CodeLifetime / time.Second), named,
	}

	secretConditions := "hash = ?1 AND kind = ?2 " +
		// Active now, and the code younger than its life, judged from the
		// creation time: the expiry is the retention of the consent guard.
		"AND (revoked_at IS NULL OR revoked_at > ?3) AND expires_at > ?3 AND created_at + ?7 > ?3"
	grantConditions := "FROM oauth_grants g " +
		"JOIN users u ON u.id = g.user_id AND u.revoked_at IS NULL " +
		"JOIN agents a ON a.id = g.agent_id AND a.revoked_at IS NULL AND a.sandbox_id IS NULL " +
		"WHERE g.client_id = ?4 AND g.redirect_uri = ?5 AND g.code_challenge = ?6"

	return append([]wantStatement{
		{
			fragments: []string{
				"UPDATE secrets SET hash = ?9, expires_at = ?10",
				// The code's hash, of a grant's secret, active, and young.
				"WHERE " + secretConditions,
				// The grant is the presented client's, for the presented redirect URI
				// and the verifier's challenge, with its account and agent live, and
				// the resource it was asked for, if one was.
				"AND id IN (SELECT g.id " + grantConditions + " AND (?8 IS NULL OR g.resource = ?8))",
				// One statement reports its own outcome, with the grant's whole scope.
				"RETURNING id AS grant_id,",
				"(SELECT g.scope FROM oauth_grants g WHERE g.id = secrets.id) AS scope",
				"(SELECT g.nonce FROM oauth_grants g WHERE g.id = secrets.id) AS nonce",
				"(SELECT g.auth_time FROM oauth_grants g WHERE g.id = secrets.id) AS auth_time",
				// The subject's profile, read in the same statement, for the ID token.
				"(SELECT u.profile FROM oauth_grants g JOIN users u ON u.id = g.user_id WHERE g.id = secrets.id) AS profile",
			},
			args: append(append([]any{}, conditions...), tokens.RefreshHash, tokens.RefreshExpiresAt.Unix()),
		},
		{
			fragments: []string{
				// The same grant and secret conditions, only the resource unjudged.
				"SELECT (?8 IS NULL OR g.resource = ?8) AS resource_ok, 1 AS scope_ok " + grantConditions,
				"AND g.id IN (SELECT id FROM secrets WHERE " + secretConditions + ")",
			},
			args: conditions,
		},
	}, accessStatements(tokens, nil)...)
}

// TestExchangeCodeStatements pins the batch of an exchange: one rotation that
// carries every guard and reports the grant, its diagnosis over the same
// conditions, then the access token's four statements. The hash compared is the
// code's, the PKCE value is the verifier's challenge (never the verifier), the
// code's life is whole seconds, and each value is where its placeholder reads it.
func TestExchangeCodeStatements(t *testing.T) {
	t.Parallel()

	for _, test := range exchangeCases(t) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(tokensRotated(exchangedRow()))

			_, err := fake.store().ExchangeCode(context.Background(), test.exchange, now)
			checkErr(t, err, nil)

			checkBatch(t, fake, exchangeStatements(test.exchange)...)

			// The challenge is a hash of the verifier: the verifier is never bound.
			ex := test.exchange
			args := fake.calls[0][0].Args

			if args[5] == ex.Verifier.String() || args[5] != ex.Verifier.Challenge().String() {
				t.Errorf("code_challenge argument = %v, want the S256 challenge of the verifier", args[5])
			}
		})
	}
}

// TestExchangeCodeDecoding holds how the rotation's row becomes the Exchanged the
// ID token is made from, for a grant with a nonce and without one.
func TestExchangeCodeDecoding(t *testing.T) {
	t.Parallel()

	nonce := "n-1"

	tests := []struct {
		name string
		row  []any
		want store.Exchanged
	}{
		{name: "a grant with a nonce", row: exchangedRow(), want: store.Exchanged{
			GrantID: grantTarget, UserID: grantOwner, AgentID: grantAgent, ClientID: oauthClient,
			Resource: resource.ProductionURL, Scope: "mcp:read openid", Nonce: &nonce, AuthTime: time.Unix(1_699_999_000, 0),
			Profile: exchangedProfile,
		}},
		{name: "a grant with none", row: with(exchangedRow(), 6, nil), want: store.Exchanged{
			GrantID: grantTarget, UserID: grantOwner, AgentID: grantAgent, ClientID: oauthClient,
			Resource: resource.ProductionURL, Scope: "mcp:read openid", Nonce: nil, AuthTime: time.Unix(1_699_999_000, 0),
			Profile: exchangedProfile,
		}},
		{name: "an empty profile is kept as it is", row: with(exchangedRow(), 8, `{}`), want: store.Exchanged{
			GrantID: grantTarget, UserID: grantOwner, AgentID: grantAgent, ClientID: oauthClient,
			Resource: resource.ProductionURL, Scope: "mcp:read openid", Nonce: &nonce,
			AuthTime: time.Unix(1_699_999_000, 0), Profile: `{}`,
		}},
	}

	calls := map[string]func(*store.Store) (store.Exchanged, error){
		"exchange": func(s *store.Store) (store.Exchanged, error) {
			return s.ExchangeCode(context.Background(), exchangeCases(t)[0].exchange, now)
		},
		"refresh": func(s *store.Store) (store.Exchanged, error) {
			return s.Refresh(context.Background(), refreshCases(t)[0].exchange, now)
		},
	}

	for callName, call := range calls {
		for _, test := range tests {
			t.Run(callName+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(tokensRotated(test.row))

				got, err := call(fake.store())
				checkErr(t, err, nil)

				if !reflect.DeepEqual(got, test.want) {
					t.Errorf("exchanged = %+v, want %+v", got, test.want)
				}
			})
		}
	}
}

// rotationCalls are the two rotations, each with the code of its defects.
func rotationCalls(t *testing.T) map[string]struct {
	rejected string
	call     func(*store.Store) (store.Exchanged, error)
} {
	t.Helper()

	return map[string]struct {
		rejected string
		call     func(*store.Store) (store.Exchanged, error)
	}{
		"exchange": {store.CodeOAuthExchangeRejected, func(s *store.Store) (store.Exchanged, error) {
			return s.ExchangeCode(context.Background(), exchangeCases(t)[0].exchange, now)
		}},
		"refresh": {store.CodeOAuthRefreshRejected, func(s *store.Store) (store.Exchanged, error) {
			return s.Refresh(context.Background(), refreshCases(t)[0].exchange, now)
		}},
	}
}

// TestRotationOutcomes holds how a rotation that matched nothing is reported,
// for both rotations. The diagnosis row says whether the live token's grant
// refuses the resource or the scope that was asked for, and each is its own
// refusal; with no row nothing about the token is right and the answer is
// ErrInvalidGrant whatever the reason. None is classified: the feature decides
// what a client is told. A diagnosis in which everything holds cannot explain a
// refusal, so it is ErrInvalidGrant too, and the resource is reported before the
// scope when both are wrong.
func TestRotationOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		diagnosis [][]any
		want      error
	}{
		{name: "no live grant of the client", diagnosis: nil, want: store.ErrInvalidGrant},
		{name: "the resource is not the grant's", diagnosis: [][]any{row(int64(0), int64(1))}, want: store.ErrInvalidTarget},
		{name: "the scope is not within the grant's", diagnosis: [][]any{row(int64(1), int64(0))},
			want: store.ErrInvalidScope},
		{name: "the resource before the scope", diagnosis: [][]any{row(int64(0), int64(0))}, want: store.ErrInvalidTarget},
		{name: "nothing wrong the diagnosis can see", diagnosis: [][]any{row(int64(1), int64(1))},
			want: store.ErrInvalidGrant},
	}

	for name, call := range rotationCalls(t) {
		for _, test := range tests {
			t.Run(name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(tokensRefused(test.diagnosis...))

				got, err := call.call(fake.store())

				wantOnlyRefusal(t, err, test.want)

				if !reflect.DeepEqual(got, store.Exchanged{}) {
					t.Errorf("a refused exchange returned %+v", got)
				}
			})
		}
	}
}

// wantOnlyRefusal holds that err is the one refusal want, and not another of
// them or a classified error.
func wantOnlyRefusal(t *testing.T, err, want error) {
	t.Helper()

	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}

	others := []error{store.ErrInvalidGrant, store.ErrInvalidScope, store.ErrInvalidTarget, store.ErrNotFound}

	for _, other := range others {
		if !errors.Is(other, want) && errors.Is(err, other) {
			t.Errorf("error %v is also %v", err, other)
		}
	}

	if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
		t.Errorf("a refusal %v is classified; the feature must decide that", err)
	}
}

// TestRotationDefects holds that a row of the rotation, or of its diagnosis, that
// is not the shape the statement promises is a defect, for both rotations.
func TestRotationDefects(t *testing.T) {
	t.Parallel()

	for name, call := range rotationCalls(t) {
		for defect, rows := range defectResults(exchangedRow(), exchangedKinds()...) {
			t.Run(name+"/"+defect, func(t *testing.T) {
				t.Parallel()

				fake := newFake(tokensRotated(rows...))

				got, err := call.call(fake.store())

				checkErr(t, err, defectOf(call.rejected))

				if got.GrantID != "" {
					t.Errorf("a defective row returned %+v", got)
				}
			})
		}

		for defect, rows := range defectResults(row(int64(1), int64(1)), "boolean", "boolean") {
			t.Run(name+"/diagnosis/"+defect, func(t *testing.T) {
				t.Parallel()

				fake := newFake(tokensRefused(rows...))

				_, err := call.call(fake.store())

				checkErr(t, err, defectOf(call.rejected))
			})
		}
	}
}

// TestExchangeCodeFailures holds how a failed or malformed batch is reported. A
// rotation writes nothing the data could collide with (the hashes are random and
// the id fresh), so a conflict is a defect.
func TestExchangeCodeFailures(t *testing.T) {
	t.Parallel()

	runDefectFailures(t, rotationStatements, store.CodeOAuthExchangeFailed, store.CodeOAuthExchangeRejected,
		tokensUnavailable, func(s *store.Store) error {
			return lastErr(s.ExchangeCode(context.Background(), exchangeCases(t)[0].exchange, now))
		})
}

// refreshCase is a refresh token presented at the token endpoint.
type refreshCase struct {
	name     string
	exchange store.RefreshExchange

	// names and scope are the arguments the request's scope becomes: the JSON
	// array the rotation checks against the grant's, and the text the access
	// token carries (nil for none).
	names string
	scope any

	// resource is the argument of the resource asked for (nil for none).
	resource any
}

func refreshCases(t *testing.T) []refreshCase {
	t.Helper()

	narrower := mustOAuthScopes(t, "mcp:write mcp:read")
	openid := mustOAuthScopes(t, "openid mcp:read")
	target := mustResourceID(t)

	return []refreshCase{
		{name: "a typical refresh", exchange: store.RefreshExchange{
			Token: mustRefreshToken(t, 1), ClientID: mustClientID(t, oauthClient, oauthTable), Scope: nil, Resource: nil,
			Tokens: exchangeTokens(10),
		}, names: "[]", scope: nil, resource: nil},
		{name: "another client and tokens", exchange: store.RefreshExchange{
			Token: mustRefreshToken(t, 2), ClientID: mustClientID(t, "http://localhost:3000/client.json", oauthDevTable),
			Scope: nil, Resource: nil, Tokens: exchangeTokens(20),
		}, names: "[]", scope: nil, resource: nil},
		{name: "a scope, in the order it was written", exchange: store.RefreshExchange{
			Token: mustRefreshToken(t, 3), ClientID: mustClientID(t, oauthClient, oauthTable), Scope: &narrower,
			Resource: nil, Tokens: exchangeTokens(30),
		}, names: `["mcp:write","mcp:read"]`, scope: "mcp:write mcp:read", resource: nil},
		{name: "openid and a resource", exchange: store.RefreshExchange{
			Token: mustRefreshToken(t, 4), ClientID: mustClientID(t, oauthClient, oauthTable), Scope: &openid,
			Resource: &target, Tokens: exchangeTokens(40),
		}, names: `["openid","mcp:read"]`, scope: "openid mcp:read", resource: resource.ProductionURL},
	}
}

// TestRefreshStatements pins the batch of a refresh: the same rotation keyed on
// the refresh token's hash and the client, with the scope and the resource asked
// for checked in the write, then its diagnosis, then the access token's four
// statements carrying the scope.
func TestRefreshStatements(t *testing.T) {
	t.Parallel()

	for _, test := range refreshCases(t) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(tokensRotated(exchangedRow()))

			_, err := fake.store().Refresh(context.Background(), test.exchange, now)
			checkErr(t, err, nil)

			ex := test.exchange
			tokens := ex.Tokens

			conditions := []any{
				ex.Token.Hash(), store.KindOAuthGrant, now.Unix(), ex.ClientID.String(), test.names, test.resource,
			}

			secretConditions := "hash = ?1 AND kind = ?2 " +
				"AND (revoked_at IS NULL OR revoked_at > ?3) AND expires_at > ?3"
			// The client only: no redirect URI and no challenge, and the account and
			// agent live.
			grantConditions := "FROM oauth_grants g " +
				"JOIN users u ON u.id = g.user_id AND u.revoked_at IS NULL " +
				"JOIN agents a ON a.id = g.agent_id AND a.revoked_at IS NULL AND a.sandbox_id IS NULL " +
				"WHERE g.client_id = ?4"
			// Every name asked for is a whole name of the grant's scope, between
			// delimiters, so mcp:read is not found in mcp:readwrite.
			within := "NOT EXISTS (SELECT 1 FROM json_each(?5) j " +
				"WHERE instr(' ' || g.scope || ' ', ' ' || j.value || ' ') = 0)"

			want := append([]wantStatement{
				{
					fragments: []string{
						"UPDATE secrets SET hash = ?8, expires_at = ?9",
						"WHERE " + secretConditions,
						"AND id IN (SELECT g.id " + grantConditions + " AND " + within + " AND (?6 IS NULL OR g.resource = ?6))",
						"RETURNING id AS grant_id,",
						// The scope of the access token being issued, not always the grant's.
						"COALESCE(?7, (SELECT g.scope FROM oauth_grants g WHERE g.id = secrets.id)) AS scope",
						"(SELECT g.nonce FROM oauth_grants g WHERE g.id = secrets.id) AS nonce",
					},
					args: append(append([]any{}, conditions...), test.scope, tokens.RefreshHash, tokens.RefreshExpiresAt.Unix()),
				},
				{
					fragments: []string{
						"SELECT (?6 IS NULL OR g.resource = ?6) AS resource_ok, " + within + " AS scope_ok " + grantConditions,
						"AND g.id IN (SELECT id FROM secrets WHERE " + secretConditions + ")",
					},
					args: conditions,
				},
			}, accessStatements(tokens, test.scope)...)

			checkBatch(t, fake, want...)
		})
	}
}

// TestRefreshFailures holds how a failed or malformed batch is reported.
func TestRefreshFailures(t *testing.T) {
	t.Parallel()

	runDefectFailures(t, rotationStatements, store.CodeOAuthRefreshFailed, store.CodeOAuthRefreshRejected,
		tokensUnavailable, func(s *store.Store) error {
			return lastErr(s.Refresh(context.Background(), refreshCases(t)[0].exchange, now))
		})
}

// TestRotationQueryGuards holds that a rotation replaces the hash and writes no
// other secret for the old one: the previous token is not kept
// (docs/secrets_design.md), so no statement of an exchange inserts a second row
// for the grant's own secret, and none deletes.
//
// The statements that explain a refused rotation only read: they run in the
// rotation's batch, after it, and must not be able to change what it decided.
func TestRotationQueryGuards(t *testing.T) {
	t.Parallel()

	runQueryGuards(t, []queryGuard{
		{
			name:           "the code rotation is in place",
			queries:        []string{"rotateCodeQuery"},
			prefix:         "UPDATE secrets SET hash = ?9, expires_at = ?10 WHERE hash = ?1",
			mustNotContain: []string{"INSERT", "revoked_at = ?"},
		},
		{
			name:           "the refresh rotation is in place",
			queries:        []string{"rotateRefreshQuery"},
			prefix:         "UPDATE secrets SET hash = ?8, expires_at = ?9 WHERE hash = ?1",
			mustNotContain: []string{"INSERT", "revoked_at = ?"},
		},
		{
			name:           "the diagnoses are plain reads",
			queries:        []string{"diagnoseCodeQuery", "diagnoseRefreshQuery"},
			prefix:         "SELECT ",
			mustNotContain: []string{"UPDATE", "INSERT", "DELETE"},
			upper:          true,
		},
		{
			name: "the queries that match a token by its hash also match its kind",
			queries: []string{
				"rotateCodeQuery", "rotateRefreshQuery", "introspectQuery", "revokeRefreshTokenQuery",
				"revokeAccessTokenQuery",
			},
			mustContain: []string{"kind = ?"},
		},
	})
}

// introspectRow is the row of a live access token: grant_id, user_id, agent_id,
// client_id, resource, scope, issued_at, expires_at.
func introspectRow() []any {
	return row(grantTarget, grantOwner, grantAgent, oauthClient, resource.ProductionURL, "mcp:read openid",
		int64(1_700_000_000), int64(1_700_000_900))
}

// TestIntrospectAccessToken holds the statement of an introspection, and how its
// row becomes the answer.
func TestIntrospectAccessToken(t *testing.T) {
	t.Parallel()

	token := mustAccessToken(t, 3)

	fake := newFake(returning(introspectRow()))

	got, found, err := fake.store().IntrospectAccessToken(context.Background(), token, mustResourceID(t), now)
	checkErr(t, err, nil)

	want := store.ActiveAccessToken{
		GrantID: grantTarget, UserID: grantOwner, AgentID: grantAgent, ClientID: oauthClient,
		Resource: resource.ProductionURL, Scope: "mcp:read openid",
		IssuedAt: time.Unix(1_700_000_000, 0), ExpiresAt: time.Unix(1_700_000_900, 0),
	}

	if !found || !reflect.DeepEqual(got, want) {
		t.Errorf("token = %+v, %v; want %+v", got, found, want)
	}

	checkBatch(t, fake, wantStatement{
		fragments: []string{
			// The access token's secret, its own row on the id and the kind together,
			// the grant, the grant's secret, the account and the agent: one read.
			"FROM secrets s JOIN oauth_access_tokens t ON t.id = s.id AND t.kind = s.kind",
			"JOIN oauth_grants g ON g.id = t.grant_id",
			"JOIN secrets gs ON gs.id = g.id AND gs.kind = g.kind",
			"JOIN users u ON u.id = g.user_id",
			"JOIN agents a ON a.id = g.agent_id",
			// The hash is of an access token's secret, which is active now.
			"WHERE s.hash = ?1 AND s.kind = ?2",
			"AND (s.revoked_at IS NULL OR s.revoked_at > ?3) AND s.expires_at > ?3",
			// The grant's secret is active too, so revoking a grant ends its token.
			"AND gs.kind = ?5 AND (gs.revoked_at IS NULL OR gs.revoked_at > ?3) AND gs.expires_at > ?3",
			// The account and the agent are not revoked, the agent is in no sandbox
			// (consent never attaches one), and the grant is for exactly this
			// resource.
			"AND u.revoked_at IS NULL AND a.revoked_at IS NULL AND a.sandbox_id IS NULL AND g.resource = ?4",
		},
		args: []any{token.Hash(), store.KindOAuthAccess, now.Unix(), resource.ProductionURL, store.KindOAuthGrant},
	})

	if strings.Contains(squash(fake.calls[0][0].Query), "s.hash AS") {
		t.Error("introspection selects the token's hash")
	}
}

// TestIntrospectAccessTokenOutcomes holds that no row is an inactive token, not an
// error, and that a malformed row is a defect.
func TestIntrospectAccessTokenOutcomes(t *testing.T) {
	t.Parallel()

	call := func(fake *fakeExec) (store.ActiveAccessToken, bool, error) {
		return fake.store().IntrospectAccessToken(context.Background(), mustAccessToken(t, 3), mustResourceID(t), now)
	}

	t.Run("no row", func(t *testing.T) {
		t.Parallel()

		got, found, err := call(newFake(returning()))
		if err != nil || found || !reflect.DeepEqual(got, store.ActiveAccessToken{}) {
			t.Errorf("got %+v, %v, %v; want the zero token, not found, no error", got, found, err)
		}
	})

	kinds := []string{"text", "text", "text", "text", "text", "text", "integer", "integer"}

	for name, rows := range defectResults(introspectRow(), kinds...) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, found, err := call(newFake(returning(rows...)))

			checkErr(t, err, defectOf(store.CodeOAuthIntrospectRejected))

			if found || got.GrantID != "" {
				t.Errorf("a defective row returned %+v, %v", got, found)
			}
		})
	}
}

// TestIntrospectAccessTokenFailures holds how a failed or malformed batch is
// reported.
func TestIntrospectAccessTokenFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeOAuthIntrospectFailed, store.CodeOAuthIntrospectRejected, tokensUnavailable,
		func(s *store.Store) error {
			return lastErr2(s.IntrospectAccessToken(context.Background(), mustAccessToken(t, 3), mustResourceID(t), now))
		})
}

// revokeTokenCase is one of the two ways to revoke a token and the batch it runs.
type revokeTokenCase struct {
	name       string
	statements []wantStatement
	call       func(*store.Store) error
}

func revokeTokenCases(t *testing.T) []revokeTokenCase {
	t.Helper()

	client := mustClientID(t, oauthClient, oauthTable)
	refresh := mustRefreshToken(t, 4)
	access := mustAccessToken(t, 5)

	return []revokeTokenCase{
		{
			name: "a refresh token",
			call: func(s *store.Store) error { return s.RevokeRefreshToken(context.Background(), refresh, client, now) },
			statements: []wantStatement{
				{
					fragments: []string{
						"UPDATE secrets SET revoked_at = ?1",
						// The grant's secret, by the refresh token's hash, for the client's grant.
						"WHERE hash = ?2 AND kind = ?3",
						// A due revocation keeps its time; a later one is brought forward.
						"AND (revoked_at IS NULL OR revoked_at > ?1)",
						"AND id IN (SELECT g.id FROM oauth_grants g WHERE g.client_id = ?4)",
					},
					args: []any{now.Unix(), refresh.Hash(), store.KindOAuthGrant, oauthClient},
				},
				{
					fragments: []string{
						"UPDATE secrets SET revoked_at = ?1",
						"WHERE (revoked_at IS NULL OR revoked_at > ?1)",
						// The grant's access token, under the same hash and client.
						"AND id IN (SELECT t.id FROM oauth_access_tokens t JOIN oauth_grants g ON g.id = t.grant_id " +
							"JOIN secrets gs ON gs.id = g.id AND gs.kind = ?4 WHERE gs.hash = ?2 AND g.client_id = ?3)",
					},
					args: []any{now.Unix(), refresh.Hash(), oauthClient, store.KindOAuthGrant},
				},
			},
		},
		{
			name: "an access token",
			call: func(s *store.Store) error { return s.RevokeAccessToken(context.Background(), access, client, now) },
			statements: []wantStatement{
				{
					fragments: []string{
						"UPDATE secrets SET revoked_at = ?1",
						// The access token's own secret only, for the client's grant.
						"WHERE hash = ?2 AND kind = ?3",
						"AND (revoked_at IS NULL OR revoked_at > ?1)",
						"AND id IN (SELECT t.id FROM oauth_access_tokens t JOIN oauth_grants g ON g.id = t.grant_id " +
							"WHERE g.client_id = ?4)",
					},
					args: []any{now.Unix(), access.Hash(), store.KindOAuthAccess, oauthClient},
				},
			},
		},
	}
}

// TestRevokeTokenStatements pins the batch of each revocation.
func TestRevokeTokenStatements(t *testing.T) {
	t.Parallel()

	for _, test := range revokeTokenCases(t) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(applied(len(test.statements)))

			checkErr(t, test.call(fake.store()), nil)

			checkBatch(t, fake, test.statements...)
		})
	}
}

// TestRevokeTokenOutcomes holds that revoking a token that matched nothing (an
// unknown token, another client's, one already revoked) is not an error: RFC
// 7009 requires the same answer, and the caller learns nothing.
func TestRevokeTokenOutcomes(t *testing.T) {
	t.Parallel()

	for _, test := range revokeTokenCases(t) {
		for _, changes := range []int64{0, 1, 2} {
			t.Run(fmt.Sprintf("%s/%d rows changed", test.name, changes), func(t *testing.T) {
				t.Parallel()

				results := make([]store.Result, len(test.statements))
				for i := range results {
					results[i].Changes = changes
				}

				fake := newFake(outcome{results: results, err: nil})

				checkErr(t, test.call(fake.store()), nil)
			})
		}
	}
}

// TestRevokeTokenFailures holds that a conflict is as much a defect as a schema
// rule: a revoke sets nothing the data could collide with.
func TestRevokeTokenFailures(t *testing.T) {
	t.Parallel()

	for _, test := range revokeTokenCases(t) {
		for _, f := range grantWriteFailures(len(test.statements),
			store.CodeOAuthRevokeFailed, store.CodeOAuthRevokeRejected, tokensUnavailable) {
			t.Run(test.name+"/"+f.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(f.outcome)

				checkFailure(t, test.call(fake.store()), f)
			})
		}
	}
}

// TestTokenCodes pins the wire codes the operations report. Clients and
// dashboards match on them, so they change only deliberately.
func TestTokenCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeOAuthExchangeFailed, "oauth_exchange_failed"},
		{store.CodeOAuthExchangeRejected, "oauth_exchange_rejected"},
		{store.CodeOAuthRefreshFailed, "oauth_refresh_failed"},
		{store.CodeOAuthRefreshRejected, "oauth_refresh_rejected"},
		{store.CodeOAuthIntrospectFailed, "oauth_introspect_failed"},
		{store.CodeOAuthIntrospectRejected, "oauth_introspect_rejected"},
		{store.CodeOAuthRevokeFailed, "oauth_revoke_failed"},
		{store.CodeOAuthRevokeRejected, "oauth_revoke_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}

// TestTokenKinds pins the kinds of the OAuth secrets.
func TestTokenKinds(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.KindOAuthGrant, "oauth_grant"},
		{store.KindOAuthAccess, "oauth_access"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("kind %q, want %q", test.got, test.want)
		}
	}
}
