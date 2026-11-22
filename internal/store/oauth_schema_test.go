package store_test

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file extends the seam of schema_test.go to the OAuth tables, with that
// file's bound table and checks. Every text column of oauth_grants bounds BYTES
// and refuses NUL, because SQLite's length() on TEXT stops at the first NUL, and
// each CHECK is tied to the constant beside the parser of the value that is
// stored there. The patterns name the table, because oauth_grants.scope has the
// same CHECK as api_keys.scope with a bound of its own.

// oauthWorstClientID is the longest ClientID there is: an https URL of exactly
// input.MaxClientIDBytes.
func oauthWorstClientID(t *testing.T) input.ClientID {
	t.Helper()

	const prefix = "https://example.com/"

	return mustClientID(t, prefix+strings.Repeat("a", input.MaxClientIDBytes-len(prefix)), oauthTable)
}

// oauthWorstRedirectURI is the longest RedirectURI there is.
func oauthWorstRedirectURI(t *testing.T) input.RedirectURI {
	t.Helper()

	const prefix = "https://example.com/"

	return mustRedirectURI(t, prefix+strings.Repeat("a", input.MaxRedirectURIBytes-len(prefix)))
}

// oauthWorstClientName is the longest client_name a metadata document can give.
func oauthWorstClientName(t *testing.T) string {
	t.Helper()

	client := mustClientID(t, oauthClient, oauthTable)
	body := fmt.Sprintf(`{"client_id":%q,"client_name":%q,"redirect_uris":[%q]}`,
		client.String(), strings.Repeat("a", input.MaxClientNameBytes), oauthRedirect)

	metadata, err := input.ParseClientMetadata(client, []byte(body))
	if err != nil {
		t.Fatalf("parse the metadata of the longest client name: %v", err)
	}

	return metadata.Name()
}

// oauthWorstScope is the longest scope text a grant can store: every scope of the
// resource, and openid.
func oauthWorstScope(t *testing.T) input.OAuthScopes {
	t.Helper()

	entry := mustResourceID(t).Entry()

	return mustOAuthScopes(t, strings.Join(append([]string{input.OpenIDScope}, entry.Scopes...), " "))
}

// oauthWorstNonce is the longest Nonce there is.
func oauthWorstNonce(t *testing.T) input.Nonce {
	t.Helper()

	return mustNonce(t, strings.Repeat("~", input.MaxNonceBytes))
}

// oauthWorstGrant is the largest consent a request can carry, with times at the
// farthest the platform holds exactly.
func oauthWorstGrant(t *testing.T, farthest time.Time) store.NewGrant {
	t.Helper()

	nonce := oauthWorstNonce(t)

	return store.NewGrant{
		ID: "id", Owner: grantOwner, AgentID: "agent",
		NewAgent: &store.GrantAgent{Name: agentWorstName(t), MaxActive: 1 << 30},
		ClientID: oauthWorstClientID(t), ClientName: oauthWorstClientName(t), RedirectURI: oauthWorstRedirectURI(t),
		Resource: mustResourceID(t), Scope: oauthWorstScope(t),
		CodeChallenge: mustVerifier(t, strings.Repeat("a", input.MaxCodeVerifierLen)).Challenge(), Nonce: &nonce,
		SessionID: grantSession, GrantedFrom: hashOf(2), CodeHash: hashOf(1), RetainUntil: farthest, CreatedAt: farthest,
	}
}

// oauthWorstTokens are tokens that expire at the farthest time.
func oauthWorstTokens(farthest time.Time) store.NewTokens {
	return store.NewTokens{
		RefreshHash: hashOf(1), RefreshExpiresAt: farthest, AccessID: "access-id", AccessHash: hashOf(2),
		AccessExpiresAt: farthest,
	}
}

// oauthText is the pattern of the size CHECK of a free-text NOT NULL column of
// oauth_grants, with its two limits captured.
func oauthText(column string) string {
	return fmt.Sprintf(`CREATE TABLE oauth_grants \(.*? %[1]s TEXT NOT NULL CHECK \(typeof\(%[1]s\) = 'text' `+
		`AND instr\(%[1]s, char\(0\)\) = 0 AND length\(cast\(%[1]s AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)`, column)
}

// oauthSchemaBounds lists the Go values of the OAuth columns with the CHECK each
// must fit inside.
func oauthSchemaBounds(t *testing.T) []bound {
	t.Helper()

	// The resource server's URL is chosen from a fixed table, so its bound is the
	// parser's constant, which every entry of both tables must fit (see
	// TestOAuthBoundsAreMeaningful).
	return []bound{
		{name: "oauth_grants.client_id bytes", pattern: oauthText("client_id"),
			lowest: 1, highest: len(oauthWorstClientID(t).String()), exact: false},
		{name: "oauth_grants.client_name bytes", pattern: oauthText("client_name"),
			lowest: 1, highest: len(oauthWorstClientName(t)), exact: false},
		{name: "oauth_grants.redirect_uri bytes", pattern: oauthText("redirect_uri"),
			lowest: 1, highest: len(oauthWorstRedirectURI(t).String()), exact: false},
		{name: "oauth_grants.resource bytes", pattern: oauthText("resource"),
			lowest: 1, highest: input.MaxResourceBytes, exact: false},
		{name: "oauth_grants.scope bytes", pattern: oauthText("scope"),
			lowest: 1, highest: input.MaxOAuthScopeBytes, exact: false},
		// The access token's scope is the grant's, or less, and is bounded as it is.
		{name: "oauth_access_tokens.scope bytes",
			pattern: `CREATE TABLE oauth_access_tokens \(.*? scope TEXT NOT NULL CHECK \(typeof\(scope\) = 'text' ` +
				`AND instr\(scope, char\(0\)\) = 0 AND length\(cast\(scope AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)`,
			lowest: 1, highest: input.MaxOAuthScopeBytes, exact: false},
		{name: "oauth_grants.code_challenge bytes",
			pattern: `CREATE TABLE oauth_grants \(.*? code_challenge TEXT NOT NULL CHECK \(typeof\(code_challenge\) = 'text' ` +
				`AND instr\(code_challenge, char\(0\)\) = 0 AND length\(cast\(code_challenge AS BLOB\)\) = (\d+)\)`,
			lowest:  len(mustVerifier(t, strings.Repeat("a", input.MinCodeVerifierLen)).Challenge().String()),
			highest: len(mustVerifier(t, strings.Repeat("a", input.MaxCodeVerifierLen)).Challenge().String()),
			exact:   true},
		{name: "oauth_grants.nonce bytes",
			pattern: `CREATE TABLE oauth_grants \(.*? nonce TEXT CHECK \(nonce IS NULL OR \(typeof\(nonce\) = 'text' ` +
				`AND instr\(nonce, char\(0\)\) = 0 AND length\(cast\(nonce AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)\)`,
			lowest: 1, highest: len(oauthWorstNonce(t).String()), exact: false},
		// The client an agent is kept for is the grant's client_id, so it has that
		// bound (migration 0002).
		{name: "agents.first_party_client bytes",
			pattern: `ADD COLUMN first_party_client TEXT CHECK \(first_party_client IS NULL OR \(first_party = 1 ` +
				`AND typeof\(first_party_client\) = 'text' AND instr\(first_party_client, char\(0\)\) = 0 ` +
				`AND length\(cast\(first_party_client AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)\)`,
			lowest: 1, highest: len(oauthWorstClientID(t).String()), exact: false},
		{name: "oauth_grants.granted_from hash",
			pattern: `CREATE TABLE oauth_grants \(.*? granted_from BLOB NOT NULL UNIQUE ` +
				`CHECK \(typeof\(granted_from\) = 'blob' AND length\(granted_from\) = (\d+)\)`,
			lowest: sha256.Size, highest: sha256.Size, exact: true},
	}
}

// TestOAuthBoundsFitTheSchema holds that every value Go can send for an OAuth
// grant fits its CHECK, and that each CHECK is found exactly once.
func TestOAuthBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	for _, b := range oauthSchemaBounds(t) {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()

			matches := regexp.MustCompile(b.pattern).FindAllStringSubmatch(text, -1)
			if len(matches) != 1 {
				t.Fatalf("%d CHECKs match %s, want exactly one; was the migration text changed?", len(matches), b.pattern)
			}

			checkBound(t, b, matches[0][1:])
		})
	}
}

// TestOAuthBoundsAreMeaningful guards the table above against a pattern that
// matches but proves nothing: each worst case must really be the largest the
// parser accepts, which is the constant the CHECK is tied to, and one more must
// be refused.
func TestOAuthBoundsAreMeaningful(t *testing.T) {
	t.Parallel()

	// The worst values are exactly as long as the constants say.
	for name, got := range map[string][2]int{
		"client_id":    {len(oauthWorstClientID(t).String()), input.MaxClientIDBytes},
		"redirect_uri": {len(oauthWorstRedirectURI(t).String()), input.MaxRedirectURIBytes},
		"client_name":  {len(oauthWorstClientName(t)), input.MaxClientNameBytes},
		"nonce":        {len(oauthWorstNonce(t).String()), input.MaxNonceBytes},
	} {
		t.Run("the worst "+name+" is as long as its constant", func(t *testing.T) {
			t.Parallel()

			if got[0] != got[1] {
				t.Errorf("the worst %s is %d bytes, want %d", name, got[0], got[1])
			}
		})
	}

	// A challenge is exactly the column's length whatever the verifier's, so the
	// column's equality check can hold for every verifier.
	for name, length := range map[string]int{
		"shortest verifier": input.MinCodeVerifierLen,
		"middle verifier":   100,
		"longest verifier":  input.MaxCodeVerifierLen,
	} {
		t.Run("the challenge of the "+name+" has the column's length", func(t *testing.T) {
			t.Parallel()

			challenge := mustVerifier(t, strings.Repeat("v", length)).Challenge().String()
			if len(challenge) != input.CodeChallengeLen {
				t.Errorf("the challenge of a verifier of %d bytes is %d, want %d", length, len(challenge), input.CodeChallengeLen)
			}
		})
	}
}

// TestOAuthBoundsAreEnforcedByTheParsers holds that one byte more than each bound
// is refused where the value is parsed, and that the NUL the CHECKs refuse is the
// parsers' refusal too.
func TestOAuthBoundsAreEnforcedByTheParsers(t *testing.T) {
	t.Parallel()

	const prefix = "https://example.com/"

	client := mustClientID(t, oauthClient, oauthTable)
	longName := fmt.Sprintf(`{"client_id":%q,"client_name":%q,"redirect_uris":[%q]}`,
		client.String(), strings.Repeat("a", input.MaxClientNameBytes+1), oauthRedirect)

	tests := []struct {
		name  string
		parse func() error
	}{
		{"a client_id over the bound", func() error {
			return lastErr(input.ParseClientID(prefix+strings.Repeat("a", input.MaxClientIDBytes), oauthTable))
		}},
		{"a redirect_uri over the bound", func() error {
			return lastErr(input.ParseRedirectURI(prefix + strings.Repeat("a", input.MaxRedirectURIBytes)))
		}},
		{"a nonce over the bound", func() error {
			return lastErr(input.ParseNonce(strings.Repeat("~", input.MaxNonceBytes+1)))
		}},
		{"a client_name over the bound", func() error {
			return lastErr(input.ParseClientMetadata(client, []byte(longName)))
		}},
		{"a scope text over the bound", func() error {
			return lastErr(input.ParseOAuthScopes(
				strings.Repeat("a", input.MaxOAuthScopeBytes+1), true, mustResourceID(t).Entry()))
		}},
		{"a client_id holding NUL", func() error { return lastErr(input.ParseClientID(prefix+"a\x00b", oauthTable)) }},
		{"a redirect_uri holding NUL", func() error { return lastErr(input.ParseRedirectURI(prefix + "a\x00b")) }},
		{"a nonce holding NUL", func() error { return lastErr(input.ParseNonce("a\x00b")) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.parse() == nil {
				t.Error("the value was accepted")
			}
		})
	}
}

// TestOAuthStoredTextFitsItsBounds holds that the resource and the scope text,
// which come from fixed tables and not from a parser of free text, fit the bounds
// of their columns for every entry of both tables.
func TestOAuthStoredTextFitsItsBounds(t *testing.T) {
	t.Parallel()

	for _, selected := range []resource.Table{oauthTable, oauthDevTable} {
		for _, entry := range selected.Entries() {
			if len(entry.URL) > input.MaxResourceBytes {
				t.Errorf("resource %q is %d bytes, over the bound %d", entry.URL, len(entry.URL), input.MaxResourceBytes)
			}

			all := strings.Join(append([]string{input.OpenIDScope}, entry.Scopes...), " ")
			if len(all) > input.MaxOAuthScopeBytes {
				t.Errorf("the scopes of %q are %d bytes, over the bound %d", entry.URL, len(all), input.MaxOAuthScopeBytes)
			}
		}
	}
}

// TestOAuthMigrationShape holds the parts of the schema that the behaviour of the
// store depends on and that no Go value can show: the uniqueness that makes a
// consent single use and a grant have one access token, the NOT NULL columns
// that turn a condition that matched nothing into a failed batch and name why,
// the cascades, the nullable nonce and the indexes the queries rely on.
func TestOAuthMigrationShape(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	tests := []struct {
		name    string
		pattern string
	}{
		{name: "a grant's account is NOT NULL and cascades",
			pattern: `CREATE TABLE oauth_grants \(.*? user_id TEXT NOT NULL REFERENCES users \(id\) ON DELETE CASCADE,`},
		{name: "a grant's agent is NOT NULL and cascades",
			pattern: `CREATE TABLE oauth_grants \(.*? agent_id TEXT NOT NULL REFERENCES agents \(id\) ON DELETE CASCADE,`},
		{name: "auth_time is NOT NULL: no session, no grant",
			pattern: `CREATE TABLE oauth_grants \(.*? auth_time INTEGER NOT NULL,`},
		{name: "the user, the agent and auth_time are checked in that order",
			pattern: `CREATE TABLE oauth_grants \(.*? user_id TEXT NOT NULL .*? agent_id TEXT NOT NULL ` +
				`.*? auth_time INTEGER NOT NULL`},
		{name: "a consent is used once", pattern: `CREATE TABLE oauth_grants \(.*? granted_from BLOB NOT NULL UNIQUE CHECK`},
		{name: "the nonce is nullable", pattern: `CREATE TABLE oauth_grants \(.*? nonce TEXT CHECK \(nonce IS NULL OR`},
		{name: "a grant has one access token, which its grant's trigger deletes (no cascade, no trigger of its own: D1)",
			pattern: `CREATE TABLE oauth_access_tokens \(.*? grant_id TEXT NOT NULL UNIQUE ` +
				`REFERENCES oauth_grants \(id\),`},
		{name: "a user's grants are listed by id",
			pattern: `CREATE INDEX oauth_grants_user_id ON oauth_grants \(user_id, id\);`},
		{name: "an agent's grants are found to revoke them",
			pattern: `CREATE INDEX oauth_grants_agent_id ON oauth_grants \(agent_id\);`},
		// Migration 0002: what the first-party login's agent relies on. The flag is
		// 0 for every agent that exists, and the unique index is what makes the
		// consent write's ON CONFLICT DO NOTHING find the agent a user already has
		// for a client, and not create a second.
		{name: "an agent is not first-party by default",
			pattern: `ALTER TABLE agents ADD COLUMN first_party INTEGER NOT NULL DEFAULT 0 CHECK \(first_party IN \(0, 1\)\);`},
		{name: "a client is recorded only for a first-party agent",
			pattern: `first_party_client IS NULL OR \(first_party = 1 AND`},
		{name: "a user has one active agent for a client, among those that have one",
			pattern: `CREATE UNIQUE INDEX agents_first_party ON agents \(user_id, first_party_client\) ` +
				`WHERE first_party_client IS NOT NULL AND revoked_at IS NULL;`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if !regexp.MustCompile(test.pattern).MatchString(text) {
				t.Errorf("no declaration matches %s; was the migration text changed?", test.pattern)
			}
		})
	}
}
