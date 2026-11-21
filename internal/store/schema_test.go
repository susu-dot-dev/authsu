//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

// This file is the seam between the Go bounds and the schema. The input package
// refuses what does not fit, and the migrations' CHECKs are the backstop that
// fires only on a Go bug; the two must stay compatible, and nothing else
// compares them. Each row reads one CHECK out of the migrations' text and
// asserts that the largest (and smallest) value Go can send fits inside it.
//
// To cover a new column: add a row to schemaBounds. pattern is a regular
// expression over the migrations with whitespace collapsed, with one capture
// group (the limit; with exact, Go's value must equal it, otherwise be at most
// it) or two (the lower and upper limit; Go's range must lie within). A row
// with no group only asserts that the CHECK is present. Every match of the
// pattern must hold, so a rule repeated across tables is checked in each.

// bound is one Go value checked against one schema CHECK.
type bound struct {
	name    string
	pattern string

	// lowest and highest are the smallest and largest value Go can send, in the
	// unit the CHECK measures.
	lowest, highest int

	// exact means the CHECK is an equality and highest must equal it.
	exact bool
}

// comment matches an SQL line comment. The migration has no string literal
// holding "--", so cutting at it is exact.
var comment = regexp.MustCompile(`--[^\n]*`)

// migrations returns the text of every migration with its comments removed and
// whitespace collapsed, so a pattern reads the declarations and never prose.
func migrations(t *testing.T) string {
	t.Helper()

	paths, err := filepath.Glob("../../migrations/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}

	var text strings.Builder

	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // the paths are a glob of the repository's own migrations
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		text.WriteString(comment.ReplaceAllString(string(raw), ""))
		text.WriteString("\n")
	}

	return squash(text.String())
}

// worstAccountName is the longest AccountName whose JSON encoding is longest:
// "<" is one byte and six once escaped.
func worstAccountName(t *testing.T) input.AccountName {
	t.Helper()

	return mustName(t, strings.Repeat("<", input.MaxAccountNameBytes))
}

// worstNewAccount returns the largest account registration can write, as the
// strings the store sends for the JSON columns.
func worstNewAccount(t *testing.T) (string, string) {
	t.Helper()

	// The longest transport list the authenticator layer allows, of the longest
	// entries (32 bytes), each made of the characters JSON escapes. The 32 is
	// that package's maxTransportLen; the count is its MaxTransports.
	transports := make([]string, webauthn.MaxTransports)
	for i := range transports {
		transports[i] = strings.Repeat(`"`, 32)
	}

	fake := newFake(applied(5))

	err := fake.store().CreateAccount(context.Background(), store.NewAccount{
		UserID: "u", UserHandle: []byte{1}, Role: "admin", Name: worstAccountName(t),
		Token: mustInvitationToken(t, 1), InvitationType: "member", CredentialRowID: "c", CredentialID: []byte{1},
		PublicKey: []byte{1}, Flags: 0, AAGUID: strings.Repeat("0", 36), Transports: transports, CreatedAt: now,
		FirstRunID: "f", FirstRunLabel: "l", FirstRunExpiresAt: now,
	})
	if err != nil {
		t.Fatalf("create worst-case account: %v", err)
	}

	statements := fake.calls[0]

	// The batch is the first-run secret and invitation, the user, the
	// organization's administrator, the passkey.
	profile, _ := statements[2].Args[3].(string)
	metadata, _ := statements[4].Args[5].(string)

	return profile, metadata
}

// secretHashCheck is the CHECK of secrets.hash: a BLOB (length() counts a TEXT
// value in characters) of exactly the length of a SHA-256.
//
//nolint:gosec // a pattern naming the hash column, not a credential
const secretHashCheck = `CHECK \(typeof\(hash\) = 'blob' AND length\(hash\) = (\d+)\)`

// schemaBounds lists every Go bound with the CHECK it must fit inside.
func schemaBounds(t *testing.T) []bound {
	t.Helper()

	profile, metadata := worstNewAccount(t)

	return []bound{
		// Identifiers: every id column is length 36 of lowercase hex and dashes,
		// which is exactly the canonical UUID form input.ID accepts.
		{name: "id length", pattern: `length\(id\) = (\d+)`, lowest: input.IDLen, highest: input.IDLen, exact: true},
		{name: "id alphabet", pattern: `NOT GLOB '\*\[\^0-9a-f-\]\*'`, lowest: 0, highest: 0, exact: false},

		// Inbound text.
		{name: "agent name bytes", pattern: `length\(cast\(name AS BLOB\)\) BETWEEN (\d+) AND (\d+)`,
			lowest: 1, highest: input.MaxAgentNameRunes * utf8.UTFMax, exact: false},
		{name: "invitation label bytes",
			pattern: `CHECK \(typeof\(label\) = 'text' AND instr\(label, char\(0\)\) = 0 ` +
				`AND length\(cast\(label AS BLOB\)\) <= (\d+)\)`,
			lowest: 0, highest: input.MaxInvitationLabelRunes * utf8.UTFMax, exact: false},
		{name: "profile JSON of the longest escaped account name", pattern: `length\(profile\) <= (\d+)`,
			lowest: 0, highest: len(profile), exact: false},

		// Every secret is stored as the hash of its token, whatever its kind.
		{name: "invitation token hash", pattern: secretHashCheck,
			lowest: len(mustInvitationToken(t, 1).Hash()), highest: len(mustInvitationToken(t, 1).Hash()), exact: true},
		{name: "session token hash", pattern: secretHashCheck,
			lowest: len(mustSessionToken(t, 1).Hash()), highest: len(mustSessionToken(t, 1).Hash()), exact: true},
		{name: "API key token hash", pattern: secretHashCheck,
			lowest: len(mustAPIKeyToken(t, 1).Hash()), highest: len(mustAPIKeyToken(t, 1).Hash()), exact: true},
		{name: "authorization code hash", pattern: secretHashCheck,
			lowest: len(mustAuthorizationCode(t, 1).Hash()), highest: len(mustAuthorizationCode(t, 1).Hash()), exact: true},
		{name: "refresh token hash", pattern: secretHashCheck,
			lowest: len(mustRefreshToken(t, 1).Hash()), highest: len(mustRefreshToken(t, 1).Hash()), exact: true},
		{name: "access token hash", pattern: secretHashCheck,
			lowest: len(mustAccessToken(t, 1).Hash()), highest: len(mustAccessToken(t, 1).Hash()), exact: true},

		// What the authenticator reports. 1023 is webauthn's maxCredentialIDLen
		// (WebAuthn section 4); the user handle is the registration challenge's
		// nonce.
		{name: "credential id", pattern: `length\(credential_id\) BETWEEN (\d+) AND (\d+)`,
			lowest: 1, highest: 1023, exact: false},
		{name: "user handle", pattern: `length\(user_handle\) BETWEEN (\d+) AND (\d+)`,
			lowest: challenge.NonceLen, highest: challenge.NonceLen, exact: false},
		{name: "credential flags are one byte", pattern: `flags BETWEEN (\d+) AND (\d+)`,
			lowest: 0, highest: 255, exact: false},
		{name: "credential metadata JSON of the longest transport list",
			pattern: `metadata TEXT NOT NULL CHECK \(typeof\(metadata\) = 'text' ` +
				`AND json_valid\(metadata\) AND length\(metadata\) <= (\d+)\)`,
			lowest: 0, highest: len(metadata), exact: false},

		// The kind of a secret is one of the constants the store writes.
		{name: "secret kind", pattern: `typeof\(kind\) = 'text' AND length\(kind\) BETWEEN (\d+) AND (\d+)`,
			lowest: min(len(store.KindInvitation), len(store.KindSession), len(store.KindAPIKey),
				len(store.KindOAuthGrant), len(store.KindOAuthAccess)),
			highest: max(len(store.KindInvitation), len(store.KindSession), len(store.KindAPIKey),
				len(store.KindOAuthGrant), len(store.KindOAuthAccess)), exact: false},

		// The session's grant is the hash of the login challenge: SHA-256, as
		// auth.LoginGrant computes it. The pattern also matches the column of an
		// OAuth grant, which is the hash of the sealed pending request, also
		// SHA-256 (oauthSchemaBounds names it).
		{name: "login grant hash", pattern: `typeof\(granted_from\) = 'blob' AND length\(granted_from\) = (\d+)`,
			lowest: sha256.Size, highest: sha256.Size, exact: true},
	}
}

// TestGoBoundsFitTheSchema holds that every value Go can send fits its CHECK.
func TestGoBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	for _, b := range schemaBounds(t) {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()

			matches := regexp.MustCompile(b.pattern).FindAllStringSubmatch(text, -1)
			if len(matches) == 0 {
				t.Fatalf("no CHECK matches %s; was the migration text changed?", b.pattern)
			}

			for _, match := range matches {
				checkBound(t, b, match[1:])
			}
		})
	}
}

// checkBound compares one match of a bound's pattern with Go's range.
func checkBound(t *testing.T, b bound, limits []string) {
	t.Helper()

	numbers := make([]int, len(limits))

	for i, limit := range limits {
		number, err := strconv.Atoi(limit)
		if err != nil {
			t.Fatalf("limit %q is not a number: %v", limit, err)
		}

		numbers[i] = number
	}

	if problem := b.violation(numbers); problem != "" {
		t.Error(problem)
	}
}

// violation says how Go's range breaks the limits a CHECK states, or "" if it
// fits. No limits is a presence check, one is an upper (or exact) limit and two
// are a range.
func (b bound) violation(limits []int) string {
	switch len(limits) {
	case 2:
		if b.lowest < limits[0] || b.highest > limits[1] {
			return fmt.Sprintf("Go sends %d to %d; the schema allows %d to %d", b.lowest, b.highest, limits[0], limits[1])
		}
	case 1:
		if b.exact && b.highest != limits[0] {
			return fmt.Sprintf("Go sends %d; the schema requires exactly %d", b.highest, limits[0])
		}

		if !b.exact && b.highest > limits[0] {
			return fmt.Sprintf("Go sends up to %d; the schema allows %d", b.highest, limits[0])
		}
	}

	return ""
}

// TestSchemaBoundsAreMeaningful guards the table above against a pattern that
// matches but proves nothing: the worst cases must be large enough to matter.
func TestSchemaBoundsAreMeaningful(t *testing.T) {
	t.Parallel()

	profile, metadata := worstNewAccount(t)

	// 128 escaped bytes: the six-fold expansion plus {"name":""}.
	if want := len(`{"name":""}`) + input.MaxAccountNameBytes*len(`\u003c`); len(profile) != want {
		t.Errorf("worst-case profile is %d bytes, want %d", len(profile), want)
	}

	if len(metadata) < webauthn.MaxTransports*32 {
		t.Errorf("worst-case metadata is only %d bytes", len(metadata))
	}
}
