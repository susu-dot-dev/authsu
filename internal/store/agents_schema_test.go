package store_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// This file extends the seam of schema_test.go to the agent columns, with that
// file's bound table and checks. agents and japikeys.scope bound BYTES and
// refuse NUL, because SQLite's length() on TEXT stops at the first NUL.

// agentDefaultScopes is the shape of the scope list every agent is created
// with (the agents feature's default bundle). Go chooses it, so it is not an
// input, but it is written to two columns whose CHECK it must fit.
const agentDefaultScopes = "default:agent"

// agentWorstName is the longest AgentName by bytes: the most runes the parser
// allows, each of the longest UTF-8 form.
func agentWorstName(t *testing.T) input.AgentName {
	t.Helper()

	return mustAgentName(t, strings.Repeat("\U00010000", input.MaxAgentNameRunes))
}

// agentSchemaBounds lists the agent columns' Go values with the CHECK each must
// fit inside.
func agentSchemaBounds(t *testing.T) []bound {
	t.Helper()

	name := agentWorstName(t)

	// column is the start of a size CHECK of 0005, so that a pattern matches
	// only the one column it names.
	column := func(name string) string {
		return fmt.Sprintf(`CHECK \(typeof\(%[1]s\) = 'text' AND instr\(%[1]s, char\(0\)\) = 0 AND `, name)
	}

	return []bound{
		{name: "agents.name bytes", pattern: column("name") + `length\(cast\(name AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)`,
			lowest: 1, highest: len(name.String()), exact: false},
		{name: "agents.scopes bytes",
			pattern: column("scopes") + `length\(cast\(scopes AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)`,
			lowest:  len(agentDefaultScopes), highest: len(agentDefaultScopes), exact: false},
		{name: "japikeys.scope bytes",
			pattern: `CHECK \(scope IS NULL OR \(typeof\(scope\) = 'text' AND instr\(scope, char\(0\)\) = 0 ` +
				`AND length\(cast\(scope AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)\)`,
			lowest: len(agentDefaultScopes), highest: len(agentDefaultScopes), exact: false},
	}
}

// TestAgentBoundsFitTheSchema holds that every value Go can send for an agent
// fits its CHECK.
func TestAgentBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	for _, b := range agentSchemaBounds(t) {
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

// TestAgentBoundsAreMeaningful guards the table above against a pattern that
// matches but proves nothing: the worst name must really be the largest, and
// the parser must really refuse the NUL the CHECK refuses.
func TestAgentBoundsAreMeaningful(t *testing.T) {
	t.Parallel()

	name := agentWorstName(t).String()

	if want := input.MaxAgentNameRunes * utf8.UTFMax; len(name) != want {
		t.Errorf("worst-case name is %d bytes, want %d", len(name), want)
	}

	_, err := input.ParseAgentName(strings.Repeat("\U00010000", input.MaxAgentNameRunes+1))
	if err == nil {
		t.Error("a name of one rune more than the maximum was accepted")
	}

	// The CHECK refuses NUL (length() would stop at it); so must the parser.
	for _, raw := range []string{"\x00", "a\x00b", "bot\x00" + strings.Repeat("x", 4096)} {
		_, err = input.ParseAgentName(raw)
		if err == nil {
			t.Errorf("a name holding NUL was accepted: %q", raw[:min(len(raw), 8)])
		}
	}

	if agentDefaultScopes == "" || strings.ContainsRune(agentDefaultScopes, 0) {
		t.Errorf("the default scopes %q break the CHECK (1 to 1024 bytes, no NUL)", agentDefaultScopes)
	}
}
